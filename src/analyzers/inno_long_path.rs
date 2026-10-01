//! Linux fallback for Inno members whose single filename component exceeds
//! the filesystem's `NAME_MAX` during extraction.
//!
//! The normal extractor path remains the fast path. This module is only used
//! after innoextract reports that it could not create an overlong output file.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;

const TRACE_WORD_BYTES: usize = std::mem::size_of::<libc::c_long>();
const MAX_PATH_BYTES: usize = 4096;

/// Run an extractor command under syscall tracing and shorten only output
/// components that exceed Linux's 255-byte filename limit.
///
/// Returns the raw wait status, captured stderr, and number of rewritten paths.
pub(crate) fn run(executable: &OsStr, args: &[&OsStr]) -> io::Result<(i32, Vec<u8>, usize)> {
    let mut stderr_file = tempfile::tempfile()?;
    let stdout_null = std::fs::File::open("/dev/null")?;
    let executable = std::ffi::CString::new(executable.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in executable path"))?;
    let mut owned_args = Vec::with_capacity(args.len() + 1);
    owned_args.push(executable.clone());
    for arg in args {
        owned_args.push(
            std::ffi::CString::new(arg.as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in argument"))?,
        );
    }
    let mut argv: Vec<*const libc::c_char> = owned_args.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: the child branch uses only async-signal-safe syscalls before
    // exec. Argument buffers and descriptors are prepared before fork.
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: this is the forked child. It stops before exec so the parent
        // can enable syscall tracing, then redirects output and execs.
        unsafe {
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) == -1
            {
                libc::_exit(126);
            }
            libc::raise(libc::SIGSTOP);
            libc::dup2(stdout_null.as_raw_fd(), libc::STDOUT_FILENO);
            libc::dup2(stderr_file.as_raw_fd(), libc::STDERR_FILENO);
            libc::execv(executable.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    let pid = pid as libc::pid_t;
    let initial_status = wait_for(pid)?;
    if !libc::WIFSTOPPED(initial_status) {
        return Err(io::Error::other(
            "Innoextract tracee did not stop before exec",
        ));
    }

    // SAFETY: pid is our direct child stopped under PTRACE_TRACEME.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL) as usize as *mut libc::c_void,
        )
    } == -1
    {
        terminate_tracee(pid);
        return Err(io::Error::last_os_error());
    }

    let mut rewritten = 0usize;
    let mut at_syscall_entry = true;
    // SAFETY: the child is stopped and owned by this tracer.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    } == -1
    {
        terminate_tracee(pid);
        return Err(io::Error::last_os_error());
    }

    let raw_status = loop {
        let status = match wait_for(pid) {
            Ok(status) => status,
            Err(error) => {
                terminate_tracee(pid);
                return Err(error);
            }
        };
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            break status;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }

        let stop_signal = libc::WSTOPSIG(status);
        if stop_signal == (libc::SIGTRAP | 0x80) {
            if at_syscall_entry
                && let Some(registers) = get_registers(pid)
                && rewrite_overlong_openat(pid, &registers)
            {
                rewritten += 1;
            }
            at_syscall_entry = !at_syscall_entry;
        }

        let delivered_signal = if stop_signal == libc::SIGSTOP || stop_signal == libc::SIGTRAP {
            0
        } else if stop_signal == (libc::SIGTRAP | 0x80) {
            0
        } else {
            stop_signal
        };

        // SAFETY: resume the stopped child and deliver only genuine signals.
        if unsafe {
            libc::ptrace(
                libc::PTRACE_SYSCALL,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                delivered_signal as usize as *mut libc::c_void,
            )
        } == -1
        {
            terminate_tracee(pid);
            return Err(io::Error::last_os_error());
        }
    };

    stderr_file.seek(SeekFrom::Start(0))?;
    let mut stderr = Vec::new();
    stderr_file.read_to_end(&mut stderr)?;
    Ok((raw_status, stderr, rewritten))
}

fn wait_for(pid: libc::pid_t) -> io::Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY: wait for the specific child process owned by this tracer.
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(status);
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}

fn get_registers(pid: libc::pid_t) -> Option<libc::user_regs_struct> {
    let mut registers = std::mem::MaybeUninit::<libc::user_regs_struct>::uninit();
    // SAFETY: the tracee is stopped at a syscall boundary; ptrace fills regs.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            registers.as_mut_ptr().cast::<libc::c_void>(),
        )
    };
    (result != -1).then(|| {
        // SAFETY: successful PTRACE_GETREGS initialized the full structure.
        unsafe { registers.assume_init() }
    })
}

fn rewrite_overlong_openat(pid: libc::pid_t, registers: &libc::user_regs_struct) -> bool {
    if registers.orig_rax as libc::c_long != libc::SYS_openat
        || registers.rdx & libc::O_CREAT as u64 == 0
    {
        return false;
    }

    let Some(original) = read_tracee_string(pid, registers.rsi) else {
        return false;
    };
    let Some(shortened) = shortened_output_path(&original) else {
        return false;
    };
    if !write_tracee_string(pid, registers.rsi, &shortened) {
        return false;
    }
    true
}

fn read_tracee_string(pid: libc::pid_t, address: u64) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < MAX_PATH_BYTES {
        let word = peek_word(pid, address.checked_add(offset as u64)?)?;
        let bytes = word.to_ne_bytes();
        if let Some(end) = bytes.iter().position(|byte| *byte == 0) {
            result.extend_from_slice(&bytes[..end]);
            return Some(result);
        }
        result.extend_from_slice(&bytes);
        offset += TRACE_WORD_BYTES;
    }
    None
}

fn peek_word(pid: libc::pid_t, address: u64) -> Option<libc::c_long> {
    // SAFETY: PTRACE_PEEKDATA reads one machine word from this stopped tracee.
    let value = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKDATA,
            pid,
            address as usize as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    (value != -1).then_some(value)
}

fn write_tracee_string(pid: libc::pid_t, address: u64, value: &[u8]) -> bool {
    let mut bytes = value.to_vec();
    bytes.push(0);
    for (index, chunk) in bytes.chunks(TRACE_WORD_BYTES).enumerate() {
        let mut word = [0u8; TRACE_WORD_BYTES];
        word[..chunk.len()].copy_from_slice(chunk);
        let word = libc::c_long::from_ne_bytes(word);
        // SAFETY: PTRACE_POKEDATA writes a word into this stopped tracee's
        // pathname buffer. The replacement ends with NUL before old bytes.
        if unsafe {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                (address as usize + index * TRACE_WORD_BYTES) as *mut libc::c_void,
                word as usize as *mut libc::c_void,
            )
        } == -1
        {
            return false;
        }
    }
    true
}

fn terminate_tracee(pid: libc::pid_t) {
    // SAFETY: terminate and reap the child if tracing cannot continue.
    unsafe {
        libc::ptrace(
            libc::PTRACE_KILL,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
}

/// Return a deterministic safe path when the final component exceeds NAME_MAX.
fn shortened_output_path(path: &[u8]) -> Option<Vec<u8>> {
    let separator = path.iter().rposition(|byte| *byte == b'/');
    let leaf_start = separator.map_or(0, |index| index + 1);
    let leaf = &path[leaf_start..];
    if leaf.len() <= 255 {
        return None;
    }

    let mut hash = 0xcbf29ce484222325u64;
    for byte in path {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    let extension = leaf
        .iter()
        .rposition(|byte| *byte == b'.')
        .map(|index| &leaf[index..])
        .filter(|extension| {
            extension.len() <= 12 && extension.iter().skip(1).all(u8::is_ascii_alphanumeric)
        })
        .unwrap_or_default();
    let replacement = format!(
        "__cleave_long_{hash:016x}{}",
        String::from_utf8_lossy(extension)
    );
    let mut result = path[..leaf_start].to_vec();
    result.extend_from_slice(replacement.as_bytes());
    Some(result)
}

/// Determine whether an innoextract diagnostic identifies an overlong path.
pub(crate) fn reports_overlong_output(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr);
    text.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("open output file") {
            return false;
        }
        let Some(start) = line.find('"') else {
            return false;
        };
        let Some(end) = line.rfind('"').filter(|end| *end > start) else {
            return false;
        };
        line[start + 1..end]
            .split(['/', '\\'])
            .any(|component| component.len() > 255)
    })
}

#[cfg(test)]
mod tests {
    use super::{reports_overlong_output, shortened_output_path};

    #[test]
    fn shortens_only_the_overlong_leaf_and_preserves_extension() {
        let original = format!("app/{}file.cmd", "\u{205f}".repeat(175));
        let shortened = shortened_output_path(original.as_bytes()).unwrap();
        let shortened = String::from_utf8(shortened).unwrap();
        assert!(shortened.starts_with("app/__cleave_long_"));
        assert!(shortened.ends_with(".cmd"));
        assert!(shortened.len() < 64);
    }

    #[test]
    fn leaves_legal_paths_unchanged() {
        assert_eq!(shortened_output_path(b"app/readme.txt"), None);
        assert_eq!(shortened_output_path(&vec![b'a'; 255]), None);
    }

    #[test]
    fn detects_only_output_failures_with_overlong_components() {
        let long = "\u{205f}".repeat(100);
        let error = format!("Could not open output file \"/tmp/out/{long}.cmd\"");
        assert!(reports_overlong_output(error.as_bytes()));
        assert!(!reports_overlong_output(
            b"Could not open output file \"/tmp/out/short.cmd\""
        ));
        assert!(!reports_overlong_output(b"Unsupported Inno stream"));
    }
}
