//! Running external tools on untrusted input with a deadline.
//!
//! A hostile archive can drive an extractor into an endless loop, and an
//! unbounded wait parks the analysis thread for good, and a decompression bomb
//! can fill the disk. Every tool cleave runs on analysis input goes through
//! [`output_with_timeout`] (extractors through [`extract_with_timeout`], which
//! also bounds what they write), and gets only the environment [`scrub_env`]
//! allows.

use std::ffi::OsString;
use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

/// How long a version or capability probe may take.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long listing an archive's contents may take.
pub(crate) const LIST_TIMEOUT: Duration = Duration::from_secs(120);
/// How long extracting an archive may take.
pub(crate) const EXTRACT_TIMEOUT: Duration = Duration::from_secs(600);

/// How often a running tool is checked for exit.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How often an extractor's output directory is measured against its budget.
const OUTPUT_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// How long output may keep draining after the tool's group was killed. A
/// helper that left the group can hold a pipe forever; its output is then
/// abandoned rather than waited for.
const DRAIN_GRACE: Duration = Duration::from_secs(1);

/// Most bytes kept from one of a tool's output streams. The rest is read and
/// discarded so the tool never blocks on a full pipe. A listing of the largest
/// archive cleave will open fits well within this.
const MAX_CAPTURE_BYTES: u64 = 128 << 20;

/// The environment variables a tool parsing untrusted input may inherit: what
/// it needs to find helpers, temp space, and a locale, plus the variables a
/// Windows process needs to start. Everything else, such as API tokens and
/// service keys, stays out of reach of a tool a hostile sample compromises.
/// Mirrors `filefacts::tools::scrub_env`, which the filefacts release cleave
/// builds against does not have yet.
const ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
];

/// The allowlisted subset of this process's environment.
pub(crate) fn allowed_env() -> impl Iterator<Item = (&'static str, OsString)> {
    ENV_ALLOWLIST
        .iter()
        .filter_map(|&key| std::env::var_os(key).map(|value| (key, value)))
}

/// Replace `command`'s environment with [`allowed_env`].
pub(crate) fn scrub_env(command: &mut Command) {
    command.env_clear().envs(allowed_env());
}

/// Spawn `command` and wait for it, killing it once `timeout` elapses.
///
/// Stdout and stderr, when `command` pipes them, are drained on helper
/// threads while waiting, so a tool cannot stall on a full pipe; unpiped
/// streams come back empty, and each keeps at most [`MAX_CAPTURE_BYTES`].
/// Returns `Ok(None)` when the tool was killed for running past `timeout`.
///
/// On Unix the tool runs in its own process group, and the deadline covers
/// its output as well as its exit: a helper the tool spawned can keep the
/// pipes open after the tool is gone. Past the deadline the group is killed.
/// That is safe even after the tool was reaped, because a helper still
/// holding a pipe keeps the group, and so its id, alive.
pub(crate) fn output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<Option<Output>> {
    run(command, timeout, || false)
}

/// [`output_with_timeout`] for an extractor writing into `out_dir`: the tool is
/// also killed once the files under `out_dir` pass `max_bytes`, so a
/// decompression bomb cannot fill the disk (or a tmpfs, which is RAM) before
/// the deadline. Returns `Ok(None)` when the tool was killed for either reason.
pub(crate) fn extract_with_timeout(
    command: &mut Command,
    timeout: Duration,
    out_dir: &std::path::Path,
    max_bytes: u64,
) -> io::Result<Option<Output>> {
    let mut next_check = Instant::now();
    run(command, timeout, || {
        if Instant::now() < next_check {
            return false;
        }
        next_check = Instant::now() + OUTPUT_CHECK_INTERVAL;
        let over = tree_bytes_exceed(out_dir, max_bytes);
        if over {
            tracing::warn!(
                out_dir = %out_dir.display(),
                max_bytes,
                "extractor output passed its size budget; killing it"
            );
        }
        over
    })
}

/// Whether the regular files under `dir` (symlinks not followed) hold more
/// than `max_bytes`. Stops counting at the first byte over.
fn tree_bytes_exceed(dir: &std::path::Path, max_bytes: u64) -> bool {
    let mut total: u64 = 0;
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| entry.metadata().ok())
        .any(|meta| {
            total = total.saturating_add(meta.len());
            total > max_bytes
        })
}

fn run(
    command: &mut Command,
    timeout: Duration,
    over_budget: impl FnMut() -> bool,
) -> io::Result<Option<Output>> {
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(command, 0);
    let deadline = Instant::now() + timeout;
    let mut child = command.spawn()?;
    let pid = child.id();
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    let status = wait_until(&mut child, deadline, over_budget)?;
    let stdout = stdout.map_or_else(Vec::new, |rx| collect(&rx, deadline, pid));
    let stderr = stderr.map_or_else(Vec::new, |rx| collect(&rx, deadline, pid));
    Ok(status.map(|status| Output {
        status,
        stdout,
        stderr,
    }))
}

fn drain(mut pipe: impl Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        // A read error only truncates the captured output; the exit status
        // still reports how the tool fared.
        let _ = (&mut pipe).take(MAX_CAPTURE_BYTES).read_to_end(&mut buf);
        let _ = io::copy(&mut pipe, &mut io::sink());
        // The receiver is gone only if the caller gave up on this output.
        let _ = tx.send(buf);
    });
    rx
}

/// The output a drain thread captured, waiting no later than `deadline`
/// before killing the tool's group (see [`output_with_timeout`]).
fn collect(rx: &Receiver<Vec<u8>>, deadline: Instant, pid: u32) -> Vec<u8> {
    if let Ok(buf) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        return buf;
    }
    kill_group(pid);
    rx.recv_timeout(DRAIN_GRACE).unwrap_or_else(|_| {
        tracing::warn!(
            pid,
            "abandoning output a detached helper process holds open"
        );
        Vec::new()
    })
}

fn wait_until(
    child: &mut Child,
    deadline: Instant,
    mut over_budget: impl FnMut() -> bool,
) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline || over_budget() {
            kill_group(child.id());
            // Kill fails only if the tool exited in the meantime; either way
            // `wait` reaps it.
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The path of the first of `names` that resolves and passes `probe_args`.
///
/// Only a success is remembered (in `cached`): a probe can fail transiently
/// (spawn refused under load, a start slower than [`PROBE_TIMEOUT`]), and a
/// long-running process must not lose the tool for good because of one. A
/// failed probe is logged and retried by the next caller.
pub(crate) fn probed_tool(
    cached: &'static std::sync::OnceLock<std::path::PathBuf>,
    names: &[&str],
    probe_args: &[&str],
) -> Option<std::path::PathBuf> {
    if let Some(path) = cached.get() {
        return Some(path.clone());
    }
    for name in names {
        let Some(path) = crate::tool_resolution::resolve(name) else {
            continue;
        };
        let mut probe = Command::new(&path);
        probe
            .args(probe_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        scrub_env(&mut probe);
        match output_with_timeout(&mut probe, PROBE_TIMEOUT) {
            Ok(Some(_)) => return Some(cached.get_or_init(|| path).clone()),
            Ok(None) => tracing::warn!(
                tool = %path.display(),
                timeout_secs = PROBE_TIMEOUT.as_secs(),
                "tool probe timed out; skipping it for this file"
            ),
            Err(error) => tracing::warn!(
                tool = %path.display(),
                %error,
                "tool probe failed to run; skipping it for this file"
            ),
        }
    }
    None
}

/// Kill the process group [`output_with_timeout`] started the tool `pid` in.
fn kill_group(pid: u32) {
    #[cfg(unix)]
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: kill has no memory-safety preconditions; a negative pid
        // names the process group the child leads, created at spawn.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::process::Stdio;

    #[test]
    fn captures_output_of_a_tool_that_finishes() {
        let mut command = Command::new("sh");
        command
            .args(["-c", "echo out; echo err >&2"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = output_with_timeout(&mut command, PROBE_TIMEOUT)
            .unwrap()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.stderr, b"err\n");
    }

    #[test]
    fn scrubbed_tool_sees_only_allowlisted_env() {
        let mut command = Command::new("env");
        command
            .env("CLEAVE_TEST_SECRET", "hunter2")
            .stdout(Stdio::piped());
        scrub_env(&mut command);
        let output = output_with_timeout(&mut command, PROBE_TIMEOUT)
            .unwrap()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("CLEAVE_TEST_SECRET"), "{stdout}");
        for line in stdout.lines() {
            let key = line.split('=').next().unwrap();
            assert!(ENV_ALLOWLIST.contains(&key), "unexpected variable {key}");
        }
        if std::env::var_os("PATH").is_some() {
            assert!(stdout.lines().any(|line| line.starts_with("PATH=")));
        }
    }

    #[test]
    fn a_timeout_kills_the_tools_children_too() {
        // The grandchild inherits stdout; if it survived, draining would block
        // until it exited.
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30 & sleep 30"])
            .stdout(Stdio::piped());
        let started = Instant::now();
        let output = output_with_timeout(&mut command, Duration::from_millis(200)).unwrap();
        assert!(output.is_none());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_helper_holding_the_pipe_after_exit_cannot_hang_the_caller() {
        // The tool exits at once; its background helper keeps stdout open.
        let mut command = Command::new("sh");
        command
            .args(["-c", "echo done; sleep 30 &"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let output = output_with_timeout(&mut command, Duration::from_millis(500))
            .unwrap()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"done\n");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn kills_a_tool_that_overruns() {
        let mut command = Command::new("sleep");
        command.arg("30");
        let started = Instant::now();
        let output = output_with_timeout(&mut command, Duration::from_millis(200)).unwrap();
        assert!(
            output.is_none(),
            "an overrunning tool is reported as timed out"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
