//! Running external tools on untrusted input with a deadline.
//!
//! A hostile archive can drive an extractor into an endless loop, and an
//! unbounded wait parks the analysis thread for good. Every tool cleave runs
//! on analysis input goes through [`output_with_timeout`].

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long a version or capability probe may take.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long listing an archive's contents may take.
pub(crate) const LIST_TIMEOUT: Duration = Duration::from_secs(120);
/// How long extracting an archive may take.
pub(crate) const EXTRACT_TIMEOUT: Duration = Duration::from_secs(600);

/// How often a running tool is checked for exit.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Spawn `command` and wait for it, killing it once `timeout` elapses.
///
/// Stdout and stderr, when `command` pipes them, are drained on helper
/// threads while waiting, so a tool cannot stall on a full pipe; unpiped
/// streams come back empty. Returns `Ok(None)` when the tool was killed for
/// running past `timeout`.
pub(crate) fn output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<Option<Output>> {
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    let status = wait_with_timeout(&mut child, timeout)?;
    let stdout = stdout.map(join).unwrap_or_default();
    let stderr = stderr.map(join).unwrap_or_default();
    Ok(status.map(|status| Output {
        status,
        stdout,
        stderr,
    }))
}

fn drain(mut pipe: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        // A read error only truncates the captured output; the exit status
        // still reports how the tool fared.
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

fn join(handle: JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            // Kill fails only if the tool exited in the meantime; either way
            // `wait` reaps it.
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
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
