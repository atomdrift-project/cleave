//! Occasional usage tips for interactive runs.
//!
//! A tip prints to stderr only when both stdout and stderr are terminals, and
//! at most once every 60 days: the time it was last shown is kept in
//! `<cache_dir>/atomdrift/cleave/tip-annotate`. Losing that file only means
//! the tip shows again; nothing else reads it.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimum interval between two showings of the same tip: 60 days.
const INTERVAL_SECS: u64 = 60 * 24 * 60 * 60;

/// Suggest `--annotate` after the default index view, if a person is watching
/// and the tip has not been shown in the last 60 days.
pub fn maybe_suggest_annotate() {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal() {
        return;
    }
    let Some(path) = dirs::cache_dir().map(|d| d.join("atomdrift/cleave/tip-annotate")) else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if claim(&path, now) {
        eprintln!("\n💡 Try --annotate mode to see source data alongside findings");
    }
}

/// Report whether the tip stamped at `path` is due at `now`, and if so record
/// `now` as its last showing. A missing or unreadable stamp is due. A stamp
/// that cannot be written is logged and the tip still shows this once.
fn claim(path: &Path, now: u64) -> bool {
    let last = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    if last.is_some_and(|last| now.saturating_sub(last) < INTERVAL_SECS) {
        return false;
    }
    let written = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| crate::cache::atomic_write(path, now.to_string().as_bytes()));
    if let Err(e) = written {
        tracing::debug!(path = %path.display(), error = %e, "tip stamp not written");
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn stamp_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("nested/tip-annotate")
    }

    #[test]
    fn first_run_shows_and_stamps() {
        let dir = tempfile::tempdir().unwrap();
        let path = stamp_path(&dir);
        assert!(claim(&path, 1_000));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "1000");
    }

    #[test]
    fn shows_once_per_interval() {
        let dir = tempfile::tempdir().unwrap();
        let path = stamp_path(&dir);
        assert!(claim(&path, 1_000));
        assert!(!claim(&path, 1_001));
        assert!(!claim(&path, 1_000 + INTERVAL_SECS - 1));
        assert!(claim(&path, 1_000 + INTERVAL_SECS));
        assert!(!claim(&path, 1_000 + INTERVAL_SECS + 1));
    }

    #[test]
    fn clock_behind_stamp_stays_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let path = stamp_path(&dir);
        assert!(claim(&path, 5_000));
        assert!(!claim(&path, 10));
    }

    #[test]
    fn garbage_stamp_is_due() {
        let dir = tempfile::tempdir().unwrap();
        let path = stamp_path(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not a number").unwrap();
        assert!(claim(&path, 1_000));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "1000");
    }
}
