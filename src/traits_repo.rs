//! Manages the external traits repository (clone, update, resolve).
//!
//! Traits (detection rules) live in a separate git repository. This module
//! handles locating, auto-cloning, and updating that repository so users
//! don't need to manage it manually.
//!
//! Resolution order:
//! 1. `--traits-dir` CLI flag / `CLEAVE_TRAITS_DIR` env var
//! 2. Platform data directory (auto-cloned from upstream)

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{OnceLock, RwLock};

const TRAITS_REPO_URL: &str = "https://codeberg.org/atomdrift/cleave-traits.git";
const STALENESS_DAYS: u64 = 30;

/// Process-wide override for the traits directory.
///
/// Set by [`set_override_dir`] (e.g. from a CLI flag or library caller) and
/// consulted before the `CLEAVE_TRAITS_DIR` env var. Lets library callers
/// configure traits resolution without mutating process environment.
static TRAITS_DIR_OVERRIDE: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();

fn traits_dir_override_lock() -> &'static RwLock<Option<PathBuf>> {
    TRAITS_DIR_OVERRIDE.get_or_init(|| RwLock::new(None))
}

/// Set a process-wide override for the traits directory.
///
/// Takes precedence over `CLEAVE_TRAITS_DIR`. Pass `None` to clear.
pub fn set_override_dir(dir: Option<PathBuf>) {
    if let Ok(mut guard) = traits_dir_override_lock().write() {
        *guard = dir;
    }
}

/// Returns the active override, if any.
#[must_use]
pub fn override_dir() -> Option<PathBuf> {
    traits_dir_override_lock()
        .read()
        .ok()
        .and_then(|g| g.clone())
}

/// Returns the explicit traits dir from override-or-env, if either is set.
fn explicit_traits_dir() -> Option<String> {
    if let Some(p) = override_dir() {
        return Some(p.to_string_lossy().into_owned());
    }
    std::env::var("CLEAVE_TRAITS_DIR").ok()
}

/// Resolve the traits directory, auto-cloning if necessary.
///
/// Returns the path to a usable traits directory, or an error if traits cannot
/// be obtained.
#[allow(dead_code)] // Used by binary target
pub fn resolve_and_ensure() -> Result<PathBuf, String> {
    // 1. Explicit override via API setter or CLEAVE_TRAITS_DIR env var
    if let Some(explicit) = explicit_traits_dir() {
        let p = PathBuf::from(&explicit);
        if p.is_dir() || p.is_file() {
            tracing::debug!("Using traits from explicit override: {}", p.display());
            return Ok(p);
        }
        return Err(format!("traits dir override {explicit} does not exist"));
    }

    // 2. Workspace-local traits checkout, if present.
    let local_dir = PathBuf::from("traits");
    if has_traits(&local_dir) {
        tracing::debug!("Using traits from local checkout: {}", local_dir.display());
        return Ok(local_dir);
    }

    // 3. Platform data directory — auto-clone if missing
    let data_dir = default_traits_dir();
    if has_traits(&data_dir) {
        tracing::debug!("Using traits from data directory: {}", data_dir.display());
        check_staleness(&data_dir);
        return Ok(data_dir);
    }
    if let Err(e) = clone_repo(&data_dir) {
        return Err(format!(
            "Failed to clone traits repository: {e}\n\nEnsure 'git' is installed, or manually clone:\n  git clone --depth 1 {TRAITS_REPO_URL} \"{}\"",
            data_dir.display()
        ));
    }
    Ok(data_dir)
}

/// Resolve the traits directory without auto-cloning or process::exit.
///
/// Same resolution order as `resolve_and_ensure()` but returns an error
/// instead of exiting. Used by hot-reload paths where killing the server
/// on a bad traits path is unacceptable.
#[allow(dead_code)] // Used by library target (shared_resources reload)
pub fn try_resolve() -> Result<PathBuf, String> {
    if let Some(explicit) = explicit_traits_dir() {
        let p = PathBuf::from(&explicit);
        if p.is_dir() || p.is_file() {
            return Ok(p);
        }
        return Err(format!("traits dir override {explicit} does not exist"));
    }

    let local_dir = PathBuf::from("traits");
    if has_traits(&local_dir) {
        return Ok(local_dir);
    }

    let data_dir = default_traits_dir();
    if has_traits(&data_dir) {
        return Ok(data_dir);
    }

    Err(format!(
        "Traits not found at {} (run 'cleave update-rules' to install)",
        data_dir.display()
    ))
}

/// Platform-specific data directory for cleave traits.
fn default_traits_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cleave")
        .join("traits")
}

/// Check if a directory looks like a valid traits checkout.
fn has_traits(path: &Path) -> bool {
    // Must exist and contain at least one of the expected subdirectories
    path.is_dir()
        && (path.join("objectives").is_dir()
            || path.join("micro-behaviors").is_dir()
            || path.join("metadata").is_dir())
}

/// Clone the traits repo into the target directory.
fn clone_repo(target: &Path) -> std::io::Result<()> {
    check_git_available()?;

    // Ensure parent directory exists
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let output = Command::new("git")
        .args(["clone", "--depth", "1", TRAITS_REPO_URL])
        .arg(target)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(stderr.to_string()));
    }
    Ok(())
}

/// Update the traits repo (git pull or force reset).
#[allow(dead_code)] // Used by binary target
pub fn update(force: bool) -> Result<(), String> {
    let traits_dir = resolve_current_traits_dir();

    if !traits_dir.exists() || !is_git_repo(&traits_dir) {
        eprintln!(
            "Traits not found at {}. Cloning from {TRAITS_REPO_URL}...",
            traits_dir.display()
        );
        clone_repo(&traits_dir).map_err(|e| {
            format!(
                "Failed to clone traits repository: {e}\n\nEnsure 'git' is installed, or manually clone:\n  git clone --depth 1 {TRAITS_REPO_URL} \"{}\"",
                traits_dir.display()
            )
        })?;
        eprintln!("Traits installed to {}", traits_dir.display());
        return Ok(());
    }

    let before = short_head(&traits_dir).unwrap_or_default();

    let output = if force {
        eprintln!("Force-updating traits from upstream...");
        let fetch = Command::new("git")
            .args(["-C", &traits_dir.to_string_lossy(), "fetch", "origin"])
            .output()
            .map_err(|e| format!("git fetch failed: {e}"))?;
        if !fetch.status.success() {
            return Err(format!(
                "git fetch failed: {}",
                String::from_utf8_lossy(&fetch.stderr)
            ));
        }
        Command::new("git")
            .args([
                "-C",
                &traits_dir.to_string_lossy(),
                "reset",
                "--hard",
                "origin/HEAD",
            ])
            .output()
            .map_err(|e| format!("git reset failed: {e}"))?
    } else {
        eprintln!("Updating traits...");
        Command::new("git")
            .args(["-C", &traits_dir.to_string_lossy(), "pull", "--ff-only"])
            .output()
            .map_err(|e| format!("git pull failed: {e}"))?
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Update failed: {stderr}"));
    }

    let after = short_head(&traits_dir).unwrap_or_default();
    if before == after {
        eprintln!("Already up to date ({after}).");
    } else {
        eprintln!("Updated: {before} -> {after}");
        // Show summary of changes
        if let Ok(diff_output) = Command::new("git")
            .args([
                "-C",
                &traits_dir.to_string_lossy(),
                "diff",
                "--stat",
                &format!("{before}..{after}"),
            ])
            .output()
            && diff_output.status.success()
        {
            let summary = String::from_utf8_lossy(&diff_output.stdout);
            if !summary.is_empty() {
                eprint!("{summary}");
            }
        }
    }
    Ok(())
}

/// Check for updates without applying them.
#[allow(dead_code)] // Used by binary target
pub fn check_updates() -> Result<(), String> {
    let traits_dir = resolve_current_traits_dir();
    if !is_git_repo(&traits_dir) {
        return Err(format!(
            "Traits directory is not a git repository: {}",
            traits_dir.display()
        ));
    }

    let fetch = Command::new("git")
        .args(["-C", &traits_dir.to_string_lossy(), "fetch", "--dry-run"])
        .output()
        .map_err(|e| format!("git fetch failed: {e}"))?;

    let local = short_head(&traits_dir).unwrap_or_default();

    // Check if we're behind
    let status = Command::new("git")
        .args([
            "-C",
            &traits_dir.to_string_lossy(),
            "status",
            "-uno",
            "--porcelain=v2",
            "--branch",
        ])
        .output()
        .map_err(|e| format!("git status failed: {e}"))?;

    if fetch.status.success() {
        let stderr = String::from_utf8_lossy(&fetch.stderr);
        if stderr.trim().is_empty() {
            eprintln!("Traits are up to date ({local}).");
        } else {
            eprintln!("Updates available (current: {local}). Run 'cleave update-rules' to update.");
        }
    }

    // Show age
    if let Some(days) = days_since_last_commit(&traits_dir) {
        eprintln!("Last updated: {days} day(s) ago.");
    }

    let _ = status; // used for the fetch above
    Ok(())
}

/// Pin traits to a specific commit.
#[allow(dead_code)] // Used by binary target
pub fn pin(commit: &str) -> Result<(), String> {
    let traits_dir = resolve_current_traits_dir();
    if !is_git_repo(&traits_dir) {
        return Err(format!(
            "Traits directory is not a git repository: {}",
            traits_dir.display()
        ));
    }

    // Fetch to make sure we have the commit
    let _ = Command::new("git")
        .args(["-C", &traits_dir.to_string_lossy(), "fetch", "origin"])
        .output();

    let output = Command::new("git")
        .args(["-C", &traits_dir.to_string_lossy(), "checkout", commit])
        .output()
        .map_err(|e| format!("git checkout failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to pin to {commit}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    eprintln!("Traits pinned to {commit}.");
    Ok(())
}

/// Get the short commit hash of the current traits HEAD.
#[must_use]
#[allow(dead_code)] // Used by binary target
pub fn version() -> Option<String> {
    let traits_dir = resolve_current_traits_dir();
    short_head(&traits_dir)
}

/// Resolve the traits directory that is currently in use (without auto-cloning).
fn resolve_current_traits_dir() -> PathBuf {
    if let Some(explicit) = explicit_traits_dir() {
        return PathBuf::from(explicit);
    }
    let local_dir = PathBuf::from("traits");
    if has_traits(&local_dir) {
        return local_dir;
    }
    default_traits_dir()
}

/// Print a staleness warning if traits haven't been updated recently.
fn check_staleness(path: &Path) {
    if let Some(days) = days_since_last_commit(path)
        && days > STALENESS_DAYS
    {
        eprintln!(
            "Note: Traits last updated {days} days ago. Run 'cleave update-rules' to refresh."
        );
    }
}

/// Get days since the last git commit in a directory.
fn days_since_last_commit(path: &Path) -> Option<u64> {
    let output = Command::new("git")
        .args(["-C", &path.to_string_lossy(), "log", "-1", "--format=%ct"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let timestamp: i64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;

    let days = (now - timestamp) / 86400;
    Some(days.max(0) as u64)
}

/// Get the short HEAD commit hash.
fn short_head(path: &Path) -> Option<String> {
    let output = Command::new("git")
        .args([
            "-C",
            &path.to_string_lossy(),
            "rev-parse",
            "--short",
            "HEAD",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn is_git_repo(path: &Path) -> bool {
    path.join(".git").exists()
}

fn check_git_available() -> std::io::Result<()> {
    Command::new("git").arg("--version").output().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("git is not installed or not in PATH: {e}"),
        )
    })?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_traits_dir_is_under_cleave() {
        let dir = default_traits_dir();
        assert!(dir.ends_with("cleave/traits"));
    }

    #[test]
    fn test_resolve_current_prefers_override() {
        // Process-wide override; restore on exit so other tests aren't affected.
        let original = override_dir();
        set_override_dir(Some(PathBuf::from("/tmp/test-traits")));
        let result = resolve_current_traits_dir();
        assert_eq!(result, PathBuf::from("/tmp/test-traits"));
        set_override_dir(original);
    }

    #[test]
    fn test_has_traits_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!has_traits(tmp.path()));
    }

    #[test]
    fn test_has_traits_with_objectives() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("objectives")).unwrap();
        assert!(has_traits(tmp.path()));
    }
}
