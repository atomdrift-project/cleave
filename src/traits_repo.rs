//! Locates the traits directory and installs/updates it from the R2 bundle.
//!
//! Traits (detection rules) are distributed as signed `.tar.zst` bundles from
//! the update bucket — see [`crate::rule_update`], which `cleave update-rules`
//! drives. This module only handles *resolution* (where traits live) and the
//! first-run bootstrap install. It performs no git *operations* — but it does
//! read `.git/HEAD` to report a version for a git-managed traits checkout,
//! which carries no bundle sidecar. See [`version`].
//!
//! Resolution order:
//! 1. `--traits-dir` CLI flag / `CLEAVE_TRAITS_DIR` env var / API override
//! 2. Workspace-local `traits/` checkout
//! 3. Platform data directory (bootstrapped from the bundle if missing)

use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

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
///
/// Drops any cached capability mapper, since it was built from the previous
/// directory. Without that, the mapper — a process-wide singleton keyed on
/// nothing — keeps serving the first traits directory any caller happened to
/// load, and every later override is silently ignored: analyses still run, just
/// against the wrong rules. Invalidation is lazy, so calling this before the
/// first analysis (the CLI's `--traits-dir`) costs nothing.
pub fn set_override_dir(dir: Option<PathBuf>) {
    *traits_dir_override_lock()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = dir;
    // Deliberately outside the guard scope: rebuilding a mapper or re-walking
    // the traits tree resolves the traits dir, so holding the override lock
    // across invalidation would invert the lock order against a concurrent build.
    crate::shared_resources::invalidate_capability_mapper();
    // The analysis/YARA cache keys carry a fingerprint of the traits tree. It is
    // memoized per process, so without this a scan after the switch is served
    // from cache under the previous directory's fingerprint.
    crate::cache::invalidate_traits_scan();
}

/// Returns the active override, if any.
#[must_use]
pub fn override_dir() -> Option<PathBuf> {
    traits_dir_override_lock()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Returns the explicit traits dir from override-or-env, if either is set.
fn explicit_traits_dir() -> Option<String> {
    if let Some(p) = override_dir() {
        return Some(p.to_string_lossy().into_owned());
    }
    std::env::var("CLEAVE_TRAITS_DIR").ok()
}

/// Resolve the traits directory, installing from the bundle if necessary.
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

    // 3. Platform data directory — bootstrap-install from the bundle if missing.
    let data_dir = default_traits_dir();
    if has_traits(&data_dir) {
        tracing::debug!("Using traits from data directory: {}", data_dir.display());
        return Ok(data_dir);
    }
    if let Err(e) = crate::rule_update::update(&data_dir, false, false) {
        return Err(format!(
            "Failed to install traits from the update bucket: {e}\n\nRun 'cleave update-rules' to install."
        ));
    }
    Ok(data_dir)
}

/// Resolve the traits directory without bootstrapping or process::exit.
///
/// Same resolution order as `resolve_and_ensure()` but returns an error
/// instead of installing. Used by hot-reload paths where killing the server
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

/// Directory the updater should install into: explicit override, a workspace
/// `traits/` checkout if present, else the platform data dir. Unlike
/// `resolve_current_traits_dir` it's public and doesn't require the dir to exist.
#[allow(dead_code)] // Used by binary target (update-rules)
#[must_use]
pub fn install_target() -> PathBuf {
    if let Some(explicit) = explicit_traits_dir() {
        return PathBuf::from(explicit);
    }
    let local = PathBuf::from("traits");
    if has_traits(&local) {
        return local;
    }
    default_traits_dir()
}

/// Platform-specific data directory for cleave traits.
fn default_traits_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("atomdrift")
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

/// Get the traits commit (short) currently in use.
///
/// Prefers the bundle's sidecar; falls back to the checked-out commit when the
/// traits directory is a git checkout, which has no sidecar because
/// [`crate::rule_update::update`] deliberately refuses to touch a git-managed
/// tree.
///
/// The fallback is not cosmetic. This value becomes `CompactReport::traits_version`,
/// serialized as `rev` and omitted entirely when `None`. Downstream, hopper's
/// `/api/known` reports a stored verdict "current" only when its recorded traits
/// version matches the producer's, and scan skips re-posting exactly those — so a
/// producer that reports no version has that negotiation silently disabled and
/// re-posts every verdict, forever. Returning `None` here is therefore expensive
/// and invisible, which is the worst combination; prefer any true answer.
#[must_use]
#[allow(dead_code)] // Used by binary target
pub fn version() -> Option<String> {
    let traits_dir = resolve_current_traits_dir();
    crate::rule_update::installed(&traits_dir)
        .map(|i| short_commit_prefix(&i.commit))
        .or_else(|| git_head_commit(&traits_dir))
}

/// First 9 chars of a commit hash — the sidecar's own convention, kept for the
/// git fallback so both sources are indistinguishable downstream.
fn short_commit_prefix(commit: &str) -> String {
    commit.chars().take(9).collect()
}

/// Validate and shorten a candidate commit hash read from git's on-disk refs.
fn checked_commit(hash: &str) -> Option<String> {
    let hash = hash.trim();
    (hash.len() >= 9 && hash.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| short_commit_prefix(hash))
}

/// Read the checked-out commit straight from git's on-disk refs.
///
/// Parsed rather than shelled out to `git`: this runs on the report-emit path,
/// cleave takes no git dependency, and a subprocess per report would be absurd.
/// Handles the three shapes that actually occur — a detached HEAD holding a raw
/// hash, a symbolic ref resolved through a loose ref file, and one resolved
/// through `packed-refs` (which is the common case in a freshly cloned tree).
fn git_head_commit(dir: &Path) -> Option<String> {
    let git = dir.join(".git");
    // A worktree or submodule stores `gitdir: <path>` in a .git FILE, not a dir.
    let git_dir = if git.is_file() {
        let text = std::fs::read_to_string(&git).ok()?;
        let target = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
        if target.is_absolute() {
            target
        } else {
            dir.join(target)
        }
    } else {
        git
    };

    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref:") else {
        return checked_commit(head); // detached HEAD
    };
    let reference = reference.trim();

    // A loose ref file wins; git only packs refs it has not since moved.
    if let Ok(text) = std::fs::read_to_string(git_dir.join(reference)) {
        return checked_commit(&text);
    }

    let packed = std::fs::read_to_string(git_dir.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        let line = line.trim();
        // '#' is the header; '^' lines are peeled tag targets, never the ref.
        if line.starts_with('#') || line.starts_with('^') {
            return None;
        }
        let (hash, name) = line.split_once(' ')?;
        if name.trim() != reference {
            return None;
        }
        checked_commit(hash)
    })
}

/// Resolve the traits directory that is currently in use (without bootstrapping).
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_traits_dir_is_under_cleave() {
        let dir = default_traits_dir();
        assert!(dir.ends_with("cleave/traits"));
    }

    /// A git-managed traits checkout must still report a version. It carries no
    /// bundle sidecar (`update` refuses to touch a git tree), and a `None` here
    /// omits `rev` from every emitted report, which silently disables hopper's
    /// `/api/known` currency negotiation and makes producers re-post verdicts
    /// forever. Covers the three on-disk shapes that actually occur.
    #[test]
    fn test_git_head_commit_resolves_every_ref_shape() {
        let hash = "4c8739fad0123456789abcdef0123456789abcde";
        let cases: Vec<(&str, Box<dyn Fn(&Path)>)> = vec![
            (
                "detached HEAD holds the hash directly",
                Box::new(move |git: &Path| {
                    std::fs::write(git.join("HEAD"), format!("{hash}\n")).unwrap();
                }),
            ),
            (
                "symbolic ref via a loose ref file",
                Box::new(move |git: &Path| {
                    std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
                    std::fs::create_dir_all(git.join("refs/heads")).unwrap();
                    std::fs::write(git.join("refs/heads/main"), format!("{hash}\n")).unwrap();
                }),
            ),
            (
                "symbolic ref via packed-refs",
                Box::new(move |git: &Path| {
                    std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
                    std::fs::write(
                        git.join("packed-refs"),
                        format!("# pack-refs with: peeled fully-peeled sorted \n{hash} refs/heads/main\n^{hash}\n"),
                    )
                    .unwrap();
                }),
            ),
        ];

        for (name, setup) in cases {
            let tmp = std::env::temp_dir().join(format!("cleave-traits-{}", std::process::id()));
            let git = tmp.join(".git");
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(&git).unwrap();
            setup(&git);
            assert_eq!(
                git_head_commit(&tmp).as_deref(),
                Some("4c8739fad"),
                "{name}"
            );
            std::fs::remove_dir_all(&tmp).unwrap();
        }
    }

    #[test]
    fn test_git_head_commit_rejects_non_git_and_garbage() {
        let tmp = std::env::temp_dir().join(format!("cleave-nogit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        assert_eq!(git_head_commit(&tmp), None, "no .git at all");

        let git = tmp.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        assert_eq!(git_head_commit(&tmp), None, "ref resolves to nothing");

        // A short or non-hex value must be rejected rather than reported as a
        // version: a bogus `rev` is worse than none, because it would make
        // hopper call an unrelated verdict current.
        std::fs::write(git.join("HEAD"), "not-a-hash\n").unwrap();
        assert_eq!(git_head_commit(&tmp), None, "garbage HEAD");
        std::fs::write(git.join("HEAD"), "abc123\n").unwrap();
        assert_eq!(git_head_commit(&tmp), None, "too short to be a commit");
        std::fs::remove_dir_all(&tmp).unwrap();
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
