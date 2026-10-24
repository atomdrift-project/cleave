//! Locates the traits directory and installs/updates it from the R2 bundle.
//!
//! Traits (detection rules) are distributed as `.tar.zst` bundles from
//! the update bucket — see [`crate::rule_update`], which `cleave update-rules`
//! drives and verifies each bundle against the manifest's SHA-256. This module
//! resolves the active traits directory and bootstraps it.
//! For git-managed checkouts without a bundle sidecar, it reads HEAD and checks
//! for local rule edits so the reported version identifies the loaded rules.
//! See [`version`].
//!
//! Resolution order:
//! 1. `--traits-dir` CLI flag / `CLEAVE_TRAITS_DIR` env var / API override
//! 2. Workspace-local `traits/` checkout
//! 3. Platform data directory (bootstrapped from the bundle if missing)

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{OnceLock, RwLock};

/// Known top-level directories in a traits checkout.
const RULE_SOURCE_DIRS: &[&str] = &[
    "metadata",
    "micro-behaviors",
    "objectives",
    "well-known",
    "third-party",
];

/// Keep rule discovery within the taxonomy, excluding checkout/build artifacts.
/// Explicit rule subtrees and standalone rule directories remain supported.
/// The selected root is admitted even if its name starts with a dot/underscore.
pub(crate) fn is_rule_source_entry(entry: &walkdir::DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_dir() {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    if name.starts_with('.') || name.starts_with('_') || name == "testdata" {
        return false;
    }
    if entry.depth() == 1 && entry.path().parent().is_some_and(has_traits) {
        return RULE_SOURCE_DIRS.contains(&name.as_ref());
    }
    true
}

/// Use the same directory-qualified ID for capability loading and inline YARA.
pub(crate) fn qualify_trait_id(id: &str, prefix: Option<&str>) -> String {
    if let Some(prefix) = prefix
        && !prefix.is_empty()
        && !id.starts_with(prefix)
        && !id.contains("::")
        && !id.contains('/')
    {
        format!("{prefix}::{id}")
    } else {
        id.to_string()
    }
}

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
    explicit_traits_dir_from(override_dir(), std::env::var("CLEAVE_TRAITS_DIR").ok())
}

/// The precedence rule behind [`explicit_traits_dir`], over given inputs: the
/// API override beats `CLEAVE_TRAITS_DIR`. Separate so it can be tested without
/// installing a process-wide override, which drops the global mapper and
/// repoints every concurrently running analysis at the test's directory.
fn explicit_traits_dir_from(override_dir: Option<PathBuf>, env: Option<String>) -> Option<String> {
    override_dir
        .map(|p| p.to_string_lossy().into_owned())
        .or(env)
}

/// Resolve the traits directory, installing from the bundle if necessary.
///
/// Returns the path to a usable traits directory, or an error if traits cannot
/// be obtained.
pub fn resolve_and_ensure() -> Result<PathBuf, String> {
    migrate_legacy_install();
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
    ensure_data_dir()
}

/// The installed tree for this run's rules edition, installing it on first
/// use.
///
/// When a held token alone chose the Enriched tree and it cannot be installed
/// — refused, or offline — the run falls back to the open-source tree rather
/// than scan with no rules at all. Under `--enriched` the failure stands.
fn ensure_data_dir() -> Result<PathBuf, String> {
    let data_dir = default_traits_dir();
    if has_traits(&data_dir) {
        if cfg!(windows)
            && crate::rule_update::installed(&data_dir).is_some_and(|i| !i.packed_rules)
        {
            tracing::warn!(
                dir = %data_dir.display(),
                "this Windows rule install predates packed storage; run `cleave update-rules` to restore rules quarantined by endpoint protection"
            );
        }
        tracing::debug!("Using traits from data directory: {}", data_dir.display());
        return Ok(data_dir);
    }
    match crate::rule_update::update(&data_dir, false, false) {
        Ok(()) => Ok(data_dir),
        Err(e) if crate::enriched::enabled() && !crate::enriched::required() => {
            crate::enriched::fall_back(&e.to_string());
            ensure_data_dir()
        }
        Err(e) => Err(format!(
            "Failed to install traits from the update bucket: {e}\n\nRun 'cleave update-rules' to install."
        )),
    }
}

/// Resolve the traits directory without bootstrapping or process::exit.
///
/// Same resolution order as `resolve_and_ensure()` but returns an error
/// instead of installing. Used by hot-reload paths where exiting the
/// process on a bad traits path is unacceptable.
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
#[must_use]
pub fn install_target() -> PathBuf {
    migrate_legacy_install();
    if let Some(explicit) = explicit_traits_dir() {
        return PathBuf::from(explicit);
    }
    let local = PathBuf::from("traits");
    if has_traits(&local) {
        return local;
    }
    default_traits_dir()
}

/// Where the update bucket's traits are installed for this process: the
/// enriched tree under `--enriched`, the open-source one otherwise.
pub(crate) fn default_traits_dir() -> PathBuf {
    installed_dir(crate::enriched::enabled())
}

/// Where the update bucket installs one channel's traits:
/// `<data>/atomdrift/cleave/traits-oss` or `…/traits-enriched`.
///
/// The two sit side by side so a host can hold both, and so the open-source
/// tree is never overwritten by, or mistaken for, the paid one. The directory
/// name is the channel.
#[must_use]
pub fn installed_dir(enriched: bool) -> PathBuf {
    installed_root().join(if enriched {
        "traits-enriched"
    } else {
        "traits-oss"
    })
}

/// Which rules a process is using, read from the tree it resolved rather than
/// from the flag it was given: `--enriched` with no Enriched tree installed
/// still scans with the open-source one, and `version` should say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edition {
    /// `traits-enriched`: isotope13's rules, the moment they clear QA.
    Enriched,
    /// `traits-oss`: the open-source rules.
    OpenSource,
    /// A checkout or an explicit directory, whatever it holds.
    Checkout(PathBuf),
}

impl Edition {
    /// The edition of the traits directory currently in use.
    #[must_use]
    pub fn current() -> Self {
        Self::of(resolve_current_traits_dir())
    }

    fn of(dir: PathBuf) -> Self {
        match dir.file_name().and_then(|name| name.to_str()) {
            Some("traits-enriched") => Self::Enriched,
            Some("traits-oss") => Self::OpenSource,
            _ => Self::Checkout(dir),
        }
    }

    /// The one-word form, for JSON and logs.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enriched => "enriched",
            Self::OpenSource => "oss",
            Self::Checkout(_) => "checkout",
        }
    }

    /// The form for a terminal: the paid edition in its colours, so a glance
    /// at any tool's `version` says which rules it is on.
    #[must_use]
    pub fn styled(&self) -> String {
        match self {
            Self::Enriched => crate::enriched::brand(),
            other => other.to_string(),
        }
    }
}

impl std::fmt::Display for Edition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Enriched => "isotope13 Enriched",
            Self::OpenSource => "open source",
            Self::Checkout(_) => "checkout",
        })
    }
}

fn installed_root() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("atomdrift")
        .join("cleave")
}

/// Move a `traits/` left by a cleave from before the split to `traits-oss/`,
/// once per process, before anything resolves or installs the default tree.
/// One atomic rename, so a host that is offline right after an upgrade still
/// has rules.
fn migrate_legacy_install() {
    static MIGRATE: std::sync::Once = std::sync::Once::new();
    MIGRATE.call_once(|| {
        let root = installed_root();
        migrate_legacy_dir(&root.join("traits"), &root.join("traits-oss"));
    });
}

/// Rename the pre-split `traits/` to `traits-oss/`, unless the new one exists.
///
/// Whatever it is moves: an installed bundle, a checkout, or a symlink to one —
/// a rename moves the link, not its target, so a developer's `traits ->
/// traits-dev` keeps pointing where it did. Leaving a git-managed tree behind
/// would instead strand it and bootstrap a public bundle in its place.
fn migrate_legacy_dir(legacy: &Path, oss: &Path) {
    if std::fs::symlink_metadata(oss).is_ok() || std::fs::symlink_metadata(legacy).is_err() {
        return;
    }
    match std::fs::rename(legacy, oss) {
        Ok(()) => {
            tracing::info!(from = %legacy.display(), to = %oss.display(), "moved installed traits")
        }
        Err(e) => {
            tracing::warn!(from = %legacy.display(), error = %e, "could not move installed traits; reinstalling")
        }
    }
}

/// Check if a directory looks like a valid traits checkout.
fn has_traits(path: &Path) -> bool {
    // Must exist and contain at least one of the expected subdirectories
    path.is_dir() && RULE_SOURCE_DIRS.iter().any(|name| path.join(name).is_dir())
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
pub fn version() -> Option<String> {
    let traits_dir = resolve_current_traits_dir();
    if let Some(installed) = crate::rule_update::installed(&traits_dir) {
        return Some(short_commit_prefix(&installed.commit));
    }
    let head = git_head_commit(&traits_dir)?;
    let rules_digest = crate::cache::traits_content_for(&traits_dir).rules;
    if git_rule_tree_dirty_cached(&traits_dir, &head, rules_digest) {
        // A checkout can load changed rules while HEAD still names the old
        // rules. Hopper uses this revision as a dedupe key, so a dirty tree
        // needs a content-derived version distinct from every commit prefix.
        Some(format!("w{}", hex::encode(&rules_digest[..8])))
    } else {
        Some(head)
    }
}

type GitDirtyCache = (PathBuf, String, [u8; 32], bool);
static GIT_DIRTY_CACHE: OnceLock<RwLock<Option<GitDirtyCache>>> = OnceLock::new();

fn git_rule_tree_dirty_cached(dir: &Path, head: &str, rules_digest: [u8; 32]) -> bool {
    let cache = GIT_DIRTY_CACHE.get_or_init(|| RwLock::new(None));
    {
        let guard = cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached_dir, cached_head, cached_digest, dirty)) = guard.as_ref()
            && cached_dir == dir
            && cached_head == head
            && *cached_digest == rules_digest
        {
            return *dirty;
        }
    }
    let dirty = git_rule_tree_dirty(dir);
    *cache
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some((dir.to_path_buf(), head.to_string(), rules_digest, dirty));
    dirty
}

/// Target this checkout even when invoked from another repository's Git hook.
/// `git -C` changes directory but does not override inherited repository paths,
/// notably the parent's GIT_INDEX_FILE (which may name its commit index.lock).
fn git_command_in(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir);
    for name in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_IMPLICIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_GRAFT_FILE",
        "GIT_SHALLOW_FILE",
        "GIT_REPLACE_REF_BASE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_PREFIX",
    ] {
        command.env_remove(name);
    }
    command
}

fn git_rule_tree_dirty(dir: &Path) -> bool {
    let result = git_command_in(dir)
        // Global excludes are a user convenience for working-tree status, but
        // they must not hide rule files from the version check. Cleave can load
        // an ignored YAML file just like any other rule source, so a global
        // `*.yaml` ignore would otherwise make the reported revision stale.
        .arg("-c")
        .arg(format!(
            "core.excludesFile={}",
            if cfg!(windows) { "NUL" } else { "/dev/null" }
        ))
        .args(["status", "--porcelain=v1", "--untracked-files=normal", "--"])
        .args(RULE_SOURCE_DIRS.iter().copied())
        .output();
    // libtest captures this output and nextest shows it when a test fails.
    // Keep the original status result: rerunning Git after an assertion could
    // hide a transient subprocess failure.
    #[cfg(test)]
    match &result {
        Ok(output) => eprintln!(
            "git rule status in {}: {}\nstdout: {}\nstderr: {}",
            dir.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => eprintln!(
            "git rule status in {} could not run: {error}",
            dir.display()
        ),
    }
    // If Git is unavailable, a content version is safer than declaring a
    // potentially edited checkout equivalent to the recorded commit.
    !matches!(result, Ok(output) if output.status.success() && output.stdout.is_empty())
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
    resolve_current_traits_dir_from(explicit_traits_dir())
}

fn resolve_current_traits_dir_from(explicit: Option<String>) -> PathBuf {
    if let Some(explicit) = explicit {
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
    fn the_edition_is_the_name_of_the_tree_in_use() {
        assert_eq!(Edition::of(installed_dir(true)), Edition::Enriched);
        assert_eq!(Edition::of(installed_dir(false)), Edition::OpenSource);
        let checkout = PathBuf::from("/src/traits");
        assert_eq!(Edition::of(checkout.clone()), Edition::Checkout(checkout));
        assert_eq!(Edition::Enriched.as_str(), "enriched");
        assert_eq!(Edition::OpenSource.to_string(), "open source");
    }

    #[test]
    fn a_pre_split_install_becomes_the_oss_tree_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (legacy, oss) = (tmp.path().join("traits"), tmp.path().join("traits-oss"));
        std::fs::create_dir_all(legacy.join("objectives")).unwrap();
        migrate_legacy_dir(&legacy, &oss);
        assert!(oss.join("objectives").is_dir());
        assert!(!legacy.exists());

        // An existing traits-oss is never replaced by a stale traits/.
        std::fs::create_dir_all(legacy.join("stale")).unwrap();
        migrate_legacy_dir(&legacy, &oss);
        assert!(legacy.join("stale").is_dir());
        assert!(!oss.join("stale").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_pre_split_symlink_moves_and_keeps_its_target() {
        let tmp = tempfile::tempdir().unwrap();
        let checkout = tmp.path().join("traits-dev");
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        std::fs::create_dir_all(checkout.join("objectives")).unwrap();
        let (legacy, oss) = (tmp.path().join("traits"), tmp.path().join("traits-oss"));
        std::os::unix::fs::symlink(&checkout, &legacy).unwrap();

        migrate_legacy_dir(&legacy, &oss);
        assert_eq!(
            std::fs::read_link(&oss).unwrap(),
            checkout,
            "the link moved, not its target"
        );
        assert!(std::fs::symlink_metadata(&legacy).is_err());
        assert!(
            checkout.join("objectives").is_dir(),
            "the checkout is untouched"
        );
    }

    #[test]
    fn git_rule_tree_dirty_tracks_only_rule_sources() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // Keep user or system Git settings (for example commit.gpgsign or a
        // custom init template) from changing this scratch repository's setup.
        let git_config = dir.join("empty-git-config");
        std::fs::write(&git_config, "").unwrap();
        let git_template = dir.join("empty-git-template");
        std::fs::create_dir(&git_template).unwrap();
        eprintln!("temporary rule repository: {}", dir.display());
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_COUNT",
        ] {
            if let Some(value) = std::env::var_os(name) {
                eprintln!("{name}={value:?}");
            }
        }
        let run = |args: &[&str]| {
            let output = git_command_in(dir)
                .env("GIT_CONFIG_GLOBAL", &git_config)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_TEMPLATE_DIR", &git_template)
                .args(args)
                .output()
                .map_err(|error| {
                    format!("could not run git -C {} {args:?}: {error}", dir.display())
                })
                .unwrap();
            assert!(
                output.status.success(),
                "git -C {} {args:?} failed: {}\nstdout: {}\nstderr: {}",
                dir.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&["init", "-q"]);
        std::fs::create_dir(dir.join("metadata")).unwrap();
        std::fs::write(dir.join("metadata/base.yaml"), "old\n").unwrap();
        run(&["add", "metadata/base.yaml"]);
        run(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "base",
        ]);
        assert!(
            !git_rule_tree_dirty(dir),
            "freshly committed rule sources should be clean"
        );

        std::fs::write(dir.join("README.md"), "unrelated\n").unwrap();
        assert!(
            !git_rule_tree_dirty(dir),
            "an unrelated README should not mark rule sources dirty"
        );
        std::fs::write(dir.join("metadata/base.yaml"), "edited\n").unwrap();
        assert!(
            git_rule_tree_dirty(dir),
            "editing a tracked rule should mark rule sources dirty"
        );
        run(&["checkout", "--", "metadata/base.yaml"]);
        std::fs::write(dir.join("metadata/new.yaml"), "new\n").unwrap();
        assert!(
            git_rule_tree_dirty(dir),
            "adding an untracked rule should mark rule sources dirty"
        );
    }

    #[test]
    fn git_rule_tree_dirty_ignores_parent_repository_environment() {
        let tmp = tempfile::tempdir().unwrap();
        let index = tmp.path().join("index.lock");
        let sentinel = b"parent commit index must remain untouched\n";
        std::fs::write(&index, sentinel).unwrap();

        // Exercise both fixture setup and production status checks in a child
        // process, without changing the environment of concurrent tests.
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "traits_repo::tests::git_rule_tree_dirty_tracks_only_rule_sources",
                "--nocapture",
            ])
            .env("GIT_INDEX_FILE", &index)
            .env("GIT_DIR", tmp.path().join("foreign.git"))
            .env("GIT_COMMON_DIR", tmp.path().join("foreign.git"))
            .env("GIT_WORK_TREE", tmp.path())
            .env("GIT_OBJECT_DIRECTORY", tmp.path().join("foreign-objects"))
            .env(
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                tmp.path().join("foreign-alternates"),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "rule repository checks failed with an inherited Git environment: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&index).unwrap(), sentinel);
    }

    #[test]
    fn test_default_traits_dir_is_under_cleave() {
        assert!(installed_dir(false).ends_with("atomdrift/cleave/traits-oss"));
        assert!(installed_dir(true).ends_with("atomdrift/cleave/traits-enriched"));
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
        // Exercised through the pure precedence helpers, not `set_override_dir`:
        // that setter is process-wide and drops the global capability mapper,
        // so while this test held it every analysis running on another test
        // thread rebuilt its mapper from `/tmp/test-traits` (and failed with
        // "traits dir override ... does not exist").
        let explicit = explicit_traits_dir_from(
            Some(PathBuf::from("/tmp/test-traits")),
            Some("/tmp/env-traits".to_string()),
        );
        assert_eq!(explicit.as_deref(), Some("/tmp/test-traits"));
        assert_eq!(
            explicit_traits_dir_from(None, Some("/tmp/env-traits".to_string())).as_deref(),
            Some("/tmp/env-traits")
        );
        assert_eq!(
            resolve_current_traits_dir_from(explicit),
            PathBuf::from("/tmp/test-traits")
        );
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod rule_source_tests {
    #[test]
    fn rule_discovery_is_limited_to_known_tiers_in_a_traits_checkout() {
        let root = tempfile::tempdir().unwrap();
        for name in super::RULE_SOURCE_DIRS.iter().copied().chain([
            "testdata",
            "samples",
            "scripts",
            "taxonomy-migration",
            "triage-reports",
            "unexpected",
            ".scratch",
            "_scratch",
            "metadata/nested",
            "metadata/.scratch",
            "metadata/_scratch",
        ]) {
            std::fs::create_dir_all(root.path().join(name)).unwrap();
            std::fs::write(root.path().join(name).join("control.yaml"), "driver: test").unwrap();
        }
        let admitted: std::collections::HashSet<_> = walkdir::WalkDir::new(root.path())
            .into_iter()
            .filter_entry(super::is_rule_source_entry)
            .map(Result::unwrap)
            .filter(|e| e.file_type().is_file())
            .map(walkdir::DirEntry::into_path)
            .collect();
        let mut expected: std::collections::HashSet<_> = super::RULE_SOURCE_DIRS
            .iter()
            .map(|name| root.path().join(name).join("control.yaml"))
            .collect();
        expected.insert(root.path().join("metadata/nested/control.yaml"));
        assert_eq!(admitted, expected);
    }

    #[test]
    fn explicitly_selected_rule_subtrees_are_not_restricted_to_tier_names() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(".rules");
        std::fs::create_dir_all(dir.join("arbitrary/category")).unwrap();
        std::fs::write(dir.join("arbitrary/category/control.yaml"), "driver: test").unwrap();
        let admitted: Vec<_> = walkdir::WalkDir::new(&dir)
            .into_iter()
            .filter_entry(super::is_rule_source_entry)
            .map(Result::unwrap)
            .filter(|e| e.file_type().is_file())
            .map(walkdir::DirEntry::into_path)
            .collect();
        assert_eq!(admitted, [dir.join("arbitrary/category/control.yaml")]);
    }
}
