//! Filesystem caching for analysis results.
//!
//! This module provides caching functionality to avoid re-analyzing unchanged files.
//! Caches are stored in OS-appropriate directories:
//! - macOS: `~/Library/Caches/cleave/`
//! - Linux: `~/.cache/cleave/`
//! - Windows: `%LOCALAPPDATA%\cleave\`
//!
//! # Cache Types
//!
//! - compiled-rule caches (`yara-rules-*.bin`, `capability-mapper-*.bin`)
//! - the SQLite analysis-report cache (`crate::analysis_cache`)
//!
//! Binary recovery results are cached by filefacts (`filefacts::cache`),
//! not here; `maintain_filefacts_cache` deletes the obsolete `re/` tree.
//!
//! # Cleanup
//!
//! Versioned compiled-rule caches are pruned automatically when a new version
//! is written. The filefacts cache (old schema versions, build-orphaned
//! entries) is maintained at startup via `maintain_filefacts_cache`.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI8, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use walkdir::WalkDir;

/// Process-wide override for the analysis-cache skip flag.
///
/// 0 = unset (defer to env var / debug default), 1 = force skip,
/// -1 = force enable. Lets library callers (and the validate command) override
/// the cache without mutating process environment.
static SKIP_CACHE_OVERRIDE: AtomicI8 = AtomicI8::new(0);
static SKIP_YARA_CACHE_OVERRIDE: AtomicI8 = AtomicI8::new(0);

fn decode_override(atom: &AtomicI8) -> Option<bool> {
    match atom.load(Ordering::Relaxed) {
        1 => Some(true),
        -1 => Some(false),
        _ => None,
    }
}

fn store_override(atom: &AtomicI8, value: Option<bool>) {
    atom.store(
        match value {
            None => 0,
            Some(true) => 1,
            Some(false) => -1,
        },
        Ordering::Relaxed,
    );
}

/// Force the analysis cache on or off for the rest of the process.
///
/// `Some(true)` skips the cache, `Some(false)` enables it,
/// `None` clears the override.
pub fn set_skip_cache_override(value: Option<bool>) {
    store_override(&SKIP_CACHE_OVERRIDE, value);
}

fn skip_cache_override() -> Option<bool> {
    decode_override(&SKIP_CACHE_OVERRIDE)
}

/// Force the YARA-rule compilation cache on or off for the rest of the process.
pub fn set_skip_yara_cache_override(value: Option<bool>) {
    store_override(&SKIP_YARA_CACHE_OVERRIDE, value);
}

/// Returns `true` if the analysis-result cache should be skipped.
///
/// Resolution order:
/// 1. Process-wide override set via [`set_skip_cache_override`]
/// 2. `CLEAVE_SKIP_CACHE=1` / `true`  → skip; `=0` / `false` → don't skip
/// 3. Default → don't skip (debug and release behave the same so iteration is predictable)
#[must_use]
pub fn skip_cache() -> bool {
    if let Some(v) = skip_cache_override() {
        return v;
    }
    crate::env::flag("CLEAVE_SKIP_CACHE")
}

/// Returns `true` if the capability-mapper cache should be skipped.
///
/// The mapper cache is keyed on trait-YAML mtime, so it self-invalidates when
/// any trait file changes. It's a pure function of the traits directory and has
/// no dependency on the file being analyzed, and re-parsing a full rule tree
/// costs seconds per process.
///
/// Unlike the analysis cache, this defaults to ENABLED even in debug builds
/// and is NOT skipped by `CLEAVE_SKIP_CACHE` — tests that want fresh per-file
/// analysis still benefit from reusing the compiled trait set.
///
/// Also gates the stat-verified traits-tree index (`indexed_scan`).
///
/// - `CLEAVE_SKIP_MAPPER_CACHE=1` / `true` → skip
/// - Env var unset                         → don't skip (always use the cache)
#[must_use]
pub fn skip_mapper_cache() -> bool {
    crate::env::flag("CLEAVE_SKIP_MAPPER_CACHE")
}

/// Returns `true` if the YARA rule-compilation cache should be skipped.
///
/// The YARA cache is invalidated by YAR-file mtime; re-compiling otherwise
/// costs 4-18 s per process (release → debug). Debug builds DO NOT default
/// to skip (unlike the analysis cache) — skipping would re-pay the compile
/// cost on every `make validate` / quick iteration, and the mtime check
/// already catches rule edits. Set `CLEAVE_SKIP_YARA_CACHE=1` explicitly to
/// force a recompile (useful when editing inline YARA inside YAML).
///
/// - `CLEAVE_SKIP_YARA_CACHE=1` / `true` → skip
/// - `CLEAVE_SKIP_CACHE=1`               → skip (legacy behavior)
/// - Env vars unset                      → don't skip (even in debug)
#[must_use]
pub fn skip_yara_cache() -> bool {
    if let Some(v) = decode_override(&SKIP_YARA_CACHE_OVERRIDE) {
        return v;
    }
    if let Some(v) = crate::env::bool_var("CLEAVE_SKIP_YARA_CACHE") {
        return v;
    }
    skip_cache_override() == Some(true) || crate::env::flag("CLEAVE_SKIP_CACHE")
}

/// Largest value read back from an on-disk cache. Cache files live in a
/// directory other processes may write, so a planted entry must not be able to
/// decompress without bound.
pub(crate) const MAX_CACHED_VALUE_BYTES: u64 = 2 << 30;

/// Decompress a zstd stream read from the cache, failing past
/// [`MAX_CACHED_VALUE_BYTES`].
pub(crate) fn decode_cached_zstd(reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    zstd::stream::read::Decoder::new(reader)?
        .take(MAX_CACHED_VALUE_BYTES + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > MAX_CACHED_VALUE_BYTES {
        return Err(std::io::Error::other("cached value exceeds the size limit"));
    }
    Ok(out)
}

/// Write `bytes` to `path` atomically: a temp file in the same directory
/// (so the final `rename` stays on one filesystem), then an atomic rename.
///
/// Use this instead of `fs::write`/`fs::File::create` for anything under
/// `cache_dir()`: those caches are read by `fs::read`-ing the exact same path
/// from other threads and, in production, from an entirely different
/// concurrently running `cleave` process sharing the directory. A direct
/// in-place write truncates before it writes, so a reader racing it can see a
/// truncated or empty file; a deserializer then either fails loudly (a
/// spurious, expensive rebuild) or — the dangerous case — succeeds against a
/// partial document, silently returning fewer entries than were written.
///
/// The temp name comes from [`tempfile::NamedTempFile`], not a
/// process-ID-suffixed name: multiple threads in the same process can race to
/// rebuild an empty/missing cache concurrently (`CapabilityMapper::try_new`
/// documents this as intentional — "wasteful but correct" for the in-memory
/// build), and a PID alone does not disambiguate threads of that same
/// process, so two of them would step on each other's temp file.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut tmp, bytes)?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Format seconds into a human-readable age string (e.g., "2h 30m", "3d 12h").
#[must_use]
pub fn format_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m {}s", secs / 60, secs % 60),
        3600..=86399 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d {}h", secs / 86400, (secs % 86400) / 3600),
    }
}

/// Get the cache directory for cleave
/// Returns OS-appropriate cache directory:
/// - macOS: ~/Library/Caches/atomdrift/cleave
/// - Linux: ~/.cache/atomdrift/cleave
/// - Windows: %LOCALAPPDATA%\atomdrift\cleave
///
/// `CLEAVE_CACHE_DIR` overrides this unconditionally (an explicit ops/test
/// escape hatch, mirroring `CLEAVE_TRAITS_DIR`). Absent that, a `cfg(test)`
/// build defaults to an isolated directory outside the real cache tree — see
/// `test_cache_dir` — so `cargo test` never shares the on-disk SQLite
/// analysis cache, the compiled-mapper cache, or the compiled-YARA cache
/// with a concurrently running production `cleave` process. Sharing that
/// tree with a live instance is not just non-deterministic (a lookup can
/// race a concurrent writer of *unrelated* content), it is unsafe: a
/// transient open failure under heavy multi-process contention is treated as
/// "database corrupt" and recovered by deleting the file — which would
/// delete the *other* process's cache out from under it.
pub fn cache_dir() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("CLEAVE_CACHE_DIR") {
        let cache_path = PathBuf::from(explicit);
        create_private_dir(&cache_path)
            .with_context(|| format!("using CLEAVE_CACHE_DIR at {}", cache_path.display()))?;
        return Ok(cache_path);
    }

    #[cfg(test)]
    {
        Ok(test_cache_dir())
    }

    #[cfg(not(test))]
    {
        let Some(base_cache) = dirs::cache_dir() else {
            anyhow::bail!("Failed to resolve user cache directory");
        };
        let cache_path = base_cache.join("atomdrift").join("cleave");
        create_private_dir(&cache_path)
            .with_context(|| format!("using cache directory {}", cache_path.display()))?;
        let probe = cache_path.join(".write-test");
        fs::write(&probe, b"ok")
            .with_context(|| format!("cache directory {} is not writable", cache_path.display()))?;
        let _ = fs::remove_file(probe);
        Ok(cache_path)
    }
}

/// Create `path` if needed and confirm only the current user can write it.
///
/// The cache holds compiled YARA rules, which are native code, and a marker
/// that lets trait loading skip validation. A directory another user can write
/// would let them plant either, so such a directory is refused rather than used.
fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        let meta = fs::metadata(path)?;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        if meta.uid() != uid {
            anyhow::bail!("owned by uid {}, not the current user ({uid})", meta.uid());
        }
        if meta.mode() & 0o022 != 0 {
            anyhow::bail!("writable by other users (mode {:o})", meta.mode() & 0o777);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
        Ok(())
    }
}

/// Isolated cache directory for `cargo test` runs: a fixed path outside the
/// real `~/.cache/atomdrift/cleave` tree, so test runs never read or write
/// the same SQLite analysis-cache DB or compiled-rule caches a real,
/// concurrently running `cleave` process is using.
///
/// Deliberately a *stable* path (not one randomized or PID-scoped per
/// process) rather than a fresh `tempfile::TempDir`: the compiled-mapper and
/// compiled-YARA caches this backs are expensive to rebuild (10s+ parsing
/// ~6500 trait YAMLs, 4-18s compiling YARA rules) and are meant to persist
/// *across* separate `cargo test` invocations, the same way the production
/// cache does — only isolated from it. `TempDir`'s own cleanup would not run
/// here anyway (this is a `static`, never dropped), so nothing is lost by
/// using a plain path.
#[cfg(test)]
fn test_cache_dir() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join("cleave-test-cache");
        let _ = fs::create_dir_all(&dir);
        dir
    })
    .clone()
}

/// Returns the traits directory path from override, env var, or platform data dir.
/// Does NOT auto-clone — use `traits_repo::resolve_and_ensure()` for that.
#[must_use]
pub fn traits_path() -> PathBuf {
    if let Some(explicit) = crate::traits_repo::override_dir() {
        return explicit;
    }
    if let Ok(explicit) = std::env::var("CLEAVE_TRAITS_DIR") {
        return PathBuf::from(explicit);
    }
    crate::traits_repo::default_traits_dir()
}

/// Returns the third-party YARA rules directory (`third-party/` inside the traits directory).
#[must_use]
pub fn third_party_path() -> PathBuf {
    traits_path().join("third-party")
}

/// Returns the most recently modified `.yar`/`.yara` file and its mtime.
///
/// Only pure YARA rule files are considered, and only for display: what
/// actually invalidates compiled rules is `rules_source_tag`, which covers
/// inline `type: yara` conditions embedded in trait YAML as well.
pub fn most_recent_yar_file() -> Result<(SystemTime, PathBuf)> {
    traits_scan()
        .newest_yar
        .clone()
        .context("No .yar/.yara files found")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RuleFilesRevision {
    pub newest_mtime: SystemTime,
    pub fingerprint: u64,
}

fn system_time_nanos(t: SystemTime) -> Result<u128> {
    Ok(t.duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid cache timestamp")?
        .as_nanos())
}

/// Bumped whenever the source-tag definition changes, so tags written by an
/// older engine can never collide with one this engine computes. A mismatch is
/// already handled — the compiled rules are ignored and rebuilt — so a bump
/// costs one recompile, while a silent collision would scan with wrong rules.
const SOURCE_TAG_VERSION: u64 = 3;

/// The first eight bytes of the SHA-256 of `parts`, each length-prefixed so
/// adjacent parts cannot run together. Stable across releases and platforms,
/// unlike `DefaultHasher`.
fn digest64(parts: &[&[u8]]) -> u64 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    first_u64(&h.finalize().into())
}

fn first_u64(digest: &[u8; 32]) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(head)
}

/// A stable 64-bit fingerprint of an opaque byte string.
pub(crate) fn digest_bytes(bytes: &[u8]) -> u64 {
    digest64(&[bytes])
}

/// Whether a trait YAML can contribute a rule to the YARA compiler.
///
/// Only `if: {type: yara, ...}` conditions do, and that comparison is against
/// the exact lowercase string, so any contributing file necessarily contains
/// these four bytes — quoted, aliased, or merged in, since YAML resolves all of
/// those within the one file. A superset of the truth, never a subset: a file
/// this rejects cannot reach the compiler, which is exactly what the tag needs.
fn mentions_yara(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|w| w == b"yara")
}

/// SHA-256 of one rule or trait file: its traits-relative path, length and
/// full contents, each length-prefixed.
fn rule_file_digest(traits_dir: &Path, path: &Path, bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let rel = path
        .strip_prefix(traits_dir)
        .unwrap_or(path)
        .as_os_str()
        .as_encoded_bytes();
    let mut h = Sha256::new();
    h.update((rel.len() as u64).to_le_bytes());
    h.update(rel);
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}

/// Read one rule or trait file: its mtime (for display only) and its
/// [`rule_file_digest`]. `None` when it cannot be read, which the loader
/// cannot do either.
fn read_rule_file(traits_dir: &Path, path: &Path) -> Option<(Option<SystemTime>, [u8; 32])> {
    use std::io::Read;

    let mut file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut bytes).ok()?;
    Some((
        metadata.modified().ok(),
        rule_file_digest(traits_dir, path, &bytes),
    ))
}

/// The first eight bytes of a digest, for keys that carry a `u64`.
fn digest_u64(digest: &[u8; 32]) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(head)
}

/// Count of full traits-directory walks this process has performed.
///
/// A warm scan should walk the traits tree exactly once — every cache key reads
/// the memoized [`traits_scan`] bundle. Each walk logs its ordinal, so a second
/// full traversal in one process (a caller that bypassed the bundle, or a cache
/// miss forcing a rebuild) is immediately visible in the logs rather than hiding
/// as unexplained latency.
static TRAITS_WALK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Everything the rule and mapper cache keys need, gathered in a single pass over
/// the traits directory.
///
/// Previously each cache key walked the tree itself — the mapper key over trait
/// YAML, the YARA key over `.yar`/`.yara`, the analysis-cache key over every
/// rule/trait file, plus a stats-display pass — so a warm scan traversed a large
/// traits checkout four times before it could even consult a cache. This bundles
/// all of those into one traversal (see [`scan_traits_dir`]); [`traits_scan_for`]
/// memoizes it for the process.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TraitsScan {
    /// Newest `.yaml`/`.yml` trait file (third-party excluded) and its path.
    newest_yaml: Option<(SystemTime, PathBuf)>,
    /// Revision fingerprint over `.yaml`/`.yml` trait files (third-party excluded),
    /// the mapper cache key.
    yaml_revision: Option<RuleFilesRevision>,
    /// Newest `.yar`/`.yara` rule file (third-party included) and its path.
    newest_yar: Option<(SystemTime, PathBuf)>,
    /// Revision fingerprint over all rule+trait files (`.yar`/`.yara`/`.yaml`/`.yml`,
    /// third-party included), plus the newest mtime across them.
    rule_revision: Option<RuleFilesRevision>,
    /// What [`TraitsContent`] reports for this tree.
    content: TraitsContent,
}

/// Content digests of a traits tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct TraitsContent {
    /// SHA-256 over every rule and trait file's path, length and contents, in
    /// path order: what `rule_revision` truncates.
    pub(crate) rules: [u8; 32],
    /// SHA-256 over the path of every directory, `.git` excluded. Validation
    /// judges directory names as well as files, so a new empty or
    /// non-rule directory changes what it would report; the caches, which
    /// only read rule files, do not key on this.
    pub(crate) layout: [u8; 32],
}

/// Walk the traits directory once, computing every rule/mapper cache input in a
/// single pass.
///
/// Every key it produces is a digest of file *contents*, never of stat data.
/// Stat keys (path, size, mtime) looked cheaper but could not be trusted: `git
/// archive` and checkouts stamp every file with one commit time at one-second
/// resolution, so two trees differing by a same-length edit shared a key and
/// served each other's mapper and analysis results. Reading the rule sources
/// is spread across rayon, and a later process skips it only when
/// [`indexed_scan`] proves, by ctime and inode, that no file has changed since.
///
/// Entries are visited in file-name order, so the digests are a function of
/// the tree alone, not of the filesystem's directory order.
///
/// A pure function of the directory's contents, so a caller that must observe a
/// mid-process edit (the tests, [`traits_content_uncached`]) calls it directly;
/// [`traits_scan_for`] memoizes it for the hot path.
fn scan_traits_dir(traits_dir: &Path) -> TraitsScan {
    let sources = crate::rule_sources::RuleSources::fresh(traits_dir).ok();
    scan_traits_dir_with_sources(traits_dir, sources.as_ref())
}

fn scan_traits_dir_with_sources(
    traits_dir: &Path,
    sources: Option<&crate::rule_sources::RuleSources>,
) -> TraitsScan {
    use rayon::prelude::*;
    use sha2::{Digest, Sha256};

    let ordinal = TRAITS_WALK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let started = Instant::now();

    let mut newest_yaml = SystemTime::UNIX_EPOCH;
    let mut newest_yaml_path = PathBuf::new();
    let mut newest_yar = SystemTime::UNIX_EPOCH;
    let mut newest_yar_path = PathBuf::new();
    let mut newest_rule = SystemTime::UNIX_EPOCH;

    let mut yaml_hasher = Sha256::new();
    let mut rule_hasher = Sha256::new();
    let mut layout_hasher = Sha256::new();
    let mut yaml_count = 0u64;
    let mut rule_count = 0u64;

    // One matching rule/trait file, classified during the (cheap) directory read
    // so the (expensive) read can be parallelized below.
    struct Candidate {
        path: PathBuf,
        is_yaml: bool,
        is_yar: bool,
        third_party: bool,
    }

    // Phase 1 — walk the tree in name order and collect matching files. This is
    // just the directory reads (`readdir`); extension and third-party
    // classification are pure path inspection, so they belong here.
    let mut candidates: Vec<Candidate> = Vec::new();
    if let Some(sources) = sources {
        for relative in sources.directories() {
            let rel = relative.as_os_str().as_encoded_bytes();
            layout_hasher.update((rel.len() as u64).to_le_bytes());
            layout_hasher.update(rel);
        }
        for file in sources.files() {
            let (is_yaml, is_yar) = match file.relative_path.extension().and_then(|e| e.to_str()) {
                Some("yaml" | "yml") => (true, false),
                Some("yar" | "yara") => (false, true),
                _ => continue,
            };
            let path = traits_dir.join(&file.relative_path);
            candidates.push(Candidate {
                third_party: path.components().any(|c| c.as_os_str() == "third-party"),
                path,
                is_yaml,
                is_yar,
            });
        }
    } else if traits_dir.exists() {
        let walker = WalkDir::new(traits_dir)
            .follow_links(true)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(crate::traits_repo::is_rule_source_entry);
        for entry in walker.flatten() {
            // `file_type()` comes from the directory read, no extra stat.
            let path = entry.path();
            if entry.file_type().is_dir() {
                let rel = path.strip_prefix(traits_dir).unwrap_or(path);
                let rel = rel.as_os_str().as_encoded_bytes();
                layout_hasher.update((rel.len() as u64).to_le_bytes());
                layout_hasher.update(rel);
                continue;
            }
            if !entry.file_type().is_file() {
                continue;
            }
            let (is_yaml, is_yar) = match path.extension().and_then(|e| e.to_str()) {
                Some("yaml" | "yml") => (true, false),
                Some("yar" | "yara") => (false, true),
                _ => continue,
            };
            candidates.push(Candidate {
                third_party: path.components().any(|c| c.as_os_str() == "third-party"),
                path: path.to_path_buf(),
                is_yaml,
                is_yar,
            });
        }
    }
    let entries_visited = candidates.len() as u64;

    // Phase 2 — read and digest every candidate at once. This is the bulk of
    // the wall-clock and is pure independent I/O plus hashing, so a parallel
    // map spreads it across the pool. `collect` preserves order, so phase 3
    // still folds deterministically. (Runs inside `traits_scan_for`'s memoized
    // init with no lock held — see there — so this rayon use cannot deadlock.)
    let files: Vec<Option<(Option<SystemTime>, [u8; 32])>> = candidates
        .par_iter()
        .map(|c| match sources {
            Some(sources) => {
                let file = sources.file(c.path.strip_prefix(traits_dir).ok()?)?;
                Some((
                    file.modified,
                    rule_file_digest(traits_dir, &c.path, &file.bytes),
                ))
            }
            None => read_rule_file(traits_dir, &c.path),
        })
        .collect();

    // Phase 3 — fold the per-file digests in walk order.
    let mut files_read = 0u64;
    for (c, file) in candidates.iter().zip(&files) {
        let Some((mtime, digest)) = file else {
            continue;
        };
        files_read += 1;

        // Analysis-cache revision: every rule/trait file, third-party included.
        rule_count += 1;
        rule_hasher.update(digest);
        if let Some(m) = *mtime
            && m > newest_rule
        {
            newest_rule = m;
        }

        if c.is_yar
            && let Some(m) = *mtime
            && m > newest_yar
        {
            newest_yar = m;
            newest_yar_path = c.path.clone();
        }

        // Mapper revision + newest trait YAML: `.yaml`/`.yml`, third-party excluded.
        if c.is_yaml && !c.third_party {
            yaml_count += 1;
            yaml_hasher.update(digest);
            if let Some(m) = *mtime
                && m > newest_yaml
            {
                newest_yaml = m;
                newest_yaml_path = c.path.clone();
            }
        }
    }
    yaml_hasher.update(yaml_count.to_le_bytes());
    rule_hasher.update(rule_count.to_le_bytes());
    let yaml_digest: [u8; 32] = yaml_hasher.finalize().into();
    let rule_digest: [u8; 32] = rule_hasher.finalize().into();

    // Report hashing separately from the snapshot's disk I/O timing.
    let elapsed = started.elapsed();
    tracing::info!(
        walk = ordinal,
        dir = %traits_dir.display(),
        entries = entries_visited,
        reads = if sources.is_some() { 0 } else { files_read },
        shared_files = if sources.is_some() { files_read } else { 0 },
        yaml_files = yaml_count,
        rule_files = rule_count,
        elapsed_ms = elapsed.as_millis(),
        "hashed traits directory"
    );

    TraitsScan {
        newest_yaml: (newest_yaml != SystemTime::UNIX_EPOCH)
            .then_some((newest_yaml, newest_yaml_path)),
        yaml_revision: (yaml_count > 0).then(|| RuleFilesRevision {
            newest_mtime: newest_yaml,
            fingerprint: digest_u64(&yaml_digest),
        }),
        newest_yar: (newest_yar != SystemTime::UNIX_EPOCH).then_some((newest_yar, newest_yar_path)),
        rule_revision: (rule_count > 0).then(|| RuleFilesRevision {
            newest_mtime: newest_rule,
            fingerprint: digest_u64(&rule_digest),
        }),
        content: TraitsContent {
            rules: rule_digest,
            layout: layout_hasher.finalize().into(),
        },
    }
}

/// Machine-portable fingerprint of the YARA rule sources — every `.yar`/`.yara`
/// plus the trait YAML carrying an inline `type: yara` rule, hashed by
/// traits-relative path and contents, no mtimes — or `None` when the traits
/// directory holds none.
///
/// This runs on every rule load, so the result is memoized on disk against the
/// [`scan_traits_dir`] content fingerprint of every rule and trait file. An
/// unchanged tree therefore reads one short file instead of re-deriving the
/// tag; any edit misses the memo and re-reads.
///
/// That memo is for *loading* only. Anything that stamps a tag into an artifact
/// others will trust — [`rules_source_tag_uncached`] — hashes the bytes every
/// time, so a shipped fingerprint is never one inherited from mtimes.
pub(crate) fn rules_source_tag() -> Option<u64> {
    let traits_dir = traits_path();
    if skip_yara_cache() {
        return compute_shared_rules_source_tag(&traits_dir);
    }
    let revision = traits_scan().rule_revision?;
    if let Some(tag) = memoized_source_tag(&traits_dir, revision) {
        return Some(tag);
    }
    let tag = compute_shared_rules_source_tag(&traits_dir)?;
    store_source_tag(&traits_dir, revision, tag);
    Some(tag)
}

fn compute_shared_rules_source_tag(traits_dir: &Path) -> Option<u64> {
    let sources = crate::rule_sources::shared(traits_dir).ok()?;
    source_tag_from_snapshot(traits_dir, &sources)
}

pub(crate) fn source_tag_from_snapshot(
    traits_dir: &Path,
    sources: &crate::rule_sources::RuleSources,
) -> Option<u64> {
    use rayon::prelude::*;
    let started = Instant::now();
    let mut digests: Vec<u64> = sources
        .files()
        .par_iter()
        .filter_map(|file| {
            let is_yar = match file.relative_path.extension().and_then(|e| e.to_str()) {
                Some("yar" | "yara") => true,
                Some("yaml" | "yml") => false,
                _ => return None,
            };
            (is_yar || mentions_yara(&file.bytes)).then(|| {
                first_u64(&rule_file_digest(
                    traits_dir,
                    &traits_dir.join(&file.relative_path),
                    &file.bytes,
                ))
            })
        })
        .collect();
    if digests.is_empty() {
        return None;
    }

    // Combine independently of walk order — readdir order differs by filesystem
    // and OS, and this tag has to match across both — but without the
    // cancellation a plain sum invites: sorting makes the fold a function of the
    // digest multiset alone, and the fold itself is order-dependent, so no pair
    // of files can trade contributions unnoticed.
    digests.sort_unstable();
    let digests: Vec<u8> = digests.iter().flat_map(|d| d.to_le_bytes()).collect();
    let tag = digest64(&[&SOURCE_TAG_VERSION.to_le_bytes(), &digests]);
    tracing::debug!(
        dir = %traits_dir.display(),
        candidates = sources.files().len(),
        rule_sources = digests.len(),
        elapsed_ms = started.elapsed().as_millis(),
        tag = %format!("{tag:016x}"),
        "hashed YARA rule sources"
    );
    Some(tag)
}

/// Per-directory memo pairing a content fingerprint with the source tag
/// computed under it. One file per traits directory: a single shared entry
/// thrashed whenever two trees alternated (a checkout and a symlink to it, or
/// a test's temporary traits), and every miss re-reads all rule text.
fn source_tag_memo_path(traits_dir: &Path) -> Option<PathBuf> {
    let tag = digest_bytes(traits_dir.as_os_str().as_encoded_bytes());
    Some(
        cache_dir()
            .ok()?
            .join(format!("yara-source-tag-{tag:016x}")),
    )
}

/// The stored tag, if it was computed for this traits directory at exactly this
/// content fingerprint. The file name already names the directory; the stored
/// directory digest guards against a hash collision in that name.
fn memoized_source_tag(traits_dir: &Path, revision: RuleFilesRevision) -> Option<u64> {
    let text = fs::read_to_string(source_tag_memo_path(traits_dir)?).ok()?;
    let mut fields = text.split_whitespace();
    let dir = fields.next()?;
    let stat = fields.next()?;
    let tag = fields.next()?;
    if dir
        != format!(
            "{:016x}",
            digest_bytes(traits_dir.as_os_str().as_encoded_bytes())
        )
        || stat != format!("{:016x}", revision.fingerprint)
    {
        return None;
    }
    u64::from_str_radix(tag, 16).ok()
}

/// Record `tag` as the content tag for this traits directory at `revision`.
/// Best effort: a memo that fails to write only costs the next run a re-hash.
fn store_source_tag(traits_dir: &Path, revision: RuleFilesRevision, tag: u64) {
    let Some(path) = source_tag_memo_path(traits_dir) else {
        return;
    };
    let dir = digest_bytes(traits_dir.as_os_str().as_encoded_bytes());
    let line = format!("{dir:016x} {:016x} {tag:016x}\n", revision.fingerprint);
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).is_err()
    {
        return;
    }
    if let Err(e) = atomic_write(&path, line.as_bytes()) {
        tracing::debug!(path = %path.display(), error = %e, "could not save the YARA source-tag memo");
    }
}

/// The memoized traits-directory scans, one per traits directory this process
/// has keyed a cache on, newest last. Emptied by [`invalidate_traits_scan`].
static TRAITS_SCANS: parking_lot::RwLock<Vec<(PathBuf, Arc<TraitsScan>)>> =
    parking_lot::RwLock::new(Vec::new());

/// Most directories [`TRAITS_SCANS`] remembers. A process scans against one
/// traits tree; a long-lived one that loads several keeps only the recent.
const MAX_TRAITS_SCANS: usize = 8;

/// Memoized cache timestamp derived from the [`traits_path`] scan.
static CACHE_TIMESTAMP: parking_lot::RwLock<Option<SystemTime>> = parking_lot::RwLock::new(None);

/// Memoized [`traits_revision_fingerprint`] for the [`traits_path`] tree.
static TRAITS_REVISION: parking_lot::RwLock<Option<i64>> = parking_lot::RwLock::new(None);

/// Drop the memoized traits scans, and the cache keys derived from them, so
/// the next lookup re-reads the tree.
///
/// Called when the traits source changes (see [`crate::traits_repo::set_override_dir`]
/// and [`crate::shared_resources::reload_capability_mapper`]). Every cache key —
/// analysis, mapper, YARA — derives from these, so a stale one means a
/// re-scan after a rule update is served from cache under the *old* rules'
/// fingerprint and the update silently doesn't take effect.
pub(crate) fn invalidate_traits_scan() {
    crate::rule_sources::invalidate();
    TRAITS_SCANS.write().clear();
    *CACHE_TIMESTAMP.write() = None;
    *TRAITS_REVISION.write() = None;
}

/// The memoized scan of `traits_dir`.
///
/// Every cache key derives from this one traversal, so it is read once per
/// directory and reused. It stays valid until the traits source changes, which
/// is what [`invalidate_traits_scan`] signals; a caller that must observe an
/// arbitrary mid-process edit calls [`scan_traits_dir`] directly.
///
/// Keyed by the directory actually being loaded, not by [`traits_path`]: a
/// mapper loaded from one tree under keys derived from another would be cached,
/// and served, as the other.
///
/// Built with no lock held. [`scan_traits_dir`] reads files with rayon, and a
/// rayon worker can steal an unrelated analysis task that re-enters here, so any
/// lock held across the build would deadlock against itself. Concurrent first
/// callers may each build a copy; the first writer wins and the rest are dropped.
fn traits_scan_for(traits_dir: &Path) -> Arc<TraitsScan> {
    let key = fs::canonicalize(traits_dir).unwrap_or_else(|_| traits_dir.to_path_buf());
    // Scoped so the read guard is released before the build below, which
    // re-enters this function through rayon.
    {
        if let Some((_, scan)) = TRAITS_SCANS.read().iter().find(|(dir, _)| *dir == key) {
            return Arc::clone(scan);
        }
    }
    let scan = Arc::new(indexed_scan(traits_dir, &key).unwrap_or_else(|| {
        let sources = crate::rule_sources::shared(traits_dir).ok();
        let scan = scan_traits_dir_with_sources(traits_dir, sources.as_deref());
        if let Some(stamp) = sources.as_deref().and_then(|s| s.tree_stamp()) {
            store_tree_index(traits_dir, stamp, &scan);
        }
        scan
    }));
    let mut scans = TRAITS_SCANS.write();
    if let Some((_, existing)) = scans.iter().find(|(dir, _)| *dir == key) {
        return Arc::clone(existing);
    }
    if scans.len() >= MAX_TRAITS_SCANS {
        scans.remove(0);
    }
    scans.push((key, Arc::clone(&scan)));
    scan
}

/// Bumped whenever [`TraitsScan`] or the index layout changes shape.
const TREE_INDEX_VERSION: u32 = 1;

/// What a tree index file holds before its [`crate::rule_sources::TreeStamp`].
#[derive(serde::Serialize, serde::Deserialize)]
struct TreeIndexHeader<S> {
    version: u32,
    /// The build that scanned: scanning is code, and new code may scan
    /// differently.
    build: String,
    traits_dir: Vec<u8>,
    scan: S,
}

/// The cached scan of `traits_dir`, one file per directory as given (the
/// scan's paths are built from it, not from `canonical`).
fn tree_index_path(traits_dir: &Path) -> Option<PathBuf> {
    let tag = digest_bytes(traits_dir.as_os_str().as_encoded_bytes());
    Some(cache_dir().ok()?.join(format!("traits-index-{tag:016x}")))
}

/// The scan a previous process stored for `traits_dir`, if the tree under
/// `canonical` provably has not changed since: every directory and rule file
/// still has the stamp it had when the scan read it. Replaces reading
/// every rule file (~0.6 s for 52k files) with a `stat` of each (~30 ms).
///
/// The analysis, mapper and YARA keys all derive from this scan; contents
/// are still read whenever one of those misses, and anything that stamps a
/// tag into an artifact for others ([`rules_source_tag_uncached`]) hashes
/// the bytes regardless.
///
/// Gated like the mapper cache, not the analysis cache: the index is a pure
/// function of the traits tree and every entry is re-verified by stamp, so a
/// stale one can only miss, never change a result. Under `CLEAVE_SKIP_CACHE=1`
/// (`make test`) skipping it made every process read all ~52k rule files, and
/// concurrent test processes serialized on the filesystem doing so.
fn indexed_scan(traits_dir: &Path, canonical: &Path) -> Option<TraitsScan> {
    if skip_mapper_cache() {
        return None;
    }
    read_tree_index(&tree_index_path(traits_dir)?, traits_dir, canonical)
}

fn read_tree_index(path: &Path, traits_dir: &Path, canonical: &Path) -> Option<TraitsScan> {
    let started = Instant::now();
    let bytes = fs::read(path).ok()?;
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    let (header, stamp) = rest.split_at_checked(usize::try_from(u32::from_le_bytes(*len)).ok()?)?;
    let (header, _): (TreeIndexHeader<TraitsScan>, usize) =
        bincode::serde::decode_from_slice(header, bincode::config::standard()).ok()?;
    if header.version != TREE_INDEX_VERSION
        || header.build != crate::traits_fingerprint::binary_identity()
        || header.traits_dir != traits_dir.as_os_str().as_encoded_bytes()
    {
        tracing::debug!(path = %path.display(), "traits index is for another build or directory");
        return None;
    }
    let unchanged = crate::rule_sources::TreeStamp::decode(stamp)?.matches(canonical);
    tracing::info!(dir = %traits_dir.display(), unchanged,
        elapsed_ms = started.elapsed().as_millis(), "checked traits index");
    unchanged.then_some(header.scan)
}

/// Record `scan` as what the tree `stamp` describes. Best effort: an index
/// that fails to write costs the next run a full read.
fn store_tree_index(traits_dir: &Path, stamp: &crate::rule_sources::TreeStamp, scan: &TraitsScan) {
    if skip_mapper_cache() {
        return;
    }
    if let Some(path) = tree_index_path(traits_dir) {
        write_tree_index(&path, traits_dir, stamp, scan);
    }
}

fn write_tree_index(
    path: &Path,
    traits_dir: &Path,
    stamp: &crate::rule_sources::TreeStamp,
    scan: &TraitsScan,
) {
    let header = TreeIndexHeader {
        version: TREE_INDEX_VERSION,
        build: crate::traits_fingerprint::binary_identity().to_string(),
        traits_dir: traits_dir.as_os_str().as_encoded_bytes().to_vec(),
        scan,
    };
    let Ok(header) = bincode::serde::encode_to_vec(&header, bincode::config::standard()) else {
        return; // A path serde cannot spell; the next run reads the tree.
    };
    let Ok(len) = u32::try_from(header.len()) else {
        return;
    };
    let bytes = [&len.to_le_bytes()[..], &header, &stamp.encode()].concat();
    if let Err(error) = atomic_write(path, &bytes) {
        tracing::debug!(path = %path.display(), %error, "could not save the traits index");
    }
}

/// The memoized scan of the process's [`traits_path`].
fn traits_scan() -> Arc<TraitsScan> {
    traits_scan_for(&traits_path())
}

/// Content digests of `traits_dir`, from the memoized scan.
#[must_use]
pub(crate) fn traits_content_for(traits_dir: &Path) -> TraitsContent {
    traits_scan_for(traits_dir).content
}

/// Content digests of `traits_dir` as it stands now, bypassing the memo.
#[must_use]
pub(crate) fn traits_content_uncached(traits_dir: &Path) -> TraitsContent {
    scan_traits_dir(traits_dir).content
}

/// Returns the most recently modified `.yaml`/`.yml` trait file and its mtime.
///
/// Excludes the `third-party/` directory (YARA vendor rules, not trait definitions).
/// Used to determine the capability mapper cache key.
pub fn most_recent_yaml_file() -> Result<(SystemTime, PathBuf)> {
    traits_scan()
        .newest_yaml
        .clone()
        .context("No .yaml/.yml files found")
}

/// Returns a content revision fingerprint for the YAML trait files of
/// `traits_dir`.
///
/// This excludes `third-party/` because those files feed the YARA cache, not the
/// trait mapper.
fn trait_yaml_revision_for(traits_dir: &Path) -> Result<RuleFilesRevision> {
    traits_scan_for(traits_dir)
        .yaml_revision
        .context("No .yaml/.yml files found")
}

/// Returns the most recent modification time across all rule and trait files.
///
/// Used by rule-stats display. Prefer `rule_files_revision()` for cache keys.
pub(crate) fn most_recent_yara_mtime() -> Result<SystemTime> {
    traits_scan()
        .rule_revision
        .map(|r| r.newest_mtime)
        .context("No YARA/trait files found")
}

/// Returns the modification time of the cleave binary
pub(crate) fn binary_mtime() -> Result<SystemTime> {
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    let metadata = fs::metadata(&exe_path).context("Failed to read binary metadata")?;

    metadata
        .modified()
        .context("Failed to get binary modification time")
}

/// Returns the appropriate timestamp for cache invalidation.
///
/// Always prefers rule file mtime so that recompiling the binary
/// (`cargo run`) does not invalidate the YARA / mapper caches.
/// Falls back to binary mtime only when no rule files exist at all
/// (true production builds with embedded rules).
pub(crate) fn cache_timestamp() -> Result<SystemTime> {
    let cached = *CACHE_TIMESTAMP.read();
    if let Some(ts) = cached {
        return Ok(ts);
    }
    // Built with no lock held: the underlying traits walk uses rayon, which can
    // steal a task that re-enters here.
    let ts = match most_recent_yara_mtime() {
        Ok(mtime) => mtime,
        Err(_) => binary_mtime()?,
    };
    Ok(*CACHE_TIMESTAMP.write().get_or_insert(ts))
}

/// Content fingerprint of the active traits tree and running analyzer.
///
/// Consumers with their own analysis caches must use this rather than the
/// traits commit: local edits and trees without Git metadata still change
/// the analysis. Includes every rule file and its relative path.
///
/// Shares the source snapshot used by rule loading; hashes once without
/// compiling rules. Memoized until a traits-directory switch or
/// [`crate::reload_capability_mapper`] invalidates the snapshot.
#[must_use]
pub fn traits_revision_fingerprint() -> i64 {
    let cached = *TRAITS_REVISION.read();
    if let Some(revision) = cached {
        return revision;
    }
    // Built with no lock held, as in `cache_timestamp`.
    let revision = traits_revision_fingerprint_for(&traits_path());
    *TRAITS_REVISION.write().get_or_insert(revision)
}

/// The analysis-cache revision fingerprint for the traits in `traits_dir`.
///
/// Mixes the content digest of every rule and trait file with the running
/// build's identity (its ELF build-id, see
/// [`crate::traits_fingerprint::binary_identity`]) so that any change to the
/// rules or to the analyzer code invalidates the analysis cache, and nothing
/// else does: rebuilding identical code, touching files, or checking the same
/// tree out again keeps every entry. Analyzer logic, file type detection, and
/// capability evaluation all live in the binary — when they change, the cached
/// `AnalysisReport` for the same SHA can be stale.
///
/// A `CapabilityMapper` pins this at load and every store keys on that pinned
/// value; only a lookup samples it live.
pub(crate) fn traits_revision_fingerprint_for(traits_dir: &Path) -> i64 {
    use sha2::{Digest, Sha256};

    let mut h = Sha256::new();
    h.update(b"cleave-traits-revision 2\0");
    h.update(traits_scan_for(traits_dir).content.rules);
    h.update(env!("CARGO_PKG_VERSION").as_bytes());
    h.update(b"\0");
    h.update(crate::traits_fingerprint::binary_identity().as_bytes());
    let digest: [u8; 32] = h.finalize().into();
    i64::from_ne_bytes(digest_u64(&digest).to_ne_bytes())
}

/// The YARA compiled-rule cache directory name for the active traits tree.
///
/// Stable across rule updates and cleave upgrades on purpose: what a compiled
/// bucket is valid for is recorded per bucket in the directory's manifest
/// (engine and sources), so an update recompiles only the buckets it changed
/// instead of starting from an empty directory. Distinct trait roots and the
/// third-party setting still get directories of their own.
pub(crate) fn yara_cache_key(third_party_enabled: bool) -> String {
    let suffix = if third_party_enabled {
        "with-3p"
    } else {
        "builtin"
    };
    // v5 keeps per-bucket tags in its manifest. v4 was keyed by the newest
    // `.yar` mtime, so every update started cold; v3 was one all-tiers blob.
    format!("yara-rules-v5-{}-{suffix}", traits_dir_tag(&traits_path()))
}

/// Path to the YARA rules cache *directory* (per-tier compiled rules + manifest).
pub fn yara_cache_path(third_party_enabled: bool) -> Result<PathBuf> {
    let cache_key = yara_cache_key(third_party_enabled);
    Ok(cache_dir()?.join(cache_key))
}

/// Generate a cache key for the capability mapper built from `traits_dir`.
///
/// Keyed on the content fingerprint of the `.yaml`/`.yml` trait files
/// (third-party directory excluded, so YARA-only rule updates do not force a
/// trait mapper rebuild) and on the running build's identity, since the parser
/// and the trait schema live in the binary. Falls back to the binary's mtime
/// when no YAML files exist.
///
/// Also incorporates a short hash of the absolute traits-directory path so that
/// distinct trait roots — `--traits-dir /tmp/A/traits` vs `/tmp/B/traits` — never
/// share a cache file even when their contents match: a mapper records the
/// source paths it was parsed from.
pub(crate) fn mapper_cache_key_for(traits_dir: &Path) -> Result<String> {
    let fingerprint = match trait_yaml_revision_for(traits_dir) {
        Ok(revision) => revision.fingerprint,
        Err(_) => system_time_nanos(binary_mtime()?)? as u64,
    };
    let version = env!("CARGO_PKG_VERSION");
    let dir_tag = traits_dir_tag(traits_dir);
    let build = digest_bytes(crate::traits_fingerprint::binary_identity().as_bytes());

    // v14: each rule line is `[defined_in, rule]`, so a hit restores the
    // source path that evaluation filters on (tiny DOS `.com` allowlists).
    // v13: new `shellcode` file type. Like v10, an older parser stored the
    // unknown `for:` token as a parse error.
    // v12: JSON lines, one rule per line, so a hit parses in parallel; and
    // stored after unreferenced exceptions are dropped.
    // v11: keyed on trait-file contents and the build-id instead of path, size
    // and mtime, which a same-length edit under a restored mtime (every `git
    // archive` of two same-second commits) could not tell apart.
    // v10: new file types (jsp, asp, cfml, mirc, ircii, …) were unknown
    // tokens to the previous parser. That build stored them as parse errors,
    // and a later build replayed the snapshot with those types missing from
    // every `for:` list.
    // v9 adds `encoding:` on `type: text`. A build without the field cannot
    // parse a file that uses it, and records that failure in the snapshot's
    // `parse_errors` -- which a later build replays on every hit, reporting a
    // valid file as unparseable and serving a mapper missing its traits.
    // v8 adds literal/field provenance predicates. Older mapper snapshots
    // must not hide their new matching semantics in same-version builds.
    // v7: bumped after a same-version development build with different
    // CompositeTrait semantics collided on this key and served a stale mapper.
    // The build-id now covers that case; bump this prefix when the key's
    // meaning changes.
    Ok(format!(
        "capability-mapper-v14-{version}-{dir_tag}-{fingerprint:016x}-{build:016x}.bin"
    ))
}

/// Short stable tag for a traits directory, suitable for cache keys. Uses the
/// absolute canonical path to discriminate concurrent processes that each pass
/// `--traits-dir` at distinct locations.
fn traits_dir_tag(traits_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canonical = std::fs::canonicalize(traits_dir).unwrap_or_else(|_| traits_dir.to_path_buf());
    // A stable hash: the tag names files on disk that later builds read back.
    let digest = Sha256::digest(canonical.as_os_str().as_encoded_bytes());
    // 8 hex chars is enough discrimination for a filename component without bloating it.
    hex::encode(&digest[..4])
}

/// Get the path to the capability mapper cache file for the process's
/// [`traits_path`].
pub fn mapper_cache_path() -> Result<PathBuf> {
    mapper_cache_path_for(&traits_path())
}

/// Get the path to the capability mapper cache file for `traits_dir`.
pub(crate) fn mapper_cache_path_for(traits_dir: &Path) -> Result<PathBuf> {
    Ok(cache_dir()?.join(mapper_cache_key_for(traits_dir)?))
}

/// Serializes cold builds of a traits tree's mapper across processes.
///
/// Processes that start together (nextest's one-per-test processes, a fleet
/// of scan workers) all miss a cold mapper cache at once, and each would parse
/// and compile the whole rule tree: N times the CPU and memory of one build,
/// with every one of them finishing late. The holder builds and saves; the
/// others wait here, then load what it saved.
///
/// Lock files are a fixed set of slots, so temporary traits directories cannot
/// leave one each behind; two trees that share a slot only wait on each other.
/// A rayon worker never waits: the holder's build may need that worker's pool,
/// and a worker blocked here could be the one it needs. `None` means build
/// unlocked (no cache directory, a filesystem without locks, or a worker).
pub(crate) fn mapper_build_lock(traits_dir: &Path) -> Option<fs::File> {
    const SLOTS: u64 = 64;
    if rayon::current_thread_index().is_some() {
        return None;
    }
    let slot = digest_bytes(traits_dir_tag(traits_dir).as_bytes()) % SLOTS;
    let path = cache_dir()
        .ok()?
        .join(format!("mapper-build-{slot:02}.lock"));
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .ok()?;
    let started = Instant::now();
    if let Err(error) = file.lock() {
        tracing::debug!(path = %path.display(), %error, "mapper build lock unavailable; building unlocked");
        return None;
    }
    tracing::info!(
        path = %path.display(),
        waited_ms = started.elapsed().as_millis(),
        "holding the mapper build lock"
    );
    Some(file)
}

/// Get the path to the rule stats cache file
pub(crate) fn rule_stats_cache_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join("rule-stats.bin"))
}

/// Save trait and composite counts to stats cache.
/// Called when mapper cache is saved.
pub fn save_rule_stats(trait_count: usize, composite_count: usize) -> Result<()> {
    let path = rule_stats_cache_path()?;
    let timestamp = cache_timestamp()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid timestamp")?
        .as_secs();

    let mut bytes = Vec::with_capacity(24);
    bytes.extend_from_slice(&(trait_count as u64).to_le_bytes());
    bytes.extend_from_slice(&(composite_count as u64).to_le_bytes());
    bytes.extend_from_slice(&timestamp.to_le_bytes());

    atomic_write(&path, &bytes)?;
    Ok(())
}

/// Maintain the filefacts disk cache that owns binary recovery.
///
/// Recovery lives in filefacts, which caches its extraction snapshot
/// (recovered imports/exports/functions/sections included) keyed by
/// `(content, filefacts build, recovery policy)`. cleave relies on that
/// cache instead of the old `re/` tree it kept before the migration.
/// filefacts' `cleanup` prunes superseded schema versions and enforces
/// its item cap (LRU eviction orphans entries left by earlier filefacts
/// builds) on its own background thread. cleave adds a one-shot removal
/// of the now-dead `re/` tree left behind on pre-migration installs.
/// Best-effort; runs in the background.
pub(crate) fn maintain_filefacts_cache() {
    // filefacts::cache::cleanup detaches its own sweep, so it never
    // blocks startup.
    filefacts::cache::cleanup();
    // One-shot cleanup of the legacy radare2 cache; harmless once gone.
    // Detach: remove_dir_all may walk a large tree on old installs.
    std::thread::spawn(|| {
        if let Ok(dir) = cache_dir() {
            let _ = fs::remove_dir_all(dir.join("re"));
        }
    });
}

/// Clean up old cache files (keep only current one)
pub fn cleanup_old_caches(current_cache: &Path) -> Result<()> {
    let cache_dir = cache_dir()?;

    for entry in fs::read_dir(&cache_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Remove stale YARA caches (except the current one): v3 single-file
        // blobs (`yara-rules-*.bin`) and v4 per-tier directories
        // (`yara-rules-v4-*`).
        let is_yara_cache = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("yara-rules-"));
        if is_yara_cache && path != current_cache {
            if path.is_dir() {
                let _ = fs::remove_dir_all(&path);
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }

    // Prune superseded capability-mapper caches (stale crate-version and
    // trait-mtime variants accumulate otherwise — each a multi-MB file, the one
    // gap with no existing cleanup).
    prune_superseded_mappers(&cache_dir);

    Ok(())
}

/// A mapper family unused this long is dropped: its traits directory is most
/// likely gone (a removed checkout, a test's temporary tree), and nothing
/// else would ever remove it. A family still in use costs one rebuild.
const UNUSED_MAPPER_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Record that a cache file was just used, so pruning ages it by last use
/// rather than by when it was written. Best-effort.
pub(crate) fn mark_used(path: &Path) {
    if let Ok(file) = fs::File::options().write(true).open(path) {
        let _ = file.set_modified(SystemTime::now());
    }
}

/// Prune superseded capability-mapper caches. Each traits-dir (plus crate
/// version) has its own mapper *family* — files sharing the
/// `capability-mapper-v7-{version}-{dir_tag}` prefix and differing only in the
/// trailing `-{timestamp}-{fingerprint}`. Only the newest of a family is ever
/// loaded, so keep that one and delete the older members. Pruning is strictly
/// *within* a family: a valid current mapper belonging to a different
/// `--traits-dir` is left untouched, preserving the `dir_tag` isolation the
/// cache key builds in. Best-effort.
fn prune_superseded_mappers(dir: &Path) {
    use std::collections::hash_map::Entry;

    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    let mut newest: HashMap<String, (PathBuf, SystemTime)> = HashMap::new();
    let mut superseded: Vec<PathBuf> = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("capability-mapper-") {
            continue;
        }
        let family = mapper_family(name).to_string();
        let mtime = fs::metadata(&path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        match newest.entry(family) {
            Entry::Occupied(mut slot) => {
                if mtime > slot.get().1 {
                    // Newer member: retire the previous newest of this family.
                    let (old_path, _) = slot.insert((path, mtime));
                    superseded.push(old_path);
                } else {
                    superseded.push(path);
                }
            }
            Entry::Vacant(slot) => {
                slot.insert((path, mtime));
            }
        }
    }
    // A whole family whose newest member went unused for the TTL goes too.
    let now = SystemTime::now();
    superseded.extend(newest.into_values().filter_map(|(path, mtime)| {
        now.duration_since(mtime)
            .is_ok_and(|age| age > UNUSED_MAPPER_TTL)
            .then_some(path)
    }));
    for path in superseded {
        let _ = fs::remove_file(path);
    }
}

/// The mapper *family* for a filename: everything before the trailing
/// `-{timestamp}-{fingerprint}.bin`, i.e. the
/// `capability-mapper-v7-{version}-{dir_tag}` prefix a given traits-dir's mappers
/// share. Timestamp and fingerprint carry no `-`, so the family is the name with
/// its last two dash-separated fields stripped.
fn mapper_family(name: &str) -> &str {
    let stem = name.strip_suffix(".bin").unwrap_or(name);
    stem.rsplitn(3, '-').nth(2).unwrap_or(stem)
}

#[cfg(test)]
mod tests;
