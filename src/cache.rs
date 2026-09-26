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
//! Rizin disassembly results are no longer cached here: rizin moved into
//! filefacts, which owns its own cache (`filefacts::cache`). The legacy
//! `re/` tree is retired by `maintain_filefacts_cache`.
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
use std::time::{Instant, SystemTime};
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
    match std::env::var("CLEAVE_SKIP_CACHE") {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => false,
    }
}

/// Returns `true` if the capability-mapper cache should be skipped.
///
/// The mapper cache is keyed on trait-YAML mtime, so it self-invalidates when
/// any trait file changes. It's a pure function of the traits directory and has
/// no dependency on the file being analyzed — re-compiling otherwise costs
/// 10s+ per process (parsing 6490 YAMLs into 35k+ regex-backed traits), which
/// dominates integration-test wall time.
///
/// Unlike the analysis cache, this defaults to ENABLED even in debug builds
/// and is NOT skipped by `CLEAVE_SKIP_CACHE` — tests that want fresh per-file
/// analysis still benefit from reusing the compiled trait set.
///
/// - `CLEAVE_SKIP_MAPPER_CACHE=1` / `true` → skip
/// - Env var unset                         → don't skip (always use the cache)
#[must_use]
pub fn skip_mapper_cache() -> bool {
    match std::env::var("CLEAVE_SKIP_MAPPER_CACHE") {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => false,
    }
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
    if let Ok(v) = std::env::var("CLEAVE_SKIP_YARA_CACHE") {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    if let Some(true) = skip_cache_override() {
        return true;
    }
    if let Ok(v) = std::env::var("CLEAVE_SKIP_CACHE") {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    false
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
/// [`test_cache_dir`] — so `cargo test` never shares the on-disk SQLite
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
        fs::create_dir_all(&cache_path)
            .with_context(|| format!("creating CLEAVE_CACHE_DIR at {}", cache_path.display()))?;
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

        if fs::create_dir_all(&cache_path).is_ok() {
            let probe = cache_path.join(".write-test");
            if fs::write(&probe, b"ok").is_ok() {
                let _ = fs::remove_file(probe);
                return Ok(cache_path);
            }
        }

        anyhow::bail!(
            "Failed to create writable cache directory at {}",
            cache_path.display()
        )
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
    // Platform data dir (same as traits_repo::default_traits_dir)
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("atomdrift")
        .join("cleave")
        .join("traits")
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuleFilesRevision {
    pub newest_mtime: SystemTime,
    pub fingerprint: u64,
}

fn system_time_nanos(t: SystemTime) -> Result<u128> {
    Ok(t.duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid cache timestamp")?
        .as_nanos())
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Bumped whenever the source-tag definition changes, so tags written by an
/// older engine can never collide with one this engine computes. A mismatch is
/// already handled — the compiled rules are ignored and rebuilt — so a bump
/// costs one recompile, while a silent collision would scan with wrong rules.
const SOURCE_TAG_VERSION: u64 = 2;

fn fnv_fold(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Fingerprint an opaque byte string with the same fold the source tag uses, so
/// every tag this crate mints reads the same way in logs and manifests.
pub(crate) fn digest_bytes(bytes: &[u8]) -> u64 {
    fnv_fold(FNV_OFFSET, bytes)
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

/// Fingerprint of one rule source file: FNV-1a over its traits-relative path
/// components, byte length, and full contents.
///
/// Deliberately NOT `DefaultHasher` (unspecified across Rust releases) and NOT
/// mtime-based (mtimes don't survive packaging/download): this tag must match
/// between the machine that ran `yara-precompile` and every machine that loads
/// the shipped `.yrc`, across OSes and engine builds. Contents rather than
/// length alone, because a same-length rule edit — one hex byte, one character
/// of a string literal — leaves the length fingerprint untouched, and the
/// engine would then load `.yrc` built from the pre-edit rule and scan with it.
fn rule_source_digest(traits_dir: &Path, path: &Path, bytes: &[u8]) -> u64 {
    let rel = path.strip_prefix(traits_dir).unwrap_or(path);
    let mut h = FNV_OFFSET;
    for comp in rel.components() {
        h = fnv_fold(h, comp.as_os_str().as_encoded_bytes());
        h = fnv_fold(h, b"/");
    }
    h = fnv_fold(h, &(bytes.len() as u64).to_le_bytes());
    fnv_fold(h, bytes)
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
/// served each other's mapper and analysis results. Reading the ~63 MB of rule
/// sources is spread across rayon and done once per process.
///
/// Entries are visited in file-name order, so the digests are a function of
/// the tree alone, not of the filesystem's directory order.
///
/// A pure function of the directory's contents, so a caller that must observe a
/// mid-process edit (the tests, [`traits_content_uncached`]) calls it directly;
/// [`traits_scan_for`] memoizes it for the hot path.
fn scan_traits_dir(traits_dir: &Path) -> TraitsScan {
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
    if traits_dir.exists() {
        let walker = WalkDir::new(traits_dir)
            .follow_links(true)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| {
                // Never descend into `.git`: it carries no rule/trait files yet
                // dwarfs the trait set in entry count.
                entry.depth() == 0
                    || !entry.file_type().is_dir()
                    || entry.file_name().to_str() != Some(".git")
            });
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
        .map(|c| read_rule_file(traits_dir, &c.path))
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

    // Info, not debug: reading the rule sources is a per-process cost every
    // scan pays once, and worth seeing when a scan is slow.
    let elapsed = started.elapsed();
    tracing::info!(
        walk = ordinal,
        dir = %traits_dir.display(),
        entries = entries_visited,
        reads = files_read,
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
        return compute_rules_source_tag(&traits_dir);
    }
    let revision = traits_scan().rule_revision?;
    if let Some(tag) = memoized_source_tag(&traits_dir, revision) {
        return Some(tag);
    }
    let tag = compute_rules_source_tag(&traits_dir)?;
    store_source_tag(&traits_dir, revision, tag);
    Some(tag)
}

/// [`rules_source_tag`] with the on-disk memo bypassed: always hashes the rule
/// sources as they stand.
///
/// Used where the tag is written into an artifact rather than merely compared
/// against one — pre-compilation and the staleness check that gates publishing.
/// Those hash the bytes themselves rather than trust any memo.
pub(crate) fn rules_source_tag_uncached() -> Option<u64> {
    compute_rules_source_tag(&traits_path())
}

/// Hash every rule source under `traits_dir` by traits-relative path and
/// contents.
///
/// Walks separately from [`scan_traits_dir`] rather than riding along with it:
/// its fold is a portable, order-independent FNV the compiled artifacts carry,
/// and it runs only when the memo above misses.
fn compute_rules_source_tag(traits_dir: &Path) -> Option<u64> {
    use rayon::prelude::*;

    let started = Instant::now();
    let mut sources: Vec<(PathBuf, bool)> = Vec::new();
    if traits_dir.exists() {
        let walker = WalkDir::new(traits_dir)
            .follow_links(true)
            .into_iter()
            .filter_entry(|entry| {
                entry.depth() == 0
                    || !entry.file_type().is_dir()
                    || entry.file_name().to_str() != Some(".git")
            });
        for entry in walker.flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let is_yar = match entry.path().extension().and_then(|e| e.to_str()) {
                Some("yar" | "yara") => true,
                // Trait YAML is a candidate, but only the few files carrying an
                // inline rule survive the content test below.
                Some("yaml" | "yml") => false,
                _ => continue,
            };
            sources.push((entry.path().to_path_buf(), is_yar));
        }
    }

    let mut digests: Vec<u64> = sources
        .par_iter()
        .filter_map(|(path, is_yar)| {
            let bytes = fs::read(path).ok()?;
            (*is_yar || mentions_yara(&bytes)).then(|| rule_source_digest(traits_dir, path, &bytes))
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
    let mut tag = fnv_fold(FNV_OFFSET, &SOURCE_TAG_VERSION.to_le_bytes());
    for digest in &digests {
        tag = fnv_fold(tag, &digest.to_le_bytes());
    }
    tracing::debug!(
        dir = %traits_dir.display(),
        candidates = sources.len(),
        rule_sources = digests.len(),
        elapsed_ms = started.elapsed().as_millis(),
        tag = %format!("{tag:016x}"),
        "hashed YARA rule sources"
    );
    Some(tag)
}

/// Single-entry memo pairing a content fingerprint with the source tag computed
/// under it. Rewritten in place, so it can neither grow nor go stale.
fn source_tag_memo_path() -> Option<PathBuf> {
    Some(cache_dir().ok()?.join("yara-source-tag"))
}

/// The stored tag, if it was computed for this traits directory at exactly this
/// content fingerprint. The directory is part of the key because the memo holds
/// one entry and several checkouts may alternate over it.
fn memoized_source_tag(traits_dir: &Path, revision: RuleFilesRevision) -> Option<u64> {
    let text = fs::read_to_string(source_tag_memo_path()?).ok()?;
    let mut fields = text.split_whitespace();
    let dir = fields.next()?;
    let stat = fields.next()?;
    let tag = fields.next()?;
    if dir
        != format!(
            "{:016x}",
            fnv_fold(FNV_OFFSET, traits_dir.as_os_str().as_encoded_bytes())
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
    let Some(path) = source_tag_memo_path() else {
        return;
    };
    let dir = fnv_fold(FNV_OFFSET, traits_dir.as_os_str().as_encoded_bytes());
    let line = format!("{dir:016x} {:016x} {tag:016x}\n", revision.fingerprint);
    if let Some(parent) = path.parent()
        && fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    if fs::write(&tmp, line).is_ok() && fs::rename(&tmp, &path).is_err() {
        let _ = fs::remove_file(&tmp);
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
    let scan = Arc::new(scan_traits_dir(traits_dir));
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

/// The analysis-cache revision fingerprint for the process's traits tree.
/// Memoized; see [`traits_revision_fingerprint_for`].
pub(crate) fn traits_revision_fingerprint() -> i64 {
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

/// Generate a cache key based on the newest `.yar`/`.yara` file mtime and third-party flag.
///
/// Only pure YARA rule files are considered, so editing trait YAMLs does not
/// force a full YARA recompile. Falls back to binary mtime when no rule files exist.
///
/// Includes the cleave version so that upgrading the binary invalidates the cache.
pub(crate) fn yara_cache_key(third_party_enabled: bool) -> Result<String> {
    let mtime = most_recent_yar_file()
        .map(|(t, _)| t)
        .or_else(|_| binary_mtime())?;
    let timestamp = system_time_nanos(mtime)?;

    let suffix = if third_party_enabled {
        "with-3p"
    } else {
        "builtin"
    };
    let version = env!("CARGO_PKG_VERSION");

    // v4 is a *directory* holding `manifest.json` + one `<tier>.yrc` per tier,
    // each compiled lazily on first scan. v3 was a single all-tiers blob whose
    // cold build held every tier's JIT'd native code resident at once.
    Ok(format!("yara-rules-v4-{version}-{timestamp}-{suffix}"))
}

/// Path to the YARA rules cache *directory* (per-tier compiled rules + manifest).
pub fn yara_cache_path(third_party_enabled: bool) -> Result<PathBuf> {
    let cache_key = yara_cache_key(third_party_enabled)?;
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
        "capability-mapper-v11-{version}-{dir_tag}-{fingerprint:016x}-{build:016x}.bin"
    ))
}

/// Short stable tag for a traits directory, suitable for cache keys. Uses the
/// absolute canonical path to discriminate concurrent processes that each pass
/// `--traits-dir` at distinct locations.
fn traits_dir_tag(traits_dir: &Path) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let canonical = std::fs::canonicalize(traits_dir).unwrap_or_else(|_| traits_dir.to_path_buf());
    let mut h = DefaultHasher::new();
    canonical.hash(&mut h);
    // 8 hex chars is enough discrimination for a filename component without bloating it.
    format!("{:08x}", (h.finish() & 0xFFFF_FFFF) as u32)
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

/// Rule stats stored in a tiny cache file for fast banner display.
/// Layout: trait_count(8) + composite_count(8) + timestamp(8) = 24 bytes
#[allow(dead_code)] // Used by binary
const STATS_CACHE_SIZE: usize = 24;

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

/// Maintain the filefacts disk cache that now owns rizin recovery.
///
/// Rizin moved into filefacts, which caches its extraction snapshot
/// (recovered imports/exports/functions/sections included) keyed by
/// `(content, filefacts build, rizin config)`. cleave relies on that
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
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    /// A traits tree with one YARA rule file and one plain trait file.
    fn traits_tree(dir: &Path) -> (PathBuf, PathBuf) {
        let rule = dir.join("third-party/vendor/rules.yar");
        fs::create_dir_all(rule.parent().unwrap()).unwrap();
        fs::write(&rule, b"rule a { strings: $s = \"abc\" condition: $s }\n").unwrap();
        let trait_file = dir.join("micro-behaviors/net/socket.yaml");
        fs::create_dir_all(trait_file.parent().unwrap()).unwrap();
        fs::write(
            &trait_file,
            b"traits:\n  - id: net/socket\n    if: {type: string, value: connect}\n",
        )
        .unwrap();
        (rule, trait_file)
    }

    /// The failure this tag exists to catch: a rule edit that leaves the file's
    /// length untouched, which a path+length fingerprint cannot see.
    #[test]
    fn test_source_tag_catches_same_length_rule_edit() {
        let tmp = tempfile::tempdir().unwrap();
        let (rule, _) = traits_tree(tmp.path());
        let before = compute_rules_source_tag(tmp.path()).expect("tag");

        fs::write(&rule, b"rule a { strings: $s = \"abd\" condition: $s }\n").unwrap();
        let after = compute_rules_source_tag(tmp.path()).expect("tag");

        assert_ne!(before, after, "same-length rule edit must change the tag");
    }

    /// The churn this tag exists to avoid: trait YAML with no inline rule
    /// cannot change a compiled `.yrc`, so editing it must not condemn one.
    #[test]
    fn test_source_tag_ignores_trait_yaml_without_inline_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, trait_file) = traits_tree(tmp.path());
        let before = compute_rules_source_tag(tmp.path()).expect("tag");

        fs::write(
            &trait_file,
            b"traits:\n  - id: net/socket\n    if: {type: string, value: connect}\n    description: a much longer file now\n",
        )
        .unwrap();
        fs::create_dir_all(tmp.path().join("well-known")).unwrap();
        fs::write(tmp.path().join("well-known/added.yaml"), b"traits: []\n").unwrap();

        assert_eq!(
            before,
            compute_rules_source_tag(tmp.path()).expect("tag"),
            "trait YAML with no inline YARA must not move the tag"
        );
    }

    /// Inline `type: yara` rules do reach the compiler, so their file is
    /// fingerprinted by content like any `.yar`.
    #[test]
    fn test_source_tag_tracks_inline_yara_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, trait_file) = traits_tree(tmp.path());
        let inline = tmp.path().join("objectives/impact/wiper.yaml");
        fs::create_dir_all(inline.parent().unwrap()).unwrap();
        let rule_of = |marker: &str| {
            format!(
                "traits:\n  - id: impact/wiper\n    if:\n      type: yara\n      source: |\n        rule w {{ strings: $s = \"{marker}\" condition: $s }}\n"
            )
        };
        fs::write(&inline, rule_of("wipe")).unwrap();
        let before = compute_rules_source_tag(tmp.path()).expect("tag");

        fs::write(&inline, rule_of("nuke")).unwrap();
        let after = compute_rules_source_tag(tmp.path()).expect("tag");
        assert_ne!(before, after, "inline YARA edit must change the tag");

        // The plain trait file next to it still contributes nothing.
        fs::write(&trait_file, b"traits: []\n").unwrap();
        assert_eq!(after, compute_rules_source_tag(tmp.path()).expect("tag"));
    }

    /// The tag travels with a bundle, so it must depend on the tree's contents
    /// and layout — never on where that tree happens to sit.
    #[test]
    fn test_source_tag_is_independent_of_traits_dir_location() {
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        traits_tree(one.path());
        traits_tree(two.path());

        assert_eq!(
            compute_rules_source_tag(one.path()).expect("tag"),
            compute_rules_source_tag(two.path()).expect("tag"),
        );
    }

    #[test]
    fn test_yara_cache_key_format() {
        // Test that cache key has expected format
        if let Ok(key) = yara_cache_key(false) {
            assert!(key.starts_with("yara-rules-v4-"));
            assert!(key.ends_with("-builtin"));
        }

        if let Ok(key) = yara_cache_key(true) {
            assert!(key.starts_with("yara-rules-v4-"));
            assert!(key.ends_with("-with-3p"));
        }
    }

    #[test]
    fn test_rule_files_revision_changes_for_same_second_edits() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let traits_dir = tmp.path();
        let rule = traits_dir.join("traits.yaml");
        fs::write(&rule, b"traits: []\n").expect("write rule");

        let fixed = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        filetime::set_file_mtime(&rule, filetime::FileTime::from_system_time(fixed))
            .expect("set mtime");

        // Walk the directory directly (not the memoized `traits_scan`) so both
        // reads reflect the file as it stands, exercising the same-second
        // fingerprint change.
        let first = scan_traits_dir(traits_dir)
            .rule_revision
            .expect("first revision");

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&rule)
            .expect("open rule");
        file.write_all(b"# edit in same second\n").expect("append");
        filetime::set_file_mtime(&rule, filetime::FileTime::from_system_time(fixed))
            .expect("reset mtime");
        let second = scan_traits_dir(traits_dir)
            .rule_revision
            .expect("second revision");

        assert_eq!(first.newest_mtime, second.newest_mtime);
        assert_ne!(first.fingerprint, second.fingerprint);
    }

    /// Rewrite `path` with `contents` and put its mtime back, so only the bytes
    /// differ from what a stat key would see.
    fn rewrite_keeping_mtime(path: &Path, contents: &str) {
        let mtime = fs::metadata(path).unwrap().modified().unwrap();
        let len = fs::metadata(path).unwrap().len();
        fs::write(path, contents).unwrap();
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), mtime);
        assert_eq!(fs::metadata(path).unwrap().len(), len);
    }

    // The edit a stat key cannot see: same path, same length, same mtime.
    #[test]
    fn same_length_edit_with_mtime_restored_changes_every_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, trait_file) = traits_tree(tmp.path());
        let before = scan_traits_dir(tmp.path());

        rewrite_keeping_mtime(
            &trait_file,
            "traits:\n  - id: net/socket\n    if: {type: string, value: cOnnect}\n",
        );
        let after = scan_traits_dir(tmp.path());

        assert_ne!(
            after.rule_revision.unwrap().fingerprint,
            before.rule_revision.unwrap().fingerprint,
            "analysis-cache revision"
        );
        assert_ne!(
            after.yaml_revision.unwrap().fingerprint,
            before.yaml_revision.unwrap().fingerprint,
            "mapper-cache revision"
        );
        assert_ne!(after.content.rules, before.content.rules);
        assert_eq!(after.content.layout, before.content.layout);
    }

    // Content keys neither trust mtimes nor depend on them: a checkout that
    // restamps every file must keep every cache entry.
    #[test]
    fn touching_files_changes_no_revision() {
        let tmp = tempfile::tempdir().unwrap();
        let (rule, trait_file) = traits_tree(tmp.path());
        let before = scan_traits_dir(tmp.path());
        let later = SystemTime::UNIX_EPOCH + Duration::from_secs(1_900_000_000);
        for path in [&rule, &trait_file] {
            fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(later)
                .unwrap();
        }
        let after = scan_traits_dir(tmp.path());
        assert_eq!(
            after.rule_revision.unwrap().fingerprint,
            before.rule_revision.unwrap().fingerprint
        );
        assert_eq!(
            after.yaml_revision.unwrap().fingerprint,
            before.yaml_revision.unwrap().fingerprint
        );
        assert_eq!(after.content, before.content);
        assert_ne!(
            after.rule_revision.unwrap().newest_mtime,
            before.rule_revision.unwrap().newest_mtime
        );
    }

    /// A one-trait tree whose trait description is `desc`.
    fn probe_tree(desc: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let yaml = dir.path().join("objectives/probe/memo.yaml");
        fs::create_dir_all(yaml.parent().unwrap()).unwrap();
        fs::write(&yaml, probe_yaml(desc)).unwrap();
        dir
    }

    fn probe_yaml(desc: &str) -> String {
        format!(
            "traits:\n  - id: memo-probe\n    desc: {desc}\n    crit: notable\n    \
             conf: 0.8\n    for: [python]\n    if:\n      type: text\n      \
             exact: memo-probe-needle\n"
        )
    }

    fn load_probe_desc(dir: &Path, full_validation: bool) -> Option<String> {
        let mapper = crate::capabilities::CapabilityMapper::from_directory_with_options(
            dir,
            crate::capabilities::CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            crate::capabilities::CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            full_validation,
            false,
        )
        .unwrap();
        mapper
            .trait_definitions()
            .iter()
            .find(|t| t.id.ends_with("memo-probe"))
            .map(|t| t.desc.clone())
    }

    // The mapper cache written for one tree must not be served for a
    // same-length edit of it under a restored mtime, whether the load
    // validates nothing or skips validation on a clean mark. Invalidating the
    // scan stands in for the next process, which reads the tree afresh.
    #[test]
    fn mapper_cache_misses_on_a_same_length_edit() {
        let dir = probe_tree("probe aaa");
        let yaml = dir.path().join("objectives/probe/memo.yaml");
        assert_eq!(
            load_probe_desc(dir.path(), false).as_deref(),
            Some("probe aaa")
        );
        assert!(mapper_cache_path_for(dir.path()).unwrap().exists());

        rewrite_keeping_mtime(&yaml, &probe_yaml("probe bbb"));
        invalidate_traits_scan();
        assert_eq!(
            load_probe_desc(dir.path(), false).as_deref(),
            Some("probe bbb")
        );

        // Full validation requested, skipped on a mark for the edited tree.
        rewrite_keeping_mtime(&yaml, &probe_yaml("probe ccc"));
        invalidate_traits_scan();
        crate::traits_fingerprint::CleanMark::for_traits(dir.path(), None)
            .unwrap()
            .set_if_unchanged(dir.path());
        assert_eq!(
            load_probe_desc(dir.path(), true).as_deref(),
            Some("probe ccc")
        );
    }

    #[test]
    fn test_cache_dir_returns_path() {
        let result = cache_dir();
        // Should either succeed or fail, but not panic
        match result {
            Ok(path) => {
                assert!(path.to_string_lossy().contains("cleave"));
            }
            Err(_) => {
                // Some environments may not have cache dir
            }
        }
    }

    #[test]
    fn test_yara_cache_path_includes_cache_key() {
        if let Ok(path) = yara_cache_path(false) {
            let path_str = path.to_string_lossy();
            assert!(path_str.contains("yara-rules-v4-"));
        }
    }

    #[test]
    fn test_yara_cache_path_different_for_third_party() {
        if let (Ok(path1), Ok(path2)) = (yara_cache_path(false), yara_cache_path(true)) {
            // Paths should be different based on third_party flag
            assert_ne!(path1, path2);
            assert!(path1.to_string_lossy().contains("builtin"));
            assert!(path2.to_string_lossy().contains("with-3p"));
        }
    }

    #[test]
    fn test_most_recent_yara_mtime_no_files() {
        // This test verifies the function handles missing directories gracefully.
        // Note: We don't change the working directory as that would affect parallel tests.
        // The actual behavior depends on whether yara/ exists in the project root.
        // If yara/ exists with files, it returns Ok; if not, it returns Err.
        let result = most_recent_yara_mtime();
        // Just verify it doesn't panic - result depends on project structure
        let _ = result;
    }

    #[test]
    fn test_cleanup_old_caches_handles_nonexistent_dir() {
        let temp_path = PathBuf::from("/nonexistent/cache/file.bin");
        // Should not panic with nonexistent path
        let _ = cleanup_old_caches(&temp_path);
    }

    #[test]
    fn mapper_family_strips_timestamp_and_fingerprint() {
        assert_eq!(
            mapper_family("capability-mapper-v7-2.3.0-aaaaaaaa-100-000000000000000a.bin"),
            "capability-mapper-v7-2.3.0-aaaaaaaa"
        );
        // A pre-release version keeps its internal dash inside the family.
        assert_eq!(
            mapper_family("capability-mapper-v7-2.3.0-rc1-bbbbbbbb-200-000000000000000b.bin"),
            "capability-mapper-v7-2.3.0-rc1-bbbbbbbb"
        );
    }

    #[test]
    fn prune_superseded_mappers_keeps_newest_per_family() {
        let dir = std::env::temp_dir().join(format!("cleave-mapper-prune-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Family A (dir_tag aaaaaaaa): an old and a new version. Family B
        // (dir_tag bbbbbbbb): a single, still-valid mapper for another
        // traits-dir — it must survive even though it is older than A's newest.
        let a_old = "capability-mapper-v7-2.3.0-aaaaaaaa-100-000000000000000a.bin";
        let a_new = "capability-mapper-v7-2.3.0-aaaaaaaa-300-000000000000000b.bin";
        let b_one = "capability-mapper-v7-2.3.0-bbbbbbbb-200-000000000000000c.bin";
        for (name, hours_old) in [(a_old, 3u64), (b_one, 2), (a_new, 1)] {
            let f = fs::File::create(dir.join(name)).unwrap();
            f.set_modified(SystemTime::now() - Duration::from_secs(hours_old * 3600))
                .unwrap();
        }
        fs::write(dir.join("yara-rules-v4-x-builtin"), b"keep").unwrap();

        prune_superseded_mappers(&dir);

        assert!(
            !dir.join(a_old).exists(),
            "superseded family-A version pruned"
        );
        assert!(dir.join(a_new).exists(), "current family-A mapper retained");
        assert!(
            dir.join(b_one).exists(),
            "another traits-dir's mapper is never pruned across families"
        );
        assert!(
            dir.join("yara-rules-v4-x-builtin").exists(),
            "non-mapper files are untouched"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_format_age() {
        assert_eq!(format_age(0), "0s");
        assert_eq!(format_age(45), "45s");
        assert_eq!(format_age(60), "1m 0s");
        assert_eq!(format_age(90), "1m 30s");
        assert_eq!(format_age(3600), "1h 0m");
        assert_eq!(format_age(3661), "1h 1m");
        assert_eq!(format_age(86400), "1d 0h");
        assert_eq!(format_age(90061), "1d 1h");
    }
}
