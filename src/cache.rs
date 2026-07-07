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
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
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

fn skip_yara_cache_override() -> Option<bool> {
    decode_override(&SKIP_YARA_CACHE_OVERRIDE)
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
    if let Some(v) = skip_yara_cache_override() {
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
pub fn cache_dir() -> Result<PathBuf> {
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
/// Only pure YARA rule files are considered; trait YAML changes do not invalidate
/// the YARA compilation cache. Inline `type: yara` conditions embedded in YAML files
/// require `CLEAVE_SKIP_CACHE=1` to force recompile if they change.
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

impl RuleFilesRevision {
    pub(crate) fn cache_i64(self) -> i64 {
        i64::from_ne_bytes(self.fingerprint.to_ne_bytes())
    }
}

fn system_time_nanos(t: SystemTime) -> Result<u128> {
    Ok(t.duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid cache timestamp")?
        .as_nanos())
}

fn hash_path_metadata(
    hasher: &mut std::collections::hash_map::DefaultHasher,
    traits_dir: &Path,
    path: &Path,
    metadata: &fs::Metadata,
) {
    use std::hash::Hash;

    let rel = path.strip_prefix(traits_dir).unwrap_or(path);
    rel.hash(hasher);
    metadata.len().hash(hasher);
    if let Ok(mtime) = metadata.modified() {
        system_time_nanos(mtime).unwrap_or(0).hash(hasher);
    }
}

/// A walk of the traits tree slow enough to be worth a warning: on a warm local
/// filesystem the single pass is tens of milliseconds, so anything past this is
/// a cold cache, a slow/networked filesystem, or a machine under I/O load — the
/// exact conditions that turn a "should be instant" scan into a multi-second (or
/// multi-minute) stall. Logging it at `warn` makes that cause visible without
/// `--verbose`.
const SLOW_TRAITS_WALK: std::time::Duration = std::time::Duration::from_millis(400);

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
/// all of those into one traversal (see [`scan_traits_dir`]); [`traits_scan`]
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
}

/// Walk the traits directory once, computing every rule/mapper cache input in a
/// single pass.
///
/// This replaces the four separate per-key walks. It descends everything except
/// `.git` (which holds no rule files but adds thousands of entries to stat) and
/// stats each rule/trait file exactly once, versus the two stats — `is_file()`
/// then `metadata()` — the previous walks did per entry. Skipping only `.git`
/// (rather than all hidden/underscore dirs) keeps the revision fingerprints
/// byte-identical to the previous functions, so existing caches are not
/// invalidated.
///
/// A pure function of the directory's contents, so a caller that must observe a
/// mid-process edit (the tests) calls it directly; [`traits_scan`] memoizes it
/// for the hot path so a warm scan walks the tree exactly once.
fn scan_traits_dir(traits_dir: &Path) -> TraitsScan {
    use rayon::prelude::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let ordinal = TRAITS_WALK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let started = Instant::now();

    let mut newest_yaml = SystemTime::UNIX_EPOCH;
    let mut newest_yaml_path = PathBuf::new();
    let mut newest_yar = SystemTime::UNIX_EPOCH;
    let mut newest_yar_path = PathBuf::new();
    let mut newest_rule = SystemTime::UNIX_EPOCH;

    let mut yaml_hasher = DefaultHasher::new();
    let mut rule_hasher = DefaultHasher::new();
    let mut yaml_count = 0u64;
    let mut rule_count = 0u64;

    // One matching rule/trait file, classified during the (cheap) directory read
    // so the (expensive) stat can be deferred and parallelized below.
    struct Candidate {
        path: PathBuf,
        is_yaml: bool,
        is_yar: bool,
        third_party: bool,
    }

    // Phase 1 — walk the tree and collect matching files, in order. This is just
    // the directory reads (`readdir`); no per-file stat happens yet. Extension and
    // third-party classification are pure path inspection, so they belong here.
    let mut candidates: Vec<Candidate> = Vec::new();
    if traits_dir.exists() {
        let walker = WalkDir::new(traits_dir)
            .follow_links(true)
            .into_iter()
            .filter_entry(|entry| {
                // Never descend into `.git`: it carries no rule/trait files yet
                // dwarfs the trait set in entry count. Everything else is walked,
                // so the hashed file set (and thus the fingerprint) is unchanged.
                entry.depth() == 0
                    || !entry.file_type().is_dir()
                    || entry.file_name().to_str() != Some(".git")
            });
        for entry in walker.flatten() {
            // `file_type()` comes from the directory read, no extra stat.
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
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

    // Phase 2 — stat every candidate at once. This is the bulk of the wall-clock
    // and is pure independent I/O, so a parallel map turns ~10k serial stats into
    // a handful of parallel batches. `collect` preserves order, so phase 3 still
    // folds the hashers deterministically. (Runs inside `traits_scan`'s memoized
    // init, which is only ever triggered from the main thread — see there — so
    // this rayon use cannot re-enter that `OnceLock`.)
    let metadatas: Vec<Option<fs::Metadata>> = candidates
        .par_iter()
        .map(|c| fs::metadata(&c.path).ok())
        .collect();

    // Phase 3 — fold the fingerprints in walk order. Identical hash inputs and
    // order to the previous serial walk, so the revision fingerprints are
    // unchanged (and cached mappers stay valid).
    let mut files_statted = 0u64;
    for (c, metadata) in candidates.iter().zip(&metadatas) {
        let Some(metadata) = metadata else {
            continue;
        };
        files_statted += 1;
        let mtime = metadata.modified().ok();

        // Analysis-cache revision: every rule/trait file, third-party included.
        rule_count += 1;
        hash_path_metadata(&mut rule_hasher, traits_dir, &c.path, metadata);
        if let Some(m) = mtime
            && m > newest_rule
        {
            newest_rule = m;
        }

        if c.is_yar
            && let Some(m) = mtime
            && m > newest_yar
        {
            newest_yar = m;
            newest_yar_path = c.path.clone();
        }

        // Mapper revision + newest trait YAML: `.yaml`/`.yml`, third-party excluded.
        if c.is_yaml && !c.third_party {
            yaml_count += 1;
            hash_path_metadata(&mut yaml_hasher, traits_dir, &c.path, metadata);
            if let Some(m) = mtime
                && m > newest_yaml
            {
                newest_yaml = m;
                newest_yaml_path = c.path.clone();
            }
        }
    }

    // Fold the counts in exactly as the previous per-key walks did, so the
    // fingerprints match byte-for-byte.
    yaml_count.hash(&mut yaml_hasher);
    rule_count.hash(&mut rule_hasher);

    let elapsed = started.elapsed();
    if elapsed >= SLOW_TRAITS_WALK {
        tracing::warn!(
            walk = ordinal,
            dir = %traits_dir.display(),
            entries = entries_visited,
            stats = files_statted,
            elapsed_ms = elapsed.as_millis(),
            "slow traits-directory walk — cold cache, a slow/networked filesystem, or I/O contention"
        );
    } else {
        tracing::debug!(
            walk = ordinal,
            dir = %traits_dir.display(),
            entries = entries_visited,
            stats = files_statted,
            yaml_files = yaml_count,
            rule_files = rule_count,
            elapsed_ms = elapsed.as_millis(),
            "walked traits directory"
        );
    }

    TraitsScan {
        newest_yaml: (newest_yaml != SystemTime::UNIX_EPOCH)
            .then_some((newest_yaml, newest_yaml_path)),
        yaml_revision: (yaml_count > 0).then(|| RuleFilesRevision {
            newest_mtime: newest_yaml,
            fingerprint: yaml_hasher.finish(),
        }),
        newest_yar: (newest_yar != SystemTime::UNIX_EPOCH).then_some((newest_yar, newest_yar_path)),
        rule_revision: (rule_count > 0).then(|| RuleFilesRevision {
            newest_mtime: newest_rule,
            fingerprint: rule_hasher.finish(),
        }),
    }
}

/// The single, memoized traits-directory scan for this process.
///
/// Every cache key derives from this one traversal. Memoized for the process
/// because the traits directory does not change under a running scan — the same
/// assumption the analysis-cache revision and YARA timestamp already made. A
/// caller that must observe a mid-process edit walks [`scan_traits_dir`]
/// directly (as the tests do).
///
/// The one-time init runs [`scan_traits_dir`], which stats files with rayon, so
/// it must first be triggered from the main thread — never from inside a rayon
/// worker, or the parallel stats could steal a task that re-enters this
/// `OnceLock` and deadlock. Every trigger (mapper cache key, YARA timestamp,
/// analysis-cache revision, `version_info`) fires during mapper load, which the
/// worker/server paths force on the main thread via `prefetch_capability_mapper`
/// and the one-shot paths reach on their own main thread.
fn traits_scan() -> &'static TraitsScan {
    static SCAN: OnceLock<TraitsScan> = OnceLock::new();
    SCAN.get_or_init(|| scan_traits_dir(&traits_path()))
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

/// Returns a stable revision fingerprint for YAML trait files.
///
/// This excludes `third-party/` because those files feed the YARA cache, not the
/// trait mapper. It includes path, file size, and nanosecond mtime so mapper
/// cache keys change even for same-second edits.
///
/// Reads the memoized [`traits_scan`] bundle, so the mapper cache key shares the
/// single per-process traits walk with every other cache key.
pub(crate) fn trait_yaml_revision() -> Result<RuleFilesRevision> {
    traits_scan()
        .yaml_revision
        .context("No .yaml/.yml files found")
}

/// Returns a stable revision fingerprint for all rule and trait files.
///
/// Used by caches that must invalidate on trait/YARA edits. The newest mtime is
/// kept for human-readable stats, while the fingerprint includes file paths,
/// sizes, and nanosecond mtimes so same-second edits do not reuse stale cache
/// entries.
///
/// Reads the memoized [`traits_scan`] bundle, so this and every other cache key
/// share one walk of the traits tree per process.
pub(crate) fn rule_files_revision() -> Result<RuleFilesRevision> {
    traits_scan()
        .rule_revision
        .context("No YARA/trait files found")
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
    static CACHED: OnceLock<SystemTime> = OnceLock::new();
    if let Some(&ts) = CACHED.get() {
        return Ok(ts);
    }
    let ts = match most_recent_yara_mtime() {
        Ok(mtime) => mtime,
        Err(_) => binary_mtime()?,
    };
    Ok(*CACHED.get_or_init(|| ts))
}

/// Returns the active rule/trait revision fingerprint for cache invalidation.
pub(crate) fn cache_revision() -> Result<RuleFilesRevision> {
    static CACHED: OnceLock<RuleFilesRevision> = OnceLock::new();
    if let Some(&revision) = CACHED.get() {
        return Ok(revision);
    }
    let revision = match rule_files_revision() {
        Ok(revision) => revision,
        Err(_) => {
            let mtime = binary_mtime()?;
            RuleFilesRevision {
                newest_mtime: mtime,
                fingerprint: system_time_nanos(mtime)? as u64,
            }
        }
    };
    Ok(*CACHED.get_or_init(|| revision))
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

/// Generate a cache key for the capability mapper.
///
/// Keyed on the newest `.yaml`/`.yml` trait file mtime (third-party directory excluded),
/// so YARA-only rule updates do not force a trait mapper rebuild.
/// Falls back to binary mtime when no YAML files exist.
///
/// Also incorporates a short hash of the absolute traits-directory path so that
/// distinct trait roots — `--traits-dir /tmp/A/traits` vs `/tmp/B/traits` — never
/// collide on the same cache file. Without this discriminator, parallel test
/// processes (or any two cleave invocations against different `--traits-dir`
/// values whose newest YAML mtime rounds to the same second) could read each
/// other's compiled mapper.
pub(crate) fn mapper_cache_key() -> Result<String> {
    let revision = trait_yaml_revision().or_else(|_| {
        let mtime = binary_mtime()?;
        Ok::<RuleFilesRevision, anyhow::Error>(RuleFilesRevision {
            newest_mtime: mtime,
            fingerprint: system_time_nanos(mtime)? as u64,
        })
    })?;
    let timestamp = system_time_nanos(revision.newest_mtime)?;
    let fingerprint = revision.fingerprint;

    let version = env!("CARGO_PKG_VERSION");
    let dir_tag = traits_dir_tag();

    Ok(format!(
        "capability-mapper-v6-{version}-{dir_tag}-{timestamp}-{fingerprint:016x}.bin"
    ))
}

/// Short stable tag for the active traits directory, suitable for cache keys.
/// Uses the absolute canonical path to discriminate concurrent processes that
/// each pass `--traits-dir` at distinct locations.
fn traits_dir_tag() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let path = traits_path();
    let canonical = std::fs::canonicalize(&path).unwrap_or(path);
    let mut h = DefaultHasher::new();
    canonical.hash(&mut h);
    // 8 hex chars is enough discrimination for a filename component without bloating it.
    format!("{:08x}", (h.finish() & 0xFFFF_FFFF) as u32)
}

/// Get the path to the capability mapper cache file
pub fn mapper_cache_path() -> Result<PathBuf> {
    let cache_key = mapper_cache_key()?;
    Ok(cache_dir()?.join(cache_key))
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
    use std::io::Write;

    let path = rule_stats_cache_path()?;
    let timestamp = cache_timestamp()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid timestamp")?
        .as_secs();

    let mut file = fs::File::create(&path)?;
    file.write_all(&(trait_count as u64).to_le_bytes())?;
    file.write_all(&(composite_count as u64).to_le_bytes())?;
    file.write_all(&timestamp.to_le_bytes())?;
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

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Write;
    use std::time::Duration;

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
