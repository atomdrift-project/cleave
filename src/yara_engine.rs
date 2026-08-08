//! YARA rule engine integration.
//!
//! This module provides YARA pattern matching for malware detection.
//! It loads and compiles YARA rules from:
//! - Built-in rules (traits/yara/)
//! - Third-party rules (if enabled)
//!
//! Rules are compiled once at startup for performance.

use crate::capabilities::CapabilityMapper;
use crate::types::{
    Evidence, MAX_EVIDENCE_PER_TRAIT, MatchedString, YaraMatch, deduplicate_evidence,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI8, Ordering};

/// Process-wide override for "load built-in YARA rules only" (skip third-party).
///
/// 0 = unset, 1 = force builtin-only, -1 = force third-party-allowed.
static BUILTIN_YARA_ONLY_OVERRIDE: AtomicI8 = AtomicI8::new(0);

/// Process-wide override for skipping YARA entirely. Used by tests that don't
/// need YARA scanning to keep startup time low.
static SKIP_YARA_OVERRIDE: AtomicI8 = AtomicI8::new(0);

fn decode(atom: &AtomicI8) -> Option<bool> {
    match atom.load(Ordering::Relaxed) {
        1 => Some(true),
        -1 => Some(false),
        _ => None,
    }
}

fn store(atom: &AtomicI8, value: Option<bool>) {
    atom.store(
        match value {
            None => 0,
            Some(true) => 1,
            Some(false) => -1,
        },
        Ordering::Relaxed,
    );
}

/// Force YARA loading to use built-in rules only (skipping third-party).
/// `Some(true)` skips third-party, `Some(false)` keeps them, `None` clears.
pub fn set_builtin_yara_only_override(value: Option<bool>) {
    store(&BUILTIN_YARA_ONLY_OVERRIDE, value);
}

/// Force YARA scanning off for the rest of the process. Mirrors
/// `CLEAVE_SKIP_YARA` but without env-var mutation.
pub fn set_skip_yara_override(value: Option<bool>) {
    store(&SKIP_YARA_OVERRIDE, value);
}

fn builtin_yara_only_active() -> bool {
    if let Some(v) = decode(&BUILTIN_YARA_ONLY_OVERRIDE) {
        return v;
    }
    std::env::var("CLEAVE_BUILTIN_YARA_ONLY").is_ok()
}

fn skip_yara_active() -> bool {
    if let Some(v) = decode(&SKIP_YARA_OVERRIDE) {
        return v;
    }
    std::env::var("CLEAVE_SKIP_YARA").is_ok()
}
use walkdir::WalkDir;
#[cfg(test)]
use yara_classify::YaraTier;

/// Bucket key for rules that apply to any file (EICAR-style). Always loaded by
/// every scan in addition to the detected file type's buckets.
const FALLBACK_BUCKET: &str = "fallback";

/// Compiled regex for YARA rule header matching — shared across all preprocessing steps.
fn rule_start_re() -> Option<&'static regex::Regex> {
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?m)^(\s*)((?:private\s+|global\s+)*)rule\s+(\w+)").ok())
        .as_ref()
}

/// Maximum pattern match ranges to collect per pattern.
///
/// Both consumers of these ranges (`build_yara_match` and the inline-trait
/// evidence builder) cap their output at `MAX_EVIDENCE_PER_TRAIT` (=16). The
/// total match count is captured separately via `pat.matches().count()`, so
/// density information is preserved regardless of this cap. Keeping the Vec
/// itself small avoids holding 100k × 16-byte tuples per high-match pattern
/// when only the first ~16 are ever read; on 16 rayon workers the savings
/// add up to GBs of in-flight memory during heavy YARA-density runs.
const MAX_PATTERN_MATCHES: usize = 8;

/// Maximum scanners to cache per thread in the engine tier cache.
///
/// Sized for the *thread's* working set, not one file's: a rayon worker
/// interleaves scans from many files (archive-member fan-out, fetched
/// dependencies) plus tier scans stolen from large payloads' parallel tier
/// fan-out, so it cycles through most of the tier universe (~75 buckets), not
/// the 1-3 tiers one file touches. At the old bound of 4 a 13k-member archive
/// scan recreated scanners ~31,000 times — each a wasmtime store + linker
/// instantiation that dominated the fetch-phase tail. 64 covers every tier a
/// thread realistically touches; tune via `CLEAVE_YARA_SCANNER_CACHE`.
fn engine_scanner_cache_size() -> usize {
    const DEFAULT: usize = 64;
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| {
        std::env::var("CLEAVE_YARA_SCANNER_CACHE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT)
    })
}

/// Payloads at least this large scan their YARA tiers in parallel; smaller ones
/// scan sequentially (the rayon task overhead exceeds a tiny scan, and avoids a
/// third nesting level under archive member fan-out). Tunable via
/// `CLEAVE_YARA_TIER_PARALLEL_MIN_BYTES`; `0` forces always-parallel.
fn tier_parallel_min_bytes() -> usize {
    const DEFAULT: usize = 256 * 1024;
    static MIN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MIN.get_or_init(|| {
        std::env::var("CLEAVE_YARA_TIER_PARALLEL_MIN_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT)
    })
}

// YARA panics indicate a broken scanner/rule state, not a recoverable per-file
// condition. Once we catch one, continuing to scan every subsequent file just
// repeats the same expensive unwind path and floods logs. Flip this breaker and
// let the rest of the analysis proceed without YARA until rules are reloaded.
static YARA_SCANS_DISABLED_AFTER_PANIC: AtomicBool = AtomicBool::new(false);

// Thread-local LRU cache for YARA scanners keyed by `Rules` pointer address.
// Avoids expensive `Scanner::new()` on every file (wasmtime VM instantiation).
// Each rayon worker thread caches its own scanners (one per filetype bucket it
// touches). The `Rules` behind each key live for the whole process (OnceLock
// statics), so cached scanners never go stale; the LRU bound is the only thing
// keeping this from growing without limit, so the cache is never cleared.
thread_local! {
    static ENGINE_SCANNER_CACHE: RefCell<lru::LruCache<usize, yara_x::Scanner<'static>>> = {
        use std::num::NonZeroUsize;
        let cache_size =
            NonZeroUsize::new(engine_scanner_cache_size()).unwrap_or(NonZeroUsize::MIN);
        RefCell::new(lru::LruCache::new(cache_size))
    };
}

fn rule_context_key(namespace: &str, rule_name: &str) -> String {
    format!("{namespace}\u{1f}{rule_name}")
}

fn extract_header_tags_from_source(rule_text: &str) -> Vec<String> {
    let header = rule_text.split('{').next().unwrap_or(rule_text);
    let Some((_, tags)) = header.split_once(':') else {
        return Vec::new();
    };
    tags.split_whitespace()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(std::string::ToString::to_string)
        .collect()
}

fn platform_label(platform: &crate::composite_rules::Platform) -> &'static str {
    platform.label()
}

fn looks_like_unix_shell_payload(lower_source: &str) -> bool {
    [
        "/bin/sh",
        "/bin/bash",
        "/etc/ld.so.preload",
        "/etc/crontab",
        "/proc/self",
        "chmod +x",
        "chmod a+x",
        "sh | sh",
        "exec bash --login",
        "mkfifo fifo ; nc.traditional -u",
        "< fifo | { bash -i; } > fifo",
        "wget ",
        "curl ",
        "tmsh",
        "big-ip",
        "launchctl",
    ]
    .iter()
    .any(|needle| lower_source.contains(needle))
}

/// Raw match data collected from a YARA scan before processing into `YaraMatch`.
struct RawRule {
    name: String,
    namespace: String,
    tags: Vec<String>,
    metadata: Vec<(String, String)>,
    patterns: Vec<(String, Vec<(usize, usize)>)>,
}

/// Rule metadata derived once from the full source text and cached alongside tiers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct RuleContext {
    filetypes: Vec<String>,
    filetype_source: String,
    platforms: Vec<String>,
    os_meta: Option<String>,
    arch_context: Option<String>,
}

struct SplitSource {
    /// Per-filetype-bucket source text, keyed by filetype string (e.g. "pe",
    /// "docx") or [`FALLBACK_BUCKET`] for rules with no filetype constraint.
    tiers: HashMap<String, String>,
    contexts: HashMap<String, RuleContext>,
}

/// YARA-X engine for pattern-based detection.
///
/// Rules are compiled into tiered sets by file type. Typed scans run the tier
/// matching the target file type plus the `CrossFormat` tier. Untyped scans can
/// additionally include the `Raw` and residual `Unknown` tiers.
///
/// Scanners are cached per-thread to avoid expensive re-creation.
/// How a tier's compiled `Rules` are produced on first access.
///
/// One lazy path for both warm and cold: [`YaraEngine::build_tier`] reads the
/// tier's per-tier compiled cache file (`<dir>/<tier>.yrc`) if present, else
/// compiles just that tier from source and writes the file. So a run only ever
/// compiles or holds the tiers it actually scans — never all ~14k rules at once
/// — and the cache fills in incrementally as file types are seen. `sources` is
/// collected (rule text read + classified) lazily on the first cache miss, so a
/// fully-warm process never touches rule text at all.
#[derive(Debug)]
enum TierSource {
    /// No rules available, or tier cells are externally pre-filled (a pre-set
    /// `OnceLock` cell is returned directly, so `build_tier` is never reached).
    Empty,
    /// Compile-or-load each tier on demand.
    Lazy {
        /// Per-tier compiled-cache directory (`None` = caching disabled).
        cache_dir: Option<std::path::PathBuf>,
        traits_dir: std::path::PathBuf,
        third_party_dir: std::path::PathBuf,
        enable_third_party: bool,
        /// Per-bucket rule source, collected on the first cache miss. Keyed by
        /// filetype string (or [`FALLBACK_BUCKET`]).
        sources: OnceLock<HashMap<String, Vec<(String, String)>>>,
    },
}

/// Metadata persisted alongside the per-tier compiled rule files. Lets a warm
/// start restore counts/contexts/namespaces without reading or classifying any
/// rule text — the tiers themselves load lazily from their `.yrc` files.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct YaraManifest {
    builtin_count: usize,
    third_party_count: usize,
    inline_namespaces: Vec<String>,
    #[serde(default)]
    rule_contexts: HashMap<String, RuleContext>,
    /// Labels of tiers that carry at least one rule.
    populated_tiers: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct YaraEngine {
    /// Per-bucket compiled rule sets, materialized lazily. The map is keyed by
    /// filetype string (e.g. "pe", "docx") plus [`FALLBACK_BUCKET`]; it is
    /// pre-keyed from [`Self::populated_tiers`] at load. Each cell is built on
    /// first access via [`YaraEngine::tier_rules`] from [`Self::source`]. `None`
    /// = bucket has no rules.
    tiers: HashMap<String, OnceLock<Option<yara_x::Rules>>>,
    /// Backing source for lazy bucket construction.
    source: TierSource,
    /// Buckets that actually carry rules — lets scans skip empty buckets and
    /// `is_empty`/scan-gating work without forcing every cell to build.
    populated_tiers: std::collections::HashSet<String>,
    /// (builtin, third_party) rule counts recorded at load, so `total_rules`
    /// doesn't have to materialize every tier.
    rule_counts: (usize, usize),
    /// Full-rule-derived sidecar metadata keyed by `(namespace, rule_name)`.
    rule_contexts: HashMap<String, RuleContext>,
    /// Namespaces compiled into the combined engine from inline trait YARA conditions.
    /// Used to split scan results: inline matches (keyed here) go to trait evaluation;
    /// all other matches are returned as regular YARA findings.
    compiled_inline_namespaces: Vec<String>,
}

impl YaraEngine {
    /// An empty tier map pre-keyed with one `OnceLock` per bucket key.
    /// Keys are filetype strings (or [`FALLBACK_BUCKET`]) that actually carry
    /// rules — bucket keys cannot be pre-enumerated, so they are seeded from the
    /// populated set discovered at load.
    fn tier_cells<'a>(
        keys: impl IntoIterator<Item = &'a str>,
    ) -> HashMap<String, OnceLock<Option<yara_x::Rules>>> {
        keys.into_iter()
            .map(|k| (k.to_string(), OnceLock::new()))
            .collect()
    }

    /// Lazily materialize the compiled rules for `bucket`, building from
    /// [`Self::source`] on first access. Thread-safe: concurrent first-touch
    /// callers block on the cell until the winner finishes. Returns `None` for
    /// a bucket that was never populated.
    fn tier_rules(&self, bucket: &str) -> Option<&yara_x::Rules> {
        self.tiers
            .get(bucket)?
            .get_or_init(|| self.build_tier(bucket))
            .as_ref()
    }

    /// Compile or deserialize one bucket's rules. Single-bucket work only (no
    /// inner rayon), so it is safe to call from a rayon worker during a scan.
    fn build_tier(&self, bucket: &str) -> Option<yara_x::Rules> {
        let TierSource::Lazy {
            cache_dir,
            traits_dir,
            third_party_dir,
            enable_third_party,
            sources,
        } = &self.source
        else {
            // Empty, or Compiled (cells externally pre-filled by a test helper).
            return None;
        };

        // 1. Per-bucket compiled cache file — deserialize + re-JIT just this one.
        if let Some(dir) = cache_dir {
            let path = dir.join(format!("{bucket}.yrc"));
            if let Ok(bytes) = std::fs::read(&path) {
                match yara_x::Rules::deserialize(&bytes) {
                    Ok(rules) => return Some(rules),
                    Err(e) => {
                        tracing::warn!(bucket = %bucket, error = ?e, "bucket cache deserialize failed; recompiling");
                    }
                }
            }
        }

        // 2. Cache miss — compile just this bucket from source. The rule text is
        //    read + classified once, lazily, and shared across buckets.
        let sources = sources.get_or_init(|| {
            Self::collect_all_sources(traits_dir, third_party_dir, *enable_third_party).0
        });
        let bucket_sources = sources.get(bucket)?;
        if bucket_sources.is_empty() {
            return None;
        }
        let mut compiler = yara_x::Compiler::new();
        for (ns, src) in bucket_sources {
            compiler.new_namespace(ns);
            if let Err(e) = compiler.add_source(src.as_bytes()) {
                tracing::warn!("Bucket {bucket}: failed to add source: {:?}", e);
            }
        }
        let rules = compiler.build();

        // 3. Write the compiled bucket back to the cache (best effort, atomic)
        //    so later scans and processes skip the compile.
        if let Some(dir) = cache_dir
            && let Ok(bytes) = rules.serialize()
            && std::fs::create_dir_all(dir).is_ok()
        {
            let tmp = dir.join(format!("{bucket}.yrc.tmp.{}", std::process::id()));
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, dir.join(format!("{bucket}.yrc")));
            }
        }
        Some(rules)
    }

    /// Collect rule source per tier (plus contexts/namespaces/counts) — the
    /// cheap text read + classify pass shared by the cold load and the lazy
    /// per-tier compile. Compiles nothing.
    fn collect_all_sources(
        traits_dir: &Path,
        third_party_dir: &Path,
        enable_third_party: bool,
    ) -> (
        HashMap<String, Vec<(String, String)>>,
        HashMap<String, RuleContext>,
        Vec<String>,
        usize,
        usize,
    ) {
        let (mut inline_tier_sources, inline_namespaces) = if traits_dir.exists() {
            Self::collect_inline_trait_sources_tiered(traits_dir)
        } else {
            (HashMap::new(), Vec::new())
        };
        let (mut builtin_tier_sources, builtin_contexts, builtin_count) = if traits_dir.exists() {
            Self::collect_builtin_sources_tiered(traits_dir)
        } else {
            (HashMap::new(), HashMap::new(), 0)
        };
        let (mut tier_sources, third_party_contexts, third_party_count, _vt, _disabled) =
            if enable_third_party && third_party_dir.exists() {
                Self::collect_third_party_sources_tiered(third_party_dir)
            } else {
                (HashMap::new(), HashMap::new(), 0, 0, 0)
            };

        let mut rule_contexts = builtin_contexts;
        rule_contexts.extend(third_party_contexts);
        for (tier, s) in builtin_tier_sources.drain() {
            tier_sources.entry(tier).or_default().extend(s);
        }
        for (tier, s) in inline_tier_sources.drain() {
            tier_sources.entry(tier).or_default().extend(s);
        }

        (
            tier_sources,
            rule_contexts,
            inline_namespaces,
            builtin_count,
            third_party_count,
        )
    }

    fn read_manifest(dir: &Path) -> Option<YaraManifest> {
        let bytes = std::fs::read(dir.join("manifest.json")).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn write_manifest(dir: &Path, manifest: &YaraManifest) {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
        if let Ok(bytes) = serde_json::to_vec(manifest) {
            let tmp = dir.join(format!("manifest.json.tmp.{}", std::process::id()));
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, dir.join("manifest.json"));
            }
        }
    }

    /// Offline pre-compilation: read + classify all rule sources, compile each
    /// populated per-filetype tier with `yara_x`, and write `<tier>.yrc` +
    /// `manifest.json` into `out_dir`. This is the producer side run by the
    /// `yara-precompile` tool at trait-package build time; the resulting `.yrc`
    /// are portable across arch/OS (they hold WASM bytecode, re-JIT'd per host)
    /// and are loaded at runtime without any in-process compilation.
    ///
    /// Returns `(builtin_count, third_party_count)`.
    pub(crate) fn precompile_to(
        out_dir: &Path,
        enable_third_party: bool,
    ) -> anyhow::Result<(usize, usize)> {
        use anyhow::Context;
        let traits_dir = crate::cache::traits_path();
        let third_party_dir = crate::cache::third_party_path();
        let (tier_sources, rule_contexts, inline_namespaces, builtin_count, third_party_count) =
            Self::collect_all_sources(&traits_dir, &third_party_dir, enable_third_party);

        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("create out dir {}", out_dir.display()))?;

        // Compile populated buckets in parallel; each yields its serialized
        // bytes (compact WASM), so only one bucket's compiler is live per rayon
        // task.
        let compiled: Vec<(String, Vec<u8>)> = tier_sources
            .par_iter()
            .filter(|(_, s)| !s.is_empty())
            .filter_map(|(bucket, sources)| {
                let mut compiler = yara_x::Compiler::new();
                for (ns, src) in sources {
                    compiler.new_namespace(ns);
                    if let Err(e) = compiler.add_source(src.as_bytes()) {
                        tracing::warn!("precompile bucket {bucket}: add_source: {:?}", e);
                    }
                }
                match compiler.build().serialize() {
                    Ok(bytes) => Some((bucket.clone(), bytes)),
                    Err(e) => {
                        tracing::warn!("precompile bucket {bucket}: serialize failed: {e}");
                        None
                    }
                }
            })
            .collect();

        let mut populated_tiers = Vec::with_capacity(compiled.len());
        for (bucket, bytes) in &compiled {
            std::fs::write(out_dir.join(format!("{bucket}.yrc")), bytes)
                .with_context(|| format!("write {bucket}.yrc"))?;
            populated_tiers.push(bucket.clone());
        }
        populated_tiers.sort();

        let builtin_count = builtin_count + inline_namespaces.len();
        Self::write_manifest(
            out_dir,
            &YaraManifest {
                builtin_count,
                third_party_count,
                inline_namespaces,
                rule_contexts,
                populated_tiers,
            },
        );
        Ok((builtin_count, third_party_count))
    }

    /// Total number of YARA rules loaded (recorded at load; does not force
    /// lazy tiers to materialize).
    #[must_use]
    pub(crate) fn total_rules(&self) -> usize {
        self.rule_counts.0 + self.rule_counts.1
    }

    /// Bucket keys a scan with `file_type_filter` should load, intersected with
    /// the populated set.
    ///
    /// A concrete filter loads the buckets named by its filetype strings plus
    /// the always-on [`FALLBACK_BUCKET`]. An unfiltered scan (unknown/untyped
    /// input, and the test path) loads every populated bucket — bucket-agnostic,
    /// so it does not depend on how rules are routed.
    fn buckets_to_scan(&self, file_type_filter: Option<&[&str]>) -> Vec<String> {
        match file_type_filter {
            Some(types) => {
                let mut buckets: Vec<String> = types
                    .iter()
                    .map(|ft| ft.to_ascii_lowercase())
                    .chain(std::iter::once(FALLBACK_BUCKET.to_string()))
                    .filter(|b| self.populated_tiers.contains(b))
                    .collect();
                buckets.sort();
                buckets.dedup();
                buckets
            }
            None => self.populated_tiers.iter().cloned().collect(),
        }
    }

    /// Eagerly materialize the buckets a scan with `file_type_filter` would use.
    ///
    /// This only fills cold `OnceLock`s; already-materialized buckets return
    /// immediately. Callers use this to overlap cache deserialization with other
    /// structural analysis before the actual YARA scan reaches the same buckets.
    pub(crate) fn prewarm_filetypes(&self, file_type_filter: Option<&[&str]>) {
        let buckets_to_warm: Vec<String> = self
            .buckets_to_scan(file_type_filter)
            .into_iter()
            .filter(|bucket| {
                self.tiers
                    .get(bucket)
                    .is_some_and(|cell| cell.get().is_none())
            })
            .collect();
        if buckets_to_warm.is_empty() {
            return;
        }

        let started = std::time::Instant::now();
        // Build the cold buckets SEQUENTIALLY when called from a rayon worker.
        //
        // `tier_rules` materializes a bucket through its `OnceLock::get_or_init`,
        // which parks contending callers on a futex — OUTSIDE rayon's cooperative
        // scheduler. A nested `par_iter` here spawns the per-bucket builds as
        // separate rayon jobs, then blocks the caller in the par_iter join waiting
        // for them; but archive-member analysis already calls in here from the
        // pool, so under a cold-start burst every worker ends up parked on a cold
        // cell or in a join, and the spawned builds have no thread left to run on
        // — a permanent wedge. Sequential warming has no such jobs: each
        // `get_or_init` winner builds inline on its own live thread and always
        // completes, so waiters are guaranteed to be released. Lazy per-filetype
        // loading is unchanged — only the buckets this scan needs are touched.
        //
        // Off the pool (no rayon worker context) the nested fan-out is safe, so a
        // bulk warm there may still parallelize.
        if buckets_to_warm.len() == 1 || rayon::current_thread_index().is_some() {
            for bucket in &buckets_to_warm {
                let _ = self.tier_rules(bucket);
            }
        } else {
            buckets_to_warm.par_iter().for_each(|bucket| {
                let _ = self.tier_rules(bucket);
            });
        }
        tracing::debug!(
            buckets = ?buckets_to_warm,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "prewarmed YARA buckets"
        );
    }

    /// Create a new YARA engine without rules loaded
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            tiers: HashMap::new(),
            source: TierSource::Empty,
            populated_tiers: std::collections::HashSet::new(),
            rule_counts: (0, 0),
            rule_contexts: HashMap::new(),
            compiled_inline_namespaces: Vec::new(),
        }
    }

    /// Create a new YARA engine with a pre-existing capability mapper (avoids duplicate loading)
    #[must_use]
    #[allow(dead_code)] // Used by binary target (commands/analyze.rs) and tests
    pub(crate) fn new_with_mapper(_capability_mapper: CapabilityMapper) -> Self {
        Self::new()
    }

    /// Create a new YARA engine for testing (without validation)
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_for_test() -> Self {
        Self::new()
    }

    /// Load all YARA rules (built-in from traits/ + optionally third-party from third_party/)
    /// Uses cache if available and valid.
    ///
    /// Rules are compiled into separate per-tier `yara_x::Rules` sets:
    /// - **CrossFormat**: built-in rules + inline trait YARA + intentionally broad rules
    /// - **Raw**: explicit raw/blob/shellcode rules that exclude normal container magic
    /// - **Pe/Elf/MachO/ScriptJs/Script/Doc**: rules classified by file type
    /// - **Unknown**: residual third-party rules still needing audit
    ///
    /// Each typed scan runs the tier matching the target + CrossFormat. Unknown
    /// rules are only scanned when the target file type is itself unknown.
    ///
    /// Environment variables:
    /// - `CLEAVE_SKIP_YARA=1`: Skip YARA entirely (for fast unit tests)
    /// - `CLEAVE_BUILTIN_YARA_ONLY=1`: Load only built-in rules, skip third-party (~500 vs 14k)
    /// - `CLEAVE_MINIMAL_RULES=1`: Load only essential rules (~100 instead of 14k)
    pub(crate) fn load_all_rules(&mut self, enable_third_party: bool) -> (usize, usize) {
        let _span = tracing::info_span!("load_yara_rules").entered();

        // Fast path: skip YARA entirely for tests that don't need it
        if skip_yara_active() {
            tracing::info!("YARA skipped (CLEAVE_SKIP_YARA or override)");
            return (0, 0);
        }

        // Tests that need YARA but not 14k rules can disable third-party rules
        // via env var or `set_builtin_yara_only_override`.
        let enable_third_party = enable_third_party && !builtin_yara_only_active();

        self.tiers = HashMap::new();
        self.populated_tiers.clear();
        self.source = TierSource::Empty;
        self.rule_counts = (0, 0);
        self.rule_contexts.clear();
        self.compiled_inline_namespaces.clear();
        YARA_SCANS_DISABLED_AFTER_PANIC.store(false, Ordering::Relaxed);

        tracing::info!("Loading YARA rules");

        let traits_dir = crate::cache::traits_path();
        let third_party_dir = crate::cache::third_party_path();
        // Pre-compiled rules shipped with the traits (produced by
        // `yara-precompile` into `third-party/compiled/`) take precedence: a
        // load-only path with no in-process compilation. They're portable
        // across arch/OS, so one build serves every client.
        let shipped = third_party_dir.join("compiled");
        let cache_dir = if Self::read_manifest(&shipped).is_some() {
            tracing::info!(
                "Using shipped pre-compiled YARA rules at {}",
                shipped.display()
            );
            Some(shipped)
        } else if crate::cache::skip_yara_cache() {
            tracing::info!("Skipping YARA cache (CLEAVE_SKIP_YARA_CACHE / CLEAVE_SKIP_CACHE)");
            None
        } else {
            crate::cache::yara_cache_path(enable_third_party).ok()
        };

        // Warm path: a manifest restores counts/contexts/namespaces without
        // reading any rule text; each tier compiles or deserializes lazily on
        // the first scan that needs it (see `build_tier`), so only the tiers a
        // run actually touches ever allocate.
        if let Some(dir) = &cache_dir
            && let Some(manifest) = Self::read_manifest(dir)
        {
            self.rule_counts = (manifest.builtin_count, manifest.third_party_count);
            self.rule_contexts = manifest.rule_contexts;
            self.compiled_inline_namespaces = manifest.inline_namespaces;
            self.tiers = Self::tier_cells(manifest.populated_tiers.iter().map(String::as_str));
            self.populated_tiers = manifest.populated_tiers.into_iter().collect();
            self.source = TierSource::Lazy {
                cache_dir: cache_dir.clone(),
                traits_dir,
                third_party_dir,
                enable_third_party,
                sources: OnceLock::new(),
            };
            tracing::info!(
                buckets = self.populated_tiers.len(),
                "Loaded YARA manifest (buckets compile lazily on first scan)"
            );
            return self.rule_counts;
        }

        // Cold path: read + classify rule text (cheap), record metadata, write
        // the manifest. Compile nothing here — each tier compiles lazily and
        // caches itself per-tier on the first scan that needs it.
        tracing::info!("Collecting YARA rule sources (tiers compile lazily on first scan)");
        let (tier_sources, rule_contexts, inline_namespaces, builtin_count, third_party_count) =
            Self::collect_all_sources(&traits_dir, &third_party_dir, enable_third_party);

        if builtin_count + third_party_count + inline_namespaces.len() == 0 {
            eprintln!("\n⚠️  No YARA rules loaded");
            return (0, 0);
        }

        self.rule_contexts = rule_contexts;
        self.compiled_inline_namespaces = inline_namespaces.clone();
        self.populated_tiers = tier_sources
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(t, _)| t.clone())
            .collect();
        self.tiers = Self::tier_cells(self.populated_tiers.iter().map(String::as_str));
        // Inline trait rules are folded into the built-in tally for reporting.
        let builtin_count = builtin_count + inline_namespaces.len();
        self.rule_counts = (builtin_count, third_party_count);

        if let Some(dir) = &cache_dir {
            Self::write_manifest(
                dir,
                &YaraManifest {
                    builtin_count,
                    third_party_count,
                    inline_namespaces,
                    rule_contexts: self.rule_contexts.clone(),
                    populated_tiers: self.populated_tiers.iter().cloned().collect(),
                },
            );
            let _ = crate::cache::cleanup_old_caches(dir);
        }

        // Pre-fill the lazy source cell so the first scan compiles straight from
        // memory instead of re-reading the rule files.
        let sources = OnceLock::new();
        let _ = sources.set(tier_sources);
        self.source = TierSource::Lazy {
            cache_dir,
            traits_dir,
            third_party_dir,
            enable_third_party,
            sources,
        };

        (builtin_count, third_party_count)
    }

    fn yaml_string_list(value: Option<&serde_yaml::Value>) -> Vec<String> {
        match value {
            Some(serde_yaml::Value::Sequence(seq)) => seq
                .iter()
                .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                .collect(),
            Some(serde_yaml::Value::String(s)) => vec![s.to_string()],
            _ => Vec::new(),
        }
    }

    fn extract_rule_name_from_source(source: &str) -> Option<String> {
        let re = rule_start_re()?;
        let caps = re.captures(source)?;
        caps.get(3).map(|m| m.as_str().to_string())
    }

    /// Determine the filetype buckets an inline trait YARA rule belongs in.
    ///
    /// Explicit `for:` filetypes (drawn from the same vocabulary as
    /// [`crate::analyzers::FileTypeExt::yara_filetypes`]) take priority and are
    /// used verbatim. Otherwise the rule's derived [`RuleContext`] filetypes are
    /// used, falling back to [`FALLBACK_BUCKET`] when nothing constrains it.
    fn classify_inline_trait_yara_tiers(
        source: &str,
        namespace: &str,
        declared_for: &[String],
    ) -> Vec<String> {
        let mut buckets: Vec<String> = declared_for
            .iter()
            .map(|ft| ft.trim().to_ascii_lowercase())
            .filter(|ft| !ft.is_empty() && ft != "none" && ft != "any" && ft != "all")
            .map(|ft| yara_classify::canonical_binary_filetype(&ft).to_string())
            .collect();
        if !buckets.is_empty() {
            let mut seen = std::collections::HashSet::new();
            buckets.retain(|ft| seen.insert(ft.clone()));
            return buckets;
        }

        if let Some(rule_name) = Self::extract_rule_name_from_source(source) {
            let context = Self::derive_rule_context(&rule_name, source, namespace);
            if !context.filetypes.is_empty() {
                return context.filetypes;
            }
        }

        vec![FALLBACK_BUCKET.to_string()]
    }

    /// Parse trait YAML files and collect all `type: yara` conditions into tiered source lists.
    ///
    /// Each rule is tagged with namespace `inline.{trait_id}` so that scan results
    /// can be mapped back to the originating trait during evaluation.
    fn collect_inline_trait_sources_tiered(
        traits_dir: &Path,
    ) -> (HashMap<String, Vec<(String, String)>>, Vec<String>) {
        let yaml_files: Vec<PathBuf> = WalkDir::new(traits_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let p = e.path();
                p.is_file()
                    && p.extension()
                        .map(|ext| ext == "yaml" || ext == "yml")
                        .unwrap_or(false)
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        let collect_one = |path: &PathBuf| {
            let Ok(content) = fs::read_to_string(path) else {
                return vec![];
            };
            let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
                return vec![];
            };

            let defaults_for = match &doc {
                serde_yaml::Value::Mapping(m) => {
                    Self::yaml_string_list(m.get("defaults").and_then(|v| v.get("for")))
                }
                _ => Vec::new(),
            };

            let items = match &doc {
                serde_yaml::Value::Mapping(m) => m
                    .get("traits")
                    .and_then(|v| v.as_sequence())
                    .map(|s| s.to_vec()),
                serde_yaml::Value::Sequence(s) => Some(s.clone()),
                _ => None,
            };

            let Some(items) = items else { return vec![] };

            let mut result = Vec::new();
            for item in &items {
                let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(if_cond) = item.get("if") else {
                    continue;
                };
                if if_cond.get("type").and_then(|v| v.as_str()) != Some("yara") {
                    continue;
                }
                let Some(source) = if_cond.get("source").and_then(|v| v.as_str()) else {
                    continue;
                };
                let item_for = Self::yaml_string_list(item.get("for"));
                let declared_for = if item_for.is_empty() {
                    defaults_for.clone()
                } else {
                    item_for
                };
                let namespace = format!("inline.{}", id);
                let buckets =
                    Self::classify_inline_trait_yara_tiers(source, &namespace, &declared_for);
                tracing::trace!("Collected inline YARA rule for trait {}", id);
                tracing::debug!(
                    trait_id = id,
                    buckets = ?buckets,
                    declared_for = ?declared_for,
                    "Classified inline YARA rule"
                );
                for bucket in buckets {
                    result.push((bucket, namespace.clone(), source.to_string()));
                }
            }
            result
        };

        // Read and parse YAML files in parallel unless already on a rayon
        // worker. Cold YARA init may happen from a library caller inside rayon;
        // starting another rayon pass there can starve the pool while peers wait
        // on the global YARA singleton.
        let collected: Vec<(String, String, String)> = if rayon::current_thread_index().is_some() {
            yaml_files.iter().flat_map(collect_one).collect()
        } else {
            yaml_files.par_iter().flat_map(collect_one).collect()
        };

        let mut tier_sources: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut namespaces = Vec::with_capacity(collected.len());
        for (bucket, namespace, source) in collected {
            namespaces.push(namespace.clone());
            tier_sources
                .entry(bucket)
                .or_default()
                .push((namespace, source));
        }
        namespaces.sort();
        namespaces.dedup();
        (tier_sources, namespaces)
    }

    /// Scan binary data and split results into regular YARA matches and inline trait results.
    ///
    /// Performs a staged scan:
    /// 1. **CrossFormat tier** — broad curated rules that intentionally apply across formats
    /// 2. **File-type tier(s)** — rules matching the target file type (PE, ELF, etc.)
    /// 3. **Raw tier** — explicit raw/blob rules for untyped inputs
    /// 4. **Unknown tier** — only when the target file type is unknown
    ///
    /// Scanners are cached per-thread to avoid expensive re-creation.
    ///
    /// Regular matches (non-`inline.*` namespaces) are returned as `Vec<YaraMatch>` for
    /// inclusion in the analysis report. Inline matches are returned as a
    /// `HashMap<String, Vec<Evidence>>` keyed by namespace (`"inline.{trait_id}"`), for use
    /// by trait evaluation via `EvaluationContext::inline_yara_results`.
    pub(crate) fn scan_bytes_with_inline(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<(Vec<YaraMatch>, HashMap<String, Vec<Evidence>>)> {
        let scan_start = std::time::Instant::now();
        if YARA_SCANS_DISABLED_AFTER_PANIC.load(Ordering::Relaxed) {
            anyhow::bail!(
                "YARA disabled after a prior panic; reload rules or restart to re-enable"
            );
        }
        if self.populated_tiers.is_empty() {
            anyhow::bail!("No YARA rules loaded");
        }

        // Determine which buckets to scan. A concrete file-type filter loads the
        // buckets named by its filetype strings plus the always-on fallback
        // bucket; an unfiltered scan (unknown/untyped input, and the test path)
        // scans every populated bucket — bucket-agnostic, so it does not depend
        // on how rules are routed.
        let buckets_to_scan = self.buckets_to_scan(file_type_filter);

        let inline_ns_set: std::collections::HashSet<&str> = self
            .compiled_inline_namespaces
            .iter()
            .map(String::as_str)
            .collect();

        tracing::debug!(buckets = buckets_to_scan.len(), "YARA scan starting");

        // Each bucket has its own compiled Rules, and Scanner only borrows
        // &Rules + &[u8], so buckets can scan concurrently on the same data
        // without contention. `tier_rules` materializes any not-yet-built bucket
        // on first touch (the common cache-hit path); the per-bucket `OnceLock`
        // makes that safe under this `par_iter` and across concurrent scans on
        // other workers.
        //
        // Small payloads scan their buckets sequentially. A tiny member's bucket
        // scan costs less than a rayon task's scheduling + steal exposure: under
        // member-level fan-out this is a third nesting level that floods a
        // saturated pool with micro-tasks, and any bucket task that blocks in a
        // join can steal an unrelated multi-second chunk onto its stack (observed:
        // 2 KB members "taking" seconds of wall under load). Sequential buckets
        // also keep one file's scans on one thread, so its scanner cache serves
        // every bucket without cross-thread churn. Tunable via
        // `CLEAVE_YARA_TIER_PARALLEL_MIN_BYTES`.
        let scan_one = |bucket: &String| {
            self.tier_rules(bucket).map(|rules| {
                let started = std::time::Instant::now();
                let result = Self::run_scanner(rules, data);
                (bucket.clone(), started.elapsed().as_millis() as u64, result)
            })
        };
        let all_raw: Vec<(String, u64, Result<Vec<RawRule>>)> =
            if data.len() < tier_parallel_min_bytes() {
                buckets_to_scan.iter().filter_map(scan_one).collect()
            } else {
                buckets_to_scan.par_iter().filter_map(scan_one).collect()
            };

        let mut yara_matches = Vec::new();
        let mut inline_results: HashMap<String, Vec<Evidence>> = HashMap::new();

        // Warn threshold: a single YARA bucket taking >30 s is beyond "large file, expected slow"
        // and enters "likely stuck in a pathological regex" territory. The 321 s .bat case fires
        // here per offending bucket, making it possible to attribute time without per-rule tracing.
        const SLOW_YARA_TIER_WARN_MS: u64 = 30_000;

        for (bucket, elapsed_ms, result) in all_raw {
            if elapsed_ms >= SLOW_YARA_TIER_WARN_MS {
                tracing::warn!(
                    bucket = %bucket,
                    elapsed_ms,
                    data_bytes = data.len(),
                    "YARA bucket scan exceeded slow threshold; \
                     set CLEAVE_BUILTIN_YARA_ONLY=1 to isolate third-party rules"
                );
            } else {
                tracing::debug!(bucket = %bucket, elapsed_ms, "YARA bucket scan finished");
            }
            let raw_rules = match result {
                Ok(rules) => rules,
                Err(e) => {
                    tracing::error!(bucket = %bucket, error = %e, "YARA bucket scan failed, skipping bucket");
                    continue;
                }
            };
            for raw in raw_rules {
                if inline_ns_set.contains(raw.namespace.as_str()) {
                    Self::collect_inline_evidence(&raw, data, &mut inline_results);
                    continue;
                }

                let yara_match = self.build_yara_match(
                    raw.name,
                    raw.namespace,
                    &raw.tags,
                    &raw.metadata,
                    &raw.patterns,
                    data,
                    file_type_filter,
                );
                if let Some(m) = yara_match {
                    yara_matches.push(m);
                }
            }
        }

        // Deduplicate evidence in inline results
        let inline_results: HashMap<String, Vec<Evidence>> = inline_results
            .into_iter()
            .map(|(k, v)| (k, deduplicate_evidence(v)))
            .collect();

        // Log bucket-level scan summary (rule count per bucket, not individual rules)
        if tracing::enabled!(tracing::Level::DEBUG) {
            for bucket in &buckets_to_scan {
                if let Some(rules) = self.tier_rules(bucket) {
                    tracing::debug!(
                        bucket = %bucket,
                        rules = rules.iter().count(),
                        "YARA scan set",
                    );
                }
            }
        }
        tracing::debug!(
            elapsed_ms = scan_start.elapsed().as_millis() as u64,
            buckets = buckets_to_scan.len(),
            matches = yara_matches.len(),
            inline_traits = inline_results.len(),
            "YARA scan complete",
        );

        Ok((yara_matches, inline_results))
    }

    /// Hard wall-clock limit for a single YARA scan. If yara-x's internal
    /// timeout fails to fire (e.g. stuck in a tight matching loop), this
    /// outer guard ensures the rayon thread is freed. Must be longer than the
    /// yara-x `set_timeout` value (20 min) to let the cooperative timeout fire
    /// first in normal cases.
    const YARA_WALL_CLOCK_LIMIT: std::time::Duration = std::time::Duration::from_secs(1260);

    /// Run a YARA scanner against data and collect raw match results.
    ///
    /// Scanners are cached per-thread to avoid expensive `Scanner::new()` calls.
    /// The cache is keyed by the `Rules` pointer address. This is safe because
    /// `Rules` live in `Arc<YaraEngine>` behind `OnceLock` statics for the
    /// program's duration.
    fn run_scanner(rules: &yara_x::Rules, data: &[u8]) -> Result<Vec<RawRule>> {
        use std::time::Duration;

        let key = rules as *const yara_x::Rules as usize;

        // Scan and collect results inside the thread-local borrow so ScanResults
        // (which borrows the Scanner) is consumed before the RefCell is released.
        ENGINE_SCANNER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache.get(&key).is_none() {
                // SAFETY: Rules are stored in Arc<YaraEngine> behind OnceLock statics
                // and live for the program's duration. Extending the borrow to 'static
                // is sound under this invariant.
                let rules_static: &'static yara_x::Rules =
                    unsafe { &*(rules as *const yara_x::Rules) };
                let mut s = yara_x::Scanner::new(rules_static);
                s.set_timeout(Duration::from_secs(1200));
                // Cap per-pattern matches at the same limit cleave collects.
                // yara-x's default is 1,000,000 — a pathological high-match
                // pattern would otherwise store that many `Match` structs in
                // native heap per scanner (GBs in-flight on dense inputs).
                // cleave only ever reads the first `MAX_PATTERN_MATCHES` ranges,
                // so storing more is pure waste. This also caps the count seen by
                // third-party rule conditions (`#a`); conditions relying on
                // counts >= MAX_PATTERN_MATCHES are not used in this deployment.
                s.max_matches_per_pattern(MAX_PATTERN_MATCHES);
                tracing::debug!("Created new YARA scanner for tier (ptr={:#x})", key);
                cache.put(key, s);
            }
            let Some(scanner) = cache.get_mut(&key) else {
                anyhow::bail!("scanner cache entry missing after insertion");
            };

            let scan_start = std::time::Instant::now();

            // Wrap the scan + result collection in catch_unwind so a panic
            // inside yara-x (e.g. deserialization bugs) becomes an Err
            // instead of poisoning the rayon thread pool.
            let raw_rules_result: Result<Vec<RawRule>> =
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let scan_result = scanner.scan(data);
                    match scan_result {
                        Err(e) => Err(anyhow::anyhow!("YARA scan failed: {:?}", e)),
                        Ok(scan_results) => {
                            let raw_rules: Vec<RawRule> = scan_results
                                .matching_rules()
                                .map(|rule| {
                                    let patterns: Vec<_> = rule
                                        .patterns()
                                        .map(|pat| {
                                            let total_matches = pat.matches().count();
                                            if total_matches > MAX_PATTERN_MATCHES {
                                                let inline_trait_id =
                                                    rule.namespace().strip_prefix("inline.");
                                                tracing::info!(
                                                    rule = %rule.identifier(),
                                                    namespace = %rule.namespace(),
                                                    pattern = %pat.identifier(),
                                                    matches = total_matches,
                                                    limit = MAX_PATTERN_MATCHES,
                                                    inline_trait_id,
                                                    "Hit YARA-pattern match limit; stopping early"
                                                );
                                            }
                                            let ranges: Vec<_> = pat
                                                .matches()
                                                .take(MAX_PATTERN_MATCHES)
                                                .map(|m| (m.range().start, m.range().end))
                                                .collect();
                                            (pat.identifier().to_string(), ranges)
                                        })
                                        .collect();
                                    RawRule {
                                        name: rule.identifier().to_string(),
                                        namespace: rule.namespace().to_string(),
                                        tags: rule
                                            .tags()
                                            .map(|t| t.identifier().to_string())
                                            .collect(),
                                        metadata: rule
                                            .metadata()
                                            .map(|(k, v)| (k.to_string(), format!("{:?}", v)))
                                            .collect(),
                                        patterns,
                                    }
                                })
                                .collect();
                            Ok(raw_rules)
                        }
                    }
                })) {
                    Ok(result) => result,
                    Err(panic_payload) => {
                        let msg = if let Some(s) = panic_payload.downcast_ref::<String>() {
                            s.clone()
                        } else if let Some(s) = panic_payload.downcast_ref::<&str>() {
                            (*s).to_string()
                        } else {
                            "unknown panic".to_string()
                        };
                        YARA_SCANS_DISABLED_AFTER_PANIC.store(true, Ordering::Relaxed);
                        tracing::error!(error = %msg, "YARA scan panicked");
                        Err(anyhow::anyhow!("YARA scan panicked: {}", msg))
                    }
                };
            let scan_elapsed = scan_start.elapsed();

            // Log any rule that exceeded 1s using yara-x built-in profiling
            // (rules-profiling feature is always enabled in Cargo.toml).
            if raw_rules_result.is_ok() {
                for pd in scanner.slowest_rules(20) {
                    let condition_ms = pd.condition_exec_time.as_millis() as u64;
                    let pattern_ms = pd.pattern_matching_time.as_millis() as u64;
                    if condition_ms + pattern_ms >= 1_000 {
                        let trait_id =
                            crate::third_party_yara::derive_trait_id(pd.namespace, pd.rule, None);
                        let disable_snippet = format!(
                            "- id: {trait_id}\n  disable: true\n  reason: \"Slow rule ({}ms)\"",
                            condition_ms + pattern_ms
                        );
                        tracing::warn!(
                            rule = pd.rule,
                            namespace = pd.namespace,
                            condition_ms,
                            pattern_ms,
                            disable_snippet,
                            "Slow YARA rule",
                        );
                    }
                }
                scanner.clear_profiling_data();
            }

            // Scanner/ScanResults borrow is now released. Evict the cached
            // scanner if the scan failed or took unreasonably long — yara-x may
            // not cleanly reset internal state after a timeout.
            if raw_rules_result.is_err() || scan_elapsed > Self::YARA_WALL_CLOCK_LIMIT {
                if scan_elapsed > Self::YARA_WALL_CLOCK_LIMIT {
                    tracing::error!(
                        elapsed_secs = scan_elapsed.as_secs(),
                        data_len = data.len(),
                        "YARA scan exceeded wall-clock limit; evicting cached scanner",
                    );
                } else if let Err(ref e) = raw_rules_result {
                    tracing::warn!(
                        elapsed_ms = scan_elapsed.as_millis() as u64,
                        data_len = data.len(),
                        error = %e,
                        "YARA scan failed; evicting cached scanner to prevent state corruption",
                    );
                }
                cache.pop(&key);
            }

            raw_rules_result
        })
    }

    /// Collect inline evidence from a raw rule match into the results map.
    fn collect_inline_evidence(
        raw: &RawRule,
        data: &[u8],
        inline_results: &mut HashMap<String, Vec<Evidence>>,
    ) {
        let evidence: Vec<Evidence> = raw
            .patterns
            .iter()
            .flat_map(|(_pattern_id, ranges)| {
                ranges.iter().map(|(start, end)| {
                    let match_len = end - start;
                    let value = if match_len <= 100 {
                        String::from_utf8_lossy(&data[*start..*end]).to_string()
                    } else {
                        format!("<{} bytes>", match_len)
                    };
                    Evidence {
                        method: "yara".to_string(),
                        source: "yara-x".to_string(),
                        value,
                        location: Some(format!("offset:0x{:x}", start)),
                        ..Default::default()
                    }
                })
            })
            .take(MAX_EVIDENCE_PER_TRAIT)
            .collect();
        let entry = inline_results.entry(raw.namespace.clone()).or_default();
        let remaining = MAX_EVIDENCE_PER_TRAIT.saturating_sub(entry.len());
        entry.extend(evidence.into_iter().take(remaining));
    }

    /// Collect built-in YARA rule sources from the traits directory, bucketing
    /// each rule by filetype with the same splitter used for third-party
    /// collections.
    ///
    /// Returns `(tier_sources, rule_contexts, builtin_file_count)`.
    fn collect_builtin_sources_tiered(
        dir: &Path,
    ) -> (
        HashMap<String, Vec<(String, String)>>,
        HashMap<String, RuleContext>,
        usize,
    ) {
        let third_party_dir = crate::cache::third_party_path();
        let rule_files: Vec<PathBuf> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                if path.starts_with(&third_party_dir) {
                    return false;
                }
                path.is_file()
                    && path
                        .extension()
                        .map(|ext| ext == "yar" || ext == "yara")
                        .unwrap_or(false)
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        tracing::debug!("Found {} built-in YARA rule files", rule_files.len());

        let Some(re) = rule_start_re() else {
            tracing::warn!(
                "failed to compile YARA rule-start regex; skipping built-in YARA preprocessing"
            );
            return (HashMap::new(), HashMap::new(), 0);
        };

        let process_one = |path: &PathBuf| {
            let bytes = fs::read(path).ok()?;
            let raw_source = String::from_utf8_lossy(&bytes);
            let source = yara_classify::inject_condition_filetype_hints(&raw_source);
            let split = Self::split_monolithic_by_tier(&source, "traits", re);
            tracing::trace!(
                path = %path.display(),
                buckets = ?split.tiers.keys().collect::<Vec<_>>(),
                "Collected built-in YARA source"
            );
            Some(split)
        };

        let processed: Vec<SplitSource> = if rayon::current_thread_index().is_some() {
            rule_files.iter().filter_map(process_one).collect()
        } else {
            rule_files.par_iter().filter_map(process_one).collect()
        };

        let mut tier_sources: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut rule_contexts: HashMap<String, RuleContext> = HashMap::new();
        let mut tier_counts: HashMap<String, usize> = HashMap::new();
        // Count actual public rules, not files: a single .yar file holds many rules.
        let mut rule_count = 0usize;

        for split in processed {
            rule_count += split.contexts.len();
            rule_contexts.extend(split.contexts);
            for (bucket, source) in split.tiers {
                *tier_counts.entry(bucket.clone()).or_insert(0) += 1;
                tier_sources
                    .entry(bucket)
                    .or_default()
                    .push(("traits".to_string(), source));
            }
        }

        for (bucket, count) in &tier_counts {
            tracing::info!("Built-in bucket {bucket}: {count} source(s)");
        }

        (tier_sources, rule_contexts, rule_count)
    }

    /// Collect third-party YARA rule sources, bucketing each rule by filetype.
    ///
    /// Small files (single-rule or few rules from one vendor) are classified as a whole.
    /// Large monolithic files (like YARAForge's single .yar with ~11K rules) are split
    /// per-rule so each rule goes to the correct bucket(s).
    ///
    /// Returns `(tier_sources, rule_contexts, total_source_count, vt_skipped, disabled_count)`.
    /// `tier_sources` maps each filetype bucket (or [`FALLBACK_BUCKET`]) to its
    /// list of `(namespace, source)` pairs.
    fn collect_third_party_sources_tiered(
        dir: &Path,
    ) -> (
        HashMap<String, Vec<(String, String)>>,
        HashMap<String, RuleContext>,
        usize,
        usize,
        usize,
    ) {
        let disabled_rules = crate::third_party_config::disabled_rule_ids();

        let rule_files: Vec<PathBuf> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                path.is_file()
                    && path
                        .extension()
                        .map(|e| e == "yar" || e == "yara")
                        .unwrap_or(false)
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        tracing::debug!("Found {} third-party YARA files", rule_files.len());

        let Some(re) = rule_start_re() else {
            tracing::warn!(
                "failed to compile YARA rule-start regex; skipping third-party YARA preprocessing"
            );
            return (HashMap::new(), HashMap::new(), 0, 0, 0);
        };

        struct Processed {
            path: PathBuf,
            namespace: String,
            split: SplitSource,
            vt_stripped: usize,
            disabled_stripped: usize,
        }

        let process_one = |path: &PathBuf| {
            let bytes = fs::read(path).ok()?;

            let namespace = path
                .strip_prefix(dir)
                .ok()
                .and_then(|rel| rel.to_str())
                .map(|s| {
                    let parts: Vec<&str> = s
                        .split(std::path::MAIN_SEPARATOR)
                        .filter(|p| !p.is_empty())
                        .collect();
                    let mut ns_parts = parts.to_vec();
                    if let Some(last) = ns_parts.last_mut() {
                        *last = last.trim_end_matches(".yar").trim_end_matches(".yara");
                    }
                    format!("3p.{}", ns_parts.join("."))
                })
                .unwrap_or_else(|| "3p".to_string());

            let raw_source = String::from_utf8_lossy(&bytes);

            let (raw_source, vt_stripped) = if raw_source.contains("vt.") {
                let (filtered, count) = Self::filter_vt_rules(&raw_source, re);
                (std::borrow::Cow::Owned(filtered), count)
            } else {
                (raw_source, 0)
            };

            if raw_source.trim().is_empty() {
                return None;
            }

            let source = yara_classify::inject_condition_filetype_hints(&raw_source);

            let (filtered_source, disabled_stripped) =
                Self::filter_disabled_rules(&source, &namespace, &disabled_rules, re);

            if filtered_source.trim().is_empty() {
                return None;
            }

            let split = Self::split_monolithic_by_tier(&filtered_source, &namespace, re);
            Some(Processed {
                path: path.clone(),
                namespace,
                split,
                vt_stripped,
                disabled_stripped,
            })
        };

        // Read and preprocess in parallel unless already on a rayon worker.
        // The transform is pure, but nested rayon here can deadlock cold YARA
        // initialization when other workers are waiting on the singleton.
        let processed: Vec<Processed> = if rayon::current_thread_index().is_some() {
            rule_files.iter().filter_map(process_one).collect()
        } else {
            rule_files.par_iter().filter_map(process_one).collect()
        };

        let mut tier_sources: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut rule_contexts: HashMap<String, RuleContext> = HashMap::new();
        // `fragments` counts per-bucket source splits (for diagnostics);
        // `rule_count` counts actual public rules — a monolithic pack holds
        // thousands per file.
        let mut fragments = 0;
        let mut rule_count = 0;
        let mut vt_skipped = 0;
        let mut disabled_count = 0;
        let mut tier_counts: HashMap<String, usize> = HashMap::new();

        for p in processed {
            if p.vt_stripped > 0 {
                tracing::debug!(
                    "{}: stripped {} rule(s) requiring VirusTotal context",
                    p.path.display(),
                    p.vt_stripped,
                );
            }
            vt_skipped += p.vt_stripped;
            disabled_count += p.disabled_stripped;
            rule_count += p.split.contexts.len();
            rule_contexts.extend(p.split.contexts);

            for (bucket, tier_source) in p.split.tiers {
                fragments += 1;
                *tier_counts.entry(bucket.clone()).or_insert(0) += 1;
                tier_sources
                    .entry(bucket)
                    .or_default()
                    .push((p.namespace.clone(), tier_source));
            }
        }

        for (bucket, count) in &tier_counts {
            tracing::info!("Third-party bucket {bucket}: {count} source(s)");
        }
        tracing::debug!(
            "Successfully added {} third-party YARA source(s) across {} bucket(s)",
            fragments,
            tier_counts.len().max(1),
        );

        (
            tier_sources,
            rule_contexts,
            rule_count,
            vt_skipped,
            disabled_count,
        )
    }

    fn derive_rule_context(rule_name: &str, rule_text: &str, namespace: &str) -> RuleContext {
        let lower = rule_text.to_ascii_lowercase();
        let tags = extract_header_tags_from_source(rule_text);
        let mut filetypes: Vec<String> = Vec::new();
        let mut filetype_source = "none".to_string();
        let mut os_meta: Option<String> = None;
        let mut arch_context: Option<String> = None;
        let mut metadata_hint_text = String::new();

        for line in lower.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with("filetype") || trimmed.starts_with("filetypes"))
                && trimmed.contains('=')
                && let Some(val) = trimmed.split('=').nth(1)
            {
                filetypes = val
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !filetypes.is_empty() {
                    filetype_source = "metadata".to_string();
                }
            }
            if trimmed.starts_with("os") && trimmed.contains('=') {
                let after_os = &trimmed[2..];
                if (after_os.starts_with(' ') || after_os.starts_with('='))
                    && let Some(val) = trimmed.split('=').nth(1)
                {
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    if !val.is_empty() {
                        os_meta = Some(val.to_string());
                    }
                }
            }
            if trimmed.starts_with("arch_context")
                && trimmed.contains('=')
                && let Some(val) = trimmed.split('=').nth(1)
            {
                let val = val.trim().trim_matches('"').trim_matches('\'');
                if !val.is_empty() {
                    arch_context = Some(val.to_string());
                }
            }
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                if matches!(
                    key,
                    "description"
                        | "source_url"
                        | "reference"
                        | "category"
                        | "classification"
                        | "threat_name"
                        | "scan_context"
                        | "tags"
                ) {
                    if !metadata_hint_text.is_empty() {
                        metadata_hint_text.push(' ');
                    }
                    metadata_hint_text.push_str(val.trim().trim_matches('"').trim_matches('\''));
                }
            }
        }

        // Strongest signal: the rule's own condition. A magic-byte check
        // (MZ / ELF / Mach-O / PDF / OLE / ZIP) or a YARA module reference
        // (`pe.` / `elf.` / `macho.` / `dotnet.`) pins the filetype regardless
        // of name or metadata, and catches rules with no naming signal at all.
        if filetypes.is_empty()
            && let Some(ft) = yara_classify::filetype_from_magic(&lower)
        {
            filetypes = vec![ft.to_string()];
            filetype_source = "condition".to_string();
        }
        // High-confidence string markers in the body (e.g. the `_CorExeMain`
        // .NET entry-point symbol) when there is no magic/module signal.
        if filetypes.is_empty() {
            let inferred = yara_classify::infer_filetypes_from_string_markers(&lower);
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "string-marker".to_string();
            }
        }
        if filetypes.is_empty() {
            let inferred = yara_classify::infer_filetypes_from_tags(&tags);
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "tag".to_string();
            }
        }
        if filetypes.is_empty() {
            let inferred = yara_classify::infer_filetypes_from_metadata_text(&metadata_hint_text);
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "metadata-text".to_string();
            }
        }
        if filetypes.is_empty() {
            let inferred = yara_classify::infer_filetypes(rule_name, os_meta.as_deref());
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "rule-name".to_string();
            }
        }
        if filetypes.is_empty() {
            let inferred =
                yara_classify::infer_filetypes_from_namespace(namespace, os_meta.as_deref());
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "namespace".to_string();
            }
        }
        // Last resort: curated rule-name → filetype overrides for known families
        // with no inferable signal. Anything still empty stays in `fallback`.
        if filetypes.is_empty() {
            let inferred = yara_classify::filetypes_from_override(rule_name);
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "override-table".to_string();
            }
        }

        // Collapse binary-format aliases (dll/exe -> pe, so/ko -> elf,
        // dylib/kext -> macho) so each rule lands in exactly one bucket. A scan
        // loads every alias of a detected type together, so separate alias
        // buckets would only duplicate the rule.
        for ft in &mut filetypes {
            let canon = yara_classify::canonical_binary_filetype(ft);
            if canon != ft.as_str() {
                *ft = canon.to_string();
            }
        }
        {
            let mut seen = std::collections::HashSet::new();
            filetypes.retain(|ft| seen.insert(ft.clone()));
        }

        let mut platforms: Vec<String> =
            crate::third_party_yara::platforms_from_name_and_os(rule_name, os_meta.as_deref())
                .iter()
                .map(platform_label)
                .map(std::string::ToString::to_string)
                .collect();

        if platforms.is_empty()
            && filetypes
                .iter()
                .any(|ft| matches!(ft.as_str(), "sh" | "bash" | "zsh"))
        {
            platforms.push("unix".to_string());
        }
        if platforms.is_empty() && looks_like_unix_shell_payload(&lower) {
            platforms.push("unix".to_string());
        }

        RuleContext {
            filetypes,
            filetype_source,
            platforms,
            os_meta,
            arch_context,
        }
    }

    /// Split a large monolithic YARA source into per-filetype-bucket chunks.
    ///
    /// Extracts import statements and private rules, then buckets each public
    /// rule by the filetype strings of its derived [`RuleContext`] (drawn from
    /// the same vocabulary as
    /// [`crate::analyzers::FileTypeExt::yara_filetypes`]). A rule with no
    /// filetype constraint lands in [`FALLBACK_BUCKET`] (always scanned). Private
    /// rules are duplicated into every bucket that has dependents (simplest
    /// approach since there are typically <30 private rules).
    fn split_monolithic_by_tier(
        source: &str,
        namespace: &str,
        rule_re: &regex::Regex,
    ) -> SplitSource {
        // Extract imports from top of file
        let mut imports = String::new();
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") {
                imports.push_str(line);
                imports.push('\n');
            }
            // Stop scanning for imports once we hit a rule
            if trimmed.starts_with("rule ") || trimmed.starts_with("private rule") {
                break;
            }
        }

        // Parse rule boundaries
        struct RuleInfo<'a> {
            start: usize,
            end: usize,
            name: &'a str,
            is_private: bool,
        }

        let mut rules: Vec<RuleInfo<'_>> = Vec::new();
        for cap in rule_re.captures_iter(source) {
            let (Some(name_match), Some(start_match)) = (cap.get(3), cap.get(0)) else {
                continue;
            };
            let name = name_match.as_str();
            let start = start_match.start();
            let is_private = cap
                .get(2)
                .map(|m| m.as_str().contains("private"))
                .unwrap_or(false);
            rules.push(RuleInfo {
                start,
                end: 0,
                name,
                is_private,
            });
        }

        // Fill end positions: each rule ends where the next begins
        let starts: Vec<usize> = rules.iter().map(|r| r.start).collect();
        for (i, rule) in rules.iter_mut().enumerate() {
            rule.end = starts.get(i + 1).copied().unwrap_or(source.len());
        }

        // Collect private rules (included in every tier)
        let private_chunk: String = rules
            .iter()
            .filter(|r| r.is_private)
            .map(|r| &source[r.start..r.end])
            .collect::<Vec<_>>()
            .join("\n");

        // Bucket each public rule into each of its filetype strings, or the
        // fallback bucket when it carries no filetype constraint.
        let mut tier_rules: HashMap<String, Vec<&str>> = HashMap::new();
        let mut contexts: HashMap<String, RuleContext> = HashMap::new();
        for r in &rules {
            if r.is_private {
                continue;
            }
            let rule_text = &source[r.start..r.end];
            let context = Self::derive_rule_context(r.name, rule_text, namespace);
            if context.filetypes.is_empty() {
                tier_rules
                    .entry(FALLBACK_BUCKET.to_string())
                    .or_default()
                    .push(rule_text);
            } else {
                for ft in &context.filetypes {
                    tier_rules
                        .entry(ft.to_ascii_lowercase())
                        .or_default()
                        .push(rule_text);
                }
            }
            contexts.insert(rule_context_key(namespace, r.name), context);
        }

        // Build per-bucket source strings
        let mut result: HashMap<String, String> = HashMap::new();
        for (bucket, rule_texts) in tier_rules {
            let mut s = String::with_capacity(imports.len() + private_chunk.len() + 4096);
            s.push_str(&imports);
            s.push('\n');
            if !private_chunk.is_empty() {
                s.push_str(&private_chunk);
                s.push('\n');
            }
            for text in rule_texts {
                s.push_str(text);
            }
            result.insert(bucket, s);
        }

        SplitSource {
            tiers: result,
            contexts,
        }
    }

    /// Filter out disabled rules from YARA source.
    /// Returns the filtered source and the count of removed rules.
    fn filter_disabled_rules(
        source: &str,
        namespace: &str,
        disabled_rules: &std::collections::HashSet<String>,
        re: &regex::Regex,
    ) -> (String, usize) {
        // Quick check: if no disabled rules, return as-is
        if disabled_rules.is_empty() {
            return (source.to_string(), 0);
        }

        let mut result = String::with_capacity(source.len());
        let mut last_end = 0;
        let mut removed = 0;

        // Find all rule starts and their positions
        let mut rule_ranges: Vec<(usize, usize, &str)> = Vec::new();
        for cap in re.captures_iter(source) {
            let (Some(rule_name_match), Some(rule_start_match)) = (cap.get(3), cap.get(0)) else {
                continue;
            };
            let rule_name = rule_name_match.as_str();
            let rule_start = rule_start_match.start();
            rule_ranges.push((rule_start, 0, rule_name)); // end will be filled later
        }

        // Fill in rule end positions (start of next rule or end of source)
        let range_starts: Vec<usize> = rule_ranges.iter().map(|r| r.0).collect();
        for (i, range) in rule_ranges.iter_mut().enumerate() {
            range.1 = range_starts.get(i + 1).copied().unwrap_or(source.len());
        }

        // Build filtered source
        for (start, end, rule_name) in rule_ranges {
            // Use trait_id format (third_party/vendor/...) for consistency with config
            let trait_id = crate::third_party_yara::derive_trait_id(namespace, rule_name, None);
            if disabled_rules.contains(&trait_id) {
                // Skip this rule - add any content before it that hasn't been added yet
                if start > last_end {
                    result.push_str(&source[last_end..start]);
                }
                last_end = end;
                removed += 1;
                tracing::debug!("Filtered disabled rule: {}", trait_id);
            }
        }

        // Add remaining content
        if last_end < source.len() {
            result.push_str(&source[last_end..]);
        }

        // If nothing was removed, return original to avoid allocation
        if removed == 0 {
            return (source.to_string(), 0);
        }

        (result, removed)
    }

    /// Strip individual rules that reference the VirusTotal module (`vt.`) from source.
    ///
    /// Returns the filtered source and the count of removed rules. Rules that don't
    /// reference `vt.` are preserved. This replaces the old whole-file skip which
    /// incorrectly dropped the entire YARAForge monolithic collection.
    fn filter_vt_rules(source: &str, re: &regex::Regex) -> (String, usize) {
        let mut rule_ranges: Vec<(usize, usize)> = Vec::new();
        for cap in re.captures_iter(source) {
            let Some(rule_start_match) = cap.get(0) else {
                continue;
            };
            let rule_start = rule_start_match.start();
            rule_ranges.push((rule_start, 0));
        }

        if rule_ranges.is_empty() {
            return (source.to_string(), 0);
        }

        // Fill end positions: each rule ends where the next begins
        let vt_starts: Vec<usize> = rule_ranges.iter().map(|r| r.0).collect();
        for (i, range) in rule_ranges.iter_mut().enumerate() {
            range.1 = vt_starts.get(i + 1).copied().unwrap_or(source.len());
        }

        let mut result = String::with_capacity(source.len());
        let mut last_end = 0;
        let mut removed = 0;

        for (start, end) in &rule_ranges {
            let rule_text = &source[*start..*end];
            if rule_text.contains("vt.") {
                // Skip this rule, keep content before it
                if *start > last_end {
                    result.push_str(&source[last_end..*start]);
                }
                last_end = *end;
                removed += 1;
            }
        }

        if removed == 0 {
            return (source.to_string(), 0);
        }

        if last_end < source.len() {
            result.push_str(&source[last_end..]);
        }

        (result, removed)
    }

    /// Extract namespace from file path with prefix
    #[allow(dead_code)] // Used by tests
    fn extract_namespace_with_prefix(&self, path: &Path, prefix: &str) -> String {
        let path_str = path.to_string_lossy();

        // Find the base directory (traits/ or third-party/)
        let search_str = if prefix == "third_party" {
            "third-party/"
        } else {
            "traits/"
        };

        if let Some(idx) = path_str.find(search_str) {
            let relative = &path_str[idx + search_str.len()..];

            // Remove filename and extension
            if let Some(parent) = Path::new(relative).parent() {
                let namespace_path = parent.to_string_lossy().replace('/', ".");
                return if namespace_path.is_empty() {
                    prefix.to_string()
                } else {
                    format!("{}.{}", prefix, namespace_path)
                };
            }
        }

        prefix.to_string()
    }

    /// Normalize a filetype string for use as a cache suffix
    /// Simplifies types like "application/x-sh" to "sh"
    #[allow(dead_code)] // Used by tests
    fn normalize_filetype_for_cache(filetype: &str) -> &str {
        // Remove MIME type prefixes
        if let Some(suffix) = filetype.strip_prefix("application/x-") {
            return suffix;
        }
        if let Some(suffix) = filetype.strip_prefix("text/x-") {
            return suffix;
        }
        // Return as-is for simple types
        filetype
    }

    /// Check if a YARA rule matches the given file types
    /// Parses the metadata section for "filetype" or "filetypes" fields
    #[allow(dead_code)] // Used by tests
    fn rule_matches_filetypes(source: &str, filter_types: &[&str]) -> bool {
        // If no metadata section, include the rule (no type restriction)
        if !source.contains("meta:") {
            return true;
        }

        // Simple text-based parsing for filetype metadata
        // Look for: filetype = "value" or filetypes = "value1,value2"
        for line in source.lines() {
            let trimmed = line.trim();

            // Single filetype
            if trimmed.starts_with("filetype")
                && trimmed.contains('=')
                && let Some(value_part) = trimmed.split('=').nth(1)
            {
                let value = value_part
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_lowercase();

                // Check if any filter type matches
                for filter_type in filter_types {
                    if value == filter_type.to_lowercase() {
                        return true;
                    }
                }
            }

            // Multiple filetypes (comma-separated)
            if trimmed.starts_with("filetypes")
                && trimmed.contains('=')
                && let Some(value_part) = trimmed.split('=').nth(1)
            {
                let value = value_part.trim().trim_matches('"').trim_matches('\'');

                // Split by comma and check each type
                for rule_type in value.split(',') {
                    let rule_type = rule_type.trim().to_lowercase();
                    for filter_type in filter_types {
                        if rule_type == filter_type.to_lowercase() {
                            return true;
                        }
                    }
                }
            }
        }

        // No matching filetype found, exclude the rule
        false
    }

    /// Scan a file with loaded YARA rules
    pub(crate) fn scan_file(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        if self.populated_tiers.is_empty() {
            anyhow::bail!("No YARA rules loaded");
        }

        let data =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;

        self.scan_bytes(&data)
    }

    /// Scan byte data with loaded YARA rules
    /// Optionally filter results by file type
    pub(crate) fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        self.scan_bytes_filtered(data, None)
    }

    /// Scan byte data with optional file type filtering.
    /// Inline YARA results (namespace `inline.*`) are silently discarded; use
    /// `scan_bytes_with_inline` when you need them for trait evaluation.
    pub(crate) fn scan_bytes_filtered(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<Vec<YaraMatch>> {
        let (matches, _inline) = self.scan_bytes_with_inline(data, file_type_filter)?;
        Ok(matches)
    }

    /// Build a `YaraMatch` from raw match data collected during scanning.
    /// Returns `None` if the rule is an inline trait rule (those go into `inline_results`).
    fn build_yara_match(
        &self,
        rule_name: String,
        namespace: String,
        tags: &[String],
        metadata: &[(String, String)],
        patterns: &[(String, Vec<(usize, usize)>)],
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Option<YaraMatch> {
        let mut description = String::new();
        let mut crit = "baseline".to_string();
        let mut capability_flag = false;
        let mut mbc_code: Option<String> = None;
        let mut attack_code: Option<String> = None;
        let mut rule_filetypes: Vec<String> = Vec::new();
        let mut filetype_source = "none".to_string(); // tracks where the filetype came from
        let mut os_meta: Option<String> = None;
        let mut arch_context_meta: Option<String> = None;
        let mut metadata_hint_text = String::new();

        for tag_name in tags {
            if matches!(
                tag_name.as_str(),
                "baseline" | "notable" | "suspicious" | "hostile"
            ) {
                crit = tag_name.clone();
                break;
            }
        }

        let is_third_party = namespace.starts_with("3p.");
        if is_third_party {
            crit = "suspicious".to_string();
        }

        for (key, value_str) in metadata {
            let value_str = if value_str.starts_with("String(\"") && value_str.ends_with("\")") {
                value_str[8..value_str.len() - 2].to_string()
            } else {
                value_str.trim_matches('"').to_string()
            };

            match key.as_str() {
                "description" => description = value_str,
                "risk" if !is_third_party => {
                    crit = value_str;
                }
                "capability" => {
                    capability_flag = value_str.to_lowercase() == "true" || value_str == "1";
                }
                "mbc" => mbc_code = Some(value_str),
                "attack" => attack_code = Some(value_str),
                "filetype" | "filetypes" => {
                    rule_filetypes = value_str
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .collect();
                    filetype_source = "metadata".to_string();
                }
                "os" => os_meta = Some(value_str.to_lowercase()),
                "arch_context" => arch_context_meta = Some(value_str.to_lowercase()),
                "source_url" | "reference" | "category" | "classification" | "threat_name"
                | "scan_context" | "tags" => {
                    if !metadata_hint_text.is_empty() {
                        metadata_hint_text.push(' ');
                    }
                    metadata_hint_text.push_str(&value_str);
                }
                _ => {}
            }
        }

        let context_key = rule_context_key(&namespace, &rule_name);
        let precompiled_context = self.rule_contexts.get(&context_key);

        if let Some(ctx) = precompiled_context {
            if !ctx.filetypes.is_empty() {
                rule_filetypes = ctx.filetypes.clone();
                filetype_source = format!("precompiled-{}", ctx.filetype_source);
            }
            if os_meta.is_none() {
                os_meta = ctx.os_meta.clone();
            }
            if arch_context_meta.is_none() {
                arch_context_meta = ctx.arch_context.clone();
            }
            if !ctx.platforms.is_empty() {
                tracing::debug!(
                    rule = %rule_name,
                    namespace = %namespace,
                    platforms = ?ctx.platforms,
                    "YARA rule platform association"
                );
            }
        } else {
            // Infer filetypes from explicit rule tags (e.g., `: PE`, `: ELF`, `: PHP`)
            if rule_filetypes.is_empty() {
                let inferred = yara_classify::infer_filetypes_from_tags(tags);
                if !inferred.is_empty() {
                    rule_filetypes = inferred
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    filetype_source = "tag".to_string();
                }
            }

            if rule_filetypes.is_empty() {
                let inferred =
                    yara_classify::infer_filetypes_from_metadata_text(&metadata_hint_text);
                if !inferred.is_empty() {
                    rule_filetypes = inferred
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    filetype_source = "metadata-text".to_string();
                }
            }

            if rule_filetypes.is_empty() {
                let inferred = yara_classify::infer_filetypes(&rule_name, os_meta.as_deref());
                if !inferred.is_empty() {
                    rule_filetypes = inferred
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    filetype_source = "rule-name".to_string();
                }
            }

            // For third-party rules: if still no filetype, try the namespace filename component.
            if rule_filetypes.is_empty() && is_third_party {
                let inferred =
                    yara_classify::infer_filetypes_from_namespace(&namespace, os_meta.as_deref());
                if !inferred.is_empty() {
                    rule_filetypes = inferred
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    filetype_source = "namespace".to_string();
                }
            }
        }

        // Log filetype association for verbose output
        crate::third_party_yara::log_filetype_association(
            &rule_name,
            &namespace,
            &rule_filetypes,
            &filetype_source,
        );

        if let Some(filter_types) = file_type_filter
            && !rule_filetypes.is_empty()
        {
            let matches_filter = rule_filetypes.iter().any(|rule_type| {
                filter_types
                    .iter()
                    .any(|ft| rule_type == &ft.to_lowercase())
            });
            if !matches_filter {
                tracing::warn!(
                    rule = %rule_name,
                    rule_targets = ?rule_filetypes,
                    scanning = ?filter_types,
                    "YARA rule filtered: targets {:?}, not applicable to {:?}",
                    rule_filetypes,
                    filter_types,
                );
                return None;
            }
        }

        let mut matched_strings = Vec::new();
        'outer: for (pattern_id, ranges) in patterns {
            for (start, end) in ranges {
                if matched_strings.len() >= MAX_EVIDENCE_PER_TRAIT {
                    break 'outer;
                }
                let match_len = end - start;
                let value = if match_len <= 100 {
                    String::from_utf8_lossy(&data[*start..*end]).to_string()
                } else {
                    format!("<{} bytes>", match_len)
                };
                matched_strings.push(MatchedString {
                    identifier: pattern_id.clone(),
                    offset: *start as u64,
                    value,
                });
            }
        }

        let is_capability = capability_flag || mbc_code.is_some() || attack_code.is_some();
        let trait_id = if is_third_party {
            Some(crate::third_party_yara::derive_trait_id(
                &namespace,
                &rule_name,
                os_meta.as_deref(),
            ))
        } else {
            None
        };

        // Apply config-based criticality for third-party rules
        // Returns None if the rule is disabled via config
        if is_third_party {
            // Returns None (via `?`) if the rule is disabled via config.
            crit = crate::third_party_config::third_party_criticality(
                &namespace,
                trait_id.as_deref(),
            )?;
        }

        Some(YaraMatch {
            rule: rule_name,
            namespace,
            crit,
            desc: description,
            matched_strings,
            is_capability,
            mbc: mbc_code,
            attack: attack_code,
            trait_id,
            arch_context: arch_context_meta,
        })
    }

    /// Check if rules are loaded
    #[must_use]
    pub(crate) fn is_loaded(&self) -> bool {
        !self.populated_tiers.is_empty()
    }

    /// Map YARA match to capability evidence
    #[must_use]
    pub(crate) fn yara_match_to_evidence(&self, yara_match: &YaraMatch) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        for matched_str in &yara_match.matched_strings {
            // Use actual matched value if printable, otherwise use identifier
            let is_printable = matched_str
                .value
                .bytes()
                .all(|b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t');
            let evidence_value = if is_printable && !matched_str.value.is_empty() {
                matched_str.value.clone()
            } else {
                matched_str.identifier.clone()
            };

            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: evidence_value,
                location: Some(format!("offset:0x{:x}", matched_str.offset)),
                ..Default::default()
            });
        }

        // If no specific strings matched, add general evidence
        if evidence.is_empty() {
            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: yara_match.rule.clone(),
                location: Some(yara_match.namespace.clone()),
                ..Default::default()
            });
        }

        evidence
    }

    /// Map YARA namespace to capability ID
    /// Returns the capability ID if the namespace maps to a known capability
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn namespace_to_capability(&self, namespace: &str) -> Option<String> {
        // YARA namespace format: exec.cmd, anti-static.obfuscation, etc.
        // Convert to capability ID: execution/command, anti-analysis/obfuscation
        let parts: Vec<&str> = namespace.split('.').collect();

        match parts.as_slice() {
            ["exec", "cmd"] | ["exec", "shell"] => Some("execution/command/shell".to_string()),
            ["exec", "program"] => Some("execution/command/direct".to_string()),
            ["net", sub] => Some(format!("net/{}", sub)),
            ["crypto", sub] => Some(format!("crypto/{}", sub)),
            ["fs", sub] => Some(format!("fs/{}", sub)),
            ["anti-static", "obfuscation"] => Some("anti-analysis/obfuscation".to_string()),
            ["process", sub] => Some(format!("process/{}", sub)),
            ["credential", sub] => Some(format!("credential/{}", sub)),
            // For third-party rules, use the namespace directly as the capability
            _ if !namespace.is_empty() => Some(namespace.replace('.', "/")),
            _ => None,
        }
    }

    /// Scan a file and return both YARA matches and derived findings
    /// This is the main entry point for universal YARA scanning
    #[allow(dead_code)]
    pub(crate) fn scan_bytes_to_findings(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<(Vec<YaraMatch>, Vec<crate::types::Finding>)> {
        use crate::types::{Criticality, Finding, FindingKind};

        let matches = self.scan_bytes_filtered(data, file_type_filter)?;
        let mut findings = Vec::new();

        for yara_match in &matches {
            // Skip filtered matches
            if yara_match.crit == "filtered" {
                continue;
            }

            // Use derived trait_id for third-party rules, otherwise map namespace to capability
            let finding_id = yara_match
                .trait_id
                .clone()
                .or_else(|| self.namespace_to_capability(&yara_match.namespace));

            if let Some(cap_id) = finding_id {
                let evidence = self.yara_match_to_evidence(yara_match);

                let criticality = match yara_match.crit.as_str() {
                    "hostile" => Criticality::Hostile,
                    "suspicious" => Criticality::Suspicious,
                    "notable" => Criticality::Notable,
                    _ => Criticality::Baseline,
                };

                findings.push(Finding {
                    src: None,
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: cap_id.into(),
                    desc: yara_match.desc.clone().into(),
                    conf: 0.9,
                    crit: criticality,
                    mbc: yara_match.mbc.clone(),
                    attack: yara_match.attack.clone(),
                    evidence,
                    match_count: 0,
                    source_file: None,
                });
            }
        }

        Ok((matches, findings))
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl YaraEngine {
    /// Compile YARA rules from source text into the always-scanned fallback
    /// bucket. For tests only — keeps functional tests filetype-agnostic since
    /// the fallback bucket is loaded by every scan regardless of filter.
    fn load_rule_source(&mut self, source: &str) -> Result<()> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source.as_bytes())
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        let rules = compiler.build();
        let count = rules.iter().count();
        let cell = self.tiers.entry(FALLBACK_BUCKET.to_string()).or_default();
        let _ = cell.set(Some(rules));
        self.populated_tiers.insert(FALLBACK_BUCKET.to_string());
        // Source stays `Empty`: the pre-set cell above is returned directly, so
        // `build_tier` is never consulted for this bucket.
        self.rule_counts = (count, 0);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Tests use direct assertions and helpers for brevity
mod tests {
    use super::*;

    #[test]
    fn test_simple_rule() {
        let rule = r#"
rule test_rule {
    meta:
        description = "Test rule"
        risk = "notable"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This contains TESTPATTERN in the data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "test_rule");
        assert!(!matches[0].matched_strings.is_empty());
    }

    #[test]
    fn test_no_match() {
        let rule = r#"
rule test_rule {
    strings:
        $test = "NOTFOUND"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This does not contain the pattern";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_new() {
        let engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());
    }

    #[test]
    fn test_default() {
        let engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());
    }

    #[test]
    fn test_is_loaded() {
        let mut engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());

        engine
            .load_rule_source(r#"rule test { strings: $a = "test" condition: $a }"#)
            .unwrap();

        assert!(engine.is_loaded());
    }

    #[test]
    fn test_scan_without_rules() {
        let engine = YaraEngine::new_for_test();
        let result = engine.scan_bytes(b"test data");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No YARA rules loaded")
        );
    }

    #[test]
    fn test_extract_namespace_with_prefix() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/traits/execution/shell/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits.execution.shell");
    }

    #[test]
    fn test_extract_namespace_with_prefix_third_party() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/third-party/malware/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "third_party");
        assert_eq!(namespace, "third_party.malware");
    }

    #[test]
    fn test_extract_namespace_with_prefix_no_subdirs() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/traits/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits");
    }

    #[test]
    fn test_rule_with_metadata() {
        let rule = r#"
rule test_rule {
    meta:
        description = "Test description"
        risk = "hostile"
        capability = "true"
        mbc = "B0001"
        attack = "T1059"
    strings:
        $test = "PATTERN"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This contains PATTERN in the data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].desc, "Test description");
        assert_eq!(matches[0].crit, "hostile");
        assert!(matches[0].is_capability);
        assert_eq!(matches[0].mbc, Some("B0001".to_string()));
        assert_eq!(matches[0].attack, Some("T1059".to_string()));
    }

    #[test]
    fn test_rule_with_tags() {
        let rule = r#"
rule test_rule : suspicious {
    strings:
        $test = "TAGGED"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TAGGED data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].crit, "suspicious");
    }

    #[test]
    fn test_yara_match_to_evidence() {
        let engine = YaraEngine::new_for_test();

        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "test.namespace".to_string(),
            crit: "hostile".to_string(),
            desc: "Test".to_string(),
            matched_strings: vec![MatchedString {
                identifier: "$pattern".to_string(),
                offset: 0x1000,
                value: "test".to_string(),
            }],
            is_capability: false,
            mbc: None,
            attack: None,
            trait_id: None,
            arch_context: None,
        };

        let evidence = engine.yara_match_to_evidence(&yara_match);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].method, "yara");
        assert_eq!(evidence[0].source, "yara-x");
        assert_eq!(evidence[0].value, "test"); // Uses actual matched value
        assert_eq!(evidence[0].location, Some("offset:0x1000".to_string()));
    }

    #[test]
    fn test_yara_match_to_evidence_no_strings() {
        let engine = YaraEngine::new_for_test();

        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "test.namespace".to_string(),
            crit: "hostile".to_string(),
            desc: "Test".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
            trait_id: None,
            arch_context: None,
        };

        let evidence = engine.yara_match_to_evidence(&yara_match);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].value, "test_rule");
        assert_eq!(evidence[0].location, Some("test.namespace".to_string()));
    }

    #[test]
    fn test_multiple_patterns() {
        let rule = r#"
rule test_rule {
    strings:
        $a = "FIRST"
        $b = "SECOND"
    condition:
        any of them
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"FIRST and SECOND patterns";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_strings.len(), 2);
    }

    #[test]
    fn test_long_match_truncation() {
        let rule = r#"
rule test_rule {
    strings:
        $long = /A{200}/
    condition:
        $long
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = vec![b'A'; 200];
        let matches = engine.scan_bytes(&test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched_strings[0].value.contains("200 bytes"));
    }

    #[test]
    fn test_capability_inference_from_mbc() {
        let rule = r#"
rule test_rule {
    meta:
        mbc = "B0015.001"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from MBC presence
    }

    #[test]
    fn test_capability_inference_from_attack() {
        let rule = r#"
rule test_rule {
    meta:
        attack = "T1059.004"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from ATT&CK presence
    }

    #[test]
    fn test_filter_disabled_rules() {
        let source = r#"
rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}

rule AlsoKeep {
    strings:
        $c = "also"
    condition:
        $c
}
"#;

        let mut disabled = std::collections::HashSet::new();
        // derive_trait_id("3p.test.file", "DisableMe", None) -> "third_party/test/file/disableme"
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
        assert!(filtered.contains("rule AlsoKeep"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_no_match() {
        let source = r#"
rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}
"#;

        let mut disabled = std::collections::HashSet::new();
        // Different namespace - won't match rules in test.file
        disabled.insert("third_party/other/file/somerule".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 0);
        assert_eq!(filtered, source);
    }

    #[test]
    fn test_filter_disabled_rules_with_tags() {
        let source = r#"
rule KeepMe : tag1 tag2 {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe : hostile malware {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepMe : tag1 tag2"));
        assert!(!filtered.contains("rule DisableMe"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_private_global() {
        let source = r#"
private rule PrivateKeep {
    strings:
        $a = "keep"
    condition:
        $a
}

global rule GlobalDisable {
    strings:
        $b = "disable"
    condition:
        $b
}

private global rule PrivateGlobalKeep {
    strings:
        $c = "keep2"
    condition:
        $c
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/globaldisable".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("private rule PrivateKeep"));
        assert!(!filtered.contains("global rule GlobalDisable"));
        assert!(filtered.contains("private global rule PrivateGlobalKeep"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_first_rule() {
        let source = r#"rule FirstDisabled {
    strings:
        $a = "first"
    condition:
        $a
}

rule Second {
    strings:
        $b = "second"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/firstdisabled".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(!filtered.contains("rule FirstDisabled"));
        assert!(filtered.contains("rule Second"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_last_rule() {
        let source = r#"
rule First {
    strings:
        $a = "first"
    condition:
        $a
}

rule LastDisabled {
    strings:
        $b = "last"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/lastdisabled".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("rule First"));
        assert!(!filtered.contains("rule LastDisabled"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_multiple() {
        let source = r#"
rule Keep1 {
    strings:
        $a = "keep1"
    condition:
        $a
}

rule Disable1 {
    strings:
        $b = "disable1"
    condition:
        $b
}

rule Keep2 {
    strings:
        $c = "keep2"
    condition:
        $c
}

rule Disable2 {
    strings:
        $d = "disable2"
    condition:
        $d
}

rule Keep3 {
    strings:
        $e = "keep3"
    condition:
        $e
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disable1".to_string());
        disabled.insert("third_party/test/file/disable2".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 2);
        assert!(filtered.contains("rule Keep1"));
        assert!(!filtered.contains("rule Disable1"));
        assert!(filtered.contains("rule Keep2"));
        assert!(!filtered.contains("rule Disable2"));
        assert!(filtered.contains("rule Keep3"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_with_imports() {
        let source = r#"import "pe"
import "math"

rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("import \"pe\""));
        assert!(filtered.contains("import \"math\""));
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
    }

    #[test]
    fn test_filter_disabled_rules_complex_condition() {
        let source = r#"
rule KeepComplex {
    meta:
        description = "Complex rule"
    strings:
        $a = "pattern1"
        $b = "pattern2"
        $c = /regex[0-9]+/
    condition:
        ($a and $b) or
        ($c and filesize < 1MB) or
        (
            for any i in (0..10) : (
                uint32(i) == 0x12345678
            )
        )
}

rule DisableMe {
    strings:
        $x = "disable"
    condition:
        $x
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepComplex"));
        assert!(filtered.contains("for any i in"));
        assert!(!filtered.contains("rule DisableMe"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_all_disabled() {
        let source = r#"
rule Disable1 {
    strings:
        $a = "d1"
    condition:
        $a
}

rule Disable2 {
    strings:
        $b = "d2"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disable1".to_string());
        disabled.insert("third_party/test/file/disable2".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 2);
        assert!(!filtered.contains("rule Disable1"));
        assert!(!filtered.contains("rule Disable2"));
        // Should be essentially empty (just whitespace)
        assert!(filtered.trim().is_empty());
    }

    #[test]
    fn test_filter_disabled_rules_preserves_comments() {
        let source = r#"
// This is a file-level comment
/* Multi-line
   comment */

rule KeepMe {
    // Rule comment
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("// This is a file-level comment"));
        assert!(filtered.contains("/* Multi-line"));
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
    }

    /// Test YARA rule tier classification against fixture files.
    ///
    /// Fixtures live in `tests/yara_tier_fixtures/{platforms}/{filetypes}/rule.yar`.
    /// The `{filetypes}` directory name determines the expected `YaraTier`.
    /// Platforms are sorted alphabetically, comma-separated (e.g. `linux,windows`).
    /// Filetypes are sorted alphabetically, comma-separated (e.g. `elf,pe`).
    ///
    /// To add a regression test for a misclassified rule, just drop the `.yar` file
    /// into the appropriate directory.
    #[test]
    fn test_tier_classification_fixtures() {
        let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("yara_tier_fixtures");

        if !fixtures_dir.exists() {
            // Skip if fixtures not present (e.g., CI without test data)
            return;
        }

        let mut tested = 0;
        let mut failures: Vec<String> = Vec::new();

        // Walk: {fixtures_dir}/{platform_dir}/{filetype_dir}/*.yar
        for platform_entry in std::fs::read_dir(&fixtures_dir).unwrap() {
            let platform_entry = platform_entry.unwrap();
            if !platform_entry.file_type().unwrap().is_dir() {
                continue;
            }
            let platform_dir = platform_entry.file_name().to_string_lossy().to_string();

            for filetype_entry in std::fs::read_dir(platform_entry.path()).unwrap() {
                let filetype_entry = filetype_entry.unwrap();
                if !filetype_entry.file_type().unwrap().is_dir() {
                    continue;
                }
                let filetype_dir = filetype_entry.file_name().to_string_lossy().to_string();

                // Map the filetype directory to the expected YaraTier.
                // The first filetype token determines the tier.
                let expected_tier = match filetype_dir.split(',').next().unwrap_or("") {
                    "pe" | "dll" | "exe" => YaraTier::Pe,
                    "elf" | "so" => YaraTier::Elf,
                    "macho" | "dylib" => YaraTier::MachO,
                    "js" | "ts" | "script-js" => YaraTier::ScriptJs,
                    "script" => YaraTier::Script,
                    "doc" => YaraTier::Doc,
                    "archive" => YaraTier::Archive,
                    "generic" => YaraTier::CrossFormat,
                    other => {
                        failures.push(format!(
                            "Unknown filetype directory: {}/{}",
                            platform_dir, other
                        ));
                        continue;
                    }
                };

                for rule_file in std::fs::read_dir(filetype_entry.path()).unwrap() {
                    let rule_file = rule_file.unwrap();
                    let path = rule_file.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("yar") {
                        continue;
                    }

                    let source = std::fs::read_to_string(&path).unwrap();
                    let rule_name = extract_rule_name(&source)
                        .unwrap_or_else(|| path.file_stem().unwrap().to_string_lossy().to_string());

                    // Use a plausible namespace for third-party rules
                    let ns = format!("3p.test.{}", platform_dir);
                    let actual_tier = YaraTier::classify_rule(&rule_name, &source, &ns);

                    if actual_tier != expected_tier {
                        failures.push(format!(
                            "FAIL: {}/{}/{} — rule '{}': expected {:?}, got {:?}",
                            platform_dir,
                            filetype_dir,
                            path.file_name().unwrap().to_string_lossy(),
                            rule_name,
                            expected_tier,
                            actual_tier,
                        ));
                    }
                    tested += 1;
                }
            }
        }

        eprintln!(
            "Tier classification: {tested} rules tested, {} failures",
            failures.len()
        );
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("  {f}");
            }
            panic!(
                "{} of {} tier classification tests failed:\n{}",
                failures.len(),
                tested,
                failures.join("\n"),
            );
        }
        assert!(tested > 0, "No fixture files found");
    }

    #[test]
    fn test_classify_rule_uses_description_and_source_url_hints() {
        let source = r#"
rule DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23 : FILE
{
    meta:
        description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
        source_url = "https://github.com/delivr-to/detections/blob/main/yara-rules/onenote_windows_script_encoding_file.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23",
                source,
                "3p.YARAForge.delivrto"
            ),
            YaraTier::Doc
        );
    }

    #[test]
    fn test_classify_rule_uses_webshell_metadata_hints() {
        let source = r#"
rule SIGNATURE_BASE_WEBSHELL_PHP_By_String_Known_Webshell : FILE
{
    meta:
        description = "Known PHP Webshells which contain unique strings"
        source_url = "https://github.com/Neo23x0/signature-base/blob/main/yara/thor-webshells.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_WEBSHELL_PHP_By_String_Known_Webshell",
                source,
                "3p.YARAForge.signature_base"
            ),
            YaraTier::Script
        );
    }

    #[test]
    fn test_classify_rule_uses_javascript_metadata_hints() {
        let source = r#"
rule suspicious_node_implant : FILE
{
    meta:
        description = "JavaScript credential stealer for Electron and Node.js applications"
        source_url = "https://example.invalid/node_stealer_javascript.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule("suspicious_node_implant", source, "3p.test.javascript"),
            YaraTier::ScriptJs
        );
    }

    #[test]
    fn test_classify_rule_uses_lnk_description_hint() {
        let source = r#"
rule APT10_ChChes_lnk {
    meta:
        description = "LNK malware ChChes downloader"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule("APT10_ChChes_lnk", source, "3p.JPCERT.apt10"),
            YaraTier::Doc
        );
    }

    #[test]
    fn test_rule_context_marks_unix_shell_payload_without_shell_script_filetype() {
        let source = r#"
rule SIGNATURE_BASE_MAL_Payload_F5_BIG_IP_Exploitations_Jul20_1 : CVE_2020_5902 FILE
{
    meta:
        description = "Detects code found in report on exploits against CVE-2020-5902 F5 BIG-IP vulnerability by NCC group"
    strings:
        $x1 = "rm -f /etc/ld.so.preload" ascii fullword
        $x2 = "chmod +x /var/log/F5-logcheck" ascii
        $x3 = ".sh | sh" ascii
    condition:
        1 of them
}
"#;
        let ctx = YaraEngine::derive_rule_context(
            "SIGNATURE_BASE_MAL_Payload_F5_BIG_IP_Exploitations_Jul20_1",
            source,
            "3p.YARAForge.yara-rules-full",
        );
        assert!(ctx.filetypes.is_empty());
        assert_eq!(ctx.platforms, vec!["unix".to_string()]);
    }

    #[test]
    fn test_rule_context_keeps_shell_script_filetype_for_bash_rule_names() {
        let source = r#"
rule Linux_Backdoor_Bash_e427876d : FILE
{
    condition:
        true
}
"#;
        let ctx = YaraEngine::derive_rule_context(
            "Linux_Backdoor_Bash_e427876d",
            source,
            "3p.elastic.Linux_Backdoor_Bash",
        );
        assert_eq!(
            ctx.filetypes,
            vec!["sh".to_string(), "bash".to_string(), "zsh".to_string()]
        );
        assert_eq!(ctx.platforms, vec!["linux".to_string()]);
    }

    #[test]
    fn test_rule_context_marks_tinyshell_shell_snippet_as_unix_platform() {
        let source = r#"
rule SEKOIA_Malware_Tinyshell_Strings : FILE
{
    strings:
        $ = "_tsh_runshell"
        $ = "exec bash --login"
    condition:
        all of them
}
"#;
        let ctx = YaraEngine::derive_rule_context(
            "SEKOIA_Malware_Tinyshell_Strings",
            source,
            "3p.YARAForge.yara-rules-full",
        );
        assert!(ctx.filetypes.is_empty());
        assert_eq!(ctx.platforms, vec!["unix".to_string()]);
    }

    #[test]
    fn test_rule_context_preserves_arch_context_metadata() {
        let source = r#"
rule ELASTIC_Windows_Generic_Threat : FILE
{
    meta:
        os = "windows"
        arch_context = "x64"
    condition:
        true
}
"#;
        let ctx = YaraEngine::derive_rule_context(
            "ELASTIC_Windows_Generic_Threat",
            source,
            "3p.elastic.windows",
        );
        assert_eq!(ctx.arch_context.as_deref(), Some("x64"));
        assert_eq!(ctx.platforms, vec!["windows".to_string()]);
    }

    #[test]
    fn test_manifest_roundtrip_preserves_rule_contexts() {
        let dir = tempfile::tempdir().unwrap();
        let mut rule_contexts = HashMap::new();
        rule_contexts.insert(
            rule_context_key("", "test_rule"),
            RuleContext {
                filetypes: vec!["sh".to_string(), "bash".to_string(), "zsh".to_string()],
                filetype_source: "manifest-roundtrip".to_string(),
                platforms: vec!["unix".to_string()],
                os_meta: Some("linux".to_string()),
                arch_context: Some("x64".to_string()),
            },
        );
        let manifest = YaraManifest {
            builtin_count: 7,
            third_party_count: 11,
            inline_namespaces: vec!["ns1".to_string()],
            rule_contexts,
            populated_tiers: vec!["pe".to_string(), FALLBACK_BUCKET.to_string()],
        };
        YaraEngine::write_manifest(dir.path(), &manifest);

        let restored = YaraEngine::read_manifest(dir.path()).expect("manifest restored");
        assert_eq!(
            (restored.builtin_count, restored.third_party_count),
            (7, 11)
        );
        let ctx = restored
            .rule_contexts
            .get(&rule_context_key("", "test_rule"))
            .expect("cached rule context restored");
        assert_eq!(
            ctx.filetypes,
            vec!["sh".to_string(), "bash".to_string(), "zsh".to_string()]
        );
        assert_eq!(ctx.filetype_source, "manifest-roundtrip");
        assert_eq!(ctx.platforms, vec!["unix".to_string()]);
        assert_eq!(ctx.os_meta.as_deref(), Some("linux"));
        assert_eq!(ctx.arch_context.as_deref(), Some("x64"));
        assert_eq!(
            restored.populated_tiers,
            vec!["pe".to_string(), FALLBACK_BUCKET.to_string()]
        );
    }

    #[test]

    fn test_lazy_tier_compiles_then_loads_from_per_tier_cache() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = "pe";
        let mut sources = HashMap::new();
        sources.insert(
            bucket.to_string(),
            vec![(
                "test_ns".to_string(),
                r#"rule r { strings: $a = "abc" condition: $a }"#.to_string(),
            )],
        );
        let cell = OnceLock::new();
        let _ = cell.set(sources);

        let mut engine = YaraEngine::new_for_test();
        engine.populated_tiers.insert(bucket.to_string());
        engine.tiers = YaraEngine::tier_cells([bucket]);
        engine.source = TierSource::Lazy {
            cache_dir: Some(dir.path().to_path_buf()),
            traits_dir: dir.path().to_path_buf(),
            third_party_dir: dir.path().to_path_buf(),
            enable_third_party: false,
            sources: cell,
        };
        // First access compiles from source and writes the per-bucket cache file.
        assert!(engine.tier_rules(bucket).is_some());
        assert!(
            dir.path().join(format!("{bucket}.yrc")).exists(),
            "compiling a bucket must write its per-bucket cache file"
        );

        // A fresh engine with NO sources must load that bucket straight from the
        // per-bucket cache file — the warm path that never touches rule text.
        let mut warm = YaraEngine::new_for_test();
        warm.populated_tiers.insert(bucket.to_string());
        warm.tiers = YaraEngine::tier_cells([bucket]);
        warm.source = TierSource::Lazy {
            cache_dir: Some(dir.path().to_path_buf()),
            traits_dir: dir.path().to_path_buf(),
            third_party_dir: dir.path().to_path_buf(),
            enable_third_party: false,
            sources: OnceLock::new(),
        };
        assert!(
            warm.tier_rules(bucket).is_some(),
            "warm engine must load the bucket from its per-bucket cache without sources"
        );
    }

    #[test]
    fn test_js_scan_selection_includes_fallback() {
        let mut engine = YaraEngine::new_for_test();
        for bucket in ["js", "ts", "ps1", "pe", FALLBACK_BUCKET] {
            engine.populated_tiers.insert(bucket.to_string());
        }

        // A concrete filter loads the named filetype buckets plus the always-on
        // fallback bucket, intersected with the populated set (results sorted).
        assert_eq!(
            engine.buckets_to_scan(Some(&["ts", "tsx", "js"])),
            vec![
                FALLBACK_BUCKET.to_string(),
                "js".to_string(),
                "ts".to_string()
            ]
        );
        assert_eq!(
            engine.buckets_to_scan(Some(&["ps1"])),
            vec![FALLBACK_BUCKET.to_string(), "ps1".to_string()]
        );
        // A filter naming an unpopulated bucket still always gets the fallback.
        assert_eq!(
            engine.buckets_to_scan(Some(&["docx"])),
            vec![FALLBACK_BUCKET.to_string()]
        );

        // An unfiltered scan loads every populated bucket.
        let mut all = engine.buckets_to_scan(None);
        all.sort();
        assert_eq!(
            all,
            vec![
                FALLBACK_BUCKET.to_string(),
                "js".to_string(),
                "pe".to_string(),
                "ps1".to_string(),
                "ts".to_string()
            ]
        );
    }

    #[test]
    fn test_classify_inline_trait_yara_uses_declared_for_metadata() {
        let source = r#"
rule demo_inline_archive_rule {
    condition:
        true
}
"#;
        // Explicit `for:` filetypes are used verbatim as bucket keys.
        assert_eq!(
            YaraEngine::classify_inline_trait_yara_tiers(
                source,
                "inline.demo-inline",
                &["ts".to_string()]
            ),
            vec!["ts".to_string()]
        );
        assert_eq!(
            YaraEngine::classify_inline_trait_yara_tiers(
                source,
                "inline.demo-inline",
                &["jar".to_string(), "zip".to_string()]
            ),
            vec!["jar".to_string(), "zip".to_string()]
        );
        assert_eq!(
            YaraEngine::classify_inline_trait_yara_tiers(
                source,
                "inline.demo-inline",
                &["ps1".to_string()]
            ),
            vec!["ps1".to_string()]
        );
    }

    #[test]
    fn test_classify_inline_trait_yara_falls_back_to_source_classification() {
        let source = r#"
rule demo_inline_php {
    strings:
        $a = "<?php" ascii
    condition:
        $a
}
"#;
        // No usable `for:`, so the rule's derived context filetypes are used —
        // the "php" token in the rule name resolves to the php bucket.
        assert_eq!(
            YaraEngine::classify_inline_trait_yara_tiers(
                source,
                "inline.demo-inline",
                &["none".to_string()]
            ),
            vec!["php".to_string()]
        );
    }

    #[test]
    fn test_split_monolithic_buckets_built_in_rules_by_filetype() {
        let source = r#"
rule builtin_js_rule {
    meta:
        description = "JavaScript credential stealer for Node.js applications"
    condition:
        true
}

rule builtin_pe_rule {
    condition:
        uint16(0) == 0x5A4D
}

rule builtin_generic_rule {
    condition:
        true
}
"#;
        // Mirror the collectors: inject filetype hints from magic conditions
        // before splitting (so the PE magic rule gets a "pe" filetype).
        let injected = yara_classify::inject_condition_filetype_hints(source);

        let split = YaraEngine::split_monolithic_by_tier(
            &injected,
            "traits",
            rule_start_re().expect("valid test regex"),
        );

        // The JS rule lands in each of its inferred filetype buckets.
        let js_bucket = split
            .tiers
            .get("js")
            .expect("js rule bucketed into js filetype");
        assert!(js_bucket.contains("builtin_js_rule"));

        let pe_bucket = split
            .tiers
            .get("pe")
            .expect("pe rule bucketed into pe filetype");
        assert!(pe_bucket.contains("builtin_pe_rule"));

        // A rule with no filetype constraint lands in the always-scanned fallback.
        let fallback = split
            .tiers
            .get(FALLBACK_BUCKET)
            .expect("generic rule bucketed into fallback");
        assert!(fallback.contains("builtin_generic_rule"));
    }

    /// Extract the rule name from YARA source text.
    fn extract_rule_name(source: &str) -> Option<String> {
        for line in source.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("rule ") {
                // "rule NAME {" or "rule NAME : TAG {"
                let name = rest.split_whitespace().next()?.trim_end_matches('{');
                return Some(name.to_string());
            }
        }
        None
    }

    /// Diagnostic test: classify all third-party YARA rules and print distribution.
    /// Run with: cargo test --lib test_classify_all_third_party -- --nocapture --ignored
    #[test]
    #[ignore]
    fn test_classify_all_third_party() {
        use std::collections::HashMap;

        let rule_re = regex::Regex::new(r"(?m)^((private\s+)?rule\s+)(\w+)").unwrap();

        let traits_dir = dirs::data_dir()
            .unwrap_or_default()
            .join("atomdrift")
            .join("cleave")
            .join("traits")
            .join("third-party");

        let mut tier_counts: HashMap<YaraTier, usize> = HashMap::new();
        let mut cross_format_names: Vec<String> = Vec::new();
        let mut unknown_names: Vec<String> = Vec::new();

        // Walk all .yar files
        for entry in walkdir::WalkDir::new(&traits_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
            })
        {
            let path = entry.path();
            let Ok(source) = std::fs::read_to_string(path) else {
                continue;
            };

            // Derive namespace from path
            let rel = path.strip_prefix(&traits_dir).unwrap_or(path);
            let ns = format!(
                "3p.{}",
                rel.with_extension("").to_string_lossy().replace('/', ".")
            );

            for cap in rule_re.captures_iter(&source) {
                let name = cap.get(3).unwrap().as_str();
                let is_private = cap
                    .get(2)
                    .map(|m| m.as_str().contains("private"))
                    .unwrap_or(false);
                if is_private {
                    continue;
                }

                let start = cap.get(0).unwrap().start();
                // Find rule body end (next rule start or EOF)
                let body_end = rule_re
                    .find_at(&source, start + 1)
                    .map(|m| m.start())
                    .unwrap_or(source.len());
                let rule_text = &source[start..body_end];

                let tier = YaraTier::classify_rule(name, rule_text, &ns);
                *tier_counts.entry(tier).or_default() += 1;
                match tier {
                    YaraTier::CrossFormat => {
                        cross_format_names.push(format!("{} (ns={})", name, ns));
                    }
                    YaraTier::Unknown => {
                        unknown_names.push(format!("{} (ns={})", name, ns));
                    }
                    _ => {}
                }
            }
        }

        eprintln!("\n=== YARA Tier Distribution ===");
        let mut total = 0;
        for tier in YaraTier::ALL {
            let count = tier_counts.get(tier).copied().unwrap_or(0);
            total += count;
            eprintln!("  {:8}: {}", tier.label(), count);
        }
        eprintln!("  {:8}: {}", "TOTAL", total);

        cross_format_names.sort();
        eprintln!(
            "\n=== Cross-Format Rules ({}) ===",
            cross_format_names.len()
        );
        for name in &cross_format_names {
            eprintln!("  {name}");
        }

        unknown_names.sort();
        eprintln!("\n=== Unknown Rules ({}) ===", unknown_names.len());
        for name in &unknown_names {
            eprintln!("  {name}");
        }
    }

    /// Diagnostic test: print the full runtime rule-name sets per tier as loaded by the engine.
    /// Includes built-in rules, inline trait YARA, and third-party rules after tier classification.
    ///
    /// Run with:
    /// `cargo test --lib test_dump_runtime_rule_sets_by_tier -- --nocapture --ignored`
    #[test]
    #[ignore]
    fn test_dump_runtime_rule_sets_by_tier() {
        use std::collections::HashMap;

        fn extract_rule_names(source: &str) -> Vec<String> {
            let Some(rule_re) = super::rule_start_re() else {
                return Vec::new();
            };

            let mut names = Vec::new();
            for cap in rule_re.captures_iter(source) {
                let name = cap.get(3).map(|m| m.as_str()).unwrap_or_default();
                let modifiers = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
                if modifiers.contains("private") {
                    continue;
                }
                names.push(name.to_string());
            }
            names
        }

        let traits_dir = crate::cache::traits_path();
        let third_party_dir = crate::cache::third_party_path();

        let (inline_tier_sources, _inline_namespaces) = if traits_dir.exists() {
            YaraEngine::collect_inline_trait_sources_tiered(&traits_dir)
        } else {
            (HashMap::new(), Vec::new())
        };
        let (builtin_tier_sources, _, _) = if traits_dir.exists() {
            YaraEngine::collect_builtin_sources_tiered(&traits_dir)
        } else {
            (HashMap::new(), HashMap::new(), 0)
        };
        let (mut third_party_sources, _, _, _, _) = if third_party_dir.exists() {
            YaraEngine::collect_third_party_sources_tiered(&third_party_dir)
        } else {
            (HashMap::new(), HashMap::new(), 0, 0, 0)
        };

        let mut tier_names: HashMap<String, Vec<String>> = HashMap::new();

        for (bucket, sources) in inline_tier_sources {
            for (namespace, source) in sources {
                for name in extract_rule_names(&source) {
                    tier_names
                        .entry(bucket.clone())
                        .or_default()
                        .push(format!("{name} (ns={namespace})"));
                }
            }
        }

        for (bucket, sources) in builtin_tier_sources {
            for (namespace, source) in sources {
                for name in extract_rule_names(&source) {
                    tier_names
                        .entry(bucket.clone())
                        .or_default()
                        .push(format!("{name} (ns={namespace})"));
                }
            }
        }

        for (bucket, sources) in third_party_sources.drain() {
            for (namespace, source) in sources {
                for name in extract_rule_names(&source) {
                    tier_names
                        .entry(bucket.clone())
                        .or_default()
                        .push(format!("{name} (ns={namespace})"));
                }
            }
        }

        eprintln!("\n=== Runtime Rule Sets By Bucket ===");
        let mut buckets: Vec<String> = tier_names.keys().cloned().collect();
        buckets.sort();
        for bucket in buckets {
            let mut names = tier_names.remove(&bucket).unwrap_or_default();
            names.sort();
            names.dedup();
            eprintln!("\n=== {} ({}) ===", bucket, names.len());
            for name in names {
                eprintln!("  {name}");
            }
        }
    }
}
