//! YARA rule engine integration.
//!
//! This module provides YARA pattern matching for malware detection.
//! It loads and compiles YARA rules from:
//! - Built-in rules (traits/yara/)
//! - Third-party rules (if enabled)
//!
//! Rules are compiled once at startup for performance.

use crate::analyzers::{FileType, FileTypeExt};
#[cfg(test)]
use crate::capabilities::CapabilityMapper;
use crate::types::{
    Evidence, MAX_EVIDENCE_PER_TRAIT, MatchedString, YaraMatch, deduplicate_evidence,
};
use anyhow::Result;
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

mod sources;

mod matches;

/// A scan's reportable matches and inline-trait evidence travel together.
/// Neither channel alone describes everything the scan found.
#[derive(Debug, Default)]
#[must_use]
pub struct YaraScan {
    /// Standalone YARA matches for the analysis report.
    pub matches: Vec<YaraMatch>,
    /// Trait evidence keyed by namespace (`inline.{trait_id}`).
    pub inline_traits: HashMap<String, Vec<Evidence>>,
}

/// Process-wide override for "load built-in YARA rules only" (skip third-party).
///
/// 0 = unset, 1 = force builtin-only, -1 = force third-party-allowed.
static BUILTIN_YARA_ONLY_OVERRIDE: AtomicI8 = AtomicI8::new(0);

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

fn builtin_yara_only_active() -> bool {
    if let Some(v) = decode(&BUILTIN_YARA_ONLY_OVERRIDE) {
        return v;
    }
    crate::env::flag("CLEAVE_BUILTIN_YARA_ONLY")
}

fn skip_yara_active() -> bool {
    crate::env::flag("CLEAVE_SKIP_YARA")
}

/// The process-wide YARA settings that change scan results outside
/// `AnalysisOptions`: whether YARA is skipped entirely, and whether
/// third-party rules are dropped. Analysis cache keys fold these in, so a
/// report written under one setting is not served to a run under another.
#[must_use]
pub(crate) fn result_affecting_overrides() -> YaraOverrides {
    YaraOverrides {
        skip: skip_yara_active(),
        builtin_only: builtin_yara_only_active(),
    }
}

/// See [`result_affecting_overrides`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct YaraOverrides {
    pub(crate) skip: bool,
    pub(crate) builtin_only: bool,
}
use walkdir::WalkDir;
#[cfg(test)]
use yara_classify::YaraTier;

/// Bucket key for rules that apply to any file (EICAR-style). Always loaded by
/// every scan in addition to the detected file type's buckets.
const FALLBACK_BUCKET: &str = "fallback";

/// Compiled regex for YARA rule header matching — shared across all preprocessing steps.
fn rule_start_re() -> Option<&'static regex::Regex> {
    static_regex!(r"(?m)^(\s*)((?:private\s+|global\s+)*)rule\s+(\w+)")
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
// Evidence is a presentation budget. Rule conditions need a separate,
// bounded candidate budget: @a[n], #a and offset loops can depend on
// occurrences after the first eight.
const MAX_PATTERN_MATCHES: usize = 8;
pub(crate) const MAX_SCANNER_PATTERN_MATCHES: usize = 4096;
/// Longest a single YARA scan may run.
pub(crate) const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1200);

/// Maximum scanners to cache per thread in the engine tier cache.
///
/// Sized for the *thread's* working set, not one file's: a rayon worker
/// interleaves scans from many files (archive-member fan-out, fetched
/// dependencies) plus tier scans stolen from large payloads' parallel tier
/// fan-out, so it cycles through most of the tier universe (~75 buckets), not
/// the 1-3 tiers one file touches. Each scanner is a wasmtime store + linker
/// instantiation, so too small a cache re-instantiates constantly; 64 covers
/// every tier a thread realistically touches.
const ENGINE_SCANNER_CACHE_SIZE: usize = 64;

/// Inputs at or above this size evict their scanner from the per-thread cache
/// after the scan (see the eviction site in `run_scanner`), returning the
/// module state a large input leaves behind. Evicting after every input saves
/// no more memory and costs re-instantiation on small files.
const YARA_EVICT_ABOVE_BYTES: usize = 1 << 20;

/// Payloads at least this large scan their YARA tiers in parallel; smaller ones
/// scan sequentially (the rayon task overhead exceeds a tiny scan, and avoids a
/// third nesting level under archive member fan-out).
const TIER_PARALLEL_MIN_BYTES: usize = 256 << 10;

// YARA panics indicate a broken scanner/rule state, not a recoverable per-file
// condition. Once we catch one, continuing to scan every subsequent file just
// repeats the same expensive unwind path and floods logs. Flip this breaker and
// let the rest of the analysis proceed without YARA until rules are reloaded.
static YARA_SCANS_DISABLED_AFTER_PANIC: AtomicBool = AtomicBool::new(false);

// Count of rule sources that failed to compile during a runtime (lazy) bucket
// build. Nonzero means scans in this process ran with fewer rules than the
// trait set defines — a degradation the CLI surfaces as a hard failure rather
// than letting verdicts silently weaken. See [`yara_degradation`].
static YARA_RUNTIME_COMPILE_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Describes how YARA scanning degraded in this process, if it did.
///
/// `Some` when a YARA panic tripped the scan breaker or any rule failed to
/// compile during a runtime bucket build. Callers (the CLIs) treat this as a
/// visible failure: results produced without the full rule set must not look
/// like a clean scan.
#[must_use]
pub fn yara_degradation() -> Option<String> {
    let mut parts = Vec::new();
    if YARA_SCANS_DISABLED_AFTER_PANIC.load(Ordering::Relaxed) {
        parts.push("YARA scanning was disabled mid-run after an engine panic".to_string());
    }
    let compile_errors = YARA_RUNTIME_COMPILE_ERRORS.load(Ordering::Relaxed);
    if compile_errors > 0 {
        parts.push(format!(
            "{compile_errors} YARA rule source(s) failed to compile at runtime"
        ));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

// Thread-local LRU cache for YARA scanners keyed by `Rules` allocation address.
// Avoids expensive `Scanner::new()` on every file (wasmtime VM instantiation).
// Each rayon worker thread caches its own scanners (one per filetype bucket it
// touches). Every entry co-owns its `Rules` (see `CachedScanner`), so a cached
// scanner never outlives its rules and no other rules can be allocated at a
// key's address while that key is cached. The LRU bound is the only thing
// keeping this from growing without limit, so the cache is never cleared.
thread_local! {
    static ENGINE_SCANNER_CACHE: RefCell<lru::LruCache<usize, cached_scanner::CachedScanner>> = {
        use std::num::NonZeroUsize;
        let cache_size =
            NonZeroUsize::new(ENGINE_SCANNER_CACHE_SIZE).unwrap_or(NonZeroUsize::MIN);
        RefCell::new(lru::LruCache::new(cache_size))
    };
}

mod cached_scanner {
    use std::sync::Arc;

    /// A cached `yara_x::Scanner` together with the `Rules` it borrows.
    ///
    /// The thread-local scanner cache outlives any one engine (rayon workers
    /// keep it across scans, and tests and `test-rules` drop their engines),
    /// so each entry co-owns its rules instead of assuming they live forever.
    /// The scanner is reachable only through [`Self::with`], whose callback
    /// cannot name the borrow's lifetime: it can neither move the scanner out
    /// nor swap in another entry's.
    pub(super) struct CachedScanner {
        // Declared before `_rules` so it drops first: fields drop in
        // declaration order, so the borrow ends before the rules can be freed.
        scanner: yara_x::Scanner<'static>,
        _rules: Arc<yara_x::Rules>,
    }

    impl CachedScanner {
        pub(super) fn new(rules: Arc<yara_x::Rules>) -> Self {
            // SAFETY: the reference points into `rules`' heap allocation, which
            // an `Arc` never moves or mutates. `_rules` keeps that allocation
            // alive for as long as `scanner` exists (see the field order), and
            // `with` never lets the `'static` borrow escape.
            let borrowed: &'static yara_x::Rules = unsafe { &*Arc::as_ptr(&rules) };
            Self {
                scanner: yara_x::Scanner::new(borrowed),
                _rules: rules,
            }
        }

        /// Run `f` on the scanner. `f` is generic over the borrow's lifetime,
        /// so nothing it returns can hold the scanner or its borrow.
        pub(super) fn with<R>(
            &mut self,
            f: impl for<'r> FnOnce(&mut yara_x::Scanner<'r>) -> R,
        ) -> R {
            f(&mut self.scanner)
        }
    }
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
        /// Local per-user compiled-cache directory, the only place compiled
        /// rules are read from or written to (`None` = caching disabled).
        ///
        /// Never a traits tree: a `.yrc` is native code (yara-x deserializes
        /// it into wasmtime, which maps its machine code as is), so it is only
        /// loaded when this host compiled it — never from a downloaded bundle.
        cache_dir: Option<std::path::PathBuf>,
        /// Per bucket, the [`bucket_tag`] its compiled file is named by. A
        /// bucket with no tag is compiled but not cached.
        bucket_tags: std::collections::BTreeMap<String, String>,
        traits_dir: std::path::PathBuf,
        third_party_dir: std::path::PathBuf,
        enable_third_party: bool,
        /// Per-bucket rule source, collected on the first cache miss. Keyed by
        /// filetype string (or [`FALLBACK_BUCKET`]).
        sources: OnceLock<HashMap<String, Vec<(String, String)>>>,
    },
}

/// Fingerprint of the compiled-rule *producer*: this build's `yara_x`, the
/// features it was built with, and anything else that changes serialized
/// output.
///
/// A `.yrc` is only loadable by an engine whose serializer agrees with the one
/// that wrote it, and nothing in the file records who that was — the same
/// sources compiled by two different cleave builds yield different bytes under
/// an identical `source_tag`, which reads downstream as "stale rules" when
/// nothing is stale. Naming a version would miss the rest: feature flags change
/// the format too (`native-code-serialization` alone roughly doubles the
/// output, and makes it architecture-specific). So probe it instead — compile
/// one fixed rule and hash what this build serializes. Two engines agree on
/// this tag exactly when they agree on the format.
///
/// Deliberately over-strict: a tag that changes when the format did not costs
/// one recompile from source, while a tag that stays put across a real format
/// change means loading rules the engine will misread.
fn engine_tag() -> u64 {
    static TAG: OnceLock<u64> = OnceLock::new();
    *TAG.get_or_init(|| {
        // Exercise several constructs, not just a literal: the more of the
        // compiler the probe touches, the less room for two builds to agree
        // here and diverge on a real rule set.
        const CANARY: &str = r#"
import "math"
rule cleave_engine_probe {
  strings:
    $text = "cleave-engine-probe" nocase
    $hex  = { 6A 40 68 00 30 00 00 6A 14 8D 91 }
    $re   = /pro(be|of)[0-9a-f]{2,8}/i
  condition:
    filesize > 0 and math.entropy(0, filesize) >= 0.0
      and ($text or $hex or #re > 1)
}"#;
        let mut compiler = yara_x::Compiler::new();
        // A probe that cannot compile or serialize means this build cannot
        // produce loadable rules at all. Return a tag no real one can equal, so
        // every cached set is rejected and recompiled rather than trusted.
        if compiler.add_source(CANARY.as_bytes()).is_err() {
            return u64::MAX;
        }
        match compiler.build().serialize() {
            Ok(mut bytes) => {
                // The serialized compiler format alone does not capture our
                // namespace and filetype routing semantics. Invalidate older
                // caches that used short IDs or unnormalized language labels.
                bytes.extend_from_slice(b"cleave-inline-routing-qualified-v3");
                crate::cache::digest_bytes(&bytes)
            }
            Err(_) => u64::MAX,
        }
    })
}

/// Metadata persisted alongside the per-tier compiled rule files. Lets a warm
/// start restore counts/contexts/namespaces without reading or classifying any
/// rule text — the tiers themselves load lazily from their `.yrc` files.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct YaraManifest {
    builtin_count: usize,
    third_party_count: usize,
    inline_namespaces: Vec<String>,
    #[serde(default, serialize_with = "serialize_sorted_contexts")]
    rule_contexts: HashMap<String, RuleContext>,
    /// Labels of tiers that carry at least one rule.
    populated_tiers: Vec<String>,
    /// Fingerprint (hex u64) of the rule sources these compiled rules were
    /// built from: path + contents, no mtimes. A manifest that does not match
    /// the loaded rule sources is ignored.
    #[serde(default)]
    source_tag: Option<String>,
    /// Fingerprint (hex u64) of the engine that compiled these `.yrc`, from
    /// [`engine_tag`]. A manifest whose tag differs from this engine's is
    /// ignored: the bytes are for a different serializer, whatever the sources
    /// say.
    #[serde(default)]
    engine_tag: Option<String>,
    /// The cleave build that classified the sources this manifest describes
    /// (counts, contexts, bucket routing all come from code, not rules).
    #[serde(default)]
    cleave_version: Option<String>,
    /// Per bucket, a digest of what its compiled file is a function of — the
    /// engine and that bucket's sources ([`bucket_tag`]). Lets a rule update
    /// recompile only the buckets it changed.
    #[serde(default)]
    bucket_tags: std::collections::BTreeMap<String, String>,
}

/// What a bucket's compiled file is a function of: the engine that compiles it
/// and the exact sources it compiles, in order.
fn bucket_tag(bucket: &str, sources: &[(String, String)]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(engine_tag().to_le_bytes());
    h.update(bucket.as_bytes());
    for (namespace, source) in sources {
        h.update([0]);
        h.update(namespace.as_bytes());
        h.update([0]);
        h.update(source.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Where a bucket compiled under `tag` lives in the cache. The tag is in the
/// name, so a file only ever answers for the sources it was compiled from: a
/// process still compiling from older rules writes a name no current reader
/// looks up, instead of overwriting the current one.
fn compiled_path(dir: &Path, bucket: &str, tag: &str) -> PathBuf {
    dir.join(format!("{bucket}.{}.yrc", tag.get(..16).unwrap_or(tag)))
}

/// Serialize the rule-context map with its keys in sorted order.
///
/// `HashMap` iteration order is randomized per process, so without this the
/// same rule sources render a different `manifest.json` on every run — the
/// bundle hash changes even when nothing changed, defeating content-based
/// change gating in the publish pipeline. Only writes are affected; the warm
/// load path still deserializes straight into the `HashMap`.
fn serialize_sorted_contexts<S: serde::Serializer>(
    map: &HashMap<String, RuleContext>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_unstable();
    let mut out = serializer.serialize_map(Some(map.len()))?;
    for key in keys {
        out.serialize_entry(key, &map[key])?;
    }
    out.end()
}

#[derive(Debug)]
pub(crate) struct YaraEngine {
    /// Per-bucket compiled rule sets, materialized lazily. The map is keyed by
    /// filetype string (e.g. "pe", "docx") plus [`FALLBACK_BUCKET`]; it is
    /// pre-keyed from [`Self::populated_tiers`] at load. Each cell is built on
    /// first access via [`YaraEngine::tier_rules`] from [`Self::source`]. `None`
    /// = bucket has no rules.
    tiers: HashMap<String, OnceLock<Option<Arc<yara_x::Rules>>>>,
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

/// Fan `f` out over `items` WITHOUT touching the shared rayon pool: on a
/// rayon worker it runs inline; elsewhere it uses a few scoped plain threads.
///
/// Bucket source collection runs inside `build_tier`, i.e. while other
/// threads may be parked on that bucket's `OnceLock`. Using the global pool
/// from a non-worker caller (a startup prewarm thread, or a library caller)
/// then deadlocks: the caller waits for the pool to run its jobs while every
/// pool thread waits for the caller to finish the bucket (observed as a
/// 30-minute STARVED stall on a fresh traits dir, where buckets compile from
/// source). Plain threads cannot be blocked by the pool.
fn off_pool_flat_map<T, R, I>(items: &[T], f: impl Fn(&T) -> I + Sync) -> Vec<R>
where
    T: Sync,
    R: Send,
    I: IntoIterator<Item = R>,
{
    if rayon::current_thread_index().is_some() || items.len() < 2 {
        return items.iter().flat_map(&f).collect();
    }
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .clamp(2, 8)
        .min(items.len());
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut per_thread: Vec<Vec<(usize, Vec<R>)>> = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(i) else { break };
                        out.push((i, f(item).into_iter().collect::<Vec<R>>()));
                    }
                    out
                })
            })
            .collect();
        for h in handles {
            if let Ok(v) = h.join() {
                per_thread.push(v);
            }
        }
    });
    // Restore item order so callers see the same sequence as the old
    // `iter().flat_map()` path.
    let mut all: Vec<(usize, Vec<R>)> = per_thread.into_iter().flatten().collect();
    all.sort_by_key(|(i, _)| *i);
    all.into_iter().flat_map(|(_, v)| v).collect()
}

/// Whether a YAML document could contain a scalar equal to `yara`, the only
/// way it can declare an inline YARA trait. Plain, single-quoted and block
/// scalars can only spell it literally. A double-quoted scalar can also build
/// it from `\x`/`\u`/`\U` escapes or join it across an escaped line
/// break -- a backslash before `\n`, `\r`, NEL, LS or PS, which libyaml
/// counts as breaks. No other escape yields a letter.
fn may_spell_yara(content: &str) -> bool {
    content.contains("yara")
        || content
            .as_bytes()
            .windows(2)
            .any(|w| w[0] == b'\\' && matches!(w[1], b'x' | b'u' | b'U' | b'\n' | b'\r'))
        || ["\\\u{85}", "\\\u{2028}", "\\\u{2029}"]
            .iter()
            .any(|s| content.contains(s))
}

impl YaraEngine {
    /// An empty tier map pre-keyed with one `OnceLock` per bucket key.
    /// Keys are filetype strings (or [`FALLBACK_BUCKET`]) that actually carry
    /// rules — bucket keys cannot be pre-enumerated, so they are seeded from the
    /// populated set discovered at load.
    fn tier_cells<'a>(
        keys: impl IntoIterator<Item = &'a str>,
    ) -> HashMap<String, OnceLock<Option<Arc<yara_x::Rules>>>> {
        keys.into_iter()
            .map(|k| (k.to_string(), OnceLock::new()))
            .collect()
    }

    /// Lazily materialize the compiled rules for `bucket`, building from
    /// [`Self::source`] on first access. Thread-safe: concurrent first-touch
    /// callers block on the cell until the winner finishes. Returns `None` for
    /// a bucket that was never populated.
    fn tier_rules(&self, bucket: &str) -> Option<&Arc<yara_x::Rules>> {
        self.tiers
            .get(bucket)?
            .get_or_init(|| self.build_tier(bucket).map(Arc::new))
            .as_ref()
    }

    /// Compile or deserialize one bucket's rules. Single-bucket work only (no
    /// inner rayon), so it is safe to call from a rayon worker during a scan.
    fn build_tier(&self, bucket: &str) -> Option<yara_x::Rules> {
        let TierSource::Lazy {
            cache_dir,
            bucket_tags,
            traits_dir,
            third_party_dir,
            enable_third_party,
            sources,
        } = &self.source
        else {
            // Empty, or Compiled (cells externally pre-filled by a test helper).
            return None;
        };

        // 1. Per-bucket compiled rule file in the local cache; deserialize +
        //    re-JIT just this one bucket.
        let cached = cache_dir
            .as_deref()
            .zip(bucket_tags.get(bucket))
            .map(|(dir, tag)| compiled_path(dir, bucket, tag));
        if let Some(path) = &cached {
            match Self::read_compiled_bucket(path) {
                Ok(bytes) => match yara_x::Rules::deserialize(&bytes) {
                    Ok(rules) => return Some(rules),
                    Err(e) => {
                        // `warn`, not `debug`: at `debug` a host can pay a full
                        // compile per tier per process indefinitely with
                        // nothing to show for it.
                        tracing::warn!(bucket = %bucket, path = %path.display(), error = ?e, "compiled YARA bucket failed to deserialize (engine/yara-x version skew or corrupt file); recompiling from source");
                    }
                },
                Err(error) => {
                    if path.exists() || path.with_extension("yrc.zst").exists() {
                        tracing::warn!(bucket = %bucket, path = %path.display(), %error,
                            "compiled YARA bucket could not be read; recompiling from source");
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
        let mut compile_errors = 0usize;
        for (ns, src) in bucket_sources {
            compiler.new_namespace(ns);
            if let Err(e) = compiler.add_source(src.as_bytes()) {
                compile_errors += 1;
                YARA_RUNTIME_COMPILE_ERRORS.fetch_add(1, Ordering::Relaxed);
                tracing::error!("Bucket {bucket}: YARA rule source failed to compile: {e}");
            }
        }
        let rules = compiler.build();

        // A bucket can have source entries that compile successfully without
        // defining any rules. Keep that empty result uncached: there is no
        // useful scanner to restore, and an empty cache file only adds work
        // and noise to every later lookup.
        rules.iter().next()?;

        // 3. Write the compiled bucket to the LOCAL cache (best effort, atomic)
        //    so later scans and processes skip the compile.
        //
        //    A bucket that lost rules to compile errors is deliberately NOT
        //    cached: caching it would silence the failure after the first run,
        //    leaving every later scan quietly missing those rules with nothing
        //    to report. Recompiling each run keeps the errors visible until the
        //    rules are fixed.
        if compile_errors > 0 {
            tracing::error!(
                bucket = %bucket,
                compile_errors,
                "bucket compiled with missing rules; not caching it so the failure stays visible"
            );
            return Some(rules);
        }
        if let Some(path) = &cached
            && let Ok(bytes) = rules.serialize()
            && std::fs::create_dir_all(path.parent().unwrap_or(path)).is_ok()
        {
            Self::write_compiled_bucket(path, &bytes);
        }
        Some(rules)
    }

    fn read_compiled_bucket(path: &Path) -> std::io::Result<Vec<u8>> {
        let packed = path.with_extension("yrc.zst");
        if packed.exists() {
            return crate::cache::decode_cached_zstd(std::fs::File::open(packed)?);
        }
        std::fs::read(path)
    }

    fn write_compiled_bucket(path: &Path, bytes: &[u8]) {
        #[cfg(windows)]
        let (path, bytes) = {
            let Ok(packed) = zstd::encode_all(bytes, 3) else {
                return;
            };
            (path.with_extension("yrc.zst"), packed)
        };
        #[cfg(not(windows))]
        let (path, bytes) = (path.to_path_buf(), bytes.to_vec());

        if crate::cache::atomic_write(&path, &bytes).is_ok() {
            #[cfg(windows)]
            {
                // Retire an older uncompressed cache entry after the packed
                // replacement is safely in place.
                let _ = std::fs::remove_file(path.with_extension(""));
            }
        }
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
        let sources = crate::rule_sources::shared(traits_dir).ok();
        Self::collect_all_sources_with_sources(
            traits_dir,
            third_party_dir,
            enable_third_party,
            sources.as_deref(),
        )
    }

    fn read_source<'a>(
        sources: Option<&'a crate::rule_sources::RuleSources>,
        dir: &Path,
        path: &Path,
    ) -> Option<std::borrow::Cow<'a, [u8]>> {
        match sources {
            Some(sources) => sources
                .file(path.strip_prefix(dir).ok()?)
                .map(|file| std::borrow::Cow::Borrowed(file.bytes.as_ref())),
            None => fs::read(path).ok().map(std::borrow::Cow::Owned),
        }
    }

    fn collect_all_sources_with_sources(
        traits_dir: &Path,
        third_party_dir: &Path,
        enable_third_party: bool,
        sources: Option<&crate::rule_sources::RuleSources>,
    ) -> (
        HashMap<String, Vec<(String, String)>>,
        HashMap<String, RuleContext>,
        Vec<String>,
        usize,
        usize,
    ) {
        let (mut inline_tier_sources, inline_namespaces) =
            if sources.is_some() || traits_dir.exists() {
                Self::collect_inline_trait_sources_tiered_with_sources(traits_dir, sources)
            } else {
                (HashMap::new(), Vec::new())
            };
        let (mut builtin_tier_sources, builtin_contexts, builtin_count) =
            if sources.is_some() || traits_dir.exists() {
                Self::collect_builtin_sources_tiered_with_sources(traits_dir, sources)
            } else {
                (HashMap::new(), HashMap::new(), 0)
            };
        let third_party_sources = sources
            .and_then(|s| s.subtree_relative(third_party_dir.strip_prefix(traits_dir).ok()?));
        let third_party_exists = sources.map_or_else(
            || third_party_dir.exists(),
            |_| third_party_sources.is_some(),
        );
        let (mut tier_sources, third_party_contexts, third_party_count, _vt, _disabled) =
            if enable_third_party && third_party_exists {
                Self::collect_third_party_sources_tiered_with_sources(
                    third_party_dir,
                    third_party_sources.as_ref(),
                )
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

    /// Read `dir`'s manifest and accept it only if it describes the rule
    /// sources currently on disk, as loaded by this build of cleave, compiled
    /// by an engine that serializes the way this one does. Anything else is a
    /// cold start: sources are re-read and only changed buckets recompile (see
    /// [`Self::retire_stale_buckets`]).
    fn validated_manifest(dir: &Path, current_tag: Option<u64>) -> Option<YaraManifest> {
        let manifest = Self::read_manifest(dir)?;
        let hex = |tag: Option<u64>| tag.map(|t| format!("{t:016x}"));
        let same_engine = manifest.engine_tag == hex(Some(engine_tag()));
        let current = same_engine
            && manifest.cleave_version.as_deref() == Some(env!("CARGO_PKG_VERSION"))
            && current_tag.is_some()
            && manifest.source_tag == hex(current_tag);
        if !current {
            tracing::debug!(
                dir = %dir.display(),
                "compiled YARA cache describes other sources or another build; recompiling what changed"
            );
        }
        current.then_some(manifest)
    }

    /// Remove every compiled file in `dir` that is not a current bucket under
    /// its current tag — a bucket whose sources (or engine) changed, one that
    /// no longer exists, or a stray. The rest stay, so a rule update
    /// recompiles only what it touched.
    fn retire_stale_buckets(dir: &Path, tags: &std::collections::BTreeMap<String, String>) {
        let current: std::collections::HashSet<PathBuf> = tags
            .iter()
            .map(|(bucket, tag)| compiled_path(dir, bucket, tag))
            .collect();
        for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
            let path = entry.path();
            let compiled = path.extension().is_some_and(|e| e == "yrc")
                || path.to_string_lossy().ends_with(".yrc.zst");
            let kept = current.contains(path) || current.contains(&path.with_extension(""));
            if entry.file_type().is_file() && compiled && !kept {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// Compile every populated bucket that has no compiled file in the cache
    /// yet, in parallel, leaving the others untouched (and unloaded). Returns
    /// `(compiled, buckets)`.
    pub(crate) fn compile_missing(&self) -> (usize, usize) {
        let TierSource::Lazy {
            cache_dir: Some(dir),
            bucket_tags,
            ..
        } = &self.source
        else {
            return (0, self.populated_tiers.len());
        };
        let missing: Vec<&String> = self
            .populated_tiers
            .iter()
            .filter(|bucket| {
                bucket_tags.get(*bucket).is_some_and(|tag| {
                    let path = compiled_path(dir, bucket, tag);
                    !path.exists() && !path.with_extension("yrc.zst").exists()
                })
            })
            .collect();
        missing.par_iter().for_each(|bucket| {
            let _ = self.build_tier(bucket);
        });
        (missing.len(), self.populated_tiers.len())
    }

    fn write_manifest(dir: &Path, manifest: &YaraManifest) {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
        if let Ok(bytes) = serde_json::to_vec(manifest) {
            let _ = crate::cache::atomic_write(&dir.join("manifest.json"), &bytes);
        }
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
    /// Build every populated bucket that is still cold, on `threads` plain
    /// (non-rayon) threads, biggest buckets first. For a long-lived worker
    /// this is the startup counterpart of lazy bucket loading: the buckets
    /// get built either way, but here it happens on otherwise idle cores
    /// while the first jobs are still being fetched, instead of inside the
    /// first archive that needs them — where the `pe` bucket alone
    /// (deserialize + wasmtime JIT, ~3 s) held one pool thread and every
    /// member queued behind it.
    ///
    /// Plain threads, not the rayon pool: the pool is the analysis engine's
    /// and a 77-job fan-out there would sit in front of the first jobs. A
    /// member that needs a bucket mid-build parks on its `OnceLock` until the
    /// builder thread finishes — bounded, and the same wait it would have had
    /// behind a sibling member building it.
    pub(crate) fn prewarm_all_cold_buckets(&self, threads: usize) {
        let mut cold: Vec<&str> = self
            .populated_tiers
            .iter()
            .map(String::as_str)
            .filter(|bucket| {
                self.tiers
                    .get(*bucket)
                    .is_some_and(|cell| cell.get().is_none())
            })
            .collect();
        if cold.is_empty() {
            return;
        }
        // The two giant buckets (`pe` ~21 MB, `elf` ~1.5 MB compiled) go on
        // one dedicated thread; every other bucket is small (~30 ms) and the
        // remaining threads sweep them alphabetically, so the buckets a
        // typical first job needs (`py`, `js`, `json`, `txt`, ...) are ready
        // within a few hundred ms instead of queueing behind `pe`.
        const HEAVY: [&str; 2] = ["pe", "elf"];
        cold.sort_unstable();
        let (heavy, light): (Vec<&str>, Vec<&str>) = cold.iter().partition(|b| HEAVY.contains(b));
        let started = std::time::Instant::now();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let threads = threads.clamp(1, cold.len());
        std::thread::scope(|scope| {
            // First the process-global scanner one-time init: `yara_x`'s
            // first `Scanner` calibrates a `quanta` clock (~200 ms of
            // spinning) — pay it here on the smallest bucket, before the
            // heavy builds, instead of inside the first member that scans.
            if let Some(first) = light.first().copied().or_else(|| heavy.first().copied()) {
                let _ = self.tier_rules(first);
                let _ = self.scan_bytes(b"prewarm", Some(&[first]));
            }
            if !heavy.is_empty() {
                scope.spawn(|| {
                    for bucket in &heavy {
                        let _ = self.tier_rules(bucket);
                    }
                });
            }
            let light_threads = threads
                .saturating_sub(usize::from(!heavy.is_empty()))
                .max(1);
            for _ in 0..light_threads {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(bucket) = light.get(i) else { break };
                        let _ = self.tier_rules(bucket);
                    }
                });
            }
        });
        tracing::info!(
            buckets = cold.len(),
            threads,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "prewarmed all YARA buckets in the background"
        );
    }

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
    pub(crate) fn load_all_rules(&mut self, enable_third_party: bool) -> (usize, usize) {
        let _span = tracing::info_span!("load_yara_rules").entered();

        // Fast path: skip YARA entirely for tests that don't need it
        if skip_yara_active() {
            tracing::info!("YARA skipped (CLEAVE_SKIP_YARA)");
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

        // The local compiled-rule cache, and its manifest when that describes
        // the rule sources on disk as this build loads them.
        // `CLEAVE_SKIP_YARA_CACHE` bypasses it, so a forced from-source
        // recompile stays possible.
        let current_tag = crate::cache::rules_source_tag();
        let (cache_dir, manifest) = if crate::cache::skip_yara_cache() {
            tracing::info!(
                "Skipping the YARA cache (CLEAVE_SKIP_YARA_CACHE / CLEAVE_SKIP_CACHE); compiling from source"
            );
            (None, None)
        } else {
            let cache_dir = crate::cache::yara_cache_path(enable_third_party).ok();
            let manifest = cache_dir
                .as_ref()
                .and_then(|dir| Self::validated_manifest(dir, current_tag));
            (cache_dir, manifest)
        };

        // Warm path: a manifest restores counts/contexts/namespaces without
        // reading any rule text; each tier compiles or deserializes lazily on
        // the first scan that needs it (see `build_tier`), so only the tiers a
        // run actually touches ever allocate.
        if let Some(manifest) = manifest {
            self.rule_counts = (manifest.builtin_count, manifest.third_party_count);
            self.rule_contexts = manifest.rule_contexts;
            self.compiled_inline_namespaces = manifest.inline_namespaces;
            self.tiers = Self::tier_cells(manifest.populated_tiers.iter().map(String::as_str));
            self.populated_tiers = manifest.populated_tiers.into_iter().collect();
            self.source = TierSource::Lazy {
                cache_dir,
                bucket_tags: manifest.bucket_tags,
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

        let bucket_tags: std::collections::BTreeMap<String, String> = tier_sources
            .iter()
            .filter(|(_, sources)| !sources.is_empty())
            .map(|(bucket, sources)| (bucket.clone(), bucket_tag(bucket, sources)))
            .collect();
        if let Some(dir) = &cache_dir {
            Self::retire_stale_buckets(dir, &bucket_tags);
            Self::write_manifest(
                dir,
                &YaraManifest {
                    builtin_count,
                    third_party_count,
                    inline_namespaces,
                    rule_contexts: self.rule_contexts.clone(),
                    populated_tiers: self.populated_tiers.iter().cloned().collect(),
                    source_tag: current_tag.map(|t| format!("{t:016x}")),
                    engine_tag: Some(format!("{:016x}", engine_tag())),
                    cleave_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    bucket_tags: bucket_tags.clone(),
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
            bucket_tags,
            traits_dir,
            third_party_dir,
            enable_third_party,
            sources,
        };

        (builtin_count, third_party_count)
    }

    fn yaml_string_list(value: Option<&serde_json::Value>) -> Vec<String> {
        match value {
            Some(serde_json::Value::Array(seq)) => seq
                .iter()
                .filter_map(|v| v.as_str().map(std::string::ToString::to_string))
                .collect(),
            Some(serde_json::Value::String(s)) => vec![s.to_string()],
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
    /// [`crate::analyzers::FileTypeExt::yara_filetypes`]) take priority. Canonical
    /// source-language labels are expanded into their scan buckets. Otherwise
    /// the rule's derived [`RuleContext`] filetypes are
    /// used, falling back to [`FALLBACK_BUCKET`] when nothing constrains it.
    fn classify_inline_trait_yara_tiers(
        source: &str,
        namespace: &str,
        declared_for: &[String],
    ) -> Vec<String> {
        // Reuse capability parsing so group names and exclusions have the
        // same meaning here as in the trait that consumes the YARA match.
        let parsed = crate::capabilities::parse_file_types(declared_for, &mut Vec::new());
        let mut buckets: Vec<String> = parsed
            .types
            .into_iter()
            .map(|ft| ft.label().to_string())
            .filter(|ft| ft != "unknown" && ft != "all")
            .flat_map(|ft| {
                let canonical = yara_classify::canonical_binary_filetype(&ft);
                if matches!(canonical, "pe" | "elf" | "macho" | "ne") {
                    vec![canonical.to_string()]
                } else if let Some(file_type) = FileType::from_label(&ft).or(match ft.as_str() {
                    "class" => Some(FileType::JavaClass),
                    "pyc" => Some(FileType::PythonBytecode),
                    "objectivec" => Some(FileType::ObjectiveC),
                    _ => None,
                }) {
                    file_type
                        .yara_filetypes()
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                } else {
                    vec![ft]
                }
            })
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
    #[cfg(test)]
    fn collect_inline_trait_sources_tiered(
        traits_dir: &Path,
    ) -> (HashMap<String, Vec<(String, String)>>, Vec<String>) {
        Self::collect_inline_trait_sources_tiered_with_sources(traits_dir, None)
    }

    fn collect_inline_trait_sources_tiered_with_sources(
        traits_dir: &Path,
        sources: Option<&crate::rule_sources::RuleSources>,
    ) -> (HashMap<String, Vec<(String, String)>>, Vec<String>) {
        let yaml_files: Vec<PathBuf> = if let Some(sources) = sources {
            sources
                .files()
                .iter()
                .filter(|file| {
                    !file.follows_directory_symlink()
                        && true
                        && matches!(
                            file.relative_path.extension().and_then(|e| e.to_str()),
                            Some("yaml" | "yml")
                        )
                })
                .map(|file| traits_dir.join(&file.relative_path))
                .collect()
        } else {
            WalkDir::new(traits_dir)
                .follow_links(false)
                .into_iter()
                .filter_entry(crate::traits_repo::is_rule_source_entry)
                .filter_map(std::result::Result::ok)
                .filter(|e| {
                    let p = e.path();
                    p.is_file()
                        && p.extension()
                            .map(|ext| ext == "yaml" || ext == "yml")
                            .unwrap_or(false)
                })
                .map(|e| e.path().to_path_buf())
                .collect()
        };

        let collect_one = |path: &PathBuf| {
            let Some(bytes) = Self::read_source(sources, traits_dir, path) else {
                return vec![];
            };
            let Ok(content) = std::str::from_utf8(&bytes) else {
                return vec![];
            };
            // Parsing every trait file to find the few that hold inline YARA
            // was over a quarter of a small file's cold analysis; on
            // only 457 of 19,611 files could hold one.
            if !may_spell_yara(content) {
                return vec![];
            }
            let Ok(doc) = crate::yaml::from_str::<serde_json::Value>(content) else {
                return vec![];
            };

            let defaults_for = match &doc {
                serde_json::Value::Object(m) => {
                    Self::yaml_string_list(m.get("defaults").and_then(|v| v.get("for")))
                }
                _ => Vec::new(),
            };

            let items = match &doc {
                serde_json::Value::Object(m) => m
                    .get("traits")
                    .and_then(|v| v.as_array())
                    .map(|s| s.to_vec()),
                serde_json::Value::Array(s) => Some(s.clone()),
                _ => None,
            };

            let Some(items) = items else { return vec![] };

            let prefix = path
                .strip_prefix(traits_dir)
                .ok()
                .and_then(|p| p.parent())
                .map(|p| p.to_string_lossy().replace('\\', "/"));

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
                let qualified_id = crate::traits_repo::qualify_trait_id(id, prefix.as_deref());
                let namespace = format!("inline.{qualified_id}");
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
        let collected: Vec<(String, String, String)> = off_pool_flat_map(&yaml_files, collect_one);

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

    /// Scan bytes, preserving both reportable matches and inline-trait evidence.
    ///
    /// Scanners are cached per-thread to avoid expensive re-creation.
    ///
    /// A concrete filter scans the named file-type buckets plus the fallback
    /// bucket; `None` scans every populated bucket. Filtering applies to both
    /// result channels and never discards inline evidence.
    pub(crate) fn scan_bytes(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<YaraScan> {
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
        // every bucket without cross-thread churn.
        let scan_one = |bucket: &String| {
            self.tier_rules(bucket).map(|rules| {
                let started = std::time::Instant::now();
                let result = Self::run_scanner(rules, data);
                (bucket.clone(), started.elapsed().as_millis() as u64, result)
            })
        };
        let all_raw: Vec<(String, u64, Result<Vec<RawRule>>)> =
            if data.len() < TIER_PARALLEL_MIN_BYTES || !crate::rayon_nest::inner_work_parallel() {
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

        Ok(YaraScan {
            matches: yara_matches,
            inline_traits: inline_results,
        })
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
    /// The cache is keyed by the address of the `Rules` allocation; each entry
    /// holds a clone of `rules`, so that address cannot be reused by other
    /// rules while it is cached.
    fn run_scanner(rules: &Arc<yara_x::Rules>, data: &[u8]) -> Result<Vec<RawRule>> {
        let key = Arc::as_ptr(rules) as usize;

        // Scan and collect results inside the thread-local borrow so ScanResults
        // (which borrows the Scanner) is consumed before the RefCell is released.
        ENGINE_SCANNER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache.get(&key).is_none() {
                let mut entry = cached_scanner::CachedScanner::new(Arc::clone(rules));
                entry.with(|s| {
                    s.set_timeout(SCAN_TIMEOUT);
                    // Keep candidate evaluation bounded without truncating it to
                    // the eight ranges retained for display. Native decoder rules
                    // routinely inspect dozens of sites before a target matches.
                    s.max_matches_per_pattern(MAX_SCANNER_PATTERN_MATCHES);
                });
                tracing::debug!("Created new YARA scanner for tier (ptr={:#x})", key);
                cache.put(key, entry);
            }
            let Some(entry) = cache.get_mut(&key) else {
                anyhow::bail!("scanner cache entry missing after insertion");
            };

            let (raw_rules_result, scan_elapsed) = entry.with(|scanner| {
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
                                                .map(|(k, v)| (k.to_string(), meta_text(&v)))
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
                            let msg = crate::panic_payload_message(&panic_payload);
                            YARA_SCANS_DISABLED_AFTER_PANIC.store(true, Ordering::Relaxed);
                            tracing::error!(error = %msg, "YARA scan panicked");
                            Err(anyhow::anyhow!("YARA scan panicked: {}", msg))
                        }
                    };
                let scan_elapsed = scan_start.elapsed();

                // Log any rule that exceeded 1s using yara-x's profiling.
                #[cfg(feature = "yara-profiling")]
                if raw_rules_result.is_ok() {
                    let aggregate = yara_rule_timing::enabled();
                    for pd in scanner.slowest_rules(20) {
                        if aggregate {
                            yara_rule_timing::record(
                                pd.namespace,
                                pd.rule,
                                pd.pattern_matching_time,
                                pd.condition_exec_time,
                            );
                        }
                        let condition_ms = pd.condition_exec_time.as_millis() as u64;
                        let pattern_ms = pd.pattern_matching_time.as_millis() as u64;
                        if condition_ms + pattern_ms >= 1_000 {
                            let trait_id =
                                crate::third_party_yara::derive_trait_id(pd.namespace, pd.rule);
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
                (raw_rules_result, scan_elapsed)
            });

            // Scanner/ScanResults borrow is now released. Evict the cached
            // scanner if the scan failed or took unreasonably long — yara-x may
            // not cleanly reset internal state after a timeout.
            // A cached scanner keeps the module structs (`pe`, `elf`, `dotnet`, …)
            // parsed from its *last* input until its next scan replaces them —
            // yara-x resets the context at scan start, never at scan end. With
            // 64 scanners per thread over 8 threads that idle state measured
            // ~380–440 MB of a 4.2 GB worker heap. Above this input size the
            // scanner is dropped after use; re-instantiating one is cheap
            // next to a scan of that size.
            let evict_for_size = data.len() >= YARA_EVICT_ABOVE_BYTES;
            if evict_for_size {
                cache.pop(&key);
            }
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

    /// Check if rules are loaded
    #[must_use]
    pub(crate) fn is_loaded(&self) -> bool {
        !self.populated_tiers.is_empty()
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
        let _ = cell.set(Some(Arc::new(rules)));
        self.populated_tiers.insert(FALLBACK_BUCKET.to_string());
        // Source stays `Empty`: the pre-set cell above is returned directly, so
        // `build_tier` is never consulted for this bucket.
        self.rule_counts = (count, 0);
        Ok(())
    }
}

/// A rule's metadata value as plain text: strings verbatim, numbers and
/// booleans in their usual spelling.
fn meta_text(value: &yara_x::MetaValue<'_>) -> String {
    match value {
        yara_x::MetaValue::String(s) => (*s).to_string(),
        yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f) => f.to_string(),
        yara_x::MetaValue::Bool(b) => b.to_string(),
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Tests use direct assertions and helpers for brevity
mod tests;

/// `CLEAVE_YARA_RULE_TIMING=1` (with the `yara-profiling` feature): sum
/// yara-x's per-rule profiling (each scan's
/// 20 slowest rules) across the whole scan and log the top consumers at the
/// end ([`yara_rule_timing::report`]). The per-scan "Slow YARA rule" warning
/// only sees single scans over a second; a rule that costs 50 ms on each of
/// thousands of members never shows there. Off by default: one cached flag.
#[cfg(feature = "yara-profiling")]
pub(crate) mod yara_rule_timing {
    use parking_lot::Mutex;
    use rustc_hash::FxHashMap;
    use std::sync::OnceLock;
    use std::time::Duration;

    type Totals = FxHashMap<(String, String), (Duration, Duration, u64)>;
    static TOTALS: Mutex<Option<Totals>> = Mutex::new(None);

    pub(crate) fn enabled() -> bool {
        static ON: OnceLock<bool> = OnceLock::new();
        *ON.get_or_init(|| crate::env::flag("CLEAVE_YARA_RULE_TIMING"))
    }

    pub(crate) fn record(namespace: &str, rule: &str, pattern: Duration, condition: Duration) {
        let key = (namespace.to_string(), rule.to_string());
        let mut guard = TOTALS.lock();
        let entry = guard
            .get_or_insert_with(Totals::default)
            .entry(key)
            .or_default();
        entry.0 += pattern;
        entry.1 += condition;
        entry.2 += 1;
        drop(guard);
    }

    pub(crate) fn report(top: usize) {
        if !enabled() {
            return;
        }
        let mut rows: Vec<_> = match TOTALS.lock().as_ref() {
            Some(totals) => totals.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            None => return,
        };
        rows.sort_by_key(|(_, (p, c, _))| std::cmp::Reverse(*p + *c));
        for ((namespace, rule), (pattern, condition, scans)) in rows.into_iter().take(top) {
            tracing::info!(
                namespace = %namespace,
                rule = %rule,
                pattern_ms = pattern.as_millis() as u64,
                condition_ms = condition.as_millis() as u64,
                scans,
                "yara rule time aggregate"
            );
        }
    }
}
