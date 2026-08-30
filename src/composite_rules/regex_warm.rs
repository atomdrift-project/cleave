//! Learned regex pre-compile list for long-lived processes.
//!
//! Trait regexes compile lazily on first use. On a fresh process the first
//! file pays every compile its rules need — for an 8.5 KB pure-Python wheel
//! that is ~640 ms of a ~640 ms analysis (the same wheel takes ~100 ms once
//! the Python rules are warm), most of it `regex_automata` building full DFAs
//! for `type: path`/`basename` rules on the archive's calling thread.
//!
//! This module records the exact keys handed to the two compile paths
//! ([`crate::composite_rules::condition::cached_regex`] and the raw-bytes
//! store behind `compile_bytes_regex`) the first time they compile, persists
//! that list beside the other cache memos, and on the next startup compiles
//! it on a few plain background threads while the process is still loading
//! models and fetching its first jobs. Only patterns this deployment has
//! actually needed are warmed, so nothing is compiled that the workload
//! would not have compiled anyway, and the compiled-regex stores stay
//! byte-budgeted exactly as before. Results are unaffected by construction:
//! a warm entry is the same `Arc` a lazy compile would have produced.

use parking_lot::Mutex;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

const FILE_NAME: &str = "regex-warm-v1.json";

/// Cap on remembered patterns; a rule set has ~20k regexes, so this only
/// trips if the memo is somehow fed garbage.
const MAX_ENTRIES: usize = 60_000;

#[derive(Default, Serialize, Deserialize)]
struct Data {
    /// `cached_regex` keys (already `(?i)`-prefixed where applicable), in
    /// first-seen order so the warm compiles the earliest-needed first.
    str_patterns: Vec<String>,
    /// `(pattern, case_insensitive)` keys of the raw-bytes store.
    bytes_patterns: Vec<(String, bool)>,
    /// `(pattern, case_insensitive)` keys of the `regex` facade cache
    /// (`build_regex`: `type: encoded` decoders and AST-query predicates).
    #[serde(default)]
    facade_patterns: Vec<(String, bool)>,
}

struct State {
    data: Data,
    str_seen: FxHashSet<String>,
    bytes_seen: FxHashSet<(String, bool)>,
    facade_seen: FxHashSet<(String, bool)>,
    dirty: bool,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| {
        let data = load().unwrap_or_default();
        let str_seen = data.str_patterns.iter().cloned().collect();
        let bytes_seen = data.bytes_patterns.iter().cloned().collect();
        let facade_seen = data.facade_patterns.iter().cloned().collect();
        Mutex::new(State {
            data,
            str_seen,
            bytes_seen,
            facade_seen,
            dirty: false,
        })
    })
}

fn memo_path() -> Option<std::path::PathBuf> {
    crate::cache::cache_dir().ok().map(|d| d.join(FILE_NAME))
}

fn load() -> Option<Data> {
    let mut bytes = std::fs::read(memo_path()?).ok()?;
    match simd_json::from_slice::<Data>(&mut bytes) {
        Ok(data) => {
            tracing::debug!(
                str_patterns = data.str_patterns.len(),
                bytes_patterns = data.bytes_patterns.len(),
                "loaded regex warm memo"
            );
            Some(data)
        }
        Err(e) => {
            tracing::debug!(error = %e, "regex warm memo unreadable; starting empty");
            None
        }
    }
}

/// Remember a `cached_regex` key that just compiled.
pub(crate) fn record_str(pattern: &str) {
    let mut s = state().lock();
    if s.str_seen.len() >= MAX_ENTRIES || s.str_seen.contains(pattern) {
        return;
    }
    s.str_seen.insert(pattern.to_owned());
    s.data.str_patterns.push(pattern.to_owned());
    s.dirty = true;
}

/// Remember a raw-bytes store key that just compiled.
pub(crate) fn record_bytes(pattern: &str, case_insensitive: bool) {
    let mut s = state().lock();
    let key = (pattern.to_owned(), case_insensitive);
    if s.bytes_seen.len() >= MAX_ENTRIES || s.bytes_seen.contains(&key) {
        return;
    }
    s.bytes_seen.insert(key.clone());
    s.data.bytes_patterns.push(key);
    s.dirty = true;
}

/// Remember a `build_regex` (regex facade) key that just compiled.
pub(crate) fn record_facade(pattern: &str, case_insensitive: bool) {
    let mut s = state().lock();
    let key = (pattern.to_owned(), case_insensitive);
    if s.facade_seen.len() >= MAX_ENTRIES || s.facade_seen.contains(&key) {
        return;
    }
    s.facade_seen.insert(key.clone());
    s.data.facade_patterns.push(key);
    s.dirty = true;
}

/// Flush the memo to disk if anything was recorded since the last flush.
/// Cheap when clean; safe to call from a periodic tick.
pub(crate) fn persist() {
    let snapshot = {
        let mut s = state().lock();
        if !s.dirty {
            return;
        }
        s.dirty = false;
        match simd_json::to_vec(&s.data) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "regex warm memo serialize failed");
                return;
            }
        }
    };
    let Some(path) = memo_path() else { return };
    let Some(dir) = path.parent() else { return };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let tmp = dir.join(format!("{FILE_NAME}.tmp.{}", std::process::id()));
    if std::fs::write(&tmp, &snapshot).is_ok() && std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Compile every remembered pattern on `threads` plain background threads.
/// Returns immediately. `threads == 0` disables the warm.
pub(crate) fn warm_background(threads: usize) {
    static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if threads == 0 || STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let (strs, bytes, facade) = {
        let s = state().lock();
        (
            s.data.str_patterns.clone(),
            s.data.bytes_patterns.clone(),
            s.data.facade_patterns.clone(),
        )
    };
    if strs.is_empty() && bytes.is_empty() && facade.is_empty() {
        return;
    }
    if let Err(e) = std::thread::Builder::new()
        .name("regex-prewarm".into())
        .spawn(move || warm_now(&strs, &bytes, &facade, threads))
    {
        tracing::warn!(error = %e, "could not spawn regex prewarm thread");
    }
}

fn warm_now(strs: &[String], bytes: &[(String, bool)], facade: &[(String, bool)], threads: usize) {
    let started = std::time::Instant::now();
    let next = AtomicUsize::new(0);
    let total = strs.len() + bytes.len() + facade.len();
    let threads = threads.clamp(1, total.max(1));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    if i < strs.len() {
                        let _ = crate::composite_rules::condition::cached_regex(&strs[i]);
                    } else if i < strs.len() + bytes.len() {
                        let (pattern, ci) = &bytes[i - strs.len()];
                        crate::composite_rules::evaluators::warm_bytes_regex(pattern, *ci);
                    } else {
                        let (pattern, ci) = &facade[i - strs.len() - bytes.len()];
                        let _ = crate::composite_rules::evaluators::build_regex(pattern, *ci);
                    }
                }
            });
        }
    });
    tracing::info!(
        str_patterns = strs.len(),
        bytes_patterns = bytes.len(),
        facade_patterns = facade.len(),
        threads,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "prewarmed trait regexes from memo"
    );
}
