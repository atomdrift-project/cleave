//! Persistent memo of pure regex-pattern derivations used by the match-index
//! builds: prefix literals ([`super::indexes::StringMatchIndex::extract_regex_literal`])
//! and mandatory atoms ([`crate::composite_rules::evaluators::best_mandatory_atom`],
//! UTF-8 side). Both derive from the pattern string alone, so entries are
//! content-addressed by the pattern itself and survive traits updates unchanged —
//! a ruleset update only computes derivations for patterns it actually added.
//!
//! Why this exists: the four match indexes re-derived every pattern on every
//! process start (~2.3 s wall of regex_syntax parsing per invocation), which
//! dominated cold-start for single-sample scans. With the memo warm the same
//! work is a hash lookup.
//!
//! Invalidation: an *algorithm* change to either derivation function must bump
//! the version in [`FILE_NAME`]; stale files are simply abandoned. Corrupt or
//! unreadable files degrade to an empty memo (everything recomputes, correctness
//! unaffected). Writes are atomic (tempfile + rename); concurrent processes
//! last-writer-wins over equivalent content.

use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// v2: mandatory_atom_set landed (any-of alternation atoms, CI runs,
// anchored prefix composition, engine-mirrored parse mode). The v1 files
// on disk hold atom_set entries computed by in-development revisions of
// that algorithm; abandoning them recomputes everything once (~2.3 s).
const FILE_NAME: &str = "regex-derivations-v2.json";

#[derive(Default, Serialize, Deserialize)]
struct MemoData {
    /// pattern -> guaranteed match prefix (>= 3 chars), or None if inextractable.
    prefix: FxHashMap<String, Option<String>>,
    /// pattern -> longest mandatory UTF-8 literal atom, or None if inextractable.
    atom: FxHashMap<String, Option<String>>,
    /// pattern -> mandatory any-of atom set (atom, case_insensitive), or None.
    /// Additive field: files written before it deserialize with an empty map
    /// and recompute lazily.
    #[serde(default)]
    atom_set: FxHashMap<String, Option<Vec<(String, bool)>>>,
}

struct Memo {
    data: MemoData,
    dirty: bool,
}

static MEMO: OnceLock<RwLock<Memo>> = OnceLock::new();

fn memo() -> &'static RwLock<Memo> {
    MEMO.get_or_init(|| {
        let data = load().unwrap_or_default();
        RwLock::new(Memo { data, dirty: false })
    })
}

fn memo_path() -> Option<std::path::PathBuf> {
    crate::cache::cache_dir().ok().map(|d| d.join(FILE_NAME))
}

fn load() -> Option<MemoData> {
    let mut bytes = std::fs::read(memo_path()?).ok()?;
    match simd_json::from_slice::<MemoData>(&mut bytes) {
        Ok(data) => {
            tracing::debug!(
                prefixes = data.prefix.len(),
                atoms = data.atom.len(),
                "loaded regex derivation memo"
            );
            Some(data)
        }
        Err(e) => {
            tracing::debug!(error = %e, "regex derivation memo unreadable; recomputing");
            None
        }
    }
}

/// Memoized [`super::indexes::StringMatchIndex::extract_regex_literal`].
pub(crate) fn prefix_literal(pattern: &str) -> Option<String> {
    if let Some(hit) = memo().read().data.prefix.get(pattern) {
        return hit.clone();
    }
    let computed = super::indexes::StringMatchIndex::extract_regex_literal(pattern);
    let mut guard = memo().write();
    guard
        .data
        .prefix
        .insert(pattern.to_owned(), computed.clone());
    guard.dirty = true;
    computed
}

/// Memoized UTF-8 projection of
/// [`crate::composite_rules::evaluators::best_mandatory_atom`] — every index
/// call site immediately discards non-UTF-8 atoms, so only the string form is
/// stored.
pub(crate) fn mandatory_atom_utf8(pattern: &str) -> Option<String> {
    if let Some(hit) = memo().read().data.atom.get(pattern) {
        return hit.clone();
    }
    let computed = crate::composite_rules::evaluators::best_mandatory_atom(pattern)
        .and_then(|b| String::from_utf8(b).ok());
    let mut guard = memo().write();
    guard.data.atom.insert(pattern.to_owned(), computed.clone());
    guard.dirty = true;
    computed
}

/// Memoized [`crate::composite_rules::evaluators::mandatory_atom_set`].
pub(crate) fn mandatory_atom_set(pattern: &str) -> Option<Vec<(String, bool)>> {
    if let Some(hit) = memo().read().data.atom_set.get(pattern) {
        return hit.clone();
    }
    let computed = crate::composite_rules::evaluators::mandatory_atom_set(pattern);
    let mut guard = memo().write();
    guard
        .data
        .atom_set
        .insert(pattern.to_owned(), computed.clone());
    guard.dirty = true;
    computed
}

/// Flush the memo to disk if any entry was added since load. Called once after
/// the match indexes finish building — the only phase that computes derivations.
pub(crate) fn persist() {
    let guard = memo().read();
    if !guard.dirty {
        return;
    }
    let Some(path) = memo_path() else { return };
    let Ok(bytes) = serde_json::to_vec(&guard.data) else {
        return;
    };
    drop(guard);
    // pid-suffixed so two cold processes never interleave writes into one tmp.
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    if std::fs::write(&tmp, &bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
        memo().write().dirty = false;
        tracing::debug!(bytes = bytes.len(), "persisted regex derivation memo");
    }
}
