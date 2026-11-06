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
//! It also keeps the literals each tree-sitter query requires
//! ([`ast_literals`]), so a later process can rule a query out for a file
//! without compiling it.
//!
//! Invalidation: an *algorithm* change to any derivation function must bump
//! the version in [`FILE_NAME`]; stale files are simply abandoned. Corrupt or
//! unreadable files degrade to an empty memo (everything recomputes, correctness
//! unaffected). Writes are atomic (tempfile + rename); concurrent processes
//! last-writer-wins over equivalent content.

use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

// v2: mandatory_atom_set landed (any-of alternation atoms, CI runs,
// anchored prefix composition, engine-mirrored parse mode). The v1 files
// on disk hold atom_set entries computed by in-development revisions of
// that algorithm; abandoning them recomputes everything once (~2.3 s).
// v3: prefix literals stop at the last whole UTF-8 character; v2 files hold
// U+FFFD-substituted prefixes for patterns whose common prefix split one.
const FILE_NAME: &str = "regex-derivations-v3.json";

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
    /// tree-sitter query text -> per pattern, the any-of literal sets every
    /// match contains (`ast_gate::RequiredLiterals`). A pure function of the
    /// query text: capture quantifiers come from the pattern's own structure,
    /// not the grammar. Only queries that compiled are recorded; a query that
    /// did not is always compiled again. Additive, like `atom_set`.
    #[serde(default)]
    ast_literals: FxHashMap<String, AstLiterals>,
}

/// The stored form of `ast_gate::RequiredLiterals`.
pub(crate) type AstLiterals = Vec<Vec<Vec<(Vec<u8>, bool)>>>;

/// The memo: what was loaded from disk, which never changes afterwards and so
/// is read without a lock, and what this process derived since, behind one.
/// The index builds read it from every pool thread at once; a shared lock on
/// the loaded entries measured ~5% of a small-archive run as reader contention.
struct Memo {
    loaded: MemoData,
    added: RwLock<MemoData>,
    dirty: AtomicBool,
}

static MEMO: OnceLock<Memo> = OnceLock::new();

fn memo() -> &'static Memo {
    MEMO.get_or_init(|| Memo {
        loaded: load().unwrap_or_default(),
        added: RwLock::new(MemoData::default()),
        dirty: AtomicBool::new(false),
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

/// The memoized value of `pattern` in `field`, computing and recording it with
/// `compute` on a miss.
fn memoized<T: Clone>(
    pattern: &str,
    field: fn(&MemoData) -> &FxHashMap<String, T>,
    field_mut: fn(&mut MemoData) -> &mut FxHashMap<String, T>,
    compute: impl FnOnce() -> T,
) -> T {
    let memo = memo();
    if let Some(hit) = field(&memo.loaded).get(pattern) {
        return hit.clone();
    }
    if let Some(hit) = field(&memo.added.read()).get(pattern) {
        return hit.clone();
    }
    let computed = compute();
    field_mut(&mut memo.added.write()).insert(pattern.to_owned(), computed.clone());
    memo.dirty.store(true, Ordering::Relaxed);
    computed
}

/// Memoized [`super::indexes::StringMatchIndex::extract_regex_literal`].
pub(crate) fn prefix_literal(pattern: &str) -> Option<String> {
    memoized(
        pattern,
        |d| &d.prefix,
        |d| &mut d.prefix,
        || super::indexes::StringMatchIndex::extract_regex_literal(pattern),
    )
}

/// Memoized UTF-8 projection of
/// [`crate::composite_rules::evaluators::best_mandatory_atom`] — every index
/// call site immediately discards non-UTF-8 atoms, so only the string form is
/// stored.
pub(crate) fn mandatory_atom_utf8(pattern: &str) -> Option<String> {
    memoized(
        pattern,
        |d| &d.atom,
        |d| &mut d.atom,
        || {
            crate::composite_rules::evaluators::best_mandatory_atom(pattern)
                .and_then(|b| String::from_utf8(b).ok())
        },
    )
}

/// Memoized [`crate::composite_rules::evaluators::mandatory_atom_set`].
pub(crate) fn mandatory_atom_set(pattern: &str) -> Option<Vec<(String, bool)>> {
    memoized(
        pattern,
        |d| &d.atom_set,
        |d| &mut d.atom_set,
        || crate::composite_rules::evaluators::mandatory_atom_set(pattern),
    )
}

thread_local! {
    /// Per-thread view of `atom_set`, handing out borrows instead of clones.
    static LOCAL_ATOM_SETS: std::cell::RefCell<FxHashMap<Box<str>, Option<std::sync::Arc<Vec<(String, bool)>>>>> =
        std::cell::RefCell::new(FxHashMap::default());
}

/// Run `f` over the memoized atom set of `pattern` without cloning it.
///
/// [`mandatory_atom_set`] returns an owned `Vec<String>` clone taken under the
/// shared read lock; the raw-window check calls it once per (trait x member),
/// and that clone + lock traffic measured ~13 s of pool time per corpus. The
/// per-thread map resolves each pattern once per thread and then answers
/// from a borrow with no shared-state access at all.
pub(crate) fn with_mandatory_atom_set<R>(
    pattern: &str,
    f: impl FnOnce(Option<&[(String, bool)]>) -> R,
) -> R {
    LOCAL_ATOM_SETS.with(|cell| {
        let mut map = cell.borrow_mut();
        if !map.contains_key(pattern) {
            let shared = mandatory_atom_set(pattern).map(std::sync::Arc::new);
            map.insert(Box::from(pattern), shared);
        }
        f(map
            .get(pattern)
            .and_then(|v| v.as_deref().map(Vec::as_slice)))
    })
}

/// Run `f` over the literals `query` requires, if a process that compiled it
/// recorded them.
pub(crate) fn with_ast_literals<R>(query: &str, f: impl FnOnce(&AstLiterals) -> R) -> Option<R> {
    let memo = memo();
    if let Some(hit) = memo.loaded.ast_literals.get(query) {
        return Some(f(hit));
    }
    memo.added.read().ast_literals.get(query).map(f)
}

/// Record the literals `query` requires, derived from its compiled form.
pub(crate) fn record_ast_literals(query: &str, literals: AstLiterals) {
    let memo = memo();
    if memo.loaded.ast_literals.contains_key(query)
        || memo.added.read().ast_literals.contains_key(query)
    {
        return;
    }
    memo.added
        .write()
        .ast_literals
        .insert(query.to_owned(), literals);
    memo.dirty.store(true, Ordering::Relaxed);
}

/// Flush the memo to disk if any entry was added since load. Called after the
/// match indexes finish building, and after each top-level analysis, which is
/// when tree-sitter queries first compile.
pub(crate) fn persist() {
    let memo = memo();
    if !memo.dirty.swap(false, Ordering::Relaxed) {
        return;
    }
    let Some(path) = memo_path() else { return };
    let bytes = {
        let added = memo.added.read();
        // Serialize the union without cloning the loaded maps: entries are
        // only ever added, so a key in both carries the same value.
        #[derive(Serialize)]
        struct Union<'a> {
            prefix: Merged<'a, Option<String>>,
            atom: Merged<'a, Option<String>>,
            atom_set: Merged<'a, Option<Vec<(String, bool)>>>,
            ast_literals: Merged<'a, AstLiterals>,
        }
        struct Merged<'a, T>(&'a FxHashMap<String, T>, &'a FxHashMap<String, T>);
        impl<T: Serialize> Serialize for Merged<'_, T> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_map(
                    self.0
                        .iter()
                        .chain(self.1.iter().filter(|(k, _)| !self.0.contains_key(*k))),
                )
            }
        }
        serde_json::to_vec(&Union {
            prefix: Merged(&memo.loaded.prefix, &added.prefix),
            atom: Merged(&memo.loaded.atom, &added.atom),
            atom_set: Merged(&memo.loaded.atom_set, &added.atom_set),
            ast_literals: Merged(&memo.loaded.ast_literals, &added.ast_literals),
        })
    };
    // pid-suffixed so two cold processes never interleave writes into one tmp.
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    match bytes {
        Ok(bytes)
            if std::fs::write(&tmp, &bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok() =>
        {
            tracing::debug!(bytes = bytes.len(), "persisted regex derivation memo");
        }
        // Keep the entries owed to disk for the next flush.
        _ => memo.dirty.store(true, Ordering::Relaxed),
    }
}
