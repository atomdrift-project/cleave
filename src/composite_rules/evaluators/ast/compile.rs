//! Compiling AST queries: from a saved pattern analysis where one exists, and
//! a grammar's whole bank across the pool the first time it is needed.

use super::{QUERY_CACHE, cached_ast_query};
use crate::composite_rules::types::FileType;

/// Compile `source` for `lang`, reusing the pattern analysis an earlier
/// process recorded for it: analysis is most of what a compile costs, and a
/// grammar's bank is a thousand queries. `None` when it does not compile.
pub(crate) fn compile_query(
    lang: &tree_sitter::Language,
    source: &str,
) -> Option<tree_sitter::Query> {
    let grammar = format!(
        "{}:{:?}:{}:{}:{}:{}",
        lang.name().unwrap_or("<unnamed>"),
        lang.metadata()
            .map(|m| (m.major_version, m.minor_version, m.patch_version)),
        lang.abi_version(),
        lang.node_kind_count(),
        lang.parse_state_count(),
        lang.field_count()
    );
    crate::capabilities::derivation_memo::with_ast_analysis(&grammar, source, |analysis| {
        tree_sitter::Query::with_analysis(lang, source, analysis).ok()
    })
}

/// Compile the queries of `query_strs` the cache lacks, across the pool. A
/// grammar's first file otherwise compiles its whole bank on one thread while
/// every other file of that language waits behind it. Called with no lock
/// held: a pool thread waiting here runs other analyses, which take them.
pub(super) fn compile_missing(
    lang: &tree_sitter::Language,
    file_type: FileType,
    query_strs: &[&str],
) {
    use rayon::prelude::*;
    let cache = QUERY_CACHE.read();
    let known = cache.get(lang);
    let missing: Vec<&str> = query_strs
        .iter()
        .copied()
        .filter(|&q| known.is_none_or(|queries| !queries.contains_key(q)))
        .collect();
    drop(cache);
    if missing.len() > 1 {
        missing.par_iter().for_each(|q| {
            cached_ast_query(lang, file_type, q);
        });
    }
}
