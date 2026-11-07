//! The one package-consistency judgement that compares archive members with
//! each other: runtime dependencies no shipped module imports. The judgement
//! itself is filefacts' (`package_context::unused_runtime_dependencies`);
//! this gathers what it judges from the members. Every single-manifest
//! judgement (typosquat, copied identity, cloned summary, self-dependency,
//! extension-pack composition) is emitted by filefacts with its parse.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// `package.json` runtime `dependencies` that no shipped module imports, as
/// `filefacts::package_context::unused_runtime_dependencies` judges them from
/// the manifest member's `dependencies.*` names and the code members'
/// imports. `None` when there is nothing to judge.
pub(super) fn compute_unused_runtime_deps(report: &AnalysisReport) -> Option<u64> {
    const DEP_PREFIX: &str = "dependencies.";

    // Declared runtime dependency names, read from the package.json member's
    // flattened kv (`dependencies.<name>` → version scalar). `<name>` may carry
    // a scope (`@scope/pkg`) or a dot (`lodash.merge`); the whole remainder is
    // the name.
    let declared = report
        .files
        .iter()
        .filter(|f| {
            Path::new(&f.path)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("package.json"))
        })
        .flat_map(|f| f.kv.keys())
        .filter_map(|k| k.strip_prefix(DEP_PREFIX));

    // Every module specifier imported by a *code* member. The manifest and
    // lockfiles are skipped: cleave surfaces a package.json's declared
    // dependencies as `imports` (so `type: import` matchers can target them),
    // and counting those here would make every dependency look "used" and mask
    // the very phantom we are hunting.
    let is_manifest_like = |path: &str| {
        Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| {
                n.eq_ignore_ascii_case("package.json")
                    || n.eq_ignore_ascii_case("package-lock.json")
                    || n.eq_ignore_ascii_case("npm-shrinkwrap.json")
            })
    };
    // `imports` is cleared on every member under compact retention
    // (`precompact_member_facts`), whose comment assumed nothing between the
    // fold and compact conversion reads it — this function does, at container
    // scope, and so saw zero imports and bailed out through the
    // "no imports observed" guard below. The names survive in the precompacted
    // facts, so read those when the live vector is gone: no member holds its
    // symbol table any longer, and the metric works on both paths again.
    let imported = report
        .files
        .iter()
        .filter(|f| !is_manifest_like(&f.path))
        .flat_map(|f| {
            let live = f.imports.iter().map(|imp| imp.symbol.as_str());
            let compacted = f
                .precompact_facts
                .as_ref()
                .into_iter()
                .flat_map(|facts| facts.imports.iter().map(|imp| imp.name.as_str()));
            live.chain(compacted)
        });
    filefacts::package_context::unused_runtime_dependencies(declared, imported)
}
