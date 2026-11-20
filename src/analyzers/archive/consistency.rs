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

/// What a package's `.pth` startup hooks load, resolved against the
/// package's own members. site.py executes a `.pth` import line in every
/// interpreter on the host, so a hook that lands on a native extension or on
/// sourceless bytecode runs code at every startup that no source-level rule
/// can read. The link is what matters: pywin32 ships a `.pth` and native
/// modules, but its hook imports a Python module.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PthStartupImports {
    /// Hook imports that resolve to a native extension (`.so`, `.pyd`).
    pub(super) native: u64,
    /// Hook imports that resolve to bytecode with no source beside it.
    pub(super) bytecode: u64,
}

/// How a module name resolves, in import-system precedence: extension
/// modules are found before source, source before legacy bytecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ModuleKind {
    Bytecode,
    Source,
    Native,
}

/// A directory path with each segment's leading underscores removed, the
/// form `Import::symbol` normalization leaves a dotted module path in.
fn normalized_dir(dir: &str) -> String {
    dir.split('/')
        .map(|segment| segment.trim_start_matches('_'))
        .collect::<Vec<_>>()
        .join("/")
}

/// The module a member provides, as (directory, normalized name, kind).
/// Names lose leading underscores to match `Import::symbol` normalization.
/// `__pycache__` bytecode is ignored: Python never imports it without source.
fn member_module(inner: &str) -> Option<(String, String, ModuleKind)> {
    let (dir, file) = inner.rsplit_once('/').unwrap_or(("", inner));
    if dir.ends_with("__pycache__") {
        return None;
    }
    let lower = file.to_ascii_lowercase();
    let kind = if lower.ends_with(".so") || lower.ends_with(".pyd") {
        ModuleKind::Native
    } else if lower.ends_with(".py") {
        ModuleKind::Source
    } else if lower.ends_with(".pyc") {
        ModuleKind::Bytecode
    } else {
        return None;
    };
    // `mod.cpython-312-x86_64-linux-gnu.so` and `mod.abi3.so` provide `mod`;
    // a package's `__init__` provides the package itself (empty name).
    let stem = file.split('.').next().unwrap_or_default();
    let name = if stem == "__init__" {
        ""
    } else {
        stem.trim_start_matches('_')
    };
    (!name.is_empty() || stem == "__init__").then(|| (normalized_dir(dir), name.to_string(), kind))
}

/// Count `.pth` hook imports that resolve to native or sourceless members.
/// `None` when the archive ships no `.pth` file.
pub(super) fn compute_pth_startup_imports(report: &AnalysisReport) -> Option<PthStartupImports> {
    // Paths relative to this archive; a nested member is `owner!inner`, and
    // resolution never crosses from one nested archive into another.
    let members: Vec<(String, String, &crate::types::FileAnalysis)> = report
        .files
        .iter()
        .map(|f| {
            let rel = archive_member_relative_path(&report.target.path, &f.path);
            let (owner, inner) = rel.rsplit_once('!').unwrap_or(("", &rel));
            (owner.to_string(), inner.to_string(), f)
        })
        .collect();

    let mut modules: std::collections::HashMap<(&str, String, String), ModuleKind> =
        std::collections::HashMap::new();
    for (owner, inner, _) in &members {
        if let Some((dir, name, kind)) = member_module(inner) {
            let best = modules.entry((owner.as_str(), dir, name)).or_insert(kind);
            *best = (*best).max(kind);
        }
    }

    let mut counts = PthStartupImports::default();
    let mut saw_pth = false;
    let mut resolved = std::collections::HashSet::new();
    for (owner, inner, f) in &members {
        if !inner.to_ascii_lowercase().ends_with(".pth") {
            continue;
        }
        saw_pth = true;
        let parent = inner.rsplit_once('/').map_or("", |(dir, _)| dir);
        // A wheel's `<dist>.data/purelib` hook sits beside modules installed
        // from the wheel root.
        let mut roots = vec![parent];
        if parent.ends_with(".data/purelib") || parent.ends_with(".data/platlib") {
            roots.push("");
        }
        let live = f.imports.iter().map(|imp| imp.symbol.as_str());
        let compacted = f
            .precompact_facts
            .as_ref()
            .into_iter()
            .flat_map(|facts| facts.imports.iter().map(|imp| imp.name.as_str()));
        for symbol in live.chain(compacted) {
            let parts: Vec<&str> = symbol.split('.').filter(|p| !p.is_empty()).collect();
            let Some((last, package)) = parts.split_last() else {
                continue;
            };
            // The first root that provides the module is the one imported.
            let kind = roots.iter().find_map(|root| {
                let join = |segments: &[&str]| {
                    let joined = std::iter::once(*root)
                        .chain(segments.iter().copied())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join("/");
                    normalized_dir(&joined)
                };
                // `a.b.c` is `a/b/c.<ext>` or the package `a/b/c/__init__`.
                let candidates = [
                    (join(package), last.trim_start_matches('_').to_string()),
                    (join(&parts), String::new()),
                ];
                candidates
                    .into_iter()
                    .filter_map(|(dir, name)| modules.get(&(owner.as_str(), dir, name)).copied())
                    .max()
            });
            let counter = match kind {
                Some(ModuleKind::Native) => &mut counts.native,
                Some(ModuleKind::Bytecode) => &mut counts.bytecode,
                _ => continue,
            };
            if resolved.insert((owner.as_str(), symbol)) {
                *counter += 1;
            }
        }
    }
    saw_pth.then_some(counts)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::types::{FileAnalysis, Import};

    fn member(path: &str, file_type: &str, imports: &[&str]) -> FileAnalysis {
        let mut f = FileAnalysis::new(0, path.into(), file_type.into(), String::new(), 0);
        f.imports = imports.iter().map(|s| Import::new(*s, None)).collect();
        f
    }

    fn pth(path: &str, imports: &[&str]) -> FileAnalysis {
        member(path, "python", imports)
    }

    fn file(path: &str) -> FileAnalysis {
        let file_type = if path.ends_with(".py") {
            "python"
        } else {
            "macho"
        };
        member(path, file_type, &[])
    }

    fn resolve(files: Vec<FileAnalysis>) -> Option<PthStartupImports> {
        let mut report = AnalysisReport::new(TargetInfo::default());
        report.files = files;
        compute_pth_startup_imports(&report)
    }

    fn counts(native: u64, bytecode: u64) -> PthStartupImports {
        PthStartupImports { native, bytecode }
    }

    #[test]
    fn pth_import_resolving_to_native_extension_counts() {
        // agent-framework shape, with the payload compiled: the hook's import
        // lands on a native extension. `_diag_hook` arrives normalized.
        let got = resolve(vec![
            pth("af_runtime_diag.pth", &["os", "sys", "_diag_hook"]),
            file("_diag_hook.cpython-312-x86_64-linux-gnu.so"),
        ]);
        assert_eq!(got, Some(counts(1, 0)));
    }

    #[test]
    fn pywin32_shape_does_not_count() {
        // The hook imports a Python bootstrap; native modules load normally.
        let got = resolve(vec![
            pth("pywin32.pth", &["pywin32_bootstrap"]),
            file("pywin32_bootstrap.py"),
            file("win32/win32api.cp312-win_amd64.pyd"),
        ]);
        assert_eq!(got, Some(counts(0, 0)));
    }

    #[test]
    fn extension_module_wins_over_source() {
        // FileFinder tries extension suffixes before source suffixes.
        let got = resolve(vec![
            pth("hook.pth", &["accel"]),
            file("accel.py"),
            file("accel.abi3.so"),
        ]);
        assert_eq!(got, Some(counts(1, 0)));
    }

    #[test]
    fn dotted_import_and_native_package_init_resolve() {
        let got = resolve(vec![
            pth("a.pth", &["pkg._accel"]),
            pth("b.pth", &["native_pkg"]),
            file("pkg/__init__.py"),
            file("pkg/_accel.cpython-312-darwin.so"),
            file("native_pkg/__init__.cpython-312-darwin.so"),
        ]);
        assert_eq!(got, Some(counts(2, 0)));
    }

    #[test]
    fn underscored_package_directory_resolves() {
        // `_pkg.mod` normalizes to `pkg.mod`; the member directory is `_pkg`.
        let got = resolve(vec![
            pth("hook.pth", &["_pkg.mod"]),
            file("_pkg/mod.cpython-312-darwin.so"),
        ]);
        assert_eq!(got, Some(counts(1, 0)));
    }

    #[test]
    fn sourceless_bytecode_counts_but_pycache_does_not() {
        let legacy = resolve(vec![pth("hook.pth", &["plain"]), file("plain.pyc")]);
        assert_eq!(legacy, Some(counts(0, 1)));
        // __pycache__ bytecode is never imported without its source.
        let cached = resolve(vec![
            pth("hook.pth", &["plain"]),
            file("__pycache__/plain.cpython-312.pyc"),
        ]);
        assert_eq!(cached, Some(counts(0, 0)));
        let with_source = resolve(vec![
            pth("hook.pth", &["plain"]),
            file("plain.py"),
            file("plain.pyc"),
        ]);
        assert_eq!(with_source, Some(counts(0, 0)));
    }

    #[test]
    fn site_packages_and_wheel_data_roots() {
        // conda/deb layouts resolve beside the hook; a wheel's .data/purelib
        // hook also resolves against the wheel root.
        let conda = resolve(vec![
            pth("lib/python3.12/site-packages/hook.pth", &["agent"]),
            file("lib/python3.12/site-packages/agent.cpython-312-darwin.so"),
            file("agent.cpython-312-darwin.so"),
        ]);
        assert_eq!(conda, Some(counts(1, 0)));
        let wheel_data = resolve(vec![
            pth("dist-1.0.data/purelib/hook.pth", &["agent"]),
            file("agent.cpython-312-darwin.so"),
        ]);
        assert_eq!(wheel_data, Some(counts(1, 0)));
        // A module elsewhere in the package is not on the hook's path.
        let elsewhere = resolve(vec![
            pth("lib/python3.12/site-packages/hook.pth", &["agent"]),
            file("tools/agent.cpython-312-darwin.so"),
        ]);
        assert_eq!(elsewhere, Some(counts(0, 0)));
    }

    #[test]
    fn nested_archives_do_not_link_to_each_other() {
        let got = resolve(vec![
            pth("a.tar.gz!!hook.pth", &["agent"]),
            file("b.tar.gz!!agent.cpython-312-darwin.so"),
        ]);
        assert_eq!(got, Some(counts(0, 0)));
        let same = resolve(vec![
            pth("a.tar.gz!!hook.pth", &["agent"]),
            file("a.tar.gz!!agent.cpython-312-darwin.so"),
        ]);
        assert_eq!(same, Some(counts(1, 0)));
    }

    #[test]
    fn duplicate_imports_count_once() {
        let got = resolve(vec![
            pth("a.pth", &["agent"]),
            pth("b.pth", &["agent", "agent"]),
            file("agent.cpython-312-darwin.so"),
        ]);
        assert_eq!(got, Some(counts(1, 0)));
    }

    #[test]
    fn none_without_pth() {
        assert_eq!(resolve(vec![file("agent.cpython-312-darwin.so")]), None);
    }

    #[test]
    fn reads_precompacted_imports() {
        // Compact retention clears live imports and keeps precompacted names
        // (see `phantom_dep_reads_precompacted_imports`).
        let mut hook = pth("hook.pth", &["agent"]);
        hook.precompact_facts = Some(crate::types::compact::compact_facts_from_parts(
            &hook, false,
        ));
        hook.imports = Vec::new();
        let got = resolve(vec![hook, file("agent.cpython-312-darwin.so")]);
        assert_eq!(got, Some(counts(1, 0)));
    }
}
