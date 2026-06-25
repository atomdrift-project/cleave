//! Resolving a file's references to the other files in the same report.
//!
//! filefacts emits each [`filefacts::Reference`] as a locator — a PURL/URL for
//! an external dependency, or a [`filefacts::RefLocator::Path`] for an
//! intra-artifact file. This module turns a locator into the *id of another
//! file in this report* when one matches: an external dependency that is
//! vendored in the bundle (its declared identity is a member), or a relative
//! path that resolves to a sibling member.
//!
//! Resolution is exact, never a guess. An external match requires the PURL's
//! package name to equal a file's declared [`identity`](filefacts::Identity)
//! name; an internal match joins the relative path against the referrer's
//! directory — bounded by the archive container (`!!`) it cannot escape — and
//! requires the full result to equal another file's path. Both feed the
//! first-class edge (`CompactRef.target_file`) and the malicious-reference
//! propagation in `finalize`.

use crate::types::Criticality;

/// The package name a PURL addresses, scope decoded and version dropped:
/// `pkg:npm/left-pad@1.3.0` → `left-pad`, `pkg:npm/%40scope/util` →
/// `@scope/util`. `None` for a string that isn't a PURL.
pub(crate) fn package_name_from_purl(purl: &str) -> Option<String> {
    let body = purl.strip_prefix("pkg:")?;
    // Drop the ecosystem type segment (`npm/`, `pypi/`, …).
    let body = body.split_once('/').map(|(_, rest)| rest)?;
    // The version is after the last `@`; a scoped name's own `@` is `%40` in a
    // PURL, so the last `@` is unambiguously the version separator.
    let name = body.rsplit_once('@').map_or(body, |(n, _)| n);
    // Drop any subpath / qualifiers.
    let name = name.split(['?', '#']).next().unwrap_or(name);
    if name.is_empty() {
        return None;
    }
    Some(name.replace("%40", "@"))
}

/// The names a file declares for itself — its package/product `name` and its
/// canonical `identifier` — used as the target side of an external match.
pub(crate) fn identity_names(identity: &filefacts::Identity) -> Vec<&str> {
    let mut out = Vec::new();
    if let Some(c) = &identity.name {
        out.push(c.value.as_str());
    }
    if let Some(c) = &identity.identifier
        && !out.contains(&c.value.as_str())
    {
        out.push(c.value.as_str());
    }
    out
}

/// Resolve a relative path reference (`./lib/index.js`, `../shared/x.js`,
/// `bin/cli.js`) found in `referrer` to a full file path in the same report.
///
/// The path is joined against the referrer's directory and normalized. `..`
/// cannot climb past the innermost archive container (the last `!!`): a member
/// can only reference files inside its own bundle, so an over-reaching `..`
/// yields `None`. The result is the path a sibling file would carry, matched
/// verbatim against the report's files.
pub(crate) fn resolve_relative_path(referrer: &str, spec: &str) -> Option<String> {
    // Split off the archive container marker `..` must not cross. For a
    // non-archive (filesystem) path there is none, so the whole path is the
    // member and `..` is bounded by the path root.
    let split = referrer.rfind("!!").map_or(0, |i| i + 2);
    let (prefix, member) = referrer.split_at(split);

    let leading_slash = member.starts_with('/');
    let mut comps: Vec<&str> = member.split('/').filter(|c| !c.is_empty()).collect();
    comps.pop(); // drop the referrer's own basename → its directory

    for c in spec.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                comps.pop()?; // climbing past the container is unresolvable
            }
            other => comps.push(other),
        }
    }

    let mut joined = comps.join("/");
    if leading_slash {
        joined.insert(0, '/');
    }
    Some(format!("{prefix}{joined}"))
}

/// Resolve a `local` reference to the id of the file it names, applying
/// Node-style resolution: an exact match first, then the implicit extensions
/// (`./index` → `index.js`/`.cjs`/`.mjs`/`.json`) and the directory-index forms
/// (`./lib` → `lib/index.js`). `lookup` maps a candidate full path to a file id.
///
/// npm manifests routinely omit the extension (`"main": "./index"`) or point at
/// a directory, so exact matching alone silently drops real edges — the chai
/// trojan's `main` is `./index` with the file at `index.js`.
pub(crate) fn resolve_local_target<F>(referrer: &str, spec: &str, lookup: F) -> Option<u32>
where
    F: Fn(&str) -> Option<u32>,
{
    let base = resolve_relative_path(referrer, spec)?;
    if let Some(id) = lookup(&base) {
        return Some(id); // exact (the spec already carried its extension)
    }
    const EXTS: [&str; 5] = [".js", ".cjs", ".mjs", ".json", ".node"];
    for ext in EXTS {
        if let Some(id) = lookup(&format!("{base}{ext}")) {
            return Some(id);
        }
    }
    for index in ["/index.js", "/index.cjs", "/index.mjs", "/index.json"] {
        if let Some(id) = lookup(&format!("{base}{index}")) {
            return Some(id);
        }
    }
    None
}

/// The criticality a *referrer* inherits for pointing at a target with the
/// given verdict: one level below, and only for the strong verdicts that
/// warrant propagation. A hostile target makes the reference suspicious; a
/// suspicious one, notable. Anything weaker propagates nothing.
pub(crate) fn one_below(target: Criticality) -> Option<Criticality> {
    match target {
        Criticality::Hostile => Some(Criticality::Suspicious),
        Criticality::Suspicious => Some(Criticality::Notable),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_name_decodes_scope_and_drops_version() {
        assert_eq!(
            package_name_from_purl("pkg:npm/left-pad@1.3.0").as_deref(),
            Some("left-pad")
        );
        assert_eq!(
            package_name_from_purl("pkg:npm/left-pad").as_deref(),
            Some("left-pad")
        );
        assert_eq!(
            package_name_from_purl("pkg:npm/%40scope/util@2.1.0").as_deref(),
            Some("@scope/util")
        );
        assert_eq!(
            package_name_from_purl("pkg:pypi/requests@2.0").as_deref(),
            Some("requests")
        );
        assert_eq!(package_name_from_purl("./not/a/purl"), None);
    }

    #[test]
    fn relative_path_resolves_within_archive_member() {
        // A package.json deep in a vendored tree names its entry point; the
        // result is the sibling's full path, container preserved.
        assert_eq!(
            resolve_relative_path("pkg.zip!!node_modules/left-pad/package.json", "./index.js")
                .as_deref(),
            Some("pkg.zip!!node_modules/left-pad/index.js")
        );
        assert_eq!(
            resolve_relative_path("pkg.zip!!a/b/package.json", "bin/cli.js").as_deref(),
            Some("pkg.zip!!a/b/bin/cli.js")
        );
        // `..` climbs within the container.
        assert_eq!(
            resolve_relative_path("pkg.zip!!a/b/manifest.json", "../shared/x.js").as_deref(),
            Some("pkg.zip!!a/shared/x.js")
        );
    }

    #[test]
    fn relative_path_cannot_escape_the_container() {
        // `..` past the archive root is unresolvable — a member can't reach out.
        assert_eq!(
            resolve_relative_path("pkg.zip!!a/package.json", "../../etc/x"),
            None
        );
    }

    #[test]
    fn relative_path_preserves_absolute_filesystem_root() {
        assert_eq!(
            resolve_relative_path("/proj/sub/package.json", "../index.js").as_deref(),
            Some("/proj/index.js")
        );
    }

    #[test]
    fn local_target_applies_node_extension_resolution() {
        // The bundle has these files; resolve specs against them.
        let files = [
            ("pkg!!package/index.js", 1u32),
            ("pkg!!package/dist/mod.cjs", 2),
            ("pkg!!package/lib/index.mjs", 3),
        ];
        let lookup = |p: &str| files.iter().find(|(path, _)| *path == p).map(|(_, id)| *id);
        let referrer = "pkg!!package/package.json";

        // Extensionless `main` → `index.js` (the chai case).
        assert_eq!(resolve_local_target(referrer, "./index", lookup), Some(1));
        // Exact match still works.
        assert_eq!(
            resolve_local_target(referrer, "./dist/mod.cjs", lookup),
            Some(2)
        );
        // Directory → its index (`.mjs` here).
        assert_eq!(resolve_local_target(referrer, "./lib", lookup), Some(3));
        // Nothing matches → None.
        assert_eq!(resolve_local_target(referrer, "./missing", lookup), None);
    }

    #[test]
    fn one_below_only_propagates_strong_verdicts() {
        assert_eq!(
            one_below(Criticality::Hostile),
            Some(Criticality::Suspicious)
        );
        assert_eq!(
            one_below(Criticality::Suspicious),
            Some(Criticality::Notable)
        );
        assert_eq!(one_below(Criticality::Notable), None);
        assert_eq!(one_below(Criticality::Baseline), None);
    }
}
