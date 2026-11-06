//! Package-consistency metrics: typosquats, identity mismatches, cloned summaries, self and phantom dependencies.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Popular / high-value PyPI package names, one edit away from which a
/// distribution name is almost certainly a typosquat.
///
/// This is public knowledge -- top-download and documented impersonation
/// targets -- not derived from any sample set. `boto` is intentionally absent
/// even though it is real, because it collides at distance 1 with `boto3` and
/// would make the legitimate legacy package flag itself.
pub(super) const POPULAR_PACKAGES: &[&str] = &[
    "requests",
    "urllib3",
    "boto3",
    "botocore",
    "setuptools",
    "numpy",
    "pandas",
    "python-dateutil",
    "six",
    "certifi",
    "idna",
    "charset-normalizer",
    "wheel",
    "pip",
    "typing-extensions",
    "packaging",
    "pyyaml",
    "cryptography",
    "click",
    "jinja2",
    "flask",
    "django",
    "fastapi",
    "aiohttp",
    "httpx",
    "starlette",
    "pydantic",
    "sqlalchemy",
    "scipy",
    "scikit-learn",
    "matplotlib",
    "pillow",
    "torch",
    "tensorflow",
    "keras",
    "transformers",
    "openai",
    "langchain",
    "langchain-openai",
    "discord",
    "discord-py",
    "colorama",
    "rich",
    "tqdm",
    "beautifulsoup4",
    "lxml",
    "selenium",
    "pytest",
    "attrs",
    "markupsafe",
    "werkzeug",
    "itsdangerous",
    "redis",
    "pymongo",
    "psycopg2",
    "protobuf",
    "grpcio",
    "pycryptodome",
    "paramiko",
    "web3",
    "eth-account",
    "eth-utils",
    "eth-abi",
    "solana",
    "pyfiglet",
    "s3transfer",
    "crytic-compile",
    "psutil",
    "pyjwt",
    "oauthlib",
    "pytz",
    "babel",
    "sphinx",
    "tornado",
    "gunicorn",
    "uvicorn",
    "celery",
    "dnspython",
    "figlet",
];

/// Canonical one-line PyPI summaries of popular packages, paired with the
/// distribution name that owns each. Public knowledge -- the target project's
/// own published tagline -- not derived from any sample set.
///
/// Only *distinctive* multi-word summaries belong here: a rename-clone copies
/// the target's metadata verbatim, so a summary that matches one of these while
/// the package's own `Name` is something else is copied identity with the label
/// swapped (`fluxhttp` shipping aiohttp's "Async http client/server framework
/// (asyncio)"). Exact normalised match is required, so a generic tagline would
/// never earn a place here and a real package (whose `Name` is the owner) is
/// exempt by construction. Entries are safe to extend: a wrong string simply
/// never matches.
pub(super) const POPULAR_SUMMARIES: &[(&str, &str)] = &[
    ("async http client/server framework (asyncio)", "aiohttp"),
    ("python http for humans.", "requests"),
    ("cross-platform colored terminal text.", "colorama"),
    ("composable command line interface toolkit", "click"),
    ("the uncompromising code formatter.", "black"),
    ("fast, extensible progress meter", "tqdm"),
    ("screen-scraping library", "beautifulsoup4"),
    ("data validation using python type hints", "pydantic"),
    ("the little asgi library that shines.", "starlette"),
];

/// True if `a` and `b` differ by at most one single-character edit
/// (substitution, insertion, or deletion) -- Levenshtein distance <= 1.
pub(super) fn within_one_edit(a: &str, b: &str) -> bool {
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if la == lb {
        // one substitution allowed
        return ab.iter().zip(bb).filter(|(x, y)| x != y).count() <= 1;
    }
    // lengths differ by one: the shorter must be the longer with one char removed
    let (short, long) = if la < lb { (ab, bb) } else { (bb, ab) };
    let (mut i, mut j, mut skipped) = (0usize, 0usize, false);
    while i < short.len() && j < long.len() {
        if short[i] == long[j] {
            i += 1;
            j += 1;
        } else if skipped {
            return false;
        } else {
            skipped = true;
            j += 1;
        }
    }
    true
}

/// Flag a distribution whose name is one edit away from a popular package but
/// is not that package -- the classic typosquat shape (`colotama` for
/// `colorama`, `rsquests` for `requests`).
///
/// Name-only, so it needs no cross-member data; it lives here beside the other
/// consistency metrics because it is a package-level judgement the per-file
/// matchers cannot make (they see one string, not its distance to a reference
/// set). Suspicious, not hostile: a near-miss name is strong evidence of
/// intent to be confused with the target, but the payload -- if any -- is a
/// separate question the objectives answer.
///
/// Returns `Some(1)` when the name typosquats a listed package, `Some(0)` when
/// a name was read but is clean, `None` when no distribution name was found.
pub(super) fn compute_name_typosquat(report: &AnalysisReport) -> Option<u64> {
    fn norm(s: &str) -> String {
        s.trim().to_ascii_lowercase().replace(['_', '.'], "-")
    }
    let mut name: Option<String> = None;
    for f in &report.files {
        let base = Path::new(&f.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if (base.eq_ignore_ascii_case("PKG-INFO") || base.eq_ignore_ascii_case("METADATA"))
            && let Some(n) = f.kv.get("name").and_then(|v| v.as_str())
        {
            let n = norm(n);
            if !n.is_empty() {
                name = Some(n);
                break;
            }
        }
    }
    let name = name?;
    // An exact listed name is the real package, not a squat.
    if POPULAR_PACKAGES.contains(&name.as_str()) {
        return Some(0);
    }
    let squat = POPULAR_PACKAGES.iter().any(|p| within_one_edit(&name, p));
    Some(u64::from(squat))
}

/// Detect a package that copied another project's identity but changed its
/// name.
///
/// A typosquat that ships the real library verbatim keeps its target's
/// metadata -- the summary, the homepage repo, the importable module all still
/// say `eth-account` -- and only edits the distribution `Name` to the
/// confusable spelling (`ether-account`). Each of those advertised-identity
/// fields is compared against the declared `Name`; when two or more of them
/// agree with *each other* on a normalised name that is not the declared one,
/// the package is presenting an identity it did not name itself.
///
/// Two converging fields are required rather than one, because a single
/// mismatch is ordinary: distribution names legitimately differ from their
/// import module (`scikit-learn` ships `sklearn`, `pillow` ships `PIL`), and a
/// homepage can point at a monorepo. What is not ordinary is the summary, the
/// homepage repo, and the module all naming the *same other* package while the
/// `Name` alone diverges -- that is copied metadata with the label swapped.
///
/// Returns the count of fields converging on the impersonated name (>= 2), or
/// `None` when the package carries no distribution metadata to judge.
pub(super) fn compute_metadata_identity_mismatch(report: &AnalysisReport) -> Option<u64> {
    fn norm(s: &str) -> String {
        s.trim().to_ascii_lowercase().replace(['_', '.'], "-")
    }

    for f in &report.files {
        let base = Path::new(&f.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if !(base.eq_ignore_ascii_case("PKG-INFO") || base.eq_ignore_ascii_case("METADATA")) {
            continue;
        }
        let Some(name) = f.kv.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let name = norm(name);
        if name.is_empty() {
            continue;
        }

        let mut advertised: Vec<String> = Vec::new();

        // Summary that opens `pkgname: description` -- the ecosystem convention
        // of prefixing the one-line summary with the package's own name.
        if let Some(summary) = f.kv.get("summary").and_then(|v| v.as_str())
            && let Some((prefix, _)) = summary.split_once(':')
        {
            let p = prefix.trim();
            if !p.is_empty()
                && p.len() <= 60
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                advertised.push(norm(p));
            }
        }

        // Homepage that points at a GitHub repo -- the repo's own name.
        if let Some(hp) = f.kv.get("home-page").and_then(|v| v.as_str())
            && let Some(rest) = hp.split("github.com/").nth(1)
            && let Some(repo) = rest.split('/').nth(1)
        {
            let repo = repo.trim_end_matches(['/', ' ']);
            if !repo.is_empty() {
                advertised.push(norm(repo));
            }
        }

        // Note: the importable module name (from `top_level.txt`) would be a
        // third signal, but member strings are cleared before this runs at
        // container scope, so only the two metadata fields above are reliable
        // here. Both must diverge for the threshold, which keeps this to the
        // clear case of copied summary *and* homepage.

        // How many advertised fields converge on the same name that is not the
        // declared one?
        use std::collections::HashMap;
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for a in &advertised {
            if *a != name {
                *counts.entry(a.as_str()).or_insert(0) += 1;
            }
        }
        let best = counts.values().copied().max().unwrap_or(0);
        return Some(if best >= 2 { best } else { 0 });
    }
    None
}

/// Detect a full library republished under a different distribution name.
///
/// The rename-clone (a.k.a. provenance-only clone) ships a working popular
/// library with every internal identifier renamed, so its metadata is
/// self-consistent -- `metadata_identity_mismatch` sees nothing -- and its code
/// carries no injected payload for the objectives to catch. The one place the
/// swap leaks is the one-line summary: renaming the source rarely rewrites the
/// human tagline, so the clone advertises the target's distinctive summary
/// under a name that is not the target's.
///
/// Matched by exact normalised equality against a bundled table of popular
/// packages' own published summaries (`POPULAR_SUMMARIES`). The real package is
/// exempt by construction -- its `Name` is the owner -- so this fires only when
/// the summary says one package and the name says another. Distinctive taglines
/// only, and exact match, keep the false-positive rate at essentially zero: two
/// unrelated projects do not independently write the same multi-word summary.
///
/// Returns `Some(1)` when the summary clones a listed package under a different
/// name, `Some(0)` when a summary was read but matches nothing (or is the real
/// owner), and `None` when no distribution summary was found.
pub(super) fn compute_cloned_summary(report: &AnalysisReport) -> Option<u64> {
    fn norm_name(s: &str) -> String {
        s.trim().to_ascii_lowercase().replace(['_', '.'], "-")
    }
    fn norm_summary(s: &str) -> String {
        s.trim()
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    for f in &report.files {
        let base = Path::new(&f.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if !(base.eq_ignore_ascii_case("PKG-INFO") || base.eq_ignore_ascii_case("METADATA")) {
            continue;
        }
        let Some(name) = f.kv.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(summary) = f.kv.get("summary").and_then(|v| v.as_str()) else {
            continue;
        };
        let name = norm_name(name);
        let summary = norm_summary(summary);
        if name.is_empty() || summary.is_empty() {
            continue;
        }
        for (canon_summary, owner) in POPULAR_SUMMARIES {
            if summary == *canon_summary && name != norm_name(owner) {
                return Some(1);
            }
        }
        return Some(0);
    }
    None
}

/// Count declared dependencies that name the package itself.
///
/// A manifest that lists its own name among its dependencies describes a
/// package that cannot resolve: the installer is told to fetch, as a
/// prerequisite for this release, the very release it is installing. No
/// working build produces it, which is why it shows up in name reservations
/// and dependency-confusion placeholders — the manifest is assembled to hold a
/// name rather than to install anything, and the dependency list is filled in
/// from the package's own identity.
///
/// The tree already carried this as two family-specific traits
/// (`base58-core-self-dependency`, and the pucuk5000 note); the shape recurs
/// across ecosystems, so it belongs here as one fact rather than one trait per
/// campaign.
///
/// Decided only where both halves are structured data: an npm `package.json`
/// (`name` + `dependencies.*`) and Python distribution metadata (`Name:` +
/// `Requires-Dist:` in `PKG-INFO`/`METADATA`, or the `requires.txt` setuptools
/// writes beside it in `*.egg-info/`). A `setup.py` declares `install_requires`
/// in code, and cleave surfaces its strings without the field they belong to,
/// so that spelling alone is not decidable -- but an sdist built from one
/// carries the same list in `requires.txt`, which is.
///
/// Returns `None` when no manifest carries both a name and a dependency list,
/// so the metric is absent rather than zero on packages it cannot judge.
pub(super) fn compute_self_dependency(report: &AnalysisReport) -> Option<u64> {
    // PEP 503 normalisation, and npm's case rules, both reduce to this.
    fn norm(s: &str) -> String {
        s.trim()
            .trim_matches('"')
            .to_ascii_lowercase()
            .replace(['_', '.'], "-")
    }
    // `Requires-Dist: foo[extra] >=1.0 ; python_version < "3.9"` -> `foo`.
    fn dep_name(spec: &str) -> &str {
        spec.split(|c: char| c == '[' || c == ';' || c == '(' || c.is_whitespace())
            .next()
            .unwrap_or("")
            .trim_end_matches(|c: char| "<>=!~,".contains(c))
    }

    let mut judged = false;
    let mut self_deps = 0u64;
    for f in &report.files {
        let base = Path::new(&f.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if base.eq_ignore_ascii_case("package.json") {
            let Some(name) = f.kv.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let name = norm(name);
            if name.is_empty() {
                continue;
            }
            let mut saw_dep = false;
            for dep in f.kv.keys().filter_map(|k| k.strip_prefix("dependencies.")) {
                saw_dep = true;
                if norm(dep) == name {
                    self_deps += 1;
                }
            }
            if saw_dep {
                judged = true;
            }
        } else if base.eq_ignore_ascii_case("PKG-INFO") || base.eq_ignore_ascii_case("METADATA") {
            let Some(name) = f.kv.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let name = norm(name);
            if name.is_empty() {
                continue;
            }
            // Repeated `Requires-Dist:` headers flatten to one key; every
            // spelling of the value is checked so a single or multi-valued
            // entry behaves the same.
            let mut saw_dep = false;
            for (k, v) in &f.kv {
                // Flattening turns repeated headers into `requires-dist[0]`,
                // `requires-dist[1]`, ...; an unflattened single value keeps
                // the bare key. Accept both.
                let key_matches = k.eq_ignore_ascii_case("requires-dist")
                    || k.get(..14)
                        .is_some_and(|p| p.eq_ignore_ascii_case("requires-dist["));
                if !key_matches {
                    continue;
                }
                saw_dep = true;
                // Repeated headers arrive as an array; a single one as a
                // scalar. Both spellings are the same list.
                let specs: Vec<&str> = match v {
                    serde_json::Value::Array(items) => {
                        items.iter().filter_map(|i| i.as_str()).collect()
                    }
                    serde_json::Value::String(one) => vec![one.as_str()],
                    _ => continue,
                };
                for spec in specs.iter().flat_map(|s| s.split([',', '\n'])) {
                    if norm(dep_name(spec)) == name {
                        self_deps += 1;
                    }
                }
            }
            if saw_dep {
                judged = true;
            }
        }
    }

    // `*.egg-info/requires.txt`: setuptools' rendering of `install_requires`,
    // one requirement per line, with `[extra]` section headers for the
    // optional groups. Only the leading section applies to a plain install,
    // and the distribution name comes from the metadata member handled above.
    let dist_names: Vec<String> = report
        .files
        .iter()
        .filter(|f| {
            let base = Path::new(&f.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            base.eq_ignore_ascii_case("PKG-INFO") || base.eq_ignore_ascii_case("METADATA")
        })
        .filter_map(|f| f.kv.get("name").and_then(|v| v.as_str()))
        .map(norm)
        .filter(|n| !n.is_empty())
        .collect();
    if !dist_names.is_empty() {
        for f in &report.files {
            let base = Path::new(&f.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if !base.eq_ignore_ascii_case("requires.txt") {
                continue;
            }
            judged = true;
            for s in &f.strings {
                for line in s.value.as_ref().lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('[') || line.starts_with('#') {
                        continue;
                    }
                    let dep = norm(dep_name(line));
                    if !dep.is_empty() && dist_names.contains(&dep) {
                        self_deps += 1;
                    }
                }
            }
        }
    }

    judged.then_some(self_deps)
}

/// Count `package.json` runtime `dependencies` that no shipped module imports.
///
/// A phantom runtime dependency — declared but never `import`ed/`require`d
/// anywhere in the package's own code — is the fingerprint of an install-time
/// payload: a hijacked publisher appends a malicious package to `dependencies`
/// (its `postinstall` does the work) without touching the code that would
/// reference it. The June 2026 Mastra scope-takeover injected `easy-day-js`
/// exactly this way.
///
/// Returns `None` (no metric emitted) unless the archive holds a `package.json`
/// with runtime dependencies *and* at least one import was observed across its
/// members — without any imports we cannot distinguish "unused" from "we never
/// parsed the code", and a types-only / asset package would false-positive.
///
/// Matching is by package name: an import specifier counts as a use of dep `D`
/// when it equals `D` or begins with `D/` (a subpath import like
/// `dayjs/plugin/utc`). Only `dependencies` is considered — never
/// `devDependencies`/`peerDependencies`/`optionalDependencies`, which the
/// shipped runtime code is not expected to import.
pub(super) fn compute_unused_runtime_deps(report: &AnalysisReport) -> Option<u64> {
    const DEP_PREFIX: &str = "dependencies.";

    // Declared runtime dependency names, read from the package.json member's
    // flattened kv (`dependencies.<name>` → version scalar). `<name>` may carry
    // a scope (`@scope/pkg`) or a dot (`lodash.merge`); the whole remainder is
    // the name.
    let declared: Vec<&str> = report
        .files
        .iter()
        .filter(|f| {
            Path::new(&f.path)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("package.json"))
        })
        .flat_map(|f| f.kv.keys())
        .filter_map(|k| k.strip_prefix(DEP_PREFIX))
        .collect();
    if declared.is_empty() {
        return None;
    }

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
    let imported: Vec<&str> = report
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
        })
        .collect();
    if imported.is_empty() {
        return None;
    }

    let used = |dep: &str| {
        imported
            .iter()
            .any(|spec| *spec == dep || spec.strip_prefix(dep).is_some_and(|r| r.starts_with('/')))
    };
    Some(declared.iter().filter(|dep| !used(dep)).count() as u64)
}

/// How a VS Code extension pack is composed: `(total entries, entries the
/// publisher owns)`.
///
/// An extension pack contributes no code of its own — `extensionPack` is a list
/// of marketplace ids the editor installs alongside it, each written
/// `publisher.name`. A vendor's pack is mostly the vendor's own extensions, and
/// a community "awesome tools" pack is entirely other people's. The laundering
/// shape sits between: forty genuinely popular third-party extensions as
/// ballast around one or two entries from the publisher, so the listing reads
/// as a curated toolkit while the entry that matters is installed with it. The
/// pack itself never looks hostile, because it is only a list.
///
/// Two neutral counts rather than a verdict — where the line falls between
/// curation and laundering is a trait's policy, not this function's.
///
/// `None` when the manifest declares no pack, or declares no publisher to
/// compare entries against.
pub(super) fn extension_pack_counts(report: &AnalysisReport) -> Option<(u64, u64)> {
    let manifest = report.files.iter().find(|f| {
        Path::new(&f.path)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("package.json"))
    })?;

    // A member's kv is flattened, so the array arrives as `extensionPack[0]`,
    // `extensionPack[1]`, ... rather than as one JSON array.
    let entries: Vec<&str> = manifest
        .kv
        .iter()
        .filter(|(k, _)| {
            k.strip_prefix("extensionPack[")
                .is_some_and(|rest| rest.ends_with(']'))
        })
        .filter_map(|(_, v)| v.as_str())
        .collect();
    if entries.is_empty() {
        return None;
    }

    let publisher = manifest
        .kv
        .get("publisher")
        .and_then(serde_json::Value::as_str)?;
    if publisher.is_empty() {
        return None;
    }

    // `publisher.name`: the publisher is everything before the first dot, since
    // neither half of a marketplace id may itself contain one.
    let own = entries
        .iter()
        .filter(|entry| {
            entry
                .split_once('.')
                .is_some_and(|(owner, _)| owner.eq_ignore_ascii_case(publisher))
        })
        .count();

    Some((entries.len() as u64, own as u64))
}
