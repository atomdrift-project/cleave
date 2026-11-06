//! File-type scope checks: dangling directory references, impossible types, containers.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Directory references that match no trait at all.
///
/// `broken-reference` validates exact `dir::id` references; a reference without
/// `::` is treated as a directory or short-name lookup and silently contributes
/// nothing when it resolves to zero traits.
///
/// Namespaces the analyzers synthesize at runtime are NOT dangling and must be
/// skipped: `metadata/import/<ecosystem>/<target>::<local-name>`, `metadata/signed/…`,
/// `metadata/entitlement/…`
/// and the rest are built from the file's own imports, code signature and
/// entitlements, so they never appear as static YAML and resolve only during a
/// scan. `is_dynamic_metadata_ref` in the loader is the authority; this must
/// stay in sync with it.
///
/// Returns `(rule id, clause, dangling reference)`.
/// Whether `ref_id` is an id (or directory) the analyzers can synthesize per
/// file. Checked against what each emitter can actually produce -- see
/// [`super::super::emitted::check_emitted_ref`] -- not waved through by prefix.
pub(crate) fn is_runtime_synthesized_namespace(ref_id: &str) -> bool {
    matches!(
        super::super::emitted::check_emitted_ref(ref_id),
        Some(Ok(()))
    )
}

pub(crate) fn find_dangling_directory_refs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, &'static str, String)> {
    let mut all_ids: Vec<&str> = trait_definitions.iter().map(|t| t.id.as_str()).collect();
    all_ids.extend(composite_rules.iter().map(|c| c.id.as_str()));
    let index = ReferenceIndex::new(all_ids);

    let mut cache: HashMap<String, Vec<&str>> = HashMap::new();
    let mut found = Vec::new();
    for rule in composite_rules {
        for (clause, conds) in [
            ("all", rule.all.as_ref()),
            ("any", rule.any.as_ref()),
            ("unless", rule.unless.as_ref()),
        ] {
            for id in conds
                .into_iter()
                .flatten()
                .flat_map(Condition::trait_references)
            {
                // Exact references are already covered by `broken-reference`.
                if id.contains("::") {
                    continue;
                }
                if is_runtime_synthesized_namespace(id) {
                    continue;
                }
                if resolve_cached(id, &index, &mut cache).is_empty() {
                    found.push((rule.id.clone(), clause, id.clone()));
                }
            }
        }
    }
    found
}

/// Find atomic traits whose `for:` mixes archive types with non-archive types.
///
/// An atomic has one matcher and runs on one node, and an archive node and the
/// files inside it are different nodes. cleave expands every archive into member
/// nodes and never runs a content scan over the container's own bytes -- a
/// `type: text` trait declared `for: [tar, shell]` can only ever fire through
/// the `shell` half, even though the marker is present verbatim in the tar's
/// bytes. (Compression is not what decides this: a *stored*, uncompressed zip
/// behaves the same.) So the two halves never both apply, and declaring both
/// hides which one the author meant.
///
/// Composites are deliberately exempt: one may bridge the two levels on
/// purpose, firing at the container for an archive and at the member for a
/// standalone file, and its `for:` says which nodes it is evaluated on.
///
/// `for: [all]` is exempt -- that is the sanctioned way to say "any node".
/// Group-derived lists are exempt too, because a named group can legitimately
/// expand to a mix (`data` covers `ipa` alongside `json`/`text`), and the YAML
/// the author wrote is a single group name.
///
/// Returns `(trait_id, archive_types, non_archive_types)`.
pub(crate) fn find_mixed_archive_filetype_traits(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, Vec<FileType>, Vec<FileType>)> {
    let mut violations = Vec::new();
    for t in trait_definitions {
        if t.for_from_groups || t.r#for.contains(&FileType::All) {
            continue;
        }
        // `type: path`/`basename` reads the analyzed node's OWN path, which
        // every node has regardless of whether it is an archive container or
        // a plain file -- unlike every other matcher kind, it never touches
        // file *content*, so the "cleave never content-scans a container's
        // own bytes" rationale this validator is built on does not apply to
        // it. `izpack-package-path` (`for: [jar, pe, shell, javascript,
        // java]`, `type: path`) is a legitimate single check on whichever
        // node's path matches, not five conflated facts -- 394 of the
        // tree's traits share this shape and none of them are the bug this
        // validator exists to catch.
        if matches!(t.r#if, Condition::Path(_)) {
            continue;
        }
        // `type: metrics` is measurement, not a content scan: `file.entropy`,
        // `consistency.*` and the `packing`/`obfuscation` scores are computed
        // for whatever node is being analysed, container and member alike. So
        // an archive type sitting beside a leaf type says nothing about
        // whether "only one half can fire" -- both halves can. The same is
        // NOT true of `type: value`: a container-scoped fact like
        // `archive.members[*].path` exists only on a node the archive
        // analyser cracked, so a leaf type listed beside it really is dead,
        // and that is this validator catching a real defect rather than
        // misfiring. Leave `value` alone.
        if matches!(t.r#if, Condition::Metrics(_)) {
            continue;
        }
        let (archive, plain): (Vec<_>, Vec<_>) =
            t.r#for.iter().partition(|ft| FileType::is_archive(ft));
        if !archive.is_empty() && !plain.is_empty() {
            violations.push((t.id.clone(), archive, plain));
        }
    }
    violations
}

/// Find composites whose `for:` lists a file type no required leg can match on.
///
/// A composite fires on one node. On a *leaf* node its `all:` legs must each be
/// able to match that node's type, so a declared type that some required leg
/// cannot match is dead: the rule can never fire on it.
///
/// `prepare-decoded-command-loader` declared `for: [javascript, typescript]`
/// while requiring `has-prepare`, which is a `package.json` field. On a
/// JavaScript node that leg can never match, so both leaf types were
/// unreachable -- the rule only ever fired on the npm package node, where the
/// container inherits the member findings. The correct `for:` was `[npm]`.
///
/// Archive types in the `for:` are skipped, because on a container the legs are
/// satisfied by inherited member findings rather than by matching the container
/// itself -- that is the whole point of a cross-archive scope. Directory
/// references and non-trait conditions are skipped too, since they resolve to
/// many definitions with differing `for:` lists.
///
/// Returns `(composite_id, impossible_type, blocking_leg_id)`.
pub(crate) fn find_impossible_composite_filetypes(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, FileType, String)> {
    let mut sink = Vec::new();
    find_impossible_composite_filetypes_inner(trait_definitions, composite_rules, &mut sink)
}

pub(super) fn find_impossible_composite_filetypes_inner(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    dead_rules: &mut Vec<String>,
) -> Vec<(String, FileType, String)> {
    let trait_for: HashMap<&str, &Vec<FileType>> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), &t.r#for))
        .collect();
    let composite_for: HashMap<&str, &Vec<FileType>> = composite_rules
        .iter()
        .map(|c| (c.id.as_str(), &c.r#for))
        .collect();

    // A retired metric leaves behind a `__cleave_missing_*__` placeholder trait
    // so its references do not dangle. That leg never matches anything, on any
    // type, so every consumer looks unreachable here -- which is true but is a
    // dead-leg problem, not a file-type one, and reporting it as the latter
    // sends the reader to the wrong fix.
    // The sentinel appears under whichever matcher the retired metric used --
    // `section` for the section-ratio ones, `string_literal` for the macOS
    // library fingerprints, and so on -- so match on the value wherever it
    // sits rather than enumerating condition kinds. Tenorshare's
    // `ts-lib-fingerprint-methods` is `string_literal: __cleave_missing_macos__`
    // and on its own made all sixteen composites in that file look dead.
    let is_retired_placeholder = |id: &str| -> bool {
        trait_definitions
            .iter()
            .find(|t| t.id == id)
            .is_some_and(|t| format!("{:?}", t.r#if).contains("__cleave_missing"))
    };

    let mut found = Vec::new();
    for rule in composite_rules {
        if rule.r#for.contains(&FileType::All) || rule.for_from_groups {
            continue;
        }
        // A pooling composite (`archive`/`package`/`outer`) runs on the
        // container and legitimately declares the *member* types whose
        // findings may satisfy its legs -- that is what `for:` means since the
        // origin filter landed (see SCOPE_PLAN.md). Those member types are not
        // leaf-match candidates, so asking "can every required leg match this
        // declared type on one node" is the wrong question for them: it made
        // this validator report a fresh violation for every member type the
        // `for:`-migration correctly added. `find_legs_outside_for` covers the
        // pooling case, from the other direction.
        if rule.effective_scope().pools_members() {
            continue;
        }
        let Some(required) = rule.all.as_ref() else {
            continue;
        };
        let before = found.len();
        let mut checkable = 0usize;
        for declared in &rule.r#for {
            // On a container the legs arrive as inherited member findings.
            if FileType::is_archive(declared) {
                continue;
            }
            checkable += 1;
            for cond in required {
                let Condition::Trait { id } = cond else {
                    continue;
                };
                // A *directory* reference resolves to many definitions with
                // differing `for:` lists, so it proves nothing here. A bare
                // same-directory name (`has-prepare`) is an ordinary trait
                // reference and must still be resolved -- skipping those was
                // what let `prepare-decoded-command-loader` past this check.
                if id.contains('/') && !id.contains("::") {
                    continue;
                }
                let own_dir = rule.id.split("::").next().unwrap_or("");
                let qualified = format!("{own_dir}::{id}");
                let Some(leg_for) = trait_for
                    .get(id.as_str())
                    .or_else(|| composite_for.get(id.as_str()))
                    .or_else(|| trait_for.get(qualified.as_str()))
                    .or_else(|| composite_for.get(qualified.as_str()))
                else {
                    continue;
                };
                if leg_for.contains(&FileType::All) || leg_for.contains(declared) {
                    continue;
                }
                if is_retired_placeholder(id) || is_retired_placeholder(&qualified) {
                    continue;
                }
                found.push((rule.id.clone(), *declared, id.clone()));
                break;
            }
        }
        // Every non-archive type it declares is unreachable AND it names no
        // container type: the rule cannot fire anywhere. That is a different
        // and worse problem than one dead entry in a list, so mark it. A
        // declared archive type is not itself re-checked here (its legs
        // arrive as inherited member findings, which this static check
        // cannot simulate), but its mere presence means the rule has a live
        // path to fire and must not be reported dead.
        //
        // A pooling scope (`outer`/`archive`/`package`) is the same escape
        // hatch even when `for:` names a non-archive container -- a
        // self-extracting PE (PyInstaller onefile) or an ISO with embedded
        // members pools its children's findings the same way an archive
        // does, without the container's FileType itself carrying the
        // `#[archive]` marker. `Scope::Archive` also degrades to `Outer`
        // (pools the whole input) when the container isn't nested inside an
        // archive at all, so it is never narrower than the type check below.
        let has_pooling_scope = rule.scope.is_some_and(Scope::pools_members);
        let names_container = rule.r#for.iter().any(FileType::is_archive) || has_pooling_scope;
        if checkable > 0 && found.len() - before == checkable && !names_container {
            dead_rules.push(rule.id.clone());
        }
    }
    found
}

/// Composites that cannot fire on *any* declared type -- see
/// [`find_impossible_composite_filetypes`], which records them as it goes.
pub(crate) fn find_dead_composites(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<String> {
    let mut dead = Vec::new();
    // Only the dead list is wanted here; the per-type detail is discarded.
    let _ =
        find_impossible_composite_filetypes_inner(trait_definitions, composite_rules, &mut dead);
    dead
}

/// A `scope: package` declaration that can never bind to a package boundary.
#[derive(Debug, Clone)]
pub(crate) struct UnbindablePackageScope {
    /// The offending composite's ID.
    pub id: String,
    /// Why it can never bind, phrased for the validator's output.
    pub reason: String,
}

/// True for a node type no package archive can ever contain.
///
/// [`FileType::Registry`] is the only one: normalized registry metadata is
/// synthesized from an API response *beside* the fetched artifact, not
/// extracted from inside it, so its findings carry no `archive:` location for
/// a package key to be derived from.
pub(super) fn is_synthetic_non_member_type(ft: &FileType) -> bool {
    matches!(ft, FileType::Registry)
}

/// Resolve a leg reference to the `for:` list of the trait or composite it
/// names. Bare same-directory names are qualified with the referring rule's
/// own directory, the way the loader resolves them. Directory references
/// resolve to many definitions with differing `for:` lists, so they return
/// `None` -- they prove nothing here.
pub(super) fn leg_file_types<'a>(
    id: &str,
    own_dir: &str,
    trait_for: &HashMap<&str, &'a Vec<FileType>>,
    composite_for: &HashMap<&str, &'a Vec<FileType>>,
) -> Option<&'a Vec<FileType>> {
    if id.ends_with('/') || (id.contains('/') && !id.contains("::")) {
        return None;
    }
    let qualified = format!("{own_dir}::{id}");
    trait_for
        .get(id)
        .or_else(|| composite_for.get(id))
        .or_else(|| trait_for.get(qualified.as_str()))
        .or_else(|| composite_for.get(qualified.as_str()))
        .copied()
}

/// Find `scope: package` composites that can never bind to a package boundary.
///
/// `scope: package` keys evidence by its nearest enclosing registry-fetch
/// package archive (npm/gem/whl/nupkg/crate/conda/egg/python_sdist) and, when
/// the evidence has no such ancestor, degrades to `scope: file` -- it never
/// widens into a global pool. That makes a merely *unlikely* package ancestor
/// harmless, which is why this check reports only declarations that can never
/// bind at all. Two shapes qualify, both grounded in `Scope::key`:
///
/// 1. Every declared `for:` type is a synthetic node no package can contain
///    (today: `registry`). Registry findings have no `archive:` location, so
///    `parent_package` has nothing to walk.
/// 2. The `all:` legs mix a registry-only leg with a leg that never runs on a
///    registry node. Registry evidence keys to the empty string while
///    artifact evidence keys to its archive or file path, so the two can never
///    land in the same scope bucket and the rule is unsatisfiable.
///
/// Both shapes want [`Scope::Outer`] instead -- the one scope that
/// deliberately pools by presence, which is exactly how the fetched artifact
/// and its separately-fetched registry metadata are meant to be joined (see
/// `evaluate_package_composites`).
///
/// Only rules that spell `scope: package` out are checked. The `for:`-derived
/// default in `CompositeTrait::default_scope` is the engine's own choice and
/// cannot be wrong in this way.
pub(crate) fn find_scope_without_valid_container(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<UnbindablePackageScope> {
    let trait_for: HashMap<&str, &Vec<FileType>> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), &t.r#for))
        .collect();
    let composite_for: HashMap<&str, &Vec<FileType>> = composite_rules
        .iter()
        .map(|c| (c.id.as_str(), &c.r#for))
        .collect();

    let mut found = Vec::new();
    for rule in composite_rules {
        if rule.scope != Some(Scope::Package) {
            continue;
        }

        // Shape 1: the node itself can never sit under a package.
        if !rule.r#for.is_empty() && rule.r#for.iter().all(is_synthetic_non_member_type) {
            found.push(UnbindablePackageScope {
                id: rule.id.clone(),
                reason: "for: names only registry nodes, which carry no archive location for a package key".to_string(),
            });
            continue;
        }

        // Shape 2: required legs straddle the registry/artifact boundary.
        let Some(all) = rule.all.as_ref() else {
            continue;
        };
        let own_dir = rule.id.split("::").next().unwrap_or("");
        let mut registry_leg: Option<&str> = None;
        let mut artifact_leg: Option<&str> = None;
        for cond in all {
            let Condition::Trait { id } = cond else {
                continue;
            };
            // Only resolvable legs count: this check fires on certainty.
            let Some(types) = leg_file_types(id, own_dir, &trait_for, &composite_for) else {
                continue;
            };
            if types.is_empty() {
                continue;
            }
            if types.iter().all(is_synthetic_non_member_type) {
                registry_leg.get_or_insert(id.as_str());
            } else if !types.contains(&FileType::All)
                && !types.iter().any(is_synthetic_non_member_type)
            {
                // Runs only on real files -- never on a registry node.
                artifact_leg.get_or_insert(id.as_str());
            }
        }
        if let (Some(reg), Some(art)) = (registry_leg, artifact_leg) {
            found.push(UnbindablePackageScope {
                id: rule.id.clone(),
                reason: format!(
                    "registry-only leg '{reg}' can never share a package key with file-based leg '{art}'"
                ),
            });
        }
    }
    found
}

/// Find composites whose pooling scope has no container to run on.
///
/// `archive`, `package` and `outer` are evaluated in the *container* pass —
/// the per-node pass takes only `file`/`leaf` (see the scope filters in
/// `evaluate_composites`). So a pooling-scoped composite runs only on a node
/// whose own type is a container, and one that declares no container type in
/// `for:` never runs at all: `for: [javascript]` + `scope: archive` reports on
/// a JavaScript node that the container pass will never hand it.
///
/// A container is an `#[archive]` type, or `registry` for `scope: outer` (the
/// synthetic artifact↔registry node is typed `registry`). `for: [all]` and
/// group-derived lists are exempt — `all` runs everywhere by definition, and a
/// named group's expansion is not what the author wrote.
///
/// Returns `(composite_id, scope, declared_types)`.
pub(crate) fn find_pooling_scope_without_container(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, Scope, Vec<FileType>)> {
    let mut found = Vec::new();
    for rule in composite_rules {
        let scope = rule.effective_scope();
        if !scope.pools_members() {
            continue;
        }
        if rule.for_from_groups || rule.r#for.is_empty() || rule.r#for.contains(&FileType::All) {
            continue;
        }
        // `Pe` is the established non-archive exception: a self-extracting PE
        // (PyInstaller onefile) or one with embedded cabinet/resource members
        // pools its children's findings the same way an archive does, without
        // carrying the `#[archive]` marker. `find_impossible_composite_filetypes`
        // already grants this exact carve-out (see its `has_pooling_scope`
        // comment and `a_pooling_scope_keeps_a_non_archive_container_alive`);
        // this check follows the same precedent rather than contradicting it.
        // `known-nondeployed-filename-context` (`for: [pe]`, `scope: outer`) is
        // the live shape: a PE's own version-resource fact joined with an
        // identity marker that may live in an embedded MSI/CAB member's path.
        // MSI, OLE compound documents and OOXML are containers too: each
        // holds more than one stream/part, and cleave cracks them and pools
        // their members' findings -- `analyzers/office/mod.rs` calls
        // `evaluate_container_composites` exactly as the archive analyser
        // does. They carry no `#[archive]` marker only because the *archive*
        // analyser is not what opens them (filefacts's `is_archive()` excludes
        // them; the office analyser owns them and emits `office.*` rather than
        // `archive.*`). Without this arm the two validators deadlock:
        // `find_impossible_composite_filetypes` tells an MSI or Office rule to
        // declare its container and take a pooling scope, and then this one
        // rejects the result -- 23 composites, most of
        // `dropper/execution/msi/msi.yaml`, had no legal state to be in.
        let has_container = rule.r#for.iter().any(|ft| {
            FileType::is_archive(ft)
                || matches!(
                    ft,
                    FileType::Pe | FileType::Msi | FileType::OleDoc | FileType::Ooxml
                )
                || (scope == Scope::Outer && *ft == FileType::Registry)
        });
        if !has_container {
            found.push((rule.id.clone(), scope, rule.r#for.clone()));
        }
    }
    found
}

/// Which clause a leg outside `for:` sits in — the consequence differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegRole {
    /// An `all:` leg: the rule can never fire.
    Required,
    /// Every `any:` alternative is outside `for:`: the rule can never fire.
    EveryAlternative,
    /// An `unless:` leg: the *carve-out* can never fire, so the rule keeps
    /// firing where the author said it should not. Reported separately because
    /// this one costs false positives rather than detections.
    Suppressor,
    /// One `any:` alternative is outside `for:` while another is reachable:
    /// the rule still fires, but never through this branch. Reported only by
    /// [`find_dead_any_alternatives`], as a warning.
    DeadAlternative,
}

/// A leg whose evidence the rule's `for:` excludes.
#[derive(Debug, Clone)]
pub(crate) struct LegOutsideFor {
    /// The composite.
    pub id: String,
    /// Its effective scope, for the message.
    pub scope: Scope,
    /// The leg that can never be satisfied.
    pub leg: String,
    /// The types that leg fires on — what `for:` is missing.
    pub leg_types: Vec<FileType>,
    /// Where the leg sits, which decides what breaks.
    pub role: LegRole,
}

/// Find pooling composites whose `for:` excludes a required leg's file types.
///
/// `for:` lists the file types a composite is about: the container it reports
/// on *and* the members whose findings may satisfy its legs (see
/// `EvaluationContext::origin_allows`). A required leg that only ever fires on
/// a type the rule does not name can therefore never be satisfied, and the
/// rule is dead.
///
/// This is the check that makes a rule *targeted*. `for: [vsix]` with a
/// JavaScript leg used to mean "any evidence in any member counts", which is
/// how `vscode-activated-curl-shell` scored hostile on a Rust crate. Naming the
/// member types is what narrows a rule to the files it is actually about, so
/// this error asks for the one edit that removes a false-positive class:
/// declare what you mix.
///
/// Only pooling scopes (`archive`/`package`/`outer`) are checked — they are the
/// ones the origin filter applies to. File-scoped composites match within one
/// node and are covered by `find_impossible_composite_filetypes`.
///
/// Skipped, because none of them proves a mistake: `for: [all]` (opts out of
/// the filter), group-derived lists, a leg declared `for: [all]`, a leg that
/// cannot be resolved, and a directory reference whose members' types are
/// unioned (any overlap clears it).
pub(crate) fn find_legs_outside_for(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<LegOutsideFor> {
    legs_outside_for(trait_definitions, composite_rules, false)
}

/// `any:` alternatives the rule's `for:` makes unreachable while a sibling
/// alternative keeps the clause alive.
///
/// The rule works, so this is a warning rather than an error, but the branch
/// is dead code with a detection's name on it. Example: a release-zip
/// correlator with `for: [zip, tar, go]` and `any: [source-hash-names,
/// binary-hash-names]` fired on source tarballs and never on the release zip
/// it was written for, because the binary alternative only fires on ELF.
pub(crate) fn find_dead_any_alternatives(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<LegOutsideFor> {
    legs_outside_for(trait_definitions, composite_rules, true)
        .into_iter()
        .filter(|l| l.role == LegRole::DeadAlternative)
        .collect()
}

pub(super) fn legs_outside_for(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    partial_any: bool,
) -> Vec<LegOutsideFor> {
    let trait_for: HashMap<&str, &Vec<FileType>> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), &t.r#for))
        .collect();
    let composite_for: HashMap<&str, &Vec<FileType>> = composite_rules
        .iter()
        .map(|c| (c.id.as_str(), &c.r#for))
        .collect();

    // A leg whose definition is a `type: path`/`basename`/`dirname` matcher is
    // not subject to the origin filter at all:
    // `evaluate_basename_traits_for_entries` runs every path trait against the
    // archive's entry list with no `for:` gate, and `analyzers/archive`
    // stamps those findings with the *container's* own type. So such a leg is
    // satisfiable by a rule that names only the container, and reporting it
    // here is a false positive -- 57 of them, 8 rules' worth entirely.
    // (The container itself still has to be declared; that is
    // `find_pooling_scope_without_container`'s job, not this one's.)
    let path_legs: std::collections::HashSet<&str> = trait_definitions
        .iter()
        .filter(|t| matches!(t.r#if, Condition::Path(_)))
        .map(|t| t.id.as_str())
        .collect();

    // Every definition sorted by id, so the ones under a directory are a
    // single run found by binary search rather than a scan of all of them.
    let mut by_id: Vec<(&str, &Vec<FileType>)> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), &t.r#for))
        .chain(composite_rules.iter().map(|c| (c.id.as_str(), &c.r#for)))
        .collect();
    by_id.sort_by_key(|&(id, _)| id);

    // Union of every definition under a directory reference.
    let dir_types = |dir: &str| -> Vec<FileType> {
        let prefix = dir.trim_end_matches('/');
        let mut out: Vec<FileType> = Vec::new();
        let first = by_id.partition_point(|&(id, _)| id < prefix);
        for (id, types) in by_id[first..]
            .iter()
            .take_while(|(id, _)| id.starts_with(prefix))
        {
            if id[prefix.len()..].starts_with([':', '/']) {
                for ft in types.iter() {
                    if !out.contains(ft) {
                        out.push(*ft);
                    }
                }
            }
        }
        out
    };

    let mut found = Vec::new();
    for rule in composite_rules {
        if !rule.effective_scope().pools_members() {
            continue;
        }
        if rule.for_from_groups || rule.r#for.is_empty() || rule.r#for.contains(&FileType::All) {
            continue;
        }
        let own_dir = rule.id.split("::").next().unwrap_or("");
        let is_path_leg = |id: &String| -> bool {
            let qualified = format!("{own_dir}::{id}");
            path_legs.contains(id.as_str()) || path_legs.contains(qualified.as_str())
        };
        let resolve = |id: &String| -> Option<Vec<FileType>> {
            if is_path_leg(id) {
                return None;
            }
            let types: Vec<FileType> =
                if id.ends_with('/') || (id.contains('/') && !id.contains("::")) {
                    dir_types(id)
                } else {
                    let qualified = format!("{own_dir}::{id}");
                    (*trait_for
                        .get(id.as_str())
                        .or_else(|| composite_for.get(id.as_str()))
                        .or_else(|| trait_for.get(qualified.as_str()))
                        .or_else(|| composite_for.get(qualified.as_str()))?)
                    .clone()
                };
            if types.is_empty() || types.contains(&FileType::All) {
                return None;
            }
            Some(types)
        };
        let excluded = |types: &[FileType]| !types.iter().any(|ft| rule.r#for.contains(ft));

        // `any:`: only dead when EVERY alternative is excluded. One reachable
        // branch is enough for the clause, so reporting per-leg here would be
        // noise on rules that are working exactly as written.
        if let Some(any) = rule.any.as_ref() {
            let resolved: Vec<(String, Vec<FileType>)> = any
                .iter()
                .filter_map(|cond| match cond {
                    Condition::Trait { id } => resolve(id).map(|t| (id.clone(), t)),
                    _ => None,
                })
                .collect();
            if !resolved.is_empty() && resolved.iter().all(|(_, t)| excluded(t)) {
                let (leg, leg_types) = resolved[0].clone();
                found.push(LegOutsideFor {
                    id: rule.id.clone(),
                    scope: rule.effective_scope(),
                    leg,
                    leg_types,
                    role: LegRole::EveryAlternative,
                });
            } else if partial_any {
                for (leg, leg_types) in resolved.iter().filter(|(_, t)| excluded(t)) {
                    found.push(LegOutsideFor {
                        id: rule.id.clone(),
                        scope: rule.effective_scope(),
                        leg: leg.clone(),
                        leg_types: leg_types.clone(),
                        role: LegRole::DeadAlternative,
                    });
                }
            }
        }

        // `unless:`: an excluded suppressor leg silently stops suppressing.
        if let Some(unless) = rule.unless.as_ref() {
            for cond in unless {
                let Condition::Trait { id } = cond else {
                    continue;
                };
                let Some(leg_types) = resolve(id) else {
                    continue;
                };
                if excluded(&leg_types) {
                    found.push(LegOutsideFor {
                        id: rule.id.clone(),
                        scope: rule.effective_scope(),
                        leg: id.clone(),
                        leg_types,
                        role: LegRole::Suppressor,
                    });
                }
            }
        }

        let Some(all) = rule.all.as_ref() else {
            continue;
        };
        for cond in all {
            let Condition::Trait { id } = cond else {
                continue;
            };
            let Some(leg_types) = resolve(id) else {
                continue;
            };
            if !excluded(&leg_types) {
                continue;
            }
            found.push(LegOutsideFor {
                id: rule.id.clone(),
                scope: rule.effective_scope(),
                leg: id.clone(),
                leg_types,
                role: LegRole::Required,
            });
        }
    }
    found
}
