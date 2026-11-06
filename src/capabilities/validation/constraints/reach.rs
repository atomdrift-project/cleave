//! Reachability checks: excessive file types, shadowed references, uncallable matchers, subsumed legs.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Find traits where `not:` is used inside a condition without `regex:`.
///
/// The `not:` field excludes individual evidence matches and only makes sense
/// with ambiguous patterns: `regex:` on string/raw/encoded conditions, or any
/// `hex:` condition (which inherently has wildcards). With `exact:`, `substr:`,
/// or `word:`, the match is already precise — change the pattern instead.
#[must_use]
pub(crate) fn find_invalid_not_usage(trait_definitions: &[TraitDefinition]) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let invalid = match &t.r#if {
            // Variants that carry both `regex` and `not`: `not` only makes sense
            // alongside an ambiguous matcher (regex). With exact/substr/word the
            // match is already precise — change the pattern instead.
            Condition::Raw(RawQuery { regex, not, .. })
            | Condition::Encoded(EncodedQuery { regex, not, .. })
            | Condition::Symbol(SymbolQuery { regex, not, .. })
            | Condition::Text(TextQuery { regex, not, .. })
            | Condition::Literal(LiteralQuery { regex, not, .. }) => {
                not.is_some() && regex.is_none()
            }
            // Hex: not is always valid (patterns are inherently ambiguous).
            // Other condition types do not have a `not:` field.
            _ => false,
        };

        if invalid {
            violations.push(format!(
                "{}: `not:` is only valid with `regex:` or `hex:` patterns",
                t.id,
            ));
        }
    }

    violations
}

/// Find text/raw conditions with `length_min`/`length_max` but no `regex:`.
///
/// The bounds constrain the regex match span (the cheap replacement for
/// counted repetitions like `{4000,}`); with `exact:`/`substr:`/`word:` the
/// match length is fixed by the pattern, so bounds are a no-op at best.
#[must_use]
pub(crate) fn find_length_bounds_without_regex(
    trait_definitions: &[TraitDefinition],
) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let invalid = match &t.r#if {
            Condition::Text(TextQuery {
                regex,
                length_min,
                length_max,
                ..
            })
            | Condition::Raw(RawQuery {
                regex,
                length_min,
                length_max,
                ..
            }) => (length_min.is_some() || length_max.is_some()) && regex.is_none(),
            _ => false,
        };

        if invalid {
            violations.push(format!(
                "{}: `length_min`/`length_max` on text/raw is only valid with `regex:`",
                t.id,
            ));
        }
    }

    violations
}

/// Find conditions with `length_min > length_max` — a bound pair no value or
/// match span can ever satisfy, so the rule never fires.
///
/// Returns `(rule_id, min, max)`.
#[must_use]
pub(crate) fn find_impossible_length_bounds(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, usize, usize)> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let bounds = match &t.r#if {
            Condition::Text(TextQuery {
                length_min,
                length_max,
                ..
            })
            | Condition::Raw(RawQuery {
                length_min,
                length_max,
                ..
            })
            | Condition::Kv(KvQuery {
                length_min,
                length_max,
                ..
            }) => (*length_min, *length_max),
            Condition::Section(SectionQuery {
                length_min,
                length_max,
                ..
            }) => (
                length_min.map(|min| usize::try_from(min).unwrap_or(usize::MAX)),
                length_max.map(|max| usize::try_from(max).unwrap_or(usize::MAX)),
            ),
            _ => (None, None),
        };

        if let (Some(min), Some(max)) = bounds
            && min > max
        {
            violations.push((t.id.clone(), min, max));
        }
    }

    violations
}

/// Check if a KV condition has a redundant `exists` field alongside a value matcher.
pub(super) fn is_kv_exists_redundant(cond: &Condition) -> bool {
    matches!(
        cond,
        Condition::Kv(KvQuery {
            exists: Some(_),
            exact,
            substr,
            regex,
            ..
        }) if exact.is_some() || substr.is_some() || regex.is_some()
    )
}

/// Find KV conditions where `exists` is set alongside a value matcher.
///
/// When `exact`, `substr`, or `regex` is present, `exists` is redundant:
/// - `exists: true` is implied (a value matcher requires the field to exist)
/// - `exists: false` is contradictory (a non-existent field can't have a value)
///
/// Returns: `Vec<rule_id>`
#[must_use]
pub(crate) fn find_kv_exists_with_matcher(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        if is_kv_exists_redundant(&t.r#if) {
            violations.push(t.id.clone());
        }
    }

    for rule in composite_rules {
        let has_redundant = [&rule.all, &rule.any, &rule.unless]
            .iter()
            .filter_map(|list| list.as_ref())
            .any(|conds| conds.iter().any(is_kv_exists_redundant));
        if has_redundant {
            violations.push(rule.id.clone());
        }
    }

    violations
}

/// Find composite rules with proximity constraints but no positive conditions.
///
/// A rule without `all:`/`any:` and with `near_lines` or `near_bytes` can never match
/// because proximity requires co-occurring evidence from positive conditions.
///
/// Returns: `Vec<rule_id>`
#[must_use]
pub(crate) fn find_none_only_with_proximity(composite_rules: &[CompositeTrait]) -> Vec<String> {
    composite_rules
        .iter()
        .filter(|rule| {
            rule.all.is_none()
                && rule.any.is_none()
                && (rule.near_lines.is_some() || rule.near_bytes.is_some())
        })
        .map(|rule| rule.id.clone())
        .collect()
}
/// The named file-type groups rules may target, and the only place they are
/// defined for validation purposes.
///
/// **Every file type appears in exactly one group.** Group membership is how
/// `for:` breadth is judged, and a type in two groups makes the judgement
/// ambiguous: while Dockerfile sat in both `manifests` and `build`, naming
/// either complete group read as a hand-written enumeration because the set
/// "touched" the other group through that one shared type. The invariant is
/// enforced by `named_groups_are_disjoint`.
pub(super) const BINARIES: &[FileType] = &[
    FileType::Elf,
    FileType::Macho,
    FileType::Pe,
    FileType::Class,
    FileType::Pyc,
    FileType::Beam,
    FileType::Wasm,
    FileType::Dex,
    FileType::StaticLib,
];
pub(super) const SCRIPTS: &[FileType] = &[
    FileType::Shell,
    FileType::Batch,
    FileType::Jcl,
    FileType::Python,
    FileType::JavaScript,
    FileType::Ruby,
    FileType::Php,
    FileType::Perl,
    FileType::Lua,
    FileType::PowerShell,
    FileType::AppleScript,
    FileType::Vbs,
    FileType::Mirc,
    FileType::IrcII,
];
pub(super) const SOURCE: &[FileType] = &[
    FileType::TypeScript,
    FileType::Rust,
    FileType::Java,
    FileType::C,
    FileType::Cpp,
    FileType::Go,
    FileType::CSharp,
    FileType::Swift,
    FileType::ObjectiveC,
    FileType::Groovy,
    FileType::Kotlin,
    FileType::Scala,
    FileType::Zig,
    FileType::Elixir,
    FileType::Clojure,
];
pub(super) const MANIFESTS: &[FileType] = &[
    FileType::Yaml,
    FileType::PackageJson,
    FileType::PackageLockJson,
    FileType::GoMod,
    FileType::Json,
    FileType::ChromeManifest,
    FileType::CargoToml,
    FileType::PyProjectToml,
    FileType::GithubActions,
    FileType::SystemdService,
    FileType::DesktopEntry,
    FileType::Xml,
    FileType::ComposerJson,
    FileType::PkgInfo,
    FileType::Reg,
    FileType::Plist,
    FileType::Nib,
    FileType::Lnk,
];
// Executable build logic, as opposed to the declarative metadata in
// `manifests`. Overlaps it on Dockerfile, which is both.
pub(super) const BUILD: &[FileType] = &[
    FileType::Makefile,
    FileType::Cmake,
    FileType::Pbxproj,
    FileType::Dockerfile,
];
pub(super) const DOCUMENTS: &[FileType] = &[
    FileType::Pdf,
    FileType::Rtf,
    FileType::Html,
    FileType::Text,
    FileType::OleDoc,
    FileType::Ooxml,
];
// `Text` lives in `documents` alongside the other readable formats; it was in
// both groups, which the one-group-per-type invariant forbids. These tables
// only decide whether a `for:` list reads as named groups — expansion happens
// in capabilities/parsing.rs — so moving it changes no rule's matching.
// `Ipa` is NOT here: it carries the `#[archive]` marker (an .ipa is a ZIP
// container) and now that ARCHIVES is derived from that same marker set
// instead of hand-duplicated, keeping Ipa in both groups would violate the
// one-group-per-type invariant below.
pub(super) const DATA: &[FileType] = &[FileType::Data];
// Derived from the same `#[archive]` enum markers that drive `is_archive()`
// and the `archives` group expansion in capabilities/parsing.rs, instead of
// hand-duplicating the member list here. The two lists had drifted before
// (this one carried `Apk` while the macro-generated family did not, because
// the old `Apk` variant lacked the `#[archive]` marker) -- deriving it
// removes that class of bug permanently.
pub(super) const ARCHIVES: &[FileType] = FileType::archive_family_types();
// Every passive container that can carry a payload — fonts, raster and
// vector images, audio, video. They share one `media.*` fact namespace
// precisely so a carrier rule is written once rather than a dozen times.
pub(super) const MEDIA: &[FileType] = &[
    FileType::Font,
    FileType::Png,
    FileType::Tiff,
    FileType::Avif,
    FileType::Jpeg,
    FileType::Svg,
    FileType::Wav,
    FileType::Aiff,
    FileType::Mp3,
    FileType::Mp4,
    FileType::Ico,
    FileType::Gif,
    FileType::Bmp,
    FileType::Webp,
];
pub(crate) const ALL_GROUPS: &[(&[FileType], &str)] = &[
    (MEDIA, "media"),
    (BINARIES, "binaries"),
    (SCRIPTS, "scripts"),
    (SOURCE, "source"),
    (MANIFESTS, "manifests"),
    (BUILD, "build"),
    (DOCUMENTS, "documents"),
    (DATA, "data"),
    (ARCHIVES, "archives"),
];

/// Find traits and composite rules with 9 or more explicit file types in their `for:` field.
///
/// Listing many individual file types defeats the purpose of specific targeting and is
/// equivalent to broad groupings like `binaries`, `scripts`, or `all`. Authors should
/// use these aggregates instead of enumerating every covered type.
///
/// Up to 8 explicit types is accepted: real traits routinely need a hand-picked spread
/// across two or three groups (e.g. a few scripts + a binary format + a manifest) that
/// no single named group expresses, and forcing a group there over-broadens coverage.
/// Nine or more almost always maps to an existing group and should use it.
///
/// Traits that already use the broadest expressible named-group union are exempt —
/// listing every member type again would only restate the groups.
///
/// Returns: `Vec<(id, count, suggestion, is_composite)>`
#[must_use]
pub(crate) fn find_excessive_file_types(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize, &'static str, bool)> {
    const MIN_FOR_WARNING: usize = 9;

    let all_groups = ALL_GROUPS;

    // Returns true if `types` is a union of complete named groups.
    //
    // A type set is expressible when every type in it is covered by at least
    // one group that lies *entirely* inside the set. The earlier form asked
    // the opposite question — that every group the set *touches* be complete —
    // which is wrong as soon as one file type belongs to two groups. Dockerfile
    // is in both `manifests` and `build`, so `for: [manifests]` "touched"
    // `build` through that single shared type and was reported as an
    // unexpressible enumeration despite being exactly one named group; the same
    // happened to `for: [carriers]`, which shares Xml with `manifests`.
    // Asking what covers the set makes overlapping groups work: a shared type
    // is satisfied by whichever group is fully present.
    let is_group_expressible = |types: &[FileType]| -> bool {
        let type_set: std::collections::HashSet<&FileType> = types.iter().collect();
        let covered: std::collections::HashSet<&FileType> = all_groups
            .iter()
            .filter(|(group, _)| group.iter().all(|ft| type_set.contains(ft)))
            .flat_map(|(group, _)| group.iter())
            .collect();
        type_set.iter().all(|ft| covered.contains(*ft))
    };

    // Only called when is_group_expressible returned false — suggest combining
    // named groups rather than listing every type (or the rejected `for: [all]`).
    let suggest = |_types: &[FileType]| -> &'static str {
        "combine named groups (binaries, scripts, source, manifests, build, documents, media, data)"
    };

    let mut violations = Vec::new();

    for t in trait_definitions {
        // Skip if the author already used named groups — platform filtering may
        // have removed some members, making the expanded set look like a partial
        // group, but the YAML source is correct.
        if t.for_from_groups || t.r#for.contains(&FileType::All) || is_group_expressible(&t.r#for) {
            continue;
        }
        if t.r#for.len() >= MIN_FOR_WARNING {
            violations.push((t.id.clone(), t.r#for.len(), suggest(&t.r#for), false));
        }
    }

    for r in composite_rules {
        if r.for_from_groups || r.r#for.contains(&FileType::All) || is_group_expressible(&r.r#for) {
            continue;
        }
        if r.r#for.len() >= MIN_FOR_WARNING {
            violations.push((r.id.clone(), r.r#for.len(), suggest(&r.r#for), true));
        }
    }

    violations
}

/// Find hex conditions targeting binary file types that lack a required section filter.
///
/// Hex pattern matching against binaries without a section constraint scans the entire
/// file content, which is both expensive and increases false-positive risk. Every hex
/// condition whose `for:` includes `all`, `pe`, `macho`, `elf`, `dylib`, `so`, or `dll`
/// must specify a `section:` field to scope the search to a named section.
///
/// Traits with an absolute `offset` or `offset_range` are exempt — a pinned location
/// already bounds the search space without needing a section.
///
/// Returns: `Vec<trait_id>`
#[must_use]
pub(crate) fn find_hex_binary_missing_section(
    trait_definitions: &[TraitDefinition],
) -> Vec<String> {
    trait_definitions
        .iter()
        .filter(|t| {
            let Condition::Hex(HexQuery {
                section,
                offset,
                offset_range,
                ..
            }) = &t.r#if
            else {
                return false;
            };
            // Absolute offset or offset_range already pins the search — exempt.
            if offset.is_some() || offset_range.is_some() {
                return false;
            }
            // Require section when targeting binary file types.
            section.is_none()
                && (t.r#for.contains(&FileType::All)
                    || t.r#for
                        .iter()
                        .any(|ft| super::super::helpers::is_binary_file_type(*ft)))
        })
        .map(|t| t.id.clone())
        .collect()
}

// Per-condition-type file-type caps moved to
// `validation::taxonomy::find_broad_filetype_traits`, which now enforces a
// single per-matcher-type threshold table (text/value/symbol/ast) plus a
// type-qualified allowlist. The former `find_condition_scope_violations`
// (tree-sitter ≤2, symbol/hex/yara ≤4) is subsumed by those caps.

/// Direct `downgrade:` entries allowed on a rule declared `notable`.
///
/// A `downgrade:` on a notable rule lands it on `Baseline`, and `Baseline`
/// means something specific: functionality nearly every program has. A clear
/// behavior does not become universal because of where it sits — `pkill <name>`
/// terminates a process by name in shipped code and in a test file alike. So
/// crossing that line is a claim about the matcher, not the context, and it
/// should be rare and argued rather than reached for as routine FP control.
pub(crate) const MAX_NOTABLE_DOWNGRADE_DIRECT: usize = 4;

/// Same limit once aggregator references are expanded.
///
/// A single directory reference can stand for hundreds of traits — one
/// `metadata/package/testing/presence/harness/` leg expands to 126, any one of
/// which fires the downgrade. Counting only the literal entries would let a
/// rule hide an unbounded trigger set behind one line.
pub(crate) const MAX_NOTABLE_DOWNGRADE_EXPANDED: usize = 8;

/// A rule declared `notable` whose `downgrade:` reaches too broadly.
pub(crate) struct BroadNotableDowngrade {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// `downgrade:` entries written literally on the rule.
    pub direct: usize,
    /// Distinct exceptions once aggregator references are expanded.
    pub expanded: usize,
}

/// Find `notable` rules whose `downgrade:` crosses into `Baseline` on too broad
/// a trigger set.
///
/// Sibling of [`find_excessive_skip_conditions`], and deliberately the same
/// shape — a direct cap plus an expanded cap — but scoped to the one transition
/// that reclassifies a behavior rather than merely de-emphasizing it. Rules at
/// `suspicious`/`hostile` are untouched: those downgrades land on `notable` or
/// `suspicious`, which say nothing false about the matcher.
#[must_use]
pub(crate) fn find_broad_notable_downgrades<'a>(
    trait_definitions: &'a [TraitDefinition],
    composite_rules: &'a [CompositeTrait],
) -> Vec<BroadNotableDowngrade> {
    let index = SuppressionIndex::new(composite_rules);

    let mut violations = Vec::new();

    let mut flag = |id: &'a str,
                    crit: crate::types::Criticality,
                    downgrade: Option<&'a DowngradeConditions>,
                    is_composite: bool| {
        if crit != crate::types::Criticality::Notable {
            return;
        }
        let Some(downgrade) = downgrade else { return };
        // A positive `all:` block narrows the alternatives and counts once.
        let all_len = downgrade.all.as_ref().map_or(0, Vec::len);
        let widening = DowngradeConditions {
            all: None,
            any: downgrade.any.clone(),
            needs: downgrade.needs,
            scope: downgrade.scope,
        };
        let conjunction = usize::from(all_len > 0);
        let (_, direct) = direct_suppression_counts(None, Some(&widening));
        let direct = direct + conjunction;
        let (expanded, _) = expand_suppressions(None, Some(&widening), &index, id);
        let expanded = expanded + conjunction;
        if direct > MAX_NOTABLE_DOWNGRADE_DIRECT || expanded > MAX_NOTABLE_DOWNGRADE_EXPANDED {
            violations.push(BroadNotableDowngrade {
                id: id.to_string(),
                is_composite,
                direct,
                expanded,
            });
        }
    };

    for t in trait_definitions {
        flag(t.id.as_str(), t.crit, t.downgrade.as_ref(), false);
    }
    for r in composite_rules {
        flag(r.id.as_str(), r.crit, r.downgrade.as_ref(), true);
    }

    violations
}

/// A clause that lists two references where one already covers the other.
pub(crate) struct ShadowedRef {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// Which clause the pair sits in (`unless`, `any`, `all`, `none`, …).
    pub clause: &'static str,
    /// The reference that is already covered by `covered_by`.
    pub specific: String,
    /// The reference that covers it — a duplicate, a parent directory, or a
    /// directory containing the trait.
    pub directory: String,
    /// How the pair overlaps, for the message.
    pub kind: &'static str,
}

/// Find clauses that list two references where one already covers the other.
///
/// Three shapes, all the same defect — a leg that cannot change the clause's
/// outcome because a sibling leg already subsumes it:
///
/// * **duplicate** — the same reference written twice.
/// * **directory over trait** — `a/b/` beside `a/b::c`.
/// * **directory over directory** — `well-known/lib/` beside
///   `well-known/lib/utext/`.
///
/// A covered leg is dead weight: `any:` was already satisfied by the covering
/// leg, `unless:` already suppressed on it. It makes a rule read as broader
/// than it is and inflates both suppression budgets
/// ([`find_excessive_skip_conditions`] and [`find_broad_notable_downgrades`])
/// with entries that carry no reach.
///
/// Keep the covering reference and drop the covered one — or, if only the
/// narrower one was meant, drop the broad reference, which is the case where
/// this check has found a real behavior bug rather than redundancy.
#[must_use]
pub(crate) fn find_directory_shadowed_refs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<ShadowedRef> {
    let mut out = Vec::new();

    // A directory reference has no `::` and at least one path separator.
    fn as_directory(r: &str) -> Option<&str> {
        let r = r.trim_end_matches('/');
        (!r.contains("::") && r.contains('/')).then_some(r)
    }

    /// Does `a` cover `b`? True when `a` is a directory and `b` names a trait
    /// or directory beneath it.
    fn covers(a: &str, b: &str) -> bool {
        let Some(dir) = as_directory(a) else {
            return false;
        };
        let b = b.trim_end_matches('/');
        b.strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with("::") || rest.starts_with('/'))
    }

    // Directory references deliberately exclude `crit: exception` members, so a
    // directory does NOT cover an exception that lives under it and the pair is
    // not redundant. Skip those, or this check would advise deleting a
    // reference that is doing real work.
    let exceptions: HashSet<&str> = trait_definitions
        .iter()
        .filter(|t| t.crit == crate::types::Criticality::Exception)
        .map(|t| t.id.as_str())
        .chain(
            composite_rules
                .iter()
                .filter(|r| r.crit == crate::types::Criticality::Exception)
                .map(|r| r.id.as_str()),
        )
        .collect();

    let mut scan = |id: &str, is_composite: bool, clause: &'static str, list: &[Condition]| {
        let refs: Vec<&str> = list.iter().filter_map(trait_ref).collect();
        for (i, b) in refs.iter().enumerate() {
            if exceptions.contains(*b) {
                continue;
            }
            for (j, a) in refs.iter().enumerate() {
                if i == j {
                    continue;
                }
                let same = a.trim_end_matches('/') == b.trim_end_matches('/');
                // For an exact duplicate only the later copy is reported, so a
                // pair yields one finding rather than two.
                let kind = if same && j < i {
                    "duplicate"
                } else if !same && covers(a, b) {
                    if b.contains("::") {
                        "directory over trait"
                    } else {
                        "directory over directory"
                    }
                } else {
                    continue;
                };
                out.push(ShadowedRef {
                    id: id.to_string(),
                    is_composite,
                    clause,
                    specific: (*b).to_string(),
                    directory: (*a).to_string(),
                    kind,
                });
                break;
            }
        }
    };

    let mut visit = |id: &str,
                     is_composite: bool,
                     all: Option<&Vec<Condition>>,
                     any: Option<&Vec<Condition>>,
                     unless: Option<&Vec<Condition>>,
                     downgrade: Option<&DowngradeConditions>| {
        for (clause, list) in [("all", all), ("any", any), ("unless", unless)] {
            if let Some(list) = list {
                scan(id, is_composite, clause, list);
            }
        }
        if let Some(d) = downgrade {
            for (clause, list) in [
                ("downgrade.all", d.all.as_ref()),
                ("downgrade.any", d.any.as_ref()),
            ] {
                if let Some(list) = list {
                    scan(id, is_composite, clause, list);
                }
            }
        }
    };

    for t in trait_definitions {
        visit(
            t.id.as_str(),
            false,
            None,
            None,
            t.unless.as_ref(),
            t.downgrade.as_ref(),
        );
    }
    for r in composite_rules {
        visit(
            r.id.as_str(),
            true,
            r.all.as_ref(),
            r.any.as_ref(),
            r.unless.as_ref(),
            r.downgrade.as_ref(),
        );
    }

    out
}

/// A `type: symbol` matcher whose literal no extracted symbol can ever equal.
pub(crate) struct UncallableSymbolMatcher {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// Which clause the matcher sits in (`if`, `unless`, …).
    pub clause: &'static str,
    /// Which field carried the literal (`exact` or `substr`).
    pub field: &'static str,
    /// The literal as written.
    pub literal: String,
    /// The same literal with argument text removed — what it should say.
    pub suggestion: String,
}

/// Is the `(` at `open` the Go receiver form, as in `net.(*Dialer).Dial`?
///
/// Compiled Go binaries really do export symbols spelled that way, so those
/// parentheses are part of a legitimate name and carry a type, not arguments.
pub(super) fn is_go_receiver_paren(literal: &str, open: usize) -> bool {
    literal[..open].ends_with('.') && literal[open + 1..].starts_with('*')
}

/// Rewrite a matcher literal into the symbol format: drop every call.
pub(super) fn strip_call_syntax(literal: &str) -> String {
    let mut out = String::with_capacity(literal.len());
    let mut depth = 0usize;
    for (i, ch) in literal.char_indices() {
        match ch {
            '(' if depth == 0 && !is_go_receiver_paren(literal, i) => depth += 1,
            '(' if depth > 0 => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    // `.system()` collapses to `.system`; a trailing dot from `foo().` would
    // be a dangling separator.
    out.trim_end_matches('.').to_string()
}

/// Find `type: symbol` matchers that are not symbols.
///
/// Two shapes, both silent: a matcher that spells out a call, and a regex
/// sitting in `exact:`/`substr:`, which compare literally.
///
/// A symbol is a dotted path of identifiers — `platform.system`,
/// `open.read`, `Date.getTimezoneOffset` — with no parentheses and no
/// argument text, whatever the language and whether the file was source or a
/// stripped binary. A matcher that writes the call (`.system()`,
/// `open().read`, `open("/tmp/x").read`, or a half-open `.eval(`) matches
/// nothing at all.
///
/// These fail silently: the trait loads, validates, and never fires. Run
/// `cleave facts <file>` on a sample to see the exact strings to match.
///
/// `regex:` is exempt — a pattern legitimately escapes `\(` — and so is the Go
/// receiver form `net.(*Dialer).Dial`, which is a real symbol in a compiled
/// binary rather than a call.
#[must_use]
pub(crate) fn find_uncallable_symbol_matchers(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<UncallableSymbolMatcher> {
    /// Characters that never appear in a symbol we emit, so their presence
    /// means the author put a regex in `exact:`/`substr:`.
    ///
    /// Deliberately narrow. `*` is excluded because Go binaries really export
    /// `net.(*Dialer).Dial`; whitespace is excluded because PE ordinal imports
    /// are named `ORDINAL 187` and C++ has `operator delete`; and a trailing
    /// `$` is excluded because it is a legal JavaScript identifier character
    /// (`$`, `jQuery$`). What is left cannot occur in any name: a subscript is
    /// normalised to a dot, so brackets never survive either.
    fn looks_like_regex(literal: &str) -> bool {
        literal.contains('\\')
            || literal.contains('|')
            || literal.contains('^')
            || literal.contains('[')
            || literal.contains(']')
            || literal.contains(".{")
    }

    /// Does this literal name something no symbol can be?
    fn carries_call_syntax(literal: &str) -> bool {
        literal
            .char_indices()
            .any(|(i, c)| c == '(' && !is_go_receiver_paren(literal, i))
    }

    let mut out = Vec::new();

    let mut check = |id: &str, is_composite: bool, clause: &'static str, cond: &Condition| {
        let Condition::Symbol(q) = cond else { return };
        for (field, literal) in [("exact", q.exact.as_ref()), ("substr", q.substr.as_ref())] {
            let Some(literal) = literal else { continue };
            if !carries_call_syntax(literal) && !looks_like_regex(literal) {
                continue;
            }
            // A literal carrying regex metacharacters is a pattern in the
            // wrong field, not a symbol with arguments. Emptying its parens
            // would produce nonsense (`\.clone\(` -> `\.clone\()`), so say
            // what is actually wrong.
            let suggestion = if looks_like_regex(literal) {
                format!("move it to `regex:` -- {literal:?} is a pattern, not a symbol")
            } else {
                format!("write it as {:?}", strip_call_syntax(literal))
            };
            out.push(UncallableSymbolMatcher {
                id: id.to_string(),
                is_composite,
                clause,
                field,
                literal: literal.clone(),
                suggestion,
            });
        }
    };

    for t in trait_definitions {
        check(&t.id, false, "if", &t.r#if);
        for c in t.unless.iter().flatten() {
            check(&t.id, false, "unless", c);
        }
    }
    for r in composite_rules {
        for c in r.unless.iter().flatten() {
            check(&r.id, true, "unless", c);
        }
    }

    out
}

/// Container filenames a collector assigns, not the attack.
///
/// A `suspicious`/`hostile` composite that *requires* an exact match on the
/// scanned artifact's own filename detects one stored copy of a specimen. The
/// name of the outer container is chosen when the sample is fetched or filed --
/// `Win32.Volk.7z`, `2026-03-27-telnyx-v4.87.2.zip` -- so it changes on
/// re-collection and carries no attack information. The same rule with the leg
/// removed usually still fires on the archive's contents.
///
/// The real distinction is container versus member: a file *inside* an archive
/// is named by the attacker or mandated by the format (`SKILL.md`,
/// `package.json`, `AUTOEXEC.BAT`), and requiring one of those is legitimate.
/// Validation is static and cannot know where a basename will land, so an
/// archive extension stands in for "this can only ever match the container".
pub(super) const COLLECTOR_NAMED_CONTAINER_EXTS: &[&str] = &[
    ".zip", ".7z", ".rar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar", ".apk", ".vsix",
    ".nupkg", ".whl", ".jar", ".gem", ".crate", ".nupkg", ".xpi", ".crx",
];

/// A path/basename literal carrying a specimen-collection date (`2026-03-27-…`)
/// is never an artifact name a registry or a victim would see.
pub(super) fn looks_like_collection_date(literal: &str) -> bool {
    let b = literal.as_bytes();
    b.windows(10).any(|w| {
        w[0..4].iter().all(u8::is_ascii_digit)
            && w[4] == b'-'
            && w[5..7].iter().all(u8::is_ascii_digit)
            && w[7] == b'-'
            && w[8..10].iter().all(u8::is_ascii_digit)
    })
}

/// The filename a trait pins a whole basename to, whether written as an exact
/// literal or as a regex.
///
/// `type: basename` normalises into a Path query with `basename: true`, so one
/// arm covers both spellings. The regex arm matters: a rule can pin a specimen
/// just as tightly with `^2026-03-21-yelp-react-component-badge-v99\.` as with
/// an `exact:`, and checking only `exact:` let that form through.
pub(super) fn required_basename_literal(trait_def: &TraitDefinition) -> Option<(&str, bool)> {
    match &trait_def.r#if {
        Condition::Path(PathQuery {
            exact: Some(x),
            basename: true,
            ..
        }) => Some((x.as_str(), false)),
        Condition::Path(PathQuery {
            regex: Some(x),
            basename: true,
            ..
        }) => Some((x.as_str(), true)),
        _ => None,
    }
}

/// Composites at `suspicious`+ whose `all:` requires a collector-assigned
/// container filename. Returns `(composite id, trait id, literal, reason)`.
pub(crate) fn find_container_name_convictions(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, String, String, &'static str)> {
    use crate::types::Criticality;

    let by_id: HashMap<&str, &TraitDefinition> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t))
        .collect();
    let index = ReferenceIndex::new(by_id.keys().copied().collect());

    let mut found = Vec::new();
    for rule in composite_rules {
        if rule.crit < Criticality::Suspicious {
            continue;
        }
        let Some(required) = rule.all.as_ref() else {
            continue;
        };
        for cond in required {
            let Condition::Trait { id } = cond else {
                continue;
            };
            for resolved in index.resolve(id) {
                let Some(def) = by_id.get(resolved) else {
                    continue;
                };
                let Some((literal, is_regex)) = required_basename_literal(def) else {
                    continue;
                };
                let lower = literal.to_ascii_lowercase();
                // A regex basename is only damning when it pins one specimen. An
                // extension alone (`(?i)\.vsix$`) is a file-type test, and a
                // family's own naming convention (`^(T1|DCM-T[123])\.zip$`) is
                // real evidence -- neither is a collector's choice. A collection
                // date is, whichever way it is written.
                let reason = if looks_like_collection_date(literal) {
                    "carries a specimen-collection date, so it only ever matches our stored copy"
                } else if !is_regex
                    && COLLECTOR_NAMED_CONTAINER_EXTS
                        .iter()
                        .any(|ext| lower.ends_with(ext))
                {
                    "names the scanned container, which is assigned when the sample is fetched"
                } else {
                    continue;
                };
                found.push((rule.id.clone(), def.id.clone(), literal.to_string(), reason));
            }
        }
    }
    found
}

/// Terminal trait ids a reference *requires*, following nested composites
/// through their `all:` only.
///
/// `None` means indeterminate, and the callers treat that as "prove nothing".
/// A directory reference (`objectives/foo/`) or a bare short name can resolve to
/// many ids, and those are alternatives -- any one of them satisfies the leg --
/// so they are not a required set. Reading them as a conjunction made every
/// single-trait leg look like a subset of every directory leg.
pub(super) fn required_terminals<'a>(
    reference: &str,
    index: &ReferenceIndex<'a>,
    composite_by_id: &HashMap<&str, &CompositeTrait>,
    depth: usize,
    cache: &mut HashMap<String, Vec<&'a str>>,
) -> Option<HashSet<String>> {
    if depth > 8 {
        return None;
    }
    let resolved = resolve_cached(reference, index, cache);
    let [id] = resolved[..] else {
        return None;
    };
    match composite_by_id.get(id) {
        Some(sub) => {
            // An `any:` clause makes the composite's requirements conditional,
            // so its required set is not determinate either.
            if sub.any.is_some() {
                return None;
            }
            let mut out = HashSet::new();
            for cond in sub.all.iter().flatten() {
                let Condition::Trait { id: child } = cond else {
                    return None;
                };
                out.extend(required_terminals(
                    child,
                    index,
                    composite_by_id,
                    depth + 1,
                    cache,
                )?);
            }
            Some(out)
        }
        None => Some(HashSet::from([id.to_string()])),
    }
}

/// Legs of one `all:` clause that another leg already requires.
///
/// Two families convicted on inflated evidence this way. `abot`'s
/// `winlogon-userinit-persistence` required an exact filename *and* a regex
/// matching the same filename; `antisocial`'s `family` required
/// `source-archive` (readme + apee) alongside `polymorphic-macro-source`
/// (readme + apee + aaa), which already contains it. Both read as several
/// independent legs and are worth one.
///
/// Returns `(composite id, redundant leg, leg that subsumes it)`.
pub(crate) fn find_subsumed_required_legs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, String, String)> {
    let composite_by_id: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut all_ids: Vec<&str> = trait_definitions.iter().map(|t| t.id.as_str()).collect();
    all_ids.extend(composite_by_id.keys().copied());
    let index = ReferenceIndex::new(all_ids);

    let mut cache: HashMap<String, Vec<&str>> = HashMap::new();
    let mut found = Vec::new();
    for rule in composite_rules {
        // Scoped to convictions. A repeated leg in a notable or exception
        // composite is untidy; in a suspicious/hostile one it manufactures
        // evidence, which is how `abot` and `antisocial` came to look
        // substantiated.
        if rule.crit < crate::types::Criticality::Suspicious {
            continue;
        }
        let Some(required) = rule.all.as_ref() else {
            continue;
        };
        let legs: Vec<&str> = required
            .iter()
            .filter_map(|c| match c {
                Condition::Trait { id } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        if legs.len() < 2 {
            continue;
        }
        let expanded: Vec<Option<HashSet<String>>> = legs
            .iter()
            .map(|l| required_terminals(l, &index, &composite_by_id, 0, &mut cache))
            .collect();
        for (i, a) in expanded.iter().enumerate() {
            let Some(a) = a else { continue };
            if a.is_empty() {
                continue;
            }
            for (j, b) in expanded.iter().enumerate() {
                let Some(b) = b else { continue };
                // `a` adds nothing `b` does not already require. On an exact tie
                // only report once, so the pair yields one finding.
                if i == j || !a.is_subset(b) || (a == b && i > j) {
                    continue;
                }
                found.push((rule.id.clone(), legs[i].to_string(), legs[j].to_string()));
                break;
            }
        }
    }
    found
}
