//! Checks on where rules apply: well-known/ placement, platforms, file
//! types, and size and section filters.

use super::{Report, ValidationInput, enabled, report};
use crate::capabilities::validation::{
    find_all_platform_rules_outside_allowlist, find_broad_filetype_traits,
    find_broad_platform_traits, find_composite_only_wellknown_files, find_dead_composites,
    find_generic_wellknown_leaf_dirs, find_hex_binary_missing_section,
    find_impossible_composite_filetypes, find_legs_outside_for, find_line_number,
    find_meta_missing_section_filter, find_mixed_archive_filetype_traits,
    find_pooling_scope_without_container, find_redundant_unix_platforms,
    find_scope_without_valid_container, find_stale_filetype_allowlist_entries,
    find_unanchored_wellknown_composites, find_wellknown_category_violations,
    find_wellknown_missing_section_filter, find_wellknown_missing_size_filter,
    find_wellknown_version_path_traits,
};
use crate::composite_rules::FileType as RuleFileType;

/// Validate well-known/ category whitelist
pub(super) fn wellknown_category_violations<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Checking well-known/ category whitelist");
        let wk_category_violations = find_wellknown_category_violations(&input.dir_list);
        if !wk_category_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} unknown categories under well-known/",
                wk_category_violations.len()
            );
            eprintln!(
                "   Only whitelisted subcategories are allowed under well-known/malware/, well-known/dual-use/, well-known/app/, well-known/lib/, and well-known/tool/:\n"
            );
            for (dir_path, category) in &wk_category_violations {
                eprintln!("   {}: unknown category '{}'", dir_path, category);
            }
            eprintln!(
                "\n   Add the category to the corresponding WELL_KNOWN_*_CATEGORIES list in taxonomy.rs if legitimate."
            );
            warnings.push(format!(
                "{} unknown categories under well-known/",
                wk_category_violations.len()
            ));
        }
    })
}

/// Validate well-known/ leaf directory names for generic technique words
pub(super) fn generic_wellknown_leaf_dirs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Checking well-known/ leaf directory names");
        let generic_leaf_violations = find_generic_wellknown_leaf_dirs(&input.dir_list);
        if !generic_leaf_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} well-known/ directories use generic technique names",
                generic_leaf_violations.len()
            );
            eprintln!(
                "   well-known/ directories should be named after specific malware families/tools:\n"
            );
            for (dir_path, word) in &generic_leaf_violations {
                eprintln!("   {}: generic technique word '{}'", dir_path, word);
            }
            eprintln!(
                "\n   Rename to a specific family name, or move generic detection to objectives/."
            );
            warnings.push(format!(
                "{} well-known/ directories use generic technique names instead of family names",
                generic_leaf_violations.len()
            ));
        }
    })
}

/// Validate well-known/ composites have local anchoring (family-specific refs)
pub(super) fn unanchored_wellknown_composites<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let unanchored =
        find_unanchored_wellknown_composites(input.composite_rules, input.rule_source_files);
    report(move |warnings| {
        tracing::trace!("Checking well-known/ composite anchoring");
        if !unanchored.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} well-known/ composites have no family-specific anchoring",
                unanchored.len()
            );
            eprintln!(
                "   well-known/ composites should reference at least one local or well-known/ trait:"
            );
            eprintln!(
                "   Composites that only combine micro-behaviors/ or objectives/ refs belong in objectives/.\n"
            );
            for (rule_id, source_file) in &unanchored {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Composite '{}' has no well-known/ anchoring",
                        source_file, line, rule_id
                    );
                } else {
                    eprintln!(
                        "   {}: Composite '{}' has no well-known/ anchoring",
                        source_file, rule_id
                    );
                }
            }
            warnings.push(format!(
                "{} well-known/ composites have no family-specific anchoring (move to objectives/)",
                unanchored.len()
            ));
        }
    })
}

/// Validate well-known/ files are not composite-only (should have atomic traits)
pub(super) fn composite_only_wellknown_files<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let composite_only =
        find_composite_only_wellknown_files(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        tracing::trace!("Checking for composite-only well-known/ files");
        if !crate::validation_controls::is_validator_disabled("wellknown-composite-only")
            && !composite_only.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} well-known/ directories contain only composites (no atomic traits in directory)",
                composite_only.len()
            );
            eprintln!(
                "   well-known/ directories should define family-specific fingerprints (atomic traits)."
            );
            eprintln!("   Possible fixes:");
            eprintln!(
                "   - Move composite-only rules to objectives/ if they detect generic behaviors"
            );
            eprintln!(
                "   - Move family-specific traits from micro-behaviors/ into well-known/ if they were misplaced\n"
            );
            for (source_file, count) in &composite_only {
                eprintln!(
                    "   {}: {} composite(s), 0 atomic traits in directory",
                    source_file, count
                );
            }
            warnings.push(format!(
    "{} well-known/ directories are composite-only (add family-specific atomic traits or move to objectives/)",
    composite_only.len()
));
        }
    })
}

/// Soft warning: `platforms: [all]` outside the directories allowed to
/// claim every platform.
pub(super) fn all_platform_rules_outside_allowlist<'a>(
    input: &'a ValidationInput<'a>,
) -> Report<'a> {
    let unapproved_all_plat = find_all_platform_rules_outside_allowlist(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("all-platforms-directory")
            && !unapproved_all_plat.is_empty()
        {
            warnings.push_count(
                "all-platforms-directory",
                unapproved_all_plat.len(),
                format!(
                    "{} rules declare platforms: [all] outside reviewed directory contracts",
                    unapproved_all_plat.len()
                ),
            );
            eprintln!(
                "\n⚠️ SOFT WARNING: {} rules use platforms: [all] outside the directory allowlist",
                unapproved_all_plat.len()
            );
            eprintln!(
                "   Audit the target OS support and declare explicit platforms. Add an allowlist contract only for OS-independent evidence."
            );
            eprintln!(
                "   A source file's presence on an OS does not establish that its behavior applies there."
            );
            for (id, source) in &unapproved_all_plat {
                eprintln!("   {source}: '{id}'");
            }
        }
    })
}

/// Platform breadth is a soft warning, not proof of invalid placement.
pub(super) fn broad_platform_traits<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let broad_plat = find_broad_platform_traits(input.trait_definitions, input.rule_source_files);
    report(move |warnings| {
        tracing::trace!("Reviewing platform scope (4+ effective platforms)");
        if !crate::validation_controls::is_validator_disabled("broad-platform-scope")
            && !broad_plat.is_empty()
        {
            warnings.push_count(
                "broad-platform-scope",
                broad_plat.len(),
                format!(
                    "{} atomic traits declare four or more platforms",
                    broad_plat.len()
                ),
            );
            eprintln!(
                "\n⚠️ SOFT WARNING: {} atomic traits declare four or more platforms",
                broad_plat.len()
            );
            eprintln!(
                "   Check each matcher supports its scope. Platform count alone is not an error."
            );
            eprintln!(
                "   Preserve justified coverage; do not duplicate rules or move them to satisfy a count."
            );
            for (trait_id, source_file, count) in &broad_plat {
                eprintln!("   {source_file}: '{trait_id}' ({count} platforms)");
            }
        }
    })
}

/// Validate: traits listing unix alongside linux or macos (redundant — unix is the superset)
pub(super) fn redundant_unix_platforms<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let redundant_unix =
        find_redundant_unix_platforms(input.trait_definitions, input.rule_source_files);
    report(move |warnings| {
        tracing::trace!("Checking for redundant unix+linux/macos platform combinations");
        if !redundant_unix.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} traits list 'unix' with redundant specific platforms",
                redundant_unix.len()
            );
            eprintln!(
                "   'unix' already covers linux and macos. Use [unix, windows] instead of [linux, macos, unix, windows]."
            );
            eprintln!();
            for (trait_id, source_file, redundant) in &redundant_unix {
                let line_hint = find_line_number(source_file, "platforms:");
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' (redundant: {})",
                        source_file, line, trait_id, redundant
                    );
                } else {
                    eprintln!(
                        "   {}: '{}' (redundant: {})",
                        source_file, trait_id, redundant
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} traits list 'unix' with redundant linux/macos (unix is the superset)",
                redundant_unix.len()
            ));
        }
    })
}

/// An allowlist entry that matches no trait is a dead exemption --
/// usually a directory that was renamed out from under it, which
/// strips the exemption silently and surfaces as a pile of cap
/// violations far from the rename.
pub(super) fn stale_filetype_allowlist<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let stale_allow = if enabled("stale-filetype-allowlist") {
        find_stale_filetype_allowlist_entries(input.rule_source_files)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        if !stale_allow.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} file-type allowlist entries match no trait",
                stale_allow.len()
            );
            eprintln!(
                "   These lift the file-type cap for a directory prefix that no longer\n   \
     exists -- most often a directory renamed without updating the entry,\n   \
     which drops the exemption for every trait under it. Point the entry at\n   \
     the new path, or delete it if the directory is gone.\n"
            );
            for entry in &stale_allow {
                eprintln!("   {entry:?} in BROAD_FILETYPE_ALLOWLIST");
            }
            eprintln!();
            warnings.push_id(
                "stale-filetype-allowlist",
                format!(
                    "{} file-type allowlist entries match no trait",
                    stale_allow.len()
                ),
            );
        }
    })
}

/// Validate: a composite may not declare a file type it cannot fire on.
pub(super) fn impossible_composite_filetypes<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let dead = find_dead_composites(input.trait_definitions, input.composite_rules);
    let impossible_ft = if enabled("impossible-composite-filetype") {
        find_impossible_composite_filetypes(input.trait_definitions, input.composite_rules)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        tracing::trace!("Checking for impossible composite file types");
        if !impossible_ft.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite file types cannot match a required leg",
                impossible_ft.len()
            );
            eprintln!("   On a leaf node every `all:` leg has to match that node, so a type some");
            eprintln!("   required leg cannot match is dead. If the rule fires on a container,");
            eprintln!("   declare the container type -- its legs arrive as member findings.\n");
            for (rule_id, ft, leg) in &impossible_ft {
                let source_file = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                eprintln!(
                    "   {}: '{}' cannot fire on {:?} -- required leg '{}' does not match it",
                    source_file, rule_id, ft, leg
                );
            }
            if !dead.is_empty() {
                eprintln!(
                    "\n   Of those, {} composites cannot fire on ANY declared type:",
                    dead.len()
                );
                for rule_id in &dead {
                    eprintln!("     DEAD {rule_id}");
                }
            }
            eprintln!();
            warnings.push_id(
                "impossible-composite-filetype",
                format!(
                    "{} composite file types cannot match a required leg",
                    impossible_ft.len()
                ),
            );
        }
    })
}

/// Validate: an atomic trait may not straddle the archive boundary.
pub(super) fn mixed_archive_filetypes<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let mixed_ft = if enabled("archive-filetype-mix") {
        find_mixed_archive_filetype_traits(input.trait_definitions)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        tracing::trace!("Checking for archive/non-archive file-type mixes");
        if !mixed_ft.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} atomic traits declare both archive and non-archive file types",
                mixed_ft.len()
            );
            eprintln!(
                "   An atomic runs on one node, and an archive node and the files inside it are"
            );
            eprintln!(
                "   different nodes -- cleave expands archives into members and never content-scans"
            );
            eprintln!(
                "   the container's own bytes, so only one half of the `for:` can ever fire.\n"
            );
            for (trait_id, archive, plain) in &mixed_ft {
                let fmt = |v: &Vec<RuleFileType>| {
                    v.iter()
                        .map(|ft| ft.label().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let source_file = input
                    .rule_source_files
                    .get(trait_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                eprintln!(
                    "   {}: '{}' archive=[{}] non-archive=[{}]",
                    source_file,
                    trait_id,
                    fmt(archive),
                    fmt(plain)
                );
            }
            eprintln!(
                "\n   Split it in two: one trait for the archive node, one for the files inside it.\n"
            );
            warnings.push_id(
                "archive-filetype-mix",
                format!(
                    "{} atomic traits declare both archive and non-archive file types",
                    mixed_ft.len()
                ),
            );
        }
    })
}

/// Validate: a pooling composite must declare the types it mixes.
pub(super) fn legs_outside_for<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let legs_outside = if enabled("leg-outside-for") {
        find_legs_outside_for(input.trait_definitions, input.composite_rules)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        tracing::trace!("Checking for required legs outside the for: list");
        if !legs_outside.is_empty() {
            eprintln!(
                "\n\u{274c} ERROR: {} required legs come from file types the rule does not declare",
                legs_outside.len()
            );
            eprintln!(
                "   `for:` lists the file types a composite is about: the container it reports"
            );
            eprintln!("   on AND the members whose findings may satisfy its legs. A leg that only");
            eprintln!(
                "   fires on an undeclared type can never be satisfied -- and a rule that names"
            );
            eprintln!(
                "   only its container used to be satisfied by ANY member, which is how a rule"
            );
            eprintln!(
                "   about a VS Code extension scored hostile on a Rust crate. Declare what you"
            );
            eprintln!("   mix; that is what makes the rule targeted.\n");
            for issue in &legs_outside {
                let source_file = input
                    .rule_source_files
                    .get(&issue.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let missing = issue
                    .leg_types
                    .iter()
                    .map(|ft| ft.label().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                // The consequence differs per clause, so say which it is:
                // a dead `all:`/`any:` leg costs a detection, while a dead
                // `unless:` leg costs false positives, and the two want
                // different urgency from whoever reads this.
                let (clause, effect) = match issue.role {
                    crate::capabilities::validation::LegRole::Required => {
                        ("requires", "the rule can never fire")
                    }
                    crate::capabilities::validation::LegRole::EveryAlternative => (
                        "has an any: clause whose every alternative, e.g.",
                        "the rule can never fire",
                    ),
                    crate::capabilities::validation::LegRole::Suppressor => (
                        "is suppressed by",
                        "the carve-out never fires, so this reports false positives",
                    ),
                    // Only `find_dead_any_alternatives` emits this role.
                    crate::capabilities::validation::LegRole::DeadAlternative => {
                        ("has an any: alternative", "that branch can never fire")
                    }
                };
                eprintln!(
                    "   {}: '{}' (scope: {:?}) {} '{}', which fires only on [{}] -- {}; add it to for:, or drop the leg",
                    source_file, issue.id, issue.scope, clause, issue.leg, missing, effect
                );
            }
            eprintln!();
            warnings.push_id(
                "leg-outside-for",
                format!(
                    "{} required legs come from file types the rule does not declare",
                    legs_outside.len()
                ),
            );
        }
    })
}

/// Soft warning: `any:` branches that `for:` makes unreachable
/// while a sibling branch keeps the rule alive. Summarised by default (the
/// corpus has a backlog); `CLEAVE_WARN_DEAD_ANY=1` lists them.
pub(super) fn dead_any_alternatives<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let dead_any_alternatives = enabled("dead-any-alternative").then(|| {
        crate::capabilities::validation::find_dead_any_alternatives(
            input.trait_definitions,
            input.composite_rules,
        )
    });
    report(move |warnings| {
        if let Some(dead_any) = dead_any_alternatives
            && !dead_any.is_empty()
        {
            let rules: std::collections::BTreeSet<&str> =
                dead_any.iter().map(|l| l.id.as_str()).collect();
            warnings.push_count(
                "dead-any-alternative",
                dead_any.len(),
                format!(
                    "{} any: alternatives in {} pooling composites are unreachable",
                    dead_any.len(),
                    rules.len()
                ),
            );
            eprintln!(
                "\n\u{26a0}\u{fe0f}  WARNING: {} any: alternatives in {} pooling composites come from file types the rule does not declare (that branch can never fire); CLEAVE_WARN_DEAD_ANY=1 lists them",
                dead_any.len(),
                rules.len()
            );
            if crate::env::flag("CLEAVE_WARN_DEAD_ANY") {
                for issue in &dead_any {
                    let source_file = input
                        .rule_source_files
                        .get(&issue.id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let missing = issue
                        .leg_types
                        .iter()
                        .map(|ft| ft.label().to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    eprintln!(
                        "   {}: '{}' any: '{}' fires only on [{}]",
                        source_file, issue.id, issue.leg, missing
                    );
                }
            }
        }
    })
}

/// Validate: a pooling scope needs a container node to run on.
pub(super) fn pooling_scope_without_container<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let pooling_without_container = if enabled("pooling-scope-no-container") {
        find_pooling_scope_without_container(input.composite_rules)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        tracing::trace!("Checking for pooling scopes with no container");
        if !pooling_without_container.is_empty() {
            eprintln!(
                "\n\u{274c} ERROR: {} composites use a pooling scope with no container to run on",
                pooling_without_container.len()
            );
            eprintln!(
                "   archive/package/outer composites are evaluated on the container node, never"
            );
            eprintln!(
                "   on a leaf -- so one whose `for:` names no container type never runs at all."
            );
            eprintln!(
                "   Name the container the rule reports on; its members' findings arrive there.\n"
            );
            for (rule_id, scope, types) in &pooling_without_container {
                let source_file = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let names = types
                    .iter()
                    .map(|ft| ft.label().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                eprintln!("   {source_file}: '{rule_id}' scope: {scope:?} for: [{names}]");
            }
            eprintln!();
            warnings.push_id(
                "pooling-scope-no-container",
                format!(
                    "{} composites use a pooling scope with no container to run on",
                    pooling_without_container.len()
                ),
            );
        }
    })
}

/// Validate: `scope: package` must be able to bind to a package.
pub(super) fn unbindable_package_scope<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let unbindable_package_scope = if enabled("unbindable-package-scope") {
        find_scope_without_valid_container(input.trait_definitions, input.composite_rules)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        tracing::trace!("Checking for unbindable package scopes");
        if !unbindable_package_scope.is_empty() {
            eprintln!(
                "\n\u{274c} ERROR: {} composites declare a `scope: package` that can never bind",
                unbindable_package_scope.len()
            );
            eprintln!("   `scope: package` keys evidence by its nearest enclosing package archive");
            eprintln!("   (npm/gem/whl/nupkg/crate/conda/egg/python_sdist). Registry metadata is");
            eprintln!(
                "   fetched beside the artifact, not from inside it, so it has no such ancestor"
            );
            eprintln!(
                "   and never shares a key with file evidence. Use `scope: outer`, the scope"
            );
            eprintln!("   that pools the artifact and its registry metadata together.\n");
            for issue in &unbindable_package_scope {
                let source_file = input
                    .rule_source_files
                    .get(&issue.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                eprintln!("   {}: '{}' -- {}", source_file, issue.id, issue.reason);
            }
            eprintln!();
            warnings.push_id(
                "unbindable-package-scope",
                format!(
                    "{} composites declare a `scope: package` that can never bind",
                    unbindable_package_scope.len()
                ),
            );
        }
    })
}

/// Validate: traits with too many file types (10+ multi-platform, 12+ single-platform)
pub(super) fn broad_filetype_traits<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let broad_ft = if enabled("broad-filetype-cap") {
        find_broad_filetype_traits(input.trait_definitions, input.rule_source_files)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        tracing::trace!("Checking for over-broad file type scope");
        if !broad_ft.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits exceed the file-type cap for their matcher type",
                broad_ft.len()
            );
            eprintln!(
                "   Caps run widest (text) to narrowest (tree-sitter) by matcher type; each line shows its own cap."
            );
            eprintln!(
                "   Narrow `for:`, or add a type-qualified allowlist entry (\"<type>:<dir-prefix>\").\n"
            );
            for (trait_id, source_file, count, matched_types, category, cap) in &broad_ft {
                let line_hint = find_line_number(source_file, "for:");
                let count_str = if *count == usize::MAX {
                    "all".to_string()
                } else {
                    count.to_string()
                };
                let types_str = matched_types
                    .iter()
                    .map(|ft| ft.label().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' (type:{} has {} types, cap {}: {})",
                        source_file, line, trait_id, category, count_str, cap, types_str
                    );
                } else {
                    eprintln!(
                        "   {}: '{}' (type:{} has {} types, cap {}: {})",
                        source_file, trait_id, category, count_str, cap, types_str
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
    "{} traits exceed the file-type cap for their matcher type (narrow for: or add a type-qualified allowlist entry)",
    broad_ft.len()
));
        }
    })
}

/// well-known/ atomic traits without file size bounds.
pub(super) fn wellknown_missing_size_filter<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let wk_no_size =
        find_wellknown_missing_size_filter(input.trait_definitions, input.rule_source_files);
    report(move |warnings| {
        let disable_wellknown_size_filter_validation =
            crate::validation_controls::is_validator_disabled("wellknown-size-filter");

        // Validate well-known/ atomic traits have file size bounds
        tracing::trace!("Checking well-known/ for missing size filters");
        if !disable_wellknown_size_filter_validation && !wk_no_size.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} well-known/ traits have no file size filter",
                wk_no_size.len()
            );
            eprintln!(
                "   well-known/ traits should include size_min/size_max to avoid false positives:\n"
            );
            for (trait_id, source_file) in &wk_no_size {
                eprintln!("   {}: Trait '{}'", source_file, trait_id);
            }
            eprintln!(
                "\n   Add 'size_min:' and/or 'size_max:' bounds appropriate to the malware family."
            );
            warnings.push(format!(
                "{} well-known/ traits lack file size filters (add size_min/size_max)",
                wk_no_size.len()
            ));
        }
    })
}

/// Validate well-known/ traits do not identify a family by version alone
pub(super) fn wellknown_version_paths<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let wk_version =
        find_wellknown_version_path_traits(input.trait_definitions, input.rule_source_files);
    report(move |warnings| {
        tracing::trace!("Checking well-known/ for bare version-path traits");
        if !crate::validation_controls::is_validator_disabled("wellknown-version-path")
            && !wk_version.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} well-known/ traits identify a family by registry metadata",
                wk_version.len()
            );
            eprintln!(
                "   well-known/malware/supply-chain/ is for behaviour-based detection of infamous"
            );
            eprintln!("   attacks -- campaigns an engineer recognises by technique -- not a");
            eprintln!("   metadata-based blacklist of published artifacts.\n");
            eprintln!(
                "   A `value` match on version asks only \"is this release numbered X\", which"
            );
            eprintln!(
                "   every package can answer; a match on name says which artifact was published,"
            );
            eprintln!(
                "   not what it did. Either way the finding still names the family, so unrelated"
            );
            eprintln!("   software is reported as that malware.\n");
            for (trait_id, source_file) in &wk_version {
                eprintln!("   {}: Trait '{}'", source_file, trait_id);
            }
            eprintln!(
                "\n   Describe behaviour that survives a rename or repack. Known-bad name and"
            );
            eprintln!(
                "   version pairs are dependency-analysis data, resolved together and updated"
            );
            eprintln!("   continuously; traits are not a blocklist.");
            warnings.push(format!(
    "{} well-known/ traits identify a family by registry metadata (detect behaviour instead)",
    wk_version.len()
));
        }
    })
}

/// well-known/ binary-targeting traits without a section filter.
pub(super) fn wellknown_missing_section_filter<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let wk_no_section =
        find_wellknown_missing_section_filter(input.trait_definitions, input.rule_source_files);
    report(move |warnings| {
        let disable_binary_section_filter_validation =
            crate::validation_controls::is_validator_disabled("binary-section-filter");

        // Validate well-known/ binary-targeting traits have a section filter
        tracing::trace!("Checking well-known/ binary traits for missing section filters");
        if !disable_binary_section_filter_validation && !wk_no_section.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} well-known/ binary traits lack a section filter",
                wk_no_section.len()
            );
            eprintln!(
                "   Binary-targeting traits in well-known/ should scope string/raw/hex matches to a section:"
            );
            eprintln!(
                "   Use 'section: .text' or 'section: .data' on the condition, or use 'type: section'.\n"
            );
            for (trait_id, source_file) in &wk_no_section {
                eprintln!("   {}: Trait '{}'", source_file, trait_id);
            }
            eprintln!();
            warnings.push(format!(
    "{} well-known/ binary traits lack section filters (add section: field to condition)",
    wk_no_section.len()
));
        }
    })
}

/// Soft warning for metadata/ binary-targeting traits without a section filter.
pub(super) fn metadata_missing_section_filter<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let meta_no_section =
        find_meta_missing_section_filter(input.trait_definitions, input.rule_source_files);
    report(move |warnings| {
        tracing::trace!("Checking metadata/ binary traits for missing section filters");
        if !crate::validation_controls::is_validator_disabled("metadata-binary-section")
            && !meta_no_section.is_empty()
        {
            warnings.push_count(
                "metadata-binary-section",
                meta_no_section.len(),
                format!(
                    "{} metadata/ binary traits lack a section filter",
                    meta_no_section.len()
                ),
            );
            eprintln!(
                "\n⚠️  SOFT WARNING: {} metadata/ binary traits lack a section filter",
                meta_no_section.len()
            );
            eprintln!("   Add a section filter when location is part of the metadata claim.");
            eprintln!(
                "   File-wide vocabulary or properties may legitimately match across sections.\n"
            );
            for (trait_id, source_file) in &meta_no_section {
                eprintln!("   {}: Trait '{}'", source_file, trait_id);
            }
            eprintln!();
        }
    })
}

/// Validate that all hex conditions targeting binary file types specify a section
pub(super) fn hex_binary_missing_section<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let hex_no_section = find_hex_binary_missing_section(input.trait_definitions);
    report(move |warnings| {
        tracing::trace!("Checking hex conditions targeting binaries for missing section");
        if !hex_no_section.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} hex condition(s) target binary file types without a section filter",
                hex_no_section.len()
            );
            eprintln!("   Hex patterns on binary targets must scope the search with 'section:'");
            eprintln!(
                "   (use 'section: text', 'section: data', etc., or add 'offset:' to pin location)\n"
            );
            for trait_id in &hex_no_section {
                let source_file = input
                    .rule_source_files
                    .get(trait_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                eprintln!("   {}: Trait '{}'", source_file, trait_id);
            }
            eprintln!();
            warnings.push(format!(
    "{} hex condition(s) target binaries without a section filter (add section: to condition)",
    hex_no_section.len()
));
        }
    })
}
