//! Checks on the trait tree's directory layout (see TAXONOMY.md).

use super::{Report, ValidationInput, report};
use crate::capabilities::validation::{
    MAX_SUBDIRECTORIES_PER_DIRECTORY, TAXONOMY_DEPTH_REVIEW_THRESHOLD,
    find_banned_directory_segments, find_deep_taxonomy_directories,
    find_duplicate_second_level_directories, find_fragmented_sibling_cohorts,
    find_metadata_content_dirs, find_new_metadata_file_literal_ids,
    find_new_metadata_file_string_ids, find_parent_duplicate_segments,
    find_permuted_directory_paths, find_platform_named_directories, find_sibling_name_restatement,
    find_wide_trait_directories, validate_directory_structure,
};
use rustc_hash::FxHashSet;
use std::collections::HashMap;
use std::path::Path;

/// Check for unknown subdirectories in taxonomy tiers
/// According to TAXONOMY.md, only specific subdirectories are allowed
pub(super) fn unknown_subdirectories<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 2b/15: Validating directory whitelist");
        if !crate::validation_controls::is_validator_disabled("unknown-subdirectory")
            && let Err(errors) = validate_directory_structure(input.dir_path)
        {
            eprintln!(
                "\n❌ ERROR: {} unknown subdirectories found in taxonomy tiers",
                errors.len()
            );
            for error in &errors {
                eprintln!("   {}", error);
            }
            eprintln!();
            for error in &errors {
                warnings.push(format!("unknown subdirectory: {error}"));
            }
        }
    })
}

/// Check for YAML files above leaf directories.
pub(super) fn non_leaf_yaml_files<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 2c/15: Checking for non-leaf YAML files");
        let non_leaf_yaml_files = find_non_leaf_yaml_files(input.yaml_files, input.dir_path);
        if !non_leaf_yaml_files.is_empty()
            && !crate::validation_controls::is_validator_disabled("leaf-yaml")
        {
            eprintln!(
                "\n❌ ERROR: {} YAML files are not in leaf directories",
                non_leaf_yaml_files.len()
            );
            eprintln!(
                "   A directory with YAML files must not also have YAML-bearing child directories."
            );
            eprintln!(
                "   Choose one taxonomy level: move parent YAML into a leaf named for the shared technique,"
            );
            eprintln!(
                "   or flatten child YAML up when the extra directory adds no ML-visible technique signal."
            );
            eprintln!(
                "   Prefer language/platform-neutral technique names; use platform directories only when"
            );
            eprintln!("   the technique itself is platform-specific. Keep depth reasonable.\n");
            for file in &non_leaf_yaml_files {
                eprintln!("   {file}");
            }
            eprintln!();
            warnings.push_id(
                "leaf-yaml",
                format!(
                    "{} YAML files are above YAML-bearing child directories",
                    non_leaf_yaml_files.len()
                ),
            );
        }
    })
}

/// Check for taxonomy violations: platform/language names as directories
/// According to TAXONOMY.md, languages should be YAML filenames, not directories
pub(super) fn platform_named_directories<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 3/15: Checking for platform-named directories");
        let platform_dir_violations = find_platform_named_directories(&input.dir_list);
        if !platform_dir_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} directories are named after platforms/languages (TAXONOMY.md violation)",
                platform_dir_violations.len()
            );
            eprintln!("   Languages and platforms should be YAML filenames, not directories:\n");
            for (dir_path, platform_name) in &platform_dir_violations {
                eprintln!(
                    "   {}: contains platform directory '{}'",
                    dir_path, platform_name
                );
            }
            eprintln!("\n   Example: Instead of 'micro-behaviors/execution/python/runtime.yaml',");
            eprintln!("   use 'micro-behaviors/execution/runtime/python.yaml'\n");
            warnings.push(format!(
                "{} directories named after platforms (should be YAML filenames)",
                platform_dir_violations.len()
            ));
        }
    })
}

/// Check for duplicate second-level directories across namespaces
/// According to TAXONOMY.md, directories should not be repeated across metadata/, micro-behaviors/, objectives/, known/
pub(super) fn duplicate_second_level_directories<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 3b/15: Checking for duplicate second-level directories");
        let duplicate_dirs = find_duplicate_second_level_directories(&input.dir_list);
        if !crate::validation_controls::is_validator_disabled("duplicate-second-level-dir")
            && !duplicate_dirs.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} second-level directories are duplicated across namespaces (TAXONOMY.md violation)",
                duplicate_dirs.len()
            );
            eprintln!(
                "   Second-level directories should not be repeated across metadata/, micro-behaviors/, objectives/, known/:"
            );
            eprintln!(
                "   This indicates traits are misplaced - objectives should only be in objectives/, capabilities in micro-behaviors/.\n"
            );
            for (dir_name, namespaces) in &duplicate_dirs {
                eprintln!(
                    "   '{}' appears in: {}/{}/ ",
                    dir_name,
                    namespaces.join("/, "),
                    dir_name
                );
            }
            eprintln!("\n   Examples:");
            eprintln!(
                "   - micro-behaviors/command-and-control/ and objectives/command-and-control/ → C2 is an objective, should only be in objectives/"
            );
            eprintln!(
                "   - micro-behaviors/discovery/ and objectives/discovery/ → Discovery is an objective, should only be in objectives/"
            );
            eprintln!(
                "   - micro-behaviors/malware/ and known/malware/ → Malware detection should not be in micro-behaviors/\n"
            );
            warnings.push(format!(
                "{} second-level directories duplicated across namespaces",
                duplicate_dirs.len()
            ));
        }
    })
}

/// Check for levels that fan out into an unbrowsable flat list
pub(super) fn wide_directories<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 3c/15: Checking for wide directories");
        let wide_dirs = find_wide_trait_directories(&input.dir_list);
        if !wide_dirs.is_empty() && !crate::validation_controls::is_validator_disabled("wide-dir") {
            eprintln!(
                "\n❌ ERROR: {} directories have more than {} immediate subdirectories",
                wide_dirs.len(),
                MAX_SUBDIRECTORIES_PER_DIRECTORY
            );
            eprintln!(
                "   Why: at this width the level is a flat list, not a taxonomy — authors can't"
            );
            eprintln!(
                "   see whether a sibling already covers their case, and the directory feature"
            );
            eprintln!("   the ML pipeline reads degenerates into one bucket per entry.");
            eprintln!(
                "   Add an intermediate grouping layer (ecosystem, vendor, or family) and move"
            );
            eprintln!("   the existing subdirectories under it.\n");
            for (dir_path, count) in &wide_dirs {
                eprintln!("   {}: {} subdirectories", dir_path, count);
            }
            eprintln!();
            warnings.push_id(
                "wide-dir",
                format!(
                    "{} directories exceed {} immediate subdirectories (add a grouping layer)",
                    wide_dirs.len(),
                    MAX_SUBDIRECTORIES_PER_DIRECTORY
                ),
            );
        }
    })
}

/// Check for banned meaningless directory segments
pub(super) fn banned_directory_segments<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 4/15: Checking for banned directory segments");
        let banned_segment_violations = find_banned_directory_segments(&input.dir_list);
        if !banned_segment_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} directories contain meaningless segment names",
                banned_segment_violations.len()
            );
            eprintln!("   These segments add no semantic value and hurt taxonomy clarity:\n");
            for (dir_path, segment) in &banned_segment_violations {
                eprintln!("   {}: contains banned segment '{}'", dir_path, segment);
            }
            eprintln!("\n   Use specific, descriptive names instead.\n");
            warnings.push(format!(
                "{} directories contain meaningless segments",
                banned_segment_violations.len()
            ));
        }
    })
}

/// Two paths made of the same segments in a different order are the
/// same subject filed twice; the traits then drift apart in places no
/// duplicate check compares.
pub(super) fn permuted_directory_paths<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let permuted = find_permuted_directory_paths(&input.dir_list);
        if !permuted.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} directory pairs use the same segments in a different order",
                permuted.len()
            );
            eprintln!(
                "   Independent dimensions have no inherent order, so nesting them lets one\n   \
     subject be filed two ways. Each path reads correctly alone, which is why\n   \
     this goes unnoticed until the two copies have diverged. Keep one:\n"
            );
            for (a, b) in &permuted {
                eprintln!("   {a}   vs   {b}");
            }
            eprintln!();
            warnings.push(format!(
                "{} directory pairs are segment-order permutations of each other",
                permuted.len()
            ));
        }
    })
}

/// Shared spelling is a soft warning, not proof of equivalence:
/// account/accounting can describe distinct subjects.
pub(super) fn sibling_name_restatement<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let restated = find_sibling_name_restatement(&input.dir_list);
        if !restated.is_empty()
            && !crate::validation_controls::is_validator_disabled("sibling-restate")
        {
            warnings.push_count(
                "sibling-restate",
                restated.len(),
                format!(
                    "{} sibling directory pairs share a name stem",
                    restated.len()
                ),
            );
            eprintln!(
                "\n⚠️ SOFT WARNING: {} sibling directory pairs share a name stem",
                restated.len()
            );
            eprintln!(
                "   Review admission criteria: merge synonyms or nest genuine refinements.\n   \
     Shared spelling alone does not prove identical meaning; retain distinct\n   \
     subjects with documented boundaries.\n"
            );
            for (parent, short, long) in &restated {
                eprintln!("   {parent}/  {short}  vs  {long}");
            }
            eprintln!();
        }
    })
}

/// Forbid content/ directories under metadata/ (content describes
/// behavior/capability, never a neutral structural property).
pub(super) fn metadata_content_dirs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let metadata_content_dirs = find_metadata_content_dirs(&input.dir_list);
        if !metadata_content_dirs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} content/ director(ies) under metadata/",
                metadata_content_dirs.len()
            );
            eprintln!(
                "   metadata/ is for neutral structural facts; a content/ bucket describes\n   \
     what a file contains or does — move these traits to objectives/ (intent) or\n   \
     micro-behaviors/ (neutral capability):\n"
            );
            for dir_path in &metadata_content_dirs {
                eprintln!("   {}", dir_path);
            }
            eprintln!();
            warnings.push(format!(
                "{} content/ directories under metadata/",
                metadata_content_dirs.len()
            ));
        }
    })
}

/// `metadata/file/string/` is a legacy namespace, not a valid
/// home for new text evidence. Grandfather exact existing IDs
/// while their definitions move; do not allow additions even in
/// an established source directory.
pub(super) fn new_metadata_file_ids<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let rule_ids: Vec<String> = input
            .trait_definitions
            .iter()
            .map(|t| t.id.clone())
            .chain(input.composite_rules.iter().map(|r| r.id.clone()))
            .collect();
        let new_string_ids = find_new_metadata_file_string_ids(&rule_ids);
        if !new_string_ids.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} new rule ID(s) under legacy metadata/file/string/",
                new_string_ids.len()
            );
            eprintln!(
                "   String literals are file content, not structural metadata. Place each rule with the subject it evidences; only exact legacy IDs are temporarily allowed:\n"
            );
            for rule_id in &new_string_ids {
                eprintln!("   {}", rule_id);
            }
            eprintln!();
            warnings.push(format!(
                "{} new rule IDs under legacy metadata/file/string/",
                new_string_ids.len()
            ));
        }

        // `metadata/file/literal/` is also closed: context-only
        // literals must move to a subject home or remain on reviewed
        // hold, not grow a generic string-evidence bucket.
        let new_literal_ids = find_new_metadata_file_literal_ids(&rule_ids);
        if !new_literal_ids.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} new rule ID(s) under legacy metadata/file/literal/",
                new_literal_ids.len()
            );
            eprintln!(
                "   Literal evidence needs a subject-specific home; only exact legacy IDs are temporarily allowed:\n"
            );
            for rule_id in &new_literal_ids {
                eprintln!("   {}", rule_id);
            }
            eprintln!();
            warnings.push(format!(
                "{} new rule IDs under legacy metadata/file/literal/",
                new_literal_ids.len()
            ));
        }
    })
}

/// Check for directory names that duplicate their parent
pub(super) fn parent_duplicate_segments<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 5/15: Checking for parent duplicate segments");
        let parent_dup_violations = find_parent_duplicate_segments(&input.dir_list);
        if !parent_dup_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} directories duplicate their parent segment",
                parent_dup_violations.len()
            );
            eprintln!("   Child directories should not repeat parent names:\n");
            for (dir_path, segment) in &parent_dup_violations {
                eprintln!("   {}: segment '{}' duplicates parent", dir_path, segment);
            }
            eprintln!();
            warnings.push(format!(
                "{} directories duplicate parent segment",
                parent_dup_violations.len()
            ));
        }
    })
}

/// Depth is an authoring-quality soft warning.
pub(super) fn deep_taxonomy_directories<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let deep_dirs = find_deep_taxonomy_directories(&input.dir_list);
        if !deep_dirs.is_empty()
            && !crate::validation_controls::is_validator_disabled("deep-taxonomy")
        {
            warnings.push_count(
                "deep-taxonomy",
                deep_dirs.len(),
                format!(
                    "{} directories exceed depth {} below the tier",
                    deep_dirs.len(),
                    TAXONOMY_DEPTH_REVIEW_THRESHOLD
                ),
            );
            eprintln!(
                "\n⚠️ SOFT WARNING: {} directories exceed depth {} below the tier",
                deep_dirs.len(),
                TAXONOMY_DEPTH_REVIEW_THRESHOLD
            );
            eprintln!("   Count directory levels only, excluding the tier and filename.");
            eprintln!(
                "   Prefer breadth when precision is unchanged; retain deeper subtechniques when justified."
            );
            for (directory, depth) in &deep_dirs {
                eprintln!("   {directory} (depth {depth})");
            }
        }
    })
}

/// Count direct rules in every leaf, then report only parents
/// fragmented into many tiny sibling directories.
pub(super) fn fragmented_sibling_cohorts<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Checking sparse taxonomy sibling cohorts");
        let mut direct_rule_counts: HashMap<String, usize> = HashMap::new();
        for id in input.rule_source_files.keys() {
            let Some((directory, _)) = id.split_once("::") else {
                continue;
            };
            *direct_rule_counts.entry(directory.to_string()).or_default() += 1;
        }
        let fragmented_cohorts = find_fragmented_sibling_cohorts(&direct_rule_counts);
        if !fragmented_cohorts.is_empty()
            && !crate::validation_controls::is_validator_disabled("sparse-siblings")
        {
            warnings.push_count(
                "sparse-siblings",
                fragmented_cohorts.len(),
                format!(
                    "{} parents have ten or more child directories averaging 8 or fewer rules",
                    fragmented_cohorts.len()
                ),
            );
            eprintln!(
                "\n⚠️ SOFT WARNING: {} parents have ten or more child directories averaging 8 or fewer rules",
                fragmented_cohorts.len()
            );
            eprintln!(
                "   Review the child directories; merge only branches that answer the same taxonomy question."
            );
            for (parent, children, rules, average) in &fragmented_cohorts {
                eprintln!(
                    "   {parent} ({children} child directories, {rules} rules, {average:.1} rules per child)"
                );
            }
        }
    })
}

fn find_non_leaf_yaml_files(yaml_files: &[std::path::PathBuf], root: &Path) -> Vec<String> {
    // A directory holds YAML below it exactly when it is a proper ancestor of
    // some YAML file's directory. Collecting those ancestors once replaces
    // testing every file against every directory, which was ~20s on the tree.
    let non_leaf: FxHashSet<&Path> = yaml_files
        .iter()
        .filter_map(|path| path.parent())
        .flat_map(|dir| dir.ancestors().skip(1))
        .collect();

    let mut violations: Vec<String> = yaml_files
        .iter()
        .filter(|file| {
            let Some(dir) = file.parent() else {
                return false;
            };
            if !non_leaf.contains(dir) {
                return false;
            }
            // These item classes have useful observations whose predicates do
            // not identify a subtype. Keep them at the supported ancestor,
            // rather than inventing a miscellaneous subtype or overclaiming.
            // This is an exact taxonomy contract, not a namespace exemption.
            !matches!(
                dir.strip_prefix(root).ok().and_then(Path::to_str),
                Some(
                    "objectives/exfiltration/stealer"
                        | "objectives/exfiltration/stealer/credential"
                        | "objectives/exfiltration/stealer/credential/value"
                        | "objectives/exfiltration/stealer/configuration"
                        | "objectives/exfiltration/stealer/application-state"
                        | "objectives/exfiltration/stealer/media"
                )
            )
        })
        .map(|file| {
            file.strip_prefix(root)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string()
        })
        .collect();
    violations.sort_unstable();
    violations
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::find_non_leaf_yaml_files;
    use std::path::{Path, PathBuf};

    /// A file is non-leaf when YAML lives anywhere below its directory, by
    /// path component: `c-d/` shares a string prefix with `c/` but is a
    /// sibling, not a child.
    #[test]
    fn non_leaf_yaml_files_have_yaml_below_their_directory() {
        let files: Vec<PathBuf> = [
            "traits/a/x.yaml",
            "traits/a/b/y.yaml",
            "traits/c/z.yaml",
            "traits/c-d/w.yaml",
            "traits/top.yaml",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(
            find_non_leaf_yaml_files(&files, Path::new("traits")),
            ["a/x.yaml", "top.yaml"]
        );
    }

    #[test]
    fn reviewed_stolen_item_ancestors_allow_unspecialized_observations() {
        let root = Path::new("traits");
        let files: Vec<PathBuf> = [
            "objectives/exfiltration/stealer/broad.yaml",
            "objectives/exfiltration/stealer/credential/broad.yaml",
            "objectives/exfiltration/stealer/credential/value/broad.yaml",
            "objectives/exfiltration/stealer/credential/value/key/specific.yaml",
            "objectives/exfiltration/stealer/configuration/broad.yaml",
            "objectives/exfiltration/stealer/configuration/environment/specific.yaml",
            "objectives/exfiltration/stealer/application-state/broad.yaml",
            "objectives/exfiltration/stealer/application-state/cookie/specific.yaml",
            "objectives/exfiltration/stealer/media/broad.yaml",
            "objectives/exfiltration/stealer/media/image/specific.yaml",
            "objectives/exfiltration/stealer/media/image/nested/specific.yaml",
            "micro-behaviors/fs/path/broad.yaml",
            "micro-behaviors/fs/path/credential/specific.yaml",
        ]
        .into_iter()
        .map(|path| root.join(path))
        .collect();
        assert_eq!(
            find_non_leaf_yaml_files(&files, root),
            [
                "micro-behaviors/fs/path/broad.yaml",
                "objectives/exfiltration/stealer/media/image/specific.yaml",
            ]
        );
    }
}
