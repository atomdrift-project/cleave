//! Directory-layout checks: names, depth, width and sibling cohorts.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Check if a directory path contains platform/language names as directories.
///
/// Returns a list of `(directory_path, platform_name)` violations.
#[must_use]
pub(crate) fn find_platform_named_directories(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        // Skip metadata/format/ paths - binary format names are legitimate there
        if dir_path.starts_with("metadata/format/") {
            continue;
        }

        // Skip interpreter/<language> paths - language names are expected there
        // e.g., objectives/execution/interpreter/powershell, objectives/execution/interpreter/python
        if dir_path.contains("/interpreter/") {
            continue;
        }

        // Split the path and check each component
        for component in dir_path.split('/') {
            let lower = component.to_lowercase();
            if PLATFORM_NAMES.contains(&lower.as_str()) {
                violations.push((dir_path.clone(), component.to_string()));
                break; // Only report first violation per path
            }
        }
    }

    violations
}

/// Check for duplicate second-level directories across metadata/, micro-behaviors/, objectives/, and well-known/.
///
/// This indicates taxonomy violations - directories should not be repeated across namespaces.
/// For example, micro-behaviors/command-and-control/ and objectives/command-and-control/ suggests
/// micro-behaviors/command-and-control/ is misplaced (C2 is an objective, not a capability).
///
/// Returns a list of `(second_level_dir, namespaces_found_in)` violations.
#[must_use]
pub(crate) fn find_duplicate_second_level_directories(
    trait_dirs: &[String],
) -> Vec<(String, Vec<String>)> {
    let mut second_level_map: HashMap<String, Vec<String>> = HashMap::new();

    for dir_path in trait_dirs {
        let parts: Vec<&str> = dir_path.split('/').collect();
        if parts.len() < 2 {
            continue; // Need at least namespace/second-level
        }

        let namespace = parts[0];
        let second_level = parts[1];

        // Only check the four main namespaces
        if !matches!(
            namespace,
            "micro-behaviors" | "objectives" | "well-known" | "metadata"
        ) {
            continue;
        }

        second_level_map
            .entry(second_level.to_string())
            .or_default()
            .push(namespace.to_string());
    }

    // Find second-level directories that appear in multiple namespaces
    let mut violations = Vec::new();
    for (second_level, mut namespaces) in second_level_map {
        // Deduplicate and sort namespaces
        namespaces.sort();
        namespaces.dedup();

        if namespaces.len() > 1 {
            violations.push((second_level, namespaces));
        }
    }

    // Sort by directory name for consistent output
    violations.sort_by(|a, b| a.0.cmp(&b.0));

    violations
}

/// Directory depth above this value produces a soft validation warning.
/// Count directories below the tier; filenames and local rule IDs do not count.
pub(crate) const TAXONOMY_DEPTH_REVIEW_THRESHOLD: usize = 5;

/// Find taxonomy directories deeper than the soft-warning threshold in any tier.
#[must_use]
pub(crate) fn find_deep_taxonomy_directories(trait_dirs: &[String]) -> Vec<(String, usize)> {
    let mut candidates = Vec::new();
    for directory in trait_dirs {
        let mut parts = directory.split('/');
        if !matches!(
            parts.next(),
            Some("micro-behaviors" | "objectives" | "metadata" | "well-known")
        ) {
            continue;
        }
        let depth = parts.count();
        if depth > TAXONOMY_DEPTH_REVIEW_THRESHOLD {
            candidates.push((directory.clone(), depth));
        }
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

/// Group directories' subtree rule counts by parent, for the sibling-cohort
/// checks. Only `micro-behaviors/` and `objectives/` are considered, and the
/// tier plus first category layer are skipped: they are too broad to be useful
/// as local organization advice.
pub(super) fn sibling_cohorts(
    direct_rule_counts: &HashMap<String, usize>,
) -> HashMap<String, Vec<(String, usize)>> {
    let mut subtree_counts: HashMap<String, usize> = HashMap::new();

    for (directory, count) in direct_rule_counts {
        if !directory.starts_with("micro-behaviors/") && !directory.starts_with("objectives/") {
            continue;
        }
        let parts: Vec<&str> = directory.split('/').collect();
        if parts.len() < 3 {
            continue;
        }
        for end in 1..=parts.len() {
            *subtree_counts.entry(parts[..end].join("/")).or_default() += count;
        }
    }

    let mut children_by_parent: HashMap<String, Vec<(String, usize)>> = HashMap::new();
    for (directory, count) in &subtree_counts {
        if let Some((parent, child)) = directory.rsplit_once('/') {
            if parent.split('/').count() < 3 {
                continue;
            }
            children_by_parent
                .entry(parent.to_string())
                .or_default()
                .push((child.to_string(), *count));
        }
    }
    children_by_parent
}

/// Find sparse sibling cohorts that may be over-fragmented in the taxonomy.
///
/// A cohort produces a soft warning when a parent has at least two rule-bearing child
/// branches and their combined subtree contains fewer than 35 rules.
/// This does not prove the branches should be flattened: the child
/// techniques may be genuinely distinct. It identifies places where cap pressure
/// does not explain the extra branching and a human should check whether breadth
/// could preserve precision with a simpler visible path.
#[must_use]
#[cfg(test)]
pub(crate) fn find_sparse_sibling_cohorts(
    direct_rule_counts: &HashMap<String, usize>,
) -> Vec<(String, usize, usize)> {
    const SPARSE_SIBLING_RULE_THRESHOLD: usize = 35;

    let mut candidates = Vec::new();
    for (parent, children) in sibling_cohorts(direct_rule_counts) {
        if children.len() < 2 {
            continue;
        }
        let sibling_rules: usize = children.iter().map(|(_, count)| count).sum();
        if sibling_rules < SPARSE_SIBLING_RULE_THRESHOLD {
            candidates.push((parent, sibling_rules, children.len()));
        }
    }
    candidates.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
    candidates
}

/// Find parents with many child directories that are sparse on average.
/// Ten branches indicate a broad directory taxonomy, and an average of eight
/// rules or fewer per branch merits review for needless fragmentation. This
/// is a review signal only: distinct techniques remain separate. Returns
/// `(parent, children, total_rules, average_rules)`, lowest average first.
#[must_use]
pub(crate) fn find_fragmented_sibling_cohorts(
    direct_rule_counts: &HashMap<String, usize>,
) -> Vec<(String, usize, usize, f64)> {
    const MIN_CHILDREN: usize = 10;
    const MAX_AVERAGE_RULES: f64 = 8.0;
    let mut candidates = Vec::new();
    for (parent, children) in sibling_cohorts(direct_rule_counts) {
        if children.len() < MIN_CHILDREN {
            continue;
        }
        let rules: usize = children.iter().map(|(_, count)| count).sum();
        let average = rules as f64 / children.len() as f64;
        if average <= MAX_AVERAGE_RULES {
            candidates.push((parent, children.len(), rules, average));
        }
    }
    candidates.sort_by(|a, b| a.3.total_cmp(&b.3).then_with(|| a.0.cmp(&b.0)));
    candidates
}

/// Find trait and composite rule IDs whose local identifier contains invalid
/// characters. Local IDs must match `[a-zA-Z0-9_-]+`.
///
/// The loader prepends `<directory>::` to YAML ids that don't already contain
/// `::` or `/`, so the canonical form here is `path::local_id`. We strip
/// everything before `::` and validate only the local part — the path prefix
/// is loader-generated and always contains `/`.
///
/// (The "user wrote a path-qualified id like `well-known/malware/foo::bar` in
/// the `id:` field" case is enforced at parse time, see parsing.rs.)
///
/// Returns a list of `(id, invalid_char, source_file)` violations.
#[must_use]
pub(crate) fn find_invalid_trait_ids(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, char, String)> {
    let mut violations = Vec::new();

    for trait_def in trait_definitions {
        let local_id = trait_def
            .id
            .rfind("::")
            .map_or(trait_def.id.as_str(), |i| &trait_def.id[i + 2..]);
        if let Some(invalid_char) = validate_trait_id_chars(local_id) {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), invalid_char, source));
        }
    }

    for rule in composite_rules {
        let local_id = rule
            .id
            .rfind("::")
            .map_or(rule.id.as_str(), |i| &rule.id[i + 2..]);
        if let Some(invalid_char) = validate_trait_id_chars(local_id) {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), invalid_char, source));
        }
    }

    violations
}

/// Find directories containing banned meaningless segments.
///
/// Returns: `Vec<(directory_path, banned_segment)>`
#[must_use]
pub(crate) fn find_banned_directory_segments(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        for segment in dir_path.split('/') {
            let lower = segment.to_lowercase();
            if BANNED_DIRECTORY_SEGMENTS.contains(&lower.as_str()) {
                if BANNED_SEGMENT_EXCEPTIONS.iter().any(|(path, allowed)| {
                    lower == *allowed
                        && (dir_path == *path || dir_path.starts_with(&format!("{path}/")))
                }) {
                    continue;
                }
                violations.push((dir_path.clone(), segment.to_string()));
                break; // Only report first violation per path
            }
        }
    }

    violations
}

/// Forbid `content/` directories anywhere under `metadata/`.
///
/// `metadata/` holds neutral facts about what a file *is* — its structure,
/// format, and provenance. A `content/` bucket describes what a file
/// *contains or does*, which is behavior: intent belongs in `objectives/`, a
/// neutral observable capability in `micro-behaviors/`. So a `content/`
/// directory under `metadata/` is always a misfiling. (`content/` is fine
/// elsewhere, e.g. `objectives/anti-static/obfuscation/encoding/content/`.)
///
/// Returns the offending directory paths.
#[must_use]
pub(crate) fn find_metadata_content_dirs(trait_dirs: &[String]) -> Vec<String> {
    trait_dirs
        .iter()
        .filter(|d| {
            d.starts_with("metadata/")
                && d.split('/').any(|seg| seg.eq_ignore_ascii_case("content"))
        })
        .cloned()
        .collect()
}

/// Reject definitions under the retired `metadata/file/string/` namespace.
#[must_use]
pub(crate) fn find_new_metadata_file_string_ids(rule_ids: &[String]) -> Vec<String> {
    let mut violations: Vec<String> = rule_ids
        .iter()
        .filter(|id| {
            id.starts_with("metadata/file/string/") || id.starts_with("metadata/file/string::")
        })
        .cloned()
        .collect();
    violations.sort();
    violations.dedup();
    violations
}

/// Reject definitions under the retired `metadata/file/literal` namespace.
#[must_use]
pub(crate) fn find_new_metadata_file_literal_ids(rule_ids: &[String]) -> Vec<String> {
    let mut violations: Vec<String> = rule_ids
        .iter()
        .filter(|id| {
            id.starts_with("metadata/file/literal/") || id.starts_with("metadata/file/literal::")
        })
        .cloned()
        .collect();
    violations.sort();
    violations.dedup();
    violations
}

/// Find directories where a segment duplicates its immediate parent.
///
/// e.g., "micro-behaviors/execution/execution/" or "objectives/credential-access/credentials/"
///
/// Returns: `Vec<(directory_path, duplicated_segment)>`
#[must_use]
pub(crate) fn find_parent_duplicate_segments(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        let segments: Vec<&str> = dir_path.split('/').collect();

        for (segment_index, window) in segments.windows(2).enumerate() {
            let parent = window[0].to_lowercase();
            let child = window[1].to_lowercase();

            // Exact duplicate
            if parent == child {
                // Check if this path is in the exceptions list
                if !PARENT_DUPLICATE_EXCEPTIONS
                    .iter()
                    .any(|exc| dir_path.starts_with(exc))
                {
                    violations.push((dir_path.clone(), window[1].to_string()));
                }
                break;
            }

            // Plural/singular variants (simple check)
            if parent.len() >= 3 && child.len() >= 3 {
                // "cred" vs "credential-access" or "credentials"
                let parent_stem = parent.trim_end_matches('s');
                let child_stem = child.trim_end_matches('s');
                if parent_stem == child_stem {
                    // Check if this path is in the exceptions list
                    if !PARENT_DUPLICATE_EXCEPTIONS
                        .iter()
                        .any(|exc| dir_path.starts_with(exc))
                    {
                        violations.push((dir_path.clone(), window[1].to_string()));
                    }
                    break;
                }

                // Product names naturally begin with their category noun (DataEase,
                // MediaForge, BrowserStack, `lint/linter`, `debug/debugpy`). Exact and
                // plural duplicates above still apply at this boundary; only
                // prefix-abbreviation matching does not.
                //
                // `>= 2` rather than `== 2`: a category may carry a grouping layer
                // (`tool/development/lint/…`), which puts the product one level
                // deeper without changing why its name echoes the category.
                if segments.first() == Some(&"well-known") && segment_index >= 2 {
                    continue;
                }

                // Check short abbreviations: "exec"/"execution", "cred"/"credential-access".
                // A fully spelled category may naturally recur in a product name,
                // such as well-known/app/browser/browserstack.
                let (shorter, longer) = if parent.len() <= child.len() {
                    (&parent, &child)
                } else {
                    (&child, &parent)
                };
                // A child that repeats its parent verbatim and then qualifies it
                // -- `clipboard/clipboard-write`, `registry/registry-run-key` --
                // stutters at any length: the path already said the noun, so the
                // child should carry only what it adds (`clipboard/write`). The
                // separator is what distinguishes this from a name that merely
                // starts with the same letters (`browser/browserstack`), which is
                // why the length-limited prefix rule below cannot see it.
                let restates_parent = longer.starts_with(&format!("{shorter}-"));
                if (restates_parent || shorter.len() <= 5) && longer.starts_with(shorter) {
                    // Check if this path is in the exceptions list
                    if !PARENT_DUPLICATE_EXCEPTIONS
                        .iter()
                        .any(|exc| dir_path.starts_with(exc))
                    {
                        violations.push((dir_path.clone(), window[1].to_string()));
                    }
                    break;
                }
            }
        }
    }

    violations
}

/// Sibling directories whose names say the same thing twice.
///
/// Siblings answer one question, so two names built from one stem are usually
/// that answer written twice. Two shapes carry the signal:
///
/// * **a refinement filed as a sibling** -- `encrypt/` beside `encrypt-dotnet/`,
///   `script/` beside `script-dropper/`. The longer name spells the shorter one
///   and then qualifies it, which is what a *child* is: it belongs under what it
///   refines, not next to it. The separator is the discriminator -- without it,
///   `cloud`/`cloudflare` and `libev`/`libevent` are coincidences, not restatements.
/// * **two word-forms of one noun** -- `header`/`headers`, `check`/`checks`,
///   `encode`/`encoded`, `resolve`/`resolver`. Nothing distinguishes them, so
///   traits land in whichever the author saw first and both fill up.
///
/// Only same-parent siblings are compared, and `well-known/` is exempt: it names
/// products, and a family legitimately shares a stem (`boto`/`boto3`).
///
/// Returns: `Vec<(parent, shorter, longer)>`
#[must_use]
pub(crate) fn find_sibling_name_restatement(
    trait_dirs: &[String],
) -> Vec<(String, String, String)> {
    // Gerunds can name a different subject (account versus accounting), so
    // compare plural/tense endings only.
    const WORD_FORMS: &[&str] = &["s", "es", "d", "ed", "r", "er"];

    let mut by_parent: HashMap<&str, Vec<&str>> = HashMap::new();
    for dir in trait_dirs {
        if let Some(idx) = dir.rfind('/') {
            by_parent
                .entry(&dir[..idx])
                .or_default()
                .push(&dir[idx + 1..]);
        }
    }

    let mut out = Vec::new();
    for (parent, mut names) in by_parent {
        if parent.starts_with("well-known") {
            continue;
        }
        names.sort_unstable();
        names.dedup();
        for i in 0..names.len() {
            for j in (i + 1)..names.len() {
                let (short, long) = if names[i].len() <= names[j].len() {
                    (names[i], names[j])
                } else {
                    (names[j], names[i])
                };
                if short.len() < 4 {
                    continue;
                }
                let restates = long.starts_with(&format!("{short}-"))
                    || long
                        .strip_prefix(short)
                        .is_some_and(|tail| WORD_FORMS.contains(&tail));
                // Cross-cutting file profiles combine network and process evidence;
                // the general network profile retains other network observations.
                let distinct_cross_cutting_profile = parent == "metadata/file/profile"
                    && short == "network"
                    && long == "network-process";
                // Request-driven execution and captured command output are
                // distinct evidence groups; both need leaf YAML directories.
                let distinct_webshell_output = parent
                    == "objectives/command-and-control/backdoor/webshell/request"
                    && short == "command"
                    && long == "command-output";
                // Hidden target files are a reviewed cross-cutting refinement;
                // the broad fetch leaf retains chains without that requirement.
                let distinct_hidden_fetch = parent
                    == "objectives/execution/payload/file-exec/command"
                    && short == "fetch"
                    && long == "fetch-hidden";
                // User-level systemd services have a distinct persistence scope;
                // the general leaf holds system-wide or unscoped service evidence.
                let distinct_systemd_user = parent == "objectives/persistence/system/service"
                    && short == "systemd"
                    && long == "systemd-user";
                if restates
                    && !distinct_systemd_user
                    && !distinct_cross_cutting_profile
                    && !distinct_webshell_output
                    && !distinct_hidden_fetch
                {
                    out.push((parent.to_string(), short.to_string(), long.to_string()));
                }
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
#[test]
pub(super) fn hidden_fetch_sibling_exception_is_specific_to_the_reviewed_pair() {
    let dirs = [
        "objectives/execution/payload/file-exec/command/fetch",
        "objectives/execution/payload/file-exec/command/fetch-hidden",
        "objectives/execution/payload/file-exec/command/fetch-other",
        "other/command/fetch",
        "other/command/fetch-hidden",
    ]
    .map(str::to_string);
    let findings = find_sibling_name_restatement(&dirs);
    assert!(!findings.contains(&(
        "objectives/execution/payload/file-exec/command".into(),
        "fetch".into(),
        "fetch-hidden".into(),
    )));
    assert!(findings.contains(&(
        "objectives/execution/payload/file-exec/command".into(),
        "fetch".into(),
        "fetch-other".into(),
    )));
    assert!(findings.contains(&(
        "other/command".into(),
        "fetch".into(),
        "fetch-hidden".into(),
    )));
}

#[cfg(test)]
#[test]
pub(super) fn network_process_profile_is_a_specific_sibling_exception() {
    let dirs = [
        "metadata/file/profile/network",
        "metadata/file/profile/network-process",
        "metadata/file/profile/network-other",
        "other/profile/network",
        "other/profile/network-process",
        "objectives/command-and-control/backdoor/webshell/request/command",
        "objectives/command-and-control/backdoor/webshell/request/command-output",
        "other/request/command",
        "other/request/command-output",
    ]
    .map(str::to_string);
    let findings = find_sibling_name_restatement(&dirs);
    assert!(!findings.contains(&(
        "metadata/file/profile".into(),
        "network".into(),
        "network-process".into()
    )));
    assert!(findings.contains(&(
        "metadata/file/profile".into(),
        "network".into(),
        "network-other".into()
    )));
    assert!(findings.contains(&(
        "other/profile".into(),
        "network".into(),
        "network-process".into()
    )));
    assert!(!findings.contains(&(
        "objectives/command-and-control/backdoor/webshell/request".into(),
        "command".into(),
        "command-output".into()
    )));
    assert!(findings.contains(&(
        "other/request".into(),
        "command".into(),
        "command-output".into()
    )));
}

/// Find directories with too many rules (suggests need for subdirectories).
/// Atomic traits and composite rules are counted together.
///
/// Returns: `Vec<(directory_path, rule_count)>`
#[must_use]
pub(crate) fn find_oversized_trait_directories(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize)> {
    // Count rules per directory (extract directory from the rule ID)
    let mut dir_counts: HashMap<&str, usize> = HashMap::new();

    let ids = trait_definitions
        .iter()
        .map(|t| t.id.as_str())
        .chain(composite_rules.iter().map(|r| r.id.as_str()));
    for id in ids {
        // Everything before `::`, else before the last `/`
        let dir = match id.find("::").or_else(|| id.rfind('/')) {
            Some(idx) => &id[..idx],
            None => continue, // No directory prefix
        };

        *dir_counts.entry(dir).or_insert(0) += 1;
    }

    let mut violations: Vec<_> = dir_counts
        .into_iter()
        .filter(|(_, count)| *count > MAX_TRAITS_PER_DIRECTORY)
        .map(|(dir, count)| (dir.to_string(), count))
        .collect();

    violations.sort_by_key(|v| std::cmp::Reverse(v.1)); // Sort by count descending
    violations
}

/// Count physical source directories as well as ID namespaces. Explicitly
/// qualified IDs can otherwise hide an oversized source directory.
pub(crate) fn find_oversized_source_directories(
    sources: &HashMap<String, String>,
    root: &std::path::Path,
) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for source in sources.values() {
        let path = std::path::Path::new(source);
        let relative = path.strip_prefix(root).unwrap_or(path);
        if let Some(parent) = relative.parent() {
            let name = parent
                .to_string_lossy()
                .trim_start_matches("./")
                .to_string();
            *counts.entry(name).or_default() += 1;
        }
    }
    let mut out: Vec<_> = counts
        .into_iter()
        .filter(|(_, count)| *count > MAX_TRAITS_PER_DIRECTORY)
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

#[cfg(test)]
#[test]
pub(super) fn physical_directory_budget_counts_qualified_ids() {
    // The qualified IDs all name `well-known/example`, yet the rules live in
    // one physical directory, which is what the budget counts.
    let sources = |n: usize| -> HashMap<String, String> {
        (0..n)
            .map(|i| {
                (
                    format!("well-known/example::rule-{i}"),
                    "./well-known/example/identity/rules.yaml".to_string(),
                )
            })
            .collect()
    };
    let root = std::path::Path::new(".");
    assert!(find_oversized_source_directories(&sources(MAX_TRAITS_PER_DIRECTORY), root).is_empty());
    assert_eq!(
        find_oversized_source_directories(&sources(MAX_TRAITS_PER_DIRECTORY + 1), root),
        vec![(
            "well-known/example/identity".to_string(),
            MAX_TRAITS_PER_DIRECTORY + 1
        )]
    );
}

/// Find directories whose immediate subdirectories exceed
/// [`MAX_SUBDIRECTORIES_PER_DIRECTORY`] and need another grouping layer.
///
/// `trait_dirs` holds the directories that directly contain traits; every
/// ancestor level is derived from those paths, so a wide level is caught
/// wherever it sits in the tree.
///
/// Returns: `Vec<(directory_path, subdirectory_count)>`, widest first.
#[must_use]
pub(crate) fn find_wide_trait_directories(trait_dirs: &[String]) -> Vec<(String, usize)> {
    // Map each ancestor path to the set of its immediate child segments.
    let mut children: HashMap<&str, HashSet<&str>> = HashMap::new();
    for dir in trait_dirs {
        for (sep, _) in dir.match_indices('/') {
            let rest = &dir[sep + 1..];
            let child = rest.split('/').next().unwrap_or(rest);
            children.entry(&dir[..sep]).or_default().insert(child);
        }
    }

    let mut violations: Vec<(String, usize)> = children
        .into_iter()
        .filter(|(_, kids)| kids.len() > MAX_SUBDIRECTORIES_PER_DIRECTORY)
        .map(|(dir, kids)| (dir.to_string(), kids.len()))
        .collect();

    // Widest first, then lexicographic so the report is stable run to run.
    violations.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    violations
}

// ============================================================================
// well-known/ taxonomy enforcement validators
// ============================================================================
