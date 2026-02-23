//! Helper functions for validation, file type detection, and metric field handling.

use crate::composite_rules::{
    CompositeTrait, Condition, FileType as RuleFileType, TraitDefinition,
};
use rustc_hash::FxHashSet;
use std::path::Path;

impl super::CapabilityMapper {
    /// Detect file type from file type string
    pub(super) fn detect_file_type(&self, file_type: &str) -> RuleFileType {
        RuleFileType::from_str(file_type)
    }
}

/// Validate trait and composite conditions for problematic patterns.
/// Returns true if errors were found.
pub(super) fn validate_conditions(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    path: &Path,
) -> bool {
    let mut has_errors = false;

    // Check trait definitions
    for trait_def in trait_definitions {
        if check_condition(&trait_def.r#if.condition, &trait_def.id, path) {
            has_errors = true;
        }
    }

    // Check composite rules
    for rule in composite_rules {
        // Check all conditions in the rule
        if let Some(all_conditions) = &rule.all {
            for cond in all_conditions {
                if check_condition(cond, &rule.id, path) {
                    has_errors = true;
                }
            }
        }
        if let Some(any_conditions) = &rule.any {
            for cond in any_conditions {
                if check_condition(cond, &rule.id, path) {
                    has_errors = true;
                }
            }
        }
        if let Some(none_conditions) = &rule.none {
            for cond in none_conditions {
                if check_condition(cond, &rule.id, path) {
                    has_errors = true;
                }
            }
        }
        if let Some(unless_conditions) = &rule.unless {
            for cond in unless_conditions {
                if check_condition(cond, &rule.id, path) {
                    has_errors = true;
                }
            }
        }
    }

    has_errors
}

/// Check raw YAML content for meaningless patterns before parsing.
/// Returns a list of warnings for patterns that are valid YAML but semantically meaningless.
pub(super) fn check_yaml_patterns(content: &str, path: &Path) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check for explicit 'offset: null' which is meaningless (same as not specifying)
    // Use regex to match the pattern with proper YAML indentation context
    #[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
    fn offset_null_re() -> &'static regex::Regex {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^\s+offset:\s*null\s*$").unwrap())
    }
    for (line_num, line) in content.lines().enumerate() {
        if offset_null_re().is_match(line) {
            warnings.push(format!(
                "{} line {}: 'offset: null' is meaningless (same as not specifying offset) - remove this line",
                path.display(),
                line_num + 1
            ));
        }
    }

    // Check for explicit 'section: null' which is also meaningless
    #[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
    fn section_null_re() -> &'static regex::Regex {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^\s+section:\s*null\s*$").unwrap())
    }
    for (line_num, line) in content.lines().enumerate() {
        if section_null_re().is_match(line) {
            warnings.push(format!(
                "{} line {}: 'section: null' is meaningless (same as not specifying section) - remove this line",
                path.display(),
                line_num + 1
            ));
        }
    }

    // Check for directories named "obfuscation" or "obfuscate" under micro-behaviors/.
    // Obfuscation detection describes attacker intent (anti-analysis evasion), not observable
    // capability — it belongs in objectives/, not micro-behaviors/.
    {
        let components: Vec<_> = path.components().collect();
        // Find the index of a component named "cap"
        let cap_idx = components
            .iter()
            .position(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case("cap"));
        if let Some(cap_pos) = cap_idx {
            // Check directory components after "micro-behaviors/" but before the filename
            let dir_components = &components[cap_pos + 1..components.len().saturating_sub(1)];
            for component in dir_components {
                let name = component.as_os_str().to_string_lossy();
                if name.eq_ignore_ascii_case("obfuscation")
                    || name.eq_ignore_ascii_case("obfuscate")
                {
                    warnings.push(format!(
                        "{}: directory '{}' must not be under 'micro-behaviors/' — obfuscation detection \
                         describes attacker intent (anti-analysis evasion), not an observable \
                         capability. Move this file to 'objectives/anti-static/obfuscation/' or \
                         'objectives/anti-analysis/obfuscation/'. See TAXONOMY.md: micro-behaviors/ captures \
                         what code can do; objectives/ captures attacker goals.",
                        path.display(),
                        name
                    ));
                    break; // one warning per file is enough
                }
            }
        }
    }

    warnings
}

/// Check a single condition for problematic patterns.
/// Returns true if an error was found.
fn check_condition(condition: &Condition, trait_id: &str, path: &Path) -> bool {
    if let Condition::Raw { exact: Some(_), .. } = condition {
        eprintln!(
            "❌ ERROR: Trait '{}' in {} uses 'type: raw' with 'exact' match. \
            This requires the entire file content to exactly match the pattern, \
            which is rarely useful. Consider using 'substr' instead.",
            trait_id,
            path.display()
        );
        return true;
    }

    false
}

/// Collect all metric field references from a trait definition
pub(super) fn collect_metric_refs_from_trait(trait_def: &TraitDefinition) -> Vec<String> {
    let mut fields = Vec::new();
    collect_metric_refs_from_condition(&trait_def.r#if.condition, &mut fields);
    fields
}

/// Recursively collect metric field references from a condition
fn collect_metric_refs_from_condition(condition: &Condition, fields: &mut Vec<String>) {
    if let Condition::Metrics { field, .. } = condition {
        fields.push(field.clone());
    }
}

/// Get all valid metric field paths
/// Dynamically extracts all field paths from metrics struct definitions
pub(super) fn get_valid_metric_fields() -> FxHashSet<String> {
    // Use the auto-generated field paths from the ValidFieldPaths derive macro
    // This ensures the validation always stays in sync with actual struct definitions
    crate::types::field_paths::all_valid_metric_paths()
        .into_iter()
        .collect()
}

/// Suggest a similar metric field for typos (simple Levenshtein distance)
pub(super) fn suggest_metric_field(valid_fields: &FxHashSet<String>, typo: &str) -> Option<String> {
    let mut best_match: Option<(String, usize)> = None;

    for valid_field in valid_fields {
        let distance = strsim::levenshtein(typo, valid_field);
        if distance <= 3 {
            // Only suggest if within 3 edits
            if let Some((_, best_dist)) = best_match {
                if distance < best_dist {
                    best_match = Some((valid_field.clone(), distance));
                }
            } else {
                best_match = Some((valid_field.clone(), distance));
            }
        }
    }

    best_match.map(|(field, _)| field)
}
