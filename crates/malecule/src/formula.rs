//! Formula string generation from findings.
//!
//! Generates molecular formula strings like "O₄(CaLaPC)H₂(DbPo)" from analysis findings.
//!
//! # Formula Structure
//!
//! - Top-level isotope number = count of unique second-level directories
//! - Subcategory isotope number = count of unique third-level+ directories
//! - Subcategories sorted by severity (most severe first), then alphabetically
//! - Isotope of 1 is omitted
//!
//! Example: `O₄(CaLaPC)H₂(DbPo)` means:
//! - O₄: 4 unique objective categories (Ca, La, P, C)
//! - H₂: 2 unique micro-behavior categories (Db, Po)

use crate::elements::{
    category_to_element, Element, HYDROGEN_MICRO, MENDELEVIUM, OXYGEN, POTASSIUM, THORIUM,
};
use crate::types::Severity;
use rustc_hash::{FxHashMap, FxHashSet};

/// A parsed finding for formula generation.
#[derive(Debug, Clone)]
pub struct FindingInput {
    /// Finding ID path (e.g., "objectives/lateral-movement/supply-chain/npm")
    pub id: String,
    /// Severity level
    pub severity: Severity,
}

/// Tracks unique subdirectories and max severity for a subcategory element.
#[derive(Debug, Default, Clone)]
struct SubcategoryInfo {
    /// Unique third-level+ directory paths beneath this subcategory
    unique_deeper_paths: FxHashSet<String>,
    /// Maximum severity among findings in this subcategory
    max_severity: Severity,
}

/// Top-level category with its subcategory elements.
#[derive(Debug, Default)]
struct CategoryGroup {
    /// Unique second-level directory names (determines top-level isotope)
    unique_second_levels: FxHashSet<String>,
    /// Maximum severity among all findings in this category
    max_severity: Severity,
    /// Subcategory elements mapped by symbol
    subcategories: FxHashMap<&'static str, SubcategoryInfo>,
}

/// Generates a formula string from findings.
///
/// # Arguments
/// * `findings` - Iterator of finding inputs
///
/// # Returns
/// A formula string like "O₄(CaLaPC)H₂(DbPo)" where:
/// - Top-level isotope = count of unique second-level directories
/// - Subcategory isotope = count of unique third-level+ directories
/// - Subcategories sorted by severity (most severe first), then alphabetically
#[must_use]
pub fn generate_formula<'a>(findings: impl Iterator<Item = &'a FindingInput>) -> String {
    // Track each top-level category with its subcategories
    let mut well_known = CategoryGroup::default();
    let mut objectives = CategoryGroup::default();
    let mut micro = CategoryGroup::default();
    let mut metadata = CategoryGroup::default();
    let mut third_party = CategoryGroup::default();

    for finding in findings {
        let parts: Vec<&str> = finding.id.split('/').collect();
        if parts.len() < 2 {
            continue;
        }

        // Determine which category group this finding belongs to
        let group = match parts[0] {
            "well-known" => &mut well_known,
            "objectives" => &mut objectives,
            "micro-behaviors" => &mut micro,
            "metadata" => &mut metadata,
            "third_party" | "third-party" => &mut third_party,
            _ => continue,
        };

        // Track unique second-level directory for top-level isotope
        group.unique_second_levels.insert(parts[1].to_string());

        // Update max severity
        if finding.severity > group.max_severity {
            group.max_severity = finding.severity;
        }

        // Find subcategory element from second-level directory
        if let Some(element) = category_to_element(parts[1]) {
            // Skip if this is a top-level element symbol
            if element.symbol == OXYGEN.symbol
                || element.symbol == HYDROGEN_MICRO.symbol
                || element.symbol == MENDELEVIUM.symbol
                || element.symbol == POTASSIUM.symbol
                || element.symbol == THORIUM.symbol
            {
                continue;
            }

            let entry = group.subcategories.entry(element.symbol).or_default();

            // Track unique third-level+ paths for subcategory isotope
            if parts.len() > 2 {
                // Join all remaining path components as the "deeper path"
                let deeper_path = parts[2..].join("/");
                entry.unique_deeper_paths.insert(deeper_path);
            }

            if finding.severity > entry.max_severity {
                entry.max_severity = finding.severity;
            }
        }
    }

    // Build formula in fixed order: well-known, objectives, micro-behaviors, metadata, third-party
    let mut formula = String::with_capacity(64);

    let categories: [(&CategoryGroup, &str); 5] = [
        (&well_known, POTASSIUM.symbol),
        (&objectives, OXYGEN.symbol),
        (&micro, HYDROGEN_MICRO.symbol),
        (&metadata, MENDELEVIUM.symbol),
        (&third_party, THORIUM.symbol),
    ];

    for (group, symbol) in categories {
        // Use unique second-level count for top-level isotope
        let top_level_count = group.unique_second_levels.len();
        if top_level_count == 0 {
            continue;
        }

        // Add top-level symbol with isotope (omit if 1)
        formula.push_str(symbol);
        if top_level_count > 1 {
            formula.push_str(&to_subscript(top_level_count));
        }

        // Add subcategories in parentheses if any
        if !group.subcategories.is_empty() {
            // Sort subcategories by severity (most severe first), then alphabetically by symbol
            let mut subs: Vec<_> = group.subcategories.iter().collect();
            subs.sort_by(|a, b| {
                severity_to_priority(a.1.max_severity)
                    .cmp(&severity_to_priority(b.1.max_severity))
                    .then_with(|| a.0.cmp(b.0))
            });

            formula.push('(');
            for (sym, info) in subs {
                formula.push_str(sym);
                // Use unique deeper paths count for subcategory isotope (omit if 1)
                let sub_count = info.unique_deeper_paths.len();
                if sub_count > 1 {
                    formula.push_str(&to_subscript(sub_count));
                }
            }
            formula.push(')');
        }
    }

    formula
}

/// Converts severity to sort priority (lower = more severe = first).
fn severity_to_priority(sev: Severity) -> u8 {
    match sev {
        Severity::Hostile => 0,
        Severity::Suspicious => 1,
        Severity::Notable => 2,
        Severity::Neutral => 3,
    }
}

/// Converts a number to subscript Unicode characters.
fn to_subscript(n: usize) -> String {
    const SUBSCRIPTS: [char; 10] = ['₀', '₁', '₂', '₃', '₄', '₅', '₆', '₇', '₈', '₉'];

    if n == 0 {
        return String::from("₀");
    }

    let mut result = String::new();
    let mut num = n;
    let mut digits = Vec::new();

    while num > 0 {
        digits.push(SUBSCRIPTS[num % 10]);
        num /= 10;
    }

    for d in digits.into_iter().rev() {
        result.push(d);
    }

    result
}

/// Parses a finding ID to extract the element for the most specific category.
#[must_use]
pub fn finding_to_element(finding_id: &str) -> Option<Element> {
    let parts: Vec<&str> = finding_id.split('/').collect();

    // Try from most specific to least specific
    for i in (1..parts.len()).rev() {
        if let Some(element) = category_to_element(parts[i]) {
            return Some(element);
        }
    }

    None
}

/// Extracts the top-level category element from a finding ID.
#[must_use]
pub fn finding_to_top_level(finding_id: &str) -> Option<Element> {
    let top = finding_id.split('/').next()?;
    category_to_element(top)
}

/// Extracts the second-level category from a finding ID.
#[must_use]
pub fn finding_to_subcategory(finding_id: &str) -> Option<&str> {
    let mut parts = finding_id.split('/');
    parts.next()?; // Skip top-level
    parts.next() // Return second level
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscript() {
        assert_eq!(to_subscript(1), "₁");
        assert_eq!(to_subscript(5), "₅");
        assert_eq!(to_subscript(12), "₁₂");
        assert_eq!(to_subscript(100), "₁₀₀");
    }

    #[test]
    fn test_generate_formula() {
        let findings = [
            FindingInput {
                id: "objectives/lateral-movement/supply-chain/npm".to_string(),
                severity: Severity::Suspicious,
            },
            FindingInput {
                id: "objectives/execution/interpreter/script".to_string(),
                severity: Severity::Notable,
            },
            FindingInput {
                id: "micro-behaviors/fs/file".to_string(),
                severity: Severity::Notable,
            },
            FindingInput {
                id: "metadata/quality".to_string(),
                severity: Severity::Notable,
            },
            FindingInput {
                id: "metadata/quality/npm".to_string(),
                severity: Severity::Notable,
            },
        ];

        let formula = generate_formula(findings.iter());
        // New format: O₂(LaXe)H(F)Md₂(Au₂)
        // - O₂ with La (lateral-movement, suspicious) and Xe (execution, notable)
        // - H with F (fs)
        // - Md₂ with Au₂ (quality x2)
        assert!(formula.contains("O₂")); // 2 objectives
        assert!(formula.contains('(')); // Has parentheses for subcategories
        assert!(formula.contains("La")); // lateral-movement
        assert!(formula.contains("Xe")); // execution
        assert!(formula.contains('H')); // Micro-behaviors
        assert!(formula.contains('F')); // fs
        assert!(formula.contains("Md")); // Metadata
        assert!(formula.contains("Au")); // quality
    }

    #[test]
    fn test_finding_to_element() {
        assert_eq!(
            finding_to_element("objectives/lateral-movement/supply-chain/npm"),
            Some(crate::elements::SULFUR)
        );
        assert_eq!(
            finding_to_element("micro-behaviors/fs/file"),
            Some(crate::elements::FLUORINE)
        );
    }

    #[test]
    fn test_finding_to_top_level() {
        assert_eq!(
            finding_to_top_level("objectives/lateral-movement"),
            Some(crate::elements::OXYGEN)
        );
        assert_eq!(
            finding_to_top_level("micro-behaviors/fs"),
            Some(crate::elements::HYDROGEN_MICRO)
        );
    }
}
