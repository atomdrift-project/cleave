//! Formula string generation from findings.
//!
//! Generates molecular formula strings like "O₇(AlCXe)H₂(FDb)" from analysis findings.
//! Format: TopLevel_count(subcategories) with subcategories sorted by severity.

use crate::elements::{
    category_to_element, Element, HYDROGEN_MICRO, MENDELEVIUM, OXYGEN, POTASSIUM, THORIUM,
};
use crate::types::Severity;
use rustc_hash::FxHashMap;

/// A parsed finding for formula generation.
#[derive(Debug, Clone)]
pub struct FindingInput {
    /// Finding ID path (e.g., "objectives/lateral-movement/supply-chain/npm")
    pub id: String,
    /// Severity level
    pub severity: Severity,
}

/// Counts of elements with their max severity.
#[derive(Debug, Default, Clone)]
struct ElementCount {
    count: usize,
    max_severity: Severity,
}

/// Top-level category with its subcategory elements.
#[derive(Debug, Default)]
struct CategoryGroup {
    count: usize,
    max_severity: Severity,
    /// Subcategory elements: (symbol, count, severity)
    subcategories: FxHashMap<&'static str, ElementCount>,
}

/// Generates a formula string from findings.
///
/// # Arguments
/// * `findings` - Iterator of finding inputs
///
/// # Returns
/// A formula string like "O₇(AlCXe)H₂(FDb)" - top-level categories with counts,
/// with subcategories in parentheses sorted by severity.
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
        if parts.is_empty() {
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

        // Update category count and max severity
        group.count += 1;
        if finding.severity > group.max_severity {
            group.max_severity = finding.severity;
        }

        // Find subcategory element (skip top-level, try from most specific to least)
        for i in (1..parts.len()).rev() {
            if let Some(element) = category_to_element(parts[i]) {
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
                entry.count += 1;
                if finding.severity > entry.max_severity {
                    entry.max_severity = finding.severity;
                }
                break;
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
        if group.count == 0 {
            continue;
        }

        // Add top-level symbol with count
        formula.push_str(symbol);
        if group.count > 1 {
            formula.push_str(&to_subscript(group.count));
        }

        // Add subcategories in parentheses if any
        if !group.subcategories.is_empty() {
            // Sort subcategories by severity (most severe first), then by count desc
            let mut subs: Vec<_> = group.subcategories.iter().collect();
            subs.sort_by(|a, b| {
                severity_to_priority(a.1.max_severity)
                    .cmp(&severity_to_priority(b.1.max_severity))
                    .then_with(|| b.1.count.cmp(&a.1.count))
            });

            formula.push('(');
            for (sym, ec) in subs {
                formula.push_str(sym);
                if ec.count > 1 {
                    formula.push_str(&to_subscript(ec.count));
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
            Some(crate::elements::LANTHANUM)
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
