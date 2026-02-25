//! Formula string generation from findings.
//!
//! Generates molecular formula strings like "C₁O₁La₁Sn₁F₂" from analysis findings.

use crate::elements::{category_to_element, Element, BORON, MAGNESIUM, OXYGEN, THORIUM, TUNGSTEN};
use crate::types::Severity;
use rustc_hash::FxHashMap;
use std::cmp::Reverse;

/// A parsed finding for formula generation.
#[derive(Debug, Clone)]
pub struct FindingInput {
    /// Finding ID path (e.g., "objectives/lateral-movement/supply-chain/npm")
    pub id: String,
    /// Severity level
    pub severity: Severity,
}

/// Counts of elements with their max severity.
#[derive(Debug, Default)]
struct ElementCount {
    count: usize,
    max_severity: Severity,
}

/// Generates a formula string from findings.
///
/// # Arguments
/// * `findings` - Iterator of finding inputs
///
/// # Returns
/// A formula string like "C₁O₁La₁Sn₁F₂Mg₁Au₂"
#[must_use]
pub fn generate_formula<'a>(findings: impl Iterator<Item = &'a FindingInput>) -> String {
    let mut element_counts: FxHashMap<&'static str, ElementCount> = FxHashMap::default();

    // Track which top-level categories are present
    let mut has_objectives = false;
    let mut has_micro_behaviors = false;
    let mut has_metadata = false;
    let mut has_well_known = false;
    let mut third_party_count = 0usize;

    for finding in findings {
        let parts: Vec<&str> = finding.id.split('/').collect();
        if parts.is_empty() {
            continue;
        }

        // Track top-level category
        match parts[0] {
            "objectives" => has_objectives = true,
            "micro-behaviors" => has_micro_behaviors = true,
            "metadata" => has_metadata = true,
            "well-known" => has_well_known = true,
            "third_party" => {
                // Third party just counts, no sub-elements
                third_party_count += 1;
                continue;
            }
            _ => {}
        }

        // Get the most specific category that maps to an element
        // Try from most specific to least specific
        for i in (1..parts.len()).rev() {
            if let Some(element) = category_to_element(parts[i]) {
                let entry = element_counts.entry(element.symbol).or_default();
                entry.count += 1;
                if finding.severity > entry.max_severity {
                    entry.max_severity = finding.severity;
                }
                break;
            }
        }
    }

    // Build formula with consistent ordering
    let mut formula_parts: Vec<(&'static str, usize, u8)> = Vec::new();

    // Add top-level category atoms in order: O, B, Mg, W, Th
    if has_objectives {
        formula_parts.push((OXYGEN.symbol, 1, 0));
    }
    if has_micro_behaviors {
        formula_parts.push((BORON.symbol, 1, 1));
    }
    if has_metadata {
        formula_parts.push((MAGNESIUM.symbol, 1, 2));
    }
    if has_well_known {
        formula_parts.push((TUNGSTEN.symbol, 1, 3));
    }
    if third_party_count > 0 {
        formula_parts.push((THORIUM.symbol, third_party_count, 4));
    }

    // Sort remaining elements by count (descending), then alphabetically
    let mut sorted: Vec<_> = element_counts.into_iter().collect();
    sorted.sort_by_key(|(sym, ec)| (Reverse(ec.count), *sym));

    for (symbol, ec) in sorted {
        // Skip top-level elements we already added
        if symbol == OXYGEN.symbol
            || symbol == BORON.symbol
            || symbol == MAGNESIUM.symbol
            || symbol == TUNGSTEN.symbol
            || symbol == THORIUM.symbol
        {
            continue;
        }
        formula_parts.push((symbol, ec.count, 10)); // 10 = subcategory priority
    }

    // Build the formula string
    let mut formula = String::with_capacity(formula_parts.len() * 4);
    for (symbol, count, _) in formula_parts {
        formula.push_str(symbol);
        if count > 1 {
            formula.push_str(&to_subscript(count));
        }
    }

    formula
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
        let findings = vec![
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
        // Should have O (objectives), B (micro-behaviors), Mg (metadata)
        // Plus La (lateral-movement), Xe (execution), F (fs), Au₂ (quality x2)
        assert!(formula.starts_with('O')); // Objectives is first top-level
        assert!(formula.contains('B'));
        assert!(formula.contains("Mg"));
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
            Some(crate::elements::BORON)
        );
    }
}
