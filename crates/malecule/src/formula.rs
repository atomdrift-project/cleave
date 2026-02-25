//! Formula string generation from findings.
//!
//! Generates molecular formula strings like "O₇C₂As₂DyXePH₂CoDb" from analysis findings.
//! Format: TopLevel^count followed by subcategories sorted by severity then count.

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

/// Generates a formula string from findings.
///
/// # Arguments
/// * `findings` - Iterator of finding inputs
///
/// # Returns
/// A formula string like "O₇C₂As₂DyXePH₂CoDb" - top-level categories with counts,
/// followed by subcategories sorted by severity (suspicious first) then count.
#[must_use]
pub fn generate_formula<'a>(findings: impl Iterator<Item = &'a FindingInput>) -> String {
    let mut element_counts: FxHashMap<&'static str, ElementCount> = FxHashMap::default();

    // Track top-level category counts and max severity
    let mut objectives_count = 0usize;
    let mut objectives_max_sev = Severity::Neutral;
    let mut micro_count = 0usize;
    let mut micro_max_sev = Severity::Neutral;
    let mut metadata_count = 0usize;
    let mut metadata_max_sev = Severity::Neutral;
    let mut well_known_count = 0usize;
    let mut well_known_max_sev = Severity::Neutral;
    let mut third_party_count = 0usize;
    let mut third_party_max_sev = Severity::Neutral;

    for finding in findings {
        let parts: Vec<&str> = finding.id.split('/').collect();
        if parts.is_empty() {
            continue;
        }

        // Track top-level category counts
        match parts[0] {
            "objectives" => {
                objectives_count += 1;
                if finding.severity > objectives_max_sev {
                    objectives_max_sev = finding.severity;
                }
            }
            "micro-behaviors" => {
                micro_count += 1;
                if finding.severity > micro_max_sev {
                    micro_max_sev = finding.severity;
                }
            }
            "metadata" => {
                metadata_count += 1;
                if finding.severity > metadata_max_sev {
                    metadata_max_sev = finding.severity;
                }
            }
            "well-known" => {
                well_known_count += 1;
                if finding.severity > well_known_max_sev {
                    well_known_max_sev = finding.severity;
                }
            }
            "third_party" => {
                third_party_count += 1;
                if finding.severity > third_party_max_sev {
                    third_party_max_sev = finding.severity;
                }
                continue; // Third party doesn't have sub-elements
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

    // Build formula parts: (symbol, count, severity_priority, is_top_level)
    // severity_priority: 0=hostile, 1=suspicious, 2=notable, 3=neutral
    let mut formula_parts: Vec<(&'static str, usize, u8, bool)> = Vec::new();

    // Add top-level categories with their counts
    if objectives_count > 0 {
        formula_parts.push((
            OXYGEN.symbol,
            objectives_count,
            severity_to_priority(objectives_max_sev),
            true,
        ));
    }
    if micro_count > 0 {
        formula_parts.push((
            HYDROGEN_MICRO.symbol,
            micro_count,
            severity_to_priority(micro_max_sev),
            true,
        ));
    }
    if metadata_count > 0 {
        formula_parts.push((
            MENDELEVIUM.symbol,
            metadata_count,
            severity_to_priority(metadata_max_sev),
            true,
        ));
    }
    if well_known_count > 0 {
        formula_parts.push((
            POTASSIUM.symbol,
            well_known_count,
            severity_to_priority(well_known_max_sev),
            true,
        ));
    }
    if third_party_count > 0 {
        formula_parts.push((
            THORIUM.symbol,
            third_party_count,
            severity_to_priority(third_party_max_sev),
            true,
        ));
    }

    // Add subcategory elements
    for (symbol, ec) in &element_counts {
        // Skip top-level elements
        if *symbol == OXYGEN.symbol
            || *symbol == HYDROGEN_MICRO.symbol
            || *symbol == MENDELEVIUM.symbol
            || *symbol == POTASSIUM.symbol
            || *symbol == THORIUM.symbol
        {
            continue;
        }
        formula_parts.push((
            symbol,
            ec.count,
            severity_to_priority(ec.max_severity),
            false,
        ));
    }

    // Sort: top-level first (by severity), then subcategories (by severity, then count desc)
    formula_parts.sort_by(|a, b| {
        // Top-level categories come first, sorted by severity
        match (a.3, b.3) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                // Same level: sort by severity (lower priority = more severe), then count desc
                a.2.cmp(&b.2).then_with(|| b.1.cmp(&a.1))
            }
        }
    });

    // Build the formula string
    let mut formula = String::with_capacity(formula_parts.len() * 4);
    for (symbol, count, _, _) in formula_parts {
        formula.push_str(symbol);
        if count > 1 {
            formula.push_str(&to_subscript(count));
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
        // Should have O₂ (2 objectives), H (1 micro-behavior), Mg₂ (2 metadata)
        // Plus La, Xe, F, Au₂ subcategories
        assert!(formula.contains('O')); // Objectives
        assert!(formula.contains('H')); // Micro-behaviors (now H not B)
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
