//! Bridge between cleave analysis types and malecule formula generation.

use crate::types::{Criticality, Finding};
use malecule::{FindingInput, Severity};

/// Convert cleave Criticality to malecule Severity.
fn criticality_to_severity(crit: Criticality) -> Severity {
    match crit {
        Criticality::Hostile => Severity::Hostile,
        Criticality::Suspicious => Severity::Suspicious,
        Criticality::Notable => Severity::Notable,
        Criticality::Baseline | Criticality::Component | Criticality::Filtered => Severity::Neutral,
    }
}

/// Generate a malecule formula string from findings.
#[allow(dead_code)] // Used by binary target
#[must_use]
pub fn formula_from_findings(findings: &[Finding]) -> String {
    let inputs: Vec<FindingInput> = findings
        .iter()
        .map(|f| FindingInput {
            id: f.id.clone(),
            severity: criticality_to_severity(f.crit),
        })
        .collect();

    malecule::generate_formula(inputs.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Evidence, FindingKind};

    fn test_finding(id: &str, crit: Criticality) -> Finding {
        Finding { src: None,
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: "Test".to_string(),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![Evidence {
                method: "test".to_string(),
                source: "test".to_string(),
                value: "test_value".to_string(),
                location: None,
                ..Default::default()
            }],
            match_count: 1,
            source_file: None,
        }
    }

    #[test]
    fn test_formula_generation() {
        let findings = vec![
            test_finding(
                "objectives/lateral-movement/supply-chain",
                Criticality::Suspicious,
            ),
            test_finding("micro-behaviors/fs/file", Criticality::Notable),
        ];

        let formula = formula_from_findings(&findings);
        assert!(formula.contains('O'), "Expected O (Oxygen) for objectives");
        assert!(
            formula.contains('H'),
            "Expected H (Hydrogen) for micro-behaviors"
        );
    }
}
