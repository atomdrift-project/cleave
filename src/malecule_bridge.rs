//! Bridge between cleave analysis types and malecule visualization.
//!
//! Converts cleave findings to malecule format for molecular visualization.

use crate::types::{Criticality, FileAnalysis, Finding};
use malecule::{FindingInput, LayoutAlgorithm, Malecule, MaleculeBuilder, Severity};

/// Convert cleave Criticality to malecule Severity.
#[must_use]
pub fn criticality_to_severity(crit: Criticality) -> Severity {
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

/// Generate a malecule formula string from a FileAnalysis.
#[allow(dead_code)] // Used by binary target
#[must_use]
pub fn formula_from_file_analysis(file: &FileAnalysis) -> String {
    formula_from_findings(&file.findings)
}

/// Build a complete Malecule from a FileAnalysis.
#[allow(dead_code)] // Used by binary target
#[must_use]
pub fn malecule_from_file_analysis(file: &FileAnalysis, layout: LayoutAlgorithm) -> Malecule {
    let name = file
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&file.path)
        .to_string();

    let mut builder = MaleculeBuilder::new(name);
    builder.layout(layout);

    for finding in &file.findings {
        let evidence: Vec<String> = finding.evidence.iter().map(|e| e.value.clone()).collect();

        builder.add_finding(malecule::Finding {
            id: finding.id.clone(),
            description: Some(finding.desc.clone()),
            severity: criticality_to_severity(finding.crit),
            evidence,
            trait_refs: finding.trait_refs.clone(),
        });
    }

    builder.build()
}

/// Generate MOL file content from a FileAnalysis.
#[allow(dead_code)] // Used by binary target
#[must_use]
pub fn mol_from_file_analysis(file: &FileAnalysis, layout: LayoutAlgorithm) -> String {
    let malecule = malecule_from_file_analysis(file, layout);
    malecule::mol::generate_mol(&malecule)
}

/// Generate metadata JSON from a FileAnalysis.
#[allow(dead_code)] // Used by binary target
pub fn metadata_json_from_file_analysis(
    file: &FileAnalysis,
    layout: LayoutAlgorithm,
) -> Result<String, serde_json::Error> {
    let malecule = malecule_from_file_analysis(file, layout);
    malecule::mol::generate_metadata_json(&malecule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Evidence, FindingKind};

    fn test_finding(id: &str, crit: Criticality) -> Finding {
        Finding {
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
            }],
            match_count: 1,
            source_file: None,
        }
    }

    #[test]
    fn test_criticality_conversion() {
        assert_eq!(
            criticality_to_severity(Criticality::Hostile),
            Severity::Hostile
        );
        assert_eq!(
            criticality_to_severity(Criticality::Suspicious),
            Severity::Suspicious
        );
        assert_eq!(
            criticality_to_severity(Criticality::Notable),
            Severity::Notable
        );
        assert_eq!(
            criticality_to_severity(Criticality::Baseline),
            Severity::Neutral
        );
    }

    #[test]
    fn test_formula_generation() {
        let findings = vec![
            test_finding("objectives/lateral-movement/supply-chain", Criticality::Suspicious),
            test_finding("micro-behaviors/fs/file", Criticality::Notable),
        ];

        let formula = formula_from_findings(&findings);
        assert!(formula.contains('C')); // Central
        assert!(formula.contains('O')); // Objectives
        assert!(formula.contains('B')); // Micro-behaviors
    }

    #[test]
    fn test_malecule_building() {
        let findings = vec![test_finding(
            "objectives/lateral-movement",
            Criticality::Suspicious,
        )];

        let mut file = FileAnalysis::new(
            0,
            "/test/sample.bin".to_string(),
            "ELF".to_string(),
            "abc123".to_string(),
            1024,
        );
        file.findings = findings;

        let malecule = malecule_from_file_analysis(&file, LayoutAlgorithm::LayeredSpherical);

        assert!(!malecule.atoms.is_empty());
        assert!(!malecule.formula.is_empty());
    }
}
