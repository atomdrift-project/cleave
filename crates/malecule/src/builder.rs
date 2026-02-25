//! Malecule builder - constructs malecules from analysis findings.

use crate::elements::{category_to_element, BORON, CARBON, MAGNESIUM, OXYGEN, TUNGSTEN};
use crate::formula::{generate_formula, FindingInput};
use crate::layout::{apply_layout, LayoutAlgorithm};
use crate::types::{Malecule, Severity};
use rustc_hash::{FxHashMap, FxHashSet};

/// Input finding for the builder.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Finding ID path (e.g., "objectives/lateral-movement/supply-chain/npm")
    pub id: String,
    /// Severity level
    pub severity: Severity,
    /// Evidence values (for overlap detection)
    pub evidence: Vec<String>,
}

/// Builds a malecule from a list of findings.
#[derive(Debug)]
pub struct MaleculeBuilder {
    name: String,
    findings: Vec<Finding>,
    layout: LayoutAlgorithm,
}

impl MaleculeBuilder {
    /// Creates a new builder with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            findings: Vec::new(),
            layout: LayoutAlgorithm::default(),
        }
    }

    /// Adds a finding.
    pub fn add_finding(&mut self, finding: Finding) -> &mut Self {
        self.findings.push(finding);
        self
    }

    /// Adds multiple findings.
    pub fn add_findings(&mut self, findings: impl IntoIterator<Item = Finding>) -> &mut Self {
        self.findings.extend(findings);
        self
    }

    /// Sets the layout algorithm.
    pub fn layout(&mut self, algorithm: LayoutAlgorithm) -> &mut Self {
        self.layout = algorithm;
        self
    }

    /// Builds the malecule.
    #[must_use]
    pub fn build(&self) -> Malecule {
        let mut malecule = Malecule::new(&self.name);

        if self.findings.is_empty() {
            return malecule;
        }

        // Generate formula first
        let formula_inputs: Vec<FindingInput> = self
            .findings
            .iter()
            .map(|f| FindingInput {
                id: f.id.clone(),
                severity: f.severity,
            })
            .collect();
        malecule.formula = generate_formula(formula_inputs.iter());

        // Track atoms by category for deduplication
        let mut category_atoms: FxHashMap<String, usize> = FxHashMap::default();
        let mut category_severity: FxHashMap<String, Severity> = FxHashMap::default();
        let mut category_count: FxHashMap<String, usize> = FxHashMap::default();

        // Track which top-level categories are present
        let mut has_objectives = false;
        let mut has_micro_behaviors = false;
        let mut has_metadata = false;
        let mut has_well_known = false;

        // First pass: collect all categories
        for finding in &self.findings {
            let parts: Vec<&str> = finding.id.split('/').collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "objectives" => has_objectives = true,
                "micro-behaviors" => has_micro_behaviors = true,
                "metadata" => has_metadata = true,
                "well-known" => has_well_known = true,
                _ => {}
            }

            // Track the most specific mapped category
            for i in (1..parts.len()).rev() {
                if category_to_element(parts[i]).is_some() {
                    let cat_path = parts[..=i].join("/");
                    *category_count.entry(cat_path.clone()).or_default() += 1;

                    let current_sev = category_severity.entry(cat_path).or_insert(Severity::Neutral);
                    if finding.severity > *current_sev {
                        *current_sev = finding.severity;
                    }
                    break;
                }
            }
        }

        // Add central carbon atom
        let central_id = malecule.add_atom(CARBON, String::new(), Severity::Neutral);

        // Add top-level category atoms
        if has_objectives {
            let id = malecule.add_atom(OXYGEN, "objectives".to_string(), Severity::Neutral);
            category_atoms.insert("objectives".to_string(), id);
            malecule.add_bond(central_id, id, 1);
        }
        if has_micro_behaviors {
            let id = malecule.add_atom(BORON, "micro-behaviors".to_string(), Severity::Neutral);
            category_atoms.insert("micro-behaviors".to_string(), id);
            malecule.add_bond(central_id, id, 1);
        }
        if has_metadata {
            let id = malecule.add_atom(MAGNESIUM, "metadata".to_string(), Severity::Neutral);
            category_atoms.insert("metadata".to_string(), id);
            malecule.add_bond(central_id, id, 1);
        }
        if has_well_known {
            let id = malecule.add_atom(TUNGSTEN, "well-known".to_string(), Severity::Neutral);
            category_atoms.insert("well-known".to_string(), id);
            malecule.add_bond(central_id, id, 1);
        }

        // Add subcategory atoms
        for (cat_path, count) in &category_count {
            let parts: Vec<&str> = cat_path.split('/').collect();
            if parts.len() < 2 {
                continue;
            }

            let subcategory = parts[1];
            let Some(element) = category_to_element(subcategory) else {
                continue;
            };

            let severity = category_severity.get(cat_path).copied().unwrap_or(Severity::Neutral);
            let atom_id = malecule.add_atom(element, cat_path.clone(), severity);
            malecule.atoms[atom_id].count = *count;
            category_atoms.insert(cat_path.clone(), atom_id);

            // Bond to parent category
            let top_level = parts[0];
            if let Some(&parent_id) = category_atoms.get(top_level) {
                malecule.add_bond(parent_id, atom_id, 1);
            }
        }

        // Add bonds between subcategories that share evidence
        self.add_evidence_bonds(&mut malecule, &category_atoms);

        // Apply layout
        apply_layout(&mut malecule, self.layout);

        malecule
    }

    /// Adds bonds between atoms whose findings share overlapping evidence.
    fn add_evidence_bonds(&self, malecule: &mut Malecule, category_atoms: &FxHashMap<String, usize>) {
        // Build evidence -> categories map
        let mut evidence_categories: FxHashMap<String, FxHashSet<String>> = FxHashMap::default();

        for finding in &self.findings {
            let parts: Vec<&str> = finding.id.split('/').collect();
            if parts.len() < 2 {
                continue;
            }

            // Find the mapped category path
            let mut cat_path = None;
            for i in (1..parts.len()).rev() {
                if category_to_element(parts[i]).is_some() {
                    cat_path = Some(parts[..=i].join("/"));
                    break;
                }
            }

            let Some(cat) = cat_path else { continue };

            // Track evidence for this category
            for ev in &finding.evidence {
                evidence_categories
                    .entry(ev.clone())
                    .or_default()
                    .insert(cat.clone());
            }
        }

        // Add bonds between categories that share evidence
        for categories in evidence_categories.values() {
            let cats: Vec<_> = categories.iter().collect();
            for i in 0..cats.len() {
                for j in (i + 1)..cats.len() {
                    let Some(&atom_a) = category_atoms.get(cats[i]) else {
                        continue;
                    };
                    let Some(&atom_b) = category_atoms.get(cats[j]) else {
                        continue;
                    };

                    // Don't duplicate bonds
                    if !malecule.has_bond(atom_a, atom_b) {
                        // Use double bond to indicate evidence overlap
                        malecule.add_bond(atom_a, atom_b, 2);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_empty() {
        let malecule = MaleculeBuilder::new("empty").build();
        assert!(malecule.atoms.is_empty());
        assert!(malecule.bonds.is_empty());
    }

    #[test]
    fn test_builder_simple() {
        let malecule = MaleculeBuilder::new("test")
            .add_finding(Finding {
                id: "objectives/lateral-movement/supply-chain/npm".to_string(),
                severity: Severity::Suspicious,
                evidence: vec!["npm install".to_string()],
            })
            .add_finding(Finding {
                id: "micro-behaviors/fs/file".to_string(),
                severity: Severity::Notable,
                evidence: vec!["unlink".to_string()],
            })
            .build();

        // Should have: C (central), O (objectives), B (micro-behaviors), La (lateral-movement), F (fs)
        assert_eq!(malecule.atoms.len(), 5);

        // Check bonds
        assert!(!malecule.bonds.is_empty());
    }

    #[test]
    fn test_builder_evidence_bonds() {
        let malecule = MaleculeBuilder::new("overlap")
            .add_finding(Finding {
                id: "objectives/lateral-movement/supply-chain".to_string(),
                severity: Severity::Suspicious,
                evidence: vec!["shared_evidence".to_string()],
            })
            .add_finding(Finding {
                id: "objectives/execution/interpreter".to_string(),
                severity: Severity::Notable,
                evidence: vec!["shared_evidence".to_string()],
            })
            .build();

        // Should have a double bond between La and Xe (shared evidence)
        let double_bonds: Vec<_> = malecule.bonds.iter().filter(|b| b.bond_type == 2).collect();
        assert!(!double_bonds.is_empty(), "Should have evidence overlap bonds");
    }

    #[test]
    fn test_formula_generation() {
        let malecule = MaleculeBuilder::new("formula_test")
            .add_finding(Finding {
                id: "objectives/lateral-movement".to_string(),
                severity: Severity::Suspicious,
                evidence: vec![],
            })
            .build();

        assert!(!malecule.formula.is_empty());
        assert!(malecule.formula.contains('C')); // Central
        assert!(malecule.formula.contains('O')); // Objectives
        assert!(malecule.formula.contains("La")); // Lateral-movement
    }
}
