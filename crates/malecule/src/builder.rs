//! Malecule builder - constructs malecules from analysis findings.

use crate::elements::{category_to_element, BORON, CARBON, MAGNESIUM, OXYGEN, THORIUM, TUNGSTEN};
use crate::formula::{generate_formula, FindingInput};
use crate::layout::{apply_layout, LayoutAlgorithm};
use crate::types::{Malecule, Severity};
use rustc_hash::FxHashMap;

/// Input finding for the builder.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Finding ID path (e.g., "objectives/lateral-movement/supply-chain/npm")
    pub id: String,
    /// Trait description (human-readable)
    pub description: Option<String>,
    /// Severity level
    pub severity: Severity,
    /// Evidence values (for overlap detection and display)
    pub evidence: Vec<String>,
    /// Trait IDs that this finding depends on (for composite findings)
    pub trait_refs: Vec<String>,
}

/// A node in the category tree.
#[derive(Debug, Default)]
struct CategoryNode {
    /// Full path to this node (e.g., "objectives/lateral-movement")
    path: String,
    /// Maximum severity of any finding in this subtree
    max_severity: Severity,
    /// All evidence from findings in this subtree (for bond detection)
    all_evidence: Vec<String>,
    /// Best finding at this exact level (if any)
    best_finding: Option<Finding>,
    /// Child category names
    children: Vec<String>,
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

        // Filter findings: keep notable+ traits, and neutral traits only if referenced by notable+
        let filtered_findings = self.filter_findings();

        // Build category tree from findings
        let tree = self.build_category_tree(&filtered_findings);

        // Generate formula from leaf nodes (deepest subdirectories)
        let formula_inputs: Vec<FindingInput> = tree
            .values()
            .filter(|node| node.children.is_empty()) // Only leaf nodes
            .filter_map(|node| {
                node.best_finding.as_ref().map(|f| FindingInput {
                    id: f.id.clone(),
                    severity: f.severity,
                })
            })
            .collect();
        malecule.formula = generate_formula(formula_inputs.iter());

        // Track atom IDs by path
        let mut path_to_atom: FxHashMap<String, usize> = FxHashMap::default();

        // Create atoms for top-level categories
        let top_levels = ["objectives", "micro-behaviors", "metadata", "well-known", "third_party"];
        let mut top_atom_ids: Vec<usize> = Vec::new();

        for top in top_levels {
            if let Some(node) = tree.get(top) {
                let element = match top {
                    "objectives" => OXYGEN,
                    "micro-behaviors" => BORON,
                    "metadata" => MAGNESIUM,
                    "well-known" => TUNGSTEN,
                    "third_party" => THORIUM,
                    _ => CARBON,
                };

                // Top-level hub atoms are always neutral (grey) - they're connectors, not findings
                let atom_id = malecule.add_atom(element, top.to_string(), Severity::Neutral);
                path_to_atom.insert(top.to_string(), atom_id);
                top_atom_ids.push(atom_id);

                // Recursively create child atoms
                self.create_child_atoms(
                    &mut malecule,
                    &tree,
                    &mut path_to_atom,
                    node,
                    atom_id,
                );
            }
        }

        // Bond top-level categories to each other
        for i in 0..top_atom_ids.len() {
            for j in (i + 1)..top_atom_ids.len() {
                malecule.add_bond(top_atom_ids[i], top_atom_ids[j], 1);
            }
        }

        // Add evidence bonds between leaf nodes that share evidence
        self.add_evidence_bonds(&mut malecule, &tree, &path_to_atom);

        // Apply layout
        apply_layout(&mut malecule, self.layout);

        malecule
    }

    /// Recursively creates child atoms for a category node.
    /// Collapses single-child intermediate nodes - only creates atoms for:
    /// - Leaf nodes (no children)
    /// - Branching nodes (2+ children) as grey connectors
    fn create_child_atoms(
        &self,
        malecule: &mut Malecule,
        tree: &FxHashMap<String, CategoryNode>,
        path_to_atom: &mut FxHashMap<String, usize>,
        parent_node: &CategoryNode,
        parent_atom_id: usize,
    ) {
        for child_name in &parent_node.children {
            let child_path = if parent_node.path.is_empty() {
                child_name.clone()
            } else {
                format!("{}/{}", parent_node.path, child_name)
            };

            if let Some(child_node) = tree.get(&child_path) {
                let is_leaf = child_node.children.is_empty();
                let is_branching = child_node.children.len() >= 2;

                if is_leaf {
                    // Leaf node - create atom with finding details
                    let element = self.find_element_for_path(&child_path);
                    let atom_id = malecule.add_trait_atom(
                        element,
                        child_path.clone(),
                        child_node.max_severity,
                        child_path.clone(),
                        child_node.best_finding.as_ref().and_then(|f| f.description.clone()),
                        child_node.all_evidence.clone(),
                    );
                    path_to_atom.insert(child_path.clone(), atom_id);
                    malecule.add_bond(parent_atom_id, atom_id, 1);
                } else if is_branching {
                    // Branching node (2+ children) - create grey connector atom
                    let element = self.find_element_for_path(&child_path);
                    let atom_id = malecule.add_atom(element, child_path.clone(), Severity::Neutral);
                    path_to_atom.insert(child_path.clone(), atom_id);
                    malecule.add_bond(parent_atom_id, atom_id, 1);
                    // Recurse with this as the new parent
                    self.create_child_atoms(malecule, tree, path_to_atom, child_node, atom_id);
                } else {
                    // Single-child intermediate - skip this node, connect child directly to parent
                    self.create_child_atoms(malecule, tree, path_to_atom, child_node, parent_atom_id);
                }
            }
        }
    }

    /// Finds the element for a category path.
    fn find_element_for_path(&self, path: &str) -> crate::elements::Element {
        let parts: Vec<&str> = path.split('/').collect();

        // Third party always uses THORIUM
        if parts.first() == Some(&"third_party") {
            return THORIUM;
        }

        // Try to find mapped element from most specific to least
        for i in (0..parts.len()).rev() {
            if let Some(element) = category_to_element(parts[i]) {
                return element;
            }
        }

        // Fallback to top-level element
        match parts.first() {
            Some(&"objectives") => OXYGEN,
            Some(&"micro-behaviors") => BORON,
            Some(&"metadata") => MAGNESIUM,
            Some(&"well-known") => TUNGSTEN,
            _ => CARBON,
        }
    }

    /// Builds a tree of categories from findings.
    /// Each node tracks the max severity and all evidence in its subtree.
    /// Tree depth is limited to 3 levels: top-level -> second -> third (leaf).
    fn build_category_tree<'a>(&self, findings: &[&'a Finding]) -> FxHashMap<String, CategoryNode> {
        let mut tree: FxHashMap<String, CategoryNode> = FxHashMap::default();

        // Maximum depth: top-level (1) -> second (2) -> third/leaf (3)
        const MAX_DEPTH: usize = 3;

        for &finding in findings {
            let parts: Vec<&str> = finding.id.split('/').collect();
            if parts.is_empty() {
                continue;
            }

            // Determine actual depth (capped at MAX_DEPTH)
            let depth = parts.len().min(MAX_DEPTH);

            for i in 1..=depth {
                let path = parts[..i].join("/");
                let parent_path = if i > 1 { parts[..i - 1].join("/") } else { String::new() };
                let name = parts[i - 1].to_string();

                // Update or create the node
                let node = tree.entry(path.clone()).or_insert_with(|| CategoryNode {
                    path: path.clone(),
                    ..Default::default()
                });

                // Update max severity
                if finding.severity > node.max_severity {
                    node.max_severity = finding.severity;
                }

                // Propagate evidence to this node and all ancestors
                node.all_evidence.extend(finding.evidence.clone());

                // Track best finding at leaf level (depth == MAX_DEPTH or actual leaf)
                if i == depth {
                    if node.best_finding.is_none() || finding.severity > node.best_finding.as_ref().unwrap().severity {
                        node.best_finding = Some(finding.clone());
                    }
                }

                // Add this node as child of parent
                if !parent_path.is_empty() {
                    let parent = tree.entry(parent_path.clone()).or_insert_with(|| CategoryNode {
                        path: parent_path,
                        ..Default::default()
                    });
                    if !parent.children.contains(&name) {
                        parent.children.push(name);
                    }
                }
            }
        }

        tree
    }

    /// Adds bonds between leaf nodes that share evidence (exact or substring match).
    fn add_evidence_bonds(
        &self,
        malecule: &mut Malecule,
        tree: &FxHashMap<String, CategoryNode>,
        path_to_atom: &FxHashMap<String, usize>,
    ) {
        // Collect leaf nodes with their evidence
        let leaves: Vec<_> = tree
            .values()
            .filter(|n| n.children.is_empty())
            .filter_map(|n| path_to_atom.get(&n.path).map(|&id| (id, &n.all_evidence)))
            .collect();

        // Exact match via hash map
        let mut evidence_atoms: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
        for &(atom_id, evidence) in &leaves {
            for ev in evidence {
                evidence_atoms.entry(ev.as_str()).or_default().push(atom_id);
            }
        }

        for atoms in evidence_atoms.values() {
            if atoms.len() < 2 {
                continue;
            }
            for i in 0..atoms.len() {
                for j in (i + 1)..atoms.len() {
                    if !malecule.has_bond(atoms[i], atoms[j]) {
                        malecule.add_bond(atoms[i], atoms[j], 2);
                    }
                }
            }
        }

        // Substring matches
        for i in 0..leaves.len() {
            for j in (i + 1)..leaves.len() {
                let (atom_a, ev_a) = leaves[i];
                let (atom_b, ev_b) = leaves[j];

                if malecule.has_bond(atom_a, atom_b) {
                    continue;
                }

                let has_overlap = ev_a.iter().any(|a| {
                    ev_b.iter().any(|b| {
                        let a = a.trim();
                        let b = b.trim();
                        a.len() >= 4 && b.len() >= 4 && (a.contains(b) || b.contains(a))
                    })
                });

                if has_overlap {
                    malecule.add_bond(atom_a, atom_b, 2);
                }
            }
        }
    }

    /// Filters findings to remove neutral traits unless referenced by notable+ traits.
    ///
    /// Returns references to findings that should be included in the malecule:
    /// - All findings with severity >= Notable
    /// - Neutral findings only if they are referenced by a notable+ finding's trait_refs
    fn filter_findings(&self) -> Vec<&Finding> {
        use rustc_hash::FxHashSet;

        // Collect all trait IDs referenced by notable+ findings
        let mut referenced_ids: FxHashSet<&str> = FxHashSet::default();
        for finding in &self.findings {
            if finding.severity >= Severity::Notable {
                for trait_ref in &finding.trait_refs {
                    referenced_ids.insert(trait_ref.as_str());
                }
            }
        }

        // Filter findings
        self.findings
            .iter()
            .filter(|f| {
                // Keep if notable+
                if f.severity >= Severity::Notable {
                    return true;
                }
                // Keep neutral if referenced by a notable+ finding
                referenced_ids.contains(f.id.as_str())
            })
            .collect()
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
                description: Some("Supply chain attack via npm".to_string()),
                severity: Severity::Suspicious,
                evidence: vec!["npm install".to_string()],
                trait_refs: vec![],
            })
            .add_finding(Finding {
                id: "micro-behaviors/fs/file".to_string(),
                description: Some("File system access".to_string()),
                severity: Severity::Notable,
                evidence: vec!["unlink".to_string()],
                trait_refs: vec![],
            })
            .build();

        // Hierarchical structure with single-child collapse:
        // O (objectives) -> supply-chain (leaf, skipping lateral-movement)
        // B (micro-behaviors) -> file (leaf, skipping fs)
        // O and B are bonded to each other
        // Total: 2 + 2 = 4 atoms
        assert_eq!(malecule.atoms.len(), 4);

        // Check bonds (includes O-B bond + hierarchical bonds)
        assert!(!malecule.bonds.is_empty());
    }

    #[test]
    fn test_builder_evidence_bonds() {
        let malecule = MaleculeBuilder::new("overlap")
            .add_finding(Finding {
                id: "objectives/lateral-movement/supply-chain".to_string(),
                description: None,
                severity: Severity::Suspicious,
                evidence: vec!["shared_evidence".to_string()],
                trait_refs: vec![],
            })
            .add_finding(Finding {
                id: "objectives/execution/interpreter".to_string(),
                description: None,
                severity: Severity::Notable,
                evidence: vec!["shared_evidence".to_string()],
                trait_refs: vec![],
            })
            .build();

        // Should have a double bond between the two trait atoms (shared evidence)
        let double_bonds: Vec<_> = malecule.bonds.iter().filter(|b| b.bond_type == 2).collect();
        assert!(!double_bonds.is_empty(), "Should have evidence overlap bonds");
    }

    #[test]
    fn test_formula_generation() {
        let malecule = MaleculeBuilder::new("formula_test")
            .add_finding(Finding {
                id: "objectives/lateral-movement".to_string(),
                description: Some("Lateral movement".to_string()),
                severity: Severity::Suspicious,
                evidence: vec![],
                trait_refs: vec![],
            })
            .build();

        assert!(!malecule.formula.is_empty());
        assert!(malecule.formula.contains('O')); // Objectives
        assert!(malecule.formula.contains("La")); // Lateral-movement
    }

    #[test]
    fn test_trait_details_preserved() {
        let malecule = MaleculeBuilder::new("details")
            .add_finding(Finding {
                id: "objectives/lateral-movement/supply-chain/npm/install-hooks".to_string(),
                description: Some("NPM install hooks allow code execution".to_string()),
                severity: Severity::Hostile,
                evidence: vec!["postinstall script".to_string(), "preinstall script".to_string()],
                trait_refs: vec![],
            })
            .build();

        // With max depth 3, the leaf is at "objectives/lateral-movement/supply-chain"
        // Find the leaf atom (the one with evidence, not intermediate nodes)
        let leaf_atom = malecule.atoms.iter().find(|a| !a.evidence.is_empty()).unwrap();
        assert_eq!(leaf_atom.trait_id.as_deref(), Some("objectives/lateral-movement/supply-chain"));
        assert_eq!(leaf_atom.description.as_deref(), Some("NPM install hooks allow code execution"));
        assert_eq!(leaf_atom.evidence.len(), 2);
    }

    #[test]
    fn test_neutral_traits_filtered() {
        // Neutral trait without being referenced should be filtered out
        let malecule = MaleculeBuilder::new("filter_test")
            .add_finding(Finding {
                id: "objectives/lateral-movement/supply-chain/npm".to_string(),
                description: Some("Lateral movement".to_string()),
                severity: Severity::Suspicious,
                evidence: vec![],
                trait_refs: vec![],
            })
            .add_finding(Finding {
                id: "metadata/format/pe".to_string(),
                description: Some("PE format".to_string()),
                severity: Severity::Neutral,
                evidence: vec![],
                trait_refs: vec![],
            })
            .build();

        // Neutral trait should be filtered out (not referenced)
        // With max depth 3, "objectives/lateral-movement/supply-chain" is the leaf
        // Only O -> lateral-movement -> supply-chain hierarchy should exist
        let leaf_atoms: Vec<_> = malecule.atoms.iter()
            .filter(|a| a.trait_id.as_deref() == Some("objectives/lateral-movement/supply-chain"))
            .collect();
        assert_eq!(leaf_atoms.len(), 1, "Should have one leaf for the notable+ trait");
    }

    #[test]
    fn test_neutral_traits_kept_when_referenced() {
        // Neutral trait that IS referenced should be kept
        let malecule = MaleculeBuilder::new("ref_test")
            .add_finding(Finding {
                id: "objectives/lateral-movement/composite".to_string(),
                description: Some("Composite lateral movement".to_string()),
                severity: Severity::Suspicious,
                evidence: vec![],
                // This composite references the neutral trait
                trait_refs: vec!["metadata/format/pe".to_string()],
            })
            .add_finding(Finding {
                id: "metadata/format/pe".to_string(),
                description: Some("PE format".to_string()),
                severity: Severity::Neutral,
                evidence: vec![],
                trait_refs: vec![],
            })
            .build();

        // Both trait hierarchies should be present (neutral is referenced)
        // objectives/lateral-movement/composite -> creates: objectives, objectives/lateral-movement, objectives/lateral-movement/composite
        // metadata/format/pe -> creates: metadata, metadata/format, metadata/format/pe
        // Check that both leaf subdirectories exist
        let has_objectives_leaf = malecule.atoms.iter()
            .any(|a| a.trait_id.as_deref() == Some("objectives/lateral-movement/composite"));
        let has_metadata_leaf = malecule.atoms.iter()
            .any(|a| a.trait_id.as_deref() == Some("metadata/format/pe"));
        assert!(has_objectives_leaf, "objectives leaf should exist");
        assert!(has_metadata_leaf, "metadata leaf should exist (referenced neutral)");
    }
}
