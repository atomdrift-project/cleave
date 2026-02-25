//! Internal types for malecule representation.

use crate::elements::Element;
use serde::{Deserialize, Serialize};

/// Severity level for coloring atoms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Neutral - gray
    #[default]
    Neutral,
    /// Notable - white
    Notable,
    /// Suspicious - blue
    Suspicious,
    /// Hostile - red
    Hostile,
}

impl Severity {
    /// Returns the hex color for this severity level.
    #[must_use]
    pub fn color(&self) -> &'static str {
        match self {
            Self::Hostile => "#ff4444",    // Red
            Self::Suspicious => "#4488ff", // Blue
            Self::Notable => "#ffffff",    // White
            Self::Neutral => "#888888",    // Gray
        }
    }

    /// Returns the RGB components (0-255).
    #[must_use]
    pub fn rgb(&self) -> (u8, u8, u8) {
        match self {
            Self::Hostile => (255, 68, 68),
            Self::Suspicious => (68, 136, 255),
            Self::Notable => (255, 255, 255),
            Self::Neutral => (136, 136, 136),
        }
    }
}

/// An atom in the malecule.
#[derive(Debug, Clone)]
pub struct Atom {
    /// Unique ID within the malecule
    pub id: usize,
    /// The periodic table element
    pub element: Element,
    /// Category path this atom represents (e.g., "objectives/lateral-movement")
    pub category: String,
    /// Severity for coloring
    pub severity: Severity,
    /// 3D position
    pub position: (f64, f64, f64),
    /// Count of findings with this category
    pub count: usize,
}

/// A bond between two atoms.
#[derive(Debug, Clone, Copy)]
pub struct Bond {
    /// First atom ID
    pub atom1: usize,
    /// Second atom ID
    pub atom2: usize,
    /// Bond type (1=single, 2=double, 3=triple)
    pub bond_type: u8,
}

/// A complete malecule structure.
#[derive(Debug, Clone)]
pub struct Malecule {
    /// Name/identifier for this malecule
    pub name: String,
    /// All atoms
    pub atoms: Vec<Atom>,
    /// All bonds
    pub bonds: Vec<Bond>,
    /// Formula string (e.g., "C₁O₁La₁Sn₁")
    pub formula: String,
}

impl Malecule {
    /// Creates a new empty malecule.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            atoms: Vec::new(),
            bonds: Vec::new(),
            formula: String::new(),
        }
    }

    /// Adds an atom and returns its ID.
    pub fn add_atom(&mut self, element: Element, category: String, severity: Severity) -> usize {
        let id = self.atoms.len();
        self.atoms.push(Atom {
            id,
            element,
            category,
            severity,
            position: (0.0, 0.0, 0.0),
            count: 1,
        });
        id
    }

    /// Adds a bond between two atoms.
    pub fn add_bond(&mut self, atom1: usize, atom2: usize, bond_type: u8) {
        self.bonds.push(Bond {
            atom1,
            atom2,
            bond_type,
        });
    }

    /// Checks if a bond exists between two atoms.
    #[must_use]
    pub fn has_bond(&self, a: usize, b: usize) -> bool {
        self.bonds
            .iter()
            .any(|bond| (bond.atom1 == a && bond.atom2 == b) || (bond.atom1 == b && bond.atom2 == a))
    }
}

/// Metadata for the JSON sidecar file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaleculeMetadata {
    /// Malecule name
    pub name: String,
    /// Formula string
    pub formula: String,
    /// Atom metadata (colors, categories)
    pub atoms: Vec<AtomMetadata>,
    /// Summary counts
    pub summary: MaleculeSummary,
}

/// Per-atom metadata for the JSON sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomMetadata {
    /// Atom index (matches MOL file atom order)
    pub index: usize,
    /// Element symbol
    pub symbol: String,
    /// Category path
    pub category: String,
    /// Severity level
    pub severity: Severity,
    /// Hex color
    pub color: String,
    /// Finding count for this category
    pub count: usize,
}

/// Summary statistics for the malecule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaleculeSummary {
    /// Total atoms
    pub total_atoms: usize,
    /// Total bonds
    pub total_bonds: usize,
    /// Count by severity
    /// Count of hostile findings.
    pub hostile: usize,
    /// Count of suspicious findings.
    pub suspicious: usize,
    /// Count of notable findings.
    pub notable: usize,
    /// Count of neutral findings.
    pub neutral: usize,
}
