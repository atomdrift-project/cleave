//! Malecule - Molecular visualization of malware analysis findings.
//!
//! Generates MOL files and JSON metadata for visualizing malware behavior
//! as molecular structures in 3D viewers like Three.js or MolView.
//!
//! # Concept
//!
//! Maps malware analysis categories to periodic table elements:
//! - **Objectives** → O (Oxygen) - what the malware tries to achieve
//! - **Micro-behaviors** → B (Boron) - low-level behaviors observed
//! - **Metadata** → Mg (Magnesium) - file metadata characteristics
//!
//! Subcategories become specific elements (e.g., lateral-movement → La, filesystem → F).
//! Bonds connect related categories, with double bonds indicating shared evidence.
//!
//! # Example
//!
//! ```
//! use malecule::{MaleculeBuilder, Finding, Severity, LayoutAlgorithm};
//! use malecule::mol::{generate_mol, generate_metadata_json};
//!
//! let malecule = MaleculeBuilder::new("suspicious_package")
//!     .add_finding(Finding {
//!         id: "objectives/lateral-movement/supply-chain/npm".to_string(),
//!         severity: Severity::Suspicious,
//!         evidence: vec!["npm install -g malware".to_string()],
//!     })
//!     .layout(LayoutAlgorithm::LayeredSpherical)
//!     .build();
//!
//! // Generate MOL file for 3D viewers
//! let mol_content = generate_mol(&malecule);
//!
//! // Generate JSON with colors and metadata
//! let json_content = generate_metadata_json(&malecule).unwrap();
//!
//! // Get formula for terminal output
//! println!("Formula: {}", malecule.formula);
//! ```

#![warn(missing_docs)]

pub mod builder;
pub mod elements;
pub mod formula;
pub mod layout;
pub mod mol;
pub mod types;

// Re-exports for convenient API
pub use builder::{Finding, MaleculeBuilder};
pub use formula::{generate_formula, FindingInput};
pub use layout::LayoutAlgorithm;
pub use types::{Malecule, Severity};
