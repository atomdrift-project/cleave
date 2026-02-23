//! Composite rules module for trait-based detection.
//!
//! This module provides the infrastructure for defining and evaluating
//! composite detection rules using a YAML-based DSL.
//!
//! ## Module Structure
//!
//! - `types`: Core enums (Platform, FileType)
//! - `condition`: Condition enum for detection logic
//! - `context`: Evaluation context and result types
//! - `evaluators`: Condition evaluation functions
//! - `traits`: TraitDefinition and CompositeTrait structs
//! - `ast_kinds`: Abstract AST kind to tree-sitter node type mapping

pub(crate) mod ast_kinds;
pub(crate) mod condition;
pub(crate) mod context;
pub(crate) mod debug;
pub(crate) mod evaluators;
pub(crate) mod section_map;
pub(crate) mod traits;
pub(crate) mod types;

// Re-export public API
pub(crate) use condition::Condition;
pub(crate) use context::EvaluationContext;
pub(crate) use section_map::SectionMap;
pub(crate) use traits::{
    CompositeTrait, ConditionWithFilters, DowngradeConditions, TraitDefinition,
};
pub(crate) use types::{FileType, Platform};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod not_validation_tests;

#[cfg(test)]
mod description_validation_tests;

#[cfg(test)]
mod python_aes_import_test;
