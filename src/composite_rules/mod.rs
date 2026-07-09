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
pub(crate) mod regex_scratch;
pub(crate) mod regex_store;
pub(crate) mod section_map;
pub(crate) mod traits;
pub mod types;

// Re-export public API
#[allow(unused_imports)]
pub use condition::StringValidator;
pub(crate) use condition::{
    CommentQuery, Condition, EncodedQuery, HexQuery, KvQuery, LiteralQuery, MetricsQuery,
    PathQuery, RawQuery, SectionQuery, SymbolQuery, TextQuery, TreeSitterQuery,
};
pub(crate) use context::EvaluationContext;
pub(crate) use section_map::SectionMap;
pub(crate) use traits::{CompositeTrait, DowngradeConditions, Scope, TraitDefinition};

#[allow(unused_imports)]
pub(crate) use types::Arch;
pub(crate) use types::FileType;
pub use types::Platform;
pub use types::platforms_intersect;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod not_validation_tests;

#[cfg(test)]
mod description_validation_tests;

#[cfg(test)]
mod python_aes_import_test;

#[cfg(test)]
mod proximity_scripting_symbols_test;

#[cfg(test)]
mod traits_test;
