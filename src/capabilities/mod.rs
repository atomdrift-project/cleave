//! Capability mapping and trait evaluation system.
//!
//! This module provides the infrastructure for mapping binary/script features to
//! security capabilities and behaviors. It consists of:
//!
//! - **Indexes**: Performance optimization structures for fast trait lookup
//! - **Models**: YAML parsing structures and data models
//! - **Parsing**: Default application and type parsing
//! - **Validation**: Rule validation and precision analysis
//! - **Mapper**: Core CapabilityMapper implementation
//!
//! ## Architecture
//!
//! The capability system works in layers:
//!
//! 1. **Symbol Mapping**: Direct symbol name → capability ID lookups
//! 2. **Trait Definitions**: Pattern-based atomic trait detection (strings, YARA, AST)
//! 3. **Composite Rules**: Combine traits using boolean logic to detect behaviors
//!
//! ## Public API
//!
//! The main entry point is `CapabilityMapper`:
//! - `CapabilityMapper::new()` - Load from traits/ directory or capabilities.yaml
//! - `mapper.evaluate_traits()` - Evaluate atomic traits against a report
//! - `mapper.evaluate_composite_rules()` - Evaluate composite rules
//! - `mapper.lookup()` - Look up symbol by name

mod error_formatting;
mod indexes;
mod mapper;
mod models;
mod parsing;
pub(crate) mod validation;

// Re-export public API (allow unreachable_pub: accessible via lib crate)
#[allow(unreachable_pub)]
pub use mapper::CapabilityMapper;

// Test module needs access to internal types
#[cfg(test)]
mod tests;

#[cfg(test)]
mod mapper_test;

#[cfg(test)]
mod filter_low_value_any_test;
