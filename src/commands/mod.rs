//! Command implementations for cleave CLI.
//!
//! This module provides the structure and re-exports for cleave's command subsystem.
//! The commands module is organized as follows:
//!
//! - **shared**: Common utilities, types, and functions used across multiple commands.
//!   This includes file path expansion, analysis report generation, rule discovery,
//!   and file format detection.
//!
//! ## Organization Strategy
//!
//! Commands are organized into logical categories that may span multiple submodules:
//!
//! - **Analyze Command**: Single file analysis with comprehensive malware detection
//!   - File type detection via magic bytes
//!   - Format-specific structural analysis (ELF, PE, Mach-O, scripts, archives)
//!   - Parallel YARA loading and capability mapping
//!   - Terminal and JSONL output formats
//!   - Module: `analyze`
//!
//! - **Extract Commands**: Utilities for extracting information from files
//!   - Extract sections, symbols, and metadata from binaries
//!   - Handles multiple binary formats (ELF, Mach-O, PE)
//!   - Module: `extract`
//!
//! - **Test Commands**: Testing functionality
//!   - Test rule sets and analysis pipelines
//!   - Module: `test`
//!
//! - **Diff Commands**: Differential analysis
//!   - Compare analysis results between files
//!   - Module: `diff`
//!
//! ## Shared Module
//!
//! The `shared` module contains critical re-exports that are used by multiple commands:
//!
//! ### Utilities
//! - Path handling: `expand_paths` - Recursively expands file globs and directories
//! - Input handling: `read_paths_from_stdin` - Reads file paths from standard input
//! - File type detection: `cli_file_type_to_internal` - Converts CLI file type to internal type
//!
//! ### Analysis Functions
//! - `process_yara_result` - Processes YARA match results for reporting
//!
//! ### Reporting Functions
//! - `create_analysis_report` - Generates comprehensive analysis reports
//! - `find_similar_rules` - Searches for rules similar to a query string
//! - `find_rules_in_directory` - Discovers rules in a specified directory
//!
//! ### Data Processing
//! - `flatten_json_to_metrics` - Flattens nested JSON to flat metric structure
//! - `extract_strings_from_ast` - Extracts string literals from syntax trees
//!
//! ## Data Types
//!
//! The shared module re-exports key data types used in command output and processing:
//!
//! - `SectionInfo` - Metadata about binary sections (address, size, entropy, permissions)
//! - `SymbolInfo` - Information about symbols in binaries (name, address, library, type)

pub mod analyze;
pub mod diff;
pub mod extract;
pub mod iter_files;
pub mod shared;
pub mod test;
pub mod validate;

// Re-export shared utilities needed by main.rs
pub use shared::expand_paths;

// Re-export command functions for main.rs
pub use analyze::{run as analyze_command, AnalyzeConfig};
pub use diff::run as diff_command;
pub use iter_files::{run as iter_files_command, IterFilesConfig};
pub use extract::{
    metrics::run as extract_metrics_command, sections::run as extract_sections_command,
    strings::run as extract_strings_command, symbols::run as extract_symbols_command,
};
pub use test::{test_match, test_rules};
pub use validate::run as validate_command;
