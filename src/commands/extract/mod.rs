//! Extraction subcommands for flayer.
//!
//! This module provides various extraction utilities for analyzing files:
//!
//! - **strings**: Extract strings from binaries and source files
//! - **symbols**: Extract imports, exports, and functions from binaries and source files
//! - **sections**: Extract section information from binary files (ELF, PE, Mach-O)
//! - **metrics**: Extract all computed metrics from a file
//!
//! Each subcommand supports both JSONL and terminal output formats.

pub(crate) mod metrics;
pub(crate) mod sections;
pub(crate) mod strings;
pub(crate) mod symbols;
