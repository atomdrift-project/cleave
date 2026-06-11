//! Core CapabilityMapper implementation.
//!
//! This module provides the main `CapabilityMapper` struct which:
//! - Loads capability definitions from YAML files
//! - Maps symbols to capability IDs
//! - Evaluates trait definitions and composite rules against analysis reports
//! - Provides platform and file type detection
//!
//! ## Module Organization
//!
//! The mapper is organized into focused submodules:
//!
//! - **builder**: Constructor methods (empty, new, with_platforms)
//! - **loader_directory**: Loading capabilities from directory of YAML files
//! - **loader_yaml**: Loading capabilities from single YAML file
//! - **lookup**: Query methods for finding traits and getting counts
//! - **evaluate_traits**: Atomic trait evaluation against analysis reports
//! - **evaluate_composites**: Composite rule evaluation
//! - **evaluate_merged**: Unified evaluation API combining traits + composites
//! - **imports**: Import finding generation and ecosystem detection
//! - **filters**: Low-value rule filtering
//! - **helpers**: Utility functions (file type detection, validation helpers)
//! - **builder**: Constructor methods (empty, new, with_platforms)

use crate::capabilities::indexes::{
    RawContentRegexIndex, StringMatchIndex, SymbolMatchIndex, TraitIndex,
};
use crate::capabilities::models::TraitInfo;
use crate::composite_rules::{CompositeTrait, Platform, TraitDefinition};
use std::collections::HashMap;

/// Maps symbols (function names, library calls) to capability IDs
/// Also supports trait definitions and composite rules that combine traits
#[derive(Clone, Debug)]
pub struct CapabilityMapper {
    pub(super) symbol_map: HashMap<String, TraitInfo>,
    pub(super) trait_definitions: Vec<TraitDefinition>,
    pub(crate) composite_rules: Vec<CompositeTrait>,
    /// Index for fast trait lookup by file type
    pub(super) trait_index: TraitIndex,
    /// Index for fast batched string matching
    pub(super) string_match_index: StringMatchIndex,
    /// Index for fast symbol matching
    pub(super) symbol_match_index: SymbolMatchIndex,
    /// Index for batched raw content regex matching
    pub(super) raw_content_regex_index: RawContentRegexIndex,
    /// Maps trait ID -> index in trait_definitions
    #[allow(dead_code)]
    pub(super) trait_id_map: std::collections::HashMap<String, usize>,
    /// Platform filter(s) for rule evaluation (default: [All])
    pub(super) platforms: Vec<Platform>,
    /// Warn threshold for slow rule evaluation in milliseconds (default: 4000)
    pub(super) slow_rule_ms: u64,
}

impl Default for CapabilityMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract relative path from full path (relative to traits directory)
/// Returns None if path conversion fails
pub(super) fn get_relative_source_file(path: &std::path::Path) -> Option<String> {
    // Try to find "traits/" in the path and return everything after it
    let path_str = path.to_string_lossy();
    if let Some(pos) = path_str.find("traits/") {
        let relative = &path_str[pos + 7..]; // Skip "traits/" prefix
        return Some(relative.to_string());
    }
    // Fallback: return the file name only if we can't find "traits/"
    path.file_name()
        .and_then(|n| n.to_str())
        .map(std::string::ToString::to_string)
}

/// Build the combined string vector from report strings, imports, and exports.
/// Used by both `evaluate_and_merge_findings` (cached path) and `evaluate_traits_filtered` (standalone).
pub(super) fn build_all_strings(
    report: &crate::types::AnalysisReport,
) -> Vec<crate::types::StringInfo> {
    let total_capacity = report.strings.len() + report.imports.len() + report.exports.len();
    let mut all_strings = Vec::with_capacity(total_capacity);
    all_strings.extend_from_slice(&report.strings);
    for imp in &report.imports {
        let offset = imp.offset.as_ref().and_then(|s| {
            let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).ok()
        });
        all_strings.push(crate::types::StringInfo {
            value: imp.symbol.clone().into(),
            offset,
            encoding: "symbol".to_string(),
            string_type: Some(crate::types::StringType::Import),
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }
    for exp in &report.exports {
        let offset = exp.offset.as_ref().and_then(|s| {
            let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).ok()
        });
        all_strings.push(crate::types::StringInfo {
            value: exp.symbol.clone().into(),
            offset,
            encoding: "symbol".to_string(),
            string_type: Some(crate::types::StringType::Export),
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }
    all_strings
}

/// Build the symbol-prefilter haystack the `SymbolMatchIndex` runs over to
/// decide which `type: symbol` traits are candidates for evaluation.
///
/// Includes import/export symbol names (binary symbol tables) *and* every
/// source-AST projection filefacts extracted — call targets, member-access
/// chains, bind targets, and identifiers (`Symbol::name()` yields the
/// matchable name for each kind). Without the filefacts names a
/// `kind: member`/`bind`/`identifier` trait could never become a candidate
/// (its literal would never appear in the haystack) and would be silently
/// skipped — the prefilter must see the same facts the evaluators do.
pub(super) fn build_all_symbols(report: &crate::types::AnalysisReport) -> Vec<String> {
    let filefacts_len = report.filefacts.as_ref().map_or(0, |v| v.symbols.len());
    let mut all = Vec::with_capacity(report.imports.len() + report.exports.len() + filefacts_len);
    all.extend(report.imports.iter().map(|i| i.symbol.clone()));
    all.extend(report.exports.iter().map(|e| e.symbol.clone()));
    if let Some(view) = report.filefacts.as_ref() {
        all.extend(
            view.symbols
                .iter()
                .filter_map(|s| s.name().map(str::to_string)),
        );
    }
    all
}

/// Map a symbol name to its file-offset (hex string such as `"0x1234"`),
/// drawn from the report's imports and exports. The symbol-match index works
/// on names alone, so its evidence is anchored back to the symbol's real
/// location via this map (an import's offset is its `.dynstr` name offset; an
/// export's is its `st_value`). Used by `fill_symbol_evidence_locations`.
pub(super) fn build_symbol_offset_map(
    report: &crate::types::AnalysisReport,
) -> rustc_hash::FxHashMap<String, String> {
    let mut map: rustc_hash::FxHashMap<String, String> = rustc_hash::FxHashMap::default();
    for i in &report.imports {
        if let Some(off) = i.offset.as_ref() {
            map.entry(i.symbol.clone()).or_insert_with(|| off.clone());
        }
    }
    for e in &report.exports {
        if let Some(off) = e.offset.as_ref() {
            map.entry(e.symbol.clone()).or_insert_with(|| off.clone());
        }
    }
    if let Some(view) = report.filefacts.as_ref() {
        for symbol in &view.symbols {
            let Some(name) = symbol.name() else {
                continue;
            };
            let offset = match symbol {
                filefacts::Symbol::Import { offset, .. }
                | filefacts::Symbol::Export { offset, .. }
                | filefacts::Symbol::Function { offset, .. }
                | filefacts::Symbol::Call { offset, .. }
                | filefacts::Symbol::Member { offset, .. }
                | filefacts::Symbol::Identifier { offset, .. } => *offset,
                filefacts::Symbol::Bind { offset, .. } => Some(*offset),
            };
            if let Some(offset) = offset {
                map.entry(name.to_string())
                    .or_insert_with(|| format!("{:#x}", offset));
            }
        }
    }
    map
}

/// Anchor symbol-index evidence at the matched symbol's file offset.
///
/// The symbol-match index emits evidence whose `value` is the symbol name but
/// with no `location` (it sees names, not offsets). Fill each such item from
/// `offsets`. Callers discard any item that remains unanchored so cached
/// symbol evidence never fabricates a file-start location.
pub(super) fn fill_symbol_evidence_locations(
    evidence: &mut [crate::types::Evidence],
    offsets: &rustc_hash::FxHashMap<String, String>,
) {
    for ev in evidence.iter_mut() {
        if ev.location.is_none() {
            ev.location = offsets.get(&ev.value).cloned();
        }
    }
}

// Extracted modules
pub(crate) mod builder;
pub(crate) mod evaluate_composites;
pub(crate) mod evaluate_merged;
pub(crate) mod evaluate_traits;
pub(crate) use evaluate_merged::AnalysisBorrow;
pub(crate) mod filters;
pub(crate) mod helpers;
pub(crate) mod loader_directory;
pub(crate) mod loader_yaml;
pub(crate) mod lookup;
