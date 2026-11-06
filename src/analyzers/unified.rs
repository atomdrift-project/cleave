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

/// Bound retained AST/decoded strings in aggregate, not by literal length.
/// Large embedded resources must remain visible to literal-based rules.
#[derive(Default)]
struct SeenStrings {
    keys: FxHashSet<SeenStringKey>,
    bytes: usize,
    truncated: bool,
}

impl SeenStrings {
    fn has_room(&mut self, length: usize) -> bool {
        let fits = self.keys.len() < crate::strings::MAX_STRINGS_PER_FILE
            && length <= crate::strings::MAX_TOTAL_STRING_BYTES.saturating_sub(self.bytes);
        if !fits && !self.truncated {
            tracing::warn!("source string retention limit reached; some literal evidence omitted");
            self.truncated = true;
        }
        fits
    }
}

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
            Some("ast-docstring") => 4,
            _ => 0,
        },
        chain_hash.finish(),
        value_hash.finish(),
    )
}

fn push_unique_string(report: &mut AnalysisReport, seen: &mut SeenStrings, info: StringInfo) {
    let key = seen_string_key(&info);
    if !seen.keys.contains(&key) && seen.has_room(info.value.len()) {
        seen.keys.insert(key);
        seen.bytes += info.value.len();
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
            // The grammar uses Java's character_literal node name for Groovy
            // single-quoted strings, including multi-character commands.
            string_node_types: &["string", "gstring", "character_literal"],
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
    engine: crate::Engine,
    /// When true, skip embedded payload detection to prevent recursion.
    /// Set for analyzers created for inner analysis (e.g. decoded PowerShell).
    skip_embedded_detection: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Encoding chain for decoded embedded-code layers.
    encoded_context: Option<Vec<String>>,
    /// Trusted parser context, never inferred from a disk filename.
    heuristic_quoted_context: bool,
}

impl std::fmt::Debug for UnifiedSourceAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedSourceAnalyzer")
            .field("config", &self.config)
            .field("file_type", &self.file_type)
            .field("engine", &self.engine)
            .finish()
    }
}

impl UnifiedSourceAnalyzer {
    /// Create a new analyzer for the given language configuration.
    pub(crate) fn new(config: LanguageConfig, file_type: crate::analyzers::FileType) -> Self {
        Self {
            config,
            file_type,
            engine: crate::Engine::empty(),
            skip_embedded_detection: false,
            cancellation: None,
            encoded_context: None,
            heuristic_quoted_context: false,
        }
    }

    /// Create an analyzer for the given file type.
    #[must_use]
    pub(crate) fn for_file_type(file_type: &crate::analyzers::FileType) -> Option<Self> {
        config_for_file_type(file_type).map(|config| Self::new(config, *file_type))
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[cfg(test)]
    pub(crate) fn with_capability_mapper(
        mut self,
        capability_mapper: crate::capabilities::CapabilityMapper,
    ) -> Self {
        self.engine = crate::Engine::from_rules(std::sync::Arc::new(capability_mapper));
        self
    }

    /// Analyze under `engine`: its rules and settings.
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.engine = engine;
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
        self.heuristic_quoted_context = false;
        self
    }

    pub(crate) fn with_heuristic_quoted_context(mut self) -> Self {
        self.heuristic_quoted_context = true;
        self.encoded_context = None;
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
        let ctx = Some(crate::analysis_context::AnalysisContext::open_with(
            filefacts::OpenOptions::new().file_type(self.file_type),
            file_path,
            content.as_bytes(),
        ));
        self.analyze_source_impl(
            file_path,
            content,
            &[],
            &[],
            None,
            false,
            self.cancellation.as_ref(),
            ctx.as_ref(),
            Some(content.as_bytes()),
        )
    }

    pub(crate) fn analyze_source(&self, file_path: &Path, content: &str) -> AnalysisReport {
        let ctx = Some(crate::analysis_context::AnalysisContext::open(
            file_path,
            content.as_bytes(),
        ));
        self.analyze_source_impl(
            file_path,
            content,
            &[],
            &[],
            None,
            false,
            self.cancellation.as_ref(),
            ctx.as_ref(),
            Some(content.as_bytes()),
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
        compact_filefacts_values: bool,
        cancellation: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
        source_ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
        original_bytes: Option<&[u8]>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: self.config.file_type.to_string(),
            size_bytes: original_bytes.map_or(content.len(), <[u8]>::len) as u64,
            sha256: precomputed_sha256.unwrap_or_else(|| {
                crate::analyzers::utils::calculate_sha256(
                    original_bytes.unwrap_or(content.as_bytes()),
                )
            }),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        if self.heuristic_quoted_context {
            report
                .findings
                .push(crate::analyzers::embedded_code_detector::heuristic_quoted_origin_finding());
        }
        // Encoding context is input to this layer's rules, not an output
        // appended after evaluation. The host still retains this layer.
        if let Some(chain) = &self.encoded_context {
            report.findings.extend(
                crate::analyzers::embedded_code_detector::generate_encoded_layer_traits(chain, 0),
            );
        }

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
        let mut ast_node_text = crate::composite_rules::evaluators::NodeTextIndex::default();
        let mut seen_strings = SeenStrings::default();
        if let Some(tree) = tree {
            // One walk for functions, string/number/comment literals and the
            // trait kind-cache. A second cursor pass in evaluate_and_merge was
            // pure walk tax.
            //
            // Call sites are NOT collected here: filefacts already named every
            // call while parsing this same tree, and `cleave facts` prints
            // those names, so a rule author can read the exact string their
            // matcher must equal off the tool. Naming calls a second way here
            // gave chained calls two spellings — filefacts `open().read`
            // versus this walk's `open("/tmp/x","w").read`, which embedded the
            // caller's argument text and so could never be matched by a fixed
            // string at all.
            let mapper = Arc::clone(self.engine.rules());
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
                &mut ast_node_text,
                &mut seen_strings,
            );
            if !required.is_empty() {
                ast_kind_cache = Some(cache);
            }
        }
        if let Some(ctx) = source_ctx {
            symbol_extraction::ingest_filefacts_calls(&ctx.parsed, &mut report);
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
                    | stng::StringMethod::Base32Decode
                    | stng::StringMethod::Base85Decode
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
                    stng::StringMethod::Base32Decode => "base32",
                    stng::StringMethod::Base85Decode => "base85",
                    stng::StringMethod::XorDecode => "xor",
                    stng::StringMethod::HexDecode => "hex",
                    stng::StringMethod::UrlDecode => "url",
                    stng::StringMethod::UnicodeEscapeDecode => "unicode-escape",
                    stng::StringMethod::ScriptDecode => "script",
                    _ => "",
                };

                let chain = if encoding_method.is_empty() {
                    Vec::new()
                } else {
                    vec![encoding_method.to_string()]
                };
                // A decoder's output can itself be encoded. Peel the rest so
                // the string is the innermost content and the chain records how
                // it was reached (`base64+base64`) — see the same call in the
                // generic analyzer.
                let (value, encoding_chain) =
                    super::generic::peel_nested_encoding(&es.value, chain);

                let decoded = crate::types::StringInfo {
                    value: value.into(),
                    offset: Some(es.data_offset),
                    string_type,
                    encoding: "utf-8".to_string(),
                    section: Some("decoded".to_string()),
                    encoding_chain,
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
        let mut owned_extracted_payloads;
        let extracted_payloads: &[crate::types::ExtractedPayload] = if self.skip_embedded_detection
        {
            &[]
        } else if !preextracted_payloads.is_empty() {
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
            owned_extracted_payloads.extend(
                crate::extractors::encoded_payload::extract_nibble_table_payloads(
                    content.as_bytes(),
                ),
            );
            if let Some(payload) =
                crate::extractors::powershell_literals::extract_powershell_literal_payload(
                    content.as_bytes(),
                )
            {
                owned_extracted_payloads.push(payload);
            }
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
            let payload_report =
                UnifiedSourceAnalyzer::for_file_type(&payload.detected_type).map(|analyzer| {
                    analyzer
                        .with_engine(self.engine.clone())
                        .with_cancellation(cancellation.cloned())
                        .with_encoded_context(payload.encoding_chain.clone())
                        .without_embedded_detection()
                        .analyze_source_as_configured(
                            Path::new(&virtual_path),
                            &String::from_utf8_lossy(&payload_content),
                        )
                });

            // Process payload report - convert to FileAnalysis for v2 flat files array
            if let Some(pr) = payload_report {
                // Prefix findings with extracted payload location (same as archive: prefix)
                let (mut file_entry, _, _) = pr.into_file_analysis(0, &self.engine);
                file_entry.path = virtual_path.clone();
                file_entry.depth = 1; // Decoded content is one level deep
                file_entry.encoding = Some(payload.encoding_chain.clone());

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
                                    .with_engine(self.engine.clone())
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
                                .with_engine(self.engine.clone())
                                .with_cancellation(cancellation.cloned())
                                .analyze_source(
                                    Path::new(&virtual_path),
                                    &String::from_utf8_lossy(&payload_content),
                                )
                        }),
                    FileType::Shell => {
                        UnifiedSourceAnalyzer::for_file_type(&FileType::Shell).map(|analyzer| {
                            analyzer
                                .with_engine(self.engine.clone())
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
                    let (mut file_entry, _, _) = pr.into_file_analysis(0, &self.engine);
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
            // Call sites were ingested from filefacts above, before this:
            // the alias pass below rewrites everything already in
            // `report.imports`, so they have to be present for
            // `alias.decompress` to resolve to `zlib.decompress`.
            // Module imports come from filefacts's per-language queries; cleave
            // only adds Python `__import__` alias resolution on top.
            if let Some(ctx) = source_ctx {
                symbol_extraction::ingest_filefacts_imports(
                    &ctx.parsed,
                    &self.file_type,
                    &mut report,
                );
                // A module's export surface (CommonJS `exports.x = …`), so a
                // diff sees the API a release adds, not only what it calls.
                report.exports.extend(ctx.exports_from_filefacts());
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
            if matches!(self.file_type, FileType::JavaScript | FileType::TypeScript)
                && let Some(ast) = source_ast
            {
                for command in super::js_xor_command::decode(ast) {
                    if let Some(layer) = super::embedded_code_detector::analyze_decoded_script_layer(
                        &parent,
                        &command.text,
                        command.offset,
                        command.file_type,
                        vec!["hex".into(), "xor".into()],
                        &self.engine,
                        parent.matches("##").count(),
                        false,
                    ) {
                        report.files.push(layer);
                    }
                }
            }
            if self.file_type == FileType::Python
                && let Some(ast) = source_ast
            {
                for command in super::python_encoded_command::decode(ast) {
                    if let Some(layer) = super::embedded_code_detector::analyze_decoded_script_layer(
                        &parent,
                        &command.text,
                        command.offset,
                        FileType::Shell,
                        command.chain,
                        &self.engine,
                        0,
                        false,
                    ) {
                        report.files.push(layer);
                    }
                }
            }
            // stng already found/decoded obfuscated script blobs during string
            // extract, but it shreds `DeobfuscationResult.decoded` into
            // `ScriptDecode` fragments. Keep the full payload as a typed
            // source layer here and skip the home-grown EncodedCommand scan.
            report.files.extend(
                crate::analyzers::embedded_code_detector::analyze_script_deobfuscation_layers(
                    &parent,
                    content,
                    &self.engine,
                    0,
                    self.cancellation.as_deref(),
                ),
            );
            // Reduce only proved constant decoder calls; retain the original
            // host and expose the result as a separate, bounded source layer.
            if matches!(self.config.name, "javascript" | "typescript")
                && let Some(ast) =
                    source_ctx.and_then(crate::analysis_context::AnalysisContext::source_ast)
                && let Some(decoded) = crate::analyzers::js_string_table::decode(ast)
                && let Some(layer) =
                    crate::analyzers::embedded_code_detector::analyze_decoded_script_layer(
                        &parent,
                        &decoded,
                        0,
                        FileType::JavaScript,
                        vec!["js-constant-string-table".to_string()],
                        &self.engine,
                        0,
                        false,
                    )
            {
                report.files.push(layer);
            }
            if matches!(self.config.name, "javascript" | "typescript")
                && let Some(ast) =
                    source_ctx.and_then(crate::analysis_context::AnalysisContext::source_ast)
            {
                for (offset, decoded) in crate::analyzers::js_joined_module::decode(ast) {
                    for (inner, extra_chain) in
                        crate::analyzers::js_joined_module::encrypted_layers(ast, &decoded, offset)
                    {
                        let mut chain = vec!["js-joined-base64-module".to_string()];
                        chain.extend(extra_chain);
                        if let Some(layer) =
                            crate::analyzers::embedded_code_detector::analyze_decoded_script_layer(
                                &parent,
                                &inner,
                                offset,
                                FileType::JavaScript,
                                chain,
                                &self.engine,
                                0,
                                false,
                            )
                        {
                            report.files.push(layer);
                        }
                    }
                    if let Some(layer) =
                        crate::analyzers::embedded_code_detector::analyze_decoded_script_layer(
                            &parent,
                            &decoded,
                            offset,
                            FileType::JavaScript,
                            vec!["js-joined-base64-module".to_string()],
                            &self.engine,
                            0,
                            false,
                        )
                    {
                        report.files.push(layer);
                    }
                }
            }
            if matches!(self.config.name, "javascript" | "typescript") {
                // Plaintext views in another language, not concealment: each
                // is analyzed as that language beside its host.
                let mut view = |path: String, file_type: FileType, embedded: &str| {
                    let Some(analyzer) = Self::for_file_type(&file_type) else {
                        return;
                    };
                    let view_report = analyzer
                        .with_engine(self.engine.clone())
                        .without_embedded_detection()
                        .analyze_source_as_configured(Path::new(&path), embedded);
                    let (mut entry, _, _) = view_report.into_file_analysis(0, &self.engine);
                    entry.path = path;
                    entry.depth = 1;
                    entry.encoding = None;
                    entry.compute_summary();
                    report.files.push(entry);
                };
                if let Some(ast) =
                    source_ctx.and_then(crate::analysis_context::AnalysisContext::source_ast)
                {
                    for (offset, embedded) in crate::analyzers::js_edge_source::extract(ast) {
                        view(
                            format!("{parent}##edge-csharp@{offset}"),
                            FileType::CSharp,
                            &embedded,
                        );
                    }
                }
                // A PHP include runs these whatever JavaScript makes of them.
                for (offset, embedded) in crate::analyzers::php_blocks::extract(content) {
                    tracing::debug!(path = %parent, offset, "carved PHP block from JavaScript");
                    view(
                        format!("{parent}##embedded-php@{offset}"),
                        FileType::Php,
                        embedded,
                    );
                }
            }
            // Borrow the host haystack instead of copying `content` and
            // `report.strings` per member.
            // A module containing only immutable quoted constants has no
            // executable use of those strings. Keep its encoded layers, but
            // do not infer program behavior from plain quoted source examples.
            let data_only = source_ctx
                .and_then(crate::analysis_context::AnalysisContext::source_ast)
                .is_some_and(|ast| match self.config.name {
                    "javascript" | "typescript" => {
                        crate::analyzers::js_literal_catalog::is_data_only(ast)
                    }
                    "python" => crate::analyzers::python_literal_catalog::is_data_only(ast),
                    _ => false,
                });
            let encoded_constants: Vec<_> = if data_only {
                report
                    .strings
                    .iter()
                    .filter(|s| !s.encoding_chain.is_empty())
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            let (encoded_layers, plain_findings) =
                crate::analyzers::embedded_code_detector::process_all_strings_with_host(
                    &parent,
                    if data_only {
                        &encoded_constants
                    } else {
                        &report.strings
                    },
                    &self.engine,
                    0,
                    Some(&self.file_type),
                    self.cancellation.as_deref(),
                    true,
                    if data_only { None } else { Some(content) },
                );
            report.files.extend(encoded_layers);
            report.findings.extend(plain_findings);
        }

        // Reconstruct literal PowerShell containers without running script code.
        // The virtual-path depth budget also bounds recursion across fresh source
        // analyzers, whose per-instance embedded-detection flag starts enabled.
        if !self.skip_embedded_detection && self.file_type == FileType::PowerShell {
            let parent = file_path.display().to_string();
            let depth = parent.matches("##").count() as u32;
            if depth < 3 {
                for payload in crate::extractors::powershell_payloads::extract(content.as_bytes()) {
                    if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
                        break;
                    }
                    let virtual_path = crate::types::encode_decoded_path(
                        &parent,
                        &payload.encoding_chain,
                        payload.original_offset,
                    );
                    let entries = crate::analyzers::subfile::analyze_subfile_bytes(
                        &payload.data,
                        &virtual_path,
                        payload.detected_type,
                        &format!("decoded@{}", payload.original_offset),
                        depth,
                        &self.engine,
                    );
                    report.files.extend(entries);
                }
            }
        }

        // Build the `source.*` kv tree from already-extracted
        // imports/exports/functions before the trait engine runs so
        // `type: value, path: source.imports, ...` traits can resolve.
        super::source_kv::attach_to_report(&mut report, Some(content.as_bytes()));

        if let Some(ctx) = source_ctx {
            let view = crate::types::FilefactsView::of(ctx, compact_filefacts_values);
            if !view.is_empty() {
                report.filefacts = Some(view);
            }
            report.identity = ctx.identity();
        }

        // Source traits need inline YARA before composites are evaluated.
        // Borrow original bytes: the parser's recovered UTF-8 source is a
        // syntax view and can replace bytes in legacy/polyglot scripts.
        let rule_bytes = source_ctx.map_or(content.as_bytes(), |ctx| ctx.content);
        let yara_bytes = original_bytes.unwrap_or(rule_bytes);
        let is_yara_rule_source = self.file_type == FileType::Yara
            || file_path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara")
                });
        let inline_yara = if is_yara_rule_source {
            None
        } else {
            self.engine.yara().map(|yara| {
                crate::process_yara_result(
                    &mut report,
                    Some(yara.scan_bytes(yara_bytes, Some(&self.file_type.yara_filetypes()))),
                    Some(yara),
                )
            })
        };

        // Evaluate all rules (atomic + composite) and merge into report,
        // borrowing the same filefacts context used for source AST extraction.
        let matching_start = tracing::enabled!(tracing::Level::DEBUG).then(std::time::Instant::now);
        self.engine.evaluate_and_merge_findings_with_precomputed(
            &mut report,
            rule_bytes,
            crate::capabilities::AnalysisBorrow::with_filefacts(tree, source_ctx)
                .with_ast_kind_cache(ast_kind_cache.as_ref())
                .with_ast_node_text(&ast_node_text),
            inline_yara.as_ref(),
            None,
            None,
            None,
        );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        if let Some(matching_start) = matching_start {
            tracing::debug!(
                path = %file_path.display(),
                size_bytes = content.len(),
                preparation_ms = matching_start.duration_since(start).as_millis() as u64,
                matching_ms = matching_start.elapsed().as_millis() as u64,
                total_ms = report.metadata.analysis_duration_ms,
                "source analysis timing",
            );
        }

        report
            .metadata
            .tools_used
            .push(format!("tree-sitter-{}", self.config.name));

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
        node_text: &mut crate::composite_rules::evaluators::NodeTextIndex,
        seen_strings: &mut SeenStrings,
    ) {
        let source = content.as_bytes();
        let mut cursor = tree.walk();
        // Collected by the walk so call-kind nodes get an `Evidence.alt_value`;
        // the imports themselves are ingested from filefacts.
        let mut call_sites: Vec<(String, u64)> = Vec::new();
        self.walk_ast_facts(
            &mut cursor,
            source,
            report,
            &mut call_sites,
            required_node_types,
            call_node_types,
            kind_cache,
            node_text,
            seen_strings,
        );
        node_text.finish();
        // `call_sites` is collected by the walk for `Evidence.alt_value` on
        // call-kind nodes; the imports themselves come from filefacts.
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
        node_text: &mut crate::composite_rules::evaluators::NodeTextIndex,
        seen_strings: &mut SeenStrings,
    ) {
        let mut depth: u32 = 0;
        loop {
            let node = cursor.node();
            let kind = node.kind();
            node_text.record_node(&node, source);
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
                self.collect_string_node(
                    &node,
                    source,
                    report,
                    seen_strings,
                    self.config.name == "python" && is_python_docstring_literal(&node),
                );
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
                depth += 1;
                node_text.note_depth(depth);
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                depth -= 1;
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
        seen_strings: &mut SeenStrings,
        is_docstring: bool,
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

        if s.is_empty() || !seen_strings.has_room(s.len()) {
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
            section: Some(if is_docstring { "ast-docstring" } else { "ast" }.to_string()),
            encoding_chain: Vec::new(),
            fragments: None,
        };
        push_unique_string(report, seen_strings, literal);

        // The literal as the program will actually use it, when the source
        // spelled it with escapes. Pushed *in addition to* the raw form, and
        // into the same `ast` section, so that `type: literal` sees both: rules
        // that deliberately match escaped spellings (obfuscation detectors
        // keying on `\x` runs) keep working, while rules written against the
        // plain text start working.
        //
        // Without this, an obfuscator's string table defeats the literal
        // matcher outright — `js-obfuscator` escapes every space, so a shipped
        // `powershell\x20-Command\x20\x22irm\x20…\x20|\x20iex\x22` is
        // invisible to a rule looking for `powershell -Command`. It also made
        // `cleave facts literals`, which reports the decoded value, disagree
        // with what rules could match — so an author following the rule guide
        // would write a matcher against a string that could never fire.
        let lua_long_string = self.config.name == "lua"
            && (text.starts_with('[')
                || node.parent().is_some_and(|parent| {
                    parent.kind() == "string"
                        && parent
                            .utf8_text(source)
                            .is_ok_and(|raw| raw.starts_with('['))
                }));
        let decoded_escapes = if lua_long_string {
            // Lua long-bracket strings are raw, unlike quoted short strings.
            s.to_string()
        } else {
            filefacts::decode_source_escapes_for_type(
                s,
                FileType::from_label(self.config.file_type).unwrap_or(FileType::Unknown),
            )
        };
        if decoded_escapes != s {
            let unescaped = StringInfo {
                value: decoded_escapes.into(),
                offset: Some(offset),
                string_type: None,
                encoding: "utf-8".to_string(),
                section: Some(if is_docstring { "ast-docstring" } else { "ast" }.to_string()),
                // Deliberately no encoding chain. This is the same datum as the
                // source literal, normalised — not a concealment layer wrapped
                // around it. Recording it as encoded would make every ordinary
                // string that merely contains a `\n` look deliberately hidden,
                // and `type: encoded` rules exist precisely to find the strings
                // someone took the trouble to hide.
                encoding_chain: Vec::new(),
                fragments: None,
            };
            push_unique_string(report, seen_strings, unescaped);
        }

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

        // Language-specific stng adapters do not all recognize the same
        // source-level Base64 spellings. Kotlin, for example, exposes a
        // parser-confirmed literal but historically did not emit the decoded
        // companion that Elixir emitted for the identical unpadded payload.
        // Decode isolated literals here so `type: encoded` has a consistent
        // surface across unified source languages. Requiring a substantial,
        // wholly printable payload avoids turning hashes and binary resources
        // into misleading decoded-string facts.
        if let Some(decoded) = decode_printable_base64_literal(s) {
            let decoded = StringInfo {
                value: decoded.into(),
                offset: Some(offset),
                string_type: None,
                encoding: "utf-8".to_string(),
                section: Some("decoded".to_string()),
                encoding_chain: vec!["base64".to_string()],
                fragments: None,
            };
            push_unique_string(report, seen_strings, decoded);
        }
    }

    /// Name a function definition.
    ///
    /// A function symbol is the function's name and nothing else -- `g`, not
    /// `g(void)`. In C the configured field (`declarator`) does not hold the
    /// name: it holds a `function_declarator` whose own text is the whole
    /// signature, wrapped in a `pointer_declarator` when the function returns
    /// a pointer. Taking that node's text verbatim named every C function
    /// after its parameter list, which no `type: symbol` matcher could equal
    /// and which disagreed with the name filefacts reports for the same node.
    /// Descend to the identifier instead.
    fn extract_function_name<'a>(
        &self,
        node: &tree_sitter::Node<'a>,
        source: &[u8],
    ) -> Option<String> {
        // Try the configured field name first
        if let Some(name_node) = node.child_by_field_name(self.config.function_name_field)
            && let Some(name) = declarator_identifier(&name_node, source, 0)
        {
            return Some(name);
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

/// Return whether a Python string node belongs to the module, class, or
/// function docstring: a standalone string expression in the first statement
/// slot of that scope. Nested literals in a call in that slot are not docs.
fn is_python_docstring_literal(node: &tree_sitter::Node<'_>) -> bool {
    let mut expression = *node;
    while expression.kind() != "expression_statement" {
        let Some(parent) = expression.parent() else {
            return false;
        };
        expression = parent;
    }

    let Some(expr_value) = expression.named_child(0) else {
        return false;
    };
    if !matches!(expr_value.kind(), "string" | "concatenated_string") {
        return false;
    }
    let Some(scope_body) = expression.parent() else {
        return false;
    };
    let scope_body_kind = scope_body.kind();
    if scope_body_kind != "module"
        && !(scope_body_kind == "block"
            && scope_body.parent().is_some_and(|parent| {
                matches!(parent.kind(), "function_definition" | "class_definition")
            }))
    {
        return false;
    }

    scope_body.named_child(0).is_some_and(|first| {
        first.kind() == "expression_statement"
            && first.start_byte() == expression.start_byte()
            && first.end_byte() == expression.end_byte()
    })
}

/// Resolve a declarator to the identifier it declares.
///
/// Returns the node's own text when it already names something; otherwise
/// follows the `declarator` field inward (`pointer_declarator` ->
/// `function_declarator` -> `identifier`) and, failing that, takes the first
/// identifier-ish named child. Bounded so a pathological declarator chain
/// cannot recurse without end.
fn declarator_identifier(
    node: &tree_sitter::Node<'_>,
    source: &[u8],
    depth: usize,
) -> Option<String> {
    const MAX_DECLARATOR_DEPTH: usize = 32;
    if depth > MAX_DECLARATOR_DEPTH {
        return None;
    }
    if matches!(
        node.kind(),
        "identifier"
            | "name"
            | "field_identifier"
            | "type_identifier"
            | "property_identifier"
            | "simple_identifier"
            | "word"
    ) {
        return node
            .utf8_text(source)
            .ok()
            .map(str::to_string)
            .filter(|n| !n.is_empty());
    }
    if let Some(inner) = node.child_by_field_name("declarator")
        && let Some(name) = declarator_identifier(&inner, source, depth + 1)
    {
        return Some(name);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(name) = declarator_identifier(&child, source, depth + 1) {
            return Some(name);
        }
    }
    None
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
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let pair = std::str::from_utf8(pair).ok()?;
        decoded.push(u8::from_str_radix(pair, 16).ok()?);
    }
    if !decoded.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
        return None;
    }

    String::from_utf8(decoded).ok()
}

/// Decode a parser-confirmed Base64 string literal when it yields meaningful
/// printable text. Both padded and unpadded standard/Base64URL forms are
/// accepted because runtime decoders commonly accept omitted padding.
fn decode_printable_base64_literal(value: &str) -> Option<String> {
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    };

    const MIN_ENCODED_LEN: usize = 24;
    const MIN_DECODED_LEN: usize = 16;

    let cleaned: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.len() < MIN_ENCODED_LEN || cleaned.len() % 4 == 1 {
        return None;
    }
    if !cleaned.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
    }) {
        return None;
    }

    let decoded = STANDARD
        .decode(&cleaned)
        .or_else(|_| STANDARD_NO_PAD.decode(&cleaned))
        .or_else(|_| URL_SAFE.decode(&cleaned))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&cleaned))
        .ok()?;
    if decoded.len() < MIN_DECODED_LEN
        || !decoded
            .iter()
            .all(|byte| matches!(byte, b'\n' | b'\r' | b'\t' | 0x20..=0x7e))
    {
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
mod numeric_literal_tests;

impl Analyzer for UnifiedSourceAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Handle UTF-16 encoding. Shares `normalize_text_encoding` with the
        // rest of the engine rather than repeating the BOM check, so a BOM
        // that lies about the encoding is treated the same everywhere: this
        // copy decoded on the BOM alone, which left source analysis reading
        // mojibake for any single-byte script with `FF FE` in front of it.
        let bytes = crate::file_io::normalize_text_encoding(input.data);

        let content = filefacts::source_text_for_ast(&bytes);

        // Pass pre-extracted stng strings and payloads to avoid redundant extraction.
        // Merge cancellation: prefer struct field (set via builder), fall back to input field
        // (set by callers that don't go through analyzer_for_file_type_arc).
        let effective_cancellation = self.cancellation.as_ref().or(input.cancellation.as_ref());
        // Reuse the threaded context only when it covers the exact bytes we
        // analyze (no UTF-16 normalization); otherwise open one on those
        // decoded bytes. The two contexts have different byte lifetimes,
        // so each branch makes its own call rather than merging into one option.
        let reuse = bytes.as_ref() == input.data;
        match input.parsed_ctx.as_ref() {
            Some(ctx) if reuse => Ok(self.analyze_source_impl(
                input.path,
                &content,
                input.strings,
                input.payloads,
                input.sha256.clone(),
                self.engine.compact_members(),
                effective_cancellation,
                Some(ctx),
                Some(input.data),
            )),
            _ => {
                let owned_ctx = Some(crate::analysis_context::AnalysisContext::open(
                    input.path,
                    bytes.as_ref(),
                ));
                Ok(self.analyze_source_impl(
                    input.path,
                    &content,
                    input.strings,
                    input.payloads,
                    input.sha256.clone(),
                    self.engine.compact_members(),
                    effective_cancellation,
                    owned_ctx.as_ref(),
                    Some(input.data),
                ))
            }
        }
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let input = AnalysisInput::new(file_path, &data, self.file_type);
        self.analyze_input(&input)
    }

    fn can_analyze(&self, _file_path: &Path) -> bool {
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
