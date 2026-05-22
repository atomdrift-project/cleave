//! Dynamic field path validation for metrics
//!
//! Provides a trait-based system for validating metric field references in YAML rules
//! without hardcoding field names.

use std::collections::HashSet;

/// Trait for types that can declare their valid field paths and descriptions.
#[doc(hidden)]
pub trait ValidFieldPaths {
    /// Returns all valid field paths for this type.
    fn valid_field_paths() -> Vec<&'static str>;

    /// Returns `(field_name, doc_comment)` pairs for all public fields.
    /// The doc comment is the concatenation of all `///` lines on the field.
    /// Default implementation returns empty — types with manual `ValidFieldPaths`
    /// impls get no descriptions unless they override this.
    #[must_use]
    fn field_descriptions() -> Vec<(&'static str, &'static str)> {
        Vec::new()
    }
}

// Canonical source-text metric field lists. Kept in sync with the
// dotted keys filefacts's source extractors emit
// (`filefacts/src/formats/source/{text,identifier,string,comment,function,import}_metrics.rs`).
// New emitter additions in filefacts must show up here too — the trait
// engine rejects unknown field paths.

const TEXT_METRIC_FIELDS: &[&str] = &[
    "char_entropy",
    "unique_chars",
    "most_common_char_codepoint",
    "most_common_char_is_null",
    "most_common_ratio",
    "non_ascii_ratio",
    "non_printable_ratio",
    "null_byte_count",
    "high_byte_ratio",
    "total_lines",
    "avg_line_length",
    "max_line_length",
    "line_length_stddev",
    "lines_over_200",
    "lines_over_500",
    "lines_over_1000",
    "last_line_length",
    "ast_parse_errors",
    "ast_max_depth",
    "empty_line_ratio",
    "whitespace_ratio",
    "tab_count",
    "space_count",
    "mixed_indent",
    "trailing_whitespace_lines",
    "unusual_whitespace",
    "max_inline_whitespace_run",
    "hex_escape_count",
    "unicode_escape_count",
    "octal_escape_count",
    "escape_density",
    "invisible_chars",
    "long_token_count",
    "repeated_char_sequences",
    "digit_ratio",
    "ascii_art_lines",
    "strings_to_functions_ratio",
    "identifiers_to_functions_ratio",
    "imports_to_functions_ratio",
    "identifier_density",
    "string_density",
    "import_density",
    "suspicious_identifier_ratio",
    "encoded_string_ratio",
    "suspicious_string_ratio",
    "suspicious_comment_ratio",
    "normalized_function_count",
    "normalized_import_count",
    "normalized_string_count",
    "normalized_unique_identifiers",
    "dynamic_string_ratio",
    "dynamic_import_ratio",
    "anonymous_function_ratio",
];

const IDENTIFIER_METRIC_FIELDS: &[&str] = &[
    "total",
    "unique_count",
    "reuse_ratio",
    "avg_length",
    "min_length",
    "max_length",
    "length_stddev",
    "single_char_count",
    "single_char_ratio",
    "avg_entropy",
    "high_entropy_count",
    "high_entropy_ratio",
    "all_lowercase_ratio",
    "all_uppercase_ratio",
    "has_digit_ratio",
    "underscore_prefix_count",
    "double_underscore_count",
    "numeric_suffix_count",
    "hex_like_names",
    "base64_like_names",
    "sequential_names",
    "keyboard_pattern_names",
    "repeated_char_names",
];

const STRING_METRIC_FIELDS: &[&str] = &[
    "total",
    "total_bytes",
    "avg_length",
    "max_length",
    "empty_count",
    "avg_entropy",
    "entropy_stddev",
    "high_entropy_count",
    "very_high_entropy_count",
    "base64_candidates",
    "hex_strings",
    "url_encoded_strings",
    "unicode_heavy_strings",
    "url_count",
    "path_count",
    "ip_count",
    "email_count",
    "domain_count",
    "concat_operations",
    "format_strings",
    "char_construction",
    "array_join_construction",
    "very_long_strings",
    "embedded_code_candidates",
    "shell_command_strings",
    "sql_strings",
];

const COMMENT_METRIC_FIELDS: &[&str] = &[
    "total",
    "lines",
    "chars",
    "to_code_ratio",
    "todo_count",
    "fixme_count",
    "hack_count",
    "xxx_count",
    "empty_comments",
    "high_entropy_comments",
    "code_in_comments",
    "url_in_comments",
    "base64_in_comments",
];

const FUNCTION_METRIC_FIELDS: &[&str] = &[
    "total",
    "anonymous",
    "async_count",
    "generator_count",
    "avg_length_lines",
    "max_length_lines",
    "min_length_lines",
    "length_stddev",
    "over_100_lines",
    "over_500_lines",
    "one_liners",
    "avg_params",
    "max_params",
    "no_params_count",
    "many_params_count",
    "avg_param_name_length",
    "single_char_params",
    "avg_name_length",
    "single_char_names",
    "high_entropy_names",
    "numeric_suffix_names",
    "max_nesting_depth",
    "avg_nesting_depth",
    "nested_functions",
    "recursive_count",
    "density_per_100_lines",
    "code_in_functions_ratio",
];

const IMPORT_METRIC_FIELDS: &[&str] = &[
    "total",
    "unique_modules",
    "stdlib_count",
    "third_party_count",
    "relative_imports",
    "wildcard_imports",
    "dynamic_imports",
    "aliased_imports",
    "conditional_imports",
    "stdlib_ratio",
    "third_party_ratio",
    "relative_ratio",
];

/// Returns all valid metric field paths for use in YAML rules
/// Returns paths like "binary.code_to_data_ratio", "text.line_count", etc.
#[must_use]
pub(crate) fn all_valid_metric_paths() -> HashSet<String> {
    // Import the trait to access its methods
    use super::field_paths::ValidFieldPaths;

    let mut paths = HashSet::new();

    use super::scores::{
        EncodedLanguageMetrics, EncodedMetrics, ObfuscationScore, PackingScore, SupplyChainScore,
    };

    // Source-text metrics live in filefacts
    // (`filefacts/src/formats/source/`). The canonical key list is
    // hardcoded below — kept in sync with the dotted keys those
    // emitters write to. New emitters must be reflected here so
    // trait field validation accepts their paths.
    for field in TEXT_METRIC_FIELDS {
        paths.insert(format!("text.{}", field));
    }
    for field in IDENTIFIER_METRIC_FIELDS {
        paths.insert(format!("identifiers.{}", field));
    }
    for field in STRING_METRIC_FIELDS {
        paths.insert(format!("strings.{}", field));
    }
    for field in COMMENT_METRIC_FIELDS {
        paths.insert(format!("comments.{}", field));
    }
    for field in FUNCTION_METRIC_FIELDS {
        paths.insert(format!("functions.{}", field));
    }
    for field in IMPORT_METRIC_FIELDS {
        paths.insert(format!("imports.{}", field));
    }
    for field in EncodedMetrics::valid_field_paths() {
        if !matches!(field, "python" | "javascript" | "php" | "shell") {
            paths.insert(format!("encoded.{}", field));
        }
    }
    for lang in ["python", "javascript", "php", "shell"] {
        for field in EncodedLanguageMetrics::valid_field_paths() {
            paths.insert(format!("encoded.{}.{}", lang, field));
        }
    }

    // Per-language metric structs (PythonMetrics / JavaScriptMetrics /
    // …) retired with the cleave→filefacts migration. No production code
    // ever emitted them — the surface is gone.

    // Binary-format metrics (`binary.*`, `pe.*`, `elf.*`, `macho.*`,
    // `java_class.*`) live exclusively in filefacts's flat metric map —
    // trait validation accepts any path under those namespaces.

    // Container/Archive metrics. `archive.*` paths are emitted by
    // filefacts's zip/tar extractors directly into `report.filefacts_metrics`.
    // The list below is the canonical manifest the trait engine accepts;
    // it mirrors the keys filefacts's `formats::zip` and `formats::tar`
    // write. Keep in sync when filefacts adds a new `archive.*` metric.
    for field in [
        // Index/size aggregates.
        "member_count",
        "file_count",
        "directory_count",
        "total_uncompressed",
        "total_compressed",
        "compression_ratio",
        "compression.ratio",
        // Compression breakdowns (the actual concrete keys are
        // `archive.compression.method_counts.<method>` and
        // `archive.format.<entry-type>_count`; those go through the
        // unrestricted-prefix path below).
        // Security / forensic counts (legacy flat names).
        "symlink_count",
        "encrypted_count",
        "max_filename_length",
        "hidden_file_count",
        "path_traversal_count",
        "symlink_escape_count",
        "executable_count",
        "script_count",
        "unicode_filename_count",
        "homoglyph_filename_count",
        "double_extension_count",
        "rtlo_filename_count",
        "nested_archive_count",
        "misplaced_executable_count",
        "zip_bomb_ratio",
        "extra_field_size",
        "uses_zip64",
        "has_comment",
        // Security sub-namespace filefacts emits alongside the flat names.
        "security.setuid_count",
        "security.setgid_count",
        "security.sticky_count",
        "security.world_writable_count",
        "security.symlink_count",
        "security.encrypted_count",
        "security.external_symlink_count",
        // Timing spread metrics computed from member mtimes.
        "timing.mtime_spread_seconds",
        "timing.mtime_unique_count",
    ] {
        paths.insert(format!("archive.{}", field));
    }
    // `chm.*` and `package_json.*` paths come from filefacts's
    // emission (no typed marker struct cleave-side).
    for field in [
        "chm.default_topic_missing",
        "chm.html_entry_count",
        "chm.max_user_entry_size",
        "chm.no_compiler_version",
        "chm.title_topic_mismatch",
        "chm.user_byte_ratio",
    ] {
        paths.insert(field.to_string());
    }

    // Image metrics (image.*, jpeg.*, png.*) flow through
    // `filefacts_metrics` rather than typed marker structs; field
    // validation accepts any of those paths.
    for field in [
        "image.width",
        "image.height",
        "image.channels",
        "image.pixel_entropy",
        "image.histogram_flatness",
        "image.edge_density",
        "image.r_entropy",
        "image.g_entropy",
        "image.b_entropy",
        "jpeg.appended_bytes",
        "jpeg.comment_bytes",
        "jpeg.exif_size",
        "png.bit_depth",
        "png.compression_ratio",
        "png.a_entropy",
    ] {
        paths.insert(field.to_string());
    }

    // Document/shortcut metrics
    // LNK whitespace/presence metrics live in filefacts's flat metric
    // map (`lnk.*` keys); no typed marker struct here.
    // PDF metrics similarly live in cleave's flat metric map under
    // `pdf.*` keys, populated by filefacts's `formats::pdf` extractor
    // and surfaced via `report.filefacts_metrics`.
    for field in [
        "lnk.args_leading_spaces",
        "lnk.args_leading_tabs",
        "lnk.args_max_whitespace_run",
        "lnk.args_whitespace_total",
        "pdf.action_count",
        "pdf.annotation_count",
        "pdf.annotations_per_page",
        "pdf.byte_range_count",
        "pdf.decoded_form_value_max_len",
        "pdf.duplicate_form_name_count",
        "pdf.duplicate_form_name_rect_count",
        "pdf.duplicate_form_rect_count",
        "pdf.embedded_file_count",
        "pdf.font_count",
        "pdf.form_field_count",
        "pdf.hidden_zero_rect_field_count",
        "pdf.jbig2_filter_count",
        "pdf.javascript_action_count",
        "pdf.leading_bytes_before_header",
        "pdf.metadata_count",
        "pdf.object_count",
        "pdf.object_stream_inner_object_count",
        "pdf.objstm_count",
        "pdf.overlapping_form_field_pair_count",
        "pdf.page_count",
        "pdf.risky_feature_score",
        "pdf.signature_object_count",
        "pdf.signed_incremental_update_count",
        "pdf.startxref_count",
        "pdf.stream_bad_delimiter_count",
        "pdf.stream_count",
        "pdf.stream_invalid_length_count",
        "pdf.stream_length_mismatch_count",
        "pdf.stream_missing_endstream_count",
        "pdf.stream_missing_length_count",
        "pdf.streams_with_unusual_filter_count",
        "pdf.three_d_object_count",
        "pdf.trailer_count",
        "pdf.trailing_bytes_after_eof",
        "pdf.unreferenced_object_count",
        "pdf.uri_action_count",
        "pdf.uri_actions_per_page",
        "pdf.visible_object_count",
        "pdf.xobject_count",
        "pdf.xref_stream_count",
    ] {
        paths.insert(field.to_string());
    }

    // Office metrics: cross-format fields plus per-container sub-structs.
    // Cross-format `office.*` fields flow through `filefacts_metrics`
    // (no typed `OfficeMetrics` struct after #41). Sub-structs
    // (`ole`, `ooxml`, `vba`, `xlm`) remain as internal data
    // carriers populated by analyzer parsers, then flattened into
    // `office.<sub>.<field>` via `flatten_into_metrics`.
    use super::office_metrics::{OleMetrics, OoxmlMetrics, VbaMetrics, XlmMetrics};
    // Cross-format `office.*` fields don't have a typed struct anymore;
    // trait validation accepts any `office.X` path that the analyzer
    // writes to `filefacts_metrics`.
    for field in [
        "office.dde_link_count",
        "office.doc_type",
        "office.embedded_executable_count",
        "office.external_frame_count",
        "office.external_image_count",
        "office.external_oleobject_count",
        "office.external_ref_count",
        "office.external_template_count",
        "office.has_macros",
        "office.is_encrypted",
        "office.is_macro_enabled_extension",
        "office.vba_module_count",
        "office.vba_source_size",
    ] {
        paths.insert(field.to_string());
    }
    for field in OleMetrics::valid_field_paths() {
        paths.insert(format!("office.ole.{}", field));
    }
    for field in OoxmlMetrics::valid_field_paths() {
        paths.insert(format!("office.ooxml.{}", field));
    }
    for field in VbaMetrics::valid_field_paths() {
        paths.insert(format!("office.vba.{}", field));
    }
    for field in XlmMetrics::valid_field_paths() {
        paths.insert(format!("office.xlm.{}", field));
    }

    // Composite scores
    for field in ObfuscationScore::valid_field_paths() {
        paths.insert(format!("obfuscation.{}", field));
    }
    for field in PackingScore::valid_field_paths() {
        paths.insert(format!("packing.{}", field));
    }
    for field in SupplyChainScore::valid_field_paths() {
        paths.insert(format!("supply_chain.{}", field));
    }

    paths
}

/// Returns a map of `"prefix.field"` → doc-comment description for every
/// known metric field.  Only fields with a non-empty doc comment are included.
#[must_use]
pub(crate) fn all_metric_descriptions() -> std::collections::HashMap<String, &'static str> {
    use super::field_paths::ValidFieldPaths;

    let mut map = std::collections::HashMap::new();

    macro_rules! add {
        ($prefix:expr, $ty:ty) => {
            for (field, desc) in <$ty>::field_descriptions() {
                if !desc.is_empty() {
                    map.insert(format!("{}.{}", $prefix, field), desc);
                }
            }
        };
    }

    use super::scores::{
        EncodedLanguageMetrics, EncodedMetrics, ObfuscationScore, PackingScore, SupplyChainScore,
    };

    // Source-text metric descriptions retired with the cleave→filefacts
    // migration. Trait-engine field descriptions for `text.*` /
    // `identifiers.*` / `strings.*` / `comments.*` / `functions.*` /
    // `imports.*` come from filefacts's emission, not from typed-struct
    // doc comments. The validation manifest is still maintained
    // above via the hardcoded `_METRIC_FIELDS` constants.
    add!("obfuscation", ObfuscationScore);
    add!("packing", PackingScore);
    add!("supply_chain", SupplyChainScore);

    // EncodedMetrics (skip nested struct fields, use sub-prefix for language variants)
    for (field, desc) in EncodedMetrics::field_descriptions() {
        if !desc.is_empty() && !matches!(field, "python" | "javascript" | "php" | "shell") {
            map.insert(format!("encoded.{}", field), desc);
        }
    }
    for lang in ["python", "javascript", "php", "shell"] {
        for (field, desc) in EncodedLanguageMetrics::field_descriptions() {
            if !desc.is_empty() {
                map.insert(format!("encoded.{}.{}", lang, field), desc);
            }
        }
    }

    // Image metrics (image.*, jpeg.*, png.*) live in
    // `filefacts_metrics` rather than typed marker structs.

    // LNK metrics live in filefacts; field descriptions for `lnk.*`
    // come from filefacts's emission rather than a typed struct here.

    // Office metrics
    // Cross-format `office.*` field descriptions retired with the
    // typed `OfficeMetrics` struct. Sub-struct descriptions stay.
    use super::office_metrics::{OleMetrics, OoxmlMetrics, VbaMetrics, XlmMetrics};
    add!("office.ole", OleMetrics);
    add!("office.ooxml", OoxmlMetrics);
    add!("office.vba", VbaMetrics);
    add!("office.xlm", XlmMetrics);

    map
}

/// Return every described field whose first doc-comment line falls
/// outside the 25–60 character target range, as `(path, len, first_line)`.
/// Shown as warnings in `cleave metrics` terminal output.
#[must_use]
pub(crate) fn metric_description_violations() -> Vec<(String, usize, String)> {
    let descs = all_metric_descriptions();
    let mut violations: Vec<(String, usize, String)> = descs
        .into_iter()
        .filter_map(|(path, desc)| {
            let first = desc
                .split('\n')
                .next()
                .unwrap_or(desc)
                .trim()
                .trim_end_matches(['.', ',', ';', ':'])
                .to_string();
            let len = first.len();
            if !(25..=60).contains(&len) {
                Some((path, len, first))
            } else {
                None
            }
        })
        .collect();
    violations.sort_by(|a, b| a.0.cmp(&b.0));
    violations
}
