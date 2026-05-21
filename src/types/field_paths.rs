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

/// Returns all valid metric field paths for use in YAML rules
/// Returns paths like "binary.code_to_data_ratio", "text.line_count", etc.
#[must_use]
pub(crate) fn all_valid_metric_paths() -> HashSet<String> {
    // Import the trait to access its methods
    use super::field_paths::ValidFieldPaths;

    let mut paths = HashSet::new();

    // Import surviving manifest types
    use super::container_metrics::ArchiveMetrics;
    use super::language_metrics::{
        CMetrics, CSharpMetrics, GoMetrics, JavaScriptMetrics, JavaSourceMetrics, LuaMetrics,
        PerlMetrics, PhpMetrics, PowerShellMetrics, PythonMetrics, RubyMetrics, RustMetrics,
        ShellMetrics,
    };
    use super::scores::{
        EncodedLanguageMetrics, EncodedMetrics, ObfuscationScore, PackingScore, SupplyChainScore,
    };
    use super::text_metrics::{
        CommentMetrics, FunctionMetrics, IdentifierMetrics, ImportMetrics, StatementMetrics,
        StringMetrics, TextMetrics,
    };

    // Add paths for each metrics section
    for field in TextMetrics::valid_field_paths() {
        paths.insert(format!("text.{}", field));
    }
    for field in IdentifierMetrics::valid_field_paths() {
        paths.insert(format!("identifiers.{}", field));
    }
    for field in StringMetrics::valid_field_paths() {
        paths.insert(format!("strings.{}", field));
    }
    for field in CommentMetrics::valid_field_paths() {
        paths.insert(format!("comments.{}", field));
    }
    for field in FunctionMetrics::valid_field_paths() {
        paths.insert(format!("functions.{}", field));
    }
    for field in StatementMetrics::valid_field_paths() {
        paths.insert(format!("statements.{}", field));
    }
    for field in ImportMetrics::valid_field_paths() {
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

    // Language-specific metrics
    for field in PythonMetrics::valid_field_paths() {
        paths.insert(format!("python.{}", field));
    }
    for field in JavaScriptMetrics::valid_field_paths() {
        paths.insert(format!("javascript.{}", field));
    }
    for field in PowerShellMetrics::valid_field_paths() {
        paths.insert(format!("powershell.{}", field));
    }
    for field in ShellMetrics::valid_field_paths() {
        paths.insert(format!("shell.{}", field));
    }
    for field in PhpMetrics::valid_field_paths() {
        paths.insert(format!("php.{}", field));
    }
    for field in RubyMetrics::valid_field_paths() {
        paths.insert(format!("ruby.{}", field));
    }
    for field in PerlMetrics::valid_field_paths() {
        paths.insert(format!("perl.{}", field));
    }
    for field in GoMetrics::valid_field_paths() {
        paths.insert(format!("go_metrics.{}", field));
    }
    for field in RustMetrics::valid_field_paths() {
        paths.insert(format!("rust_metrics.{}", field));
    }
    for field in CMetrics::valid_field_paths() {
        paths.insert(format!("c_metrics.{}", field));
    }
    for field in JavaSourceMetrics::valid_field_paths() {
        paths.insert(format!("java.{}", field));
    }
    for field in LuaMetrics::valid_field_paths() {
        paths.insert(format!("lua.{}", field));
    }
    for field in CSharpMetrics::valid_field_paths() {
        paths.insert(format!("csharp.{}", field));
    }

    // Binary-format metrics (`binary.*`, `pe.*`, `elf.*`, `macho.*`,
    // `java_class.*`) live exclusively in expose's flat metric map —
    // trait validation accepts any path under those namespaces.

    // Container/Archive metrics
    // `archive.*` flows through expose_metrics via flattened
    // `ArchiveMetrics`. The struct's field set still acts as the
    // canonical path manifest.
    for field in ArchiveMetrics::valid_field_paths() {
        paths.insert(format!("archive.{}", field));
    }
    // `chm.*` and `package_json.*` paths come from expose's
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
    // `expose_metrics` rather than typed marker structs; field
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
    // LNK whitespace/presence metrics live in expose's flat metric
    // map (`lnk.*` keys); no typed marker struct here.
    // PDF metrics similarly live in cleave's flat metric map under
    // `pdf.*` keys, populated by `analyzers::pdf::pdf_kv::populate_pdf_metrics`.
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
    // Cross-format `office.*` fields flow through `expose_metrics`
    // (no typed `OfficeMetrics` struct after #41). Sub-structs
    // (`ole`, `ooxml`, `vba`, `xlm`) remain as internal data
    // carriers populated by analyzer parsers, then flattened into
    // `office.<sub>.<field>` via `flatten_into_metrics`.
    use super::office_metrics::{OleMetrics, OoxmlMetrics, VbaMetrics, XlmMetrics};
    // Cross-format `office.*` fields don't have a typed struct anymore;
    // trait validation accepts any `office.X` path that the analyzer
    // writes to `expose_metrics`.
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

    use super::container_metrics::ArchiveMetrics;
    use super::language_metrics::{
        CMetrics, CSharpMetrics, GoMetrics, JavaScriptMetrics, JavaSourceMetrics, LuaMetrics,
        PerlMetrics, PhpMetrics, PowerShellMetrics, PythonMetrics, RubyMetrics, RustMetrics,
        ShellMetrics,
    };
    use super::scores::{
        EncodedLanguageMetrics, EncodedMetrics, ObfuscationScore, PackingScore, SupplyChainScore,
    };
    use super::text_metrics::{
        CommentMetrics, FunctionMetrics, IdentifierMetrics, ImportMetrics, StatementMetrics,
        StringMetrics, TextMetrics,
    };

    add!("text", TextMetrics);
    add!("identifiers", IdentifierMetrics);
    add!("strings", StringMetrics);
    add!("comments", CommentMetrics);
    add!("functions", FunctionMetrics);
    add!("statements", StatementMetrics);
    add!("imports", ImportMetrics);
    // Binary-format metric descriptions live in expose now; the
    // typed `*Metrics` projection structs that supplied them retired.
    add!("archive", ArchiveMetrics);
    // chm and package_json descriptions retired (typed structs gone).
    // PDF descriptions live in expose's emission rather than a typed
    // marker struct.
    add!("python", PythonMetrics);
    add!("javascript", JavaScriptMetrics);
    add!("powershell", PowerShellMetrics);
    add!("shell", ShellMetrics);
    add!("php", PhpMetrics);
    add!("ruby", RubyMetrics);
    add!("perl", PerlMetrics);
    add!("go_metrics", GoMetrics);
    add!("rust_metrics", RustMetrics);
    add!("c_metrics", CMetrics);
    add!("java", JavaSourceMetrics);
    add!("lua", LuaMetrics);
    add!("csharp", CSharpMetrics);
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
    // `expose_metrics` rather than typed marker structs.

    // LNK metrics live in expose; field descriptions for `lnk.*`
    // come from expose's emission rather than a typed struct here.

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
