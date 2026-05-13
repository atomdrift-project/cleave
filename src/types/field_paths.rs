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

    // Import all metrics types
    use super::binary_metrics::{
        BinaryMetrics, ElfMetrics, JavaClassMetrics, MachoMetrics, PeMetrics,
    };
    use super::container_metrics::{ArchiveMetrics, ChmMetrics, PackageJsonMetrics};
    use super::language_metrics::{
        CMetrics, CSharpMetrics, GoMetrics, JavaScriptMetrics, JavaSourceMetrics, LuaMetrics,
        PerlMetrics, PhpMetrics, PowerShellMetrics, PythonMetrics, RubyMetrics, RustMetrics,
        ShellMetrics,
    };
    use super::pdf_metrics::PdfMetrics;
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

    // Binary-specific metrics
    for field in BinaryMetrics::valid_field_paths() {
        paths.insert(format!("binary.{}", field));
    }
    for field in ElfMetrics::valid_field_paths() {
        paths.insert(format!("elf.{}", field));
    }
    for field in PeMetrics::valid_field_paths() {
        paths.insert(format!("pe.{}", field));
    }
    for field in MachoMetrics::valid_field_paths() {
        paths.insert(format!("macho.{}", field));
    }
    for field in JavaClassMetrics::valid_field_paths() {
        paths.insert(format!("java_class.{}", field));
    }

    // Container/Archive metrics
    for field in ArchiveMetrics::valid_field_paths() {
        paths.insert(format!("archive.{}", field));
    }
    for field in PackageJsonMetrics::valid_field_paths() {
        paths.insert(format!("package_json.{}", field));
    }
    for field in ChmMetrics::valid_field_paths() {
        paths.insert(format!("chm.{}", field));
    }

    // Image metrics (shared across PNG and JPEG)
    use super::image_metrics::ImageMetrics;
    for field in ImageMetrics::valid_field_paths() {
        paths.insert(format!("image.{}", field));
    }

    // Format-specific image metrics
    use super::jpeg_metrics::JpegMetrics;
    use super::png_metrics::PngMetrics;
    for field in PngMetrics::valid_field_paths() {
        paths.insert(format!("png.{}", field));
    }
    for field in JpegMetrics::valid_field_paths() {
        paths.insert(format!("jpeg.{}", field));
    }

    // Document/shortcut metrics
    use super::lnk_metrics::LnkMetrics;
    for field in LnkMetrics::valid_field_paths() {
        paths.insert(format!("lnk.{}", field));
    }
    for field in PdfMetrics::valid_field_paths() {
        paths.insert(format!("pdf.{}", field));
    }

    // Office metrics: cross-format fields plus per-container sub-structs.
    // Sub-structs (`ole`, `ooxml`, `vba`, `xlm`) are flattened so a trait can
    // write `field: office.xlm.char_count` directly, mirroring how `binary.*`
    // and the language-specific metrics expose their fields.
    use super::office_metrics::{OfficeMetrics, OleMetrics, OoxmlMetrics, VbaMetrics, XlmMetrics};
    for field in OfficeMetrics::valid_field_paths() {
        // Skip the four nested-struct field names; they're not numeric and
        // are exposed as `office.<sub>.<field>` instead.
        if !matches!(field, "ole" | "ooxml" | "vba" | "xlm") {
            paths.insert(format!("office.{}", field));
        }
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

    use super::binary_metrics::{
        BinaryMetrics, ElfMetrics, JavaClassMetrics, MachoMetrics, PeMetrics,
    };
    use super::container_metrics::{ArchiveMetrics, ChmMetrics, PackageJsonMetrics};
    use super::language_metrics::{
        CMetrics, CSharpMetrics, GoMetrics, JavaScriptMetrics, JavaSourceMetrics, LuaMetrics,
        PerlMetrics, PhpMetrics, PowerShellMetrics, PythonMetrics, RubyMetrics, RustMetrics,
        ShellMetrics,
    };
    use super::pdf_metrics::PdfMetrics;
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
    add!("binary", BinaryMetrics);
    add!("elf", ElfMetrics);
    add!("pe", PeMetrics);
    add!("macho", MachoMetrics);
    add!("java_class", JavaClassMetrics);
    add!("archive", ArchiveMetrics);
    add!("package_json", PackageJsonMetrics);
    add!("chm", ChmMetrics);
    add!("pdf", PdfMetrics);
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

    // Image metrics
    use super::image_metrics::ImageMetrics;
    use super::jpeg_metrics::JpegMetrics;
    use super::png_metrics::PngMetrics;
    add!("image", ImageMetrics);
    add!("png", PngMetrics);
    add!("jpeg", JpegMetrics);

    // LNK / Office
    use super::lnk_metrics::LnkMetrics;
    add!("lnk", LnkMetrics);

    use super::office_metrics::{OfficeMetrics, OleMetrics, OoxmlMetrics, VbaMetrics, XlmMetrics};
    for (field, desc) in OfficeMetrics::field_descriptions() {
        if !desc.is_empty() && !matches!(field, "ole" | "ooxml" | "vba" | "xlm") {
            map.insert(format!("office.{}", field), desc);
        }
    }
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
