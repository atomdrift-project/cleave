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

// The metric surface is no longer described here. filefacts declares every
// key it emits at the emission site and enumerates them through
// `known_metrics()`; cleave declares only the metrics its own analyzers
// compute. The lists that used to live here were a hand-maintained copy of
// filefacts' emitters, and a copy is exactly what drifts.

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

    // Everything filefacts can emit, declared at its emission sites and
    // enumerated through `known_metrics()`. This used to be a hand-copied
    // manifest here, which drifted the moment filefacts renamed a key: the
    // rule still validated and simply stopped matching. filefacts now fails
    // its own build on an undeclared key, so this list is derived, not
    // maintained. Templated keys (`ast.op.<operator>`) are matched
    // separately, by shape.
    let (catalog, _families) = filefacts::known_metrics();
    for field in catalog {
        paths.insert((*field).to_string());
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

    // Format-specific metrics — `archive.*`, `binary.*`, `pe.*`, `elf.*`,
    // `macho.*`, `chm.*`, `image.*`, `pdf.*`, `lnk.*`, the cross-format
    // `office.*` fields — all come from the filefacts catalog above. They
    // were once re-listed here by hand, or waved through by namespace, which
    // is how a batch of renamed keys stayed "valid" while matching nothing.

    // Office metrics: cross-format fields plus per-container sub-structs.
    // Cross-format `office.*` fields flow through `filefacts_metrics`
    // (no typed `OfficeMetrics` struct after #41). Sub-structs
    // (`ole`, `ooxml`, `vba`, `xlm`) remain as internal data
    // carriers populated by analyzer parsers, then flattened into
    // `office.<sub>.<field>` via `flatten_into_metrics`.
    use super::office_metrics::{OleMetrics, OoxmlMetrics, VbaMetrics, XlmMetrics};
    // Cross-format `office.*` fields have no typed struct: cleave's office
    // analyzer writes them straight into `filefacts_metrics`, so this is
    // their declaration.
    for field in [
        "office.dde_link_count",
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

    // Cross-field metrics cleave computes itself, after filefacts has run,
    // and writes into `filefacts_metrics` by name. filefacts cannot declare
    // these because it never sees them; declaring them here is what keeps
    // them inside the same check as everything else.
    for field in CLEAVE_OWNED_METRIC_FIELDS {
        paths.insert((*field).to_string());
    }

    paths
}

/// Metrics cleave's own analyzers still write into the flat map.
///
/// This list is a migration backlog, not a home. Measurement belongs in
/// filefacts, where a key is declared at its emission site and the build
/// fails if it is not; a metric computed here is outside that guarantee and
/// can be renamed or dropped without anything noticing. Every entry should
/// either move to a filefacts extractor or justify why cleave is the only
/// place it can be computed.
///
/// What is left has to justify itself against one test: could filefacts
/// compute it from a single file's bytes? `consistency.name_repo_mismatch`
/// and `consistency.publisher_repo_owner_mismatch` could — both only compare
/// two claims the same `package.json` makes — so they moved to
/// `filefacts::formats::npm`, which is where that manifest is parsed. The
/// remaining entries genuinely cannot: `unused_runtime_deps` needs every
/// shipped module's imports beside the manifest, `vsix.*` needs the manifest
/// as a member of a container filefacts does not crack, and `references.*` is
/// the outcome of a network fetch. The `binary.*` / `pe.*` entries have no
/// such excuse — they are per-file measurements sitting on the wrong side of
/// the boundary.
pub(crate) const CLEAVE_OWNED_METRIC_FIELDS: &[&str] = &[
    // Needs every shipped module's imports beside the manifest, so no
    // single-file parse can reach it.
    "consistency.unused_runtime_deps",
    "consistency.self_dependency",
    "vsix.extension_pack_self_entries",
    "vsix.extension_pack_size",
    // Written by scan's follow phase (`attribute_reference_outcomes`), which
    // attributes each fetch outcome back to the file that declared it. Neither
    // filefacts nor cleave can compute these — only a run that actually
    // followed the references knows how they resolved — but they land in the
    // same `filefacts_metrics` map, so this is where they have to be declared
    // to stay inside the check. Absent entirely on an offline scan.
    "references.declared_count",
    "references.unresolved_count",
    "references.unresolved_extension_count",
    // How many of a file's declared dependencies resolved to a registry
    // security hold — the provider's statement that it removed the package.
    // Counted from the registry documents a follow materializes, which is a
    // different path from the fetch records the two counts above come from: a
    // dependency can resolve without a live download and still have a record.
    "references.security_hold_count",
    // Per-file measurements that should move into filefacts.
    "binary.embedded_binaries",
    "pe.directory_section_mismatch_count",
    "pe.executable_prose_section_count",
    "pe.headers_size",
    "pe.headers_size_ratio",
    "pe.prose_section_count",
];

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
