//! Dynamic field path validation for metrics
//!
//! Provides a trait-based system for validating metric field references in YAML rules
//! without hardcoding field names.

#[cfg(feature = "lint")]
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

// filefacts declares every metric key it emits at the emission site and
// enumerates them through `known_metrics()`; cleave declares only the
// metrics its own analyzers compute. Keeping no copy here means nothing can
// drift.

/// Returns all valid metric field paths for use in YAML rules
/// Returns paths like "binary.code_to_data_ratio", "text.line_count", etc.
#[must_use]
#[cfg(feature = "lint")]
pub(crate) fn all_valid_metric_paths() -> HashSet<String> {
    // Import the trait to access its methods
    use super::field_paths::ValidFieldPaths;

    let mut paths = HashSet::new();

    use super::scores::{ObfuscationScore, PackingScore, SupplyChainScore};

    // Everything filefacts can emit, declared at its emission sites and
    // enumerated through `known_metrics()`. A hand-copied manifest would
    // drift the moment filefacts renamed a key: the rule would still
    // validate and simply stop matching. filefacts fails
    // its own build on an undeclared key, so this list is derived, not
    // maintained. Templated keys (`ast.op.<operator>`) are matched
    // separately, by shape.
    let (catalog, _families) = filefacts::known_metrics();
    for field in catalog {
        paths.insert((*field).to_string());
    }

    // Per-language metric structs (PythonMetrics / JavaScriptMetrics /
    // …) retired with the cleave→filefacts migration. No production code
    // ever emitted them — the surface is gone.

    // Format-specific metrics — `archive.*`, `binary.*`, `pe.*`, `elf.*`,
    // `macho.*`, `chm.*`, `image.*`, `pdf.*`, `lnk.*`, the cross-format
    // `office.*` fields — all come from the filefacts catalog above. They
    // were once re-listed here by hand, or waved through by namespace, which
    // is how a batch of renamed keys stayed "valid" while matching nothing.

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
/// shipped module's imports beside the manifest, `references.*` is the
/// outcome of a network fetch, `archive.guard.*` is what extraction
/// observed, and `strings.*` reports cleave's own retention caps.
#[cfg(feature = "lint")]
pub(crate) const CLEAVE_OWNED_METRIC_FIELDS: &[&str] = &[
    // Needs every shipped module's imports beside the manifest, so no
    // single-file parse can reach it.
    "consistency.unused_runtime_deps",
    // Written by scan's follow phase (`attribute_reference_outcomes`), which
    // attributes each fetch outcome back to the file that declared it. Neither
    // filefacts nor cleave can compute these — only a run that actually
    // followed the references knows how they resolved — but they land in the
    // same `filefacts_metrics` map, so this is where they have to be declared
    // to stay inside the check. Absent entirely on an offline scan.
    "references.declared_count",
    "references.undeclared_import_count",
    "references.unresolved_count",
    "references.unavailable_command_count",
    "references.unresolved_extension_count",
    // How many of a file's declared dependencies resolved to a registry
    // security hold — the provider's statement that it removed the package.
    // Counted from the registry documents a follow materializes, which is a
    // different path from the fetch records the two counts above come from: a
    // dependency can resolve without a live download and still have a record.
    "references.security_hold_count",
    // What cleave's extraction guards observed while unpacking (see
    // `archive::findings::push_archive_hostile_findings`): outcomes of
    // extraction, which only the extractor can report.
    "archive.guard.compression_ratio",
    "archive.guard.longest_entry_name",
    "archive.guard.member_limit_reached",
    "archive.guard.path_traversal_count",
    "archive.guard.total_size",
    // Cleave's own string-retention policy: filefacts offers every text row,
    // cleave's per-file caps decide what rules search. Only the side that
    // applies the cap can say how many rows it dropped.
    "strings.extracted_count",
    "strings.retained_count",
    "strings.truncated",
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

    use super::scores::{ObfuscationScore, PackingScore, SupplyChainScore};

    // Source-text metric descriptions retired with the cleave→filefacts
    // migration. Trait-engine field descriptions for `text.*` /
    // `identifiers.*` / `strings.*` / `comments.*` / `functions.*` /
    // `imports.*` come from filefacts's emission, not from typed-struct
    // doc comments. The validation manifest is still maintained
    // above via the hardcoded `_METRIC_FIELDS` constants.
    add!("obfuscation", ObfuscationScore);
    add!("packing", PackingScore);
    add!("supply_chain", SupplyChainScore);

    // Image metrics (image.*, jpeg.*, png.*) live in
    // `filefacts_metrics` rather than typed marker structs.

    // LNK metrics live in filefacts; field descriptions for `lnk.*`
    // come from filefacts's emission rather than a typed struct here.

    // Office metrics (`office.*`) come from filefacts, described where it
    // emits them.

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
