use super::{is_open_filefacts_metric_path, matches_metric_family};

/// Fixed keys are accepted by exact name, not because their namespace is
/// waved through. The second list is the point of the change: these are
/// real metric names from before the cleave→filefacts migration, and
/// under the old namespace exemption every one of them validated while
/// matching nothing.
#[test]
fn fixed_metric_keys_are_checked_by_name() {
    let valid = crate::types::field_paths::all_valid_metric_paths();
    for field in [
        "chm.user_entry_count",
        "archive.member_count",
        "image.width",
        "wasm.import_count",
        "registry.downloads_recent",
        "file.entropy",
    ] {
        assert!(valid.contains(field), "{field} should be a known metric");
    }

    for field in [
        "binary.overall_entropy",
        "text.total_lines",
        "strings.total",
        "pe.has_rich_header",
        "chmx.user_entry_count",
    ] {
        assert!(
            !valid.contains(field) && !is_open_filefacts_metric_path(field),
            "{field} is not emitted and must not validate"
        );
    }
}

/// Templated keys are matched by shape, one path segment per placeholder.
#[test]
fn templated_metric_keys_match_by_shape() {
    for field in [
        "ast.op.xor",
        "archive.compression.method_counts.deflate",
        "archive.format.regular_count",
        "consistency.extension_content_mismatch.binary_as_text",
        "source.query_limited.identifiers",
        "source.query_limited.identifiers.output_limit",
    ] {
        assert!(
            is_open_filefacts_metric_path(field),
            "{field} should match a family"
        );
    }

    // A placeholder covers one segment, so a template must not swallow a
    // longer path that has a template of its own — otherwise a typo in
    // the suffix would validate against the shorter form.
    assert!(!matches_metric_family(
        "source.query_limited.identifiers.output_limit",
        "source.query_limited.<query>"
    ));
    // An empty placeholder is not a value.
    assert!(!matches_metric_family("ast.op.", "ast.op.<operator>"));
    // Literal text around the placeholder still has to line up.
    assert!(!matches_metric_family("ast.ops.xor", "ast.op.<operator>"));
}
