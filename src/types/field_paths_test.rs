//! Tests for the static field-path manifest.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
mod tests {

    #[test]
    fn test_text_metrics_field_paths_in_manifest() {
        // Text-side typed structs retired; the manifest is now a
        // hardcoded list inside `field_paths.rs`. Verify the canonical
        // `text.*` keys are still claimed.
        let paths = super::super::field_paths::all_valid_metric_paths();
        assert!(paths.contains("text.char_entropy"));
        assert!(paths.contains("text.lines"));
        assert!(paths.contains("text.avg_line_length"));
        assert!(paths.contains("text.whitespace_ratio"));
    }

    #[test]
    fn test_all_valid_metric_paths() {
        let paths = super::super::field_paths::all_valid_metric_paths();

        // Source-text paths come from filefacts' catalog, not from a manifest
        // maintained here.
        assert!(paths.contains("text.char_entropy"));
        assert!(paths.contains("text.lines"));

        // Binary-format paths are in the same set now. They used to be
        // exempted by namespace, which is how a renamed key kept validating.
        assert!(paths.contains("file.entropy"));
        assert!(paths.contains("pe.checksum"));

        // A floor well under the real count (filefacts alone declares 600+),
        // there to catch the catalog failing to load rather than to pin a
        // number that grows with every extractor.
        assert!(
            paths.len() > 500,
            "Expected 500+ paths, got {}",
            paths.len()
        );
    }

    #[test]
    fn print_metric_description_violations() {
        let v = super::super::field_paths::metric_description_violations();
        eprintln!("\n{} violations (outside 25–60 chars):", v.len());
        for (path, len, first) in &v {
            eprintln!("  [{len:>3}] {path}  \"{first}\"");
        }
    }
}
