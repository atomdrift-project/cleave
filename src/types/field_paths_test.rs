//! Tests for the static field-path manifest.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
mod tests {
    use super::super::field_paths::ValidFieldPaths;
    use super::super::text_metrics::TextMetrics;

    #[test]
    fn test_text_metrics_field_paths() {
        let fields = TextMetrics::valid_field_paths();

        // Should include all public fields
        assert!(fields.contains(&"char_entropy"));
        assert!(fields.contains(&"total_lines"));
        assert!(fields.contains(&"avg_line_length"));
        assert!(fields.contains(&"whitespace_ratio"));

        // Should have extracted many fields
        assert!(
            fields.len() > 20,
            "Expected 20+ fields, got {}",
            fields.len()
        );
    }

    #[test]
    fn test_all_valid_metric_paths() {
        let paths = super::super::field_paths::all_valid_metric_paths();

        // Text-side paths still come from the typed manifest.
        assert!(paths.contains("text.char_entropy"));
        assert!(paths.contains("text.total_lines"));

        // Should have many paths (text + container + language + score
        // manifests still contribute even after the binary-format
        // projections retired).
        assert!(
            paths.len() > 50,
            "Expected 50+ paths, got {}",
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
