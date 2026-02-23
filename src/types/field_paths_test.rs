//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Test for ValidFieldPaths derive macro

#[cfg(test)]
mod tests {
    use super::super::binary_metrics::BinaryMetrics;
    use super::super::field_paths::ValidFieldPaths;
    use super::super::text_metrics::TextMetrics;

    #[test]
    fn test_binary_metrics_field_paths() {
        let fields = BinaryMetrics::valid_field_paths();

        // Should include all public fields
        assert!(fields.contains(&"overall_entropy"));
        assert!(fields.contains(&"code_to_data_ratio"));
        assert!(fields.contains(&"string_count"));
        assert!(fields.contains(&"import_count"));
        assert!(fields.contains(&"function_count"));

        // Should have extracted many fields (BinaryMetrics has 50+ fields)
        assert!(
            fields.len() > 50,
            "Expected 50+ fields, got {}",
            fields.len()
        );
    }

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

        // Should contain paths with correct format
        assert!(paths.contains("binary.overall_entropy"));
        assert!(paths.contains("binary.code_to_data_ratio"));
        assert!(paths.contains("text.char_entropy"));
        assert!(paths.contains("text.total_lines"));

        // Should have hundreds of paths (all metrics combined)
        eprintln!("Total dynamic metric paths: {}", paths.len());
        assert!(
            paths.len() > 100,
            "Expected 100+ paths, got {}",
            paths.len()
        );
    }
}
