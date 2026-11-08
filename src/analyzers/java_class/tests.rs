//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::analyzers::{AnalysisInput, Analyzer, FileType, java_class::JavaClassAnalyzer};
    use std::path::Path;

    // =============================================================================
    // Basic analyzer tests
    // =============================================================================

    #[test]
    fn test_analyze_projects_filefacts_imports() {
        let analyzer = JavaClassAnalyzer::new();
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/java/Suspicious.class"
        ));

        let report = analyzer.analyze(path).expect("analyze Java class fixture");
        let symbols: std::collections::BTreeSet<&str> =
            report.imports.iter().map(|i| i.symbol.as_str()).collect();

        assert!(
            symbols.contains("java/lang/Runtime.exec"),
            "Java bytecode method refs should be owner-qualified for trait matching"
        );
        assert!(
            symbols.contains("java/lang/ProcessBuilder.start"),
            "ProcessBuilder.start should be available to symbol traits"
        );
    }

    #[test]
    fn test_analyze_input_preserves_preextracted_strings() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/java/Suspicious.class"
        ));
        let data = std::fs::read(path).expect("read Java class fixture");
        let strings = [stng::ExtractedString::new(
            "java-text-regression-marker".to_string(),
            42,
            stng::StringMethod::RawScan,
        )];
        let input = AnalysisInput::with_strings(path, &data, &strings, FileType::JavaClass);

        let report = JavaClassAnalyzer::new()
            .analyze_input(&input)
            .expect("analyze Java class fixture");

        assert!(
            report
                .strings
                .iter()
                .any(|row| &*row.value == "java-text-regression-marker"),
            "Java analysis must retain AnalysisInput strings for text traits"
        );
    }

    // =============================================================================
    // Version mapping tests
    // =============================================================================

    #[test]
    fn test_analyze_hello_world_class() {
        let fixture_path = Path::new("tests/fixtures/java/HelloWorld.class");
        if !fixture_path.exists() {
            eprintln!("Skipping test: fixture not found at {:?}", fixture_path);
            return;
        }

        let analyzer = JavaClassAnalyzer::new();
        let result = analyzer.analyze(fixture_path);

        assert!(
            result.is_ok(),
            "Failed to analyze HelloWorld.class: {:?}",
            result.err()
        );
        let report = result.unwrap();

        assert_eq!(report.target.file_type, "java_class");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());

        // Should have Java bytecode structure
        assert!(
            report
                .structure
                .iter()
                .any(|s| s.id == "source/language/java")
        );
    }

    #[test]
    fn test_analyze_suspicious_class() {
        let fixture_path = Path::new("tests/fixtures/java/Suspicious.class");
        if !fixture_path.exists() {
            eprintln!("Skipping test: fixture not found at {:?}", fixture_path);
            return;
        }

        let analyzer = JavaClassAnalyzer::new();
        let result = analyzer.analyze(fixture_path);

        assert!(
            result.is_ok(),
            "Failed to analyze Suspicious.class: {:?}",
            result.err()
        );
        let report = result.unwrap();

        assert_eq!(report.target.file_type, "java_class");
    }

    #[test]
    fn test_analyze_nonexistent_file() {
        let analyzer = JavaClassAnalyzer::new();
        let result = analyzer.analyze(Path::new("/nonexistent/path/Test.class"));
        assert!(result.is_err());
    }

    // =============================================================================
    // Capability heuristic tests (over constant-pool facts)
    // =============================================================================
}
