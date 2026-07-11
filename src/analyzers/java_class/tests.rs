//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::analyzers::{Analyzer, java_class::JavaClassAnalyzer};
    use crate::types::{AnalysisReport, TargetInfo};
    use std::path::Path;

    // =============================================================================
    // Basic analyzer tests
    // =============================================================================

    #[test]
    fn test_can_analyze_class_extension() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("Test.class")));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("test.java")));
    }

    #[test]
    fn test_can_analyze_nested_class() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("Test$Inner.class")));
    }

    #[test]
    fn test_cannot_analyze_jar() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("test.jar")));
    }

    #[test]
    fn test_cannot_analyze_no_extension() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("testclass")));
    }

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

    // =============================================================================
    // Version mapping tests
    // =============================================================================

    #[test]
    fn test_major_version_mapping() {
        assert_eq!(JavaClassAnalyzer::major_to_java_version(52), "8");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(55), "11");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(61), "17");
    }

    #[test]
    fn test_major_version_mapping_java_1x() {
        assert_eq!(JavaClassAnalyzer::major_to_java_version(45), "1.1");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(46), "1.2");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(47), "1.3");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(48), "1.4");
    }

    #[test]
    fn test_major_version_mapping_java_5_7() {
        assert_eq!(JavaClassAnalyzer::major_to_java_version(49), "5");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(50), "6");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(51), "7");
    }

    #[test]
    fn test_major_version_mapping_java_9_21() {
        assert_eq!(JavaClassAnalyzer::major_to_java_version(53), "9");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(54), "10");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(56), "12");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(57), "13");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(58), "14");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(59), "15");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(60), "16");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(62), "18");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(63), "19");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(64), "20");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(65), "21");
    }

    #[test]
    fn test_major_version_mapping_future() {
        assert_eq!(JavaClassAnalyzer::major_to_java_version(66), "22");
        assert_eq!(JavaClassAnalyzer::major_to_java_version(70), "26");
    }

    // =============================================================================
    // End-to-end fixture tests
    //
    // Constant-pool parsing now lives in filefacts; these exercise the full
    // analyze() path (filefacts parse -> `class.class_refs`/`class.strings`
    // -> cleave capability heuristics).
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

        // Should detect execution/process capability (Runtime.exec, ProcessBuilder)
        // — sourced from filefacts `class.class_refs`.
        let has_exec = report.findings.iter().any(|f| f.id.contains("exec"));
        assert!(
            has_exec,
            "Should detect exec capability. Findings: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
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

    #[test]
    fn test_sig_stub_skips_capability_heuristics() {
        let analyzer = JavaClassAnalyzer::new();
        let class_refs = vec![
            "java/rmi/server/RMIClassLoader".to_string(),
            "javax/naming/ldap/StartTlsResponse".to_string(),
        ];
        let strings = vec![
            "DEFECTIVE_CREDENTIAL".to_string(),
            "shutdown.exe /s /t 0".to_string(),
        ];
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/tmp/fake/ct.sym/java.rmi/java/rmi/server/RMIClassLoader.sig".to_string(),
            file_type: "java_class".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });

        analyzer.detect_capabilities_from_facts(&class_refs, &strings, &mut report);

        assert!(
            report.findings.is_empty(),
            "signature stubs should not emit capabilities: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_demo_artifact_skips_system_control_strings() {
        let analyzer = JavaClassAnalyzer::new();
        let class_refs = vec!["java/lang/System".to_string()];
        let strings = vec!["shutDown".to_string()];
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/tmp/demo/jfc/J2Ddemo/java2d/J2Ddemo.class".to_string(),
            file_type: "java_class".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });

        analyzer.detect_capabilities_from_facts(&class_refs, &strings, &mut report);

        assert!(
            report.findings.iter().all(|f| f.id != "impact/control"),
            "demo artifacts should not emit impact/control: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_generic_keystroke_and_capture_strings_are_not_keyloggers() {
        let analyzer = JavaClassAnalyzer::new();
        let class_refs: Vec<String> = vec![];
        let strings = vec!["keyStroke".to_string(), "Keystroke: ".to_string()];
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/tmp/app/ShortcutManager.class".to_string(),
            file_type: "java_class".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });

        analyzer.detect_capabilities_from_facts(&class_refs, &strings, &mut report);

        assert!(
            report
                .findings
                .iter()
                .all(|f| f.id != "credential/keylogger"),
            "shortcut handling should not emit keylogger findings: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_browser_bypass_class_is_not_password_theft() {
        let analyzer = JavaClassAnalyzer::new();
        let class_refs: Vec<String> = vec![];
        let strings = vec!["Lcom/github/proxy/search/browser/ie/IELocalByPassFilter;".to_string()];
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/tmp/app/IELocalByPassFilter.class".to_string(),
            file_type: "java_class".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });

        analyzer.detect_capabilities_from_facts(&class_refs, &strings, &mut report);

        assert!(
            report
                .findings
                .iter()
                .all(|f| f.id != "credential/password"),
            "browser bypass class names should not emit password theft: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_upload_metadata_is_not_data_exfiltration() {
        let analyzer = JavaClassAnalyzer::new();
        let class_refs: Vec<String> = vec![];
        let strings = vec![
            "aws.s3.upload_id".to_string(),
            "AWS_S3_UPLOAD_ID".to_string(),
        ];
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/tmp/io/opentelemetry/semconv/AwsIncubatingAttributes.class".to_string(),
            file_type: "java_class".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });

        analyzer.detect_capabilities_from_facts(&class_refs, &strings, &mut report);

        assert!(
            report.findings.iter().all(|f| f.id != "exfiltration/data"),
            "upload metadata should not imply exfiltration: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_explicit_exfiltration_vocabulary_is_detected() {
        let analyzer = JavaClassAnalyzer::new();
        let class_refs: Vec<String> = vec![];
        let strings = vec!["exfiltrate collected data".to_string()];
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/tmp/app/Transfer.class".to_string(),
            file_type: "java_class".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });

        analyzer.detect_capabilities_from_facts(&class_refs, &strings, &mut report);

        assert!(
            report.findings.iter().any(|f| {
                f.id == "exfiltration/data" && f.desc == "Data exfiltration reference"
            }),
            "explicit exfiltration vocabulary should remain detected: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_static_dictionary_text_is_not_java_dropper() {
        let analyzer = JavaClassAnalyzer::new();
        let class_refs = vec![
            "java/lang/Object".to_string(),
            "java/lang/RuntimeException".to_string(),
            "java/lang/String".to_string(),
        ];
        let strings = vec![
            "Corrupted brotli dictionary".to_string(),
            "download featured football selected language distance execution context".to_string(),
        ];
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/tmp/org/brotli/dec/Dictionary.class".to_string(),
            file_type: "java_class".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });

        analyzer.detect_capabilities_from_facts(&class_refs, &strings, &mut report);

        assert!(
            report
                .findings
                .iter()
                .all(|f| f.id != "command-and-control/dropper"),
            "static dictionary text should not emit Java dropper findings: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    // =============================================================================
    // is_interesting_string tests
    // =============================================================================

    #[test]
    fn test_is_interesting_string_urls() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(analyzer.is_interesting_string("http://example.com"));
        assert!(analyzer.is_interesting_string("https://malware.com/payload"));
    }

    #[test]
    fn test_is_interesting_string_paths() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(analyzer.is_interesting_string("/bin/bash"));
        assert!(analyzer.is_interesting_string("C:\\Windows\\System32"));
    }

    #[test]
    fn test_is_interesting_string_executables() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(analyzer.is_interesting_string("malware.exe"));
        assert!(analyzer.is_interesting_string("payload.dll"));
        assert!(analyzer.is_interesting_string("dropper.jar"));
    }

    #[test]
    fn test_is_interesting_string_commands() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(analyzer.is_interesting_string("cmd.exe /c"));
        assert!(analyzer.is_interesting_string("powershell -enc"));
        assert!(analyzer.is_interesting_string("bash -c command"));
    }

    #[test]
    fn test_is_interesting_string_short_rejected() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(!analyzer.is_interesting_string("ab"));
        assert!(!analyzer.is_interesting_string("abc"));
    }

    #[test]
    fn test_is_interesting_string_descriptors_rejected() {
        let analyzer = JavaClassAnalyzer::new();
        assert!(!analyzer.is_interesting_string("()V"));
        assert!(!analyzer.is_interesting_string("(Ljava/lang/String;)I"));
        assert!(!analyzer.is_interesting_string("[Ljava/lang/Object;"));
    }

    // =============================================================================
    // Property-based tests
    // =============================================================================

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_is_interesting_string_never_panics(s in ".*") {
            let analyzer = JavaClassAnalyzer::new();
            // Should never panic on any string
            let _ = analyzer.is_interesting_string(&s);
        }

        #[test]
        fn test_can_analyze_never_panics(filename in ".*") {
            let analyzer = JavaClassAnalyzer::new();
            let path = Path::new(&filename);
            // Should never panic on any filename
            let _ = analyzer.can_analyze(path);
        }
    }
}
