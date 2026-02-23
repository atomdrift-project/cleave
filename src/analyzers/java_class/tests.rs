//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::analyzers::{java_class::JavaClassAnalyzer, Analyzer};
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
    // Real fixture tests - parsing
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
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/java"));
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
        let has_exec = report.findings.iter().any(|f| f.id.contains("exec"));
        assert!(
            has_exec,
            "Should detect exec capability. Findings: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_parse_class_file_from_bytes() {
        let fixture_path = Path::new("tests/fixtures/java/HelloWorld.class");
        if !fixture_path.exists() {
            return;
        }

        let data = std::fs::read(fixture_path).unwrap();
        let analyzer = JavaClassAnalyzer::new();
        let result = analyzer.parse_class_file(&data);

        assert!(
            result.is_ok(),
            "Failed to parse class file: {:?}",
            result.err()
        );
        let class_info = result.unwrap();

        // Should reference System class (for println) or PrintStream
        assert!(
            class_info
                .class_refs
                .iter()
                .any(|c| c.contains("System") || c.contains("PrintStream")),
            "Should reference System or PrintStream. Class refs: {:?}",
            class_info.class_refs
        );

        // Should reference Object (base class)
        assert!(
            class_info.class_refs.iter().any(|c| c.contains("Object")),
            "Should reference Object. Class refs: {:?}",
            class_info.class_refs
        );
    }

    #[test]
    fn test_parse_suspicious_class_detects_dangerous_refs() {
        let fixture_path = Path::new("tests/fixtures/java/Suspicious.class");
        if !fixture_path.exists() {
            return;
        }

        let data = std::fs::read(fixture_path).unwrap();
        let analyzer = JavaClassAnalyzer::new();
        let result = analyzer.parse_class_file(&data);

        assert!(result.is_ok());
        let class_info = result.unwrap();

        // Should detect Runtime class reference
        let has_runtime = class_info.class_refs.iter().any(|c| c.contains("Runtime"));
        assert!(
            has_runtime,
            "Should reference Runtime. Class refs: {:?}",
            class_info.class_refs
        );

        // Should detect ProcessBuilder class reference
        let has_processbuilder = class_info
            .class_refs
            .iter()
            .any(|c| c.contains("ProcessBuilder"));
        assert!(
            has_processbuilder,
            "Should reference ProcessBuilder. Class refs: {:?}",
            class_info.class_refs
        );

        // Should detect Socket class reference
        let has_socket = class_info.class_refs.iter().any(|c| c.contains("Socket"));
        assert!(
            has_socket,
            "Should reference Socket. Class refs: {:?}",
            class_info.class_refs
        );

        // Should detect Cipher class reference
        let has_cipher = class_info.class_refs.iter().any(|c| c.contains("Cipher"));
        assert!(
            has_cipher,
            "Should reference Cipher. Class refs: {:?}",
            class_info.class_refs
        );
    }

    #[test]
    fn test_parse_suspicious_class_extracts_strings() {
        let fixture_path = Path::new("tests/fixtures/java/Suspicious.class");
        if !fixture_path.exists() {
            return;
        }

        let data = std::fs::read(fixture_path).unwrap();
        let analyzer = JavaClassAnalyzer::new();
        let result = analyzer.parse_class_file(&data);

        assert!(result.is_ok());
        let class_info = result.unwrap();

        // Should extract suspicious strings
        let has_cmd = class_info.strings.iter().any(|s| s.contains("cmd.exe"));
        let has_url = class_info.strings.iter().any(|s| s.contains("http://"));
        let has_bash = class_info.strings.iter().any(|s| s.contains("/bin/bash"));

        assert!(
            has_cmd || has_url || has_bash,
            "Should extract suspicious strings. Strings: {:?}",
            class_info.strings
        );
    }

    #[test]
    fn test_parse_suspicious_class_extracts_class_names() {
        let fixture_path = Path::new("tests/fixtures/java/Suspicious.class");
        if !fixture_path.exists() {
            return;
        }

        let data = std::fs::read(fixture_path).unwrap();
        let analyzer = JavaClassAnalyzer::new();
        let result = analyzer.parse_class_file(&data);

        assert!(result.is_ok());
        let class_info = result.unwrap();

        // Should extract class name references from constant pool
        // The class file should reference the Suspicious class itself
        assert!(
            !class_info.class_refs.is_empty(),
            "Should have class references. Got: {:?}",
            class_info.class_refs
        );

        // Should have references to standard library classes
        let has_java_refs = class_info.class_refs.iter().any(|c| c.contains("java/"));
        assert!(
            has_java_refs,
            "Should reference java.* classes. Class refs: {:?}",
            class_info.class_refs
        );
    }

    // =============================================================================
    // Edge case tests
    // =============================================================================

    #[test]
    fn test_parse_invalid_magic() {
        let analyzer = JavaClassAnalyzer::new();
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("magic"));
    }

    #[test]
    fn test_parse_too_small() {
        let analyzer = JavaClassAnalyzer::new();
        let data = vec![0xCA, 0xFE, 0xBA, 0xBE];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_truncated_constant_pool() {
        let analyzer = JavaClassAnalyzer::new();
        // Valid magic + version but claims 100 pool entries with no data
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor version
            0x00, 0x34, // major version (Java 8)
            0x00, 0x64, // constant pool count = 100
        ];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_file() {
        let analyzer = JavaClassAnalyzer::new();
        let data: Vec<u8> = vec![];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_nonexistent_file() {
        let analyzer = JavaClassAnalyzer::new();
        let result = analyzer.analyze(Path::new("/nonexistent/path/Test.class"));
        assert!(result.is_err());
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
    // Additional edge case tests - Malformed inputs
    // =============================================================================

    #[test]
    fn test_parse_truncated_utf8_length() {
        let analyzer = JavaClassAnalyzer::new();
        // Valid magic, version, and pool count, but UTF8 entry with truncated length
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor version
            0x00, 0x34, // major version (Java 8)
            0x00, 0x02, // constant pool count = 2
            0x01, // tag = UTF8
            0x00, // truncated length (only 1 byte instead of 2)
        ];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Truncated"));
    }

    #[test]
    fn test_parse_truncated_utf8_data() {
        let analyzer = JavaClassAnalyzer::new();
        // UTF8 entry claims 100 bytes but data ends early
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor version
            0x00, 0x34, // major version (Java 8)
            0x00, 0x02, // constant pool count = 2
            0x01, // tag = UTF8
            0x00, 0x64, // length = 100
                  // but no actual data follows
        ];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_constant_pool_tag() {
        let analyzer = JavaClassAnalyzer::new();
        // Valid header but invalid constant pool tag
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor version
            0x00, 0x34, // major version (Java 8)
            0x00, 0x02, // constant pool count = 2
            0xFF, // invalid tag (255)
        ];

        let result = analyzer.parse_class_file(&data);
        // Should handle gracefully (either error or skip)
        // The important part is it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_parse_class_with_zero_constant_pool_count() {
        let analyzer = JavaClassAnalyzer::new();
        // Constant pool count of 0 is unusual (should be at least 1)
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor version
            0x00, 0x34, // major version (Java 8)
            0x00, 0x00, // constant pool count = 0 (unusual but handled)
        ];

        let result = analyzer.parse_class_file(&data);
        // Parser handles this case (will eventually fail on missing class info data)
        // The important thing is it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_parse_class_with_large_constant_pool_count() {
        let analyzer = JavaClassAnalyzer::new();
        // Claims 65535 constant pool entries
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor version
            0x00, 0x34, // major version (Java 8)
            0xFF, 0xFF, // constant pool count = 65535 (max u16)
        ];

        let result = analyzer.parse_class_file(&data);
        // Should error due to truncation
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_cafebabe_at_wrong_offset() {
        let analyzer = JavaClassAnalyzer::new();
        // CAFEBABE magic at wrong position
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // wrong magic
            0xCA, 0xFE, 0xBA, 0xBE, // CAFEBABE here doesn't count
            0x00, 0x00, // minor version
            0x00, 0x34, // major version
        ];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn test_parse_one_byte_file() {
        let analyzer = JavaClassAnalyzer::new();
        let data = vec![0xCA];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_only_magic() {
        let analyzer = JavaClassAnalyzer::new();
        let data = vec![0xCA, 0xFE, 0xBA, 0xBE];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_magic_plus_version() {
        let analyzer = JavaClassAnalyzer::new();
        // Magic + minor + major but nothing else
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor
            0x00, 0x34, // major
        ];

        let result = analyzer.parse_class_file(&data);
        assert!(result.is_err());
    }

    // =============================================================================
    // Property-based tests using proptest
    // =============================================================================

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_parse_never_panics_on_random_bytes(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let analyzer = JavaClassAnalyzer::new();
            // Should never panic, only return Ok or Err
            let _ = analyzer.parse_class_file(&data);
        }

        #[test]
        fn test_parse_never_panics_on_small_random_inputs(data in prop::collection::vec(any::<u8>(), 0..50)) {
            let analyzer = JavaClassAnalyzer::new();
            let _ = analyzer.parse_class_file(&data);
        }

        #[test]
        fn test_parse_never_panics_with_valid_magic(
            minor_version in any::<u16>(),
            major_version in any::<u16>(),
            rest in prop::collection::vec(any::<u8>(), 0..500)
        ) {
            let analyzer = JavaClassAnalyzer::new();
            let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE];
            data.extend_from_slice(&minor_version.to_be_bytes());
            data.extend_from_slice(&major_version.to_be_bytes());
            data.extend(rest);

            // Should never panic
            let _ = analyzer.parse_class_file(&data);
        }

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

    // =============================================================================
    // Constant pool parsing edge cases
    // =============================================================================

    #[test]
    fn test_parse_class_ref_out_of_bounds() {
        let analyzer = JavaClassAnalyzer::new();
        // Class entry referencing non-existent constant pool index
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor
            0x00, 0x34, // major
            0x00, 0x03, // pool count = 3
            0x01, // tag = UTF8
            0x00, 0x04, // length = 4
            b'T', b'e', b's', b't', // "Test"
            0x07, // tag = Class
            0xFF, 0xFF, // name index = 65535 (out of bounds)
        ];

        let result = analyzer.parse_class_file(&data);
        // Should handle gracefully
        let _ = result;
    }

    #[test]
    fn test_parse_multiple_long_and_double_entries() {
        let analyzer = JavaClassAnalyzer::new();
        // Long and Double take 2 constant pool slots
        let data = vec![
            0xCA, 0xFE, 0xBA, 0xBE, // magic
            0x00, 0x00, // minor
            0x00, 0x34, // major
            0x00, 0x05, // pool count = 5
            0x05, // tag = Long
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // value
            // Entry 2 is implicitly Empty (Long takes 2 slots)
            0x06, // tag = Double
            0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // value (1.0)
                  // Entry 4 is implicitly Empty
        ];

        let result = analyzer.parse_class_file(&data);
        // Should handle Long/Double which occupy 2 slots each
        let _ = result;
    }
}
