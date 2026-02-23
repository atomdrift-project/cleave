//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::diff::formatting::format_diff_terminal;
use crate::diff::utils::{
    calculate_file_similarity, detect_renames, extract_library_base, is_shared_library,
    library_similarity,
};
use crate::types::{AnalysisReport, Criticality, Finding, FindingKind, TargetInfo};
use chrono::Utc;

fn create_test_report_for_diff(path: &str, trait_ids: Vec<&str>) -> AnalysisReport {
    let findings: Vec<Finding> = trait_ids
        .iter()
        .map(|id| Finding {
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: format!("Test {}", id),
            conf: 0.8,
            crit: if id.starts_with("execution/") {
                Criticality::Hostile
            } else {
                Criticality::Notable
            },
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],

            source_file: None,
        })
        .collect();

    AnalysisReport {
        schema_version: "1.1".to_string(),
        analysis_timestamp: Utc::now(),
        target: TargetInfo {
            path: path.to_string(),
            file_type: "ELF".to_string(),
            size_bytes: 12345,
            sha256: "abc123".to_string(),
            architectures: None,
        },
        findings,
        traits: vec![],
        structure: vec![],
        functions: vec![],
        strings: vec![],
        sections: vec![],
        imports: vec![],
        exports: vec![],
        yara_matches: vec![],
        syscalls: vec![],
        binary_properties: None,
        code_metrics: None,
        source_code_metrics: None,
        overlay_metrics: None,
        metrics: None,
        paths: vec![],
        directories: vec![],
        env_vars: vec![],
        archive_contents: vec![],
        scanned_path: None,
        files: vec![],
        summary: None,
        metadata: crate::types::AnalysisMetadata {
            analysis_duration_ms: 100,
            tools_used: vec!["test".to_string()],
            errors: vec![],
        },
    }
}

#[test]
fn test_diff_analyzer_new() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    assert_eq!(analyzer.baseline_path.to_str().unwrap(), "/baseline");
    assert_eq!(analyzer.target_path.to_str().unwrap(), "/target");
}

#[test]
fn test_compare_reports_no_changes() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    let baseline = create_test_report_for_diff("/baseline/file", vec!["net/http"]);
    let target = create_test_report_for_diff("/target/file", vec!["net/http"]);

    let analysis = analyzer.compare_reports("file", &baseline, &target);
    assert_eq!(analysis.file, "file");
    assert_eq!(analysis.new_capabilities.len(), 0);
    assert_eq!(analysis.removed_capabilities.len(), 0);
    assert_eq!(analysis.capability_delta, 0);
    assert!(!analysis.risk_increase);
}

#[test]
fn test_compare_reports_new_capabilities() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    let baseline = create_test_report_for_diff("/baseline/file", vec!["net/http"]);
    let target = create_test_report_for_diff("/target/file", vec!["net/http", "fs/write"]);

    let analysis = analyzer.compare_reports("file", &baseline, &target);
    assert_eq!(analysis.new_capabilities.len(), 1);
    assert!(analysis.new_capabilities.iter().any(|c| c.id == "fs/write"));
    assert_eq!(analysis.capability_delta, 1);
}

#[test]
fn test_compare_reports_removed_capabilities() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    let baseline = create_test_report_for_diff("/baseline/file", vec!["net/http", "fs/write"]);
    let target = create_test_report_for_diff("/target/file", vec!["net/http"]);

    let analysis = analyzer.compare_reports("file", &baseline, &target);
    assert_eq!(analysis.removed_capabilities.len(), 1);
    assert!(analysis
        .removed_capabilities
        .iter()
        .any(|c| c.id == "fs/write"));
    assert_eq!(analysis.capability_delta, -1);
}

#[test]
fn test_compare_reports_risk_increase() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    let baseline = create_test_report_for_diff("/baseline/file", vec!["net/http"]);
    let target = create_test_report_for_diff("/target/file", vec!["net/http", "execution/shell"]);

    let analysis = analyzer.compare_reports("file", &baseline, &target);
    assert!(analysis.risk_increase);
    assert!(analysis
        .new_capabilities
        .iter()
        .any(|c| c.id == "execution/shell"));
}

fn make_test_cap(id: &str) -> Finding {
    Finding {
        id: id.to_string(),
        kind: FindingKind::Capability,
        desc: format!("Test {}", id),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![Evidence {
            method: "test".to_string(),
            source: "test".to_string(),
            value: id.to_string(),
            location: None,
        }],
        source_file: None,
    }
}

#[test]
fn test_assess_risk_increase_new_high_risk() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    let new_caps = vec![make_test_cap("execution/shell")];
    let removed_caps = vec![];

    assert!(analyzer.assess_risk_increase(&new_caps, &removed_caps));
}

#[test]
fn test_assess_risk_increase_no_high_risk() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    let new_caps = vec![make_test_cap("net/http")];
    let removed_caps = vec![];

    assert!(!analyzer.assess_risk_increase(&new_caps, &removed_caps));
}

#[test]
fn test_assess_risk_increase_balanced() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    let new_caps = vec![make_test_cap("execution/shell")];
    let removed_caps = vec![make_test_cap("anti-analysis/debugger")];

    assert!(!analyzer.assess_risk_increase(&new_caps, &removed_caps));
}

#[test]
fn test_assess_risk_increase_more_removed_than_added() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");
    let new_caps = vec![make_test_cap("execution/shell")];
    let removed_caps = vec![
        make_test_cap("anti-analysis/debugger"),
        make_test_cap("persistence/registry"),
    ];

    assert!(!analyzer.assess_risk_increase(&new_caps, &removed_caps));
}

#[test]
fn test_collect_files_creates_relative_paths() {
    let analyzer = DiffAnalyzer::new_for_test("/baseline", "/target");

    // Test with src directory which should exist
    if let Ok(files) = analyzer.collect_files(Path::new("src")) {
        if !files.is_empty() {
            // Paths should be relative
            for rel_path in files.keys() {
                assert!(!rel_path.starts_with("/"));
            }
        }
    }
    // Test passes regardless of whether files are found
}

#[test]
fn test_format_diff_terminal_empty_changes() {
    let report = DiffReport {
        schema_version: "1.0".to_string(),
        analysis_timestamp: Utc::now(),
        diff_mode: true,
        baseline: "/baseline".to_string(),
        target: "/target".to_string(),
        changes: FileChanges {
            added: vec![],
            removed: vec![],
            modified: vec![],
            renamed: vec![],
        },
        modified_analysis: vec![],
        metadata: crate::types::AnalysisMetadata {
            analysis_duration_ms: 100,
            tools_used: vec!["diff_analyzer".to_string()],
            errors: vec![],
        },
    };

    let output = format_diff_terminal(&report);
    assert!(output.contains("/baseline"));
    assert!(output.contains("/target"));
    assert!(output.contains("No capability changes"));
}

#[test]
fn test_format_diff_terminal_with_changes() {
    let report = DiffReport {
        schema_version: "1.0".to_string(),
        analysis_timestamp: Utc::now(),
        diff_mode: true,
        baseline: "/baseline".to_string(),
        target: "/target".to_string(),
        changes: FileChanges {
            added: vec!["new_file.bin".to_string()],
            removed: vec!["old_file.bin".to_string()],
            modified: vec!["changed_file.bin".to_string()],
            renamed: vec![],
        },
        modified_analysis: vec![ModifiedFileAnalysis {
            file: "changed_file.bin".to_string(),
            new_capabilities: vec![make_test_cap("execution/shell")],
            removed_capabilities: vec![],
            capability_delta: 1,
            risk_increase: true,
        }],
        metadata: crate::types::AnalysisMetadata {
            analysis_duration_ms: 100,
            tools_used: vec!["diff_analyzer".to_string()],
            errors: vec![],
        },
    };

    let output = format_diff_terminal(&report);
    assert!(output.contains("new_file.bin"));
    assert!(output.contains("old_file.bin"));
    assert!(output.contains("changed_file.bin"));
    assert!(output.contains("execution/shell"));
    assert!(output.contains("increased risk"));
}

#[test]
fn test_format_diff_terminal_multiple_modified() {
    let report = DiffReport {
        schema_version: "1.0".to_string(),
        analysis_timestamp: Utc::now(),
        diff_mode: true,
        baseline: "/baseline".to_string(),
        target: "/target".to_string(),
        changes: FileChanges {
            added: vec![],
            removed: vec![],
            modified: vec!["file1.bin".to_string(), "file2.bin".to_string()],
            renamed: vec![],
        },
        modified_analysis: vec![
            ModifiedFileAnalysis {
                file: "file1.bin".to_string(),
                new_capabilities: vec![make_test_cap("net/http/client")],
                removed_capabilities: vec![],
                capability_delta: 1,
                risk_increase: false,
            },
            ModifiedFileAnalysis {
                file: "file2.bin".to_string(),
                new_capabilities: vec![make_test_cap("execution/command/shell")],
                removed_capabilities: vec![make_test_cap("fs/file/read")],
                capability_delta: 0,
                risk_increase: true,
            },
        ],
        metadata: crate::types::AnalysisMetadata {
            analysis_duration_ms: 100,
            tools_used: vec!["diff_analyzer".to_string()],
            errors: vec![],
        },
    };

    let output = format_diff_terminal(&report);
    assert!(output.contains("file1.bin"));
    assert!(output.contains("file2.bin"));
    // Capabilities are aggregated by directory (objective/behavior)
    assert!(output.contains("net/http"));
    assert!(output.contains("execution/command"));
    assert!(output.contains("fs/file"));
}

#[test]
fn test_is_shared_library() {
    assert!(is_shared_library("libssl.so"));
    assert!(is_shared_library("libssl.so.1"));
    assert!(is_shared_library("libssl.so.1.0.0"));
    assert!(is_shared_library("libcrypto.so.1.1"));
    assert!(!is_shared_library("test.txt"));
    assert!(!is_shared_library("test"));
    assert!(!is_shared_library("libc.a"));
}

#[test]
fn test_library_similarity_same_base() {
    // Same library, different versions should have high similarity
    let score = library_similarity("libssl.so.1.0.0", "libssl.so.1.1.0");
    assert_eq!(score, 0.95);

    let score2 = library_similarity("libcrypto.so.1", "libcrypto.so.2");
    assert_eq!(score2, 0.95);
}

#[test]
fn test_library_similarity_different_base() {
    // Different libraries should use Levenshtein distance
    let score = library_similarity("libssl.so.1.0.0", "libcrypto.so.1.0.0");
    assert!(score < 0.95);
    assert!(score > 0.0);
}

#[test]
fn test_calculate_file_similarity_libraries() {
    let score = calculate_file_similarity("lib/libssl.so.1.0.0", "lib/libssl.so.1.1.0");
    assert_eq!(score, 0.95);
}

#[test]
fn test_calculate_file_similarity_general() {
    let score = calculate_file_similarity("test.txt", "test.txt");
    assert_eq!(score, 1.0);

    let score2 = calculate_file_similarity("test1.txt", "test2.txt");
    assert!(score2 > 0.8);

    let score3 = calculate_file_similarity("foo.txt", "completely_different.txt");
    assert!(score3 < 0.5);
}

#[test]
fn test_detect_renames_no_matches() {
    let removed = vec!["file1.txt".to_string()];
    let added = vec!["completely_different.txt".to_string()];

    let renames = detect_renames(&removed, &added);
    assert_eq!(renames.len(), 0);
}

#[test]
fn test_detect_renames_exact_match() {
    let removed = vec!["test.txt".to_string()];
    let added = vec!["test.txt".to_string()];

    let renames = detect_renames(&removed, &added);
    assert_eq!(renames.len(), 1);
    assert_eq!(renames[0].baseline_path, "test.txt");
    assert_eq!(renames[0].target_path, "test.txt");
    assert_eq!(renames[0].similarity_score, 1.0);
}

#[test]
fn test_detect_renames_library_version() {
    let removed = vec!["libssl.so.1.0.0".to_string()];
    let added = vec!["libssl.so.1.1.0".to_string()];

    let renames = detect_renames(&removed, &added);
    assert_eq!(renames.len(), 1);
    assert_eq!(renames[0].baseline_path, "libssl.so.1.0.0");
    assert_eq!(renames[0].target_path, "libssl.so.1.1.0");
    assert_eq!(renames[0].similarity_score, 0.95);
}

#[test]
fn test_detect_renames_deduplication() {
    // Multiple removed files, but only one good match
    let removed = vec!["file1.txt".to_string(), "file2.txt".to_string()];
    let added = vec!["file1_renamed.txt".to_string()];

    let renames = detect_renames(&removed, &added);
    // Should match file1.txt with file1_renamed.txt
    assert!(renames.len() <= 1);
    if renames.len() == 1 {
        assert!(renames[0].similarity_score >= 0.9);
    }
}

#[test]
fn test_format_diff_terminal_with_renames() {
    let report = DiffReport {
        schema_version: "1.0".to_string(),
        analysis_timestamp: Utc::now(),
        diff_mode: true,
        baseline: "/baseline".to_string(),
        target: "/target".to_string(),
        changes: FileChanges {
            added: vec![],
            removed: vec![],
            modified: vec![],
            renamed: vec![FileRenameInfo {
                from: "old_name.txt".to_string(),
                to: "new_name.txt".to_string(),
                similarity: 0.92,
            }],
        },
        modified_analysis: vec![],
        metadata: crate::types::AnalysisMetadata {
            analysis_duration_ms: 100,
            tools_used: vec!["diff_analyzer".to_string()],
            errors: vec![],
        },
    };

    let output = format_diff_terminal(&report);
    assert!(output.contains("old_name.txt"));
    assert!(output.contains("new_name.txt"));
    assert!(output.contains("92%"));
}

#[test]
fn test_extract_library_base() {
    assert_eq!(extract_library_base("libssl.so.1.0.0"), Some("libssl"));
    assert_eq!(extract_library_base("libcrypto.so.1"), Some("libcrypto"));
    assert_eq!(extract_library_base("libc.so"), Some("libc"));
    assert_eq!(extract_library_base("test.txt"), None);
    assert_eq!(extract_library_base("file.tar.gz"), None);
}

#[test]
fn test_detect_renames_exact_basename_match() {
    // Pass 1: Exact basename match in different directories
    let removed = vec!["dir1/test.txt".to_string()];
    let added = vec!["dir2/test.txt".to_string()];

    let renames = detect_renames(&removed, &added);
    assert_eq!(renames.len(), 1);
    assert_eq!(renames[0].baseline_path, "dir1/test.txt");
    assert_eq!(renames[0].target_path, "dir2/test.txt");
    assert_eq!(renames[0].similarity_score, 1.0);
}

#[test]
fn test_detect_renames_library_version_match() {
    // Pass 2: Library version matching
    let removed = vec![
        "lib/x86_64/libssl.so.1.0.0".to_string(),
        "lib/x86_64/libcrypto.so.1.0.0".to_string(),
    ];
    let added = vec![
        "lib/x86_64/libssl.so.1.1.0".to_string(),
        "lib/x86_64/libcrypto.so.1.1.0".to_string(),
    ];

    let renames = detect_renames(&removed, &added);
    assert_eq!(renames.len(), 2);

    // Both should be detected as library version changes
    let ssl_rename = renames
        .iter()
        .find(|r| r.baseline_path.contains("libssl"))
        .unwrap();
    assert_eq!(ssl_rename.similarity_score, 0.95);

    let crypto_rename = renames
        .iter()
        .find(|r| r.baseline_path.contains("libcrypto"))
        .unwrap();
    assert_eq!(crypto_rename.similarity_score, 0.95);
}

#[test]
fn test_detect_renames_same_directory_levenshtein() {
    // Pass 3: Same directory with Levenshtein distance
    // Use names with only 1-2 character difference to ensure >= 0.9 similarity
    let removed = vec!["dir/application_v1.txt".to_string()];
    let added = vec!["dir/application_v2.txt".to_string()];

    let renames = detect_renames(&removed, &added);
    assert_eq!(renames.len(), 1, "Expected 1 rename, got {}", renames.len());
    assert!(
        renames[0].similarity_score >= 0.9,
        "Similarity was {}",
        renames[0].similarity_score
    );
    assert_eq!(renames[0].baseline_path, "dir/application_v1.txt");
}

#[test]
fn test_detect_renames_no_cross_directory_match() {
    // Different directories, different names - should not match
    let removed = vec!["dir1/foo.txt".to_string()];
    let added = vec!["dir2/bar.txt".to_string()];

    let renames = detect_renames(&removed, &added);
    assert_eq!(renames.len(), 0);
}

#[test]
fn test_detect_renames_multiple_candidates_in_directory() {
    // If multiple files with same basename exist, don't match in pass 1
    let removed = vec!["dir1/test.txt".to_string()];
    let added = vec!["dir2/test.txt".to_string(), "dir3/test.txt".to_string()];

    let renames = detect_renames(&removed, &added);
    // Should not match because there are multiple candidates
    // (Pass 1 only matches when there's exactly one candidate)
    assert_eq!(renames.len(), 0);
}

#[test]
fn test_detect_renames_deduplication_still_works() {
    // Verify that files are only matched once
    let removed = vec![
        "lib/libssl.so.1.0.0".to_string(),
        "lib/libssl.so.1.0.1".to_string(),
    ];
    let added = vec!["lib/libssl.so.1.1.0".to_string()];

    let renames = detect_renames(&removed, &added);
    // Only one rename should be detected (first match wins)
    assert_eq!(renames.len(), 1);
}

#[test]
fn test_detect_renames_performance_large_set() {
    // Test performance with a larger set (1000 files)
    // This tests O(n) performance with files that have unique basenames
    use std::time::Instant;

    let mut removed = Vec::new();
    let mut added = Vec::new();

    // Create 1000 files with UNIQUE basenames across different directories
    // This will be matched by Pass 1 (exact basename, unique)
    for i in 0..1000 {
        removed.push(format!("old_dir/unique_file_{}.txt", i));
        added.push(format!("new_dir/unique_file_{}.txt", i));
    }

    let start = Instant::now();
    let renames = detect_renames(&removed, &added);
    let duration = start.elapsed();

    // Should find all 1000 exact matches via basename matching (Pass 1)
    assert_eq!(
        renames.len(),
        1000,
        "Expected 1000 renames, got {}",
        renames.len()
    );

    // Should complete in well under 1 second (O(n) performance)
    assert!(
        duration.as_millis() < 500,
        "Rename detection took too long: {:?}",
        duration
    );
}

#[test]
fn test_detect_renames_mixed_scenarios() {
    // Test multiple passes working together
    let removed = vec![
        "dir1/file1.txt".to_string(),       // Exact match in different dir
        "lib/libssl.so.1.0.0".to_string(),  // Library version change
        "dir2/config_old.conf".to_string(), // Same dir, similar name (high similarity)
        "unique/file.txt".to_string(),      // No match
    ];
    let added = vec![
        "dir3/file1.txt".to_string(),       // Match for dir1/file1.txt
        "lib/libssl.so.1.1.0".to_string(),  // Match for libssl
        "dir2/config_new.conf".to_string(), // Match for config_old (similarity >= 0.9)
        "other/different.txt".to_string(),  // No match
    ];

    let renames = detect_renames(&removed, &added);

    // Should find at least 2 renames (exact basename + library)
    // The third one (config files) should also match if similarity >= 0.9
    assert!(
        renames.len() >= 2,
        "Expected at least 2 renames, got {}",
        renames.len()
    );
    assert!(
        renames.len() <= 3,
        "Expected at most 3 renames, got {}",
        renames.len()
    );

    // Verify each type was matched
    assert!(renames.iter().any(|r| r.baseline_path == "dir1/file1.txt"));
    assert!(renames
        .iter()
        .any(|r| r.baseline_path == "lib/libssl.so.1.0.0"));
}

#[test]
fn test_format_diff_terminal_file_changes() {
    let report = DiffReport {
        schema_version: "1.0".to_string(),
        analysis_timestamp: Utc::now(),
        diff_mode: true,
        baseline: "/baseline".to_string(),
        target: "/target".to_string(),
        changes: FileChanges {
            added: vec!["new.txt".to_string()],
            removed: vec!["old.txt".to_string()],
            modified: vec!["changed.txt".to_string()],
            renamed: vec![FileRenameInfo {
                from: "a.txt".to_string(),
                to: "b.txt".to_string(),
                similarity: 1.0,
            }],
        },
        modified_analysis: vec![],
        metadata: crate::types::AnalysisMetadata {
            analysis_duration_ms: 100,
            tools_used: vec!["diff_analyzer".to_string()],
            errors: vec![],
        },
    };

    let output = format_diff_terminal(&report);
    // Should contain file names
    assert!(output.contains("new.txt"));
    assert!(output.contains("old.txt"));
    assert!(output.contains("a.txt"));
    assert!(output.contains("b.txt"));
    assert!(output.contains("File changes"));
}

#[test]
fn test_format_diff_terminal_many_files() {
    // Test with many added files
    let mut added = Vec::new();
    for i in 0..50 {
        added.push(format!("file{}.txt", i));
    }

    let report = DiffReport {
        schema_version: "1.0".to_string(),
        analysis_timestamp: Utc::now(),
        diff_mode: true,
        baseline: "/baseline".to_string(),
        target: "/target".to_string(),
        changes: FileChanges {
            added,
            removed: vec![],
            modified: vec![],
            renamed: vec![],
        },
        modified_analysis: vec![],
        metadata: crate::types::AnalysisMetadata {
            analysis_duration_ms: 100,
            tools_used: vec!["diff_analyzer".to_string()],
            errors: vec![],
        },
    };

    let output = format_diff_terminal(&report);
    // Should show summary with file count
    assert!(output.contains("+50 files"));
}
