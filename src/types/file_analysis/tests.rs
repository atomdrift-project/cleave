use super::*;

// ==================== Constants Tests ====================

#[test]
fn test_archive_delimiter() {
    assert_eq!(ARCHIVE_DELIMITER, "!!");
}

#[test]
fn test_encoding_delimiter() {
    assert_eq!(ENCODING_DELIMITER, "##");
}

// ==================== FileAnalysis Tests ====================

#[test]
fn test_file_analysis_new() {
    let fa = FileAnalysis::new(
        0,
        "test.py".to_string(),
        "python".to_string(),
        "abc123def".to_string(),
        1024,
    );
    assert_eq!(fa.id, 0);
    assert_eq!(fa.path, "test.py");
    assert_eq!(fa.file_type, "python");
    assert_eq!(fa.sha256, "abc123def");
    assert_eq!(fa.size, 1024);
    assert_eq!(fa.depth, 0);
    assert!(fa.parent_id.is_none());
}

#[test]
fn test_file_analysis_new_all_collections_empty() {
    let fa = FileAnalysis::new(
        0,
        "test.py".to_string(),
        "python".to_string(),
        "abc".to_string(),
        100,
    );
    assert!(fa.findings.is_empty());
    assert!(fa.traits.is_empty());
    assert!(fa.structure.is_empty());
    assert!(fa.functions.is_empty());
    assert!(fa.strings.is_empty());
    assert!(fa.sections.is_empty());
    assert!(fa.imports.is_empty());
    assert!(fa.exports.is_empty());
    assert!(fa.yara_matches.is_empty());
    assert!(fa.syscalls.is_empty());
}

#[test]
fn test_file_analysis_new_all_options_none() {
    let fa = FileAnalysis::new(
        0,
        "test.py".to_string(),
        "python".to_string(),
        "abc".to_string(),
        100,
    );
    assert_eq!(fa.score, 0);
    assert!(fa.counts.is_none());
    assert!(fa.encoding.is_none());
}

#[test]
fn test_file_analysis_compute_summary_empty() {
    let mut fa = FileAnalysis::new(
        0,
        "test.py".to_string(),
        "python".to_string(),
        "abc".to_string(),
        100,
    );
    fa.compute_summary();
    assert_eq!(fa.score, 0);
    assert!(fa.counts.is_none());
}

#[test]
fn test_file_analysis_compute_summary_notable_only() {
    let mut fa = FileAnalysis::new(
        0,
        "test.py".to_string(),
        "python".to_string(),
        "abc".to_string(),
        100,
    );
    fa.findings.push(
        Finding::capability("test/notable".to_string(), "Test".to_string(), 0.5)
            .with_criticality(Criticality::Notable),
    );
    fa.compute_summary();
    // ceil(notable(1) * conf(0.5)) = ceil(0.5) = 1
    assert_eq!(fa.score, 1);
    let counts = fa.counts.unwrap();
    assert_eq!(counts.notable, 1);
    assert_eq!(counts.suspicious, 0);
    assert_eq!(counts.hostile, 0);
}

#[test]
fn test_file_analysis_compute_summary_baseline_only() {
    let mut fa = FileAnalysis::new(
        0,
        "test.py".to_string(),
        "python".to_string(),
        "abc".to_string(),
        100,
    );
    fa.findings.push(
        Finding::capability("test/baseline".to_string(), "Test".to_string(), 0.1)
            .with_criticality(Criticality::Baseline),
    );
    fa.compute_summary();
    // baseline findings contribute 0.2 * conf; ceil(0.2 * 0.1) = 1
    assert_eq!(fa.score, 1);
    assert!(fa.counts.is_none());
}

// ==================== FindingCounts Tests ====================

#[test]
fn test_finding_counts_default() {
    let counts = FindingCounts::default();
    assert_eq!(counts.hostile, 0);
    assert_eq!(counts.suspicious, 0);
    assert_eq!(counts.notable, 0);
}

#[test]
fn test_finding_counts_with_values() {
    let counts = FindingCounts {
        hostile: 5,
        suspicious: 10,
        notable: 15,
    };
    assert_eq!(counts.hostile, 5);
    assert_eq!(counts.suspicious, 10);
    assert_eq!(counts.notable, 15);
}

// ==================== ReportSummary Tests ====================

#[test]
fn test_report_summary_default() {
    let summary = ReportSummary::default();
    assert_eq!(summary.files_analyzed, 0);
    assert_eq!(summary.counts.hostile, 0);
    assert_eq!(summary.counts.hostile, 0);
    assert_eq!(summary.counts.suspicious, 0);
    assert_eq!(summary.counts.notable, 0);
}

#[test]
fn test_report_summary_from_empty_files() {
    let summary = ReportSummary::from_files(&[]);
    assert_eq!(summary.files_analyzed, 0);
    assert_eq!(summary.counts.hostile, 0);
}

#[test]
fn test_report_summary_from_single_file() {
    let mut file = FileAnalysis::new(
        0,
        "a.py".to_string(),
        "python".to_string(),
        "abc".to_string(),
        100,
    );
    file.depth = 0;

    let summary = ReportSummary::from_files(&[file]);
    assert_eq!(summary.files_analyzed, 1);
    assert_eq!(summary.counts.hostile, 0);
}

#[test]
fn test_report_summary_multiple_files() {
    let file1 = FileAnalysis::new(
        0,
        "a.py".to_string(),
        "python".to_string(),
        "abc".to_string(),
        100,
    );

    let file2 = FileAnalysis::new(
        1,
        "b.py".to_string(),
        "python".to_string(),
        "def".to_string(),
        200,
    );

    let file3 = FileAnalysis::new(
        2,
        "c.py".to_string(),
        "python".to_string(),
        "ghi".to_string(),
        300,
    );

    let summary = ReportSummary::from_files(&[file1, file2, file3]);
    assert_eq!(summary.files_analyzed, 3);
}

// ==================== is_zero helper Tests ====================

#[test]
fn test_is_zero_true() {
    assert!(is_zero(&0));
}

#[test]
fn test_is_zero_false() {
    assert!(!is_zero(&1));
    assert!(!is_zero(&100));
}

// ==================== Path Encoding Tests ====================

#[test]
fn test_encode_archive_path() {
    assert_eq!(
        encode_archive_path("foo.zip", "inner/file.py"),
        "foo.zip!!inner/file.py"
    );
}

#[test]
fn test_encode_archive_path_nested() {
    let p1 = encode_archive_path("a.zip", "b.tar");
    let p2 = encode_archive_path(&p1, "c.py");
    assert_eq!(p2, "a.zip!!b.tar!!c.py");
}

#[test]
fn test_encode_decoded_path() {
    assert_eq!(
        encode_decoded_path("file.py", &["base64".to_string(), "gzip".to_string()], 1234),
        "file.py##base64+gzip@1234"
    );
}

#[test]
fn test_encode_upx_path() {
    assert_eq!(encode_upx_path("sample.elf"), "sample.elf!!upx@0");
}

#[test]
fn test_encode_upx_path_with_directory() {
    assert_eq!(encode_upx_path("/tmp/sample.elf"), "/tmp/sample.elf!!upx@0");
}

#[test]
fn test_finding_counts() {
    let mut file = FileAnalysis::new(
        0,
        "test.py".to_string(),
        "python".to_string(),
        "abc123".to_string(),
        100,
    );

    file.findings.push(
        Finding::capability("test/hostile/a".to_string(), "Test".to_string(), 0.9)
            .with_criticality(Criticality::Hostile),
    );

    file.findings.push(
        Finding::capability("test/suspicious/b".to_string(), "Test".to_string(), 0.8)
            .with_criticality(Criticality::Suspicious),
    );

    file.compute_summary();

    // Different top-3 paths: "test/hostile/a" and "test/suspicious/b"
    // Both contribute: ceil(120*0.9 + 40*0.8) = 140
    assert_eq!(file.score, 140);
    let counts = file.counts.unwrap();
    assert_eq!(counts.hostile, 1);
    assert_eq!(counts.suspicious, 1);
    assert_eq!(counts.notable, 0);
}

#[test]
fn test_score_grouping() {
    let mut file = FileAnalysis::new(
        0,
        "test.py".to_string(),
        "python".to_string(),
        "abc123".to_string(),
        100,
    );

    // Same top-3 path: "test/foo/bar"
    file.findings.push(
        Finding::capability("test/foo/bar/a".to_string(), "Test".to_string(), 0.9)
            .with_criticality(Criticality::Hostile),
    );

    file.findings.push(
        Finding::capability("test/foo/bar/b".to_string(), "Test".to_string(), 0.8)
            .with_criticality(Criticality::Suspicious),
    );

    file.compute_summary();

    // Same top-3 path: only the highest contributes
    // ceil(120*0.9) = 108
    assert_eq!(file.score, 108);
    let counts = file.counts.unwrap();
    assert_eq!(counts.hostile, 1);
    assert_eq!(counts.suspicious, 1);
}

#[test]
fn score_is_independent_of_group_accumulation_order() {
    // These four f32 values sum exactly to 3 in wider arithmetic, but
    // some f32 accumulation orders yield 3.0000002 and ceil to 4.
    let confidence = [0.7, 0.8, 0.9, 0.6];
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    let mut unique = order;
                    unique.sort_unstable();
                    if unique != [0, 1, 2, 3] {
                        continue;
                    }
                    let mut file = FileAnalysis::new(
                        0,
                        "control.rs".into(),
                        "rust".into(),
                        "score-order".into(),
                        0,
                    );
                    for (group, index) in order.into_iter().enumerate() {
                        file.findings.push(
                            Finding::capability(
                                format!("metadata/score/group-{group}::observation"),
                                "Neutral test observation".into(),
                                confidence[index],
                            )
                            .with_criticality(Criticality::Notable),
                        );
                    }
                    file.compute_summary();
                    assert_eq!(file.score, 3, "confidence order: {order:?}");
                }
            }
        }
    }
}

#[test]
fn stable_sum_preserves_score_precision_and_real_fractional_excess() {
    let mut file = FileAnalysis::new(
        0,
        "control.rs".into(),
        "rust".into(),
        "score-precision".into(),
        0,
    );
    for group in 0..5 {
        file.findings.push(
            Finding::capability(
                format!("metadata/score/group-{group}::baseline"),
                "Baseline".into(),
                1.0,
            )
            .with_criticality(Criticality::Baseline),
        );
    }
    file.compute_summary();
    assert_eq!(
        file.score, 1,
        "five 0.2 baselines retain the existing score precision"
    );
    file.findings.clear();
    for (group, conf) in [0.7, 0.8, 0.9, 0.6001].into_iter().enumerate() {
        file.findings.push(
            Finding::capability(
                format!("metadata/score/group-{group}::notable"),
                "Notable".into(),
                conf,
            )
            .with_criticality(Criticality::Notable),
        );
    }
    file.compute_summary();
    assert_eq!(file.score, 4, "a real fractional excess still rounds up");
}

#[test]
fn test_report_summary() {
    let mut file1 = FileAnalysis::new(
        0,
        "a.py".to_string(),
        "python".to_string(),
        "abc".to_string(),
        100,
    );
    file1.depth = 0;
    file1.counts = Some(FindingCounts {
        hostile: 1,
        suspicious: 2,
        notable: 0,
    });

    let mut file2 = FileAnalysis::new(
        1,
        "b.py".to_string(),
        "python".to_string(),
        "def".to_string(),
        200,
    );
    file2.depth = 2;
    file2.counts = Some(FindingCounts {
        hostile: 0,
        suspicious: 1,
        notable: 3,
    });

    let summary = ReportSummary::from_files(&[file1, file2]);
    assert_eq!(summary.files_analyzed, 2);
    assert_eq!(summary.counts.hostile, 1);
    assert_eq!(summary.counts.suspicious, 3);
    assert_eq!(summary.counts.notable, 3);
}
