use super::*;
use crate::types::{AnalysisReport, Finding, FindingKind, TargetInfo};
use tempfile::TempDir;

fn create_test_yaml(content: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.yaml");
    std::fs::write(&file_path, content).unwrap();
    (dir, file_path)
}

fn create_debug_test_mapper() -> CapabilityMapper {
    let yaml = r#"
defaults:
  for: [binaries, scripts, source, manifests, documents, media, data, archives]

traits:
  - id: "micro-behaviors/data/embedded/zstd-magic"
    desc: "Detect zstd magic"
    crit: notable
    conf: 0.9
    for: [elf]
    if:
      type: text
      exact: "ZSTD"

  - id: "known/malware/botnet/mirai/detected"
    desc: "Detect Mirai marker"
    crit: hostile
    conf: 0.9
    for: [elf]
    size_min: 30000
    if:
      type: text
      exact: "mirai"

composite_rules:
  - id: "objectives/command-and-control/webshell/backdoor/php-rce"
    desc: "PHP webshell RCE behavior"
    crit: hostile
    conf: 0.9
    for: [php]
    any:
      - type: trait
        id: "objectives/anti-static/obfuscation"
      - type: trait
        id: "micro-behaviors/data/user-input/request/get"
    needs: 1

  - id: "objectives/lateral-movement/trojanize/app/objc-app-hook"
    desc: "Objective-C app hooking behavior"
    crit: notable
    conf: 0.9
    platforms: [macos]
    for: [macho]
    all:
      - type: trait
        id: "micro-behaviors/execution/dylib/load/objc-method-swizzle"
      - type: trait
        id: "micro-behaviors/execution/dylib/load/nsbundle"
    any:
      - type: trait
        id: "micro-behaviors/communications/socket/send/send"
    needs: 1
"#;
    let (_dir, path) = create_test_yaml(yaml);
    CapabilityMapper::from_yaml(&path).unwrap()
}

fn create_test_report_with_findings(findings: Vec<Finding>) -> AnalysisReport {
    let target = TargetInfo {
        path: "/test/file.php".to_string(),
        file_type: "php".to_string(),
        size_bytes: 100,
        sha256: "test".to_string(),
        architectures: None,
    };
    let mut report = AnalysisReport::new(target);
    report.findings = findings;
    report
}

#[test]
fn debug_inline_yara_evaluates_uncompiled_conditions() {
    let mapper = CapabilityMapper::empty();
    let report = create_test_report_with_findings(vec![]);
    let source = r#"rule test { strings: $a = "needle" condition: $a }"#;
    for (data, expected) in [(b"needle".as_slice(), true), (b"nothing".as_slice(), false)] {
        let debugger = RuleDebugger::new(&mapper, &report, data, vec![Platform::All], None);
        assert_eq!(
            debugger
                .debug_yara_inline_condition(source, None, None)
                .matched,
            expected
        );
    }
    let debugger = RuleDebugger::new(&mapper, &report, b"needle", vec![Platform::All], None);
    let invalid = debugger.debug_yara_inline_condition("not a YARA rule", None, None);
    assert!(!invalid.matched);
    assert!(
        invalid
            .details
            .iter()
            .any(|detail| detail.contains("failed to compile"))
    );
}

#[test]
fn debug_inline_yara_uses_prescanned_results() {
    let mapper = CapabilityMapper::empty();
    let report = create_test_report_with_findings(vec![]);
    let results = HashMap::new();
    let debugger = RuleDebugger::new(
        &mapper,
        &report,
        b"needle",
        vec![Platform::All],
        Some(&results),
    );
    let result = debugger.debug_yara_inline_condition("not a YARA rule", Some("test"), None);
    assert!(!result.matched);
    assert!(
        result
            .details
            .iter()
            .any(|detail| detail.contains("did not match"))
    );
}

fn create_test_finding(id: &str) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        id: id.to_string().into(),
        kind: FindingKind::Capability,
        desc: format!("Test finding: {}", id).into(),
        conf: 0.9,
        crit: crate::types::Criticality::Notable,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        source_file: None,
        match_count: 0,
        downgraded: false,
    }
}

/// `test-rules` judges raw conditions with the scan's evaluator, so modifiers
/// a scan honors (here `case_insensitive`) are honored here too.
#[test]
fn raw_conditions_use_the_scan_evaluator() {
    let report = create_test_report_with_findings(Vec::new());
    let mapper = create_debug_test_mapper();
    let debugger = RuleDebugger::new(&mapper, &report, b"Hello WORLD", vec![Platform::All], None);
    let condition: Condition =
        crate::yaml::from_str("type: raw\nsubstr: world\ncase_insensitive: true").unwrap();
    assert!(debugger.debug_condition(&condition).matched);
}

/// Test that match status from real evaluation is consistent with debug output
#[test]
fn test_debug_rule_match_consistency_with_real_evaluation() {
    // Create a report with findings that should match certain rules
    let findings = vec![
        create_test_finding("objectives/anti-static/obfuscation/encoding/test"),
        create_test_finding("micro-behaviors/data/user-input/request/get"),
    ];
    let report = create_test_report_with_findings(findings);
    let binary_data = b"<?php test ?>";

    let mapper = create_debug_test_mapper();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Test a composite rule that references traits by prefix
    // The rule should match if the findings contain matching prefixes
    let result = debugger
        .debug_rule("objectives/command-and-control/webshell/backdoor/php-rce")
        .expect("expected local php-rce composite fixture");

    // Verify consistency: if matched is true, at least one condition should show as matched
    if result.matched {
        let has_matched_condition = result.condition_results.iter().any(|c| c.matched);
        assert!(
            has_matched_condition,
            "Rule marked as matched but no conditions show as matched"
        );
    }
}

#[test]
fn test_debug_text_condition_uses_real_text_evaluator() {
    let mut report = create_test_report_with_findings(vec![]);
    report.target.file_type = "elf".to_string();
    report.strings = crate::strings::StringExtractor::default().convert_stng_strings(&[
        stng::ExtractedString::new("ZSTD".to_string(), 12, stng::StringMethod::RawScan),
    ]);
    let mapper = create_debug_test_mapper();
    let debugger = RuleDebugger::new(
        &mapper,
        &report,
        b"binary fixture",
        vec![Platform::All],
        None,
    );

    let result = debugger
        .debug_rule("micro-behaviors/data/embedded/zstd-magic")
        .expect("expected local zstd trait fixture");

    assert!(result.matched, "real trait evaluation should match");
    assert_eq!(result.condition_results.len(), 1);
    assert!(
        result.condition_results[0].matched,
        "debug condition must agree with real text evaluation"
    );
}

#[test]
fn debug_call_conditions_agree_with_canonical_provenance_and_arguments() {
    let yaml = r#"
defaults:
  platforms: [unix, windows]
traits:
  - id: canonical-call
    desc: Fixture bytes enter request body
    crit: notable
    conf: 0.9
    for: [go]
    if:
      type: symbol
      kind: call
      exact: net/http.Post
      arg:
        index: 2
        from:
          call: '^os\.ReadFile$'
          literal: '^fixture\.txt$'
          through:
            - call: '^bytes\.NewReader$'
              arguments: [0]
  - id: wrong-arguments
    desc: Fixture request uses JSON content type
    crit: notable
    conf: 0.9
    for: [go]
    if:
      type: symbol
      kind: call
      exact: client.Post
      args:
        - index: 0
          exact: https://fixture.invalid/upload
        - index: 1
          exact: application/json
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    for (filename, expected) in [("fixture.txt", true), ("public.txt", false)] {
        let source = format!(
            r#"package fixture
import (client "net/http"; files "os"; "bytes")
func upload() {{
    data, _ := files.ReadFile("{filename}")
    client.Post("https://fixture.invalid/upload", "text/plain", bytes.NewReader(data))
}}
"#
        );
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("fixture.go"))
            .open(source.as_bytes());
        let mut report = create_test_report_with_findings(vec![]);
        report.target.path = "fixture.go".into();
        report.target.file_type = "go".into();
        report.target.size_bytes = source.len() as u64;
        report.filefacts = Some(crate::types::FilefactsView {
            symbols: parsed.symbols().into_iter().cloned().collect(),
            flow: parsed.flow().cloned(),
            ..Default::default()
        });
        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            source.as_bytes(),
            vec![Platform::All],
            None,
        );
        for (id, expected) in [("canonical-call", expected), ("wrong-arguments", false)] {
            let result = debugger.debug_rule(id).unwrap();
            assert_eq!(result.matched, expected, "{id}: {filename}");
            assert_eq!(result.condition_results.len(), 1);
            assert_eq!(
                result.condition_results[0].matched, expected,
                "{id}: {filename}"
            );
            if expected {
                assert!(!result.condition_results[0].evidence.is_empty());
            }
        }
    }
}

/// Test that skip reasons are correctly captured
#[test]
fn test_debug_rule_skip_reason_file_type_mismatch() {
    // Create a PHP report but test a rule that requires ELF
    let report = create_test_report_with_findings(vec![]);
    let binary_data = b"<?php test ?>";

    let mapper = create_debug_test_mapper();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Test a rule that requires ELF file type (zstd-magic is for binaries)
    let result = debugger
        .debug_rule("micro-behaviors/data/embedded/zstd-magic")
        .expect("expected local zstd trait fixture");
    assert!(!result.matched, "Rule should not match for PHP file");
    assert!(
        result.skipped_reason.is_some(),
        "Should have a skip reason for file type mismatch"
    );
    let reason = result.skipped_reason.as_ref().unwrap();
    assert!(
        reason.contains("File type mismatch"),
        "Skip reason should mention file type mismatch, got: {}",
        reason
    );
}

/// Test that size constraints are reported as skip reasons
#[test]
fn test_debug_rule_skip_reason_size_constraint() {
    // Create a tiny report (5 bytes)
    let target = TargetInfo {
        path: "/test/tiny.elf".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 5, // Very small
        sha256: "test".to_string(),
        architectures: None,
    };
    let report = AnalysisReport::new(target);
    let binary_data = b"\x7fELF\x00";

    let mapper = create_debug_test_mapper();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::Linux], None);

    // Test mirai detection which has size_min: 30000
    let result = debugger
        .debug_rule("known/malware/botnet/mirai/detected")
        .expect("expected local mirai trait fixture");
    assert!(!result.matched, "Rule should not match for tiny file");
    assert!(
        result.skipped_reason.is_some(),
        "Should have a skip reason for size constraint"
    );
    let reason = result.skipped_reason.as_ref().unwrap();
    assert!(
        reason.contains("Size too small"),
        "Skip reason should mention size constraint, got: {}",
        reason
    );
}

/// Test that prefix matching works correctly in condition debugging
#[test]
fn test_debug_condition_prefix_matching() {
    // Create findings with specific prefixes
    let findings = vec![
        create_test_finding("objectives/anti-static/obfuscation/encoding/test"),
        create_test_finding("objectives/anti-static/obfuscation/code-metrics/test2"),
    ];
    let report = create_test_report_with_findings(findings);
    let binary_data = b"test";

    let mapper = CapabilityMapper::empty();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Directly test the prefix matching in debug_condition
    let condition = Condition::Trait {
        id: "objectives/anti-static/obfuscation".to_string(),
    };
    let result = debugger.debug_condition(&condition);

    assert!(
        result.matched,
        "Prefix 'objectives/anti-static/obfuscation' should match findings with that prefix"
    );
    assert!(
        !result.details.is_empty(),
        "Should have details about matched findings"
    );
}

/// Test that non-matching prefix returns false
#[test]
fn test_debug_condition_prefix_no_match() {
    let findings = vec![create_test_finding(
        "micro-behaviors/data/user-input/request/get",
    )];
    let report = create_test_report_with_findings(findings);
    let binary_data = b"test";

    let mapper = CapabilityMapper::empty();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Test a prefix that doesn't match any findings
    let condition = Condition::Trait {
        id: "objectives/anti-static/obfuscation".to_string(),
    };
    let result = debugger.debug_condition(&condition);

    assert!(
        !result.matched,
        "Prefix should not match when no findings have that prefix"
    );
}

/// Test that the match count in condition group matches the actual matched conditions
#[test]
fn test_debug_composite_condition_count_consistency() {
    let findings = vec![
        create_test_finding("objectives/anti-static/obfuscation/encoding/test"),
        create_test_finding("micro-behaviors/data/user-input/request/get"),
    ];
    let report = create_test_report_with_findings(findings);
    let binary_data = b"<?php test ?>";

    let mapper = create_debug_test_mapper();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Find and debug a composite rule
    let result = debugger
        .debug_rule("objectives/command-and-control/webshell/backdoor/php-rce")
        .expect("expected local php-rce composite fixture");
    // For each condition group (all/any), verify count matches
    for cond_result in &result.condition_results {
        // Parse the condition description to get claimed count
        // e.g., "any: (1/2 needed: 1)"
        if cond_result.condition_desc.contains("(") {
            let matched_in_sub = cond_result.sub_results.iter().filter(|r| r.matched).count();

            // The description should contain the correct count
            if let Some(start) = cond_result.condition_desc.find('(')
                && let Some(slash) = cond_result.condition_desc.find('/')
            {
                let claimed_count: usize = cond_result.condition_desc[start + 1..slash]
                    .parse()
                    .unwrap_or(999);
                assert_eq!(
                    claimed_count, matched_in_sub,
                    "Claimed match count {} doesn't match actual {}",
                    claimed_count, matched_in_sub
                );
            }
        }
    }
}

/// The debugger must apply the same exclusions production does.
///
/// `test-rules` builds its own condition and calls the real evaluator. A
/// field it forgets to carry across makes it report a match the scan does
/// not produce -- and the operator trusts the debugger precisely when the
/// two disagree, so the divergence is worse than either behaviour alone.
#[test]
fn debug_value_condition_honours_not_exclusions() {
    let target = TargetInfo {
        path: "/test/package.json".to_string(),
        file_type: "packagejson".to_string(),
        size_bytes: 64,
        sha256: "test".to_string(),
        architectures: None,
    };
    let report = AnalysisReport::new(target);
    let json = br#"{"name":"p","files":["report.accreport.html"]}"#;
    let mapper = CapabilityMapper::empty();
    let debugger = RuleDebugger::new(&mapper, &report, json, vec![Platform::All], None);

    let with_not: Condition = crate::yaml::from_str(
        r#"
type: value
path: files[*]
regex: '(?i)\.html?$'
not:
  - regex: 'accreport\.html?$'
"#,
    )
    .unwrap();
    let without_not: Condition = crate::yaml::from_str(
        r#"
type: value
path: files[*]
regex: '(?i)\.html?$'
"#,
    )
    .unwrap();

    assert!(
        debugger.debug_condition(&without_not).matched,
        "the condition should match without the exclusion"
    );
    assert!(
        !debugger.debug_condition(&with_not).matched,
        "the debugger ignored a not: the evaluator applies"
    );
}

/// test-rules applies the same member-type origin filter as production
/// container evaluation.
#[test]
fn container_origin_mask_matches_production() {
    // A zip holding a zip-typed member (leg a) and an ELF member (leg b),
    // both rolled up to the container. Production counts a member's
    // finding only when its type is in the composite's `for:`; test-rules
    // used to allow every origin and reported MATCHED for the narrow rule.
    let yaml = r#"
defaults:
  for: [zip, elf]
  crit: notable
  conf: 0.9

traits:
  - id: "fixture/origin::leg-a"
    desc: "leg a"
    if:
      type: text
      exact: "AAAA"
  - id: "fixture/origin::leg-b"
    desc: "leg b"
    if:
      type: text
      exact: "BBBB"

composite_rules:
  - id: "fixture/origin::narrow"
    desc: "names only the container"
    for: [zip]
    scope: archive
    all:
      - id: "fixture/origin::leg-a"
      - id: "fixture/origin::leg-b"
  - id: "fixture/origin::wide"
    desc: "names the ELF member too"
    for: [zip, elf]
    scope: archive
    all:
      - id: "fixture/origin::leg-a"
      - id: "fixture/origin::leg-b"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let a = create_test_finding("fixture/origin::leg-a");
    let b = create_test_finding("fixture/origin::leg-b");
    let mut report = create_test_report_with_findings(vec![a.clone(), b.clone()]);
    report.target.path = "release.zip".into();
    report.target.file_type = "zip".into();
    report.files = vec![
        crate::types::FileAnalysis {
            path: "release.zip!!inner.zip".into(),
            file_type: "zip".into(),
            findings: vec![a],
            ..Default::default()
        },
        crate::types::FileAnalysis {
            path: "release.zip!!provider".into(),
            file_type: "elf".into(),
            findings: vec![b],
            ..Default::default()
        },
    ];

    let debugger = RuleDebugger::new(&mapper, &report, b"", vec![Platform::All], None);

    let narrow = debugger.debug_rule("fixture/origin::narrow").unwrap();
    assert!(!narrow.matched, "ELF leg must not count for for: [zip]");
    let text = format_debug_output(std::slice::from_ref(&narrow));
    assert!(
        text.contains("origin filter drops it"),
        "trace must say why leg b failed:\n{text}"
    );

    let wide = debugger.debug_rule("fixture/origin::wide").unwrap();
    assert!(wide.matched, "listing elf lets the ELF leg count");
}

/// A leg the container finds itself counts as the container's, even when a
/// member of an unlisted type found the same id -- the scan stamps the
/// container's own findings (here, a basename trait over its entry list)
/// with its bit. test-rules once kept only the member's bit and blamed the
/// origin filter, as it did for a JetBrains plugin's `plugin.xml`.
#[test]
fn container_own_finding_keeps_container_origin() {
    let yaml = r#"
defaults:
  for: [zip, elf]
  crit: notable
  conf: 0.9

traits:
  - id: "fixture/origin::leg-a"
    desc: "leg a"
    for: [xml]
    if:
      type: basename
      exact: plugin.xml

composite_rules:
  - id: "fixture/origin::container-only"
    desc: "names only the container"
    for: [zip]
    all:
      - id: "fixture/origin::leg-a"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let a = create_test_finding("fixture/origin::leg-a");
    let mut report = create_test_report_with_findings(vec![a.clone()]);
    report.target.path = "release.zip".into();
    report.target.file_type = "zip".into();
    report.archive_contents = vec![crate::types::ArchiveEntry {
        path: "pkg/META-INF/plugin.xml".into(),
        file_type: "xml".into(),
        ..Default::default()
    }];
    report.files = vec![crate::types::FileAnalysis {
        path: "release.zip!!pkg/META-INF/plugin.xml".into(),
        file_type: "xml".into(),
        findings: vec![a],
        ..Default::default()
    }];

    let debugger = RuleDebugger::new(&mapper, &report, b"", vec![Platform::All], None);
    let rule = debugger
        .debug_rule("fixture/origin::container-only")
        .unwrap();
    let text = format_debug_output(std::slice::from_ref(&rule));
    assert!(rule.matched, "{text}");
    assert!(!text.contains("origin filter drops it"), "{text}");
}

/// Test that exact trait ID match in findings is detected
#[test]
fn test_debug_trait_reference_exact_match_in_findings() {
    let findings = vec![create_test_finding(
        "micro-behaviors/communications/socket/send/send",
    )];
    let report = create_test_report_with_findings(findings);
    let binary_data = b"test";

    let mapper = CapabilityMapper::empty();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Test exact match - should find the finding directly
    let condition = Condition::Trait {
        id: "micro-behaviors/communications/socket/send/send".to_string(),
    };
    let result = debugger.debug_condition(&condition);

    assert!(
        result.matched,
        "Exact trait ID match should be found in findings"
    );
    assert!(
        result.details.iter().any(|d| d.contains("exact match")),
        "Details should mention exact match, got: {:?}",
        result.details
    );
}

/// Test that suffix matching works for short trait names
#[test]
fn test_debug_trait_reference_suffix_match() {
    let findings = vec![create_test_finding(
        "micro-behaviors/execution/process/terminate",
    )];
    let report = create_test_report_with_findings(findings);
    let binary_data = b"test";

    let mapper = CapabilityMapper::empty();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Test suffix match with short name
    let condition = Condition::Trait {
        id: "terminate".to_string(),
    };
    let result = debugger.debug_condition(&condition);

    assert!(
        result.matched,
        "Short trait name 'terminate' should match via suffix '/terminate'"
    );
    assert!(
        result.details.iter().any(|d| d.contains("suffix")),
        "Details should mention suffix match, got: {:?}",
        result.details
    );
}

/// Test that condition match status is consistent with overall match status
/// This is the core test for the mismatch bug we fixed
#[test]
fn test_debug_composite_no_condition_overall_mismatch() {
    // Create findings that should satisfy a composite's conditions
    let findings = vec![
        create_test_finding("micro-behaviors/execution/dylib/load/objc-method-swizzle"),
        create_test_finding("micro-behaviors/execution/dylib/load/nsbundle"),
        create_test_finding("micro-behaviors/communications/socket/send/send"),
    ];

    // Create a MachO file type report
    let target = TargetInfo {
        path: "/test/app.macho".to_string(),
        file_type: "macho".to_string(),
        size_bytes: 50000,
        sha256: "test".to_string(),
        architectures: Some(vec!["arm64".to_string()]),
    };
    let mut report = AnalysisReport::new(target);
    report.findings = findings;
    let binary_data = b"\xCF\xFA\xED\xFE"; // MachO magic

    let mapper = create_debug_test_mapper();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::MacOS], None);

    // Test the objc-app-hook composite if it exists
    let result = debugger
        .debug_rule("objectives/lateral-movement/trojanize/app/objc-app-hook")
        .expect("expected local objc-app-hook composite fixture");
    // KEY INVARIANT: If all condition groups show matched, overall should be matched
    // (unless there's a skip reason or other constraint that explains the difference)
    let all_condition_groups_matched = result
        .condition_results
        .iter()
        .filter(|c| c.condition_desc.starts_with("all:") || c.condition_desc.starts_with("any:"))
        .all(|c| c.matched);

    if all_condition_groups_matched && result.skipped_reason.is_none() {
        // If all groups match and no skip reason, overall should match
        assert!(
            result.matched,
            "All condition groups show matched but overall is NOT MATCHED - this is the mismatch bug!\n\
                 Condition results: {:?}",
            result
                .condition_results
                .iter()
                .map(|c| format!("{}: {}", c.condition_desc, c.matched))
                .collect::<Vec<_>>()
        );
    }

    // Also verify: if overall matched, at least one condition group should match
    if result.matched {
        let has_matched_condition = result.condition_results.iter().any(|c| c.matched);
        assert!(
            has_matched_condition,
            "Overall matched but no condition groups show matched"
        );
    }
}

/// Test that trait not in findings shows as not matched even if re-evaluation would succeed
#[test]
fn test_debug_trait_reference_not_in_findings() {
    // Create an empty findings list
    let report = create_test_report_with_findings(vec![]);
    let binary_data = b"test data with some content";

    let mapper = CapabilityMapper::empty();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Test a trait that exists in definitions but not in findings
    let condition = Condition::Trait {
        id: "micro-behaviors/execution/process/terminate".to_string(),
    };
    let result = debugger.debug_condition(&condition);

    // The trait is not in findings, so it should NOT match
    // (regardless of whether re-evaluation would succeed)
    assert!(
        !result.matched,
        "Trait not in findings should show as not matched"
    );
}

/// Test that prefix directory matching mirrors eval_trait behavior
#[test]
fn test_debug_trait_reference_prefix_match_mirrors_eval() {
    // Create findings with a specific path
    let findings = vec![
        create_test_finding("micro-behaviors/communications/socket/send/unix"),
        create_test_finding("micro-behaviors/communications/socket/send/windows"),
    ];
    let report = create_test_report_with_findings(findings);
    let binary_data = b"test";

    let mapper = CapabilityMapper::empty();
    let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

    // Test prefix match - should find both findings
    let condition = Condition::Trait {
        id: "micro-behaviors/communications/socket/send".to_string(),
    };
    let result = debugger.debug_condition(&condition);

    assert!(
        result.matched,
        "Prefix 'micro-behaviors/communications/socket/send' should match findings with that prefix"
    );
    // Should mention both matched findings
    let detail_text = result.details.join(" ");
    assert!(
        detail_text.contains("2 finding"),
        "Should mention 2 findings matched, got: {}",
        detail_text
    );
}
