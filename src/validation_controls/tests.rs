use super::*;

#[test]
fn legacy_issue_extracts_prefix_location() {
    let issue = ValidationIssue::legacy("./traits/a.yaml:12: broken rule");
    assert_eq!(issue.file.as_deref(), Some("./traits/a.yaml"));
    assert_eq!(issue.line, Some(12));
    assert_eq!(issue.location(), "./traits/a.yaml:12");
}

#[test]
fn legacy_issue_extracts_in_location() {
    let issue = ValidationIssue::legacy("trait 'x' in \"./traits/a.yaml\": bad");
    assert_eq!(issue.file.as_deref(), Some("./traits/a.yaml"));
    assert_eq!(issue.line, None);
    assert_eq!(issue.location(), "./traits/a.yaml");
}

#[test]
fn detection_integrity_validators_are_hard() {
    // The whole `--soft` policy: these break loading or firing, so they stay
    // fatal even in soft mode.
    for id in [
        "duplicate-trait-id",
        "invalid-file-type",
        "score-caps",
        "self-reference",
        "broken-reference",
        "impossible-constraint",
        "no-search-pattern",
        "malformed-condition",
        "count-min-regex-alternation",
        "invalid-id-chars",
    ] {
        assert_eq!(
            validator_severity(id),
            Severity::Hard,
            "{id} must be Hard (fatal in --soft)"
        );
    }
}

#[test]
fn hygiene_validators_are_soft() {
    // Representative authoring-hygiene checks: the rule loads and fires, so
    // soft mode downgrades them to advisory.
    for id in [
        "regex-length",
        "regex-memory",
        "brittle-path-pattern",
        "oversized-dir",
        "wide-dir",
        "tier-violation",
        "precision",
        "wellknown-size-filter",
        "broad-filetype-cap",
        "for-all",
        "unknown-subdirectory",
        "malware-subcategory",
        "wellknown-composite-only",
        "pure-alias",
        "broad-platform-scope",
        "all-platforms-directory",
        "hostile-too-few-notable-legs",
        // Forward-compat degradation on older engines, not a load-breaking flaw.
        "unknown-metric-field",
        "unknown-file-type",
        // Unknown/legacy ids default to Soft.
        "validation",
    ] {
        assert_eq!(
            validator_severity(id),
            Severity::Soft,
            "{id} must be Soft (advisory in --soft)"
        );
    }
}

#[test]
fn every_hard_id_has_a_spec() {
    // Hard ids must render with a real label/fix, not the UNKNOWN fallback.
    for id in HARD_VALIDATOR_IDS {
        assert!(
            validator_spec(id).is_some(),
            "hard validator {id} needs a ValidatorSpec"
        );
    }
}

#[test]
fn soft_threshold_only_when_soft_mode() {
    set_soft_validation_mode(false);
    assert_eq!(fatal_severity_threshold(), Severity::Soft);
    set_soft_validation_mode(true);
    assert_eq!(fatal_severity_threshold(), Severity::Hard);
    set_soft_validation_mode(false);
}

#[test]
fn terminal_output_groups_fixes() {
    let issues = vec![
        ValidationIssue::new("regex-length", "first").with_location("a.yaml", Some(1)),
        ValidationIssue::new("regex-length", "second").with_location("a.yaml", Some(1)),
    ];
    let out = format_validation_issues_terminal(&issues);
    assert!(out.contains("a.yaml:1"));
    assert!(out.contains("qual/re-len              2"));
    assert_eq!(out.matches("qual/re-len:").count(), 1);
}
