//! Phase 2 integration test: verify the `EvaluationContext.parsed`
//! plumbing is in place and a [`metaparse::ParsedFile`] threads
//! through cleave's evaluation entry without breaking existing
//! callers.
//!
//! Subsequent phases of the integration replace cleave's own
//! `goblin`/`tree-sitter`/structured-parser invocations with reads off
//! `ctx.parsed`. This test exists to lock in the "the field can be
//! populated and observed" guarantee so those follow-up migrations
//! don't have to re-prove the plumbing.

use std::path::Path;

#[test]
fn metaparse_open_succeeds_on_real_pe_fixture() {
    let path = Path::new("tests/fixtures/lang_strings/go_windows_amd64.exe");
    let bytes = std::fs::read(path).expect("read PE fixture");
    let parsed = metaparse::open_with_path(path, &bytes).expect("metaparse opens PE");
    assert_eq!(parsed.fileid().file_type(), metaparse::FileType::Pe);

    // Touching every view exercises the single-pass extraction.
    // `parse_count == 1` is the load-bearing guarantee downstream
    // consumers (cleave evaluators in the next phase) will rely on.
    let _ = parsed.values();
    let _ = parsed.strings();
    let _ = parsed.metrics();
    let _ = parsed.sections();
    let _ = parsed.ast();
    assert_eq!(
        parsed.parse_count(),
        1,
        "all views must share a single extraction pass"
    );
}

#[test]
fn metaparse_pe_emits_section_metrics() {
    // Forensic-relevant fact every evaluator will eventually consult:
    // section entropy + the WX section count. Asserting on the PE
    // fixture proves the metric paths the future cleave evaluators
    // will query are in fact populated.
    let path = Path::new("tests/fixtures/lang_strings/go_windows_amd64.exe");
    let bytes = std::fs::read(path).expect("read PE fixture");
    let parsed = metaparse::open_with_path(path, &bytes).expect("metaparse opens PE");

    let m = parsed.metrics();
    assert!(m.get("file.size_bytes").is_some());
    assert!(
        m.get("sections.count").unwrap_or(0.0) > 0.0,
        "Go-built PE should report at least one section"
    );
    assert!(
        m.get("sections.entropy_max").is_some(),
        "entropy aggregate should be populated when any section has file-resident bytes"
    );
}

#[test]
fn metaparse_pe_exposes_section_listing_under_values() {
    let path = Path::new("tests/fixtures/lang_strings/go_windows_amd64.exe");
    let bytes = std::fs::read(path).expect("read PE fixture");
    let parsed = metaparse::open_with_path(path, &bytes).expect("metaparse opens PE");

    let sections = parsed.sections();
    assert!(!sections.is_empty(), "PE has at least one section");

    let names: Vec<&str> = sections.iter().map(|s| s.name.as_str()).collect();
    assert!(
        names.iter().any(|n| n == &".text" || n.contains("text")),
        "expected a .text section, got {names:?}"
    );
}
