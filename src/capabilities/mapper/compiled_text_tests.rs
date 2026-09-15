//! Compiled AppleScript must use extracted text throughout evaluation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::composite_rules::context::{EvaluationContext, StringParams};
use crate::composite_rules::evaluators::eval_text;
use crate::types::{AnalysisReport, StringInfo, TargetInfo};

const SECRET: &str = "Chrome Safe Storage";

fn compiled() -> Vec<u8> {
    let mut bytes = b"FasdUAS 1.101.10".to_vec();
    bytes.extend(SECRET.encode_utf16().flat_map(u16::to_be_bytes));
    bytes.extend_from_slice(b"raw-only-marker");
    bytes
}

fn report(bytes: &[u8], extracted: bool) -> AnalysisReport {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "fixture.scpt".into(),
        file_type: "applescript".into(),
        size_bytes: bytes.len() as u64,
        sha256: String::new(),
        architectures: None,
    });
    if extracted {
        report.strings.push(StringInfo {
            value: SECRET.into(),
            offset: Some(16),
            encoding: "utf-16be".into(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }
    report
}

fn mapper() -> CapabilityMapper {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("compiled.yaml");
    std::fs::write(
        &path,
        r#"
defaults:
  for: [applescript]
  platforms: [macos]
traits:
  - id: test/compiled::exact
    desc: Stored secret name
    crit: notable
    if: {type: text, exact: "Chrome Safe Storage"}
  - id: test/compiled::substr
    desc: Stored secret substring
    crit: notable
    if: {type: text, substr: "Safe Storage"}
  - id: test/compiled::regex
    desc: Stored secret expression
    crit: notable
    if: {type: text, regex: 'Chrome\s+Safe Storage'}
  - id: test/compiled::word
    desc: Stored secret word
    crit: notable
    if: {type: text, word: "Chrome"}
  - id: test/compiled::gibberish
    desc: Raw bytes are not extracted text
    crit: notable
    if: {type: text, substr: "raw-only-marker"}
  - id: test/compiled::raw
    desc: Explicit raw content still matches
    crit: notable
    if: {type: raw, substr: "raw-only-marker"}
  - id: test/compiled::part-raw
    desc: Raw composite component
    crit: component
    if: {type: raw, regex: 'raw-only-marker'}
  - id: test/compiled::part-text
    desc: Text composite component
    crit: component
    if: {type: text, regex: 'Chrome\s+Safe Storage'}
composite_rules:
  - id: test/compiled::combined
    desc: Raw and stored text
    crit: notable
    all:
      - id: test/compiled::part-raw
      - id: test/compiled::part-text
"#,
    )
    .unwrap();
    CapabilityMapper::from_yaml(&path).unwrap()
}

#[test]
fn compiled_text_mode_depends_on_magic_and_file_type() {
    assert!(RuleFileType::AppleScript.uses_raw_text_search());
    assert!(!RuleFileType::AppleScript.uses_raw_text_search_for(b"FasdUAS 1.101.10"));
    assert!(RuleFileType::AppleScript.uses_raw_text_search_for(b"Fas"));
    assert!(RuleFileType::AppleScript.uses_raw_text_search_for(b"set x to \"Fasd\""));
    assert!(RuleFileType::AppleScript.uses_raw_text_search_for(b""));
    // The compiled-format gate must use the format's full magic. A source
    // file that merely starts with the 4-byte prefix is still source: if it
    // switched the haystack to extracted strings, an attacker could disable
    // every `type: text` rule by prepending four bytes.
    assert!(RuleFileType::AppleScript.uses_raw_text_search_for(b"Fasd is not compiled"));
    assert!(RuleFileType::AppleScript.uses_raw_text_search_for(b"FasdUAS"));
    for kind in [
        RuleFileType::Python,
        RuleFileType::Text,
        RuleFileType::Pe,
        RuleFileType::Json,
    ] {
        assert_eq!(
            kind.uses_raw_text_search_for(b"FasdUAS 1.101.10"),
            kind.uses_raw_text_search()
        );
    }
}

#[test]
fn source_prefixed_with_partial_magic_still_matches_raw_text_rules() {
    let mapper = mapper();
    // `exact:` matches a whole trimmed line in raw-text mode, so the partial
    // magic sits on its own line rather than fused to the secret.
    let mut bytes = b"Fasd\n".to_vec();
    bytes.extend_from_slice(SECRET.as_bytes());
    bytes.resize(200, b'\n');
    let report = report(&bytes, false);
    let findings = mapper.evaluate_traits(&report, &bytes);
    for suffix in ["exact", "substr", "regex", "word"] {
        let id = format!("test/compiled::{suffix}");
        assert!(
            findings.iter().any(|f| f.id == id),
            "four magic bytes suppressed raw-text rule {id}"
        );
    }
}

#[test]
fn compiled_text_reads_utf16_extraction_not_raw_bytes() {
    let bytes = compiled();
    let report = report(&bytes, true);
    let ctx = EvaluationContext::new(
        &report,
        &bytes,
        RuleFileType::AppleScript,
        &[Platform::All],
        None,
        None,
    );
    // The container happens to be valid UTF-8, but it is still compiled data.
    assert!(std::str::from_utf8(&bytes).is_ok());
    assert!(ctx.cached_source_utf8.is_none());
    for (needle, matched) in [(SECRET, true), ("raw-only-marker", false)] {
        let needle = needle.to_string();
        let params = StringParams {
            exact: None,
            substr: Some(&needle),
            regex: None,
            word: None,
            case_insensitive: false,
            length_min: None,
            length_max: None,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            arch_clamp: None,
        };
        assert_eq!(eval_text(&params, None, &ctx, None).matched, matched);
    }
}

#[test]
fn compiled_text_prefilter_uses_stored_strings() {
    let mapper = mapper();
    let bytes = compiled();
    let report = report(&bytes, true);
    let prefilter = build_string_prefilter(
        &mapper.match_indexes().string_match_index,
        &RuleFileType::AppleScript,
        &bytes,
        &report,
    );
    assert!(!prefilter.source_text_prefiltered);
    for suffix in ["exact", "substr"] {
        let idx = mapper
            .trait_definitions
            .iter()
            .position(|t| t.id == format!("test/compiled::{suffix}"))
            .unwrap();
        assert!(prefilter.matched.contains(&idx), "{suffix}");
    }
    let source = SECRET.as_bytes();
    let source_report = self::report(source, false);
    assert!(
        !build_string_prefilter(
            &mapper.match_indexes().string_match_index,
            &RuleFileType::AppleScript,
            source,
            &source_report,
        )
        .source_text_prefiltered
    );
    let mut source = source.to_vec();
    source.resize(StringMatchIndex::MIN_SOURCE_TEXT_PREFILTER_BYTES, b'\n');
    let source_report = self::report(&source, false);
    assert!(
        build_string_prefilter(
            &mapper.match_indexes().string_match_index,
            &RuleFileType::AppleScript,
            &source,
            &source_report,
        )
        .source_text_prefiltered
    );
}

#[test]
fn compiled_text_runtime_prefilters_agree() {
    let mapper = mapper();
    let bytes = compiled();
    for pass in 0..3 {
        let mut report = report(&bytes, true);
        let findings = match pass {
            0 => mapper.evaluate_traits(&report, &bytes),
            1 => mapper.evaluate_traits_filtered(&report, &bytes, None, None, false),
            _ => {
                mapper.evaluate_and_merge_findings(&mut report, &bytes, None, None);
                report.findings
            }
        };
        for suffix in ["exact", "substr", "regex", "word", "raw"] {
            let id = format!("test/compiled::{suffix}");
            assert!(findings.iter().any(|f| f.id == id), "pass {pass}: {id}");
        }
        assert!(!findings.iter().any(|f| f.id == "test/compiled::gibberish"));
        if pass == 2 {
            assert!(findings.iter().any(|f| f.id == "test/compiled::combined"));
        }
    }
}

#[test]
fn compiled_text_source_still_matches_without_extracted_strings() {
    let mapper = mapper();
    // The mapper intentionally skips sub-100-byte files with no extracted facts.
    // Cover source matching both below and at the 16 KiB prefilter threshold.
    for size in [100, StringMatchIndex::MIN_SOURCE_TEXT_PREFILTER_BYTES] {
        let mut bytes = SECRET.as_bytes().to_vec();
        bytes.resize(size, b'\n');
        let report = report(&bytes, false);
        let findings = mapper.evaluate_traits(&report, &bytes);
        for suffix in ["exact", "substr", "regex", "word"] {
            let id = format!("test/compiled::{suffix}");
            assert!(findings.iter().any(|f| f.id == id), "size {size}: {id}");
        }
    }
}

#[test]
fn compiled_text_small_source_exact_matches_a_complete_line() {
    let bytes = SECRET.as_bytes();
    let report = report(bytes, false);
    let ctx = EvaluationContext::new(
        &report,
        bytes,
        RuleFileType::AppleScript,
        &[Platform::MacOS],
        None,
        None,
    );
    assert_eq!(ctx.cached_source_utf8, Some(SECRET));
    let exact = SECRET.to_string();
    let params = StringParams {
        exact: Some(&exact),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        length_min: None,
        length_max: None,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };
    assert!(eval_text(&params, None, &ctx, None).matched);
}
