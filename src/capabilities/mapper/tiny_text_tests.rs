//! Tiny raw-text files must reach text rules even when their only text is a
//! comment: they carry no extracted strings or symbols, but `type: text`
//! searches the file's own bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::types::{AnalysisReport, TargetInfo};

/// A 31-byte C file whose only content is a comment naming an API.
const COMMENT_ONLY: &[u8] = b"/*\nCryptImportPublicKeyInfo\n*/\n";

fn report(bytes: &[u8]) -> AnalysisReport {
    AnalysisReport::new(TargetInfo {
        path: "fixture.c".into(),
        file_type: "c".into(),
        size_bytes: bytes.len() as u64,
        sha256: String::new(),
        architectures: None,
    })
}

fn mapper() -> CapabilityMapper {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.yaml");
    std::fs::write(
        &path,
        r#"
defaults:
  for: [c]
  platforms: [windows]
  crit: notable
traits:
  - id: test/tiny::exact
    desc: API name as a whole line
    if: {type: text, exact: CryptImportPublicKeyInfo}
  - id: test/tiny::substr
    desc: API name fragment
    if: {type: text, substr: ImportPublicKey}
  - id: test/tiny::regex
    desc: API name expression
    if: {type: text, regex: 'Crypt\w+KeyInfo'}
  - id: test/tiny::word
    desc: API name as a word
    if: {type: text, word: CryptImportPublicKeyInfo}
  # Same matcher, but the unless: reference moves it to the dependent pass.
  - id: test/tiny::exact-dependent
    desc: API name as a whole line, with a trait reference
    if: {type: text, exact: CryptImportPublicKeyInfo}
    unless:
      - id: test/tiny::absent
  - id: test/tiny::absent
    desc: Never present
    if: {type: text, exact: NeverPresentInThisFixture}
"#,
    )
    .unwrap();
    CapabilityMapper::from_yaml(&path).unwrap()
}

fn ids(bytes: &[u8]) -> Vec<String> {
    let mut ids: Vec<String> = mapper()
        .evaluate_traits(&report(bytes), bytes)
        .into_iter()
        .map(|f| f.id.to_string())
        .collect();
    ids.sort();
    ids
}

#[test]
fn comment_only_tiny_source_matches_text_rules() {
    assert!(
        COMMENT_ONLY.len() < 100,
        "fixture must stay below the tiny-file bound"
    );
    let ids = ids(COMMENT_ONLY);
    for suffix in ["exact", "substr", "regex", "word"] {
        let id = format!("test/tiny::{suffix}");
        assert!(ids.contains(&id), "{id} missing from {ids:?}");
    }
}

/// The verdict once depended on whether the rule had an unrelated trait
/// reference: only rules without one were short-circuited.
#[test]
fn tiny_source_verdict_does_not_depend_on_a_trait_reference() {
    let ids = ids(COMMENT_ONLY);
    assert_eq!(
        ids.contains(&"test/tiny::exact".to_string()),
        ids.contains(&"test/tiny::exact-dependent".to_string()),
        "{ids:?}"
    );
    assert!(
        ids.contains(&"test/tiny::exact-dependent".to_string()),
        "{ids:?}"
    );
}

#[test]
fn whitespace_only_tiny_source_has_no_text_findings() {
    assert_eq!(ids(b" \n\t\n"), Vec::<String>::new());
}
