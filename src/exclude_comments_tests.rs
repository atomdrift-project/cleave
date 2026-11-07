//! `exclude_comments` on `type: text`: commented-out code and prose do not
//! match, the same text in code does, and rules without the option still
//! read comments. Runs the whole pipeline so the comment spans come from
//! filefacts, as in a scan.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::sync::Arc;

use crate::capabilities::CapabilityMapper;
use crate::{AnalysisOptions, analyze_file_with_mapper};

const RULES: &str = r#"
defaults:
  platforms: [windows, linux, macos]
  crit: notable
  conf: 0.9
traits:
  - id: test/comments::wallet-key-in-code
    desc: Wallet key variable outside comments
    for: [javascript]
    if: {type: text, regex: 'process\.env\.WALLET_PRIVATE_KEY', exclude_comments: true}
  - id: test/comments::wallet-key-anywhere
    desc: Wallet key variable anywhere
    for: [javascript]
    if: {type: text, regex: 'process\.env\.WALLET_PRIVATE_KEY'}
  - id: test/comments::variant-in-code
    desc: Malware variant term outside comments
    for: [python]
    if: {type: text, regex: '(?i)\bvariants?\b.{0,32}\bmalware\b', exclude_comments: true}
  - id: test/comments::public-exe-in-code
    desc: Public-folder executable outside comments
    for: [batch]
    if: {type: text, regex: '(?i)Users\\Public\\\w+\.exe', exclude_comments: true}
"#;

fn ids(suffix: &str, content: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules.yaml");
    std::fs::write(&rules, RULES).unwrap();
    let mapper = Arc::new(CapabilityMapper::from_yaml(&rules).unwrap());
    let mut file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    let options = AnalysisOptions {
        yara: false,
        ..AnalysisOptions::default()
    };
    let report = analyze_file_with_mapper(file.path(), &options, &mapper).unwrap();
    let mut ids: Vec<String> = report
        .findings
        .iter()
        .chain(report.files.iter().flat_map(|f| f.findings.iter()))
        .map(|f| f.id.to_string())
        .filter(|id| id.starts_with("test/comments::"))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn commented_out_code_does_not_match() {
    let found = ids(".js", "// const key = process.env.WALLET_PRIVATE_KEY;\n");
    assert_eq!(found, ["test/comments::wallet-key-anywhere"]);
}

#[test]
fn code_still_matches() {
    let found = ids(
        ".js",
        "// read the key\nconst key = process.env.WALLET_PRIVATE_KEY;\n",
    );
    assert_eq!(
        found,
        [
            "test/comments::wallet-key-anywhere",
            "test/comments::wallet-key-in-code"
        ]
    );
}

#[test]
fn python_and_batch_comments_are_masked() {
    assert!(ids(".py", "# Generate variants for this malware payload.\n").is_empty());
    assert_eq!(
        ids(".py", "label = 'variants of malware'\n"),
        ["test/comments::variant-in-code"]
    );
    assert!(ids(".bat", "rem copy to Users\\Public\\worker.exe\r\n").is_empty());
    assert_eq!(
        ids(".bat", "copy a.bin Users\\Public\\worker.exe\r\n"),
        ["test/comments::public-exe-in-code"]
    );
}
