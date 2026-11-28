#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! A GGUF model end to end: its chat template and trailing bytes are
//! analyzed as files of their own, a raw deflate tail inflates like any
//! compressed file, and the tensor weights are never read.

use std::fs;
use std::io::Write;
use tempfile::TempDir;

const RULES: &str = r#"
defaults:
  platforms: [unix, windows]
traits:
  - id: "test/template::marker"
    desc: Template marker
    for: [text, gguf]
    crit: notable
    if:
      type: text
      substr: "TEMPLATE_MARKER"
  - id: "test/tail::marker"
    desc: Tail marker
    for: [pe]
    crit: notable
    if:
      type: raw
      substr: "TAIL_MARKER"
  - id: "test/weights::marker"
    desc: Weights marker
    for: [gguf]
    crit: notable
    if:
      type: raw
      substr: "WEIGHTS_MARKER"
"#;

/// A minimal PE32+ image carrying `marker`.
fn pe(marker: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; 0x400];
    image[..2].copy_from_slice(b"MZ");
    image[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    image[0x80..0x84].copy_from_slice(b"PE\0\0");
    image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    image[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    image[0x300..0x300 + marker.len()].copy_from_slice(marker);
    image
}

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// A GGUF model whose template and weights carry markers, with `tail` past
/// its last tensor.
fn model(tail: &[u8]) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s);
    }
    let template = b"{% for m in messages %}TEMPLATE_MARKER {{ m.content }}{% endfor %}";
    let mut out = b"GGUF".to_vec();
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    string(&mut out, b"tokenizer.chat_template");
    out.extend_from_slice(&8u32.to_le_bytes());
    string(&mut out, template);
    string(&mut out, b"w");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&64u64.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.resize(out.len().next_multiple_of(32), 0);
    let mut weights = vec![0x11u8; 256];
    weights[100..114].copy_from_slice(b"WEIGHTS_MARKER");
    out.extend_from_slice(&weights);
    out.extend_from_slice(tail);
    out
}

fn analyze(bytes: &[u8]) -> cleave::types::AnalysisReport {
    let tmp = TempDir::new().unwrap();
    let rules = tmp.path().join("rules.yaml");
    fs::write(&rules, RULES).unwrap();
    let mapper =
        std::sync::Arc::new(cleave::capabilities::CapabilityMapper::from_yaml(&rules).unwrap());
    let path = tmp.path().join("model.gguf");
    fs::write(&path, bytes).unwrap();
    let mut report = cleave::analyze_file_with_mapper(
        &path,
        &cleave::AnalysisOptions {
            yara: false,
            ..Default::default()
        },
        &mapper,
    )
    .unwrap();
    report.finalize();
    report
}

/// Each file's path tail, type, and the test findings it carries.
fn files(report: &cleave::types::AnalysisReport) -> Vec<(String, String, Vec<String>)> {
    report
        .files
        .iter()
        .map(|f| {
            let name = f
                .path
                .rsplit_once("model.gguf")
                .map_or("", |(_, rest)| rest);
            let ids = f
                .findings
                .iter()
                .map(|x| x.id.to_string())
                .filter(|id| id.starts_with("test/"))
                .collect();
            (name.to_string(), f.file_type.clone(), ids)
        })
        .collect()
}

#[test]
fn template_and_deflated_tail_are_analyzed_and_weights_are_not() {
    let report = analyze(&model(&raw_deflate(&pe(b"TAIL_MARKER"))));
    let files = files(&report);
    let has = |name_prefix: &str, file_type: &str, id: Option<&str>| {
        files.iter().any(|(name, ft, ids)| {
            name.starts_with(name_prefix)
                && ft == file_type
                && id.is_none_or(|id| ids.iter().any(|x| x == id))
        })
    };
    assert!(
        has(
            "##gguf-chat-template@",
            "text",
            Some("test/template::marker")
        ),
        "{files:?}"
    );
    assert!(has("##gguf-trailing-data@", "deflate", None), "{files:?}");
    assert!(
        has("##gguf-trailing-data@", "pe", Some("test/tail::marker")),
        "{files:?}"
    );
    assert!(
        files
            .iter()
            .all(|(_, _, ids)| !ids.iter().any(|x| x == "test/weights::marker")),
        "tensor weights must not be scanned: {files:?}"
    );
    let mut names: Vec<&str> = files.iter().map(|(name, _, _)| name.as_str()).collect();
    let all = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), all, "every file has its own path: {files:?}");
}

#[test]
fn plain_executable_tail_is_its_own_file() {
    let report = analyze(&model(&pe(b"TAIL_MARKER")));
    let files = files(&report);
    assert!(
        files
            .iter()
            .any(|(name, ft, ids)| name.starts_with("##gguf-trailing-data@")
                && ft == "pe"
                && ids.iter().any(|x| x == "test/tail::marker")),
        "{files:?}"
    );
}

#[test]
fn child_files_are_exact_chains() {
    let chain = |c: &[&str]| c.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    assert!(super::is_child_file(&chain(&["gguf-chat-template"])));
    assert!(super::is_child_file(&chain(&["mime-base64"])));
    assert!(!super::is_child_file(&chain(&["mime-base64", "gzip"])));
    assert!(!super::is_child_file(&chain(&["base64"])));
}
