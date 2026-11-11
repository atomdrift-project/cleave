#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crate as cleave;
use std::fs;
use tempfile::TempDir;
fn write_minimal_pe_at(buf: &mut Vec<u8>, offset: usize, section_count: u16) {
    const E_LFANEW: usize = 0x80;
    const OPTIONAL_HEADER_SIZE: u16 = 0xE0;
    const FIRST_SECTION_RAW_PTR: u32 = 0x200;
    const FIRST_SECTION_RAW_SIZE: u32 = 0x200;
    const SIZE_OF_IMAGE: u32 = 0x1000;

    let pe = offset + E_LFANEW;
    let section_table = pe + 24 + OPTIONAL_HEADER_SIZE as usize;
    let min_len = offset + FIRST_SECTION_RAW_PTR as usize + FIRST_SECTION_RAW_SIZE as usize;
    if buf.len() < min_len {
        buf.resize(min_len, 0);
    }

    buf[offset] = 0x4D; // M
    buf[offset + 1] = 0x5A; // Z
    buf[offset + 0x3C..offset + 0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());

    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    buf[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // Machine: i386
    buf[pe + 6..pe + 8].copy_from_slice(&section_count.to_le_bytes());
    buf[pe + 20..pe + 22].copy_from_slice(&OPTIONAL_HEADER_SIZE.to_le_bytes());
    buf[pe + 24..pe + 26].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    buf[pe + 24 + 56..pe + 24 + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());

    // Minimal .text section that satisfies embedded_binary_detector validation.
    let section = section_table;
    buf[section..section + 8].copy_from_slice(b".text\0\0\0");
    buf[section + 8..section + 12].copy_from_slice(&FIRST_SECTION_RAW_SIZE.to_le_bytes()); // VirtualSize
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    buf[section + 16..section + 20].copy_from_slice(&FIRST_SECTION_RAW_SIZE.to_le_bytes()); // SizeOfRawData
    buf[section + 20..section + 24].copy_from_slice(&FIRST_SECTION_RAW_PTR.to_le_bytes());
    // PointerToRawData
}

/// Minimal PE stub with a valid section table and raw section span.
fn minimal_pe_stub() -> Vec<u8> {
    let mut buf = Vec::new();
    write_minimal_pe_at(&mut buf, 0, 1);
    buf
}

/// Embed a valid PE32 header at `offset` within `buf`.
fn embed_pe_at(buf: &mut Vec<u8>, offset: usize) {
    write_minimal_pe_at(buf, offset, 2);
}

/// Embed a valid ELF64 LE header at `offset` within `buf`.
#[allow(dead_code)]
fn embed_elf_at(buf: &mut Vec<u8>, offset: usize) {
    while buf.len() < offset + 64 {
        buf.push(0u8);
    }
    buf[offset] = 0x7F;
    buf[offset + 1] = 0x45; // E
    buf[offset + 2] = 0x4C; // L
    buf[offset + 3] = 0x46; // F
    buf[offset + 4] = 2; // EI_CLASS: 64-bit
    buf[offset + 5] = 1; // EI_DATA: LE
    buf[offset + 6] = 1; // EI_VERSION: 1
    buf[offset + 16..offset + 18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf[offset + 18..offset + 20].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
}

// These rules can match only a carved child (the host exceeds size_max).
// Reading the parent's raw bytes must not substitute for child inheritance.
fn embedded_carrier_report(include_right: bool) -> cleave::types::AnalysisReport {
    let tmp = TempDir::new().unwrap();
    let rules = tmp.path().join("rules.yaml");
    fs::write(
        &rules,
        r#"
defaults:
  platforms: [unix, windows]
traits:
  - id: "test/payload::left"
    desc: Left child behavior
    for: [pe]
    crit: suspicious
    conf: 1.0
    size_max: 1500
    if:
      type: raw
      substr: "CHILD_LEFT_BEHAVIOR"
  - id: "test/payload::right"
    desc: Right child behavior
    for: [pe]
    crit: suspicious
    conf: 1.0
    size_max: 1500
    if:
      type: raw
      substr: "CHILD_RIGHT_BEHAVIOR"
composite_rules:
  - id: "test/carrier::child-pair"
    desc: Combines behavior from two children
    for: [pe]
    scope: archive
    crit: hostile
    conf: 1.0
    all:
      - id: "test/payload::left"
      - id: "test/payload::right"
"#,
    )
    .unwrap();
    let mapper =
        std::sync::Arc::new(cleave::capabilities::CapabilityMapper::from_yaml(&rules).unwrap());
    let mut bytes = minimal_pe_stub();
    bytes.resize(0x3000, 0);
    embed_pe_at(&mut bytes, 0x800);
    let left = b"CHILD_LEFT_BEHAVIOR";
    bytes[0xa20..0xa20 + left.len()].copy_from_slice(left);
    if include_right {
        embed_pe_at(&mut bytes, 0x1800);
        let right = b"CHILD_RIGHT_BEHAVIOR";
        bytes[0x1a20..0x1a20 + right.len()].copy_from_slice(right);
    }
    let path = tmp.path().join("carrier.exe");
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

#[test]
fn embedded_carrier_inherits_child_findings_with_canonical_paths() {
    let report = embedded_carrier_report(false);
    let root = &report.files[0];
    let child = report
        .files
        .iter()
        .find(|f| f.depth == 1)
        .expect("embedded PE child");
    assert_eq!(child.parent_id, Some(root.id));
    assert_eq!(child.path, format!("{}!!embedded:pe@0x800", root.path));
    let inherited = root
        .findings
        .iter()
        .find(|f| f.id == "test/payload::left")
        .expect("root inherits child behavior");
    assert_eq!(inherited.crit, cleave::types::Criticality::Suspicious);
    assert_eq!(inherited.src, Some(child.id));
    assert!(child.findings.iter().any(|f| f.id == "test/payload::left"));
    assert!(
        !root
            .findings
            .iter()
            .any(|f| f.id == "test/carrier::child-pair"),
        "one child must not satisfy a two-child composite"
    );
}

#[test]
fn embedded_carrier_combines_distinct_children_without_sibling_leakage() {
    let mut report = embedded_carrier_report(true);
    let root = &report.files[0];
    let composite = root
        .findings
        .iter()
        .find(|f| f.id == "test/carrier::child-pair")
        .expect("carrier composite sees both children");
    assert_eq!(composite.crit, cleave::types::Criticality::Hostile);
    let children: Vec<_> = report.files.iter().filter(|f| f.depth == 1).collect();
    assert_eq!(children.len(), 2);
    for child in children {
        assert_eq!(child.parent_id, Some(root.id));
        assert_eq!(
            child
                .findings
                .iter()
                .filter(|f| f.id.starts_with("test/payload::"))
                .count(),
            1
        );
        assert!(
            !child
                .findings
                .iter()
                .any(|f| f.id == "test/carrier::child-pair"),
            "a child must not see its sibling's evidence"
        );
    }
    let sources = root
        .composite_sources
        .get("test/carrier::child-pair")
        .expect("cross-file provenance");
    assert_eq!(sources.len(), 2);
    assert_ne!(sources[0].file, sources[1].file);
    report.strip_unmatched_traits();
    let compact = cleave::types::compact_from_files(&report.files, cleave::types::Facts::Full);
    let wire = serde_json::to_value(&compact).unwrap();
    let traits = wire["files"][0]["traits"].as_array().unwrap();
    assert!(traits.iter().any(|f| f["id"] == "test/carrier::child-pair"));
}

#[test]
fn carrier_composite_policy_covers_every_file_type_and_anonymous_children() {
    use crate::types::{AnalysisReport, Criticality, FileAnalysis, Finding, TargetInfo};
    let dir = TempDir::new().unwrap();
    let rules = dir.path().join("rules.yaml");
    fs::write(
        &rules,
        r#"
defaults:
  platforms: [unix, windows]
  crit: notable
  conf: 1.0
traits:
  - id: test/child::left
    desc: Left behavior
    if: {type: raw, substr: left}
  - id: test/child::right
    desc: Right behavior
    if: {type: raw, substr: right}
composite_rules:
  - id: test/carrier::pooled
    desc: Behavior across children
    scope: archive
    all: [{id: test/child::left}, {id: test/child::right}]
  - id: test/carrier::python-only
    desc: Requires Python origin evidence
    for: [python]
    scope: archive
    all: [{id: test/child::left}, {id: test/child::right}]
  - id: test/carrier::local
    desc: Behavior in one file
    scope: file
    all: [{id: test/child::left}, {id: test/child::right}]
  - id: test/carrier::leaf
    desc: Behavior in one leaf
    scope: leaf
    all: [{id: test/child::left}, {id: test/child::right}]
"#,
    )
    .unwrap();
    let mapper =
        std::sync::Arc::new(crate::capabilities::CapabilityMapper::from_yaml(&rules).unwrap());
    let engine = crate::Engine::from_rules(mapper);
    // Derive this matrix from the enum so new file types get coverage automatically.
    for kind in crate::composite_rules::FileType::all_concrete_variants() {
        let kind = serde_json::to_value(kind)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        for delimiter in ["!!", "##"] {
            for nested in [false, true] {
                let mut report = AnalysisReport::new(TargetInfo {
                    path: "/samples/carrier".into(),
                    file_type: kind.clone(),
                    size_bytes: 1,
                    sha256: "root".into(),
                    architectures: None,
                });
                report.engine = Some(engine.clone());
                let owner = if nested {
                    let path = format!("/samples/carrier{delimiter}embedded:wrapper");
                    let mut wrapper =
                        FileAnalysis::new(0, path.clone(), "unknown".into(), "wrapper".into(), 1);
                    wrapper.depth = 1;
                    report.files.push(wrapper);
                    path
                } else {
                    "/samples/carrier".to_string()
                };
                for (i, name) in ["left", "right"].into_iter().enumerate() {
                    let mut child = FileAnalysis::new(
                        report.files.len() as u32,
                        format!("{owner}{delimiter}embedded:unknown@{i}"),
                        "unknown".into(),
                        name.into(),
                        1,
                    );
                    child.depth = if nested { 2 } else { 1 };
                    let mut finding =
                        Finding::capability(format!("test/child::{name}"), name.into(), 1.0);
                    finding.crit = Criticality::Notable;
                    child.findings.push(finding);
                    report.files.push(child);
                }
                super::evaluate_child_composites(&mut report, b"", &engine);
                report.finalize();
                let root = &report.files[0];
                assert!(
                    root.findings.iter().any(|f| f.id == "test/carrier::pooled"),
                    "{kind} {delimiter}"
                );
                assert!(
                    !root
                        .findings
                        .iter()
                        .any(|f| f.id == "test/carrier::local" || f.id == "test/carrier::leaf"),
                    "file/leaf scope pooled children: {kind}"
                );
                assert_eq!(
                    root.composite_sources["test/carrier::pooled"].len(),
                    2,
                    "{kind} {delimiter}"
                );
                assert!(
                    !root
                        .findings
                        .iter()
                        .any(|f| f.id == "test/carrier::python-only"),
                    "child origin restriction lost: {kind} {delimiter}"
                );
                for child in report
                    .files
                    .iter()
                    .filter(|f| f.path.contains("embedded:unknown@"))
                {
                    assert_eq!(child.parent_id, Some(if nested { 1 } else { root.id }));
                    assert_eq!(child.findings.len(), 1, "sibling leakage: {kind}");
                }
            }
        }
    }
}
