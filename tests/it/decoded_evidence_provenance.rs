//! A decoded member's offsets are local to that member. Composites on its
//! wrapper must carry member provenance, while the member keeps byte context.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

const MARKER: &[u8] = b"fixture_clipboard_evidence_marker";
const OFFSET: usize = 512;
const ATOM: &str = "metadata/test/decoded::payload-marker";
const COMPOSITE: &str = "metadata/test/decoded::wrapper-marker";

fn payload() -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&128u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[132..134].copy_from_slice(&0x14cu16.to_le_bytes());
    bytes[148..150].copy_from_slice(&224u16.to_le_bytes());
    bytes[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
    bytes[OFFSET..OFFSET + MARKER.len()].copy_from_slice(MARKER);
    bytes
}

fn analyze(root: &Path, path: &Path) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_cleave"))
        .args([
            "--traits-dir",
            root.to_str().unwrap(),
            "--disable",
            "yara,radare2,upx",
            "--format",
            "snapshot",
            "analyze",
            path.to_str().unwrap(),
        ])
        .env("CLEAVE_SKIP_CACHE", "1")
        .env("CLEAVE_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    let errors = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "{errors}");
    assert!(
        !errors.contains("content match has no file offset"),
        "{errors}"
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn setup(root: &Path) -> std::path::PathBuf {
    let rules = root.join("metadata/test/decoded");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("markers.yaml"),
        r#"
defaults:
  platforms: [unix, windows]
traits:
  - id: payload-marker
    desc: Decoded payload byte marker
    crit: notable
    conf: 1.0
    for: [pe]
    if: {type: text, substr: fixture_clipboard_evidence_marker}
composite_rules:
  - id: wrapper-marker
    desc: Wrapper carries decoded byte marker
    crit: suspicious
    conf: 1.0
    for: [powershell]
    any:
      - id: payload-marker
"#,
    )
    .unwrap();
    let numbers = payload()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let source = format!("[Byte[]]$payload = ({numbers})\n");
    assert!(!source.contains(std::str::from_utf8(MARKER).unwrap()));
    let path = root.join("loader.ps1");
    std::fs::write(&path, source).unwrap();
    path
}

fn assert_provenance(report: &Value) {
    let files = report["files"].as_array().unwrap();
    let member = files
        .iter()
        .find(|f| f["file_type"] == "pe")
        .expect("decoded PE analyzed");
    let atom = member["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == ATOM)
        .expect("marker found in decoded bytes");
    let offsets = atom["evidence"][0]["offsets"]
        .as_array()
        .expect("decoded member retains concrete offsets");
    assert!(offsets.iter().any(|n| n.as_u64() == Some(OFFSET as u64)));
    let contexts: Vec<cleave::types::ContextLine> = member["context"]
        .as_array()
        .expect("decoded member retains byte context")
        .iter()
        .map(|c| serde_json::from_value(c.clone()).unwrap())
        .collect();
    assert!(
        contexts.iter().any(|c| {
            let start = c.loc as usize;
            start <= OFFSET
                && OFFSET + MARKER.len() <= start + c.data.len()
                && c.data[OFFSET - start..OFFSET - start + MARKER.len()] == *MARKER
        }),
        "decoded match must render against its own bytes: {contexts:?}"
    );
    let wrapper = files
        .iter()
        .find(|f| f["file_type"] == "powershell")
        .expect("wrapper analyzed");
    let composite = wrapper["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == COMPOSITE)
        .expect("wrapper composite matched decoded member");
    assert!(composite["evidence"].as_array().unwrap().iter().all(|e| {
        e["location"]
            .as_str()
            .is_some_and(|loc| loc.starts_with("archive:") && loc.contains("##"))
    }));
}

#[test]
fn decoded_payload_offsets_remain_local_and_wrapper_evidence_is_member_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let path = setup(dir.path());
    assert_provenance(&analyze(dir.path(), &path));
}

#[test]
fn decoded_payload_provenance_survives_a_containing_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = setup(dir.path());
    let archive = dir.path().join("package.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
    zip.start_file(
        "package/loader.ps1",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    std::io::Write::write_all(&mut zip, &std::fs::read(path).unwrap()).unwrap();
    zip.finish().unwrap();
    assert_provenance(&analyze(dir.path(), &archive));
}

#[test]
fn host_evidence_still_joins_an_existing_literal_program_layer() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("metadata/test/layers");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("markers.yaml"),
        r#"
defaults:
  platforms: [unix, windows]
  for: [powershell]
  conf: 1.0
traits:
  - id: host-marker
    desc: Host literal marker
    crit: notable
    if: {type: text, substr: fixture_wrapper_marker}
  - id: payload-marker
    desc: Decoded script literal marker
    crit: notable
    if: {type: text, substr: fixture_payload_marker}
composite_rules:
  - id: joined-marker
    desc: Host combines with decoded script
    crit: suspicious
    all:
      - id: host-marker
      - id: payload-marker
"#,
    )
    .unwrap();
    let stage = "$value = 'fixture_payload_marker'; Write-Host $value; Write-Host 'inert padding for the literal program reconstruction regression control';";
    let numbers = stage
        .bytes()
        .map(|b| (i32::from(b) - 500).to_string())
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "$key=-500;$data=@({numbers});$code='';for($i=0;$i -lt $data.Length;$i++){{$code += [char]([int32] $data[ $i ] - $key)}};[scriptblock]::Create($code).Invoke();Write-Host 'fixture_wrapper_marker'\n"
    );
    assert!(!source.contains("fixture_payload_marker"));
    let path = dir.path().join("literal-loader.ps1");
    std::fs::write(&path, source).unwrap();
    let report = analyze(dir.path(), &path);
    let files = report["files"].as_array().unwrap();
    assert!(
        files
            .iter()
            .skip(1)
            .any(
                |file| file["findings"].as_array().is_some_and(|findings| findings
                    .iter()
                    .any(|f| f["id"] == "metadata/test/layers::payload-marker"))
            ),
        "literal program must be reconstructed"
    );
    assert!(
        files[0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "metadata/test/layers::joined-marker" && f["crit"] == "suspicious"),
        "host and decoded stage must retain file-scope pooling"
    );
}
