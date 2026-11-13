use super::*;

/// One plain (unobfuscated, uncompressed) `ISSetupStream` entry.
fn entry(name: &str, data: &[u8]) -> Vec<u8> {
    let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut entry = Vec::new();
    entry.extend_from_slice(&u32::try_from(name.len()).unwrap().to_le_bytes());
    entry.extend_from_slice(&0u32.to_le_bytes());
    entry.extend_from_slice(&[0; 2]);
    entry.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    entry.extend_from_slice(&[0; 8]);
    entry.extend_from_slice(&1u16.to_le_bytes());
    entry.extend_from_slice(&name);
    entry.extend_from_slice(data);
    entry
}

fn stream(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut stream = installshield::MAGIC.to_vec();
    stream.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
    stream.resize(46, 0);
    for entry in entries {
        stream.extend_from_slice(entry);
    }
    stream
}

fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn installshield_entries_become_sanitized_unique_members() {
    let data = stream(&[
        entry("Product.msi", b"msi"),
        entry("..\\..\\evil.dll", b"one"),
        entry("dir/evil.dll", b"two"),
        entry("..", b"three"),
    ]);
    let out = tempfile::tempdir().unwrap();
    assert_eq!(
        extract_installshield(&data, Path::new("setup.exe"), out.path()),
        4
    );
    assert_eq!(
        files(out.path()),
        vec![
            ("Product.msi".to_string(), b"msi".to_vec()),
            ("entry".to_string(), b"three".to_vec()),
            ("evil.dll".to_string(), b"one".to_vec()),
            ("evil.dll~2".to_string(), b"two".to_vec()),
        ]
    );
}

#[test]
fn unreadable_or_truncated_streams_write_what_decodes() {
    let out = tempfile::tempdir().unwrap();
    assert_eq!(
        extract_installshield(b"MZ", Path::new("x.exe"), out.path()),
        0
    );
    let mut data = stream(&[entry("kept.txt", b"kept"), entry("cut.txt", &[7; 64])]);
    data.truncate(data.len() - 8);
    assert_eq!(
        extract_installshield(&data, Path::new("x.exe"), out.path()),
        1
    );
    assert_eq!(
        files(out.path()),
        vec![("kept.txt".to_string(), b"kept".to_vec())]
    );
}

#[test]
fn output_cap_applies_ratio_entry_and_budget_limits() {
    assert_eq!(
        output_cap(1000, MAX_TOTAL_BYTES),
        MIN_ZIP_BOMB_UNCOMPRESSED_SIZE
    );
    assert_eq!(
        output_cap(10 << 20, MAX_TOTAL_BYTES),
        MAX_ENTRY_BYTES.min((10 << 20) * MAX_COMPRESSION_RATIO)
    );
    assert_eq!(output_cap(usize::MAX, MAX_TOTAL_BYTES), MAX_ENTRY_BYTES);
    assert_eq!(output_cap(1000, 10), 10);
}

/// An NSIS installer whose header block is stored uncompressed: one `Exec`.
fn nsis_installer() -> Vec<u8> {
    let command = b"rundll32.exe payload.dll,Run\0";
    let entries_at = 4 + 8 * 8;
    let strings_at = entries_at + 28;
    let mut header = 0u32.to_le_bytes().to_vec();
    let mut blocks = [(0u32, 0u32); 8];
    blocks[2] = (u32::try_from(entries_at).unwrap(), 1);
    blocks[3] = (u32::try_from(strings_at).unwrap(), 0);
    blocks[4] = (u32::try_from(strings_at + 1 + command.len()).unwrap(), 0);
    for (offset, count) in blocks {
        header.extend_from_slice(&offset.to_le_bytes());
        header.extend_from_slice(&count.to_le_bytes());
    }
    for field in [41i32, 1, 0, 0, 0, 0, 0] {
        header.extend_from_slice(&field.to_le_bytes());
    }
    header.push(0);
    header.extend_from_slice(command);
    let mut data = b"MZ".to_vec();
    data.resize(512, 0);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(b"\xef\xbe\xad\xdeNullsoftInst");
    data.extend_from_slice(&u32::try_from(header.len()).unwrap().to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&u32::try_from(header.len()).unwrap().to_le_bytes());
    data.extend_from_slice(&header);
    data
}

#[test]
fn nsis_script_is_written_as_a_member_and_never_overwrites() {
    let out = tempfile::tempdir().unwrap();
    assert!(write_nsis_script(
        &nsis_installer(),
        Path::new("i.exe"),
        out.path()
    ));
    let script = std::fs::read_to_string(out.path().join(NSIS_SCRIPT_NAME)).unwrap();
    assert!(
        script.contains("Exec \"rundll32.exe payload.dll,Run\""),
        "{script}"
    );
    // A script already extracted there is kept.
    std::fs::write(out.path().join(NSIS_SCRIPT_NAME), "from 7-Zip").unwrap();
    assert!(!write_nsis_script(
        &nsis_installer(),
        Path::new("i.exe"),
        out.path()
    ));
    assert_eq!(
        std::fs::read_to_string(out.path().join(NSIS_SCRIPT_NAME)).unwrap(),
        "from 7-Zip"
    );
    // Not an NSIS installer: nothing written.
    let empty = tempfile::tempdir().unwrap();
    assert!(!write_nsis_script(b"MZ", Path::new("i.exe"), empty.path()));
    assert!(files(empty.path()).is_empty());
}

#[test]
fn installshield_kind_routes_to_native_extraction() {
    let values = filefacts::Values::from(serde_json::json!({
        "binary": {"installer": {"kind": "installshield", "marker_offset": 1024}}
    }));
    assert_eq!(
        super::super::installer_from_values(&values, 0),
        Some((super::super::SfxKind::InstallShield, Some(1024)))
    );
}
