use super::*;

/// Archive members and Office macros take the `Arc` factory, top-level
/// files the plain one. They are one table now; the `Arc` copy used to lack
/// Flatpak, which it then treated as an archive and left unanalyzed.
#[test]
fn both_factories_cover_the_same_types() {
    for file_type in [FileType::Flatpak, FileType::Yaml, FileType::PgpSignature] {
        assert!(
            analyzer_for_file_type(&file_type, None).is_some(),
            "{file_type:?}"
        );
        assert!(
            analyzer_for_file_type_arc(&file_type, &crate::Engine::empty()).is_some(),
            "{file_type:?}"
        );
    }
}

#[test]
fn bridge_detect_from_disk() {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::with_suffix(".py").unwrap();
    f.write_all(b"import os\n").unwrap();
    assert_eq!(detect_file_type(f.path()).unwrap(), FileType::Python);
}

/// Commands type a file from the same full contents a scan reads: a
/// call-over-blob shellcode whose `pop` target lies past the first KiB must
/// be shellcode both ways (it was `data` when commands sniffed a 1 KiB prefix).
#[test]
fn detect_file_type_matches_scan_detection_past_first_kib() {
    let mut data = vec![0xE8, 0x00, 0x10, 0x00, 0x00];
    data.extend(std::iter::repeat_n(0xA5u8, 0x1000));
    data.extend([0x59, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xC3]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload.bin");
    std::fs::write(&path, &data).unwrap();
    let scanned = detect_file_type_from_data(&path, &data);
    assert_eq!(detect_file_type(&path).unwrap(), scanned);
    assert_eq!(scanned, FileType::Shellcode);
}

#[test]
fn bridge_report_file_type_delegates_to_filefacts_label() {
    // The report type is filefacts's canonical label verbatim — no
    // hand-rolled aliases, no Debug-lowercase mangling.
    assert_eq!(
        FileType::SystemdService.report_file_type(),
        "systemd_service"
    );
    assert_eq!(
        FileType::PythonBytecode.report_file_type(),
        "python_bytecode"
    );
    assert_eq!(FileType::ObjectiveC.report_file_type(), "objective_c");
    assert_eq!(FileType::Elf.report_file_type(), "elf");
}
