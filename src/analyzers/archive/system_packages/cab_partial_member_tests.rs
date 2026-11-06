use super::*;

#[test]
fn checksum_error_keeps_decompressed_member_prefix_for_analysis() {
    const SAMPLE: &[u8] = include_bytes!("../../../../testdata/cab/corrupt-inner-mszip.cab");
    let dir = tempfile::tempdir().unwrap();
    let guard = ExtractionGuard::new();

    extract_cab_from_reader(Cursor::new(SAMPLE), dir.path(), &guard).unwrap();

    let partial = fs::read(dir.path().join("PO_UB7635_Specifications_Details.cmd")).unwrap();
    assert!(
        partial
            .windows(b"extrac32 /y".len())
            .any(|window| window == b"extrac32 /y")
    );
    assert!(guard.take_extraction_notes().iter().any(|note| {
        note.contains("PO_UB7635_Specifications_Details.cmd") && note.contains("partial")
    }));
}
