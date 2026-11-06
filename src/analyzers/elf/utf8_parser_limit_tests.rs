use super::*;
#[test]
fn non_utf8_metadata_is_not_header_evasion() {
    let f = malformed_header_finding("renamed.so", b"\x7fELF", "bad input invalid utf8 (36)");
    assert_eq!(f.crit, Criticality::Notable);
    assert!(f.attack.is_none());
    assert!(f.id.starts_with("metadata/"));
}
#[test]
fn broken_extent_remains_suspicious() {
    let f = malformed_header_finding("renamed.so", b"\x7fELF", "section exceeds file");
    assert_eq!(f.crit, Criticality::Suspicious);
}
#[test]
fn unbacked_load_extent_is_checked_without_overflow() {
    let segments = serde_json::json!([
        {"type":"load", "file_offset":0, "file_size":1092},
        {"type":"gnu_stack", "file_offset":0, "file_size":0}
    ]);
    assert!(has_unbacked_load_segment(&segments, 992));
    assert!(!has_unbacked_load_segment(&segments, 1092));
    assert!(!has_unbacked_load_segment(&serde_json::json!([]), 0));
}
