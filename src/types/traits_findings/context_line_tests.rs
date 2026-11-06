#![allow(clippy::unwrap_used)]
use super::ContextLine;

fn window(data: &[u8]) -> ContextLine {
    ContextLine {
        loc: 7,
        line: Some(2),
        col: Some(1),
        data: data.to_vec(),
    }
}

#[test]
fn writes_byte_text_and_reads_it_back() {
    let w = window(b"exec(\0)\n");
    let json = serde_json::to_string(&w).unwrap();
    assert_eq!(
        json,
        "{\"ln\":7,\"line\":2,\"col\":1,\"s\":\"exec(\u{100})\\n\"}"
    );
    assert_eq!(serde_json::from_str::<ContextLine>(&json).unwrap(), w);
}

#[test]
fn reads_schema_8_z85_and_ignores_stored_notes() {
    let old = r#"{"ln":7,"line":2,"col":1,"b":"HelloWorld","n":[{"c":3,"i":"a/b","o":7}]}"#;
    let w: ContextLine = serde_json::from_str(old).unwrap();
    assert_eq!(w.data, [0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]);
}

#[test]
fn rejects_ambiguous_or_missing_bytes() {
    assert!(serde_json::from_str::<ContextLine>(r#"{"ln":0,"s":"a","b":"HelloWorld"}"#).is_err());
    assert!(serde_json::from_str::<ContextLine>(r#"{"ln":0}"#).is_err());
    assert!(serde_json::from_str::<ContextLine>(r#"{"ln":0,"s":"\u0000"}"#).is_err());
}
