use super::*;

#[test]
fn test_parse_hex_pattern_simple() {
    let segments = parse_hex_pattern("7F 45 4C 46").unwrap();
    assert_eq!(segments.len(), 1);
    match &segments[0] {
        HexSegment::Bytes(b) => assert_eq!(b, &[0x7F, 0x45, 0x4C, 0x46]),
        _ => panic!("expected Bytes"),
    }
}

#[test]
fn test_parse_hex_pattern_wildcards() {
    let segments = parse_hex_pattern("31 ?? 48 83").unwrap();
    assert_eq!(segments.len(), 3);
    match &segments[0] {
        HexSegment::Bytes(b) => assert_eq!(b, &[0x31]),
        _ => panic!("expected Bytes"),
    }
    assert!(matches!(segments[1], HexSegment::Wildcard));
    match &segments[2] {
        HexSegment::Bytes(b) => assert_eq!(b, &[0x48, 0x83]),
        _ => panic!("expected Bytes"),
    }
}

#[test]
fn test_parse_hex_pattern_fixed_gap() {
    let segments = parse_hex_pattern("00 03 [4] 00 04").unwrap();
    assert_eq!(segments.len(), 3);
    match &segments[1] {
        HexSegment::Gap { min, max } => {
            assert_eq!(*min, 4);
            assert_eq!(*max, 4);
        }
        _ => panic!("expected Gap"),
    }
}

#[test]
fn test_parse_hex_pattern_variable_gap() {
    let segments = parse_hex_pattern("00 [2-8] FF").unwrap();
    assert_eq!(segments.len(), 3);
    match &segments[1] {
        HexSegment::Gap { min, max } => {
            assert_eq!(*min, 2);
            assert_eq!(*max, 8);
        }
        _ => panic!("expected Gap"),
    }
}

#[test]
fn test_match_simple_pattern() {
    let data = b"\x7F\x45\x4C\x46\x01\x02\x03";
    let segments = parse_hex_pattern("7F 45 4C 46").unwrap();
    assert!(match_pattern_at(data, 0, &segments));
    assert!(!match_pattern_at(data, 1, &segments));
}

#[test]
fn test_match_wildcard_pattern() {
    let data = b"\x31\xC0\x48\x83";
    let segments = parse_hex_pattern("31 ?? 48 83").unwrap();
    assert!(match_pattern_at(data, 0, &segments));

    let data2 = b"\x31\xFF\x48\x83";
    assert!(match_pattern_at(data2, 0, &segments));

    let data3 = b"\x31\xC0\x48\x84"; // Last byte differs
    assert!(!match_pattern_at(data3, 0, &segments));
}

#[test]
fn test_match_fixed_gap() {
    let data = b"\x00\x03\xAA\xBB\xCC\xDD\x00\x04";
    let segments = parse_hex_pattern("00 03 [4] 00 04").unwrap();
    assert!(match_pattern_at(data, 0, &segments));
}

#[test]
fn test_match_variable_gap() {
    // Gap of 2
    let data2 = b"\x00\xAA\xBB\xFF";
    let segments = parse_hex_pattern("00 [2-4] FF").unwrap();
    assert!(match_pattern_at(data2, 0, &segments));

    // Gap of 4
    let data4 = b"\x00\xAA\xBB\xCC\xDD\xFF";
    assert!(match_pattern_at(data4, 0, &segments));

    // Gap of 5 (too long)
    let data5 = b"\x00\xAA\xBB\xCC\xDD\xEE\xFF";
    assert!(!match_pattern_at(data5, 0, &segments));
}

#[test]
fn test_is_simple_pattern() {
    let simple = parse_hex_pattern("7F 45 4C 46").unwrap();
    assert!(is_simple_pattern(&simple));

    let with_wildcard = parse_hex_pattern("7F ?? 4C 46").unwrap();
    assert!(!is_simple_pattern(&with_wildcard));

    let with_gap = parse_hex_pattern("7F [2] 46").unwrap();
    assert!(!is_simple_pattern(&with_gap));
}

#[test]
fn test_extract_best_atom() {
    let segments = parse_hex_pattern("31 ?? 48 83 C4 08").unwrap();
    let atom = extract_best_atom(&segments).unwrap();
    // Should extract "48 83 C4 08" (4 bytes) not "31" (1 byte)
    assert_eq!(atom, &[0x48, 0x83, 0xC4, 0x08]);
}

#[test]
fn hex_alternative_atoms_cover_every_matching_branch() {
    let patterns = [
        "(AA BB|CC DD)",
        "(AA [0-2] BB|CC ?? DD) (11|22)",
        "(AA BB|??) CC DD",
        "(AA BB|??)",
        "[0-2] (AA BB|CC DD)",
        "(?? AA BB|CC DD AA BB)",
        "(AA BB|CC DD) (AA BB|DD CC)",
    ];
    // Exhaustive small inputs exercise alternatives, wildcard branches,
    // and zero-length versus nonzero-length gaps.
    let alphabet = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22];
    for pattern in patterns {
        let segments = parse_hex_pattern(pattern).unwrap();
        let atoms = mandatory_hex_atoms(&segments);
        for value in 0..6usize.pow(5) {
            let mut v = value;
            let data: Vec<_> = (0..5)
                .map(|_| {
                    let b = alphabet[v % 6];
                    v /= 6;
                    b
                })
                .collect();
            if (0..data.len()).any(|pos| match_pattern_at(&data, pos, &segments)) {
                assert!(
                    atoms.as_ref().is_none_or(|atoms| atoms
                        .iter()
                        .any(|atom| memchr::memmem::find(&data, atom.bytes).is_some())),
                    "gate dropped {pattern} on {data:?}"
                );
            }
            if let Some(atoms) = &atoms {
                for (start, end) in [(0, 5), (0, 1), (1, 4)] {
                    let expected: Vec<_> = (start..end)
                        .filter(|pos| match_pattern_at(&data, *pos, &segments))
                        .take(2)
                        .collect();
                    let actual: Vec<_> =
                        anchored_hex_matches(&data, start, end, &segments, atoms, |_| true, 2)
                            .into_iter()
                            .collect();
                    assert_eq!(actual, expected, "{pattern} on {data:?}, {start}..{end}");
                }
            }
        }
    }
    assert!(mandatory_hex_atoms(&parse_hex_pattern("(AA BB|??)").unwrap()).is_none());
    assert_eq!(
        mandatory_hex_atoms(&parse_hex_pattern("(AA BB|CC DD)").unwrap())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn hex_alternative_anchors_preserve_counts_order_and_exclusions() {
    // The same atom occurs at different branch offsets, and the branches
    // overlap. Evidence must remain in file order and count each start once.
    let segments = parse_hex_pattern("(AA BB|?? AA BB|[0-3] AA BB)").unwrap();
    let atoms = mandatory_hex_atoms(&segments).unwrap();
    let data = [0, 0xAA, 0xBB, 0, 0, 0xAA, 0xBB, 0, 0xAA, 0xBB];
    for limit in [0, 1, 2, 16] {
        let expected: Vec<_> = (0..data.len())
            .filter(|pos| pos % 2 == 0 && match_pattern_at(&data, *pos, &segments))
            .take(limit)
            .collect();
        let actual: Vec<_> = anchored_hex_matches(
            &data,
            0,
            data.len(),
            &segments,
            &atoms,
            |pos| pos % 2 == 0,
            limit,
        )
        .into_iter()
        .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn hex_alternative_partial_atom_in_large_buffer() {
    let segments = parse_hex_pattern("(AA BB CC DD ?? 11 22|55 66 77 88 ?? 33 44)").unwrap();
    let atoms = mandatory_hex_atoms(&segments).unwrap();
    let mut data = vec![0; 8 * 1024 * 1024];
    // An atom alone used to defeat the rejection gate and trigger a full
    // byte-by-byte walk, even though no complete signature was present.
    data[4096..4100].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    assert!(anchored_hex_matches(&data, 0, data.len(), &segments, &atoms, |_| true, 16).is_empty());
    let end = data.len();
    data[end - 7..].copy_from_slice(&[0x55, 0x66, 0x77, 0x88, 0x99, 0x33, 0x44]);
    assert_eq!(
        anchored_hex_matches(&data, 0, end, &segments, &atoms, |_| true, 16)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![end - 7]
    );
}

#[test]
fn test_parse_invalid_hex() {
    assert!(parse_hex_pattern("ZZ 45").is_err());
    assert!(parse_hex_pattern("[abc]").is_err());
}

// === Nibble wildcard tests ===

#[test]
fn test_parse_nibble_wildcard_high() {
    // 4? = high nibble 0x40, low nibble wild
    let segments = parse_hex_pattern("4?").unwrap();
    assert_eq!(segments.len(), 1);
    match &segments[0] {
        HexSegment::NibbleMask {
            high_mask,
            low_mask,
            value,
        } => {
            assert_eq!(*high_mask, 0xF0);
            assert_eq!(*low_mask, 0x00);
            assert_eq!(*value, 0x40);
        }
        _ => panic!("expected NibbleMask"),
    }
}

#[test]
fn test_parse_nibble_wildcard_low() {
    // ?A = high nibble wild, low nibble 0x0A
    let segments = parse_hex_pattern("?A").unwrap();
    assert_eq!(segments.len(), 1);
    match &segments[0] {
        HexSegment::NibbleMask {
            high_mask,
            low_mask,
            value,
        } => {
            assert_eq!(*high_mask, 0x00);
            assert_eq!(*low_mask, 0x0F);
            assert_eq!(*value, 0x0A);
        }
        _ => panic!("expected NibbleMask"),
    }
}

#[test]
fn test_parse_nibble_wildcard_complex() {
    // Mozi-style pattern
    let segments = parse_hex_pattern("31 ?? 4? 7?").unwrap();
    assert_eq!(segments.len(), 4);
    assert!(matches!(&segments[0], HexSegment::Bytes(b) if b == &[0x31]));
    assert!(matches!(segments[1], HexSegment::Wildcard));
    assert!(matches!(
        segments[2],
        HexSegment::NibbleMask { value: 0x40, .. }
    ));
    assert!(matches!(
        segments[3],
        HexSegment::NibbleMask { value: 0x70, .. }
    ));
}

#[test]
fn test_match_nibble_wildcard_high() {
    let segments = parse_hex_pattern("4?").unwrap();

    // 4? should match 0x40-0x4F
    assert!(match_pattern_at(&[0x40], 0, &segments));
    assert!(match_pattern_at(&[0x4F], 0, &segments));
    assert!(match_pattern_at(&[0x48], 0, &segments));

    // Should not match 0x5F (different high nibble)
    assert!(!match_pattern_at(&[0x5F], 0, &segments));
    assert!(!match_pattern_at(&[0x30], 0, &segments));
}

#[test]
fn test_match_nibble_wildcard_low() {
    let segments = parse_hex_pattern("?A").unwrap();

    // ?A should match any byte ending in A
    assert!(match_pattern_at(&[0x0A], 0, &segments));
    assert!(match_pattern_at(&[0xFA], 0, &segments));
    assert!(match_pattern_at(&[0x5A], 0, &segments));

    // Should not match xB
    assert!(!match_pattern_at(&[0xFB], 0, &segments));
    assert!(!match_pattern_at(&[0x00], 0, &segments));
}

#[test]
fn test_match_mozi_xor_pattern() {
    // Real Mozi XOR loop pattern: 31 ?? 88 ?? 4? 83 ?? ?? 7?
    let data = &[0x31, 0xC0, 0x88, 0x03, 0x48, 0x83, 0xC0, 0x01, 0x75];
    let segments = parse_hex_pattern("31 ?? 88 ?? 4? 83 ?? ?? 7?").unwrap();
    assert!(match_pattern_at(data, 0, &segments));

    // Different high nibble at position 4 should fail
    let data_bad = &[0x31, 0xC0, 0x88, 0x03, 0x58, 0x83, 0xC0, 0x01, 0x75];
    assert!(!match_pattern_at(data_bad, 0, &segments));
}

// === Byte alternation tests ===

#[test]
fn test_parse_byte_alternation() {
    let segments = parse_hex_pattern("(00|80)").unwrap();
    assert_eq!(segments.len(), 1);
    match &segments[0] {
        HexSegment::ByteSet(bytes) => {
            assert_eq!(bytes, &[0x00, 0x80]);
        }
        _ => panic!("expected ByteSet"),
    }
}

#[test]
fn test_parse_byte_alternation_many() {
    // LZMA-style: many alternatives
    let segments = parse_hex_pattern("(01|02|03|04|05)").unwrap();
    assert_eq!(segments.len(), 1);
    match &segments[0] {
        HexSegment::ByteSet(bytes) => {
            assert_eq!(bytes, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        }
        _ => panic!("expected ByteSet"),
    }
}

#[test]
fn test_parse_nibble_wildcard_alternation() {
    // YARA/YARA-X accept nibble wildcards inside alternatives.
    let segments = parse_hex_pattern("1F 8B 08 (0?|1?)").unwrap();
    assert!(matches!(&segments[0], HexSegment::Bytes(b) if b == &[0x1F, 0x8B, 0x08]));
    assert!(matches!(
        &segments[1],
        HexSegment::NibbleSet(alternatives)
            if alternatives == &[(0x00, 0xF0), (0x10, 0xF0)]
    ));
}

#[test]
fn test_match_spaced_sequence_alternation() {
    let segments = parse_hex_pattern("(33 C0 | 31 C0) C3").unwrap();
    assert!(match_pattern_at(&[0x33, 0xC0, 0xC3], 0, &segments));
    assert!(match_pattern_at(&[0x31, 0xC0, 0xC3], 0, &segments));
    assert!(!match_pattern_at(&[0x33, 0xC1, 0xC3], 0, &segments));
}

#[test]
fn test_match_negated_byte_alternation() {
    let segments = parse_hex_pattern("(~00 ??|00 ~00)").unwrap();
    assert!(match_pattern_at(&[0x01, 0x00], 0, &segments));
    assert!(match_pattern_at(&[0x00, 0x01], 0, &segments));
    assert!(!match_pattern_at(&[0x00, 0x00], 0, &segments));
}

#[test]
fn test_match_nibble_wildcard_alternation() {
    let segments = parse_hex_pattern("1F 8B 08 (0?|1?)").unwrap();
    assert!(match_pattern_at(&[0x1F, 0x8B, 0x08, 0x00], 0, &segments));
    assert!(match_pattern_at(&[0x1F, 0x8B, 0x08, 0x1F], 0, &segments));
    assert!(!match_pattern_at(&[0x1F, 0x8B, 0x08, 0x20], 0, &segments));
}

#[test]
fn test_parse_combined_pattern() {
    // LZMA-style: fixed + alternation + gap + wildcard
    let segments = parse_hex_pattern("5D 00 00 (00|80) [7] ??").unwrap();
    assert_eq!(segments.len(), 4);
    assert!(matches!(&segments[0], HexSegment::Bytes(b) if b == &[0x5D, 0x00, 0x00]));
    assert!(matches!(&segments[1], HexSegment::ByteSet(b) if b == &[0x00, 0x80]));
    assert!(matches!(segments[2], HexSegment::Gap { min: 7, max: 7 }));
    assert!(matches!(segments[3], HexSegment::Wildcard));
}

#[test]
fn test_match_byte_alternation() {
    let segments = parse_hex_pattern("(00|80)").unwrap();

    assert!(match_pattern_at(&[0x00], 0, &segments));
    assert!(match_pattern_at(&[0x80], 0, &segments));

    // Not in set
    assert!(!match_pattern_at(&[0x40], 0, &segments));
    assert!(!match_pattern_at(&[0x01], 0, &segments));
}

#[test]
fn test_match_byte_alternation_in_context() {
    // Test alternation between fixed bytes
    let segments = parse_hex_pattern("5D 00 00 (00|80) 00").unwrap();

    let data1 = &[0x5D, 0x00, 0x00, 0x80, 0x00];
    assert!(match_pattern_at(data1, 0, &segments));

    let data2 = &[0x5D, 0x00, 0x00, 0x00, 0x00]; // 00 variant
    assert!(match_pattern_at(data2, 0, &segments));

    let data3 = &[0x5D, 0x00, 0x00, 0x40, 0x00]; // 40 not in set
    assert!(!match_pattern_at(data3, 0, &segments));
}

#[test]
fn test_match_lzma_pattern() {
    // Simplified LZMA header pattern: 5D 00 00 (00|80) 00 (10|20) [7] ??
    let data = &[
        0x5D, 0x00, 0x00, 0x80, 0x00, 0x10, // Header + decompressed size byte
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 bytes gap
        0xFF, // Final byte
    ];
    let segments = parse_hex_pattern("5D 00 00 (00|80) 00 (10|20) [7] ??").unwrap();
    assert!(match_pattern_at(data, 0, &segments));

    // With 00 variant instead of 80
    let data2 = &[
        0x5D, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAB,
    ];
    assert!(match_pattern_at(data2, 0, &segments));
}

#[test]
fn test_extract_nibble_wildcard_bytes() {
    let segments = parse_hex_pattern("31 4? ??").unwrap();

    // Should match 31 48 XX (0x48 has high nibble 4)
    let data = &[0x31, 0x48, 0xFF];
    assert!(match_pattern_at(data, 0, &segments));

    let extracted = extract_wildcard_bytes(data, 0, &segments);
    // Should extract 0x48 (nibble mask) and 0xFF (wildcard)
    assert_eq!(extracted, vec![0x48, 0xFF]);
}

#[test]
fn test_extract_byte_set_bytes() {
    let data = &[0x5D, 0x00, 0x80, 0xFF];
    let segments = parse_hex_pattern("5D 00 (00|80) ??").unwrap();
    assert!(match_pattern_at(data, 0, &segments));

    let extracted = extract_wildcard_bytes(data, 0, &segments);
    // Should extract 0x80 (byte set) and 0xFF (wildcard)
    assert_eq!(extracted, vec![0x80, 0xFF]);
}

#[test]
fn test_is_simple_pattern_with_new_types() {
    let with_nibble = parse_hex_pattern("4? 45").unwrap();
    assert!(!is_simple_pattern(&with_nibble));

    let with_byteset = parse_hex_pattern("(00|80) 45").unwrap();
    assert!(!is_simple_pattern(&with_byteset));
}
