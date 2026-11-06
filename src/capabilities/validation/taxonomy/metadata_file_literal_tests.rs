use super::find_new_metadata_file_literal_ids;

fn ids(v: &[&str]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

#[test]
fn rejects_former_exact_legacy_ids() {
    let input = ids(&[
        "metadata/file/literal::lex-word-reference",
        "metadata/file/literal::lowercase-alnum-alphabet",
        "metadata/file/literal::bracket-http-url-prefix",
        "metadata/file/literal::push-string-literal",
        "metadata/file/literal::bracketed-shift-string",
        "metadata/file/literal::c-256-entry-array-declaration",
        "metadata/file/literal::dns-tunnel-phrase",
        "metadata/file/literal::dns-exfil",
        "metadata/file/literal::dns-c2",
        "metadata/file/literal::dns-beacon",
        "metadata/file/literal::hex-byte-token-3f",
        "metadata/file/literal::hex-byte-token-ff",
        "metadata/file/literal::bracket-hex-zero-prefix",
        "metadata/file/literal::hex-number-text",
        "metadata/file/literal::hex-token-length-undefined-cluster",
        "metadata/file/literal::js-long-integer-array-literal",
        "metadata/file/literal::repeated-85-to-95-character-variable-strings",
        "metadata/file/literal::powershell-numeric-array-8-plus",
        "metadata/file/literal::js-numeric-array-64-plus",
        "metadata/file/literal::remote-desktop-feature-word",
        "metadata/file/literal::safety-system-phrase",
        "metadata/file/literal::search-setindex-reference",
        "metadata/file/literal::staging-key-identifier-reference",
        "metadata/file/literal::session-identifier-reference",
        "metadata/file/literal::python-large-numeric-array-literal",
        "metadata/file/literal::cve-pattern-many",
        "metadata/file/literal::lowercase-digits-alphabet",
        "micro-behaviors/data/string::replace",
    ]);
    let mut expected = input[..input.len() - 1].to_vec();
    expected.sort();
    assert_eq!(find_new_metadata_file_literal_ids(&input), expected);
}

#[test]
fn rejects_new_root_and_subleaf_ids() {
    let input = ids(&[
        "metadata/file/literal::new-root-literal",
        "metadata/file/literal::lowercase-alnum-alphabet-v2",
        "metadata/file/literal/new-subject::new-literal",
        "metadata/file/literal/hex::hex-token",
        "micro-behaviors/data/string::replace",
    ]);
    assert_eq!(
        find_new_metadata_file_literal_ids(&input),
        vec![
            "metadata/file/literal/hex::hex-token".to_string(),
            "metadata/file/literal/new-subject::new-literal".to_string(),
            "metadata/file/literal::lowercase-alnum-alphabet-v2".to_string(),
            "metadata/file/literal::new-root-literal".to_string(),
        ]
    );
}

#[test]
fn rejects_retired_legacy_ids() {
    let input = ids(&["metadata/file/literal::retired-literal"]);
    assert_eq!(find_new_metadata_file_literal_ids(&input), input);
}
