use super::*;

fn encode_permutation(text: &str, mut seed: u64) -> String {
    let mut swaps = Vec::new();
    let n = text.len() as u64;
    for index in 0..n {
        let a = seed * (index + 179) + seed % 18_929;
        let b = seed * (index + 658) + seed % 13_606;
        swaps.push(((a % n) as usize, (b % n) as usize));
        seed = (a + b) % 5_578_712;
    }
    let mut bytes = text.as_bytes().to_vec();
    for (a, b) in swaps.into_iter().rev() {
        bytes.swap(a, b);
    }
    String::from_utf8(bytes).expect("ASCII encoder")
}
fn encode_dictionary_literal(text: &str) -> String {
    let codes = [
        32, 42, 39, 92, 10, 96, 80, 70, 66, 86, 60, 85, 71, 74, 87, 72, 75, 88, 81, 90, 76, 94, 82,
        89, 79, 65,
    ];
    let mut output = String::new();
    for byte in text.bytes() {
        if byte == b'.' {
            output.push_str(".!");
        } else if let Some(index) = codes.iter().position(|c| *c == byte) {
            output.push('.');
            output.push(char::from(b'a' + index as u8));
        } else {
            output.push(char::from(byte));
        }
    }
    output
}
fn encoded(program: &str, seed: u64) -> String {
    let permutation = PERMUTATION.replacen("y=0", &format!("y={seed}"), 1);
    let dictionary = DICTIONARY
        .strip_prefix("function unpack(){")
        .and_then(|s| s.strip_suffix('}'))
        .expect("dictionary body");
    let key = encode_permutation("constructorabcdefghijklmnopqrstuvwxyz", seed);
    let body = encode_permutation(dictionary, seed);
    let data = encode_permutation(&encode_dictionary_literal(program), seed);
    format!(
        "(function(){{var empty=\"\",width=11;{permutation}var key=perm({key}).substr(0,width);var body={body};var factory=perm[key];var parameters=\"\";var other=factory;var decoder=factory(parameters,perm(body));var text=decoder(perm({data}));var stage=other(empty,text);stage(7);return 0;}})();",
        key = serde_json::to_string(&key).expect("key"),
        body = serde_json::to_string(&body).expect("body"),
        data = serde_json::to_string(&data).expect("data")
    )
}

fn encoded_alternate(program: &str, seed: u64) -> String {
    fn encode_permutation_alt(text: &str, mut seed: u64) -> String {
        let mut swaps = Vec::new();
        let len = text.len() as u64;
        for index in 0..len {
            let a = seed * (index + 525) + seed % 28_432;
            let b = seed * (index + 186) + seed % 32_819;
            swaps.push(((a % len) as usize, (b % len) as usize));
            seed = (a + b) % 5_145_329;
        }
        let mut bytes = text.as_bytes().to_vec();
        for (a, b) in swaps.into_iter().rev() {
            bytes.swap(a, b);
        }
        String::from_utf8(bytes).expect("ASCII encoder")
    }
    let codes = [
        92, 39, 42, 10, 96, 32, 87, 94, 85, 71, 86, 89, 82, 76, 74, 81, 72, 60, 75, 65, 66, 79, 88,
        80, 90, 70,
    ];
    let mut encoded = String::new();
    for byte in program.bytes() {
        if byte == b'.' {
            encoded.push_str(".!");
        } else if let Some(index) = codes.iter().position(|c| *c == byte) {
            encoded.push('.');
            encoded.push(char::from(b'a' + index as u8));
        } else {
            encoded.push(char::from(byte));
        }
    }
    let permutation = PERMUTATION_ALT.replacen("53180", &seed.to_string(), 1);
    let dictionary = DICTIONARY_ALT
        .strip_prefix("function unpack(){")
        .and_then(|s| s.strip_suffix('}'))
        .expect("dictionary");
    let key = encode_permutation_alt("constructorabcdefghijklmnopqrstuvwxyz", seed);
    let body = encode_permutation_alt(dictionary, seed);
    let data = encode_permutation_alt(&encoded, seed);
    format!(
        "(function(){{var empty=\"\",width=11;{permutation}var key=iXB({key}).substr(0,width);var body={body};var factory=iXB[key];var decoder=factory(empty,iXB(body));var text=decoder(iXB({data}));WScript.Echo(text);var stage=factory(empty,text);WScript.Echo(stage);stage(7);WScript.Echo(stage(7));return 0;}})();",
        key = serde_json::to_string(&key).unwrap(),
        body = serde_json::to_string(&body).unwrap(),
        data = serde_json::to_string(&data).unwrap()
    )
}

#[test]
fn reconstructs_alternate_permutation_with_inert_echoes() {
    let program = "WScript.Echo('fixture');";
    let source = encoded_alternate(program, 53180);
    assert!(decode(&source).iter().any(|(_, text)| text == program));
    assert!(decode(&source.replace("5145329", "5145330")).is_empty());
    assert!(decode(&source.replace("WScript.Echo(text)", "unknown(text)")).is_empty());
    assert!(
        decode(&source.replace("WScript.Echo(text)", "var WScript=5;WScript.Echo(text)"))
            .is_empty()
    );
}
#[test]
fn recovers_program_without_executing_it() {
    let program = "require('child_process').exec('never execute this test');";
    for seed in [17, 2461180] {
        let source = encoded(program, seed);
        assert_eq!(
            decode(&source)
                .iter()
                .map(|r| r.1.as_str())
                .collect::<Vec<_>>(),
            [program]
        );
        let renamed = source
            .replace("perm", "different_transform")
            .replace("factory", "compiler_alias");
        assert_eq!(decode(&renamed)[0].1, program);
    }
}
#[test]
fn rejects_inert_modified_and_unknown_recipes() {
    let source = encoded("console.log('harmless');", 17);
    for negative in [
        serde_json::to_string(&source).expect("quoted source"),
        format!("/* {source} */"),
        source.replace("stage(7);", ""),
        source.replace("var other=factory;", "var other=unknown;"),
        source.replace(
            "return x.join",
            "fetch('https://example.invalid');return x.join",
        ),
        source.replace("stage(7);", "stage=unknown;stage(7);"),
        source.replace("var key=perm", "perm.constructor=unknown;var key=perm"),
    ] {
        assert!(decode(&negative).is_empty(), "{negative}");
    }
}
#[test]
fn reconstructs_reviewed_loader_exactly() {
    let source = include_str!("../../../tests/data/javascript-permutation/loader.js");
    let expected = include_str!("../../../tests/data/javascript-permutation/expected.js");
    let parsed = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::JavaScript)
        .cache(false)
        .open(source.as_bytes());
    let all = nodes(parsed.source_ast().expect("source AST").tree.root_node()).expect("nodes");
    let p = template_signature(PERMUTATION, true).expect("permutation");
    let d = template_signature(DICTIONARY, false).expect("dictionary");
    let recovered: Vec<_> = all
        .into_iter()
        .filter(|n| n.kind() == "statement_block")
        .filter_map(|n| recipe(n, source, &p, &d))
        .flatten()
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].1, expected);
    let result = decode(source);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1, decode(expected)[0].1);
}
#[test]
fn reconstructs_only_proven_literal_configuration_table() {
    let source = include_str!("../../../tests/data/javascript-permutation/expected.js");
    let result = decode(source);
    assert_eq!(result.len(), 1);
    assert!(
        result[0]
            .1
            .contains("https://api.binplorer.com/getAddressHistory/")
    );
    assert!(result[0].1.contains("$v$5;kmc$ldm*5SA"));
    for negative in [
        serde_json::to_string(source).expect("quoted source"),
        source.replace("return a+ b", "return fetch(a)+b"),
        format!("{source};String=unknown;"),
        source.replace("return String", "return unknown"),
    ] {
        assert!(decode(&negative).is_empty());
    }
}
#[test]
fn dictionary_and_permutation_are_bounded() {
    assert!(dictionary("P", Profile::Legacy).is_none());
    assert!(dictionary("P!", Profile::Legacy).is_none());
    assert!(permute("non-ASCII \u{20ac}", 17, Profile::Legacy).is_none());
    assert!(permute(&"a".repeat(MAX_PARTS + 1), 17, Profile::Legacy).is_none());
    assert!(decode(&"x".repeat(MAX_SOURCE + 1)).is_empty());
}
