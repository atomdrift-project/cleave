use super::decode_variation_selector_payload;

#[test]
#[allow(clippy::expect_used)]
fn decodes_escaped_variation_selector_run() {
    // "console.log(1)" repeated to clear the minimum-length bar, written
    // the way a bundler emits it: literal \u{...} escape text.
    let payload = "console.log(1);".repeat(8);
    let escaped: String = payload
        .bytes()
        .map(|b| {
            if b < 16 {
                format!("\\u{{{:X}}}", 0xFE00 + u32::from(b))
            } else {
                format!("\\u{{{:X}}}", 0xE0100 + u32::from(b) - 16)
            }
        })
        .collect();
    let host = format!("const s=`{escaped}`; eval(s);");
    let (decoded, _) = decode_variation_selector_payload(&host).expect("run decodes");
    assert_eq!(decoded, payload);
}
