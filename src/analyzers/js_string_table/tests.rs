use super::*;
use std::path::Path;
const BASE: &str = include_str!("../../../testdata/vsix-string-table/base64-proxies.js");
const RC4: &str = include_str!("../../../testdata/vsix-string-table/rc4-proxies.js");
fn reduce(source: &str) -> Option<String> {
    let ctx =
        crate::analysis_context::AnalysisContext::open(Path::new("input.js"), source.as_bytes());
    decode(ctx.source_ast()?)
}
#[test]
fn reduces_proved_plain_string_table_without_executing_code() {
    let source = r#"
function table() {
  const values = ['11a', '22b', 'Chrome', 'User Data', 'chrome.e', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19'];
  table = function() { return values; };
  return table();
}
function decode(i) { i = i - 16; const values = table(); let value = values[i]; return value; }
(function(t, expected) {
  const values = t();
  while (!![]) { try { const result = parseInt(decode(16)); if (result === expected) break; else values.push(values.shift()); } catch (e) { values.push(values.shift()); } }
})(table, 22);
console.log(decode(17), decode(18), decode(19));
"#;
    let out = reduce(source).expect("proved literal table rotation");
    assert!(out.contains("console.log(\"Chrome\", \"User Data\", \"chrome.e\")"));
    assert!(reduce(&source.replace("return value;", "return value + 'changed';")).is_none());
    assert!(
        reduce(&source.replace(
            "let value = values[i];",
            "let value = values[i], ignored = mutate();"
        ))
        .is_none()
    );
    assert!(
        reduce(&source.replace("const values = table();", "const values = table(mutate());"))
            .is_none()
    );
    assert!(reduce(&source.replace("})(table, 22);", "})(table, 999);")).is_none());
    let aliased = source
        .replace(
            "const values = t();",
            "const reader = decode, values = t();",
        )
        .replace("parseInt(decode(16))", "parseInt(reader(16))")
        .replace(
            "console.log(decode(17), decode(18), decode(19));",
            "const read = decode; console.log(read(17), read(18), read(19));",
        );
    let out = reduce(&aliased).expect("immutable decoder aliases");
    assert!(out.contains("console.log(\"Chrome\", \"User Data\", \"chrome.e\")"));
    assert!(reduce(&aliased.replace("const read = decode;", "let read = decode;")).is_none());
    assert!(
        reduce(&aliased.replace(
            "const read = decode;",
            "const read = decode; unknown(read);"
        ))
        .is_none()
    );
    let nested = aliased.replace(
        "const read = decode; console.log(read(17), read(18), read(19));",
        "const read = decode; function invoke() { const nested = read; console.log(nested(17), nested(18), nested(19)); }",
    );
    let out = reduce(&nested).expect("nested immutable decoder aliases");
    assert!(out.contains("console.log(\"Chrome\", \"User Data\", \"chrome.e\")"));
}
#[test]
fn coerces_radix_strings_without_parse_int_prefix_truncation() {
    for (text, want) in [
        ("0x20", 32.),
        ("0Xff", 255.),
        ("0o10", 8.),
        ("0b11", 3.),
        ("", 0.),
    ] {
        assert_eq!(Val::string(text.into()).numeric(), want);
    }
    for text in ["0x20junk", "-0x20", "32junk", "inf", "infinity"] {
        assert!(Val::string(text.into()).numeric().is_nan());
    }
}
#[test]
fn reduces_string_valued_offset_objects_and_obscured_rc4_modulus() {
    let number_fields =
        regex::Regex::new(r"(:\s*)(0x[0-9a-fA-F]+)\b").expect("valid numeric-field pattern");
    let source = number_fields
        .replace_all(RC4, r#"$1"$2""#)
        .to_string()
        .replace("0x100", "(0x80+0x80)");
    let out = reduce(&source).expect("constant string offsets and arithmetic RC4 bounds");
    assert!(out.contains("\"runInContext\""));
    assert!(out.contains("\"getSignaturesForAddress\""));
}
#[test]
fn reduces_mixed_decoders_sharing_the_checksum_table() {
    let source = include_str!("../../../testdata/vsix-string-table/mixed-decoders.js");
    let out = reduce(source).expect("mixed plain/RC4 table checksum");
    assert!(out.contains("\"child_process\""));
    assert!(out.contains("\"runInContext\""));
    assert!(out.contains("\"ordinary text\""));
    let overwritten = source.replace(
        "console.log",
        "B = function() { return 'changed'; }; console.log",
    );
    assert!(reduce(&overwritten).is_none());
    let escaped = source.replace(
        "console.log",
        "var leaked = Z(); leaked.reverse(); console.log",
    );
    assert!(reduce(&escaped).is_none());
    let nested_escape = source.replace(
        "var t = F[B];",
        "var t = F[B]; var leaked = Z(); leaked.reverse();",
    );
    assert!(reduce(&nested_escape).is_none());
    let shadowed = format!(
        "var offsets = {{a:0x1d2}}; function unrelated() {{ var offsets = {{}}; return offsets; }} {}",
        source.replace("B(0x1d2)", "B(offsets.a)")
    );
    let reduced = reduce(&shadowed).expect("independent shadowing object");
    assert!(reduced.contains("\"child_process\""));
    let escaped_object = format!("unknown(offsets); {}", shadowed);
    if let Some(reduced) = reduce(&escaped_object) {
        assert!(reduced.contains("B(offsets.a)"));
    }
}
#[test]
fn reduces_base64_proxy_chains_and_constant_string_joins() {
    let out = reduce(BASE).expect("recognized Base64 table");
    assert!(out.contains("require(\n      \"child_process\""));
    assert!(out.contains("--install-extension"));
    assert!(
        out.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .contains("x(c,[\"--install-extension\",u,\"--force\"],F)"),
        "pure call forwarding should reduce"
    );
    assert!(out.contains("autoimport-smart-tool-2.5.8.vsix"));
}
#[test]
fn reduces_rc4_keys_through_numeric_proxies() {
    let out = reduce(RC4).expect("recognized RC4 table");
    assert!(out.contains("\"runInContext\""));
    assert!(out.contains("\"getSignaturesForAddress\""));
    assert!(out.contains("\"base64\""));
}
#[test]
fn rejects_unproved_rotation_and_nondecoder_lookalikes() {
    let wrong = BASE.replace(
        "})(e, -0xb7fb3 + 0xb252c + 0x1 * 0x97d71);",
        "})(e, 9999999999);",
    );
    assert_ne!(wrong, BASE);
    assert!(reduce(&wrong).is_none());
    assert!(reduce(&BASE.replace("charAt", "readCharacter")).is_none());
}
#[test]
fn rejects_table_mutation_and_escaped_array_producers() {
    assert!(reduce(&BASE.replace("return cR;", "cR.reverse(); return cR;")).is_none());
    let escaped = BASE.replace(
        "var l = require(\"fs\")",
        "const leaked = e(); leaked.reverse(); var l = require(\"fs\")",
    );
    assert_ne!(escaped, BASE);
    assert!(reduce(&escaped).is_none());
    let mutated = BASE.replace("const t = a();", "const t = a(); t.reverse();");
    assert_ne!(mutated, BASE);
    assert!(reduce(&mutated).is_none());
}
#[test]
fn retains_shadowed_proxy_calls_and_rejects_callable_reassignment() {
    let shadowed = BASE.replace("function V(c) {", "function V(c) { let ad = unknown;");
    let out = reduce(&shadowed).expect("unshadowed calls still reduce");
    assert!(out.contains("let ad = unknown"));
    let changed = BASE.replace(
        "var l = require(\"fs\")",
        "f = unknown; var l = require(\"fs\")",
    );
    assert!(reduce(&changed).is_none());
    let changed = BASE.replace(
        "var l = require(\"fs\")",
        "const parseInt = unknown; var l = require(\"fs\")",
    );
    assert!(reduce(&changed).is_none());
}
#[test]
fn preserves_calls_shadowed_by_arrow_and_destructured_bindings() {
    for parameter in ["ad", "(ad)", "({ad})"] {
        let extra =
            format!("function V(c) {{ const callback = {parameter} => ad(-239,-140,-156,-124);");
        let source = BASE.replace("function V(c) {", &extra);
        let out = reduce(&source).expect("other unshadowed lookups reduce");
        assert!(out.contains("ad(-239,-140,-156,-124)"), "{parameter}");
    }
}
#[test]
fn preserves_indirect_eval_and_async_forwarding() {
    let source = BASE.replace("            x,", "            eval,");
    assert_ne!(source, BASE);
    let out = reduce(&source).expect("other lookups reduce");
    assert!(out.contains("z[\"vdfOy\"]("));
    let source = BASE.replace(
        "vdfOy: function (G, J, K, N)",
        "vdfOy: async function (G, J, K, N)",
    );
    assert_ne!(source, BASE);
    let out = reduce(&source).expect("other lookups reduce");
    assert!(out.contains("z[\"vdfOy\"]("));
}
#[test]
fn integer_conversion_uses_javascript_wrapping() {
    assert_eq!(js_i32(4294967297.0), 1);
    assert_eq!(js_i32(2147483648.0), i32::MIN);
    assert_eq!(js_i32(-4294967297.0), -1);
    assert_eq!(js_i32(f64::NAN), 0);
}
#[test]
fn preserves_dynamic_calls_and_side_effecting_proxies() {
    let source = BASE.replace(
        "function ae(a, c, t, u) {",
        "function ae(a, c, t, u) { audit();",
    );
    let out = reduce(&source).expect("other safe proxies still reduce");
    assert!(out.contains("ae(0x415, 0x3aa, 0x3a3, 0x472)"));
    let source = BASE.replace(
        "ad(-0xef, -0x8c, -0x9c, -0x7c)",
        "ad(-0xef, readKey(), -0x9c, -0x7c)",
    );
    let out = reduce(&source).expect("remaining constants reduce");
    assert!(out.contains("ad(-0xef, readKey(), -0x9c, -0x7c)"));
}
fn escaped_terminal_fixture() -> String {
    BASE.replace(
        "function activate(context) {",
        "function activate(context, e) {",
    )
    .replace(
        "}\nexports.activate = activate;",
        "return external(e);\n}\nexports.activate = activate;",
    )
}
#[test]
fn recovers_only_immediate_prefix_before_terminal_producer_escape() {
    let input = escaped_terminal_fixture();
    assert!(input.contains("return external(e);"));
    let out = reduce(&input).expect("stable immediate prefix");
    assert!(out.contains("https://github.com/francesca898/dqwffqw/releases/download/vsx/autoimport-smart-tool-2.5.8.vsix"));
    assert!(out.contains("return external(e);"));
    assert!(
        !out.contains("\"--install-extension\""),
        "deferred installer bodies must remain unreduced after an escape"
    );
}
#[test]
fn accepts_a_simple_parameter_shadowed_by_the_table_function() {
    let input = BASE.replace(
        "function activate(context) {",
        "function activate(context, e) {",
    );
    assert!(
        reduce(&input)
            .expect("body function shadows parameter")
            .contains("--install-extension")
    );
}
#[test]
fn rejects_earlier_producer_escape_and_mutation_even_with_terminal_return() {
    for extra in ["external(e);", "e().push('mutation');"] {
        let input = escaped_terminal_fixture().replace(
            "return external(e);",
            &format!("{extra} return external(e);"),
        );
        assert!(reduce(&input).is_none(), "{extra}");
    }
}
#[test]
fn terminal_escape_does_not_rewrite_nested_function_bodies() {
    let input = escaped_terminal_fixture();
    let out = reduce(&input).expect("stable prefix");
    fn deferred(source: &str) -> String {
        let ctx = crate::analysis_context::AnalysisContext::open(
            Path::new("input.js"),
            source.as_bytes(),
        );
        let ast = ctx.source_ast().expect("parsed JavaScript fixture");
        let node = nodes(ast.tree.root_node())
            .expect("fixture within AST node limit")
            .into_iter()
            .find(|n| {
                n.kind() == "function_declaration"
                    && function_name(*n, source).as_deref() == Some("W")
            })
            .expect("deferred fixture function");
        text(node, source)
            .expect("deferred fixture function source")
            .to_owned()
    }
    let original = deferred(&input);
    let retained = deferred(&out);
    assert_eq!(original, retained);
}
