//! Bounded, literal-only evaluation of a fully recognized nested shuffle.
use super::{
    MAX_FUEL, MAX_OUTPUT, MAX_PARTS, children, literal, nodes, number, raw, signature,
    template_signature, unwrap,
};

const SHUFFLE: &str = r#"function Ox$(b,q){var r=b.length;var m=[];for(var z=0;z<r;z++){m[z]=b.charAt(z)};for(var z=0;z<r;z++){var e=q*(z+114)+(q%37316);var g=q*(z+661)+(q%53955);var x=e%r;var l=g%r;var t=m[x];m[x]=m[l];m[l]=t;q=(e+g)%4338439;};var a=String.fromCharCode(127);var p='';var h='%';var o='#1';var n='%';var u='#0';var f='#';return m.join(p).split(h).join(a).split(o).join(n).split(u).join(f).split(a);}"#;

fn parse(source: &str) -> Option<tree_sitter::Tree> {
    let parsed = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::JavaScript)
        .cache(false)
        .open(source.as_bytes());
    let tree = parsed.source_ast()?.tree.clone();
    (!tree.root_node().has_error()).then_some(tree)
}

fn shuffled(input: &str, mut seed: u64) -> Option<String> {
    if !input.is_ascii() || input.is_empty() || input.len() > MAX_PARTS || seed >= 4_338_439 {
        return None;
    }
    let mut bytes = input.as_bytes().to_vec();
    let len = bytes.len() as u64;
    for index in 0..len {
        let a = seed.checked_mul(index + 114)?.checked_add(seed % 37_316)?;
        let b = seed.checked_mul(index + 661)?.checked_add(seed % 53_955)?;
        if a > (1u64 << 53) || b > (1u64 << 53) || a.checked_add(b)? > (1u64 << 53) {
            return None;
        }
        bytes.swap((a % len) as usize, (b % len) as usize);
        seed = (a + b) % 4_338_439;
    }
    let result = String::from_utf8(bytes).ok()?;
    let result = result
        .replace('%', "\u{7f}")
        .replace("#1", "%")
        .replace("#0", "#");
    Some(result.split('\u{7f}').next()?.to_owned())
}

/// Decode only direct eval(shuffle(literal, integer)[0]) calls when the whole
/// shuffle body is recognized and none of the relevant names are rebound.
pub(super) fn expand(source: &str) -> Option<String> {
    const PREFIX: &str = "function __cleave_decoded_scope(){";
    let expected = template_signature(SHUFFLE, false)?;
    let mut current = source.to_owned();
    let mut remaining = MAX_FUEL;
    let mut changed = false;
    for _ in 0..3 {
        let wrapped = format!("{PREFIX}{current}\n}}");
        let tree = parse(&wrapped)?;
        let all = nodes(tree.root_node())?;
        let mut shuffle_name = None;
        let mut shuffle_id = None;
        for node in &all {
            if node.kind() == "function_declaration"
                && signature(*node, &wrapped, None).as_deref() == Some(expected.as_str())
            {
                let name = raw(node.child_by_field_name("name")?, &wrapped)?.to_owned();
                if shuffle_name.replace(name).is_some() {
                    return None;
                }
                shuffle_id = Some(node.id());
            }
        }
        let shuffle_name = shuffle_name?;
        // A mutation or local binding of a critical global invalidates proof.
        for node in &all {
            let binding = match node.kind() {
                "assignment_expression" | "augmented_assignment_expression" => {
                    node.child_by_field_name("left")
                }
                "update_expression" => node.child_by_field_name("argument"),
                "variable_declarator" => node.child_by_field_name("name"),
                "identifier"
                    if node
                        .parent()
                        .is_some_and(|p| p.kind() == "formal_parameters") =>
                {
                    Some(*node)
                }
                "function_declaration" if Some(node.id()) != shuffle_id => {
                    node.child_by_field_name("name")
                }
                _ => None,
            };
            if let Some(binding) = binding.and_then(unwrap) {
                if binding.kind() == "identifier"
                    && [shuffle_name.as_str(), "eval", "String"].contains(&raw(binding, &wrapped)?)
                {
                    return None;
                }
                if matches!(binding.kind(), "member_expression" | "subscript_expression")
                    && binding
                        .child_by_field_name("object")
                        .and_then(unwrap)
                        .and_then(|n| raw(n, &wrapped))
                        == Some("String")
                {
                    return None;
                }
            }
        }
        let mut edits = Vec::new();
        for call in all.into_iter().filter(|n| n.kind() == "call_expression") {
            let Some(callee) = call.child_by_field_name("function").and_then(unwrap) else {
                continue;
            };
            if callee.kind() != "identifier" || raw(callee, &wrapped) != Some("eval") {
                continue;
            }
            let Some(arguments) = call.child_by_field_name("arguments") else {
                continue;
            };
            let args = children(arguments);
            if args.len() != 1 {
                continue;
            }
            let Some(indexed) = unwrap(args[0]) else {
                continue;
            };
            if indexed.kind() != "subscript_expression" {
                continue;
            }
            if indexed
                .child_by_field_name("index")
                .and_then(|n| number(n, &wrapped))
                != Some(0)
            {
                continue;
            }
            let Some(inner) = indexed.child_by_field_name("object").and_then(unwrap) else {
                continue;
            };
            if inner.kind() != "call_expression" {
                continue;
            }
            let Some(target) = inner.child_by_field_name("function").and_then(unwrap) else {
                continue;
            };
            if target.kind() != "identifier" || raw(target, &wrapped) != Some(shuffle_name.as_str())
            {
                continue;
            }
            let Some(params) = inner.child_by_field_name("arguments") else {
                continue;
            };
            let params = children(params);
            if params.len() != 2 {
                continue;
            }
            let Some(input) = literal(params[0], &wrapped) else {
                continue;
            };
            let Some(seed) = number(params[1], &wrapped) else {
                continue;
            };
            remaining = remaining.checked_sub(input.len())?;
            let Some(decoded) = shuffled(&input, seed) else {
                continue;
            };
            // Only expression-valued eval bodies can be safely substituted.
            if parse(&format!("({decoded});")).is_none() {
                continue;
            }
            let range = call.byte_range();
            if range.start < PREFIX.len() || range.end > PREFIX.len() + current.len() {
                continue;
            }
            edits.push((
                range.start - PREFIX.len()..range.end - PREFIX.len(),
                format!("({decoded})"),
            ));
        }
        if edits.is_empty() {
            break;
        }
        edits.sort_by_key(|(range, _)| range.start);
        let mut out = String::new();
        let mut end = 0;
        for (range, replacement) in edits {
            if range.start < end {
                continue;
            }
            out.push_str(current.get(end..range.start)?);
            out.push_str(&replacement);
            if out.len() > MAX_OUTPUT {
                return None;
            }
            end = range.end;
        }
        out.push_str(current.get(end..)?);
        if out.len() > MAX_OUTPUT {
            return None;
        }
        current = out;
        changed = true;
    }
    changed.then_some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(input: &str, mut seed: u64) -> String {
        let mut swaps = Vec::new();
        let n = input.len() as u64;
        for i in 0..n {
            let a = seed * (i + 114) + seed % 37_316;
            let b = seed * (i + 661) + seed % 53_955;
            swaps.push(((a % n) as usize, (b % n) as usize));
            seed = (a + b) % 4_338_439;
        }
        let mut bytes = input.as_bytes().to_vec();
        for (a, b) in swaps.into_iter().rev() {
            bytes.swap(a, b);
        }
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn expands_literal_expression_without_executing_it() {
        let program = "(function(){return 42})()";
        let input = serde_json::to_string(&encode(program, 100)).unwrap();
        let source = format!("{SHUFFLE}return eval(Ox$({input},100)[0]);");
        let recovered = expand(&source).expect("valid literal recipe");
        assert!(recovered.contains(program));
        assert!(!recovered.contains("eval(Ox$("));
        assert!(expand(&source.replace("4338439", "4338440")).is_none());
        assert!(
            expand(&format!(
                "{SHUFFLE}var Ox$=5;return eval(Ox$({input},100)[0]);"
            ))
            .is_none()
        );
        assert!(
            expand(&format!(
                "{SHUFFLE}String.fromCharCode=other;return eval(Ox$({input},100)[0]);"
            ))
            .is_none()
        );
        let statements = serde_json::to_string(&encode("var a = 1;", 100)).unwrap();
        assert!(expand(&format!("{SHUFFLE}return eval(Ox$({statements},100)[0]);")).is_none());
    }

    #[test]
    fn expands_nested_literal_calls_in_separate_passes() {
        let program = "(function(){return 42})()";
        let inner = serde_json::to_string(&encode(program, 101)).unwrap();
        let intermediate = format!("eval(Ox$({inner},101)[0])");
        let outer = serde_json::to_string(&encode(&intermediate, 102)).unwrap();
        let source = format!("{SHUFFLE}return eval(Ox$({outer},102)[0]);");
        let recovered = expand(&source).expect("nested literal recipes");
        assert!(recovered.contains(program));
        assert!(!recovered.contains("eval(Ox$("));
    }
}
