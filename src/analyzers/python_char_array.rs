//! Recover a literal character-array recipe without executing Python.
//!
//! This recognizes a specific builtin lookup as well as the literal integer
//! arithmetic used for its codepoints. Rebinding or dynamic access to the
//! relevant builtins makes the result ambiguous, so those cases are rejected.
use tree_sitter::{Node, Tree};

const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_NODES: usize = 1_000_000;
const MAX_ITEMS: usize = 8192;
const MAX_FUEL: usize = 8_000_000;
const GETTER: &str =
    "getattr(__builtins__,oct.__str__()[-3<<0]+hex.__str__()[-1<<2]+copyright.__str__()[4<<0])";
const PROTECTED: &[&str] = &["map", "getattr", "__builtins__", "oct", "hex", "copyright"];
const DYNAMIC: &[&str] = &[
    "exec",
    "eval",
    "globals",
    "locals",
    "vars",
    "setattr",
    "delattr",
    "builtins",
    "__import__",
];

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}
fn nodes(root: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut todo = vec![root];
    let mut out = Vec::new();
    while let Some(node) = todo.pop() {
        if out.len() >= MAX_NODES {
            return None;
        }
        todo.extend(children(node));
        out.push(node);
    }
    Some(out)
}
fn text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}
fn parse(source: &str) -> Option<Tree> {
    let options = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::Python)
        .cache(false);
    let parsed = options.open(source.as_bytes());
    let tree = parsed.source_ast()?.tree.clone();
    (!tree.root_node().has_error()).then_some(tree)
}
fn integer(node: Node<'_>, source: &str, depth: usize, fuel: &mut usize) -> Option<i64> {
    *fuel = fuel.checked_sub(1)?;
    if depth > 24 {
        return None;
    }
    let n = children(node);
    let value = match node.kind() {
        "integer" => text(node, source)?.parse::<i64>().ok()?,
        "parenthesized_expression" if n.len() == 1 => integer(n[0], source, depth + 1, fuel)?,
        "unary_operator" if n.len() == 1 => {
            let v = integer(n[0], source, depth + 1, fuel)?;
            match source.get(node.start_byte()..n[0].start_byte())?.trim() {
                "-" => v.checked_neg()?,
                "+" => v,
                _ => return None,
            }
        }
        "binary_operator" if n.len() == 2 => {
            let a = integer(n[0], source, depth + 1, fuel)?;
            let b = integer(n[1], source, depth + 1, fuel)?;
            match source.get(n[0].end_byte()..n[1].start_byte())?.trim() {
                "+" => a.checked_add(b)?,
                "-" => a.checked_sub(b)?,
                "*" => a.checked_mul(b)?,
                "<<" if (0..=16).contains(&b) => a.checked_shl(b as u32)?,
                ">>" if (0..=16).contains(&b) => a.checked_shr(b as u32)?,
                "^" => a ^ b,
                _ => return None,
            }
        }
        _ => return None,
    };
    (value.unsigned_abs() <= 0x10ffff).then_some(value)
}
fn binds_protected(node: Node<'_>, source: &str, fuel: &mut usize) -> Option<bool> {
    let mut pending = vec![node];
    while let Some(n) = pending.pop() {
        *fuel = fuel.checked_sub(1)?;
        pending.extend(children(n));
        if n.kind() == "identifier" && PROTECTED.contains(&text(n, source)?) {
            return Some(true);
        }
    }
    Some(false)
}

pub(crate) fn decode(source: &str) -> Option<(String, Vec<(usize, String)>)> {
    if source.len() > MAX_SOURCE
        || !source.contains("__builtins__")
        || !source.contains("copyright.__str__")
    {
        return None;
    }
    let tree = parse(source)?;
    let all = nodes(tree.root_node())?;
    let mut fuel = MAX_FUEL;
    for n in &all {
        if n.kind() == "identifier" && DYNAMIC.contains(&text(*n, source)?) {
            return None;
        }
        let binding = match n.kind() {
            "assignment" | "augmented_assignment" | "for_statement" => {
                n.child_by_field_name("left")
            }
            "named_expression" => n
                .child_by_field_name("name")
                .or_else(|| n.child_by_field_name("left")),
            "parameters"
            | "lambda_parameters"
            | "import_statement"
            | "import_from_statement"
            | "as_pattern"
            | "delete_statement"
            | "global_statement"
            | "nonlocal_statement" => Some(*n),
            "function_definition" | "class_definition" => n.child_by_field_name("name"),
            _ => None,
        };
        if let Some(binding) = binding
            && binds_protected(binding, source, &mut fuel)?
        {
            return None;
        }
    }
    let mut edits = Vec::new();
    let mut written_scripts = Vec::new();
    let mut recognized_builtins = std::collections::HashSet::new();
    for node in all.iter().filter(|n| n.kind() == "call") {
        let Some(function) = node.child_by_field_name("function") else {
            continue;
        };
        if function.kind() != "attribute"
            || function
                .child_by_field_name("attribute")
                .and_then(|n| text(n, source))
                != Some("join")
        {
            continue;
        }
        let Some(obj) = function
            .child_by_field_name("object")
            .and_then(|n| text(n, source))
        else {
            continue;
        };
        if obj != "''" && obj != "\"\"" {
            continue;
        }
        let Some(args) = node.child_by_field_name("arguments") else {
            continue;
        };
        let args = children(args);
        if args.len() != 1 || args[0].kind() != "call" {
            continue;
        }
        let map = args[0];
        if map
            .child_by_field_name("function")
            .and_then(|n| text(n, source))
            != Some("map")
        {
            continue;
        }
        let Some(map_args) = map.child_by_field_name("arguments") else {
            continue;
        };
        let args = children(map_args);
        if args.len() != 2 || !matches!(args[1].kind(), "list" | "tuple") {
            continue;
        }
        let getter_source = text(args[0], source)?;
        if getter_source.len() > 512 {
            continue;
        }
        let getter: String = getter_source
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if getter != GETTER {
            continue;
        }
        let items = children(args[1]);
        if items.len() > MAX_ITEMS {
            continue;
        }
        let mut decoded = String::new();
        let mut valid = true;
        for item in items {
            let Some(c) = integer(item, source, 0, &mut fuel)
                .and_then(|v| u32::try_from(v).ok())
                .and_then(char::from_u32)
            else {
                valid = false;
                break;
            };
            decoded.push(c);
            if decoded.len() > MAX_OUTPUT {
                return None;
            }
        }
        if valid {
            for inner in nodes(args[0])? {
                if inner.kind() == "identifier" && text(inner, source) == Some("__builtins__") {
                    recognized_builtins.insert(inner.start_byte());
                }
            }
            // A complete decoded literal passed directly to a write call can
            // contain a second language. Analyze it separately only when the
            // language detector identifies JavaScript; writing text does not
            // establish that the resulting file was executed.
            let is_write_argument = node.parent().is_some_and(|args| {
                args.kind() == "argument_list"
                    && children(args).first() == Some(node)
                    && args.parent().is_some_and(|call| {
                        call.kind() == "call"
                            && call.child_by_field_name("function").is_some_and(|f| {
                                f.kind() == "attribute"
                                    && f.child_by_field_name("attribute")
                                        .and_then(|a| text(a, source))
                                        == Some("write")
                            })
                    })
            });
            if is_write_argument
                && decoded.len() >= 64
                && stng::script::detect::detect_script_language(decoded.as_bytes())
                    == Some(stng::script::detect::ScriptLanguage::JavaScript)
            {
                written_scripts.push((node.start_byte(), decoded.clone()));
            }
            edits.push((node.byte_range(), serde_json::to_string(&decoded).ok()?));
        }
    }
    if edits.is_empty()
        || all.iter().any(|n| {
            n.kind() == "identifier"
                && text(*n, source) == Some("__builtins__")
                && !recognized_builtins.contains(&n.start_byte())
        })
    {
        return None;
    }
    edits.sort_by_key(|(r, _)| r.start);
    let mut result = String::new();
    let mut end = 0;
    for (range, replacement) in edits {
        if range.start < end {
            return None;
        }
        result.push_str(source.get(end..range.start)?);
        result.push_str(&replacement);
        end = range.end;
        if result.len() > MAX_OUTPUT {
            return None;
        }
    }
    result.push_str(source.get(end..)?);
    (result.len() <= MAX_OUTPUT).then_some((result, written_scripts))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "invalid fixtures should fail the test"
)]
mod tests {
    use super::*;
    const EXPR: &str = "''.join(map(getattr(__builtins__, oct.__str__()[-3 << 0] + hex.__str__()[-1 << 2] + copyright.__str__()[4 << 0]), [(8 << 3) + 1, (5 << 4) + 2]))";
    #[test]
    fn decodes_literal_arithmetic_without_running_python() {
        let (recovered, scripts) = decode(&format!("x = {EXPR}\n")).expect("literal recipe");
        assert_eq!(recovered, "x = \"AR\"\n");
        assert!(scripts.is_empty());
    }
    #[test]
    fn exposes_written_javascript_but_not_unwritten_or_plain_text() {
        let js = "function collect() { const x = document.title; console.log(x); return x; }";
        let encoded = js
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let expr = EXPR.replace("(8 << 3) + 1, (5 << 4) + 2", &encoded);
        let (_, scripts) = decode(&format!("out.write({expr})\n")).unwrap();
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].1, js);
        let (_, scripts) = decode(&format!("text = {expr}\n")).unwrap();
        assert!(scripts.is_empty());
        let text = "this is plain descriptive text and contains no code ".repeat(2);
        let encoded = text
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let expr = EXPR.replace("(8 << 3) + 1, (5 << 4) + 2", &encoded);
        let (_, scripts) = decode(&format!("out.write({expr})\n")).unwrap();
        assert!(scripts.is_empty());
    }
    #[test]
    fn rejects_mutation_unknown_inputs_and_modified_recipe() {
        for source in [
            format!("map = f\nx = {EXPR}\n"),
            format!("def f(map):\n  return {EXPR}\n"),
            format!("exec(input())\nx = {EXPR}\n"),
            format!("alias = __builtins__\nx = {EXPR}\n"),
            format!("vars(object())\nx = {EXPR}\n"),
            format!(
                "x = {}\n",
                EXPR.replace("oct.__str__", &format!("{}oct.__str__", " ".repeat(513)))
            ),
            format!("x = {}\n", EXPR.replace("(8 << 3) + 1", "unknown()")),
            format!("x = {}\n", EXPR.replace("-3 << 0", "-2 << 0")),
            format!("x = {}\n", EXPR.replace("(8 << 3) + 1", "1 << 100")),
        ] {
            assert!(decode(&source).is_none(), "{source}");
        }
    }
}
