// Literal-only decimal Packer reduction. No JavaScript is executed.
use regex::Regex;
use std::{collections::HashMap, sync::LazyLock};
use tree_sitter::{Node, Tree};

const SIMPLE: &str = r#"function unpack(p,a,c,k,e,d){while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+c+'\\b','g'),k[c])}}return p}"#;
const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_TOTAL: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = 2_000_000;
const MAX_TABLE: usize = 16_384;
const CANONICAL: &str = r#"function unpack(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}"#;
#[allow(clippy::expect_used)]
static WORD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b\w+\b)").expect("static word regex"));

fn parse(source: &str) -> Option<Tree> {
    if source.len() > MAX_SOURCE {
        return None;
    }
    let options = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::JavaScript)
        .cache(false);
    let parsed = options.open(source.as_bytes());
    let tree = parsed.source_ast()?.tree.clone();
    (!tree.root_node().has_error()).then_some(tree)
}
fn text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}
fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}
fn nodes(root: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut pending = vec![root];
    let mut result = Vec::new();
    while let Some(node) = pending.pop() {
        if result.len() >= MAX_NODES {
            return None;
        }
        pending.extend(children(node));
        result.push(node);
    }
    Some(result)
}
fn literal(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = text(node, source)?;
    Some(filefacts::decode_source_escapes_for_type(
        &raw[1..raw.len() - 1],
        filefacts::FileType::JavaScript,
    ))
}
fn integer(node: Node<'_>, source: &str) -> Option<usize> {
    if node.kind() != "number" {
        return None;
    }
    let raw = text(node, source)?;
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else {
        raw.parse().ok()
    }
}
fn member<'a>(node: Node<'a>, source: &str) -> Option<(Node<'a>, String)> {
    let object = node.child_by_field_name("object")?;
    let property = if node.kind() == "member_expression" {
        text(node.child_by_field_name("property")?, source)?.to_owned()
    } else if node.kind() == "subscript_expression" {
        literal(node.child_by_field_name("index")?, source)?
    } else {
        return None;
    };
    Some((object, property))
}

/// Constant string-array reads are reduced only when every use is a fixed,
/// read-only subscript. Passing the array, writes and shadowing all reject it.
pub(crate) fn constant_tables(source: &str) -> Option<String> {
    let tree = parse(source)?;
    let all = nodes(tree.root_node())?;
    let mut edits = Vec::<(usize, usize, String)>::new();
    let mut fuel = 8_000_000usize;
    for declaration in children(tree.root_node()) {
        if !matches!(
            declaration.kind(),
            "variable_declaration" | "lexical_declaration"
        ) {
            continue;
        }
        for binding in children(declaration) {
            if binding.kind() != "variable_declarator" {
                continue;
            }
            let Some(name) = binding.child_by_field_name("name") else {
                continue;
            };
            let Some(value) = binding.child_by_field_name("value") else {
                continue;
            };
            if name.kind() != "identifier" || value.kind() != "array" {
                continue;
            }
            let items = children(value);
            if items.is_empty() || items.len() > MAX_TABLE {
                continue;
            }
            let Some(strings) = items
                .into_iter()
                .map(|n| literal(n, source))
                .collect::<Option<Vec<_>>>()
            else {
                continue;
            };
            let name_text = text(name, source)?;
            let mut uses = Vec::new();
            let mut valid = true;
            for node in &all {
                fuel = fuel.checked_sub(1)?;
                if node.kind() != "identifier"
                    || text(*node, source) != Some(name_text)
                    || node.id() == name.id()
                {
                    continue;
                }
                let Some(parent) = node.parent() else {
                    valid = false;
                    break;
                };
                if parent.kind() != "subscript_expression"
                    || parent
                        .child_by_field_name("object")
                        .is_none_or(|n| n.id() != node.id())
                {
                    valid = false;
                    break;
                }
                if parent.parent().is_some_and(|p| {
                    matches!(
                        p.kind(),
                        "assignment_expression"
                            | "augmented_assignment_expression"
                            | "update_expression"
                    ) && p
                        .child_by_field_name("left")
                        .or_else(|| p.child_by_field_name("argument"))
                        .is_some_and(|target| target.id() == parent.id())
                }) {
                    valid = false;
                    break;
                }
                let Some(index) = parent
                    .child_by_field_name("index")
                    .and_then(|n| integer(n, source))
                else {
                    valid = false;
                    break;
                };
                let Some(item) = strings.get(index) else {
                    valid = false;
                    break;
                };
                uses.push((
                    parent.start_byte(),
                    parent.end_byte(),
                    serde_json::to_string(item).ok()?,
                ));
            }
            if valid {
                edits.extend(uses);
            }
        }
    }
    if edits.is_empty() {
        return None;
    }
    edits.sort_by_key(|e| e.0);
    edits.dedup_by_key(|e| (e.0, e.1));
    let mut result = String::new();
    let mut at = 0;
    for (start, end, value) in edits {
        if start < at
            || result
                .len()
                .checked_add(start - at)?
                .checked_add(value.len())?
                > MAX_SOURCE
        {
            return None;
        }
        result.push_str(source.get(at..start)?);
        result.push_str(&value);
        at = end;
    }
    result.push_str(source.get(at..)?);
    (result.len() <= MAX_SOURCE).then_some(result)
}

// Compare the complete decoder body, preserving operators, control flow and
// literals. Only parameter names, optional semicolons and member spelling vary.
fn normalize(
    node: Node<'_>,
    source: &str,
    names: &HashMap<String, String>,
    depth: usize,
) -> Option<String> {
    if depth > 128 {
        return None;
    }
    if let Some((object, property)) = member(node, source) {
        return Some(format!(
            "member({},{})",
            normalize(object, source, names, depth + 1)?,
            property
        ));
    }
    if let Some(value) = literal(node, source) {
        return Some(format!("str{}", serde_json::to_string(&value).ok()?));
    }
    if node.child_count() == 0 {
        let raw = text(node, source)?;
        return Some(names.get(raw).cloned().unwrap_or_else(|| raw.to_owned()));
    }
    let mut out = format!("{}(", node.kind());
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if matches!(child.kind(), ";" | "comment" | "empty_statement") {
            continue;
        }
        out.push_str(&normalize(child, source, names, depth + 1)?);
        out.push('|');
    }
    out.push(')');
    Some(out)
}
fn decoder_body(function: Node<'_>, source: &str) -> Option<String> {
    if !matches!(
        function.kind(),
        "function_expression" | "function_declaration"
    ) {
        return None;
    }
    let parameters = children(function.child_by_field_name("parameters")?);
    if parameters.len() != 6 || parameters.iter().any(|n| n.kind() != "identifier") {
        return None;
    }
    let mut names = HashMap::new();
    for (node, canonical) in parameters.into_iter().zip(["p", "a", "c", "k", "e", "d"]) {
        names.insert(text(node, source)?.to_owned(), canonical.to_owned());
    }
    if names.len() != 6 {
        return None;
    }
    normalize(function.child_by_field_name("body")?, source, &names, 0)
}
fn unpack_once(source: &str) -> Option<String> {
    let tree = parse(source)?;
    let canonical_tree = parse(CANONICAL)?;
    let canonical = decoder_body(*children(canonical_tree.root_node()).first()?, CANONICAL)?;
    let simple_tree = parse(SIMPLE)?;
    let simple = decoder_body(*children(simple_tree.root_node()).first()?, SIMPLE)?;
    for call in nodes(tree.root_node())? {
        if call.kind() != "call_expression"
            || call
                .child_by_field_name("function")
                .and_then(|n| text(n, source))
                != Some("eval")
        {
            continue;
        }
        let args = children(call.child_by_field_name("arguments")?);
        if args.len() != 1 || args[0].kind() != "call_expression" {
            continue;
        }
        let packed = args[0];
        let function = packed.child_by_field_name("function")?;
        let Some(body) = decoder_body(function, source) else {
            continue;
        };
        let fast = body == canonical;
        if !fast && body != simple {
            continue;
        }
        let args = children(packed.child_by_field_name("arguments")?);
        if (fast && args.len() != 6)
            || (!fast && !(4..=6).contains(&args.len()))
            || integer(args[1], source) != Some(10)
        {
            continue;
        }
        let count = integer(args[2], source)?;
        if count > MAX_TABLE || args[3].kind() != "call_expression" {
            continue;
        }
        let (table_node, method) = member(args[3].child_by_field_name("function")?, source)?;
        let separator = children(args[3].child_by_field_name("arguments")?);
        if method != "split"
            || separator.len() != 1
            || literal(separator[0], source).as_deref() != Some("|")
        {
            continue;
        }
        if (args.len() > 4 && integer(args[4], source) != Some(0))
            || (args.len() > 5 && (args[5].kind() != "object" || !children(args[5]).is_empty()))
        {
            continue;
        }
        let payload = literal(args[0], source)?;
        let dictionary = literal(table_node, source)?;
        let words: Vec<_> = dictionary.split('|').collect();
        if words.len() != count {
            continue;
        }
        let mut expanded = Vec::<String>::new();
        let mut stored = 0usize;
        for word in &words {
            let item = if fast {
                (*word).to_owned()
            } else {
                replace_words(word, &expanded)?
            };
            stored = stored.checked_add(item.len())?;
            if stored > MAX_TOTAL {
                return None;
            }
            expanded.push(item);
        }
        let result = replace_words(&payload, &expanded)?;
        return (result.len() <= MAX_SOURCE).then_some(result);
    }
    None
}
fn replace_words(input: &str, words: &[String]) -> Option<String> {
    let mut result = String::new();
    let mut at = 0;
    for found in WORD.find_iter(input) {
        let replacement = found
            .as_str()
            .parse::<usize>()
            .ok()
            .and_then(|n| words.get(n))
            .filter(|s| !s.is_empty())
            .map_or(found.as_str(), String::as_str);
        let prefix = input.get(at..found.start())?;
        if result
            .len()
            .checked_add(prefix.len())?
            .checked_add(replacement.len())?
            > MAX_SOURCE
        {
            return None;
        }
        result.push_str(prefix);
        result.push_str(replacement);
        at = found.end();
    }
    let tail = input.get(at..)?;
    if result.len().checked_add(tail.len())? > MAX_SOURCE {
        return None;
    }
    result.push_str(tail);
    Some(result)
}
pub(crate) fn decode(source: &str) -> Option<String> {
    if source.len() > MAX_SOURCE || !source.contains("eval") || !source.contains("RegExp") {
        return None;
    }
    let mut current = source.to_owned();
    let mut decoded = false;
    let mut budget = MAX_TOTAL;
    for _ in 0..10 {
        let reduced = constant_tables(&current).unwrap_or_else(|| current.clone());
        let Some(next) = unpack_once(&reduced) else {
            if decoded {
                current = reduced;
            }
            break;
        };
        budget = budget.checked_sub(next.len())?;
        current = next;
        decoded = true;
    }
    decoded.then_some(current)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn packed() -> String {
        format!(
            "eval({}('0.1(2)',10,3,'console|log|42'.split('|'),0,{{}}))",
            CANONICAL.replacen("function unpack", "function", 1)
        )
    }
    #[test]
    fn decodes_without_running_source() -> Result<(), serde_json::Error> {
        assert_eq!(decode(&packed()).as_deref(), Some("console.log(42)"));
        let two = format!(
            "eval({}({},10,0,''.split('|'),0,{{}}))",
            CANONICAL.replacen("function unpack", "function", 1),
            serde_json::to_string(&packed())?
        );
        // A malformed dictionary cardinality is rejected rather than guessed.
        assert!(decode(&two).is_none());
        Ok(())
    }
    #[test]
    fn nested_and_reverse_dictionary() -> Result<(), serde_json::Error> {
        let two = format!(
            "eval({}({},10,1,''.split('|'),0,{{}}))",
            CANONICAL.replacen("function unpack", "function", 1),
            serde_json::to_string(&packed())?
        );
        assert_eq!(decode(&two).as_deref(), Some("console.log(42)"));
        let cascade = format!(
            "eval({}('1 0',10,2,'console|0'.split('|'),0,{{}}))",
            SIMPLE.replacen("function unpack", "function", 1)
        );
        assert_eq!(decode(&cascade).as_deref(), Some("console console"));
        let short = cascade.replace(",0,{})", ")");
        assert_eq!(decode(&short).as_deref(), Some("console console"));
        assert_eq!(
            decode(&("eval(unrelated());".to_owned() + &packed())).as_deref(),
            Some("console.log(42)")
        );
        Ok(())
    }
    #[test]
    fn rejects_changed_semantics_or_dynamic_inputs() {
        for s in [
            packed().replace("return p}", "return 'different'}"),
            packed().replace("10,3", "36,3"),
            packed().replace("'console|log|42'", "readFile()"),
            "eval('console.log(42)')".to_owned(),
        ] {
            assert!(decode(&s).is_none());
        }
    }
    #[test]
    fn substitutes_table_reads_on_assignment_right_hand_sides() {
        assert_eq!(
            constant_tables("var t=['a','b'];let value;value=t[0];value+=t[1];").as_deref(),
            Some("var t=['a','b'];let value;value=\"a\";value+=\"b\";")
        );
        assert!(constant_tables("var t=['a','b'];t[0]+='x';console.log(t[1]);").is_none());
        assert!(constant_tables("var t=['1','b'];t[0]++;console.log(t[1]);").is_none());
    }
    #[test]
    fn refuses_mutated_or_shadowed_constant_tables() {
        assert!(constant_tables("var t=['a','b'];t[0]='x';console.log(t[1]);").is_none());
        assert!(
            constant_tables("var t=['a','b'];function f(t){return t[0]} console.log(t[1]);")
                .is_none()
        );
        assert!(constant_tables("var t=['a','b'];unknown(t);console.log(t[1]);").is_none());
        assert!(decode(&"x".repeat(MAX_SOURCE + 1)).is_none());
    }
}
