//! Extract C# source supplied through the documented Edge.js comment convention.
//! The wrapper remains ordinary JavaScript; the additional C# view is plaintext,
//! not an encoding/concealment finding. No managed code is compiled or executed.
use tree_sitter::Node;
fn text<'a>(n: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(n.byte_range())
}
fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = n.walk();
    n.named_children(&mut cursor).collect()
}
fn literal<'a>(n: Node<'_>, source: &'a str) -> Option<&'a str> {
    if n.kind() != "string" {
        return None;
    }
    let raw = text(n, source)?;
    let body = raw.get(1..raw.len().checked_sub(1)?)?;
    (!body.contains('\\')).then_some(body)
}
pub(crate) fn extract(ast: filefacts::SourceAst<'_>) -> Vec<(u64, String)> {
    let source = ast.source;
    if source.len() > 4 * 1024 * 1024 || !source.contains("edge-js") || !source.contains("func") {
        return vec![];
    }
    let mut all = Vec::new();
    let mut cursor = ast.tree.root_node().walk();
    loop {
        all.push(cursor.node());
        if all.len() > 1_000_000 {
            return vec![];
        }
        if cursor.goto_first_child() || cursor.goto_next_sibling() {
            continue;
        }
        loop {
            if !cursor.goto_parent() {
                break;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
        if cursor.node() == ast.tree.root_node() {
            break;
        }
    }
    // A lexically shadowed or escaped require is outside this recognizer.
    if all.iter().any(|n| {
        n.kind() == "identifier"
            && text(*n, source) == Some("require")
            && !n.parent().is_some_and(|p| {
                p.kind() == "call_expression" && p.child_by_field_name("function") == Some(*n)
            })
    }) {
        return vec![];
    }
    let mut out = Vec::new();
    for declaration in all
        .iter()
        .copied()
        .filter(|n| n.kind() == "variable_declarator")
    {
        let Some(binding) = declaration
            .child_by_field_name("name")
            .filter(|n| n.kind() == "identifier")
        else {
            continue;
        };
        let Some(name) = text(binding, source) else {
            continue;
        };
        let Some(value) = declaration
            .child_by_field_name("value")
            .filter(|n| n.kind() == "call_expression")
        else {
            continue;
        };
        if value
            .child_by_field_name("function")
            .and_then(|n| text(n, source))
            != Some("require")
        {
            continue;
        }
        let Some(args) = value.child_by_field_name("arguments") else {
            continue;
        };
        let args = children(args);
        if args.len() != 1
            || !args
                .first()
                .and_then(|n| literal(*n, source))
                .is_some_and(|s| matches!(s, "edge-js" | "electron-edge-js"))
        {
            continue;
        }
        let refs: Vec<_> = all
            .iter()
            .copied()
            .filter(|n| {
                matches!(
                    n.kind(),
                    "identifier"
                        | "shorthand_property_identifier"
                        | "shorthand_property_identifier_pattern"
                ) && text(*n, source) == Some(name)
            })
            .collect();
        if refs.len() != 2 {
            continue;
        }
        let Some(receiver) = refs.iter().copied().find(|n| n.id() != binding.id()) else {
            continue;
        };
        let Some(member) = receiver.parent().filter(|n| {
            matches!(n.kind(), "member_expression" | "subscript_expression")
                && n.child_by_field_name("object") == Some(receiver)
        }) else {
            continue;
        };
        let key = member
            .child_by_field_name("property")
            .and_then(|n| text(n, source))
            .or_else(|| {
                member
                    .child_by_field_name("index")
                    .and_then(|n| literal(n, source))
            });
        if key != Some("func") {
            continue;
        }
        let Some(call) = member.parent().filter(|n| {
            n.kind() == "call_expression" && n.child_by_field_name("function") == Some(member)
        }) else {
            continue;
        };
        let Some(scope) = declaration.parent().and_then(|n| n.parent()) else {
            continue;
        };
        if receiver.start_byte() < declaration.end_byte()
            || receiver.end_byte() > scope.end_byte()
            || receiver.start_byte() < scope.start_byte()
        {
            continue;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            continue;
        };
        let args = children(args);
        if args.len() != 1 {
            continue;
        }
        let function = args[0];
        if function.kind() != "function_expression" {
            continue;
        }
        if !function
            .child_by_field_name("parameters")
            .is_some_and(|n| children(n).is_empty())
        {
            continue;
        }
        let Some(body) = function.child_by_field_name("body") else {
            continue;
        };
        let body = children(body);
        if body.len() != 1 || body[0].kind() != "comment" {
            continue;
        }
        let Some(comment) = text(body[0], source)
            .and_then(|s| s.strip_prefix("/*"))
            .and_then(|s| s.strip_suffix("*/"))
        else {
            continue;
        };
        if comment.len() < 64 || comment.len() > 1024 * 1024 {
            continue;
        }
        out.push((body[0].start_byte() as u64 + 2, comment.to_owned()));
        if out.len() >= 8 {
            break;
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    const CSHARP: &str = "using System; using System.Threading.Tasks; class Startup { public async Task<object> Invoke(object input) { return input; } }";
    fn input(module: &str) -> String {
        format!(
            "const bridge=require('{}'); const compiled=bridge.func(function(){{/*{}*/}});",
            module, CSHARP
        )
    }
    fn run(s: &str) -> Vec<(u64, String)> {
        let ctx = crate::analysis_context::AnalysisContext::open(
            std::path::Path::new("input.js"),
            s.as_bytes(),
        );
        ctx.source_ast().map(extract).unwrap_or_default()
    }
    #[test]
    fn extracts_only_import_bound_comment_source() {
        for module in ["edge-js", "electron-edge-js"] {
            let values = run(&input(module));
            assert_eq!(values.len(), 1);
            assert_eq!(values[0].1, CSHARP);
        }
    }
    #[test]
    fn rejects_other_module_and_plain_documentation() {
        assert!(run(&input("ordinary-lib")).is_empty());
        assert!(run(&format!("/*{}*/", input("edge-js"))).is_empty());
    }
    #[test]
    fn rejects_alias_mutation_escape_shadow_and_require_rebinding() {
        for extra in [
            "bridge=other;",
            "bridge.func=other;",
            "send(bridge);",
            "const alias=bridge;",
            "const extra={bridge};",
            "function unrelated(bridge){}",
            "const require=custom;",
        ] {
            let s =
                input("edge-js").replace(" const compiled", &format!(" {} const compiled", extra));
            assert!(run(&s).is_empty(), "{extra}");
        }
    }
    #[test]
    fn rejects_javascript_callback_bodies_and_parameters() {
        for s in [
            input("edge-js").replace("function(){", "function(input){"),
            input("edge-js").replace("/*using", "return; /*using"),
            input("edge-js").replace("bridge.func(", "other.func("),
        ] {
            assert!(run(&s).is_empty());
        }
    }
    #[test]
    fn supports_renamed_receiver_and_bracket_member() {
        assert_eq!(
            run(&input("edge-js")
                .replace("bridge", "adapter")
                .replace("adapter.func", "adapter['func']"))
            .len(),
            1
        );
    }
}
