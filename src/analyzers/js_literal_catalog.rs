//! Recognize data-only modules before treating their plain string constants as
//! executable embedded programs. Encoded payload analysis remains available.
use tree_sitter::Node;
fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut c = n.walk();
    n.named_children(&mut c)
        .filter(|n| n.kind() != "comment")
        .collect()
}
pub(crate) fn is_data_only(ast: filefacts::SourceAst<'_>) -> bool {
    let root = ast.tree.root_node();
    if ast.source.len() > 4 * 1024 * 1024 || root.has_error() {
        return false;
    }
    let statements = children(root);
    if statements.is_empty() || statements.len() > 4096 {
        return false;
    }
    statements.into_iter().all(|n| {
        if n.kind() != "lexical_declaration" || !ast.source[n.byte_range()].starts_with("const ") {
            return false;
        }
        let declarations = children(n);
        !declarations.is_empty()
            && declarations.into_iter().all(|d| {
                d.kind() == "variable_declarator"
                    && d.child_by_field_name("name")
                        .is_some_and(|n| n.kind() == "identifier")
                    && d.child_by_field_name("value")
                        .is_some_and(|n| n.kind() == "string")
            })
    })
}
#[cfg(test)]
#[allow(clippy::expect_used, reason = "invalid fixtures should fail the test")]
mod tests {
    use super::*;
    fn check(s: &str) -> bool {
        let p = filefacts::OpenOptions::new()
            .path(std::path::Path::new("catalog.js"))
            .open(s.as_bytes());
        is_data_only(p.source_ast().expect("parsed JavaScript fixture"))
    }
    #[test]
    fn quoted_source_is_data() {
        assert!(check(
            "// example\nconst example = 'require(\"https\").get(url);';"
        ));
    }
    #[test]
    fn multiple_constants_are_data() {
        assert!(check("const a='hello', b='world'; const c='\\u0061';"));
    }
    #[test]
    fn invoked_or_exported_source_is_not_a_catalog() {
        assert!(!check("const example='dangerous()';eval(example);"));
        assert!(!check(
            "const example='dangerous()';module.exports=example;"
        ));
    }
    #[test]
    fn initializer_calls_and_interpolation_are_not_data() {
        assert!(!check("const example=loadCode();"));
        assert!(!check("const example=`${loadCode()}`;"));
    }
    #[test]
    fn mutations_and_other_statements_are_not_catalogs() {
        assert!(!check("let example='hello'; example=loadCode();"));
        assert!(!check("const example='hello'; startup();"));
    }
    #[test]
    fn invalid_syntax_fails_closed() {
        assert!(!check("const example = 'broken"));
    }
}
