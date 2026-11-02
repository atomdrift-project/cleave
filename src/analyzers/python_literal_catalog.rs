//! Recognize inert Python string catalogs before analyzing plain quoted source.
//! Encoded payload layers and the host's ordinary source facts remain visible.
use tree_sitter::Node;

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect()
}

fn plain_string(node: Node<'_>) -> bool {
    node.kind() == "string"
        && children(node).into_iter().all(|child| {
            matches!(
                child.kind(),
                "string_start" | "string_content" | "string_end"
            )
        })
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
    statements.into_iter().all(|statement| {
        if statement.kind() != "expression_statement" {
            return false;
        }
        let expressions = children(statement);
        if expressions.len() != 1 {
            return false;
        }
        let expression = expressions[0];
        plain_string(expression)
            || (expression.kind() == "assignment"
                && expression.child_by_field_name("type").is_none()
                && expression
                    .child_by_field_name("left")
                    .is_some_and(|left| left.kind() == "identifier")
                && expression
                    .child_by_field_name("right")
                    .is_some_and(plain_string))
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "invalid fixtures should fail the test")]
mod tests {
    use super::*;
    fn check(source: &str) -> bool {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("catalog.py"))
            .open(source.as_bytes());
        is_data_only(parsed.source_ast().expect("parsed Python fixture"))
    }
    #[test]
    fn quoted_source_and_docstrings_are_data() {
        assert!(check("# example\nexample = 'exec(payload)'\n"));
        assert!(check(
            "\"\"\"A module docstring.\"\"\"\nexample = r'exec(payload)'\n"
        ));
        assert!(check("one = 'hello'\ntwo = b'world'\n"));
    }
    #[test]
    fn evaluated_or_called_source_is_not_a_catalog() {
        assert!(!check("example='exec(payload)'\nexec(example)\n"));
        assert!(!check("example='exec(payload)'\nmain()\n"));
    }
    #[test]
    fn computed_initializers_and_interpolation_are_not_data() {
        assert!(!check("example=load_code()\n"));
        assert!(!check("example=f'{load_code()}'\n"));
        assert!(!check("example: load_type() = 'text'\n"));
    }
    #[test]
    fn imports_mutations_and_attribute_targets_are_not_data() {
        assert!(!check("import loader\nexample='text'\n"));
        assert!(!check("example='text'\nexample += load_code()\n"));
        assert!(!check("get_object().example='text'\n"));
    }
    #[test]
    fn invalid_syntax_fails_closed() {
        assert!(!check("example = 'broken\n"));
    }
}
