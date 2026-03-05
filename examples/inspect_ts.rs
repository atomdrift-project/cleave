use tree_sitter::Parser;

fn main() {
    let p = Parser::new();
    // Intentionally cause an error to see the methods on `p`
    p.this_method_does_not_exist();
}
