//! Verify tree-sitter parser initialization.

use tree_sitter::Parser;

fn main() {
    let _parser = Parser::new();
    println!("tree-sitter parser initialized");
}
