//! Reconstruct two constant Buffer-XOR recipes consumed by child_process.exec.
//! This is a bounded AST reducer, not a JS interpreter. Unknown bindings,
//! mutations, escapes, callbacks, loop bodies or shell overrides stop recovery.
use crate::analyzers::FileType;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 200_000;
const MAX_BYTES: usize = 1024 * 1024;

pub(crate) struct Command {
    pub offset: u64,
    pub text: String,
    pub file_type: FileType,
}
fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = n.walk();
    n.named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}
fn unwrap(mut n: Node<'_>) -> Node<'_> {
    for _ in 0..32 {
        if n.kind() != "parenthesized_expression" {
            break;
        }
        let Some(inner) = n.named_child(0) else { break };
        n = inner;
    }
    n
}
fn inside(n: Node<'_>, parent: Node<'_>) -> bool {
    n.start_byte() >= parent.start_byte() && n.end_byte() <= parent.end_byte()
}
fn previous(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        node = node.prev_named_sibling()?;
        if !matches!(node.kind(), "comment" | "empty_statement") {
            return Some(node);
        }
    }
}
fn binding(n: Node<'_>) -> bool {
    let Some(p) = n.parent() else { return false };
    match p.kind() {
        "variable_declarator" | "function_declaration" | "function_expression" => {
            p.child_by_field_name("name") == Some(n)
        }
        "formal_parameters" | "rest_pattern" | "namespace_import" | "import_clause"
        | "object_pattern" => true,
        "pair_pattern" => p.child_by_field_name("value") == Some(n),
        "required_parameter" | "optional_parameter" => p.child_by_field_name("pattern") == Some(n),
        "catch_clause" => p.child_by_field_name("parameter") == Some(n),
        "import_specifier" => {
            p.child_by_field_name("alias")
                .or_else(|| p.child_by_field_name("name"))
                == Some(n)
        }
        _ => false,
    }
}
struct Context<'a, 'tree> {
    source: &'a str,
    nodes: Vec<Node<'tree>>,
    refs: HashMap<&'a str, Vec<Node<'tree>>>,
    definitions: HashMap<&'a str, Vec<Node<'tree>>>,
    mutations: HashSet<&'a str>,
}
impl<'a, 'tree> Context<'a, 'tree> {
    fn text(&self, n: Node<'_>) -> Option<&'a str> {
        self.source.get(n.byte_range())
    }
    fn refs(&self, name: &str) -> &[Node<'tree>] {
        self.refs.get(name).map_or(&[], Vec::as_slice)
    }
    fn definitions(&self, name: &str) -> &[Node<'tree>] {
        self.definitions.get(name).map_or(&[], Vec::as_slice)
    }
    fn named(&self, n: Node<'_>, name: &str) -> bool {
        n.kind() == "identifier" && self.text(n) == Some(name)
    }
    #[cfg(test)]
    fn mentions(&self, n: Node<'_>, name: &str) -> bool {
        self.refs(name).iter().any(|r| inside(*r, n))
    }
    fn mutated(&self, name: &str) -> bool {
        self.mutations.contains(name)
    }

    fn declaration(&self, reference: Node<'tree>) -> Option<Node<'tree>> {
        let name = self.text(reference)?;
        let [definition] = self.definitions(name) else {
            return None;
        };
        let decl = definition.parent()?;
        if decl.kind() != "variable_declarator"
            || decl.child_by_field_name("name") != Some(*definition)
            || decl.end_byte() >= reference.start_byte()
        {
            return None;
        }
        let statement = decl.parent()?;
        if statement.kind() != "lexical_declaration" || statement.child(0)?.kind() != "const" {
            return None;
        }
        let block = statement.parent()?;
        // A sibling branch's assignment does not establish a value at this use.
        let mut ancestor = reference;
        loop {
            if ancestor == block {
                return Some(decl);
            }
            ancestor = ancestor.parent()?;
        }
    }
    fn scalar(&self, n: Node<'tree>, depth: usize) -> Option<Node<'tree>> {
        if depth > 32 {
            return None;
        }
        let n = unwrap(n);
        if n.kind() != "identifier" {
            return Some(n);
        }
        if self.mutated(self.text(n)?) {
            return None;
        }
        self.scalar(
            self.declaration(n)?.child_by_field_name("value")?,
            depth + 1,
        )
    }
    fn string(&self, n: Node<'tree>) -> Option<(Node<'tree>, &'a str)> {
        let n = self.scalar(n, 0)?;
        if n.kind() != "string" {
            return None;
        }
        let raw = self.text(n)?;
        let first = *raw.as_bytes().first()?;
        if !matches!(first, b'\'' | b'"') || raw.as_bytes().last().copied()? != first {
            return None;
        }
        let body = raw.get(1..raw.len().checked_sub(1)?)?;
        (!body.contains(['\\', '\n', '\r']) && body.len() <= 2 * MAX_BYTES).then_some((n, body))
    }
    fn integer(&self, n: Node<'tree>) -> Option<u64> {
        let n = self.scalar(n, 0)?;
        if n.kind() != "number" {
            return None;
        }
        let raw = self.text(n)?.replace('_', "");
        if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16).ok();
        }
        if raw.len() > 1 && raw.starts_with('0') {
            return None;
        } // sloppy-mode octal is not decimal
        raw.parse().ok()
    }
    fn method(&self, n: Node<'tree>, property: &str) -> Option<(Node<'tree>, Vec<Node<'tree>>)> {
        let n = unwrap(n);
        if n.kind() != "call_expression" || n.child_by_field_name("optional_chain").is_some() {
            return None;
        }
        let function = n.child_by_field_name("function")?;
        if function.kind() != "member_expression"
            || function.child_by_field_name("optional_chain").is_some()
            || function
                .child_by_field_name("property")
                .and_then(|n| self.text(n))
                != Some(property)
        {
            return None;
        }
        Some((
            function.child_by_field_name("object")?,
            children(n.child_by_field_name("arguments")?),
        ))
    }
    fn buffer_global(&self) -> bool {
        self.definitions("Buffer").is_empty()
            && !self.mutated("Buffer")
            && self.refs("Buffer").iter().all(|n| {
                n.parent().is_some_and(|member| {
                    member.kind() == "member_expression"
                        && member.child_by_field_name("object") == Some(*n)
                        && member
                            .child_by_field_name("property")
                            .and_then(|n| self.text(n))
                            .is_some_and(|p| matches!(p, "from" | "alloc"))
                        && member.parent().is_some_and(|call| {
                            call.kind() == "call_expression"
                                && call.child_by_field_name("function") == Some(member)
                        })
                })
            })
    }
    fn raw(&self, n: Node<'tree>) -> Option<(Node<'tree>, Vec<u8>)> {
        let (object, args) = self.method(n, "from")?;
        let [value, encoding] = args.as_slice() else {
            return None;
        };
        if !self.named(object, "Buffer") || !self.string(*encoding)?.1.eq_ignore_ascii_case("hex") {
            return None;
        }
        let (origin, hex) = self.string(*value)?;
        if hex.len() < 48 || hex.len() > 2 * MAX_BYTES || !hex.len().is_multiple_of(2) {
            return None;
        }
        Some((origin, hex::decode(hex).ok()?))
    }
    fn xor(&self, expression: Node<'tree>, byte: Node<'tree>) -> Option<u8> {
        let expression = unwrap(expression);
        if expression.kind() != "binary_expression"
            || expression
                .child_by_field_name("operator")
                .and_then(|n| self.text(n))
                != Some("^")
        {
            return None;
        }
        let left = unwrap(expression.child_by_field_name("left")?);
        let right = unwrap(expression.child_by_field_name("right")?);
        let key = if self.text(left) == self.text(byte) {
            right
        } else if self.text(right) == self.text(byte) {
            left
        } else {
            return None;
        };
        u8::try_from(self.integer(key)?).ok()
    }
    fn map(&self, n: Node<'tree>) -> Option<(Node<'tree>, Vec<u8>)> {
        let (raw, args) = self.method(n, "map")?;
        let [callback] = args.as_slice() else {
            return None;
        };
        if !matches!(callback.kind(), "arrow_function" | "function_expression") {
            return None;
        }
        let parameters = callback
            .child_by_field_name("parameter")
            .map(|n| vec![n])
            .or_else(|| callback.child_by_field_name("parameters").map(children))?;
        let [parameter] = parameters.as_slice() else {
            return None;
        };
        let parameter = if parameter.kind() == "required_parameter" {
            parameter.child_by_field_name("pattern")?
        } else {
            *parameter
        };
        if parameter.kind() != "identifier" {
            return None;
        }
        let body = callback.child_by_field_name("body")?;
        let expression = if body.kind() == "statement_block" {
            let statements = children(body);
            let [statement] = statements.as_slice() else {
                return None;
            };
            if statement.kind() != "return_statement" {
                return None;
            }
            statement.named_child(0)?
        } else {
            body
        };
        let key = self.xor(expression, parameter)?;
        let (origin, mut bytes) = self.raw(raw)?;
        for byte in &mut bytes {
            *byte ^= key;
        }
        Some((origin, bytes))
    }
    fn length(&self, n: Node<'tree>, name: &str) -> bool {
        n.kind() == "member_expression"
            && n.child_by_field_name("object")
                .is_some_and(|n| self.named(n, name))
            && n.child_by_field_name("property").and_then(|n| self.text(n)) == Some("length")
    }
    fn index(&self, n: Node<'tree>, object: &str, index: &str) -> bool {
        n.kind() == "subscript_expression"
            && n.child_by_field_name("object")
                .is_some_and(|n| self.named(n, object))
            && n.child_by_field_name("index")
                .is_some_and(|n| self.named(n, index))
    }
    fn loop_bytes(&self, buffer: Node<'tree>, call: Node<'tree>) -> Option<(Node<'tree>, Vec<u8>)> {
        if buffer.kind() != "identifier" {
            return None;
        }
        let output_name = self.text(buffer)?;
        let output_decl = self.declaration(buffer)?;
        let (allocator, args) = self.method(output_decl.child_by_field_name("value")?, "alloc")?;
        let [size] = args.as_slice() else { return None };
        if !self.named(allocator, "Buffer") || size.kind() != "member_expression" {
            return None;
        }
        let input = size.child_by_field_name("object")?;
        if input.kind() != "identifier" {
            return None;
        }
        let input_name = self.text(input)?;
        if !self.length(*size, input_name) {
            return None;
        }
        let input_decl = self.declaration(input)?;
        let output_statement = output_decl.parent()?;
        if previous(output_statement) != Some(input_decl.parent()?) {
            return None;
        }
        let mut statement = call;
        while statement.parent()? != output_statement.parent()? {
            statement = statement.parent()?;
        }
        let loop_ = previous(statement)?;
        if loop_.kind() != "for_statement" || previous(loop_) != Some(output_statement) {
            return None;
        }
        let init = loop_.child_by_field_name("initializer")?;
        let init_children = children(init);
        let [counter] = init_children.as_slice() else {
            return None;
        };
        let index = counter.child_by_field_name("name")?;
        let index_name = self.text(index)?;
        if index.kind() != "identifier"
            || self.integer(counter.child_by_field_name("value")?) != Some(0)
        {
            return None;
        }
        let condition = loop_.child_by_field_name("condition")?;
        if condition.kind() != "binary_expression"
            || condition
                .child_by_field_name("operator")
                .and_then(|n| self.text(n))
                != Some("<")
            || !condition
                .child_by_field_name("left")
                .is_some_and(|n| self.named(n, index_name))
            || !self.length(condition.child_by_field_name("right")?, input_name)
        {
            return None;
        }
        let increment = loop_.child_by_field_name("increment")?;
        if increment.kind() != "update_expression"
            || increment
                .child_by_field_name("operator")
                .and_then(|n| self.text(n))
                != Some("++")
            || !increment
                .child_by_field_name("argument")
                .is_some_and(|n| self.named(n, index_name))
        {
            return None;
        }
        let mut body = loop_.child_by_field_name("body")?;
        if body.kind() == "statement_block" {
            let statements = children(body);
            let [statement] = statements.as_slice() else {
                return None;
            };
            body = *statement;
        }
        if body.kind() == "expression_statement" {
            body = body.named_child(0)?;
        }
        // The grammar uses assignment_expression only for '='; compound
        // operators have an augmented_assignment_expression node instead.
        if body.kind() != "assignment_expression"
            || !self.index(body.child_by_field_name("left")?, output_name, index_name)
        {
            return None;
        }
        let expression = unwrap(body.child_by_field_name("right")?);
        if expression.kind() != "binary_expression"
            || expression
                .child_by_field_name("operator")
                .and_then(|n| self.text(n))
                != Some("^")
        {
            return None;
        }
        let left = expression.child_by_field_name("left")?;
        let right = expression.child_by_field_name("right")?;
        let key = if self.index(left, input_name, index_name) {
            self.integer(right)?
        } else if self.index(right, input_name, index_name) {
            self.integer(left)?
        } else {
            return None;
        };
        let key = u8::try_from(key).ok()?;
        // These exact uses exhaust the buffers/counter: no mutation, alias,
        // escape, shadow or additional loop operation can be silently skipped.
        if self.refs(input_name).len() != 4
            || self.refs(output_name).len() != 3
            || self.refs(index_name).len() != 5
        {
            return None;
        }
        let (origin, mut bytes) = self.raw(input_decl.child_by_field_name("value")?)?;
        for byte in &mut bytes {
            *byte ^= key;
        }
        Some((origin, bytes))
    }
    fn decoded(
        &self,
        n: Node<'tree>,
        call: Node<'tree>,
        depth: usize,
    ) -> Option<(Node<'tree>, String)> {
        if depth > 32 {
            return None;
        }
        let n = unwrap(n);
        if n.kind() == "identifier" {
            if self.mutated(self.text(n)?) {
                return None;
            }
            return self.decoded(
                self.declaration(n)?.child_by_field_name("value")?,
                call,
                depth + 1,
            );
        }
        let (buffer, args) = self.method(n, "toString")?;
        if args.len() > 1
            || args.first().is_some_and(|n| {
                !self.string(*n).is_some_and(|(_, encoding)| {
                    matches!(encoding.to_ascii_lowercase().as_str(), "utf8" | "utf-8")
                })
            })
        {
            return None;
        }
        let (origin, bytes) = if buffer.kind() == "identifier" {
            self.loop_bytes(buffer, call)?
        } else {
            self.map(buffer)?
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (!text.contains('\0') && text.len() >= 24).then_some((origin, text))
    }
    fn require(&self, value: Node<'tree>) -> bool {
        let value = unwrap(value);
        if value.kind() != "call_expression"
            || !value
                .child_by_field_name("function")
                .is_some_and(|n| self.named(n, "require"))
            || !self.definitions("require").is_empty()
            || self.mutated("require")
        {
            return false;
        }
        let Some(args) = value.child_by_field_name("arguments").map(children) else {
            return false;
        };
        let [argument] = args.as_slice() else {
            return false;
        };
        self.string(*argument)
            .is_some_and(|(_, name)| matches!(name, "child_process" | "node:child_process"))
    }
    fn callee(&self, n: Node<'tree>) -> Node<'tree> {
        let n = unwrap(n);
        if n.kind() == "sequence_expression" {
            let parts = children(n);
            if parts.len() == 2 && self.integer(parts[0]) == Some(0) {
                return unwrap(parts[1]);
            }
        }
        n
    }
    fn imported_exec(&self, n: Node<'tree>) -> bool {
        let n = self.callee(n);
        if n.kind() == "identifier" {
            let Some(name) = self.text(n) else {
                return false;
            };
            if self.mutated(name) {
                return false;
            }
            let [definition] = self.definitions(name) else {
                return false;
            };
            let Some(parent) = definition.parent() else {
                return false;
            };
            if parent.kind() == "import_specifier" {
                return parent
                    .child_by_field_name("name")
                    .and_then(|n| self.text(n))
                    == Some("exec")
                    && self.import_source(parent).is_some_and(|name| {
                        matches!(name, "child_process" | "node:child_process")
                    });
            }
            let pattern = if definition.kind() == "shorthand_property_identifier_pattern" {
                *definition
            } else {
                parent
            };
            let imported = if pattern.kind() == "pair_pattern" {
                pattern
                    .child_by_field_name("key")
                    .and_then(|n| self.text(n))
            } else if pattern.kind() == "shorthand_property_identifier_pattern" {
                self.text(pattern)
            } else {
                None
            };
            if imported != Some("exec") {
                return false;
            }
            let Some(decl) = pattern.parent().and_then(|p| p.parent()) else {
                return false;
            };
            return decl.kind() == "variable_declarator"
                && decl.parent().is_some_and(|p| {
                    p.kind() == "lexical_declaration"
                        && p.child(0).is_some_and(|n| n.kind() == "const")
                        && p.parent().is_some_and(|scope| inside(n, scope))
                })
                && decl.start_byte() < n.start_byte()
                && decl
                    .child_by_field_name("value")
                    .is_some_and(|v| self.require(v));
        }
        if n.kind() != "member_expression"
            || n.child_by_field_name("property").and_then(|n| self.text(n)) != Some("exec")
        {
            return false;
        }
        let Some(object) = n
            .child_by_field_name("object")
            .filter(|n| n.kind() == "identifier")
        else {
            return false;
        };
        let Some(name) = self.text(object) else {
            return false;
        };
        if self.mutated(name) {
            return false;
        }
        let [definition] = self.definitions(name) else {
            return false;
        };
        // A namespace handed to another routine can have exec replaced. Only
        // its defining import and actual exec-callee reads are supported.
        if self.refs(name).iter().copied().any(|r| {
            if r == *definition {
                return false;
            }
            let Some(member) = r.parent() else {
                return true;
            };
            if member.kind() != "member_expression"
                || member.child_by_field_name("object") != Some(r)
                || member
                    .child_by_field_name("property")
                    .and_then(|n| self.text(n))
                    != Some("exec")
            {
                return true;
            }
            let mut head = member;
            for _ in 0..8 {
                let Some(parent) = head.parent() else {
                    return true;
                };
                if parent.kind() == "call_expression" {
                    return parent
                        .child_by_field_name("function")
                        .map(|f| self.callee(f))
                        != Some(member);
                }
                if !matches!(
                    parent.kind(),
                    "parenthesized_expression" | "sequence_expression"
                ) {
                    return true;
                }
                head = parent;
            }
            true
        }) {
            return false;
        }
        let Some(parent) = definition.parent() else {
            return false;
        };
        if parent.kind() == "namespace_import" {
            return self
                .import_source(parent)
                .is_some_and(|name| matches!(name, "child_process" | "node:child_process"));
        }
        self.declaration(object)
            .and_then(|d| d.child_by_field_name("value"))
            .is_some_and(|v| self.require(v))
    }
    fn import_source(&self, mut node: Node<'tree>) -> Option<&'a str> {
        while node.kind() != "import_statement" {
            node = node.parent()?;
        }
        Some(self.string(node.child_by_field_name("source")?)?.1)
    }
    fn exec(&self, n: Node<'tree>) -> Option<Command> {
        if !self.imported_exec(n.child_by_field_name("function")?) {
            return None;
        }
        let args = children(n.child_by_field_name("arguments")?);
        if args.is_empty() || args.len() > 3 || args.iter().any(|n| n.kind() == "spread_element") {
            return None;
        }
        if let Some(options) = args.get(1) {
            if options.kind() == "object" {
                for property in children(*options) {
                    if property.kind() != "pair" {
                        return None;
                    }
                    let key = property.child_by_field_name("key")?;
                    let key = if key.kind() == "property_identifier" {
                        self.text(key)?
                    } else {
                        self.string(key)?.1
                    };
                    if key == "shell" {
                        return None;
                    }
                }
            } else if !matches!(options.kind(), "arrow_function" | "function_expression") {
                return None;
            }
        }
        let (origin, text) = self.decoded(args[0], n, 0)?;
        let first = text
            .split_whitespace()
            .next()?
            .trim_matches('"')
            .rsplit(['/', '\\'])
            .next()?
            .to_ascii_lowercase();
        let file_type = if matches!(
            first.as_str(),
            "mshta"
                | "mshta.exe"
                | "rundll32"
                | "rundll32.exe"
                | "cmd"
                | "cmd.exe"
                | "powershell"
                | "powershell.exe"
        ) {
            FileType::Batch
        } else {
            FileType::Shell
        };
        Some(Command {
            offset: origin.start_byte() as u64,
            text,
            file_type,
        })
    }
}
// Collect all identifiers and mutation targets in the same bounded traversal.
fn collect_context(ast: filefacts::SourceAst<'_>) -> Option<Context<'_, '_>> {
    let mut pending = vec![(ast.tree.root_node(), false)];
    let mut context = Context {
        source: ast.source,
        nodes: vec![],
        refs: HashMap::new(),
        definitions: HashMap::new(),
        mutations: HashSet::new(),
    };
    while let Some((n, mutating)) = pending.pop() {
        if context.nodes.len() == MAX_NODES {
            return None;
        }
        // Propagate assignment-target membership during this one tree walk.
        // Every identifier inside the target is conservative mutation evidence,
        // including computed properties and destructuring, as in the old
        // byte-range check. No identifier query needs to scan the tree again.
        let target = match n.kind() {
            "assignment_expression" | "augmented_assignment_expression" => {
                n.child_by_field_name("left")
            }
            "update_expression" => n.child_by_field_name("argument"),
            "unary_expression"
                if n.child_by_field_name("operator")
                    .and_then(|n| context.text(n))
                    == Some("delete") =>
            {
                n.child_by_field_name("argument")
            }
            _ => None,
        };
        pending.extend(children(n).into_iter().map(|child| {
            (
                child,
                mutating || target.is_some_and(|target| inside(child, target)),
            )
        }));
        if matches!(n.kind(), "with_statement")
            || n.kind() == "call_expression"
                && n.child_by_field_name("function")
                    .is_some_and(|f| context.named(f, "eval"))
        {
            return None;
        }
        if matches!(
            n.kind(),
            "identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        ) && let Some(name) = context.text(n)
        {
            context.refs.entry(name).or_default().push(n);
            if mutating {
                context.mutations.insert(name);
            }
            if binding(n) {
                context.definitions.entry(name).or_default().push(n);
            }
        }
        context.nodes.push(n);
    }
    Some(context)
}

pub(crate) fn decode(ast: filefacts::SourceAst<'_>) -> Vec<Command> {
    if !matches!(ast.file_type, FileType::JavaScript | FileType::TypeScript)
        || ast.source.len() > MAX_SOURCE
        || !ast.source.contains('^')
        || !ast.source.contains("Buffer")
        || !ast.source.contains("exec")
        || ast.tree.root_node().has_error()
    {
        return vec![];
    }
    let Some(context) = collect_context(ast) else {
        return vec![];
    };
    if !context.buffer_global() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut total = 0usize;
    for call in context
        .nodes
        .iter()
        .copied()
        .filter(|n| n.kind() == "call_expression")
    {
        if out.len() == 8 {
            break;
        }
        if let Some(command) = context.exec(call) {
            total = total.saturating_add(command.text.len());
            if total > MAX_BYTES {
                break;
            }
            if !out
                .iter()
                .any(|c: &Command| c.offset == command.offset && c.text == command.text)
            {
                out.push(command);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
