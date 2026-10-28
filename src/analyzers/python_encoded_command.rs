//! Recover constant encoded values actually passed to an explicit POSIX shell.
//! This reduces a small expression grammar over the shared source AST; no Python
//! interpreter, import, callback, command, or network operation is evaluated.
use crate::analyzers::FileType;
use tree_sitter::Node;

const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 200_000;
const MAX_VALUE: usize = 1024 * 1024;

pub(crate) struct Command {
    pub offset: u64,
    pub text: String,
    pub chain: Vec<String>,
}

#[derive(Clone)]
enum Value {
    Text(String),
    Bytes(Vec<u8>),
    Integer(i64),
}
#[derive(Clone)]
struct Constant {
    value: Value,
    offset: usize,
    chain: Vec<String>,
}
struct Context<'a, 'tree> {
    source: &'a str,
    nodes: Vec<Node<'tree>>,
    bindings: std::collections::HashMap<String, Vec<Node<'tree>>>,
    fuel: usize,
}
fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}
fn bounded_nodes(root: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut pending = vec![root];
    let mut nodes = Vec::new();
    while let Some(node) = pending.pop() {
        if nodes.len() == MAX_NODES {
            return None;
        }
        pending.extend(children(node));
        nodes.push(node);
    }
    Some(nodes)
}
fn scope(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "function_definition" | "class_definition" | "module" | "lambda"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}
impl<'tree> Context<'_, 'tree> {
    fn text(&self, node: Node<'_>) -> Option<&str> {
        self.source.get(node.byte_range())
    }
    fn import_name(&self, node: Node<'_>) -> Option<String> {
        if node.kind() == "aliased_import" {
            self.text(node.child_by_field_name("alias")?)
                .map(str::to_owned)
        } else if node.kind() == "dotted_name" {
            Some(self.text(node)?.split('.').next()?.to_owned())
        } else {
            None
        }
    }
    // Deliberately reject duplicate bindings even in separate functions. This
    // subset does not try to resolve dynamic namespaces, global/nonlocal writes,
    // parameter shadows, destructuring, imports or assignment through attributes.
    fn index_bindings(&mut self) {
        for node in &self.nodes {
            let field = match node.kind() {
                "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
                    Some("left")
                }
                "named_expression" | "function_definition" | "class_definition" => Some("name"),
                _ => None,
            };
            let target = field.and_then(|f| node.child_by_field_name(f)).or_else(|| {
                matches!(
                    node.kind(),
                    "parameters"
                        | "lambda_parameters"
                        | "delete_statement"
                        | "as_pattern"
                        | "global_statement"
                        | "nonlocal_statement"
                )
                .then_some(*node)
            });
            let mut names = Vec::new();
            if let Some(target) = target
                && let Some(nodes) = bounded_nodes(target)
            {
                for n in nodes.iter().filter(|n| n.kind() == "identifier") {
                    if let Some(name) = self.text(*n) {
                        names.push(name.to_owned());
                    }
                }
            }
            if matches!(node.kind(), "import_statement" | "import_from_statement") {
                names.extend(
                    children(*node)
                        .into_iter()
                        .filter_map(|n| self.import_name(n)),
                );
            }
            names.sort();
            names.dedup();
            for name in names {
                self.bindings.entry(name).or_default().push(*node);
            }
        }
    }
    fn bindings(&self, name: &str) -> &[Node<'tree>] {
        self.bindings.get(name).map_or(&[], Vec::as_slice)
    }
    fn module(&self, identifier: Node<'_>, expected: &str) -> bool {
        let Some(name) = self.text(identifier) else {
            return false;
        };
        let bindings = self.bindings(name);
        let [import] = bindings else { return false };
        if self.nodes.iter().copied().any(|n| {
            n.kind() == "identifier"
                && self.text(n) == Some(name)
                && !(n.start_byte() >= import.start_byte() && n.end_byte() <= import.end_byte())
                && !n.parent().is_some_and(|attribute| {
                    attribute.kind() == "attribute"
                        && attribute.child_by_field_name("object") == Some(n)
                        && attribute
                            .child_by_field_name("attribute")
                            .and_then(|p| self.text(p))
                            .is_some_and(|method| {
                                if expected == "base64" {
                                    method == "b32decode"
                                } else {
                                    matches!(
                                        method,
                                        "run" | "Popen" | "call" | "check_call" | "check_output"
                                    )
                                }
                            })
                        && attribute.parent().is_some_and(|call| {
                            call.kind() == "call"
                                && call.child_by_field_name("function") == Some(attribute)
                        })
                })
        }) {
            return false;
        }
        import.kind() == "import_statement"
            && import.parent().is_some_and(|p| p.kind() == "module")
            && import.start_byte() < identifier.start_byte()
            && children(*import).into_iter().any(|n| {
                self.import_name(n).as_deref() == Some(name)
                    && (self.text(n) == Some(expected)
                        || n.child_by_field_name("name").and_then(|n| self.text(n))
                            == Some(expected))
            })
    }
    fn assignment(&self, reference: Node<'tree>) -> Option<Node<'tree>> {
        let bindings = self.bindings(self.text(reference)?);
        let [assignment] = bindings else { return None };
        if assignment.kind() != "assignment"
            || assignment.end_byte() >= reference.start_byte()
            || assignment.child_by_field_name("left")?.kind() != "identifier"
        {
            return None;
        }
        let statement = assignment.parent()?;
        if statement.kind() != "expression_statement" {
            return None;
        }
        if statement.parent()?.kind() == "module" {
            return assignment.child_by_field_name("right");
        }
        if scope(*assignment) != scope(reference) {
            return None;
        }
        // A local value is established by the immediately preceding statement
        // in this same block, rather than a branch elsewhere in the function.
        let mut use_statement = reference;
        while use_statement.parent()? != statement.parent()? {
            use_statement = use_statement.parent()?;
        }
        let mut next = statement.next_named_sibling()?;
        while next.kind() == "comment" {
            next = next.next_named_sibling()?;
        }
        (next == use_statement)
            .then(|| assignment.child_by_field_name("right"))
            .flatten()
    }
    fn eval(&mut self, node: Node<'tree>, depth: usize) -> Option<Constant> {
        if depth > 32 || self.fuel == 0 {
            return None;
        }
        self.fuel -= 1;
        let plain = |value| Constant {
            value,
            offset: node.start_byte(),
            chain: vec![],
        };
        match node.kind() {
            "string" => {
                let raw = self.text(node)?;
                let (raw, bytes) = raw
                    .strip_prefix('b')
                    .or_else(|| raw.strip_prefix('B'))
                    .map_or((raw, false), |s| (s, true));
                let quote = raw.as_bytes().first().copied()?;
                if !matches!(quote, b'\'' | b'"') || raw.as_bytes().last().copied()? != quote {
                    return None;
                }
                let body = raw.get(1..raw.len().checked_sub(1)?)?;
                if body.contains(['\\', '\n', '\r', '\'', '"']) || body.len() > MAX_VALUE {
                    return None;
                }
                Some(plain(if bytes {
                    Value::Bytes(body.as_bytes().to_vec())
                } else {
                    Value::Text(body.to_owned())
                }))
            }
            "integer" => Some(plain(Value::Integer(self.text(node)?.parse().ok()?))),
            "identifier" => {
                let rhs = self.assignment(node)?;
                self.eval(rhs, depth + 1)
            }
            "parenthesized_expression" => self.eval(node.named_child(0)?, depth + 1),
            "unary_operator" => {
                if self.text(node.child_by_field_name("operator")?)? != "-" {
                    return None;
                }
                let value = self.eval(node.child_by_field_name("argument")?, depth + 1)?;
                if let Value::Integer(n) = value.value {
                    Some(plain(Value::Integer(n.checked_neg()?)))
                } else {
                    None
                }
            }
            "binary_operator" => {
                let op = self.text(node.child_by_field_name("operator")?)?.to_owned();
                let mut left = self.eval(node.child_by_field_name("left")?, depth + 1)?;
                let right = self.eval(node.child_by_field_name("right")?, depth + 1)?;
                left.value = match (left.value, right.value, op.as_str()) {
                    (Value::Text(a), Value::Text(b), "+")
                        if a.len().checked_add(b.len())? <= MAX_VALUE =>
                    {
                        Value::Text(a + &b)
                    }
                    (Value::Text(a), Value::Integer(n), "*")
                        if n >= 0
                            && a.len().checked_mul(usize::try_from(n).ok()?)? <= MAX_VALUE =>
                    {
                        Value::Text(a.repeat(usize::try_from(n).ok()?))
                    }
                    (Value::Integer(a), Value::Integer(b), "%") if b > 0 => {
                        Value::Integer(a.checked_rem_euclid(b)?)
                    }
                    _ => return None,
                };
                left.chain.extend(right.chain);
                Some(left)
            }
            "call" => self.call(node, depth),
            _ => None,
        }
    }
    fn call(&mut self, node: Node<'tree>, depth: usize) -> Option<Constant> {
        let function = node.child_by_field_name("function")?;
        let args = children(node.child_by_field_name("arguments")?);
        if function.kind() == "identifier"
            && self.text(function) == Some("len")
            && self.bindings("len").is_empty()
        {
            let [arg] = args.as_slice() else { return None };
            let value = self.eval(*arg, depth + 1)?;
            let length = match value.value {
                Value::Text(s) => s.chars().count(),
                Value::Bytes(b) => b.len(),
                _ => return None,
            };
            return Some(Constant {
                value: Value::Integer(length.try_into().ok()?),
                ..value
            });
        }
        if function.kind() != "attribute" {
            return None;
        }
        let object = function.child_by_field_name("object")?;
        let name = self
            .text(function.child_by_field_name("attribute")?)?
            .to_owned();
        if object.kind() == "identifier" && self.module(object, "base64") && name == "b32decode" {
            let [arg] = args.as_slice() else { return None };
            let input = self.eval(*arg, depth + 1)?;
            let value = match input.value {
                Value::Text(s) => s,
                Value::Bytes(b) => String::from_utf8(b).ok()?,
                _ => return None,
            };
            // Preserve exact bytes. String-extraction decoders may normalize
            // UTF-16/BOM text, which would change Python's subsequent decode().
            let bytes = data_encoding::BASE32.decode(value.as_bytes()).ok()?;
            if bytes.len() > MAX_VALUE {
                return None;
            }
            let mut chain = input.chain;
            chain.push("base32".to_owned());
            return Some(Constant {
                value: Value::Bytes(bytes),
                offset: input.offset,
                chain,
            });
        }
        if name == "decode" {
            if args.len() > 1 {
                return None;
            }
            let mut ascii = false;
            if let Some(arg) = args.first() {
                let encoding = self.eval(*arg, depth + 1)?;
                if !matches!(encoding.value, Value::Text(ref s) if matches!(s.as_str(), "utf-8" | "utf8" | "ascii"))
                {
                    return None;
                }
                ascii = matches!(encoding.value, Value::Text(ref s) if s == "ascii");
            }
            let value = self.eval(object, depth + 1)?;
            let Value::Bytes(bytes) = value.value else {
                return None;
            };
            let text = String::from_utf8(bytes).ok()?;
            if ascii && !text.is_ascii() {
                return None;
            }
            return Some(Constant {
                value: Value::Text(text),
                ..value
            });
        }
        None
    }
    fn command(&mut self, node: Node<'tree>) -> Option<Command> {
        let function = node.child_by_field_name("function")?;
        if function.kind() != "attribute"
            || !matches!(
                self.text(function.child_by_field_name("attribute")?)?,
                "run" | "Popen" | "call" | "check_call" | "check_output"
            )
        {
            return None;
        }
        if !self.module(function.child_by_field_name("object")?, "subprocess") {
            return None;
        }
        let args = children(node.child_by_field_name("arguments")?);
        let first = *args.first()?;
        if first.kind() != "list" {
            return None;
        }
        let mut keywords = std::collections::HashSet::new();
        for arg in &args[1..] {
            if arg.kind() != "keyword_argument" {
                return None;
            }
            let name = self.text(arg.child_by_field_name("name")?)?;
            if !keywords.insert(name)
                || !matches!(
                    name,
                    "capture_output"
                        | "timeout"
                        | "check"
                        | "text"
                        | "encoding"
                        | "errors"
                        | "stdout"
                        | "stderr"
                        | "stdin"
                        | "cwd"
                        | "env"
                        | "input"
                        | "shell"
                )
            {
                return None;
            }
            if name == "shell" && self.text(arg.child_by_field_name("value")?) != Some("False") {
                return None;
            }
        }
        let argv = children(first);
        let [interpreter, option, argument] = argv.as_slice() else {
            return None;
        };
        if !matches!(self.eval(*interpreter, 0)?.value, Value::Text(ref s) if matches!(s.as_str(), "/bin/sh" | "/bin/bash" | "/usr/bin/bash"))
            || !matches!(self.eval(*option, 0)?.value, Value::Text(ref s) if s == "-c")
        {
            return None;
        }
        let value = self.eval(*argument, 0)?;
        let Value::Text(text) = value.value else {
            return None;
        };
        if value.chain.is_empty() || text.len() < 24 || text.contains('\0') {
            return None;
        }
        Some(Command {
            offset: value.offset as u64,
            text,
            chain: value.chain,
        })
    }
}

pub(crate) fn decode(ast: filefacts::SourceAst<'_>) -> Vec<Command> {
    if ast.file_type != FileType::Python
        || ast.source.len() > MAX_SOURCE
        || !ast.source.contains("b32decode")
        || ast.tree.root_node().has_error()
    {
        return vec![];
    }
    let Some(nodes) = bounded_nodes(ast.tree.root_node()) else {
        return vec![];
    };
    if nodes.iter().any(|n| {
        n.kind() == "wildcard_import"
            || n.kind() == "call"
                && n.child_by_field_name("function").is_some_and(|f| {
                    f.kind() == "identifier"
                        && ast.source.get(f.byte_range()).is_some_and(|name| {
                            matches!(name, "globals" | "locals" | "vars" | "exec" | "eval")
                        })
                })
    }) {
        return vec![];
    }
    let calls: Vec<_> = nodes
        .iter()
        .copied()
        .filter(|n| n.kind() == "call")
        .collect();
    let mut context = Context {
        source: ast.source,
        nodes,
        bindings: Default::default(),
        fuel: 4096,
    };
    context.index_bindings();
    let mut out = Vec::new();
    let mut size = 0usize;
    for call in calls {
        if out.len() == 32 || context.fuel == 0 {
            break;
        }
        if let Some(command) = context.command(call) {
            size = size.saturating_add(command.text.len());
            if size > 2 * MAX_VALUE {
                break;
            }
            if !out
                .iter()
                .any(|old: &Command| old.offset == command.offset && old.text == command.text)
            {
                out.push(command);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "invalid fixtures should fail the test"
    )]
    use super::*;
    const PAYLOAD: &str =
        "OBZGS3TUMYQCOJLTLRXCOIBHNBQXE3LMMVZXGIDEMVRW6ZDFOIQGG33OORZG63BAN5XGY6JH";
    const COMMAND: &str = "printf '%s\\n' 'harmless decoder control only'";
    fn fixture() -> String {
        format!(
            "import base64\nimport subprocess\nDATA = '{PAYLOAD}'\ndef helper():\n    entry = base64.b32decode(DATA + '=' * (-len(DATA) % 8))\n    subprocess.run(['/bin/sh', '-c', entry.decode()], capture_output=True, timeout=15)\n"
        )
    }
    fn run(source: &str) -> Vec<Command> {
        let ctx = crate::analysis_context::AnalysisContext::open(
            std::path::Path::new("input.py"),
            source.as_bytes(),
        );
        ctx.source_ast().map(decode).unwrap_or_default()
    }
    #[test]
    fn recovers_bound_shell_argument_and_exact_carrier_offset() {
        let source = fixture();
        let output = run(&source);
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].text, COMMAND);
        assert_eq!(
            output[0].offset as usize,
            source.find(&format!("'{PAYLOAD}'")).unwrap()
        );
        assert_eq!(output[0].chain, ["base32"]);
    }
    #[test]
    fn supports_renamed_bindings_and_standard_import_aliases() {
        let source = fixture()
            .replace("import base64", "import base64 as encoding")
            .replace("base64.b32decode", "encoding.b32decode")
            .replace("import subprocess", "import subprocess as process")
            .replace("subprocess.run", "process.check_output")
            .replace("DATA", "ENCODED_TEXT")
            .replace("entry", "result")
            .replace("'/bin/sh'", "'/bin/bash'")
            .replace("result.decode()", "result.decode('utf-8')");
        assert_eq!(run(&source)[0].text, COMMAND);
    }
    #[test]
    fn padding_uses_python_negative_modulo_and_supports_direct_bytes() {
        // An extra newline requires six '=' bytes. The reducer must implement
        // Python's positive remainder, rather than Rust's negative remainder.
        let padded = "OBZGS3TUMYQCOJLTLRXCOIBHNBQXE3LMMVZXGIDEMVRW6ZDFOIQGG33OORZG63BAN5XGY6JHBI";
        let source = fixture().replace(PAYLOAD, padded);
        assert_eq!(run(&source)[0].text, format!("{COMMAND}\n"));
        let source = format!(
            "import subprocess\nimport base64\nsubprocess.run(['/bin/sh','-c',base64.b32decode(b'{PAYLOAD}').decode()])\n"
        );
        assert_eq!(run(&source)[0].text, COMMAND);
    }
    #[test]
    fn rejects_shadowing_and_mutated_or_conditional_bindings() {
        for source in [
            fixture().replace("def helper():", "def helper(base64):"),
            fixture().replace("def helper():", "def helper(DATA):"),
            fixture().replace("def helper():", "def helper(subprocess):"),
            fixture().replace("def helper():", "def len(x):\n    return 0\ndef helper():"),
            fixture().replace(
                "    subprocess.run",
                "    entry = b'other command'\n    subprocess.run",
            ),
            fixture().replace("    entry =", "    if condition:\n        entry ="),
            fixture() + "\nDATA = 'REPLACED'\n",
            fixture() + "\nbase64.b32decode = replacement\n",
            fixture() + "\nmutate(base64)\n",
            fixture() + "\nmutate(subprocess)\n",
            fixture() + "\nfrom unreviewed_module import *\n",
            fixture().replace(
                "    subprocess.run",
                "    globals()['entry'] = b'changed'\n    subprocess.run",
            ),
        ] {
            assert!(run(&source).is_empty(), "{source}");
        }
    }
    #[test]
    fn rejects_opaque_inputs_non_shell_sinks_and_overridden_interpreters() {
        for source in [
            fixture().replace("DATA + '=' * (-len(DATA) % 8)", "read_payload()"),
            fixture().replace("subprocess.run", "print"),
            fixture().replace("'/bin/sh'", "'/bin/echo'"),
            fixture().replace("'-c'", "'--version'"),
            fixture().replace("timeout=15", "executable='/bin/echo'"),
            fixture().replace("timeout=15", "shell=True"),
            fixture().replace("timeout=15", "**options"),
            fixture().replace("entry.decode()", "other.decode()"),
            fixture().replace("entry.decode()", "entry.decode('utf-16')"),
            fixture().replace("DATA + '=' * (-len(DATA) % 8)", "DATA, casefold=True"),
            fixture().replace(PAYLOAD, "INVALID BASE32 VALUE CANNOT BE RECOVERED"),
        ] {
            assert!(run(&source).is_empty(), "{source}");
        }
    }
    #[test]
    fn rejects_large_repetition_syntax_errors_and_recursive_values() {
        for source in [
            fixture().replace("(-len(DATA) % 8)", "999999999999"),
            fixture().replace("DATA + '=' * (-len(DATA) % 8)", "DATA + '=' * -2"),
            fixture().replace(&format!("'{PAYLOAD}'"), "DATA"),
            fixture() + "\ninvalid (\n",
            format!("{}\n{}", "#".repeat(MAX_SOURCE), fixture()),
        ] {
            assert!(run(&source).is_empty());
        }
    }
    #[test]
    fn preserves_exact_bytes_without_utf16_or_bom_normalization() {
        let wide: Vec<u8> = COMMAND.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let wide = data_encoding::BASE32.encode(&wide);
        assert!(run(&fixture().replace(PAYLOAD, &wide)).is_empty());
        let with_bom = format!("\u{feff}{COMMAND}");
        let encoded = data_encoding::BASE32.encode(with_bom.as_bytes());
        assert_eq!(run(&fixture().replace(PAYLOAD, &encoded))[0].text, with_bom);
        let source = fixture()
            .replace(PAYLOAD, &encoded)
            .replace("entry.decode()", "entry.decode('ascii')");
        assert!(run(&source).is_empty());
        let source = source
            .replace("import base64\n", "import base64\nENCODING = 'ascii'\n")
            .replace("decode('ascii')", "decode(ENCODING)");
        assert!(run(&source).is_empty());
    }
    #[test]
    fn unified_analysis_exposes_decoded_shell_layer_with_exact_hash() {
        let source = fixture();
        let analyzer =
            super::super::unified::UnifiedSourceAnalyzer::for_file_type(&FileType::Python)
                .unwrap()
                .with_engine(crate::Engine::empty());
        let report = analyzer.analyze_source(std::path::Path::new("bound.py"), &source);
        let expected = crate::analyzers::utils::calculate_sha256(COMMAND.as_bytes());
        let child = report
            .files
            .iter()
            .find(|f| f.sha256 == expected)
            .expect("decoded command layer");
        assert_eq!(child.file_type, "shell");
        assert_eq!(
            child.encoding.as_deref(),
            Some(["base32".to_owned()].as_slice())
        );
        assert!(child.path.contains(&format!(
            "@{}",
            source.find(&format!("'{PAYLOAD}'")).unwrap()
        )));
    }
}
