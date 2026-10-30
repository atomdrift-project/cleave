//! Literal-only reconstruction of permutation/Function bootstrap recipes.
//!
//! This is not a JavaScript runtime. Only a completely recognized local
//! permutation function, its constructor, literal strings and the recognized
//! dictionary decoder have values. Unknown calls/writes end reconstruction.
use std::collections::HashMap;
use tree_sitter::Node;

const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_NODES: usize = 1_000_000;
const MAX_FUEL: usize = 8_000_000;
const MAX_PARTS: usize = 65_536;

const PERMUTATION: &str = r#"function perm(l){var y=0;var i=l.length;var x=[];for(var v=0;v<i;v++){x[v]=l.charAt(v);}for(var v=0;v<i;v++){var h=y*(v+179)+(y%18929);var w=y*(v+658)+(y%13606);var s=h%i;var f=w%i;var j=x[s];x[s]=x[f];x[f]=j;y=(h+w)%5578712;}return x.join("");}"#;
const DICTIONARY: &str = r#"function unpack(){var n=10,w=42,l=70;var u="abcdefghijklmnopqrstuvwxyz";var o=[80,70,66,86,60,85,71,74,87,72,75,88,81,90,76,94,82,89,79,65];var m=[];for(var e=0;e<o.length;e++)m[o[e]]=e+1;var i=[];n+=23;w+=51;l+=26;for(var t=0;t<arguments.length;t++){var h=arguments[t].split(" ");for(var j=h.length-1;j>=0;j--){var d=null;var b=h[j];var q=null;var p=0;var y=b.length;var r;for(var g=0;g<y;g++){var z=b.charCodeAt(g);var c=m[z];if(c){d=(c-1)*w+b.charCodeAt(g+1)-n;r=g;g++;}else if(z==l){d=w*(o.length-n+b.charCodeAt(g+1))+b.charCodeAt(g+2)-n;r=g;g+=2;}else{continue;}if(q==null)q=[];if(r>p)q.push(b.substring(p,r));q.push(h[d+1]);p=g+1;}if(q!=null){if(p<y)q.push(b.substring(p));h[j]=q.join("");}}i.push(h[0]);}var v=i.join("");var a=[32,42,39,92,10,96].concat(o);var s=String.fromCharCode(46);for(var e=0;e<a.length;e++)v=v.split(s+u.charAt(e)).join(String.fromCharCode(a[e]));return v.split(s+"!").join(s);}"#;

const WRAPPED_PERMUTATION: &str = r#"function _$af26623(j,jso$setrpl$m){var m={},f={},v={},o={},a={},c={},x={};m._= jso$setrpl$m;var z=j.length;f._= [];;for(var d=0;LESS(d,z);d++){f._[d]= j.charAt(d)};for(var d=0;LESS(d,z);d++){v._= ADD(m._* (ADD(d,179)),(MOD(m._,18929)));;o._= ADD(m._* (ADD(d,658)),(MOD(m._,13606)));;a._= MOD(v._,z);;c._= MOD(o._,z);;x._= f._[a._];;COPY(a,f,c);SET(c,f,x);ADVANCE(m,v,o)};var n=STRING().fromCharCode(127);var s='';var i='%';var u='#1';var h='%';var b='#0';var p='#';return f._.join(s).split(i).join(n).split(u).join(h).split(b).join(p).split(n)}"#;

#[derive(Clone)]
enum Value {
    Text(String),
    Number(u64),
    Permutation(u64),
    Constructor,
    Dictionary,
    Program(String),
}

fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = n.walk();
    n.named_children(&mut cursor)
        .filter(|n| !matches!(n.kind(), "comment" | "empty_statement"))
        .collect()
}
fn nodes(root: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut pending = vec![root];
    let mut result = Vec::new();
    while let Some(node) = pending.pop() {
        if result.len() >= MAX_NODES {
            return None;
        }
        pending.extend(children(node).into_iter().rev());
        result.push(node);
    }
    Some(result)
}
fn raw<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}
fn literal(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let s = raw(node, source)?;
    Some(filefacts::decode_source_escapes_for_type(
        s.get(1..s.len().checked_sub(1)?)?,
        filefacts::FileType::JavaScript,
    ))
}
fn number(node: Node<'_>, source: &str) -> Option<u64> {
    if node.kind() != "number" {
        return None;
    }
    let text = raw(node, source)?;
    let result = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        text.parse().ok()?
    };
    (result <= (1u64 << 53)).then_some(result)
}
fn unwrap(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "parenthesized_expression" {
        node = *children(node).first()?;
    }
    Some(node)
}

/// Alpha-normalized syntax, with operators and literal values retained.
/// This compares complete function bodies, not a collection of regex clues.
fn signature_with_globals(
    function: Node<'_>,
    source: &str,
    seed: Option<usize>,
    globals: &HashMap<String, String>,
) -> Option<String> {
    let mut locals = HashMap::<String, usize>::new();
    if let Some(name) = function.child_by_field_name("name") {
        locals.insert(raw(name, source)?.to_owned(), 0);
    }
    for node in nodes(function)? {
        let declaration = if node.kind() == "variable_declarator" {
            node.child_by_field_name("name")
        } else {
            None
        };
        let parameter = node
            .parent()
            .is_some_and(|p| p.kind() == "formal_parameters");
        let binding = declaration.or_else(|| parameter.then_some(node));
        if let Some(binding) = binding {
            if binding.kind() != "identifier" {
                return None;
            }
            let name = raw(binding, source)?.to_owned();
            let next = locals.len();
            locals.entry(name).or_insert(next);
        }
    }
    fn visit(
        n: Node<'_>,
        source: &str,
        locals: &HashMap<String, usize>,
        seed: Option<usize>,
        output: &mut String,
        depth: usize,
        globals: &HashMap<String, String>,
    ) -> Option<()> {
        if depth > 256 {
            return None;
        }
        if matches!(n.kind(), "comment" | "empty_statement") {
            return Some(());
        }
        output.push('(');
        output.push_str(n.kind());
        if Some(n.id()) == seed {
            output.push_str(":SEED");
        } else if n.kind() == "identifier" {
            let name = raw(n, source)?;
            if let Some(index) = locals.get(name) {
                output.push_str(&format!(":local{index}"));
            } else {
                output.push(':');
                output.push_str(globals.get(name).map(String::as_str).unwrap_or(name));
            }
        } else if n.kind() == "property_identifier" {
            output.push(':');
            output.push_str(raw(n, source)?);
        } else if n.kind() == "number" {
            output.push_str(&format!(":{}", number(n, source)?));
        } else if n.kind() == "string" {
            output.push(':');
            output.push_str(&serde_json::to_string(&literal(n, source)?).ok()?);
        } else {
            if let Some(operator) = n.child_by_field_name("operator") {
                output.push(':');
                output.push_str(raw(operator, source)?);
            } else if matches!(n.kind(), "unary_expression" | "update_expression") {
                let mut cursor = n.walk();
                for child in n.children(&mut cursor).filter(|c| !c.is_named()) {
                    output.push(':');
                    output.push_str(raw(child, source)?);
                }
            }
            for child in children(n) {
                visit(child, source, locals, seed, output, depth + 1, globals)?;
            }
        }
        output.push(')');
        Some(())
    }
    let mut result = String::new();
    visit(function, source, &locals, seed, &mut result, 0, globals)?;
    Some(result)
}
fn signature(function: Node<'_>, source: &str, seed: Option<usize>) -> Option<String> {
    signature_with_globals(function, source, seed, &HashMap::new())
}
fn seed<'tree>(function: Node<'tree>, source: &str) -> Option<(Node<'tree>, u64)> {
    let body = function.child_by_field_name("body")?;
    let declaration = *children(body).first()?;
    let binding = *children(declaration).first()?;
    let value = binding.child_by_field_name("value")?;
    let value_number = number(value, source)?;
    (value_number < 5_578_712).then_some((value, value_number))
}
fn template_signature(source: &str, with_seed: bool) -> Option<String> {
    let parsed = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::JavaScript)
        .cache(false)
        .open(source.as_bytes());
    let tree = &parsed.source_ast()?.tree;
    let function = *children(tree.root_node()).first()?;
    let seed_id = if with_seed {
        Some(seed(function, source)?.0.id())
    } else {
        None
    };
    signature(function, source, seed_id)
}

fn permute(input: &str, mut seed: u64) -> Option<String> {
    if !input.is_ascii() || input.is_empty() || input.len() > MAX_PARTS {
        return None;
    }
    let mut bytes = input.as_bytes().to_vec();
    let size = bytes.len() as u64;
    for index in 0..size {
        // The bounds above keep every operation below JS's exact-integer limit.
        let first = seed.checked_mul(index + 179)?.checked_add(seed % 18_929)?;
        let second = seed.checked_mul(index + 658)?.checked_add(seed % 13_606)?;
        bytes.swap((first % size) as usize, (second % size) as usize);
        seed = first.checked_add(second)? % 5_578_712;
    }
    String::from_utf8(bytes).ok()
}

fn dictionary(input: &str) -> Option<String> {
    const CODES: [u8; 20] = [
        80, 70, 66, 86, 60, 85, 71, 74, 87, 72, 75, 88, 81, 90, 76, 94, 82, 89, 79, 65,
    ];
    if !input.is_ascii() || input.len() > MAX_OUTPUT {
        return None;
    }
    let mut words: Vec<String> = input.split(' ').map(str::to_owned).collect();
    if words.len() > MAX_PARTS {
        return None;
    }
    let mut fuel = MAX_FUEL;
    for index in (0..words.len()).rev() {
        let word = words.get(index)?.as_bytes();
        let mut output = String::new();
        let mut at = 0;
        while at < word.len() {
            fuel = fuel.checked_sub(1)?;
            let code = word[at];
            let (reference, consumed) =
                if let Some(position) = CODES.iter().position(|c| *c == code) {
                    let digit = i64::from(*word.get(at + 1)?) - 33;
                    (Some((position as i64) * 93 + digit + 1), 2)
                } else if code == 96 {
                    let first = i64::from(*word.get(at + 1)?);
                    let second = i64::from(*word.get(at + 2)?);
                    (Some(93 * (20 - 33 + first) + second - 33 + 1), 3)
                } else {
                    (None, 1)
                };
            if let Some(reference) = reference {
                let reference = usize::try_from(reference).ok()?;
                // Generated dictionaries point rightwards to already-expanded
                // entries. Cycles, missing entries and dangling digits decline.
                if reference <= index {
                    return None;
                }
                let piece = words.get(reference)?;
                fuel = fuel.checked_sub(piece.len())?;
                output.push_str(piece);
            } else {
                output.push(char::from(code));
            }
            if output.len() > MAX_OUTPUT {
                return None;
            }
            at += consumed;
        }
        words[index] = output;
    }
    let mut result = words.into_iter().next()?;
    let alphabet = b"abcdefghijklmnopqrstuvwxyz";
    for (index, code) in [32, 42, 39, 92, 10, 96]
        .into_iter()
        .chain(CODES)
        .enumerate()
    {
        let marker = format!(".{}", char::from(*alphabet.get(index)?));
        result = result.replace(&marker, &char::from(code).to_string());
        if result.len() > MAX_OUTPUT {
            return None;
        }
    }
    Some(result.replace(".!", "."))
}

fn evaluate(
    node: Node<'_>,
    source: &str,
    env: &HashMap<String, Value>,
    dictionary_signature: &str,
    fuel: &mut usize,
    depth: usize,
) -> Option<Value> {
    if depth > 128 {
        return None;
    }
    *fuel = fuel.checked_sub(1)?;
    let node = unwrap(node)?;
    match node.kind() {
        "string" => Some(Value::Text(literal(node, source)?)),
        "number" => Some(Value::Number(number(node, source)?)),
        "identifier" => env.get(raw(node, source)?).cloned(),
        "binary_expression" => {
            let Value::Number(left) = evaluate(
                node.child_by_field_name("left")?,
                source,
                env,
                dictionary_signature,
                fuel,
                depth + 1,
            )?
            else {
                return None;
            };
            let Value::Number(right) = evaluate(
                node.child_by_field_name("right")?,
                source,
                env,
                dictionary_signature,
                fuel,
                depth + 1,
            )?
            else {
                return None;
            };
            let result = match raw(node.child_by_field_name("operator")?, source)? {
                "+" => left.checked_add(right)?,
                "-" => left.checked_sub(right)?,
                "*" => left.checked_mul(right)?,
                _ => return None,
            };
            (result <= (1u64 << 53)).then_some(Value::Number(result))
        }
        "subscript_expression" | "member_expression" => {
            let object = evaluate(
                node.child_by_field_name("object")?,
                source,
                env,
                dictionary_signature,
                fuel,
                depth + 1,
            )?;
            let property = if node.kind() == "subscript_expression" {
                let Value::Text(property) = evaluate(
                    node.child_by_field_name("index")?,
                    source,
                    env,
                    dictionary_signature,
                    fuel,
                    depth + 1,
                )?
                else {
                    return None;
                };
                property
            } else {
                raw(node.child_by_field_name("property")?, source)?.to_owned()
            };
            (matches!(object, Value::Permutation(_)) && property == "constructor")
                .then_some(Value::Constructor)
        }
        "call_expression" => {
            let function = unwrap(node.child_by_field_name("function")?)?;
            let args = children(node.child_by_field_name("arguments")?);
            if function.kind() == "member_expression" {
                let property = raw(function.child_by_field_name("property")?, source)?;
                if matches!(property, "substr" | "substring" | "slice") {
                    let Value::Text(value) = evaluate(
                        function.child_by_field_name("object")?,
                        source,
                        env,
                        dictionary_signature,
                        fuel,
                        depth + 1,
                    )?
                    else {
                        return None;
                    };
                    let Value::Number(start) = evaluate(
                        *args.first()?,
                        source,
                        env,
                        dictionary_signature,
                        fuel,
                        depth + 1,
                    )?
                    else {
                        return None;
                    };
                    let Value::Number(end) = evaluate(
                        *args.get(1)?,
                        source,
                        env,
                        dictionary_signature,
                        fuel,
                        depth + 1,
                    )?
                    else {
                        return None;
                    };
                    if start != 0 || args.len() != 2 || !value.is_ascii() {
                        return None;
                    }
                    return Some(Value::Text(
                        value[..usize::try_from(end).ok()?.min(value.len())].to_owned(),
                    ));
                }
            }
            let function = evaluate(function, source, env, dictionary_signature, fuel, depth + 1)?;
            let values = args
                .into_iter()
                .map(|arg| evaluate(arg, source, env, dictionary_signature, fuel, depth + 1))
                .collect::<Option<Vec<_>>>()?;
            match (function, values.as_slice()) {
                (Value::Permutation(seed), [Value::Text(input)]) => {
                    Some(Value::Text(permute(input, seed)?))
                }
                (Value::Dictionary, [Value::Text(input)]) => Some(Value::Text(dictionary(input)?)),
                (Value::Constructor, [Value::Text(parameters), Value::Text(body)])
                    if parameters.is_empty() && body.len() <= MAX_OUTPUT =>
                {
                    let wrapped = format!("function decoded(){{{body}}}");
                    let is_dictionary = template_signature(&wrapped, false).as_deref()
                        == Some(dictionary_signature);
                    Some(if is_dictionary {
                        Value::Dictionary
                    } else {
                        Value::Program(body.clone())
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn recipe(
    body: Node<'_>,
    source: &str,
    permutation_signature: &str,
    dictionary_signature: &str,
) -> Option<Vec<(usize, String)>> {
    let mut env = HashMap::new();
    let mut fuel = MAX_FUEL;
    let statements = children(body);
    for statement in &statements {
        if statement.kind() != "function_declaration" {
            continue;
        }
        let Some((seed_node, value)) = seed(*statement, source) else {
            continue;
        };
        if signature(*statement, source, Some(seed_node.id())).as_deref()
            == Some(permutation_signature)
        {
            let name = raw(statement.child_by_field_name("name")?, source)?.to_owned();
            if env.insert(name, Value::Permutation(value)).is_some() {
                return None;
            }
        }
    }
    if env.is_empty() {
        return None;
    }
    let mut output = Vec::new();
    for statement in statements {
        match statement.kind() {
            "function_declaration" => {}
            "variable_declaration" | "lexical_declaration" => {
                for declaration in children(statement) {
                    if declaration.kind() != "variable_declarator" {
                        return None;
                    }
                    let name = declaration.child_by_field_name("name")?;
                    if name.kind() != "identifier" {
                        return None;
                    }
                    let name = raw(name, source)?.to_owned();
                    let value = evaluate(
                        declaration.child_by_field_name("value")?,
                        source,
                        &env,
                        dictionary_signature,
                        &mut fuel,
                        0,
                    )?;
                    if env.insert(name, value).is_some() {
                        return None;
                    }
                }
            }
            "expression_statement" | "return_statement" => {
                let Some(expression) = children(statement).first().copied() else {
                    continue;
                };
                if expression.kind() != "call_expression" {
                    if statement.kind() == "return_statement" {
                        break;
                    }
                    return None;
                }
                let function = evaluate(
                    expression.child_by_field_name("function")?,
                    source,
                    &env,
                    dictionary_signature,
                    &mut fuel,
                    0,
                )?;
                let Value::Program(program) = function else {
                    return None;
                };
                // Arguments must themselves be inert constants too.
                for arg in children(expression.child_by_field_name("arguments")?) {
                    evaluate(arg, source, &env, dictionary_signature, &mut fuel, 0)?;
                }
                output.push((expression.start_byte(), program));
                if statement.kind() == "return_statement" {
                    break;
                }
            }
            _ => return None,
        }
    }
    Some(output)
}

/// Recognize the second permutation's complete body and every helper it calls.
/// Only its literal invocation is reduced; none of the surrounding program runs.
fn literal_table(source: &str, root: Node<'_>, all: &[Node<'_>]) -> Option<String> {
    let mut functions = HashMap::new();
    let mut blocked = std::collections::HashSet::new();
    for node in children(root) {
        if node.kind() == "function_declaration" {
            let name = raw(node.child_by_field_name("name")?, source)?.to_owned();
            if functions.insert(name.clone(), node).is_some() {
                blocked.insert(name);
            }
        }
    }
    for node in all {
        let binding = match node.kind() {
            "assignment_expression" => node.child_by_field_name("left"),
            "update_expression" => node.child_by_field_name("argument"),
            "variable_declarator" => node.child_by_field_name("name"),
            "identifier"
                if node
                    .parent()
                    .is_some_and(|p| p.kind() == "formal_parameters") =>
            {
                Some(*node)
            }
            _ => None,
        };
        if let Some(binding) = binding.filter(|b| b.kind() == "identifier") {
            blocked.insert(raw(binding, source)?.to_owned());
        }
    }
    let helpers = [
        ("ADD", "function add(a,b){return a+b}"),
        ("MOD", "function modulo(a,b){return a%b}"),
        ("LESS", "function less(a,b){return a<b}"),
        ("STRING", "function string(){return String}"),
        ("COPY", "function copy(a,f,c){f._[a._]=f._[c._]}"),
        ("SET", "function set(c,f,x){f._[c._]=x._}"),
        (
            "ADVANCE",
            "function advance(m,v,o){m._=MOD((ADD(v._,o._)),5578712)}",
        ),
    ];
    let mut globals = HashMap::new();
    for (label, template) in helpers {
        if label == "STRING" && blocked.contains("String") {
            continue;
        }
        let expected = template_signature(template, false)?;
        for (name, function) in &functions {
            if !blocked.contains(name)
                && signature_with_globals(*function, source, None, &globals).as_deref()
                    == Some(expected.as_str())
            {
                globals.insert(name.clone(), label.to_owned());
            }
        }
    }
    let expected = template_signature(WRAPPED_PERMUTATION, false)?;
    let transforms: std::collections::HashSet<_> = functions
        .iter()
        .filter_map(|(name, function)| {
            (!blocked.contains(name)
                && signature_with_globals(*function, source, None, &globals).as_deref()
                    == Some(expected.as_str()))
            .then_some(name.as_str())
        })
        .collect();
    if transforms.is_empty() {
        return None;
    }
    let mut replacements = Vec::new();
    for node in all.iter().filter(|n| n.kind() == "call_expression") {
        let callee = unwrap(node.child_by_field_name("function")?)?;
        if callee.kind() != "identifier" || !transforms.contains(raw(callee, source)?) {
            continue;
        }
        let arguments = children(node.child_by_field_name("arguments")?);
        if arguments.len() != 2 {
            continue;
        }
        let Some(input) = literal(arguments[0], source) else {
            continue;
        };
        let Some(seed) = number(arguments[1], source).filter(|s| *s < 5_578_712) else {
            continue;
        };
        let text = permute(&input, seed)?
            .replace('%', "\u{7f}")
            .replace("#1", "%")
            .replace("#0", "#");
        let parts: Vec<_> = text.split('\u{7f}').collect();
        replacements.push((node.byte_range(), serde_json::to_string(&parts).ok()?));
    }
    if replacements.is_empty() {
        return None;
    }
    let mut result = source.to_owned();
    for (range, text) in replacements.into_iter().rev() {
        result.replace_range(range, &text);
    }
    if result.len() > MAX_OUTPUT {
        return None;
    }
    Some(super::js_decimal_packer::constant_tables(&result).unwrap_or(result))
}

fn reduce_literal_table(source: &str) -> Option<String> {
    if !source.contains("5578712") || !source.contains("charAt") {
        return None;
    }
    let parsed = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::JavaScript)
        .cache(false)
        .open(source.as_bytes());
    let root = parsed.source_ast()?.tree.root_node();
    if root.has_error() {
        return None;
    }
    literal_table(source, root, &nodes(root)?)
}

pub(crate) fn decode(source: &str) -> Vec<(usize, String)> {
    if source.len() > MAX_SOURCE || !source.contains("5578712") || !source.contains("charAt") {
        return Vec::new();
    }
    let parsed = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::JavaScript)
        .cache(false)
        .open(source.as_bytes());
    let Some(ast) = parsed.source_ast() else {
        return Vec::new();
    };
    if ast.tree.root_node().has_error() {
        return Vec::new();
    }
    let Some(all) = nodes(ast.tree.root_node()) else {
        return Vec::new();
    };
    let Some(permutation_signature) = template_signature(PERMUTATION, true) else {
        return Vec::new();
    };
    let Some(dictionary_signature) = template_signature(DICTIONARY, false) else {
        return Vec::new();
    };
    let mut output = Vec::new();
    let mut budget = MAX_OUTPUT;
    if let Some(table) = literal_table(source, ast.tree.root_node(), &all) {
        budget = budget.saturating_sub(table.len());
        output.push((0, table));
    }
    for node in all
        .into_iter()
        .filter(|n| n.kind() == "statement_block")
        .take(4096)
    {
        let Some(results) = recipe(node, source, &permutation_signature, &dictionary_signature)
        else {
            continue;
        };
        for (offset, text) in results {
            // Embedded layers intentionally disable further generic extraction.
            // Finish the recognized literal table here so the recovered layer
            // includes its real configuration on the first analysis pass.
            let text = reduce_literal_table(&text).unwrap_or(text);
            let Some(left) = budget.checked_sub(text.len()) else {
                return output;
            };
            budget = left;
            output.push((offset, text));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_permutation(text: &str, mut seed: u64) -> String {
        let mut swaps = Vec::new();
        let n = text.len() as u64;
        for index in 0..n {
            let a = seed * (index + 179) + seed % 18_929;
            let b = seed * (index + 658) + seed % 13_606;
            swaps.push(((a % n) as usize, (b % n) as usize));
            seed = (a + b) % 5_578_712;
        }
        let mut bytes = text.as_bytes().to_vec();
        for (a, b) in swaps.into_iter().rev() {
            bytes.swap(a, b);
        }
        String::from_utf8(bytes).expect("ASCII encoder")
    }
    fn encode_dictionary_literal(text: &str) -> String {
        let codes = [
            32, 42, 39, 92, 10, 96, 80, 70, 66, 86, 60, 85, 71, 74, 87, 72, 75, 88, 81, 90, 76, 94,
            82, 89, 79, 65,
        ];
        let mut output = String::new();
        for byte in text.bytes() {
            if byte == b'.' {
                output.push_str(".!");
            } else if let Some(index) = codes.iter().position(|c| *c == byte) {
                output.push('.');
                output.push(char::from(b'a' + index as u8));
            } else {
                output.push(char::from(byte));
            }
        }
        output
    }
    fn encoded(program: &str, seed: u64) -> String {
        let permutation = PERMUTATION.replacen("y=0", &format!("y={seed}"), 1);
        let dictionary = DICTIONARY
            .strip_prefix("function unpack(){")
            .and_then(|s| s.strip_suffix('}'))
            .expect("dictionary body");
        let key = encode_permutation("constructorabcdefghijklmnopqrstuvwxyz", seed);
        let body = encode_permutation(dictionary, seed);
        let data = encode_permutation(&encode_dictionary_literal(program), seed);
        format!(
            "(function(){{var empty=\"\",width=11;{permutation}var key=perm({key}).substr(0,width);var body={body};var factory=perm[key];var parameters=\"\";var other=factory;var decoder=factory(parameters,perm(body));var text=decoder(perm({data}));var stage=other(empty,text);stage(7);return 0;}})();",
            key = serde_json::to_string(&key).expect("key"),
            body = serde_json::to_string(&body).expect("body"),
            data = serde_json::to_string(&data).expect("data")
        )
    }
    #[test]
    fn recovers_program_without_executing_it() {
        let program = "require('child_process').exec('never execute this test');";
        for seed in [17, 2461180] {
            let source = encoded(program, seed);
            assert_eq!(
                decode(&source)
                    .iter()
                    .map(|r| r.1.as_str())
                    .collect::<Vec<_>>(),
                [program]
            );
            let renamed = source
                .replace("perm", "different_transform")
                .replace("factory", "compiler_alias");
            assert_eq!(decode(&renamed)[0].1, program);
        }
    }
    #[test]
    fn rejects_inert_modified_and_unknown_recipes() {
        let source = encoded("console.log('harmless');", 17);
        for negative in [
            serde_json::to_string(&source).expect("quoted source"),
            format!("/* {source} */"),
            source.replace("stage(7);", ""),
            source.replace("var other=factory;", "var other=unknown;"),
            source.replace(
                "return x.join",
                "fetch('https://example.invalid');return x.join",
            ),
            source.replace("stage(7);", "stage=unknown;stage(7);"),
            source.replace("var key=perm", "perm.constructor=unknown;var key=perm"),
        ] {
            assert!(decode(&negative).is_empty(), "{negative}");
        }
    }
    #[test]
    fn reconstructs_reviewed_loader_exactly() {
        let source = include_str!("../../tests/data/javascript-permutation/loader.js");
        let expected = include_str!("../../tests/data/javascript-permutation/expected.js");
        let parsed = filefacts::OpenOptions::new()
            .file_type(filefacts::FileType::JavaScript)
            .cache(false)
            .open(source.as_bytes());
        let all = nodes(parsed.source_ast().expect("source AST").tree.root_node()).expect("nodes");
        let p = template_signature(PERMUTATION, true).expect("permutation");
        let d = template_signature(DICTIONARY, false).expect("dictionary");
        let recovered: Vec<_> = all
            .into_iter()
            .filter(|n| n.kind() == "statement_block")
            .filter_map(|n| recipe(n, source, &p, &d))
            .flatten()
            .collect();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].1, expected);
        let result = decode(source);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, decode(expected)[0].1);
    }
    #[test]
    fn reconstructs_only_proven_literal_configuration_table() {
        let source = include_str!("../../tests/data/javascript-permutation/expected.js");
        let result = decode(source);
        assert_eq!(result.len(), 1);
        assert!(
            result[0]
                .1
                .contains("https://api.binplorer.com/getAddressHistory/")
        );
        assert!(result[0].1.contains("$v$5;kmc$ldm*5SA"));
        for negative in [
            serde_json::to_string(source).expect("quoted source"),
            source.replace("return a+ b", "return fetch(a)+b"),
            format!("{source};String=unknown;"),
            source.replace("return String", "return unknown"),
        ] {
            assert!(decode(&negative).is_empty());
        }
    }
    #[test]
    fn dictionary_and_permutation_are_bounded() {
        assert!(dictionary("P").is_none());
        assert!(dictionary("P!").is_none());
        assert!(permute("non-ASCII \u{20ac}", 17).is_none());
        assert!(permute(&"a".repeat(MAX_PARTS + 1), 17).is_none());
        assert!(decode(&"x".repeat(MAX_SOURCE + 1)).is_empty());
    }
}
