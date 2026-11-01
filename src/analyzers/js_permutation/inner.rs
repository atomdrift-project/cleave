//! Reduce a proved literal-table rotation and its read-only lookup aliases.
//! This only emits source; it never invokes JavaScript, network or process APIs.
use super::{
    HashMap, MAX_FUEL, MAX_OUTPUT, Node, children, literal, nodes, number, raw,
    signature_with_globals, unwrap,
};
use std::collections::HashSet;

fn parse(source: &str) -> Option<tree_sitter::Tree> {
    let parsed = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::JavaScript)
        .cache(false)
        .open(source.as_bytes());
    let tree = parsed.source_ast()?.tree.clone();
    (!tree.root_node().has_error()).then_some(tree)
}
fn name(n: Node<'_>, source: &str) -> Option<String> {
    (n.kind() == "identifier").then(|| raw(n, source).map(str::to_owned))?
}
fn field<'a>(n: Node<'a>, key: &str) -> Option<Node<'a>> {
    n.child_by_field_name(key)
}
fn expression(n: Node<'_>) -> Option<Node<'_>> {
    children(n).first().copied().and_then(unwrap)
}
fn call(n: Node<'_>) -> Option<(Node<'_>, Vec<Node<'_>>)> {
    let n = unwrap(n)?;
    (n.kind() == "call_expression").then_some((
        unwrap(field(n, "function")?)?,
        children(field(n, "arguments")?),
    ))
}
fn edits(source: &str, mut replacements: Vec<(std::ops::Range<usize>, String)>) -> Option<String> {
    if replacements.is_empty() {
        return None;
    }
    replacements.sort_by_key(|r| r.0.start);
    let mut end = 0;
    let mut out = String::new();
    for (range, value) in replacements {
        if range.start < end {
            continue;
        }
        out.push_str(source.get(end..range.start)?);
        out.push_str(&value);
        end = range.end;
        if out.len() > MAX_OUTPUT {
            return None;
        }
    }
    out.push_str(source.get(end..)?);
    (out.len() <= MAX_OUTPUT).then_some(out)
}
fn scope(mut n: Node<'_>) -> usize {
    while let Some(p) = n.parent() {
        n = p;
        if matches!(
            n.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "generator_function"
        ) {
            return n.id();
        }
    }
    n.id()
}

/// Only complete one-return helpers, immutable and without shadowed free names.
/// Each parameter occurs once, in argument order, so evaluation is preserved.
fn inline_helpers(source: &str) -> Option<String> {
    let tree = parse(source)?;
    let all = nodes(tree.root_node())?;
    let mut functions = HashMap::new();
    let mut blocked = HashSet::new();
    let mut local_names = HashSet::new();
    for n in &all {
        match n.kind() {
            "function_declaration" => {
                let id = name(field(*n, "name")?, source)?;
                if scope(*n) == tree.root_node().id() {
                    if functions.insert(id.clone(), *n).is_some() {
                        blocked.insert(id);
                    }
                } else {
                    local_names.insert(id);
                }
            }
            "variable_declarator" => {
                if let Some(id) = field(*n, "name").and_then(|n| name(n, source)) {
                    local_names.insert(id);
                }
            }
            "assignment_expression" | "augmented_assignment_expression" | "update_expression" => {
                if let Some(id) = field(*n, "left")
                    .or_else(|| field(*n, "argument"))
                    .and_then(|n| name(n, source))
                {
                    blocked.insert(id);
                }
            }
            "identifier" if n.parent().is_some_and(|p| p.kind() == "formal_parameters") => {
                local_names.insert(name(*n, source)?);
            }
            _ => {}
        }
    }
    let mut helpers = HashMap::new();
    for (id, n) in functions {
        if blocked.contains(&id) || local_names.contains(&id) {
            continue;
        }
        let parameters = children(field(n, "parameters")?);
        let body = children(field(n, "body")?);
        if body.len() != 1 || body[0].kind() != "return_statement" {
            continue;
        }
        let Some(value) = expression(body[0]) else {
            continue;
        };
        let recipe = if parameters.is_empty()
            && value.kind() == "identifier"
            && !local_names.contains(raw(value, source)?)
        {
            Some((String::new(), raw(value, source)?.to_owned()))
        } else if parameters.len() == 1
            && value.kind() == "unary_expression"
            && field(value, "argument")
                .is_some_and(|a| raw(a, source) == raw(parameters[0], source))
        {
            let op = raw(field(value, "operator")?, source)?;
            matches!(op, "!" | "-").then(|| (op.to_owned(), String::new()))
        } else if parameters.len() == 2
            && value.kind() == "binary_expression"
            && field(value, "left").is_some_and(|a| raw(a, source) == raw(parameters[0], source))
            && field(value, "right").is_some_and(|a| raw(a, source) == raw(parameters[1], source))
        {
            let op = raw(field(value, "operator")?, source)?;
            matches!(op, "+" | "-" | "*" | "/" | "%" | "<" | "==" | "===" | "^")
                .then(|| (op.to_owned(), String::new()))
        } else {
            None
        };
        if let Some(recipe) = recipe {
            helpers.insert(id, (parameters.len(), recipe));
        }
    }
    let mut replacements = Vec::new();
    for n in all {
        if n.kind() == "parenthesized_expression" {
            let value = unwrap(n)?;
            if value.kind() == "identifier"
                || value.kind() == "string"
                    && n.parent()
                        .is_some_and(|p| p.kind() == "subscript_expression")
            {
                replacements.push((n.byte_range(), raw(value, source)?.to_owned()));
                continue;
            }
        }
        if let Some((callee, args)) = call(n).filter(|_| n.kind() == "call_expression")
            && let Some((arity, (op, getter))) =
                name(callee, source).and_then(|id| helpers.get(&id))
        {
            if args.len() != *arity {
                continue;
            }
            let value = match args.as_slice() {
                [] => format!("({getter})"),
                [a] => format!("({op}({}))", raw(*a, source)?),
                [a, b] => format!("(({}){op}({}))", raw(*a, source)?, raw(*b, source)?),
                _ => continue,
            };
            replacements.push((n.byte_range(), value));
            continue;
        }
        if n.kind() == "binary_expression" && raw(field(n, "operator")?, source) == Some("&&") {
            let left = unwrap(field(n, "left")?)?;
            if number(left, source).is_some_and(|v| v != 0) || left.kind() == "true" {
                replacements.push((
                    n.byte_range(),
                    format!("({})", raw(field(n, "right")?, source)?),
                ));
            }
        }
        if n.kind() == "unary_expression" && raw(field(n, "operator")?, source) == Some("!") {
            let arg = unwrap(field(n, "argument")?)?;
            let known = match arg.kind() {
                "true" => Some(false),
                "false" => Some(true),
                "array" if children(arg).is_empty() => Some(false),
                _ => None,
            };
            if let Some(value) = known {
                replacements.push((n.byte_range(), value.to_string()));
            }
        }
    }
    edits(source, replacements)
}

fn fingerprint(
    source: &str,
    function: Node<'_>,
    globals: &HashMap<String, String>,
    mask: Option<usize>,
) -> Option<String> {
    // Parentheses do not alter these parsed function bodies or operator trees.
    // Use the parent's signature, which normalizes parentheses but retains all
    // control flow, operators, names, and literal values outside the one mask.
    signature_with_globals(function, source, mask, globals)
}
fn template(source: &str, mask_kind: Option<&str>) -> Option<String> {
    let tree = parse(source)?;
    let f = *children(tree.root_node()).first()?;
    let mask = mask_kind.and_then(|k| {
        nodes(f)?
            .into_iter()
            .find(|n| n.kind() == k)
            .map(|n| n.id())
    });
    fingerprint(source, f, &HashMap::new(), mask)
}
fn same(
    source: &str,
    f: Node<'_>,
    globals: &HashMap<String, String>,
    text: &str,
    mask: Option<Node<'_>>,
    kind: Option<&str>,
) -> bool {
    fingerprint(source, f, globals, mask.map(|n| n.id()))
        .is_some_and(|got| template(text, kind).is_some_and(|expected| got == expected))
}

const PRODUCER: &str = "function producer(){var v={};v._=[];TABLE=MAKE_TABLE(v);return TABLE()}";
const MAKE_TABLE: &str = "function make(v){return function(){AFTER();return v._}}";
const AFTER: &str = "function after(){if(ROTATE==0){PRODUCER=\"transactionHash\"}}";
const LOOKUP: &str =
    "function lookup(a,b){var c={};c._=TABLE();return DECODER=MAKE_LOOKUP(c),DECODER(a,b)}";
const MAKE_LOOKUP: &str = "function make(c){return function(input,e){var d={};d._=input;OFFSET(d);let f=c._[d._];return f}}";
const OFFSET: &str = "function offset(d){d._=d._-0}";
const ROTATE: &str = "function rotate(a,b){const o=DECODER,c=a();while(true){try{const d=0;if(d===b){break}else{c[\"push\"](c[\"shift\"]())}}catch(e){c[\"push\"](c[\"shift\"]())}}}";

struct Proof<'a> {
    table: Vec<String>,
    offset: u64,
    rotation: usize,
    decoder: String,
    functions: HashMap<String, Node<'a>>,
    globals: HashMap<String, String>,
    rotate: Node<'a>,
    allowed_writes: HashSet<usize>,
}
fn prove<'a>(source: &str, root: Node<'a>, all: &[Node<'a>]) -> Option<Proof<'a>> {
    let mut functions = HashMap::new();
    for n in children(root)
        .into_iter()
        .filter(|n| n.kind() == "function_declaration")
    {
        if functions
            .insert(name(field(n, "name")?, source)?, n)
            .is_some()
        {
            return None;
        }
    }
    for producer in functions.values() {
        let body = children(field(*producer, "body")?);
        if body.len() != 4 {
            continue;
        }
        let Some(array) = expression(body[1])
            .and_then(|n| field(n, "right"))
            .filter(|n| n.kind() == "array")
        else {
            continue;
        };
        let table = children(array)
            .into_iter()
            .map(|n| literal(n, source))
            .collect::<Option<Vec<_>>>()?;
        if !(20..=4096).contains(&table.len()) {
            continue;
        }
        let assignment = expression(body[2])?;
        let table_alias = name(field(assignment, "left")?, source)?;
        let table_builder = name(call(field(assignment, "right")?)?.0, source)?;
        let mut globals = HashMap::from([
            (table_alias.clone(), "TABLE".into()),
            (table_builder.clone(), "MAKE_TABLE".into()),
            (name(field(*producer, "name")?, source)?, "PRODUCER".into()),
        ]);
        if !same(
            source,
            *producer,
            &globals,
            PRODUCER,
            Some(array),
            Some("array"),
        ) {
            continue;
        }

        let make_table = *functions.get(&table_builder)?;
        let after = nodes(make_table)?
            .into_iter()
            .find(|n| n.kind() == "call_expression")?;
        let after_name = name(call(after)?.0, source)?;
        globals.insert(after_name.clone(), "AFTER".into());
        if !same(source, make_table, &globals, MAKE_TABLE, None, None) {
            continue;
        }
        let after = *functions.get(&after_name)?;
        let comparison = nodes(after)?
            .into_iter()
            .find(|n| n.kind() == "binary_expression")?;
        let rotate_name = name(unwrap(field(comparison, "left")?)?, source)?;
        globals.insert(rotate_name.clone(), "ROTATE".into());
        if !same(source, after, &globals, AFTER, None, None) {
            continue;
        }

        let rotate = *functions.get(&rotate_name)?;
        let rotate_body = children(field(rotate, "body")?);
        let declarations = children(*rotate_body.first()?);
        let decoder = name(unwrap(field(*declarations.first()?, "value")?)?, source)?;
        globals.insert(decoder.clone(), "DECODER".into());
        let mut allowed_writes = HashSet::from([assignment.id()]);
        let mut lookup = None;
        for n in all
            .iter()
            .filter(|n| n.kind() == "assignment_expression" && scope(**n) == root.id())
        {
            if name(field(*n, "left")?, source).as_deref() == Some(decoder.as_str()) {
                let function = name(field(*n, "right")?, source)?;
                lookup = Some(*functions.get(&function)?);
                allowed_writes.insert(n.id());
            }
            if name(field(*n, "left")?, source).as_deref() == Some(table_alias.as_str()) {
                if name(field(*n, "right")?, source) != name(field(*producer, "name")?, source) {
                    return None;
                }
                allowed_writes.insert(n.id());
            }
        }
        let lookup = lookup?;
        let returned = children(field(lookup, "body")?).last().copied()?;
        let sequence = expression(returned)?;
        let assignment = *children(sequence).first()?;
        let lookup_builder = name(call(field(assignment, "right")?)?.0, source)?;
        globals.insert(lookup_builder.clone(), "MAKE_LOOKUP".into());
        allowed_writes.insert(assignment.id());
        if !same(source, lookup, &globals, LOOKUP, None, None) {
            return None;
        }

        let make_lookup = *functions.get(&lookup_builder)?;
        let offset_call = nodes(make_lookup)?
            .into_iter()
            .find(|n| n.kind() == "call_expression")?;
        let offset_name = name(call(offset_call)?.0, source)?;
        globals.insert(offset_name.clone(), "OFFSET".into());
        if !same(source, make_lookup, &globals, MAKE_LOOKUP, None, None) {
            return None;
        }
        let offset_fn = *functions.get(&offset_name)?;
        let offset_value = nodes(offset_fn)?
            .into_iter()
            .find(|n| n.kind() == "number")?;
        let offset = number(offset_value, source)?;
        if !same(
            source,
            offset_fn,
            &globals,
            OFFSET,
            Some(offset_value),
            Some("number"),
        ) {
            return None;
        }

        let checksum = nodes(rotate)?.into_iter().find_map(|n| {
            (n.kind() == "variable_declarator")
                .then(|| field(n, "value"))
                .flatten()
                .filter(|v| unwrap(*v).is_some_and(|v| v.kind() == "binary_expression"))
        })?;
        if !same(
            source,
            rotate,
            &globals,
            ROTATE,
            Some(checksum),
            Some("number"),
        ) {
            return None;
        }

        // Only the documented, impossible function==0/function-falsy branches
        // may assign the producer declaration. Other role mutations reject.
        for n in all.iter().filter(|n| n.kind() == "assignment_expression") {
            let Some(left) = name(field(*n, "left")?, source) else {
                continue;
            };
            if globals.get(&left).map(String::as_str) == Some("PRODUCER") {
                if scope(*n) == after.id() {
                    allowed_writes.insert(n.id());
                    continue;
                }
                let parent = n.parent()?;
                if let Some(branch) = parent
                    .parent()
                    .filter(|p| p.kind() == "statement_block")
                    .and_then(|p| p.parent())
                    .filter(|p| p.kind() == "if_statement")
                {
                    let test = unwrap(field(branch, "condition")?)?;
                    if raw(field(test, "operator")?, source) == Some("!")
                        && name(unwrap(field(test, "argument")?)?, source).as_deref()
                            == Some(left.as_str())
                        && number(field(*n, "right")?, source) == Some(0)
                    {
                        allowed_writes.insert(n.id());
                    }
                }
            }
        }
        for n in all {
            match n.kind() {
                "assignment_expression"
                | "augmented_assignment_expression"
                | "update_expression" => {
                    let left = field(*n, "left").or_else(|| field(*n, "argument"))?;
                    if let Some(id) = name(left, source) {
                        if (globals.contains_key(&id)
                            || functions.contains_key(&id)
                            || id == "parseInt")
                            && !allowed_writes.contains(&n.id())
                        {
                            return None;
                        }
                    } else if let Some(object) = field(left, "object")
                        .and_then(unwrap)
                        .and_then(|n| name(n, source))
                        && (globals.contains_key(&object)
                            || functions.contains_key(&object)
                            || object == "parseInt")
                    {
                        return None;
                    }
                }
                "identifier"
                    if n.parent().is_some_and(|p| {
                        p.kind() == "formal_parameters"
                            || p.kind() == "variable_declarator"
                                && field(p, "name").is_some_and(|v| v.id() == n.id())
                    }) && (globals.contains_key(raw(*n, source)?)
                        || functions.contains_key(raw(*n, source)?)
                        || raw(*n, source) == Some("parseInt")) =>
                {
                    return None;
                }
                _ => {}
            }
        }
        let activations: Vec<_> = all
            .iter()
            .filter_map(|n| {
                if n.kind() != "call_expression" || scope(*n) != root.id() {
                    return None;
                }
                let (f, args) = call(*n)?;
                (name(f, source).as_deref() == Some(rotate_name.as_str())
                    && args.len() == 2
                    && name(args[0], source).as_deref() == Some(table_alias.as_str()))
                .then(|| number(args[1], source))
                .flatten()
            })
            .collect();
        if activations.len() != 1 {
            return None;
        }

        // Before rotation, permit only declarations and the proved alias
        // initializers. The payload IIFE follows rotation in the same sequence.
        // Thus an unknown top-level call cannot mutate the table first.
        let producer_name = raw(field(*producer, "name")?, source)?;
        for statement in children(root) {
            match statement.kind() {
                "function_declaration" => {}
                "variable_declaration" | "lexical_declaration" => {
                    for d in children(statement) {
                        let value = field(d, "value")?;
                        if value.kind() != "array"
                            || children(value)
                                .iter()
                                .any(|v| literal(*v, source).is_none())
                        {
                            return None;
                        }
                    }
                }
                "expression_statement" => {
                    let value = expression(statement)?;
                    if allowed_writes.contains(&value.id()) {
                        continue;
                    }
                    if value.kind() != "sequence_expression" {
                        return None;
                    }
                    let terms = children(value);
                    if terms.len() != 2 {
                        return None;
                    }
                    let (f, args) = call(terms[0])?;
                    if name(f, source).as_deref() != Some(rotate_name.as_str()) || args.len() != 2 {
                        return None;
                    }
                    let (stage, _) = call(terms[1])?;
                    if stage.kind() != "arrow_function" {
                        return None;
                    }
                }
                "if_statement" => {
                    let condition = unwrap(field(statement, "condition")?)?;
                    if condition.kind() != "unary_expression"
                        || raw(field(condition, "operator")?, source) != Some("!")
                        || name(unwrap(field(condition, "argument")?)?, source).as_deref()
                            != Some(producer_name)
                        || field(statement, "alternative").is_some()
                    {
                        return None;
                    }
                    let body = children(field(statement, "consequence")?);
                    if body.len() != 1 || !allowed_writes.contains(&expression(body[0])?.id()) {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        // The actual table object may only reach the three proved functions.
        // Reject additional reads/escapes, including calls through the producer.
        for n in all.iter().filter(|n| n.kind() == "identifier") {
            if raw(*n, source) != Some(table_alias.as_str()) {
                continue;
            }
            if scope(*n) == producer.id() || scope(*n) == lookup.id() {
                continue;
            }
            let p = n.parent()?;
            if p.kind() == "assignment_expression" && allowed_writes.contains(&p.id()) {
                continue;
            }
            if p.kind() == "arguments"
                && p.parent().is_some_and(|p| {
                    call(p).is_some_and(|(f, _)| {
                        name(f, source).as_deref() == Some(rotate_name.as_str())
                    })
                })
            {
                continue;
            }
            let owner = *functions.values().find(|f| f.id() == scope(*n))?;
            let body = children(field(owner, "body")?);
            let own_name = raw(field(owner, "name")?, source)?;
            if body.len() != 1
                || body[0].kind() != "return_statement"
                || expression(body[0])?.id() != n.id()
                || all
                    .iter()
                    .filter(|n| n.kind() == "identifier" && raw(**n, source) == Some(own_name))
                    .count()
                    != 1
            {
                return None;
            }
        }
        let mut rotations = Vec::new();
        let mut fuel = MAX_FUEL;
        for shift in 0..table.len() {
            let checksum_alias = raw(field(*declarations.first()?, "name")?, source)?;
            if eval(
                checksum,
                source,
                &table,
                shift,
                offset,
                checksum_alias,
                &mut fuel,
                0,
            )
            .is_some_and(|v| v == activations[0] as f64)
            {
                rotations.push(shift);
            }
            if fuel == 0 {
                return None;
            }
        }
        if rotations.len() != 1 {
            return None;
        }
        return Some(Proof {
            table,
            offset,
            rotation: rotations[0],
            decoder,
            functions,
            globals,
            rotate,
            allowed_writes,
        });
    }
    None
}

fn eval(
    n: Node<'_>,
    source: &str,
    table: &[String],
    rotation: usize,
    offset: u64,
    alias: &str,
    fuel: &mut usize,
    depth: usize,
) -> Option<f64> {
    if depth > 128 {
        return None;
    }
    *fuel = fuel.checked_sub(1)?;
    let n = unwrap(n)?;
    match n.kind() {
        "number" => Some(number(n, source)? as f64),
        "unary_expression" if raw(field(n, "operator")?, source) == Some("-") => Some(-eval(
            field(n, "argument")?,
            source,
            table,
            rotation,
            offset,
            alias,
            fuel,
            depth + 1,
        )?),
        "binary_expression" => {
            let a = eval(
                field(n, "left")?,
                source,
                table,
                rotation,
                offset,
                alias,
                fuel,
                depth + 1,
            )?;
            let b = eval(
                field(n, "right")?,
                source,
                table,
                rotation,
                offset,
                alias,
                fuel,
                depth + 1,
            )?;
            let value = match raw(field(n, "operator")?, source)? {
                "+" => a + b,
                "-" => a - b,
                "*" => a * b,
                "/" => a / b,
                "%" => a % b,
                _ => return None,
            };
            value.is_finite().then_some(value)
        }
        "call_expression" => {
            let (f, args) = call(n)?;
            if name(f, source).as_deref() != Some("parseInt") || args.len() != 1 {
                return None;
            }
            let (f, args) = call(args[0])?;
            if name(f, source).as_deref() != Some(alias) || args.len() != 1 {
                return None;
            }
            let index = number(args[0], source)?.checked_sub(offset)? as usize;
            if index >= table.len() {
                return None;
            }
            let text = &table[(index + rotation) % table.len()];
            let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
            (!digits.is_empty())
                .then(|| digits.parse::<f64>().ok())
                .flatten()
        }
        _ => None,
    }
}

pub(super) fn reduce(source: &str) -> Option<String> {
    if source.len() > 128 * 1024 || !source.contains("parseInt") || !source.contains("shift") {
        return None;
    }
    let mut normalized = source.to_owned();
    for _ in 0..16 {
        let Some(next) = inline_helpers(&normalized) else {
            break;
        };
        normalized = next;
    }
    let tree = parse(&normalized)?;
    let all = nodes(tree.root_node())?;
    let proof = prove(&normalized, tree.root_node(), &all)?;
    // The alias reducer below never treats a lexical name as a global binding.
    let mut result = reduce_aliases(&normalized, tree.root_node(), &all, &proof)?;
    for _ in 0..4 {
        let Some(next) = inline_helpers(&result) else {
            break;
        };
        result = next;
    }
    Some(result)
}

type Key = (usize, Option<String>);
struct Bindings {
    parent: HashMap<usize, usize>,
    declared: HashMap<(usize, String), Vec<usize>>,
    root: usize,
}
impl Bindings {
    fn resolve(&self, id: &str, mut at: usize) -> Option<usize> {
        loop {
            if let Some(ids) = self.declared.get(&(at, id.to_owned())) {
                return (ids.len() == 1).then_some(ids[0]);
            }
            at = *self.parent.get(&at)?;
        }
    }
    fn key(&self, n: Node<'_>, source: &str) -> Option<Key> {
        let n = unwrap(n)?;
        if let Some(id) = name(n, source) {
            return Some((self.resolve(&id, scope(n))?, None));
        }
        if !matches!(n.kind(), "member_expression" | "subscript_expression") {
            return None;
        }
        let object = unwrap(field(n, "object")?)?;
        let id = name(object, source)?;
        let property = if n.kind() == "member_expression" {
            raw(field(n, "property")?, source)?.to_owned()
        } else {
            literal(field(n, "index")?, source)?
        };
        Some((self.resolve(&id, scope(n))?, Some(property)))
    }
}
fn reduce_aliases(
    source: &str,
    root: Node<'_>,
    all: &[Node<'_>],
    proof: &Proof<'_>,
) -> Option<String> {
    let mut bindings = Bindings {
        parent: HashMap::new(),
        declared: HashMap::new(),
        root: root.id(),
    };
    let decoder_key = (usize::MAX, None);
    bindings
        .declared
        .insert((root.id(), proof.decoder.clone()), vec![decoder_key.0]);
    for n in all {
        if matches!(
            n.kind(),
            "function_declaration" | "function_expression" | "arrow_function"
        ) {
            bindings.parent.insert(n.id(), scope(*n));
        }
        let declaration = if n.kind() == "variable_declarator" {
            field(*n, "name")
        } else if n.kind() == "identifier"
            && n.parent().is_some_and(|p| p.kind() == "formal_parameters")
        {
            Some(*n)
        } else {
            None
        };
        if let Some(id) = declaration.and_then(|n| name(n, source).map(|id| (id, n.start_byte()))) {
            bindings
                .declared
                .entry((scope(*n), id.0))
                .or_default()
                .push(id.1);
        }
    }
    let mut writes: HashMap<Key, Vec<Option<Node<'_>>>> = HashMap::new();
    let mut bad_owners = HashSet::new();
    let mut candidates = Vec::new();
    for n in all {
        let pair = match n.kind() {
            "variable_declarator" => Some((field(*n, "name")?, field(*n, "value"))),
            "assignment_expression" => Some((field(*n, "left")?, field(*n, "right"))),
            "augmented_assignment_expression" => Some((field(*n, "left")?, None)),
            "update_expression" => Some((field(*n, "argument")?, None)),
            "unary_expression" if raw(field(*n, "operator")?, source) == Some("delete") => {
                Some((field(*n, "argument")?, None))
            }
            _ => None,
        };
        if let Some((left, value)) = pair {
            if let Some(key) = bindings.key(left, source) {
                writes.entry(key.clone()).or_default().push(value);
                if let Some(value) = value {
                    candidates.push((key, value));
                }
            } else if matches!(left.kind(), "member_expression" | "subscript_expression")
                && let Some(owner) = field(left, "object").and_then(|o| bindings.key(o, source))
            {
                bad_owners.insert(owner.0);
            }
        }
    }
    // A wrapper passed or returned as a whole can be mutated through an alias.
    // Only direct member access and the declaration itself are read-only here.
    let owners: HashSet<_> = candidates
        .iter()
        .filter(|(k, _)| k.1.is_some())
        .map(|(k, _)| k.0)
        .collect();
    for n in all.iter().filter(|n| n.kind() == "identifier") {
        let Some(key) = bindings.key(*n, source) else {
            continue;
        };
        if !owners.contains(&key.0) {
            continue;
        }
        let p = n.parent()?;
        let declaration =
            p.kind() == "variable_declarator" && field(p, "name").is_some_and(|v| v.id() == n.id());
        let member = matches!(p.kind(), "member_expression" | "subscript_expression")
            && field(p, "object").is_some_and(|v| v.id() == n.id());
        if !declaration && !member {
            bad_owners.insert(key.0);
        }
    }
    let mut aliases = HashSet::from([decoder_key.clone()]);
    for _ in 0..32 {
        let before = aliases.len();
        for (key, value) in &candidates {
            if *key == decoder_key || writes.get(key).is_none_or(|v| v.len() != 1) {
                continue;
            }
            if key.1.is_some()
                && (bad_owners.contains(&key.0)
                    || writes.get(&(key.0, None)).is_none_or(|v| v.len() != 1))
            {
                continue;
            }
            if bindings
                .key(*value, source)
                .is_some_and(|v| aliases.contains(&v))
            {
                aliases.insert(key.clone());
            }
        }
        if aliases.len() == before {
            break;
        }
    }
    let mut replacements = Vec::new();
    for n in all.iter().filter(|n| n.kind() == "call_expression") {
        if n.start_byte() >= proof.rotate.start_byte() && n.end_byte() <= proof.rotate.end_byte() {
            continue;
        }
        let (f, args) = call(*n)?;
        if args.len() != 1
            || !bindings
                .key(f, source)
                .is_some_and(|v| aliases.contains(&v))
        {
            continue;
        }
        let Some(index) = number(unwrap(args[0])?, source)
            .and_then(|i| i.checked_sub(proof.offset))
            .and_then(|i| usize::try_from(i).ok())
            .filter(|i| *i < proof.table.len())
        else {
            continue;
        };
        let value = &proof.table[(index + proof.rotation) % proof.table.len()];
        replacements.push((n.byte_range(), serde_json::to_string(value).ok()?));
    }
    let _ = (
        &proof.functions,
        &proof.globals,
        &proof.allowed_writes,
        bindings.root,
    );
    edits(source, replacements)
}

#[cfg(test)]
mod tests {
    fn configuration() -> Result<String, Box<dyn std::error::Error>> {
        let source = include_str!("../../../tests/data/javascript-permutation/expected.js");
        let tree = super::parse(source).ok_or("parse source")?;
        let all = super::nodes(tree.root_node()).ok_or("nodes")?;
        super::super::literal_table(source, tree.root_node(), &all)
            .ok_or_else(|| "literal table".into())
    }
    #[test]
    fn exposes_reviewed_stage_calls_without_running_them() -> Result<(), Box<dyn std::error::Error>>
    {
        let input = include_str!("../../../tests/data/javascript-permutation/expected.js");
        let config = super::super::reduce_literal_table(input).ok_or("configuration")?;
        let mut normalized = config.clone();
        for _ in 0..16 {
            let Some(next) = super::inline_helpers(&normalized) else {
                break;
            };
            normalized = next;
        }
        let tree = super::parse(&normalized).ok_or("parse")?;
        let all = super::nodes(tree.root_node()).ok_or("nodes")?;
        assert!(
            super::prove(&normalized, tree.root_node(), &all).is_some(),
            "proof failed: {normalized}"
        );
        assert!(config.contains("[\"spawn\"]("), "{config}");
        assert!(config.contains("[\"get\"]("));
        assert!(config.contains("[\"Buffer\"][\"from\"]("));
        let renamed = configuration()?
            .replace("a0b", "lookup_index")
            .replace("a0a", "get_words")
            .replace("const o=", "const integer_lookup=")
            .replace("o(0x", "integer_lookup(0x");
        assert!(
            super::reduce(&renamed)
                .ok_or("renamed decoder")?
                .contains("[\"spawn\"](")
        );
        Ok(())
    }
    #[test]
    fn refuses_changed_recipes_and_ambiguous_table_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let input = configuration()?;
        for changed in [
            format!("{input};a0b=unknown;"),
            format!("{input};parseInt=unknown;"),
            format!("{input};mutate(a0a());"),
            input.replace(
                "try{const c=( await",
                "a0a().push('changed');try{const c=( await",
            ),
            input.replace("jso$ft$boe$_45(d._,0x11c)", "jso$ft$boe$_43(d._,0x11c)"),
            input.replace("0x938b0", "0x938b1"),
            input.replace("return v._}}", "return unknown(v._)}}"),
            serde_json::to_string(&input)?,
        ] {
            assert_ne!(changed, input, "negative control changed no source");
            assert!(
                super::reduce(&changed).is_none(),
                "accepted changed recipe: {changed}"
            );
        }
        assert!(super::reduce(&"x".repeat(128 * 1024 + 1)).is_none());
        Ok(())
    }
    #[test]
    fn tracks_read_only_aliases_in_their_own_lexical_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = configuration()?;
        for extra in ["t._=unknown;", "mutate(t);", "t=unknown;"] {
            let changed = input.replace(
                "t._= jso$ft$giden$a_48b();",
                &format!("t._= jso$ft$giden$a_48b();{extra}"),
            );
            assert_ne!(changed, input);
            let reduced =
                super::reduce(&changed).ok_or("other read-only lookups remain available")?;
            assert!(
                !reduced.contains("[\"spawn\"]("),
                "rewrote a mutated/escaped launch alias"
            );
        }
        let changed = input.replace(
            "try{const c=( await",
            "function noise(){var t={};t._=unknown;}try{const c=( await",
        );
        assert_ne!(changed, input);
        assert!(
            super::reduce(&changed)
                .ok_or("different lexical binding")?
                .contains("[\"spawn\"](")
        );
        Ok(())
    }
}
