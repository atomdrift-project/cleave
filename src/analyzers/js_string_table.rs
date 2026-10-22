//! Bounded reduction of checksum-rotated JavaScript literal tables.
//!
//! This recognizes the table decoder, proves its rotation checksum, and reduces
//! only constant calls through side-effect-free numeric proxies. It never runs
//! JavaScript, follows imports, or substitutes dynamic call arguments. The host
//! remains analyzed separately; the result is an additional decoded source view.
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use std::{cell::Cell, collections::HashMap};
use tree_sitter::Node;

const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_TABLE: usize = 4096;
const MAX_NODES: usize = 1_000_000;
const MAX_FUEL: usize = 2_000_000;
type Span = (usize, usize);

#[derive(Clone)]
enum Value {
    Number(f64),
    String(String),
}
#[derive(Clone)]
struct Val {
    value: Value,
    decoded: bool,
}
impl Val {
    fn number(n: f64) -> Self {
        Self {
            value: Value::Number(n),
            decoded: false,
        }
    }
    fn string(s: String) -> Self {
        Self {
            value: Value::String(s),
            decoded: false,
        }
    }
    fn numeric(&self) -> f64 {
        match &self.value {
            Value::Number(n) => *n,
            Value::String(s) => s.trim().parse().unwrap_or(f64::NAN),
        }
    }
    fn text(&self) -> String {
        match &self.value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
        }
    }
}
struct Table {
    binding: usize,
    visible: Span,
    function: Span,
    name: String,
    scope: Span,
    strings: Vec<String>,
}
struct Object {
    visible: Span,
    declaration: usize,
    name: String,
    scope: Span,
    fields: HashMap<String, Val>,
    forwards: HashMap<String, usize>,
}
struct Proxy<'a> {
    binding: usize,
    visible: Span,
    name: String,
    scope: Span,
    parameters: Vec<String>,
    result: Node<'a>,
}
struct Decoder {
    binding: usize,
    visible: Span,
    function: Span,
    name: String,
    table: usize,
    offset: f64,
    rc4: bool,
}
struct Context<'a> {
    source: &'a str,
    references: HashMap<String, Vec<Node<'a>>>,
    bindings: HashMap<String, Vec<Binding>>,
    tables: Vec<Table>,
    objects: Vec<Object>,
    proxies: Vec<Proxy<'a>>,
    decoders: Vec<Decoder>,
    active: usize,
    rotation: usize,
    fuel: Cell<usize>,
}
fn text<'a>(n: Node<'_>, s: &'a str) -> Option<&'a str> {
    s.get(n.byte_range())
}
fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut c = n.walk();
    n.named_children(&mut c)
        .filter(|n| n.kind() != "comment")
        .collect()
}
fn scope_function(n: Node<'_>) -> bool {
    matches!(
        n.kind(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
    )
}
fn scope(mut n: Node<'_>) -> Span {
    while let Some(p) = n.parent() {
        n = p;
        if scope_function(n) || n.kind() == "program" {
            return (n.start_byte(), n.end_byte());
        }
    }
    (0, usize::MAX)
}
fn covers(span: Span, at: usize) -> bool {
    span.0 <= at && at < span.1
}
fn raw_string(n: Node<'_>, source: &str) -> Option<String> {
    if !matches!(n.kind(), "string" | "string_literal") {
        return None;
    }
    let s = text(n, source)?;
    let first = s.as_bytes().first()?;
    if !matches!(first, b'\'' | b'"') || s.as_bytes().last()? != first {
        return None;
    }
    Some(filefacts::decode_source_escapes_for_type(
        &s[1..s.len() - 1],
        filefacts::FileType::JavaScript,
    ))
}
fn member<'a>(n: Node<'a>, source: &str) -> Option<(Node<'a>, String)> {
    if n.kind() == "member_expression" {
        Some((
            n.child_by_field_name("object")?,
            text(n.child_by_field_name("property")?, source)?.to_owned(),
        ))
    } else if n.kind() == "subscript_expression" {
        Some((
            n.child_by_field_name("object")?,
            raw_string(n.child_by_field_name("index")?, source)?,
        ))
    } else {
        None
    }
}
// Numeric proxy constants must not escape or be assigned through aliases.
fn immutable_object(
    object: &Object,
    references: &HashMap<String, Vec<Node<'_>>>,
    source: &str,
) -> bool {
    references
        .get(&object.name)
        .into_iter()
        .flatten()
        .filter(|n| {
            covers(object.scope, n.start_byte())
                && matches!(n.kind(), "identifier" | "shorthand_property_identifier")
                && text(**n, source) == Some(object.name.as_str())
        })
        .all(|n| {
            if shadowed_parameter(*n, object, source) {
                return true;
            }
            if n.start_byte() == object.declaration {
                return true;
            }
            let Some(parent) = n.parent() else {
                return false;
            };
            if !matches!(parent.kind(), "member_expression" | "subscript_expression")
                || parent
                    .child_by_field_name("object")
                    .is_none_or(|o| o.byte_range() != n.byte_range())
            {
                return false;
            }
            let mut ancestor = parent;
            while let Some(next) = ancestor.parent() {
                if next.start_byte() < object.scope.0 || next.end_byte() > object.scope.1 {
                    break;
                }
                let target = if matches!(
                    next.kind(),
                    "assignment_expression" | "augmented_assignment_expression"
                ) {
                    next.child_by_field_name("left")
                } else if next.kind() == "update_expression"
                    || (next.kind() == "unary_expression"
                        && next
                            .child_by_field_name("operator")
                            .and_then(|n| text(n, source))
                            == Some("delete"))
                {
                    next.child_by_field_name("argument")
                        .or_else(|| next.named_child(0))
                } else {
                    None
                };
                if target.is_some_and(|mut target| {
                    while matches!(
                        target.kind(),
                        "member_expression" | "subscript_expression" | "parenthesized_expression"
                    ) {
                        let Some(child) = target.child_by_field_name("object").or_else(|| {
                            (target.kind() == "parenthesized_expression")
                                .then(|| target.named_child(0))
                                .flatten()
                        }) else {
                            break;
                        };
                        target = child;
                    }
                    text(target, source) == Some(object.name.as_str())
                }) {
                    return false;
                }
                if next.kind().ends_with("statement") {
                    break;
                }
                ancestor = next;
            }
            true
        })
}

fn shadowed_parameter(mut n: Node<'_>, object: &Object, source: &str) -> bool {
    while let Some(p) = n.parent() {
        n = p;
        if (n.start_byte(), n.end_byte()) == object.scope {
            return false;
        }
        if (is_function(n) || n.kind() == "arrow_function")
            && n.child_by_field_name("parameters").is_some_and(|p| {
                children(p)
                    .iter()
                    .any(|n| text(*n, source) == Some(object.name.as_str()))
            })
        {
            return true;
        }
    }
    false
}
fn forward_arity(n: Node<'_>, source: &str) -> Option<usize> {
    if text(n, source)?.trim_start().starts_with("async") {
        return None;
    }
    if !is_function(n) && n.kind() != "arrow_function" {
        return None;
    }
    let parameters = children(n.child_by_field_name("parameters")?);
    if parameters.is_empty() || parameters.iter().any(|p| p.kind() != "identifier") {
        return None;
    }
    let names: std::collections::HashSet<_> =
        parameters.iter().filter_map(|n| text(*n, source)).collect();
    if names.len() != parameters.len() {
        return None;
    }
    let body = children(n.child_by_field_name("body")?);
    if body.len() != 1 || body[0].kind() != "return_statement" {
        return None;
    }
    let call = body[0].named_child(0)?;
    if call.kind() != "call_expression"
        || call
            .child_by_field_name("function")
            .and_then(|n| text(n, source))
            != text(parameters[0], source)
    {
        return None;
    }
    let arguments = children(call.child_by_field_name("arguments")?);
    if arguments.len() + 1 != parameters.len()
        || !arguments
            .iter()
            .zip(&parameters[1..])
            .all(|(a, p)| a.kind() == "identifier" && text(*a, source) == text(*p, source))
    {
        return None;
    }
    Some(parameters.len())
}
fn add_literal_objects<'a>(ctx: &mut Context<'a>, all: &[Node<'a>]) {
    for &n in all {
        let Some((name, value)) = declaration(n) else {
            continue;
        };
        if value.kind() != "object"
            || ctx
                .objects
                .iter()
                .any(|o| o.declaration == name.start_byte())
        {
            continue;
        }
        let Some(name_text) = text(name, ctx.source) else {
            continue;
        };
        let mut object = Object {
            visible: visible_scope(n),
            declaration: name.start_byte(),
            name: name_text.to_owned(),
            scope: scope(n),
            fields: HashMap::new(),
            forwards: HashMap::new(),
        };
        for pair in children(value) {
            let (Some(key), Some(value)) = (
                pair.child_by_field_name("key"),
                pair.child_by_field_name("value"),
            ) else {
                continue;
            };
            let key =
                raw_string(key, ctx.source).or_else(|| text(key, ctx.source).map(str::to_owned));
            let Some(key) = key else {
                continue;
            };
            object.fields.remove(&key);
            object.forwards.remove(&key);
            if key == "__proto__" {
                continue;
            }
            if let Some(arity) = forward_arity(value, ctx.source) {
                object.forwards.insert(key, arity);
            } else if let Some(value) = ctx.eval(value, &HashMap::new(), 0) {
                object.fields.insert(key, value);
            }
        }
        if (!object.fields.is_empty() || !object.forwards.is_empty())
            && immutable_object(&object, &ctx.references, ctx.source)
        {
            ctx.objects.push(object);
        }
        if ctx.objects.len() > 4096 {
            break;
        }
    }
}
fn render_reduced<'a>(ctx: &Context<'a>, n: Node<'a>, depth: usize) -> Option<String> {
    if depth > 48 {
        return None;
    }
    if let Some(value) = ctx.eval(n, &HashMap::new(), 0)
        && (value.decoded || matches!(n.kind(), "member_expression" | "subscript_expression"))
        && let Value::String(value) = value.value
    {
        return serde_json::to_string(&value).ok();
    }
    if n.kind() == "call_expression" {
        let function = n.child_by_field_name("function")?;
        let (receiver, key) = ctx.member_value(function, &HashMap::new(), 0)?;
        let object = ctx
            .objects
            .iter()
            .filter(|o| {
                Some(o.name.as_str()) == text(receiver, ctx.source)
                    && covers(o.visible, n.start_byte())
                    && ctx.resolves(&o.name, n.start_byte(), o.declaration)
            })
            .min_by_key(|o| o.visible.1 - o.visible.0)?;
        let arity = *object.forwards.get(&key)?;
        let arguments = children(n.child_by_field_name("arguments")?);
        if arguments.len() != arity
            || arguments[0].kind() != "identifier"
            || text(arguments[0], ctx.source) == Some("eval")
            || arguments.iter().any(|n| n.kind() == "spread_element")
        {
            return None;
        }
        let mut out = text(arguments[0], ctx.source)?.to_owned();
        out.push('(');
        for (i, &arg) in arguments[1..].iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&render_children(ctx, arg, depth + 1)?);
        }
        out.push(')');
        return Some(out);
    }
    None
}
fn render_children<'a>(ctx: &Context<'a>, n: Node<'a>, depth: usize) -> Option<String> {
    if depth > 48 {
        return Some(text(n, ctx.source)?.to_owned());
    }
    if let Some(value) = render_reduced(ctx, n, depth + 1) {
        return Some(value);
    }
    let mut out = text(n, ctx.source)?.to_owned();
    for child in children(n).into_iter().rev() {
        if let Some(value) = render_children(ctx, child, depth + 1)
            && Some(value.as_str()) != text(child, ctx.source)
        {
            out.replace_range(
                child.start_byte() - n.start_byte()..child.end_byte() - n.start_byte(),
                &value,
            );
        }
    }
    Some(out)
}

fn unwrap(mut n: Node<'_>) -> Node<'_> {
    loop {
        if matches!(
            n.kind(),
            "parenthesized_expression" | "expression_statement" | "else_clause" | "statement_block"
        ) && children(n).len() == 1
        {
            n = children(n)[0];
        } else {
            return n;
        }
    }
}
fn table_producer(f: Node<'_>, binding: Node<'_>, source: &str) -> bool {
    let Some(name) = f.child_by_field_name("name").and_then(|n| text(n, source)) else {
        return false;
    };
    let Some(body) = f.child_by_field_name("body").map(children) else {
        return false;
    };
    if body.len() != 3 {
        return false;
    }
    if children(body[0]).len() != 1
        || children(body[0])[0]
            .child_by_field_name("name")
            .is_none_or(|n| n.byte_range() != binding.byte_range())
    {
        return false;
    }
    let assigned = unwrap(body[1]);
    if assigned.kind() != "assignment_expression"
        || assigned
            .child_by_field_name("left")
            .and_then(|n| text(n, source))
            != Some(name)
    {
        return false;
    }
    let Some(cache) = assigned.child_by_field_name("right") else {
        return false;
    };
    if !is_function(cache) {
        return false;
    }
    let Some(cache_body) = cache.child_by_field_name("body").map(children) else {
        return false;
    };
    if cache_body.len() != 1
        || cache_body[0].kind() != "return_statement"
        || cache_body[0].named_child(0).and_then(|n| text(n, source)) != text(binding, source)
    {
        return false;
    }
    if body[2].kind() != "return_statement" {
        return false;
    }
    let Some(call) = body[2].named_child(0) else {
        return false;
    };
    call.kind() == "call_expression"
        && call
            .child_by_field_name("function")
            .and_then(|n| text(n, source))
            == Some(name)
        && call
            .child_by_field_name("arguments")
            .is_some_and(|n| children(n).is_empty())
}
fn rotate_call(n: Node<'_>, array: &str, source: &str) -> bool {
    let n = unwrap(n);
    if n.kind() != "call_expression" {
        return false;
    }
    let Some((object, key)) = n
        .child_by_field_name("function")
        .and_then(|n| member(n, source))
    else {
        return false;
    };
    if text(object, source) != Some(array) || key != "push" {
        return false;
    }
    let Some(args) = n.child_by_field_name("arguments").map(children) else {
        return false;
    };
    if args.len() != 1 {
        return false;
    }
    let inner = args[0];
    inner.kind() == "call_expression"
        && inner
            .child_by_field_name("function")
            .and_then(|n| member(n, source))
            .is_some_and(|(object, key)| text(object, source) == Some(array) && key == "shift")
        && inner
            .child_by_field_name("arguments")
            .is_some_and(|n| children(n).is_empty())
}
fn rotation_shape(
    ctx: &Context<'_>,
    function: Node<'_>,
    condition: Node<'_>,
    checksum: Node<'_>,
) -> bool {
    let source = ctx.source;
    let Some(parameters) = function.child_by_field_name("parameters").map(children) else {
        return false;
    };
    let Some(body) = function.child_by_field_name("body").map(children) else {
        return false;
    };
    let mut array = None;
    let mut loop_node = None;
    for statement in body {
        match statement.kind() {
            "function_declaration" => {
                if !ctx.proxies.iter().any(|p| {
                    p.scope == (function.start_byte(), function.end_byte())
                        && Some(p.name.as_str())
                            == statement
                                .child_by_field_name("name")
                                .and_then(|n| text(n, source))
                }) {
                    return false;
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                for var in children(statement) {
                    let Some((name, value)) = declaration(var) else {
                        return false;
                    };
                    if value.kind() == "object"
                        && ctx
                            .objects
                            .iter()
                            .any(|o| o.declaration == name.start_byte())
                    {
                        continue;
                    }
                    if value.kind() == "call_expression"
                        && value
                            .child_by_field_name("function")
                            .and_then(|n| text(n, source))
                            == text(parameters[0], source)
                        && value
                            .child_by_field_name("arguments")
                            .is_some_and(|n| children(n).is_empty())
                        && array.is_none()
                    {
                        array = text(name, source);
                    } else {
                        return false;
                    }
                }
            }
            "while_statement" => {
                if loop_node.replace(statement).is_some() {
                    return false;
                }
            }
            _ => return false,
        }
    }
    let (Some(array), Some(loop_node)) = (array, loop_node) else {
        return false;
    };
    let Some(test) = loop_node
        .child_by_field_name("condition")
        .and_then(|n| text(n, source))
    else {
        return false;
    };
    if !matches!(
        test.chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .as_str(),
        "(!![])" | "!![]"
    ) {
        return false;
    }
    let Some(loop_body) = loop_node.child_by_field_name("body").map(children) else {
        return false;
    };
    if loop_body.len() != 1 || loop_body[0].kind() != "try_statement" {
        return false;
    }
    let trial = loop_body[0];
    let Some(try_body) = trial.child_by_field_name("body").map(children) else {
        return false;
    };
    if try_body.len() != 2
        || children(try_body[0]).len() != 1
        || children(try_body[0])[0]
            .child_by_field_name("value")
            .is_none_or(|n| n.byte_range() != checksum.byte_range())
    {
        return false;
    }
    let branch = try_body[1];
    if branch.kind() != "if_statement"
        || branch
            .child_by_field_name("condition")
            .is_none_or(|n| unwrap(n).byte_range() != condition.byte_range())
        || branch
            .child_by_field_name("consequence")
            .is_none_or(|n| unwrap(n).kind() != "break_statement")
        || branch
            .child_by_field_name("alternative")
            .is_none_or(|n| !rotate_call(n, array, source))
    {
        return false;
    }
    let Some(catch) = children(trial)
        .into_iter()
        .find(|n| n.kind() == "catch_clause")
    else {
        return false;
    };
    let Some(catch_body) = catch.child_by_field_name("body").map(children) else {
        return false;
    };
    catch_body.len() == 1 && rotate_call(catch_body[0], array, source)
}
#[derive(Clone, Copy)]
enum ReductionRegion {
    Whole,
    ImmediatePrefix {
        owner: Span,
        after: usize,
        before: usize,
    },
}
impl ReductionRegion {
    fn allows(self, node: Node<'_>) -> bool {
        match self {
            Self::Whole => true,
            Self::ImmediatePrefix {
                owner,
                after,
                before,
            } => node.start_byte() >= after && node.end_byte() <= before && scope(node) == owner,
        }
    }
}
fn table_reference_region(
    ctx: &Context<'_>,
    all: &[Node<'_>],
    rotator: Span,
) -> Option<ReductionRegion> {
    let d = &ctx.decoders[ctx.active];
    let table = &ctx.tables[d.table];
    if !all
        .iter()
        .filter(|n| {
            n.kind() == "identifier"
                && covers(d.visible, n.start_byte())
                && text(**n, ctx.source) == Some(d.name.as_str())
        })
        .all(|n| {
            covers(d.function, n.start_byte())
                || n.parent().is_some_and(|p| {
                    p.kind() == "call_expression"
                        && p.child_by_field_name("function")
                            .is_some_and(|f| f.byte_range() == n.byte_range())
                })
        })
    {
        return None;
    }
    let unsafe_refs: Vec<_> = all
        .iter()
        .copied()
        .filter(|n| {
            n.kind() == "identifier"
                && covers(table.scope, n.start_byte())
                && text(*n, ctx.source) == Some(table.name.as_str())
        })
        .filter(|n| {
            // A simple parameter declaration is not an array escape. A direct body
            // function declaration with the same name shadows it; normal binding
            // resolution still controls every reduced call in the body.
            let owner_parameter = n.parent().is_some_and(|p| {
                p.kind() == "formal_parameters"
                    && p.parent()
                        .is_some_and(|f| (f.start_byte(), f.end_byte()) == table.scope)
            });
            !owner_parameter
                && !covers(table.function, n.start_byte())
                && !covers(d.function, n.start_byte())
                && !covers(rotator, n.start_byte())
        })
        .collect();
    if unsafe_refs.is_empty() {
        return Some(ReductionRegion::Whole);
    }
    // A terminal return may pass the producer to unknown/deferred code. The
    // array is then no longer proved immutable for nested callbacks. Recover
    // only immediate owner expressions after the direct checksum rotation and
    // before that return. Every deferred function body remains untouched.
    let owner = all
        .iter()
        .copied()
        .find(|n| is_function(*n) && (n.start_byte(), n.end_byte()) == table.scope)?;
    let body = owner.child_by_field_name("body")?;
    let returned = children(body)
        .into_iter()
        .filter(|n| n.kind() != "comment")
        .last()?;
    if returned.kind() != "return_statement"
        || !unsafe_refs
            .iter()
            .all(|n| returned.start_byte() <= n.start_byte() && n.end_byte() <= returned.end_byte())
    {
        return None;
    }
    let mut rotation_call = all
        .iter()
        .copied()
        .find(|n| (n.start_byte(), n.end_byte()) == rotator && n.kind() == "call_expression")?;
    while let Some(parent) = rotation_call
        .parent()
        .filter(|n| n.kind() == "parenthesized_expression")
    {
        rotation_call = parent;
    }
    let statement = rotation_call.parent()?;
    if statement.kind() != "expression_statement"
        || statement.parent() != Some(body)
        || rotator.1 > returned.start_byte()
    {
        return None;
    }
    Some(ReductionRegion::ImmediatePrefix {
        owner: table.scope,
        after: rotator.1,
        before: returned.start_byte(),
    })
}

#[derive(Clone)]
struct Binding {
    scope: Span,
    declaration: usize,
}
fn visible_scope(mut node: Node<'_>) -> Span {
    let is_var = node.kind() == "variable_declarator"
        && node
            .parent()
            .is_some_and(|p| p.kind() == "variable_declaration");
    while let Some(parent) = node.parent() {
        node = parent;
        if (is_var && scope_function(node))
            || (!is_var && matches!(node.kind(), "statement_block" | "program"))
        {
            return (node.start_byte(), node.end_byte());
        }
    }
    (0, usize::MAX)
}
fn identifier_writes(
    all: &[Node<'_>],
    name: &str,
    visible: Span,
    source: &str,
    allowed: Option<Span>,
) -> bool {
    all.iter().any(|n| {
        covers(visible, n.start_byte())
            && !allowed.is_some_and(|s| covers(s, n.start_byte()))
            && matches!(
                n.kind(),
                "assignment_expression" | "augmented_assignment_expression" | "update_expression"
            )
            && n.child_by_field_name("left")
                .or_else(|| n.child_by_field_name("argument"))
                .and_then(|n| text(n, source))
                == Some(name)
    })
}

fn js_i32(value: f64) -> i32 {
    if !value.is_finite() || value == 0.0 {
        0
    } else {
        (value.trunc().rem_euclid(4294967296.0) as u32) as i32
    }
}
fn parse_number(s: &str) -> Option<f64> {
    let s = s.replace('_', "");
    for (p, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(v) = s.strip_prefix(p) {
            return u64::from_str_radix(v, radix).ok().map(|n| n as f64);
        }
    }
    s.parse().ok()
}
fn parse_int(s: &str) -> Option<f64> {
    if !s.is_ascii() {
        return None;
    }
    let s = s.trim_start();
    let (sign, s) = if let Some(s) = s.strip_prefix('-') {
        (-1., s)
    } else {
        (1., s.strip_prefix('+').unwrap_or(s))
    };
    let (radix, s) = if s.starts_with("0x") || s.starts_with("0X") {
        (16, &s[2..])
    } else {
        (10, s)
    };
    let digits: String = s.chars().take_while(|c| c.is_digit(radix)).collect();
    u64::from_str_radix(&digits, radix)
        .ok()
        .map(|v| sign * v as f64)
}
fn base64_text(encoded: &str) -> Option<String> {
    let mut mapped = Vec::with_capacity(encoded.len());
    const STANDARD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for c in encoded.bytes().take_while(|b| *b != b'=') {
        mapped.push(*STANDARD.get(ALPHABET.as_bytes().iter().position(|b| *b == c)?)?);
    }
    String::from_utf8(STANDARD_NO_PAD.decode(mapped).ok()?).ok()
}
fn rc4(cipher: &str, key: &str) -> Option<String> {
    let key: Vec<u16> = key.encode_utf16().collect();
    if key.is_empty() || key.len() > 256 {
        return None;
    }
    let mut state: Vec<usize> = (0..256).collect();
    let mut j = 0;
    for i in 0..256 {
        j = (j + state[i] + usize::from(key[i % key.len()])) % 256;
        state.swap(i, j);
    }
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    for c in cipher.encode_utf16() {
        i = (i + 1) % 256;
        j = (j + state[i]) % 256;
        state.swap(i, j);
        out.push(c ^ state[(state[i] + state[j]) % 256] as u16);
    }
    String::from_utf16(&out).ok()
}
impl<'a> Context<'a> {
    fn resolves(&self, name: &str, at: usize, declaration: usize) -> bool {
        let Some(bindings) = self.bindings.get(name) else {
            return false;
        };
        let selected: Vec<_> = bindings.iter().filter(|b| covers(b.scope, at)).collect();
        let Some(width) = selected.iter().map(|b| b.scope.1 - b.scope.0).min() else {
            return false;
        };
        selected
            .iter()
            .filter(|b| b.scope.1 - b.scope.0 == width)
            .all(|b| b.declaration == declaration)
    }

    fn member_value(
        &self,
        n: Node<'a>,
        env: &HashMap<String, Val>,
        depth: usize,
    ) -> Option<(Node<'a>, String)> {
        if let Some(value) = member(n, self.source) {
            return Some(value);
        }
        if n.kind() == "subscript_expression" {
            let key = self.eval(n.child_by_field_name("index")?, env, depth + 1)?;
            if let Value::String(key) = key.value {
                return Some((n.child_by_field_name("object")?, key));
            }
        }
        None
    }

    fn eval(&self, n: Node<'a>, env: &HashMap<String, Val>, depth: usize) -> Option<Val> {
        if depth > 48 || self.fuel.get() == 0 {
            return None;
        }
        self.fuel.set(self.fuel.get() - 1);
        let raw = text(n, self.source)?;
        match n.kind() {
            "number" => Some(Val::number(parse_number(raw)?)),
            "string" | "string_literal" => Some(Val::string(raw_string(n, self.source)?)),
            "identifier" => env.get(raw).cloned(),
            "parenthesized_expression" => self.eval(n.named_child(0)?, env, depth + 1),
            "unary_expression" => {
                let arg = self.eval(n.child_by_field_name("argument")?, env, depth + 1)?;
                let op = text(n.child_by_field_name("operator")?, self.source)?;
                let v = match op {
                    "-" => -arg.numeric(),
                    "+" => arg.numeric(),
                    "~" => f64::from(!js_i32(arg.numeric())),
                    _ => return None,
                };
                Some(Val {
                    value: Value::Number(v),
                    decoded: arg.decoded,
                })
            }
            "binary_expression" => {
                let a = self.eval(n.child_by_field_name("left")?, env, depth + 1)?;
                let b = self.eval(n.child_by_field_name("right")?, env, depth + 1)?;
                let op = text(n.child_by_field_name("operator")?, self.source)?;
                let decoded = a.decoded || b.decoded;
                if op == "+"
                    && (matches!(a.value, Value::String(_)) || matches!(b.value, Value::String(_)))
                {
                    let s = a.text() + &b.text();
                    return (s.len() <= MAX_SOURCE).then_some(Val {
                        value: Value::String(s),
                        decoded,
                    });
                }
                let (x, y) = (a.numeric(), b.numeric());
                let v = match op {
                    "+" => x + y,
                    "-" => x - y,
                    "*" => x * y,
                    "/" => x / y,
                    "%" => x % y,
                    "^" => f64::from(js_i32(x) ^ js_i32(y)),
                    "&" => f64::from(js_i32(x) & js_i32(y)),
                    "|" => f64::from(js_i32(x) | js_i32(y)),
                    "<<" => f64::from(js_i32(x).wrapping_shl((js_i32(y) as u32) & 31)),
                    ">>" => f64::from(js_i32(x).wrapping_shr((js_i32(y) as u32) & 31)),
                    _ => return None,
                };
                Some(Val {
                    value: Value::Number(v),
                    decoded,
                })
            }
            "member_expression" | "subscript_expression" => {
                let (object, key) = self.member_value(n, env, depth + 1)?;
                let name = text(object, self.source)?;
                if env.contains_key(name) {
                    return None;
                }
                self.objects
                    .iter()
                    .filter(|o| {
                        o.name == name
                            && covers(o.visible, n.start_byte())
                            && self.resolves(name, n.start_byte(), o.declaration)
                    })
                    .min_by_key(|o| o.visible.1 - o.visible.0)?
                    .fields
                    .get(&key)
                    .cloned()
            }
            "call_expression" => {
                let function = n.child_by_field_name("function")?;
                if function.kind() != "identifier" {
                    return None;
                }
                let name = text(function, self.source)?;
                if env.contains_key(name) {
                    return None;
                }
                let mut args = Vec::new();
                for a in children(n.child_by_field_name("arguments")?) {
                    args.push(self.eval(a, env, depth + 1)?);
                }
                let d = self.decoders.get(self.active);
                if d.is_some_and(|d| {
                    d.name == name
                        && covers(d.visible, n.start_byte())
                        && self.resolves(name, n.start_byte(), d.binding)
                }) {
                    let d = d?;
                    let index = args.first()?.numeric() - d.offset;
                    if !index.is_finite() || index < 0. || index.fract() != 0. {
                        return None;
                    }
                    let table = self.tables.get(d.table)?;
                    let index = index as usize;
                    if index >= table.strings.len() {
                        return None;
                    }
                    let cipher = &table.strings[(index + self.rotation) % table.strings.len()];
                    let value = if d.rc4 {
                        rc4(cipher, &args.get(1)?.text())?
                    } else {
                        cipher.clone()
                    };
                    return Some(Val {
                        value: Value::String(value),
                        decoded: true,
                    });
                }
                if name == "parseInt" {
                    if args.len() != 1
                        || self
                            .bindings
                            .get(name)
                            .is_some_and(|bs| bs.iter().any(|b| covers(b.scope, n.start_byte())))
                    {
                        return None;
                    }
                    let a = args.first()?;
                    return Some(Val {
                        value: Value::Number(parse_int(&a.text())?),
                        decoded: a.decoded,
                    });
                }
                let p = self
                    .proxies
                    .iter()
                    .filter(|p| {
                        p.name == name
                            && covers(p.visible, n.start_byte())
                            && self.resolves(name, n.start_byte(), p.binding)
                    })
                    .min_by_key(|p| p.visible.1 - p.visible.0)?;
                if args.len() != p.parameters.len() {
                    return None;
                }
                let env = p.parameters.iter().cloned().zip(args).collect();
                self.eval(p.result, &env, depth + 1)
            }
            _ => None,
        }
    }
}
fn nodes(root: Node<'_>) -> Option<Vec<Node<'_>>> {
    let mut out = Vec::new();
    let mut cursor = root.walk();
    loop {
        out.push(cursor.node());
        if out.len() > MAX_NODES {
            return None;
        }
        if cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            continue;
        }
        loop {
            if !cursor.goto_parent() {
                return Some(out);
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }
}
fn declaration(n: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    if n.kind() != "variable_declarator" {
        return None;
    }
    Some((
        n.child_by_field_name("name")?,
        n.child_by_field_name("value")?,
    ))
}
fn is_function(n: Node<'_>) -> bool {
    matches!(n.kind(), "function_declaration" | "function_expression")
}
fn function_name(n: Node<'_>, source: &str) -> Option<String> {
    Some(text(n.child_by_field_name("name")?, source)?.to_owned())
}

/// Produce an additional source view when a recognized decoder's rotation is proved.
pub(crate) fn decode(ast: filefacts::SourceAst<'_>) -> Option<String> {
    let source = ast.source;
    if source.len() > MAX_SOURCE
        || !source.contains(ALPHABET)
        || !source.contains("parseInt")
        || !source.contains("decodeURIComponent")
    {
        return None;
    }
    let all = nodes(ast.tree.root_node())?;
    let mut ctx = Context {
        source,
        references: HashMap::new(),
        bindings: HashMap::new(),
        tables: Vec::new(),
        objects: Vec::new(),
        proxies: Vec::new(),
        decoders: Vec::new(),
        active: 0,
        rotation: 0,
        fuel: Cell::new(MAX_FUEL),
    };
    for &n in &all {
        if matches!(
            n.kind(),
            "identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        ) && let Some(name) = text(n, source)
        {
            ctx.references.entry(name.to_owned()).or_default().push(n);
        }
    }
    for &n in &all {
        if matches!(n.kind(), "variable_declarator" | "function_declaration")
            && let Some(name) = n.child_by_field_name("name")
        {
            for binding in nodes(name)?.iter().filter(|b| {
                matches!(
                    b.kind(),
                    "identifier" | "shorthand_property_identifier_pattern"
                )
            }) {
                if let Some(name) = text(*binding, source) {
                    ctx.bindings
                        .entry(name.to_owned())
                        .or_default()
                        .push(Binding {
                            scope: visible_scope(n),
                            declaration: binding.start_byte(),
                        });
                }
            }
        }
        if scope_function(n)
            && let Some(parameters) = n
                .child_by_field_name("parameters")
                .or_else(|| n.child_by_field_name("parameter"))
        {
            for binding in nodes(parameters)?.iter().filter(|b| {
                matches!(
                    b.kind(),
                    "identifier" | "shorthand_property_identifier_pattern"
                )
            }) {
                if let Some(name) = text(*binding, source) {
                    ctx.bindings
                        .entry(name.to_owned())
                        .or_default()
                        .push(Binding {
                            scope: (n.start_byte(), n.end_byte()),
                            declaration: binding.start_byte(),
                        });
                }
            }
        }
    }
    for &n in &all {
        if let Some((name, value)) = declaration(n) {
            if value.kind() == "array" {
                let entries = children(value);
                if !(20..=MAX_TABLE).contains(&entries.len()) {
                    continue;
                }
                let Some(mut f) = n.parent() else {
                    continue;
                };
                while !is_function(f) {
                    let Some(p) = f.parent() else {
                        break;
                    };
                    f = p;
                }
                let Some(fn_name) = function_name(f, source) else {
                    continue;
                };
                if !table_producer(f, name, source) {
                    continue;
                }
                let decoded: Option<Vec<_>> = entries
                    .iter()
                    .map(|e| base64_text(&raw_string(*e, source)?))
                    .collect();
                if let Some(strings) = decoded
                    && strings.iter().map(String::len).sum::<usize>() <= MAX_SOURCE
                {
                    ctx.tables.push(Table {
                        binding: f.child_by_field_name("name")?.start_byte(),
                        visible: visible_scope(f),
                        function: (f.start_byte(), f.end_byte()),
                        name: fn_name,
                        scope: scope(f),
                        strings,
                    });
                }
            } else if value.kind() == "object" {
                let fields = children(value);
                if fields.is_empty() || fields.len() > 512 {
                    continue;
                }
                let mut out = HashMap::new();
                let mut valid = true;
                for p in fields {
                    let Some(k) = p.child_by_field_name("key") else {
                        valid = false;
                        break;
                    };
                    let Some(v) = p
                        .child_by_field_name("value")
                        .and_then(|v| ctx.eval(v, &HashMap::new(), 0))
                    else {
                        valid = false;
                        break;
                    };
                    if !matches!(v.value, Value::Number(_)) {
                        valid = false;
                        break;
                    }
                    let key = raw_string(k, source).or_else(|| text(k, source).map(str::to_owned));
                    let Some(key) = key else {
                        valid = false;
                        break;
                    };
                    out.insert(key, v);
                }
                if valid && let Some(name) = text(name, source) {
                    ctx.objects.push(Object {
                        visible: visible_scope(n),
                        declaration: n
                            .child_by_field_name("name")
                            .map_or(n.start_byte(), |name| name.start_byte()),
                        name: name.to_owned(),
                        scope: scope(n),
                        fields: out,
                        forwards: HashMap::new(),
                    });
                }
            }
        }
    }
    ctx.objects
        .retain(|o| immutable_object(o, &ctx.references, source));
    if ctx.tables.len() > 8 || ctx.objects.len() > 4096 {
        return None;
    }
    if ctx.tables.is_empty() {
        return None;
    }
    for &f in all.iter().filter(|n| is_function(**n)) {
        let Some(name) = function_name(f, source) else {
            continue;
        };
        let Some(body) = f.child_by_field_name("body") else {
            continue;
        };
        let statements = children(body);
        let parameters: Vec<_> = f
            .child_by_field_name("parameters")
            .map(children)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| {
                (p.kind() == "identifier")
                    .then(|| text(p, source).map(str::to_owned))
                    .flatten()
            })
            .collect();
        if statements.len() <= 2
            && let Some(last) = statements.last()
            && last.kind() == "return_statement"
            && let Some(result) = last.named_child(0)
            && result.kind() == "call_expression"
        {
            let safe = statements[..statements.len() - 1].iter().all(|d| {
                children(*d).into_iter().all(|v| {
                    declaration(v).is_some_and(|(name, value)| {
                        value.kind() == "object"
                            && ctx.objects.iter().any(|o| {
                                Some(o.name.as_str()) == text(name, source)
                                    && o.scope == (f.start_byte(), f.end_byte())
                            })
                    })
                })
            });
            if safe {
                ctx.proxies.push(Proxy {
                    binding: f.child_by_field_name("name")?.start_byte(),
                    visible: visible_scope(f),
                    name: name.clone(),
                    scope: scope(f),
                    parameters: parameters.clone(),
                    result,
                });
            }
        }
        if parameters.is_empty() || statements.len() < 3 {
            continue;
        }
        let Some(raw) = text(f, source) else {
            continue;
        };
        if !raw.contains(ALPHABET)
            || !raw.contains("fromCharCode")
            || !raw.contains("indexOf")
            || !raw.contains("charAt")
        {
            continue;
        }
        let Some(assignment) = statements[0].named_child(0) else {
            continue;
        };
        if assignment.kind() != "assignment_expression" {
            continue;
        }
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        if text(left, source) != Some(parameters[0].as_str()) {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        if right.kind() != "binary_expression"
            || right
                .child_by_field_name("operator")
                .and_then(|n| text(n, source))
                != Some("-")
            || right
                .child_by_field_name("left")
                .and_then(|n| text(n, source))
                != Some(parameters[0].as_str())
        {
            continue;
        }
        let Some(offset) = right
            .child_by_field_name("right")
            .and_then(|n| ctx.eval(n, &HashMap::new(), 0))
            .map(|v| v.numeric())
        else {
            continue;
        };
        if !offset.is_finite() {
            continue;
        }
        let Some((table_binding, table_call)) = statements[1].named_child(0).and_then(declaration)
        else {
            continue;
        };
        if table_call.kind() != "call_expression" {
            continue;
        }
        let Some(table_fn) = table_call
            .child_by_field_name("function")
            .and_then(|n| text(n, source))
        else {
            continue;
        };
        let Some(table) = ctx.tables.iter().position(|t| {
            t.name == table_fn
                && covers(t.visible, f.start_byte())
                && ctx.resolves(table_fn, table_call.start_byte(), t.binding)
        }) else {
            continue;
        };
        let Some((_, lookup)) = statements[2].named_child(0).and_then(declaration) else {
            continue;
        };
        if lookup.kind() != "subscript_expression"
            || lookup
                .child_by_field_name("object")
                .and_then(|n| text(n, source))
                != text(table_binding, source)
            || lookup
                .child_by_field_name("index")
                .and_then(|n| text(n, source))
                != Some(parameters[0].as_str())
        {
            continue;
        }
        let table_object = Object {
            visible: (f.start_byte(), f.end_byte()),
            declaration: table_binding.start_byte(),
            name: text(table_binding, source)?.to_owned(),
            scope: (f.start_byte(), f.end_byte()),
            fields: HashMap::new(),
            forwards: HashMap::new(),
        };
        if !immutable_object(&table_object, &ctx.references, source)
            || all.iter().any(|n| {
                covers(table_object.scope, n.start_byte())
                    && n.kind() == "call_expression"
                    && n.child_by_field_name("function")
                        .and_then(|n| member(n, source))
                        .is_some_and(|(receiver, _)| {
                            text(receiver, source) == Some(table_object.name.as_str())
                                && !shadowed_parameter(receiver, &table_object, source)
                        })
            })
        {
            continue;
        }
        let rc4 = raw.contains('^')
            && raw.contains("charCodeAt")
            && (raw.contains("0x100") || raw.contains("256"));
        if !rc4 || parameters.len() >= 2 {
            ctx.decoders.push(Decoder {
                binding: f.child_by_field_name("name")?.start_byte(),
                visible: visible_scope(f),
                function: (f.start_byte(), f.end_byte()),
                name,
                table,
                offset,
                rc4,
            });
        }
    }
    ctx.proxies
        .retain(|p| !identifier_writes(&all, &p.name, p.visible, source, None));
    ctx.decoders
        .retain(|d| !identifier_writes(&all, &d.name, d.visible, source, None));
    if ctx.decoders.len() > 8 || ctx.proxies.len() > 4096 {
        return None;
    }
    let mut attempts = 0;
    for active in 0..ctx.decoders.len() {
        ctx.active = active;
        let table_name = ctx.tables[ctx.decoders[active].table].name.clone();
        for &call in all.iter().filter(|n| n.kind() == "call_expression") {
            let Some(function) = call.child_by_field_name("function") else {
                continue;
            };
            let mut function = function;
            while function.kind() == "parenthesized_expression" {
                let Some(n) = function.named_child(0) else {
                    break;
                };
                function = n;
            }
            if !is_function(function) {
                continue;
            }
            let Some(args) = call.child_by_field_name("arguments").map(children) else {
                continue;
            };
            if args.len() != 2 || text(args[0], source) != Some(table_name.as_str()) {
                continue;
            }
            let table = &ctx.tables[ctx.decoders[active].table];
            if !ctx.resolves(&table.name, args[0].start_byte(), table.binding) {
                continue;
            }
            let Some(target) = ctx.eval(args[1], &HashMap::new(), 0).map(|v| v.numeric()) else {
                continue;
            };
            if !target.is_finite() {
                continue;
            }
            attempts += 1;
            if attempts > 16 || ctx.fuel.get() == 0 {
                return None;
            }
            let Some(parameters) = function.child_by_field_name("parameters").map(children) else {
                continue;
            };
            if parameters.len() != 2 {
                continue;
            }
            let Some(local) = text(parameters[1], source) else {
                continue;
            };
            let Some(body) = function.child_by_field_name("body") else {
                continue;
            };
            let inside: Vec<_> = all
                .iter()
                .copied()
                .filter(|n| n.start_byte() >= body.start_byte() && n.end_byte() <= body.end_byte())
                .collect();
            // Require the characteristic array rotation, rather than finding an
            // arbitrary checksum coincidence elsewhere in the program.
            let rotates = inside.iter().any(|n| {
                n.kind() == "call_expression"
                    && n.child_by_field_name("function")
                        .and_then(|f| member(f, source))
                        .is_some_and(|(receiver, key)| {
                            key == "push"
                                && n.child_by_field_name("arguments")
                                    .and_then(|a| a.named_child(0))
                                    .is_some_and(|a| {
                                        a.kind() == "call_expression"
                                            && a.child_by_field_name("function")
                                                .and_then(|f| member(f, source))
                                                .is_some_and(|(r, k)| {
                                                    k == "shift"
                                                        && text(r, source) == text(receiver, source)
                                                })
                                    })
                        })
            });
            if !rotates || !inside.iter().any(|n| n.kind() == "while_statement") {
                continue;
            }
            for condition in inside.iter().filter(|n| n.kind() == "binary_expression") {
                if condition
                    .child_by_field_name("operator")
                    .and_then(|n| text(n, source))
                    != Some("===")
                    || condition
                        .child_by_field_name("right")
                        .and_then(|n| text(n, source))
                        != Some(local)
                {
                    continue;
                }
                let Some(check_name) = condition
                    .child_by_field_name("left")
                    .and_then(|n| text(n, source))
                else {
                    continue;
                };
                let Some(checksum) = inside.iter().find_map(|n| {
                    declaration(*n).and_then(|(name, value)| {
                        (text(name, source) == Some(check_name)).then_some(value)
                    })
                }) else {
                    continue;
                };
                if !rotation_shape(&ctx, function, *condition, checksum) {
                    continue;
                }
                let Some(region) =
                    table_reference_region(&ctx, &all, (call.start_byte(), call.end_byte()))
                else {
                    continue;
                };
                for rotation in 0..ctx.tables[ctx.decoders[active].table].strings.len() {
                    if ctx.fuel.get() == 0 {
                        return None;
                    }
                    ctx.rotation = rotation;
                    if ctx
                        .eval(checksum, &HashMap::new(), 0)
                        .is_some_and(|v| (v.numeric() - target).abs() < 0.000001)
                    {
                        add_literal_objects(&mut ctx, &all);
                        let mut replacements = Vec::new();
                        let mut end = 0;
                        for &n in &all {
                            if n.start_byte() < end
                                || !region.allows(n)
                                || covers(
                                    (function.start_byte(), function.end_byte()),
                                    n.start_byte(),
                                )
                                || !matches!(
                                    n.kind(),
                                    "call_expression"
                                        | "binary_expression"
                                        | "member_expression"
                                        | "subscript_expression"
                                )
                            {
                                continue;
                            }
                            if let Some(value) = render_reduced(&ctx, n, 0) {
                                end = n.end_byte();
                                replacements.push((n.byte_range(), value));
                            }
                        }
                        if replacements.len() < 3 {
                            return None;
                        }
                        let mut out = source.to_owned();
                        for (range, value) in replacements.into_iter().rev() {
                            out.replace_range(range, &value);
                        }
                        return (out.len() <= MAX_SOURCE * 2).then_some(out);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "failed fixture reductions should fail the test"
)]
mod tests {
    use super::*;
    use std::path::Path;
    const BASE: &str = include_str!("../../testdata/vsix-string-table/base64-proxies.js");
    const RC4: &str = include_str!("../../testdata/vsix-string-table/rc4-proxies.js");
    fn reduce(source: &str) -> Option<String> {
        let ctx = crate::analysis_context::AnalysisContext::open(
            Path::new("input.js"),
            source.as_bytes(),
        );
        decode(ctx.source_ast()?)
    }
    #[test]
    fn reduces_base64_proxy_chains_and_constant_string_joins() {
        let out = reduce(BASE).expect("recognized Base64 table");
        assert!(out.contains("require(\n      \"child_process\""));
        assert!(out.contains("--install-extension"));
        assert!(
            out.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .contains("x(c,[\"--install-extension\",u,\"--force\"],F)"),
            "pure call forwarding should reduce"
        );
        assert!(out.contains("autoimport-smart-tool-2.5.8.vsix"));
    }
    #[test]
    fn reduces_rc4_keys_through_numeric_proxies() {
        let out = reduce(RC4).expect("recognized RC4 table");
        assert!(out.contains("\"runInContext\""));
        assert!(out.contains("\"getSignaturesForAddress\""));
        assert!(out.contains("\"base64\""));
    }
    #[test]
    fn rejects_unproved_rotation_and_nondecoder_lookalikes() {
        let wrong = BASE.replace(
            "})(e, -0xb7fb3 + 0xb252c + 0x1 * 0x97d71);",
            "})(e, 9999999999);",
        );
        assert_ne!(wrong, BASE);
        assert!(reduce(&wrong).is_none());
        assert!(reduce(&BASE.replace("charAt", "readCharacter")).is_none());
    }
    #[test]
    fn rejects_table_mutation_and_escaped_array_producers() {
        assert!(reduce(&BASE.replace("return cR;", "cR.reverse(); return cR;")).is_none());
        let escaped = BASE.replace(
            "var l = require(\"fs\")",
            "const leaked = e(); leaked.reverse(); var l = require(\"fs\")",
        );
        assert_ne!(escaped, BASE);
        assert!(reduce(&escaped).is_none());
        let mutated = BASE.replace("const t = a();", "const t = a(); t.reverse();");
        assert_ne!(mutated, BASE);
        assert!(reduce(&mutated).is_none());
    }
    #[test]
    fn retains_shadowed_proxy_calls_and_rejects_callable_reassignment() {
        let shadowed = BASE.replace("function V(c) {", "function V(c) { let ad = unknown;");
        let out = reduce(&shadowed).expect("unshadowed calls still reduce");
        assert!(out.contains("let ad = unknown"));
        let changed = BASE.replace(
            "var l = require(\"fs\")",
            "f = unknown; var l = require(\"fs\")",
        );
        assert!(reduce(&changed).is_none());
        let changed = BASE.replace(
            "var l = require(\"fs\")",
            "const parseInt = unknown; var l = require(\"fs\")",
        );
        assert!(reduce(&changed).is_none());
    }
    #[test]
    fn preserves_calls_shadowed_by_arrow_and_destructured_bindings() {
        for parameter in ["ad", "(ad)", "({ad})"] {
            let extra = format!(
                "function V(c) {{ const callback = {parameter} => ad(-239,-140,-156,-124);"
            );
            let source = BASE.replace("function V(c) {", &extra);
            let out = reduce(&source).expect("other unshadowed lookups reduce");
            assert!(out.contains("ad(-239,-140,-156,-124)"), "{parameter}");
        }
    }
    #[test]
    fn preserves_indirect_eval_and_async_forwarding() {
        let source = BASE.replace("            x,", "            eval,");
        assert_ne!(source, BASE);
        let out = reduce(&source).expect("other lookups reduce");
        assert!(out.contains("z[\"vdfOy\"]("));
        let source = BASE.replace(
            "vdfOy: function (G, J, K, N)",
            "vdfOy: async function (G, J, K, N)",
        );
        assert_ne!(source, BASE);
        let out = reduce(&source).expect("other lookups reduce");
        assert!(out.contains("z[\"vdfOy\"]("));
    }
    #[test]
    fn integer_conversion_uses_javascript_wrapping() {
        assert_eq!(js_i32(4294967297.0), 1);
        assert_eq!(js_i32(2147483648.0), i32::MIN);
        assert_eq!(js_i32(-4294967297.0), -1);
        assert_eq!(js_i32(f64::NAN), 0);
    }
    #[test]
    fn preserves_dynamic_calls_and_side_effecting_proxies() {
        let source = BASE.replace(
            "function ae(a, c, t, u) {",
            "function ae(a, c, t, u) { audit();",
        );
        let out = reduce(&source).expect("other safe proxies still reduce");
        assert!(out.contains("ae(0x415, 0x3aa, 0x3a3, 0x472)"));
        let source = BASE.replace(
            "ad(-0xef, -0x8c, -0x9c, -0x7c)",
            "ad(-0xef, readKey(), -0x9c, -0x7c)",
        );
        let out = reduce(&source).expect("remaining constants reduce");
        assert!(out.contains("ad(-0xef, readKey(), -0x9c, -0x7c)"));
    }
    fn escaped_terminal_fixture() -> String {
        BASE.replace(
            "function activate(context) {",
            "function activate(context, e) {",
        )
        .replace(
            "}\nexports.activate = activate;",
            "return external(e);\n}\nexports.activate = activate;",
        )
    }
    #[test]
    fn recovers_only_immediate_prefix_before_terminal_producer_escape() {
        let input = escaped_terminal_fixture();
        assert!(input.contains("return external(e);"));
        let out = reduce(&input).expect("stable immediate prefix");
        assert!(out.contains("https://github.com/francesca898/dqwffqw/releases/download/vsx/autoimport-smart-tool-2.5.8.vsix"));
        assert!(out.contains("return external(e);"));
        assert!(
            !out.contains("\"--install-extension\""),
            "deferred installer bodies must remain unreduced after an escape"
        );
    }
    #[test]
    fn accepts_a_simple_parameter_shadowed_by_the_table_function() {
        let input = BASE.replace(
            "function activate(context) {",
            "function activate(context, e) {",
        );
        assert!(
            reduce(&input)
                .expect("body function shadows parameter")
                .contains("--install-extension")
        );
    }
    #[test]
    fn rejects_earlier_producer_escape_and_mutation_even_with_terminal_return() {
        for extra in ["external(e);", "e().push('mutation');"] {
            let input = escaped_terminal_fixture().replace(
                "return external(e);",
                &format!("{extra} return external(e);"),
            );
            assert!(reduce(&input).is_none(), "{extra}");
        }
    }
    #[test]
    fn terminal_escape_does_not_rewrite_nested_function_bodies() {
        let input = escaped_terminal_fixture();
        let out = reduce(&input).expect("stable prefix");
        fn deferred(source: &str) -> String {
            let ctx = crate::analysis_context::AnalysisContext::open(
                Path::new("input.js"),
                source.as_bytes(),
            );
            let ast = ctx.source_ast().unwrap();
            let node = nodes(ast.tree.root_node())
                .unwrap()
                .into_iter()
                .find(|n| {
                    n.kind() == "function_declaration"
                        && function_name(*n, source).as_deref() == Some("W")
                })
                .expect("deferred fixture function");
            text(node, source).unwrap().to_owned()
        }
        let original = deferred(&input);
        let retained = deferred(&out);
        assert_eq!(original, retained);
    }
}
