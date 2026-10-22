//! Static extraction of literal-array Base64 modules passed to import().
//! No JavaScript runs. Arrays with aliases, writes, shadow bindings or other
//! references are rejected, including potential escapes before a deferred join.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tree_sitter::Node;
const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 1_000_000;
const PREFIX: &str = "data:text/javascript;base64,";
fn text<'a>(n: Node<'_>, s: &'a str) -> Option<&'a str> {
    s.get(n.byte_range())
}
fn children(n: Node<'_>) -> Vec<Node<'_>> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}
fn literal(n: Node<'_>, s: &str) -> Option<String> {
    if n.kind() != "string" {
        return None;
    }
    let raw = text(n, s)?;
    let body = raw.get(1..raw.len().checked_sub(1)?)?;
    // Base64 and this data-URL prefix need no escapes. Decline other syntax.
    (!body.contains('\\')).then(|| body.to_owned())
}
pub(crate) fn decode(ast: filefacts::SourceAst<'_>) -> Vec<(u64, String)> {
    let s = ast.source;
    if s.len() > MAX_SOURCE || !s.contains(PREFIX) || !s.contains("join") {
        return vec![];
    }
    let mut nodes = Vec::new();
    let mut cursor = ast.tree.root_node().walk();
    loop {
        nodes.push(cursor.node());
        if nodes.len() > MAX_NODES {
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
    let mut out = Vec::new();
    for n in nodes
        .iter()
        .copied()
        .filter(|n| n.kind() == "call_expression")
    {
        let Some(function) = n.child_by_field_name("function") else {
            continue;
        };
        if function.kind() != "import" {
            continue;
        }
        let Some(arguments) = n.child_by_field_name("arguments") else {
            continue;
        };
        let args = children(arguments);
        if args.len() != 1 || args[0].kind() != "binary_expression" {
            continue;
        }
        let expr = args[0];
        if expr
            .child_by_field_name("operator")
            .and_then(|n| text(n, s))
            != Some("+")
        {
            continue;
        }
        let Some(left) = expr.child_by_field_name("left") else {
            continue;
        };
        if literal(left, s).as_deref() != Some(PREFIX) {
            continue;
        }
        let Some(join) = expr.child_by_field_name("right") else {
            continue;
        };
        if join.kind() != "call_expression" {
            continue;
        }
        let Some(member) = join.child_by_field_name("function") else {
            continue;
        };
        if member.kind() != "member_expression"
            || member.child_by_field_name("optional_chain").is_some()
        {
            continue;
        }
        if member
            .child_by_field_name("property")
            .and_then(|n| text(n, s))
            != Some("join")
        {
            continue;
        }
        let Some(object) = member.child_by_field_name("object") else {
            continue;
        };
        if object.kind() != "identifier" {
            continue;
        }
        let Some(joinargs) = join.child_by_field_name("arguments") else {
            continue;
        };
        let joinargs = children(joinargs);
        if joinargs.len() != 1 || literal(joinargs[0], s).as_deref() != Some("") {
            continue;
        }
        let Some(name) = text(object, s) else {
            continue;
        };
        // Exactly two uses: a const declaration and this join. This deliberately
        // rejects aliases, mutations, shorthand escapes, shadow declarations,
        // deferred mutable arrays and other reads regardless of source order.
        let refs: Vec<_> = nodes
            .iter()
            .copied()
            .filter(|n| {
                matches!(
                    n.kind(),
                    "identifier"
                        | "shorthand_property_identifier"
                        | "shorthand_property_identifier_pattern"
                ) && text(*n, s) == Some(name)
            })
            .collect();
        if refs.len() != 2 {
            continue;
        }
        let Some(binding) = refs.iter().copied().find(|r| r.id() != object.id()) else {
            continue;
        };
        let Some(decl) = binding.parent() else {
            continue;
        };
        if decl.kind() != "variable_declarator" || decl.child_by_field_name("name") != Some(binding)
        {
            continue;
        }
        let Some(statement) = decl.parent() else {
            continue;
        };
        if statement.kind() != "lexical_declaration"
            || statement
                .child_by_field_name("kind")
                .and_then(|n| text(n, s))
                != Some("const")
        {
            continue;
        }
        // The join must be in the declaration's lexical scope, after its binding.
        if object.start_byte() < decl.end_byte() {
            continue;
        }
        let Some(scope) = statement.parent() else {
            continue;
        };
        if !(scope.start_byte() <= object.start_byte() && object.end_byte() <= scope.end_byte()) {
            continue;
        }
        let Some(array) = decl.child_by_field_name("value") else {
            continue;
        };
        if array.kind() != "array" {
            continue;
        }
        let items = children(array);
        if items.is_empty() || items.len() > 4096 {
            continue;
        }
        let Some(parts) = items
            .into_iter()
            .map(|v| literal(v, s))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let encoded = parts.concat();
        if encoded.len() > 2 * 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = STANDARD.decode(encoded) else {
            continue;
        };
        if bytes.len() < 64
            || bytes
                .iter()
                .any(|b| !matches!(*b, b'\t' | b'\r' | b'\n' | 32..=126))
        {
            continue;
        }
        let Ok(decoded) = String::from_utf8(bytes) else {
            continue;
        };
        if !out.iter().any(|(_, existing)| existing == &decoded) {
            out.push((n.start_byte() as u64, decoded));
        }
        if out.len() >= 4 {
            break;
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    fn run(source: &str) -> Vec<(u64, String)> {
        let ctx = crate::analysis_context::AnalysisContext::open(
            std::path::Path::new("input.js"),
            source.as_bytes(),
        );
        ctx.source_ast().map(decode).unwrap_or_default()
    }
    fn fixture() -> String {
        let payload = "export async function hello(){ return 'A harmless substantial JavaScript module fixture for static extraction'; }";
        let encoded = STANDARD.encode(payload);
        let mid = encoded.len() / 2;
        format!(
            "const pieces=['{}','{}']; (async()=>{{await import('{}'+pieces.join(''));}})();",
            &encoded[..mid],
            &encoded[mid..],
            PREFIX
        )
    }
    #[test]
    fn extracts_joined_import_without_executing_it() {
        let out = run(&fixture());
        assert_eq!(out.len(), 1);
        assert!(out[0].1.starts_with("export async function hello"));
    }
    #[test]
    fn rejects_mutation_alias_escape_and_shadowing() {
        for extra in [
            "pieces.push('QQ==');",
            "pieces[0]='QQ==';",
            "const alias=pieces;",
            "send(pieces);",
            "const escaped={pieces};",
            "function f(pieces){return pieces;}",
        ] {
            let s = fixture().replace(" (async", &format!(" {extra} (async"));
            assert!(run(&s).is_empty(), "{extra}");
        }
    }
    #[test]
    fn rejects_nonliteral_wrong_sink_and_mutable_binding() {
        for s in [
            fixture().replace("const pieces", "let pieces"),
            fixture().replace("import(", "load("),
            fixture().replace("join('')", "join(':')"),
            fixture().replace("data:text/javascript;base64,", "data:text/plain;base64,"),
            fixture().replace("['", "[getChunk(),'"),
        ] {
            assert!(run(&s).is_empty());
        }
    }
}

/// Decode bounded, explicit `salt:iv:ciphertext` envelopes with Node's default
/// scrypt parameters. This extracts embedded bytes, not a claim that a call runs.
/// Passwords are literal arguments to the just-imported module, or the literal
/// second argument of an envelope-decryption call. No guessing or network I/O.
pub(crate) fn encrypted_layers(
    host: filefacts::SourceAst<'_>,
    decoded: &str,
    import_offset: u64,
) -> Vec<(String, Vec<String>)> {
    if !decoded.contains("scryptSync") || !decoded.contains("aes-256-cbc") {
        return vec![];
    }
    let host_source = host.source;
    // The extracted module must have a literal password supplied at its own
    // import binding, rather than mining unrelated strings in the host bundle.
    let mut passwords = Vec::new();
    let all = bounded_nodes(host.tree.root_node());
    for import in all.iter().copied().filter(|n| {
        n.kind() == "call_expression"
            && n.child_by_field_name("function")
                .is_some_and(|f| f.kind() == "import")
    }) {
        let Some(arg) = import
            .child_by_field_name("arguments")
            .and_then(|a| a.named_child(0))
        else {
            continue;
        };
        if import.start_byte() as u64 != import_offset
            || !text(arg, host_source).is_some_and(|v| v.contains(PREFIX))
        {
            continue;
        }
        let mut owner = import;
        if let Some(parent) = owner.parent().filter(|p| p.kind() == "await_expression") {
            owner = parent;
        }
        let Some(decl) = owner.parent().filter(|p| {
            p.kind() == "variable_declarator" && p.child_by_field_name("value") == Some(owner)
        }) else {
            continue;
        };
        let Some(binding) = decl
            .child_by_field_name("name")
            .filter(|n| n.kind() == "identifier")
            .and_then(|n| text(n, host_source))
        else {
            continue;
        };
        if all
            .iter()
            .filter(|n| {
                matches!(
                    n.kind(),
                    "identifier"
                        | "shorthand_property_identifier"
                        | "shorthand_property_identifier_pattern"
                ) && text(**n, host_source) == Some(binding)
            })
            .count()
            != 2
        {
            continue;
        }
        for call in all
            .iter()
            .copied()
            .filter(|n| n.kind() == "call_expression")
        {
            let Some(member) = call
                .child_by_field_name("function")
                .filter(|n| n.kind() == "member_expression")
            else {
                continue;
            };
            if member
                .child_by_field_name("object")
                .and_then(|n| text(n, host_source))
                != Some(binding)
            {
                continue;
            }
            if let Some(password) = call
                .child_by_field_name("arguments")
                .and_then(|n| n.named_child(0))
                .and_then(|n| literal(n, host_source))
                .filter(|s| !s.is_empty() && s.len() <= 128)
            {
                if !passwords.contains(&password) {
                    passwords.push(password);
                }
                if passwords.len() >= 4 {
                    break;
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut budget = 4;
    decrypt_layer(decoded, &passwords, &mut budget, 0, &[], &mut out);
    out
}
fn bounded_nodes(root: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut cursor = root.walk();
    loop {
        out.push(cursor.node());
        if out.len() > MAX_NODES {
            return vec![];
        }
        if cursor.goto_first_child() || cursor.goto_next_sibling() {
            continue;
        }
        loop {
            if !cursor.goto_parent() {
                return out;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }
}
fn envelope(value: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if value.len() > 256 * 1024 {
        return None;
    }
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let salt = STANDARD.decode(parts[0]).ok()?;
    let iv = STANDARD.decode(parts[1]).ok()?;
    let data = STANDARD.decode(parts[2]).ok()?;
    (salt.len() == 16 && iv.len() == 16 && data.len() >= 64 && data.len() % 16 == 0)
        .then_some((salt, iv, data))
}
fn decrypt_layer(
    source: &str,
    external_passwords: &[String],
    budget: &mut usize,
    depth: usize,
    chain: &[String],
    out: &mut Vec<(String, Vec<String>)>,
) {
    if depth >= 2
        || *budget == 0
        || source.len() > MAX_SOURCE
        || !source.contains("scryptSync")
        || !source.contains("aes-256-cbc")
    {
        return;
    }
    let ctx = crate::analysis_context::AnalysisContext::open(
        std::path::Path::new("embedded.js"),
        source.as_bytes(),
    );
    let Some(ast) = ctx.source_ast() else { return };
    let nodes = bounded_nodes(ast.tree.root_node());
    let mut candidates = Vec::new();
    // Prefer an explicit decrypt(envelope, password) pair in the same call.
    for call in nodes
        .iter()
        .copied()
        .filter(|n| n.kind() == "call_expression")
    {
        let Some(args) = call.child_by_field_name("arguments") else {
            continue;
        };
        let args = children(args);
        if args.len() == 2 {
            if let (Some(blob), Some(password)) = (
                literal(args[0], source).filter(|s| envelope(s).is_some()),
                literal(args[1], source).filter(|s| !s.is_empty() && s.len() <= 128),
            ) {
                candidates.push((blob, password));
            }
        }
    }
    for n in nodes.iter().copied().filter(|n| n.kind() == "string") {
        let Some(blob) = literal(n, source).filter(|s| envelope(s).is_some()) else {
            continue;
        };
        for password in external_passwords.iter().take(4) {
            if !candidates.contains(&(blob.clone(), password.clone())) {
                candidates.push((blob.clone(), password.clone()));
            }
        }
        if candidates.len() >= 8 {
            break;
        }
    }
    for (blob, password) in candidates {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let Some((salt, iv, ciphertext)) = envelope(&blob) else {
            continue;
        };
        let Ok(params) = scrypt::Params::new(14, 8, 1, 32) else {
            continue;
        };
        let mut key = [0u8; 32];
        if scrypt::scrypt(password.as_bytes(), &salt, &params, &mut key).is_err() {
            continue;
        }
        let Some(plain) =
            crate::extractors::aes_payload::decrypt_aes_256_cbc(&ciphertext, &key, &iv)
        else {
            continue;
        };
        let Ok(mut decoded) = String::from_utf8(plain) else {
            continue;
        };
        let mut next = chain.to_vec();
        next.extend(["scrypt".into(), "aes-256-cbc".into()]);
        if let Ok(bytes) = STANDARD.decode(&decoded) {
            if let Ok(value) = String::from_utf8(bytes) {
                if value.len() >= 64
                    && value
                        .bytes()
                        .all(|b| matches!(b, b'\t' | b'\r' | b'\n' | 32..=126))
                {
                    decoded = value;
                    next.push("base64".into());
                }
            }
        }
        if decoded.len() < 64
            || !decoded
                .bytes()
                .all(|b| matches!(b, b'\t' | b'\r' | b'\n' | 32..=126))
        {
            continue;
        }
        // Retain only parser-confirmed executable source rather than arbitrary
        // successfully decrypted data or a lone identifier/string expression.
        let parsed = crate::analysis_context::AnalysisContext::open(
            std::path::Path::new("payload.js"),
            decoded.as_bytes(),
        );
        let Some(ast) = parsed.source_ast() else {
            continue;
        };
        if ast.tree.root_node().has_error()
            || !bounded_nodes(ast.tree.root_node()).iter().any(|n| {
                matches!(
                    n.kind(),
                    "call_expression" | "function_declaration" | "import_statement"
                )
            })
        {
            continue;
        }
        if out.iter().any(|(s, _)| s == &decoded) {
            continue;
        }
        out.push((decoded.clone(), next.clone()));
        decrypt_layer(&decoded, &[], budget, depth + 1, &next, out);
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::*;
    const PASSWORD: &str = "changed-fixture-password";
    const OUTER: &str = "import crypto from 'node:crypto'; const mode='aes-256-cbc'; function scryptSync(){} const envelope=\"AAECAwQFBgcICQoLDA0ODw==:EBESExQVFhcYGRobHB0eHw==:kCJ7pxz1RIJQRQV3nLUdGKxYWxjNCNpnxY9RDmrQC86DGP3n4zxU33u0I6o0Vmu8Usr5hPgL5Bs7h1GQ0VnyuYYexZyXSjvm0P/3l00RGTLtAc+3Gdy7QOMpaf+jOJujwn6lkuqkWfVJNv2NpDEr2X88GX+fMC6sygWBAEPDEO40v4iIvRU0pNgJj6jB5+Y6zk9pXtzkLd4PUZgltfVHyDZWr4mGuJ0ubciOmmMhFYZt1ONLoE7z0Bm3+HZ8JfZkDSMS9NDxDAKm9X6YTxe2cWWnpF28XRkdC1svu67ypR/fn05/M/bmQPf2PKfs+THHwyeXKVeE7V4JVj0vnhp+vAHvP/aNM57Kyv3Cg1dp8eeOoyzijPEraBrfBMkcbFwBduNmQbDc0aUMjttz0y9lhSHf5nhhu1mNBQxsVX3qqHyWJRIxTLeEGpQSd+X8dPNFschMbtAQ/T7KDOnnJlnZUN+mEggPKs6cNfBkBSFhlbIRdkmoW+5h60HFwIknHFuBTNpk+7QdrQGHbiDLrCLi3esTEco5MzL8MFHDoU4qDWY/oubOC/0kbE/8EFDDFr6DZUu05oQw1wqZezcYHG+v7ruXk2Hjdfp8766zyV7TiAfqy+S4mWNZ8f4hrZrBJ9iBPUWaVTjf8+aIDMJMGVGWtA==\";";
    const FINAL: &str = "export function fixture(){ return 'A harmless complete JavaScript module used to verify bounded static decryption'; }";
    fn extract(password: &str, receiver: &str) -> Vec<(String, Vec<String>)> {
        let host = format!(
            "const module=await import('{}'+['ignored'].join('')); {}.run('{}');",
            PREFIX, receiver, password
        );
        let ctx = crate::analysis_context::AnalysisContext::open(
            std::path::Path::new("host.js"),
            host.as_bytes(),
        );
        encrypted_layers(
            ctx.source_ast().unwrap(),
            OUTER,
            host.find("import(").unwrap() as u64,
        )
    }
    #[test]
    fn recovers_two_layers_with_changed_password_and_envelope() {
        let layers = extract(PASSWORD, "module");
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[1].0, FINAL);
        assert_eq!(
            layers[1].1,
            vec!["scrypt", "aes-256-cbc", "base64", "scrypt", "aes-256-cbc"]
        );
    }
    #[test]
    fn rejects_wrong_password_and_unrelated_module_argument() {
        assert!(extract("wrong-password", "module").is_empty());
        assert!(extract(PASSWORD, "otherModule").is_empty());
    }
    #[test]
    fn rejects_invalid_envelope_before_deriving_keys() {
        assert!(envelope("YQ==:YQ==:YQ==").is_none());
        assert!(envelope("not-an-envelope").is_none());
    }
    #[test]
    fn enforces_key_attempt_and_recursion_limits() {
        let mut out = Vec::new();
        let mut budget = 0;
        decrypt_layer(OUTER, &[PASSWORD.into()], &mut budget, 0, &[], &mut out);
        assert!(out.is_empty());
        budget = 4;
        decrypt_layer(OUTER, &[PASSWORD.into()], &mut budget, 2, &[], &mut out);
        assert!(out.is_empty());
        budget = 1;
        decrypt_layer(OUTER, &[PASSWORD.into()], &mut budget, 0, &[], &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(budget, 0);
    }
}
