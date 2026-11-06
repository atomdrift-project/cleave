use super::retain_dependency_symbols;
use filefacts::{Arg, Symbol};

#[test]
fn compact_members_keep_literal_module_loads_and_fetch_calls() {
    let call = |name: &str, args| Symbol::Call {
        target: Some(name.into()),
        args,
        offset: None,
    };
    let literal = || {
        vec![Arg::String {
            value: "axios".into(),
        }]
    };
    let mut symbols = vec![
        call("require", literal()),
        call("import", literal()),
        call("__import__", literal()),
        call("importlib.import_module", literal()),
        call("require", vec![Arg::Identifier { name: "x".into() }]),
        call("console.log", literal()),
        call(
            "curl",
            vec![Arg::Identifier {
                name: "https://stage.test/a".into(),
            }],
        ),
        call("/usr/bin/wget", literal()),
    ];
    retain_dependency_symbols(&mut symbols, "shell");
    assert_eq!(symbols.len(), 6);
}

#[test]
fn folded_members_preserve_python_imports_and_ruby_process_shadow_context() -> anyhow::Result<()> {
    use super::{FileAnalysis, precompact_member_facts};
    use crate::{Engine, analysis_context::AnalysisContext, types::FilefactsView};
    use anyhow::Context;
    let engine = Engine::empty().with_compact_members(true);
    for (name, file_type, source) in [
        ("entry.py", "python", "from provider.api import client\n"),
        (
            "entry.rb",
            "ruby",
            "def system(command); puts command; end\nKernel = Logger\nsystem('curl https://example.invalid/one')\nKernel.exec(\"curl #{url}\")\n",
        ),
    ] {
        let context = AnalysisContext::open(std::path::Path::new(name), source.as_bytes());
        let mut file = FileAnalysis {
            path: name.into(),
            file_type: file_type.into(),
            filefacts: Some(FilefactsView::from_ctx(&context)),
            ..Default::default()
        };
        precompact_member_facts(&mut file, &engine);
        let symbols = &file.filefacts.as_ref().context("retained view")?.symbols;
        if file_type == "python" {
            assert!(
                symbols
                    .iter()
                    .any(|symbol| matches!(symbol, Symbol::Import { .. }))
            );
        } else {
            assert!(symbols.iter().any(|symbol| matches!(symbol, Symbol::Call { target: Some(target), .. } if target == "system")));
            // Preserve the receiver-qualified target and its call offset;
            // dependency discovery distinguishes Kernel from other receivers.
            let exec_offset = source.find("Kernel.exec").context("exec call")? as u64;
            assert!(symbols.iter().any(|symbol| matches!(symbol, Symbol::Call { target: Some(target), offset: Some(offset), .. } if target == "Kernel.exec" && *offset == exec_offset)));
            assert!(
                symbols.iter().any(
                    |symbol| matches!(symbol, Symbol::Function { name, .. } if name == "system")
                )
            );
            assert!(
                symbols.iter().any(
                    |symbol| matches!(symbol, Symbol::Bind { target, .. } if target == "Kernel")
                )
            );
            assert!(!symbols.iter().any(|symbol| matches!(symbol, Symbol::Call { target: Some(target), .. } if target == "puts")));
        }
    }
    Ok(())
}
