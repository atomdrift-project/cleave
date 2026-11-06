use super::{all_filters_match_distinct, arg_matches};
use crate::composite_rules::condition::ArgFilter;

fn s(v: &str) -> filefacts::Arg {
    filefacts::Arg::String {
        value: v.to_string(),
    }
}
fn rx(pat: &str) -> ArgFilter {
    ArgFilter {
        kind: Some("string".to_string()),
        regex: Some(pat.to_string()),
        ..Default::default()
    }
}

#[test]
fn argument_value_filters_require_compatible_shapes() {
    let values: Vec<filefacts::Arg> = serde_json::from_value(serde_json::json!([
        {"shape": "string", "value": "needle"},
        {"shape": "template", "value": "needle"},
        {"shape": "identifier", "name": "needle"},
        {"shape": "number", "text": "7", "value": 7, "radix": 10},
        {"shape": "bool", "value": true},
        {"shape": "null"}, {"shape": "object"}, {"shape": "array"},
        {"shape": "function"}, {"shape": "call"}, {"shape": "expression"}
    ]))
    .unwrap();
    for (yaml, accepted) in [
        ("regex: '^needle$'", vec![0, 1]),
        ("exact: needle", vec![0, 1]),
        ("substr: eed", vec![0, 1]),
        ("value: 7", vec![3]),
        ("radix: 10", vec![3]),
        ("name: needle", vec![2]),
        ("name_regex: '^needle$'", vec![2]),
        ("name_regex: '^other$'", vec![]),
    ] {
        let filter: ArgFilter = crate::yaml::from_str(yaml).unwrap();
        for (index, value) in values.iter().enumerate() {
            assert_eq!(
                super::arg_matches(value, &filter),
                accepted.contains(&index),
                "{yaml} must not ignore its constraint on {value:?}"
            );
        }
    }
    let named: ArgFilter = crate::yaml::from_str("regex: '^needle$'").unwrap();
    // The unknown call argument cannot substitute for the missing literal.
    assert!(!all_filters_match_distinct(
        &[filefacts::Arg::Call, s("other")],
        &[named]
    ));
    let provenance: ArgFilter = crate::yaml::from_str("from:\n  value: '^needle$'").unwrap();
    for value in &values {
        // Shape-only filters remain valid; origin checks run separately.
        let shape = ArgFilter {
            kind: Some(super::arg_shape(value).into()),
            ..Default::default()
        };
        assert!(super::arg_matches(value, &shape));
        assert!(super::arg_matches(value, &provenance));
    }
}

#[test]
fn matches_distinct_positions() {
    // File.rename("a.png", "b.exe") — img arg + exe arg, distinct.
    let args = [s("a.png"), s("b.exe")];
    let filters = [rx(r"\.png$"), rx(r"\.exe$")];
    assert!(all_filters_match_distinct(&args, &filters));
}

#[test]
fn is_validates_the_arguments_own_text() {
    use crate::composite_rules::condition::StringValidator;
    let external = ArgFilter {
        is: Some(StringValidator::ExternalIp),
        ..Default::default()
    };
    assert!(arg_matches(&s("http://93.184.216.34/x"), &external));
    assert!(!arg_matches(&s("http://10.0.0.5/x"), &external));
    assert!(!arg_matches(&s("http://example.com/x"), &external));
    // A shell word is recorded as an identifier; its name is its text.
    let word = filefacts::Arg::Identifier {
        name: "http://93.184.216.34/x".to_string(),
    };
    assert!(arg_matches(&word, &external));
    // An argument without literal text cannot satisfy the check.
    assert!(!arg_matches(&filefacts::Arg::Expression, &external));
    // It composes with the other fields: both must hold.
    let narrowed = ArgFilter {
        regex: Some("^https?://".to_string()),
        ..external
    };
    assert!(arg_matches(&s("http://93.184.216.34/x"), &narrowed));
    assert!(!arg_matches(&s("ftp://93.184.216.34/x"), &narrowed));
}

#[test]
fn positional_filters_do_not_match_other_arguments() {
    let args = [s("source"), s("destination")];
    let filter = ArgFilter {
        index: Some(1),
        exact: Some("destination".into()),
        ..Default::default()
    };
    assert!(all_filters_match_distinct(
        &args,
        std::slice::from_ref(&filter)
    ));
    let wrong = ArgFilter {
        index: Some(0),
        ..filter.clone()
    };
    assert!(!all_filters_match_distinct(&args, &[wrong]));
    let missing = ArgFilter {
        index: Some(2),
        ..filter.clone()
    };
    assert!(!all_filters_match_distinct(&args, &[missing]));
    assert!(!all_filters_match_distinct(
        &args,
        &[filter.clone(), filter]
    ));
    assert!(all_filters_match_distinct(
        &args,
        &[
            ArgFilter {
                index: Some(0),
                ..Default::default()
            },
            rx("destination")
        ]
    ));
}

#[test]
fn yaml_provenance_uses_models_and_exact_argument_positions() {
    use crate::composite_rules::context::EvaluationContext;
    use crate::composite_rules::types::FileType;
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filter: ArgFilter = crate::yaml::from_str("index: 1\nfrom:\n  call: '^acquire$'\n  literal: '^SERVICE_TOKEN$'\n  through:\n    - call: '^wrap$'\n      arguments: [0]\n").unwrap();
    for (source, expected) in [
        (
            "function run(){send('url',wrap(acquire('SERVICE_TOKEN')));}",
            true,
        ),
        (
            "function identity(x){return x} function run(){send('url',identity(acquire('SERVICE_TOKEN')));}",
            true,
        ),
        (
            "function run(){send(acquire('SERVICE_TOKEN'),'constant');}",
            false,
        ),
        (
            "function run(){send('url',wrap(acquire('PUBLIC_SETTING')));}",
            false,
        ),
        (
            "function run(){send('url',opaque(acquire('SERVICE_TOKEN')));}",
            false,
        ),
        (
            "function read(name){return acquire(name)} function run(){send('url',read('SERVICE_TOKEN'));}",
            true,
        ),
        (
            "function read(name){return acquire(name)} function run(){read('SERVICE_TOKEN');send('url',read('PUBLIC_SETTING'));}",
            false,
        ),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.js"))
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.js".into(),
            file_type: "javascript".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().into_iter().cloned().collect(),
            ..Default::default()
        });
        let ctx = EvaluationContext::new(
            &report,
            source.as_bytes(),
            FileType::JavaScript,
            &[],
            None,
            None,
        );
        let result = super::eval_call(
            Some(&"send".into()),
            None,
            None,
            Some(&filter),
            None,
            super::CallSite::default(),
            &ctx,
        );
        assert_eq!(result.matched, expected, "{source}");
        assert_eq!(
            report.analysis_gaps.is_empty(),
            !source.contains("opaque("),
            "{source}: {:?}",
            report.analysis_gaps
        );
    }
}

#[test]
fn canonical_chained_call_provenance_uses_its_own_arguments() {
    use crate::composite_rules::context::EvaluationContext;
    use crate::composite_rules::types::FileType;
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};

    let filter: ArgFilter =
        crate::yaml::from_str("index: 0\nfrom:\n  call: '^acquire$'\n").unwrap();
    for (expression, expected) in [
        ("rt.Send(acquire()).Finish()", true),
        ("rt.Send(\"public\").Finish()", false),
        ("rt.Send(\"public\").Finish(acquire())", false),
    ] {
        let source =
            format!("package p\nimport rt \"example.org/runtime\"\nfunc run(){{ {expression} }}");
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.go"))
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.go".into(),
            file_type: "go".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().into_iter().cloned().collect(),
            ..Default::default()
        });
        let ctx = EvaluationContext::new(&report, source.as_bytes(), FileType::Go, &[], None, None);
        let result = super::eval_call(
            Some(&"example.org/runtime.Send".into()),
            None,
            None,
            Some(&filter),
            None,
            super::CallSite::default(),
            &ctx,
        );
        assert_eq!(result.matched, expected, "{expression}");
    }
}

#[test]
fn flow_gaps_survive_negative_matches_folding_cache_and_compact_output() {
    use crate::composite_rules::context::EvaluationContext;
    use crate::composite_rules::types::FileType;
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let source = "function run(){send(acquire(opaqueName()));}";
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new("a.js"))
        .open(source.as_bytes());
    let base = AnalysisReport::new(TargetInfo {
        path: "a.js".into(),
        file_type: "javascript".into(),
        size_bytes: source.len() as u64,
        sha256: String::new(),
        architectures: None,
    });
    let mut base = base;
    base.filefacts = Some(FilefactsView {
        flow: parsed.flow().cloned(),
        symbols: parsed.symbols().into_iter().cloned().collect(),
        ..Default::default()
    });
    let filter: ArgFilter =
        crate::yaml::from_str("index: 0\nfrom:\n  call: '^acquire$'\n  literal: '^TOKEN$'\n")
            .unwrap();
    for (variant, expected) in [
        (0, "flow-query-incomplete"),
        (1, "flow-unavailable"),
        (2, "flow-schema-unsupported"),
        (3, "flow-call-unavailable"),
        (4, "flow-graph-limited"),
    ] {
        let mut report = base.clone();
        let view = report.filefacts.as_mut().unwrap();
        match variant {
            1 => view.flow = None,
            2 => view.flow.as_mut().unwrap().version = 99,
            3 => view.flow.as_mut().unwrap().values.clear(),
            4 => {
                view.flow
                    .as_mut()
                    .unwrap()
                    .limitations
                    .insert(filefacts::Limitation::NodeBudget);
            }
            _ => {}
        }
        let ctx = EvaluationContext::new(
            &report,
            source.as_bytes(),
            FileType::JavaScript,
            &[],
            None,
            None,
        );
        let result = super::eval_call(
            Some(&"send".into()),
            None,
            None,
            Some(&filter),
            None,
            super::CallSite::default(),
            &ctx,
        );
        assert!(!result.matched);
        assert!(report.analysis_gaps.iter().any(|g| g.label() == expected));
        let (file, _, _) = report.into_file_analysis(0, &crate::Engine::empty());
        let encoded = serde_json::to_string(&file).unwrap();
        let file = serde_json::from_str(&encoded).unwrap();
        let restored = crate::report_from_file_analysis(file, "a.js".into());
        assert!(restored.analysis_gaps.iter().any(|g| g.label() == expected));
        let (file, _, _) = restored.into_file_analysis(0, &crate::Engine::empty());
        let compact = crate::types::compact_from_files(&[file.clone()], crate::types::Facts::Full);
        assert!(
            compact.files[0]
                .analysis_gaps
                .iter()
                .any(|g| g.label() == expected)
        );
        let mut display = base.clone();
        display.files = vec![file];
        let rendered = crate::output::format_context(&display, &crate::output::TinyOpts::tiny());
        assert!(rendered.contains("Analysis incomplete") && rendered.contains(expected));
    }
    assert!(
        base.analysis_gaps.is_empty(),
        "cloned evaluations must not contaminate another report"
    );
}

#[test]
fn yaml_complete_number_provenance_rejects_stale_and_partial_values() {
    use crate::composite_rules::{Condition, context::EvaluationContext, types::FileType};
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filter: ArgFilter = crate::yaml::from_str("index: 1\nfrom:\n  whole_number: 0\n").unwrap();
    for (path, kind, source, expected) in [
        ("a.lua", FileType::Lua, "ffi.C.ShowWindow(h,0)", true),
        (
            "a.lua",
            FileType::Lua,
            "local renamed=0x0; ffi.C.ShowWindow(h,renamed)",
            true,
        ),
        (
            "a.lua",
            FileType::Lua,
            "local renamed=0; local alias=renamed; ffi.C.ShowWindow(h,alias)",
            true,
        ),
        (
            "a.lua",
            FileType::Lua,
            "local mode=0; mode=1; ffi.C.ShowWindow(h,mode)",
            false,
        ),
        (
            "a.lua",
            FileType::Lua,
            "local mode=1; mode=0; ffi.C.ShowWindow(h,mode)",
            true,
        ),
        (
            "a.lua",
            FileType::Lua,
            "local mode=0+1; ffi.C.ShowWindow(h,mode)",
            false,
        ),
        (
            "a.lua",
            FileType::Lua,
            "ffi.C.ShowWindow(h,opaque(0))",
            false,
        ),
        ("a.lua", FileType::Lua, "ffi.C.ShowWindow(0,1)", false),
        ("a.lua", FileType::Lua, "ffi.C.ShowWindow(h,'0')", false),
        ("a.lua", FileType::Lua, "ffi.C.ShowWindow(h,false)", false),
        (
            "a.lua",
            FileType::Lua,
            "local mode=0; function f(mode) ffi.C.ShowWindow(h,mode) end",
            false,
        ),
        (
            "a.js",
            FileType::JavaScript,
            "let mode=0; ffi.C.ShowWindow(h,mode);",
            true,
        ),
        (
            "a.js",
            FileType::JavaScript,
            "let mode=0; mode=1; ffi.C.ShowWindow(h,mode);",
            false,
        ),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new(path))
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: path.into(),
            file_type: if path.ends_with("lua") {
                "lua"
            } else {
                "javascript"
            }
            .into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().into_iter().cloned().collect(),
            ..Default::default()
        });
        let ctx = EvaluationContext::new(&report, source.as_bytes(), kind, &[], None, None);
        let result = super::eval_call(
            Some(&"ffi.C.ShowWindow".into()),
            None,
            None,
            Some(&filter),
            None,
            super::CallSite::default(),
            &ctx,
        );
        assert_eq!(result.matched, expected, "{source}");
    }
    for (selection, valid) in [
        ("{whole_number: 0}", true),
        ("{whole_number: -1}", true),
        ("{field: mode, whole_number: 0}", true),
        ("{whole_number: 0, value: '0'}", false),
        ("{whole_number: 0, whole_value: '0'}", false),
        ("{whole_number: 0, call: source}", false),
        ("{whole_number: 0, field_exists: true, field: mode}", false),
        ("{whole_number: 0, literal: '0'}", false),
        (
            "{whole_number: 0, through: [{call: '^identity$', arguments: [0]}]}",
            false,
        ),
    ] {
        let condition: Condition = crate::yaml::from_str(&format!(
            "type: symbol\nkind: call\nexact: sink\narg:\n  from: {selection}\n"
        ))
        .unwrap();
        assert_eq!(condition.validate().is_ok(), valid, "{selection}");
    }
}

#[test]
fn yaml_literal_provenance_keeps_position_and_helper_context() {
    use crate::composite_rules::{Condition, context::EvaluationContext, types::FileType};
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filter: ArgFilter = crate::yaml::from_str("index: 0\nfrom:\n  value: '^needle$'\n  through:\n    - call: '^join$'\n      arguments: [0, 1]\n").unwrap();
    for (source, expected) in [
        ("function run(){write(join('root','needle'),'data')}", true),
        (
            "function identity(p){return p} function run(){write(identity('needle'),'data')}",
            true,
        ),
        (
            "function identity(p){return p} function run(){identity('needle');write(identity('public'),'needle')}",
            false,
        ),
        ("function run(){write(opaque('needle'),'data')}", false),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.js"))
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.js".into(),
            file_type: "javascript".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().into_iter().cloned().collect(),
            ..Default::default()
        });
        let ctx = EvaluationContext::new(
            &report,
            source.as_bytes(),
            FileType::JavaScript,
            &[],
            None,
            None,
        );
        let result = super::eval_call(
            Some(&"write".into()),
            None,
            None,
            Some(&filter),
            None,
            super::CallSite::default(),
            &ctx,
        );
        assert_eq!(result.matched, expected, "{source}");
    }
    for (selection, valid) in [
        ("{value: needle}", true),
        ("{call: acquire}", true),
        ("{}", false),
        ("{call: acquire, value: needle}", false),
        ("{value: needle, literal: x}", false),
    ] {
        let condition: Condition = crate::yaml::from_str(&format!(
            "type: symbol\nkind: call\nexact: write\narg:\n  from: {selection}\n"
        ))
        .unwrap();
        assert_eq!(condition.validate().is_ok(), valid, "{selection}");
    }
}

#[test]
fn order_independent_via_backtracking() {
    // Args in the opposite order still match — and a greedy first-fit that
    // grabbed the wrong arg would fail, so this exercises the backtracking.
    let args = [s("b.exe"), s("a.png")];
    let filters = [rx(r"\.png$"), rx(r"\.exe$")];
    assert!(all_filters_match_distinct(&args, &filters));
}

#[test]
fn one_arg_cannot_satisfy_two_filters() {
    // A single ".exe" arg must not satisfy both an img and an exe filter.
    let args = [s("only.exe")];
    let filters = [rx(r"\.png$"), rx(r"\.exe$")];
    assert!(!all_filters_match_distinct(&args, &filters));
}

#[test]
fn distinct_required_for_same_filter_twice() {
    // Two ".exe" filters need two distinct ".exe" args.
    assert!(!all_filters_match_distinct(
        &[s("a.exe")],
        &[rx(r"\.exe$"), rx(r"\.exe$")]
    ));
    assert!(all_filters_match_distinct(
        &[s("a.exe"), s("b.exe")],
        &[rx(r"\.exe$"), rx(r"\.exe$")]
    ));
}

/// `module_level` and `receiver` answer what a tree-sitter query over
/// `program` children used to: a method invoked on a `require` result in
/// code that runs when the module loads. Each line is a separate file.
#[test]
fn call_site_scope_and_receiver_provenance() {
    use crate::composite_rules::condition::{FlowOriginFilter, SymbolQuery};
    use crate::composite_rules::context::EvaluationContext;
    use crate::composite_rules::types::FileType;
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};

    let require = FlowOriginFilter {
        call: "^require$".into(),
        ..Default::default()
    };
    let load_time = super::CallSite {
        module_level: true,
        receiver: Some(&require),
    };
    for (source, expected) in [
        (
            "const cp = require('child_process'); cp.execSync('id');",
            true,
        ),
        (
            "var cp = require('child_process'); if (x) { cp.execSync('id'); }",
            true,
        ),
        ("require('child_process').execSync('id');", true),
        // Runs only when `later` is called.
        (
            "const cp = require('child_process'); function later() { cp.execSync('id'); }",
            false,
        ),
        // The receiver is not the require result.
        (
            "const cp = require('child_process'); console.warn('x');",
            false,
        ),
        ("const cp = make(); cp.execSync('id');", false),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.js"))
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.js".into(),
            file_type: "javascript".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().into_iter().cloned().collect(),
            ..Default::default()
        });
        let ctx = EvaluationContext::new(
            &report,
            source.as_bytes(),
            FileType::JavaScript,
            &[],
            None,
            None,
        );
        let result = super::eval_call(None, None, None, None, None, load_time, &ctx);
        assert_eq!(result.matched, expected, "{source}");
    }

    // Both filters belong to call sites alone.
    let misplaced = crate::composite_rules::Condition::Symbol(SymbolQuery {
        exact: Some("cp".into()),
        module_level: true,
        ..Default::default()
    });
    assert!(misplaced.validate().is_err());
}
