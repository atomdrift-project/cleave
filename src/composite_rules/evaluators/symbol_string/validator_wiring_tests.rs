use super::validate_match;
use crate::composite_rules::condition::StringValidator;

#[test]
fn base64_yaml_selector_reaches_the_validator() -> anyhow::Result<()> {
    let validator: StringValidator = crate::yaml::from_str("base64")?;
    assert_eq!(validator, StringValidator::Base64);
    assert_eq!(serde_json::to_string(&validator)?, "\"base64\"");
    assert!(validate_match("Zg==", Some(validator)));
    assert!(!validate_match("Zh==", Some(validator)));
    assert!(!validate_match("Zg=", Some(validator)));
    assert!(!validate_match("not base64!", Some(validator)));
    assert!(validate_match("not base64!", None));
    Ok(())
}

#[test]
fn random_like_reaches_the_validator() {
    // The arm that connects `is: random_like` to the model. Without it
    // the validator silently accepts everything, and every trait built
    // on it matches every value.
    assert!(validate_match(
        "kwTfNTTv",
        Some(StringValidator::RandomLike)
    ));
    assert!(validate_match(
        "QDnqfZpMxb",
        Some(StringValidator::RandomLike)
    ));
    assert!(!validate_match(
        "Administrator",
        Some(StringValidator::RandomLike)
    ));
    assert!(!validate_match(
        "Kostenkontrolle",
        Some(StringValidator::RandomLike)
    ));
    // No validator declared means no opinion.
    assert!(validate_match("anything at all", None));
}
#[test]
fn cfml_member_origin_matches_values_not_spelling_or_adjacent_attributes() {
    use crate::composite_rules::condition::ArgFilter;
    use crate::composite_rules::{Condition, context::EvaluationContext, types::FileType};
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filter: ArgFilter =
        crate::yaml::from_str("index: 0\nfrom:\n  field: name\n  member: '^form\\.job$'\n")
            .unwrap();
    for (source, expected) in [
        ("<cfexecute name='#FORM.job#'>", true),
        (
            "<cfset a=form.job><cfset renamed=a><cfexecute name='#renamed#'>",
            true,
        ),
        (
            "<cfset a=form.job><cfset a='fixed'><cfexecute name='#a#'>",
            false,
        ),
        ("<cfexecute name='form.job'>", false),
        ("<cfexecute name='##form.job##'>", false),
        ("<cfexecute name='fixed' arguments='#form.job#'>", false),
        ("<cfexecute name='#url.job#'>", false),
        (
            "<cfif x><cfset a=form.job><cfelse><cfset a='fixed'></cfif><cfexecute name='#a#'>",
            true,
        ),
        (
            "<cfif x><cfset a=form.job><cfelse><cfexecute name='#a#'></cfif>",
            false,
        ),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.cfm"))
            .file_type(filefacts::FileType::Cfml)
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.cfm".into(),
            file_type: "cfml".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().iter().cloned().collect(),
            ..Default::default()
        });
        let ctx =
            EvaluationContext::new(&report, source.as_bytes(), FileType::Cfml, &[], None, None);
        let result = super::eval_call(
            Some(&"cfexecute".into()),
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
        ("{member: '^form\\.job$'}", true),
        ("{member: ''}", false),
        ("{member: '['}", false),
        ("{member: x, call: f}", false),
        ("{member: x, value: x}", false),
        ("{member: x, literal: x}", false),
        ("{member: x, argument: 1}", false),
    ] {
        let condition: Condition = crate::yaml::from_str(&format!(
            "type: symbol\nkind: call\nexact: cfexecute\narg:\n  from: {selection}\n"
        ))
        .unwrap();
        assert_eq!(condition.validate().is_ok(), valid, "{selection}");
    }
}

#[test]
fn cfml_named_origins_join_on_one_call_and_distinct_fields() {
    use crate::composite_rules::{
        condition::ArgFilter, context::EvaluationContext, types::FileType,
    };
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filters: Vec<ArgFilter> = crate::yaml::from_str("- index: 0\n  from: {field: name, value: '^cmd[.]exe$'}\n- index: 0\n  from: {field: arguments, member: '^form[.]job$'}\n").unwrap();
    for (source, expected) in [
        ("<cfexecute name='cmd.exe' arguments='#form.job#'>", true),
        ("<cfexecute arguments='#form.job#' name='cmd.exe'>", true),
        ("<cfexecute name='grep' arguments='#form.job#'>", false),
        (
            "<cfexecute name='cmd.exe' arguments='fixed'><cfexecute name='grep' arguments='#form.job#'>",
            false,
        ),
        ("<cfexecute name='cmd.exe' outputfile='#form.job#'>", false),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.cfm"))
            .file_type(filefacts::FileType::Cfml)
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.cfm".into(),
            file_type: "cfml".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().iter().cloned().collect(),
            ..Default::default()
        });
        let ctx =
            EvaluationContext::new(&report, source.as_bytes(), FileType::Cfml, &[], None, None);
        assert_eq!(
            super::eval_call(
                Some(&"cfexecute".into()),
                None,
                None,
                None,
                Some(&filters),
                super::CallSite::default(),
                &ctx
            )
            .matched,
            expected,
            "{source}"
        );
        let duplicate = vec![filters[0].clone(), filters[0].clone()];
        assert!(
            !super::eval_call(
                Some(&"cfexecute".into()),
                None,
                None,
                None,
                Some(&duplicate),
                super::CallSite::default(),
                &ctx
            )
            .matched
        );
    }
}

#[test]
fn whole_number_provenance_requires_complete_numeric_value() {
    use crate::composite_rules::{
        condition::ArgFilter, context::EvaluationContext, types::FileType,
    };
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let arg: ArgFilter = crate::yaml::from_str("index: 1\nfrom: {whole_number: 0}\n").unwrap();
    for (source, expected) in [
        ("ShowWindow(hwnd, 0)", true),
        ("const HIDE = 0; ShowWindow(hwnd, HIDE)", true),
        ("const HIDE = 1; ShowWindow(hwnd, HIDE)", false),
        ("ShowWindow(hwnd, unknown)", false),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("fixture.js"))
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "fixture.js".into(),
            file_type: "javascript".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().iter().cloned().collect(),
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
        let matched = super::eval_call(
            Some(&"ShowWindow".into()),
            None,
            None,
            Some(&arg),
            None,
            super::CallSite::default(),
            &ctx,
        )
        .matched;
        assert_eq!(matched, expected, "{source}");
    }
}

#[test]
fn positional_and_named_argument_filters_join_on_the_same_call() {
    use crate::composite_rules::{
        condition::ArgFilter, context::EvaluationContext, types::FileType,
    };
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filters: Vec<ArgFilter> = crate::yaml::from_str(
        r#"
- index: 0
  kind: identifier
  name_regex: '^(endpoint|url|target)$'
- index: 1
  kind: object
  from: {field: method, whole_value: '^POST$'}
- index: 1
  kind: object
  from: {field: body, call: '^JSON\.stringify$'}
"#,
    )
    .unwrap();
    for (source, expected) in [
        (
            r#"fetch(endpoint, {method:'POST', body:JSON.stringify(data)});"#,
            true,
        ),
        (
            r#"fetch(url, {body:JSON.stringify(data), method:'POST'});"#,
            true,
        ),
        (
            r#"fetch(endpoint, {method:'GET', body:JSON.stringify(data)});"#,
            false,
        ),
        (
            r#"fetch(endpoint, {method:'POST', body:'JSON.stringify(data)'});"#,
            false,
        ),
        (
            r#"fetch(endpoint, {method:'POST'}); fetch(url, {body:JSON.stringify(data)});"#,
            false,
        ),
        (
            r#"fetch(other, {method:'POST', body:JSON.stringify(data)});"#,
            false,
        ),
        (
            r#"fetch(endpoint, {method:'POST', body:JSON.stringify(data), method:'GET'});"#,
            false,
        ),
        (
            r#"const opts={method:'POST',body:JSON.stringify(data)}; opts.body='static'; fetch(target,opts);"#,
            false,
        ),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("request.js"))
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "request.js".into(),
            file_type: "javascript".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().iter().cloned().collect(),
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
        let evaluate = |filters: &[ArgFilter]| {
            super::eval_call(
                Some(&"fetch".into()),
                None,
                None,
                None,
                Some(filters),
                super::CallSite::default(),
                &ctx,
            )
            .matched
        };
        assert_eq!(evaluate(&filters), expected, "{source}");
        assert!(
            !evaluate(&[filters[0].clone(), filters[0].clone()]),
            "duplicate position: {source}"
        );
        assert!(
            !evaluate(&[filters[0].clone(), filters[1].clone(), filters[1].clone()]),
            "duplicate field: {source}"
        );
    }
}

#[test]
fn cfml_whole_literal_values_do_not_match_fragments() {
    use crate::composite_rules::{
        Condition, condition::ArgFilter, context::EvaluationContext, types::FileType,
    };
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filter: ArgFilter =
        crate::yaml::from_str("index: 0\nfrom: {field: action, whole_value: '^read$'}\n").unwrap();
    for (source, expected) in [
        (r#"<cffile action='read'>"#, true),
        (r##"<cffile action="#'re' & 'ad'#">"##, true),
        (r##"<cffile action="re#'ad'#">"##, true),
        (r##"<cffile action="#'read' & 'Bogus'#">"##, false),
        (r##"<cffile action="#'read'#Bogus">"##, false),
        (r##"<cffile action="#'read' & url.suffix#">"##, false),
        (r##"<cffile action="#opaque('read')#">"##, false),
        (r##"<cfset a='read'><cffile action="#a#">"##, true),
        (
            r##"<cfset a='read'><cfset a='write'><cffile action="#a#">"##,
            false,
        ),
        (
            r##"<cfif x><cfset a='read'><cfelse><cfset a='write'></cfif><cffile action="#a#">"##,
            true,
        ),
        (r#"<cffile action='write' file='read'>"#, false),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.cfm"))
            .file_type(filefacts::FileType::Cfml)
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.cfm".into(),
            file_type: "cfml".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().iter().cloned().collect(),
            ..Default::default()
        });
        let ctx =
            EvaluationContext::new(&report, source.as_bytes(), FileType::Cfml, &[], None, None);
        assert_eq!(
            super::eval_call(
                Some(&"cffile".into()),
                None,
                None,
                Some(&filter),
                None,
                super::CallSite::default(),
                &ctx
            )
            .matched,
            expected,
            "{source}"
        );
    }
    for (selection, valid) in [
        ("{whole_value: '^read$'}", true),
        ("{whole_number: 0}", true),
        ("{whole_number: 0, whole_value: x}", false),
        ("{whole_number: 0, value: x}", false),
        ("{whole_number: 0, call: f}", false),
        (
            "{whole_number: 0, through: [{call: f, arguments: [0]}]}",
            false,
        ),
        ("{whole_value: '['}", false),
        ("{whole_value: x, value: x}", false),
        ("{whole_value: x, member: x}", false),
        ("{whole_value: x, call: f}", false),
        ("{whole_value: x, literal: x}", false),
        (
            "{whole_value: x, through: [{call: f, arguments: [0]}]}",
            false,
        ),
    ] {
        let condition: Condition = crate::yaml::from_str(&format!(
            "type: symbol\nkind: call\nexact: cffile\narg:\n  from: {selection}\n"
        ))
        .unwrap();
        assert_eq!(condition.validate().is_ok(), valid, "{selection}");
    }
}

#[test]
fn named_field_absence_requires_a_concrete_attribute_map() {
    use crate::composite_rules::{
        Condition, condition::ArgFilter, context::EvaluationContext, types::FileType,
    };
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filter: ArgFilter =
        crate::yaml::from_str("index: 0\nfrom: {field: outputfile, field_absent: true}\n").unwrap();
    for (source, expected) in [
        (
            r#"<cfexecute name='reporter' outputfile='/srv/out'>"#,
            false,
        ),
        (r#"<cfexecute OUTPUTFILE='' name='reporter'>"#, false),
        (
            r##"<cfexecute name='reporter' outputfile="#form.path#">"##,
            false,
        ),
        (
            r##"<cfexecute name='reporter' outputfile="#opaque()#">"##,
            false,
        ),
        (
            r##"<cfexecute name='reporter' outputfile="#GetTempDirectory()#tmp#counter#.txt">"##,
            false,
        ),
        (r#"<cfexecute name='reporter'>"#, true),
        (
            r#"<cfexecute name='reporter' arguments='outputfile=/srv/out'>"#,
            true,
        ),
        (
            r#"<cfexecute name='reporter' outputfileName='/srv/out'>"#,
            true,
        ),
        (r#"<cfhttp outputfile='/srv/out'>"#, false),
        (
            r#"<!--- <cfexecute name='reporter' outputfile='/srv/out'> --->"#,
            false,
        ),
        (
            r#"<cfset text="<cfexecute name='reporter' outputfile='/srv/out'>">"#,
            false,
        ),
        (
            r#"<cfexecute name='reporter' outputfile='a' OUTPUTFILE='b'>"#,
            false,
        ),
        (r#"<cfexecute name='reporter' outputfile="#, false),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.cfm"))
            .file_type(filefacts::FileType::Cfml)
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.cfm".into(),
            file_type: "cfml".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().iter().cloned().collect(),
            ..Default::default()
        });
        let ctx =
            EvaluationContext::new(&report, source.as_bytes(), FileType::Cfml, &[], None, None);
        assert_eq!(
            super::eval_call(
                Some(&"cfexecute".into()),
                None,
                None,
                Some(&filter),
                None,
                super::CallSite::default(),
                &ctx
            )
            .matched,
            expected,
            "{source}"
        );
    }
    for (selection, valid) in [
        ("{field: outputfile, field_absent: true}", true),
        ("{field_absent: true}", false),
        ("{field: '', field_absent: true}", false),
        (
            "{field: outputfile, field_absent: true, field_exists: true}",
            false,
        ),
        ("{field: outputfile, field_absent: true, call: f}", false),
        (
            "{field: outputfile, field_absent: true, through: [{call: f, arguments: [0]}]}",
            false,
        ),
    ] {
        let condition: Condition = crate::yaml::from_str(&format!(
            "type: symbol\nkind: call\nexact: cfexecute\narg:\n  from: {selection}\n"
        ))
        .unwrap();
        assert_eq!(condition.validate().is_ok(), valid, "{selection}");
    }
}

#[test]
fn named_field_presence_requires_a_real_projected_field() {
    use crate::composite_rules::{
        Condition, condition::ArgFilter, context::EvaluationContext, types::FileType,
    };
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let filter: ArgFilter =
        crate::yaml::from_str("index: 0\nfrom: {field: outputfile, field_exists: true}\n").unwrap();
    for (source, expected) in [
        (r#"<cfexecute name='reporter' outputfile='/srv/out'>"#, true),
        (r#"<cfexecute OUTPUTFILE='' name='reporter'>"#, true),
        (
            r##"<cfexecute name='reporter' outputfile="#form.path#">"##,
            true,
        ),
        (
            r##"<cfexecute name='reporter' outputfile="#opaque()#">"##,
            true,
        ),
        (
            r##"<cfexecute name='reporter' outputfile="#GetTempDirectory()#tmp#counter#.txt">"##,
            true,
        ),
        (r#"<cfexecute name='reporter'>"#, false),
        (
            r#"<cfexecute name='reporter' arguments='outputfile=/srv/out'>"#,
            false,
        ),
        (
            r#"<cfexecute name='reporter' outputfileName='/srv/out'>"#,
            false,
        ),
        (r#"<cfhttp outputfile='/srv/out'>"#, false),
        (
            r#"<!--- <cfexecute name='reporter' outputfile='/srv/out'> --->"#,
            false,
        ),
        (
            r#"<cfset text="<cfexecute name='reporter' outputfile='/srv/out'>">"#,
            false,
        ),
        (
            r#"<cfexecute name='reporter' outputfile='a' OUTPUTFILE='b'>"#,
            false,
        ),
        (r#"<cfexecute name='reporter' outputfile="#, false),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.cfm"))
            .file_type(filefacts::FileType::Cfml)
            .open(source.as_bytes());
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.cfm".into(),
            file_type: "cfml".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: parsed.flow().cloned(),
            symbols: parsed.symbols().iter().cloned().collect(),
            ..Default::default()
        });
        let ctx =
            EvaluationContext::new(&report, source.as_bytes(), FileType::Cfml, &[], None, None);
        assert_eq!(
            super::eval_call(
                Some(&"cfexecute".into()),
                None,
                None,
                Some(&filter),
                None,
                super::CallSite::default(),
                &ctx
            )
            .matched,
            expected,
            "{source}"
        );
    }
    for (selection, valid) in [
        ("{field: outputfile, field_exists: true}", true),
        ("{field_exists: true}", false),
        ("{field: '', field_exists: true}", false),
        ("{field: outputfile, field_exists: false}", false),
        ("{field: outputfile, field_exists: true, value: x}", false),
        (
            "{field: outputfile, field_exists: true, whole_value: x}",
            false,
        ),
        ("{field: outputfile, field_exists: true, member: x}", false),
        ("{field: outputfile, field_exists: true, call: f}", false),
        ("{field: outputfile, field_exists: true, literal: x}", false),
        (
            "{field: outputfile, field_exists: true, through: [{call: f, arguments: [0]}]}",
            false,
        ),
    ] {
        let condition: Condition = crate::yaml::from_str(&format!(
            "type: symbol\nkind: call\nexact: cfexecute\narg:\n  from: {selection}\n"
        ))
        .unwrap();
        assert_eq!(condition.validate().is_ok(), valid, "{selection}");
    }
}

#[test]
fn field_presence_handles_alternatives_and_opaque_objects() {
    use crate::composite_rules::{
        condition::ArgFilter, context::EvaluationContext, types::FileType,
    };
    use crate::types::{AnalysisReport, FilefactsView, TargetInfo};
    let source = b"<cfexecute name='reporter' outputfile='/srv/out'>";
    let filter: ArgFilter =
        crate::yaml::from_str("index: 0\nfrom: {field: outputfile, field_exists: true}\n").unwrap();
    for (mode, expected) in [
        ("mixed", true),
        ("missing", false),
        ("unknown", false),
        ("cycle", false),
        ("invalid", false),
    ] {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("a.cfm"))
            .file_type(filefacts::FileType::Cfml)
            .open(source);
        let mut flow = parsed.flow().unwrap().clone();
        let call = flow
            .values
            .iter()
            .position(|v| v.target.as_deref() == Some("cfexecute"))
            .unwrap();
        let present = flow.values[call].inputs[0];
        let mut absent = flow.values[present].clone();
        absent.fields.remove("outputfile");
        let missing = flow.values.len();
        flow.values.push(absent);
        let mut alternative = flow.values[0].clone();
        alternative.kind = filefacts::FlowKind::Alternative;
        let id = flow.values.len();
        alternative.inputs = match mode {
            "mixed" => vec![present, missing],
            "missing" => vec![missing],
            "unknown" => vec![0],
            "cycle" => vec![id],
            _ => vec![usize::MAX],
        };
        flow.values.push(alternative);
        flow.values[call].inputs[0] = id;
        let mut report = AnalysisReport::new(TargetInfo {
            path: "a.cfm".into(),
            file_type: "cfml".into(),
            size_bytes: source.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        report.filefacts = Some(FilefactsView {
            flow: Some(flow),
            symbols: parsed.symbols().iter().cloned().collect(),
            ..Default::default()
        });
        let ctx = EvaluationContext::new(&report, source, FileType::Cfml, &[], None, None);
        assert_eq!(
            super::eval_call(
                Some(&"cfexecute".into()),
                None,
                None,
                Some(&filter),
                None,
                super::CallSite::default(),
                &ctx
            )
            .matched,
            expected,
            "{mode}"
        );
    }
}
