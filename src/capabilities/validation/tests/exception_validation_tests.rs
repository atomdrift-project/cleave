use crate::capabilities::validation::taxonomy::{
    find_benign_misplaced, find_exception_atomic_traits, find_exception_inline_conditions,
    find_exception_non_notable_members, find_exception_positive_refs, find_unreferenced_exceptions,
};
use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions};
use crate::composite_rules::{Condition, TraitDefinition};
use crate::types::Criticality;
use std::collections::HashMap;

fn tcond(id: &str) -> Condition {
    Condition::Trait { id: id.to_string() }
}

fn inline_cond() -> Condition {
    Condition::Syscall {
        name: Some(vec!["socket".to_string()]),
        number: None,
        arch: None,
        args: Vec::new(),
    }
}

fn atom(id: &str, crit: Criticality) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "d".to_string(),
        crit,
        ..Default::default()
    }
}

fn comp(id: &str, crit: Criticality) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "d".to_string(),
        crit,
        ..Default::default()
    }
}

fn with_all(mut c: CompositeTrait, refs: &[&str]) -> CompositeTrait {
    c.all = Some(refs.iter().map(|r| tcond(r)).collect());
    c
}

fn with_any(mut c: CompositeTrait, refs: &[&str]) -> CompositeTrait {
    c.any = Some(refs.iter().map(|r| tcond(r)).collect());
    c
}

fn with_unless(mut c: CompositeTrait, refs: &[&str]) -> CompositeTrait {
    c.unless = Some(refs.iter().map(|r| tcond(r)).collect());
    c
}

fn sources(ids: &[&str]) -> HashMap<String, String> {
    ids.iter()
        .map(|i| ((*i).to_string(), "test.yaml".to_string()))
        .collect()
}

// ---- V1: only composites may be crit: exception ----

#[test]
fn v1_flags_atomic_exception_only() {
    let traits = vec![
        atom("micro-behaviors/x::a", Criticality::Exception),
        atom("micro-behaviors/x::b", Criticality::Notable),
    ];
    let src = sources(&["micro-behaviors/x::a", "micro-behaviors/x::b"]);
    let v = find_exception_atomic_traits(&traits, &src);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].0, "micro-behaviors/x::a");
}

// ---- V2: exception referenced as positive evidence ----

#[test]
fn v2_flags_exact_positive_ref_from_non_exception() {
    let composites = vec![
        comp(
            "well-known/tool/foo::benign-pattern",
            Criticality::Exception,
        ),
        with_all(
            comp("objectives/c2::beacon", Criticality::Suspicious),
            &["well-known/tool/foo::benign-pattern"],
        ),
    ];
    let src = sources(&[
        "well-known/tool/foo::benign-pattern",
        "objectives/c2::beacon",
    ]);
    let v = find_exception_positive_refs(&[], &composites, &src);
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].0, "objectives/c2::beacon");
}

#[test]
fn v2_flags_exact_positive_ref_in_any_clause() {
    let composites = vec![
        comp(
            "well-known/tool/foo::benign-pattern",
            Criticality::Exception,
        ),
        with_any(
            comp("objectives/c2::beacon", Criticality::Suspicious),
            &["well-known/tool/foo::benign-pattern"],
        ),
    ];
    let src = sources(&[
        "well-known/tool/foo::benign-pattern",
        "objectives/c2::beacon",
    ]);
    let v = find_exception_positive_refs(&[], &composites, &src);
    assert_eq!(v.len(), 1, "{v:?}");
}

#[test]
fn v2_ignores_directory_ref_containing_exception() {
    // A bare-directory positive ref that *contains* an exception is NOT a violation —
    // the runtime excludes the exception from directory expansion.
    let composites = vec![
        comp(
            "objectives/tools/foo::benign-pattern",
            Criticality::Exception,
        ),
        with_all(
            comp("objectives/c2::beacon", Criticality::Suspicious),
            &["objectives/tools"],
        ),
    ];
    let src = sources(&[
        "objectives/tools/foo::benign-pattern",
        "objectives/c2::beacon",
    ]);
    let v = find_exception_positive_refs(&[], &composites, &src);
    assert!(v.is_empty(), "directory ref should not be flagged: {v:?}");
}

#[test]
fn v2_exempts_exception_parent() {
    let composites = vec![
        comp("well-known/tool/a::exc-a", Criticality::Exception),
        with_all(
            comp("well-known/tool/b::exc-b", Criticality::Exception),
            &["well-known/tool/a::exc-a"],
        ),
    ];
    let src = sources(&["well-known/tool/a::exc-a", "well-known/tool/b::exc-b"]);
    let v = find_exception_positive_refs(&[], &composites, &src);
    assert!(
        v.is_empty(),
        "exception parent may compose exceptions: {v:?}"
    );
}

#[test]
fn v2_allows_unless_ref_to_exception() {
    let composites = vec![
        comp(
            "well-known/tool/foo::benign-pattern",
            Criticality::Exception,
        ),
        with_unless(
            comp("objectives/c2::beacon", Criticality::Suspicious),
            &["well-known/tool/foo::benign-pattern"],
        ),
    ];
    let src = sources(&[
        "well-known/tool/foo::benign-pattern",
        "objectives/c2::beacon",
    ]);
    let v = find_exception_positive_refs(&[], &composites, &src);
    assert!(v.is_empty(), "unless ref is fine: {v:?}");
}

// ---- V3: unreferenced exceptions ----

#[test]
fn v3_flags_unreferenced_exception() {
    let composites = vec![comp("well-known/tool/foo::lonely", Criticality::Exception)];
    let src = sources(&["well-known/tool/foo::lonely"]);
    let v = find_unreferenced_exceptions(&[], &composites, &src);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].0, "well-known/tool/foo::lonely");
}

#[test]
fn v3_exact_unless_ref_satisfies() {
    let composites = vec![
        comp("well-known/tool/foo::exc", Criticality::Exception),
        with_unless(
            comp("objectives/c2::beacon", Criticality::Suspicious),
            &["well-known/tool/foo::exc"],
        ),
    ];
    let src = sources(&["well-known/tool/foo::exc", "objectives/c2::beacon"]);
    let v = find_unreferenced_exceptions(&[], &composites, &src);
    assert!(v.is_empty(), "{v:?}");
}

#[test]
fn v3_exception_parent_directory_ref_satisfies() {
    // An exception parent IS allowed to assemble a directory of exceptions, so a
    // directory ref from one reaches (references) the exceptions beneath it.
    let composites = vec![
        comp("objectives/tools/foo::exc", Criticality::Exception),
        with_all(
            comp("objectives/tools::bundle", Criticality::Exception),
            &["objectives/tools"],
        ),
        with_unless(
            comp("objectives/c2::beacon", Criticality::Suspicious),
            &["objectives/tools::bundle"],
        ),
    ];
    let src = sources(&[
        "objectives/tools/foo::exc",
        "objectives/tools::bundle",
        "objectives/c2::beacon",
    ]);
    let v = find_unreferenced_exceptions(&[], &composites, &src);
    // foo::exc is reached by the bundle's directory ref; the bundle by the
    // beacon's unless. Neither is unreferenced.
    assert!(v.is_empty(), "{v:?}");
}

#[test]
fn v3_directory_ref_does_not_satisfy() {
    // Only an exact ref reaches an exception; a directory ref leaves it dead.
    let composites = vec![
        comp("objectives/tools/foo::exc", Criticality::Exception),
        with_unless(
            comp("objectives/c2::beacon", Criticality::Suspicious),
            &["objectives/tools"],
        ),
    ];
    let src = sources(&["objectives/tools/foo::exc", "objectives/c2::beacon"]);
    let v = find_unreferenced_exceptions(&[], &composites, &src);
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].0, "objectives/tools/foo::exc");
}

// ---- V4: members must be exactly notable (or another exception) ----

#[test]
fn v4_allows_notable_and_exception_members() {
    let traits = vec![atom("objectives/x::n", Criticality::Notable)];
    let composites = vec![
        comp("well-known/tool/sub::exc-sub", Criticality::Exception),
        with_all(
            comp("well-known/tool/foo::exc", Criticality::Exception),
            &["objectives/x::n", "well-known/tool/sub::exc-sub"],
        ),
    ];
    let src = sources(&[
        "objectives/x::n",
        "well-known/tool/sub::exc-sub",
        "well-known/tool/foo::exc",
    ]);
    let v = find_exception_non_notable_members(&traits, &composites, &src);
    assert!(v.is_empty(), "{v:?}");
}

#[test]
fn v4_flags_baseline_and_suspicious_members() {
    let traits = vec![
        atom("objectives/x::base", Criticality::Baseline),
        atom("objectives/x::susp", Criticality::Suspicious),
    ];
    let composites = vec![with_all(
        comp("well-known/tool/foo::exc", Criticality::Exception),
        &["objectives/x::base", "objectives/x::susp"],
    )];
    let src = sources(&[
        "objectives/x::base",
        "objectives/x::susp",
        "well-known/tool/foo::exc",
    ]);
    let v = find_exception_non_notable_members(&traits, &composites, &src);
    assert_eq!(v.len(), 2, "{v:?}");
}

#[test]
fn v4_directory_member_requires_notable_non_exceptions() {
    let traits = vec![
        atom("objectives/dir::n", Criticality::Notable),
        atom("objectives/dir::base", Criticality::Baseline),
    ];
    let composites = vec![
        comp("objectives/dir::exc-inside", Criticality::Exception),
        with_all(
            comp("well-known/tool/foo::exc", Criticality::Exception),
            &["objectives/dir"],
        ),
    ];
    let src = sources(&[
        "objectives/dir::n",
        "objectives/dir::base",
        "objectives/dir::exc-inside",
        "well-known/tool/foo::exc",
    ]);
    let v = find_exception_non_notable_members(&traits, &composites, &src);
    // Only the baseline under the dir is flagged; the notable and the nested
    // exception are fine.
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].1, "objectives/dir::base");
}

#[test]
fn v4_directory_member_covers_its_subtree_and_nothing_beside_it() {
    // Ids sort `objectives/dir-x` < `objectives/dir/sub` < `objectives/dir::…`
    // < `objectives/dirx`, so the ids beneath the directory are two ranges
    // with its neighbours on either side.
    let traits = vec![
        atom("objectives/dir-x::base", Criticality::Baseline),
        atom("objectives/dir/sub::base", Criticality::Baseline),
        atom("objectives/dir::base", Criticality::Baseline),
        atom("objectives/dir::n", Criticality::Notable),
        atom("objectives/dirx::base", Criticality::Baseline),
    ];
    let composites = vec![with_all(
        comp("well-known/tool/foo::exc", Criticality::Exception),
        &["objectives/dir"],
    )];
    let src = sources(&["well-known/tool/foo::exc"]);
    let v = find_exception_non_notable_members(&traits, &composites, &src);
    let members: Vec<&str> = v.iter().map(|(_, member, _, _)| member.as_str()).collect();
    assert_eq!(
        members,
        ["objectives/dir/sub::base", "objectives/dir::base"]
    );
}

// ---- V5: named traits only (no inline conditions) ----

#[test]
fn v5_flags_inline_condition_in_any_clause() {
    let mut c = comp("well-known/tool/foo::exc", Criticality::Exception);
    c.all = Some(vec![tcond("objectives/x::n")]);
    c.any = Some(vec![inline_cond()]);
    let composites = vec![c];
    let src = sources(&["well-known/tool/foo::exc"]);
    let v = find_exception_inline_conditions(&composites, &src);
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].1, "any");
    assert_eq!(v[0].2, "syscall");
}

#[test]
fn v5_flags_inline_condition_in_downgrade() {
    let mut c = comp("well-known/tool/foo::exc", Criticality::Exception);
    c.all = Some(vec![tcond("objectives/x::n")]);
    c.downgrade = Some(DowngradeConditions {
        any: Some(vec![inline_cond()]),
        all: None,
        needs: None,
        scope: None,
    });
    let composites = vec![c];
    let src = sources(&["well-known/tool/foo::exc"]);
    let v = find_exception_inline_conditions(&composites, &src);
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].1, "downgrade.any");
}

#[test]
fn v5_allows_all_trait_refs() {
    let composites = vec![with_all(
        comp("well-known/tool/foo::exc", Criticality::Exception),
        &["objectives/x::n"],
    )];
    let src = sources(&["well-known/tool/foo::exc"]);
    let v = find_exception_inline_conditions(&composites, &src);
    assert!(v.is_empty(), "{v:?}");
}

// ---- benign-misplaced ----

#[test]
fn benign_flags_objectives_and_wellknown_malware() {
    let traits = vec![atom("objectives/c2::benign-beacon", Criticality::Notable)];
    let mut malware = comp("well-known/malware/trojan::x", Criticality::Notable);
    malware.desc = "safety-context suppressor".to_string();
    let composites = vec![malware];
    let src = sources(&[
        "objectives/c2::benign-beacon",
        "well-known/malware/trojan::x",
    ]);
    let v = find_benign_misplaced(&traits, &composites, &src);
    assert_eq!(v.len(), 2, "{v:?}");
}

#[test]
fn benign_flags_context_and_fp_context_conventions() {
    let traits = vec![
        // `*-context` suppression-context convention (the dominant one in-corpus).
        atom(
            "objectives/supply-chain/trojanized::ghost-theme-preview-context",
            Criticality::Notable,
        ),
        // `fp-context` explicitly, in a description.
        atom(
            "well-known/malware/trojan/x::network-helper",
            Criticality::Component,
        ),
    ];
    let mut traits = traits;
    traits[1].desc = "fp-context for known network library".to_string();
    let src = sources(&[
        "objectives/supply-chain/trojanized::ghost-theme-preview-context",
        "well-known/malware/trojan/x::network-helper",
    ]);
    let v = find_benign_misplaced(&traits, &[], &src);
    assert_eq!(v.len(), 2, "{v:?}");
}

#[test]
fn benign_flags_fp_and_exceptions_suffixes() {
    let traits = vec![
        atom(
            "objectives/anti-static/shape::control-flow-soft-fp",
            Criticality::Component,
        ),
        atom(
            "objectives/anti-static/shape::many-strings-known-fps",
            Criticality::Component,
        ),
        atom(
            "objectives/c2/dropper::curl-pipe-shell-exceptions",
            Criticality::Notable,
        ),
    ];
    let src = sources(&[
        "objectives/anti-static/shape::control-flow-soft-fp",
        "objectives/anti-static/shape::many-strings-known-fps",
        "objectives/c2/dropper::curl-pipe-shell-exceptions",
    ]);
    let v = find_benign_misplaced(&traits, &[], &src);
    assert_eq!(v.len(), 3, "{v:?}");
}

#[test]
fn benign_does_not_flag_plain_detection_rules() {
    // A normal detection rule with no suppression marker is left alone.
    let traits = vec![
        atom("objectives/c2/http::beacon-interval", Criticality::Notable),
        atom(
            "well-known/malware/trojan/x::c2-domain",
            Criticality::Notable,
        ),
    ];
    let src = sources(&[
        "objectives/c2/http::beacon-interval",
        "well-known/malware/trojan/x::c2-domain",
    ]);
    let v = find_benign_misplaced(&traits, &[], &src);
    assert!(v.is_empty(), "{v:?}");
}

#[test]
fn benign_exempts_exception_and_other_tiers() {
    let traits = vec![
        // wrong tier: micro-behaviors is fine
        atom("micro-behaviors/x::benign-thing", Criticality::Baseline),
        // well-known/tool is not malware: fine
        atom("well-known/tool/foo::benign-id", Criticality::Notable),
    ];
    // crit: exception in objectives with "benign" in id — the sanctioned home.
    let composites = vec![comp(
        "objectives/c2::benign-pattern",
        Criticality::Exception,
    )];
    let src = sources(&[
        "micro-behaviors/x::benign-thing",
        "well-known/tool/foo::benign-id",
        "objectives/c2::benign-pattern",
    ]);
    let v = find_benign_misplaced(&traits, &composites, &src);
    assert!(v.is_empty(), "{v:?}");
}
