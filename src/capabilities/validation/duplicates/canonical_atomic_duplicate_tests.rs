use super::*;

#[test]
fn platform_equivalence_does_not_confuse_overlap_with_coverage() {
    let unix = [Platform::Unix, Platform::Windows];
    let desktop = [Platform::Linux, Platform::MacOS, Platform::Windows];
    assert!(!platforms_equivalent(&unix, &desktop));
    assert!(!platforms_equivalent(&desktop, &unix));
    assert!(platforms_overlap(&unix, &[Platform::FreeBsd]));
    assert!(!platforms_overlap(&desktop, &[Platform::FreeBsd]));
    assert!(!platforms_equivalent(
        &[Platform::Appliance],
        &[Platform::RouterOs]
    ));
    assert!(platforms_equivalent(
        &[Platform::Appliance, Platform::RouterOs],
        &[Platform::Appliance],
    ));
    assert!(platforms_equivalent(&[], &[Platform::All]));
    assert!(!platforms_equivalent(&[], &[Platform::Unix]));
    assert!(platforms_equivalent(
        &[Platform::Windows, Platform::Unix, Platform::FreeBsd],
        &unix,
    ));
}

#[test]
fn platform_only_difference_is_reported_for_shared_matcher() {
    let (mut a, _) = dos_pair();
    a.platforms = vec![Platform::Unix, Platform::Windows];
    let mut b = a.clone();
    b.id = "desktop-only".into();
    b.platforms = vec![Platform::Linux, Platform::MacOS, Platform::Windows];
    let issues = find_atomic_logic_duplicates(&[a, b]);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].2.contains("platforms:"));
}

fn dos_pair() -> (TraitDefinition, TraitDefinition) {
    let a: TraitDefinition = crate::yaml::from_str(
        "id: dos-list-of-lists-call\n\
             desc: DOS list-of-lists interrupt\n\
             crit: notable\n\
             conf: 0.88\n\
             platforms: [windows, unix]\n\
             for: [dos_com, staticlib]\n\
             size_max: 65536\n\
             if: {type: hex, pattern: 'B4 52 E8'}\n",
    )
    .unwrap();
    let mut b = a.clone();
    b.id = "dos-get-list-of-lists-near".into();
    b.conf = 0.80;
    b.r#for.push(RuleFileType::Data);
    (a, b)
}

#[test]
fn overlapping_scope_and_small_confidence_difference_is_reported() {
    let (a, b) = dos_pair();
    let issues = find_atomic_logic_duplicates(&[a, b]);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].2.contains("for:"));
    assert!(issues[0].2.contains("conf: 0.88 vs 0.8"));
}

#[test]
fn scope_duplicates_respect_filetype_caps() {
    let (mut a, mut b) = dos_pair();
    b.conf = a.conf;
    a.r#for = vec![RuleFileType::DosCom, RuleFileType::StaticLib];
    b.r#for = vec![RuleFileType::Data, RuleFileType::Shell];
    let sources = HashMap::new();
    assert!(find_for_only_duplicates(&[a.clone(), b.clone()], &sources).is_empty());
    b.r#for.pop();
    assert_eq!(
        find_for_only_duplicates(&[a.clone(), b.clone()], &sources).len(),
        1
    );
    b.r#for = vec![
        RuleFileType::DosCom,
        RuleFileType::Data,
        RuleFileType::Shell,
    ];
    assert_eq!(find_for_only_duplicates(&[a, b], &sources).len(), 1);
}

#[test]
fn confidence_is_not_rounded_away() {
    let (a, mut b) = dos_pair();
    b.conf = 0.881;
    // Scope-only cannot assume these verdict confidences are identical.
    assert!(find_for_only_duplicates(&[a.clone(), b.clone()], &HashMap::new()).is_empty());
    assert_eq!(find_atomic_logic_duplicates(&[a, b]).len(), 1);
}

#[test]
fn disjoint_scopes_are_not_overlapping_logic_duplicates() {
    let (a, b) = dos_pair();
    let mut disjoint_file = b.clone();
    disjoint_file.r#for = vec![RuleFileType::Shell];
    assert!(find_atomic_logic_duplicates(&[a.clone(), disjoint_file]).is_empty());
    let mut linux = a.clone();
    linux.platforms = vec![Platform::Linux];
    let mut windows = b.clone();
    windows.platforms = vec![Platform::Windows];
    assert!(find_atomic_logic_duplicates(&[linux, windows]).is_empty());
    let mut x86 = a;
    x86.arch = vec![Arch::X86];
    let mut arm = b;
    arm.arch = vec![Arch::Arm];
    assert!(find_atomic_logic_duplicates(&[x86.clone(), arm.clone()]).is_empty());
    arm.conf = x86.conf;
    assert!(find_for_only_duplicates(&[x86.clone(), arm.clone()], &HashMap::new()).is_empty());
    arm.r#for = x86.r#for.clone();
    let mut exact = Vec::new();
    find_duplicate_atomic_traits(&[x86, arm], &mut exact);
    assert!(exact.is_empty());
}

#[test]
fn exact_check_shares_default_and_scope_order_normalization() {
    let (a, mut b) = dos_pair();
    b.r#for = a.r#for.iter().rev().cloned().collect();
    b.platforms.reverse();
    b.count_min = Some(1);
    let mut exact = Vec::new();
    find_duplicate_atomic_traits(&[a, b], &mut exact);
    assert_eq!(exact.len(), 1);
}

#[test]
fn explicit_exists_true_uses_the_same_exact_matcher() {
    let mut a: TraitDefinition = crate::yaml::from_str(
        "id: field-present\ndesc: Field present\nif: {type: value, path: name}\n",
    )
    .unwrap();
    let mut b = a.clone();
    a.id = "a".into();
    b.id = "b".into();
    if let Condition::Kv(query) = &mut b.r#if {
        query.exists = Some(true);
    } else {
        panic!("expected a value query");
    }
    let mut exact = Vec::new();
    find_duplicate_atomic_traits(&[a, b], &mut exact);
    assert_eq!(exact.len(), 1);
}

#[test]
fn string_duplicate_check_respects_count_and_density() {
    let mut a: TraitDefinition = crate::yaml::from_str(
        "id: repeated-name\ndesc: Repeated name\ncrit: notable\nfor: [shell]\nif: {type: text, word: splarm}\n",
    ).unwrap();
    a.defined_in = "a.yaml".into();
    let mut b = a.clone();
    b.id = "other-name".into();
    b.defined_in = "b.yaml".into();
    let check = |a: &TraitDefinition, b: &TraitDefinition| {
        let mut entries = extract_patterns(a);
        entries.extend(extract_patterns(b));
        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&ExtractedPatterns(entries), &mut warnings);
        warnings
    };
    assert_eq!(check(&a, &b).len(), 1);
    b.count_min = Some(1);
    assert_eq!(check(&a, &b).len(), 1);
    a.count_min = Some(2);
    b.count_min = Some(6);
    assert!(check(&a, &b).is_empty());
    b.count_min = a.count_min;
    assert_eq!(check(&a, &b).len(), 1);
    b.count_max = Some(12);
    assert!(check(&a, &b).is_empty());
    b.count_max = None;
    b.per_kb_min = Some(0.5);
    assert!(check(&a, &b).is_empty());
    a.per_kb_min = b.per_kb_min;
    assert_eq!(check(&a, &b).len(), 1);
    b.per_kb_max = Some(3.0);
    assert!(check(&a, &b).is_empty());
}

#[test]
fn different_thresholds_keep_distinct_observations() {
    let (a, mut b) = dos_pair();
    b.count_min = Some(6);
    let mut exact = Vec::new();
    find_duplicate_atomic_traits(&[a.clone(), b.clone()], &mut exact);
    assert!(exact.is_empty());
    assert!(find_for_only_duplicates(&[a.clone(), b.clone()], &HashMap::new()).is_empty());
    assert!(find_atomic_logic_duplicates(&[a, b]).is_empty());
}

#[test]
fn conditional_verdicts_are_not_identical_predicates() {
    let (a, mut b) = dos_pair();
    b.r#for = a.r#for.clone();
    b.conf = a.conf;
    b.downgrade = Some(
        crate::yaml::from_str(
            "any:\n  - id: metadata/package/testing/presence/harness::test-directory-path\n",
        )
        .unwrap(),
    );
    let mut exact = Vec::new();
    find_duplicate_atomic_traits(&[a.clone(), b.clone()], &mut exact);
    assert!(exact.is_empty());
    assert!(find_for_only_duplicates(&[a.clone(), b.clone()], &HashMap::new()).is_empty());
    let issues = find_atomic_logic_duplicates(&[a, b]);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].2.contains("downgrade: differs"));
}
