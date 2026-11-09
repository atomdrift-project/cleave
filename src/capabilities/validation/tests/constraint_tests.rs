use crate::capabilities::validation::constraints::{
    MISSING_CONDITIONS, find_empty_condition_clauses, find_invalid_hex_patterns, find_needs_zero,
    find_none_only_with_proximity, find_pure_alias_traits, find_too_short_patterns,
};
use crate::capabilities::validation::{
    find_many_directory_refs, find_pure_directory_alias_composites, find_redundant_any_refs,
    find_self_referencing_composites,
};
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, FileType, KvQuery, Platform, RawQuery, TraitDefinition,
};
use crate::types::Criticality;
use crate::validation_controls::{Severity, validator_severity};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Helper to create a trait with a trait reference condition
fn create_trait_ref(
    id: &str,
    ref_id: &str,
    crit: Criticality,
    count_min: Option<usize>,
    has_downgrade: bool,
) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test trait".to_string(),
        conf: 1.0,
        crit,
        mbc: None,
        attack: None,
        r#if: Condition::Trait {
            id: ref_id.to_string(),
        },
        size_min: None,
        size_max: None,
        count_min,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: vec![FileType::All],
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        not: None,
        unless: None,
        downgrade: if has_downgrade {
            Some(crate::composite_rules::DowngradeConditions {
                any: Some(vec![Condition::Trait {
                    id: "some-other-trait".to_string(),
                }]),
                all: None,
                needs: None,
                scope: None,
            })
        } else {
            None
        },
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

/// Helper to create a base trait (not a reference)
fn create_base_trait(id: &str, crit: Criticality) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "base trait".to_string(),
        conf: 1.0,
        crit,
        mbc: None,
        attack: None,
        r#if: Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: vec![FileType::All],
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

fn short_raw_trait(id: &str, condition: Condition) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "short raw trait".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        r#if: condition,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: vec![FileType::All],
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

fn raw_exact_with_offsets(
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section: Option<&str>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
) -> Condition {
    Condition::Raw(RawQuery {
        length_min: None,
        length_max: None,
        exact: Some("MZ".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: section.map(String::from),
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        not: None,
    })
}

fn short_hex_trait(pattern: &str, offset: Option<i64>) -> Condition {
    Condition::Hex(crate::composite_rules::condition::HexQuery {
        pattern: pattern.to_string(),
        not: None,
        offset,
        offset_range: None,
        section: None,
        section_offset: None,
        section_offset_range: None,
    })
}

#[test]
fn short_hex_patterns_rejected_unpinned_and_allowed_pinned() {
    // Unpinned two-byte pattern is impossibly short; offset-pinned is fine.
    let traits = vec![
        short_raw_trait("test/hex-unpinned", short_hex_trait("5C ?? 44", None)),
        short_raw_trait("test/hex-pinned", short_hex_trait("5C ?? 44", Some(0))),
    ];
    let violations = find_too_short_patterns(&traits);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].0, "test/hex-unpinned");
}

#[test]
fn hex_alternation_counts_as_one_concrete_byte() {
    // (5C|5D) constrains a full byte, exactly like a nibble wildcard does.
    let traits = vec![short_raw_trait(
        "test/hex-alternation",
        short_hex_trait("A3 (5C|5D) 19", None),
    )];
    assert!(
        find_too_short_patterns(&traits).is_empty(),
        "literal + alternation + literal = 3 concrete bytes"
    );
}

#[test]
fn invalid_hex_patterns_are_reported_as_hard_validation_inputs() {
    let traits = vec![
        short_raw_trait(
            "test/valid-yara-nibble-alternation",
            short_hex_trait("1F 8B 08 (0?|1?)", None),
        ),
        short_raw_trait(
            "test/invalid-hex",
            short_hex_trait("1F 8B 08 (0?|ZZ)", None),
        ),
    ];
    let violations = find_invalid_hex_patterns(&traits);
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].0, "test/invalid-hex");
    assert!(violations[0].2.contains("invalid"));
    assert_eq!(
        validator_severity("invalid-hex-pattern"),
        Severity::Hard,
        "unparseable hex must fail even in --soft validation"
    );
}

#[test]
fn short_patterns_allow_exact_or_limited_byte_offsets() {
    let traits = vec![
        short_raw_trait(
            "test/absolute-offset",
            raw_exact_with_offsets(Some(0), None, None, None, None),
        ),
        short_raw_trait(
            "test/absolute-range",
            raw_exact_with_offsets(None, Some((0, Some(64))), None, None, None),
        ),
        short_raw_trait(
            "test/section-offset",
            raw_exact_with_offsets(None, None, Some(".text"), Some(16), None),
        ),
        short_raw_trait(
            "test/section-range",
            raw_exact_with_offsets(None, None, Some(".rdata"), None, Some((8, Some(128)))),
        ),
    ];

    assert!(find_too_short_patterns(&traits).is_empty());
}

#[test]
fn short_patterns_reject_open_or_large_byte_ranges() {
    let traits = vec![
        short_raw_trait(
            "test/open-absolute-range",
            raw_exact_with_offsets(None, Some((0, None)), None, None, None),
        ),
        short_raw_trait(
            "test/large-absolute-range",
            raw_exact_with_offsets(None, Some((0, Some(16_384))), None, None, None),
        ),
        short_raw_trait(
            "test/open-section-range",
            raw_exact_with_offsets(None, None, Some(".text"), None, Some((0, None))),
        ),
        short_raw_trait(
            "test/large-section-range",
            raw_exact_with_offsets(None, None, Some(".rdata"), None, Some((0, Some(16_384)))),
        ),
    ];

    let violations = find_too_short_patterns(&traits);
    assert_eq!(violations.len(), 4);
}

#[test]
fn test_pure_alias_detected() {
    // Trait A references Trait B with same criticality and no constraints
    let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
    let alias = create_trait_ref(
        "objectives/test::alias",
        "micro-behaviors/test::base",
        Criticality::Notable, // Same as base
        None,                 // No count_min
        false,                // No downgrade
    );

    let traits = vec![base, alias];
    let violations = find_pure_alias_traits(&traits);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].0, "objectives/test::alias");
    assert_eq!(violations[0].1, "micro-behaviors/test::base");
}

#[test]
fn test_criticality_change_is_still_a_pure_alias() {
    // A different `crit:` used to exempt an alias on the theory that it
    // "adds value". It does not: the alias matches exactly what the base
    // matches, so the file gets the same evidence twice under two names at
    // two severities, and a reader has to work out which id to believe.
    // Promoting is the worse direction — it relabels one matcher's hit as a
    // stronger verdict with no new evidence behind it.
    let base = create_base_trait("micro-behaviors/test::base", Criticality::Baseline);
    let alias = create_trait_ref(
        "objectives/test::upgraded",
        "micro-behaviors/test::base",
        Criticality::Suspicious, // Different from base
        None,
        false,
    );

    let traits = vec![base, alias];
    let violations = find_pure_alias_traits(&traits);

    assert_eq!(violations.len(), 1, "a retiered rename is still a rename");
    assert_eq!(violations[0].0, "objectives/test::upgraded");
}

#[test]
fn test_directory_reference_is_not_a_pure_alias() {
    // `if: id: <dir>/` is an OR across every trait beneath the directory —
    // real logic, not a rename of one trait — so it must stay exempt. The
    // old code skipped it only as a side effect of failing the criticality
    // lookup; with that gone the guard has to be explicit.
    let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
    let alias = create_trait_ref(
        "objectives/test::fans-out",
        "micro-behaviors/test/", // directory, not a single trait
        Criticality::Notable,
        None,
        false,
    );

    let traits = vec![base, alias];
    assert!(
        find_pure_alias_traits(&traits).is_empty(),
        "a directory reference matches many traits, so it is not an alias"
    );
}

#[test]
fn test_count_constraint_not_flagged() {
    // Trait A references Trait B with count_min - this adds value
    let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
    let alias = create_trait_ref(
        "objectives/test::with-count",
        "micro-behaviors/test::base",
        Criticality::Notable,
        Some(5), // Has count_min constraint
        false,
    );

    let traits = vec![base, alias];
    let violations = find_pure_alias_traits(&traits);

    assert!(
        violations.is_empty(),
        "Should not flag traits with count constraints"
    );
}

#[test]
fn test_downgrade_not_flagged() {
    // Trait A references Trait B with downgrade - this adds value
    let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
    let alias = create_trait_ref(
        "objectives/test::with-downgrade",
        "micro-behaviors/test::base",
        Criticality::Notable,
        None,
        true, // Has downgrade
    );

    let traits = vec![base, alias];
    let violations = find_pure_alias_traits(&traits);

    assert!(
        violations.is_empty(),
        "Should not flag traits with downgrade"
    );
}

#[test]
fn test_self_reference_not_flagged() {
    // Trait references itself - this is a different bug, not a pure alias
    let self_ref = create_trait_ref(
        "micro-behaviors/test::self-ref",
        "micro-behaviors/test::self-ref", // Same ID
        Criticality::Notable,
        None,
        false,
    );

    let traits = vec![self_ref];
    let violations = find_pure_alias_traits(&traits);

    assert!(violations.is_empty(), "Should not flag self-references");
}

#[test]
fn test_short_ref_not_flagged() {
    // Short reference without :: or / should not be flagged
    let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
    let short_ref = create_trait_ref(
        "objectives/test::short-ref",
        "base", // Short reference (no :: or /)
        Criticality::Notable,
        None,
        false,
    );

    let traits = vec![base, short_ref];
    let violations = find_pure_alias_traits(&traits);

    assert!(violations.is_empty(), "Should not flag short references");
}

#[test]
fn test_external_ref_not_flagged() {
    // Reference to trait not in our list - can't compare, don't flag
    let alias = create_trait_ref(
        "objectives/test::external-ref",
        "some-external/trait::not-in-list",
        Criticality::Notable,
        None,
        false,
    );

    let traits = vec![alias];
    let violations = find_pure_alias_traits(&traits);

    assert!(
        violations.is_empty(),
        "Should not flag references to unknown traits"
    );
}

#[test]
fn test_multiple_violations() {
    // Multiple pure aliases should all be detected
    let base1 = create_base_trait("micro-behaviors/a::base1", Criticality::Notable);
    let base2 = create_base_trait("micro-behaviors/b::base2", Criticality::Suspicious);

    let alias1 = create_trait_ref(
        "objectives/a::alias1",
        "micro-behaviors/a::base1",
        Criticality::Notable,
        None,
        false,
    );
    let alias2 = create_trait_ref(
        "objectives/b::alias2",
        "micro-behaviors/b::base2",
        Criticality::Suspicious,
        None,
        false,
    );

    let traits = vec![base1, base2, alias1, alias2];
    let violations = find_pure_alias_traits(&traits);

    assert_eq!(violations.len(), 2);
}

fn create_composite_any(id: &str, refs: &[&str]) -> CompositeTrait {
    CompositeTrait {
        required_trait_indices: Vec::new(),
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(
            refs.iter()
                .map(|id| Condition::Trait {
                    id: (*id).to_string(),
                })
                .collect(),
        ),
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

fn dir_traits(dir: &str, ids: &[&str]) -> HashMap<String, HashSet<String>> {
    let mut map = HashMap::new();
    map.insert(
        dir.to_string(),
        ids.iter().map(|id| (*id).to_string()).collect(),
    );
    map
}

#[test]
fn test_pure_directory_alias_composite_detected() {
    let traits = dir_traits(
        "foo/bar",
        &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
    );
    let rules = vec![create_composite_any(
        "other/dir::alias",
        &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
    )];

    let violations = find_pure_directory_alias_composites(&rules, &traits);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].0, "other/dir::alias");
    assert_eq!(violations[0].1, "foo/bar");
}

#[test]
fn test_small_directory_alias_composite_not_flagged() {
    // Three members is small enough that naming them beats the indirection.
    let traits = dir_traits("foo/bar", &["foo/bar::a", "foo/bar::b", "foo/bar::c"]);
    let rules = vec![create_composite_any(
        "other/dir::alias",
        &["foo/bar::a", "foo/bar::b", "foo/bar::c"],
    )];

    assert!(find_pure_directory_alias_composites(&rules, &traits).is_empty());
}

/// A directory whose entire membership is what the rule enumerates.
fn fully_covered(dir: &str, n: usize) -> std::collections::HashMap<String, usize> {
    std::collections::HashMap::from([(dir.to_string(), n)])
}

#[test]
fn test_redundant_any_refs_needs_eight_from_one_directory() {
    let sizes = fully_covered("foo/bar", 8);
    let seven: Vec<String> = (0..7).map(|i| format!("foo/bar::t{i}")).collect();
    let seven_refs: Vec<&str> = seven.iter().map(String::as_str).collect();
    let rule = create_composite_any("other/dir::rule", &seven_refs);
    assert!(
        find_redundant_any_refs(&rule, &sizes).is_empty(),
        "seven refs are still hand-listable"
    );

    let eight: Vec<String> = (0..8).map(|i| format!("foo/bar::t{i}")).collect();
    let eight_refs: Vec<&str> = eight.iter().map(String::as_str).collect();
    let rule = create_composite_any("other/dir::rule", &eight_refs);
    let violations = find_redundant_any_refs(&rule, &sizes);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].1, "foo/bar");
    assert_eq!(violations[0].2, 8);
}

#[test]
fn redundant_any_refs_preserve_nearly_complete_subsets() {
    for (selected, total) in [(8, 10), (21, 23), (99, 100)] {
        let ids: Vec<String> = (0..selected).map(|i| format!("foo/bar::t{i}")).collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let rule = create_composite_any("other/dir::rule", &refs);
        assert!(
            find_redundant_any_refs(&rule, &fully_covered("foo/bar", total)).is_empty(),
            "{selected} of {total} must not be widened to the whole directory"
        );
    }
}

#[test]
fn redundant_any_refs_do_not_count_duplicate_refs_as_coverage() {
    let rule = create_composite_any("other/dir::rule", &["foo/bar::a"; 8]);
    assert!(find_redundant_any_refs(&rule, &fully_covered("foo/bar", 8)).is_empty());
    assert!(find_redundant_any_refs(&rule, &fully_covered("foo/bar", 1)).is_empty());
}

#[test]
fn test_redundant_any_refs_flags_metadata_directory() {
    let refs: Vec<String> = (0..8).map(|i| format!("metadata/foo::t{i}")).collect();
    let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
    let rule = create_composite_any("other/dir::rule", &refs);

    let violations = find_redundant_any_refs(&rule, &fully_covered("metadata/foo", 8));

    assert_eq!(violations.len(), 1, "metadata/ is no longer exempt");
    assert_eq!(violations[0].1, "metadata/foo");
}

/// Eight references into a large directory is not redundancy — it is the
/// rule being specific. Collapsing to `id: <dir>` there would match the
/// other 295 members too. `generic-bundle-id-pattern` enumerates 8 of
/// ~303 ids under `metadata/signature/verified/id`; naming the directory would have
/// matched every signed application, `com.apple.*` included.
#[test]
fn enumerating_a_small_slice_of_a_large_directory_is_not_redundant() {
    let refs: Vec<String> = (0..8)
        .map(|i| format!("metadata/signature/verified/id::t{i}"))
        .collect();
    let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
    let rule = create_composite_any("other/dir::rule", &refs);

    let violations =
        find_redundant_any_refs(&rule, &fully_covered("metadata/signature/verified/id", 303));

    assert!(
        violations.is_empty(),
        "8 of 303 is precision, not redundancy"
    );
}

/// A directory cleave knows nothing about is never flagged: without its
/// size there is no way to tell a collapse from a widening.
#[test]
fn an_unknown_directory_is_not_flagged() {
    let refs: Vec<String> = (0..8).map(|i| format!("foo/bar::t{i}")).collect();
    let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
    let rule = create_composite_any("other/dir::rule", &refs);

    assert!(find_redundant_any_refs(&rule, &std::collections::HashMap::new()).is_empty());
}

#[test]
fn full_directory_conjunction_is_not_an_any_of_alias() {
    let ids = [
        "foo/bar::a",
        "foo/bar::b",
        "foo/bar::c",
        "foo/bar::d",
        "foo/bar::e",
    ];
    let traits = dir_traits("foo/bar", &ids);
    let mut rule = create_composite_any("other/dir::rule", &ids);
    rule.all = rule.any.take();
    assert!(find_many_directory_refs(&rule, &traits).is_empty());
}

#[test]
fn test_same_directory_alias_composite_not_recommended() {
    let traits = dir_traits(
        "foo/bar",
        &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
    );
    let rule = create_composite_any(
        "foo/bar::alias",
        &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
    );

    assert!(
        find_many_directory_refs(&rule, &traits).is_empty(),
        "same-directory replacement would recursively include the composite"
    );
    assert!(
        find_pure_directory_alias_composites(&[rule], &traits).is_empty(),
        "same-directory aliases must not be rewritten as recursive directory refs"
    );
}

#[test]
fn exhaustive_directory_suppressor_is_detected() {
    use crate::capabilities::validation::constraints::find_exhaustive_suppressors;
    fn unless(v: &[&str]) -> Vec<Condition> {
        v.iter()
            .map(|r| Condition::Trait {
                id: (*r).to_string(),
            })
            .collect()
    }

    use crate::composite_rules::condition::MetricsQuery;

    let metric = |id: &str, min: Option<f64>, max: Option<f64>, fts: Vec<FileType>| {
        let mut t = create_trait_ref(id, "x::x", Criticality::Baseline, None, false);
        t.r#if = Condition::Metrics(MetricsQuery {
            field: "exports.count".to_string(),
            min,
            max,
            min_size: None,
            max_size: None,
        });
        t.r#for = fts;
        t
    };

    // Complementary halves of one integer metric, same file types: their
    // union is every file that emits it.
    let none = metric("g/dir::no-exports", None, Some(0.0), vec![FileType::Elf]);
    let some = metric("g/dir::has-exports", Some(1.0), None, vec![FileType::Elf]);

    // The rule that stands down on the whole directory.
    let mut victim = create_trait_ref("v::packer", "x::x", Criticality::Notable, None, false);
    victim.unless = Some(unless(&["g/dir/"]));

    let found = find_exhaustive_suppressors(&[none, some, victim], &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].id, "v::packer");
    assert_eq!(found[0].field, "exports.count");
}

#[test]
fn suppressor_with_a_real_gap_is_not_flagged() {
    use crate::capabilities::validation::constraints::find_exhaustive_suppressors;
    fn unless(v: &[&str]) -> Vec<Condition> {
        v.iter()
            .map(|r| Condition::Trait {
                id: (*r).to_string(),
            })
            .collect()
    }

    use crate::composite_rules::condition::MetricsQuery;

    let ratio = |id: &str, min: Option<f64>, max: Option<f64>| {
        let mut t = create_trait_ref(id, "x::x", Criticality::Baseline, None, false);
        t.r#if = Condition::Metrics(MetricsQuery {
            field: "binary.largest_section_ratio".to_string(),
            min,
            max,
            min_size: None,
            max_size: None,
        });
        t.r#for = vec![FileType::Pe];
        t
    };
    // A continuous metric has no "next value", so 0.1 and 0.95 leave a
    // genuine band uncovered -- this is an ordinary pair of filters.
    let low = ratio("g/dir::small-section", None, Some(0.1));
    let high = ratio("g/dir::dominant-section", Some(0.95), None);
    let mut victim = create_trait_ref("v::rule", "x::x", Criticality::Notable, None, false);
    victim.unless = Some(unless(&["g/dir/"]));

    let found = find_exhaustive_suppressors(&[low, high, victim], &[]);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn disjoint_file_types_are_not_exhaustive() {
    use crate::capabilities::validation::constraints::find_exhaustive_suppressors;
    fn unless(v: &[&str]) -> Vec<Condition> {
        v.iter()
            .map(|r| Condition::Trait {
                id: (*r).to_string(),
            })
            .collect()
    }

    use crate::composite_rules::condition::MetricsQuery;

    let metric = |id: &str, min: Option<f64>, max: Option<f64>, ft: FileType| {
        let mut t = create_trait_ref(id, "x::x", Criticality::Baseline, None, false);
        t.r#if = Condition::Metrics(MetricsQuery {
            field: "exports.count".to_string(),
            min,
            max,
            min_size: None,
            max_size: None,
        });
        t.r#for = vec![ft];
        t
    };
    // No single file is both a PE and an ELF, so neither half ever covers
    // what the other misses. This is the real shape of
    // metadata/binary/symbols/exports/, and it is not this defect.
    let none = metric("g/dir::no-exports", None, Some(0.0), FileType::Pe);
    let some = metric("g/dir::has-exports", Some(1.0), None, FileType::Elf);
    let mut victim = create_trait_ref("v::rule", "x::x", Criticality::Notable, None, false);
    victim.unless = Some(unless(&["g/dir/"]));

    let found = find_exhaustive_suppressors(&[none, some, victim], &[]);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn test_dead_downgrade_detected() {
    use crate::capabilities::validation::constraints::find_dead_downgrades;
    use crate::composite_rules::traits::DowngradeConditions;

    fn dg(any: Option<&[&str]>, all: Option<&[&str]>) -> DowngradeConditions {
        let conv = |v: &[&str]| {
            v.iter()
                .map(|r| Condition::Trait {
                    id: (*r).to_string(),
                })
                .collect::<Vec<_>>()
        };
        DowngradeConditions {
            any: any.map(conv),
            all: all.map(conv),
            needs: None,
            scope: None,
        }
    }
    fn unless(v: &[&str]) -> Vec<Condition> {
        v.iter()
            .map(|r| Condition::Trait {
                id: (*r).to_string(),
            })
            .collect()
    }

    // Whole `any:` clause dead — every leg is also suppressed.
    let mut whole = create_trait_ref("d::whole", "x::x", Criticality::Suspicious, None, false);
    whole.unless = Some(unless(&["g::a"]));
    whole.downgrade = Some(dg(Some(&["g::a"]), None));

    // Partially dead `any:` — one leg survives, so the clause still works.
    let mut partial = create_trait_ref("d::partial", "x::x", Criticality::Suspicious, None, false);
    partial.unless = Some(unless(&["g::a"]));
    partial.downgrade = Some(dg(Some(&["g::a", "g::b"]), None));

    // `all:` needs every leg, so one suppressed leg kills the whole clause.
    let mut all_dead = create_trait_ref("d::all", "x::x", Criticality::Suspicious, None, false);
    all_dead.unless = Some(unless(&["g::a"]));
    all_dead.downgrade = Some(dg(None, Some(&["g::a", "g::b"])));

    // Disjoint unless/downgrade — the ordinary, healthy shape.
    let mut clean = create_trait_ref("d::clean", "x::x", Criticality::Suspicious, None, false);
    clean.unless = Some(unless(&["g::a"]));
    clean.downgrade = Some(dg(Some(&["g::b"]), None));

    let traits = [whole, partial, all_dead, clean];
    let found = find_dead_downgrades(&traits, &[]);

    let ids: Vec<&str> = found.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(ids, ["d::whole", "d::partial", "d::all"]);
    assert!(
        found[0].whole_clause,
        "single dead any: leg is the whole clause"
    );
    assert!(
        !found[1].whole_clause,
        "a surviving any: leg keeps the clause alive"
    );
    assert!(found[2].whole_clause, "all: dies on one suppressed leg");
    assert_eq!(found[2].clause, "all");
    assert!(found.iter().all(|d| !d.is_composite));
}

#[test]
fn test_trait_self_suppression_detected() {
    use crate::capabilities::validation::composite::find_self_suppressing_traits;

    // Direct self-reference in `unless:`.
    let mut direct = create_trait_ref(
        "foo/bar::alias",
        "unrelated/dir::x",
        Criticality::Notable,
        None,
        false,
    );
    direct.unless = Some(vec![Condition::Trait {
        id: "foo/bar::alias".to_string(),
    }]);

    // Own-directory reference in `unless:` — the shape that killed
    // objectives/lateral-movement/ssh/backdoor-deploy::ssh-permit-root.
    let mut via_dir = create_trait_ref(
        "foo/bar::other",
        "unrelated/dir::x",
        Criticality::Notable,
        None,
        false,
    );
    via_dir.unless = Some(vec![Condition::Trait {
        id: "foo/bar".to_string(),
    }]);

    // Self-reference in `downgrade:` — pins the trait a level below its
    // declared criticality forever.
    let mut downgraded = create_trait_ref(
        "foo/bar::pinned",
        "unrelated/dir::x",
        Criticality::Notable,
        None,
        false,
    );
    downgraded.downgrade = Some(crate::composite_rules::traits::DowngradeConditions {
        any: Some(vec![Condition::Trait {
            id: "foo/bar::pinned".to_string(),
        }]),
        all: None,
        needs: None,
        scope: None,
    });

    // A reference to a different directory is legitimate.
    let mut clean = create_trait_ref(
        "foo/bar::fine",
        "unrelated/dir::x",
        Criticality::Notable,
        None,
        false,
    );
    clean.unless = Some(vec![Condition::Trait {
        id: "other/dir".to_string(),
    }]);

    let traits = [direct, via_dir, downgraded, clean];
    let violations = find_self_suppressing_traits(&traits);

    assert_eq!(violations.len(), 3, "{violations:?}");
    assert_eq!(violations[0].0.id, "foo/bar::alias");
    assert_eq!(violations[0].2, "unless");
    assert_eq!(violations[1].0.id, "foo/bar::other");
    assert_eq!(violations[1].1, "foo/bar");
    assert_eq!(violations[2].0.id, "foo/bar::pinned");
    assert_eq!(violations[2].2, "downgrade");
}

#[test]
fn test_composite_suppressed_by_own_leg_detected() {
    use crate::capabilities::validation::composite::find_leg_suppressing_composites;
    use crate::composite_rules::traits::{DowngradeConditions, Scope};

    fn refs(ids: &[&str]) -> Vec<Condition> {
        ids.iter()
            .map(|id| Condition::Trait {
                id: (*id).to_string(),
            })
            .collect()
    }
    fn rule(id: &str, all: &[&str], any: &[&str], unless: &[&str]) -> CompositeTrait {
        let mut r = create_composite_any(id, any);
        r.all = (!all.is_empty()).then(|| refs(all));
        r.any = (!any.is_empty()).then(|| refs(any));
        r.unless = (!unless.is_empty()).then(|| refs(unless));
        r
    }

    // The shape that killed pkginfo-minimal-shell-package: the unless
    // directory contains a required all: leg.
    let dir_covers_all = rule(
        "x/y::shell",
        &["meta/versioning/scheme::lowest", "meta/eco::core"],
        &[],
        &["meta/versioning/"],
    );
    // Every any: leg covered (by different suppressors).
    let covers_every_any = rule(
        "x/y::every-any",
        &["a/b::base"],
        &["c/d::one", "e/f::two"],
        &["c/d/", "e/f::two"],
    );
    // One any: leg survives, so the rule can still fire.
    let one_any_survives = rule(
        "x/y::survives",
        &["a/b::base"],
        &["c/d::one", "e/f::two"],
        &["c/d/"],
    );
    // A directory leg inside the unless directory.
    let dir_leg_in_dir = rule("x/y::dir-leg", &["m/n/o/"], &[], &["m/n"]);
    // Archive scope: the leg can come from another member, not provable.
    let mut archive = rule("x/y::archive", &["m/n::leg"], &[], &["m/n/"]);
    archive.scope = Some(Scope::Archive);
    // A downgrade whose only entry is a required leg pins the tier.
    let mut pinned = rule("x/y::pinned", &["s/t::leg", "u/v::other"], &[], &[]);
    pinned.downgrade = Some(DowngradeConditions {
        any: Some(refs(&["s/t/"])),
        all: None,
        needs: None,
        scope: None,
    });
    // A downgrade that also needs something outside the legs is fine.
    let mut conditional = rule("x/y::conditional", &["s/t::leg"], &[], &[]);
    conditional.downgrade = Some(DowngradeConditions {
        any: None,
        all: Some(refs(&["s/t::leg", "w/z::context"])),
        needs: None,
        scope: None,
    });
    // Prefix of a sibling directory name is not containment.
    let sibling_prefix = rule(
        "x/y::sibling",
        &["meta/versioning-extra::leg"],
        &[],
        &["meta/versioning"],
    );

    let rules = [
        dir_covers_all,
        covers_every_any,
        one_any_survives,
        dir_leg_in_dir,
        archive,
        pinned,
        conditional,
        sibling_prefix,
    ];
    let found = find_leg_suppressing_composites(&rules);
    let got: Vec<(&str, &str, &str, &str)> = found
        .iter()
        .map(|(r, s, l, c)| (r.id.as_str(), s.as_str(), l.as_str(), *c))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "x/y::shell",
                "meta/versioning/",
                "meta/versioning/scheme::lowest",
                "unless"
            ),
            ("x/y::every-any", "c/d/", "c/d::one", "unless"),
            ("x/y::dir-leg", "m/n", "m/n/o/", "unless"),
            ("x/y::pinned", "s/t/", "s/t::leg", "downgrade"),
        ]
    );
}

/// The branches the first leg-suppression test does not reach: which
/// scopes count as file-local, which downgrade shapes can miss a match,
/// and which `any:` clauses can still fire without a covered trait.
#[test]
fn test_leg_suppression_scope_and_clause_boundaries() {
    use crate::capabilities::validation::composite::find_leg_suppressing_composites;
    use crate::composite_rules::traits::{DowngradeConditions, Scope};

    fn refs(ids: &[&str]) -> Option<Vec<Condition>> {
        (!ids.is_empty()).then(|| {
            ids.iter()
                .map(|id| Condition::Trait {
                    id: (*id).to_string(),
                })
                .collect()
        })
    }
    fn rule(id: &str, all: &[&str], unless: &[&str], scope: Option<Scope>) -> CompositeTrait {
        let mut r = create_composite_any(id, &[]);
        r.all = refs(all);
        r.any = None;
        r.unless = refs(unless);
        r.scope = scope;
        r
    }
    fn dg(
        any: &[&str],
        all: &[&str],
        needs: Option<usize>,
        scope: Option<Scope>,
    ) -> DowngradeConditions {
        DowngradeConditions {
            any: refs(any),
            all: refs(all),
            needs,
            scope,
        }
    }

    let leaf_scope = rule("r::leaf-scope", &["a/b::leg"], &["a/b"], Some(Scope::Leaf));
    let package_scope = rule(
        "r::package-scope",
        &["a/b::leg"],
        &["a/b/"],
        Some(Scope::Package),
    );
    let outer_scope = rule(
        "r::outer-scope",
        &["a/b::leg"],
        &["a/b/"],
        Some(Scope::Outer),
    );
    // Leg is a directory; suppressor names the same directory, with and
    // without the slash.
    let same_dir = rule("r::same-dir", &["a/b/"], &["a/b"], None);

    // `any:` with an inline condition can match without any trait, so
    // covering every trait entry does not make the rule dead.
    let mut inline_any = rule("r::inline-any", &[], &["c/d/"], None);
    inline_any.any = Some(vec![
        Condition::Trait {
            id: "c/d::one".to_string(),
        },
        Condition::Syscall {
            name: Some(vec!["socket".to_string()]),
            number: None,
            arch: None,
            args: Vec::new(),
        },
    ]);

    let mut dg_scoped = rule("r::dg-scoped", &["s/t::leg"], &[], None);
    dg_scoped.downgrade = Some(dg(&["s/t/"], &[], None, Some(Scope::Archive)));
    let mut dg_needs_short = rule("r::dg-needs-short", &["s/t::leg"], &[], None);
    dg_needs_short.downgrade = Some(dg(&["s/t/", "x/y::ctx"], &[], Some(2), None));
    let mut dg_needs_met = rule("r::dg-needs-met", &["s/t::leg", "u/v::leg"], &[], None);
    dg_needs_met.downgrade = Some(dg(&["s/t/", "u/v::leg"], &[], Some(2), None));

    let rules = [
        leaf_scope,
        package_scope,
        outer_scope,
        same_dir,
        inline_any,
        dg_scoped,
        dg_needs_short,
        dg_needs_met,
    ];
    let flagged: Vec<(&str, &str)> = find_leg_suppressing_composites(&rules)
        .iter()
        .map(|(r, _, _, clause)| (r.id.as_str(), *clause))
        .collect();
    assert_eq!(
        flagged,
        [
            ("r::leaf-scope", "unless"),
            ("r::same-dir", "unless"),
            ("r::dg-needs-met", "downgrade"),
        ]
    );
}

#[test]
fn test_composite_directory_self_reference_detected() {
    let rule = create_composite_any("foo/bar::alias", &["foo/bar"]);
    let rules = [rule];
    let violations = find_self_referencing_composites(&rules);

    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].0.id, "foo/bar::alias");
    assert_eq!(violations[0].1, "foo/bar");
}

#[test]
fn test_directory_alias_with_constraints_not_flagged() {
    let traits = dir_traits(
        "foo/bar",
        &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
    );
    let mut rule = create_composite_any(
        "foo/bar::alias",
        &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
    );
    rule.needs = Some(2);

    let violations = find_pure_directory_alias_composites(&[rule], &traits);

    assert!(violations.is_empty());
}

#[test]
fn test_single_directory_ref_with_needs_not_flagged_as_alias() {
    // A single `any:` entry that is a *directory* reference with `needs: 2`
    // is a real k-of-N marker (>= 2 distinct member traits), not a pure
    // alias, and must not be flagged by the single-item validator. (The
    // engine weights the dir-ref by its matched-member count.)
    use crate::capabilities::validation::find_single_item_clauses;
    let mut rule =
        create_composite_any("well-known/lib/ffmpeg::marker", &["well-known/lib/ffmpeg"]);
    rule.needs = Some(2);

    assert!(
        find_single_item_clauses(&rule).is_empty(),
        "single directory-ref + needs must not be flagged as a single-item alias"
    );

    // Control: a single *specific* trait ref (with `::`) IS a pure alias.
    let alias = create_composite_any("foo/bar::alias", &["foo/bar::a"]);
    assert_eq!(
        find_single_item_clauses(&alias).len(),
        1,
        "single specific trait ref is a pure alias and must be flagged"
    );
}

#[test]
fn test_kv_exists_with_exact_is_flagged() {
    use crate::capabilities::validation::constraints::find_kv_exists_with_matcher;

    let traits = vec![TraitDefinition {
        id: "test/kv-redundant".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        r#if: Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "scripts.postinstall".to_string(),
            exact: Some("curl".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: Some(false),
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        }),
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: vec![FileType::All],
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];

    let v = find_kv_exists_with_matcher(&traits, &[]);
    assert_eq!(v.len(), 1, "exists: false + exact should be flagged");
}

#[test]
fn test_kv_exists_without_matcher_is_ok() {
    use crate::capabilities::validation::constraints::find_kv_exists_with_matcher;

    let traits = vec![TraitDefinition {
        id: "test/kv-ok".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        r#if: Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: Some(false),
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        }),
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: vec![FileType::All],
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];

    let v = find_kv_exists_with_matcher(&traits, &[]);
    assert!(v.is_empty(), "exists: false without matcher is valid");
}

#[test]
fn test_none_only_with_proximity_is_flagged() {
    let rules = vec![CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/none-prox".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: None,
        unless: Some(vec![Condition::Trait {
            id: "some-trait".to_string(),
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: Some(10),
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];
    let result = find_none_only_with_proximity(&rules);
    assert_eq!(result, vec!["test/none-prox"]);
}

#[test]
fn test_none_with_all_and_proximity_is_ok() {
    let rules = vec![CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/none-plus-all".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Trait {
            id: "some-trait".to_string(),
        }]),
        any: None,
        unless: Some(vec![Condition::Trait {
            id: "other-trait".to_string(),
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: Some(10),
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];
    let result = find_none_only_with_proximity(&rules);
    assert!(result.is_empty());
}

#[test]
fn test_empty_all_with_none_is_flagged() {
    // all: [] + none: [something] should still be flagged — empty all vacuously matches
    let rules = vec![CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/empty-all-none".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![]),
        any: None,
        unless: Some(vec![Condition::Trait {
            id: "some-trait".to_string(),
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];
    let result = find_empty_condition_clauses(&rules);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], ("test/empty-all-none".to_string(), "all"));
}

/// A composite with neither `all:` nor `any:` fires on nothing —
/// `evaluate_with_gates` matches `(None, None)` and bails — so it must be
/// flagged. This is the shape authors actually write, since YAML omits a
/// key rather than spelling out `all: []`.
#[test]
fn test_absent_all_and_any_is_flagged() {
    let rules = vec![CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/no-conditions".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];
    let result = find_empty_condition_clauses(&rules);
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0],
        ("test/no-conditions".to_string(), MISSING_CONDITIONS)
    );
}

/// Filter fields and `unless:` constrain or withhold evidence; they never
/// supply it. A composite carrying only those still fires on nothing.
#[test]
fn test_filters_and_unless_do_not_count_as_conditions() {
    let rules = vec![CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/filters-only".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::Pe],
        for_from_groups: false,
        size_min: Some(512),
        size_max: Some(102_400),
        all: None,
        any: None,
        unless: Some(vec![Condition::Trait {
            id: "some-trait".to_string(),
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];
    let result = find_empty_condition_clauses(&rules);
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0],
        ("test/filters-only".to_string(), MISSING_CONDITIONS)
    );
}

/// A composite that carries real conditions is untouched, and the check
/// only ever inspects composites — a size-only *atomic* trait is legal
/// (`parsing.rs` synthesizes an always-true condition for it) and cannot
/// reach this validator at all.
#[test]
fn test_populated_conditions_are_not_flagged() {
    let rules = vec![CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/has-conditions".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Trait {
            id: "some-trait".to_string(),
        }]),
        any: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];
    assert!(find_empty_condition_clauses(&rules).is_empty());
}

#[test]
fn test_needs_zero_is_flagged() {
    let rules = vec![CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-zero".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![Condition::Trait {
            id: "some-trait".to_string(),
        }]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(0),
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];
    let result = find_needs_zero(&rules);
    assert_eq!(result, vec!["test/needs-zero"]);
}

#[test]
fn test_needs_one_is_not_flagged_by_needs_zero() {
    let rules = vec![CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-one".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![Condition::Trait {
            id: "some-trait".to_string(),
        }]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(1),
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }];
    let result = find_needs_zero(&rules);
    assert!(result.is_empty());
}

#[test]
fn a_symbol_validator_is_a_search_pattern() {
    use crate::capabilities::validation::constraints::find_missing_search_patterns;
    use crate::composite_rules::condition::{StringValidator, SymbolQuery};
    let symbol = |is_check| {
        let mut t = create_base_trait("t::symbol", Criticality::Notable);
        t.r#if = Condition::Symbol(SymbolQuery {
            is_check,
            ..Default::default()
        });
        t
    };
    let typo = "top-npm-packages".parse().ok().map(StringValidator::TypoOf);
    assert!(typo.is_some());
    assert!(find_missing_search_patterns(&[symbol(typo)]).is_empty());
    assert_eq!(find_missing_search_patterns(&[symbol(None)]), ["t::symbol"]);
}
