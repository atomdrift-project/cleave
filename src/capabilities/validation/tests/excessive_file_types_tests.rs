use crate::capabilities::validation::constraints::find_excessive_file_types;
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, FileType, Platform, RawQuery, TraitDefinition,
};
use crate::types::Criticality;
use std::path::PathBuf;

fn trait_with_for(id: &str, types: Vec<FileType>) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
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
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: types,
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

fn trait_with_for_from_groups(id: &str, types: Vec<FileType>) -> TraitDefinition {
    let mut t = trait_with_for(id, types);
    t.for_from_groups = true;
    t
}

#[test]
fn test_under_threshold_not_flagged() {
    let traits = vec![trait_with_for(
        "test::few-types",
        vec![FileType::Elf, FileType::Macho, FileType::Pe],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(result.is_empty());
}

#[test]
fn test_eight_types_accepted() {
    // 8 hand-picked types that don't form a canonical group — accepted
    // (a spread across groups that no single named group expresses).
    let traits = vec![trait_with_for(
        "test::eight-types",
        vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Class,
            FileType::Pyc,
            FileType::Python,
            FileType::Shell,
            FileType::Php,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(result.is_empty(), "8 explicit types should be accepted");
}

#[test]
fn test_exactly_threshold_flagged() {
    // 9 types that don't form a canonical group — must be flagged
    let traits = vec![trait_with_for(
        "test::nine-types",
        vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Class,
            FileType::Pyc,
            FileType::Python,
            FileType::Shell, // not the canonical `binaries` set
            FileType::Php,
            FileType::JavaScript,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "test::nine-types");
    assert_eq!(result[0].1, 9);
}

#[test]
fn test_all_exempt() {
    let traits = vec![trait_with_for("test::all-types", vec![FileType::All])];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(result.is_empty());
}

#[test]
fn test_exact_binaries_group_exempt() {
    // Exact `binaries` expansion must not be flagged — the author used `for: [binaries]`
    // and the parser expanded it; we should not warn them to do what they already did.
    let traits = vec![trait_with_for(
        "test::all-binaries",
        vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Class,
            FileType::Pyc,
            FileType::Beam,
            FileType::Wasm,
            FileType::Dex,
            FileType::StaticLib,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(
        result.is_empty(),
        "exact `binaries` expansion should not warn"
    );
}

#[test]
fn test_exact_scripts_group_exempt() {
    // Exact `scripts` expansion must not be flagged.
    let traits = vec![trait_with_for(
        "test::all-scripts",
        vec![
            FileType::Shell,
            FileType::Batch,
            FileType::Jcl,
            FileType::Python,
            FileType::JavaScript,
            FileType::Ruby,
            FileType::Php,
            FileType::Perl,
            FileType::Lua,
            FileType::PowerShell,
            FileType::AppleScript,
            FileType::Vbs,
            FileType::Mirc,
            FileType::IrcII,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(
        result.is_empty(),
        "exact `scripts` expansion should not warn"
    );
}

#[test]
fn test_exact_source_group_exempt() {
    let traits = vec![trait_with_for(
        "test::all-source",
        vec![
            FileType::TypeScript,
            FileType::Rust,
            FileType::Java,
            FileType::C,
            FileType::Cpp,
            FileType::Go,
            FileType::CSharp,
            FileType::Swift,
            FileType::ObjectiveC,
            FileType::Groovy,
            FileType::Kotlin,
            FileType::Scala,
            FileType::Zig,
            FileType::Elixir,
            FileType::Clojure,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(
        result.is_empty(),
        "exact `source` expansion should not warn"
    );
}

#[test]
fn test_subset_of_source_suggests_source() {
    // All types are within `source` but not the exact canonical set → suggest `source`
    let traits = vec![trait_with_for(
        "test::some-source",
        vec![
            FileType::TypeScript,
            FileType::Rust,
            FileType::Java,
            FileType::C,
            FileType::Cpp,
            FileType::Go,
            FileType::CSharp,
            FileType::Swift,
            FileType::Kotlin,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert_eq!(result.len(), 1);
    assert!(result[0].2.contains("source"));
}

#[test]
fn test_mixed_types_suggest_named_groups() {
    // Mix spanning multiple groups → suggest combining named groups, not `all`
    let traits = vec![trait_with_for(
        "test::mixed",
        vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Python,
            FileType::Shell,
            FileType::Ruby,
            FileType::Rust,
            FileType::Php,
            FileType::Java,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert_eq!(result.len(), 1);
    assert!(result[0].2.contains("named groups"));
    assert!(!result[0].2.contains("[all]"));
}

#[test]
fn test_multi_group_union_exempt() {
    // `for: [scripts, binaries, source]` in YAML expands to the concrete
    // union of those named groups. The validator must not re-warn the
    // author to use groups they already used.
    let scripts = vec![
        FileType::Shell,
        FileType::Batch,
        FileType::Jcl,
        FileType::Python,
        FileType::JavaScript,
        FileType::Ruby,
        FileType::Php,
        FileType::Perl,
        FileType::Lua,
        FileType::PowerShell,
        FileType::AppleScript,
        FileType::Vbs,
        FileType::Mirc,
        FileType::IrcII,
    ];
    let binaries = vec![
        FileType::Elf,
        FileType::Macho,
        FileType::Pe,
        FileType::Class,
        FileType::Pyc,
        FileType::Beam,
        FileType::Wasm,
        FileType::Dex,
        FileType::StaticLib,
    ];
    let source = vec![
        FileType::TypeScript,
        FileType::Rust,
        FileType::Java,
        FileType::C,
        FileType::Cpp,
        FileType::Go,
        FileType::CSharp,
        FileType::Swift,
        FileType::ObjectiveC,
        FileType::Groovy,
        FileType::Kotlin,
        FileType::Scala,
        FileType::Zig,
        FileType::Elixir,
        FileType::Clojure,
    ];
    let combined: Vec<FileType> = scripts.into_iter().chain(binaries).chain(source).collect();
    assert_eq!(combined.len(), 38);
    let traits = vec![trait_with_for("test::multi-group", combined)];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(
        result.is_empty(),
        "union of complete named groups should not be flagged"
    );
}

#[test]
fn test_partial_group_still_flagged() {
    // Cherry-picking types from multiple groups (not complete groups) must still warn.
    // [elf, macho, pe] is a partial binaries group; [python, shell] is partial scripts.
    let traits = vec![trait_with_for(
        "test::partial-groups",
        vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Python,
            FileType::Shell,
            FileType::Ruby,
            FileType::Rust,
            FileType::Php,
            FileType::Lua,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert_eq!(result.len(), 1, "partial group selection should still warn");
}

#[test]
fn test_composite_rule_flagged() {
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test::composite-many".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Class,
            FileType::Pyc,
            FileType::Python,
            FileType::Shell, // not the canonical `binaries` set
            FileType::Php,
            FileType::JavaScript,
        ],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let result = find_excessive_file_types(&[], &[rule]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "test::composite-many");
    assert!(result[0].3); // is_composite
}

#[test]
fn test_from_groups_skips_check_with_many_types() {
    // `for: [binaries, c]` expands to 9 types with for_from_groups=true.
    // After platform filtering the set may be a partial group, but the
    // author already used named groups — don't flag it.
    let traits = vec![trait_with_for_from_groups(
        "test::groups-plus-extra",
        vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Class,
            FileType::Pyc,
            FileType::C,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(
        result.is_empty(),
        "for_from_groups=true should suppress the warning"
    );
}

#[test]
fn test_from_groups_platform_filtered_not_flagged() {
    // `for: [scripts, binaries]` after platform filtering for unix-only:
    // PE/DLL/Batch/VBS removed → partial groups. Still exempt because
    // for_from_groups=true.
    let traits = vec![trait_with_for_from_groups(
        "test::filtered-groups",
        vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Class,
            FileType::Pyc,
            FileType::Shell,
            FileType::Python,
            FileType::JavaScript,
            FileType::Ruby,
            FileType::Php,
            FileType::Perl,
            FileType::Lua,
            FileType::AppleScript,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert!(
        result.is_empty(),
        "platform-filtered groups should not be flagged"
    );
}

#[test]
fn test_not_from_groups_still_flagged() {
    // Same 14 types but for_from_groups=false — author manually listed them.
    let traits = vec![trait_with_for(
        "test::manual-many",
        vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Class,
            FileType::Pyc,
            FileType::Shell,
            FileType::Python,
            FileType::JavaScript,
            FileType::Ruby,
            FileType::Php,
            FileType::Perl,
            FileType::Lua,
            FileType::AppleScript,
        ],
    )];
    let result = find_excessive_file_types(&traits, &[]);
    assert_eq!(result.len(), 1, "manual listing should still be flagged");
}
/// The check must still catch a genuine hand-enumeration: a set no
/// complete group covers.
#[test]
fn partial_enumeration_is_still_reported() {
    let hand_picked = vec![
        FileType::Png,
        FileType::Jpeg,
        FileType::Wav,
        FileType::Elf,
        FileType::Macho,
        FileType::Pe,
        FileType::Python,
        FileType::Shell,
        FileType::Ruby,
    ];
    let violations = find_excessive_file_types(&[trait_with_for("t/handpicked", hand_picked)], &[]);
    assert_eq!(violations.len(), 1, "{violations:?}");
}

/// Every file type belongs to exactly one named group.
///
/// Group membership is how `for:` breadth is judged, so a type in two
/// groups makes that judgement ambiguous: naming one complete group then
/// partially "touches" the other through the shared type and reads as a
/// hand-written enumeration. Dockerfile was in both `manifests` and
/// `build`, and folding SVG into `media` while `Xml` stayed in `manifests`
/// would have reintroduced it. This test is the enforcement.
#[test]
fn named_groups_are_disjoint() {
    use crate::capabilities::validation::constraints::ALL_GROUPS;
    let mut owner: std::collections::HashMap<FileType, &str> = std::collections::HashMap::new();
    let mut clashes = Vec::new();
    for (types, name) in ALL_GROUPS {
        for ft in *types {
            if let Some(prev) = owner.insert(*ft, name) {
                clashes.push(format!("{ft:?} is in both `{prev}` and `{name}`"));
            }
        }
    }
    assert!(
        clashes.is_empty(),
        "file-type groups must be disjoint:\n  {}",
        clashes.join("\n  ")
    );
}

/// A complete named group is expressible however many types it holds.
#[test]
fn each_named_group_is_expressible_on_its_own() {
    use crate::capabilities::validation::constraints::ALL_GROUPS;
    for (types, name) in ALL_GROUPS {
        let violations = find_excessive_file_types(&[trait_with_for("t/g", types.to_vec())], &[]);
        assert!(
            violations.is_empty(),
            "group `{name}` should be expressible: {violations:?}"
        );
    }
}
