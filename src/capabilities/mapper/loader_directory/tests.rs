use std::path::Path;

#[test]
#[allow(clippy::expect_used)]
fn full_validation_rejects_unparseable_yaml_as_a_hard_error() {
    let mut warnings = crate::validation_controls::ValidationIssues::new();
    let error = super::report_validation(
        &mut warnings,
        &["Failed to parse YAML in traits.yaml: unknown field `future_field`".to_string()],
        true,
    )
    .expect_err("unparseable rules must fail full validation");
    let message = format!("{error:#}");
    assert!(
        message.contains("YAML parsing error") || message.contains("parse error"),
        "unexpected validation error: {message}"
    );
    assert!(
        message.contains("traits.yaml"),
        "parse failure should identify its source file: {message}"
    );
}

#[test]
fn registry_policy_is_identified_before_parsing_local_rule_id() {
    let yaml = r#"defaults:
  for: [registry]
  platforms: [all]
composite_rules:
  - id: registry-security-held-package
    desc: Registry reports security hold
    crit: hostile
    scope: file
    any:
      - id: metadata/registry::registry-security-hold
      - id: metadata/registry::registry-security-hold-record
"#;
    let mappings = crate::yaml::from_str(yaml).unwrap();
    let root = Path::new("traits");
    let path = root.join("objectives/supply-chain/security-hold/withdrawn.yaml");
    let file = super::prepare_trait_file(&path, mappings, Vec::new(), root, false, false);
    assert!(
        file.rule_parsing_warnings.is_empty(),
        "{:?}",
        file.rule_parsing_warnings
    );
    assert_eq!(file.rules[0].rule.crit, crate::types::Criticality::Hostile);
}

#[test]
#[allow(clippy::expect_used)]
fn full_validation_rejects_new_metadata_file_string_definition() {
    let dir = tempfile::tempdir().expect("create temporary trait tree");
    let string_dir = dir.path().join("metadata/file/string");
    std::fs::create_dir_all(&string_dir).expect("create string directory");
    std::fs::write(
        string_dir.join("new.yaml"),
        r#"defaults:
  for: [pe]
  platforms: [windows]
traits:
- id: new-string
  desc: New generic file string
  crit: baseline
  conf: 0.5
  if: {type: text, exact: a new generic file string}
"#,
    )
    .expect("write temporary string rule");

    let error = super::super::CapabilityMapper::from_directory_exact(
        dir.path(),
        crate::LoadOptions {
            full_validation: true,
            ..crate::LoadOptions::default()
        },
    )
    .expect_err("new metadata/file/string definitions must fail validation");
    let message = format!("{error:#}");
    assert!(
        message.contains("new rule IDs under legacy metadata/file/string/"),
        "unexpected validation error: {message}"
    );
}

#[test]
#[allow(clippy::expect_used)]
fn full_validation_rejects_new_metadata_file_literal_definition() {
    let dir = tempfile::tempdir().expect("create temporary trait tree");
    let literal_dir = dir.path().join("metadata/file/literal");
    std::fs::create_dir_all(&literal_dir).expect("create literal directory");
    std::fs::write(
        literal_dir.join("new.yaml"),
        r#"defaults:
  for: [pe]
  platforms: [windows]
traits:
- id: new-literal
  desc: New context literal
  crit: baseline
  conf: 0.5
  if: {type: text, exact: a new context literal}
"#,
    )
    .expect("write temporary literal rule");

    let error = super::super::CapabilityMapper::from_directory_exact(
        dir.path(),
        crate::LoadOptions {
            full_validation: true,
            ..crate::LoadOptions::default()
        },
    )
    .expect_err("new metadata/file/literal definitions must fail validation");
    let message = format!("{error:#}");
    assert!(
        message.contains("new rule IDs under legacy metadata/file/literal/"),
        "unexpected validation error: {message}"
    );
}

/// Issues `prepare_trait_file` + `push_parsing_warning` raise for one file.
#[allow(clippy::expect_used)]
fn file_type_issues(yaml: &str) -> Vec<(&'static str, String)> {
    let mappings: crate::capabilities::models::TraitMappings =
        crate::yaml::from_str(yaml).expect("valid trait YAML");
    let dir = Path::new("traits");
    let path = dir.join("x/y.yaml");
    let file = super::prepare_trait_file(&path, mappings, Vec::new(), dir, false, false);
    let mut issues = crate::validation_controls::ValidationIssues::new();
    for w in file
        .trait_parsing_warnings
        .into_iter()
        .chain(file.rule_parsing_warnings)
    {
        super::push_parsing_warning(&mut issues, "traits/x/y.yaml", w);
    }
    issues
        .iter()
        .filter(|i| i.validator_id.ends_with("file-type"))
        .map(|i| (i.validator_id, i.message.clone()))
        .collect()
}

/// A mapper-cache hit must restore each rule's `defined_in`: the field is
/// `#[serde(skip)]` on the rule types, yet evaluation filters on it, so a
/// warm run would otherwise drop rules a cold run keeps.
#[test]
#[allow(clippy::expect_used)]
fn mapper_cache_round_trip_keeps_defined_in() {
    let trait_path = Path::new("/traits/metadata/binary/layout/msdos.yaml");
    let rule_path = Path::new("/traits/objectives/impact/infect/virus/msdos-binary.yaml");
    let t = super::TraitDefinition {
        id: "metadata/binary/layout::msdos".into(),
        defined_in: trait_path.to_path_buf(),
        ..Default::default()
    };
    let c = super::CompositeTrait {
        id: "objectives/impact/infect/virus::msdos".into(),
        defined_in: rule_path.to_path_buf(),
        ..Default::default()
    };

    let mut bytes = super::MapperCacheData::to_json_lines(&[t], &[c], &[]).expect("encode cache");
    let data = super::MapperCacheData::parse(&mut bytes).expect("decode cache");
    assert_eq!(data.trait_definitions[0].defined_in, trait_path);
    assert_eq!(data.composite_rules[0].defined_in, rule_path);
}

/// Cached rules must regain the runtime YARA state omitted by serde.
/// Otherwise inline support traits and YARA composite legs silently stop
/// matching after the first process warms the mapper cache.
#[test]
#[allow(clippy::expect_used)]
fn mapper_cache_round_trip_restores_yara_runtime_state() {
    let source = "rule cache_probe { strings: $a = \"QACACHE\" condition: $a }";
    let mut atomic = super::TraitDefinition {
        id: "objectives/test::inline-yara".into(),
        r#if: super::Condition::Yara {
            source: source.into(),
            compiled: None,
            namespace: None,
        },
        ..Default::default()
    };
    atomic.set_yara_if_namespace();
    let mut composite = super::CompositeTrait {
        id: "objectives/test::composite-yara".into(),
        all: Some(vec![super::Condition::Yara {
            source: source.into(),
            compiled: None,
            namespace: None,
        }]),
        ..Default::default()
    };
    composite.compile_yara();
    let mut bytes =
        super::MapperCacheData::to_json_lines(&[atomic], &[composite], &[]).expect("encode cache");
    let cached = super::MapperCacheData::parse(&mut bytes).expect("decode cache");
    assert!(
        matches!(
            &cached.trait_definitions[0].r#if,
            super::Condition::Yara { namespace, .. }
                if namespace.as_deref() == Some("inline.objectives/test::inline-yara")
        ),
        "cached atomic YARA namespace must be restored"
    );
    let conditions = cached.composite_rules[0]
        .all
        .as_ref()
        .expect("all conditions");
    assert!(
        matches!(
            &conditions[0],
            super::Condition::Yara {
                compiled: Some(_),
                ..
            }
        ),
        "cached composite YARA must be compiled again"
    );
}

/// An unknown name in `defaults: for:` is reported once for the file, under
/// the same validator as a rule's own `for:`, even when every rule
/// overrides `for:` and nothing inherits the default.
#[test]
fn unknown_default_for_is_reported_once_per_file() {
    let issues = file_type_issues(
        "defaults:\n  for: [archive-typo, zip]\n  platforms: [linux]\n\
             traits:\n\
             - {id: a, desc: first trait here, for: [zip], if: {type: text, substr: aaaa}}\n\
             - {id: b, desc: second trait here, for: [zip], if: {type: text, substr: bbbb}}\n",
    );
    assert_eq!(issues.len(), 1, "{issues:?}");
    let (id, message) = &issues[0];
    assert_eq!(*id, "unknown-file-type");
    assert!(message.contains("'archive-typo'"), "{message}");
    assert!(message.contains("defaults: for:"), "{message}");
    assert!(message.contains("traits/x/y.yaml"), "{message}");
}

/// Inheriting the bad default does not repeat the unknown-type issue per
/// rule; a rule left with no file type at all is its own hard issue.
#[test]
fn default_for_resolving_to_nothing_is_empty_file_type() {
    let issues = file_type_issues(
        "defaults:\n  for: [archive-typo]\n  platforms: [linux]\n\
             traits:\n\
             - {id: a, desc: first trait here, if: {type: text, substr: aaaa}}\n\
             - {id: b, desc: second trait here, if: {type: text, substr: bbbb}}\n\
             composite_rules:\n\
             - {id: c, desc: composite rule here, all: [{id: a}, {id: b}]}\n",
    );
    let unknown = issues
        .iter()
        .filter(|(id, _)| *id == "unknown-file-type")
        .count();
    assert_eq!(unknown, 1, "{issues:?}");
    let empty: Vec<&String> = issues
        .iter()
        .filter(|(id, _)| *id == "empty-file-type")
        .map(|(_, m)| m)
        .collect();
    assert_eq!(empty.len(), 3, "{issues:?}");
    // Composites are named by their canonical id: they are qualified
    // before parsing so policy checks see it.
    assert!(
        empty.iter().any(|m| m.contains("composite rule 'x::c'")),
        "{empty:?}"
    );
    assert_eq!(
        crate::validation_controls::validator_severity("empty-file-type"),
        crate::validation_controls::Severity::Hard
    );
}
