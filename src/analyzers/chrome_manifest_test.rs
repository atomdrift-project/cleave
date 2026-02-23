//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for Chrome extension manifest analyzer - supply chain security
//!
//! Comprehensive test coverage for:
//! - Manifest version detection (V2 deprecated, V3 modern)
//! - Permission analysis (Critical, High, Medium, Low risk levels)
//! - Overprivileged extension detection
//! - Host permission analysis (<all_urls>, wildcards, shopping sites)
//! - Content script analysis (all_frames, run_at, URL patterns)
//! - Suspicious patterns (externally_connectable, web_accessible_resources, persistent background)
//! - Update URL validation (external vs Chrome Web Store)
//! - Global TLD coverage detection

use super::*;
use crate::analyzers::chrome_manifest::ChromeManifestAnalyzer;
use crate::types::Criticality;

/// Helper: Create test analyzer
fn create_analyzer() -> ChromeManifestAnalyzer {
    ChromeManifestAnalyzer::new()
}

/// Helper: Parse and analyze manifest content
fn analyze_content(content: &str) -> AnalysisReport {
    let analyzer = create_analyzer();
    analyzer
        .analyze_manifest(Path::new("test_manifest.json"), content)
        .expect("Failed to parse manifest.json")
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

/// Helper: Count findings matching ID substring
fn count_findings(report: &AnalysisReport, id_substr: &str) -> usize {
    report.findings.iter().filter(|f| f.id.contains(id_substr)).count()
}

// ==================== Basic Parsing Tests ====================

#[test]
fn test_parse_minimal_manifest() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test Extension",
        "version": "1.0.0"
    }"#;
    let report = analyze_content(content);
    assert_eq!(report.target.file_type, "chrome-manifest");
    assert!(report.structure.iter().any(|s| s.id.contains("chrome/extension")));
}

#[test]
fn test_parse_manifest_v2() {
    let content = r#"{
        "manifest_version": 2,
        "name": "Old Extension",
        "version": "1.0.0"
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "manifest-v2"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("manifest-v2") && f.desc.contains("deprecated")
    }));
}

#[test]
fn test_parse_manifest_v3() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Modern Extension",
        "version": "1.0.0"
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "manifest-v3"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("manifest-v3") && f.crit == Criticality::Baseline
    }));
}

// ==================== Permission Tests - Critical Risk ====================

#[test]
fn test_detect_debugger_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["debugger"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-critical/debugger"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("permission-critical/debugger") && f.crit == Criticality::Suspicious
    }));
}

#[test]
fn test_detect_native_messaging_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["nativeMessaging"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-critical/nativeMessaging"));
}

#[test]
fn test_detect_all_urls_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["<all_urls>"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-critical/<all_urls>"));
}

// ==================== Permission Tests - High Risk ====================

#[test]
fn test_detect_web_request_permission() {
    let content = r#"{
        "manifest_version": 2,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["webRequest"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/webRequest"));
}

#[test]
fn test_detect_web_request_blocking_permission() {
    let content = r#"{
        "manifest_version": 2,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["webRequestBlocking"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/webRequestBlocking"));
}

#[test]
fn test_detect_cookies_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["cookies"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/cookies"));
}

#[test]
fn test_detect_history_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["history"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/history"));
}

#[test]
fn test_detect_proxy_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["proxy"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/proxy"));
}

#[test]
fn test_detect_clipboard_read_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["clipboardRead"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/clipboardRead"));
}

#[test]
fn test_detect_management_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["management"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/management"));
}

#[test]
fn test_detect_privacy_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["privacy"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/privacy"));
}

// ==================== Permission Tests - Medium Risk ====================

#[test]
fn test_detect_tabs_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["tabs"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-medium/tabs"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("permission-medium/tabs") && f.crit == Criticality::Notable
    }));
}

#[test]
fn test_detect_bookmarks_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["bookmarks"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-medium/bookmarks"));
}

#[test]
fn test_detect_downloads_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["downloads"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-medium/downloads"));
}

#[test]
fn test_detect_geolocation_permission() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["geolocation"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-medium/geolocation"));
}

// ==================== Permission Tests - Low Risk (Not Reported) ====================

#[test]
fn test_low_risk_permissions_not_reported() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["storage", "alarms", "notifications", "contextMenus"]
    }"#;
    let report = analyze_content(content);
    // Low risk permissions should not generate individual findings
    assert!(!has_finding(&report, "permission-low"));
    assert!(!has_finding(&report, "permission-medium/storage"));
    assert!(!has_finding(&report, "permission-medium/alarms"));
}

// ==================== Overprivileged Extension Detection ====================

#[test]
fn test_detect_overprivileged_critical() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["debugger", "webRequest"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "overprivileged"));
    assert!(has_attack(&report, "T1176"));
}

#[test]
fn test_detect_overprivileged_multiple_high_risk() {
    let content = r#"{
        "manifest_version": 2,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["webRequest", "cookies", "history"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "overprivileged"));
    assert_eq!(count_findings(&report, "permission-high"), 3);
}

#[test]
fn test_not_overprivileged_few_permissions() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["tabs", "storage"]
    }"#;
    let report = analyze_content(content);
    assert!(!has_finding(&report, "overprivileged"));
}

// ==================== Wildcard Permission Patterns ====================

#[test]
fn test_detect_wildcard_all_protocols_all_domains() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["*://*/"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/*://*/"));
}

#[test]
fn test_detect_http_wildcard() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["http://*/*"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/http://*/*"));
}

#[test]
fn test_detect_https_wildcard() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "permissions": ["https://*/*"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "permission-high/https://*/*"));
}

// ==================== Host Permissions Analysis ====================

#[test]
fn test_detect_host_all_urls() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "host_permissions": ["<all_urls>"]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "host-all-urls"));
    assert!(has_attack(&report, "T1185"));
}

#[test]
fn test_detect_shopping_site_targeting() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "host_permissions": [
            "*://*.amazon.com/*",
            "*://*.ebay.com/*",
            "*://*.walmart.com/*"
        ]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "targets-shopping"));
}

#[test]
fn test_shopping_sites_below_threshold() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "host_permissions": [
            "*://*.amazon.com/*",
            "*://*.ebay.com/*"
        ]
    }"#;
    let report = analyze_content(content);
    // Need 3+ shopping sites to trigger finding
    assert!(!has_finding(&report, "targets-shopping"));
}

#[test]
fn test_detect_global_tld_coverage() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "host_permissions": [
            "*://*.example.com/*",
            "*://*.example.co.uk/*",
            "*://*.example.de/*",
            "*://*.example.fr/*",
            "*://*.example.jp/*",
            "*://*.example.ca/*",
            "*://*.example.au/*",
            "*://*.example.in/*",
            "*://*.example.br/*",
            "*://*.example.mx/*"
        ]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "global-tld-access"));
}

// ==================== Content Scripts Analysis ====================

#[test]
fn test_detect_content_script_all_frames() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "content_scripts": [{
            "matches": ["*://*.example.com/*"],
            "js": ["content.js"],
            "all_frames": true
        }]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "content-script-all-frames"));
}

#[test]
fn test_detect_content_script_all_urls() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "content_scripts": [{
            "matches": ["<all_urls>"],
            "js": ["inject.js"]
        }]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "host-all-urls"));
}

#[test]
fn test_detect_content_script_wildcard_pattern() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "content_scripts": [{
            "matches": ["*://*/*"],
            "js": ["universal.js"]
        }]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "host-all-urls"));
}

// ==================== Suspicious Patterns ====================

#[test]
fn test_detect_externally_connectable() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "externally_connectable": {
            "matches": ["*://*.example.com/*"]
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "externally-connectable"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("externally-connectable") && f.crit == Criticality::Notable
    }));
}

#[test]
fn test_detect_web_accessible_resources() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "web_accessible_resources": [
            {
                "resources": ["images/*.png"],
                "matches": ["*://*.example.com/*"]
            }
        ]
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "web-accessible-resources"));
}

#[test]
fn test_detect_persistent_background() {
    let content = r#"{
        "manifest_version": 2,
        "name": "Test",
        "version": "1.0.0",
        "background": {
            "scripts": ["background.js"],
            "persistent": true
        }
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "persistent-background"));
}

#[test]
fn test_non_persistent_background_no_finding() {
    let content = r#"{
        "manifest_version": 2,
        "name": "Test",
        "version": "1.0.0",
        "background": {
            "scripts": ["background.js"],
            "persistent": false
        }
    }"#;
    let report = analyze_content(content);
    assert!(!has_finding(&report, "persistent-background"));
}

// ==================== Update URL Validation ====================

#[test]
fn test_detect_external_update_url() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "update_url": "https://evil.com/updates.xml"
    }"#;
    let report = analyze_content(content);
    assert!(has_finding(&report, "external-update-url"));
    assert!(has_attack(&report, "T1195.002"));
    assert!(report.findings.iter().any(|f| {
        f.id.contains("external-update-url") && f.crit == Criticality::Suspicious
    }));
}

#[test]
fn test_chrome_web_store_update_url_allowed() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0",
        "update_url": "https://clients2.google.com/service/update2/crx"
    }"#;
    let report = analyze_content(content);
    // Chrome Web Store official update URL should not trigger finding
    assert!(!has_finding(&report, "external-update-url"));
}

#[test]
fn test_no_update_url_no_finding() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Test",
        "version": "1.0.0"
    }"#;
    let report = analyze_content(content);
    assert!(!has_finding(&report, "external-update-url"));
}

// ==================== Integration Tests ====================

#[test]
fn test_real_world_malicious_extension() {
    let content = r#"{
        "manifest_version": 2,
        "name": "SuperCouponFinder",
        "version": "1.0.0",
        "permissions": [
            "debugger",
            "webRequest",
            "webRequestBlocking",
            "cookies",
            "history",
            "<all_urls>"
        ],
        "host_permissions": [
            "*://*.amazon.com/*",
            "*://*.ebay.com/*",
            "*://*.walmart.com/*",
            "*://*.target.com/*"
        ],
        "content_scripts": [{
            "matches": ["<all_urls>"],
            "js": ["inject.js"],
            "all_frames": true,
            "run_at": "document_start"
        }],
        "background": {
            "scripts": ["background.js"],
            "persistent": true
        },
        "update_url": "https://malware-cdn.tk/updates.xml"
    }"#;
    let report = analyze_content(content);

    // Should detect multiple suspicious patterns
    assert!(has_finding(&report, "manifest-v2"));
    assert!(has_finding(&report, "permission-critical"));
    assert!(has_finding(&report, "overprivileged"));
    assert!(has_finding(&report, "host-all-urls"));
    assert!(has_finding(&report, "targets-shopping"));
    assert!(has_finding(&report, "content-script-all-frames"));
    assert!(has_finding(&report, "persistent-background"));
    assert!(has_finding(&report, "external-update-url"));

    // Should have multiple Suspicious findings
    let suspicious_count = report.findings.iter()
        .filter(|f| f.crit == Criticality::Suspicious)
        .count();
    assert!(suspicious_count >= 3, "Should have multiple Suspicious findings");
}

#[test]
fn test_benign_extension_minimal_findings() {
    let content = r#"{
        "manifest_version": 3,
        "name": "Simple Timer",
        "version": "1.0.0",
        "description": "A simple timer extension",
        "permissions": ["storage", "alarms"],
        "action": {
            "default_popup": "popup.html"
        }
    }"#;
    let report = analyze_content(content);

    // Should have minimal findings
    assert!(has_finding(&report, "manifest-v3")); // V3 is baseline (good)
    assert!(!has_finding(&report, "permission-critical"));
    assert!(!has_finding(&report, "permission-high"));
    assert!(!has_finding(&report, "overprivileged"));
    assert!(!has_finding(&report, "host-all-urls"));

    // Should have no Suspicious findings
    let suspicious_count = report.findings.iter()
        .filter(|f| f.crit == Criticality::Suspicious)
        .count();
    assert_eq!(suspicious_count, 0, "Benign extension should have no Suspicious findings");
}

// Note: can_analyze() requires actual files on disk with Chrome extension content,
// so it's tested via the inline tests in chrome_manifest.rs instead.
