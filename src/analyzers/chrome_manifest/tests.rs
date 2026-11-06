use super::*;

#[test]
fn test_host_tokens_preserve_breadth_and_reject_lossy_names() {
    for (pattern, expected) in [
        ("<all_urls>", Some("all-urls")),
        ("*://*/*", Some("all-hosts")),
        ("https://*/*", Some("all-hosts")),
        ("file:///*", Some("file-urls")),
        ("https://*.Example.org:443/path*", Some("example.org")),
        ("https://exam!ple.org/*", None),
        ("https://example..org/*", None),
        ("https://-example.org/*", None),
        ("https:///path", None),
    ] {
        assert_eq!(
            ChromeManifestAnalyzer::normalize_host(pattern).as_deref(),
            expected,
            "{pattern}"
        );
    }
}

#[test]
fn test_host_declarations_keep_field_and_original_pattern() {
    let report = ChromeManifestAnalyzer::new()
        .analyze_manifest(
            Path::new("manifest.json"),
            r#"{
            "manifest_version":3,"name":"Host declarations","version":"1.0",
            "permissions":["identity.email","https://*/*"],
            "host_permissions":["file:///*"],
            "content_scripts":[{"matches":["*://*.EXAMPLE.org/path*"],"js":["content.js"]}]
        }"#,
        )
        .unwrap();
    for (id, location, pattern) in [
        (
            "metadata/permission/host/all-hosts::declared",
            "permissions[1]",
            "https://*/*",
        ),
        (
            "metadata/permission/host/file-urls::declared",
            "host_permissions[0]",
            "file:///*",
        ),
        (
            "metadata/permission/host/example.org::declared",
            "content_scripts[0].matches[0]",
            "*://*.EXAMPLE.org/path*",
        ),
    ] {
        let finding = report.findings.iter().find(|f| f.id == id).unwrap();
        assert!(
            finding
                .evidence
                .iter()
                .any(|e| e.location.as_deref() == Some(location) && e.value == pattern)
        );
    }
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id.contains("host/identity.email") || f.id.contains("host/all-urls"))
    );
}

#[test]
fn test_noncanonical_api_names_are_metadata_and_deduplicated() {
    let report = ChromeManifestAnalyzer::new()
        .analyze_manifest(
            Path::new("manifest.json"),
            r#"{
            "manifest_version":3,"name":"API declarations","version":"1.0",
            "permissions":["management","management","customAPI","downloads","storage"]
        }"#,
        )
        .unwrap();
    for id in [
        "metadata/permission/extension-api/management::declared",
        "metadata/permission/extension-api/custom-a-p-i::declared",
    ] {
        assert_eq!(report.findings.iter().filter(|f| f.id == id).count(), 1);
    }
    assert!(!report.findings.iter().any(|f| {
        f.id.starts_with("micro-behaviors/browser-extension/permission/")
    }));
}

#[test]
fn test_permission_fallback_requires_matching_canonical_to_deduplicate() {
    let manifest: ChromeManifest =
        serde_json::from_str(r#"{"permissions":["downloads"]}"#).unwrap();
    let mut report = ChromeManifestAnalyzer::new()
        .analyze_manifest(
            Path::new("manifest.json"),
            r#"{
            "manifest_version":3,"name":"Fallback","version":"1.0","permissions":["downloads"]
        }"#,
        )
        .unwrap();
    let fallback = "metadata/permission/extension-api/downloads::declared";
    let canonical = "metadata/permission/download::permission-downloads";
    assert!(report.findings.iter().any(|f| f.id == fallback));
    report.add_finding(Finding::indicator(
        canonical.to_string(),
        "Declares downloads permission".to_string(),
        0.9,
    ));
    let mut consumer = Finding::indicator(
        "metadata/permission/manifest::synthetic-profile".to_string(),
        "Permission profile".to_string(),
        0.9,
    );
    consumer.trait_refs = vec![fallback.into()];
    report.add_finding(consumer);
    ChromeManifestAnalyzer::deduplicate_declared_permissions(&manifest, &mut report);
    assert!(!report.findings.iter().any(|f| f.id == fallback));
    assert!(report.findings.iter().any(|f| f.id == canonical));
    assert!(
        report
            .findings
            .iter()
            .find(|f| f.id == "metadata/permission/manifest::synthetic-profile")
            .unwrap()
            .trait_refs
            .iter()
            .any(|r| r == canonical)
    );
}

#[test]
fn test_resource_entry_count_and_activation_are_declarations() {
    let report = ChromeManifestAnalyzer::new().analyze_manifest(Path::new("manifest.json"), r#"{
            "manifest_version":2,"name":"Declaration fields","version":"1.0",
            "permissions":[],"externally_connectable":{},
            "background":{"scripts":["background.js"],"persistent":true},
            "web_accessible_resources":[{"resources":["a.js","b.js","c.js"],"matches":["https://example.org/*"]}]
        }"#).unwrap();
    let resources = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/permission/extension-api::web-accessible-resource-entries")
        .unwrap();
    assert!(resources.desc.contains("1 web-accessible resource entries"));
    assert!(
        resources
            .evidence
            .iter()
            .any(|e| e.value == "1 resource entries")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/permission/activation::persistent-background-declaration")
    );
    assert!(report.findings.iter().any(|f| f.id
        == "metadata/permission/extension-api::external-connection-policy"
        && f.desc == "Declares external connection policy"));
}

#[test]
fn test_basic_manifest() {
    let content = r#"{
            "manifest_version": 3,
            "name": "Test Extension",
            "version": "1.0.0",
            "permissions": ["storage"]
        }"#;

    let analyzer = ChromeManifestAnalyzer::new();
    let report = analyzer
        .analyze_manifest(Path::new("manifest.json"), content)
        .unwrap();

    assert_eq!(report.target.file_type, "chrome-manifest");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/permission/extension-api/storage::declared")
    );
}

#[test]
fn test_dangerous_permissions() {
    let content = r#"{
            "manifest_version": 3,
            "name": "Suspicious Extension",
            "version": "1.0.0",
            "permissions": ["debugger", "cookies", "history", "webRequest"]
        }"#;

    let analyzer = ChromeManifestAnalyzer::new();
    let report = analyzer
        .analyze_manifest(Path::new("manifest.json"), content)
        .unwrap();

    // Each declared API permission becomes a neutral capability trait,
    // kebab-cased into the trait-ID path.
    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(
        ids.contains(&"metadata/permission/extension-api/debugger::declared"),
        "{ids:?}"
    );
    assert!(ids.contains(&"metadata/permission/extension-api/cookies::declared"));
    assert!(ids.contains(&"metadata/permission/extension-api/web-request::declared"));
    assert!(ids.contains(&"metadata/permission/extension-api/history::declared"));
    // The risk/intent verdict is no longer hardcoded here.
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id.contains("overprivileged"))
    );
}

#[test]
fn test_all_urls_permission() {
    let content = r#"{
            "manifest_version": 3,
            "name": "All URLs Extension",
            "version": "1.0.0",
            "permissions": ["<all_urls>"]
        }"#;

    let analyzer = ChromeManifestAnalyzer::new();
    let report = analyzer
        .analyze_manifest(Path::new("manifest.json"), content)
        .unwrap();

    // A broad grant collapses to the `all-urls` host-access token, not a
    // bogus `permission/all-urls`.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/permission/host/all-urls::declared")
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id.contains("permission/all-urls"))
    );
}

#[test]
fn test_host_access_traits() {
    let content = r#"{
            "manifest_version": 3,
            "name": "Shopping Extension",
            "version": "1.0.0",
            "host_permissions": [
                "*://*.amazon.com/*",
                "*://*.amazon.co.uk/*",
                "*://*.ebay.com/*"
            ]
        }"#;

    let analyzer = ChromeManifestAnalyzer::new();
    let report = analyzer
        .analyze_manifest(Path::new("manifest.json"), content)
        .unwrap();

    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    // One dynamic per-origin capability trait per host; the registrable
    // domain is the ML-keyed leaf path component.
    assert!(ids.contains(&"metadata/permission/host/amazon.com::declared"));
    assert!(ids.contains(&"metadata/permission/host/amazon.co.uk::declared"));
    assert!(ids.contains(&"metadata/permission/host/ebay.com::declared"));
}

#[test]
fn test_external_update_url() {
    let content = r#"{
            "manifest_version": 3,
            "name": "External Update Extension",
            "version": "1.0.0",
            "update_url": "https://evil.com/updates.xml"
        }"#;

    let analyzer = ChromeManifestAnalyzer::new();
    let report = analyzer
        .analyze_manifest(Path::new("manifest.json"), content)
        .unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "objectives/supply-chain/metadata-anomaly/update-url::external")
    );
}

/// Byte-for-byte copy of Electron's chrome-api fixture manifest.
const ELECTRON_CHROME_API_MANIFEST: &str = r#"{
  "name": "chrome-api",
  "version": "1.0",
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["main.js"],
      "run_at": "document_start"
    }
  ],
  "background": {
    "scripts": ["background.js"],
    "persistent": false
  },
  "permissions": [
    "<all_urls>"
  ],
  "manifest_version": 2
}
"#;

#[test]
fn test_only_the_exact_electron_fixture_is_exempt() {
    let analyzer = ChromeManifestAnalyzer::new();
    let has_all_urls = |content: &str| {
        analyzer
            .analyze_manifest(Path::new("manifest.json"), content)
            .unwrap()
            .findings
            .iter()
            .any(|f| f.id == "metadata/permission/host/all-urls::declared")
    };
    assert!(!has_all_urls(ELECTRON_CHROME_API_MANIFEST));
    // The same shape under any other bytes is an ordinary extension.
    assert!(has_all_urls(
        &ELECTRON_CHROME_API_MANIFEST.replace("\"1.0\"", "\"1.1\"")
    ));
}
