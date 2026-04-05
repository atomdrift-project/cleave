//! Chrome extension manifest.json analyzer.
//!
//! Detects suspicious patterns in Chrome extension manifests including:
//! - Dangerous permissions (debugger, webRequest, cookies, history)
//! - Overly broad host permissions
//! - Content scripts running on all URLs
//! - External update URLs

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Chrome extension manifest.json analyzer
#[derive(Debug)]
pub(crate) struct ChromeManifestAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

/// Chrome extension manifest structure
/// Note: Some fields are only used for deserialization tolerance
#[derive(Deserialize, Default, Debug)]
struct ChromeManifest {
    manifest_version: Option<u8>,
    name: Option<String>,
    version: Option<String>,
    #[allow(dead_code)] // Deserialized from JSON
    description: Option<String>,
    #[serde(default)]
    permissions: Vec<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)] // Deserialized from JSON
    optional_permissions: Vec<serde_json::Value>,
    #[serde(default)]
    host_permissions: Vec<String>,
    #[serde(default)]
    content_scripts: Vec<ContentScript>,
    background: Option<Background>,
    update_url: Option<String>,
    externally_connectable: Option<serde_json::Value>,
    #[serde(default)]
    web_accessible_resources: Vec<serde_json::Value>,
}

#[derive(Deserialize, Default, Debug)]
struct ContentScript {
    #[serde(default)]
    matches: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)] // Deserialized from JSON
    js: Vec<String>,
    run_at: Option<String>,
    #[serde(default)]
    all_frames: bool,
}

#[derive(Deserialize, Default, Debug)]
struct Background {
    #[allow(dead_code)] // Deserialized from JSON
    service_worker: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // Deserialized from JSON
    scripts: Vec<String>,
    persistent: Option<bool>,
}

/// Permission risk levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl ChromeManifestAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
        }
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    pub(crate) fn analyze_manifest(
        &self,
        file_path: &Path,
        content: &str,
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Strip UTF-8 BOM if present
        let content = content.strip_prefix('\u{FEFF}').unwrap_or(content);

        let manifest: ChromeManifest =
            serde_json::from_str(content).context("Failed to parse manifest.json")?;

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "chrome-manifest".to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "manifest/chrome/extension".to_string(),
            desc: format!(
                "Chrome extension manifest: {} v{} (MV{})",
                manifest.name.as_deref().unwrap_or("unknown"),
                manifest.version.as_deref().unwrap_or("unknown"),
                manifest.manifest_version.unwrap_or(0)
            ),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "serde_json".to_string(),
                value: "manifest.json".to_string(),
                location: None,
                ..Default::default()
            }],
        });

        // Check manifest version
        self.check_manifest_version(&manifest, &mut report);

        // Analyze permissions
        self.analyze_permissions(&manifest, &mut report);

        // Analyze host permissions
        self.analyze_host_permissions(&manifest, &mut report);

        // Analyze content scripts
        self.analyze_content_scripts(&manifest, &mut report);

        // Check for suspicious patterns
        self.check_suspicious_patterns(&manifest, &mut report);

        // Check update URL
        self.check_update_url(&manifest, &mut report);

        // Evaluate YAML-based rules
        self.capability_mapper.evaluate_and_merge_findings(
            &mut report,
            content.as_bytes(),
            None,
            None,
        );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["serde_json".to_string()];

        Ok(report)
    }

    fn check_manifest_version(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        match manifest.manifest_version {
            Some(2) => {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/chrome-ext/manifest-v2".to_string(),
                        "Uses deprecated Manifest V2 (end of life)".to_string(),
                        0.95,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "parser".to_string(),
                        source: "manifest.json".to_string(),
                        value: "manifest_version: 2".to_string(),
                        location: Some("manifest_version".to_string()),
                        ..Default::default()
                    }]),
                );
            }
            Some(3) => {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/chrome-ext/manifest-v3".to_string(),
                        "Uses Manifest V3".to_string(),
                        0.95,
                    )
                    .with_criticality(Criticality::Baseline)
                    .with_evidence(vec![Evidence {
                        method: "parser".to_string(),
                        source: "manifest.json".to_string(),
                        value: "manifest_version: 3".to_string(),
                        location: Some("manifest_version".to_string()),
                        ..Default::default()
                    }]),
                );
            }
            _ => {}
        }
    }

    fn analyze_permissions(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        let mut dangerous_perms: Vec<(String, PermissionRisk, &str)> = Vec::new();

        // Define permission risk levels
        let permission_risks: &[(&str, PermissionRisk, &str)] = &[
            // Critical permissions
            (
                "debugger",
                PermissionRisk::Critical,
                "Can debug and control other tabs",
            ),
            (
                "nativeMessaging",
                PermissionRisk::Critical,
                "Can communicate with native applications",
            ),
            // High risk permissions
            (
                "webRequest",
                PermissionRisk::High,
                "Can intercept all web requests",
            ),
            (
                "webRequestBlocking",
                PermissionRisk::High,
                "Can block/modify web requests",
            ),
            ("proxy", PermissionRisk::High, "Can modify proxy settings"),
            (
                "cookies",
                PermissionRisk::High,
                "Can read/write cookies for any site",
            ),
            ("history", PermissionRisk::High, "Can read browsing history"),
            (
                "browsingData",
                PermissionRisk::High,
                "Can clear browsing data",
            ),
            (
                "clipboardRead",
                PermissionRisk::High,
                "Can read clipboard content",
            ),
            (
                "management",
                PermissionRisk::High,
                "Can manage other extensions",
            ),
            (
                "privacy",
                PermissionRisk::High,
                "Can modify privacy settings",
            ),
            (
                "webNavigation",
                PermissionRisk::High,
                "Can observe navigation events",
            ),
            (
                "declarativeNetRequestWithHostAccess",
                PermissionRisk::High,
                "Can modify network requests",
            ),
            // Medium risk permissions
            (
                "tabs",
                PermissionRisk::Medium,
                "Can access tab URLs and titles",
            ),
            (
                "activeTab",
                PermissionRisk::Medium,
                "Can access current tab on user action",
            ),
            (
                "bookmarks",
                PermissionRisk::Medium,
                "Can read/modify bookmarks",
            ),
            ("downloads", PermissionRisk::Medium, "Can manage downloads"),
            (
                "geolocation",
                PermissionRisk::Medium,
                "Can access user location",
            ),
            (
                "topSites",
                PermissionRisk::Medium,
                "Can access most visited sites",
            ),
            (
                "sessions",
                PermissionRisk::Medium,
                "Can access recently closed tabs",
            ),
            (
                "clipboardWrite",
                PermissionRisk::Medium,
                "Can write to clipboard",
            ),
            // Low risk permissions
            ("storage", PermissionRisk::Low, "Extension storage access"),
            ("alarms", PermissionRisk::Low, "Can schedule tasks"),
            (
                "notifications",
                PermissionRisk::Low,
                "Can show notifications",
            ),
            (
                "contextMenus",
                PermissionRisk::Low,
                "Can add context menu items",
            ),
            (
                "identity",
                PermissionRisk::Low,
                "Can get user identity token",
            ),
        ];

        // Check all permissions
        for perm in &manifest.permissions {
            let perm_str = match perm {
                serde_json::Value::String(s) => s.as_str(),
                _ => continue,
            };

            // Check for <all_urls>
            if perm_str == "<all_urls>" {
                dangerous_perms.push((
                    perm_str.to_string(),
                    PermissionRisk::Critical,
                    "Access to ALL websites",
                ));
                continue;
            }

            // Check for wildcard patterns
            if perm_str.contains("*://*/") || perm_str == "http://*/*" || perm_str == "https://*/*"
            {
                dangerous_perms.push((
                    perm_str.to_string(),
                    PermissionRisk::High,
                    "Broad website access pattern",
                ));
                continue;
            }

            // Check against known permissions
            for (known_perm, risk, desc) in permission_risks {
                if perm_str == *known_perm {
                    dangerous_perms.push((perm_str.to_string(), *risk, desc));
                    break;
                }
            }
        }

        // Report findings based on risk
        let critical_count = dangerous_perms
            .iter()
            .filter(|(_, r, _)| *r == PermissionRisk::Critical)
            .count();
        let high_count = dangerous_perms
            .iter()
            .filter(|(_, r, _)| *r == PermissionRisk::High)
            .count();

        for (perm, risk, desc) in &dangerous_perms {
            let (crit, finding_id) = match risk {
                PermissionRisk::Critical => (
                    Criticality::Suspicious,
                    format!("supply-chain/chrome-ext/permission-critical/{}", perm),
                ),
                PermissionRisk::High => (
                    Criticality::Suspicious,
                    format!("supply-chain/chrome-ext/permission-high/{}", perm),
                ),
                PermissionRisk::Medium => (
                    Criticality::Notable,
                    format!("supply-chain/chrome-ext/permission-medium/{}", perm),
                ),
                PermissionRisk::Low => continue, // Don't report low risk individually
            };

            report.add_finding(
                Finding::indicator(finding_id, format!("Permission '{}': {}", perm, desc), 0.95)
                    .with_criticality(crit)
                    .with_evidence(vec![Evidence {
                        method: "parser".to_string(),
                        source: "manifest.json".to_string(),
                        value: perm.clone(),
                        location: Some("permissions".to_string()),
                        ..Default::default()
                    }]),
            );
        }

        // Add composite finding for overprivileged extension
        if critical_count >= 1 || high_count >= 3 {
            report.add_finding(
                Finding::indicator(
                    "supply-chain/chrome-ext/overprivileged".to_string(),
                    format!(
                        "Overprivileged extension ({} critical, {} high-risk permissions)",
                        critical_count, high_count
                    ),
                    0.9,
                )
                .with_criticality(Criticality::Suspicious)
                .with_attack("T1176".to_string())
                .with_evidence(vec![Evidence {
                    method: "heuristic".to_string(),
                    source: "manifest.json".to_string(),
                    value: dangerous_perms
                        .iter()
                        .map(|(p, _, _)| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    location: Some("permissions".to_string()),
                    ..Default::default()
                }]),
            );
        }
    }

    fn analyze_host_permissions(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        let mut all_hosts: HashSet<String> = HashSet::new();
        let mut shopping_sites = 0;
        let mut has_all_urls = false;

        for host in &manifest.host_permissions {
            all_hosts.insert(host.clone());

            if host == "<all_urls>" || host.contains("*://*/*") {
                has_all_urls = true;
            }

            // Count shopping site access
            let shopping_domains = [
                "amazon",
                "ebay",
                "walmart",
                "target",
                "bestbuy",
                "aliexpress",
                "etsy",
            ];
            for domain in shopping_domains {
                if host.to_lowercase().contains(domain) {
                    shopping_sites += 1;
                    break;
                }
            }
        }

        // Also check content script matches for host access
        for cs in &manifest.content_scripts {
            for pattern in &cs.matches {
                if pattern == "<all_urls>" || pattern.contains("*://*/*") {
                    has_all_urls = true;
                }
            }
        }

        if has_all_urls {
            report.add_finding(
                Finding::indicator(
                    "supply-chain/chrome-ext/host-all-urls".to_string(),
                    "Extension has access to ALL websites".to_string(),
                    0.95,
                )
                .with_criticality(Criticality::Suspicious)
                .with_attack("T1185".to_string())
                .with_evidence(vec![Evidence {
                    method: "parser".to_string(),
                    source: "manifest.json".to_string(),
                    value: "<all_urls>".to_string(),
                    location: Some("host_permissions".to_string()),
                    ..Default::default()
                }]),
            );
        }

        // Check for broad TLD access (same domain, multiple TLDs)
        let unique_base_domains: HashSet<String> = all_hosts
            .iter()
            .filter_map(|h| {
                // Extract base domain (e.g., "amazon" from "*://*.amazon.com/*")
                let parts: Vec<&str> = h.split('.').collect();
                if parts.len() >= 2 {
                    Some(parts[parts.len() - 2].replace("*://", "").replace("*", ""))
                } else {
                    None
                }
            })
            .collect();

        if shopping_sites >= 3 {
            report.add_finding(
                Finding::indicator(
                    "supply-chain/chrome-ext/targets-shopping".to_string(),
                    format!("Extension targets {} e-commerce sites", shopping_sites),
                    0.9,
                )
                .with_criticality(Criticality::Notable)
                .with_evidence(vec![Evidence {
                    method: "heuristic".to_string(),
                    source: "manifest.json".to_string(),
                    value: format!("{} shopping sites", shopping_sites),
                    location: Some("host_permissions".to_string()),
                    ..Default::default()
                }]),
            );
        }

        // Check for global TLD coverage (suspicious for affiliate fraud)
        let host_count = all_hosts.len();
        if host_count >= 10 && unique_base_domains.len() <= 3 {
            report.add_finding(
                Finding::indicator(
                    "supply-chain/chrome-ext/global-tld-access".to_string(),
                    format!(
                        "Extension targets {} TLDs for {} base domain(s) (global coverage)",
                        host_count,
                        unique_base_domains.len()
                    ),
                    0.85,
                )
                .with_criticality(Criticality::Notable)
                .with_evidence(vec![Evidence {
                    method: "heuristic".to_string(),
                    source: "manifest.json".to_string(),
                    value: all_hosts
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    location: Some("host_permissions".to_string()),
                    ..Default::default()
                }]),
            );
        }
    }

    fn analyze_content_scripts(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        for (idx, cs) in manifest.content_scripts.iter().enumerate() {
            // Check for all_frames (can access iframes)
            if cs.all_frames {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/chrome-ext/content-script-all-frames".to_string(),
                        "Content script runs in all frames including iframes".to_string(),
                        0.85,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "parser".to_string(),
                        source: "manifest.json".to_string(),
                        value: "all_frames: true".to_string(),
                        location: Some(format!("content_scripts[{}]", idx)),
                        ..Default::default()
                    }]),
                );
            }

            // Check run_at timing
            if cs.run_at.as_deref() == Some("document_start") {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/chrome-ext/content-script-early".to_string(),
                        "Content script runs at document_start (before page loads)".to_string(),
                        0.8,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "parser".to_string(),
                        source: "manifest.json".to_string(),
                        value: "run_at: document_start".to_string(),
                        location: Some(format!("content_scripts[{}]", idx)),
                        ..Default::default()
                    }]),
                );
            }
        }
    }

    fn check_suspicious_patterns(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        // Check externally_connectable
        if manifest.externally_connectable.is_some() {
            report.add_finding(
                Finding::indicator(
                    "supply-chain/chrome-ext/externally-connectable".to_string(),
                    "Extension allows external webpage connections".to_string(),
                    0.85,
                )
                .with_criticality(Criticality::Notable)
                .with_evidence(vec![Evidence {
                    method: "parser".to_string(),
                    source: "manifest.json".to_string(),
                    value: "externally_connectable present".to_string(),
                    location: Some("externally_connectable".to_string()),
                    ..Default::default()
                }]),
            );
        }

        // Check web_accessible_resources
        if !manifest.web_accessible_resources.is_empty() {
            report.add_finding(
                Finding::indicator(
                    "supply-chain/chrome-ext/web-accessible-resources".to_string(),
                    format!(
                        "Extension exposes {} resources to web pages",
                        manifest.web_accessible_resources.len()
                    ),
                    0.75,
                )
                .with_criticality(Criticality::Baseline)
                .with_evidence(vec![Evidence {
                    method: "parser".to_string(),
                    source: "manifest.json".to_string(),
                    value: format!("{} resources", manifest.web_accessible_resources.len()),
                    location: Some("web_accessible_resources".to_string()),
                    ..Default::default()
                }]),
            );
        }

        // Check for persistent background (MV2 only)
        if let Some(ref bg) = manifest.background {
            if bg.persistent == Some(true) {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/chrome-ext/persistent-background".to_string(),
                        "Extension uses persistent background page".to_string(),
                        0.8,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "parser".to_string(),
                        source: "manifest.json".to_string(),
                        value: "persistent: true".to_string(),
                        location: Some("background".to_string()),
                        ..Default::default()
                    }]),
                );
            }
        }
    }

    fn check_update_url(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        if let Some(ref url) = manifest.update_url {
            // Google's official update URL
            if url.contains("clients2.google.com") {
                return; // Normal Chrome Web Store update
            }

            report.add_finding(
                Finding::indicator(
                    "supply-chain/chrome-ext/external-update-url".to_string(),
                    format!("Extension updates from external URL: {}", url),
                    0.9,
                )
                .with_criticality(Criticality::Suspicious)
                .with_attack("T1195.002".to_string())
                .with_evidence(vec![Evidence {
                    method: "parser".to_string(),
                    source: "manifest.json".to_string(),
                    value: url.clone(),
                    location: Some("update_url".to_string()),
                    ..Default::default()
                }]),
            );
        }
    }
}

impl Default for ChromeManifestAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ChromeManifestAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        let content = String::from_utf8_lossy(input.data);
        self.analyze_manifest(input.path, &content)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_manifest(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        // Check if it's a manifest.json that looks like a Chrome extension
        if let Some(name) = file_path.file_name() {
            if name == "manifest.json" {
                // Try to peek at content to verify it's a Chrome extension manifest
                if let Ok(content) = fs::read_to_string(file_path) {
                    return content.contains("manifest_version")
                        && (content.contains("permissions")
                            || content.contains("content_scripts")
                            || content.contains("background"));
                }
            }
        }
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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

        // Should have findings for dangerous permissions
        assert!(report
            .findings
            .iter()
            .any(|f| f.id.contains("permission-critical")));
        assert!(report
            .findings
            .iter()
            .any(|f| f.id.contains("overprivileged")));
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

        assert!(report
            .findings
            .iter()
            .any(|f| f.desc.contains("ALL websites")));
    }

    #[test]
    fn test_shopping_site_targeting() {
        let content = r#"{
            "manifest_version": 3,
            "name": "Shopping Extension",
            "version": "1.0.0",
            "host_permissions": [
                "*://*.amazon.com/*",
                "*://*.amazon.co.uk/*",
                "*://*.ebay.com/*",
                "*://*.walmart.com/*"
            ]
        }"#;

        let analyzer = ChromeManifestAnalyzer::new();
        let report = analyzer
            .analyze_manifest(Path::new("manifest.json"), content)
            .unwrap();

        assert!(report
            .findings
            .iter()
            .any(|f| f.id.contains("targets-shopping")));
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

        assert!(report
            .findings
            .iter()
            .any(|f| f.id.contains("external-update-url")));
    }
}
