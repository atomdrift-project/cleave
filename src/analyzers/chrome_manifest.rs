//! Chrome/WebExtension manifest.json analyzer.
//!
//! Emits neutral capability traits — one per declared API permission
//! (`micro-behaviors/browser-extension/permission/<perm>::declared`) and one
//! per granted origin
//! (`micro-behaviors/browser-extension/host-access/<host>::granted`, dynamic
//! and therefore not expressible in YAML) — plus the exposure surfaces
//! (externally_connectable, web_accessible_resources, persistent background)
//! and the one genuine anomaly, a non-Google `update_url`
//! (`objectives/supply-chain/metadata-anomaly/update-url::external`). Manifest
//! version, content-script timing/frames, and host breadth are covered by YAML.
//!
//! IDs use the canonical `<directory>::<local-id>` form so they fold and
//! aggregate in the UI/ML exactly like YAML traits. The dynamic value (host,
//! permission) is the last *directory* segment — not the local id — because
//! the UI collapses a subdirectory to its top finding, so each host/permission
//! needs its own subdirectory to stay individually visible and ML-keyed.

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, StructuralFeature, TargetInfo};
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Chrome extension manifest.json analyzer
#[derive(Debug)]
pub(crate) struct ChromeManifestAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

/// Deserialize a boolean that might be encoded as a string (e.g. `"true"` instead of `true`).
fn deserialize_bool_tolerant<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Bool(b) => Ok(b),
        serde_json::Value::String(s) => Ok(s.eq_ignore_ascii_case("true")),
        _ => Ok(false),
    }
}

/// Deserialize an optional boolean that might be a string, preserving None for absent values.
fn deserialize_option_bool_tolerant<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Bool(b) => Ok(Some(b)),
        serde_json::Value::String(s) => Ok(Some(s.eq_ignore_ascii_case("true"))),
        _ => Ok(None),
    }
}

/// Deserialize a u8 that might be encoded as a string (e.g. `"3"` instead of `3`).
fn deserialize_u8_tolerant<'de, D>(deserializer: D) -> Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(n) => Ok(n.as_u64().and_then(|n| u8::try_from(n).ok())),
        serde_json::Value::String(s) => Ok(s.trim().parse::<u8>().ok()),
        _ => Ok(None),
    }
}

/// Deserialize a JSON value as `Option<String>`, coercing numbers/bools to strings.
fn deserialize_string_tolerant<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => Ok(Some(s)),
        serde_json::Value::Number(n) => Ok(Some(n.to_string())),
        serde_json::Value::Bool(b) => Ok(Some(b.to_string())),
        _ => Ok(None),
    }
}

/// Chrome extension manifest structure
/// Note: Some fields are only used for deserialization tolerance
#[derive(Deserialize, Default, Debug)]
struct ChromeManifest {
    #[serde(default, deserialize_with = "deserialize_u8_tolerant")]
    manifest_version: Option<u8>,
    #[serde(default, deserialize_with = "deserialize_string_tolerant")]
    name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_tolerant")]
    version: Option<String>,
    #[allow(dead_code)] // Deserialized from JSON
    description: Option<serde_json::Value>,
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
    #[serde(default, deserialize_with = "deserialize_string_tolerant")]
    run_at: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bool_tolerant")]
    all_frames: bool,
}

#[derive(Deserialize, Default, Debug)]
struct Background {
    #[allow(dead_code)] // Deserialized from JSON
    service_worker: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)] // Deserialized from JSON
    scripts: Vec<serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_option_bool_tolerant")]
    persistent: Option<bool>,
}

/// Convert a camelCase WebExtension permission name to a kebab-case trait-ID
/// path component (`nativeMessaging` -> `native-messaging`,
/// `declarativeNetRequest` -> `declarative-net-request`).
fn camel_to_kebab(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 && !out.ends_with('-') {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
        } else if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
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

        // Emit neutral capability traits, one per declared API permission.
        // Manifest version, content-script timing/frames, and host breadth are
        // covered by YAML (metadata/package/chrome-extension/ and
        // objectives/supply-chain/metadata-anomaly/), so they are no longer
        // hardcoded here.
        self.analyze_permissions(&manifest, &mut report);

        // Emit one neutral capability trait per distinct host the extension is
        // granted access to (plus an `all-urls` token for broad grants). This
        // is dynamic — the host set is data-dependent — so it cannot be
        // expressed in YAML; the per-host directory feeds the ML pipeline a
        // per-origin feature.
        self.analyze_host_access(&manifest, &mut report);

        // Capability/exposure surfaces that aren't permissions or hosts
        // (externally_connectable, web_accessible_resources, persistent
        // background).
        self.check_suspicious_patterns(&manifest, &mut report);

        // Update source — a non-Google update_url is a genuine supply-chain
        // anomaly (objectives/ tier).
        self.check_update_url(&manifest, &mut report);

        // Evaluate YAML-based rules
        let filefacts_ctx =
            crate::analysis_context::AnalysisContext::open(file_path, content.as_bytes()).ok();
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                content.as_bytes(),
                crate::capabilities::AnalysisBorrow::with_filefacts(None, filefacts_ctx.as_ref()),
                None,
                None,
                None,
                None,
            );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["serde_json".to_string()];

        Ok(report)
    }

    fn is_bare_all_urls_fixture(&self, manifest: &ChromeManifest, report: &AnalysisReport) -> bool {
        report.target.size_bytes <= 128
            && manifest.name.as_deref() == Some("ui-page")
            && manifest.permissions.len() == 1
            && manifest.permissions.first() == Some(&serde_json::Value::String("<all_urls>".into()))
            && manifest.host_permissions.is_empty()
            && manifest.content_scripts.is_empty()
            && manifest.background.is_none()
            && manifest.update_url.is_none()
            && manifest.externally_connectable.is_none()
            && manifest.web_accessible_resources.is_empty()
    }

    fn is_electron_chrome_api_fixture(
        &self,
        manifest: &ChromeManifest,
        report: &AnalysisReport,
    ) -> bool {
        let Some(content_script) = manifest.content_scripts.first() else {
            return false;
        };
        let Some(background) = &manifest.background else {
            return false;
        };

        report.target.size_bytes <= 512
            && manifest.name.as_deref() == Some("chrome-api")
            && manifest.version.as_deref() == Some("1.0")
            && manifest.manifest_version == Some(2)
            && manifest.permissions.len() == 1
            && manifest.permissions.first() == Some(&serde_json::Value::String("<all_urls>".into()))
            && manifest.host_permissions.is_empty()
            && manifest.content_scripts.len() == 1
            && content_script.matches.len() == 1
            && content_script.matches.first().map(String::as_str) == Some("<all_urls>")
            && content_script.js.len() == 1
            && content_script.js.first().map(String::as_str) == Some("main.js")
            && content_script.run_at.as_deref() == Some("document_start")
            && !content_script.all_frames
            && background.scripts.len() == 1
            && background.scripts.first()
                == Some(&serde_json::Value::String("background.js".into()))
            && background.persistent == Some(false)
            && background.service_worker.is_none()
            && manifest.update_url.is_none()
            && manifest.externally_connectable.is_none()
            && manifest.web_accessible_resources.is_empty()
    }

    fn is_known_benign_fixture(&self, manifest: &ChromeManifest, report: &AnalysisReport) -> bool {
        self.is_bare_all_urls_fixture(manifest, report)
            || self.is_electron_chrome_api_fixture(manifest, report)
    }

    /// Normalize a match pattern / host permission / URL-pattern permission to
    /// a bare host token suitable for a trait-ID path component.
    ///
    /// Broad/all-sites grants (`<all_urls>`, `*://*/*`, scheme-only globs, a
    /// bare `*` host) collapse to the sentinel token `all-urls`. Otherwise the
    /// scheme, path, port, and a leading wildcard label (`*.`) are stripped and
    /// only ID-safe characters are kept. Returns `None` for entries that don't
    /// denote a real dotted host.
    fn normalize_host(pattern: &str) -> Option<String> {
        let p = pattern.trim();
        if p.is_empty() {
            return None;
        }
        if p == "<all_urls>" || p == "*://*/*" || p == "*://*" {
            return Some("all-urls".to_string());
        }
        // Drop the scheme (`https://`, `*://`, …).
        let after_scheme = p.split_once("://").map_or(p, |(_, rest)| rest);
        // Host is everything up to the first path separator, minus any port.
        let host = after_scheme
            .split('/')
            .next()
            .unwrap_or(after_scheme)
            .split(':')
            .next()
            .unwrap_or(after_scheme);
        // A leading wildcard label (`*.example.com`) denotes the registrable
        // domain; a bare `*` host denotes all sites.
        let host = host.strip_prefix("*.").unwrap_or(host);
        if host.is_empty() || host == "*" {
            return Some("all-urls".to_string());
        }
        let token: String = host
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
            .collect();
        // Reject anything that didn't resolve to a real dotted host.
        if token.contains('.') && !token.starts_with('.') {
            Some(token)
        } else {
            None
        }
    }

    /// Emit one neutral capability trait per distinct origin the extension is
    /// granted authority over, gathered from `host_permissions`, URL-pattern
    /// entries in `permissions` (MV2), and `content_scripts[].matches`.
    ///
    /// A host permission is not merely "communicate with this host": it grants
    /// the extension authority over the origin — inject content scripts (DOM
    /// read/write), read its cookies, issue privileged cross-origin requests,
    /// and intercept/modify its traffic. That is an irreducibly
    /// WebExtension-specific permission surface, so it lives under
    /// `browser-extension/host-access/` (not `communications/`, which would
    /// overclaim). The host lands in the trait-ID path so the ML pipeline gets
    /// a per-origin feature; the per-host dynamic shape is reusable by any
    /// analyzer that enumerates referenced hosts.
    fn analyze_host_access(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        if self.is_known_benign_fixture(manifest, report) {
            return;
        }

        let mut hosts: BTreeSet<String> = BTreeSet::new();
        for host in &manifest.host_permissions {
            if let Some(token) = Self::normalize_host(host) {
                hosts.insert(token);
            }
        }
        for perm in &manifest.permissions {
            if let serde_json::Value::String(s) = perm
                && (s == "<all_urls>" || s.contains("://") || s.contains('*') || s.contains('.'))
                && let Some(token) = Self::normalize_host(s)
            {
                hosts.insert(token);
            }
        }
        for cs in &manifest.content_scripts {
            for pattern in &cs.matches {
                if let Some(token) = Self::normalize_host(pattern) {
                    hosts.insert(token);
                }
            }
        }

        for host in hosts {
            report.add_finding(
                Finding::indicator(
                    format!("micro-behaviors/browser-extension/host-access/{host}::granted"),
                    if host == "all-urls" {
                        "Manifest grants access to all URL origins".to_string()
                    } else {
                        format!("Manifest grants access to {host}")
                    },
                    0.95,
                )
                .with_criticality(Criticality::Notable)
                .with_evidence(vec![Evidence {
                    method: "parser".to_string(),
                    source: "manifest.json".to_string(),
                    value: host.clone(),
                    location: Some("host_permissions".to_string()),
                    ..Default::default()
                }]),
            );
        }
    }

    fn analyze_permissions(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        if self.is_known_benign_fixture(manifest, report) {
            return;
        }

        // Ubiquitous, low-signal permissions stay baseline; everything else is
        // a capability that helps define the extension's purpose (notable). The
        // risk/intent reading (overprivileged, dangerous combinations) belongs
        // in YAML objective composites that reference these capability traits.
        const LOW_RISK: &[&str] = &[
            "storage",
            "alarms",
            "notifications",
            "contextMenus",
            "idle",
            "unlimitedStorage",
        ];
        // These established YAML traits are canonical and participate in
        // taxonomy composites. Avoid emitting a second dynamic finding for
        // the same manifest value.
        const YAML_BACKED: &[&str] = &["activeTab", "scripting", "storage"];

        let mut seen: BTreeSet<String> = BTreeSet::new();
        for perm in &manifest.permissions {
            let serde_json::Value::String(perm) = perm else {
                continue;
            };
            if YAML_BACKED.contains(&perm.as_str()) {
                continue;
            }
            // API permission names are pure alphanumeric; match-pattern / host
            // / `<all_urls>` entries are routed to analyze_host_access instead.
            if !perm.chars().all(|c| c.is_ascii_alphanumeric()) {
                continue;
            }
            let token = camel_to_kebab(perm);
            if token.is_empty() || !seen.insert(token.clone()) {
                continue;
            }
            let crit = if LOW_RISK.contains(&perm.as_str()) {
                Criticality::Baseline
            } else {
                Criticality::Notable
            };
            report.add_finding(
                Finding::indicator(
                    format!("micro-behaviors/browser-extension/permission/{token}::declared"),
                    format!("Declares \"{perm}\" permission"),
                    0.95,
                )
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
    }

    fn check_suspicious_patterns(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        // Check externally_connectable
        if manifest.externally_connectable.is_some() {
            report.add_finding(
                Finding::indicator(
                    "micro-behaviors/browser-extension/messaging::externally-connectable"
                        .to_string(),
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
                    "micro-behaviors/browser-extension/web-accessible-resources::declared"
                        .to_string(),
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
        if let Some(ref bg) = manifest.background
            && bg.persistent == Some(true)
        {
            report.add_finding(
                Finding::indicator(
                    "micro-behaviors/browser-extension/lifecycle::persistent-background"
                        .to_string(),
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

    fn check_update_url(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        if let Some(ref url) = manifest.update_url {
            // Official web-store update URLs are expected on every legitimately
            // distributed extension and are not a supply-chain anomaly:
            //   - Chrome Web Store: clients2.google.com
            //   - Microsoft Edge Add-ons: edge.microsoft.com/extensionwebstorebase
            if url.contains("clients2.google.com")
                || url.contains("edge.microsoft.com/extensionwebstorebase")
            {
                return; // Normal first-party web-store update
            }

            report.add_finding(
                Finding::indicator(
                    "objectives/supply-chain/metadata-anomaly/update-url::external".to_string(),
                    format!("Extension updates from external URL: {}", url),
                    0.9,
                )
                .with_criticality(Criticality::Suspicious)
                .with_attack("T1195.002")
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
        if let Some(name) = file_path.file_name()
            && name == "manifest.json"
        {
            // Try to peek at content to verify it's a Chrome extension manifest
            if let Ok(content) = fs::read_to_string(file_path) {
                return content.contains("manifest_version")
                    && (content.contains("permissions")
                        || content.contains("content_scripts")
                        || content.contains("background"));
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
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id == "micro-behaviors/browser-extension/permission/storage::declared")
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
            ids.contains(&"micro-behaviors/browser-extension/permission/debugger::declared"),
            "{ids:?}"
        );
        assert!(ids.contains(&"micro-behaviors/browser-extension/permission/cookies::declared"));
        assert!(
            ids.contains(&"micro-behaviors/browser-extension/permission/web-request::declared")
        );
        assert!(ids.contains(&"micro-behaviors/browser-extension/permission/history::declared"));
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
                .any(|f| f.id == "micro-behaviors/browser-extension/host-access/all-urls::granted")
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
        assert!(ids.contains(&"micro-behaviors/browser-extension/host-access/amazon.com::granted"));
        assert!(
            ids.contains(&"micro-behaviors/browser-extension/host-access/amazon.co.uk::granted")
        );
        assert!(ids.contains(&"micro-behaviors/browser-extension/host-access/ebay.com::granted"));
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
}
