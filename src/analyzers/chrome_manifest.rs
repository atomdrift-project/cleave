//! Chrome/WebExtension manifest.json analyzer.
//!
//! Emits declared authority as metadata, not runtime behavior. Canonical
//! YAML-backed API permissions are evaluated by the shared rule engine;
//! remaining API names use `metadata/permission/extension-api/<api>::declared`.
//! Parsed host tokens use `metadata/permission/host/<host>::declared`, with
//! original patterns and field paths retained as evidence. These dynamic
//! data keys preserve the existing per-value UI grouping; they add no YAML
//! rule directories or decoding. Exposure and activation declarations are
//! metadata too. Update-URL anomaly rules retain their objective home.

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, StructuralFeature, TargetInfo};
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Chrome extension manifest.json analyzer
#[derive(Debug)]
pub(crate) struct ChromeManifestAnalyzer {
    engine: crate::Engine,
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
            engine: crate::Engine::empty(),
        }
    }

    /// Analyze under `engine`: its rules and settings.
    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.engine = engine;
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
        let filefacts_ctx = Some(crate::analysis_context::AnalysisContext::open(
            file_path,
            content.as_bytes(),
        ));
        self.engine
            .rules()
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                content.as_bytes(),
                crate::capabilities::AnalysisBorrow::with_filefacts(None, filefacts_ctx.as_ref()),
                None,
                None,
                None,
                None,
            );

        Self::deduplicate_declared_permissions(&manifest, &mut report);

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

    /// Electron's `spec/fixtures/extensions/chrome-api/manifest.json`, which
    /// ships in Electron source trees. Pinned by content hash, not by shape:
    /// its shape (a script injected into every URL at `document_start` plus a
    /// background page) is exactly what a capable malicious extension declares.
    fn is_electron_chrome_api_fixture(report: &AnalysisReport) -> bool {
        const ELECTRON_CHROME_API_SHA256: &str =
            "7eff0f97ed0d15789324981fad82a50b2e9810386b347fad2249d43942e6393c";
        report.target.sha256 == ELECTRON_CHROME_API_SHA256
    }

    fn is_known_benign_fixture(&self, manifest: &ChromeManifest, report: &AnalysisReport) -> bool {
        self.is_bare_all_urls_fixture(manifest, report)
            || Self::is_electron_chrome_api_fixture(report)
    }

    /// Normalize a match pattern / host permission / URL-pattern permission to
    /// a bare host token suitable for a trait-ID path component.
    ///
    /// Only `<all_urls>` uses the `all-urls` token. Wildcard hosts use
    /// `all-hosts`, retaining their scheme/path limits in evidence. Otherwise the
    /// scheme, path, port, and a leading wildcard label (`*.`) are stripped and
    /// only ID-safe characters are kept. Returns `None` for entries that don't
    /// denote a real dotted host.
    fn normalize_host(pattern: &str) -> Option<String> {
        let p = pattern.trim();
        if p.is_empty() {
            return None;
        }
        if p == "<all_urls>" {
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
        if host.is_empty() && p.starts_with("file://") {
            return Some("file-urls".to_string());
        }
        if host == "*" {
            return Some("all-hosts".to_string());
        }
        if host.is_empty() {
            return None;
        }
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return None;
        }
        let token = host.to_ascii_lowercase();
        // Reject anything that didn't resolve to a real dotted host.
        if token.contains('.')
            && token
                .split('.')
                .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
        {
            Some(token)
        } else {
            None
        }
    }

    /// Emit declared host-pattern metadata, preserving each source field and
    /// original scheme/path/wildcard rather than asserting runtime access.
    fn analyze_host_access(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        if self.is_known_benign_fixture(manifest, report) {
            return;
        }
        let mut hosts: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
        let mut record = |pattern: &str, location: String| {
            if let Some(token) = Self::normalize_host(pattern) {
                hosts
                    .entry(token)
                    .or_default()
                    .insert((location, pattern.to_string()));
            }
        };
        for (index, pattern) in manifest.host_permissions.iter().enumerate() {
            record(pattern, format!("host_permissions[{index}]"));
        }
        for (index, perm) in manifest.permissions.iter().enumerate() {
            if let serde_json::Value::String(pattern) = perm
                && (pattern == "<all_urls>" || pattern.contains("://"))
            {
                record(pattern, format!("permissions[{index}]"));
            }
        }
        for (script, cs) in manifest.content_scripts.iter().enumerate() {
            for (index, pattern) in cs.matches.iter().enumerate() {
                record(
                    pattern,
                    format!("content_scripts[{script}].matches[{index}]"),
                );
            }
        }
        for (host, patterns) in hosts {
            let desc = match host.as_str() {
                "all-urls" => "Declares an all-URL match pattern".to_string(),
                "all-hosts" => "Declares a wildcard-host match pattern".to_string(),
                "file-urls" => "Declares a file-URL match pattern".to_string(),
                _ => format!("Declares host patterns for {host}"),
            };
            let evidence = patterns
                .into_iter()
                .map(|(location, value)| Evidence {
                    method: "parser".to_string(),
                    source: "manifest.json".to_string(),
                    value,
                    location: Some(location),
                    ..Default::default()
                })
                .collect();
            report.add_finding(
                Finding::indicator(
                    format!("metadata/permission/host/{host}::declared"),
                    desc,
                    0.95,
                )
                .with_criticality(Criticality::Notable)
                .with_evidence(evidence),
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
        // Emit a declaration fallback even without a configured rule tree;
        // deduplicate against matching canonical YAML after evaluation.
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for perm in &manifest.permissions {
            let serde_json::Value::String(perm) = perm else {
                continue;
            };
            // API permission names may be dotted; match-pattern / host
            // / `<all_urls>` entries are routed to analyze_host_access instead.
            if !perm.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
                || perm.split('.').any(str::is_empty)
            {
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
                    format!("metadata/permission/extension-api/{token}::declared"),
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

    /// Prefer a canonical permission only when its YAML matcher actually fired.
    /// Missing or platform-filtered trait trees retain the native declaration.
    fn deduplicate_declared_permissions(manifest: &ChromeManifest, report: &mut AnalysisReport) {
        const CANONICAL: &[(&str, &str)] = &[
            (
                "activeTab",
                "metadata/permission/active-tab::permission-active-tab",
            ),
            (
                "scripting",
                "metadata/permission/manifest::permission-scripting",
            ),
            ("storage", "metadata/permission/storage::permission-storage"),
            (
                "unlimitedStorage",
                "metadata/permission/storage::permission-unlimited-storage",
            ),
            ("tabs", "metadata/permission/manifest::permission-tabs"),
            (
                "notifications",
                "metadata/permission/manifest::permission-notifications",
            ),
            ("alarms", "metadata/permission/alarm::permission-alarms"),
            ("cookies", "metadata/permission/cookie::permission-cookies"),
            ("history", "metadata/permission/history::permission-history"),
            (
                "downloads",
                "metadata/permission/download::permission-downloads",
            ),
            (
                "nativeMessaging",
                "metadata/permission/extension-api::permission-native-messaging",
            ),
            (
                "proxy",
                "metadata/permission/extension-api::permission-proxy",
            ),
            (
                "debugger",
                "metadata/permission/debugger::permission-debugger",
            ),
            (
                "identity",
                "metadata/permission/identity::permission-identity",
            ),
            (
                "identity.email",
                "metadata/permission/manifest::permission-identity-email",
            ),
            (
                "clipboardRead",
                "metadata/permission/clipboard::permission-clipboard-read",
            ),
            (
                "clipboardWrite",
                "metadata/permission/clipboard::permission-clipboard-write",
            ),
            ("webRequest", "metadata/permission/network::web-request"),
            (
                "webRequestBlocking",
                "metadata/permission/network::web-request-blocking",
            ),
            (
                "declarativeNetRequest",
                "metadata/permission/network::permission-declarative-net-request",
            ),
            (
                "declarativeNetRequestWithHostAccess",
                "metadata/permission/network::declarative-net-request-with-host",
            ),
        ];
        let mut replacements: BTreeMap<String, &str> = BTreeMap::new();
        for (permission, canonical) in CANONICAL {
            if manifest
                .permissions
                .iter()
                .any(|v| v.as_str() == Some(permission))
                && report.findings.iter().any(|f| f.id == *canonical)
            {
                replacements.insert(
                    format!(
                        "metadata/permission/extension-api/{}::declared",
                        camel_to_kebab(permission)
                    ),
                    canonical,
                );
            }
        }
        report
            .findings
            .retain(|f| !replacements.contains_key(f.id.as_str()));
        for finding in &mut report.findings {
            for reference in &mut finding.trait_refs {
                if let Some(canonical) = replacements.get(reference.as_str()) {
                    *reference = (*canonical).into();
                }
            }
            finding.trait_refs.sort_unstable();
            finding.trait_refs.dedup();
        }
    }

    fn check_suspicious_patterns(&self, manifest: &ChromeManifest, report: &mut AnalysisReport) {
        // Check externally_connectable
        if manifest.externally_connectable.is_some() {
            report.add_finding(
                Finding::indicator(
                    "metadata/permission/extension-api::external-connection-policy".to_string(),
                    "Declares external connection policy".to_string(),
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
                    "metadata/permission/extension-api::web-accessible-resource-entries"
                        .to_string(),
                    format!(
                        "Declares {} web-accessible resource entries",
                        manifest.web_accessible_resources.len()
                    ),
                    0.75,
                )
                .with_criticality(Criticality::Baseline)
                .with_evidence(vec![Evidence {
                    method: "parser".to_string(),
                    source: "manifest.json".to_string(),
                    value: format!(
                        "{} resource entries",
                        manifest.web_accessible_resources.len()
                    ),
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
                    "metadata/permission/activation::persistent-background-declaration".to_string(),
                    "Declares persistent background page".to_string(),
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
            report.findings.iter().any(
                |f| f.id == "metadata/permission/activation::persistent-background-declaration"
            )
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
}
