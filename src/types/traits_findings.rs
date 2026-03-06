//! Traits and Findings - the core model for observable characteristics and interpretive conclusions

use serde::{Deserialize, Serialize};

use super::core::Criticality;

// ========================================================================
// Traits + Findings Model
// ========================================================================

/// Kind of trait - observable characteristics of a file
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TraitKind {
    /// String literal extracted from binary or source
    String,
    /// File or directory path
    Path,
    /// Environment variable reference
    EnvVar,
    /// Imported symbol (function/variable from external library)
    Import,
    /// Exported symbol (function/variable exposed by this file)
    Export,
    /// IP address (v4 or v6)
    Ip,
    /// URL or URI
    Url,
    /// Domain name
    Domain,
    /// Email address
    Email,
    /// Base64-encoded data
    Base64,
    /// Cryptographic hash
    Hash,
    /// Registry key (Windows)
    Registry,
    /// Function or method name
    Function,
}

/// Observable characteristic of a file - a fact without interpretation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Trait {
    /// Kind of trait
    pub kind: TraitKind,
    /// The raw value discovered (truncated to 4KB on serialization)
    #[serde(serialize_with = "serialize_truncated_value")]
    pub value: String,
    /// Offset in file (hex format like "0x1234")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    /// Encoding for strings (utf8, utf16le, utf16be, ascii)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub encoding: Option<String>,
    /// Section where found (for binaries: .text, .data, .rodata)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub section: Option<String>,
    /// Source tool that discovered this trait
    pub source: String,
}

/// Kind of finding - what type of conclusion this represents
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingKind {
    /// What the code CAN do (behavioral) - e.g., net/socket, fs/write, execution/eval, anti-debug
    #[default]
    Capability,
    /// How the file is built/hidden - e.g., obfuscation, packing, high entropy, missing security features
    Structural,
    /// Signs of malicious intent (threat signals) - e.g., C2 patterns, malware signatures
    Indicator,
    /// Security vulnerabilities - e.g., SQL injection, buffer overflow
    Weakness,
}

impl FindingKind {
    /// Check if this is the default kind (Capability)
    fn is_default(&self) -> bool {
        matches!(self, Self::Capability)
    }
}

/// Check if a usize value is zero (for skip_serializing_if)
fn is_zero_usize(n: &usize) -> bool {
    *n == 0
}

/// A finding - an interpretive conclusion based on traits
/// Findings represent what we CONCLUDE from traits (capabilities, threats, behaviors)
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Finding {
    /// Finding identifier using / delimiter (e.g., "command-and-control/hardcoded-ip", "net/socket")
    pub id: String,
    /// Kind of finding (capability, structural, indicator, weakness)
    #[serde(default, skip_serializing_if = "FindingKind::is_default")]
    pub kind: FindingKind,
    /// Human-readable description (empty for compact internal findings)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub desc: String,
    /// Confidence score (0.5 = heuristic, 1.0 = definitive)
    #[serde(alias = "confidence", default)]
    pub conf: f32,
    /// Criticality level
    #[serde(default)]
    pub crit: Criticality,
    /// MBC (Malware Behavior Catalog) ID
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,
    /// MITRE ATT&CK Technique ID
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,
    /// Trait IDs that contributed to this finding (for aggregated findings)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub trait_refs: Vec<String>,
    /// Additional evidence (for findings not tied to specific traits)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,
    /// Total match count for density/frequency analysis (may exceed evidence.len())
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    pub match_count: usize,
    /// Source file path (relative to traits directory) where this trait/rule was defined
    #[allow(dead_code)] // Populated during trait evaluation, skip-serialized in output
    #[serde(skip_serializing, default)]
    pub source_file: Option<String>,
}

impl Finding {
    /// Create a new finding with the given identifier, kind, description, and confidence
    #[must_use]
    pub fn new(id: String, kind: FindingKind, desc: String, conf: f32) -> Self {
        Self {
            id,
            kind,
            desc,
            conf,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: Vec::new(),
            evidence: Vec::new(),
            match_count: 0,
            source_file: None,
        }
    }

    /// Create a capability finding
    #[must_use]
    pub fn capability(id: String, desc: String, conf: f32) -> Self {
        Self::new(id, FindingKind::Capability, desc, conf)
    }

    /// Create a structural finding (obfuscation, packing, etc.)
    #[must_use]
    pub fn structural(id: String, desc: String, conf: f32) -> Self {
        Self::new(id, FindingKind::Structural, desc, conf)
    }

    /// Create an indicator finding (threat signals)
    #[must_use]
    pub fn indicator(id: String, desc: String, conf: f32) -> Self {
        Self::new(id, FindingKind::Indicator, desc, conf)
    }

    /// Override the criticality level of this finding
    #[must_use]
    pub fn with_criticality(mut self, crit: Criticality) -> Self {
        self.crit = crit;
        self
    }

    /// Attach a Malware Behavior Catalog (MBC) identifier to this finding
    #[must_use]
    pub fn with_mbc(mut self, mbc: String) -> Self {
        self.mbc = Some(mbc);
        self
    }

    /// Attach a MITRE ATT&CK technique identifier to this finding
    #[must_use]
    pub fn with_attack(mut self, attack: String) -> Self {
        self.attack = Some(attack);
        self
    }

    /// Attach supporting evidence to this finding
    #[must_use]
    pub fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Legacy trait structure - being replaced by Artifact + Finding model
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StructuralFeature {
    /// Feature identifier using / delimiter (e.g., "binary/format/macho")
    pub id: String,
    /// Human-readable description
    pub desc: String,
    /// Evidence supporting this feature
    pub evidence: Vec<Evidence>,
}

/// Maximum size for evidence value field (4KB)
const MAX_EVIDENCE_VALUE_SIZE: usize = 4096;

/// Maximum number of evidence items per trait/finding.
/// Prevents output explosion from patterns that match thousands of times.
pub(crate) const MAX_EVIDENCE_PER_TRAIT: usize = 16;

/// Serialize evidence value, truncating to MAX_EVIDENCE_VALUE_SIZE
fn serialize_truncated_value<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if value.len() <= MAX_EVIDENCE_VALUE_SIZE {
        serializer.serialize_str(value)
    } else {
        // Truncate at a valid UTF-8 boundary
        let truncated = truncate_str(value, MAX_EVIDENCE_VALUE_SIZE - 12);
        let with_marker = format!("{}...[truncated]", truncated);
        serializer.serialize_str(&with_marker)
    }
}

/// Truncate a string at a valid UTF-8 char boundary
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

/// Maximum number of byte offsets to include in JSON output
const MAX_OFFSETS_IN_JSON: usize = 8;

/// Serialize byte offsets, truncating to MAX_OFFSETS_IN_JSON
fn serialize_truncated_offsets<S>(offsets: &[u64], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let len = offsets.len().min(MAX_OFFSETS_IN_JSON);
    let mut seq = serializer.serialize_seq(Some(len))?;
    for offset in offsets.iter().take(MAX_OFFSETS_IN_JSON) {
        seq.serialize_element(offset)?;
    }
    seq.end()
}

/// A single piece of evidence supporting a finding.
/// Evidence items with the same (method, source, value) tuple can be deduplicated
/// by merging their offsets into a single Evidence with multiple locations.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Evidence {
    /// Detection method (symbol, yara, tree-sitter, radare2, entropy, magic, etc.)
    pub method: String,
    /// Source tool (goblin, yara-x, radare2, tree-sitter-bash, etc.)
    pub source: String,
    /// Value discovered (symbol name, pattern match, etc.) - truncated to 4KB on serialization
    #[serde(serialize_with = "serialize_truncated_value")]
    pub value: String,
    /// Optional location context (semantic labels like "import", archive paths, etc.)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub location: Option<String>,
    /// Byte offsets where this evidence was found (truncated to 8 in JSON output)
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        default,
        serialize_with = "serialize_truncated_offsets"
    )]
    pub offsets: Vec<u64>,
    /// Total occurrence count when offsets are truncated (0 means use offsets.len())
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    pub count: usize,
}

impl Evidence {
    /// Create a new evidence item with the given method, source, and value.
    #[allow(dead_code)] // Builder API for future use
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        source: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            source: source.into(),
            value: value.into(),
            location: None,
            offsets: Vec::new(),
            count: 0,
        }
    }

    /// Set the location context.
    #[allow(dead_code)] // Builder API for future use
    #[must_use]
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    /// Add a byte offset where this evidence was found.
    #[allow(dead_code)] // Builder API for future use
    #[must_use]
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offsets.push(offset);
        self
    }

    /// Add multiple byte offsets.
    #[allow(dead_code)] // Builder API for future use
    #[must_use]
    pub fn with_offsets(mut self, offsets: impl IntoIterator<Item = u64>) -> Self {
        self.offsets.extend(offsets);
        self
    }

    /// Returns the deduplication key for this evidence.
    #[allow(dead_code)] // Used internally for debugging
    fn dedup_key(&self) -> (&str, &str, &str) {
        (&self.method, &self.source, &self.value)
    }

    /// Merge another evidence item with the same (method, source, value) into this one.
    /// Combines offsets and updates the count.
    pub fn merge(&mut self, other: Evidence) {
        // Add other's count (or 1 if unset)
        let other_count = if other.count > 0 { other.count } else { 1 };
        if self.count == 0 {
            self.count = 1;
        }
        self.count += other_count;

        // On first merge, extract self's location offset too (otherwise it's lost)
        if self.offsets.is_empty() {
            if let Some(offset) = self.parse_offset_from_location() {
                self.offsets.push(offset);
            }
        }

        // Try to extract offset from other.location if it looks like a hex offset
        if let Some(offset) = other.parse_offset_from_location() {
            self.offsets.push(offset);
        }

        // Merge other's offsets
        self.offsets.extend(other.offsets);
    }

    /// Try to parse a byte offset from the location string.
    /// Handles formats like "0x1234", "offset:0x1234", "offset:1234"
    fn parse_offset_from_location(&self) -> Option<u64> {
        let loc = self.location.as_ref()?;

        // Try "offset:0x..." or "offset:..."
        if let Some(rest) = loc.strip_prefix("offset:") {
            return parse_hex_or_dec(rest);
        }

        // Try plain "0x..."
        if loc.starts_with("0x") || loc.starts_with("0X") {
            return parse_hex_or_dec(loc);
        }

        None
    }
}

/// Parse a string as hex (0x prefix) or decimal
fn parse_hex_or_dec(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Deduplicate a list of evidence items by (method, source, value).
/// Items with the same key are merged, combining their offsets and counts.
#[must_use]
pub(crate) fn deduplicate_evidence(evidence: Vec<Evidence>) -> Vec<Evidence> {
    use std::collections::HashMap;

    if evidence.len() <= 1 {
        return evidence;
    }

    // Group by (method, source, value)
    // Use Entry API with match to avoid clone in and_modify (ev consumed exactly once)
    use std::collections::hash_map::Entry;
    let mut groups: HashMap<(String, String, String), Evidence> = HashMap::new();

    for ev in evidence {
        let key = (ev.method.clone(), ev.source.clone(), ev.value.clone());
        match groups.entry(key) {
            Entry::Occupied(mut entry) => entry.get_mut().merge(ev),
            Entry::Vacant(entry) => {
                entry.insert(ev);
            }
        }
    }

    groups.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== TraitKind Tests ====================

    #[test]
    fn test_trait_kind_equality() {
        assert_eq!(TraitKind::String, TraitKind::String);
        assert_ne!(TraitKind::String, TraitKind::Path);
    }

    #[test]
    fn test_trait_kind_all_variants() {
        // Ensure all variants are distinct
        let variants = vec![
            TraitKind::String,
            TraitKind::Path,
            TraitKind::EnvVar,
            TraitKind::Import,
            TraitKind::Export,
            TraitKind::Ip,
            TraitKind::Url,
            TraitKind::Domain,
            TraitKind::Email,
            TraitKind::Base64,
            TraitKind::Hash,
            TraitKind::Registry,
            TraitKind::Function,
        ];
        for (i, v1) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v1, v2);
                } else {
                    assert_ne!(v1, v2);
                }
            }
        }
    }

    // ==================== FindingKind Tests ====================

    #[test]
    fn test_finding_kind_default() {
        assert_eq!(FindingKind::default(), FindingKind::Capability);
    }

    #[test]
    fn test_finding_kind_equality() {
        assert_eq!(FindingKind::Capability, FindingKind::Capability);
        assert_ne!(FindingKind::Capability, FindingKind::Structural);
    }

    // ==================== Finding Tests ====================

    #[test]
    fn test_finding_new() {
        let f = Finding::new(
            "test/cap".to_string(),
            FindingKind::Capability,
            "Test capability".to_string(),
            0.9,
        );

        assert_eq!(f.id, "test/cap");
        assert_eq!(f.kind, FindingKind::Capability);
        assert_eq!(f.desc, "Test capability");
        assert!((f.conf - 0.9).abs() < f32::EPSILON);
        assert_eq!(f.crit, Criticality::Baseline);
        assert!(f.mbc.is_none());
        assert!(f.attack.is_none());
        assert!(f.trait_refs.is_empty());
        assert!(f.evidence.is_empty());
    }

    #[test]
    fn test_finding_capability() {
        let f = Finding::capability(
            "net/socket".to_string(),
            "Socket operations".to_string(),
            0.8,
        );

        assert_eq!(f.id, "net/socket");
        assert_eq!(f.kind, FindingKind::Capability);
    }

    #[test]
    fn test_finding_structural() {
        let f = Finding::structural(
            "obfuscation/base64".to_string(),
            "Base64 obfuscation".to_string(),
            0.7,
        );

        assert_eq!(f.kind, FindingKind::Structural);
    }

    #[test]
    fn test_finding_indicator() {
        let f = Finding::indicator(
            "command-and-control/beacon".to_string(),
            "C2 beacon pattern".to_string(),
            0.95,
        );

        assert_eq!(f.kind, FindingKind::Indicator);
    }

    #[test]
    fn test_finding_with_criticality() {
        let f = Finding::capability("test".to_string(), "desc".to_string(), 0.9)
            .with_criticality(Criticality::Hostile);

        assert_eq!(f.crit, Criticality::Hostile);
    }

    #[test]
    fn test_finding_with_mbc() {
        let f = Finding::capability("test".to_string(), "desc".to_string(), 0.9)
            .with_mbc("B0015.001".to_string());

        assert_eq!(f.mbc, Some("B0015.001".to_string()));
    }

    #[test]
    fn test_finding_with_attack() {
        let f = Finding::capability("test".to_string(), "desc".to_string(), 0.9)
            .with_attack("T1059.001".to_string());

        assert_eq!(f.attack, Some("T1059.001".to_string()));
    }

    #[test]
    fn test_finding_with_evidence() {
        let evidence = vec![Evidence {
            method: "symbol".to_string(),
            source: "goblin".to_string(),
            value: "connect".to_string(),
            location: Some("0x1000".to_string()),
            ..Default::default()
        }];

        let f = Finding::capability("test".to_string(), "desc".to_string(), 0.9)
            .with_evidence(evidence);

        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.evidence[0].value, "connect");
    }

    #[test]
    fn test_finding_builder_chain() {
        let f = Finding::capability("net/http".to_string(), "HTTP client".to_string(), 0.95)
            .with_criticality(Criticality::Suspicious)
            .with_mbc("C0002".to_string())
            .with_attack("T1071.001".to_string());

        assert_eq!(f.id, "net/http");
        assert_eq!(f.crit, Criticality::Suspicious);
        assert_eq!(f.mbc, Some("C0002".to_string()));
        assert_eq!(f.attack, Some("T1071.001".to_string()));
    }

    // ==================== truncate_str Tests ====================

    #[test]
    fn test_truncate_str_short() {
        let s = "hello";
        assert_eq!(truncate_str(s, 100), "hello");
    }

    #[test]
    fn test_truncate_str_exact() {
        let s = "hello";
        assert_eq!(truncate_str(s, 5), "hello");
    }

    #[test]
    fn test_truncate_str_cut() {
        let s = "hello world";
        assert_eq!(truncate_str(s, 5), "hello");
    }

    #[test]
    fn test_truncate_str_utf8_boundary() {
        // "é" is 2 bytes in UTF-8
        let s = "café";
        // Truncating at byte 3 would split the é, so it should back up to byte 3 (caf)
        let result = truncate_str(s, 4);
        assert_eq!(result, "caf");
    }

    #[test]
    fn test_truncate_str_multibyte() {
        // "日" is 3 bytes in UTF-8
        let s = "日本語"; // 9 bytes total
                          // Truncating at 5 bytes should give us just "日" (3 bytes)
        let result = truncate_str(s, 5);
        assert_eq!(result, "日");
    }

    #[test]
    fn test_truncate_str_zero() {
        let s = "hello";
        assert_eq!(truncate_str(s, 0), "");
    }

    // ==================== Evidence Tests ====================

    #[test]
    fn test_evidence_creation() {
        let e = Evidence {
            method: "yara".to_string(),
            source: "yara-x".to_string(),
            value: "suspicious_pattern".to_string(),
            location: Some("0x1234".to_string()),
            ..Default::default()
        };

        assert_eq!(e.method, "yara");
        assert_eq!(e.source, "yara-x");
        assert_eq!(e.value, "suspicious_pattern");
        assert_eq!(e.location, Some("0x1234".to_string()));
    }

    #[test]
    fn test_evidence_no_location() {
        let e = Evidence {
            method: "import".to_string(),
            source: "goblin".to_string(),
            value: "CreateRemoteThread".to_string(),
            location: None,
            ..Default::default()
        };

        assert!(e.location.is_none());
    }

    // ==================== StructuralFeature Tests ====================

    #[test]
    fn test_structural_feature_creation() {
        let sf = StructuralFeature {
            id: "binary/format/pe".to_string(),
            desc: "PE executable format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "goblin".to_string(),
                value: "MZ".to_string(),
                location: Some("0x0".to_string()),
                ..Default::default()
            }],
        };

        assert_eq!(sf.id, "binary/format/pe");
        assert_eq!(sf.evidence.len(), 1);
    }
}
