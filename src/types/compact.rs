//! Compact v4 output types for minimal JSON serialization
//!
//! These types represent the v4 schema designed for 50%+ size reduction over v3.
//! Each file's JSON is fully self-contained (splittable for per-file DB storage).
//! Conversion from internal types happens via `AnalysisReport::to_compact()`.

use std::collections::HashMap;

use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use super::core::{AnalysisReport, Criticality};

/// Maximum strings per file in compact output
const MAX_STRINGS: usize = 256;

/// Maximum imports per file in compact output
const MAX_IMPORTS: usize = 4096;

/// Maximum chars per string value
const MAX_STRING_CHARS: usize = 128;

/// Maximum chars per evidence value
const MAX_EVIDENCE_CHARS: usize = 128;

/// Default confidence value (omitted from output)
const DEFAULT_CONF: f32 = 0.5;

// ========================================================================
// Compact output types (v4 schema)
// ========================================================================

/// Top-level v4 report
#[derive(Debug, Serialize)]
pub struct CompactReport {
    /// Schema version — always "4"
    pub v: &'static str,
    /// Traits repo commit hash (first 5 chars)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tv: Option<String>,
    /// Files array
    pub fs: Vec<CompactFile>,
}

/// Per-file analysis in v4 schema
#[derive(Debug, Serialize)]
pub struct CompactFile {
    /// Sequential file ID
    pub id: u32,
    /// File path (archive paths use !! delimiter)
    pub path: String,
    /// File type (e.g., "python", "elf", "pe")
    #[serde(rename = "type")]
    pub file_type: String,
    /// SHA256 hash
    pub sha: String,
    /// File size in bytes
    pub sz: u64,
    /// Weighted risk score
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub x: u32,
    /// Archive nesting depth (omit when 0)
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub dp: u32,
    /// Molecular formula
    #[serde(skip_serializing_if = "Option::is_none")]
    pub f: Option<String>,
    /// Traits (findings)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ts: Vec<CompactTrait>,
    /// Strings as tuples: [offset, value] or [offset, encoding, value]
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_string_tuples"
    )]
    pub ss: Vec<CompactString>,
    /// Import symbol names
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub is: Vec<String>,
    /// Metrics (nested structure, floats rounded to 2dp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<RoundedMetrics>,
    /// Flat structural-kv map. Path → leaf value (`a.b[0].c`
    /// notation). Auto-populated from `FileAnalysis.kv`; type-default
    /// leaves already filtered out upstream so the map is always
    /// minimal. Surfaces `go.go_root`, `jar.manifest.built_by`,
    /// `png.has_trailing_bytes`, etc. for ML pipelines without
    /// requiring a separate extraction pass.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub k: std::collections::BTreeMap<String, serde_json::Value>,
}

/// A finding/trait in compact form
#[derive(Debug, Serialize)]
pub struct CompactTrait {
    /// Trait identifier (e.g., "objectives/execution/shell/bash")
    pub i: String,
    /// Criticality level: 0=filtered, 1=component, 2=baseline, 3=notable, 4=suspicious, 5=hostile
    pub l: u8,
    /// Description
    #[serde(skip_serializing_if = "String::is_empty")]
    pub d: String,
    /// Confidence (omit when 0.5)
    #[serde(skip_serializing_if = "is_default_conf")]
    pub c: f32,
    /// MBC (Malware Behavior Catalog) ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub m: Option<String>,
    /// MITRE ATT&CK Technique ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a: Option<String>,
    /// Evidence values (flattened from Evidence structs)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub e: Vec<String>,
}

/// A string in compact tuple form
#[derive(Debug)]
pub struct CompactString {
    /// Byte offset in file
    pub offset: u64,
    /// Encoding chain (empty for plain strings)
    pub encoding: String,
    /// String value (truncated to MAX_STRING_CHARS)
    pub value: String,
}

/// Wrapper for metrics that rounds floats to 2dp during serialization
#[derive(Debug)]
pub struct RoundedMetrics(pub serde_json::Value);

impl Serialize for RoundedMetrics {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

// ========================================================================
// Helpers
// ========================================================================

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn is_default_conf(v: &f32) -> bool {
    (*v - DEFAULT_CONF).abs() < f32::EPSILON || *v == 0.0
}

/// Truncate a string at a valid UTF-8 char boundary
fn truncate_at_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Convert Criticality enum to v4 ordinal (0-5).
/// 0=filtered, 1=component, 2=baseline, 3=notable, 4=suspicious, 5=hostile
fn crit_to_int(c: Criticality) -> u8 {
    match c {
        Criticality::Filtered => 0,
        Criticality::Component => 1,
        Criticality::Baseline => 2,
        Criticality::Notable => 3,
        Criticality::Suspicious => 4,
        Criticality::Hostile => 5,
    }
}

/// Round all floats in a serde_json::Value to 2 decimal places
fn round_json_floats(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                let rounded = (f * 100.0).round() / 100.0;
                serde_json::Value::Number(
                    serde_json::Number::from_f64(rounded)
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                )
            } else {
                serde_json::Value::Number(n)
            }
        }
        serde_json::Value::Object(map) => {
            let rounded: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, round_json_floats(v)))
                .collect();
            serde_json::Value::Object(rounded)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(round_json_floats).collect())
        }
        other => other,
    }
}

/// Custom serializer for string tuples: [offset, value] or [offset, encoding, value]
fn serialize_string_tuples<S>(strings: &[CompactString], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(strings.len()))?;
    for s in strings {
        if s.encoding.is_empty() {
            seq.serialize_element(&(s.offset, &s.value))?;
        } else {
            seq.serialize_element(&(s.offset, &s.encoding, &s.value))?;
        }
    }
    seq.end()
}

// ========================================================================
// Conversion from internal types
// ========================================================================

/// Convert a FileAnalysis into a CompactFile
fn convert_file(file: &super::file_analysis::FileAnalysis) -> CompactFile {
    // Dedup findings by ID within this file, merge evidence
    let mut trait_map: HashMap<&str, CompactTrait> = HashMap::new();
    let mut trait_order: Vec<&str> = Vec::new();

    for finding in &file.findings {
        let evidence_values: Vec<String> = finding
            .evidence
            .iter()
            .filter(|e| !e.value.is_empty())
            .map(|e| truncate_at_boundary(&e.value, MAX_EVIDENCE_CHARS).to_string())
            .collect();

        if let Some(existing) = trait_map.get_mut(finding.id.as_str()) {
            // Merge evidence into existing trait
            for ev in evidence_values {
                if !existing.e.contains(&ev) {
                    existing.e.push(ev);
                }
            }
            // Keep highest criticality
            let new_crit = crit_to_int(finding.crit);
            if new_crit > existing.l {
                existing.l = new_crit;
            }
        } else {
            trait_order.push(&finding.id);
            trait_map.insert(
                &finding.id,
                CompactTrait {
                    i: finding.id.clone(),
                    l: crit_to_int(finding.crit),
                    d: finding.desc.clone(),
                    c: finding.conf,
                    m: finding.mbc.clone(),
                    a: finding.attack.clone(),
                    e: evidence_values,
                },
            );
        }
    }

    let traits: Vec<CompactTrait> = trait_order
        .into_iter()
        .filter_map(|id| trait_map.remove(id))
        .collect();

    // Convert strings to compact tuples, capped at MAX_STRINGS
    let str_tuples: Vec<CompactString> = file
        .strings
        .iter()
        .take(MAX_STRINGS)
        .map(|s| {
            let value = truncate_at_boundary(&s.value, MAX_STRING_CHARS).to_string();
            let encoding = if s.encoding_chain.is_empty() {
                String::new()
            } else {
                s.encoding_chain.join(",")
            };
            CompactString {
                offset: s.offset.unwrap_or(0),
                encoding,
                value,
            }
        })
        .collect();

    // Flatten imports to bare symbol names, capped to prevent oversized output
    let imports: Vec<String> = file
        .imports
        .iter()
        .take(MAX_IMPORTS)
        .map(|i| i.symbol.clone())
        .collect();

    // Round metrics floats to 2dp. Only the flat expose_metrics map
    // survives — typed projections were retired.
    let metrics = file.expose_metrics.as_ref().and_then(|m| {
        serde_json::to_value(m)
            .ok()
            .map(round_json_floats)
            .map(RoundedMetrics)
    });

    // Compute formula if not already present. Use the canonical filter so the
    // JSON `f` field stays in lockstep with the CLI header — both must reflect
    // notable-or-higher findings only.
    let formula = file.formula.clone().or_else(|| {
        let filtered = crate::output::filter_findings_for_formula(&file.findings);
        let f = crate::malecule_bridge::formula_from_findings(&filtered);
        (!f.is_empty()).then_some(f)
    });

    CompactFile {
        id: file.id,
        path: file.path.clone(),
        file_type: file.file_type.clone(),
        sha: file.sha256.clone(),
        sz: file.size,
        x: file.score,
        dp: file.depth,
        f: formula,
        ts: traits,
        ss: str_tuples,
        is: imports,
        ms: metrics,
        k: file.kv.clone(),
    }
}

/// Build a CompactReport from an already-finalized report's files array.
///
/// Use this when the report has already been through `finalize()` and post-processing
/// (encoding layer merging, criticality filtering). This is the primary entry point
/// for the binary crate's JSON output path.
#[must_use]
pub fn compact_from_files(files: &[super::file_analysis::FileAnalysis]) -> CompactReport {
    let fs = files.iter().map(convert_file).collect();
    let tv =
        crate::traits_repo::version().map(|v| if v.len() > 5 { v[..5].to_string() } else { v });
    CompactReport { v: "4", tv, fs }
}

impl AnalysisReport {
    /// Convert this pre-finalized report to compact v4 output format.
    ///
    /// This is a non-mutating conversion — the internal report is unchanged.
    /// Builds the root file from top-level data and includes archive members.
    /// For post-finalize reports, use `compact_from_files(&report.files)` instead.
    #[must_use]
    pub fn to_compact(&self) -> CompactReport {
        // Build the root file entry from the report's top-level data
        let root_file = self.to_file_analysis(0);
        let mut all_files = vec![root_file];

        // Add pre-populated files (archive members, decoded payloads)
        if !self.files.is_empty() {
            for (idx, file) in self.files.iter().enumerate() {
                let mut f = file.clone();
                f.id = (idx + 1) as u32;
                all_files.push(f);
            }
            all_files[0].path = self.target.path.clone();
        }

        compact_from_files(&all_files)
    }
}

#[cfg(test)]
mod formula_tests {
    use super::super::file_analysis::FileAnalysis;
    use super::super::traits_findings::Finding;
    use super::super::{Criticality, Evidence, FindingKind};
    use super::compact_from_files;

    fn finding(id: &str, crit: Criticality, conf: f32) -> Finding {
        Finding {
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: "test".to_string(),
            conf,
            crit,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![Evidence {
                method: "test".to_string(),
                source: "test".to_string(),
                value: "v".to_string(),
                location: None,
                ..Default::default()
            }],
            match_count: 1,
            source_file: None,
        }
    }

    fn file_with(findings: Vec<Finding>) -> FileAnalysis {
        let mut fa = FileAnalysis::new(0, "t.py".into(), "python".into(), "sha".into(), 1);
        fa.findings = findings;
        fa
    }

    /// JSON `f` formula must mirror the CLI: only notable-or-higher findings
    /// with confidence ≥ 0.65. Component- and baseline-criticality findings
    /// must not contribute, even when they would survive the lib-side
    /// component-reference filter.
    #[test]
    fn json_formula_excludes_component_and_baseline() {
        let files = vec![file_with(vec![
            finding("objectives/c2/http/beacon", Criticality::Notable, 0.9),
            finding("micro-behaviors/fs/file/read", Criticality::Component, 0.95),
            finding("metadata/lang/source", Criticality::Baseline, 0.95),
        ])];

        let compact = compact_from_files(&files);
        let formula = compact.fs[0].f.as_deref().unwrap_or("");
        assert!(
            formula.contains('O'),
            "expected O (objectives/Notable) in `{formula}`",
        );
        assert!(
            !formula.contains('H'),
            "did not expect H (micro-behaviors/Component) in `{formula}`",
        );
        assert!(
            !formula.contains("Md"),
            "did not expect Md (metadata/Baseline) in `{formula}`",
        );
    }

    /// Findings below the 0.65 confidence floor must not contribute, even
    /// when their criticality is otherwise eligible.
    #[test]
    fn json_formula_drops_low_confidence() {
        let files = vec![file_with(vec![finding(
            "objectives/c2/http/beacon",
            Criticality::Notable,
            0.6,
        )])];
        let compact = compact_from_files(&files);
        assert!(
            compact.fs[0].f.is_none(),
            "expected no formula when sole finding is below 0.65 conf, got {:?}",
            compact.fs[0].f,
        );
    }

    /// JSON output must reuse a pre-populated `file.formula` rather than
    /// recomputing from raw findings. This is the path that fires after
    /// `AnalysisReport::finalize()` calls `refresh_formula`.
    #[test]
    fn json_formula_prefers_prepopulated_value() {
        let mut fa = file_with(vec![finding(
            "objectives/c2/http/beacon",
            Criticality::Notable,
            0.9,
        )]);
        fa.formula = Some("PRECOMPUTED".to_string());
        let compact = compact_from_files(&[fa]);
        assert_eq!(compact.fs[0].f.as_deref(), Some("PRECOMPUTED"));
    }
}
