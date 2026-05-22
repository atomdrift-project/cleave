//! Compact v5 output types for minimal JSON serialization
//!
//! These types represent the v5 schema designed for dense filefacts-backed output.
//! Each file's JSON is fully self-contained (splittable for per-file DB storage).
//! Conversion from internal types happens via `AnalysisReport::to_compact()`.

use std::collections::{BTreeMap, HashMap};

use serde::ser::{SerializeSeq, SerializeStruct};
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
// Compact output types (v5 schema)
// ========================================================================

/// Top-level v5 report
#[derive(Debug, Serialize)]
pub struct CompactReport {
    /// Schema version — always "5"
    pub v: &'static str,
    /// Traits repo commit hash (first 5 chars)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tv: Option<String>,
    /// Files array
    pub fs: Vec<CompactFile>,
}

/// Per-file analysis in v5 schema
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
    /// Dense filefacts-derived facts. This is command-complete for cleave's
    /// facts/value/metrics/sections/symbol commands, but not a lossless mirror
    /// of filefacts' researcher-facing JSON.
    #[serde(skip_serializing_if = "CompactFacts::is_empty")]
    ff: CompactFacts,
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

/// Dense filefacts-backed fact block for compact v5.
#[derive(Debug)]
struct CompactFacts {
    /// File identity without source/provenance tags. Usually mirrors the
    /// top-level `type` field but stays under `ff` for consumers that treat
    /// facts as an independent cache unit.
    id: String,
    /// Metrics (nested structure, floats rounded to 2dp).
    metrics: Option<RoundedMetrics>,
    /// Flat structural-value map. Path → leaf value (`a.b[0].c` notation).
    values: BTreeMap<String, serde_json::Value>,
    /// Strings as tuples: [offset, encoding, value].
    strings: Vec<CompactString>,
    /// Imports as tuples: [library, name] or [library, name, ordinal].
    imports: Vec<CompactImport>,
    /// Exports as tuples: [name] or [name, forward_to].
    exports: Vec<CompactExport>,
    /// Functions as tuples: [name], [name, offset], or [name, offset, kind].
    functions: Vec<CompactFunction>,
    /// Sections as tuples: [name, file_offset, file_size, entropy, flags].
    sections: Vec<CompactSection>,
    /// AST targets.
    targets: Vec<String>,
    /// AST members.
    members: Vec<String>,
    /// AST call string arguments.
    call_args: Vec<CompactCallArg>,
    /// Recoverable extraction errors as [kind, stage].
    errors: Vec<CompactError>,
}

impl CompactFacts {
    fn is_empty(&self) -> bool {
        self.id.is_empty()
            && self.metrics.is_none()
            && self.values.is_empty()
            && self.strings.is_empty()
            && self.imports.is_empty()
            && self.exports.is_empty()
            && self.functions.is_empty()
            && self.sections.is_empty()
            && self.targets.is_empty()
            && self.members.is_empty()
            && self.call_args.is_empty()
            && self.errors.is_empty()
    }
}

impl Serialize for CompactFacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut fields = usize::from(!self.id.is_empty());
        fields += usize::from(self.metrics.is_some());
        fields += usize::from(!self.values.is_empty());
        fields += usize::from(!self.strings.is_empty());
        fields += usize::from(!self.imports.is_empty());
        fields += usize::from(!self.exports.is_empty());
        fields += usize::from(!self.functions.is_empty());
        fields += usize::from(!self.sections.is_empty());
        fields += usize::from(!self.targets.is_empty());
        fields += usize::from(!self.members.is_empty());
        fields += usize::from(!self.call_args.is_empty());
        fields += usize::from(!self.errors.is_empty());

        let mut st = serializer.serialize_struct("CompactFacts", fields)?;
        if !self.id.is_empty() {
            st.serialize_field("id", &self.id)?;
        }
        if let Some(metrics) = &self.metrics {
            st.serialize_field("m", metrics)?;
        }
        if !self.values.is_empty() {
            st.serialize_field("v", &self.values)?;
        }
        if !self.strings.is_empty() {
            st.serialize_field("s", &StringTuples(&self.strings))?;
        }
        if !self.imports.is_empty() {
            st.serialize_field("i", &self.imports)?;
        }
        if !self.exports.is_empty() {
            st.serialize_field("x", &self.exports)?;
        }
        if !self.functions.is_empty() {
            st.serialize_field("fn", &self.functions)?;
        }
        if !self.sections.is_empty() {
            st.serialize_field("sc", &self.sections)?;
        }
        if !self.targets.is_empty() {
            st.serialize_field("ct", &self.targets)?;
        }
        if !self.members.is_empty() {
            st.serialize_field("mc", &self.members)?;
        }
        if !self.call_args.is_empty() {
            st.serialize_field("ca", &self.call_args)?;
        }
        if !self.errors.is_empty() {
            st.serialize_field("er", &self.errors)?;
        }
        st.end()
    }
}

#[derive(Debug)]
struct CompactImport {
    library: String,
    name: String,
    ordinal: Option<u64>,
}

impl Serialize for CompactImport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = if self.ordinal.is_some() { 3 } else { 2 };
        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(&self.library)?;
        seq.serialize_element(&self.name)?;
        if let Some(ordinal) = self.ordinal {
            seq.serialize_element(&ordinal)?;
        }
        seq.end()
    }
}

#[derive(Debug)]
struct CompactExport {
    name: String,
    forward_to: Option<String>,
}

impl Serialize for CompactExport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = if self.forward_to.is_some() { 2 } else { 1 };
        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(&self.name)?;
        if let Some(forward_to) = &self.forward_to {
            seq.serialize_element(forward_to)?;
        }
        seq.end()
    }
}

#[derive(Debug)]
struct CompactFunction {
    name: String,
    offset: Option<u64>,
    kind: Option<String>,
}

impl Serialize for CompactFunction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = if self.kind.is_some() {
            3
        } else if self.offset.is_some() {
            2
        } else {
            1
        };
        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(&self.name)?;
        if let Some(offset) = self.offset {
            seq.serialize_element(&offset)?;
        }
        if let Some(kind) = &self.kind {
            seq.serialize_element(kind)?;
        }
        seq.end()
    }
}

#[derive(Debug)]
struct CompactSection {
    name: String,
    offset: u64,
    size: u64,
    entropy: f64,
    flags: String,
}

impl Serialize for CompactSection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(5))?;
        seq.serialize_element(&self.name)?;
        seq.serialize_element(&self.offset)?;
        seq.serialize_element(&self.size)?;
        seq.serialize_element(&self.entropy)?;
        seq.serialize_element(&self.flags)?;
        seq.end()
    }
}

#[derive(Debug)]
struct CompactCallArg {
    callee: String,
    value: String,
}

impl Serialize for CompactCallArg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.callee)?;
        seq.serialize_element(&self.value)?;
        seq.end()
    }
}

#[derive(Debug)]
struct CompactError {
    kind: String,
    stage: String,
}

impl Serialize for CompactError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.kind)?;
        seq.serialize_element(&self.stage)?;
        seq.end()
    }
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

fn nest_flat_metrics(metrics: &BTreeMap<String, f64>) -> serde_json::Value {
    let mut root = serde_json::Map::new();
    for (key, value) in metrics {
        let Some(number) = serde_json::Number::from_f64(*value) else {
            continue;
        };
        let (group, field) = key.split_once('.').unwrap_or(("default", key.as_str()));
        let entry = root
            .entry(group.to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let serde_json::Value::Object(fields) = entry {
            fields.insert(field.to_string(), serde_json::Value::Number(number));
        }
    }
    serde_json::Value::Object(root)
}

struct StringTuples<'a>(&'a [CompactString]);

impl Serialize for StringTuples<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for s in self.0 {
            seq.serialize_element(&(s.offset, &s.encoding, &s.value))?;
        }
        seq.end()
    }
}

fn compact_encoding(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "" | "ascii" => "a".to_string(),
        "utf8" | "utf-8" => "u8".to_string(),
        "utf16le" | "utf-16le" | "wide" => "u16".to_string(),
        other => other.to_string(),
    }
}

fn parse_hex_or_decimal_u64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
    if let Some(hex) = hex {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_string)
}

fn compact_errors(file: &super::file_analysis::FileAnalysis) -> Vec<CompactError> {
    file.filefacts
        .as_ref()
        .map(|view| {
            view.errors
                .iter()
                .filter_map(|err| {
                    let kind = json_string(err, "kind")?;
                    let stage = json_string(err, "stage").unwrap_or_default();
                    Some(CompactError { kind, stage })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn compact_ast(
    file: &super::file_analysis::FileAnalysis,
) -> (Vec<String>, Vec<String>, Vec<CompactCallArg>) {
    let Some(view) = file.filefacts.as_ref() else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    if view.ast.is_null() {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    let targets = json_string_array(&view.ast, "targets");
    let members = json_string_array(&view.ast, "members");
    let mut call_args = Vec::new();
    if let Some(args_by_target) = view
        .ast
        .get("call_strings")
        .and_then(serde_json::Value::as_object)
    {
        for (callee, values) in args_by_target {
            let Some(values) = values.as_array() else {
                continue;
            };
            for value in values.iter().filter_map(serde_json::Value::as_str) {
                call_args.push(CompactCallArg {
                    callee: callee.clone(),
                    value: value.to_string(),
                });
            }
        }
    }

    (targets, members, call_args)
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
                compact_encoding(&s.encoding)
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

    // Flatten symbol-like collections into dense tuples, capped to prevent oversized output.
    let imports: Vec<CompactImport> = file
        .imports
        .iter()
        .take(MAX_IMPORTS)
        .map(|i| CompactImport {
            library: i.library.clone().unwrap_or_default(),
            name: i.symbol.clone(),
            ordinal: None,
        })
        .collect();

    let exports: Vec<CompactExport> = file
        .exports
        .iter()
        .take(MAX_IMPORTS)
        .map(|x| CompactExport {
            name: x.symbol.clone(),
            forward_to: x.forward_to.clone(),
        })
        .collect();

    let functions: Vec<CompactFunction> = file
        .functions
        .iter()
        .take(MAX_IMPORTS)
        .map(|f| CompactFunction {
            name: f.name.clone(),
            offset: f.offset.as_deref().and_then(parse_hex_or_decimal_u64),
            kind: None,
        })
        .collect();

    let sections: Vec<CompactSection> = file
        .sections
        .iter()
        .map(|s| CompactSection {
            name: s.name.clone(),
            offset: s.offset.unwrap_or(0),
            size: s.size,
            entropy: (s.entropy * 100.0).round() / 100.0,
            flags: s.permissions.clone().unwrap_or_else(|| s.flags.join(",")),
        })
        .collect();

    // Round metrics floats to 2dp. Only the flat filefacts_metrics map
    // survives — typed projections were retired.
    let metrics = file
        .filefacts_metrics
        .as_ref()
        .map(nest_flat_metrics)
        .map(round_json_floats)
        .map(RoundedMetrics);

    // Compute formula if not already present. Use the canonical filter so the
    // JSON `f` field stays in lockstep with the CLI header — both must reflect
    // notable-or-higher findings only.
    let formula = file.formula.clone().or_else(|| {
        let filtered = crate::output::filter_findings_for_formula(&file.findings);
        let f = crate::malecule_bridge::formula_from_findings(&filtered);
        (!f.is_empty()).then_some(f)
    });

    let (targets, members, call_args) = compact_ast(file);

    let ff = CompactFacts {
        id: file.file_type.clone(),
        metrics,
        values: file.kv.clone(),
        strings: str_tuples,
        imports,
        exports,
        functions,
        sections,
        targets,
        members,
        call_args,
        errors: compact_errors(file),
    };

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
        ff,
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
    CompactReport { v: "5", tv, fs }
}

impl AnalysisReport {
    /// Convert this pre-finalized report to compact v5 output format.
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
    use super::super::binary::{Import, Section, StringInfo};
    use super::super::file_analysis::FileAnalysis;
    use super::super::filefacts_view::FilefactsView;
    use super::super::traits_findings::Finding;
    use super::super::{Criticality, Evidence, FindingKind};
    use super::compact_from_files;
    use serde_json::json;

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

    #[test]
    fn compact_v5_packs_filefacts_under_ff() {
        let mut fa = FileAnalysis::new(0, "t.exe".into(), "pe".into(), "sha".into(), 7);
        fa.strings.push(StringInfo {
            value: "CreateFileW".into(),
            offset: Some(0x40),
            encoding: "utf16le".into(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
        fa.imports.push(Import::new(
            "CreateFileW",
            Some("kernel32.dll".into()),
            "test",
        ));
        fa.sections.push(Section {
            name: ".text".into(),
            address: Some(0x1000),
            offset: Some(0x400),
            size: 0x1000,
            entropy: 6.424,
            permissions: Some("r-x".into()),
            flags: Vec::new(),
        });
        fa.filefacts_metrics = Some(
            [("binary.overall_entropy".to_string(), 7.125)]
                .into_iter()
                .collect(),
        );
        fa.kv.insert("pe.machine".into(), json!("x86_64"));
        fa.filefacts = Some(FilefactsView {
            ast: json!({
                "targets": ["fetch"],
                "members": ["window.localStorage"],
                "call_strings": { "fetch": ["https://example.com"] }
            }),
            ..FilefactsView::default()
        });

        let value = serde_json::to_value(compact_from_files(&[fa]));
        assert!(value.is_ok(), "serialize compact: {value:?}");
        let Ok(value) = value else {
            return;
        };
        assert_eq!(
            value.get("v").and_then(serde_json::Value::as_str),
            Some("5")
        );
        let ff = &value["fs"][0]["ff"];
        assert_eq!(ff["id"], "pe");
        assert_eq!(ff["m"]["binary"]["overall_entropy"], 7.13);
        assert_eq!(ff["v"]["pe.machine"], "x86_64");
        assert_eq!(ff["s"][0], json!([64, "u16", "CreateFileW"]));
        assert_eq!(ff["i"][0], json!(["kernel32.dll", "CreateFileW"]));
        assert_eq!(ff["sc"][0], json!([".text", 1024, 4096, 6.42, "r-x"]));
        assert_eq!(ff["ct"], json!(["fetch"]));
        assert_eq!(ff["mc"], json!(["window.localStorage"]));
        assert_eq!(ff["ca"][0], json!(["fetch", "https://example.com"]));
        assert!(value["fs"][0].get("ms").is_none());
        assert!(value["fs"][0].get("k").is_none());
    }
}
