//! Compact v7 output types for minimal JSON serialization
//!
//! These types represent the v7 schema designed for dense filefacts-backed output.
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

/// Default confidence value (omitted from output)
const DEFAULT_CONF: f32 = 0.5;

// ========================================================================
// Compact output types (v7 schema)
// ========================================================================

/// Top-level v7 report
#[derive(Debug, Serialize)]
pub struct CompactReport {
    /// Schema version — always "7"
    #[serde(rename = "v")]
    pub version: &'static str,
    /// Traits repo commit hash (first 5 chars)
    #[serde(rename = "tv")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traits_version: Option<String>,
    /// Files array
    #[serde(rename = "files")]
    pub files: Vec<CompactFile>,
}

/// Per-file analysis in v7 schema
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
    #[serde(rename = "size")]
    pub size: u64,
    /// Weighted risk score
    #[serde(rename = "risk")]
    #[serde(skip_serializing_if = "super::is_zero_u32")]
    pub risk: u32,
    /// Archive nesting depth (omit when 0)
    #[serde(rename = "dp")]
    #[serde(skip_serializing_if = "super::is_zero_u32")]
    pub depth: u32,
    /// Molecular formula
    #[serde(rename = "mol")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formula: Option<String>,
    /// Normalized identity claims (filefacts `Identity`) for the file this
    /// record was extracted from: name, version, signer, trust tier, and other
    /// cross-format provenance. Omitted when the file asserts no identity.
    #[serde(rename = "idn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<filefacts::Identity>,
    /// Traits (findings)
    #[serde(rename = "find")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CompactTrait>,
    /// Merged context: the matched content shown once, in file order, annotated
    /// with the findings that touch it (notes reference findings by id). The
    /// context-centric successor to per-finding `ev`/`loc` evidence.
    #[serde(rename = "ctx")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<crate::types::ContextLine>,
    /// Dense filefacts-derived facts. This is command-complete for cleave's
    /// facts/value/metrics/sections/symbol commands, but not a lossless mirror
    /// of filefacts' researcher-facing JSON.
    #[serde(rename = "fact")]
    #[serde(skip_serializing_if = "CompactFacts::is_empty")]
    facts: CompactFacts,
}

/// A finding/trait in compact form
#[derive(Debug, Serialize)]
pub struct CompactTrait {
    /// Trait identifier (e.g., "objectives/execution/shell/bash")
    #[serde(rename = "id")]
    pub id: String,
    /// Criticality level: 0=filtered, 1=component, 2=baseline, 3=notable, 4=suspicious, 5=hostile
    #[serde(rename = "crit")]
    pub criticality: u8,
    /// Description
    #[serde(rename = "desc")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Confidence (omit when 0.5)
    #[serde(rename = "conf")]
    #[serde(skip_serializing_if = "is_default_conf")]
    pub confidence: f32,
    /// MBC (Malware Behavior Catalog) ID
    #[serde(rename = "mbc")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbc: Option<String>,
    /// MITRE ATT&CK Technique ID
    #[serde(rename = "atk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack: Option<String>,
    /// Origin file index when this finding was inherited from an embedded
    /// member; absent when native to this file. Index into `files[]` — the
    /// member's own context renders it, so traverse there instead of anchoring
    /// the offsets here (they index the member's bytes, not this file's).
    #[serde(rename = "src")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<u32>,
    /// For a cross-file composite, the archive members it fired on — each a
    /// member `files[]` id with the component's location where a context note
    /// pins it. Lets a consumer tie the composite to the files (and offsets) it
    /// was based on, since the linking component traits are filtered from output.
    #[serde(rename = "srcs")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<CompactSource>,
    // Per-trait evidence (`ev`/`loc`) was removed in favour of the per-file
    // `ctx` block: the matched content is shown once, in context, and each
    // context note references the finding by `id`. Highlight a match via
    // `note.off - line_addr .. + note.len`.
}

/// One member a cross-file composite drew from, in compact form.
#[derive(Debug, Serialize)]
pub struct CompactSource {
    /// Contributing member's `files[]` id.
    #[serde(rename = "f")]
    pub file: u32,
    /// 1-based source line of the component match, when known.
    #[serde(rename = "ln", skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// Byte offset of the component match, when known.
    #[serde(rename = "o", skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
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

/// Dense filefacts-backed fact block for compact v7.
#[derive(Debug)]
struct CompactFacts {
    /// File identity without source/provenance tags. Usually mirrors the
    /// top-level `type` field but stays under `fact` for consumers that treat
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
            st.serialize_field("met", metrics)?;
        }
        if !self.values.is_empty() {
            st.serialize_field("val", &self.values)?;
        }
        if !self.strings.is_empty() {
            st.serialize_field("str", &StringTuples(&self.strings))?;
        }
        if !self.imports.is_empty() {
            st.serialize_field("imp", &self.imports)?;
        }
        if !self.exports.is_empty() {
            st.serialize_field("exp", &self.exports)?;
        }
        if !self.functions.is_empty() {
            st.serialize_field("fn", &self.functions)?;
        }
        if !self.sections.is_empty() {
            st.serialize_field("sec", &self.sections)?;
        }
        if !self.targets.is_empty() {
            st.serialize_field("tgt", &self.targets)?;
        }
        if !self.members.is_empty() {
            st.serialize_field("mbr", &self.members)?;
        }
        if !self.call_args.is_empty() {
            st.serialize_field("arg", &self.call_args)?;
        }
        if !self.errors.is_empty() {
            st.serialize_field("err", &self.errors)?;
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
fn crit_to_int(criticality: Criticality) -> u8 {
    match criticality {
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

fn compact_ast(
    file: &super::file_analysis::FileAnalysis,
) -> (Vec<String>, Vec<String>, Vec<CompactCallArg>) {
    let Some(view) = file.filefacts.as_ref() else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    if view.symbols.is_empty() {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    // Targets: sorted-unique Call.target across all call symbols.
    let mut target_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut member_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for sym in &view.symbols {
        match sym {
            filefacts::Symbol::Call {
                target: Some(target),
                ..
            } => {
                target_set.insert(target.clone());
            }
            filefacts::Symbol::Member { path, .. } => {
                member_set.insert(path.clone());
            }
            _ => {}
        }
    }

    // call_args (callee → literal value) was derived from the old
    // `Ast::call_strings` index. The unified Symbol::Call no longer
    // carries an inline strings field — literal values live in
    // top-level `literals` and correlate by offset window. Return
    // empty here; rule engines that need this correlation do it
    // themselves via Stage 5's offset-window predicate.
    let call_args = Vec::new();

    (
        target_set.into_iter().collect(),
        member_set.into_iter().collect(),
        call_args,
    )
}

// ========================================================================
// Conversion from internal types
// ========================================================================

/// Convert a FileAnalysis into a CompactFile
fn convert_file(file: &super::file_analysis::FileAnalysis, id: u32) -> CompactFile {
    // Dedup findings by ID within this file, merge evidence
    let mut trait_map: HashMap<&str, CompactTrait> = HashMap::new();
    let mut trait_order: Vec<&str> = Vec::new();

    for finding in &file.findings {
        // Dedup findings by id, keeping the highest criticality. The matched
        // content now lives once in the file-level `ctx` block; each context
        // note references the finding by id, so no per-trait evidence here.
        if let Some(existing) = trait_map.get_mut(finding.id.as_str()) {
            let new_crit = crit_to_int(finding.crit);
            if new_crit > existing.criticality {
                existing.criticality = new_crit;
            }
            // A copy native to this file (src=None) outranks an inherited one.
            existing.src = existing.src.and(finding.src);
        } else {
            trait_order.push(&finding.id);
            let sources = file
                .composite_sources
                .get(&finding.id)
                .map(|srcs| {
                    srcs.iter()
                        .map(|s| CompactSource {
                            file: s.file,
                            line: s.line,
                            offset: s.offset,
                        })
                        .collect()
                })
                .unwrap_or_default();
            trait_map.insert(
                &finding.id,
                CompactTrait {
                    id: finding.id.clone(),
                    criticality: crit_to_int(finding.crit),
                    description: finding.desc.clone(),
                    confidence: finding.conf,
                    mbc: finding.mbc.clone(),
                    attack: finding.attack.clone(),
                    src: finding.src,
                    sources,
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

    let facts = CompactFacts {
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
        id,
        path: file.path.clone(),
        file_type: file.file_type.clone(),
        sha: file.sha256.clone(),
        size: file.size,
        risk: file.score,
        depth: file.depth,
        formula,
        identity: file.identity.clone(),
        findings: traits,
        context: file.context.clone(),
        facts,
    }
}

/// Build a CompactReport from an already-finalized report's files array.
///
/// Use this when the report has already been through `finalize()` and post-processing
/// (encoding layer merging, criticality filtering). This is the primary entry point
/// for the binary crate's JSON output path.
#[must_use]
pub fn compact_from_files(files: &[super::file_analysis::FileAnalysis]) -> CompactReport {
    let compact_files: Vec<CompactFile> = files.iter().map(|f| convert_file(f, f.id)).collect();
    let traits_version =
        crate::traits_repo::version().map(|v| if v.len() > 5 { v[..5].to_string() } else { v });
    CompactReport {
        version: "7",
        traits_version,
        files: compact_files,
    }
}

impl AnalysisReport {
    /// Convert this pre-finalized report to compact v7 output format.
    ///
    /// This is a non-mutating conversion — the internal report is unchanged.
    /// Builds the root file from top-level data and includes archive members.
    /// For post-finalize reports, use `compact_from_files(&report.files)` instead.
    #[must_use]
    pub fn to_compact(&self) -> CompactReport {
        // Build the root file entry from the report's top-level data (its path is
        // already `target.path`), then convert pre-populated members (archive
        // members, decoded payloads) in place — `convert_file` takes the id
        // explicitly, so members need no clone just to be renumbered.
        let root_file = self.to_file_analysis(0);
        let mut files = Vec::with_capacity(1 + self.files.len());
        files.push(convert_file(&root_file, 0));
        for (idx, file) in self.files.iter().enumerate() {
            files.push(convert_file(file, (idx + 1) as u32));
        }

        let traits_version =
            crate::traits_repo::version().map(|v| if v.len() > 5 { v[..5].to_string() } else { v });
        CompactReport {
            version: "7",
            traits_version,
            files,
        }
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
            src: None,
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
        let formula = compact.files[0].formula.as_deref().unwrap_or("");
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
            compact.files[0].formula.is_none(),
            "expected no formula when sole finding is below 0.65 conf, got {:?}",
            compact.files[0].formula,
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
        assert_eq!(compact.files[0].formula.as_deref(), Some("PRECOMPUTED"));
    }

    #[test]
    fn compact_v7_packs_filefacts_under_fact() {
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
        fa.imports
            .push(Import::new("CreateFileW", Some("kernel32.dll".into())));
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
            symbols: vec![
                filefacts::Symbol::Call {
                    target: Some("fetch".to_string()),
                    args: vec![filefacts::Arg::String {
                        value: "https://example.com".to_string(),
                    }],
                    offset: None,
                },
                filefacts::Symbol::Member {
                    path: "window.localStorage".to_string(),
                    offset: Some(0),
                },
            ],
            ..FilefactsView::default()
        });

        let value = serde_json::to_value(compact_from_files(&[fa]));
        assert!(value.is_ok(), "serialize compact: {value:?}");
        let Ok(value) = value else {
            return;
        };
        assert_eq!(
            value.get("v").and_then(serde_json::Value::as_str),
            Some("7")
        );
        let ff = &value["files"][0]["fact"];
        assert_eq!(ff["id"], "pe");
        assert_eq!(ff["met"]["binary"]["overall_entropy"], 7.13);
        assert_eq!(ff["val"]["pe.machine"], "x86_64");
        assert_eq!(ff["str"][0], json!([64, "u16", "CreateFileW"]));
        assert_eq!(ff["imp"][0], json!(["kernel32.dll", "CreateFileW"]));
        assert_eq!(ff["sec"][0], json!([".text", 1024, 4096, 6.42, "r-x"]));
        assert_eq!(ff["tgt"], json!(["fetch"]));
        assert_eq!(ff["mbr"], json!(["window.localStorage"]));
        // call_args was derived from the dropped Ast.call_strings index.
        // The unified Symbol::Call no longer carries inline strings —
        // literal values live in top-level `literals` and correlate by
        // offset window. compact_ast returns empty here; rule engines
        // do the offset correlation themselves.
        assert!(value["files"][0].get("ms").is_none());
        assert!(value["files"][0].get("k").is_none());
    }
}
