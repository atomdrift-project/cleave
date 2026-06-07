//! Compact v6 output types for minimal JSON serialization
//!
//! These types represent the v6 schema designed for dense filefacts-backed output.
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
// Compact output types (v6 schema)
// ========================================================================

/// Top-level v6 report
#[derive(Debug, Serialize)]
pub struct CompactReport {
    /// Schema version — always "6"
    pub v: &'static str,
    /// Traits repo commit hash (first 5 chars)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tv: Option<String>,
    /// Files array
    pub fs: Vec<CompactFile>,
}

/// Per-file analysis in v6 schema
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
    /// Evidence locations parallel to `e`. Populated when archive roll-up
    /// has attributed a finding to a specific member. The two vecs always
    /// share a length when this is present, so downstream consumers can pair
    /// `e[i]` with `el[i]`. Skipped entirely when no location is known for any
    /// entry.
    ///
    /// As of report `v: "6"`, an archive-member location is compacted to
    /// `"<fs-id>[:<offset>]"` — `fs-id` indexes the report's `fs[]` array, so
    /// the (often long, repeated) member path is resolved once via `fs[id]`
    /// rather than embedded in every entry. Byte offsets are emitted as bare
    /// hex (no `0x` prefix) to keep the JSON slim; the `0x` is redundant in this
    /// always-hex position. A member that can't be resolved to an `fs[]` file
    /// (un-extracted nested archive) keeps its `archive:<path>` string, so a
    /// single `el` array may mix both forms — consumers tell them apart by the
    /// leading character: a digit is an id, `archive:` a path. (Cleave's own
    /// internal `Evidence.location` strings keep the `0x` prefix; the slimming
    /// happens only here, at the JSON boundary.)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub el: Vec<String>,
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

/// Dense filefacts-backed fact block for compact v6.
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
fn convert_file(file: &super::file_analysis::FileAnalysis) -> CompactFile {
    // Dedup findings by ID within this file, merge evidence
    let mut trait_map: HashMap<&str, CompactTrait> = HashMap::new();
    let mut trait_order: Vec<&str> = Vec::new();

    for finding in &file.findings {
        // Pair each evidence value with its location. Empty-value evidence
        // is dropped, but a present value with no location keeps "" as its
        // location placeholder so the e/el vectors stay aligned by index.
        let pairs: Vec<(String, String)> = finding
            .evidence
            .iter()
            .filter(|e| !e.value.is_empty())
            .map(|e| {
                (
                    truncate_at_boundary(&e.value, MAX_EVIDENCE_CHARS).to_string(),
                    e.location.clone().unwrap_or_default(),
                )
            })
            .collect();

        if let Some(existing) = trait_map.get_mut(finding.id.as_str()) {
            // Dedup on the (value, location) pair so identical matches from
            // the same place collapse, but the same value matched in two
            // different members produces two entries.
            for (val, loc) in pairs {
                let already = existing
                    .e
                    .iter()
                    .zip(existing.el.iter())
                    .any(|(v, l)| v == &val && l == &loc);
                if !already {
                    existing.e.push(val);
                    existing.el.push(loc);
                }
            }
            // Keep highest criticality
            let new_crit = crit_to_int(finding.crit);
            if new_crit > existing.l {
                existing.l = new_crit;
            }
        } else {
            trait_order.push(&finding.id);
            let (e, el): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
            trait_map.insert(
                &finding.id,
                CompactTrait {
                    i: finding.id.clone(),
                    l: crit_to_int(finding.crit),
                    d: finding.desc.clone(),
                    c: finding.conf,
                    m: finding.mbc.clone(),
                    a: finding.attack.clone(),
                    e,
                    el,
                },
            );
        }
    }

    // Drop `el` entirely when no location is known for any entry. Keeps
    // the JSON output unchanged for findings that never went through an
    // archive roll-up, and lets `skip_serializing_if = "Vec::is_empty"`
    // omit the field on those traits.
    for trait_entry in trait_map.values_mut() {
        if trait_entry.el.iter().all(String::is_empty) {
            trait_entry.el.clear();
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
    let mut fs: Vec<CompactFile> = files.iter().map(convert_file).collect();
    rewrite_evidence_locations(&mut fs);
    let tv =
        crate::traits_repo::version().map(|v| if v.len() > 5 { v[..5].to_string() } else { v });
    CompactReport { v: "6", tv, fs }
}

/// Rewrite archive-attributed `el` evidence locations from the verbose
/// `archive:<member-path>[:<offset>]` form to a compact `<fs-id>[:<offset>]`
/// form, where `<fs-id>` indexes the report's `fs[]` array. The member path
/// (often a long `<sha>.<type>` name) repeats across every match in a file; the
/// id collapses it to a digit or two, and consumers resolve the path once via
/// `fs[id]`. The offset — the genuinely per-match part — is preserved verbatim.
///
/// Only `archive:`-prefixed entries whose member resolves to a known `fs[]`
/// file are rewritten; everything else (plain `offset:` locations, semantic
/// labels, or members we can't resolve, e.g. un-extracted nested archives) is
/// left untouched, so the encoding degrades gracefully and stays mixed-safe.
fn rewrite_evidence_locations(fs: &mut [CompactFile]) {
    // Map each file's terminal path segment (after the last `!!` archive
    // delimiter) to its id. This mirrors how the report's consumers key files
    // for display, so the id we emit selects the same file they would have.
    // Owned keys so the immutable borrow ends before we mutate `fs` below.
    let mut id_by_segment: HashMap<String, u32> = HashMap::with_capacity(fs.len());
    for file in fs.iter() {
        let segment = file.path.rsplit("!!").next().unwrap_or(&file.path);
        id_by_segment.insert(segment.to_string(), file.id);
    }

    for file in fs.iter_mut() {
        for trait_entry in &mut file.ts {
            for loc in &mut trait_entry.el {
                *loc = normalize_el_location(loc, &id_by_segment);
            }
        }
    }
}

/// Compact one `el` entry for slim JSON. Two transforms, both keep the entry
/// usable while shrinking it:
///   * resolve an `archive:<member>` location to its `fs[]` id, so the long
///     (and repeated) member path becomes a one/two-digit index; and
///   * drop the redundant `0x` prefix from the trailing byte offset, since
///     offsets are unambiguously hex in this position.
///
/// The member path is preserved verbatim when it can't be resolved to a file
/// (un-extracted nested archives, etc.). Non-`archive:` locations are returned
/// unchanged apart from the `0x`-strip on a pure byte-offset; positional
/// `row:col` locations carry no `0x` and pass through.
fn normalize_el_location(loc: &str, id_by_segment: &HashMap<String, u32>) -> String {
    if let Some(rest) = loc.strip_prefix("archive:") {
        let (member, offset) = split_member_offset(rest);
        let offset = strip_offset_0x(offset);
        return match id_by_segment.get(member) {
            Some(id) => format!("{id}{offset}"),
            None => format!("archive:{member}{offset}"),
        };
    }
    // Pure byte-offset locations (`offset:0x..`, `0x..`) also shed the prefix.
    if loc.starts_with("offset:") || loc.starts_with("0x") || loc.starts_with("0X") {
        return strip_offset_0x(loc);
    }
    loc.to_string()
}

/// Split an archive member location into `(member, offset_suffix)`, where
/// `offset_suffix` keeps its leading `:` (`":0x3718c0"`, `":offset:0x10"`) or
/// is empty. The offset is the trailing hex token; member paths don't contain
/// `:`. Mirrors the offset shapes produced across the analyzers.
fn split_member_offset(s: &str) -> (&str, &str) {
    if let Some(idx) = s.rfind(":offset:") {
        return (&s[..idx], &s[idx..]);
    }
    if let Some(idx) = s.rfind(':') {
        let suffix = &s[idx + 1..];
        let hex = suffix
            .strip_prefix("0x")
            .or_else(|| suffix.strip_prefix("0X"))
            .unwrap_or(suffix);
        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return (&s[..idx], &s[idx..]);
        }
    }
    (s, "")
}

/// Drop a `0x`/`0X` prefix from the hex offset that follows the final `:` of a
/// location (or the whole string when it has no `:`). Leaves an already-bare
/// offset and the non-offset head untouched: `":0x3718c0"` → `":3718c0"`,
/// `"offset:0x10"` → `"offset:10"`, `"0x10"` → `"10"`.
fn strip_offset_0x(s: &str) -> String {
    let (head, tail) = match s.rfind(':') {
        Some(i) => s.split_at(i + 1),
        None => ("", s),
    };
    let tail = tail
        .strip_prefix("0x")
        .or_else(|| tail.strip_prefix("0X"))
        .unwrap_or(tail);
    format!("{head}{tail}")
}

impl AnalysisReport {
    /// Convert this pre-finalized report to compact v6 output format.
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

    /// Evidence locations populated by the archive roll-up must survive
    /// the compact conversion. This was previously dropped — the bug
    /// surfaced as archive-level rootkit traits with no way to attribute
    /// back to the inner file that matched. Here the attributed members are
    /// not present as `fs[]` entries, so they exercise the graceful fallback:
    /// the verbose `archive:<path>` string is kept verbatim.
    #[test]
    fn evidence_location_preserved_in_compact() {
        let mut f = finding("well-known/malware/rootkit/x", Criticality::Suspicious, 0.9);
        f.evidence = vec![
            Evidence {
                method: "text".into(),
                source: "yara".into(),
                value: "package assets".into(),
                location: Some("archive:k8s.io/kops/.../assets.go".into()),
                ..Default::default()
            },
            // Same value matched in a different member — should round-trip
            // as two parallel entries, not collapsed to one.
            Evidence {
                method: "text".into(),
                source: "yara".into(),
                value: "package assets".into(),
                location: Some("archive:k8s.io/kops/.../other.go".into()),
                ..Default::default()
            },
        ];

        let compact = compact_from_files(&[file_with(vec![f])]);
        #[allow(clippy::expect_used)]
        let t = compact
            .fs
            .iter()
            .flat_map(|cf| cf.ts.iter())
            .find(|t| t.i.ends_with("/x"))
            .expect("trait survived compact conversion");
        assert_eq!(
            t.e.len(),
            2,
            "both evidence values kept (different locations)"
        );
        assert_eq!(t.el.len(), t.e.len(), "el is parallel to e");
        assert!(t.el.iter().any(|l| l.contains("assets.go")));
        assert!(t.el.iter().any(|l| l.contains("other.go")));
    }

    /// Traits with no location info on any evidence must omit `el`
    /// entirely so older consumers see the same JSON shape.
    #[test]
    fn evidence_location_absent_when_unknown() {
        let f = finding("objectives/c2/http/beacon", Criticality::Notable, 0.9);
        let compact = compact_from_files(&[file_with(vec![f])]);
        #[allow(clippy::expect_used)]
        let t = compact
            .fs
            .iter()
            .flat_map(|cf| cf.ts.iter())
            .find(|t| t.i.contains("beacon"))
            .expect("trait survived compact conversion");
        assert!(
            t.el.is_empty(),
            "el should stay empty when no location is known"
        );
    }

    /// When the attributed member IS an `fs[]` entry, its (repeated, often
    /// long) path collapses to the file's index, with the per-match offset
    /// preserved: `archive:<member>:<offset>` → `"<id>:<offset>"`.
    #[test]
    fn evidence_location_rewritten_to_fs_index() {
        let member_name = "0a8ab3d16b12d3a453ee5a3208fe04744ad54514.macho";
        let mut container =
            FileAnalysis::new(0, "bundle.tar".into(), "archive".into(), "sha0".into(), 10);
        let mut f = finding("well-known/malware/rootkit/x", Criticality::Hostile, 0.9);
        f.evidence = vec![
            Evidence {
                method: "sym".into(),
                source: "yara".into(),
                value: "a".into(),
                location: Some(format!("archive:{member_name}:0x3718c0")),
                ..Default::default()
            },
            Evidence {
                method: "sym".into(),
                source: "yara".into(),
                value: "b".into(),
                location: Some(format!("archive:{member_name}:0x10025a5c4")),
                ..Default::default()
            },
        ];
        container.findings = vec![f];

        // The member is fs[1]; its terminal `!!` segment equals member_name.
        let member = FileAnalysis::new(
            1,
            format!("bundle.tar!!{member_name}"),
            "macho".into(),
            "sha1".into(),
            5,
        );

        let compact = compact_from_files(&[container, member]);
        #[allow(clippy::expect_used)]
        let t = compact
            .fs
            .iter()
            .flat_map(|cf| cf.ts.iter())
            .find(|t| t.i.ends_with("/x"))
            .expect("trait survived compact conversion");
        assert_eq!(
            t.el,
            vec!["1:3718c0".to_string(), "1:10025a5c4".to_string()],
            "member path collapses to fs id; offset loses its 0x prefix"
        );

        // An un-resolvable member (not an fs[] entry) keeps its path, but the
        // offset is still slimmed to bare hex.
        let mut lonely =
            FileAnalysis::new(0, "bundle.tar".into(), "archive".into(), "sha0".into(), 10);
        let mut g = finding("well-known/malware/rootkit/y", Criticality::Hostile, 0.9);
        g.evidence = vec![Evidence {
            method: "sym".into(),
            source: "yara".into(),
            value: "a".into(),
            location: Some("archive:not-in-fs.macho:0x10".into()),
            ..Default::default()
        }];
        lonely.findings = vec![g];
        let compact = compact_from_files(&[lonely]);
        #[allow(clippy::expect_used)]
        let t = compact
            .fs
            .iter()
            .flat_map(|cf| cf.ts.iter())
            .find(|t| t.i.ends_with("/y"))
            .expect("trait survived compact conversion");
        assert_eq!(t.el, vec!["archive:not-in-fs.macho:10".to_string()]);
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
    fn compact_v6_packs_filefacts_under_ff() {
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
            Some("6")
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
        // call_args was derived from the dropped Ast.call_strings index.
        // The unified Symbol::Call no longer carries inline strings —
        // literal values live in top-level `literals` and correlate by
        // offset window. compact_ast returns empty here; rule engines
        // do the offset correlation themselves.
        assert!(value["fs"][0].get("ms").is_none());
        assert!(value["fs"][0].get("k").is_none());
    }
}
