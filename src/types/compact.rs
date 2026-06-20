//! Compact v7 output types for minimal JSON serialization
//!
//! These types represent the v7 schema designed for dense filefacts-backed output.
//! Each file's JSON is fully self-contained (splittable for per-file DB storage).
//! Conversion from internal types happens via `compact_from_files()`.

use std::collections::{BTreeMap, HashMap};

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};

use super::core::Criticality;

/// Maximum imports per file in compact output
const MAX_IMPORTS: usize = 4096;

/// Default confidence value (omitted from output)
const DEFAULT_CONF: f32 = 0.5;

// ========================================================================
// Compact output types (v7 schema)
// ========================================================================

/// Top-level v7 report
#[derive(Debug, Serialize)]
pub struct CompactReport {
    /// Schema version — always "8"
    #[serde(rename = "v")]
    pub version: &'static str,
    /// Traits repo revision (first 8 chars of commit hash)
    #[serde(rename = "rev")]
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
    #[serde(rename = "depth")]
    #[serde(skip_serializing_if = "super::is_zero_u32")]
    pub depth: u32,
    /// Molecular formula
    #[serde(rename = "mol")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formula: Option<String>,
    /// Normalized identity claims: name, version, signer, trust tier.
    #[serde(rename = "ident")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<filefacts::Identity>,
    /// Traits (findings)
    #[serde(rename = "traits")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CompactTrait>,
    /// External references this file declares (deps, URLs, repository), each
    /// with its byte offset — the file→dependency edges of the galaxy view.
    #[serde(rename = "refs")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<CompactRef>,
    /// Merged context windows: raw bytes in file order for match highlighting.
    /// Render mode (hex vs text) is derived from the file's `type` field.
    #[serde(rename = "ctx")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<crate::types::ContextLine>,
    /// Dense filefacts-derived facts.
    #[serde(rename = "facts")]
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
    /// Source files this finding came from. A single-entry vec means the
    /// finding was inherited from that embedded member; multiple entries means
    /// a cross-file composite that fired across several members.
    /// Omitted when the finding is native to this file.
    #[serde(rename = "from")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<CompactSource>,
    /// Evidence locations: `[[offset, length], ...]` byte spans, capped at 8.
    /// Locate matching content in `ctx` via range intersection:
    /// a ctx window covering `[addr, addr+len)` that overlaps `[off, off+len)`
    /// contains this finding's match. Omitted when empty.
    #[serde(rename = "spans")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ev: Vec<[u64; 2]>,
}

/// One member a cross-file composite drew from, in compact form.
#[derive(Debug, Serialize)]
pub struct CompactSource {
    /// Contributing member's `files[]` id.
    pub file: u32,
    /// 1-based source line of the component match, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// Byte offset of the component match, when known.
    #[serde(rename = "off", skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// One reference a file declares — what it points at, how it was expressed, and
/// where in the file it sits. Lets a downstream consumer (prism's galaxy view)
/// draw byte-anchored edges from each file to what it references.
///
/// The target is either *external* — a package/URL named by `to` — or
/// *internal* — another file in the same bundle, named by `file` (its `files[]`
/// id). External today; `file` is reserved so that when cleave resolves
/// intra-bundle references (a relative `require`/`import`, an HTML `src`, a
/// manifest pointing at a sibling) — work that currently lives in prism — those
/// file→file edges ride the same list instead of being re-derived downstream.
#[derive(Debug, Serialize)]
pub struct CompactRef {
    /// The reference text/locator: a PURL or URL for an external target, or the
    /// raw specifier (e.g. `./util`) for an internal one.
    #[serde(rename = "to")]
    pub locator: String,
    /// Coarse kind: `dependency`, `command`, `url_fetch`, `repository`, ….
    pub kind: String,
    /// Byte offset of the reference in this file — the citation anchor.
    #[serde(rename = "off")]
    pub offset: u64,
    /// When the reference resolves to another file in this bundle, that file's
    /// `files[]` id — the intra-bundle (file→file) edge. Absent for external
    /// references.
    #[serde(rename = "file", skip_serializing_if = "Option::is_none")]
    pub target_file: Option<u32>,
}

/// Dense filefacts-backed fact block for compact v7.
#[derive(Debug)]
struct CompactFacts {
    /// Metrics (nested structure, floats rounded to 2dp).
    metrics: Option<RoundedMetrics>,
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
}

impl CompactFacts {
    fn is_empty(&self) -> bool {
        self.metrics.is_none()
            && self.imports.is_empty()
            && self.exports.is_empty()
            && self.functions.is_empty()
            && self.sections.is_empty()
            && self.targets.is_empty()
            && self.members.is_empty()
    }
}

impl Serialize for CompactFacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut fields = usize::from(self.metrics.is_some());
        fields += usize::from(!self.imports.is_empty());
        fields += usize::from(!self.exports.is_empty());
        fields += usize::from(!self.functions.is_empty());
        fields += usize::from(!self.sections.is_empty());
        fields += usize::from(!self.targets.is_empty());
        fields += usize::from(!self.members.is_empty());

        let mut st = serializer.serialize_struct("CompactFacts", fields)?;
        if let Some(metrics) = &self.metrics {
            st.serialize_field("metrics", metrics)?;
        }
        if !self.imports.is_empty() {
            st.serialize_field("imp", &self.imports)?;
        }
        if !self.exports.is_empty() {
            st.serialize_field("exp", &self.exports)?;
        }
        if !self.functions.is_empty() {
            st.serialize_field("funcs", &self.functions)?;
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

fn compact_ast(file: &super::file_analysis::FileAnalysis) -> (Vec<String>, Vec<String>) {
    let Some(view) = file.filefacts.as_ref() else {
        return (Vec::new(), Vec::new());
    };
    if view.symbols.is_empty() {
        return (Vec::new(), Vec::new());
    }

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

    (
        target_set.into_iter().collect(),
        member_set.into_iter().collect(),
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
        // Collect local evidence spans: (offset, len) for evidence whose offset
        // lives in this file's byte space (skip archive: member offsets).
        let mut ev_spans: Vec<[u64; 2]> = finding
            .evidence
            .iter()
            .filter(|e| {
                !e.location
                    .as_deref()
                    .is_some_and(|l| l.starts_with("archive:"))
            })
            .filter_map(|e| {
                e.byte_offset().map(|off| {
                    // A decoded-layer match sets `match_len` to its encoded
                    // source size; otherwise the span is the value's own length.
                    let len = e.match_len.unwrap_or_else(|| {
                        u64::from(u32::try_from(e.value.len()).unwrap_or(u32::MAX))
                    });
                    [off, len]
                })
            })
            .collect();
        ev_spans.sort_unstable_by_key(|s| s[0]);
        ev_spans.dedup_by_key(|s| s[0]);
        ev_spans.truncate(crate::types::traits_findings::MAX_EV_LOCS);

        if let Some(existing) = trait_map.get_mut(finding.id.as_str()) {
            let new_crit = crit_to_int(finding.crit);
            if new_crit > existing.criticality {
                existing.criticality = new_crit;
            }
            // A copy native to this file (from empty) outranks an inherited one.
            if finding.src.is_none() && !file.composite_sources.contains_key(finding.id.as_str()) {
                existing.from.clear();
            }
            // Merge ev spans — deduplicate by offset, cap at MAX_EV_LOCS.
            if !ev_spans.is_empty() {
                existing.ev.extend(ev_spans);
                existing.ev.sort_unstable_by_key(|s| s[0]);
                existing.ev.dedup_by_key(|s| s[0]);
                existing
                    .ev
                    .truncate(crate::types::traits_findings::MAX_EV_LOCS);
            }
        } else {
            trait_order.push(&finding.id);
            // Build `from`: composite sources take priority; fall back to the
            // scalar `src` for a single inherited finding.
            let from: Vec<CompactSource> =
                if let Some(srcs) = file.composite_sources.get(&finding.id) {
                    srcs.iter()
                        .map(|s| CompactSource {
                            file: s.file,
                            line: s.line,
                            offset: s.offset,
                        })
                        .collect()
                } else if let Some(src_id) = finding.src {
                    vec![CompactSource {
                        file: src_id,
                        line: None,
                        offset: None,
                    }]
                } else {
                    Vec::new()
                };
            trait_map.insert(
                &finding.id,
                CompactTrait {
                    id: finding.id.clone(),
                    criticality: crit_to_int(finding.crit),
                    description: finding.desc.clone(),
                    confidence: finding.conf,
                    mbc: finding.mbc.clone(),
                    attack: finding.attack.clone(),
                    from,
                    ev: ev_spans,
                },
            );
        }
    }

    let traits: Vec<CompactTrait> = trait_order
        .into_iter()
        .filter_map(|id| trait_map.remove(id))
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

    // External references this file declares, byte-anchored, for the galaxy
    // view. Read straight from the filefacts view so every reference (fetched
    // or not) is attributed to the file that named it.
    let refs: Vec<CompactRef> = file
        .filefacts
        .as_ref()
        .map(|ff| {
            ff.references
                .iter()
                .map(|r| CompactRef {
                    locator: match &r.locator {
                        filefacts::RefLocator::Purl(p) => p.clone(),
                        filefacts::RefLocator::Url(u) => u.clone(),
                    },
                    kind: ref_kind_str(r.kind).to_string(),
                    offset: r.offset,
                    // External today; intra-bundle resolution (prism's job for
                    // now) will fill this when it moves into cleave.
                    target_file: None,
                })
                .collect()
        })
        .unwrap_or_default();

    let (targets, members) = compact_ast(file);

    let facts = CompactFacts {
        metrics,
        imports,
        exports,
        functions,
        sections,
        targets,
        members,
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
        refs,
        context: file.context.clone(),
        facts,
    }
}

/// The stable snake_case name for a reference kind, for the compact `refs`
/// view. `RefKind` is `#[non_exhaustive]`, so an unrecognized kind maps to
/// `undefined` rather than failing.
fn ref_kind_str(kind: filefacts::RefKind) -> &'static str {
    match kind {
        filefacts::RefKind::Dependency => "dependency",
        filefacts::RefKind::Command => "command",
        filefacts::RefKind::UrlFetch => "url_fetch",
        filefacts::RefKind::Repository => "repository",
        _ => "undefined",
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
    assemble_report(compact_files)
}

/// Strip every cross-file reference that does not resolve to an emitted file id.
/// An inherited finding's `src` and a composite's `srcs[].f` both index into
/// `files[]`; if a caller filtered or renumbered `files[]` without remapping
/// these, the index would dangle and the trait renders with no file context
/// downstream. A dangling `src` is cleared (the finding stays, attributed to its
/// own file); a dangling composite source is dropped from its list. Either way
/// the result is a structurally valid report. Returns the number of references
/// neutralized so the caller can surface the upstream defect.
fn sanitize_references(files: &mut [CompactFile]) -> usize {
    let ids: std::collections::HashSet<u32> = files.iter().map(|f| f.id).collect();
    let mut dangling = 0usize;
    for file in files.iter_mut() {
        for tr in &mut file.findings {
            let before = tr.from.len();
            tr.from.retain(|s| ids.contains(&s.file));
            dangling += before - tr.from.len();
        }
    }
    dangling
}

/// The single choke point both conversion entry points pass through: it stamps
/// the version fields and guarantees the report's internal consistency, so a
/// `CompactReport` can never be emitted carrying a dangling cross-file reference
/// regardless of how the caller built `files[]`. In debug builds a stray
/// reference trips the assertion at its source; in release it is healed and
/// logged rather than panicking (library code must not panic).
fn assemble_report(mut files: Vec<CompactFile>) -> CompactReport {
    let dangling = sanitize_references(&mut files);
    debug_assert_eq!(
        dangling, 0,
        "compact: dangling cross-file reference(s) reached emit — a caller dropped \
         or renumbered files[] without remapping src/srcs",
    );
    if dangling > 0 {
        tracing::warn!(
            dangling,
            files = files.len(),
            "compact: neutralized dangling cross-file reference(s) before emit",
        );
    }
    let traits_version =
        crate::traits_repo::version().map(|v| if v.len() > 5 { v[..5].to_string() } else { v });
    CompactReport {
        version: "8",
        traits_version,
        files,
    }
}

#[cfg(test)]
mod formula_tests {
    use super::super::binary::{Import, Section};
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

    /// The emit guard must neutralize any cross-file reference that does not
    /// resolve to an emitted file id: a dangling inherited `src` is cleared and
    /// a dangling composite source is dropped, while valid references survive.
    /// This is what makes a dangling-ref report (the symptom of an upstream
    /// drop/renumber) impossible to emit.
    #[test]
    fn sanitize_strips_only_dangling_references() {
        use super::{CompactSource, convert_file, sanitize_references};

        let mut files = vec![
            convert_file(
                &file_with(vec![finding("a/b/c", Criticality::Notable, 0.9)]),
                0,
            ),
            convert_file(
                &file_with(vec![finding("d/e/f", Criticality::Notable, 0.9)]),
                1,
            ),
        ];
        let src = |f: u32| CompactSource {
            file: f,
            line: None,
            offset: None,
        };
        files[0].findings[0].from = vec![src(1), src(9)]; // one valid, one dangling

        let dangling = sanitize_references(&mut files);

        assert_eq!(dangling, 1, "one dangling from entry");
        let kept = &files[0].findings[0].from;
        assert_eq!(kept.len(), 1, "dangling source dropped");
        assert_eq!(kept[0].file, 1, "valid source kept");
        // A clean report passes through untouched.
        assert_eq!(sanitize_references(&mut files), 0);
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
            Some("8")
        );
        let ff = &value["files"][0]["facts"];
        assert_eq!(ff["metrics"]["binary"]["overall_entropy"], 7.13);
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
