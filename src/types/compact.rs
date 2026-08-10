//! Compact v7 output types for minimal JSON serialization
//!
//! These types represent the v7 schema designed for dense filefacts-backed output.
//! Each file's JSON is fully self-contained (splittable for per-file DB storage).
//! Conversion from internal types happens via `compact_from_files()`.

use std::collections::{BTreeMap, HashMap};

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::core::Criticality;
use super::file_analysis::{Rel, Role};

/// Maximum imports per file in compact output
const MAX_IMPORTS: usize = 4096;

/// Current compact schema version. `CompactReport::version` is a
/// `&'static str` that always reports the version this build emits, so it is
/// never read from the wire — a decoded report re-encodes as the current
/// schema, not the one it was written with.
const SCHEMA_VERSION: &str = "8";

fn current_schema_version() -> &'static str {
    SCHEMA_VERSION
}

// ========================================================================
// Compact output types (v7 schema)
// ========================================================================

/// Top-level v7 report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactReport {
    /// Schema version — always "8"
    #[serde(rename = "v")]
    #[serde(skip_deserializing, default = "current_schema_version")]
    pub version: &'static str,
    /// Traits repo revision (first 8 chars of commit hash)
    #[serde(rename = "rev")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub traits_version: Option<String>,
    /// Files array
    #[serde(rename = "files")]
    pub files: Vec<CompactFile>,
    /// Fetch edges (`source_sha256 → content_sha256`, one per reference) for a
    /// consumer that retrieved referenced content and grafted it into this
    /// report. Report-level rather than per-file because a fetch is a per-event
    /// observation, so it never falsely dedups when content is exploded by hash.
    ///
    /// Opaque `Value`s: the record shape belongs to the fetching layer, which
    /// cleave does not depend on. The list is one small object per fetch.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub fetched: Vec<serde_json::Value>,
    /// Directory the analyzed archive's members were extracted into, when the
    /// caller kept them on disk for a downstream consumer to open. Absent on
    /// ordinary runs, which extract to a temporary directory and discard it.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub extracted_path: Option<String>,
}

/// An empty report of the current schema — no files, no fetch edges. Hand-written
/// rather than derived so `version` reports the schema this build emits; a derived
/// `Default` would leave it the empty string and produce a report claiming no
/// schema at all.
impl Default for CompactReport {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            traits_version: None,
            files: Vec::new(),
            fetched: Vec::new(),
            extracted_path: None,
        }
    }
}

/// Per-file analysis in v7 schema
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// Weighted risk score. Signed because `-1` is the sentinel scan writes for
    /// an archive member it listed but never analyzed; a `u32` here made such a
    /// report fail to deserialize.
    #[serde(rename = "risk")]
    #[serde(skip_serializing_if = "super::is_zero_i64")]
    #[serde(default)]
    pub risk: i64,
    /// Archive nesting depth (omit when 0)
    #[serde(rename = "depth")]
    #[serde(skip_serializing_if = "super::is_zero_u32")]
    #[serde(default)]
    pub depth: u32,
    /// Compact `id` of the archive/container this file was extracted from — the
    /// structural parent edge, `None` for the root. Lets a downstream consumer
    /// rebuild the archive tree and identify containers (a file is a container
    /// iff some file's `pid` points at it) without parsing the `!!`/`!` path
    /// delimiters, which nest inconsistently. Ids are stable: the compact `id`
    /// is the source `FileAnalysis.id`, so `pid` indexes `files[]` directly.
    #[serde(rename = "pid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub parent: Option<u32>,
    /// Edge type to `pid` — how this file was obtained. Omitted for ordinary
    /// containment; a root is identified by an absent `pid`. See [`Rel`].
    #[serde(skip_serializing_if = "Rel::is_member")]
    #[serde(default)]
    pub rel: Rel,
    /// For `rel = fetched`, the resolved locator it was fetched via.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub via: Option<String>,
    /// Analysis participation — how ML and presentation treat this node.
    /// Omitted for content. See [`Role`].
    #[serde(skip_serializing_if = "Role::is_content")]
    #[serde(default)]
    pub role: Role,
    /// Molecular formula
    #[serde(rename = "mol")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub formula: Option<String>,
    /// Normalized identity claims: name, version, signer, trust tier.
    #[serde(rename = "ident")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub identity: Option<filefacts::Identity>,
    /// Traits (findings)
    #[serde(rename = "traits")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub findings: Vec<CompactTrait>,
    /// External references this file declares (deps, URLs, repository), each
    /// with its byte offset — the file→dependency edges of the galaxy view.
    #[serde(rename = "refs")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub refs: Vec<CompactRef>,
    /// Merged context windows: raw bytes in file order for match highlighting.
    /// Render mode (hex vs text) is derived from the file's `type` field.
    #[serde(rename = "ctx")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub context: Vec<crate::types::ContextLine>,
    /// Dense filefacts-derived facts.
    #[serde(rename = "facts")]
    #[serde(skip_serializing_if = "CompactFacts::is_empty")]
    #[serde(default)]
    pub facts: CompactFacts,
}

/// A finding/trait in compact form
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    #[serde(default)]
    pub description: String,
    /// Confidence, always emitted.
    ///
    /// It used to be omitted at 0.5 (and 0.0), which saved ~2% of findings
    /// twelve bytes each and cost far more than that: the round trip was lossy,
    /// and each reader invented its own value for the absence — 0.5 in one
    /// place, 1.0 in the featurizer and collimator. A finding scored 0.5 was
    /// therefore read as 1.0 downstream, clearing a 0.65 inclusion gate it
    /// should have failed. Writing the number is cheaper than agreeing on what
    /// its absence meant.
    ///
    /// A missing `conf` (only reports from builds that omitted it) decodes to
    /// 0.0, which reads as "no confidence recorded" and falls below every
    /// downstream inclusion gate — the same side of every threshold as the 0.5
    /// those builds meant, without a surprising default to remember.
    #[serde(rename = "conf")]
    #[serde(default)]
    pub confidence: f32,
    /// MBC (Malware Behavior Catalog) ID
    #[serde(rename = "mbc")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub mbc: Option<String>,
    /// MITRE ATT&CK Technique ID
    #[serde(rename = "atk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub attack: Option<String>,
    /// Source files this finding came from. A single-entry vec means the
    /// finding was inherited from that embedded member; multiple entries means
    /// a cross-file composite that fired across several members.
    /// Omitted when the finding is native to this file.
    #[serde(rename = "from")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub from: Vec<CompactSource>,
    /// Evidence locations: `[[offset, length], ...]` byte spans, capped at 8.
    /// Locate matching content in `ctx` via range intersection:
    /// a ctx window covering `[addr, addr+len)` that overlaps `[off, off+len)`
    /// contains this finding's match. Omitted when empty.
    #[serde(rename = "spans")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub ev: Vec<[u64; 2]>,
    /// Machine-readable identity of a dependency this finding is about, set by a
    /// consumer that resolved the reference and graded what it fetched. `desc`
    /// carries the same facts as prose for a human or an LLM; this is the copy a
    /// program reads to link the finding to a specific artifact without parsing
    /// the sentence. `None` for ordinary findings, which are about the file
    /// itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub dep: Option<CompactDep>,
}

/// The dependency a [`CompactTrait::dep`] finding refers to: what named it, what
/// bytes came back, and what those bytes turned out to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactDep {
    /// Resolved PURL or URL the dependency was fetched via.
    pub locator: String,
    /// SHA256 of the fetched content, so a consumer can link straight to the
    /// dependency's own analysis.
    pub sha: String,
    /// Detected file type of the fetched content.
    #[serde(rename = "type")]
    pub file_type: String,
}

/// One member a cross-file composite drew from, in compact form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactSource {
    /// Contributing member's `files[]` id.
    pub file: u32,
    /// 1-based source line of the component match, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub line: Option<u64>,
    /// Byte offset of the component match, when known.
    #[serde(rename = "off", skip_serializing_if = "Option::is_none", default)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default)]
pub struct CompactFacts {
    /// Metrics (nested structure, floats rounded to 2dp).
    pub metrics: Option<RoundedMetrics>,
    /// Imports as tuples: [library, name] or [library, name, ordinal].
    pub imports: Vec<CompactImport>,
    /// Exports as tuples: [name] or [name, forward_to].
    pub exports: Vec<CompactExport>,
    /// Functions as tuples: [name], [name, offset], or [name, offset, kind].
    pub functions: Vec<CompactFunction>,
    /// Sections as tuples: [name, file_offset, file_size, entropy, flags].
    pub sections: Vec<CompactSection>,
    /// AST targets.
    pub targets: Vec<String>,
    /// AST members.
    pub members: Vec<String>,
}

impl CompactFacts {
    /// Whether every fact slot is empty (the block is then omitted).
    #[must_use]
    pub fn is_empty(&self) -> bool {
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

/// One import, encoded as `[library, name]` or `[library, name, ordinal]`.
#[derive(Debug, Clone)]
pub struct CompactImport {
    /// Library the symbol is imported from (e.g. `kernel32.dll`).
    pub library: String,
    /// Imported symbol name.
    pub name: String,
    /// Ordinal, when the import is by ordinal rather than name.
    pub ordinal: Option<u64>,
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

/// One export, encoded as `[name]` or `[name, forward_to]`.
#[derive(Debug, Clone)]
pub struct CompactExport {
    /// Exported symbol name.
    pub name: String,
    /// Target when this export forwards to another module's symbol.
    pub forward_to: Option<String>,
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

/// One function, encoded as `[name]`, `[name, offset]` or
/// `[name, offset, kind]` — `offset` occupies the slot before `kind`, so a
/// function carrying a kind always carries an offset slot too.
#[derive(Debug, Clone)]
pub struct CompactFunction {
    /// Function name.
    pub name: String,
    /// File offset of the function, when known.
    pub offset: Option<u64>,
    /// Coarse kind label (e.g. `export`), when known.
    pub kind: Option<String>,
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

/// One binary section, encoded as
/// `[name, offset, size, entropy, flags]` — always five elements.
#[derive(Debug, Clone)]
pub struct CompactSection {
    /// Section name (e.g. `.text`).
    pub name: String,
    /// File offset of the section's data.
    pub offset: u64,
    /// Section size on disk, in bytes.
    pub size: u64,
    /// Shannon entropy of the section's bytes.
    pub entropy: f64,
    /// Permission/characteristic flags, as a short string (e.g. `rx`).
    pub flags: String,
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
#[derive(Debug, Clone)]
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
// Deserialization — exact inverses of the hand-written encoders above
// ========================================================================
//
// The six types above encode as *positional, variable-length* sequences
// (`[library, name]` vs `[library, name, ordinal]`) or as a struct that omits
// empty fields, so `#[derive(Deserialize)]` cannot reproduce them. These
// impls exist so a compact report can be read back into its typed form
// instead of a `serde_json::Value` DOM — the featurizer's DOM walk is what
// forces a multi-GB tree to exist for a report whose serialized form is a
// few hundred MB (see MEMORY_EXPERIMENTS.md, N2).
//
// Every impl is paired with a round-trip test below; a shape change to an
// encoder must be mirrored here or that test fails.

/// Read a positional tuple whose trailing elements are optional.
macro_rules! seq_next {
    ($seq:expr, $ty:ty) => {
        $seq.next_element::<$ty>()?
    };
}

impl<'de> Deserialize<'de> for CompactImport {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CompactImport;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("[library, name] or [library, name, ordinal]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let library =
                    seq_next!(seq, String).ok_or_else(|| A::Error::missing_field("library"))?;
                let name = seq_next!(seq, String).ok_or_else(|| A::Error::missing_field("name"))?;
                Ok(CompactImport {
                    library,
                    name,
                    ordinal: seq_next!(seq, u64),
                })
            }
        }
        d.deserialize_seq(V)
    }
}

impl<'de> Deserialize<'de> for CompactExport {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CompactExport;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("[name] or [name, forward_to]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let name = seq_next!(seq, String).ok_or_else(|| A::Error::missing_field("name"))?;
                Ok(CompactExport {
                    name,
                    forward_to: seq_next!(seq, String),
                })
            }
        }
        d.deserialize_seq(V)
    }
}

impl<'de> Deserialize<'de> for CompactFunction {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CompactFunction;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("[name], [name, offset] or [name, offset, kind]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let name = seq_next!(seq, String).ok_or_else(|| A::Error::missing_field("name"))?;
                Ok(CompactFunction {
                    name,
                    offset: seq_next!(seq, u64),
                    kind: seq_next!(seq, String),
                })
            }
        }
        d.deserialize_seq(V)
    }
}

impl<'de> Deserialize<'de> for CompactSection {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CompactSection;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("[name, offset, size, entropy, flags]")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let need = |field| A::Error::missing_field(field);
                Ok(CompactSection {
                    name: seq_next!(seq, String).ok_or_else(|| need("name"))?,
                    offset: seq_next!(seq, u64).ok_or_else(|| need("offset"))?,
                    size: seq_next!(seq, u64).ok_or_else(|| need("size"))?,
                    entropy: seq_next!(seq, f64).ok_or_else(|| need("entropy"))?,
                    flags: seq_next!(seq, String).ok_or_else(|| need("flags"))?,
                })
            }
        }
        d.deserialize_seq(V)
    }
}

impl<'de> Deserialize<'de> for RoundedMetrics {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Values are already rounded on the wire; reading them back must not
        // round again (rounding is not idempotent-safe to reapply blindly).
        serde_json::Value::deserialize(d).map(RoundedMetrics)
    }
}

impl<'de> Deserialize<'de> for CompactFacts {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        /// Mirrors the encoder's keys; every field is omitted when empty, so
        /// all are optional here.
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            metrics: Option<RoundedMetrics>,
            #[serde(default)]
            imp: Vec<CompactImport>,
            #[serde(default)]
            exp: Vec<CompactExport>,
            #[serde(default)]
            funcs: Vec<CompactFunction>,
            #[serde(default)]
            sec: Vec<CompactSection>,
            #[serde(default)]
            tgt: Vec<String>,
            #[serde(default)]
            mbr: Vec<String>,
        }
        let w = Wire::deserialize(d)?;
        Ok(CompactFacts {
            metrics: w.metrics,
            imports: w.imp,
            exports: w.exp,
            functions: w.funcs,
            sections: w.sec,
            targets: w.tgt,
            members: w.mbr,
        })
    }
}

// ========================================================================
// Helpers
// ========================================================================

/// Convert Criticality enum to v4 ordinal (0-5).
/// 0=filtered, 1=component, 2=baseline, 3=notable, 4=suspicious, 5=hostile
///
/// `Exception` is assembly-only — it is stripped before serialization and so never
/// reaches this encoder. It shares the `0` floor with `Filtered` to keep the existing
/// v4 ordinals stable (shifting them would break the compact wire format).
fn crit_to_int(criticality: Criticality) -> u8 {
    match criticality {
        Criticality::Filtered | Criticality::Exception => 0,
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
                if let Some(srcs) = file.composite_sources.get(finding.id.as_str()) {
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
                    id: finding.id.to_string(),
                    criticality: crit_to_int(finding.crit),
                    description: finding.desc.to_string(),
                    confidence: finding.conf,
                    mbc: finding.mbc.as_deref().map(str::to_owned),
                    attack: finding.attack.as_deref().map(str::to_owned),
                    from,
                    ev: ev_spans,
                    dep: None,
                },
            );
        }
    }

    let traits: Vec<CompactTrait> = trait_order
        .into_iter()
        .filter_map(|id| trait_map.remove(id))
        .collect();

    let mut facts = file
        .precompact_facts
        .clone()
        .unwrap_or_else(|| compact_facts_from(file));
    // A fold-time projection leaves metrics unset (see
    // `compact_facts_from_parts`); round the retained flat map now.
    if facts.metrics.is_none() {
        facts.metrics = file
            .filefacts_metrics
            .as_ref()
            .map(nest_flat_metrics)
            .map(round_json_floats)
            .map(RoundedMetrics);
    }

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
                        filefacts::RefLocator::Purl(s)
                        | filefacts::RefLocator::Url(s)
                        | filefacts::RefLocator::Path(s) => s.clone(),
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

    CompactFile {
        id,
        path: file.path.clone(),
        file_type: file.file_type.clone(),
        sha: file.sha256.clone(),
        size: file.size,
        risk: i64::from(file.score),
        depth: file.depth,
        parent: file.parent_id,
        rel: file.rel,
        via: file.via.clone(),
        role: file.role,
        formula,
        identity: file.identity.clone(),
        findings: traits,
        refs,
        context: file.context.clone(),
        facts,
    }
}

/// Project a file's fact-bearing collections into the compact `facts` block:
/// dense capped tuples for imports/exports/functions/sections, 2dp-rounded
/// nested metrics, and the AST target/member string sets.
///
/// Called at convert time on the full-fidelity path. In compact-member mode
/// the member fold calls it early (see `FileAnalysis::precompact_facts`) so
/// the typed source vectors can be dropped while the rest of the archive
/// analyzes — the output is identical by construction, it is the same
/// function either way.
pub(crate) fn compact_facts_from(file: &super::file_analysis::FileAnalysis) -> CompactFacts {
    compact_facts_from_parts(file, true)
}

/// The projection behind [`compact_facts_from`]. `with_metrics: false` leaves
/// `metrics` unset for a fold-time caller that keeps the flat
/// `filefacts_metrics` map instead — the nested rounded `Value` tree is ~4×
/// the flat map's weight, so it is only built at convert time.
pub(crate) fn compact_facts_from_parts(
    file: &super::file_analysis::FileAnalysis,
    with_metrics: bool,
) -> CompactFacts {
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
    let metrics = if with_metrics {
        file.filefacts_metrics
            .as_ref()
            .map(nest_flat_metrics)
            .map(round_json_floats)
            .map(RoundedMetrics)
    } else {
        None
    };

    let (targets, members) = compact_ast(file);

    CompactFacts {
        metrics,
        imports,
        exports,
        functions,
        sections,
        targets,
        members,
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
        filefacts::RefKind::Local => "local",
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
/// Fill each reference's `target_file` with the id of the report file it
/// resolves to — the first-class file→file edge. An external dependency (PURL)
/// resolves when its package name matches a file's declared identity (a vendored
/// dependency present in the bundle); a `local` path resolves to a sibling by
/// full path. Truly-remote references and unmatched paths keep `target_file`
/// unset. See [`super::reference_graph`].
fn link_reference_targets(files: &mut [CompactFile]) {
    use super::reference_graph as rg;
    use std::collections::HashMap;

    let mut by_name: HashMap<String, u32> = HashMap::new();
    let mut by_path: HashMap<String, u32> = HashMap::new();
    for f in files.iter() {
        by_path.entry(f.path.clone()).or_insert(f.id);
        if let Some(identity) = &f.identity {
            for name in rg::identity_names(identity) {
                by_name.entry(name.to_string()).or_insert(f.id);
            }
        }
    }
    for f in files.iter_mut() {
        let own_id = f.id;
        let own_path = f.path.clone();
        for r in &mut f.refs {
            if r.target_file.is_some() {
                continue;
            }
            let target = if r.kind == "local" {
                rg::resolve_local_target(&own_path, &r.locator, |p| by_path.get(p).copied())
            } else {
                rg::package_name_from_purl(&r.locator).and_then(|n| by_name.get(&n).copied())
            };
            if let Some(tid) = target.filter(|tid| *tid != own_id) {
                r.target_file = Some(tid);
            }
        }
    }
}

fn assemble_report(mut files: Vec<CompactFile>) -> CompactReport {
    link_reference_targets(&mut files);
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
        version: SCHEMA_VERSION,
        traits_version,
        files,
        fetched: Vec::new(),
        extracted_path: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod wire_roundtrip_tests {

    /// A member whose facts were projected at fold time must convert to the
    /// same CompactFile as one converted directly — same function either way,
    /// pinned so a future divergence fails instead of silently changing output.
    #[test]
    fn precompacted_member_converts_identically() {
        let mut fa = crate::FileAnalysis {
            id: 1,
            path: "pkg.zip!!lib.dll".to_string(),
            file_type: "pe".to_string(),
            sha256: "a".repeat(64),
            size: 4096,
            depth: 1,
            ..Default::default()
        };
        fa.imports = vec![crate::types::Import {
            symbol: "CreateProcessW".to_string(),
            library: Some("kernel32.dll".to_string()),
            ..Default::default()
        }];
        fa.filefacts_metrics = Some(std::collections::BTreeMap::from([(
            "binary.overall_entropy".to_string(),
            7.123_456,
        )]));

        let direct = compact_from_files(&[fa.clone()]);

        let mut folded = fa;
        // Mirror `precompact_member_facts`: metrics stay flat until convert.
        folded.precompact_facts = Some(compact_facts_from_parts(&folded, false));
        folded.imports = Vec::new();
        let via_fold = compact_from_files(&[folded]);

        assert_eq!(
            serde_json::to_value(&direct).expect("direct"),
            serde_json::to_value(&via_fold).expect("folded"),
            "fold-time projection must not change the compact output"
        );
    }
    use super::*;

    /// Encode with the hand-written `Serialize`, decode with the hand-written
    /// `Deserialize`, and require the wire form to be stable across the round
    /// trip. These encoders emit *positional, variable-length* tuples, so a
    /// decoder that mis-orders or mis-counts elements is silently wrong rather
    /// than an error — which would corrupt ML features, not crash. Re-encoding
    /// and comparing JSON catches that.
    fn roundtrip<T>(value: &T) -> serde_json::Value
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let encoded = serde_json::to_value(value).expect("encode");
        let decoded: T = serde_json::from_value(encoded.clone()).expect("decode");
        let re_encoded = serde_json::to_value(&decoded).expect("re-encode");
        assert_eq!(encoded, re_encoded, "wire form changed across round trip");
        encoded
    }

    #[test]
    fn import_roundtrips_with_and_without_ordinal() {
        let short = roundtrip(&CompactImport {
            library: "kernel32.dll".into(),
            name: "VirtualAlloc".into(),
            ordinal: None,
        });
        assert_eq!(short, serde_json::json!(["kernel32.dll", "VirtualAlloc"]));

        let long = roundtrip(&CompactImport {
            library: "ws2_32.dll".into(),
            name: "connect".into(),
            ordinal: Some(4),
        });
        assert_eq!(long, serde_json::json!(["ws2_32.dll", "connect", 4]));
    }

    #[test]
    fn export_roundtrips_with_and_without_forward() {
        assert_eq!(
            roundtrip(&CompactExport {
                name: "start".into(),
                forward_to: None,
            }),
            serde_json::json!(["start"])
        );
        assert_eq!(
            roundtrip(&CompactExport {
                name: "puts".into(),
                forward_to: Some("msvcrt.puts".into()),
            }),
            serde_json::json!(["puts", "msvcrt.puts"])
        );
    }

    /// `offset` is positionally before `kind`, so a function carrying a kind
    /// always carries an offset slot too — the decoder must not read the kind
    /// string into the offset.
    #[test]
    fn function_roundtrips_at_each_arity() {
        assert_eq!(
            roundtrip(&CompactFunction {
                name: "main".into(),
                offset: None,
                kind: None,
            }),
            serde_json::json!(["main"])
        );
        assert_eq!(
            roundtrip(&CompactFunction {
                name: "main".into(),
                offset: Some(4096),
                kind: None,
            }),
            serde_json::json!(["main", 4096])
        );
        assert_eq!(
            roundtrip(&CompactFunction {
                name: "main".into(),
                offset: Some(4096),
                kind: Some("export".into()),
            }),
            serde_json::json!(["main", 4096, "export"])
        );
    }

    #[test]
    fn section_roundtrips_all_five_positions() {
        assert_eq!(
            roundtrip(&CompactSection {
                name: ".text".into(),
                offset: 1024,
                size: 2048,
                entropy: 6.5,
                flags: "rx".into(),
            }),
            serde_json::json!([".text", 1024, 2048, 6.5, "rx"])
        );
    }

    /// The whole point of the decoders: a real report, built the way emit
    /// builds one, must survive the wire round trip byte-for-byte. This is the
    /// guarantee the typed featurizer depends on — if it does not hold, reading
    /// a report typed instead of as a `serde_json::Value` would silently change
    /// ML features rather than fail.
    /// `scan` marks an archive member it listed but never analyzed with
    /// `risk: -1`. That is a real value on the wire, so the typed schema must
    /// accept it — with `risk: u32` this input failed to deserialize outright,
    /// and the other round-trip tests missed it because their fixtures were
    /// all non-negative.
    #[test]
    fn negative_risk_sentinel_roundtrips() {
        let wire = serde_json::json!({
            "v": "8",
            "files": [{
                "id": 1, "path": "a.zip!!m.bin", "type": "data",
                "sha": "b".repeat(64), "size": 10, "depth": 1, "risk": -1
            }]
        });
        let decoded: CompactReport =
            serde_json::from_value(wire).expect("unanalyzed-member report must decode");
        assert_eq!(decoded.files[0].risk, -1);
        let re = serde_json::to_value(&decoded).expect("re-encode");
        assert_eq!(re["files"][0]["risk"], serde_json::json!(-1));
    }

    #[test]
    fn full_report_roundtrips_byte_for_byte() {
        use super::super::file_analysis::FileAnalysis;
        use super::super::traits_findings::Finding;
        use super::super::{Criticality, FindingKind};

        let mut fa = FileAnalysis::new(
            0,
            "pkg.zip!!lib/mod.py".to_string(),
            "python".to_string(),
            "a".repeat(64),
            4096,
        );
        let mut finding = Finding::new(
            "objectives/execution/shell",
            FindingKind::Capability,
            "spawns a shell",
            0.9,
        );
        finding.crit = Criticality::Suspicious;
        fa.findings.push(finding);
        fa.depth = 1;
        fa.parent_id = Some(0);

        let report = compact_from_files(&[fa]);
        let encoded = serde_json::to_string(&report).expect("encode");
        let decoded: CompactReport = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(
            encoded,
            serde_json::to_string(&decoded).expect("re-encode"),
            "a full compact report did not survive the wire round trip"
        );
        assert_eq!(decoded.files.len(), 1);
        assert_eq!(decoded.files[0].findings.len(), 1);
        assert_eq!(decoded.version, SCHEMA_VERSION);
    }

    /// Every `CompactFacts` field is omitted when empty, so the decoder must
    /// default each one rather than fail — and an all-empty block must survive
    /// as all-empty.
    #[test]
    fn facts_roundtrips_sparse_and_populated() {
        let empty = CompactFacts {
            metrics: None,
            imports: Vec::new(),
            exports: Vec::new(),
            functions: Vec::new(),
            sections: Vec::new(),
            targets: Vec::new(),
            members: Vec::new(),
        };
        assert_eq!(roundtrip(&empty), serde_json::json!({}));

        let populated = CompactFacts {
            metrics: Some(RoundedMetrics(
                serde_json::json!({"binary": {"entropy": 6.5}}),
            )),
            imports: vec![CompactImport {
                library: "libc".into(),
                name: "execve".into(),
                ordinal: None,
            }],
            exports: Vec::new(),
            functions: vec![CompactFunction {
                name: "f".into(),
                offset: Some(1),
                kind: None,
            }],
            sections: Vec::new(),
            targets: vec!["os.system".into()],
            members: vec!["a.b".into()],
        };
        let wire = roundtrip(&populated);
        // Field *names* are part of the contract the featurizer reads.
        let obj = wire.as_object().unwrap();
        assert!(obj.contains_key("metrics") && obj.contains_key("imp"));
        assert!(obj.contains_key("funcs") && obj.contains_key("tgt") && obj.contains_key("mbr"));
        assert!(!obj.contains_key("exp"), "empty fields stay omitted");
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
            id: id.to_string().into(),
            kind: FindingKind::Capability,
            desc: "test".to_string().into(),
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

    /// Provenance fields serialize sparsely: an ordinary content member emits
    /// none of them, keeping the common case free of the new keys. `rel` and
    /// `role` are orthogonal — a fetched dependency is `Content` (no `role`),
    /// while a registry record is `Sidecar` with no `via`.
    #[test]
    fn rel_role_via_serialize_sparsely() {
        use super::super::file_analysis::{Rel, Role};
        use super::convert_file;

        let obj = |fa: &FileAnalysis| -> serde_json::Value {
            let v = serde_json::to_value(convert_file(fa, fa.id));
            assert!(v.is_ok(), "serialize compact file: {v:?}");
            v.unwrap_or(serde_json::Value::Null)
        };

        // Ordinary content member emits none of the provenance keys.
        let o = obj(&file_with(vec![]));
        for k in ["rel", "via", "role", "pid"] {
            assert!(o.get(k).is_none(), "content member should omit {k}");
        }

        // Fetched dependency: content by role, so `role` stays absent while
        // `rel`/`via`/`pid` are present.
        let mut fetched = FileAnalysis::new(1, "4.13.0".into(), "gz".into(), "s".into(), 9);
        fetched.parent_id = Some(0);
        fetched.rel = Rel::Fetched;
        fetched.via = Some("https://example.test/4.13.0.tar.gz".into());
        let o = obj(&fetched);
        assert_eq!(o["pid"], json!(0));
        assert_eq!(o["rel"], json!("fetched"));
        assert_eq!(o["via"], json!("https://example.test/4.13.0.tar.gz"));
        assert!(o.get("role").is_none(), "fetched content should omit role");

        // Registry sidecar: `rel`/`role`/`pid` present, no `via`.
        let mut sidecar = FileAnalysis::new(2, "registry".into(), "registry".into(), "s".into(), 4);
        sidecar.parent_id = Some(0);
        sidecar.rel = Rel::Registry;
        sidecar.role = Role::Sidecar;
        let o = obj(&sidecar);
        assert_eq!(o["rel"], json!("registry"));
        assert_eq!(o["role"], json!("sidecar"));
        assert!(
            o.get("via").is_none(),
            "sidecar without fetch should omit via"
        );
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
