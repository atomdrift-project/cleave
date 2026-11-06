//! The compact report: cleave's JSON output and stored form (schema 9).
//!
//! Each file's JSON is fully self-contained (splittable for per-file DB storage).
//! Conversion from internal types happens via [`compact_from_files`].

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
const SCHEMA_VERSION: &str = "9";

fn current_schema_version() -> &'static str {
    SCHEMA_VERSION
}

/// Which facts a compact report keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Facts {
    /// Only the facts the shipping models read (`model_facts`); the report's
    /// `fp` names that profile.
    #[default]
    Model,
    /// Every fact: imports, exports, functions, sections and all metrics.
    Full,
}

/// The compact report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactReport {
    /// Schema version this build writes.
    #[serde(rename = "v")]
    #[serde(skip_deserializing, default = "current_schema_version")]
    pub version: &'static str,
    /// Traits repo revision (first 8 chars of commit hash)
    #[serde(rename = "rev")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub traits_version: Option<String>,
    /// The fact profile `facts` was reduced to (`model_facts::profile_id`);
    /// absent when every fact is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
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
}

/// An empty report of the current schema — no files, no fetch edges. Hand-written
/// rather than derived so `version` reports the schema this build emits; a derived
/// `Default` would leave it the empty string and produce a report claiming no
/// schema at all.
impl CompactReport {
    /// Reduce every file's facts to the model-input profile and name it in
    /// `fp`: the same report [`Facts::Model`] conversion builds, for a caller
    /// that needed the full facts first (a model extracts features from them).
    pub fn retain_model_facts(&mut self) {
        // A newer manifest cannot restore inputs omitted by an older producer.
        if self.fp.is_some() {
            return;
        }
        for file in &mut self.files {
            file.facts = crate::model_facts::project(&file.facts);
        }
        self.fp = Some(crate::model_facts::profile_id().to_string());
    }
}

impl Default for CompactReport {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            traits_version: None,
            fp: None,
            files: Vec::new(),
            fetched: Vec::new(),
        }
    }
}

/// Per-file analysis in v7 schema
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompactFile {
    /// Per-file analysis limitations, retained even without findings.
    #[serde(default, skip_serializing_if = "super::AnalysisGaps::is_empty")]
    pub analysis_gaps: super::AnalysisGaps,
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
    /// Notable-or-above traits this file matched that were withheld or demoted
    /// by their own `unless:`/`downgrade:` legs — what the analysis decided not
    /// to report, with the legs and byte spans behind that call.
    #[serde(rename = "supp")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub suppressions: Vec<crate::types::Suppression>,
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
    /// place, 1.0 in the featurizer and the ML pipeline. A finding scored 0.5 was
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
    /// For a composite: indices into this file's own `traits[]` of the
    /// component traits it fired on — the composite→atomic edges of the trait
    /// graph, which a visualization otherwise has no way to reconstruct (the
    /// trait ids alone don't say which composite consumed which atom).
    ///
    /// Indices, not ids, because the ids are already in the array and repeating
    /// them costs far more than a small integer. They address `traits[]` of the
    /// **same** file, are ascending, and never dangle.
    ///
    /// A container resolves its own edges: archive and encoding-layer
    /// inheritance copies a composite *and* the components it fired on into the
    /// parent's findings, so a member's composite re-emitted on the zip indexes
    /// the zip's own `traits[]` while [`Self::from`] names the member it came
    /// from. The two are complementary — `uses` is the shape of the detection,
    /// `from` is where it happened.
    ///
    /// A ref that resolves to nothing is dropped, not emitted as a dangling
    /// index. That is rare (~0.6% of edges on the full trait corpus) and means
    /// the component is not in the report: an `unless:`-suppressed leg the
    /// composite still recorded, or a leg that stayed behind in a member.
    /// Empty for atomic traits.
    #[serde(rename = "uses")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub uses: Vec<u32>,
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
/// where in the file it sits. Lets a downstream consumer (a report viewer's galaxy view)
/// draw byte-anchored edges from each file to what it references.
///
/// The target is either *external* — a package/URL named by `to` — or
/// *internal* — another file in the same bundle, named by `file` (its `files[]`
/// id). External today; `file` is reserved so that when cleave resolves
/// intra-bundle references (a relative `require`/`import`, an HTML `src`, a
/// manifest pointing at a sibling) — work that currently lives in a report viewer — those
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
    /// Absent when filefacts could not place it.
    #[serde(rename = "off", default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
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
    /// Imports as tuples: `[library, name]` or `[library, name, ordinal]`.
    pub imports: Vec<CompactImport>,
    /// Exports as tuples: `[name]` or `[name, forward_to]`.
    pub exports: Vec<CompactExport>,
    /// Functions as tuples: `[name]`, `[name, offset]`, or `[name, offset, kind]`.
    pub functions: Vec<CompactFunction>,
    /// Sections as tuples: `[name, file_offset, file_size, entropy, flags]`.
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
        self.serialize_with_metrics(serializer, self.metrics.as_ref())
    }
}

impl CompactFacts {
    /// Reuse the fact field contract with a metric serialization adapter.
    pub(crate) fn serialize_with_metrics<S: Serializer, M: Serialize>(
        &self,
        serializer: S,
        metrics: Option<&M>,
    ) -> Result<S::Ok, S::Error> {
        let mut fields = usize::from(metrics.is_some());
        fields += usize::from(!self.imports.is_empty());
        fields += usize::from(!self.exports.is_empty());
        fields += usize::from(!self.functions.is_empty());
        fields += usize::from(!self.sections.is_empty());
        fields += usize::from(!self.targets.is_empty());
        fields += usize::from(!self.members.is_empty());

        let mut st = serializer.serialize_struct("CompactFacts", fields)?;
        if let Some(metrics) = metrics {
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
pub(crate) fn round_json_floats(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                let rounded = (f * 100.0).round() / 100.0;
                // Integer-valued metrics serialize as integers ("4" not
                // "4.0") — numerically identical JSON, two bytes less per
                // value, and most metric values are counts.
                #[allow(clippy::cast_possible_truncation)]
                if rounded.fract() == 0.0 && rounded.abs() < 9_007_199_254_740_992.0 {
                    serde_json::Value::Number(serde_json::Number::from(rounded as i64))
                } else {
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(rounded)
                            .unwrap_or_else(|| serde_json::Number::from(0)),
                    )
                }
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

fn compact_ast(
    file: &super::file_analysis::FileAnalysis,
    retain_model: bool,
) -> (Vec<String>, Vec<String>) {
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
            } if !retain_model || crate::model_facts::needed_symbol(target) => {
                target_set.insert(target.clone());
            }
            filefacts::Symbol::Member { path, .. }
                if !retain_model || crate::model_facts::needed_symbol(path) =>
            {
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
fn convert_file(file: &super::file_analysis::FileAnalysis, id: u32, facts: Facts) -> CompactFile {
    // Dedup findings by ID within this file, merge evidence
    let mut trait_map: HashMap<&str, CompactTrait> = HashMap::new();
    let mut trait_order: Vec<&str> = Vec::new();
    // Component ids per trait id, unioned across the duplicate findings the
    // loop below folds together. Resolved to `traits[]` indices once the array
    // is final — the ids alone are meaningless to a consumer drawing the graph.
    let mut refs_by_id: HashMap<&str, Vec<&str>> = HashMap::new();

    for finding in &file.findings {
        if !finding.trait_refs.is_empty() {
            let refs = refs_by_id.entry(&finding.id).or_default();
            for trait_ref in &finding.trait_refs {
                if !refs.contains(&trait_ref.as_str()) {
                    refs.push(trait_ref);
                }
            }
        }
        // Local evidence spans — precomputed at fold for compact-retained
        // members, else derived here; one shared definition either way.
        let ev_spans: Vec<[u64; 2]> = crate::types::traits_findings::finding_spans(finding);

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
                crate::types::traits_findings::sort_dedup_spans_by_offset(&mut existing.ev);
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
                    uses: Vec::new(),
                    dep: None,
                },
            );
        }
    }

    let mut traits: Vec<CompactTrait> = trait_order
        .into_iter()
        .filter_map(|id| trait_map.remove(id))
        .collect();

    // Resolve each composite's component ids to positions in `traits`. Done in
    // a second pass because a composite is folded before some of the components
    // it references, so no index is knowable until the array is complete.
    if !refs_by_id.is_empty() {
        let position: HashMap<&str, u32> = traits
            .iter()
            .enumerate()
            .map(|(i, t)| (t.id.as_str(), i as u32))
            .collect();
        let mut unresolved = 0usize;
        let uses: Vec<Vec<u32>> = traits
            .iter()
            .map(|t| {
                let refs = refs_by_id.get(t.id.as_str()).map_or(&[][..], Vec::as_slice);
                let mut idx: Vec<u32> = refs
                    .iter()
                    // A ref the report doesn't carry is dropped rather than
                    // left dangling; see `CompactTrait::uses`.
                    .filter_map(|id| position.get(id).copied())
                    .collect();
                idx.sort_unstable();
                idx.dedup();
                unresolved += refs.len() - idx.len();
                idx
            })
            .collect();
        if unresolved > 0 {
            tracing::debug!(
                file = %file.path,
                unresolved,
                "composite components absent from this file's traits",
            );
        }
        for (t, idx) in traits.iter_mut().zip(uses) {
            t.uses = idx;
        }
    }

    let facts = match facts {
        Facts::Model => crate::model_facts::from_file(file),
        Facts::Full => facts_from_file(file),
    };

    // Compute formula if not already present. Use the canonical filter so the
    // JSON `f` field stays in lockstep with the CLI header — both must reflect
    // notable-or-higher findings only.
    let formula = file
        .formula
        .clone()
        .or_else(|| crate::formula::of(&file.findings));

    let refs = refs_from_file(file);

    CompactFile {
        id,
        analysis_gaps: file.analysis_gaps.clone(),
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
        suppressions: file.suppressions.clone(),
        refs,
        context: file.context.clone(),
        facts,
    }
}

/// Effective facts shared by the legacy and candidate wire encoders.
pub(crate) fn facts_from_file(file: &super::FileAnalysis) -> CompactFacts {
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

    facts
}

/// Effective declarations, including those read from a saved wire report.
pub(crate) fn refs_from_file(file: &super::FileAnalysis) -> Vec<CompactRef> {
    if let Some(refs) = &file.precompact_refs {
        return refs.clone();
    }
    // External references this file declares, byte-anchored, for the galaxy
    // view. Read straight from the filefacts view so every reference (fetched
    // or not) is attributed to the file that named it.
    let refs: Vec<CompactRef> = file
        .filefacts
        .as_ref()
        .map(|ff| {
            ff.references
                .iter()
                .filter_map(|r| {
                    let locator = match &r.locator {
                        filefacts::RefLocator::Purl(s)
                        | filefacts::RefLocator::Url(s)
                        | filefacts::RefLocator::Path(s) => s.clone(),
                        // A locator kind newer than this build.
                        _ => return None,
                    };
                    Some(CompactRef {
                        locator,
                        kind: ref_kind_str(r.kind).to_string(),
                        offset: r.offset,
                        // External today; intra-bundle resolution (a report viewer's job for
                        // now) will fill this when it moves into cleave.
                        target_file: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    refs
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
    compact_facts_selected(file, with_metrics, false)
}

/// Shared projection: model retention filters after the existing caps, before
/// cloning rows. Full analysis/cache and v8 output keep their previous behavior.
pub(crate) fn compact_facts_selected(
    file: &super::file_analysis::FileAnalysis,
    with_metrics: bool,
    retain_model: bool,
) -> CompactFacts {
    // Flatten symbol-like collections into dense tuples, capped to prevent oversized output.
    let imports: Vec<CompactImport> = file
        .imports
        .iter()
        .take(MAX_IMPORTS)
        .filter(|i| {
            !retain_model
                || crate::model_facts::needed_symbol(&i.symbol)
                || (i.symbol.is_empty()
                    && i.library
                        .as_deref()
                        .is_some_and(crate::model_facts::needed_symbol))
        })
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
        .filter(|x| !retain_model || crate::model_facts::needed_symbol(&x.symbol))
        .map(|x| CompactExport {
            name: x.symbol.clone(),
            forward_to: x.forward_to.clone(),
        })
        .collect();

    let functions: Vec<CompactFunction> = file
        .functions
        .iter()
        .take(MAX_IMPORTS)
        .filter(|f| !retain_model || crate::model_facts::needed_symbol(&f.name))
        .map(|f| CompactFunction {
            name: f.name.clone(),
            offset: f.offset.as_deref().and_then(parse_hex_or_decimal_u64),
            kind: None,
        })
        .collect();

    let sections: Vec<CompactSection> = if retain_model {
        Vec::new()
    } else {
        file.sections
            .iter()
            .map(|s| CompactSection {
                name: s.name.clone(),
                offset: s.offset.unwrap_or(0),
                size: s.size,
                entropy: (s.entropy * 100.0).round() / 100.0,
                flags: s.permissions.clone().unwrap_or_else(|| s.flags.join(",")),
            })
            .collect()
    };

    // Round metrics floats to 2dp. Only the flat filefacts_metrics map
    // survives — typed projections were retired.
    let metrics = if with_metrics && retain_model {
        crate::model_facts::flat_metrics(file.filefacts_metrics.as_ref())
    } else if with_metrics {
        file.filefacts_metrics
            .as_ref()
            .map(nest_flat_metrics)
            .map(round_json_floats)
            .map(RoundedMetrics)
    } else {
        None
    };

    let (targets, members) = compact_ast(file, retain_model);

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
pub fn compact_from_files(
    files: &[super::file_analysis::FileAnalysis],
    facts: Facts,
) -> CompactReport {
    let compact_files: Vec<CompactFile> =
        files.iter().map(|f| convert_file(f, f.id, facts)).collect();
    assemble_report(compact_files, facts)
}

/// [`compact_from_files`], but consuming: each `FileAnalysis` is dropped as
/// soon as its compact projection exists, so a member-heavy report and its
/// compact copy never fully co-reside. Output-identical to the borrowing
/// version — `convert_file` is pure. Use from callers that are done with the
/// typed files (the JSON emission path); callers that still render the typed
/// report keep the borrowing version.
#[must_use]
pub fn compact_from_files_consuming(
    files: Vec<super::file_analysis::FileAnalysis>,
    facts: Facts,
) -> CompactReport {
    let compact_files: Vec<CompactFile> = files
        .into_iter()
        .map(|f| convert_file(&f, f.id, facts))
        .collect();
    assemble_report(compact_files, facts)
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

fn assemble_report(mut files: Vec<CompactFile>, facts: Facts) -> CompactReport {
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
    let traits_version = crate::traits_repo::version().map(wire_traits_version);
    CompactReport {
        version: SCHEMA_VERSION,
        traits_version,
        fp: (facts == Facts::Model).then(|| crate::model_facts::profile_id().to_string()),
        files,
        fetched: Vec::new(),
    }
}

fn wire_traits_version(version: String) -> String {
    // Commit revisions keep the compact wire format. A dirty-tree revision is
    // content-derived and needs all 64 bits: truncating it to five characters
    // would make unrelated rule edits collide in a consumer's dedupe key.
    if version.starts_with('w') {
        version
    } else if version.len() > 5 {
        version[..5].to_string()
    } else {
        version
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod wire_roundtrip_tests;

#[cfg(test)]
mod formula_tests;
