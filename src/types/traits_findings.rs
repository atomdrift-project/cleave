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
    #[serde(skip_serializing_if = "String::is_empty", default)]
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

// ========================================================================
// Context Model — the LLM/output surface that replaces raw Evidence.
//
// A file's `context` is a merged, render-ready set of lines: the matched
// content shown once, in file order, annotated with the findings that touch
// it. Overlapping or adjacent match windows are merged (within and across
// findings), so a line two traits share is stored once with two notes, and a
// composite spanning regions just annotates several lines. Each note carries
// the match Location (`off`) + Length (`len`), so the old per-match Evidence
// (value/method) is synthesizable from the content slice if ever needed.
// ========================================================================

/// One unit of merged context: a contiguous run of raw file bytes plus the
/// findings whose match falls inside it. Analysis emits the bytes; rendering
/// them as text or a hex+ascii dump is a render-time concern derived from the
/// file's `type`. A unit with no notes is pure context (`-` in tiny output); a
/// unit with notes is a hit (`:`).
///
/// `loc` is the absolute byte offset of `data[0]` — always, for binary and text
/// alike, never a line number. `line` and `col` are its 1-based source
/// position, present for textual chunks and absent for binaries; they are a
/// derived label for byte-blind consumers. A note's own position is `line`/`col`
/// advanced by the newlines and columns between `data[0]` and `note.off`, and
/// its highlight spans `note.off - loc .. note.off - loc + note.len`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContextLine {
    /// Absolute byte offset of `data[0]`. Always a byte offset — binary and
    /// text alike; never a line number.
    #[serde(rename = "ln")]
    pub loc: u64,
    /// 1-based source line of `data[0]`. `Some` for textual chunks; `None` for
    /// binary windows, which carry no line structure.
    #[serde(rename = "line", default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// 1-based column of `data[0]` within its line. `Some` for textual chunks;
    /// `None` for binary. Exceeds 1 when the chunk is a mid-line slice of an
    /// ultra-long line.
    #[serde(rename = "col", default, skip_serializing_if = "Option::is_none")]
    pub col: Option<u64>,
    /// Raw content bytes, Z85-encoded. Binary files render as hex+ascii;
    /// textual files render as decoded text. Render mode is derived from the
    /// file's `type` field — no per-line flag needed.
    #[serde(rename = "b", with = "crate::types::z85::serde_z85")]
    pub data: Vec<u8>,
    /// Findings whose match falls on this unit. Serialized (as `n`) so a cached
    /// report round-trips losslessly — the renderer reads these notes directly,
    /// and they're rebuilt only during a fresh capture, not on a cache hit.
    /// Omitted when empty (pure-context lines), so most rows stay lean; public
    /// consumers (prism) can still locate matches via `finding.spans` × ctx.
    #[serde(rename = "n", default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<Note>,
}

/// Serialize/deserialize a [`Criticality`] as its ordinal `0..=5`, matching the
/// compact finding `crit` field and keeping context notes small.
mod crit_ordinal {
    use super::Criticality;
    use serde::{Deserialize, Deserializer, Serializer};

    // Stable wire ordinals, decoupled from the enum's `as u8` discriminant so that
    // inserting a variant (e.g. `Exception`) never shifts the serialized values.
    // `Exception` takes 6 — past the original 0..=5 range — so existing caches stay
    // valid. Keep `serialize` and `deserialize` exact inverses.
    pub(super) fn serialize<S: Serializer>(c: &Criticality, s: S) -> Result<S::Ok, S::Error> {
        let ordinal: u8 = match c {
            Criticality::Filtered => 0,
            Criticality::Component => 1,
            Criticality::Baseline => 2,
            Criticality::Notable => 3,
            Criticality::Suspicious => 4,
            Criticality::Hostile => 5,
            Criticality::Exception => 6,
        };
        s.serialize_u8(ordinal)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Criticality, D::Error> {
        Ok(match u8::deserialize(d)? {
            0 => Criticality::Filtered,
            1 => Criticality::Component,
            3 => Criticality::Notable,
            4 => Criticality::Suspicious,
            5 => Criticality::Hostile,
            6 => Criticality::Exception,
            _ => Criticality::Baseline,
        })
    }
}

/// A finding annotation on a [`ContextLine`] — one trait's match at this spot.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Note {
    /// Criticality of the annotating finding.
    #[serde(rename = "c", with = "crit_ordinal")]
    pub crit: Criticality,
    /// Finding identifier. Interned: shares the finding's allocation.
    #[serde(rename = "i")]
    pub id: super::Istr,
    /// Human-readable description (may be empty). Interned.
    #[serde(rename = "d", default, skip_serializing_if = "super::Istr::is_empty")]
    pub desc: super::Istr,
    /// Exact byte offset of the match (the "Location").
    #[serde(rename = "o")]
    pub off: u64,
    /// Match length in bytes (the "Length"); 0 when unknown.
    #[serde(rename = "z", default, skip_serializing_if = "super::is_zero_u32")]
    pub len: u32,
    /// Finding confidence (used to rank overlapping matches: the highest
    /// `conf × crit` wins). Serialized (as `cf`) so a cached note round-trips
    /// with the strength the render-time dedup needs; omitted when zero.
    #[serde(rename = "cf", default, skip_serializing_if = "super::is_zero_f32")]
    pub conf: f32,
}

/// A finding - an interpretive conclusion based on traits
/// Findings represent what we CONCLUDE from traits (capabilities, threats, behaviors)
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Finding {
    /// Finding identifier using / delimiter (e.g., "command-and-control/hardcoded-ip", "net/socket").
    /// Interned: a report holds each distinct id once, however many findings carry it.
    pub id: super::Istr,
    /// Kind of finding (capability, structural, indicator, weakness)
    #[serde(default, skip_serializing_if = "FindingKind::is_default")]
    pub kind: FindingKind,
    /// Human-readable description (empty for compact internal findings). Interned.
    #[serde(default, skip_serializing_if = "super::Istr::is_empty")]
    pub desc: super::Istr,
    /// Confidence score (0.5 = heuristic, 1.0 = definitive)
    #[serde(alias = "confidence", default)]
    pub conf: f32,
    /// Criticality level
    #[serde(default)]
    pub crit: Criticality,
    /// MBC (Malware Behavior Catalog) ID. Interned — static per trait.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<super::Istr>,
    /// MITRE ATT&CK Technique ID. Interned — static per trait.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<super::Istr>,
    /// Trait IDs that contributed to this finding (for aggregated findings).
    /// Interned — these are the same ids the findings themselves carry.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub trait_refs: Vec<super::Istr>,
    /// Raw per-match evidence produced by the matchers — the offsets the
    /// context-capture pass and the compact `spans` derivation consume. The
    /// public compact output exposes only the derived `spans`, but the raw
    /// report serializes evidence (omitted when empty) so a cached report
    /// round-trips losslessly: a cache hit skips analysis, so without this the
    /// compact `spans` would come out empty. `alt_value`/internal matcher
    /// helpers stay skipped — they're consumed during matching, which has run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// Total match count for density/frequency analysis (may exceed evidence.len())
    #[serde(skip_serializing_if = "is_zero_usize", default)]
    pub match_count: usize,
    /// Source file path where this trait/rule was defined.
    ///
    /// NOT interned, deliberately: several analyzers (embedded-code, subfile)
    /// set this to the *analyzed member's* path rather than a rule path, so it
    /// is one distinct string per member. Interning it pinned ~55k member paths
    /// in the pool's strong refs and cost ~0.3-1.2 GB on the benchmark — the
    /// opposite of the intended effect. Only low-cardinality fields belong in
    /// `Istr`.
    #[allow(dead_code)] // Populated during trait evaluation, skip-serialized in output
    #[serde(skip_serializing, default)]
    pub source_file: Option<String>,
    /// Provenance for an inherited finding: the `FileAnalysis::id` of the
    /// embedded child file it was actually located in. `None` for a finding
    /// native to the file that lists it. Set during `finalize` once file ids are
    /// assigned, so consumers can attribute and de-duplicate a finding across the
    /// archive tree by traversal (`src` → `files[id]`) rather than re-deriving it
    /// from byte offsets that only make sense in the child's own byte space.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub src: Option<u32>,
}

impl Finding {
    /// Create a new finding with the given identifier, kind, description, and confidence
    #[must_use]
    pub fn new(
        id: impl Into<super::Istr>,
        kind: FindingKind,
        desc: impl Into<super::Istr>,
        conf: f32,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            desc: desc.into(),
            conf,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: Vec::new(),
            evidence: Vec::new(),
            match_count: 0,
            source_file: None,
            src: None,
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
    pub fn with_mbc(mut self, mbc: &str) -> Self {
        self.mbc = Some(mbc.into());
        self
    }

    /// Attach a MITRE ATT&CK technique identifier to this finding
    #[must_use]
    pub fn with_attack(mut self, attack: &str) -> Self {
        self.attack = Some(attack.into());
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

/// Maximum number of evidence items collected per trait/finding internally.
pub(crate) const MAX_EVIDENCE_PER_TRAIT: usize = 64;

/// Maximum match locations stored in JSON output and used for context windows.
pub(crate) const MAX_EV_LOCS: usize = 8;

/// The bounded, sanitized form of an evidence value — what serialization
/// emits. `None` when the value is already within bounds and clean.
///
/// The truncated form (content + `...[truncated]`) fits within
/// `MAX_EVIDENCE_VALUE_SIZE`, which makes bounding idempotent: a value
/// already bounded at member-fold time passes through serialization
/// unchanged. (The content budget is the marker's 14 bytes below the cap;
/// it was previously 12, so historically-truncated values shift by 2
/// bytes of content — a v3-only cosmetic change, evidence text never
/// reaches the compact schema.)
pub(crate) fn bound_evidence_value(value: &str) -> Option<String> {
    let clean = sanitize_evidence_for_json(value);
    let v = clean.as_deref().unwrap_or(value);
    if v.len() <= MAX_EVIDENCE_VALUE_SIZE {
        return clean;
    }
    // Truncate at a valid UTF-8 boundary; marker included, total stays ≤ cap.
    let truncated = truncate_str(v, MAX_EVIDENCE_VALUE_SIZE - 14);
    Some(format!("{truncated}...[truncated]"))
}

/// Serialize evidence value, truncating to MAX_EVIDENCE_VALUE_SIZE.
/// Strips null bytes (\0) which are common in strings extracted from malware
/// binaries but cannot be stored in PostgreSQL JSONB.
fn serialize_truncated_value<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match bound_evidence_value(value) {
        Some(bounded) => serializer.serialize_str(&bounded),
        None => serializer.serialize_str(value),
    }
}

/// Remove null bytes from a string. Returns None if the string is already clean
/// (avoids allocation in the common case).
fn sanitize_evidence_for_json(s: &str) -> Option<String> {
    if s.contains('\0') {
        Some(s.replace('\0', ""))
    } else {
        None
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

/// Max bytes of a matched value retained **in memory** as evidence. The full
/// value is only needed during matching; the stored copy is for context/display,
/// so we cap it at storage time (not just at serialization) to bound per-worker
/// RSS — long binary strings stored verbatim were a peak driver.
pub(crate) const MAX_EVIDENCE_VALUE_STORED: usize = 128;

/// Truncate a matched value to [`MAX_EVIDENCE_VALUE_STORED`] at a char boundary,
/// for storage in an [`Evidence`]. Allocates the (bounded) owned string.
#[must_use]
pub(crate) fn truncate_evidence_value(value: &str) -> String {
    truncate_str(value, MAX_EVIDENCE_VALUE_STORED).to_string()
}

/// Maximum number of byte offsets to include in JSON output
pub(crate) const MAX_OFFSETS_IN_JSON: usize = 8;

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
    #[serde(skip_serializing_if = "String::is_empty", default)]
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
    /// Source-byte length of the match, when it differs from `value.len()`.
    /// Set for matches against a decoded string layer (base64/xor/…): `value`
    /// holds the decoded text but the match occupies the longer *encoded* form in
    /// the source, so the emitted span must use this length, not the decoded
    /// one. `None` means the span length is `value.len()` (the common case).
    /// Serialized (omitted when absent) so a cached evidence item yields the
    /// same compact `spans` length on a cache hit as on a fresh analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_len: Option<u64>,
    /// Secondary value the matcher may try as a fallback. Currently
    /// only populated by the AST cache for `call`-kind nodes, where
    /// `value` is the full call expression text (`name(args)`) and
    /// `alt_value` is the extracted call name (`name`). The matcher
    /// tries `value` first, then `alt_value`, so a single AST node
    /// produces at most one match regardless of which form the trait
    /// pattern targets. Skipped in serialization — it's an internal
    /// matching helper, not part of the observable Evidence surface.
    #[serde(skip)]
    pub alt_value: Option<String>,
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
            match_len: None,
            alt_value: None,
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
        if self.offsets.is_empty()
            && let Some(offset) = self.parse_offset_from_location()
        {
            self.offsets.push(offset);
        }

        // Try to extract offset from other.location if it looks like a hex offset
        if let Some(offset) = other.parse_offset_from_location() {
            self.offsets.push(offset);
        }

        // Merge other's offsets
        self.offsets.extend(other.offsets);
    }

    /// Best byte offset for this evidence: the first concrete offset if the
    /// matcher recorded one, else an offset parsed from the location string.
    /// Used by the context-capture pass to anchor a content window.
    #[must_use]
    pub(crate) fn byte_offset(&self) -> Option<u64> {
        self.offsets
            .first()
            .copied()
            .or_else(|| self.parse_offset_from_location())
    }

    /// Re-anchor this evidence's byte offset into `offsets` before its
    /// `location` string is repurposed as a semantic label (e.g. `embedded@…`,
    /// `decoded:…`, `extracted:…`).
    ///
    /// Content matchers (string/text/string_literal/symbol) record where they
    /// matched in `location` as a parseable `0x…` string and leave `offsets`
    /// empty. A later relabel overwrites that string, which would strand the
    /// offset: [`byte_offset`](Self::byte_offset) then returns `None` and the
    /// context-capture pass logs the match as anchor-less. Lifting the offset
    /// into `offsets` first makes it survive the relabel.
    ///
    /// `shift` is added to each offset: pass `0` when the evidence stays local
    /// to its own (sub-)buffer, or the parent byte offset when re-anchoring a
    /// snippet's matches into the parent's byte space. Call this *before*
    /// overwriting `location`.
    pub(crate) fn reanchor_offset(&mut self, shift: u64) {
        if self.offsets.is_empty() {
            if let Some(local) = self.byte_offset() {
                self.offsets.push(local.saturating_add(shift));
            }
        } else if shift != 0 {
            for off in &mut self.offsets {
                *off = off.saturating_add(shift);
            }
        }
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
    if evidence.len() <= 1 {
        return evidence;
    }

    // Group by (method, source, value). FxHashMap (not SipHash) for the hot
    // post-eval dedup; output order follows iteration order, which isn't
    // guaranteed either way.
    use std::collections::hash_map::Entry;
    let mut groups: rustc_hash::FxHashMap<(String, String, String), Evidence> =
        rustc_hash::FxHashMap::default();

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
#[allow(clippy::expect_used)]
mod tests {

    /// Fold-time bounding must be idempotent with serialization: the bounded
    /// form re-bounds to itself, so a member bounded at fold serializes
    /// byte-identically to one bounded only on the wire.
    #[test]
    fn bound_evidence_value_is_idempotent() {
        let long = "x".repeat(MAX_EVIDENCE_VALUE_SIZE * 2);
        let bounded = bound_evidence_value(&long).expect("over-cap value is bounded");
        assert!(bounded.len() <= MAX_EVIDENCE_VALUE_SIZE);
        assert!(bounded.ends_with("...[truncated]"));
        assert_eq!(
            bound_evidence_value(&bounded),
            None,
            "already-bounded value passes through untouched"
        );

        assert_eq!(bound_evidence_value("short"), None);
        assert_eq!(
            bound_evidence_value("nul\0led").as_deref(),
            Some("nulled"),
            "sanitization applies below the cap too"
        );
    }
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

    // ==================== reanchor_offset Tests ====================

    /// A content match that stored its offset only in `location` (the common
    /// case for string/text/string_literal matchers) must keep that offset when
    /// the location is later relabeled — otherwise `byte_offset` returns `None`
    /// and the context pass reports it as anchor-less.
    #[test]
    fn reanchor_lifts_location_only_offset_into_offsets() {
        let mut ev = Evidence {
            method: "string_literal".to_string(),
            location: Some("0x1a".to_string()),
            ..Default::default()
        };
        ev.reanchor_offset(0x100);
        assert_eq!(ev.offsets, vec![0x11a]);
        // Relabeling the location no longer strands the offset.
        ev.location = Some("embedded@0x100:0x1a".to_string());
        assert_eq!(ev.byte_offset(), Some(0x11a));
    }

    /// With a zero shift (evidence rendered against its own sub-buffer) the
    /// location offset is preserved verbatim.
    #[test]
    fn reanchor_zero_shift_preserves_local_offset() {
        let mut ev = Evidence {
            method: "text".to_string(),
            location: Some("0x40".to_string()),
            ..Default::default()
        };
        ev.reanchor_offset(0);
        assert_eq!(ev.offsets, vec![0x40]);
    }

    /// Existing concrete offsets are shifted (not duplicated) into the parent's
    /// byte space.
    #[test]
    fn reanchor_shifts_existing_offsets() {
        let mut ev = Evidence {
            method: "raw".to_string(),
            offsets: vec![0x10, 0x20],
            location: Some("0x10".to_string()),
            ..Default::default()
        };
        ev.reanchor_offset(0x1000);
        assert_eq!(ev.offsets, vec![0x1010, 0x1020]);
    }

    /// Evidence with neither offsets nor a parseable location gains nothing —
    /// genuinely position-less facts stay position-less.
    #[test]
    fn reanchor_noop_without_any_offset() {
        let mut ev = Evidence {
            method: "string".to_string(),
            location: Some("import".to_string()),
            ..Default::default()
        };
        ev.reanchor_offset(0x100);
        assert!(ev.offsets.is_empty());
        assert_eq!(ev.byte_offset(), None);
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
        let f =
            Finding::capability("test".to_string(), "desc".to_string(), 0.9).with_mbc("B0015.001");

        assert_eq!(f.mbc, Some(crate::types::Istr::from("B0015.001")));
    }

    #[test]
    fn test_finding_with_attack() {
        let f = Finding::capability("test".to_string(), "desc".to_string(), 0.9)
            .with_attack("T1059.001");

        assert_eq!(f.attack, Some(crate::types::Istr::from("T1059.001")));
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
            .with_mbc("C0002")
            .with_attack("T1071.001");

        assert_eq!(f.id, "net/http");
        assert_eq!(f.crit, Criticality::Suspicious);
        assert_eq!(f.mbc, Some(crate::types::Istr::from("C0002")));
        assert_eq!(f.attack, Some(crate::types::Istr::from("T1071.001")));
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
