//! Type definitions for the lenient PDF byte-scan extractor.
//!
//! These types describe what the extractor recovers from raw PDF
//! bytes — *not* a complete PDF model. We intentionally avoid
//! resolving cross-reference tables, decrypting encrypted streams,
//! or reconstructing the linearized object graph; malicious PDFs
//! routinely break those features to evade strict parsers.

use std::collections::BTreeMap;

/// Result of a single PDF lenient parse pass.
#[derive(Debug, Clone, Default)]
pub(crate) struct PdfDocument {
    /// Every `%PDF-1.x` header in the file. Multiple = stacked
    /// PDFs (a known evasion technique).
    pub headers: Vec<PdfHeader>,
    /// Recovered objects keyed by `<id> <gen>`. Each carries its
    /// top-level dictionary keys and (if present) stream metadata.
    pub objects: Vec<PdfObject>,
    /// Number of `%%EOF` markers; > 1 means incremental updates.
    pub eof_count: u32,
    /// File-level structural flags surfaced for kv/metrics traits.
    pub structural: PdfStructural,
    /// Action records (OpenAction, /JS, /Launch, /URI, /SubmitForm)
    /// extracted from object dicts and the catalog.
    pub actions: Vec<PdfAction>,
    /// Embedded file records (filename + size) discovered via
    /// /Type /Filespec or /EmbeddedFiles name tree.
    pub embedded_files: Vec<PdfEmbeddedFile>,
    /// Decoded stream summaries. Payloads stay capped; this exists so traits
    /// can reason about Flate/ASCII-decoded JavaScript and embedded content.
    pub streams: Vec<PdfStreamRecord>,
    /// AcroForm/widget field records with direct values recovered from
    /// field dictionaries.
    pub form_fields: Vec<PdfFormField>,
    /// Document-info dict values (Author, Title, Producer, etc.)
    /// — string values only. Numeric fields don't appear in
    /// /Info per spec.
    pub info: BTreeMap<String, String>,
}

/// PDF header (`%PDF-1.x`).
#[derive(Debug, Clone)]
pub(crate) struct PdfHeader {
    /// Version string after the dash (e.g. `"1.7"`, `"2.0"`).
    pub version: String,
}

/// One indirect object as recovered between an `obj` and `endobj` token.
#[derive(Debug, Clone)]
pub(crate) struct PdfObject {
    pub id: u32,
    /// Top-level dict keys → raw value bytes (verbatim text, not
    /// re-parsed). Trait authors that need finer-grained values can
    /// extract via regex on the `value`.
    pub dict: BTreeMap<String, String>,
    /// Raw top-level dict values keyed by name. Used for PDF string
    /// decoding where lossy UTF-8 conversion would destroy UTF-16 BOMs.
    pub dict_raw: BTreeMap<String, Vec<u8>>,
    /// Direct non-dictionary object value, capped by the parser. This lets
    /// `/JS 12 0 R` resolve when object 12 is a literal string inside ObjStm.
    pub raw_value: String,
    /// Filter names in `/Filter` order. A multi-element list means
    /// chained decompression (e.g. `[FlateDecode ASCIIHexDecode]`).
    pub stream_filters: Vec<String>,
    /// Raw stream bytes between `stream\n` and `\nendstream` (best
    /// effort — capped at `MAX_STREAM_BYTES`). Empty when no stream
    /// or when the stream wasn't recoverable.
    pub stream_bytes: Vec<u8>,
    /// Stream-level parser anomalies recovered while locating the stream.
    pub stream_anomalies: PdfStreamAnomalies,
}

/// Malformed stream facts inspired by parser-recovery behavior in
/// intentionally malformed PDFs.
#[derive(Debug, Clone, Default)]
pub(crate) struct PdfStreamAnomalies {
    pub has_stream: bool,
    pub declared_length: Option<u64>,
    pub observed_length: Option<u64>,
    pub missing_length: bool,
    pub invalid_length: bool,
    pub length_mismatch: bool,
    pub bad_delimiter: bool,
    pub missing_endstream: bool,
}

/// Structural / vulnerability-relevant flags.
#[derive(Debug, Clone, Default)]
pub(crate) struct PdfStructural {
    pub encrypted: bool,
    pub linearized: bool,
    /// `/AcroForm` present in catalog.
    pub has_acroform: bool,
    /// `/AcroForm /XFA` present (legacy XFA forms — historic JS surface).
    pub has_xfa: bool,
    /// `/Type /Catalog /OpenAction` present.
    pub has_openaction: bool,
    /// `/Type /Catalog /AA` present (additional actions).
    pub has_additional_actions: bool,
    /// `/Names` contains a `/JavaScript` name tree.
    pub has_names_javascript: bool,
    /// `/RichMedia` appears in an object dictionary.
    pub has_richmedia: bool,
    /// `/Type /3D` annotations present.
    pub has_3d: bool,
    /// `/JBIG2Decode` filter referenced anywhere (CVE-2010-1297 family).
    pub jbig2_filter_count: u32,
    /// `/Type /3D` annotations present (CVE-2009-1493 family).
    pub three_d_object_count: u32,
    pub visible_object_count: u32,
    pub object_stream_inner_object_count: u32,
    pub page_count: u32,
    pub annotation_count: u32,
    pub xobject_count: u32,
    pub font_count: u32,
    pub metadata_count: u32,
    pub objstm_count: u32,
    pub xref_stream_count: u32,
    pub unreferenced_object_count: u32,
    pub trailing_bytes_after_eof: u64,
    pub leading_bytes_before_header: u64,
    pub trailer_count: u32,
    pub startxref_count: u32,
    pub stream_count: u32,
    pub stream_missing_length_count: u32,
    pub stream_invalid_length_count: u32,
    pub stream_length_mismatch_count: u32,
    pub stream_bad_delimiter_count: u32,
    pub stream_missing_endstream_count: u32,
    pub streams_with_unusual_filter_count: u32,
    pub signature_object_count: u32,
    pub byte_range_count: u32,
}

/// Trailer dictionary.
#[derive(Debug, Clone, Default)]
pub(crate) struct PdfTrailer {
    /// Top-level trailer keys. `/Root` and `/Info` carry indirect refs;
    /// raw text is preserved so callers can decode references.
    pub dict: BTreeMap<String, String>,
}

/// One action discovered while walking objects/catalog dicts.
#[derive(Debug, Clone)]
pub(crate) struct PdfAction {
    pub kind: PdfActionKind,
    /// Where the action was attached: `"openaction"`, `"named:<name>"`,
    /// `"annotation"`, `"acroform_field"`, or `"object:<id>"`.
    pub source: String,
    /// First ~200 chars of the JavaScript / target / URI value, for
    /// kv-tree surfacing. Long values truncated.
    pub snippet: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PdfActionKind {
    JavaScript,
    Launch,
    Uri,
    SubmitForm,
    Named,
    GoToR,
    GoToE,
    Movie,
    Sound,
    Rendition,
    ImportData,
}

impl PdfActionKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::Launch => "launch",
            Self::Uri => "uri",
            Self::SubmitForm => "submitform",
            Self::Named => "named",
            Self::GoToR => "gotor",
            Self::GoToE => "gotoe",
            Self::Movie => "movie",
            Self::Sound => "sound",
            Self::Rendition => "rendition",
            Self::ImportData => "importdata",
        }
    }
}

/// Embedded file record.
#[derive(Debug, Clone)]
pub(crate) struct PdfEmbeddedFile {
    pub filename: String,
    pub size: u64,
}

/// Decoded stream metadata exposed through PDF kv.
#[derive(Debug, Clone)]
pub(crate) struct PdfStreamRecord {
    pub object_id: u32,
    pub filters: Vec<String>,
    pub magic_hex: String,
    pub decoded_text: String,
}

/// Recovered PDF form field.
#[derive(Debug, Clone)]
pub(crate) struct PdfFormField {
    pub name: String,
    pub field_type: String,
    pub rect: String,
    pub value_length: u32,
    pub decoded_value_length: u32,
    pub decoded_value: String,
    pub decoded_value_snippet: String,
}
