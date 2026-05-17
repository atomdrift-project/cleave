//! PDF-specific derived metrics.
//!
//! Raw PDF records and direct metadata stay in the PDF kv tree. Counts,
//! ratios, and parser coverage measurements live here so traits can use
//! `type: metrics, field: pdf.*` with numeric thresholds.

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_zero_f32, is_zero_u32, is_zero_u64};

/// Derived metrics for PDF structure and parser coverage.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PdfMetrics {
    /// Top-level indirect objects recovered from raw file bytes.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub visible_object_count: u32,
    /// Total objects recovered, including `/ObjStm` members.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub object_count: u32,
    /// Objects recovered from decoded object streams.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub object_stream_inner_object_count: u32,
    /// `/Type /Page` object count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub page_count: u32,
    /// `/Type /Annot` object count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub annotation_count: u32,
    /// `/Type /XObject` object count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xobject_count: u32,
    /// `/Type /Font` object count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub font_count: u32,
    /// `/Type /Metadata` object count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub metadata_count: u32,
    /// `/Type /ObjStm` stream count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub objstm_count: u32,
    /// `/Type /XRef` stream count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xref_stream_count: u32,
    /// Recovered objects with no inbound PDF references.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unreferenced_object_count: u32,
    /// Bytes after the last `%%EOF` marker.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub trailing_bytes_after_eof: u64,
    /// Bytes before the first `%PDF-` header.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub leading_bytes_before_header: u64,
    /// Number of `trailer` dictionaries observed.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trailer_count: u32,
    /// Number of `startxref` markers observed.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub startxref_count: u32,
    /// Objects containing a `stream` keyword.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_count: u32,
    /// Streams without a `/Length` entry.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_missing_length_count: u32,
    /// Streams with a direct `/Length` value that is not numeric.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_invalid_length_count: u32,
    /// Streams whose direct `/Length` disagrees with observed bytes.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_length_mismatch_count: u32,
    /// Streams whose `stream` keyword is not followed by an EOL.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_bad_delimiter_count: u32,
    /// Streams missing a matching `endstream` marker.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_missing_endstream_count: u32,
    /// Streams using JBIG2, LZW, or Crypt filters.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub streams_with_unusual_filter_count: u32,
    /// Objects declaring a signature or signature form field
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub signature_object_count: u32,
    /// `/ByteRange` entries observed in the raw PDF.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub byte_range_count: u32,
    /// Incremental updates in a signed PDF (`%%EOF`-1)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub signed_incremental_update_count: u32,
    /// Streams using `/JBIG2Decode`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub jbig2_filter_count: u32,
    /// Number of `/Type /3D` objects.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub three_d_object_count: u32,
    /// Embedded files recovered by the PDF parser.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_file_count: u32,
    /// Form fields recovered by the PDF parser.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub form_field_count: u32,
    /// Form fields with a zero-area rectangle.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hidden_zero_rect_field_count: u32,
    /// Non-signature form fields with repeated `/T` name
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub duplicate_form_name_count: u32,
    /// Non-signature form fields with repeated rectangle
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub duplicate_form_rect_count: u32,
    /// Non-signature fields repeating name and rectangle
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub duplicate_form_name_rect_count: u32,
    /// Pairs of non-signature fields with overlapping rects
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub overlapping_form_field_pair_count: u32,
    /// Largest decoded form-field value length.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub decoded_form_value_max_len: u32,
    /// Action records recovered by the PDF parser.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub action_count: u32,
    /// URI action records recovered by the PDF parser.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub uri_action_count: u32,
    /// JavaScript action records recovered by the PDF parser.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub javascript_action_count: u32,
    /// Weighted pdfid-style risky feature score, clamped to 0..100.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub risky_feature_score: u32,
    /// `annotation_count / page_count`.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub annotations_per_page: f32,
    /// `uri_action_count / page_count`.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub uri_actions_per_page: f32,
}
