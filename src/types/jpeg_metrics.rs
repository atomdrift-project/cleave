//! JPEG-specific image metrics
//!
//! Shared metrics (pixel entropy, histogram flatness, edge density, per-channel entropy)
//! are in `ImageMetrics`. This struct holds JPEG-only fields.

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_zero_u32, is_zero_u64};

/// JPEG-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct JpegMetrics {
    /// Bytes appended after the JPEG EOI marker (FF D9)
    /// Any non-zero value means data is hidden after the image
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub appended_bytes: u64,
    /// Total bytes in JFIF COM (comment) markers
    /// Large comment fields are sometimes used to hide binary payloads
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub comment_bytes: u64,
    /// Total bytes in APP1 (EXIF) markers
    /// Unusually large EXIF blocks can conceal embedded data
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub exif_size: u64,
    /// Total marker segments walked (excluding entropy-coded scan).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub segment_count: u32,
    /// Number of APP0..APP15 segments. High counts hint at unusual
    /// metadata layering (e.g. Photoshop multi-section blobs).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub app_segment_count: u32,
    /// Number of COM (comment) markers. Multiple COMs in one JPEG
    /// is unusual and a classic stego carrier.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub com_count: u32,
    /// Number of DQT (quantization table) markers — useful baseline
    /// for tools like jsteg that mutate them.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dqt_count: u32,
    /// Number of DHT (Huffman table) markers.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dht_count: u32,
    /// Number of SOI (start of image) markers seen. Legitimate JPEGs
    /// have exactly 1; >1 means concatenated images.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub soi_count: u32,
    /// Bytes occupied by EXIF MakerNote tags. Vendor-opaque blobs
    /// ranging up to a few KB on real cameras; values much larger
    /// or much different from a known camera baseline can hide data.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub maker_note_bytes: u32,
}
