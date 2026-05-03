//! PNG-specific image metrics
//!
//! Shared metrics (pixel entropy, histogram flatness, edge density, per-channel entropy)
//! are in `ImageMetrics`. This struct holds PNG-only fields.

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_zero_f32, is_zero_u32};

/// PNG-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PngMetrics {
    /// Bits per channel (typically 8 or 16)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bit_depth: u32,
    /// Compression ratio (compressed_size / raw_pixel_size)
    /// Random data doesn't compress well (ratio close to 1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub compression_ratio: f32,
    /// Alpha channel entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub a_entropy: f32,
    /// Total chunk count walked from the chunk-table.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chunks_total: u32,
    /// Number of `IDAT` chunks (multi-IDAT is normal but spike-y
    /// counts vs file size can hint at chunked stego payloads).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chunks_idat: u32,
    /// Chunks present after the `IEND` end-of-image marker. Almost
    /// always zero for legitimate PNGs; nonzero values are a strong
    /// stego / appended-payload signal.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chunks_after_iend: u32,
    /// Raw bytes appended after the last chunk's CRC. Same signal
    /// class as `chunks_after_iend` but for un-framed payloads (the
    /// most common image-as-payload technique).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trailing_bytes: u32,
    /// Total bytes occupied by `tEXt` / `zTXt` / `iTXt` chunks
    /// (excluding chunk headers/CRC). High values relative to image
    /// size indicate text-payload stego.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub text_chunks_total_bytes: u32,
    /// Count of unrecognized 4-letter chunk codes (anything outside
    /// PNG 1.2 + APNG + eXIf). Custom chunk types are rare and a
    /// classic stego carrier.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unknown_chunks_count: u32,
}
