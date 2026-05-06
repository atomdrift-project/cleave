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
    /// Ratio of compressed size to raw pixel data size
    ///
    /// Random data doesn't compress well (ratio close to 1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub compression_ratio: f32,
    /// Shannon entropy of the alpha image channel
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub a_entropy: f32,
    /// Total chunk count walked from the chunk-table.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chunks_total: u32,
    /// Number of IDAT image data chunks
    ///
    /// Multi-IDAT is normal but spike-y counts vs file size can hint at chunked stego
    /// payloads.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chunks_idat: u32,
    /// Chunks present after the IEND end-of-image marker
    ///
    /// Almost always zero for legitimate PNGs; nonzero values are a strong stego /
    /// appended-payload signal.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chunks_after_iend: u32,
    /// Raw bytes appended after the last chunk CRC
    ///
    /// Same signal class as `chunks_after_iend` but for un-framed payloads (the most
    /// common image-as-payload technique).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trailing_bytes: u32,
    /// Total bytes in tEXt, zTXt, and iTXt chunks
    ///
    /// (excluding chunk headers/CRC). High values relative to image size indicate
    /// text-payload stego.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub text_chunks_total_bytes: u32,
    /// Count of unrecognized non-standard chunk types
    ///
    /// Anything outside PNG 1.2 + APNG + eXIf. Custom chunk types are rare and a classic
    /// stego carrier.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unknown_chunks_count: u32,
}
