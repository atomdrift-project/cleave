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
}
