//! PNG image metrics for steganography detection
//!
//! # Steganography Indicators
//!
//! Images hiding data typically exhibit:
//!
//! - **High pixel entropy**: Random-looking pixel values (near 8.0 bits)
//!   - Normal images: 4.0-6.5 bits
//!   - Compressed images: 6.0-7.0 bits
//!   - Steganographic: 7.5-8.0 bits
//!
//! - **Flat color histogram**: Uniform distribution across color values
//!   - Normal images: Peaked around common colors
//!   - Steganographic: Nearly uniform (flatness > 0.9)
//!
//! - **No visual structure**: Lack of edges and gradients
//!   - Normal images: Edge density 0.1-0.4
//!   - Noise images: Edge density < 0.05

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_zero_f32, is_zero_u32};

/// Metrics extracted from PNG images for steganography detection
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PngMetrics {
    // === Image dimensions ===
    /// Image width in pixels
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub width: u32,
    /// Image height in pixels
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub height: u32,
    /// Bits per channel (typically 8 or 16)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bit_depth: u32,
    /// Number of color channels (1=grayscale, 3=RGB, 4=RGBA)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub channels: u32,

    // === Steganography indicators ===
    /// Shannon entropy of raw pixel data (0-8 bits)
    /// Higher values indicate more random/encrypted content
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub pixel_entropy: f32,

    /// Histogram flatness (0.0 = peaked, 1.0 = perfectly uniform)
    /// High values indicate uniform random distribution (suspicious)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub histogram_flatness: f32,

    /// Edge density (0.0 = no edges, 1.0 = all edges)
    /// Low values indicate lack of visual structure
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub edge_density: f32,

    /// Compression ratio (compressed_size / raw_pixel_size)
    /// Random data doesn't compress well (ratio close to 1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub compression_ratio: f32,

    // === Per-channel entropy ===
    /// Red channel entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub r_entropy: f32,
    /// Green channel entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub g_entropy: f32,
    /// Blue channel entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub b_entropy: f32,
    /// Alpha channel entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub a_entropy: f32,
}
