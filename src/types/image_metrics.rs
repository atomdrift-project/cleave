//! Shared image metrics for steganography detection
//!
//! Common metrics computed from decoded pixel data, shared across PNG and JPEG analyzers.
//! Format-specific metrics remain in `PngMetrics` and `JpegMetrics`.

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_zero_f32, is_zero_u32};

/// Shared metrics extracted from decoded image pixel data
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ImageMetrics {
    // === Image dimensions ===
    /// Image width measured in pixels
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub width: u32,
    /// Image height measured in pixels
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub height: u32,
    /// Number of color channels (1=grayscale, 3=RGB, 4=RGBA)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub channels: u32,

    // === Steganography indicators ===
    /// Shannon entropy of raw pixel data (0-8 bits)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub pixel_entropy: f32,
    /// Histogram flatness (0.0 = peaked, 1.0 = perfectly uniform)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub histogram_flatness: f32,
    /// Edge density (0.0 = no edges, 1.0 = all edges)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub edge_density: f32,

    // === Per-channel entropy ===
    /// Shannon entropy of the red image channel
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub r_entropy: f32,
    /// Shannon entropy of the green image channel
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub g_entropy: f32,
    /// Shannon entropy of the blue image channel
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub b_entropy: f32,
}
