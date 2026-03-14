//! JPEG image metrics for steganography detection
//!
//! # Steganography Indicators
//!
//! JPEG images are commonly used to hide data via:
//!
//! - **Appended data after EOI**: Bytes after the FF D9 end-of-image marker
//!   are invisible to decoders but trivially extracted by attackers
//!
//! - **LSB steganography in DCT coefficients**: Tools like JSteg, OutGuess,
//!   and F5 embed data in the least-significant bits of DCT coefficients
//!   — detectable as high pixel entropy after decoding
//!
//! - **COM marker abuse**: The JFIF comment marker (FF FE) can carry
//!   arbitrary binary data; unusually large comments are suspicious
//!
//! - **EXIF payload injection**: APP1 (FF E1) carries EXIF metadata and is
//!   sometimes abused to embed executable content

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_zero_f32, is_zero_u32, is_zero_u64};

/// Metrics extracted from JPEG images for steganography detection
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct JpegMetrics {
    // === Image dimensions ===
    /// Image width in pixels
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub width: u32,
    /// Image height in pixels
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub height: u32,
    /// Number of color channels (1=grayscale, 3=YCbCr/RGB, 4=CMYK)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub channels: u32,

    // === Steganography indicators ===
    /// Shannon entropy of decoded pixel data (0-8 bits)
    /// Higher values indicate more random content — possible LSB steganography
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub pixel_entropy: f32,

    /// Histogram flatness of decoded pixels (0.0 = peaked, 1.0 = perfectly uniform)
    /// High values indicate uniform random distribution (suspicious)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub histogram_flatness: f32,

    /// Edge density of decoded image (0.0 = no edges, 1.0 = all edges)
    /// Unexpectedly low values can indicate lack of visual structure
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub edge_density: f32,

    // === JPEG-specific indicators ===
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
}
