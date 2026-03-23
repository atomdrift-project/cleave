//! JPEG-specific image metrics
//!
//! Shared metrics (pixel entropy, histogram flatness, edge density, per-channel entropy)
//! are in `ImageMetrics`. This struct holds JPEG-only fields.

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::is_zero_u64;

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
}
