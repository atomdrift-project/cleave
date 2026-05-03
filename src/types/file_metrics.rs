//! Universal file-level metrics — measurements that apply to every file
//! type, regardless of whether it's text, binary, or container.
//!
//! Other `*_metrics.rs` modules cover format-specific signals; this one is
//! the floor everyone shares. Currently just file size; future fields could
//! include analyzer time, decompressed size, magic-byte confidence, etc.
use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::is_zero_u64;

/// Universal file-level metrics. Always populated by the analysis pipeline
/// regardless of file type, so consumers (the diff command in particular)
/// can rely on `file.size` being present for every analyzed file.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct FileMetrics {
    /// File size in bytes.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub size: u64,
}
