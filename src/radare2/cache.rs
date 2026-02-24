//! Caching for radare2/rizin analysis results.
//!
//! This module provides caching functionality to avoid re-analyzing the same binaries.
//! Analysis results are stored as zstd-compressed JSON files, keyed by file SHA256.
//!
//! # Cache Location
//! Cache files are stored in `~/.cache/cleave/re/` by default.
//!
//! # Cache Format
//! - Files are named by their SHA256 hash
//! - Content is JSON serialized `BatchedAnalysis` compressed with zstd
//! - Compression level 3 provides good balance of size and speed

use super::BatchedAnalysis;
use crate::cache::re_cache_path;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::Path;

use super::Radare2Analyzer;

impl Radare2Analyzer {
    pub(super) fn compute_file_sha256(file_path: &Path) -> Option<String> {
        let mut file = File::open(file_path).ok()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = file.read(&mut buffer).ok()?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        Some(format!("{:x}", hasher.finalize()))
    }

    /// Load cached BatchedAnalysis from disk (zstd compressed)
    pub(super) fn load_from_cache(sha256: &str) -> Option<BatchedAnalysis> {
        let cache_path = re_cache_path(sha256).ok()?;
        if !cache_path.exists() {
            return None;
        }

        let compressed = fs::read(&cache_path).ok()?;
        let decompressed = zstd::decode_all(compressed.as_slice()).ok()?;
        bincode::serde::decode_from_slice(&decompressed, bincode::config::standard())
            .map(|(v, _)| v)
            .ok()
    }

    /// Save BatchedAnalysis to disk cache (zstd compressed)
    pub(super) fn save_to_cache(sha256: &str, analysis: &BatchedAnalysis) {
        if let Ok(cache_path) = re_cache_path(sha256) {
            // Serialize with bincode, then compress with zstd
            if let Ok(serialized) =
                bincode::serde::encode_to_vec(analysis, bincode::config::standard())
            {
                // Use compression level 3 (good balance of speed and ratio)
                if let Ok(compressed) = zstd::encode_all(&serialized[..], 3) {
                    // Write atomically: temp file then rename
                    let temp_path = cache_path.with_extension("tmp");
                    if let Ok(mut file) = File::create(&temp_path) {
                        if file.write_all(&compressed).is_ok() {
                            let _ = fs::rename(&temp_path, &cache_path);
                        } else {
                            let _ = fs::remove_file(&temp_path);
                        }
                    }
                }
            }
        }
    }
}
