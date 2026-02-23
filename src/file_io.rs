//! Efficient file I/O utilities with memory optimization.
//!
//! Provides smart file reading that uses memory-mapping for large files
//! to reduce memory usage and improve performance.
//!
//! Automatically detects and converts UTF-16 LE/BE files to UTF-8 for
//! consistent text processing across all analysis modules.
//!
//! Note: Uses unwrap for internal slice operations where bounds are verified.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use encoding_rs::{UTF_16BE, UTF_16LE};
use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

/// Threshold for using memory-mapping instead of loading into memory.
/// Files larger than this will be memory-mapped (zero-copy).
const MMAP_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MB

/// File data that can be either memory-mapped or owned.
#[derive(Debug)]
pub enum FileData {
    /// Memory-mapped file (zero-copy, for large files)
    Mapped(Mmap),
    /// Owned data (for small files)
    Owned(Vec<u8>),
}

impl FileData {
    /// Get the data as a byte slice
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            FileData::Mapped(mmap) => mmap,
            FileData::Owned(vec) => vec,
        }
    }

    /// Get the length of the data
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Check if the data is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsRef<[u8]> for FileData {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Detect if data is UTF-16 encoded and convert to UTF-8 if needed.
///
/// Detects UTF-16 LE/BE by BOM (FF FE or FE FF) and converts to UTF-8.
/// Returns the original data if no UTF-16 BOM is detected.
///
/// # Arguments
///
/// * `data` - Raw file data that may be UTF-16 encoded
///
/// # Returns
///
/// UTF-8 encoded data (either converted or original if already UTF-8)
fn normalize_text_encoding(data: &[u8]) -> Vec<u8> {
    // Check for UTF-16 LE BOM (FF FE)
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        tracing::debug!("Detected UTF-16 LE encoding, converting to UTF-8");

        // Decode UTF-16 LE (skip BOM)
        let (decoded, _encoding, had_errors) = UTF_16LE.decode(&data[2..]);

        if had_errors {
            tracing::warn!("UTF-16 LE decoding had some errors, using lossy conversion");
        }

        return decoded.into_owned().into_bytes();
    }

    // Check for UTF-16 BE BOM (FE FF)
    if data.len() >= 2 && data[0] == 0xFE && data[1] == 0xFF {
        tracing::debug!("Detected UTF-16 BE encoding, converting to UTF-8");

        // Decode UTF-16 BE (skip BOM)
        let (decoded, _encoding, had_errors) = UTF_16BE.decode(&data[2..]);

        if had_errors {
            tracing::warn!("UTF-16 BE decoding had some errors, using lossy conversion");
        }

        return decoded.into_owned().into_bytes();
    }

    // No UTF-16 BOM detected, return original data
    data.to_vec()
}

/// Read a file efficiently, using memory-mapping for large files.
///
/// For files larger than 10MB, this uses memory-mapping (zero-copy).
/// For smaller files, it reads into memory for better cache locality.
///
/// **Note**: This function does NOT normalize text encoding. Use
/// `read_file_normalized()` if you need UTF-16 to UTF-8 conversion.
///
/// # Arguments
///
/// * `path` - Path to the file to read
///
/// # Returns
///
/// A `FileData` that can be used as a byte slice
pub fn read_file_smart(path: &Path) -> Result<FileData> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();

    if file_size > MMAP_THRESHOLD {
        // Large file: use memory-mapping (zero-copy)
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        tracing::debug!(
            "Memory-mapped large file ({:.2} MB): {}",
            file_size as f64 / 1024.0 / 1024.0,
            path.display()
        );
        Ok(FileData::Mapped(mmap))
    } else {
        // Small file: read into memory for better cache locality
        let data = std::fs::read(path)?;
        Ok(FileData::Owned(data))
    }
}

/// Read a file with automatic UTF-16 to UTF-8 conversion.
///
/// This function detects UTF-16 LE/BE encoded files (by BOM) and converts
/// them to UTF-8 for consistent text processing. Files without UTF-16 BOMs
/// are returned as-is.
///
/// Use this for text files where encoding normalization is important
/// (source code analysis, string extraction, AST parsing, etc.).
///
/// # Arguments
///
/// * `path` - Path to the file to read
///
/// # Returns
///
/// UTF-8 normalized file data
pub fn read_file_normalized(path: &Path) -> Result<FileData> {
    let raw_data = read_file_smart(path)?;
    let raw_bytes = raw_data.as_slice();

    // Check if encoding normalization is needed
    if raw_bytes.len() >= 2
        && ((raw_bytes[0] == 0xFF && raw_bytes[1] == 0xFE)  // UTF-16 LE
            || (raw_bytes[0] == 0xFE && raw_bytes[1] == 0xFF))
    // UTF-16 BE
    {
        let normalized = normalize_text_encoding(raw_bytes);
        Ok(FileData::Owned(normalized))
    } else {
        // No conversion needed, return original data
        Ok(raw_data)
    }
}

/// Read a file into an owned Vec<u8>.
///
/// This is a convenience wrapper that always returns owned data.
/// Use `read_file_smart` if you want automatic memory-mapping for large files.
pub fn read_file_to_vec(path: &Path) -> Result<Vec<u8>> {
    Ok(std::fs::read(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_small_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test data").unwrap();
        temp_file.flush().unwrap();

        let data = read_file_smart(temp_file.path()).unwrap();
        assert_eq!(data.as_slice(), b"test data");
        assert_eq!(data.len(), 9);
        assert!(!data.is_empty());

        // Small file should be owned
        assert!(matches!(data, FileData::Owned(_)));
    }

    #[test]
    fn test_read_large_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let large_data = vec![0u8; 20 * 1024 * 1024]; // 20 MB
        temp_file.write_all(&large_data).unwrap();
        temp_file.flush().unwrap();

        let data = read_file_smart(temp_file.path()).unwrap();
        assert_eq!(data.len(), 20 * 1024 * 1024);

        // Large file should be memory-mapped
        assert!(matches!(data, FileData::Mapped(_)));
    }

    #[test]
    fn test_as_ref_trait() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test").unwrap();
        temp_file.flush().unwrap();

        let data = read_file_smart(temp_file.path()).unwrap();
        let slice: &[u8] = data.as_ref();
        assert_eq!(slice, b"test");
    }

    #[test]
    fn test_utf16le_detection_and_conversion() {
        // Create UTF-16 LE file with BOM
        let mut temp_file = NamedTempFile::new().unwrap();

        // UTF-16 LE BOM (FF FE) + "hello" in UTF-16 LE
        let utf16le_data: Vec<u8> = vec![
            0xFF, 0xFE, // BOM
            0x68, 0x00, // h
            0x65, 0x00, // e
            0x6C, 0x00, // l
            0x6C, 0x00, // l
            0x6F, 0x00, // o
        ];
        temp_file.write_all(&utf16le_data).unwrap();
        temp_file.flush().unwrap();

        let data = read_file_normalized(temp_file.path()).unwrap();
        let text = String::from_utf8(data.as_slice().to_vec()).unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn test_utf16be_detection_and_conversion() {
        // Create UTF-16 BE file with BOM
        let mut temp_file = NamedTempFile::new().unwrap();

        // UTF-16 BE BOM (FE FF) + "hello" in UTF-16 BE
        let utf16be_data: Vec<u8> = vec![
            0xFE, 0xFF, // BOM
            0x00, 0x68, // h
            0x00, 0x65, // e
            0x00, 0x6C, // l
            0x00, 0x6C, // l
            0x00, 0x6F, // o
        ];
        temp_file.write_all(&utf16be_data).unwrap();
        temp_file.flush().unwrap();

        let data = read_file_normalized(temp_file.path()).unwrap();
        let text = String::from_utf8(data.as_slice().to_vec()).unwrap();
        assert_eq!(text, "hello");
    }

    #[test]
    fn test_utf8_passthrough() {
        // Regular UTF-8 file should pass through unchanged
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"regular utf-8 text").unwrap();
        temp_file.flush().unwrap();

        let data = read_file_normalized(temp_file.path()).unwrap();
        assert_eq!(data.as_slice(), b"regular utf-8 text");
    }

    #[test]
    fn test_normalize_encoding_utf16le() {
        let utf16le_data: Vec<u8> = vec![
            0xFF, 0xFE, // BOM
            0x74, 0x00, // t
            0x65, 0x00, // e
            0x73, 0x00, // s
            0x74, 0x00, // t
        ];

        let result = normalize_text_encoding(&utf16le_data);
        assert_eq!(result, b"test");
    }

    #[test]
    fn test_normalize_encoding_no_bom() {
        let utf8_data = b"plain text";
        let result = normalize_text_encoding(utf8_data);
        assert_eq!(result, utf8_data);
    }
}
