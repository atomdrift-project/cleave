//! VBA macro extraction and analysis for Microsoft Office documents.
//!
//! Implements MS-OVBA decompression (Section 2.4.1) to extract VBA source code
//! from OLE2 compound documents. Works for both legacy Office formats (.doc/.xls/.ppt)
//! and OOXML vbaProject.bin containers.

use anyhow::{bail, Result};
use std::io::{Cursor, Read};

/// A single VBA module extracted from a document.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for Debug output and VBA analysis context
pub(crate) struct VbaModule {
    pub name: String,
    pub source_code: String,
    pub module_type: VbaModuleType,
}

/// Type of VBA module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // All variants populated by dir stream parsing
pub(crate) enum VbaModuleType {
    Standard,
    Class,
    Document,
}

/// Module metadata parsed from the dir stream.
struct ModuleInfo {
    name: String,
    stream_name: String,
    offset: u32,
    module_type: VbaModuleType,
}

/// Extract VBA modules from a CFBF compound file.
///
/// Navigates to VBA/dir stream, parses module metadata, then reads and
/// decompresses each module's source code.
pub(crate) fn extract_vba_modules(data: &[u8]) -> Result<Vec<VbaModule>> {
    let cursor = Cursor::new(data);
    let mut comp = cfb::CompoundFile::open(cursor)?;

    // Find the VBA directory - check common paths
    let vba_prefix = find_vba_prefix(&mut comp)?;

    // Read and decompress the dir stream
    let dir_path = format!("{}/dir", vba_prefix);
    let dir_data = read_cfb_stream(&mut comp, &dir_path)?;
    let dir_decompressed = decompress_vba(&dir_data)?;

    // Parse module info from dir stream
    let modules_info = parse_dir_stream(&dir_decompressed);

    // Extract each module's source code
    let mut modules = Vec::with_capacity(modules_info.len());
    for info in &modules_info {
        let stream_path = format!("{}/{}", vba_prefix, info.stream_name);
        match read_cfb_stream(&mut comp, &stream_path) {
            Ok(stream_data) => {
                if (info.offset as usize) < stream_data.len() {
                    let compressed = &stream_data[info.offset as usize..];
                    match decompress_vba(compressed) {
                        Ok(source_bytes) => {
                            let source = String::from_utf8_lossy(&source_bytes).to_string();
                            modules.push(VbaModule {
                                name: info.name.clone(),
                                source_code: source,
                                module_type: info.module_type,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(
                                module = %info.name,
                                error = %e,
                                "Failed to decompress VBA module"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    stream = %stream_path,
                    error = %e,
                    "Failed to read VBA module stream"
                );
            }
        }
    }

    Ok(modules)
}

/// Find the VBA project prefix path in the compound file.
fn find_vba_prefix(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>) -> Result<String> {
    // Collect entries first to avoid borrow issues
    let entries: Vec<String> = comp
        .walk()
        .map(|e| e.path().to_string_lossy().to_string())
        .collect();

    // Common locations for VBA project
    let candidates = [
        "/VBA",
        "/Macros/VBA",
        "/_VBA_PROJECT_CUR/VBA",
        "/Word/VBA",
        "/Excel/VBA",
    ];

    for candidate in &candidates {
        // Normalize: cfb paths use forward slashes, may or may not have leading /
        let normalized = candidate.trim_start_matches('/');
        for entry in &entries {
            let entry_normalized = entry.trim_start_matches('/');
            if entry_normalized.eq_ignore_ascii_case(&format!("{normalized}/dir")) {
                return Ok(format!("/{normalized}"));
            }
        }
    }

    // Fallback: search for any path ending in /VBA/dir
    for entry in &entries {
        let lower = entry.to_lowercase();
        if lower.ends_with("/vba/dir") || lower.ends_with("\\vba\\dir") {
            let prefix = &entry[..entry.len() - 4]; // strip "/dir"
            return Ok(prefix.to_string());
        }
    }

    bail!("No VBA project directory found in compound file")
}

/// Maximum size of a decompressed VBA module (10 MB).
const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

/// Maximum size of a CFB stream (20 MB).
const MAX_STREAM_SIZE: u64 = 20 * 1024 * 1024;

/// Read a stream from the compound file with size limits.
fn read_cfb_stream(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>, path: &str) -> Result<Vec<u8>> {
    let mut stream = comp.open_stream(path)?;
    let size = stream.len();

    if size > MAX_STREAM_SIZE {
        bail!(
            "CFB stream {} exceeds size limit ({} > {})",
            path,
            size,
            MAX_STREAM_SIZE
        );
    }

    let mut data = Vec::with_capacity(size as usize);
    stream.read_to_end(&mut data)?;
    Ok(data)
}

// ---------------------------------------------------------------------------
// MS-OVBA Compression/Decompression (MS-OVBA 2.4.1)
// ---------------------------------------------------------------------------

/// Decompress VBA compressed data per MS-OVBA Section 2.4.1.
///
/// The format uses a signature byte (0x01) followed by compressed chunks.
/// Each chunk has a 2-byte header encoding size and whether it's compressed.
/// Compressed chunks use LZ-style copy tokens with variable-length offsets.
pub(crate) fn decompress_vba(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    // First byte must be the compression signature 0x01
    if data[0] != 0x01 {
        bail!("Invalid VBA compression signature: 0x{:02x}", data[0]);
    }

    let mut output = Vec::with_capacity(data.len().saturating_mul(2).min(MAX_DECOMPRESSED_SIZE));
    let mut pos = 1; // skip signature byte

    while pos < data.len() {
        if pos + 1 >= data.len() {
            break;
        }

        // Read chunk header (2 bytes, little-endian)
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        let chunk_size = (header & 0x0FFF) as usize + 3; // 12 bits for size
        let is_compressed = (header & 0x8000) != 0; // bit 15

        if !is_compressed {
            // Uncompressed chunk: copy 4096 bytes directly
            let end = (pos + 4096).min(data.len());
            let copy_len = end - pos;

            if output.len() + copy_len > MAX_DECOMPRESSED_SIZE {
                bail!("Decompressed VBA size exceeds limit");
            }

            output.extend_from_slice(&data[pos..end]);
            pos = end;
        } else {
            // Compressed chunk
            let chunk_end = (pos + chunk_size - 2).min(data.len());
            let decompressed_start = output.len();

            while pos < chunk_end {
                if pos >= data.len() {
                    break;
                }

                // Flag byte: each bit indicates literal (0) or copy token (1)
                let flag_byte = data[pos];
                pos += 1;

                for bit_index in 0..8u8 {
                    if pos >= chunk_end {
                        break;
                    }

                    if (flag_byte >> bit_index) & 1 == 0 {
                        // Literal byte
                        if pos < data.len() {
                            if output.len() + 1 > MAX_DECOMPRESSED_SIZE {
                                bail!("Decompressed VBA size exceeds limit");
                            }
                            output.push(data[pos]);
                            pos += 1;
                        }
                    } else {
                        // Copy token (2 bytes, little-endian)
                        if pos + 1 >= data.len() {
                            pos = data.len();
                            break;
                        }

                        let token = u16::from_le_bytes([data[pos], data[pos + 1]]);
                        pos += 2;

                        // Calculate bit sizes based on decompressed chunk position
                        let decompressed_pos = output.len() - decompressed_start;
                        let bit_count = max_bit_count(decompressed_pos);
                        let len_mask = 0xFFFFu16 >> bit_count;
                        let offset_mask = !len_mask;

                        let length = ((token & len_mask) + 3) as usize;
                        let offset = ((token & offset_mask) >> (16 - bit_count)) as usize + 1;

                        if output.len() + length > MAX_DECOMPRESSED_SIZE {
                            bail!("Decompressed VBA size exceeds limit");
                        }

                        // Copy bytes from earlier in the output (may overlap)
                        for _ in 0..length {
                            let src_pos = output.len().wrapping_sub(offset);
                            if src_pos < output.len() {
                                let byte = output[src_pos];
                                output.push(byte);
                            } else {
                                // This case should not happen in valid MS-OVBA
                                output.push(0);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(output)
}

/// Calculate the number of bits used for offset in a copy token.
/// Per MS-OVBA 2.4.1.3.19.1.
fn max_bit_count(decompressed_pos: usize) -> u16 {
    if decompressed_pos <= 0x80 {
        return 12;
    }
    let mut result = 12u16;
    let mut threshold = 0x80usize;
    while threshold < decompressed_pos {
        threshold <<= 1;
        if result > 4 {
            result -= 1;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// VBA dir stream parsing (MS-OVBA 2.3.4.2)
// ---------------------------------------------------------------------------

/// Parse the decompressed VBA dir stream to extract module metadata.
fn parse_dir_stream(data: &[u8]) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    let mut pos = 0;

    // Skip PROJECTINFORMATION and PROJECTREFERENCES records
    // We scan for MODULE records which start with id 0x0019
    while pos + 6 <= data.len() {
        let record_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let record_size =
            u32::from_le_bytes([data[pos + 2], data[pos + 3], data[pos + 4], data[pos + 5]])
                as usize;

        match record_id {
            0x000F => {
                // MODULETERMINATOR - end of modules
                break;
            }
            0x0019 => {
                // MODULE NAME record
                pos += 6;
                let name = read_ascii_string(data, pos, record_size);
                pos += record_size;

                // Parse remaining module records
                let mut stream_name = name.clone();
                let mut offset = 0u32;
                let mut module_type = VbaModuleType::Standard;

                while pos + 6 <= data.len() {
                    let sub_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    let sub_size = u32::from_le_bytes([
                        data[pos + 2],
                        data[pos + 3],
                        data[pos + 4],
                        data[pos + 5],
                    ]) as usize;

                    match sub_id {
                        0x0047 => {
                            // MODULE NAMEUNICODE - skip
                            pos += 6 + sub_size;
                        }
                        0x001A => {
                            // MODULE STREAMNAME (MBCS)
                            pos += 6;
                            stream_name = read_ascii_string(data, pos, sub_size);
                            pos += sub_size;
                            // Skip the unicode version that follows (0x0032)
                            if pos + 6 <= data.len() {
                                let next_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
                                if next_id == 0x0032 {
                                    let next_size = u32::from_le_bytes([
                                        data[pos + 2],
                                        data[pos + 3],
                                        data[pos + 4],
                                        data[pos + 5],
                                    ]) as usize;
                                    pos += 6 + next_size;
                                }
                            }
                        }
                        0x001C => {
                            // MODULE DOCSTRING - skip
                            pos += 6 + sub_size;
                            // Skip unicode version (0x0048)
                            if pos + 6 <= data.len() {
                                let next_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
                                if next_id == 0x0048 {
                                    let next_size = u32::from_le_bytes([
                                        data[pos + 2],
                                        data[pos + 3],
                                        data[pos + 4],
                                        data[pos + 5],
                                    ]) as usize;
                                    pos += 6 + next_size;
                                }
                            }
                        }
                        0x0031 => {
                            // MODULE OFFSET
                            pos += 6;
                            if sub_size >= 4 && pos + 4 <= data.len() {
                                offset = u32::from_le_bytes([
                                    data[pos],
                                    data[pos + 1],
                                    data[pos + 2],
                                    data[pos + 3],
                                ]);
                            }
                            pos += sub_size;
                        }
                        0x001E => {
                            // MODULE HELPCONTEXT - skip
                            pos += 6 + sub_size;
                        }
                        0x002C => {
                            // MODULE COOKIE - skip
                            pos += 6 + sub_size;
                        }
                        0x0021 => {
                            // MODULE TYPE: procedural
                            module_type = VbaModuleType::Standard;
                            pos += 6 + sub_size;
                        }
                        0x0022 => {
                            // MODULE TYPE: class/document
                            module_type = VbaModuleType::Class;
                            pos += 6 + sub_size;
                        }
                        0x0025 => {
                            // MODULE READONLY - skip
                            pos += 6 + sub_size;
                        }
                        0x0028 => {
                            // MODULE PRIVATE - skip
                            pos += 6 + sub_size;
                        }
                        0x002B => {
                            // MODULE TERMINATOR - end of this module
                            pos += 6;
                            break;
                        }
                        _ => {
                            // Unknown record, skip
                            pos += 6 + sub_size;
                        }
                    }
                }

                modules.push(ModuleInfo {
                    name,
                    stream_name,
                    offset,
                    module_type,
                });
            }
            _ => {
                // Skip unknown record
                pos += 6 + record_size;
            }
        }
    }

    modules
}

fn read_ascii_string(data: &[u8], pos: usize, len: usize) -> String {
    if pos + len > data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&data[pos..pos + len])
        .trim_end_matches('\0')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn test_decompress_empty() {
        assert!(decompress_vba(&[])
            .expect("Empty data should return empty vec")
            .is_empty());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_decompress_invalid_signature() {
        assert!(decompress_vba(&[0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_decompress_valid_uncompressed_chunk() {
        // Signature + uncompressed chunk header (size=4096, compressed=0)
        let mut data = vec![0x01]; // signature
        let header: u16 = 0x0FFD; // 4096-3 = 4093 = 0x0FFD, compressed bit not set
        data.extend_from_slice(&header.to_le_bytes());
        data.extend_from_slice(&[b'A'; 4096]);
        let result = decompress_vba(&data).expect("VBA decompression failed");
        assert_eq!(result.len(), 4096);
        assert!(result.iter().all(|&b| b == b'A'));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_decompress_compressed_literals_only() {
        // A compressed chunk with only literal bytes (no copy tokens)
        // Flag byte 0x00 = 8 literals
        let mut data = vec![0x01]; // signature

        // We'll create a small compressed chunk with 3 literal bytes: "ABC"
        // Flag byte: 0x00 (all literals), then 3 bytes
        let chunk_data = [0x00u8, b'A', b'B', b'C'];
        // Chunk size = chunk_data.len() + 2 (header) - 3 = chunk_data.len() - 1
        let chunk_size = chunk_data.len() as u16 - 1; // 3
        let header: u16 = 0x8000 | (chunk_size & 0x0FFF); // compressed bit set
        data.extend_from_slice(&header.to_le_bytes());
        data.extend_from_slice(&chunk_data);

        let result = decompress_vba(&data).expect("VBA decompression failed");
        assert_eq!(&result[..3], b"ABC");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_max_bit_count() {
        assert_eq!(max_bit_count(0), 12);
        assert_eq!(max_bit_count(1), 12);
        assert_eq!(max_bit_count(0x80), 12);
        assert_eq!(max_bit_count(0x81), 11);
        assert_eq!(max_bit_count(0x100), 11);
        assert_eq!(max_bit_count(0x101), 10);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_vba_module_struct() {
        let module = VbaModule {
            name: "Module1".to_string(),
            source_code: "Sub Test()\nMsgBox \"hello\"\nEnd Sub".to_string(),
            module_type: VbaModuleType::Standard,
        };
        assert_eq!(module.name, "Module1");
        assert!(module.source_code.contains("MsgBox"));
    }
}
