//! ZIP-based archive format handlers.
//!
//! This module handles ZIP files and ZIP-based formats including:
//! - Standard ZIP archives
//! - JAR/WAR/EAR (Java archives)
//! - APK/AAR (Android packages)
//! - Chrome extensions (.crx)
//! - Python packages (.egg, .whl)
//! - NuGet packages (.nupkg)
//! - VS Code extensions (.vsix)
//! - Firefox extensions (.xpi)

use super::guards::{
    CancellableReader, ExtractedMemberMetadata, ExtractionGuard, HostileArchiveReason,
    LimitedReader, MAX_FILE_SIZE, MAX_PATH_COMPONENT_LEN, sanitize_entry_path, symlink_escapes,
};
use crate::types::ArchiveEntry;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::Path;

/// Extract a ZIP archive from in-memory data.
pub(crate) fn extract_zip_from_data(
    data: &[u8],
    dest_dir: &Path,
    guard: &ExtractionGuard,
    zip_passwords: &[String],
) -> Result<()> {
    use std::io::Cursor;
    use tracing::{debug, info, trace};

    let mut archive =
        zip::ZipArchive::new(Cursor::new(data)).context("Failed to read ZIP archive")?;
    if archive.len() > super::guards::MAX_ZIP_ENTRIES {
        anyhow::bail!(
            "ZIP central directory claims {} entries (max {})",
            archive.len(),
            super::guards::MAX_ZIP_ENTRIES
        );
    }

    debug!("Opening in-memory ZIP archive ({} entries)", archive.len());

    let is_encrypted = if !archive.is_empty() {
        let mut found_encrypted = false;
        for i in 0..archive.len().min(10) {
            match archive.by_index(i) {
                Ok(entry) => {
                    if !entry.is_dir() && entry.encrypted() {
                        found_encrypted = true;
                        break;
                    }
                }
                Err(_) => {
                    found_encrypted = true;
                    break;
                }
            }
        }
        found_encrypted
    } else {
        false
    };

    if is_encrypted {
        if zip_passwords.is_empty() {
            anyhow::bail!("Archive is encrypted but no passwords configured");
        }

        let password_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);

        for (idx, password) in zip_passwords.iter().enumerate() {
            if guard.is_cancelled() {
                anyhow::bail!("Request cancelled during password attempts");
            }
            if std::time::Instant::now() > password_deadline {
                info!(
                    "Password attempt budget exhausted after {}/{} passwords",
                    idx,
                    zip_passwords.len()
                );
                break;
            }

            trace!("Trying password {}/{}", idx + 1, zip_passwords.len());
            // Re-create the archive for each attempt (cheap — Cursor borrows data)
            let mut archive =
                zip::ZipArchive::new(Cursor::new(data)).context("Failed to read ZIP archive")?;

            match extract_zip_entries_safe(&mut archive, dest_dir, Some(password.as_bytes()), guard)
            {
                Ok(()) => {
                    info!("✓ Decrypted with password");
                    return Ok(());
                }
                Err(_) => continue,
            }
        }
        anyhow::bail!(
            "Password required to decrypt file (tried {} passwords)",
            zip_passwords.len()
        );
    }

    extract_zip_entries_safe(&mut archive, dest_dir, None, guard)
}

/// Return the byte offset where the ZIP payload begins inside a CRX file.
pub(crate) fn crx_zip_offset(data: &[u8]) -> Result<usize> {
    if data.len() < 12 {
        anyhow::bail!("CRX data too small for header");
    }
    if &data[0..4] != b"Cr24" {
        anyhow::bail!("Invalid CRX magic number");
    }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let zip_offset = match version {
        3 => {
            let header_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
            12usize
                .checked_add(header_size)
                .context("CRX3 header specifies invalid offset (overflow)")?
        }
        2 => {
            if data.len() < 16 {
                anyhow::bail!("CRX2 data too small for header");
            }
            let pubkey_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
            let sig_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
            16usize
                .checked_add(pubkey_len)
                .and_then(|s| s.checked_add(sig_len))
                .context("CRX2 header specifies invalid offsets (overflow)")?
        }
        _ => anyhow::bail!("Unsupported CRX version: {version}"),
    };

    if zip_offset >= data.len() {
        anyhow::bail!(
            "CRX file truncated or invalid header (offset {} >= size {})",
            zip_offset,
            data.len()
        );
    }
    Ok(zip_offset)
}

/// Read a ZIP member from filefacts central-directory offsets.
pub(crate) fn read_indexed_zip_member(
    data: &[u8],
    entry: &ArchiveEntry,
    limit: u64,
) -> Result<Vec<u8>> {
    let data_offset = entry
        .data_offset
        .ok_or_else(|| anyhow::anyhow!("missing ZIP data offset"))?;
    let compressed_size = entry
        .compressed_size
        .ok_or_else(|| anyhow::anyhow!("missing ZIP compressed size"))?;
    let start =
        usize::try_from(data_offset).map_err(|e| anyhow::anyhow!("ZIP offset too large: {e}"))?;
    let compressed_len = usize::try_from(compressed_size)
        .map_err(|e| anyhow::anyhow!("ZIP compressed size too large: {e}"))?;
    let end = start
        .checked_add(compressed_len)
        .ok_or_else(|| anyhow::anyhow!("ZIP member range overflow"))?;
    if end > data.len() {
        anyhow::bail!("ZIP member range exceeds archive size");
    }

    let compressed = &data[start..end];
    match entry.compression_method.as_deref() {
        Some("stored") => {
            if compressed.len() as u64 > limit {
                anyhow::bail!("ZIP stored member exceeds read limit");
            }
            Ok(compressed.to_vec())
        }
        Some("deflate") => {
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            let mut limited = LimitedReader::new(&mut decoder, limit);
            let mut out = Vec::with_capacity(entry.size_bytes.min(16 * 1024 * 1024) as usize);
            limited.read_to_end(&mut out)?;
            if limited.is_limited() {
                anyhow::bail!("ZIP deflated member exceeds read limit");
            }
            Ok(out)
        }
        Some(method) => anyhow::bail!("unsupported indexed ZIP compression method: {method}"),
        None => anyhow::bail!("missing ZIP compression method"),
    }
}

/// Extract a CRX (Chrome extension) archive from in-memory data.
pub(crate) fn extract_crx_from_data(
    data: &[u8],
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    use std::io::Cursor;

    let zip_offset = crx_zip_offset(data)?;

    let mut archive = zip::ZipArchive::new(Cursor::new(&data[zip_offset..]))
        .context("Failed to read ZIP from CRX")?;
    if archive.len() > super::guards::MAX_ZIP_ENTRIES {
        anyhow::bail!(
            "CRX ZIP central directory claims {} entries (max {})",
            archive.len(),
            super::guards::MAX_ZIP_ENTRIES
        );
    }

    extract_zip_entries_safe(&mut archive, dest_dir, None, guard)
}

/// Extract ZIP entries with optional password
pub(crate) fn extract_zip_entries_safe<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    dest_dir: &Path,
    password: Option<&[u8]>,
    guard: &ExtractionGuard,
) -> Result<()> {
    use tracing::{debug, trace};

    let password_display = password.map(|_| "***").unwrap_or("none");
    debug!(
        "Extracting {} entries with password: {}",
        archive.len(),
        password_display
    );

    for i in 0..archive.len() {
        // Check file count limit
        if !guard.check_file_count() {
            anyhow::bail!(
                "Exceeded maximum file count ({})",
                super::guards::MAX_FILE_COUNT
            );
        }

        trace!("Processing entry {}/{}", i + 1, archive.len());

        let mut entry = match password {
            Some(pw) => match archive.by_index_decrypt(i, pw) {
                Ok(file) => {
                    trace!("Entry {} decrypted successfully", i);
                    file
                }
                Err(e) => {
                    debug!("Failed to decrypt entry {}: {}", i, e);
                    return Err(e.into());
                }
            },
            None => archive.by_index(i)?,
        };

        let entry_name = entry.name().to_string();
        trace!("Entry {}: {}", i, entry_name);

        let compressed_size = Some(entry.compressed_size());
        let compression_method = Some(format_zip_compression(entry.compression()));
        let mtime_unix = entry.last_modified().and_then(zip_datetime_to_unix);
        let mode_octal = entry.unix_mode();
        let is_dir_flag = entry.is_dir();
        let is_symlink_flag = entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000);
        let entry_type_str = if is_dir_flag {
            "directory"
        } else if is_symlink_flag {
            "symlink"
        } else {
            "regular"
        };

        if entry_name.len() > MAX_PATH_COMPONENT_LEN {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                len: entry_name.len(),
                preview: entry_name.chars().take(80).collect(),
            });
        }

        // Sanitize path to prevent zip slip
        let Some(outpath) = sanitize_entry_path(&entry_name, dest_dir) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
            continue; // Skip this file but continue extraction
        };

        let rel_path = outpath
            .strip_prefix(dest_dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| entry_name.clone());
        let mut linkname_capture: Option<String> = None;

        // Check for symlinks (zip files can contain them via external attributes)
        // S_IFLNK = 0o120000, S_IFMT = 0o170000
        if let Some(mode) = entry.unix_mode()
            && mode & 0o170000 == 0o120000
        {
            // Symlink target is stored as file content in ZIP
            // Use LimitedReader to prevent unbounded allocation from malicious entries
            let mut target_buf = Vec::new();
            let mut limited = LimitedReader::new(&mut entry, 4096);
            if let Ok(read_size) = limited.read_to_end(&mut target_buf)
                && read_size > 0
                && read_size < 4096
            {
                // Reasonable symlink path length
                if let Ok(target_str) = String::from_utf8(target_buf) {
                    if symlink_escapes(&outpath, &target_str, dest_dir) {
                        guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                            "{} -> {}",
                            entry_name, target_str
                        )));
                    }
                    linkname_capture = Some(target_str);
                }
            }
            guard.record_member_metadata(ExtractedMemberMetadata {
                archive_path: rel_path,
                compressed_size,
                compression_method,
                mtime_unix,
                mode_octal,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
                entry_type: Some(entry_type_str.to_string()),
                linkname: linkname_capture,
                host_os: None,
            });
            // Skip symlinks regardless (we don't extract them)
            continue;
        }

        guard.record_member_metadata(ExtractedMemberMetadata {
            archive_path: rel_path,
            compressed_size,
            compression_method,
            mtime_unix,
            mode_octal,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
            entry_type: Some(entry_type_str.to_string()),
            linkname: None,
            host_os: None,
        });

        if entry.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            // Check compression ratio before extraction (zip bomb detection)
            let compressed = entry.compressed_size();
            let uncompressed = entry.size();
            if !guard.check_compression_ratio(compressed, uncompressed) {
                continue; // Skip but continue
            }

            // Check if this single file would exceed limits
            if uncompressed > MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: entry_name.clone(),
                    size: uncompressed,
                });
                continue;
            }

            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }

            // Extract with size limit and cancellation support
            let mut outfile = File::create(&outpath)?;
            let written = if let Some(c) = guard.cancellation() {
                let mut cancellable = CancellableReader::new(&mut entry, c);
                let mut limited = LimitedReader::new(&mut cancellable, MAX_FILE_SIZE);
                let w = std::io::copy(&mut limited, &mut outfile)
                    .with_context(|| format!("Failed to extract: {}", entry_name))?;

                if limited.is_limited() {
                    drop(outfile);
                    let _ = std::fs::remove_file(&outpath);
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name.clone(),
                        size: MAX_FILE_SIZE,
                    });
                    continue;
                }
                w
            } else {
                let mut limited = LimitedReader::new(&mut entry, MAX_FILE_SIZE);
                let w = std::io::copy(&mut limited, &mut outfile)
                    .with_context(|| format!("Failed to extract: {}", entry_name))?;

                if limited.is_limited() {
                    drop(outfile);
                    let _ = std::fs::remove_file(&outpath);
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name.clone(),
                        size: MAX_FILE_SIZE,
                    });
                    continue;
                }
                w
            };

            // Track total bytes
            if !guard.check_bytes(written, &entry_name) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
        }
    }
    Ok(())
}

/// Short label for a ZIP compression method.
pub(super) fn format_zip_compression(method: zip::CompressionMethod) -> String {
    use zip::CompressionMethod;
    match method {
        CompressionMethod::Stored => "stored".to_string(),
        CompressionMethod::Deflated => "deflate".to_string(),
        CompressionMethod::Bzip2 => "bzip2".to_string(),
        CompressionMethod::Zstd => "zstd".to_string(),
        CompressionMethod::Lzma => "lzma".to_string(),
        CompressionMethod::Xz => "xz".to_string(),
        CompressionMethod::Aes => "aes".to_string(),
        other => format!("{:?}", other).to_ascii_lowercase(),
    }
}

/// Convert a ZIP `DateTime` (interpreted as UTC) to unix seconds.
///
/// ZIP stores timestamps as MS-DOS date/time pairs with no timezone; treating
/// them as UTC is the conventional interpretation for forensic comparison.
pub(super) fn zip_datetime_to_unix(dt: zip::DateTime) -> Option<i64> {
    let year = dt.year();
    if !(1970..=2999).contains(&year) {
        return None;
    }
    let days = days_from_civil(year as i32, dt.month() as u32, dt.day() as u32)?;
    let secs = (dt.hour() as i64) * 3600 + (dt.minute() as i64) * 60 + (dt.second() as i64);
    Some(days * 86_400 + secs)
}

/// Days from 1970-01-01 for the given Gregorian (y, m, d).
/// Based on Howard Hinnant's chrono algorithms (date.h). Returns `None` for
/// invalid month/day values.
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || d == 0 || d > 31 {
        return None;
    }
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = (y_adj - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era as i64) * 146_097 + doe as i64 - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::archive::guards::ExtractionGuard;
    use tempfile::tempdir;

    #[test]
    fn test_days_from_civil_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(1970, 1, 2), Some(1));
        assert_eq!(days_from_civil(2000, 1, 1), Some(10_957));
        assert_eq!(days_from_civil(2024, 1, 1), Some(19_723));
    }

    #[test]
    fn test_days_from_civil_invalid() {
        assert_eq!(days_from_civil(2024, 0, 1), None);
        assert_eq!(days_from_civil(2024, 13, 1), None);
        assert_eq!(days_from_civil(2024, 1, 0), None);
        assert_eq!(days_from_civil(2024, 1, 32), None);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_extract_crx2_invalid_offsets() {
        let dir = tempdir().expect("Failed to create temp dir");
        let guard = ExtractionGuard::new();

        // Malformed CRX2: pubkey_len exceeds file size
        let mut crx_data = Vec::new();
        crx_data.extend_from_slice(b"Cr24");
        crx_data.extend_from_slice(&2u32.to_le_bytes()); // version 2
        crx_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // massive pubkey_len
        crx_data.extend_from_slice(&0u32.to_le_bytes()); // sig_len

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("Failed to create dest dir");

        let result = extract_crx_from_data(&crx_data, &dest, &guard);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(err_msg.contains("truncated") || err_msg.contains("invalid"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_extract_crx3_invalid_offsets() {
        let dir = tempdir().expect("Failed to create temp dir");
        let guard = ExtractionGuard::new();

        // Malformed CRX3: header_size exceeds file size
        let mut crx_data = Vec::new();
        crx_data.extend_from_slice(b"Cr24");
        crx_data.extend_from_slice(&3u32.to_le_bytes()); // version 3
        crx_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // massive header_size

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("Failed to create dest dir");

        let result = extract_crx_from_data(&crx_data, &dest, &guard);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(err_msg.contains("truncated") || err_msg.contains("invalid"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_extract_crx3_valid() {
        let dir = tempdir().expect("Failed to create temp dir");
        let guard = ExtractionGuard::new();

        // Build a ZIP payload
        let zip_data = {
            let mut buf = Vec::new();
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options = zip::write::FileOptions::<()>::default();
            zw.start_file("manifest.json", options).expect("start_file");
            std::io::Write::write_all(&mut zw, b"{\"manifest_version\": 3}")
                .expect("write manifest");
            zw.finish().expect("finish zip");
            buf
        };

        // CRX3: magic(4) + version=3(4) + header_size(4) + header(header_size) + ZIP
        let header_size: u32 = 48;
        let mut crx_data = Vec::new();
        crx_data.extend_from_slice(b"Cr24");
        crx_data.extend_from_slice(&3u32.to_le_bytes());
        crx_data.extend_from_slice(&header_size.to_le_bytes());
        crx_data.extend_from_slice(&vec![0u8; header_size as usize]);
        crx_data.extend_from_slice(&zip_data);

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("Failed to create dest dir");

        let result = extract_crx_from_data(&crx_data, &dest, &guard);
        assert!(result.is_ok(), "CRX3 extraction failed: {result:?}");
        assert!(dest.join("manifest.json").exists());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_extract_crx_unsupported_version() {
        let dir = tempdir().expect("Failed to create temp dir");
        let guard = ExtractionGuard::new();

        let mut crx_data = Vec::new();
        crx_data.extend_from_slice(b"Cr24");
        crx_data.extend_from_slice(&99u32.to_le_bytes()); // unsupported version
        crx_data.extend_from_slice(&[0u8; 8]);

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("Failed to create dest dir");

        let result = extract_crx_from_data(&crx_data, &dest, &guard);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("Unsupported CRX version")
        );
    }
}
