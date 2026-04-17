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
    sanitize_entry_path, symlink_escapes, CancellableReader, ExtractionGuard, HostileArchiveReason,
    LimitedReader, MAX_FILE_SIZE, MAX_PATH_COMPONENT_LEN,
};
use crate::types::{container_metrics::ArchiveMetrics, ArchiveEntry};
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::Path;

/// Read ZIP central directory metadata from an in-memory reader.
pub(crate) fn inspect_zip_metadata_from_reader<R: Read + Seek>(
    reader: R,
) -> Result<(Vec<ArchiveEntry>, ArchiveMetrics)> {
    let mut archive = zip::ZipArchive::new(reader).context("Failed to read ZIP archive")?;
    if archive.len() > super::guards::MAX_ZIP_ENTRIES {
        anyhow::bail!(
            "ZIP central directory claims {} entries (max {})",
            archive.len(),
            super::guards::MAX_ZIP_ENTRIES
        );
    }

    let mut entries = Vec::with_capacity(archive.len());
    let mut metrics = ArchiveMetrics {
        has_comment: !archive.comment().is_empty(),
        ..ArchiveMetrics::default()
    };

    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        if entry.is_dir() {
            metrics.directory_count += 1;
            continue;
        }

        metrics.file_count += 1;
        metrics.total_uncompressed += entry.size();
        metrics.total_compressed += entry.compressed_size();
        metrics.max_filename_length = metrics.max_filename_length.max(name.len() as u32);
        if name.starts_with('.') || name.split('/').any(|part| part.starts_with('.')) {
            metrics.hidden_files += 1;
        }
        if entry.encrypted() {
            metrics.encrypted_entries += 1;
        }

        entries.push(ArchiveEntry {
            path: name,
            file_type: "unknown".to_string(),
            sha256: String::new(),
            size_bytes: entry.size(),
        });
    }

    if metrics.total_uncompressed > 0 {
        metrics.compression_ratio =
            metrics.total_compressed as f32 / metrics.total_uncompressed as f32;
    }

    Ok((entries, metrics))
}

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

/// Extract a CRX (Chrome extension) archive from in-memory data.
pub(crate) fn extract_crx_from_data(
    data: &[u8],
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    use std::io::Cursor;

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

        // Check for symlinks (zip files can contain them via external attributes)
        // S_IFLNK = 0o120000, S_IFMT = 0o170000
        if let Some(mode) = entry.unix_mode() {
            if mode & 0o170000 == 0o120000 {
                // Symlink target is stored as file content in ZIP
                // Use LimitedReader to prevent unbounded allocation from malicious entries
                let mut target_buf = Vec::new();
                let mut limited = LimitedReader::new(&mut entry, 4096);
                if let Ok(read_size) = limited.read_to_end(&mut target_buf) {
                    if read_size > 0 && read_size < 4096 {
                        // Reasonable symlink path length
                        if let Ok(target_str) = String::from_utf8(target_buf) {
                            if symlink_escapes(&outpath, &target_str, dest_dir) {
                                guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(
                                    format!("{} -> {}", entry_name, target_str),
                                ));
                            }
                        }
                    }
                }
                // Skip symlinks regardless (we don't extract them)
                continue;
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::archive::guards::ExtractionGuard;
    use tempfile::tempdir;

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
        assert!(result
            .expect_err("Expected error")
            .to_string()
            .contains("Unsupported CRX version"));
    }
}
