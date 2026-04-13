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
    LimitedReader, MAX_FILE_SIZE,
};
use crate::types::{container_metrics::ArchiveMetrics, ArchiveEntry};
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::Path;

/// Read ZIP central directory metadata without extracting contents.
pub(crate) fn inspect_zip_metadata(
    archive_path: &Path,
) -> Result<(Vec<ArchiveEntry>, ArchiveMetrics)> {
    let file = File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;
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

/// Extract ZIP archive with bomb protection
pub(crate) fn extract_zip_safe(
    archive_path: &Path,
    dest_dir: &Path,
    guard: &ExtractionGuard,
    zip_passwords: &[String],
) -> Result<()> {
    use tracing::{debug, info, trace};

    let file = File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;
    if archive.len() > super::guards::MAX_ZIP_ENTRIES {
        anyhow::bail!(
            "ZIP central directory claims {} entries (max {})",
            archive.len(),
            super::guards::MAX_ZIP_ENTRIES
        );
    }

    debug!(
        "Opening ZIP archive: {:?} ({} entries)",
        archive_path,
        archive.len()
    );

    // Check if the archive is encrypted by finding the first file (not directory)
    // Directories in zips often have encrypted=false even if files are encrypted
    let is_encrypted = if !archive.is_empty() {
        let mut found_encrypted = false;
        for i in 0..archive.len().min(10) {
            // Check first 10 entries
            match archive.by_index(i) {
                Ok(entry) => {
                    // Skip directories, check actual files
                    if !entry.is_dir() {
                        let encrypted = entry.encrypted();
                        trace!("Entry {} ({}) encrypted: {}", i, entry.name(), encrypted);
                        if encrypted {
                            found_encrypted = true;
                            break;
                        }
                    } else {
                        trace!("Entry {} is directory, skipping encryption check", i);
                    }
                }
                Err(_) => {
                    debug!("Cannot read entry {}, assuming encrypted", i);
                    found_encrypted = true;
                    break;
                }
            }
        }
        found_encrypted
    } else {
        debug!("Empty archive");
        false
    };

    if is_encrypted {
        info!(
            "ZIP archive is encrypted, attempting {} passwords",
            zip_passwords.len()
        );

        if zip_passwords.is_empty() {
            anyhow::bail!("Archive is encrypted but no passwords configured");
        }

        // Try each password with a time budget to prevent DoS on large encrypted archives
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

            debug!(
                "Trying password {}/{} ({}B)",
                idx + 1,
                zip_passwords.len(),
                password.len()
            );

            // Re-open the archive for each password attempt
            let file = File::open(archive_path)?;
            let mut archive = zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;

            match extract_zip_entries_safe(&mut archive, dest_dir, Some(password.as_bytes()), guard)
            {
                Ok(()) => {
                    info!("✓ Decrypted with password: {}", password);
                    return Ok(());
                }
                Err(e) => {
                    debug!("Password '{}' failed: {}", password, e);
                    continue;
                }
            }
        }
        anyhow::bail!(
            "Password required to decrypt file (tried {} passwords)",
            zip_passwords.len()
        );
    } else {
        debug!("Archive is not encrypted, extracting directly");
    }

    // Try without password
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

/// Extract Chrome extension (.crx) files
///
/// CRX2: "Cr24" (4) + version=2 (4) + pubkey_len (4) + sig_len (4) + pubkey + sig + ZIP
/// CRX3: "Cr24" (4) + version=3 (4) + header_size (4) + signed_header (header_size) + ZIP
pub(crate) fn extract_crx_safe(
    archive_path: &Path,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    let mut file = File::open(archive_path)?;
    let file_len = file.metadata()?.len() as usize;
    let mut header = [0u8; 12];

    // Read CRX header (first 12 bytes are common to CRX2 and CRX3)
    file.read_exact(&mut header)
        .context("Failed to read CRX header")?;

    // Verify magic number "Cr24"
    if &header[0..4] != b"Cr24" {
        anyhow::bail!("Invalid CRX magic number");
    }

    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

    let zip_offset = match version {
        3 => {
            // CRX3: bytes 8..12 = header_size (protobuf signed header length)
            let header_size =
                u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
            12usize
                .checked_add(header_size)
                .context("CRX3 header specifies invalid offset (overflow)")?
        }
        2 => {
            // CRX2: bytes 8..12 = pubkey_len, bytes 12..16 = sig_len
            let pubkey_len =
                u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
            let mut extra = [0u8; 4];
            file.read_exact(&mut extra)
                .context("Failed to read CRX2 sig_len")?;
            let sig_len = u32::from_le_bytes(extra) as usize;
            16usize
                .checked_add(pubkey_len)
                .and_then(|sum| sum.checked_add(sig_len))
                .context("CRX2 header specifies invalid offsets (overflow)")?
        }
        _ => anyhow::bail!("Unsupported CRX version: {version}"),
    };

    if zip_offset >= file_len {
        anyhow::bail!(
            "CRX file truncated or invalid header (offset {} >= size {})",
            zip_offset,
            file_len
        );
    }

    // Seek to the start of the ZIP data
    file.seek(std::io::SeekFrom::Start(zip_offset as u64))?;

    // Create ZipArchive from the file (ZipArchive will seek as needed)
    let mut archive = zip::ZipArchive::new(file).context("Failed to read ZIP from CRX")?;
    if archive.len() > super::guards::MAX_ZIP_ENTRIES {
        anyhow::bail!(
            "CRX ZIP central directory claims {} entries (max {})",
            archive.len(),
            super::guards::MAX_ZIP_ENTRIES
        );
    }

    // Use the same extraction logic as regular ZIP (but without password support for now)
    extract_zip_entries_safe(&mut archive, dest_dir, None, guard)
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

        // Create a malformed CRX2 with pubkey_len that exceeds file size
        let mut crx_data = Vec::new();
        crx_data.extend_from_slice(b"Cr24");
        crx_data.extend_from_slice(&2u32.to_le_bytes()); // version 2
        crx_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // massive pubkey_len
        crx_data.extend_from_slice(&0u32.to_le_bytes()); // sig_len

        let crx_path = dir.path().join("invalid.crx");
        std::fs::write(&crx_path, &crx_data).expect("Failed to write crx data");

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("Failed to create dest dir");

        let result = extract_crx_safe(&crx_path, &dest, &guard);
        assert!(result.is_err());
        let err_msg = result.expect_err("Expected error").to_string();
        assert!(err_msg.contains("truncated") || err_msg.contains("invalid"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_extract_crx3_invalid_offsets() {
        let dir = tempdir().expect("Failed to create temp dir");
        let guard = ExtractionGuard::new();

        // Create a malformed CRX3 with header_size that exceeds file size
        let mut crx_data = Vec::new();
        crx_data.extend_from_slice(b"Cr24");
        crx_data.extend_from_slice(&3u32.to_le_bytes()); // version 3
        crx_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // massive header_size

        let crx_path = dir.path().join("invalid_v3.crx");
        std::fs::write(&crx_path, &crx_data).expect("Failed to write crx data");

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("Failed to create dest dir");

        let result = extract_crx_safe(&crx_path, &dest, &guard);
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
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options = zip::write::FileOptions::<()>::default();
            zip.start_file("manifest.json", options).expect("start_file");
            std::io::Write::write_all(&mut zip, b"{\"manifest_version\": 3}")
                .expect("write manifest");
            zip.finish().expect("finish zip");
            buf
        };

        // CRX3: magic(4) + version=3(4) + header_size(4) + header(header_size) + ZIP
        let header_size: u32 = 48; // fake protobuf header
        let mut crx_data = Vec::new();
        crx_data.extend_from_slice(b"Cr24");
        crx_data.extend_from_slice(&3u32.to_le_bytes());
        crx_data.extend_from_slice(&header_size.to_le_bytes());
        crx_data.extend_from_slice(&vec![0u8; header_size as usize]); // fake signed header
        crx_data.extend_from_slice(&zip_data);

        let crx_path = dir.path().join("extension_v3.crx");
        std::fs::write(&crx_path, &crx_data).expect("Failed to write crx data");

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("Failed to create dest dir");

        let result = extract_crx_safe(&crx_path, &dest, &guard);
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
        crx_data.extend_from_slice(&[0u8; 8]); // padding

        let crx_path = dir.path().join("unsupported.crx");
        std::fs::write(&crx_path, &crx_data).expect("Failed to write crx data");

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("Failed to create dest dir");

        let result = extract_crx_safe(&crx_path, &dest, &guard);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("Unsupported CRX version")
        );
    }
}
