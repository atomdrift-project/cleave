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

/// Read an archive member from the offsets filefacts indexed for it (a ZIP
/// central directory, a phar manifest): the `[data_offset, +compressed_size)`
/// slice, decompressed by its method and capped at `limit` bytes. A member
/// past the cap is an error.
pub(crate) fn read_indexed_member(
    data: &[u8],
    entry: &ArchiveEntry,
    limit: u64,
) -> Result<Vec<u8>> {
    let (bytes, truncated) = read_indexed_member_prefix(data, entry, limit)?;
    if truncated {
        anyhow::bail!("member exceeds read limit");
    }
    Ok(bytes)
}

/// [`read_indexed_member`], keeping the first `cap` bytes of a member that
/// runs past them; the flag says whether it did. Decoding stops one byte past
/// the cap, so a bomb costs no more than the cap.
pub(crate) fn read_indexed_member_prefix(
    data: &[u8],
    entry: &ArchiveEntry,
    cap: u64,
) -> Result<(Vec<u8>, bool)> {
    let data_offset = entry
        .data_offset
        .ok_or_else(|| anyhow::anyhow!("missing member data offset"))?;
    let compressed_size = entry
        .compressed_size
        .ok_or_else(|| anyhow::anyhow!("missing member compressed size"))?;
    let start = usize::try_from(data_offset)
        .map_err(|e| anyhow::anyhow!("member offset too large: {e}"))?;
    let compressed_len = usize::try_from(compressed_size)
        .map_err(|e| anyhow::anyhow!("member compressed size too large: {e}"))?;
    let end = start
        .checked_add(compressed_len)
        .ok_or_else(|| anyhow::anyhow!("member range overflow"))?;
    if end > data.len() {
        anyhow::bail!("member range exceeds archive size");
    }

    let cap_len = usize::try_from(cap).unwrap_or(usize::MAX);
    let compressed = &data[start..end];
    let inflate = |decoder: &mut dyn Read| -> Result<(Vec<u8>, bool)> {
        let mut out = Vec::with_capacity(entry.size_bytes.min(16 * 1024 * 1024) as usize);
        decoder.take(cap.saturating_add(1)).read_to_end(&mut out)?;
        let truncated = out.len() > cap_len;
        out.truncate(cap_len);
        Ok((out, truncated))
    };
    match entry.compression_method.as_deref() {
        Some("stored") => Ok((
            compressed[..compressed.len().min(cap_len)].to_vec(),
            compressed.len() > cap_len,
        )),
        // Raw deflate, no zlib header: ZIP and phar both store it this way.
        Some("deflate") => inflate(&mut flate2::read::DeflateDecoder::new(compressed)),
        Some("bzip2") => inflate(&mut bzip2::read::BzDecoder::new(compressed)),
        Some(method) => anyhow::bail!("unsupported indexed compression method: {method}"),
        None => anyhow::bail!("missing member compression method"),
    }
}

/// Extract a CRX (Chrome extension) archive from in-memory data, its ZIP
/// payload starting at `zip_offset` (filefacts' `crx.archive_offset`).
pub(crate) fn extract_crx_from_data(
    data: &[u8],
    zip_offset: usize,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    use std::io::Cursor;

    let payload = data
        .get(zip_offset..)
        .context("CRX archive offset past end of file")?;
    let mut archive =
        zip::ZipArchive::new(Cursor::new(payload)).context("Failed to read ZIP from CRX")?;
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

        let entry_name = entry.name().map_or_else(
            |_| String::from_utf8_lossy(entry.name_raw()).into_owned(),
            std::borrow::Cow::into_owned,
        );
        trace!("Entry {}: {}", i, entry_name);

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

        // A file whose name a previous member already claimed
        // (case-insensitively) is renamed rather than left to overwrite it.
        // Directories keep their sanitized name so members extracted beneath
        // them still resolve.
        let outpath = if entry.is_dir() {
            outpath
        } else {
            guard.claim_output_path(outpath)
        };

        let rel_path = outpath
            .strip_prefix(dest_dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| entry_name.clone());

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
                && let Ok(target_str) = String::from_utf8(target_buf)
                && symlink_escapes(&outpath, &target_str, dest_dir)
            {
                guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                    "{entry_name} -> {target_str}"
                )));
            }
            guard.record_member_metadata(ExtractedMemberMetadata {
                archive_path: rel_path,
                entry_type: Some(entry_type_str.to_string()),
            });
            // No link is created. But the JVM, Android and pip ignore unix
            // modes and load this entry as an ordinary file, so its bytes are
            // extracted and analyzed like any other member's.
            drop(entry);
            entry = match password {
                Some(pw) => archive.by_index_decrypt(i, pw)?,
                None => archive.by_index(i)?,
            };
        } else {
            guard.record_member_metadata(ExtractedMemberMetadata {
                archive_path: rel_path,
                entry_type: Some(entry_type_str.to_string()),
            });
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

        let result = extract_crx_from_data(&crx_data, 12 + header_size as usize, &dest, &guard);
        assert!(result.is_ok(), "CRX3 extraction failed: {result:?}");
        assert!(dest.join("manifest.json").exists());
    }
}

/// Recover members with false encryption flags only after bounded decompression
/// reproduces the complete declared size and CRC. Real encryption still takes
/// the password path; the original forensic flag remains in archive metadata.
pub(super) fn read_verified_plaintext_member(
    data: &[u8],
    entry: &ArchiveEntry,
    limit: u64,
) -> Result<Vec<u8>> {
    if entry.size_bytes > limit {
        anyhow::bail!("plaintext member exceeds read cap");
    }
    let crc = entry
        .crc32
        .ok_or_else(|| anyhow::anyhow!("missing plaintext CRC"))?;
    let bytes = read_indexed_member(data, entry, limit)?;
    if bytes.len() as u64 != entry.size_bytes || crc32fast::hash(&bytes) != crc {
        anyhow::bail!("encrypted member is not verified plaintext");
    }
    Ok(bytes)
}

/// Keep truly encrypted APKs on the existing password path. Probe only a
/// bounded set of flagged files, without allowing one fake flag to suppress
/// every ordinary DEX member or force extraction through filesystem collisions.
pub(super) fn only_plaintext_encryption_flags(data: &[u8], entries: &[ArchiveEntry]) -> bool {
    let mut remaining = 32 * 1024 * 1024u64;
    let mut seen = 0usize;
    for entry in entries
        .iter()
        .filter(|e| e.encrypted && e.entry_type.as_deref() != Some("directory"))
    {
        seen += 1;
        if seen > 128
            || entry.size_bytes > remaining
            || entry.size_bytes > entry.compressed_size.unwrap_or(0).saturating_mul(1000)
            || read_verified_plaintext_member(data, entry, remaining).is_err()
        {
            return false;
        }
        remaining -= entry.size_bytes;
    }
    seen > 0
}

#[cfg(test)]
mod plaintext_flag_tests {
    use super::*;

    fn entry(bytes: &[u8]) -> ArchiveEntry {
        ArchiveEntry {
            path: "classes.dex".into(),
            size_bytes: bytes.len() as u64,
            compressed_size: Some(bytes.len() as u64),
            data_offset: Some(0),
            compression_method: Some("stored".into()),
            encrypted: true,
            crc32: Some(crc32fast::hash(bytes)),
            ..Default::default()
        }
    }

    #[test]
    fn false_flags_require_complete_size_crc_and_budget() -> Result<()> {
        let bytes = b"plaintext member";
        let mut e = entry(bytes);
        assert_eq!(read_verified_plaintext_member(bytes, &e, 100)?, bytes);
        assert!(only_plaintext_encryption_flags(bytes, &[e.clone()]));
        assert!(read_verified_plaintext_member(bytes, &e, 3).is_err());
        e.crc32 = Some(1);
        assert!(!only_plaintext_encryption_flags(bytes, &[e.clone()]));
        e = entry(bytes);
        e.size_bytes += 1;
        assert!(read_verified_plaintext_member(bytes, &e, 100).is_err());
        e = entry(bytes);
        e.data_offset = Some(u64::MAX);
        assert!(read_verified_plaintext_member(bytes, &e, 100).is_err());
        assert!(!only_plaintext_encryption_flags(bytes, &[]));
        assert!(!only_plaintext_encryption_flags(
            bytes,
            &vec![entry(bytes); 129]
        ));
        e = entry(bytes);
        e.size_bytes = 33 * 1024 * 1024;
        assert!(!only_plaintext_encryption_flags(bytes, &[e]));
        Ok(())
    }
}
