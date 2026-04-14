//! System package format handlers.
//!
//! This module handles OS-specific package formats:
//! - Debian packages (.deb)
//! - RPM packages (.rpm)
//! - macOS packages (.pkg)
//! - 7-Zip archives (.7z)
//! - RAR archives (.rar)
//! - Windows cabinet (.cab)
//! - Standalone compression (.gz, .xz, .bz2)

use std::io::Seek;

use super::guards::{
    sanitize_entry_path, symlink_escapes, CancellableWriter, ExtractionGuard, HostileArchiveReason,
    LimitedReader, MAX_FILE_SIZE,
};
use super::tar::extract_tar_entries_safe;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;

fn extract_7z_entry_safe<R: Read + ?Sized>(
    entry: &sevenz_rust::SevenZArchiveEntry,
    reader: &mut R,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> std::result::Result<bool, sevenz_rust::Error> {
    use std::fs;

    // Check file count limit
    if !guard.check_file_count() {
        return Err(sevenz_rust::Error::other("Exceeded maximum file count"));
    }

    let name = entry.name();

    // Skip entries with empty names
    if name.is_empty() {
        return Ok(true);
    }

    // Sanitize path to prevent path traversal
    let Some(outpath) = sanitize_entry_path(name, dest_dir) else {
        guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.to_string()));
        return Ok(true); // Continue extraction
    };

    // Check if entry is a directory
    if entry.is_directory() {
        fs::create_dir_all(&outpath)
            .map_err(|e| sevenz_rust::Error::other(format!("mkdir failed: {}", e)))?;
        return Ok(true);
    }

    // Check size limits
    let uncompressed = entry.size();
    if uncompressed > MAX_FILE_SIZE {
        guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
            file: name.to_string(),
            size: uncompressed,
        });
        return Ok(true); // Skip but continue
    }

    // Create parent directory
    if let Some(parent) = outpath.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| sevenz_rust::Error::other(format!("mkdir failed: {}", e)))?;
    }

    // Extract file with size limiting and cancellation checks every 64 KiB.
    // A single large entry can take minutes without these checks.
    let mut limited_reader = LimitedReader::new(reader, uncompressed);
    let mut output = File::create(&outpath)
        .map_err(|e| sevenz_rust::Error::other(format!("create file failed: {}", e)))?;

    let mut buf = [0u8; 65536];
    let mut written = 0u64;
    loop {
        if guard.is_cancelled() {
            return Err(sevenz_rust::Error::other("cancelled"));
        }
        let n = limited_reader
            .read(&mut buf)
            .map_err(|e| sevenz_rust::Error::other(format!("read failed: {e}")))?;
        if n == 0 {
            break;
        }
        output
            .write_all(&buf[..n])
            .map_err(|e| sevenz_rust::Error::other(format!("write failed: {e}")))?;
        written += n as u64;
    }

    // Track total bytes
    if !guard.check_bytes(written, name) {
        return Err(sevenz_rust::Error::other(
            "Exceeded maximum total extraction size",
        ));
    }

    Ok(true) // Continue
}

/// Extract a 7z archive from in-memory data.
///
/// Password retry re-creates the cursor over the same slice — no disk I/O.
pub(crate) fn extract_7z_from_data(
    data: &[u8],
    dest_dir: &Path,
    guard: &ExtractionGuard,
    zip_passwords: &[String],
) -> Result<()> {
    use sevenz_rust::{Password, SevenZReader};
    use std::io::Cursor;
    use tracing::{debug, info};

    let size = data.len() as u64;

    let result = (|| -> Result<()> {
        let mut sz = SevenZReader::new(Cursor::new(data), size, Password::empty())
            .context("Failed to create 7z reader")?;
        sz.for_each_entries(|entry, reader| extract_7z_entry_safe(entry, reader, dest_dir, guard))
            .map_err(|e| anyhow::anyhow!(e))
            .context("Failed to extract 7z archive")
    })();

    let err = match result {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };

    // Check the full error chain (not just the outermost message) so we catch
    // PasswordRequired even when it's wrapped by a context like "Failed to create 7z reader".
    let is_password_error = err.chain().any(|e| {
        let s = e.to_string();
        s.contains("Password")
            || s.contains("encrypted")
            || s.contains("decryption")
            || s.contains("Invalid password")
    });

    if is_password_error {
        info!(
            "7z archive appears encrypted, trying {} passwords",
            zip_passwords.len()
        );
        for password in zip_passwords {
            debug!("Trying 7z password ({}B)", password.len());
            let password_obj = Password::from(password.as_str());
            if let Ok(mut sz) = SevenZReader::new(Cursor::new(data), size, password_obj) {
                if sz
                    .for_each_entries(|entry, reader| {
                        extract_7z_entry_safe(entry, reader, dest_dir, guard)
                    })
                    .is_ok()
                {
                    info!("✓ Decrypted 7z with password");
                    return Ok(());
                }
            }
        }
        anyhow::bail!(
            "Failed to decrypt 7z archive (tried {} passwords). Original error: {}",
            zip_passwords.len(),
            err
        );
    }

    Err(err).context("7z extraction failed")
}

/// Extract a macOS PKG (XAR) archive from an in-memory reader.
///
/// `data_len` is the byte length of the underlying data (used for ToC-size
/// validation to prevent allocation bombs from malformed headers).
pub(crate) fn extract_pkg_from_reader<R: Read + Seek + std::fmt::Debug>(
    mut reader: R,
    data_len: u64,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    // Validate XAR header before calling XarReader::new(), which allocates
    // based on the toc_length_compressed field.
    {
        let mut header = [0u8; 28];
        if reader.read_exact(&mut header).is_err() {
            anyhow::bail!("PKG file too small for XAR header");
        }
        if &header[0..4] != b"xar!" {
            anyhow::bail!("Not a valid XAR/PKG file (bad magic)");
        }
        let toc_compressed = u64::from_be_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| anyhow::anyhow!("XAR header too short"))?,
        );
        if toc_compressed > data_len {
            anyhow::bail!(
                "XAR header claims compressed ToC is {} bytes but data is only {} bytes",
                toc_compressed,
                data_len
            );
        }
        reader.seek(std::io::SeekFrom::Start(0))?;
    }

    let mut xar =
        apple_xar::reader::XarReader::new(reader).context("Failed to read PKG (XAR) archive")?;

    // Get all files in the archive
    let files = xar.files().context("Failed to list XAR files")?;

    for (path, file_entry) in files {
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }

        // Sanitize path
        let Some(out_path) = sanitize_entry_path(&path, dest_dir) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(path.clone()));
            continue;
        };

        // Check file size
        if let Some(size) = file_entry.size {
            if size > MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: path.clone(),
                    size,
                });
                continue;
            }
        }

        // Check symlinks and hardlinks
        use apple_xar::table_of_contents::FileType as XarFileType;
        if matches!(
            file_entry.file_type,
            XarFileType::Link | XarFileType::HardLink
        ) {
            // For XAR files, we conservatively flag all symlinks as potentially escaping
            // TODO: Extract link target from XAR metadata if apple_xar exposes it
            guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(path.clone()));
            // Skip symlinks regardless (we don't extract them)
            continue;
        }

        // Create parent directories
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Extract file; wrap the output so cancellation interrupts the C library
        // call on the next write boundary (typically every decompressed chunk).
        let mut output = File::create(&out_path)?;
        let written = if let Some(cancelled) = guard.cancellation() {
            let mut cw = CancellableWriter::new(&mut output, cancelled);
            xar.write_file_data_decoded_from_file(&file_entry, &mut cw)
                .context(format!("Failed to extract file: {}", path))? as u64
        } else {
            xar.write_file_data_decoded_from_file(&file_entry, &mut output)
                .context(format!("Failed to extract file: {}", path))? as u64
        };

        if !guard.check_bytes(written, &path) {
            anyhow::bail!("Exceeded maximum total extraction size");
        }
    }

    Ok(())
}

/// Extract a Debian package from an in-memory reader.
pub(crate) fn extract_deb_from_reader<R: Read>(
    reader: R,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    let mut archive = ar::Archive::new(reader);

    while let Some(entry_result) = archive.next_entry() {
        let mut entry = entry_result.context("Failed to read AR entry")?;
        let name = String::from_utf8_lossy(entry.header().identifier()).to_string();

        // We're mainly interested in data.tar.* which contains the actual files
        if name.starts_with("data.tar") {
            let sub_dest = dest_dir.join("data");
            fs::create_dir_all(&sub_dest)?;

            if name.ends_with(".gz") {
                let decoder = flate2::read::GzDecoder::new(&mut entry);
                extract_tar_entries_safe(decoder, &sub_dest, guard)?;
            } else if name.ends_with(".xz") {
                let decoder = xz2::read::XzDecoder::new(&mut entry);
                extract_tar_entries_safe(decoder, &sub_dest, guard)?;
            } else if name.ends_with(".zst") {
                let decoder = zstd::stream::read::Decoder::new(&mut entry)
                    .context("Failed to create zstd decoder")?;
                extract_tar_entries_safe(decoder, &sub_dest, guard)?;
            } else if name == "data.tar" {
                extract_tar_entries_safe(&mut entry, &sub_dest, guard)?;
            } else if name.ends_with(".bz2") {
                let decoder = bzip2::read::BzDecoder::new(&mut entry);
                extract_tar_entries_safe(decoder, &sub_dest, guard)?;
            }
        } else if name.starts_with("control.tar") {
            // Also extract control files for analysis
            let sub_dest = dest_dir.join("control");
            fs::create_dir_all(&sub_dest)?;

            if name.ends_with(".gz") {
                let decoder = flate2::read::GzDecoder::new(&mut entry);
                extract_tar_entries_safe(decoder, &sub_dest, guard)?;
            } else if name.ends_with(".xz") {
                let decoder = xz2::read::XzDecoder::new(&mut entry);
                extract_tar_entries_safe(decoder, &sub_dest, guard)?;
            } else if name.ends_with(".zst") {
                let decoder = zstd::stream::read::Decoder::new(&mut entry)
                    .context("Failed to create zstd decoder")?;
                extract_tar_entries_safe(decoder, &sub_dest, guard)?;
            } else if name == "control.tar" {
                extract_tar_entries_safe(&mut entry, &sub_dest, guard)?;
            }
        }
    }

    Ok(())
}

/// Extract an RPM package from an in-memory reader.
pub(crate) fn extract_rpm_from_reader<R: Read>(
    reader: R,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    let mut reader = BufReader::new(reader);

    // RPM magic: 0xedabeedb
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != [0xed, 0xab, 0xee, 0xdb] {
        anyhow::bail!("Not a valid RPM file (invalid magic)");
    }

    // Read RPM lead (96 bytes total, we already read 4)
    let mut lead_rest = [0u8; 92];
    reader.read_exact(&mut lead_rest)?;

    // Skip signature header and get its size
    let sig_size = skip_rpm_header(&mut reader)?;

    // Align to 8-byte boundary after signature
    let pos = sig_size;
    let padding = (8 - (pos % 8)) % 8;
    if padding > 0 {
        let mut pad = vec![0u8; padding];
        reader.read_exact(&mut pad)?;
    }

    // Skip main header
    skip_rpm_header(&mut reader)?;

    // The rest is the CPIO archive, possibly compressed
    // Try to detect compression by reading first bytes
    let mut peek = [0u8; 6];
    reader.read_exact(&mut peek)?;

    // Create a chain reader with the peeked bytes
    let peek_cursor = std::io::Cursor::new(peek.to_vec());
    let chained = peek_cursor.chain(reader);

    // Detect compression and extract
    if peek[0..2] == [0x1f, 0x8b] {
        // gzip
        let decoder = flate2::read::GzDecoder::new(chained);
        extract_cpio(decoder, dest_dir, guard)?;
    } else if peek[0..3] == [0xfd, 0x37, 0x7a] {
        // xz
        let decoder = xz2::read::XzDecoder::new(chained);
        extract_cpio(decoder, dest_dir, guard)?;
    } else if peek[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        // zstd
        let decoder =
            zstd::stream::read::Decoder::new(chained).context("Failed to create zstd decoder")?;
        extract_cpio(decoder, dest_dir, guard)?;
    } else if peek[0..3] == [0x42, 0x5a, 0x68] {
        // bzip2
        let decoder = bzip2::read::BzDecoder::new(chained);
        extract_cpio(decoder, dest_dir, guard)?;
    } else if peek[0..2] == [0x5d, 0x00] {
        // LZMA (legacy) - try xz decoder
        let decoder = xz2::read::XzDecoder::new(chained);
        extract_cpio(decoder, dest_dir, guard)?;
    } else {
        // Uncompressed CPIO
        extract_cpio(chained, dest_dir, guard)?;
    }

    Ok(())
}

/// Maximum RPM header size to prevent allocation bombs from crafted headers.
/// Real RPM headers are typically under 1MB; 16MB is generous.
const MAX_RPM_HEADER_SIZE: usize = 16 * 1024 * 1024;

fn skip_rpm_header<R: Read>(reader: &mut R) -> Result<usize> {
    // Header magic
    let mut magic = [0u8; 3];
    reader.read_exact(&mut magic)?;
    if magic != [0x8e, 0xad, 0xe8] {
        anyhow::bail!("Invalid RPM header magic");
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;

    // Reserved
    let mut reserved = [0u8; 4];
    reader.read_exact(&mut reserved)?;

    // Number of index entries (big-endian)
    let mut nindex = [0u8; 4];
    reader.read_exact(&mut nindex)?;
    let nindex = u32::from_be_bytes(nindex) as usize;

    // Size of data section (big-endian)
    let mut hsize = [0u8; 4];
    reader.read_exact(&mut hsize)?;
    let hsize = u32::from_be_bytes(hsize) as usize;

    // Bounds-check before allocating to prevent crafted headers from causing
    // multi-gigabyte allocations (nindex and hsize are attacker-controlled u32s).
    let index_size = nindex.saturating_mul(16);
    if index_size > MAX_RPM_HEADER_SIZE || hsize > MAX_RPM_HEADER_SIZE {
        anyhow::bail!(
            "RPM header too large (index: {} bytes, data: {} bytes)",
            index_size,
            hsize
        );
    }

    // Skip index entries (16 bytes each)
    let mut index_data = vec![0u8; index_size];
    reader.read_exact(&mut index_data)?;

    // Skip data section
    let mut data = vec![0u8; hsize];
    reader.read_exact(&mut data)?;

    // Return total header size (16 for header + index + data)
    Ok(16 + index_size + hsize)
}

fn extract_cpio<R: Read>(mut reader: R, dest_dir: &Path, guard: &ExtractionGuard) -> Result<()> {
    loop {
        // Check file count limit
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }

        // Try to read next CPIO entry
        let entry_reader = match cpio::newc::Reader::new(&mut reader) {
            Ok(r) => r,
            Err(e) => {
                // End of archive or invalid entry
                if e.kind() == std::io::ErrorKind::InvalidData {
                    break;
                }
                return Err(e.into());
            }
        };

        let entry = entry_reader.entry();
        let name = entry.name().to_string();

        if name == "TRAILER!!!" {
            break;
        }

        // Skip . and empty entries
        if name.is_empty() || name == "." {
            // Consume remaining data to advance reader
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
            continue;
        }

        // Clean up path (remove leading ./ or /)
        let clean_name = name.trim_start_matches("./").trim_start_matches('/');
        if clean_name.is_empty() {
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
            continue;
        }

        // Sanitize path to prevent traversal
        let Some(out_path) = sanitize_entry_path(clean_name, dest_dir) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.clone()));
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
            continue;
        };

        let mode = entry.mode();
        let file_size = entry.file_size() as u64;

        // Check file size limit
        if file_size > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: clean_name.to_string(),
                size: file_size,
            });
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
            continue;
        }

        if mode & 0o170000 == 0o040000 {
            // Directory
            fs::create_dir_all(&out_path).ok();
            // Consume remaining data
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
        } else if mode & 0o170000 == 0o100000 {
            // Regular file
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = File::create(&out_path)?;
            let mut limited = LimitedReader::new(entry_reader, MAX_FILE_SIZE);
            // Check cancellation every 64 KiB so a large single entry doesn't
            // block indefinitely after a timeout fires.
            let mut buf = [0u8; 65536];
            let mut written = 0u64;
            loop {
                if guard.is_cancelled() {
                    anyhow::bail!("cancelled");
                }
                let n = limited.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                file.write_all(&buf[..n])?;
                written += n as u64;
            }

            // Track total bytes
            if !guard.check_bytes(written, clean_name) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
        } else if mode & 0o170000 == 0o120000 {
            // Symlink - target is stored as file data
            let mut target_buf = Vec::new();
            if file_size > 0 && file_size < 4096 {
                // Reasonable symlink path length
                let mut limited = LimitedReader::new(entry_reader, file_size.min(4096));
                if limited.read_to_end(&mut target_buf).is_ok() {
                    if let Ok(target_str) = String::from_utf8(target_buf) {
                        if symlink_escapes(&out_path, &target_str, dest_dir) {
                            guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                                "{} -> {}",
                                clean_name, target_str
                            )));
                        }
                    }
                }
            } else {
                // Consume the entry data
                let mut sink = std::io::sink();
                std::io::copy(&mut { entry_reader }, &mut sink).ok();
            }
        } else {
            // Skip other types (devices, etc.)
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
        }
    }

    Ok(())
}

/// Extract a RAR archive (.rar) with bomb protection
pub(crate) fn extract_rar(
    archive_path: &Path,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    let mut archive = unrar::Archive::new(archive_path)
        .open_for_processing()
        .context("Failed to open RAR archive")?;

    loop {
        // Check file count limit
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }

        // Read the next header
        let header_result = archive.read_header();
        match header_result {
            Ok(Some(file_archive)) => {
                let header = file_archive.entry();
                let filename = header.filename.to_string_lossy().to_string();
                let is_file = header.is_file();
                let is_directory = header.is_directory();
                let unpacked_size = header.unpacked_size;

                if is_file {
                    // Check file size limit
                    if unpacked_size > MAX_FILE_SIZE {
                        guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                            file: filename.clone(),
                            size: unpacked_size,
                        });
                        archive = file_archive.skip().context("Failed to skip RAR entry")?;
                        continue;
                    }

                    // Note: RAR unrar crate doesn't expose packed_size, so we can't check
                    // compression ratio directly. We rely on unpacked_size limit above.

                    // Sanitize path
                    let Some(out_path) = sanitize_entry_path(&filename, dest_dir) else {
                        guard.add_hostile_reason(HostileArchiveReason::PathTraversal(
                            filename.clone(),
                        ));
                        archive = file_archive.skip().context("Failed to skip RAR entry")?;
                        continue;
                    };

                    // Create parent directories
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    // Extract the file
                    archive = file_archive
                        .extract_to(&out_path)
                        .context("Failed to extract RAR entry")?;

                    // Track bytes
                    if !guard.check_bytes(unpacked_size, &filename) {
                        anyhow::bail!("Exceeded maximum total extraction size");
                    }
                } else if is_directory {
                    let Some(dir_path) = sanitize_entry_path(&filename, dest_dir) else {
                        guard.add_hostile_reason(HostileArchiveReason::PathTraversal(
                            filename.clone(),
                        ));
                        archive = file_archive.skip().context("Failed to skip RAR entry")?;
                        continue;
                    };
                    fs::create_dir_all(&dir_path)?;
                    archive = file_archive
                        .skip()
                        .context("Failed to skip RAR directory")?;
                } else {
                    archive = file_archive.skip().context("Failed to skip RAR entry")?;
                }
            }
            Ok(None) => break, // No more entries
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// Extract a Windows CAB archive from an in-memory reader.
pub(crate) fn extract_cab_from_reader<R: Read + Seek>(
    reader: R,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    let mut cabinet = cab::Cabinet::new(reader).context("Failed to parse CAB archive")?;

    // Collect file names first (cab crate requires sequential access per folder).
    // Cap at 200k entries to prevent OOM from malformed CAB headers.
    let file_names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries().map(|f| f.name().to_string()))
        .take(200_000)
        .collect();

    for name in &file_names {
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }

        let Some(out_path) = sanitize_entry_path(name, dest_dir) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.clone()));
            continue;
        };

        let mut reader = cabinet
            .read_file(name)
            .with_context(|| format!("Failed to read CAB entry: {name}"))?;

        // Read into a size-limited buffer; check cancellation every 64 KiB.
        let mut buf = Vec::new();
        {
            let mut limited = LimitedReader::new(&mut reader, MAX_FILE_SIZE);
            let mut chunk = [0u8; 65536];
            loop {
                if guard.is_cancelled() {
                    anyhow::bail!("cancelled");
                }
                let n = limited
                    .read(&mut chunk)
                    .with_context(|| format!("Failed to decompress CAB entry: {name}"))?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            if limited.is_limited() {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: name.clone(),
                    size: MAX_FILE_SIZE,
                });
                continue;
            }
        }

        if !guard.check_bytes(buf.len() as u64, name) {
            anyhow::bail!("Exceeded maximum total extraction size");
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut out_file =
            File::create(&out_path).with_context(|| format!("Failed to create {out_path:?}"))?;
        out_file.write_all(&buf)?;
    }

    Ok(())
}
