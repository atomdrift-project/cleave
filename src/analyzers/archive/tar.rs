//! TAR-based archive format handlers.
//!
//! This module handles TAR archives and compressed variants:
//! - Plain TAR (.tar)
//! - Gzip-compressed TAR (.tar.gz, .tgz)
//! - Bzip2-compressed TAR (.tar.bz2, .tbz2, .tbz)
//! - XZ-compressed TAR (.tar.xz, .txz)
//! - Zstd-compressed TAR (.tar.zst, .tzst)
//! - Ruby gems (.gem) - plain TAR format
//! - Rust crates (.crate) - TAR.GZ format
//! - Arch Linux packages (.pkg.tar.zst, .pkg.tar.xz)
//! - Void Linux packages (.xbps) - TAR.ZSTD format
//! - Alpine Linux packages (.apk) - TAR.GZ format (detected by magic)

use super::guards::{
    sanitize_entry_path, symlink_escapes, ExtractionGuard, HostileArchiveReason, LimitedReader,
    MAX_FILE_SIZE,
};
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Extract TAR archive with optional compression
pub(crate) fn extract_tar_safe(
    archive_path: &Path,
    dest_dir: &Path,
    compression: Option<&str>,
    guard: &ExtractionGuard,
) -> Result<()> {
    let file = File::open(archive_path)?;

    let reader: Box<dyn Read> = match compression {
        Some("gzip") => Box::new(flate2::read::GzDecoder::new(file)),
        Some("bzip2") => Box::new(bzip2::read::BzDecoder::new(file)),
        Some("xz") => Box::new(xz2::read::XzDecoder::new(file)),
        Some("zstd") => Box::new(
            zstd::stream::read::Decoder::new(file).context("Failed to create zstd decoder")?,
        ),
        None => Box::new(file),
        _ => anyhow::bail!("Unsupported compression: {:?}", compression),
    };

    let mut archive = tar::Archive::new(reader);

    for entry_result in archive.entries()? {
        // Check file count
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }

        let mut entry = entry_result.context("Failed to read tar entry")?;
        let entry_path = entry.path()?;
        let entry_name = entry_path.to_string_lossy().to_string();

        // Sanitize path
        let Some(outpath) = sanitize_entry_path(&entry_name, dest_dir) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
            continue;
        };

        // Check for symlinks - validate that target doesn't escape
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            if let Ok(Some(link_target)) = entry.link_name() {
                let target_str = link_target.to_string_lossy();
                if symlink_escapes(&outpath, &target_str, dest_dir) {
                    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                        "{} -> {}",
                        entry_name, target_str
                    )));
                }
            }
            // Skip symlinks regardless (we don't extract them)
            continue;
        }

        let size = entry.header().size()?;

        if entry_type.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else if entry_type.is_file() {
            // Check file size
            if size > MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: entry_name.clone(),
                    size,
                });
                continue;
            }

            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }

            // Extract with limit
            let mut outfile = File::create(&outpath)?;
            let mut limited = LimitedReader::new(&mut entry, MAX_FILE_SIZE);
            let written = std::io::copy(&mut limited, &mut outfile)
                .with_context(|| format!("Failed to extract: {}", entry_name))?;

            if !guard.check_bytes(written, &entry_name) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
        }
        // Skip other entry types (devices, fifos, etc.)
    }

    Ok(())
}

/// Helper to extract tar entries with guard protection (used by DEB extractor)
pub(crate) fn extract_tar_entries_safe<R: Read>(
    reader: R,
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    let mut archive = tar::Archive::new(reader);

    for entry_result in archive.entries()? {
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }

        let mut entry = entry_result.context("Failed to read tar entry")?;
        let entry_path = entry.path()?;
        let entry_name = entry_path.to_string_lossy().to_string();

        let Some(outpath) = sanitize_entry_path(&entry_name, dest_dir) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
            continue;
        };

        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            if let Ok(Some(link_target)) = entry.link_name() {
                let target_str = link_target.to_string_lossy();
                if symlink_escapes(&outpath, &target_str, dest_dir) {
                    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                        "{} -> {}",
                        entry_name, target_str
                    )));
                }
            }
            // Skip symlinks regardless (we don't extract them)
            continue;
        }

        let size = entry.header().size()?;

        if entry_type.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else if entry_type.is_file() {
            if size > MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: entry_name.clone(),
                    size,
                });
                continue;
            }

            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut outfile = File::create(&outpath)?;
            let mut limited = LimitedReader::new(&mut entry, MAX_FILE_SIZE);
            let written = std::io::copy(&mut limited, &mut outfile)
                .with_context(|| format!("Failed to extract: {}", entry_name))?;

            if !guard.check_bytes(written, &entry_name) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
        }
    }

    Ok(())
}
