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
    MAX_FILE_SIZE, MAX_PATH_COMPONENT_LEN,
};
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

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

        if entry_name.len() > MAX_PATH_COMPONENT_LEN {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                len: entry_name.len(),
                preview: entry_name.chars().take(80).collect(),
            });
        }

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
            // Check cancellation every 64 KiB so a large entry doesn't block
            // indefinitely after a timeout fires.
            let mut buf = [0u8; 65536];
            let mut written = 0u64;
            loop {
                if guard.is_cancelled() {
                    anyhow::bail!("cancelled");
                }
                let n = limited
                    .read(&mut buf)
                    .with_context(|| format!("Failed to extract: {}", entry_name))?;
                if n == 0 {
                    break;
                }
                outfile
                    .write_all(&buf[..n])
                    .with_context(|| format!("Failed to write: {}", entry_name))?;
                written += n as u64;
            }

            if limited.is_limited() {
                drop(outfile);
                let _ = fs::remove_file(&outpath);
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: entry_name.clone(),
                    size: MAX_FILE_SIZE,
                });
                continue;
            }

            if !guard.check_bytes(written, &entry_name) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
        }
    }

    Ok(())
}
