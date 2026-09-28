//! Bounded extraction of SquashFS images (including Snap packages).

use super::guards::{
    ExtractionGuard, HostileArchiveReason, MAX_ARCHIVE_MEMBER_DEPTH, MAX_FILE_SIZE,
    sanitize_entry_path, symlink_escapes,
};
use anyhow::{Context, Result};
use fs_core::FileDevice;
use fs_squashfs::{FileType as SquashFsType, Filesystem};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

const READ_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Extract regular files and directories from a SquashFS image. Symlinks and
/// special files are inspected but never created on disk, so later filesystem
/// operations cannot follow an archive-provided link out of the extraction root.
pub(crate) fn extract_from_data(
    data: &[u8],
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    // The reader needs random access and owns its block device. Back it with a
    // temporary file so large Snap images do not require a second in-memory copy.
    let mut image = tempfile::Builder::new().suffix(".squashfs").tempfile()?;
    image
        .write_all(data)
        .context("Failed to spool SquashFS image")?;
    let device = Arc::new(FileDevice::open(image.path()).context("Failed to open SquashFS image")?);
    let filesystem = Filesystem::open(device).context("Failed to parse SquashFS image")?;
    let mut pending_dirs = vec![(String::new(), filesystem.root_inode()?, 0usize)];
    let mut buffer = Vec::new();

    while let Some((parent, directory, depth)) = pending_dirs.pop() {
        if guard.is_cancelled() {
            anyhow::bail!("SquashFS extraction cancelled");
        }
        let entries = match filesystem.read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                guard.add_extraction_note(format!("SquashFS directory {parent:?}: {error}"));
                continue;
            }
        };

        for entry in entries {
            if !guard.check_file_count() {
                anyhow::bail!("Exceeded maximum SquashFS member count");
            }
            let name = entry_name(&entry.name);
            let archive_path = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };
            let Some(output_path) = sanitize_entry_path(&archive_path, dest_dir) else {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(archive_path));
                continue;
            };
            let inode = match filesystem.read_inode(entry.inode_ref) {
                Ok(inode) => inode,
                Err(error) => {
                    guard.add_extraction_note(format!("SquashFS inode {archive_path:?}: {error}"));
                    continue;
                }
            };

            match inode.file_type() {
                SquashFsType::Dir => {
                    if depth >= MAX_ARCHIVE_MEMBER_DEPTH {
                        guard.add_extraction_note(format!(
                            "SquashFS member depth exceeded at {archive_path:?}"
                        ));
                        continue;
                    }
                    fs::create_dir_all(&output_path)
                        .with_context(|| format!("Failed to create {archive_path:?}"))?;
                    pending_dirs.push((archive_path, inode, depth + 1));
                }
                SquashFsType::Symlink => {
                    if let Ok(target) = std::str::from_utf8(&inode.symlink_target)
                        && symlink_escapes(&output_path, target, dest_dir)
                    {
                        guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(archive_path));
                    }
                }
                SquashFsType::RegFile => {
                    let size = inode.file_size;
                    if size > MAX_FILE_SIZE {
                        guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                            file: archive_path,
                            size,
                        });
                        continue;
                    }
                    let output_path = guard.claim_output_path(output_path);
                    let Some(parent_dir) = output_path.parent() else {
                        guard.add_extraction_note(format!(
                            "SquashFS member has no parent: {archive_path:?}"
                        ));
                        continue;
                    };
                    fs::create_dir_all(parent_dir)
                        .with_context(|| format!("Failed to create parent for {archive_path:?}"))?;
                    let mut output = File::create(&output_path)
                        .with_context(|| format!("Failed to create {archive_path:?}"))?;
                    buffer.resize(size.min(READ_CHUNK_SIZE as u64) as usize, 0);
                    let mut offset = 0u64;
                    while offset < size {
                        if guard.is_cancelled() {
                            anyhow::bail!("SquashFS extraction cancelled");
                        }
                        let requested = buffer.len().min((size - offset) as usize);
                        let count = filesystem
                            .read_file(&inode, offset, &mut buffer[..requested])
                            .with_context(|| format!("Failed to read {archive_path:?}"))?;
                        if count == 0 {
                            guard.add_extraction_note(format!(
                                "SquashFS file {archive_path:?} ended at {offset} of {size} bytes"
                            ));
                            break;
                        }
                        output.write_all(&buffer[..count])?;
                        if !guard.check_bytes(count as u64, &archive_path) {
                            anyhow::bail!("Exceeded maximum SquashFS extraction size");
                        }
                        offset += count as u64;
                    }
                    output.flush()?;
                }
                SquashFsType::CharDev
                | SquashFsType::BlockDev
                | SquashFsType::Fifo
                | SquashFsType::Socket
                | SquashFsType::Unknown => {
                    // These entries have no regular file contents to analyze;
                    // never instantiate devices, pipes, or sockets from input.
                }
            }
        }
    }
    Ok(())
}

fn entry_name(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(name) => name.to_string(),
        Err(_) => raw.iter().map(|byte| format!("%{byte:02X}")).collect(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use backhand::v4::compressor::Compressor;
    use backhand::{FilesystemCompressor, FilesystemWriter, NodeHeader};
    use std::io::Cursor;

    fn fixture() -> Vec<u8> {
        let mut writer = FilesystemWriter::default();
        writer.set_compressor(FilesystemCompressor::new(Compressor::Gzip, None).unwrap());
        let header = NodeHeader::default();
        writer.push_dir_all("usr/bin", header).unwrap();
        writer
            .push_file(
                Cursor::new(b"compiler payload".to_vec()),
                "usr/bin/kotlinc",
                header,
            )
            .unwrap();
        writer
            .push_symlink("../../../outside", "usr/bin/escape", header)
            .unwrap();
        let mut image = Cursor::new(Vec::new());
        writer.write(&mut image).unwrap();
        image.into_inner()
    }

    #[test]
    fn extracts_squashfs_files_and_never_materializes_symlinks() {
        let image = fixture();
        let temp = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();

        extract_from_data(&image, temp.path(), &guard).unwrap();

        assert_eq!(
            fs::read(temp.path().join("usr/bin/kotlinc")).unwrap(),
            b"compiler payload"
        );
        assert!(!temp.path().join("usr/bin/escape").exists());
        assert!(!temp.path().parent().unwrap().join("outside").exists());
        assert!(matches!(
            guard.take_reasons().as_slice(),
            [HostileArchiveReason::SymlinkEscape(_)]
        ));
    }

    #[test]
    fn rejects_non_squashfs_input() {
        let temp = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        assert!(extract_from_data(b"not squashfs", temp.path(), &guard).is_err());
    }
}
