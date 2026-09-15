//! Materialize the bounded CPIO extents indexed by filefacts. No header parser
//! or package execution lives here; links and special files are never created.

use super::guards::{
    ExtractedMemberMetadata, ExtractionGuard, HostileArchiveReason, MAX_FILE_SIZE,
    sanitize_entry_path, symlink_escapes,
};
use crate::types::ArchiveEntry;
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub(crate) fn extract_from_data(
    data: &[u8],
    members: &[ArchiveEntry],
    dest: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    for member in members {
        if guard.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }
        let name = member.path.as_str();
        if matches!(name, "" | "." | "./") {
            continue;
        }
        let Some(path) = sanitize_entry_path(name, dest) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.into()));
            continue;
        };
        let entry_type = member.entry_type.as_deref();
        let path = if entry_type == Some("directory") {
            path
        } else {
            guard.claim_output_path(path)
        };
        guard.record_member_metadata(ExtractedMemberMetadata {
            archive_path: path.strip_prefix(dest)?.to_string_lossy().into_owned(),
            mtime_unix: member.mtime_unix,
            mode_octal: member.mode_octal,
            uid: member.uid,
            gid: member.gid,
            entry_type: member.entry_type.clone(),
            linkname: member.linkname.clone(),
            ..Default::default()
        });
        match entry_type {
            Some("directory") => {
                fs::create_dir_all(&path)?;
                continue;
            }
            Some("symlink") => {
                if member
                    .linkname
                    .as_ref()
                    .is_some_and(|target| symlink_escapes(&path, target, dest))
                {
                    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(name.into()));
                }
                continue;
            }
            Some("regular") => {}
            _ => continue,
        }
        if member.size_bytes > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: name.into(),
                size: member.size_bytes,
            });
            anyhow::bail!("Exceeded maximum CPIO file size");
        }
        let offset = member
            .data_offset
            .context("CPIO member has no data extent")?;
        let start = usize::try_from(offset)?;
        let len = usize::try_from(member.size_bytes)?;
        let end = start.checked_add(len).context("CPIO extent overflow")?;
        let payload = data.get(start..end).context("CPIO extent outside input")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Refuse even a pathological collision fallback rather than overwrite
        // evidence. Permissions remain non-executable regardless of archive mode.
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        for chunk in payload.chunks(65536) {
            if guard.is_cancelled() {
                anyhow::bail!("cancelled");
            }
            if !guard.check_bytes(chunk.len() as u64, name) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
            out.write_all(chunk)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(name: &str, kind: &str, offset: u64, len: u64) -> ArchiveEntry {
        ArchiveEntry {
            path: name.into(),
            entry_type: Some(kind.into()),
            data_offset: Some(offset),
            size_bytes: len,
            ..Default::default()
        }
    }

    #[test]
    fn later_and_duplicate_members_survive_unsafe_paths_and_links() {
        let dir = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        let mut link = entry("link", "symlink", 0, 0);
        link.linkname = Some("../../outside".into());
        let members = [
            entry("../outside", "regular", 0, 1),
            entry("/absolute", "regular", 0, 1),
            link,
            entry("pipe", "fifo", 0, 0),
            entry("./same", "regular", 0, 1),
            entry("same", "regular", 1, 1),
        ];
        extract_from_data(b"ab", &members, dir.path(), &guard).unwrap();
        assert_eq!(fs::read(dir.path().join("same")).unwrap(), b"a");
        assert_eq!(fs::read(dir.path().join("same~2")).unwrap(), b"b");
        assert!(!dir.path().join("link").exists());
        assert!(!dir.path().join("pipe").exists());
        assert_eq!(guard.take_reasons().len(), 3);
    }

    #[test]
    fn invalid_extents_and_cancellation_fail_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        for member in [
            entry("bad", "regular", u64::MAX, 4),
            entry("bad", "regular", 1, 4),
        ] {
            assert!(
                extract_from_data(b"a", &[member], dir.path(), &ExtractionGuard::new()).is_err()
            );
        }
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let guard = ExtractionGuard::with_cancellation(Some(cancelled));
        assert!(
            extract_from_data(b"a", &[entry("later", "regular", 0, 1)], dir.path(), &guard)
                .is_err()
        );
        assert!(!dir.path().join("later").exists());
    }

    #[test]
    fn total_byte_budget_applies_before_writing_payload() {
        let dir = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        assert!(guard.check_bytes(super::super::guards::MAX_TOTAL_SIZE, "prior members"));
        assert!(
            extract_from_data(b"a", &[entry("later", "regular", 0, 1)], dir.path(), &guard)
                .is_err()
        );
        assert_eq!(fs::read(dir.path().join("later")).unwrap(), b"");
        assert!(
            guard
                .take_reasons()
                .iter()
                .any(|reason| matches!(reason, HostileArchiveReason::ExcessiveTotalSize(_)))
        );
    }

    #[cfg(unix)]
    #[test]
    fn archived_executable_mode_does_not_make_extracted_files_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut member = entry("script", "regular", 0, 1);
        member.mode_octal = Some(0o100777);
        extract_from_data(b"x", &[member], dir.path(), &ExtractionGuard::new()).unwrap();
        assert_eq!(
            fs::metadata(dir.path().join("script"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}
