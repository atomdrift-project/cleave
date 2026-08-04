//! Optical-disc image (`.iso`) member extraction.
//!
//! ISO 9660 and UDF store file data verbatim in addressable sector runs, so
//! there is nothing to decompress: every member is a byte range of the image
//! that filefacts already located while reading the descriptors. Extraction
//! is therefore a bounded copy out of the buffer cleave has in hand — no
//! second parse of the image, no decoder, and no dependency on an external
//! `7z`.
//!
//! (The previous route sent ISOs to `sevenz_rust`, which reads the `.7z`
//! container format only. It rejected every image at the signature check,
//! which is why no ISO member was ever analysed.)
//!
//! Members whose bytes are *not* one contiguous range — interleaved
//! recording, or a multi-extent file split across the image — arrive here
//! with no data offset and are skipped rather than mis-sliced. They stay
//! visible in the report through the container's `iso.files[]` facts.
//!
//! The member list also carries the image's *unclaimed* byte ranges (entry
//! type `slack` / `trailing`) — space no descriptor, path table, directory,
//! or file extent accounts for. Those are extracted like any other member,
//! so a payload parked where a file listing will never show it still gets
//! identified and analysed on its own.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

use super::guards::{
    ExtractedMemberMetadata, ExtractionGuard, HostileArchiveReason, MAX_FILE_SIZE,
    MAX_PATH_COMPONENT_LEN, sanitize_entry_path,
};
use crate::types::ArchiveEntry;

/// Copy each ISO member out of `data` into `dest_dir`.
///
/// `members` is the filefacts member list for this image, which the archive
/// analyzer has already computed for the report — the extents are read once
/// per image, not once per consumer.
pub(crate) fn extract_iso_from_data(
    data: &[u8],
    members: &[ArchiveEntry],
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    if members.is_empty() {
        anyhow::bail!("no ISO 9660 or UDF directory entries");
    }

    let mut extracted = 0_usize;
    for member in members {
        if guard.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }

        let name = member.path.as_str();
        if name.len() > MAX_PATH_COMPONENT_LEN {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                len: name.len(),
                preview: name.chars().take(80).collect(),
            });
        }
        let Some(outpath) = sanitize_entry_path(name, dest_dir) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.to_string()));
            continue;
        };
        let rel_path = outpath
            .strip_prefix(dest_dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| name.to_string());

        guard.record_member_metadata(ExtractedMemberMetadata {
            archive_path: rel_path,
            // Stored verbatim: there is no compressed size distinct from the
            // real one, and no per-member codec.
            compressed_size: None,
            compression_method: None,
            mtime_unix: member.mtime_unix,
            mode_octal: member.mode_octal,
            uid: member.uid,
            gid: member.gid,
            uname: None,
            gname: None,
            entry_type: member.entry_type.clone(),
            linkname: member.linkname.clone(),
            host_os: member.host_os.clone(),
        });

        match member.entry_type.as_deref() {
            Some("directory") => {
                fs::create_dir_all(&outpath)
                    .with_context(|| format!("Failed to create directory: {name}"))?;
                continue;
            }
            // Rock Ridge symlinks name a path on the *mounting* host, not a
            // member of the image; there is nothing here to extract. The
            // target is already recorded above as member metadata.
            Some("symlink") => continue,
            _ => {}
        }

        if member.size_bytes > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: name.to_string(),
                size: member.size_bytes,
            });
            continue;
        }
        // No offset means filefacts could not express the member as one
        // range (interleaved or split). Writing the bytes at its first
        // extent would produce a file that is not what the image holds.
        let Some(offset) = member.data_offset else {
            continue;
        };
        let Ok(start) = usize::try_from(offset) else {
            continue;
        };
        let Ok(len) = usize::try_from(member.size_bytes) else {
            continue;
        };
        let Some(payload) = data.get(start..start.saturating_add(len)) else {
            // The directory record points past the end of the image.
            guard.add_extraction_note(format!(
                "ISO member {name} extent {offset}+{len} lies outside the image"
            ));
            continue;
        };
        if !guard.check_bytes(payload.len() as u64, name) {
            anyhow::bail!("Exceeded maximum total extraction size");
        }

        if let Some(parent) = outpath.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut outfile =
            File::create(&outpath).with_context(|| format!("Failed to create: {name}"))?;
        outfile
            .write_all(payload)
            .with_context(|| format!("Failed to write: {name}"))?;
        extracted += 1;
    }

    if extracted == 0 {
        anyhow::bail!("ISO image holds no extractable file members");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn entry(path: &str, offset: u64, size: u64) -> ArchiveEntry {
        ArchiveEntry {
            path: path.to_string(),
            size_bytes: size,
            data_offset: Some(offset),
            entry_type: Some("regular".to_string()),
            ..ArchiveEntry::default()
        }
    }

    #[test]
    fn members_are_sliced_at_their_extents() {
        let mut image = vec![0_u8; 4096];
        image[2048..2053].copy_from_slice(b"MZ\x90\x00\x03");
        let dir = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        extract_iso_from_data(
            &image,
            &[entry("setup.exe", 2048, 5)],
            dir.path(),
            &guard,
        )
        .unwrap();
        assert_eq!(
            fs::read(dir.path().join("setup.exe")).unwrap(),
            b"MZ\x90\x00\x03"
        );
    }

    #[test]
    fn an_extent_past_the_end_is_skipped_not_truncated() {
        let image = vec![0_u8; 2048];
        let dir = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        // Only member points outside the image, so nothing extracts.
        let err = extract_iso_from_data(&image, &[entry("a.bin", 2000, 4096)], dir.path(), &guard)
            .unwrap_err();
        assert!(err.to_string().contains("no extractable file members"));
        assert!(!dir.path().join("a.bin").exists());
    }

    #[test]
    fn a_member_with_no_offset_is_skipped() {
        let image = vec![0_u8; 4096];
        let dir = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        let mut split = entry("split.bin", 0, 16);
        split.data_offset = None;
        let ok = entry("plain.bin", 2048, 4);
        extract_iso_from_data(&image, &[split, ok], dir.path(), &guard).unwrap();
        assert!(!dir.path().join("split.bin").exists());
        assert!(dir.path().join("plain.bin").exists());
    }

    #[test]
    fn traversal_paths_do_not_escape_the_destination() {
        let image = vec![0_u8; 4096];
        let dir = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        let _ = extract_iso_from_data(
            &image,
            &[entry("../../escape.bin", 2048, 4), entry("ok.bin", 2048, 4)],
            dir.path(),
            &guard,
        );
        assert!(dir.path().join("ok.bin").exists());
        assert!(!guard.take_reasons().is_empty());
    }
}
