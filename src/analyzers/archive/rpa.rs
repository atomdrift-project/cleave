//! Materialize Ren'Py RPA members from the bounded filefacts index reader.
//! Pickle is decoded as inert data; no Python code or archive scripts run.

use super::guards::{
    ExtractedMemberMetadata, ExtractionGuard, HostileArchiveReason, MAX_FILE_SIZE,
    sanitize_entry_path,
};
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub(crate) fn extract_from_data(data: &[u8], dest: &Path, guard: &ExtractionGuard) -> Result<()> {
    let members = filefacts::rpa::members(data).map_err(anyhow::Error::msg)?;
    for member in members {
        if guard.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum RPA member count");
        }
        if member.size > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: member.path.clone(),
                size: member.size,
            });
            anyhow::bail!("Exceeded maximum RPA member size");
        }
        let Some(path) = sanitize_entry_path(&member.path, dest) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(member.path));
            continue;
        };
        let path = guard.claim_output_path(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        guard.record_member_metadata(ExtractedMemberMetadata {
            archive_path: path.strip_prefix(dest)?.to_string_lossy().into_owned(),
            compression_method: Some("stored".into()),
            entry_type: Some("regular".into()),
            ..Default::default()
        });
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        for chunk in member.chunks {
            if guard.is_cancelled() {
                anyhow::bail!("cancelled");
            }
            if !guard.check_bytes(chunk.prefix.len() as u64, &member.path) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
            out.write_all(&chunk.prefix)?;
            let start = usize::try_from(chunk.offset).context("RPA chunk offset overflow")?;
            let len = usize::try_from(chunk.length).context("RPA chunk length overflow")?;
            let end = start
                .checked_add(len)
                .context("RPA chunk extent overflow")?;
            let body = data.get(start..end).context("RPA chunk outside input")?;
            for part in body.chunks(65536) {
                if guard.is_cancelled() {
                    anyhow::bail!("cancelled");
                }
                if !guard.check_bytes(part.len() as u64, &member.path) {
                    anyhow::bail!("Exceeded maximum total extraction size");
                }
                out.write_all(part)?;
            }
        }
    }
    Ok(())
}
