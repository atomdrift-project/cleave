//! Members of installers filefacts decodes natively: the files of an
//! InstallShield `ISSetupStream` and the install script of an NSIS installer.
//!
//! filefacts parses the formats; this module only writes what it decodes
//! into the extraction directory, under cleave's archive limits, so the
//! archive analyzer treats them like any other extracted member.

use crate::analyzers::archive::{
    MAX_COMPRESSION_RATIO, MIN_ZIP_BOMB_UNCOMPRESSED_SIZE, sanitize_entry_path,
};
use filefacts::recover::{installshield, nsis};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

/// The member name the decoded NSIS script is published under, the name
/// 7-Zip's own NSIS handler gives it.
pub(super) const NSIS_SCRIPT_NAME: &str = "[NSIS].nsi";
/// Most bytes one `ISSetupStream` entry may decompress to.
const MAX_ENTRY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Most bytes all entries of one stream may decompress to.
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Most bytes an entry of `stored` bytes may expand to: the archive-wide
/// ratio limit, which only bites past the size a bomb needs to matter, never
/// more than [`MAX_ENTRY_BYTES`] or what the stream's budget has left.
fn output_cap(stored: usize, budget_left: u64) -> u64 {
    u64::try_from(stored)
        .unwrap_or(u64::MAX)
        .saturating_mul(MAX_COMPRESSION_RATIO)
        .clamp(MIN_ZIP_BOMB_UNCOMPRESSED_SIZE, MAX_ENTRY_BYTES)
        .min(budget_left)
}

/// The basename an entry is written under: its last path component, never
/// empty or a dot name, and never clashing with an earlier entry.
fn member_name(name: &str, index: usize, taken: &mut HashSet<String>) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .map(|base| base.replace('\0', ""))
        .filter(|base| !base.trim_matches('.').is_empty())
        .unwrap_or_else(|| "entry".to_string());
    let name = if taken.contains(&base) {
        format!("{base}~{index}")
    } else {
        base
    };
    taken.insert(name.clone());
    name
}

/// Write every entry of the `ISSetupStream` that `stream` starts with into
/// `out`, returning how many were written. An entry that does not decode or
/// breaks a size limit is skipped and logged; its partial file is removed.
pub(super) fn extract_installshield(stream: &[u8], file_path: &Path, out: &Path) -> usize {
    let listing = match installshield::entries(stream) {
        Ok(listing) => listing,
        Err(error) => {
            tracing::warn!(path = %file_path.display(), %error, "unreadable ISSetupStream");
            return 0;
        }
    };
    if !listing.complete {
        tracing::warn!(
            path = %file_path.display(),
            declared = listing.declared,
            read = listing.entries.len(),
            "ISSetupStream table breaks off; extracting the entries before it"
        );
    }
    let mut taken = HashSet::new();
    let mut written = 0usize;
    let mut budget_left = MAX_TOTAL_BYTES;
    for (index, entry) in listing.entries.iter().enumerate() {
        if budget_left == 0 {
            tracing::warn!(path = %file_path.display(), index, "ISSetupStream output limit reached");
            break;
        }
        let name = member_name(&entry.name, index, &mut taken);
        let Some(path) = sanitize_entry_path(&name, out) else {
            tracing::warn!(path = %file_path.display(), entry = %entry.name, "unusable ISSetupStream entry name");
            continue;
        };
        let cap = output_cap(entry.stored_size, budget_left);
        let result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(anyhow::Error::from)
            .and_then(|mut file| {
                let bytes = installshield::decode_entry(stream, entry, &mut file, cap)?;
                file.flush()?;
                Ok(bytes)
            });
        match result {
            Ok(bytes) => {
                budget_left = budget_left.saturating_sub(bytes);
                written = written.saturating_add(1);
                tracing::debug!(
                    path = %file_path.display(),
                    entry = %entry.name,
                    stored = entry.stored_size,
                    bytes,
                    "extracted ISSetupStream entry"
                );
            }
            Err(error) => {
                // A partial file would be analyzed as if it were the member.
                let _ = std::fs::remove_file(&path);
                tracing::warn!(path = %file_path.display(), entry = %entry.name, %error, "ISSetupStream entry skipped");
            }
        }
    }
    written
}

/// Write the install script decoded from the header of the NSIS installer
/// `data` into `out` as [`NSIS_SCRIPT_NAME`], reporting whether it was
/// written. A script an extractor already wrote there is kept.
pub(super) fn write_nsis_script(data: &[u8], file_path: &Path, out: &Path) -> bool {
    let script = match nsis::script(data) {
        Ok(script) => script.render(),
        Err(error) => {
            tracing::debug!(path = %file_path.display(), %error, "NSIS script not decoded");
            return false;
        }
    };
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join(NSIS_SCRIPT_NAME))
        .and_then(|mut file| file.write_all(script.as_bytes()));
    match written {
        Ok(()) => {
            tracing::debug!(path = %file_path.display(), bytes = script.len(), "decoded NSIS script");
            true
        }
        Err(error) => {
            tracing::debug!(path = %file_path.display(), %error, "NSIS script not written");
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests;
