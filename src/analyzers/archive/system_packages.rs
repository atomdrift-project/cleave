//! System package format handlers.
//!
//! This module handles OS-specific package formats:
//! - Debian packages (.deb)
//! - RPM packages (.rpm)
//! - macOS packages (.pkg)
//! - 7-Zip archives (.7z)
//! - RAR archives (.rar)
//! - Windows cabinet (.cab)
//! - Apple disk images (.dmg / UDIF)
//! - Standalone compression (.gz, .xz, .bz2)

use std::io::Seek;

use super::guards::{
    CancellableWriter, ExtractionGuard, HostileArchiveReason, LimitedReader, MAX_FILE_SIZE,
    MAX_TOTAL_SIZE, sanitize_entry_path, symlink_escapes,
};
use super::tar::extract_tar_entries_safe;
use crate::analyzers::FileTypeExt;
use crate::types::ArchiveEntry;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
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

    // Past the directory case above, so this is a file: rename it if a previous
    // member already claimed the name case-insensitively.
    let outpath = guard.claim_output_path(outpath);

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
            if let Ok(mut sz) = SevenZReader::new(Cursor::new(data), size, password_obj)
                && sz
                    .for_each_entries(|entry, reader| {
                        extract_7z_entry_safe(entry, reader, dest_dir, guard)
                    })
                    .is_ok()
            {
                info!("✓ Decrypted 7z with password");
                return Ok(());
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

/// Read 7z directory metadata without extracting member contents.
///
/// Password-protected 7z archives often leave filenames, sizes, and timestamps
/// visible while encrypting the payload streams. Preserving those headers lets
/// archive-layout traits still fire when the payload password is unknown.
pub(crate) fn list_7z_entries_from_file(path: &Path) -> Result<Vec<ArchiveEntry>> {
    // Header-encrypted 7z archives make `7z l` prompt for a password on stdin,
    // which would block forever. Detach stdin and pass `-y`/empty `-p` so the
    // tool fails fast instead of waiting for interactive input.
    let run = |bin: &str| {
        std::process::Command::new(bin)
            .arg("l")
            .arg("-y")
            .arg("-p")
            .arg(path)
            .stdin(std::process::Stdio::null())
            .output()
    };
    let output = run("7z")
        .or_else(|_| run("7zz"))
        .context("Failed to run 7z listing")?;
    if !output.status.success() {
        anyhow::bail!("7z listing failed with status {}", output.status);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut in_table = false;
    let mut entries = Vec::new();
    for line in stdout.lines() {
        if line.starts_with("-------------------") {
            if in_table {
                break;
            }
            in_table = true;
            continue;
        }
        if !in_table || line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let Some(size_bytes) = parts.get(3).and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        let name_start = if parts
            .get(4)
            .is_some_and(|s| s.chars().all(|c| c.is_ascii_digit()))
        {
            5
        } else {
            4
        };
        if parts.len() <= name_start {
            continue;
        }
        let name = parts[name_start..].join(" ");
        let file_type =
            crate::analyzers::detect_file_type_from_path(Path::new(&name)).report_file_type();
        let compressed_size = parts
            .get(4)
            .filter(|s| s.chars().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok());

        entries.push(ArchiveEntry {
            path: name.replace('\\', "/"),
            file_type,
            sha256: String::new(),
            size_bytes,
            compressed_size,
            compression_method: Some("7z".to_string()),
            entry_type: Some("regular".to_string()),
            encrypted: true,
            ..ArchiveEntry::default()
        });
    }

    Ok(entries)
}

/// Extract an Apple disk image (`.dmg` / UDIF) in two stages.
///
/// **Stage 1 — system `7z`/`7zz` on the image directly.** 7-Zip walks the UDIF
/// container, decompresses the blocks it knows (zlib/bzip2/LZFSE/ADC), unpacks
/// an **HFS+** filesystem to a real file tree, and recovers the embedded
/// universal Mach-O from **APFS** images (whose filesystem it can't read). This
/// handles the common case.
///
/// **Stage 2 — dmgwiz reconstruction, only if stage 1 lands no real files.** An
/// LZMA(ULMO) image is opaque to 7-Zip, which then dumps only partition
/// pseudo-files (`*.MBR`, GPT tables, an undecompressed `*.Apple_APFS` blob);
/// dmgwiz decompresses *every* UDIF codec, so we rebuild the raw disk image and
/// hand that back to 7-Zip.
///
/// Success is judged by what landed, not 7-Zip's exit code: it exits non-zero on
/// HFS+ images carrying symlinks/special files it can't recreate, even though it
/// extracted the tree fine.
///
/// Best-effort throughout: an image neither tool can crack still carries its
/// host-level `dmg.*` facts (filesystem, builder fingerprint, volume name,
/// `newfs_apfs` version, dates), which filefacts merges independently — so this
/// returns `Ok` rather than failing the analysis when nothing extracts. Full
/// APFS file trees remain the libfsapfs path.
pub(crate) fn extract_dmg_from_data(
    data: &[u8],
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    // The UDIF trailer declares the mounted volume size — the upper bound on
    // what extraction will write. Refuse images that would blow the total-size
    // budget before we shell out, since a subprocess extraction can't be
    // bounded entry-by-entry the way the in-process extractors are. Record the
    // reason and stop (not an error): the host-level metadata floor survives.
    if let Some(uncompressed) = udif_uncompressed_size(data)
        && uncompressed > MAX_TOTAL_SIZE
    {
        guard.add_hostile_reason(HostileArchiveReason::ExcessiveTotalSize(uncompressed));
        return Ok(());
    }

    // Stage 1: 7-Zip reads from a path, not a stream; materialize the image.
    let temp = tempfile::Builder::new()
        .prefix("cleave-dmg-")
        .suffix(".dmg")
        .tempfile()
        .context("Failed to create temp file for DMG extraction")?;
    fs::write(temp.path(), data).context("Failed to write DMG to temp file")?;
    crate::analyzers::sfx_detector::run_7z(temp.path(), dest_dir);
    if dir_has_real_content(dest_dir) {
        return Ok(()); // HFS+ file tree or APFS Mach-O carve
    }

    // Stage 1 produced only partition pseudo-files (or nothing) — typically an
    // ULMO/LZMA image 7-Zip can't decompress. Discard the partials, then rebuild
    // the raw disk image with dmgwiz (which handles every UDIF codec) and let
    // 7-Zip read that.
    clear_dir(dest_dir);
    let raw = tempfile::Builder::new()
        .suffix(".img")
        .tempfile()
        .context("Failed to create temp file for DMG reconstruction")?;
    if reconstruct_dmg_raw(data, raw.path()).is_ok() {
        crate::analyzers::sfx_detector::run_7z(raw.path(), dest_dir);
    }
    Ok(())
}

/// Reconstruct the raw whole-disk image from a UDIF `.dmg` using dmgwiz, which
/// decompresses every UDIF block codec (including LZMA/ULMO, which 7-Zip can't).
///
/// dmgwiz parses attacker-controlled block tables with `.unwrap()`, so a crafted
/// DMG can panic it. Since this runs on hostile input, the panic is isolated
/// with `catch_unwind` (cleave builds with the default unwind strategy) and
/// turned into a recoverable error — the caller then keeps the metadata floor
/// rather than letting one bad image abort the analysis.
fn reconstruct_dmg_raw(data: &[u8], out_path: &Path) -> Result<()> {
    let extract = std::panic::AssertUnwindSafe(|| -> Result<()> {
        let mut wiz = dmgwiz::DmgWiz::from_reader(Cursor::new(data), dmgwiz::Verbosity::None)
            .map_err(|e| anyhow::anyhow!("dmgwiz could not parse DMG: {e}"))?;
        let out = BufWriter::new(File::create(out_path)?);
        wiz.extract_all(out)
            .map_err(|e| anyhow::anyhow!("dmgwiz could not reconstruct image: {e}"))?;
        Ok(())
    });
    match std::panic::catch_unwind(extract) {
        Ok(result) => result,
        Err(_) => anyhow::bail!("dmgwiz panicked on malformed DMG"),
    }
}

/// Whether `dir` holds at least one real extracted file — i.e. something other
/// than the partition pseudo-files 7-Zip dumps when it can't read the
/// filesystem. Used to decide stage 1 succeeded without trusting 7-Zip's exit
/// code (which is non-zero for HFS+ images with unrecreatable symlinks).
fn dir_has_real_content(dir: &Path) -> bool {
    walkdir::WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .any(|e| {
            e.file_type().is_file() && !is_partition_artifact(&e.file_name().to_string_lossy())
        })
}

/// 7-Zip's partition-layer entry names, emitted when it parses the GPT/MBR but
/// can't read the contained filesystem: `0.MBR`, `*.Primary GPT Table`,
/// `3.free`, an undecompressed `4.Apple_APFS`/`*.Apple_HFS` blob, etc.
fn is_partition_artifact(name: &str) -> bool {
    name.ends_with(".MBR")
        || name.ends_with(".free")
        || name.contains("GPT")
        || name.contains("Apple_APFS")
        || name.contains("Apple_HFS")
}

/// Remove every entry beneath `dir` — discards a failed extraction's partial
/// output before the reconstruction retry writes into the same directory.
fn clear_dir(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let _ = if path.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
    }
}

/// The mounted (uncompressed) volume size declared in the UDIF `koly` trailer:
/// `sector_count` (big-endian u64 at trailer offset 492) × 512. `None` when the
/// trailer is absent or truncated.
fn udif_uncompressed_size(data: &[u8]) -> Option<u64> {
    let trailer = data.get(data.len().checked_sub(512)?..)?;
    if !trailer.starts_with(b"koly") {
        return None;
    }
    let sectors = u64::from_be_bytes(trailer.get(492..500)?.try_into().ok()?);
    sectors.checked_mul(512)
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
                .map_err(|e| anyhow::anyhow!("XAR header too short: {e}"))?,
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
        // XAR extraction only ever creates files.
        let out_path = guard.claim_output_path(out_path);

        // Check file size
        if let Some(size) = file_entry.size
            && size > MAX_FILE_SIZE
        {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: path.clone(),
                size,
            });
            continue;
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

/// Extract an Alpine/Wolfi `.apk` package.
///
/// An apk v2 is **not** a single gzip-tar: it is several gzip streams
/// concatenated back to back — an optional signature segment, the control
/// segment (`.PKGINFO` and install scripts), and the data segment (the
/// installed files, including every ELF binary). A single-stream `GzDecoder`
/// decompresses only the first segment, and the `tar` crate stops at the first
/// archive's end-of-archive marker regardless, so the data segment — where the
/// binaries live — was silently dropped. We walk each concatenated gzip member
/// in turn, extracting every tar segment into `dest_dir`, so the data segment's
/// members are analyzed like any other archive member.
pub(crate) fn extract_apk_alpine_from_data(
    data: &[u8],
    dest_dir: &Path,
    guard: &ExtractionGuard,
) -> Result<()> {
    use std::io::{BufRead, Cursor};

    let mut input = BufReader::new(Cursor::new(data));
    loop {
        // A gzip member begins with the magic 0x1f 0x8b. Anything else (or an
        // empty buffer) marks the end of the concatenated segments, including
        // any trailing padding a packager may append after the data segment.
        let header = input.fill_buf().context("Failed to read apk segment")?;
        if header.len() < 2 || header[0] != 0x1f || header[1] != 0x8b {
            break;
        }

        // `bufread::GzDecoder` decodes exactly one gzip member and leaves the
        // underlying reader positioned at the next member's first byte (just
        // past this member's 8-byte trailer) — the property that lets us
        // advance segment by segment. The shared `guard` enforces the file-count
        // and total-byte caps across every segment, so a multi-segment apk can't
        // evade the zip-bomb limits.
        let mut decoder = flate2::bufread::GzDecoder::new(&mut input);
        extract_tar_entries_safe(&mut decoder, dest_dir, guard)?;

        // The tar walk stops at the segment's end-of-archive marker, which can
        // leave trailing zero-block padding and the gzip trailer unread. Drain
        // them so the BufReader advances to the next concatenated member.
        std::io::copy(&mut decoder, &mut std::io::sink()).context("Failed to drain apk segment")?;
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

/// `st_mode` file-type bits, as CPIO stores them (POSIX `S_IFMT` family).
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Longest symlink target worth retaining for the escape check.
const MAX_SYMLINK_TARGET: u64 = 4096;

fn extract_cpio<R: Read>(mut reader: R, dest_dir: &Path, guard: &ExtractionGuard) -> Result<()> {
    loop {
        if guard.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        if !guard.check_file_count() {
            anyhow::bail!("Exceeded maximum file count");
        }

        // The dependency allocates namesize bytes before reading the name.
        // Bound that allocation before handing the unchanged header to it.
        // This is a resource preflight, not a second CPIO metadata parser.
        let mut header = [0u8; 110];
        reader
            .read_exact(&mut header[..6])
            .context("Truncated CPIO magic")?;
        match &header[..6] {
            b"070701" | b"070702" => {}
            b"07070X" => anyhow::bail!(
                "Unsupported RPM stripped CPIO payload: requires RPM file-index metadata"
            ),
            b"070707" => anyhow::bail!("Unsupported old-ASCII CPIO payload"),
            _ => anyhow::bail!("Invalid CPIO magic"),
        }
        reader
            .read_exact(&mut header[6..])
            .context("Truncated CPIO header")?;
        let name_size = u32::from_str_radix(std::str::from_utf8(&header[94..102])?, 16)
            .context("Invalid CPIO name size")?;
        anyhow::ensure!(
            (1..=1024 * 1024).contains(&name_size),
            "CPIO name size exceeds limit"
        );
        // Large names in many compressed entries also consume resources;
        // do not charge only retained file bodies against the stream budget.
        if !guard.check_bytes(110 + u64::from(name_size), "CPIO header/name") {
            anyhow::bail!("Exceeded maximum total extraction size");
        }
        let prefixed = Cursor::new(header).chain(&mut reader);
        let mut entry_reader = cpio::newc::Reader::new(prefixed).context("Invalid CPIO entry")?;

        let entry = entry_reader.entry();
        let name = entry.name().to_string();
        let mode = entry.mode() & S_IFMT;
        let file_size = u64::from(entry.file_size());
        if name == "TRAILER!!!" {
            anyhow::ensure!(file_size == 0, "CPIO trailer has file data");
            break;
        }

        // Preserve the original name for the shared sanitizer. Stripping a
        // leading slash would conceal that the archive supplied an absolute path.
        let out_path = if matches!(name.as_str(), "" | "." | "./") {
            None
        } else {
            let path = sanitize_entry_path(&name, dest_dir);
            if path.is_none() {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.clone()));
            }
            path.map(|path| {
                if mode == S_IFDIR {
                    path
                } else {
                    guard.claim_output_path(path)
                }
            })
        };
        if file_size > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: name.clone(),
                size: file_size,
            });
            anyhow::bail!("Exceeded maximum CPIO file size");
        }

        let mut file = None;
        if let Some(path) = out_path.as_ref() {
            if mode == S_IFDIR {
                fs::create_dir_all(path)?;
            } else if mode == S_IFREG {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                file = Some(File::create(path)?);
            }
        }
        // Every entry is drained under the same bounds; only the destination
        // differs. A retained symlink target goes to a buffer, a regular file
        // to disk, and everything else — devices, skipped names — to a sink.
        let mut target_buf = Vec::new();
        let mut discard = std::io::sink();
        let writer: &mut dyn Write = match file.as_mut() {
            Some(file) => file,
            None if mode == S_IFLNK && out_path.is_some() && file_size < MAX_SYMLINK_TARGET => {
                &mut target_buf
            }
            None => &mut discard,
        };
        copy_cpio_data(&mut entry_reader, writer, file_size, guard, &name)?;
        // Reading to EOF consumes only file data, NOT the alignment padding.
        // Finish every entry, including ignored names, links and directories.
        entry_reader
            .finish()
            .context("Truncated CPIO entry padding")?;
        if let Some(path) = out_path.as_ref()
            && let Ok(target) = std::str::from_utf8(&target_buf)
            && !target.is_empty()
            && symlink_escapes(path, target, dest_dir)
        {
            guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                "{name} -> {target}"
            )));
        }
    }

    Ok(())
}

/// Drain each entry exactly, with the same bounds for retained and skipped data.
fn copy_cpio_data(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    expected: u64,
    guard: &ExtractionGuard,
    name: &str,
) -> Result<()> {
    let mut buf = [0u8; 65536];
    let mut copied = 0u64;
    loop {
        if guard.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if !guard.check_bytes(n as u64, name) {
            anyhow::bail!("Exceeded maximum total extraction size");
        }
        writer.write_all(&buf[..n])?;
        copied += n as u64;
    }
    anyhow::ensure!(copied == expected, "Truncated CPIO entry data: {name}");
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

                    // Note: RAR unrar crate doesn't filefacts packed_size, so we can't check
                    // compression ratio directly. We rely on unpacked_size limit above.

                    // Sanitize path
                    let Some(out_path) = sanitize_entry_path(&filename, dest_dir) else {
                        guard.add_hostile_reason(HostileArchiveReason::PathTraversal(
                            filename.clone(),
                        ));
                        archive = file_archive.skip().context("Failed to skip RAR entry")?;
                        continue;
                    };

                    // This is the non-directory branch, so disambiguate a
                    // case-insensitive collision with an earlier member.
                    let out_path = guard.claim_output_path(out_path);

                    // Create parent directories
                    if let Some(parent) = out_path.parent() {
                        fs::create_dir_all(parent)?;
                    }

                    // One encrypted member does not make the rest unreadable.
                    // Names, sizes and times still come from the filefacts header walk.
                    if header.is_encrypted() {
                        guard.add_extraction_note(format!("{filename}: encrypted, skipped"));
                        archive = file_archive
                            .skip()
                            .context("Failed to skip encrypted RAR entry")?;
                        continue;
                    }

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
        // CAB entries are always files.
        let out_path = guard.claim_output_path(out_path);

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn cpio_fixture(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, mode, body) in entries {
            let mut writer = cpio::newc::Builder::new(name)
                .mode(*mode)
                .write(&mut bytes, body.len() as u32);
            writer.write_all(body).unwrap();
            writer.finish().unwrap();
        }
        cpio::newc::trailer(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn cpio_entry_padding_preserves_following_files() {
        let bytes = cpio_fixture(&[
            ("one.txt", 0o100644, b"1"),
            ("two.txt", 0o100644, b"22"),
            ("three.txt", 0o100644, b"333"),
            ("four.txt", 0o100644, b"4444"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_cpio(bytes.as_slice(), dir.path(), &ExtractionGuard::new()).unwrap();
        for (name, content) in [
            ("one.txt", "1"),
            ("two.txt", "22"),
            ("three.txt", "333"),
            ("four.txt", "4444"),
        ] {
            assert_eq!(fs::read_to_string(dir.path().join(name)).unwrap(), content);
        }
    }

    #[test]
    fn cpio_malformed_header_is_not_successful_end_of_archive() {
        let dir = tempfile::tempdir().unwrap();
        let invalid = [b'x'; 110];
        assert!(extract_cpio(invalid.as_slice(), dir.path(), &ExtractionGuard::new()).is_err());
        let mut after_file = cpio_fixture(&[("ok.txt", 0o100644, b"okay")]);
        let trailer = after_file
            .windows(6)
            .rposition(|magic| magic == b"070701")
            .unwrap();
        after_file[trailer] = b'x';
        assert!(extract_cpio(after_file.as_slice(), dir.path(), &ExtractionGuard::new()).is_err());
    }

    #[test]
    fn cpio_empty_archive_with_trailer_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        extract_cpio(
            cpio_fixture(&[]).as_slice(),
            dir.path(),
            &ExtractionGuard::new(),
        )
        .unwrap();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn cpio_skipped_names_and_links_do_not_hide_following_files() {
        let bytes = cpio_fixture(&[
            (".", 0o040755, b""),
            ("../escape", 0o100644, b"one"),
            ("./../escape", 0o100644, b"two"),
            ("/absolute", 0o100644, b"three"),
            ("link", 0o120777, b"../outside"),
            ("safe.txt", 0o100644, b"safe"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        extract_cpio(bytes.as_slice(), dir.path(), &guard).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("safe.txt")).unwrap(),
            "safe"
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        let reasons = guard.take_reasons();
        assert_eq!(
            reasons
                .iter()
                .filter(|r| matches!(r, HostileArchiveReason::PathTraversal(_)))
                .count(),
            3
        );
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, HostileArchiveReason::SymlinkEscape(_)))
        );
    }

    #[test]
    fn cpio_truncation_never_reports_complete_extraction() {
        let bytes = cpio_fixture(&[("ok.txt", 0o100644, b"abc")]);
        let dir = tempfile::tempdir().unwrap();
        for len in 0..bytes.len() {
            assert!(
                extract_cpio(&bytes[..len], dir.path(), &ExtractionGuard::new()).is_err(),
                "accepted prefix of {len} bytes"
            );
        }
    }

    #[test]
    fn cpio_duplicate_names_preserve_both_bodies() {
        let bytes = cpio_fixture(&[
            ("same.txt", 0o100644, b"one"),
            ("same.txt", 0o100644, b"two"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_cpio(bytes.as_slice(), dir.path(), &ExtractionGuard::new()).unwrap();
        let mut bodies: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
            .collect();
        bodies.sort();
        assert_eq!(bodies, ["one", "two"]);
    }

    #[test]
    fn cpio_name_allocation_is_bounded_before_dependency_parser() {
        let mut header = cpio_fixture(&[]);
        header[94..102].copy_from_slice(b"ffffffff");
        let dir = tempfile::tempdir().unwrap();
        let error =
            extract_cpio(header.as_slice(), dir.path(), &ExtractionGuard::new()).unwrap_err();
        assert!(error.to_string().contains("name size exceeds limit"));
    }

    #[test]
    fn cpio_metadata_cannot_bypass_total_byte_budget() {
        let dir = tempfile::tempdir().unwrap();
        let guard = ExtractionGuard::new();
        assert!(guard.check_bytes(MAX_TOTAL_SIZE - 100, "previous entries"));
        let error = extract_cpio(cpio_fixture(&[]).as_slice(), dir.path(), &guard).unwrap_err();
        assert!(error.to_string().contains("maximum total extraction size"));
    }

    #[test]
    fn cpio_known_unsupported_formats_are_not_called_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        for magic in [b"07070X", b"070707"] {
            let error =
                extract_cpio(magic.as_slice(), dir.path(), &ExtractionGuard::new()).unwrap_err();
            assert!(error.to_string().starts_with("Unsupported"));
        }
    }

    #[test]
    fn cpio_trailer_cannot_silently_discard_claimed_data() {
        let mut bytes = cpio_fixture(&[]);
        bytes[54..62].copy_from_slice(b"00000004");
        bytes.extend_from_slice(b"data");
        let dir = tempfile::tempdir().unwrap();
        assert!(
            extract_cpio(bytes.as_slice(), dir.path(), &ExtractionGuard::new())
                .unwrap_err()
                .to_string()
                .contains("trailer has file data")
        );
    }

    #[test]
    fn cpio_cancellation_interrupts_discarded_member_data() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct CancelReader {
            inner: Cursor<Vec<u8>>,
            flag: Arc<AtomicBool>,
        }
        impl Read for CancelReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.inner.read(buf)?;
                if self.inner.position() > 128 * 1024 {
                    self.flag.store(true, Ordering::Release);
                }
                Ok(n)
            }
        }
        let flag = Arc::new(AtomicBool::new(false));
        // A large ignored link must not bypass cancellation or byte accounting.
        let body = vec![b'x'; 256 * 1024];
        let bytes = cpio_fixture(&[("link", 0o120777, &body)]);
        let reader = CancelReader {
            inner: Cursor::new(bytes),
            flag: Arc::clone(&flag),
        };
        let guard = ExtractionGuard::with_cancellation(Some(flag));
        let dir = tempfile::tempdir().unwrap();
        assert!(
            extract_cpio(reader, dir.path(), &guard)
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// A crafted DMG: valid `koly` trailer + a plist whose only `blkx` carries a
    /// `Data` blob too short for the BLKXTable header. dmgwiz navigates the plist
    /// fine, then panics in `BLKXTable::from` (bincode `.unwrap()` hits EOF
    /// before `sector_number`). `reconstruct_dmg_raw` must catch that and return
    /// an error rather than unwinding into the analyzer — so one hostile DMG
    /// can't abort a batch scan.
    #[test]
    fn reconstruct_dmg_raw_isolates_dmgwiz_panic() {
        // A complete 204-byte BLKXTable header (so navigation/parse succeeds)
        // that claims 1000 chunks but supplies none — the chunk-deserialize loop
        // then `.unwrap()`s an EOF error and panics.
        let mut mish = vec![0u8; 204];
        mish[0..4].copy_from_slice(b"mish");
        mish[200..204].copy_from_slice(&1000u32.to_be_bytes()); // num_chunks, no chunk data
        let mut entry = plist::Dictionary::new();
        entry.insert(
            "Name".into(),
            plist::Value::String("disk image (Apple_APFS : 4)".into()),
        );
        entry.insert("Data".into(), plist::Value::Data(mish));
        let mut rsrc = plist::Dictionary::new();
        rsrc.insert(
            "blkx".into(),
            plist::Value::Array(vec![plist::Value::Dictionary(entry)]),
        );
        let mut root = plist::Dictionary::new();
        root.insert("resource-fork".into(), plist::Value::Dictionary(rsrc));
        let mut xml = Vec::new();
        plist::to_writer_xml(&mut xml, &plist::Value::Dictionary(root)).unwrap();

        // Layout: [data fork][xml][koly]. The data fork must be non-empty or
        // dmgwiz rejects the image before parsing the (panicking) block table.
        let data_fork = vec![0u8; 16];
        let mut bytes = data_fork.clone();
        let xml_offset = bytes.len() as u64;
        bytes.extend_from_slice(&xml);
        let mut koly = vec![0u8; 512];
        koly[0..4].copy_from_slice(b"koly");
        koly[4..8].copy_from_slice(&4u32.to_be_bytes()); // version
        koly[8..12].copy_from_slice(&512u32.to_be_bytes()); // header size
        koly[24..32].copy_from_slice(&0u64.to_be_bytes()); // data fork offset
        koly[32..40].copy_from_slice(&(data_fork.len() as u64).to_be_bytes()); // data fork length
        koly[216..224].copy_from_slice(&xml_offset.to_be_bytes()); // xml offset
        koly[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes()); // xml length
        koly[492..500].copy_from_slice(&8u64.to_be_bytes()); // sector count
        bytes.extend_from_slice(&koly);

        let tmp = tempfile::Builder::new().suffix(".img").tempfile().unwrap();
        let err = reconstruct_dmg_raw(&bytes, tmp.path())
            .expect_err("malformed blkx must not unwind into the caller");
        assert!(
            err.to_string().contains("panicked"),
            "expected the dmgwiz panic to be caught, got: {err}"
        );
    }
}
