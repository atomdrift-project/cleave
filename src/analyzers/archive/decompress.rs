//! Recursive decompression of single-stream compressed files.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Decompress a single-file stream into `dest_dir`, applying size and ratio guards.
///
/// The output filename is derived from `archive_path`'s stem (e.g. `foo.gz` → `foo`).
pub(super) const MAX_RECURSIVE_DECOMPRESSION_LAYERS: usize = 16;

/// Bytes of a decoded stream kept for content sniffing (tar magic, nested
/// codec magic). Every header this dispatch reads on sits far below this.
pub(super) const DECOMPRESS_SNIFF_LEN: u64 = 1024 * 1024;

pub(super) fn decompress_to_file<R: std::io::Read>(
    mut decoder: R,
    archive_path: &Path,
    dest_dir: &Path,
    compressed_size: u64,
    guard: &guards::ExtractionGuard,
) -> Result<()> {
    decompress_to_file_at_depth(
        &mut decoder,
        archive_path,
        dest_dir,
        compressed_size,
        guard,
        0,
    )
}

/// Build a decoder for the legacy LZMA-alone stream format (`.lzma`).
/// `XzDecoder::new` expects an XZ container; the explicit stream is required
/// for LZMA-alone files such as the payload carrier used in the xz incident.
pub(super) fn lzma_alone_decoder<R: std::io::Read>(reader: R) -> Result<xz2::read::XzDecoder<R>> {
    let stream = xz2::stream::Stream::new_lzma_decoder(u64::MAX)
        .context("Failed to create LZMA-alone decoder")?;
    Ok(xz2::read::XzDecoder::new_stream(reader, stream))
}

/// Stream `decoder` into a temp file beside the output, never materializing
/// the decoded stream in memory.
///
/// The decode is *tolerant*: a stream that breaks mid-way keeps whatever came
/// out before the error. Propagating the read error would throw away every
/// byte recovered so far and leave the extraction directory empty — which
/// `analyze_archive_with_data` can only report as a total analysis failure. A
/// truncated `.gz` therefore used to yield no verdict at all, even when the
/// decoded prefix was a complete tar minus its last member. That is both a
/// routine collection artifact and a cheap way to make a scanner give up, so
/// the prefix is what we analyze: those bytes decoded successfully and are as
/// genuine as any others. Only a stream that yields nothing is a hard error —
/// there is nothing to fall back to, and the caller should hear why.
///
/// Guard verdicts are fatal here: the per-chunk byte budget bails the
/// extraction as soon as the total is exceeded, and a stream that turns out
/// to be a decompression bomb (see [`guards::ExtractionGuard::check_compression_ratio`])
/// is refused once decoded, mirroring the zip member path.
pub(super) fn decompress_to_file_at_depth<R: std::io::Read>(
    mut decoder: R,
    archive_path: &Path,
    dest_dir: &Path,
    compressed_size: u64,
    guard: &guards::ExtractionGuard,
    decompression_depth: usize,
) -> Result<()> {
    use std::io::Write;

    let stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("extracted");

    let tmp = tempfile::Builder::new()
        .prefix(".cleave-decode-")
        .tempfile_in(dest_dir)
        .context("Failed to create decompression temp file")?;
    let mut tmp = Some(tmp);
    let mut limited = guards::LimitedReader::new(&mut decoder, guards::MAX_FILE_SIZE);
    // Matches the tar extractor's chunk: small enough to check cancellation
    // and the byte budget promptly on a stream that decodes for minutes.
    let mut buf = [0u8; 65536];
    let mut written = 0u64;
    loop {
        if guard.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        match std::io::Read::read(&mut limited, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(file) = tmp.as_mut() {
                    file.write_all(&buf[..n])
                        .with_context(|| format!("Failed to write decompressed data: {stem}"))?;
                }
                written += n as u64;
                if !guard.check_bytes(n as u64, stem) {
                    anyhow::bail!("Exceeded maximum total extraction size");
                }
                // Once this monotone ratio crosses the bomb threshold, the
                // decoded file can never be dispatched. Remove it now, but
                // finish reading so the final hostile reason still reports
                // the complete uncompressed size and late decoder errors.
                if tmp.is_some()
                    && guards::ExtractionGuard::compression_ratio_exceeded(compressed_size, written)
                {
                    drop(tmp.take());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if written == 0 => {
                return Err(anyhow::Error::new(e).context(format!("Failed to decompress: {stem}")));
            }
            Err(e) => {
                tracing::debug!(
                    stem,
                    decoded_bytes = written,
                    error = %e,
                    "compressed stream ended early; analyzing the decoded prefix",
                );
                guard.add_extraction_note(format!(
                    "{stem}: compressed stream ended early after {written} bytes ({e}); analyzed the decoded prefix"
                ));
                break;
            }
        }
    }

    if limited.is_limited() {
        guard.add_hostile_reason(guards::HostileArchiveReason::ExcessiveFileSize {
            file: stem.to_string(),
            size: guards::MAX_FILE_SIZE,
        });
        anyhow::bail!("Exceeded maximum single-file decompression size");
    }
    if !guard.check_compression_ratio(compressed_size, written) {
        anyhow::bail!("decompression bomb refused: {stem}");
    }

    dispatch_decompressed_file(
        tmp.context("decoded scratch unexpectedly missing")?,
        stem,
        dest_dir,
        guard,
        decompression_depth,
        written,
    )
}

/// Decide what a fully decoded stream is and route it: tar containers are
/// streamed straight into member extraction, nested single-file codecs
/// recurse (bounded by [`MAX_RECURSIVE_DECOMPRESSION_LAYERS`]), and anything
/// else is persisted as `dest_dir/stem`. The temp file holds the decoded
/// bytes; it is removed automatically on every path except the leaf.
pub(super) fn dispatch_decompressed_file(
    tmp: tempfile::NamedTempFile,
    stem: &str,
    dest_dir: &Path,
    guard: &guards::ExtractionGuard,
    decompression_depth: usize,
    decoded_len: u64,
) -> Result<()> {
    // Sniff the decoded content from a bounded prefix.
    let mut sniff = Vec::new();
    let mut sniff_file = reopen_decoded(&tmp, stem)?;
    std::io::Read::read_to_end(
        &mut std::io::Read::take(&mut sniff_file, DECOMPRESS_SNIFF_LEN),
        &mut sniff,
    )
    .with_context(|| format!("Failed to reread decompressed data: {stem}"))?;

    let logical_path = Path::new(stem);
    let detected = crate::analyzers::detect_file_type_from_data(logical_path, &sniff);

    if looks_like_tar_archive(&sniff)
        || matches!(
            detected,
            FileType::Tar
                | FileType::Gem
                | FileType::Hex
                | FileType::OciImage
                | FileType::GentooBinpkg
        )
    {
        return tar::extract_tar_entries_safe(reopen_decoded(&tmp, stem)?, dest_dir, guard);
    }

    match detected {
        FileType::TarGz
        | FileType::Npm
        | FileType::Crate
        | FileType::PythonSdist
        | FileType::Pub
        | FileType::Cran
        | FileType::Cpan
        | FileType::Hackage => tar::extract_tar_entries_safe(
            flate2::read::GzDecoder::new(reopen_decoded(&tmp, stem)?),
            dest_dir,
            guard,
        ),
        FileType::TarBz2 => tar::extract_tar_entries_safe(
            bzip2::read::BzDecoder::new(reopen_decoded(&tmp, stem)?),
            dest_dir,
            guard,
        ),
        FileType::TarXz => tar::extract_tar_entries_safe(
            xz2::read::XzDecoder::new(reopen_decoded(&tmp, stem)?),
            dest_dir,
            guard,
        ),
        FileType::TarZst | FileType::PkgArch | FileType::PkgFreebsd | FileType::Xbps => {
            tar::extract_tar_entries_safe(
                zstd::stream::read::Decoder::new(reopen_decoded(&tmp, stem)?)
                    .context("Failed to create zstd decoder")?,
                dest_dir,
                guard,
            )
        }
        FileType::Gz | FileType::Bz2 | FileType::Xz | FileType::Lzma | FileType::Zst
            if decompression_depth >= MAX_RECURSIVE_DECOMPRESSION_LAYERS =>
        {
            persist_decoded_leaf(tmp, dest_dir, stem)
        }
        FileType::Gz => decompress_to_file_at_depth(
            flate2::read::GzDecoder::new(reopen_decoded(&tmp, stem)?),
            logical_path,
            dest_dir,
            decoded_len,
            guard,
            decompression_depth + 1,
        ),
        FileType::Bz2 => decompress_to_file_at_depth(
            bzip2::read::BzDecoder::new(reopen_decoded(&tmp, stem)?),
            logical_path,
            dest_dir,
            decoded_len,
            guard,
            decompression_depth + 1,
        ),
        FileType::Xz => decompress_to_file_at_depth(
            xz2::read::XzDecoder::new(reopen_decoded(&tmp, stem)?),
            logical_path,
            dest_dir,
            decoded_len,
            guard,
            decompression_depth + 1,
        ),
        FileType::Lzma => decompress_to_file_at_depth(
            lzma_alone_decoder(reopen_decoded(&tmp, stem)?)?,
            logical_path,
            dest_dir,
            decoded_len,
            guard,
            decompression_depth + 1,
        ),
        FileType::Zst => decompress_to_file_at_depth(
            zstd::stream::read::Decoder::new(reopen_decoded(&tmp, stem)?)
                .context("Failed to create zstd decoder")?,
            logical_path,
            dest_dir,
            decoded_len,
            guard,
            decompression_depth + 1,
        ),
        _ => persist_decoded_leaf(tmp, dest_dir, stem),
    }
}

/// Reopen the decoded stream for a second pass (member extraction, nested
/// decode, sniffing). Each pass gets its own handle with the cursor at 0.
pub(super) fn reopen_decoded(tmp: &tempfile::NamedTempFile, stem: &str) -> Result<std::fs::File> {
    tmp.reopen()
        .with_context(|| format!("Failed to reread decompressed data: {stem}"))
}

/// Keep a decoded stream as the extraction's output file. `persist` renames
/// within `dest_dir` (same filesystem), so the leaf never waits on a copy.
/// The stem comes from the archive's name: one named `..gz` or `...gz` has
/// the stem `.` or `..`, which names a directory, not a file, and the decoded
/// payload would be lost with the failed rename.
pub(super) fn persist_decoded_leaf(
    tmp: tempfile::NamedTempFile,
    dest_dir: &Path,
    stem: &str,
) -> Result<()> {
    let stem = match stem {
        "" | "." | ".." => "extracted",
        stem => stem,
    };
    let out_path = dest_dir.join(stem);
    tmp.persist(&out_path)
        .with_context(|| format!("Failed to persist decompressed file: {stem}"))?;
    Ok(())
}

pub(super) fn looks_like_tar_archive(data: &[u8]) -> bool {
    if data.get(257..262) == Some(b"ustar") {
        return true;
    }
    if data.len() < 512 {
        return false;
    }

    let checksum_field = &data[148..156];
    let checksum_text = checksum_field
        .iter()
        .copied()
        .take_while(|b| *b != 0 && *b != b' ')
        .collect::<Vec<_>>();
    if checksum_text.is_empty() || !checksum_text.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let Ok(expected) =
        u32::from_str_radix(std::str::from_utf8(&checksum_text).unwrap_or_default(), 8)
    else {
        return false;
    };

    let actual = data[..512]
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                b' ' as u32
            } else {
                *b as u32
            }
        })
        .sum::<u32>();
    actual == expected
}
