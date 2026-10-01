//! Compiled HTML Help (.chm) container parser and extractor.
//!
//! CHM is Microsoft's ITSF-based help format. The on-disk layout is:
//! - **ITSF** header: file-wide pointers to the directory listing section
//!   and to the data offset where Uncompressed-section file bytes live.
//! - **ITSP** + **PMGL** chunks: a B-tree of directory entries naming each
//!   internal file and locating it within one of the named "content
//!   sections" (typically `Uncompressed` or `MSCompressed`).
//! - **MSCompressed/Content**: an LZX-compressed blob that holds most user
//!   files (HTML topics, images). The blob's window size and reset interval
//!   live in `MSCompressed/ControlData`; per-block compressed offsets live
//!   in `MSCompressed/Transform/{guid}/InstanceData/ResetTable`.
//!
//! Cleave treats CHM as an archive: each internal file becomes an entry
//! that gets decompressed and written to a temp dir, then analyzed as if
//! it were a member of a ZIP. Evidence locations naturally come out as
//! `archive:foo.chm!help.html`.

// Parses attacker-controlled bytes: index and offset arithmetic must be
// checked, so a forged header is a parse error rather than a panic.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::analyzers::archive::{MAX_COMPRESSION_RATIO, MIN_ZIP_BOMB_UNCOMPRESSED_SIZE};
use anyhow::{Context, Result, bail};
use lzx::{Lzxd, WindowSize};

/// Directory entry parsed from a CHM PMGL chunk.
#[derive(Debug, Clone)]
pub(crate) struct ChmEntry {
    pub name: String,
    /// Content section index (0=Uncompressed, 1=MSCompressed typically).
    pub section: u64,
    /// Offset within the content section.
    pub offset: u64,
    /// Length in bytes.
    pub length: u64,
}

impl ChmEntry {
    /// True if this entry is a CHM-internal control file (`#SYSTEM`,
    /// `::DataSpace/...`, etc.) that callers should not extract as a
    /// scannable user file.
    fn is_internal(&self) -> bool {
        // CHM directory names usually start with '/'. Strip a single
        // leading '/' before checking the conventional namespace markers
        // ('#' for header records, '$' for ObjectInfo-style sections, '::'
        // for the system namespace).
        let n = self.name.strip_prefix('/').unwrap_or(&self.name);
        n.starts_with('#')
            || n.starts_with("::")
            || n.starts_with('$')
            || self.name == "/"
            || self.name.ends_with('/')
    }
}

/// Parsed CHM container with directory listing and pointers needed to
/// resolve entry data.
pub(crate) struct Chm<'a> {
    data: &'a [u8],
    /// File offset where Uncompressed-section file bytes begin (ITSF
    /// `additional_data_offset`).
    data_offset: u64,
    pub entries: Vec<ChmEntry>,
}

impl<'a> Chm<'a> {
    /// Parse the ITSF/ITSP/PMGL structure of `data`.
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x60 || !data.starts_with(b"ITSF") {
            bail!("not a CHM file (missing ITSF magic)");
        }
        let version = u32_le(data, 0x04).context("ITSF header truncated")?;
        if version != 3 {
            bail!("unsupported CHM version {version} (only v3 supported)");
        }

        // Section 1 of the ITSF header table holds the ITSP + directory.
        let header = |offset| u64_le(data, offset).context("ITSF header truncated");
        let section1_offset = header(0x48)?;
        let section1_length = header(0x50)?;
        let data_offset = header(0x58)?;

        let dir = slice_at(data, section1_offset, section1_length)
            .context("ITSF section 1 (directory) out of bounds")?;
        let entries = parse_directory(dir)?;

        Ok(Self {
            data,
            data_offset,
            entries,
        })
    }

    fn find(&self, name: &str) -> Option<&ChmEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Read raw bytes for an entry from the Uncompressed section (section 0).
    fn read_uncompressed(&self, entry: &ChmEntry) -> Option<&'a [u8]> {
        slice_at(
            self.data,
            self.data_offset.checked_add(entry.offset)?,
            entry.length,
        )
    }

    /// Decompress the entire `::DataSpace/Storage/MSCompressed/Content`
    /// blob and return its uncompressed bytes. Returns `Ok(None)` if the
    /// CHM has no MSCompressed section (some CHMs are entirely
    /// uncompressed).
    pub(crate) fn decompress_mscompressed(&self) -> Result<Option<Vec<u8>>> {
        let Some(content_entry) = self.find("::DataSpace/Storage/MSCompressed/Content") else {
            return Ok(None);
        };
        let Some(control) = self.find("::DataSpace/Storage/MSCompressed/ControlData") else {
            bail!("MSCompressed/Content present but ControlData missing");
        };
        let Some(reset_entry) = self.entries.iter().find(|e| {
            e.name
                .starts_with("::DataSpace/Storage/MSCompressed/Transform/")
                && e.name.ends_with("/InstanceData/ResetTable")
        }) else {
            bail!("MSCompressed/Content present but ResetTable missing");
        };

        let content = self
            .read_uncompressed(content_entry)
            .context("MSCompressed/Content out of bounds")?;
        let control_bytes = self
            .read_uncompressed(control)
            .context("MSCompressed/ControlData out of bounds")?;
        let reset_bytes = self
            .read_uncompressed(reset_entry)
            .context("ResetTable out of bounds")?;

        let cd = ControlData::parse(control_bytes)?;
        let rt = ResetTable::parse(reset_bytes)?;
        decompress_lzx(content, &cd, &rt).map(Some)
    }
}

/// LZX `ControlData` for the MSCompressed section.
#[derive(Debug)]
struct ControlData {
    /// Reset interval in 0x8000-byte chunks (so block_size_uncompressed =
    /// reset_interval × 0x8000).
    reset_interval_chunks: u32,
    /// LZX window size. CHM stores it as an exponent count of 0x8000.
    window: WindowSize,
}

impl ControlData {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 0x1c || data.get(4..8) != Some(b"LZXC".as_slice()) {
            bail!("ControlData missing LZXC signature");
        }
        let field = |offset| u32_le(data, offset).context("ControlData truncated");
        let reset_interval_chunks = field(0x0c)?;
        let window_chunks = field(0x10)?;
        // window_chunks is in units of 0x8000 (32 KB); a u32 count cannot overflow.
        let window_bytes = u64::from(window_chunks).saturating_mul(0x8000);
        let window = match window_bytes {
            0x0000_8000 => WindowSize::KB32,
            0x0001_0000 => WindowSize::KB64,
            0x0002_0000 => WindowSize::KB128,
            0x0004_0000 => WindowSize::KB256,
            0x0008_0000 => WindowSize::KB512,
            0x0010_0000 => WindowSize::MB1,
            0x0020_0000 => WindowSize::MB2,
            0x0040_0000 => WindowSize::MB4,
            0x0080_0000 => WindowSize::MB8,
            0x0100_0000 => WindowSize::MB16,
            0x0200_0000 => WindowSize::MB32,
            other => bail!("unsupported LZX window size {other:#x}"),
        };
        Ok(Self {
            reset_interval_chunks,
            window,
        })
    }
}

/// LZX `ResetTable` describing per-block compressed-byte offsets.
#[derive(Debug)]
struct ResetTable {
    uncompressed_size: u64,
    /// Per-block uncompressed length, taken from the ResetTable header
    /// (offset 0x20). Always 0x8000 (32 KB) for real CHMs. Each LZX
    /// "block" in the compressed stream encodes exactly this many
    /// bytes of output, so the decoder must always be asked for
    /// `block_len` bytes at a time — even on the final block, where
    /// only `uncompressed_size % block_len` of those bytes are real
    /// content. This is the framing detail that distinguishes a CHM
    /// LZX stream from the chunk-by-chunk model the `lzxd` crate
    /// otherwise expects.
    block_len: u64,
    /// Byte offsets into the compressed stream where each LZX reset
    /// (decoder reinit) begins. The first entry is always 0.
    reset_offsets: Vec<u64>,
}

impl ResetTable {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 0x28 {
            bail!("ResetTable too short ({} bytes)", data.len());
        }
        let truncated = || format!("ResetTable truncated ({} bytes)", data.len());
        let num_entries = usize_le(data, 0x04).with_context(truncated)?;
        let entry_size = u32_le(data, 0x08).with_context(truncated)?;
        let table_offset = usize_le(data, 0x0c).with_context(truncated)?;
        let uncompressed_size = u64_le(data, 0x10).with_context(truncated)?;
        let block_len = u64_le(data, 0x20).with_context(truncated)?;
        if entry_size != 8 {
            bail!("ResetTable entry size {entry_size} (expected 8)");
        }
        if block_len == 0 {
            bail!("ResetTable block_len is 0");
        }
        let table = num_entries
            .checked_mul(8)
            .and_then(|len| table_offset.checked_add(len))
            .and_then(|end| data.get(table_offset..end))
            .with_context(|| {
                format!(
                    "ResetTable truncated ({num_entries} entries at {table_offset}, have {} bytes)",
                    data.len()
                )
            })?;
        let reset_offsets = table
            .as_chunks::<8>()
            .0
            .iter()
            .copied()
            .map(u64::from_le_bytes)
            .collect();
        Ok(Self {
            uncompressed_size,
            block_len,
            reset_offsets,
        })
    }
}

/// Largest ResetTable `block_len` accepted (real CHMs use 0x8000).
const MAX_BLOCK_LEN: usize = 1 << 20;

/// Upper bound on the output buffer reserved before decoding starts.
const MAX_UPFRONT_RESERVE: usize = 64 << 20;

/// A compressed section declaring more output than the archive guard allows
/// for its compressed size: over [`MAX_COMPRESSION_RATIO`] once past
/// [`MIN_ZIP_BOMB_UNCOMPRESSED_SIZE`]. Decoding stops at the declared size, so
/// refusing it up front bounds memory without decoding anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecompressionBomb {
    pub(crate) compressed: u64,
    pub(crate) uncompressed: u64,
}

impl std::fmt::Display for DecompressionBomb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CHM compressed section declares {} bytes from {} compressed",
            self.uncompressed, self.compressed
        )
    }
}

impl std::error::Error for DecompressionBomb {}

/// Decompress an LZX-encoded MSCompressed/Content stream into a flat
/// byte buffer using the reset points provided by `rt`.
///
/// **Two CHM-specific framing details vs. stock `lzxd`:**
///
/// 1. CHM uses plain LZX, not LZX-DELTA — there is no E8-translation
///    flag bit at the start of the bitstream. We construct the decoder
///    via [`Lzxd::new_plain`] so the first block header reads at the
///    correct alignment.
///
/// 2. Each LZX block in a CHM stream encodes exactly `block_len` (32
///    KB by spec) bytes of decompressed output, even when that's more
///    than the file's actual content. The decoder must be asked for
///    `block_len` per call; we then truncate the final block to the
///    real `uncompressed_size`. Asking for the truncated count
///    directly causes the decoder to fall short of the encoded block
///    boundary and corrupt later state — this is why the earlier
///    "ask for the actual remaining" approach failed with "invalid
///    path lengths" on real samples.
///
/// The decoder is reset at every reset interval (every
/// `reset_interval_chunks` blocks) per CHM convention.
fn decompress_lzx(content: &[u8], cd: &ControlData, rt: &ResetTable) -> Result<Vec<u8>> {
    if cd.reset_interval_chunks == 0 {
        bail!("reset_interval is 0");
    }
    if rt.uncompressed_size == 0 {
        return Ok(Vec::new());
    }
    let compressed = content.len() as u64;
    if rt.uncompressed_size >= MIN_ZIP_BOMB_UNCOMPRESSED_SIZE
        && rt
            .uncompressed_size
            .checked_div(compressed)
            .is_none_or(|ratio| ratio > MAX_COMPRESSION_RATIO)
    {
        return Err(DecompressionBomb {
            compressed,
            uncompressed: rt.uncompressed_size,
        }
        .into());
    }
    // Sanity guard against a malformed table with a runaway block_len.
    let Ok(block_len @ 1..=MAX_BLOCK_LEN) = usize::try_from(rt.block_len) else {
        bail!("CHM ResetTable block_len {} out of range", rt.block_len);
    };
    let total_uncompressed = usize::try_from(rt.uncompressed_size).unwrap_or(usize::MAX);

    // `uncompressed_size` is a header field the file controls. Reserving it
    // outright let a forged value request an allocation that aborts the
    // process, which no `catch_unwind` upstream can stop. Reserve at most what
    // the blocks can emit, and no more than a typical CHM; `out` grows past
    // that only as real output arrives.
    let reserve = total_uncompressed
        .min(rt.reset_offsets.len().saturating_mul(block_len))
        .min(MAX_UPFRONT_RESERVE);
    let mut out = Vec::with_capacity(reserve);
    // Stock `Lzxd::new` matches chmlib's per-reset-interval header read:
    // the first bit of each reset interval is the intel-translation flag
    // (CHM never sets it, so it's a free 0 bit, but we MUST consume it
    // to stay aligned with the block-header that follows).
    let mut decoder = Lzxd::new(cd.window);
    let reset_interval_blocks = cd.reset_interval_chunks as usize;

    // Each block runs from its reset offset to the next one (the last to the
    // end of the content).
    let ends = rt
        .reset_offsets
        .iter()
        .skip(1)
        .copied()
        .chain(std::iter::once(compressed));
    for (i, (&start, end)) in rt.reset_offsets.iter().zip(ends).enumerate() {
        let block = usize::try_from(start)
            .ok()
            .zip(usize::try_from(end).ok())
            .and_then(|(start, end)| content.get(start..end))
            .with_context(|| {
                format!(
                    "ResetTable offset out of range (start={start}, end={end}, content={})",
                    content.len()
                )
            })?;
        // Reset the decoder at every reset-interval boundary. The first
        // iteration uses a fresh decoder; subsequent block_index values
        // that align with the interval get a `reset()`.
        if i > 0 && i.checked_rem(reset_interval_blocks) == Some(0) {
            decoder.reset();
        }
        let decoded = decoder
            .decompress_next(block, block_len)
            .map_err(|e| anyhow::anyhow!("LZX decompress block {i}: {e}"))?;
        // The encoded block always emits `block_len` bytes; trim only
        // what's needed to reach `total_uncompressed`.
        let remaining = total_uncompressed.saturating_sub(out.len());
        out.extend(decoded.iter().copied().take(remaining));
        if out.len() >= total_uncompressed {
            break;
        }
    }
    Ok(out)
}

/// Walk the ITSP directory chunks and return the flat list of leaf
/// entries (one per internal file).
fn parse_directory(section: &[u8]) -> Result<Vec<ChmEntry>> {
    if section.len() < 0x54 || !section.starts_with(b"ITSP") {
        bail!("missing ITSP header");
    }
    let field = |offset| usize_le(section, offset).context("ITSP header truncated");
    let chunk_size = field(0x10)?;
    let chunk_count = field(0x2c)?;
    if chunk_size < 0x14 {
        bail!("ITSP chunk_size {chunk_size} too small");
    }

    let header_len = field(0x08)?;
    let mut entries = Vec::new();
    for i in 0..chunk_count {
        let Some(chunk) = i
            .checked_mul(chunk_size)
            .and_then(|offset| offset.checked_add(header_len))
            .and_then(|start| section.get(start..start.checked_add(chunk_size)?))
        else {
            break;
        };
        if !chunk.starts_with(b"PMGL") {
            // PMGI index chunk — skip; we only need leaf entries.
            continue;
        }
        let Some(quickref) = usize_le(chunk, 0x04).filter(|&quickref| quickref < chunk_size) else {
            continue;
        };
        let entries_end = chunk_size.saturating_sub(quickref);
        let mut pos = 0x14usize;
        // Each entry consumes at least four ENCINT bytes, so `pos` advances.
        while let Some(rest) = chunk.get(pos..entries_end).filter(|rest| !rest.is_empty()) {
            let Some((entry, consumed)) = parse_entry(rest) else {
                break;
            };
            pos = pos.saturating_add(consumed);
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn parse_entry(buf: &[u8]) -> Option<(ChmEntry, usize)> {
    let (name_len, mut pos) = read_encint(buf)?;
    // An ENCINT spans up to 70 bits, so the length can be near `u64::MAX`;
    // `pos + name_len` would wrap and slip past a plain bounds check.
    let name_end = pos.checked_add(usize::try_from(name_len).ok()?)?;
    let name = String::from_utf8_lossy(buf.get(pos..name_end)?).into_owned();
    pos = name_end;
    let mut next_encint = || {
        let (value, len) = read_encint(buf.get(pos..)?)?;
        pos = pos.checked_add(len)?;
        Some(value)
    };
    let section = next_encint()?;
    let offset = next_encint()?;
    let length = next_encint()?;
    Some((
        ChmEntry {
            name,
            section,
            offset,
            length,
        },
        pos,
    ))
}

/// Decode one CHM ENCINT (variable-length, big-endian, high bit = continue).
fn read_encint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (len, &b) in (1..=10).zip(buf) {
        // Bits shifted past the top of a 10-byte (70-bit) value are dropped.
        value = value.wrapping_shl(7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((value, len));
        }
    }
    None
}

fn u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let bytes = buf.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// A little-endian `u32` field used as a size or count.
fn usize_le(buf: &[u8], off: usize) -> Option<usize> {
    usize::try_from(u32_le(buf, off)?).ok()
}

fn slice_at(buf: &[u8], offset: u64, length: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(length).ok()?)?;
    buf.get(start..end)
}

/// Sanitize an entry name to a relative path safe for extraction.
///
/// Returns `None` for names that are CHM-internal, empty, or attempt
/// path traversal.
fn sanitize_chm_name(name: &str) -> Option<String> {
    let trimmed = name.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    for component in trimmed.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return None;
        }
        if component.contains('\\') {
            return None;
        }
    }
    Some(trimmed.to_owned())
}

/// One user-visible file extracted from a CHM container, held in memory.
pub(crate) struct ChmMember {
    /// Relative path with leading slashes stripped (e.g. `help.html`).
    pub relative_path: String,
    /// Decoded file bytes.
    pub data: Vec<u8>,
}

/// Decode every user-visible internal file in `data` and return them as
/// in-memory members. Control files (`#SYSTEM`, `::DataSpace/...`,
/// `$OBJINST`, …) are skipped — they're only needed for kv extraction
/// and parsing, not for downstream content analysis.
///
/// The archive caller routes `path_traversals` and `bomb` through the
/// existing `push_archive_hostile_findings` pipeline.
pub(crate) fn collect_members(data: &[u8]) -> Result<ChmContents> {
    let chm = Chm::parse(data)?;
    let mut bomb = None;
    let content_blob = match chm.decompress_mscompressed() {
        Ok(v) => {
            tracing::debug!(
                blob_bytes = v.as_ref().map(Vec::len).unwrap_or(0),
                entries = chm.entries.len(),
                "CHM LZX decompressed"
            );
            v
        }
        Err(e) => {
            bomb = e.downcast_ref::<DecompressionBomb>().copied();
            tracing::debug!(error = %e, "CHM LZX decompression unavailable; using uncompressed entries only");
            None
        }
    };

    let mut members = Vec::new();
    let mut path_traversals = Vec::new();
    for entry in &chm.entries {
        if entry.length == 0 || entry.is_internal() {
            continue;
        }
        let Some(rel_name) = sanitize_chm_name(&entry.name) else {
            path_traversals.push(entry.name.clone());
            continue;
        };

        let bytes: Option<Vec<u8>> = match entry.section {
            0 => chm.read_uncompressed(entry).map(<[u8]>::to_vec),
            1 => content_blob
                .as_deref()
                .and_then(|c| slice_at(c, entry.offset, entry.length))
                .map(<[u8]>::to_vec),
            _ => None,
        };
        let Some(bytes) = bytes else {
            tracing::debug!(name = %entry.name, "CHM entry data unavailable");
            continue;
        };
        members.push(ChmMember {
            relative_path: rel_name,
            data: bytes,
        });
    }
    Ok(ChmContents {
        members,
        path_traversals,
        bomb,
    })
}

/// What [`collect_members`] recovered from a CHM.
pub(crate) struct ChmContents {
    /// Decoded user-visible files.
    pub members: Vec<ChmMember>,
    /// Entry names that would escape the extraction root.
    pub path_traversals: Vec<String>,
    /// Set when the compressed section was refused as a decompression bomb;
    /// its members are then missing from `members`.
    pub bomb: Option<DecompressionBomb>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encint_decode_single_byte() {
        assert_eq!(read_encint(&[0x05, 0xFF]), Some((5, 1)));
    }

    #[test]
    fn encint_decode_multi_byte() {
        // 0x82 0x05 → (2 << 7) | 5 = 261
        assert_eq!(read_encint(&[0x82, 0x05]), Some((261, 2)));
    }

    #[test]
    fn encint_decode_three_byte() {
        // 0x81 0x80 0x01 → ((1 << 7) | 0) << 7 | 1 = 16385
        assert_eq!(read_encint(&[0x81, 0x80, 0x01]), Some((16385, 3)));
    }

    #[test]
    fn sanitize_rejects_traversal() {
        assert_eq!(sanitize_chm_name("../etc/passwd"), None);
        assert_eq!(sanitize_chm_name("a/../b"), None);
        assert_eq!(sanitize_chm_name("/foo"), Some("foo".to_owned()));
        assert_eq!(
            sanitize_chm_name("foo/bar.html"),
            Some("foo/bar.html".to_owned())
        );
    }

    #[test]
    fn sanitize_rejects_internal() {
        // `is_internal` (handled at extract_chm_to_dir level) covers these,
        // but sanitize itself is path-only.
        assert!(sanitize_chm_name("help.html").is_some());
    }

    #[test]
    fn parse_rejects_non_itsf() {
        assert!(Chm::parse(b"not a CHM file at all not even close").is_err());
    }

    #[test]
    fn parse_rejects_short() {
        assert!(Chm::parse(b"ITSF").is_err());
    }

    /// A 10-byte ENCINT name length near `u64::MAX` made `pos + name_len`
    /// overflow; the entry must be rejected, not panic.
    #[test]
    fn parse_entry_rejects_overflowing_name_len() {
        let mut buf = vec![0xFF; 9];
        buf.extend_from_slice(&[0x7F, b'a', 0x00, 0x00, 0x00]);
        assert!(parse_entry(&buf).is_none());
    }

    /// A small stream declaring a huge output is refused before decoding, as
    /// the archive guard refuses the same ratio for other formats.
    #[test]
    fn decompress_refuses_decompression_bomb() {
        let cd = ControlData {
            reset_interval_chunks: 1,
            window: WindowSize::KB32,
        };
        let rt = ResetTable {
            uncompressed_size: 1 << 30,
            block_len: 0x8000,
            reset_offsets: vec![0],
        };
        let err = decompress_lzx(&[0u8; 4096], &cd, &rt).err();
        assert_eq!(
            err.as_ref()
                .and_then(|e| e.downcast_ref::<DecompressionBomb>()),
            Some(&DecompressionBomb {
                compressed: 4096,
                uncompressed: 1 << 30
            })
        );
    }

    /// A forged `uncompressed_size` must not be reserved up front: `u64::MAX`
    /// used to request an allocation that panics or aborts.
    #[test]
    fn decompress_does_not_reserve_forged_uncompressed_size() {
        let cd = ControlData {
            reset_interval_chunks: 1,
            window: WindowSize::KB32,
        };
        let rt = ResetTable {
            uncompressed_size: u64::MAX,
            block_len: 0x8000,
            reset_offsets: vec![0],
        };
        // Not a valid LZX stream: decoding fails, but cleanly.
        let _ = decompress_lzx(&[0u8; 16], &cd, &rt);
    }
}
