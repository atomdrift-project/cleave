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
        if data.len() < 0x60 || &data[0..4] != b"ITSF" {
            bail!("not a CHM file (missing ITSF magic)");
        }
        let version = u32_le(data, 0x04);
        if version != 3 {
            bail!("unsupported CHM version {version} (only v3 supported)");
        }

        // Section 1 of the ITSF header table holds the ITSP + directory.
        let section1_offset = u64_le(data, 0x48);
        let section1_length = u64_le(data, 0x50);
        let data_offset = u64_le(data, 0x58);

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
        slice_at(self.data, self.data_offset + entry.offset, entry.length)
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
        if data.len() < 0x1c || &data[4..8] != b"LZXC" {
            bail!("ControlData missing LZXC signature");
        }
        let reset_interval_chunks = u32_le(data, 0x0c);
        let window_chunks = u32_le(data, 0x10);
        // window_chunks is in units of 0x8000 (32 KB).
        let window_bytes = u64::from(window_chunks) * 0x8000;
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
        let num_entries = u32_le(data, 0x04) as usize;
        let entry_size = u32_le(data, 0x08);
        let table_offset = u32_le(data, 0x0c) as usize;
        let uncompressed_size = u64_le(data, 0x10);
        let block_len = u64_le(data, 0x20);
        if entry_size != 8 {
            bail!("ResetTable entry size {entry_size} (expected 8)");
        }
        if block_len == 0 {
            bail!("ResetTable block_len is 0");
        }
        let needed = table_offset + num_entries * 8;
        if data.len() < needed {
            bail!(
                "ResetTable truncated (need {needed} bytes, have {})",
                data.len()
            );
        }
        let mut reset_offsets = Vec::with_capacity(num_entries);
        for i in 0..num_entries {
            reset_offsets.push(u64_le(data, table_offset + i * 8));
        }
        Ok(Self {
            uncompressed_size,
            block_len,
            reset_offsets,
        })
    }
}

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
    let block_len = rt.block_len as usize;
    let total_uncompressed = rt.uncompressed_size as usize;
    // Sanity guard against a malformed table with a runaway block_len.
    if block_len == 0 || block_len > 1 << 20 {
        bail!("CHM ResetTable block_len {block_len} out of range");
    }

    let mut out = Vec::with_capacity(total_uncompressed);
    // Stock `Lzxd::new` matches chmlib's per-reset-interval header read:
    // the first bit of each reset interval is the intel-translation flag
    // (CHM never sets it, so it's a free 0 bit, but we MUST consume it
    // to stay aligned with the block-header that follows).
    let mut decoder = Lzxd::new(cd.window);
    let reset_interval_blocks = cd.reset_interval_chunks as usize;

    for i in 0..rt.reset_offsets.len() {
        let start = rt.reset_offsets[i] as usize;
        let end = rt
            .reset_offsets
            .get(i + 1)
            .map(|&v| v as usize)
            .unwrap_or(content.len());
        if start > content.len() || end > content.len() || end < start {
            bail!(
                "ResetTable offset out of range (start={start}, end={end}, content={})",
                content.len()
            );
        }
        // Reset the decoder at every reset-interval boundary. The first
        // iteration uses a fresh decoder; subsequent block_index values
        // that align with the interval get a `reset()`.
        if i > 0 && reset_interval_blocks > 0 && i % reset_interval_blocks == 0 {
            decoder.reset();
        }
        let decoded = decoder
            .decompress_next(&content[start..end], block_len)
            .map_err(|e| anyhow::anyhow!("LZX decompress block {i}: {e}"))?;
        // The encoded block always emits `block_len` bytes; trim only
        // what's needed to reach `total_uncompressed`.
        let remaining = total_uncompressed - out.len();
        let take = remaining.min(decoded.len());
        out.extend_from_slice(&decoded[..take]);
        if out.len() >= total_uncompressed {
            break;
        }
    }
    Ok(out)
}

/// Walk the ITSP directory chunks and return the flat list of leaf
/// entries (one per internal file).
fn parse_directory(section: &[u8]) -> Result<Vec<ChmEntry>> {
    if section.len() < 0x54 || &section[0..4] != b"ITSP" {
        bail!("missing ITSP header");
    }
    let chunk_size = u32_le(section, 0x10) as usize;
    let chunk_count = u32_le(section, 0x2c) as usize;
    if chunk_size < 0x14 {
        bail!("ITSP chunk_size {chunk_size} too small");
    }

    let header_len = u32_le(section, 0x08) as usize;
    let mut entries = Vec::new();
    for i in 0..chunk_count {
        let off = header_len + i * chunk_size;
        if off + chunk_size > section.len() {
            break;
        }
        let chunk = &section[off..off + chunk_size];
        if &chunk[0..4] != b"PMGL" {
            // PMGI index chunk — skip; we only need leaf entries.
            continue;
        }
        let quickref = u32_le(chunk, 0x04) as usize;
        if quickref >= chunk_size {
            continue;
        }
        let entries_end = chunk_size - quickref;
        let mut pos = 0x14usize;
        while pos < entries_end {
            let Some((entry, consumed)) = parse_entry(&chunk[pos..entries_end]) else {
                break;
            };
            pos += consumed;
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn parse_entry(buf: &[u8]) -> Option<(ChmEntry, usize)> {
    let mut pos = 0;
    let (name_len, n) = read_encint(&buf[pos..])?;
    pos += n;
    let name_len = name_len as usize;
    if pos + name_len > buf.len() {
        return None;
    }
    let name = String::from_utf8_lossy(&buf[pos..pos + name_len]).into_owned();
    pos += name_len;
    let (section, n) = read_encint(&buf[pos..])?;
    pos += n;
    let (offset, n) = read_encint(&buf[pos..])?;
    pos += n;
    let (length, n) = read_encint(&buf[pos..])?;
    pos += n;
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
    for (i, &b) in buf.iter().take(10).enumerate() {
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

fn u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
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
/// Returns `(members, hostile_reasons)`. `hostile_reasons` carries any
/// path-traversal or oversize reasons surfaced during walk so the
/// archive caller can route them through the existing
/// `push_archive_hostile_findings` pipeline.
pub(crate) fn collect_members(data: &[u8]) -> Result<(Vec<ChmMember>, Vec<String>)> {
    let chm = Chm::parse(data)?;
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
            1 => content_blob.as_deref().and_then(|c| {
                let start = entry.offset as usize;
                let end = start.checked_add(entry.length as usize)?;
                c.get(start..end).map(<[u8]>::to_vec)
            }),
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
    Ok((members, path_traversals))
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
}
