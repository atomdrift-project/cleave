//! Pure-Rust extractor for PyInstaller-bundled Windows/Linux executables.
//!
//! PyInstaller appends a "CArchive" overlay to the host executable. The overlay
//! ends with an `MEI\x0c\x0b\x0a\x0b\x0e` cookie that points back to a table of
//! contents (TOC); each TOC entry describes a packaged file (Python source,
//! compiled module, native library, data resource, or a nested PYZ archive).
//!
//! This crate detects the cookie, walks the TOC, and streams every entry to
//! disk. Compressed entries are decompressed through a zlib stream straight
//! into the output file, so memory stays bounded regardless of entry size.
//! Nested PYZ archives are walked in the same pass and their inner `.pyc`
//! files are written alongside the rest.
//!
//! Reference: <https://github.com/extremecoders-re/pyinstxtractor>

#![deny(unsafe_code)]

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use thiserror::Error;

mod marshal;

/// PyInstaller cookie magic.
const MAGIC: &[u8; 8] = b"MEI\x0c\x0b\x0a\x0b\x0e";

/// Cookie size for PyInstaller 2.0 (no `pylibname` field).
const COOKIE_V20: usize = 24;

/// Cookie size for PyInstaller 2.1+ (adds 64-byte `pylibname`).
const COOKIE_V21: usize = 24 + 64;

/// PYZ archive magic.
const PYZ_MAGIC: &[u8; 4] = b"PYZ\0";

/// Errors returned by [`extract`].
#[derive(Debug, Error)]
pub enum Error {
    /// The byte slice does not contain a PyInstaller cookie.
    #[error("not a PyInstaller archive (cookie not found)")]
    NotPyInstaller,
    /// The cookie was located but the surrounding archive is structurally invalid.
    #[error("malformed PyInstaller archive: {0}")]
    Malformed(&'static str),
    /// Underlying filesystem or stream I/O error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Summary returned from a successful extraction.
#[derive(Debug, Default)]
pub struct Stats {
    /// Number of files written to the output directory (top-level + PYZ contents).
    pub files_written: usize,
    /// Python version embedded in the cookie, if recovered. (major, minor).
    pub py_version: Option<(u8, u8)>,
    /// Names of TOC entries marked as Python source entry points (`s` type).
    pub entry_points: Vec<String>,
}

/// Quick check: does this byte slice contain a PyInstaller cookie?
#[must_use]
pub fn is_pyinstaller(data: &[u8]) -> bool {
    memchr::memmem::rfind(data, MAGIC).is_some()
}

/// Extract a PyInstaller archive into `out_dir`.
///
/// `out_dir` is created if it does not exist. Existing files inside it may be
/// overwritten on name collision (deduplication is handled per-archive via a
/// numeric suffix when the same name appears twice).
pub fn extract(data: &[u8], out_dir: &Path) -> Result<Stats, Error> {
    let cookie_pos =
        memchr::memmem::rfind(data, MAGIC).ok_or(Error::NotPyInstaller)?;

    let cookie = parse_cookie(data, cookie_pos)?;
    fs::create_dir_all(out_dir)?;

    let mut stats = Stats {
        py_version: Some(cookie.py_version),
        ..Default::default()
    };

    let mut writer = Writer::new(out_dir);
    let mut pyc_magic: Option<[u8; 4]> = None;
    let mut bare_pycs: Vec<PathBuf> = Vec::new();
    let mut pyz_blobs: Vec<PathBuf> = Vec::new();

    let toc = data
        .get(cookie.toc_pos..cookie.toc_pos.saturating_add(cookie.toc_len))
        .ok_or(Error::Malformed("TOC out of bounds"))?;

    let mut cursor = 0usize;
    while cursor < toc.len() {
        let entry = match parse_toc_entry(toc, cursor) {
            Some(e) => e,
            None => break,
        };
        cursor = cursor.saturating_add(entry.entry_size);

        // Runtime options / dependencies are not files.
        if entry.type_byte == b'd' || entry.type_byte == b'o' {
            continue;
        }

        let abs_pos = cookie
            .overlay_pos
            .checked_add(entry.position)
            .ok_or(Error::Malformed("entry position overflow"))?;
        let raw = data
            .get(abs_pos..abs_pos.saturating_add(entry.compressed_size))
            .ok_or(Error::Malformed("entry data out of bounds"))?;

        let safe_name = sanitize_path(&entry.name);

        match entry.type_byte {
            b's' => {
                // Python source entry point — wrap as .pyc with a placeholder header.
                let path = writer.path_for(&format!("{safe_name}.pyc"));
                stats.entry_points.push(safe_name.clone());
                let body = decompress_to_vec(raw, entry.compressed_flag)?;
                write_pyc(&path, pyc_magic.as_ref(), cookie.py_version, &body)?;
                if pyc_magic.is_none() {
                    bare_pycs.push(path);
                }
                stats.files_written += 1;
            }
            b'M' | b'm' => {
                // Modules / packages: pyc files. Pre-5.3 keeps the header,
                // post-5.3 drops it.
                let path = writer.path_for(&format!("{safe_name}.pyc"));
                let body = decompress_to_vec(raw, entry.compressed_flag)?;
                if body.len() >= 4 && &body[2..4] == b"\r\n" {
                    if pyc_magic.is_none() {
                        if let Ok(m) = body[0..4].try_into() {
                            pyc_magic = Some(m);
                        }
                    }
                    write_raw(&path, &body)?;
                } else {
                    write_pyc(&path, pyc_magic.as_ref(), cookie.py_version, &body)?;
                    if pyc_magic.is_none() {
                        bare_pycs.push(path);
                    }
                }
                stats.files_written += 1;
            }
            b'z' | b'Z' => {
                let path = writer.path_for(&safe_name);
                stream_to_file(raw, entry.compressed_flag, &path)?;
                stats.files_written += 1;
                pyz_blobs.push(path);
            }
            _ => {
                let path = writer.path_for(&safe_name);
                stream_to_file(raw, entry.compressed_flag, &path)?;
                stats.files_written += 1;
            }
        }
    }

    // Walk PYZ archives now that we may have learned the pyc magic.
    for pyz_path in pyz_blobs {
        let pyz_data = match fs::read(&pyz_path) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!("pyinstx: cannot read pyz {pyz_path:?}: {e}");
                continue;
            }
        };
        let inner_dir = pyz_path.with_extension("pyz_extracted");
        let written = extract_pyz(&pyz_data, &inner_dir, &mut pyc_magic, cookie.py_version)?;
        stats.files_written = stats.files_written.saturating_add(written);
    }

    // Patch bare pyc files now that we know the magic (if we ever learned it).
    if let Some(magic) = pyc_magic {
        for path in bare_pycs {
            patch_pyc_magic(&path, &magic)?;
        }
    }

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Cookie parsing
// ---------------------------------------------------------------------------

struct Cookie {
    overlay_pos: usize,
    toc_pos: usize,
    toc_len: usize,
    py_version: (u8, u8),
}

fn parse_cookie(data: &[u8], cookie_pos: usize) -> Result<Cookie, Error> {
    // Distinguish 2.0 from 2.1+: 2.1+ has the python lib name string starting
    // 24 bytes after the cookie magic. The reference checks for "python" in
    // the next 64 bytes lower-cased.
    let probe_start = cookie_pos
        .checked_add(COOKIE_V20)
        .ok_or(Error::Malformed("cookie position overflow"))?;
    let probe = data
        .get(probe_start..probe_start.saturating_add(64))
        .unwrap_or(&[]);
    let is_v21 = probe
        .windows(6)
        .any(|w| w.eq_ignore_ascii_case(b"python"));

    let cookie_size = if is_v21 { COOKIE_V21 } else { COOKIE_V20 };
    let cookie_end = cookie_pos
        .checked_add(cookie_size)
        .ok_or(Error::Malformed("cookie size overflow"))?;
    let cookie = data
        .get(cookie_pos..cookie_end)
        .ok_or(Error::Malformed("cookie out of bounds"))?;

    // Layout (big-endian):
    //   [0..8]   magic
    //   [8..12]  length_of_package (u32)
    //   [12..16] toc offset within overlay (u32)
    //   [16..20] toc length (i32)
    //   [20..24] python version (i32)
    //   [24..88] python lib name (v21 only)
    let length_of_package =
        u32::from_be_bytes(arr4(cookie, 8)?) as usize;
    let toc = u32::from_be_bytes(arr4(cookie, 12)?) as usize;
    let toc_len = u32::from_be_bytes(arr4(cookie, 16)?) as usize;
    let pyver = u32::from_be_bytes(arr4(cookie, 20)?) as usize;

    let (py_major, py_minor) = if pyver >= 100 {
        ((pyver / 100) as u8, (pyver % 100) as u8)
    } else {
        ((pyver / 10) as u8, (pyver % 10) as u8)
    };

    let tail_bytes = data
        .len()
        .checked_sub(cookie_pos)
        .and_then(|v| v.checked_sub(cookie_size))
        .ok_or(Error::Malformed("tail bytes underflow"))?;
    let overlay_size = length_of_package
        .checked_add(tail_bytes)
        .ok_or(Error::Malformed("overlay size overflow"))?;
    let overlay_pos = data
        .len()
        .checked_sub(overlay_size)
        .ok_or(Error::Malformed("overlay position underflow"))?;
    let toc_pos = overlay_pos
        .checked_add(toc)
        .ok_or(Error::Malformed("toc position overflow"))?;

    if toc_pos.saturating_add(toc_len) > data.len() {
        return Err(Error::Malformed("toc extends beyond file"));
    }

    Ok(Cookie {
        overlay_pos,
        toc_pos,
        toc_len,
        py_version: (py_major, py_minor),
    })
}

fn arr4(buf: &[u8], offset: usize) -> Result<[u8; 4], Error> {
    buf.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Malformed("short read"))
}

// ---------------------------------------------------------------------------
// TOC entry parsing
// ---------------------------------------------------------------------------

struct TocEntry {
    entry_size: usize,
    position: usize,
    compressed_size: usize,
    #[allow(dead_code)]
    uncompressed_size: usize,
    compressed_flag: u8,
    type_byte: u8,
    name: String,
}

fn parse_toc_entry(toc: &[u8], cursor: usize) -> Option<TocEntry> {
    // Per-entry layout (big-endian):
    //   [0..4]  entrySize (i32)            -- includes the entrySize field itself
    //   [4..8]  entryPos (u32)
    //   [8..12] cmprsdDataSize (u32)
    //   [12..16] uncmprsdDataSize (u32)
    //   [16]   cmprsFlag (u8)
    //   [17]   typeCmprsData (1 byte char)
    //   [18..]  name (NUL-padded, length = entrySize - 18)
    let header_len = 18;
    let entry_size_bytes = toc.get(cursor..cursor + 4)?;
    let entry_size = i32::from_be_bytes(entry_size_bytes.try_into().ok()?);
    if entry_size < header_len as i32 {
        return None;
    }
    let entry_size = entry_size as usize;
    let end = cursor.checked_add(entry_size)?;
    let entry = toc.get(cursor..end)?;

    let position = u32::from_be_bytes(entry.get(4..8)?.try_into().ok()?) as usize;
    let compressed_size = u32::from_be_bytes(entry.get(8..12)?.try_into().ok()?) as usize;
    let uncompressed_size = u32::from_be_bytes(entry.get(12..16)?.try_into().ok()?) as usize;
    let compressed_flag = *entry.get(16)?;
    let type_byte = *entry.get(17)?;
    let name_bytes = entry.get(18..)?;
    // Strip trailing NULs and decode lossily — names are usually ASCII.
    let trimmed = match name_bytes.iter().position(|&b| b == 0) {
        Some(idx) => &name_bytes[..idx],
        None => name_bytes,
    };
    let name = String::from_utf8_lossy(trimmed).into_owned();
    let name = if name.is_empty() {
        format!("unnamed_{position:08x}")
    } else {
        name
    };

    Some(TocEntry {
        entry_size,
        position,
        compressed_size,
        uncompressed_size,
        compressed_flag,
        type_byte,
        name,
    })
}

// ---------------------------------------------------------------------------
// PYZ extraction
// ---------------------------------------------------------------------------

fn extract_pyz(
    pyz: &[u8],
    out_dir: &Path,
    pyc_magic: &mut Option<[u8; 4]>,
    py_version: (u8, u8),
) -> Result<usize, Error> {
    if pyz.len() < 12 || &pyz[0..4] != PYZ_MAGIC {
        return Ok(0);
    }
    fs::create_dir_all(out_dir)?;

    let inner_pyc_magic: [u8; 4] = pyz[4..8]
        .try_into()
        .map_err(|_| Error::Malformed("pyz pyc magic"))?;
    if pyc_magic.is_none() {
        *pyc_magic = Some(inner_pyc_magic);
    }
    let toc_pos = u32::from_be_bytes(pyz[8..12].try_into().unwrap_or([0; 4])) as usize;
    if toc_pos >= pyz.len() {
        return Ok(0);
    }

    // Marshal-decode the inner TOC (a list of (name, (ispkg, pos, length)) tuples).
    let toc = match marshal::parse_pyz_toc(&pyz[toc_pos..]) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("pyz marshal decode failed: {e:?}");
            return Ok(0);
        }
    };

    let mut writer = Writer::new(out_dir);
    let mut written = 0usize;

    for entry in toc {
        let safe_key = sanitize_path(&entry.key.replace('.', std::path::MAIN_SEPARATOR_STR));
        let rel = if entry.is_pkg {
            format!("{safe_key}/__init__.pyc")
        } else {
            format!("{safe_key}.pyc")
        };
        let out_path = writer.path_for(&rel);
        let blob = match pyz.get(entry.pos..entry.pos.saturating_add(entry.length)) {
            Some(b) => b,
            None => continue,
        };
        if entry.length == 0 {
            write_pyc(&out_path, Some(&inner_pyc_magic), py_version, &[])?;
            written += 1;
            continue;
        }
        match decompress_to_vec(blob, 1) {
            Ok(decoded) => {
                write_pyc(&out_path, Some(&inner_pyc_magic), py_version, &decoded)?;
                written += 1;
            }
            Err(_) => {
                // Encrypted or corrupt — drop the raw blob with a marker.
                let raw_path = out_path.with_extension("pyc.encrypted");
                write_raw(&raw_path, blob)?;
                written += 1;
            }
        }
    }

    Ok(written)
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

struct Writer {
    root: PathBuf,
    seen: std::collections::HashSet<PathBuf>,
}

impl Writer {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            seen: std::collections::HashSet::new(),
        }
    }

    fn path_for(&mut self, rel: &str) -> PathBuf {
        let mut path = self.root.join(rel);
        let mut counter = 1usize;
        while self.seen.contains(&path) {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("dup")
                .to_string();
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string());
            let new_name = match ext {
                Some(e) => format!("{stem}.{counter}.{e}"),
                None => format!("{stem}.{counter}"),
            };
            path = path.with_file_name(new_name);
            counter += 1;
        }
        self.seen.insert(path.clone());
        path
    }
}

fn sanitize_path(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for component in name.split(['/', '\\']) {
        if component.is_empty() || component == "." {
            continue;
        }
        let safe = if component == ".." {
            "__"
        } else {
            component
        };
        if !out.is_empty() {
            out.push(std::path::MAIN_SEPARATOR);
        }
        // Strip characters that are illegal on Windows so cleave can extract
        // these archives on any host without write failures.
        for ch in safe.chars() {
            if matches!(ch, '\0' | ':' | '*' | '?' | '<' | '>' | '|' | '"') {
                out.push('_');
            } else {
                out.push(ch);
            }
        }
    }
    if out.is_empty() {
        out.push_str("unnamed");
    }
    out
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn stream_to_file(src: &[u8], compressed_flag: u8, path: &Path) -> Result<(), Error> {
    ensure_parent(path)?;
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    if compressed_flag == 1 {
        let mut decoder = ZlibDecoder::new(src);
        // Tolerate corrupt zlib streams: write what we successfully decoded,
        // log the rest. Malware sometimes ships truncated entries.
        if let Err(e) = io::copy(&mut decoder, &mut writer) {
            tracing::debug!("pyinstx zlib stream error for {path:?}: {e}");
        }
    } else {
        writer.write_all(src)?;
    }
    writer.flush()?;
    Ok(())
}

fn decompress_to_vec(src: &[u8], compressed_flag: u8) -> Result<Vec<u8>, Error> {
    if compressed_flag != 1 {
        return Ok(src.to_vec());
    }
    let mut decoder = ZlibDecoder::new(src);
    let mut out = Vec::with_capacity(src.len() * 2);
    io::copy(&mut decoder, &mut out)?;
    Ok(out)
}

fn write_raw(path: &Path, data: &[u8]) -> Result<(), Error> {
    ensure_parent(path)?;
    fs::write(path, data)?;
    Ok(())
}

fn write_pyc(
    path: &Path,
    pyc_magic: Option<&[u8; 4]>,
    py_version: (u8, u8),
    body: &[u8],
) -> Result<(), Error> {
    ensure_parent(path)?;
    let mut f = BufWriter::new(File::create(path)?);
    let placeholder = [0u8; 4];
    let header = pyc_magic.copied().unwrap_or(placeholder);
    f.write_all(&header)?;
    let (major, minor) = py_version;
    if major >= 3 && minor >= 7 {
        // PEP-552 deterministic pyc: 4 bytes flags + 8 bytes (timestamp+size or hash).
        f.write_all(&[0u8; 4])?;
        f.write_all(&[0u8; 8])?;
    } else {
        // Pre-3.7: 4-byte timestamp; 3.3+ adds a 4-byte size.
        f.write_all(&[0u8; 4])?;
        if major >= 3 && minor >= 3 {
            f.write_all(&[0u8; 4])?;
        }
    }
    f.write_all(body)?;
    f.flush()?;
    Ok(())
}

fn patch_pyc_magic(path: &Path, magic: &[u8; 4]) -> Result<(), Error> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.seek(SeekFrom::Start(0))?;
    f.write_all(magic)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_magic() {
        let mut data = vec![0u8; 256];
        data[100..108].copy_from_slice(MAGIC);
        assert!(is_pyinstaller(&data));
    }

    #[test]
    fn rejects_non_archive() {
        assert!(!is_pyinstaller(b"hello world"));
    }

    #[test]
    fn sanitizes_traversal() {
        assert_eq!(sanitize_path("../../etc/passwd"), "__/__/etc/passwd");
        assert_eq!(sanitize_path("/abs/path"), "abs/path");
        assert_eq!(sanitize_path(""), "unnamed");
        assert_eq!(sanitize_path("a/./b"), "a/b");
    }
}
