//! Pure-Rust extractor for PyInstaller-bundled Windows/Linux executables.
//!
//! PyInstaller appends a "CArchive" overlay to the host executable. The overlay
//! ends with an `MEI\x0c\x0b\x0a\x0b\x0e` cookie that points back to a table of
//! contents (TOC); each TOC entry describes a packaged file (Python source,
//! compiled module, native library, data resource, or a nested PYZ archive).
//!
//! The crate exposes two public entry points:
//!
//! * [`extract_to_memory`] decodes every entry (CArchive top-level + nested
//!   PYZ contents) into an in-memory [`Vec`] of [`MemoryEntry`]. This is the
//!   primary path — used by callers (e.g. cleave) that want to feed each
//!   entry directly into a downstream analyzer without touching the disk.
//! * [`extract`] is a thin convenience wrapper that writes the same entries
//!   to a destination directory.
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

/// Errors returned by [`extract_to_memory`] and [`extract`].
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

/// Coarse classification of a PyInstaller TOC entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Python source script entry-point (CArchive type `s`).
    PySource,
    /// Pre-compiled Python module or package (CArchive type `m`/`M`).
    PyModule,
    /// File extracted from a nested PYZ archive (always a `.pyc`).
    PyzMember,
    /// Splash screen resource (CArchive type `x`).
    Splash,
    /// Native shared library, data resource, or anything else.
    Binary,
}

/// Build provenance recovered from the PyInstaller cookie + TOC.
///
/// Populated by [`extract_to_memory`] and exposed through
/// [`MemoryStats::provenance`]. All fields are best-effort — fields default
/// to empty when the source archive lacks them.
#[derive(Debug, Default, Clone)]
pub struct Provenance {
    /// Embedded Python interpreter version, `(major, minor)`.
    pub python_version: Option<(u8, u8)>,
    /// Filename of the bundled Python shared library, e.g. `python311.dll`
    /// or `libpython3.11.so.1.0`.
    pub python_lib: Option<String>,
    /// `"2.0"` (pre-2014 cookie) or `"2.1+"` (2014+).
    pub cookie_version: &'static str,
    /// Names of `s`-type Python entry-point scripts.
    pub entry_points: Vec<String>,
    /// `o`-type bootloader runtime options (e.g. `pyi-hide-console`,
    /// `pyi-disable-windowed-traceback`, Python `-O`/`-v`/`-s` flags).
    pub runtime_options: Vec<String>,
    /// `d`-type dependency entries — names of sibling CArchives this bundle
    /// references (only present in PyInstaller multi-file `--onedir` style
    /// bundles).
    pub dependencies: Vec<String>,
    /// True if the archive carries a splash screen resource (`x` type).
    pub has_splash: bool,
    /// Total number of entries in the CArchive TOC (including runtime
    /// options and dependencies).
    pub toc_entry_count: usize,
    /// Per-`type_byte` entry counts. Keys are the raw single-byte type codes
    /// observed (`'s'`, `'m'`, `'M'`, `'b'`, `'z'`, `'Z'`, `'d'`, `'o'`,
    /// `'x'`, etc.).
    pub type_counts: std::collections::BTreeMap<u8, usize>,
    /// Sum of compressed sizes across the CArchive TOC.
    pub compressed_size: u64,
    /// Sum of uncompressed sizes across the CArchive TOC.
    pub uncompressed_size: u64,
}

/// One decoded entry held in memory.
#[derive(Debug, Clone)]
pub struct MemoryEntry {
    /// Archive-relative path. Forward slashes; never starts with `/`; never
    /// contains `..` segments.
    pub name: String,
    /// Coarse classification.
    pub kind: EntryKind,
    /// Decompressed bytes. For `.pyc` outputs the bytes already include the
    /// reconstructed pyc header.
    pub data: Vec<u8>,
}

/// Result of an in-memory extraction.
#[derive(Debug, Default)]
pub struct MemoryStats {
    /// Python version embedded in the cookie, if recovered. (major, minor).
    pub py_version: Option<(u8, u8)>,
    /// Names of TOC entries marked as Python source entry points (`s` type).
    pub entry_points: Vec<String>,
    /// All decoded entries (CArchive top-level + PYZ contents).
    pub entries: Vec<MemoryEntry>,
    /// Recovered build provenance.
    pub provenance: Provenance,
}

/// Result of a disk-based extraction.
#[derive(Debug, Default)]
pub struct Stats {
    /// Number of files written to the output directory.
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

/// Decode every CArchive + PYZ entry into an in-memory [`Vec`].
///
/// No filesystem I/O is performed.
pub fn extract_to_memory(data: &[u8]) -> Result<MemoryStats, Error> {
    let cookie_pos = memchr::memmem::rfind(data, MAGIC).ok_or(Error::NotPyInstaller)?;
    let cookie = parse_cookie(data, cookie_pos)?;

    let mut stats = MemoryStats {
        py_version: Some(cookie.py_version),
        ..Default::default()
    };
    stats.provenance.python_version = Some(cookie.py_version);
    stats.provenance.python_lib = cookie.pylibname.clone();
    stats.provenance.cookie_version = if cookie.is_v21 { "2.1+" } else { "2.0" };

    // Indices in stats.entries that need pyc magic back-patching once we learn it.
    let mut bare_pyc_indices: Vec<usize> = Vec::new();
    let mut pyc_magic: Option<[u8; 4]> = None;
    // Defer PYZ walking until after the top-level pass so we know pyc magic.
    let mut pyz_blobs: Vec<Vec<u8>> = Vec::new();

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

        stats.provenance.toc_entry_count = stats.provenance.toc_entry_count.saturating_add(1);
        *stats
            .provenance
            .type_counts
            .entry(entry.type_byte)
            .or_insert(0) += 1;
        stats.provenance.compressed_size = stats
            .provenance
            .compressed_size
            .saturating_add(entry.compressed_size as u64);
        stats.provenance.uncompressed_size = stats
            .provenance
            .uncompressed_size
            .saturating_add(entry.uncompressed_size as u64);

        // Runtime options and dependencies aren't files — they're metadata
        // baked into the TOC entry name.
        match entry.type_byte {
            b'o' => {
                stats.provenance.runtime_options.push(entry.name.clone());
                continue;
            }
            b'd' => {
                stats.provenance.dependencies.push(entry.name.clone());
                continue;
            }
            _ => {}
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
                // Python source entry point — wrap as .pyc with placeholder magic
                // for now; we may patch the magic at the end.
                let body = decompress_to_vec(raw, entry.compressed_flag)?;
                let pyc = build_pyc(pyc_magic.as_ref(), cookie.py_version, &body);
                stats.entry_points.push(safe_name.clone());
                stats.provenance.entry_points.push(safe_name.clone());
                let needs_patch = pyc_magic.is_none();
                stats.entries.push(MemoryEntry {
                    name: format!("{safe_name}.pyc"),
                    kind: EntryKind::PySource,
                    data: pyc,
                });
                if needs_patch {
                    bare_pyc_indices.push(stats.entries.len() - 1);
                }
            }
            b'x' => {
                // Splash screen resource — usually a PNG.
                stats.provenance.has_splash = true;
                let body = decompress_to_vec(raw, entry.compressed_flag)?;
                stats.entries.push(MemoryEntry {
                    name: safe_name,
                    kind: EntryKind::Splash,
                    data: body,
                });
            }
            b'M' | b'm' => {
                let body = decompress_to_vec(raw, entry.compressed_flag)?;
                let (pyc, needs_patch) = if body.len() >= 4 && &body[2..4] == b"\r\n" {
                    // Pre-PyInstaller 5.3 format: header is intact.
                    if pyc_magic.is_none() {
                        if let Ok(m) = body[0..4].try_into() {
                            pyc_magic = Some(m);
                        }
                    }
                    (body, false)
                } else {
                    // Post-5.3: header is stripped.
                    let needs_patch = pyc_magic.is_none();
                    (
                        build_pyc(pyc_magic.as_ref(), cookie.py_version, &body),
                        needs_patch,
                    )
                };
                stats.entries.push(MemoryEntry {
                    name: format!("{safe_name}.pyc"),
                    kind: EntryKind::PyModule,
                    data: pyc,
                });
                if needs_patch {
                    bare_pyc_indices.push(stats.entries.len() - 1);
                }
            }
            b'z' | b'Z' => {
                // Defer; the raw PYZ blob itself is internal — we yield only its inner files.
                let body = decompress_to_vec(raw, entry.compressed_flag)?;
                pyz_blobs.push(body);
            }
            _ => {
                // Generic data / native library — stream-decompress to a Vec.
                let body = decompress_to_vec(raw, entry.compressed_flag)?;
                stats.entries.push(MemoryEntry {
                    name: safe_name,
                    kind: EntryKind::Binary,
                    data: body,
                });
            }
        }
    }

    // Walk PYZ archives now that pyc_magic may be known.
    for (idx, pyz) in pyz_blobs.into_iter().enumerate() {
        let prefix = format!("PYZ-{idx:02}.pyz_extracted");
        walk_pyz_into(
            &pyz,
            &prefix,
            &mut pyc_magic,
            cookie.py_version,
            &mut stats.entries,
        );
    }

    // Patch bare pyc magic in already-emitted entries.
    if let Some(magic) = pyc_magic {
        for idx in bare_pyc_indices {
            if let Some(entry) = stats.entries.get_mut(idx) {
                if entry.data.len() >= 4 {
                    entry.data[0..4].copy_from_slice(&magic);
                }
            }
        }
    }

    Ok(stats)
}

/// Extract a PyInstaller archive into `out_dir`.
///
/// Convenience wrapper that calls [`extract_to_memory`] and writes each entry
/// to disk. `out_dir` is created if it does not exist.
pub fn extract(data: &[u8], out_dir: &Path) -> Result<Stats, Error> {
    let mem = extract_to_memory(data)?;
    fs::create_dir_all(out_dir)?;

    let mut stats = Stats {
        py_version: mem.py_version,
        entry_points: mem.entry_points,
        ..Default::default()
    };

    let mut writer = Writer::new(out_dir);
    for entry in mem.entries {
        let path = writer.path_for(&entry.name);
        ensure_parent(&path)?;
        let mut f = BufWriter::new(File::create(&path)?);
        f.write_all(&entry.data)?;
        f.flush()?;
        stats.files_written = stats.files_written.saturating_add(1);
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
    is_v21: bool,
    /// Bundled Python library filename (only present in v21+ cookies).
    pylibname: Option<String>,
}

fn parse_cookie(data: &[u8], cookie_pos: usize) -> Result<Cookie, Error> {
    let probe_start = cookie_pos
        .checked_add(COOKIE_V20)
        .ok_or(Error::Malformed("cookie position overflow"))?;
    let probe = data
        .get(probe_start..probe_start.saturating_add(64))
        .unwrap_or(&[]);
    let is_v21 = probe.windows(6).any(|w| w.eq_ignore_ascii_case(b"python"));

    let cookie_size = if is_v21 { COOKIE_V21 } else { COOKIE_V20 };
    let cookie_end = cookie_pos
        .checked_add(cookie_size)
        .ok_or(Error::Malformed("cookie size overflow"))?;
    let cookie = data
        .get(cookie_pos..cookie_end)
        .ok_or(Error::Malformed("cookie out of bounds"))?;

    let length_of_package = u32::from_be_bytes(arr4(cookie, 8)?) as usize;
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

    let pylibname = if is_v21 {
        // Bytes 24..88 of the cookie are a NUL-padded ASCII filename.
        let raw = cookie.get(24..88).unwrap_or(&[]);
        let trimmed = match raw.iter().position(|&b| b == 0) {
            Some(idx) => &raw[..idx],
            None => raw,
        };
        if trimmed.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(trimmed).into_owned())
        }
    } else {
        None
    };

    Ok(Cookie {
        overlay_pos,
        toc_pos,
        toc_len,
        py_version: (py_major, py_minor),
        is_v21,
        pylibname,
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
    uncompressed_size: usize,
    compressed_flag: u8,
    type_byte: u8,
    name: String,
}

fn parse_toc_entry(toc: &[u8], cursor: usize) -> Option<TocEntry> {
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

fn walk_pyz_into(
    pyz: &[u8],
    prefix: &str,
    pyc_magic: &mut Option<[u8; 4]>,
    py_version: (u8, u8),
    out: &mut Vec<MemoryEntry>,
) {
    if pyz.len() < 12 || &pyz[0..4] != PYZ_MAGIC {
        return;
    }
    let inner_pyc_magic: [u8; 4] = match pyz[4..8].try_into() {
        Ok(m) => m,
        Err(_) => return,
    };
    if pyc_magic.is_none() {
        *pyc_magic = Some(inner_pyc_magic);
    }
    let toc_bytes = match pyz.get(8..12) {
        Some(b) => b,
        None => return,
    };
    let toc_pos = u32::from_be_bytes(match toc_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return,
    }) as usize;
    if toc_pos >= pyz.len() {
        return;
    }

    let toc = match marshal::parse_pyz_toc(&pyz[toc_pos..]) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("pyz marshal decode failed: {e:?}");
            return;
        }
    };

    for entry in toc {
        let safe_key = sanitize_path(&entry.key.replace('.', "/"));
        let rel = if entry.is_pkg {
            format!("{prefix}/{safe_key}/__init__.pyc")
        } else {
            format!("{prefix}/{safe_key}.pyc")
        };
        let blob = match pyz.get(entry.pos..entry.pos.saturating_add(entry.length)) {
            Some(b) => b,
            None => continue,
        };
        if entry.length == 0 {
            out.push(MemoryEntry {
                name: rel,
                kind: EntryKind::PyzMember,
                data: build_pyc(Some(&inner_pyc_magic), py_version, &[]),
            });
            continue;
        }
        match decompress_to_vec(blob, 1) {
            Ok(decoded) => {
                out.push(MemoryEntry {
                    name: rel,
                    kind: EntryKind::PyzMember,
                    data: build_pyc(Some(&inner_pyc_magic), py_version, &decoded),
                });
            }
            Err(_) => {
                // Encrypted or corrupt — emit the raw blob as a Binary entry.
                out.push(MemoryEntry {
                    name: format!("{rel}.encrypted"),
                    kind: EntryKind::Binary,
                    data: blob.to_vec(),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
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
        let safe = if component == ".." { "__" } else { component };
        if !out.is_empty() {
            out.push('/');
        }
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

fn decompress_to_vec(src: &[u8], compressed_flag: u8) -> Result<Vec<u8>, Error> {
    if compressed_flag != 1 {
        return Ok(src.to_vec());
    }
    let mut decoder = ZlibDecoder::new(src);
    let mut out = Vec::with_capacity(src.len() * 2);
    io::copy(&mut decoder, &mut out)?;
    Ok(out)
}

fn build_pyc(pyc_magic: Option<&[u8; 4]>, py_version: (u8, u8), body: &[u8]) -> Vec<u8> {
    let header = pyc_magic.copied().unwrap_or([0u8; 4]);
    // Header: magic(4) + flags-or-timestamp(4) + size-or-hash(0..8) + body.
    let (major, minor) = py_version;
    let prelude_len = if major >= 3 && minor >= 7 {
        4 + 4 + 8
    } else if major >= 3 && minor >= 3 {
        4 + 4 + 4
    } else {
        4 + 4
    };
    let mut out = Vec::with_capacity(prelude_len + body.len());
    out.extend_from_slice(&header);
    if major >= 3 && minor >= 7 {
        out.extend_from_slice(&[0u8; 4]); // flags
        out.extend_from_slice(&[0u8; 8]); // timestamp+size or hash
    } else {
        out.extend_from_slice(&[0u8; 4]); // timestamp
        if major >= 3 && minor >= 3 {
            out.extend_from_slice(&[0u8; 4]); // size
        }
    }
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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

    #[test]
    fn build_pyc_lengths() {
        // Python 3.11: 4 + 4 + 8 = 16 byte prelude
        let p = build_pyc(Some(&[1, 2, 3, 4]), (3, 11), b"body");
        assert_eq!(p.len(), 16 + 4);
        assert_eq!(&p[0..4], &[1, 2, 3, 4]);
        // Python 3.5: 4 + 4 + 4 = 12 byte prelude
        let p = build_pyc(Some(&[1, 2, 3, 4]), (3, 5), b"body");
        assert_eq!(p.len(), 12 + 4);
        // Python 2.7: 4 + 4 = 8 byte prelude
        let p = build_pyc(Some(&[1, 2, 3, 4]), (2, 7), b"body");
        assert_eq!(p.len(), 8 + 4);
    }
}
