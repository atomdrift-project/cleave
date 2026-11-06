//! Reading archive members back out by their in-archive path.
//!
//! A differential consumer needs the *old* text of a changed member to show
//! which lines a new release added; the diff carries only analysis metadata,
//! so the bytes have to come from the archive itself. Both entry points reuse
//! the decoders analysis does (gzip / bzip2 / xz / zstd tarballs and zip),
//! detected by magic rather than extension so a mislabeled archive still
//! resolves.
//!
//! A member is absent — `Ok(None)`, never an error — when the archive lacks
//! it, the file is not a supported archive, or the path names a member of a
//! *nested* archive (a `!` in it), which would need recursive extraction.

use anyhow::{Context as _, Result};
use rustc_hash::FxHashMap;
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

/// Hard ceiling on a single extracted member, mirroring analysis's per-member
/// guard: differential evidence never needs a whole disk image resident.
const MAX_EXTRACTED_MEMBER: u64 = 64 * 1024 * 1024;

/// Most member bytes [`ArchiveMembers`] holds for one tar. A larger tar is
/// re-read per member instead of held resident.
const MAX_HELD: u64 = 512 * 1024 * 1024;

/// Read one member of `archive`, at most its first 64 MiB (a longer member is
/// truncated, and the truncation logged). Each call reads and decodes the archive
/// again; a caller reading several members of one archive wants
/// [`ArchiveMembers`].
pub fn extract_member(archive: &Path, member: &str) -> Result<Option<Vec<u8>>> {
    if member.contains('!') {
        return Ok(None);
    }
    let data = read(archive)?;
    if is_zip(&data) {
        return match ::zip::ZipArchive::new(Cursor::new(data)) {
            Ok(mut zip) => zip_member(&mut zip, member),
            Err(_) => Ok(None),
        };
    }
    tar_stream(&data).map_or(Ok(None), |tar| scan(tar, member))
}

/// An archive decoded once for many member reads.
///
/// [`extract_member`] decodes a compressed tar from the start for every
/// member, so reading each changed file of a release is quadratic in the
/// archive. Opening reads a tar's members in one pass and holds them; a zip, whose
/// members are addressed directly, stays open and inflates on request.
pub struct ArchiveMembers(Store);

enum Store {
    Zip(Mutex<::zip::ZipArchive<Cursor<Vec<u8>>>>),
    /// By path, `./` stripped; the first of a duplicated path wins, as a
    /// stream scan finds it first.
    Tar(FxHashMap<String, Vec<u8>>),
    /// A tar whose members exceed [`MAX_HELD`]: the archive bytes, decoded
    /// again on each read.
    Stream(Vec<u8>),
}

impl ArchiveMembers {
    /// Open `archive`, or `None` when it is not a supported archive.
    ///
    /// # Errors
    ///
    /// When `archive` cannot be read.
    pub fn open(archive: &Path) -> Result<Option<Self>> {
        Self::open_holding(archive, MAX_HELD)
    }

    fn open_holding(archive: &Path, limit: u64) -> Result<Option<Self>> {
        let data = read(archive)?;
        if is_zip(&data) {
            return Ok(::zip::ZipArchive::new(Cursor::new(data))
                .ok()
                .map(|zip| Self(Store::Zip(Mutex::new(zip)))));
        }
        let Some(tar) = tar_stream(&data) else {
            return Ok(None);
        };
        let store = match hold(tar, limit) {
            Some(members) => {
                tracing::debug!(
                    archive = %archive.display(),
                    members = members.len(),
                    bytes = members.values().map(Vec::len).sum::<usize>(),
                    "holding archive members"
                );
                Store::Tar(members)
            }
            None => {
                tracing::debug!(
                    archive = %archive.display(),
                    limit,
                    "archive members exceed the hold limit; reading each by a stream scan"
                );
                Store::Stream(data)
            }
        };
        Ok(Some(Self(store)))
    }

    /// Read one member.
    ///
    /// # Errors
    ///
    /// When a zip member or a re-scanned tar member fails to decode.
    pub fn member(&self, member: &str) -> Result<Option<Vec<u8>>> {
        if member.contains('!') {
            return Ok(None);
        }
        match &self.0 {
            Store::Tar(held) => Ok(held.get(member).cloned()),
            Store::Zip(zip) => zip_member(
                &mut zip.lock().unwrap_or_else(PoisonError::into_inner),
                member,
            ),
            Store::Stream(data) => tar_stream(data).map_or(Ok(None), |tar| scan(tar, member)),
        }
    }
}

impl std::fmt::Debug for ArchiveMembers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let store = match &self.0 {
            Store::Zip(_) => "zip",
            Store::Tar(_) => "held tar",
            Store::Stream(_) => "streamed tar",
        };
        f.debug_tuple("ArchiveMembers").field(&store).finish()
    }
}

fn read(archive: &Path) -> Result<Vec<u8>> {
    std::fs::read(archive).with_context(|| format!("reading archive {}", archive.display()))
}

fn is_zip(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
}

/// The uncompressed tar stream inside `data`, or `None` when it is no tar.
fn tar_stream(data: &[u8]) -> Option<Box<dyn Read + '_>> {
    Some(if data.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(data))
    } else if data.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        Box::new(xz2::read::XzDecoder::new(data))
    } else if data.starts_with(b"BZh") {
        Box::new(bzip2::read::BzDecoder::new(data))
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Box::new(zstd::stream::read::Decoder::with_buffer(data).ok()?)
    } else if data.get(257..262) == Some(b"ustar") {
        Box::new(data)
    } else {
        return None;
    })
}

fn zip_member<R: Read + Seek>(
    zip: &mut ::zip::ZipArchive<R>,
    member: &str,
) -> Result<Option<Vec<u8>>> {
    let Ok(entry) = zip.by_name(member) else {
        return Ok(None);
    };
    Ok(Some(read_capped(entry)?))
}

/// A member's bytes, at most [`MAX_EXTRACTED_MEMBER`] of them.
fn read_capped(entry: impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    entry.take(MAX_EXTRACTED_MEMBER + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_EXTRACTED_MEMBER {
        buf.truncate(MAX_EXTRACTED_MEMBER as usize);
        tracing::warn!(
            limit_bytes = MAX_EXTRACTED_MEMBER,
            "archive member truncated to the extraction limit"
        );
    }
    Ok(buf)
}

/// Stream `tar` up to `member`.
fn scan(tar: impl Read, member: &str) -> Result<Option<Vec<u8>>> {
    let mut archive = ::tar::Archive::new(tar);
    let Ok(entries) = archive.entries() else {
        return Ok(None);
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Ok(path) = entry.path() else { continue };
        // Tar entries may or may not carry a `./` prefix; the diff's member
        // path never does.
        let path = path.to_string_lossy();
        if path == member || path.strip_prefix("./") == Some(member) {
            return Ok(Some(read_capped(entry)?));
        }
    }
    Ok(None)
}

/// Every member of `tar`, or `None` once their bytes pass `limit`.
///
/// A member that fails to decode ends the pass with what was read before
/// it: the stream past a corrupt entry is unreachable either way, and the
/// members ahead of it are still worth having.
fn hold(tar: impl Read, limit: u64) -> Option<FxHashMap<String, Vec<u8>>> {
    let mut held = FxHashMap::default();
    let mut archive = ::tar::Archive::new(tar);
    let Ok(entries) = archive.entries() else {
        return Some(held);
    };
    let mut total: u64 = 0;
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let Ok(path) = entry.path() else { continue };
        let path = path.to_string_lossy();
        let path = path.strip_prefix("./").unwrap_or(&path).to_owned();
        let bytes = match read_capped(entry) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%path, %error, "archive member failed to decode; later members are unreadable");
                break;
            }
        };
        total += bytes.len() as u64;
        if total > limit {
            return None;
        }
        held.entry(path).or_insert(bytes);
    }
    Some(held)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{ArchiveMembers, Store, extract_member};
    use std::io::Write as _;
    use std::path::Path;

    /// A gzip tarball of `members`, in order.
    fn tarball(dir: &Path, members: &[(&str, &str)]) -> std::path::PathBuf {
        let path = dir.join("members.tgz");
        let gz = flate2::write::GzEncoder::new(
            std::fs::File::create(&path).unwrap(),
            flate2::Compression::fast(),
        );
        let mut tar = tar::Builder::new(gz);
        for (name, body) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, body.as_bytes()).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
        path
    }

    fn text(bytes: Option<Vec<u8>>) -> Option<String> {
        bytes.map(|b| String::from_utf8(b).unwrap())
    }

    const MEMBERS: &[(&str, &str)] = &[
        ("./pkg/a.js", "first a"),
        ("pkg/b.js", "first b"),
        ("pkg/b.js", "second b"),
    ];

    /// Both readers agree on every lookup: what a one-shot stream scan finds
    /// is what the held archive returns.
    fn agree(members: &ArchiveMembers, path: &Path) {
        for (member, want) in [
            ("pkg/a.js", Some("first a")),
            ("pkg/b.js", Some("first b")),
            ("pkg/c.js", None),
            ("pkg/a.js!inner.js", None),
        ] {
            let want = want.map(str::to_owned);
            assert_eq!(text(members.member(member).unwrap()), want, "{member}");
            assert_eq!(
                text(extract_member(path, member).unwrap()),
                want,
                "{member}"
            );
        }
    }

    #[test]
    fn a_held_tar_reads_like_a_stream_scan() {
        let dir = tempfile::tempdir().unwrap();
        let path = tarball(dir.path(), MEMBERS);
        let members = ArchiveMembers::open(&path).unwrap().unwrap();
        assert!(matches!(members.0, Store::Tar(_)));
        agree(&members, &path);
    }

    #[test]
    fn a_tar_past_the_hold_limit_is_scanned_per_member() {
        let dir = tempfile::tempdir().unwrap();
        let path = tarball(dir.path(), MEMBERS);
        let members = ArchiveMembers::open_holding(&path, 8).unwrap().unwrap();
        assert!(matches!(members.0, Store::Stream(_)));
        agree(&members, &path);
    }

    #[test]
    fn a_zip_is_read_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("members.zip");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        zip.start_file("pkg/a.js", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"zipped a").unwrap();
        zip.finish().unwrap();
        let members = ArchiveMembers::open(&path).unwrap().unwrap();
        assert!(matches!(members.0, Store::Zip(_)));
        assert_eq!(
            text(members.member("pkg/a.js").unwrap()).as_deref(),
            Some("zipped a")
        );
        assert_eq!(members.member("pkg/b.js").unwrap(), None);
    }

    #[test]
    fn a_plain_file_is_no_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.js");
        std::fs::write(&path, "console.log(1);\n").unwrap();
        assert!(ArchiveMembers::open(&path).unwrap().is_none());
        assert_eq!(extract_member(&path, "plain.js").unwrap(), None);
    }

    #[test]
    fn a_missing_archive_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ArchiveMembers::open(&dir.path().join("absent.tgz")).is_err());
    }
}
