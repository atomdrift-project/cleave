//! Reads a blank tar header size field as zero.
//!
//! bsdtar and node-tar (what `npm install` unpacks with) read a numeric header
//! field that holds no digits as 0. The `tar` crate rejects one, and because it
//! parses the size field to find the next header, a blank size ends the whole
//! walk ("numeric field was not a number:  when getting size for
//! package"). A package published with such headers installs normally while
//! every one of its members stays hidden from analysis.
//!
//! [`BlankFieldRepair`] sits between the decoder and `tar::Archive`. It follows
//! the archive's framing exactly as the crate does, and in each header whose
//! checksum is valid it rewrites a blank size field to octal zero and
//! recomputes the checksum. Blank uid, gid and mtime fields are left alone: the
//! crate never parses them while walking, and `tar::Builder` itself writes them. Wherever it cannot be certain where
//! the next header starts (a checksum it cannot verify, a GNU sparse member,
//! the end-of-archive block, an oversized PAX record set, a truncated stream)
//! it stops repairing and passes the rest through unchanged, so the crate sees
//! exactly the bytes it would have seen without it.

use super::guards::{ExtractionGuard, HostileArchiveReason};
use std::io::{self, Read};
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const BLOCK: usize = 512;
const SIZE: Range<usize> = 124..136;
const CKSUM: Range<usize> = 148..156;
const TYPEFLAG: usize = 156;
const MAGIC: Range<usize> = 257..265;
/// Largest PAX record set followed for a size override. The crate holds these
/// in memory as well; real ones are a few hundred bytes.
const MAX_PAX: u64 = 1 << 20;

/// A `Read` adapter that repairs blank numeric tar header fields. See the
/// module documentation.
pub(crate) struct BlankFieldRepair<R> {
    inner: R,
    block: [u8; BLOCK],
    /// Bytes of the current header held in `block`.
    filled: usize,
    /// Bytes of `block` already handed to the caller.
    served: usize,
    /// Entry bytes (data and padding) to pass through before the next header.
    data_left: u64,
    /// Records of a PAX local header being read, and the record bytes still due.
    pax: Option<(Vec<u8>, u64)>,
    /// Size override from the last PAX local header, pending its member.
    pax_size: Option<u64>,
    passthrough: bool,
    repaired: Arc<AtomicUsize>,
}

/// How many headers a [`BlankFieldRepair`] rewrote, readable after the
/// archive that owns the reader has been walked.
#[derive(Debug, Clone, Default)]
pub(crate) struct RepairCount(Arc<AtomicUsize>);

impl RepairCount {
    pub(crate) fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    /// Record the repairs, if any, as the `archive.guard.blank_size_headers`
    /// observation. It is not an extraction note: every member was read, so
    /// the analysis is not partial. Whether a blank size is a careless packer
    /// or an attempt to blind strict parsers is for traits to judge.
    pub(crate) fn report(&self, guard: &ExtractionGuard) {
        let n = self.get();
        if n > 0 {
            guard.add_hostile_reason(HostileArchiveReason::BlankSizeField(n));
        }
    }
}

impl<R: Read> BlankFieldRepair<R> {
    pub(crate) fn new(inner: R) -> (Self, RepairCount) {
        let count = RepairCount::default();
        let reader = Self {
            inner,
            block: [0; BLOCK],
            filled: 0,
            served: 0,
            data_left: 0,
            pax: None,
            pax_size: None,
            passthrough: false,
            repaired: Arc::clone(&count.0),
        };
        (reader, count)
    }

    /// Repair the header in `block` and work out where the next one starts,
    /// mirroring `tar::Entries::next_entry_raw` and `next_entry`.
    fn inspect_header(&mut self) {
        let h = &mut self.block;
        // The crate ends the archive at the first zero block (cleave never
        // sets ignore_zeros); nothing after it is parsed.
        if h.iter().all(|&b| b == 0) {
            self.passthrough = true;
            return;
        }
        // Only a header that is intact apart from its blank fields is
        // rewritten; recomputing the checksum of anything else would launder it.
        if octal(&h[CKSUM]).map(|c| c as u32) != Some(checksum(h)) {
            self.passthrough = true;
            return;
        }
        if is_blank(&h[SIZE]) {
            h[SIZE].fill(b'0');
            h[SIZE.end - 1] = 0;
            let sum = format!("{:06o}\0 ", checksum(h));
            h[CKSUM].copy_from_slice(sum.as_bytes());
            self.repaired.fetch_add(1, Ordering::Relaxed);
        }

        let flag = h[TYPEFLAG];
        let recognized = &h[MAGIC] == b"ustar\x0000" || &h[MAGIC] == b"ustar  \0";
        let extension = matches!(flag, b'L' | b'K' | b'x' | b'g');
        let Some(raw) = size_field(&h[SIZE]) else {
            self.passthrough = true; // the crate stops here too
            return;
        };
        let size = match self.pax_size {
            Some(pax) if !extension => pax,
            _ => raw,
        };
        // A PAX override survives GNU long-name headers and is consumed by
        // whatever header comes next.
        if !(recognized && matches!(flag, b'L' | b'K')) {
            self.pax_size = None;
        }
        // GNU sparse members may carry extension blocks the crate reads as part
        // of the header, which this reader does not track.
        if flag == b'S' {
            self.passthrough = true;
            return;
        }
        if recognized && flag == b'x' && size > 0 {
            if size > MAX_PAX {
                self.passthrough = true;
                return;
            }
            self.pax = Some((Vec::with_capacity(size as usize), size));
        }
        match size.checked_add(BLOCK as u64 - 1) {
            Some(padded) => self.data_left = padded & !(BLOCK as u64 - 1),
            None => self.passthrough = true,
        }
    }

    fn capture_pax(&mut self, data: &[u8]) {
        let Some((records, due)) = &mut self.pax else {
            return;
        };
        let take = data.len().min(usize::try_from(*due).unwrap_or(usize::MAX));
        records.extend_from_slice(&data[..take]);
        *due -= take as u64;
        if *due == 0 {
            self.pax_size = pax_size(records);
            self.pax = None;
        }
    }
}

impl<R: Read> Read for BlankFieldRepair<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.served < self.filled {
                let n = (self.filled - self.served).min(buf.len());
                buf[..n].copy_from_slice(&self.block[self.served..self.served + n]);
                self.served += n;
                return Ok(n);
            }
            if self.passthrough {
                return self.inner.read(buf);
            }
            if self.data_left > 0 {
                let want = buf
                    .len()
                    .min(usize::try_from(self.data_left).unwrap_or(usize::MAX));
                let n = self.inner.read(&mut buf[..want])?;
                if n == 0 {
                    self.passthrough = true;
                    return Ok(0);
                }
                self.data_left -= n as u64;
                self.capture_pax(&buf[..n]);
                return Ok(n);
            }
            // At a header boundary: hold the whole block before serving any of it.
            self.filled = 0;
            self.served = 0;
            while self.filled < BLOCK {
                match self.inner.read(&mut self.block[self.filled..]) {
                    Ok(0) => break,
                    Ok(n) => self.filled += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        // Serve what was read, unrepaired, after the error.
                        self.passthrough = true;
                        return Err(e);
                    }
                }
            }
            if self.filled == 0 {
                return Ok(0);
            }
            if self.filled < BLOCK {
                self.passthrough = true;
            } else {
                self.inspect_header();
            }
        }
    }
}

/// The header checksum as the crate computes it: every byte, with the checksum
/// field itself counted as spaces.
fn checksum(h: &[u8; BLOCK]) -> u32 {
    h[..CKSUM.start]
        .iter()
        .chain(&h[CKSUM.end..])
        .fold(0, |sum, &b| sum + u32::from(b))
        + 8 * u32::from(b' ')
}

/// The field up to its first NUL, as the crate reads it.
fn digits(field: &[u8]) -> &[u8] {
    field
        .iter()
        .position(|&b| b == 0)
        .map_or(field, |end| &field[..end])
}

/// A field the crate would reject for holding no digits at all. Fields with
/// other junk in them are left alone: those are not what bsdtar reads as zero.
fn is_blank(field: &[u8]) -> bool {
    digits(field)
        .iter()
        .all(|&b| b.is_ascii() && char::from(b).is_whitespace())
}

/// An octal field, parsed as the crate's `octal_from` does.
fn octal(field: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(digits(field)).ok()?;
    u64::from_str_radix(text.trim(), 8).ok()
}

/// The 12-byte size field: octal, or base-256 when the high bit is set, in
/// which case the crate reads only its last eight bytes.
fn size_field(field: &[u8]) -> Option<u64> {
    if field[0] & 0x80 == 0 {
        return octal(field);
    }
    let tail: [u8; 8] = field[field.len() - 8..].try_into().ok()?;
    Some(u64::from_be_bytes(tail))
}

/// The `size` record of a PAX record set, parsed as the crate's
/// `pax_extensions_value` does: any malformed record before it voids the lookup.
fn pax_size(records: &[u8]) -> Option<u64> {
    for line in records.split(|&b| b == b'\n') {
        if line.is_empty() {
            return None;
        }
        let space = line.iter().position(|&b| b == b' ')?;
        let len: usize = std::str::from_utf8(&line[..space]).ok()?.parse().ok()?;
        if line.len() + 1 != len {
            return None;
        }
        let record = &line[space + 1..];
        let equals = record.iter().position(|&b| b == b'=')?;
        if &record[..equals] == b"size" {
            return std::str::from_utf8(&record[equals + 1..])
                .ok()?
                .parse()
                .ok();
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A ustar header with a valid checksum and the given fields blanked to NULs.
    fn header(name: &str, flag: u8, size: u64, blank: &[Range<usize>]) -> [u8; BLOCK] {
        let mut h = tar::Header::new_ustar();
        h.set_path(name).unwrap();
        h.set_size(size);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::new(flag));
        let mut block = *h.as_bytes();
        for field in blank {
            block[field.clone()].fill(0);
        }
        let sum = format!("{:06o}\0 ", checksum(&block));
        block[CKSUM].copy_from_slice(sum.as_bytes());
        block
    }

    fn padded(data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        v.resize(data.len().div_ceil(BLOCK) * BLOCK, 0);
        v
    }

    fn walk(archive: &[u8]) -> (Result<Vec<(String, Vec<u8>)>, String>, usize) {
        let (reader, count) = BlankFieldRepair::new(archive);
        let mut out = Vec::new();
        let mut tar = tar::Archive::new(reader);
        let result = (|| {
            for entry in tar.entries().map_err(|e| e.to_string())? {
                let mut entry = entry.map_err(|e| e.to_string())?;
                let path = entry
                    .path()
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .into_owned();
                let mut data = Vec::new();
                entry.read_to_end(&mut data).map_err(|e| e.to_string())?;
                out.push((path, data));
            }
            Ok(out)
        })();
        (result, count.get())
    }

    /// The layout of the npm packages that failed in production: a leading
    /// directory entry with blank uid, gid and size fields.
    #[test]
    fn blank_directory_fields_no_longer_hide_members() {
        let mut archive = Vec::new();
        archive.extend(header("package", b'5', 0, &[108..116, 116..124, SIZE]));
        archive.extend(header("package/package.json", b'0', 13, &[]));
        archive.extend(padded(b"{\"name\":\"x\"}\n"));
        archive.extend([0; 2 * BLOCK]);

        let mut strict = tar::Archive::new(archive.as_slice());
        let err = strict.entries().unwrap().next().unwrap().err().unwrap();
        assert!(
            err.to_string().contains("when getting size for package"),
            "{err}"
        );

        let (members, repaired) = walk(&archive);
        let members = members.unwrap();
        assert_eq!(repaired, 1);
        assert_eq!(members.len(), 2);
        assert_eq!(
            members[1],
            (
                "package/package.json".into(),
                b"{\"name\":\"x\"}\n".to_vec()
            )
        );
    }

    #[test]
    fn blank_file_size_reads_as_empty_member() {
        let mut archive = Vec::new();
        archive.extend(header("empty", b'0', 0, &[SIZE]));
        archive.extend(header("next", b'0', 3, &[]));
        archive.extend(padded(b"abc"));
        archive.extend([0; 2 * BLOCK]);
        let (members, repaired) = walk(&archive);
        assert_eq!(repaired, 1);
        assert_eq!(
            members.unwrap(),
            vec![("empty".into(), vec![]), ("next".into(), b"abc".to_vec())]
        );
    }

    #[test]
    fn pax_size_override_keeps_framing() {
        let records = b"12 size=600\n";
        let mut archive = Vec::new();
        archive.extend(header("PaxHeader", b'x', records.len() as u64, &[]));
        archive.extend(padded(records));
        // The header's own size field is blank; the PAX record governs.
        archive.extend(header("big", b'0', 0, &[SIZE]));
        archive.extend(padded(&[b'z'; 600]));
        archive.extend(header("after", b'0', 2, &[]));
        archive.extend(padded(b"ok"));
        archive.extend([0; 2 * BLOCK]);
        let (members, repaired) = walk(&archive);
        let members = members.unwrap();
        assert_eq!(repaired, 1);
        assert_eq!(
            members
                .iter()
                .map(|(p, d)| (p.as_str(), d.len()))
                .collect::<Vec<_>>(),
            [("big", 600), ("after", 2)]
        );
    }

    #[test]
    fn intact_archives_pass_through_byte_for_byte() {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in [("a.txt", &b"alpha"[..]), ("dir/b.bin", &[7u8; 1500][..])] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o600);
            h.set_cksum();
            builder.append_data(&mut h, name, body).unwrap();
        }
        let archive = builder.into_inner().unwrap();
        let (mut reader, count) = BlankFieldRepair::new(archive.as_slice());
        let mut copy = Vec::new();
        // Small reads exercise partial header serving.
        let mut buf = [0u8; 7];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            copy.extend_from_slice(&buf[..n]);
        }
        assert!(copy == archive, "an intact archive was rewritten");
        assert_eq!(count.get(), 0);
    }

    #[test]
    fn bad_checksum_is_not_laundered() {
        let mut block = header("package", b'5', 0, &[SIZE]);
        block[CKSUM].copy_from_slice(b"000001\0 ");
        let mut archive = block.to_vec();
        archive.extend([0; 2 * BLOCK]);
        let (members, repaired) = walk(&archive);
        assert_eq!(repaired, 0);
        assert!(members.unwrap_err().contains("checksum"));
    }

    #[test]
    fn pax_record_parsing_matches_the_crate() {
        assert_eq!(pax_size(b"12 size=600\n"), Some(600));
        assert_eq!(pax_size(b"20 path=a/b/c/d.txt\n12 size=600\n"), Some(600));
        assert_eq!(pax_size(b"99 size=600\n"), None);
        assert_eq!(pax_size(b"13 size=abc!\n"), None);
        assert_eq!(pax_size(b"14 mtime=1.5x\n"), None);
    }
}
