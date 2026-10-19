//! Data-only .NET single-file bundle reader. Layouts follow dotnet/runtime's
//! bundle/header.h and file_entry.h (versions 1, 2 and 6). The native host's
//! fixed marker is preceded by the manifest offset; compressed v6 members
//! are raw DEFLATE, not zlib streams. Never load or execute an assembly.
use anyhow::{Context, Result, bail, ensure};
use std::io::{Cursor, Read};

pub(super) const SIGNATURE: &[u8; 32] = &[
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
];
const MAX_STRING: usize = 4096;
pub(super) const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct Entry {
    pub path: String,
    pub offset: u64,
    pub size: u64,
    pub compressed: u64,
}

#[derive(Debug)]
pub(super) struct Bundle {
    pub major: u32,
    pub minor: u32,
    pub header: usize,
    pub entries: Vec<Entry>,
    pub notes: Vec<String>,
}

fn u32le(reader: &mut impl Read) -> Result<u32> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}
fn u64le(reader: &mut impl Read) -> Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
fn string(reader: &mut impl Read) -> Result<String> {
    let mut len = 0u32;
    for shift in (0..35).step_by(7) {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        ensure!(shift != 28 || byte[0] <= 7, "invalid string length");
        len |= u32::from(byte[0] & 127) << shift;
        if byte[0] < 128 {
            ensure!(len as usize <= MAX_STRING, "bundle string exceeds limit");
            let mut bytes = vec![0; len as usize];
            reader.read_exact(&mut bytes)?;
            return String::from_utf8(bytes).context("invalid UTF-8 bundle path");
        }
    }
    bail!("invalid string length")
}

fn manifest(data: &[u8], header: usize) -> Result<Bundle> {
    let mut reader = Cursor::new(data.get(header..).context("bundle header outside file")?);
    let major = u32le(&mut reader)?;
    let minor = u32le(&mut reader)?;
    ensure!(
        matches!(major, 1 | 2 | 6) && minor == 0,
        "unsupported bundle version {major}.{minor}"
    );
    let count = u32le(&mut reader)? as usize;
    ensure!(
        count > 0 && count <= super::guards::MAX_ZIP_ENTRIES,
        "invalid bundle member count"
    );
    let _bundle_id = string(&mut reader)?;
    if major >= 2 {
        let mut locations_and_flags = [0; 40];
        reader.read_exact(&mut locations_and_flags)?;
    }
    let mut bundle = Bundle {
        major,
        minor,
        header,
        entries: Vec::new(),
        notes: Vec::new(),
    };
    for index in 0..count {
        if reader.position() > 8 * 1024 * 1024 {
            bundle
                .notes
                .push("bundle manifest exceeded 8 MiB parsing budget".to_string());
            break;
        }
        let entry = (|| -> Result<Entry> {
            let offset = u64le(&mut reader)?;
            let size = u64le(&mut reader)?;
            let compressed = if major >= 6 { u64le(&mut reader)? } else { 0 };
            let mut kind = [0];
            reader.read_exact(&mut kind)?;
            let path = string(&mut reader)?;
            Ok(Entry {
                path,
                offset,
                size,
                compressed,
            })
        })();
        match entry {
            Ok(entry) => bundle.entries.push(entry),
            Err(error) => {
                bundle.notes.push(format!(
                    "bundle manifest stopped at member {index}/{count}: {error:#}"
                ));
                break;
            }
        }
    }
    Ok(bundle)
}

/// Zero offsets are unpatched apphosts, not bundles. Do not let an earlier
/// decoy marker mask a later valid manifest. Bound candidate work as well as
/// member counts; malformed bundles are reported as incomplete by the caller.
pub(super) fn parse(data: &[u8]) -> Result<Option<Bundle>> {
    let mut error = None;
    for (index, marker) in memchr::memmem::find_iter(data, SIGNATURE).enumerate() {
        ensure!(index < 32, "too many .NET bundle markers");
        let Some(offset) = marker
            .checked_sub(8)
            .and_then(|start| data.get(start..marker))
        else {
            continue;
        };
        let header = u64::from_le_bytes(offset.try_into()?);
        if header == 0 {
            continue;
        }
        match usize::try_from(header)
            .context("bundle offset overflow")
            .and_then(|header| manifest(data, header))
        {
            Ok(bundle) => return Ok(Some(bundle)),
            Err(problem) => error = Some(problem),
        }
    }
    match error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

/// The caller enforces its member and aggregate byte budgets before calling.
/// Decoding reads at most declared_size + 1, and rejects truncated, oversized
/// or trailing compressed data. Bad members do not discard other entries.
pub(super) fn read_member(
    data: &[u8],
    bundle: &Bundle,
    entry: &Entry,
    limit: u64,
) -> Result<Vec<u8>> {
    ensure!(entry.size <= limit, "bundle member exceeds memory limit");
    ensure!(
        entry.size <= MAX_BUNDLE_BYTES,
        "bundle member exceeds expanded byte cap"
    );
    let stored = if entry.compressed == 0 {
        entry.size
    } else {
        entry.compressed
    };
    let end = entry
        .offset
        .checked_add(stored)
        .context("bundle member range overflow")?;
    ensure!(
        end <= bundle.header as u64,
        "bundle member extends into manifest or beyond file"
    );
    let start = usize::try_from(entry.offset)?;
    let end = usize::try_from(end)?;
    let raw = data.get(start..end).context("bundle member outside file")?;
    if entry.compressed == 0 {
        return Ok(raw.to_vec());
    }
    // Require explicit StreamEnd: Read-based decoders can report EOF on an
    // incomplete stream. One extra output byte also detects size underclaims.
    let mut verifier = flate2::Decompress::new(false);
    let mut out = vec![
        0;
        usize::try_from(entry.size)?
            .checked_add(1)
            .context("bundle size overflow")?
    ];
    let status = verifier.decompress(raw, &mut out, flate2::FlushDecompress::Finish)?;
    ensure!(
        status == flate2::Status::StreamEnd
            && verifier.total_out() == entry.size
            && verifier.total_in() == stored,
        "bundle DEFLATE stream did not terminate exactly"
    );
    out.truncate(entry.size as usize);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    pub(super) fn fixture(major: u32, compressed: bool) -> Vec<u8> {
        let payload = b"print('bundle member')\n";
        let mut data = vec![0; 8];
        data.extend_from_slice(SIGNATURE);
        let offset = data.len() as u64;
        let body = if compressed {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(payload).unwrap();
            encoder.finish().unwrap()
        } else {
            payload.to_vec()
        };
        data.extend_from_slice(&body);
        let header = data.len() as u64;
        data[..8].copy_from_slice(&header.to_le_bytes());
        data.extend_from_slice(&major.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"\x02id");
        if major >= 2 {
            data.extend_from_slice(&[0; 40]);
        }
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        if major >= 6 {
            data.extend_from_slice(&(if compressed { body.len() as u64 } else { 0 }).to_le_bytes());
        }
        data.push(1);
        data.extend_from_slice(b"\x0apayload.py");
        data
    }

    #[test]
    fn dotnet_bundle_versions_and_compression() {
        for (version, compressed) in [(1, false), (2, false), (6, false), (6, true)] {
            let data = fixture(version, compressed);
            let bundle = parse(&data).unwrap().unwrap();
            assert_eq!(bundle.major, version);
            assert_eq!(bundle.entries.len(), 1);
            assert!(bundle.notes.is_empty());
            assert_eq!(
                read_member(&data, &bundle, &bundle.entries[0], 100).unwrap(),
                b"print('bundle member')\n"
            );
        }
    }

    #[test]
    fn dotnet_bundle_unpatched_decoy_and_invalid_headers() {
        assert!(parse(b"not a bundle").unwrap().is_none());
        let mut data = vec![0; 8];
        data.extend_from_slice(SIGNATURE);
        assert!(parse(&data).unwrap().is_none());
        data[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse(&data).is_err());
        let valid = fixture(6, true);
        // A decoy precedes the actual fixed marker. Adjust its header and
        // entry offset for the prefix without changing the compressed body.
        let prefix = data.len();
        let mut valid = valid;
        let header = u64::from_le_bytes(valid[..8].try_into().unwrap()) as usize;
        valid[..8].copy_from_slice(&((header + prefix) as u64).to_le_bytes());
        valid[header + 55..header + 63].copy_from_slice(&((40 + prefix) as u64).to_le_bytes());
        data.extend_from_slice(&valid);
        let bundle = parse(&data).unwrap().unwrap();
        assert_eq!(
            read_member(&data, &bundle, &bundle.entries[0], 100).unwrap(),
            b"print('bundle member')\n"
        );
    }

    #[test]
    fn dotnet_bundle_member_bounds_and_bombs() {
        let data = fixture(6, true);
        let mut bundle = parse(&data).unwrap().unwrap();
        assert!(read_member(&data, &bundle, &bundle.entries[0], 1).is_err());
        bundle.entries[0].size = u64::MAX;
        assert!(read_member(&data, &bundle, &bundle.entries[0], u64::MAX).is_err());
        bundle.entries[0].size = 22;
        bundle.entries[0].offset = u64::MAX;
        assert!(read_member(&data, &bundle, &bundle.entries[0], 100).is_err());
    }

    #[test]
    fn dotnet_bundle_truncation_is_visible() {
        let mut data = fixture(6, true);
        data.pop();
        let bundle = parse(&data).unwrap().unwrap();
        assert!(bundle.entries.is_empty());
        assert!(!bundle.notes.is_empty());
        let data = fixture(6, true);
        let mut bundle = parse(&data).unwrap().unwrap();
        bundle.entries[0].compressed -= 1;
        assert!(read_member(&data, &bundle, &bundle.entries[0], 100).is_err());
    }

    #[test]
    fn dotnet_bundle_member_analysis_preserves_identity_and_limits() {
        use crate::analyzers::archive::ArchiveAnalyzer;
        use crate::types::{AnalysisReport, Criticality, TargetInfo};
        let data = fixture(6, true);
        let analyzer = ArchiveAnalyzer::new();
        let mut report = AnalysisReport::new(TargetInfo {
            path: "bundle.exe".to_string(),
            file_type: "pe".to_string(),
            size_bytes: data.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        assert!(analyzer.analyze_dotnet_bundle(&data, &mut report));
        assert!(
            report
                .archive_contents
                .iter()
                .any(|entry| entry.path == "payload.py"
                    && entry.compression_method.as_deref() == Some("deflate"))
        );
        assert!(report.files.iter().any(|file| file.path == "payload.py"));
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.crit >= Criticality::Suspicious)
        );
        let mut limited = AnalysisReport::new(report.target.clone());
        assert!(
            analyzer
                .with_max_memory_file_size(1)
                .analyze_dotnet_bundle(&data, &mut limited)
        );
        assert!(limited.files.is_empty());
        assert!(
            limited
                .findings
                .iter()
                .any(|finding| finding.id == "metadata/file/archive::partial-extraction")
        );
    }
}
