//! Members of a .NET single-file bundle, as filefacts read its manifest
//! (`binary.dotnet_bundle`), decoded from the apphost's bytes: stored
//! members are sliced, v6 compressed members are raw DEFLATE (not zlib).
//! Never load or execute an assembly.
use anyhow::{Context, Result, ensure};
use serde_json::Value as JsonValue;

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
    pub header: usize,
    pub entries: Vec<Entry>,
    pub notes: Vec<String>,
}

/// The bundle filefacts found: `Ok(None)` when the host carries none,
/// `Err` when it carries a manifest that could not be read.
pub(super) fn from_values(values: &filefacts::Values) -> Result<Option<Bundle>> {
    let Some(bundle) = values.get("binary.dotnet_bundle") else {
        return Ok(None);
    };
    if let Some(error) = bundle.get("error").and_then(JsonValue::as_str) {
        anyhow::bail!("{error}");
    }
    let header = bundle
        .get("header_offset")
        .and_then(JsonValue::as_u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .context("bundle manifest without a header offset")?;
    let field = |member: &JsonValue, name: &str| member.get(name).and_then(JsonValue::as_u64);
    let entries = bundle
        .get("members")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|member| {
            Some(Entry {
                path: member.get("path")?.as_str()?.to_string(),
                offset: field(member, "offset")?,
                size: field(member, "size")?,
                compressed: field(member, "compressed_size").unwrap_or(0),
            })
        })
        .collect();
    let notes = bundle
        .get("notes")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|note| note.as_str().map(str::to_string))
        .collect();
    Ok(Some(Bundle {
        header,
        entries,
        notes,
    }))
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

    const PAYLOAD: &[u8] = b"print('bundle member')\n";

    /// A host whose bytes hold `PAYLOAD` at offset 8 (raw DEFLATE when
    /// `compressed`), with the manifest filefacts would report for it.
    fn fixture(compressed: bool) -> (Vec<u8>, filefacts::Values) {
        let body = if compressed {
            let mut encoder =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(PAYLOAD).unwrap();
            encoder.finish().unwrap()
        } else {
            PAYLOAD.to_vec()
        };
        let mut data = vec![0; 8];
        data.extend_from_slice(&body);
        let header = data.len();
        data.extend_from_slice(&[0; 16]);
        let values = filefacts::Values::from(serde_json::json!({"binary": {"dotnet_bundle": {
            "version": 6,
            "header_offset": header,
            "members": [{
                "path": "payload.py",
                "offset": 8,
                "size": PAYLOAD.len(),
                "compressed_size": if compressed { body.len() } else { 0 },
            }],
        }}}));
        (data, values)
    }

    #[test]
    fn stored_and_compressed_members_decode() {
        for compressed in [false, true] {
            let (data, values) = fixture(compressed);
            let bundle = from_values(&values).unwrap().unwrap();
            assert_eq!(bundle.entries.len(), 1);
            assert_eq!(
                read_member(&data, &bundle, &bundle.entries[0], 100).unwrap(),
                PAYLOAD
            );
        }
    }

    #[test]
    fn absent_and_unreadable_manifests() {
        assert!(from_values(&filefacts::Values::new()).unwrap().is_none());
        let broken = filefacts::Values::from(serde_json::json!(
            {"binary": {"dotnet_bundle": {"error": "unsupported bundle version 9.0"}}}
        ));
        assert!(from_values(&broken).is_err());
    }

    #[test]
    fn member_bounds_and_bombs() {
        let (data, values) = fixture(true);
        let mut bundle = from_values(&values).unwrap().unwrap();
        assert!(read_member(&data, &bundle, &bundle.entries[0], 1).is_err());
        bundle.entries[0].size = u64::MAX;
        assert!(read_member(&data, &bundle, &bundle.entries[0], u64::MAX).is_err());
        bundle.entries[0].size = PAYLOAD.len() as u64;
        bundle.entries[0].offset = u64::MAX;
        assert!(read_member(&data, &bundle, &bundle.entries[0], 100).is_err());
        let mut bundle = from_values(&values).unwrap().unwrap();
        bundle.entries[0].compressed -= 1;
        assert!(read_member(&data, &bundle, &bundle.entries[0], 100).is_err());
    }

    #[test]
    fn member_analysis_preserves_identity_and_limits() {
        use crate::analyzers::archive::ArchiveAnalyzer;
        use crate::types::{AnalysisReport, Criticality, TargetInfo};
        let (data, values) = fixture(true);
        let analyzer = ArchiveAnalyzer::new();
        let mut report = AnalysisReport::new(TargetInfo {
            path: "bundle.exe".to_string(),
            file_type: "pe".to_string(),
            size_bytes: data.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        assert!(analyzer.analyze_dotnet_bundle(&data, &values, &mut report));
        assert!(
            report
                .archive_contents
                .iter()
                .any(|entry| entry.path == "payload.py")
        );
        assert!(report.files.iter().any(|file| file.path == "payload.py"));
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.crit >= Criticality::Suspicious)
        );
        let mut limited = AnalysisReport::new(report.target.clone());
        assert!(analyzer.with_max_memory_file_size(1).analyze_dotnet_bundle(
            &data,
            &values,
            &mut limited
        ));
        assert!(limited.files.is_empty());
        assert!(
            limited
                .analysis_gaps
                .contains(crate::types::AnalysisGap::ExtractionPartial)
        );
    }
}
