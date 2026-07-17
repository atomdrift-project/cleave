//! Regression test: Alpine/Wolfi `.apk` packages must be walked across *all*
//! their concatenated gzip segments, not just the first.
//!
//! An apk v2 is several gzip streams concatenated back to back: an optional
//! signature segment, the control segment (`.PKGINFO`, install scripts), and
//! the **data** segment (the installed files — every ELF binary and library).
//!
//! The exploder previously wrapped an apk in a single-stream `GzDecoder`, which
//! decompresses only the first segment (control). Production evidence: across
//! the entire hopper sample catalog, *zero* ELF members were ever ingested from
//! `feed='wolfi.dev'` (or `feed='alpinelinux.org'`) — only `.PKGINFO` — while
//! ELF ingestion worked for every other binary feed. The binaries in the data
//! segment were silently dropped.
//!
//! This test builds a faithful multi-segment apk (control gzip ++ data gzip)
//! with an ELF in the data segment and asserts the ELF member is analyzed. With
//! the single-segment decoder it fails (the ELF is never reached); with
//! per-segment walking it passes.

use anyhow::{Context, Result};
use cleave::{AnalysisOptions, analyze_file};
use std::io::Write;

fn opts() -> AnalysisOptions {
    AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    }
}

/// A minimal but validly-detected ELF: the 8-byte magic cleave keys on
/// (`\x7fELF`, 64-bit, little-endian, version 1) followed by a zero-padded
/// Elf64 header so the member is a plausible binary rather than a bare stub.
fn minimal_elf() -> Vec<u8> {
    let mut elf = vec![0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
    elf.resize(64, 0); // pad out to a full, zero-filled Elf64 header.
    elf[18] = 0x3e; // e_machine = EM_X86_64 (little-endian u16 at offset 18).
    elf
}

/// Build one gzip-compressed tar segment from `(path, contents)` members. A
/// real apk is several of these concatenated.
fn gzip_tar_segment(members: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);
    for (path, contents) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, path, *contents)
            .context("append tar member")?;
    }
    let enc = tar.into_inner().context("finish tar")?;
    enc.finish().context("finish gzip")
}

#[test]
fn apk_alpine_data_segment_elf_is_analyzed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let apk_path = dir.path().join("hello-1.0-r0.apk");

    // Control segment: just `.PKGINFO`, as Wolfi packages carry (no signature
    // segment). The ELF lives in a *separate*, second gzip segment — exactly
    // where a single-stream decoder stops short.
    let control = gzip_tar_segment(&[(
        ".PKGINFO",
        b"pkgname = hello\npkgver = 1.0-r0\narch = x86_64\n".as_slice(),
    )])?;
    let data = gzip_tar_segment(&[("usr/bin/hello", minimal_elf().as_slice())])?;

    {
        let mut f = std::fs::File::create(&apk_path)?;
        f.write_all(&control)?;
        f.write_all(&data)?;
    }

    let report = analyze_file(&apk_path, &opts())?;
    assert_eq!(
        report.target.file_type, "apk_alpine",
        "fixture must be detected as an Alpine apk, got {:?}",
        report.target.file_type
    );

    // The control member proves the first segment is still walked.
    assert!(
        report.files.iter().any(|m| m.path.ends_with(".PKGINFO")),
        "control segment member .PKGINFO missing; members: {:?}",
        report.files.iter().map(|m| &m.path).collect::<Vec<_>>()
    );

    // The point of the test: the ELF from the *data* segment must be analyzed.
    let elf_member = report
        .files
        .iter()
        .find(|m| m.path.ends_with("usr/bin/hello"))
        .with_context(|| {
            format!(
                "data-segment ELF member usr/bin/hello was not analyzed — the apk's \
                 second gzip segment is being skipped. members: {:?}",
                report.files.iter().map(|m| &m.path).collect::<Vec<_>>()
            )
        })?;
    assert_eq!(
        elf_member.file_type, "elf",
        "data-segment member must be classified as elf, got {:?}",
        elf_member.file_type
    );

    Ok(())
}
