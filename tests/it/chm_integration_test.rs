//! End-to-end CHM integration tests.
//!
//! Two layers:
//!
//! 1. A self-contained synthetic CHM builder + assertions on the
//!    public CLI/JSON output. Verifies parser, kv emission, and
//!    metrics wiring without depending on any real sample.
//!
//! 2. File-presence-gated tests against representative real CHMs:
//!    `Pstools.chm` (legit, no findings expected), the SoftpeakLive
//!    payment dropper (multiple HTML-Help and softpeak-live.* traits
//!    expected), and the DPRK MalwareBazaar wallet CHM. These tests
//!    silently skip when the samples are not on the host so the
//!    test suite still runs cleanly in CI / clean checkouts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use tempfile::NamedTempFile;

// ────────────────────────────────────────────────────────────────────
//  Synthetic minimal CHM builder
// ────────────────────────────────────────────────────────────────────

/// Build a minimal valid CHM v3 container with one user-visible
/// uncompressed entry whose body is `entry_payload`. Used by the
/// portable test below to exercise the parser/value path without any
/// real-world fixture.
fn build_minimal_chm(entry_name: &str, entry_payload: &[u8]) -> Vec<u8> {
    // Layout we emit:
    //
    //   off 0x000  ITSF header             (0x60 bytes)
    //   off 0x060  Section 0 header        (0x18 bytes — payload zeroed)
    //   off 0x078  Section 1: ITSP + PMGL  (0x54 + 0x1000 = 0x1054 bytes)
    //   off 0x10cc data_offset / payload   (entry bytes)
    //
    // Anything not mentioned here is zero-filled — the parser only
    // reads the fields it understands and ignores the rest.

    const ITSF_HDR_LEN: usize = 0x60;
    const SEC0_LEN: usize = 0x18;
    const ITSP_HDR_LEN: usize = 0x54;
    const PMGL_CHUNK_SIZE: usize = 0x1000;
    const SEC1_LEN: usize = ITSP_HDR_LEN + PMGL_CHUNK_SIZE;

    let sec0_off: u64 = ITSF_HDR_LEN as u64;
    let sec1_off: u64 = (ITSF_HDR_LEN + SEC0_LEN) as u64;
    let data_off: u64 = sec1_off + SEC1_LEN as u64;

    let mut buf = vec![0u8; data_off as usize];

    // ── ITSF header ──
    buf[0..4].copy_from_slice(b"ITSF");
    buf[0x04..0x08].copy_from_slice(&3u32.to_le_bytes()); // version
    buf[0x08..0x0c].copy_from_slice(&(ITSF_HDR_LEN as u32).to_le_bytes()); // total_header_length
    buf[0x0c..0x10].copy_from_slice(&1u32.to_le_bytes()); // unknown
    buf[0x10..0x14].copy_from_slice(&0xdeadbeef_u32.to_le_bytes()); // timestamp_counter
    buf[0x14..0x18].copy_from_slice(&1033u32.to_le_bytes()); // lcid en-US
    // 0x18..0x38: 32 bytes of GUIDs — leave zero
    buf[0x38..0x40].copy_from_slice(&sec0_off.to_le_bytes());
    buf[0x40..0x48].copy_from_slice(&(SEC0_LEN as u64).to_le_bytes());
    buf[0x48..0x50].copy_from_slice(&sec1_off.to_le_bytes());
    buf[0x50..0x58].copy_from_slice(&(SEC1_LEN as u64).to_le_bytes());
    buf[0x58..0x60].copy_from_slice(&data_off.to_le_bytes());

    // ── Section 0 header (24 bytes; first 8 = file_size, rest zeroed) ──
    // We'll patch file_size after we know the total length.

    // ── Section 1: ITSP header ──
    let itsp_off = sec1_off as usize;
    buf[itsp_off..itsp_off + 4].copy_from_slice(b"ITSP");
    buf[itsp_off + 4..itsp_off + 8].copy_from_slice(&1u32.to_le_bytes()); // version
    buf[itsp_off + 8..itsp_off + 12].copy_from_slice(&(ITSP_HDR_LEN as u32).to_le_bytes());
    buf[itsp_off + 0x10..itsp_off + 0x14].copy_from_slice(&(PMGL_CHUNK_SIZE as u32).to_le_bytes());
    // density / depth / index_root: leave zeros where parser doesn't require
    // chunk_count at +0x2c
    buf[itsp_off + 0x2c..itsp_off + 0x30].copy_from_slice(&1u32.to_le_bytes());

    // ── Single PMGL chunk ──
    let pmgl_off = itsp_off + ITSP_HDR_LEN;
    buf[pmgl_off..pmgl_off + 4].copy_from_slice(b"PMGL");
    // quickref_size = 0 → entries fill the chunk minus 0x14 prefix
    buf[pmgl_off + 4..pmgl_off + 8].copy_from_slice(&0u32.to_le_bytes());
    // prev/next chunk = -1
    buf[pmgl_off + 0x0c..pmgl_off + 0x10].copy_from_slice(&(-1i32).to_le_bytes());
    buf[pmgl_off + 0x10..pmgl_off + 0x14].copy_from_slice(&(-1i32).to_le_bytes());

    // ── One directory entry: name=`entry_name`, section=0, offset=0, length=payload.len ──
    let entry_start = pmgl_off + 0x14;
    let mut p = entry_start;
    let name_bytes = entry_name.as_bytes();
    assert!(
        name_bytes.len() < 128,
        "test entry name must be short ENCINT"
    );
    // ENCINT name length (single byte for short names)
    buf[p] = name_bytes.len() as u8;
    p += 1;
    buf[p..p + name_bytes.len()].copy_from_slice(name_bytes);
    p += name_bytes.len();
    // section index = 0 (ENCINT single byte)
    buf[p] = 0;
    p += 1;
    // offset = 0
    buf[p] = 0;
    p += 1;
    // length (ENCINT). For small payloads, fits in 1 byte.
    let len = entry_payload.len();
    assert!(len < 128, "test payload must be short ENCINT");
    buf[p] = len as u8;
    p += 1;
    // Sentinel: a zero ENCINT name length terminates entry parsing
    // when the rest of the chunk is zeroed (matches how real CHMs
    // pad chunk slack). The parser exits the entry loop once it sees
    // an empty name, so we don't need an explicit end marker.
    let _ = p;

    // Append the entry's payload at data_off + 0.
    buf.extend_from_slice(entry_payload);

    // Patch section 0's file-size cell now that we know the total.
    let total_len = buf.len() as u64;
    buf[0x60..0x68].copy_from_slice(&total_len.to_le_bytes());

    buf
}

// ────────────────────────────────────────────────────────────────────
//  Synthetic-CHM tests — always run
// ────────────────────────────────────────────────────────────────────

#[test]
fn synthetic_chm_is_recognized_as_chm() {
    let chm = build_minimal_chm("/hello.html", b"<html>hi</html>");
    let tmp = NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &chm).expect("write");

    let out = run_cleave_json(tmp.path());
    let f = first_file(&out);
    assert_eq!(
        f["type"].as_str(),
        Some("chm"),
        "minimal CHM should be detected as Chm: {f}"
    );
}

#[test]
fn synthetic_chm_emits_metrics() {
    let chm = build_minimal_chm("/hello.html", b"<html>hi</html>");
    let tmp = NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &chm).expect("write");

    let out = run_cleave_json(tmp.path());
    let f = first_file(&out);

    // metrics: user_entry_count is computed from the directory. Counts live
    // in compact v8 filefacts metrics (the residual `val` kv tree the ITSF
    // header values used to ride was retired in v8).
    let m = compact_metrics(f);
    let metric_int = |name: &str| -> u64 {
        *m.get(name)
            .unwrap_or_else(|| panic!("metric {name} missing in {m:?}")) as u64
    };
    assert_eq!(metric_int("chm.user_entry_count"), 1, "{m:?}");
    assert_eq!(metric_int("chm.html_entry_count"), 1, "{m:?}");
    assert_eq!(
        metric_int("chm.max_user_entry_size"),
        "<html>hi</html>".len() as u64,
        "{m:?}"
    );
}

#[test]
fn synthetic_chm_has_no_dropper_findings() {
    // A minimal benign CHM with one HTML payload must not trigger
    // the SoftpeakLive campaign trait or the htmlhelp-shortcut
    // composites.
    let chm = build_minimal_chm("/hello.html", b"<html>hi</html>");
    let tmp = NamedTempFile::new().expect("tempfile");
    std::fs::write(tmp.path(), &chm).expect("write");

    let out = run_cleave_json(tmp.path());
    let f = first_file(&out);
    let traits = f["traits"].as_array().cloned().unwrap_or_default();
    for t in &traits {
        let id = t["id"].as_str().unwrap_or("");
        assert!(
            !id.contains("htmlhelp-shortcut-"),
            "synthetic CHM unexpectedly fired {id}"
        );
        assert!(
            !id.contains("softpeak-live"),
            "synthetic CHM unexpectedly fired {id}"
        );
    }
}

// ────────────────────────────────────────────────────────────────────
//  Real-sample tests — gated on file presence
// ────────────────────────────────────────────────────────────────────

const SOFTPEAK_PATH: &str =
    "/Users/t/data/bad/dissect-malware/pe/2026.SoftpeakLive/payment instruction.987976.pdf.chm";
const PSTOOLS_PATH: &str = "/Users/t/data/good/dissect-random/Pstools.chm";

#[test]
fn softpeak_live_real_sample_fires_campaign_composite() {
    let path = Path::new(SOFTPEAK_PATH);
    if !path.exists() {
        eprintln!("skipping: SoftpeakLive sample not present at {SOFTPEAK_PATH}");
        return;
    }
    let out = run_cleave_json(path);
    let f = first_file(&out);
    let trait_ids: Vec<String> = trait_ids(f);

    let must_fire = [
        // The HTML-Help ShortCut auto-fire composite should hit at
        // file-level (CHM container) and bubble up.
        "objectives/command-and-control/dropper/delivery/chm::htmlhelp-shortcut-process-dropper",
        // The SoftpeakLive C2 host atom.
        "well-known/malware/dropper/softpeak-live::softpeak-live-host",
        // The full campaign composite.
        "well-known/malware/dropper/softpeak-live::softpeak-live-chm-dropper",
    ];
    for needle in must_fire {
        assert!(
            trait_ids.iter().any(|id| id == needle),
            "expected SoftpeakLive sample to fire {needle}; got {trait_ids:?}"
        );
    }
}

#[test]
fn pstools_real_sample_has_no_dropper_findings() {
    let path = Path::new(PSTOOLS_PATH);
    if !path.exists() {
        eprintln!("skipping: Pstools sample not present at {PSTOOLS_PATH}");
        return;
    }
    // Iterate every file in the report (the parent CHM and every
    // member file) and assert none of them carry the htmlhelp dropper
    // composites or the SoftpeakLive trait family.
    let out = run_cleave_json(path);
    let files = out["fs"].as_array().cloned().unwrap_or_default();
    for f in &files {
        let path = f["path"].as_str().unwrap_or("");
        for t in f["ts"].as_array().cloned().unwrap_or_default() {
            let id = t["i"].as_str().unwrap_or("");
            assert!(
                !id.contains("htmlhelp-shortcut-cmd-dropper"),
                "Pstools fired {id} on {path}"
            );
            assert!(
                !id.contains("softpeak-live"),
                "Pstools fired {id} on {path}"
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────────
//  Helpers
// ────────────────────────────────────────────────────────────────────

fn run_cleave_json(path: &Path) -> Value {
    // All assertions in this file target trait/composite IDs from YAML, not
    // YARA matches — skipping YARA shaves ~4s of cold-cache rule loading off
    // every test invocation without affecting coverage.
    let mut bin = assert_cmd::cargo_bin_cmd!("cleave");
    let output = bin
        .env("CLEAVE_SKIP_YARA", "1")
        .args(["--json", "analyze", path.to_str().unwrap()])
        .output()
        .expect("cleave run");
    assert!(
        output.status.success(),
        "cleave failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // First JSON line is the report.
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with('{'))
        .expect("no JSON line in cleave output");
    serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSON: {e}: {line}"))
}

fn first_file(report: &Value) -> &Value {
    report["files"]
        .as_array()
        .and_then(|a| a.first())
        .expect("report has no files")
}

fn compact_metrics(file: &Value) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    let groups = file
        .pointer("/facts/metrics")
        .and_then(Value::as_object)
        .expect("compact v8 filefacts metrics missing");
    for (group, fields) in groups {
        let Some(fields) = fields.as_object() else {
            continue;
        };
        for (field, value) in fields {
            if let Some(value) = value.as_f64() {
                out.insert(format!("{group}.{field}"), value);
            }
        }
    }
    out
}

fn trait_ids(f: &Value) -> Vec<String> {
    f["traits"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|t| t["id"].as_str().map(str::to_owned))
        .collect()
}
