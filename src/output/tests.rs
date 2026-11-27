use super::*;
use crate::types::{AnalysisReport, Evidence, FindingKind, TargetInfo, YaraMatch};
use chrono::Utc;

/// Identity fixture from JSON, so a test reads as the claims a file makes
/// rather than as struct assembly.
fn identity(json: serde_json::Value) -> filefacts::Identity {
    serde_json::from_value(json).expect("identity fixture")
}

fn identity_lines(id: &filefacts::Identity) -> String {
    let mut out = String::new();
    render_identity(&mut out, id, false, false);
    out
}

/// A package's self-description reaches the reader on its own line, cut to
/// fit, and is not repeated when it merely echoes the package name.
#[test]
fn package_description_renders_as_an_about_line() {
    let id = identity(serde_json::json!({
        "name": {"value": "@acme/cli-win32-x64", "source": "npm.name"},
        "identifier": {"value": "@acme/cli-win32-x64", "source": "npm.name"},
        "version": {"value": "5.6.1", "source": "npm.version"},
        "description": {
            "value": "Sandbox CLI core binary for Windows x64",
            "source": "npm.description",
        },
        "trust": "unsigned",
    }));
    let lines = identity_lines(&id);
    assert!(
        lines.contains("  about  \"Sandbox CLI core binary for Windows x64\"\n"),
        "{lines}"
    );

    let long = identity(serde_json::json!({
        "description": {"value": "x".repeat(150), "source": "whl.summary"},
        "trust": "unsigned",
    }));
    let lines = identity_lines(&long);
    assert!(
        lines.contains(&format!("about  \"{}…\"", "x".repeat(100))),
        "{lines}"
    );

    let echo = identity(serde_json::json!({
        "identifier": {"value": "left-pad", "source": "npm.name"},
        "description": {"value": "left-pad", "source": "npm.description"},
        "trust": "unsigned",
    }));
    assert!(!identity_lines(&echo).contains("about"));

    // A PE FileDescription that restates its ProductName adds nothing.
    let product = identity(serde_json::json!({
        "name": {"value": "tool.exe", "source": "pe.version.original_filename"},
        "project": {"value": "Acme Tool", "source": "pe.version.product_name"},
        "description": {"value": "acme tool", "source": "pe.version.description"},
        "trust": "unsigned",
    }));
    assert!(!identity_lines(&product).contains("about"));
}

/// A copyright notice becomes one claims token when it names someone other
/// than the company or signer, and is dropped when it only restates them.
#[test]
fn copyright_renders_only_when_it_names_a_different_holder() {
    let differs = identity(serde_json::json!({
        "name": {"value": "sandbox-cli.exe", "source": "pe.version.original_filename"},
        "organization": {"value": "Acme Ltd", "source": "pe.version.company"},
        "copyright": {
            "value": "Copyright (C) 2024 Tencent. All Rights Reserved. Licensed to example users",
            "source": "pe.version.copyright",
        },
        "trust": "unsigned",
    }));
    let lines = identity_lines(&differs);
    assert!(
        lines.contains(&format!(
            "copyright=\"{}…\"",
            "Copyright (C) 2024 Tencent. All Rights Reserved."
        )),
        "{lines}"
    );

    let restates = identity(serde_json::json!({
        "name": {"value": "msvcp140.dll", "source": "pe.version.original_filename"},
        "organization": {"value": "Microsoft Corporation", "source": "pe.signatures[0]"},
        "copyright": {
            "value": "© Microsoft Corporation. All rights reserved.",
            "source": "pe.version.copyright",
        },
        "trust": "platform",
    }));
    assert!(!identity_lines(&restates).contains("copyright"));

    let bare = identity(serde_json::json!({
        "name": {"value": "a.exe", "source": "pe.version.original_filename"},
        "copyright": {"value": "Copyright (C) 2024", "source": "pe.version.copyright"},
        "trust": "unsigned",
    }));
    assert!(!identity_lines(&bare).contains("copyright"));
}

/// A signed PE that claims one company in its version resource and carries
/// another on its Authenticode chain. The headline can only name one of
/// them; the disagreement is the signal, so both must reach the reader.
#[test]
fn pe_identity_shows_the_version_resource_beside_the_signature() {
    let id = identity(serde_json::json!({
        "name": {"value": "setup.exe", "source": "pe.version.original_filename"},
        "project": {"value": "Contoso Updater", "source": "pe.version.product_name"},
        "version": {"value": "3.5.1", "source": "pe.version.file_version"},
        "organization": {"value": "Contoso Ltd", "source": "pe.version.company_name"},
        "signer": {
            "common_name": "Vanguard Tech Limited",
            "organization": "Vanguard Tech Limited",
            "issuer": "DigiCert Trusted G4 Code Signing RSA4096",
            "signed_at": "2024-01-05T00:00:00Z",
            "source": "pe.signatures[0]",
        },
        "trust": "ca_signed",
        "build_path": {"value": "C:\\Users\\dev\\proj\\src\\main.rs", "source": "strings"},
    }));
    let headline = strip_ansi(&identity_headline(&id).expect("headline"));
    let lines = identity_lines(&id);

    // The headline names the signer; the claims line names what the binary
    // says about itself, and the two disagree in plain sight.
    assert!(headline.contains("Vanguard Tech Limited"), "{headline}");
    assert!(lines.contains(r#"product="Contoso Updater""#), "{lines}");
    assert!(lines.contains(r#"company="Contoso Ltd""#), "{lines}");
    // The signer's own words, so the chain can be judged rather than trusted.
    assert!(lines.contains("issuer=\"DigiCert"), "{lines}");
    assert!(lines.contains("at=\"2024-01-05"), "{lines}");
    // The build path still reaches the reader.
    assert!(lines.contains(r"C:\Users\dev"), "{lines}");
    // Nothing the headline already showed is repeated.
    assert!(
        !lines.contains("O=\"Vanguard"),
        "signer org duplicated: {lines}"
    );
    assert!(
        !lines.contains("CN=\"Vanguard"),
        "signer name duplicated: {lines}"
    );
    assert!(
        !lines.contains(r#"file="setup.exe""#),
        "subject duplicated: {lines}"
    );
    assert!(
        !lines.contains(r#"version="3.5.1""#),
        "folded version duplicated: {lines}"
    );
}

/// A Mach-O keeps its team id and bundle version beside the signing
/// identity: a Developer ID whose team does not match the bundle it ships
/// is the same class of tell as the PE above.
#[test]
fn macho_identity_keeps_team_and_bundle_version() {
    let id = identity(serde_json::json!({
        "identifier": {"value": "com.contoso.helper", "source": "macho.bundle_identifier"},
        "version": {"value": "1.4.0", "source": "macho.bundle_version"},
        "team_id": {"value": "AB12CD34EF", "source": "macho.code_signature"},
        "signer": {
            "common_name": "Developer ID Application: Contoso Ltd (AB12CD34EF)",
            "organization": "Contoso Ltd",
            "source": "macho.code_signature",
        },
        "trust": "developer_id",
    }));
    let headline = strip_ansi(&identity_headline(&id).expect("headline"));
    let lines = identity_lines(&id);
    assert!(headline.contains("com.contoso.helper"), "{headline}");
    assert!(headline.contains("developer-id"), "{headline}");
    // The identifier is the subject, so the version is *not* folded in and
    // must be carried here instead.
    assert!(lines.contains(r#"version="1.4.0""#), "{lines}");
    assert!(lines.contains(r#"team="AB12CD34EF""#), "{lines}");
    assert!(lines.contains("CN=\"Developer ID Application"), "{lines}");
}

/// An Office document names an author, a company and the application that
/// produced it. The headline shows two of the three; all three matter when
/// a document arrives from outside the company it claims.
#[test]
fn docx_identity_keeps_company_beside_author_and_producer() {
    let id = identity(serde_json::json!({
        "title": {"value": "Q3 Vendor Invoice", "source": "docprops.core.title"},
        "authors": [
            {"name": "Aleksandr Petrov", "email": "a.petrov@example.invalid",
             "role": "author", "source": "office.creator"},
            {"name": "Finance Bot", "role": "last_modified_by",
             "source": "docprops.core.lastModifiedBy"},
        ],
        "organization": {"value": "Contoso Ltd", "source": "docprops.app.company"},
        "producer": {"value": "Microsoft Office Word", "source": "docprops.app.application"},
        "trust": "unsigned",
    }));
    let headline = strip_ansi(&identity_headline(&id).expect("headline"));
    let lines = identity_lines(&id);
    assert!(headline.contains("Q3 Vendor Invoice"), "{headline}");
    assert!(headline.contains("Aleksandr Petrov"), "{headline}");
    // The company the document claims — dropped from the headline because
    // an author outranked it — and the second party that touched it.
    assert!(lines.contains(r#"company="Contoso Ltd""#), "{lines}");
    assert!(lines.contains("Finance Bot"), "{lines}");
    assert!(lines.contains("(last_modified_by)"), "{lines}");
    // The author the headline already named is not repeated, but their
    // address — which the headline has no room for — is not lost either.
    assert!(!lines.contains("authors  Aleksandr Petrov,"), "{lines}");
    // Unsigned, so the producer is the headline's third slot: not repeated.
    assert!(!lines.contains(r#"producer="Microsoft"#), "{lines}");
}

/// A signed artifact shows its producing tool too: the headline spends its
/// third slot on the trust tier, so the tool would otherwise vanish.
#[test]
fn a_signed_artifact_still_names_its_producing_tool() {
    let id = identity(serde_json::json!({
        "title": {"value": "Quarterly Report", "source": "docprops.core.title"},
        "producer": {"value": "LibreOffice 7.6", "source": "docprops.app.application"},
        "signer": {"common_name": "Contoso Ltd", "source": "ooxml.signature"},
        "trust": "ca_signed",
    }));
    let headline = strip_ansi(&identity_headline(&id).expect("headline"));
    assert!(headline.contains("ca-signed"), "{headline}");
    assert!(!headline.contains("LibreOffice"), "{headline}");
    assert!(
        identity_lines(&id).contains(r#"producer="LibreOffice 7.6""#),
        "{}",
        identity_lines(&id)
    );
}

/// The terminal view keeps the header to what a human scans: no severity
/// tally, no `claims`/`ids` identity lines, and no file-level observation
/// without a location unless it is suspicious or worse.
#[test]
fn terminal_view_trims_counts_claims_ids_and_locationless_notables() {
    let mut file = src_file(
        0,
        "Installer",
        5,
        vec![
            finding_with("t/notable-note", Criticality::Notable),
            finding_with("t/suspicious-note", Criticality::Suspicious),
            finding_with("t/windowed", Criticality::Notable),
        ],
        vec![ctx_line(
            1,
            "WINDOWED_BYTES",
            Some(ctx_note("t/windowed", Criticality::Notable, 1)),
        )],
    );
    file.file_type = "macho".to_string();
    file.identity = Some(identity(serde_json::json!({
        "name": {"value": "authorization", "source": "macho.name"},
        "project": {"value": "Contoso Updater", "source": "macho.product"},
        "signer": {"organization": "Contoso Ltd", "source": "macho.signature"},
        "unique_ids": {"cdhash": "39aa9a55c001d58cdeadbeef"},
        "trust": "ad_hoc",
    })));
    let report = report_with_files(vec![file]);

    let terminal = format_context(&report, &TinyOpts::terminal());
    assert!(!terminal.contains("claims"), "{terminal}");
    assert!(!terminal.contains("cdhash"), "{terminal}");
    assert!(!terminal.contains("1S"), "{terminal}");
    assert!(!terminal.contains("1N"), "{terminal}");
    assert!(!terminal.contains("t/notable-note"), "{terminal}");
    assert!(terminal.contains("t/suspicious-note"), "{terminal}");
}

#[test]
fn embedded_label_formats_kind_offset_and_size() {
    assert_eq!(
        embedded_label("embedded:elf@0x324f9", 2508).as_deref(),
        Some("Embedded ELF @ 0x324f9 [2508 bytes]")
    );
    // Carrier-named payload (PE metadata name) keeps the name in the headline.
    assert_eq!(
        embedded_label("embedded:pe:payload.exe@0x5010", 4096).as_deref(),
        Some("Embedded PE payload.exe @ 0x5010 [4096 bytes]")
    );
    // A name that itself contains ':' splits only on the first separator.
    assert_eq!(
        embedded_label("embedded:pe:a:b@0x10", 1).as_deref(),
        Some("Embedded PE a:b @ 0x10 [1 bytes]")
    );
    // Ordinary paths are not embedded markers.
    assert_eq!(embedded_label("alvr/deps", 100), None);
}

fn finding_with(id: &str, crit: Criticality) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: id.to_string().into(),
        desc: id.to_string().into(),
        conf: 0.9,
        crit,
        mbc: None,
        attack: None,
        evidence: vec![],
        match_count: 0,
        source_file: None,
        downgraded: false,
    }
}

fn file_with_findings(findings: Vec<Finding>) -> FileAnalysis {
    let mut fa = FileAnalysis::new(0, "/t".to_string(), "elf".to_string(), "sha".to_string(), 1);
    fa.findings = findings;
    fa
}

/// A source (`python`) file with an explicit score, findings, and pre-built
/// context — the inputs the context view ranks and renders from.
fn src_file(
    id: u32,
    path: &str,
    score: u32,
    findings: Vec<Finding>,
    context: Vec<Win>,
) -> FileAnalysis {
    let mut fa = FileAnalysis::new(
        id,
        path.to_string(),
        "python".to_string(),
        format!("sha{id}"),
        100,
    );
    fa.score = score;
    fa.findings = findings;
    annotate(&mut fa, context);
    fa
}

/// A context window and the notes a test means it to carry.
struct Win {
    line: crate::types::ContextLine,
    notes: Vec<crate::types::Note>,
}

/// Append `context`'s windows to `fa`. Notes are derived from findings when
/// a report renders, so each intended note becomes a span (and the label)
/// of its finding, and a finding the test didn't supply is added from it.
fn annotate(fa: &mut FileAnalysis, context: Vec<Win>) {
    for Win { line, notes } in context {
        for n in notes {
            let at = fa
                .findings
                .iter()
                .position(|f| f.id == n.id)
                .unwrap_or_else(|| {
                    let mut f = Finding::new(
                        n.id.to_string(),
                        FindingKind::Capability,
                        n.desc.to_string(),
                        n.conf,
                    );
                    f.crit = n.crit;
                    fa.findings.push(f);
                    fa.findings.len() - 1
                });
            // One label per finding: a note's description replaces the
            // id-as-description placeholder `finding_with` gives a finding.
            let f = &mut fa.findings[at];
            if f.desc == f.id {
                f.desc = n.desc;
            }
            f.precomputed_spans
                .get_or_insert_with(Vec::new)
                .push([n.off, u64::from(n.len)]);
        }
        fa.context.push(line);
    }
}

/// Bytes reserved per test line, so windows on different lines never share
/// bytes (capture never emits overlapping windows).
const LINE_BYTES: u64 = 1000;

/// A single-line textual chunk at display line `line`, carrying an optional
/// note written with `off == line` meaning `data[0]` (ids and columns read
/// naturally; the bytes sit at `line * LINE_BYTES`).
fn ctx_line(line: u64, data: &str, note: Option<crate::types::Note>) -> Win {
    let loc = line * LINE_BYTES;
    Win {
        line: crate::types::ContextLine {
            loc,
            line: Some(line),
            col: Some(1),
            data: data.as_bytes().to_vec(),
        },
        notes: note
            .into_iter()
            .map(|n| crate::types::Note {
                off: loc + n.off.saturating_sub(line),
                ..n
            })
            .collect(),
    }
}

fn ctx_note(id: &str, crit: Criticality, loc: u64) -> crate::types::Note {
    crate::types::Note {
        crit,
        id: id.to_string().into(),
        desc: format!("{id} desc").into(),
        off: loc,
        len: 4,
        conf: 0.9,
    }
}

/// An empty finalized report with `files` swapped in — the context view reads
/// `report.files` directly, so this drives `format_context` from raw files.
fn report_with_files(files: Vec<FileAnalysis>) -> AnalysisReport {
    let mut report = create_test_report(vec![], vec![]);
    report.files = files;
    report
}

/// A binary (`elf`) file with a score, findings, and pre-built byte context —
/// what the hex view renders from.
fn bin_file(id: u32, score: u32, findings: Vec<Finding>, context: Vec<Win>) -> FileAnalysis {
    let mut fa = FileAnalysis::new(
        id,
        format!("/mal{id}.bin"),
        "elf".to_string(),
        format!("sha{id}"),
        4096,
    );
    fa.score = score;
    fa.findings = findings;
    annotate(&mut fa, context);
    fa
}

/// A raw-byte context unit starting at byte offset `loc`, carrying `notes`
/// (each note's `off` is an absolute file offset). No `line`/`col` marks it a
/// binary byte unit rather than a textual chunk.
fn byte_unit(loc: u64, data: &[u8], notes: Vec<crate::types::Note>) -> Win {
    Win {
        line: crate::types::ContextLine {
            loc,
            line: None,
            col: None,
            data: data.to_vec(),
        },
        notes,
    }
}

/// an embedding host's focused terminal knobs: hard cap of 5, selection narrowed to
/// suspicious+ and their legs, colorless for deterministic assertions.
fn focused_opts() -> TinyOpts {
    TinyOpts {
        top_n: 5,
        always_crit: None,
        focus_crit: Some(Criticality::Suspicious),
        context_lines: Some(1),
        full_context: false,
        color: false,
        ..TinyOpts::terminal()
    }
}

/// The terminal view draws a match's own rows plus one row either side —
/// two for a hostile hit — however many bytes capture reserved around it.
/// A criticality-sized window (up to 128/256 bytes) rendered whole turned a
/// single finding into a twenty-row block.
#[test]
fn terminal_hex_window_keeps_one_margin_row_two_when_hostile() {
    let opts = TinyOpts {
        color: false,
        ..TinyOpts::terminal()
    };
    let rows = |crit: Criticality| {
        let finding = Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "a/hit".to_string().into(),
            desc: "a/hit desc".into(),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        };
        // 160 bytes of captured window; the match is four bytes in the middle.
        let unit = byte_unit(0, &[0x41; 160], vec![ctx_note("a/hit", crit, 80)]);
        let report = report_with_files(vec![bin_file(1, 50, vec![finding], vec![unit])]);
        format_context(&report, &opts)
            .lines()
            .filter(|l| l.starts_with(|c: char| c.is_ascii_hexdigit()))
            .count()
    };
    // One hit row (a 4-byte match cannot straddle more than two) plus its
    // margin: 1 either side for notable, 2 for hostile.
    assert_eq!(rows(Criticality::Notable), 3);
    assert_eq!(rows(Criticality::Hostile), 5);
}

#[test]
fn focused_selection_keeps_suspicious_plus_legs_only() {
    // A hostile composite, the component leg it references (anchored to a
    // source line), and an unreferenced notable. Focused selection keeps
    // the composite and its windowed leg; the bystander notable is dropped.
    let composite = Finding {
        trait_refs: vec!["c2/leg".to_string().into()],
        ..finding_with("objectives/c2/implant", Criticality::Hostile)
    };
    let leg = finding_with("c2/leg", Criticality::Component);
    let bystander = finding_with("misc/loose-notable", Criticality::Notable);
    let leg_ctx = ctx_line(
        1,
        "import socket_beacon",
        Some(ctx_note("c2/leg", Criticality::Component, 1)),
    );
    let report = report_with_files(vec![src_file(
        0,
        "/a.py",
        5,
        vec![composite, leg, bystander],
        vec![leg_ctx],
    )]);

    let out = format_context(&report, &focused_opts());
    assert!(out.contains("c2/implant"), "{out:?}");
    assert!(out.contains("import socket_beacon"), "{out:?}");
    assert!(!out.contains("misc/loose-notable"), "{out:?}");
}

#[test]
fn focused_locationless_stays_suspicious_and_above() {
    // A location-less notable — a container's archive-shape observation,
    // say — has no window to anchor it, and the focused view refuses to
    // surface it as a floating note. A location-less *hostile* (a
    // cross-file composite) still renders: that's the verdict's evidence.
    let report = report_with_files(vec![src_file(
        0,
        "/b.py",
        2,
        vec![
            finding_with("objectives/c2/implant", Criticality::Hostile),
            finding_with("misc/loose-notable", Criticality::Notable),
        ],
        vec![],
    )]);
    let out = format_context(&report, &focused_opts());
    assert!(out.contains("c2/implant"), "{out:?}");
    assert!(!out.contains("misc/loose-notable"), "{out:?}");
}

#[test]
fn focused_file_without_flags_keeps_windowed_notables() {
    // Nothing at focus_crit fired: selection falls back to the ordinary
    // notable view, so an unremarkable file is not silenced — but only
    // through its windows; a location-less notable stays dropped.
    let anchored = finding_with("misc/anchored-notable", Criticality::Notable);
    let floating = finding_with("misc/floating-notable", Criticality::Notable);
    let ctx = ctx_line(
        1,
        "import ctypes",
        Some(ctx_note("misc/anchored-notable", Criticality::Notable, 1)),
    );
    let report = report_with_files(vec![src_file(
        0,
        "/b.py",
        2,
        vec![anchored, floating],
        vec![ctx],
    )]);
    let out = format_context(&report, &focused_opts());
    assert!(out.contains("import ctypes"), "{out:?}");
    assert!(!out.contains("misc/floating-notable"), "{out:?}");
}

#[test]
fn focused_multi_row_hit_earns_no_trailing_row() {
    // A hostile span that already continues onto multiple hex rows has
    // shown its continuation — no trailing row is added after it. A
    // one-row hit still keeps its single trail. The renderer's stride
    // follows the detected terminal width, so derive the expected number
    // of match-bearing rows instead of assuming a 16-byte stride.
    let long_hit = finding_with("objectives/spans-two-rows", Criticality::Hostile);
    let mut note = ctx_note("objectives/spans-two-rows", Criticality::Hostile, 0);
    note.len = 20;
    let mut file = bin_file(
        0,
        9,
        vec![long_hit],
        vec![byte_unit(0, &[0x42; 64], vec![note])],
    );
    file.file_type = "elf".to_string();
    let report = report_with_files(vec![file]);
    let out = format_context(&report, &focused_opts());
    let hex_rows = out.lines().filter(|l| l.contains("42 42 42")).count();
    let loc_width = format!("{:x}", 64).len();
    let expected_match_rows = 20_usize.div_ceil(hex_stride(terminal_width(), loc_width));
    assert_eq!(hex_rows, expected_match_rows, "{out:?}");
}

#[test]
fn focused_cap_is_hard_even_for_hostile() {
    // Seven hostiles at descending confidence: only the strongest five
    // render — always_crit: None means nothing bypasses top_n.
    let findings: Vec<Finding> = (0..7)
        .map(|i| Finding {
            conf: 0.99 - 0.05 * i as f32,
            ..finding_with(&format!("objectives/h{i}"), Criticality::Hostile)
        })
        .collect();
    let report = report_with_files(vec![src_file(0, "/c.py", 9, findings, vec![])]);
    let out = format_context(&report, &focused_opts());
    for i in 0..5 {
        assert!(out.contains(&format!("objectives/h{i}\n")), "{out:?}");
    }
    for i in 5..7 {
        assert!(!out.contains(&format!("objectives/h{i}\n")), "{out:?}");
    }
}

#[test]
fn focused_hex_window_drops_unselected_notes_and_keeps_a_trail() {
    // One merged 64-byte window: a hostile note at its head, an unselected
    // notable's note further down. Focused rendering keeps the hit row and
    // one trailing row; the notable neither renders a row nor a comment.
    let hostile = finding_with("objectives/h", Criticality::Hostile);
    let mut file = bin_file(
        0,
        9,
        vec![hostile],
        vec![byte_unit(
            0,
            &[0x41; 64],
            vec![
                ctx_note("objectives/h", Criticality::Hostile, 0),
                ctx_note("misc/loose-notable", Criticality::Notable, 48),
            ],
        )],
    );
    file.file_type = "elf".to_string();
    let report = report_with_files(vec![file]);
    let out = format_context(&report, &focused_opts());
    assert!(out.contains("objectives/h desc"), "{out:?}");
    assert!(!out.contains("misc/loose-notable"), "{out:?}");
    // Hit row plus at least one trailing context row of hex cells.
    let hex_rows = out.lines().filter(|l| l.contains("41 41 41")).count();
    assert!(
        hex_rows >= 2,
        "expected hit row + trail, got {hex_rows}: {out:?}"
    );
}

#[test]
fn focused_source_trail_skips_near_empty_and_stops_after_one_line() {
    // A hostile hit keeps the next *real* line (the lone `}` is skipped);
    // rows past the trail are dropped even though the chunk carries them.
    let hostile = finding_with("objectives/h", Criticality::Hostile);
    let chunk = Win {
        line: crate::types::ContextLine {
            loc: 0,
            line: Some(1),
            col: Some(1),
            data: b"sudo ./payload run\n}\ninstall -Dm755 target\nunrelated trailing line\n"
                .to_vec(),
        },
        notes: vec![ctx_note("objectives/h", Criticality::Hostile, 0)],
    };
    let report = report_with_files(vec![src_file(0, "/d.sh", 9, vec![hostile], vec![chunk])]);
    let out = format_context(&report, &focused_opts());
    assert!(out.contains("sudo ./payload run"), "{out:?}");
    assert!(out.contains("install -Dm755 target"), "{out:?}");
    assert!(!out.contains("unrelated trailing line"), "{out:?}");
}

#[test]
fn container_shows_cross_file_composites_not_member_duplicates() {
    // An archive container re-evaluates member content at container scope, so
    // it accumulates both genuine cross-file composites (native only here) and
    // copies of member findings (also native on the member). The container
    // must surface the former and drop the latter, which renders on the member.
    let composite = Finding {
        trait_refs: vec!["a".to_string().into(), "b".to_string().into()],
        ..finding_with(
            "objectives/supply-chain/install-hook::native-implant",
            Criticality::Hostile,
        )
    };
    // A member atomic that also got re-evaluated onto the container.
    let dup_on_container = finding_with(
        "metadata/package/fields/scripts::has-preinstall",
        Criticality::Suspicious,
    );
    // The same finding, native to the member where it was actually located.
    let dup_on_member = finding_with(
        "metadata/package/fields/scripts::has-preinstall",
        Criticality::Suspicious,
    );

    let mut container = FileAnalysis::new(
        0,
        "/x/pkg.tgz".to_string(),
        "tar.gz".to_string(),
        "sha".to_string(),
        10,
    );
    container.depth = 0;
    container.findings = vec![composite, dup_on_container];

    let mut member = FileAnalysis::new(
        1,
        "/x/pkg.tgz!!package/package.json".to_string(),
        "package.json".to_string(),
        "sha2".to_string(),
        5,
    );
    member.depth = 1;
    member.findings = vec![dup_on_member];

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/x/pkg.tgz".to_string(),
        ..Default::default()
    });
    report.files = vec![container, member];

    let out = strip_ansi(&format_terminal_ctx(&report));

    // The cross-file composite is the container's verdict and must show.
    assert!(
        out.contains("native-implant") || out.contains("install-hook"),
        "container must show the cross-file composite, got:\n{out}"
    );
    // The duplicated atomic renders on the member (indented), not the container.
    let member_indented = out
        .lines()
        .any(|l| l.starts_with("  ") && l.contains("has-preinstall"));
    assert!(
        member_indented,
        "member finding must render indented under the archive, got:\n{out}"
    );
    // It must NOT appear at the container's (unindented) level.
    let on_container = out
        .lines()
        .any(|l| !l.starts_with(' ') && l.contains("has-preinstall"));
    assert!(
        !on_container,
        "duplicated member atomic must not render on the container, got:\n{out}"
    );
}

#[test]
fn registry_purl_rebuilds_from_registry_facts() {
    let mut reg = FileAnalysis::new(
        0,
        "be5invis_iosevka.registry.json".to_string(),
        "registry".to_string(),
        "sha".to_string(),
        64,
    );
    // Non-registry file: no purl regardless of any kv.
    let mut js = FileAnalysis::new(1, "/a.js".into(), "javascript".into(), "s2".into(), 8);
    js.kv
        .insert("registry.ecosystem".into(), serde_json::json!("github"));
    assert_eq!(registry_purl(&js), None, "non-registry file yields no purl");

    // A versionless registry node drops the `@version` suffix.
    reg.kv
        .insert("registry.ecosystem".into(), serde_json::json!("github"));
    reg.kv.insert(
        "registry.name".into(),
        serde_json::json!("be5invis/iosevka"),
    );
    assert_eq!(
        registry_purl(&reg).as_deref(),
        Some("pkg:github/be5invis/iosevka")
    );

    // With a version it is appended.
    reg.kv
        .insert("registry.version".into(), serde_json::json!("34.7.0"));
    assert_eq!(
        registry_purl(&reg).as_deref(),
        Some("pkg:github/be5invis/iosevka@34.7.0")
    );

    // Missing name → no purl (a fact's absence is meaningful).
    reg.kv.remove("registry.name");
    assert_eq!(registry_purl(&reg), None);
}

#[test]
fn composite_source_trail_shows_member_and_registry_provenance() {
    use crate::types::file_analysis::{ARCHIVE_DELIMITER, CompositeSource};

    let fid = "supply-chain::obfuscated-exfil";
    let mut container = FileAnalysis::new(0, "/pkg.tgz".into(), "tar.gz".into(), "s0".into(), 100);
    container.composite_sources.insert(
        fid.to_string(),
        vec![
            CompositeSource {
                file: 1,
                line: Some(12),
                offset: Some(200),
            },
            CompositeSource {
                file: 2,
                line: None,
                offset: Some(0),
            },
        ],
    );

    let member = FileAnalysis::new(
        1,
        format!("/pkg.tgz{ARCHIVE_DELIMITER}pkg/install.js"),
        "javascript".into(),
        "s1".into(),
        20,
    );
    let mut registry = FileAnalysis::new(
        2,
        "be5invis_iosevka.registry.json".into(),
        "registry".into(),
        "s2".into(),
        64,
    );
    registry
        .kv
        .insert("registry.ecosystem".into(), serde_json::json!("github"));
    registry.kv.insert(
        "registry.name".into(),
        serde_json::json!("be5invis/iosevka"),
    );

    let id_to_file: HashMap<u32, &FileAnalysis> =
        [(1u32, &member), (2u32, &registry)].into_iter().collect();

    let trail = composite_source_trail(&container, fid, &id_to_file);
    // The code leg renders as a member path + line; the provenance leg as a
    // reconstructed purl, not the synthetic `*.registry.json` filename.
    assert!(
        trail.contains(&"pkg/install.js:12".to_string()),
        "archive member leg with line, got: {trail:?}"
    );
    assert!(
        trail.contains(&"registry/pkg:github/be5invis/iosevka".to_string()),
        "registry provenance leg as registry/<purl>, got: {trail:?}"
    );
}

pub(super) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn select_ids_always_shows_suspicious_and_hostile_past_cap() {
    // 60 hostile findings with a cap of 50: every one must survive,
    // because suspicious/hostile bypass `top_n` entirely.
    let findings = (0..60)
        .map(|i| finding_with(&format!("hostile-{i}"), Criticality::Hostile))
        .collect();
    let file = file_with_findings(findings);
    let selected = select_ids(&file, &TinyOpts::terminal());
    assert_eq!(
        selected.len(),
        60,
        "all 60 hostile must show despite cap 50"
    );
}

#[test]
fn select_ids_caps_lower_crit_remainder_but_keeps_high() {
    // 60 notable + 8 suspicious/hostile, cap 40. All 8 high-crit show;
    // the notable remainder fills to a total of 40 (32 notables).
    let mut findings: Vec<Finding> = (0..60)
        .map(|i| finding_with(&format!("notable-{i}"), Criticality::Notable))
        .collect();
    for i in 0..5 {
        findings.push(finding_with(&format!("sus-{i}"), Criticality::Suspicious));
    }
    for i in 0..3 {
        findings.push(finding_with(&format!("hostile-{i}"), Criticality::Hostile));
    }
    let file = file_with_findings(findings);
    let selected = select_ids(&file, &TinyOpts::terminal());
    assert_eq!(selected.len(), 40, "total capped at 40");
    for i in 0..5 {
        assert!(selected.contains(&format!("sus-{i}").as_str()));
    }
    for i in 0..3 {
        assert!(selected.contains(&format!("hostile-{i}").as_str()));
    }
    let notables = selected
        .iter()
        .filter(|id| id.starts_with("notable-"))
        .count();
    assert_eq!(
        notables, 32,
        "lower-crit remainder fills the rest of the 40"
    );
}

#[test]
fn terminal_view_caps_notables_at_40() {
    // 300 notable findings: the terminal cap (40) truncates hard.
    let findings = (0..300)
        .map(|i| finding_with(&format!("notable-{i}"), Criticality::Notable))
        .collect();
    let file = file_with_findings(findings);
    assert_eq!(select_ids(&file, &TinyOpts::terminal()).len(), 40);
}

#[test]
fn undetected_file_stays_quiet_in_terminal() {
    // A benign file with only low-tier traits: the human terminal view stays
    // quiet.
    let comp = finding_with("micro/fs::readdir", Criticality::Component);
    let base = finding_with("meta/build::debuglink", Criticality::Baseline);
    let file = src_file(
        0,
        "/bin/fake",
        1,
        vec![comp, base],
        vec![
            ctx_line(
                1,
                "readdir(dirp);",
                Some(ctx_note("micro/fs::readdir", Criticality::Component, 1)),
            ),
            ctx_line(
                2,
                "debuglink(section);",
                Some(ctx_note("meta/build::debuglink", Criticality::Baseline, 2)),
            ),
        ],
    );
    let report = report_with_files(vec![file]);

    let terminal = format_context(&report, &TinyOpts::terminal());
    assert!(
        terminal.is_empty(),
        "terminal view stays quiet for an undetected file, got: {terminal:?}"
    );
}

#[test]
fn trait_family_takes_segments_below_the_namespace() {
    let id = "objectives/command-and-control/infrastructure/paste::shz-al";
    assert_eq!(
        trait_family(id, 2),
        "objectives/command-and-control/infrastructure"
    );
    assert_eq!(
        trait_family(id, 3),
        "objectives/command-and-control/infrastructure/paste"
    );
    assert_eq!(trait_family("t/one", 3), "t/one");
}

// Window sizing by inherited composite severity — a leg rendered with its
// stronger composite's radius — is decided at capture time now, and covered by
// `context::tests::{textual,binary}_atomic_leg_reserves_stronger_composites_window`.
// The render layer emits every row of the captured chunk, so the former
// per-line radius tests here have no rendering decision left to exercise.

#[test]
fn terminal_keeps_file_gap_lines_with_full_paths() {
    // A per-file analysis gap is for a reader deciding whether to trust
    // silence.
    let mut file = src_file(
        0,
        "/corpus/samples/hostile/x.py",
        50,
        vec![],
        vec![ctx_line(
            1,
            "run()",
            Some(ctx_note("t/one", Criticality::Notable, 1)),
        )],
    );
    file.analysis_gaps = vec![crate::types::AnalysisGap::FlowGraphLimited].into();
    let report = report_with_files(vec![file]);

    // The terminal view keeps the gap, with the full path for the human who
    // filed it.
    let term = format_context(&report, &TinyOpts::terminal());
    assert!(
        term.contains("Analysis incomplete for \"/corpus/samples/hostile/x.py\""),
        "{term}"
    );
}

fn create_test_report(findings: Vec<Finding>, yara_matches: Vec<YaraMatch>) -> AnalysisReport {
    let mut report = AnalysisReport {
        analysis_gaps: Default::default(),
        version: "3.0".to_string(),
        analysis_timestamp: Some(Utc::now()),
        target: TargetInfo {
            path: "/test/sample.bin".to_string(),
            file_type: "ELF".to_string(),
            size_bytes: 12345,
            sha256: "def456abc".to_string(),
            architectures: Some(vec!["x86_64".to_string()]),
        },
        findings,
        suppressions: vec![],
        context: vec![],
        traits: vec![],
        structure: vec![],
        functions: vec![],
        strings: vec![],
        sections: vec![],
        imports: vec![],
        exports: vec![],
        yara_matches,
        syscalls: vec![],
        filefacts: None,
        identity: None,
        cache_hit: false,
        values_tree: None,
        cached_member_kv: None,
        engine: None,
        fragment_host_type: None,
        filefacts_metrics: None,
        filefacts_metric_spans: None,
        comments: vec![],
        archive_contents: vec![],
        scanned_path: None,
        files: vec![],
        summary: None,
        metadata: crate::types::AnalysisMetadata {
            analysis_duration_ms: 100,
            tools_used: vec!["test".to_string()],
            errors: vec![],
        },
        diff: None,
    };
    // Finalize to populate files array
    report.finalize();
    report
}

#[test]
fn test_aggregate_findings_empty() {
    let findings: Vec<Finding> = vec![];
    let aggregated = aggregate_findings_by_directory(&findings);
    assert_eq!(aggregated.len(), 0);
}

#[test]
fn test_aggregate_findings_different_directories() {
    let findings = vec![
        Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "execution/shell::bash-variant".to_string().into(),
            desc: "Execute bash".to_string().into(),
            conf: 0.9,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        },
        Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "net/http::get-variant".to_string().into(),
            desc: "HTTP GET request".to_string().into(),
            conf: 0.8,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        },
    ];
    let aggregated = aggregate_findings_by_directory(&findings);
    assert_eq!(aggregated.len(), 2);
    // IDs should be base trait IDs (without ::variant suffix)
    let ids: Vec<_> = aggregated.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"execution/shell"));
    assert!(ids.contains(&"net/http"));
}

#[test]
fn test_aggregate_findings_same_directory_keeps_highest_criticality() {
    let findings = vec![
        Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "execution/shell::bash-variant".to_string().into(),
            desc: "Execute bash".to_string().into(),
            conf: 0.7,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        },
        Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "execution/shell::sh-variant".to_string().into(),
            desc: "Execute sh".to_string().into(),
            conf: 0.7,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        },
    ];
    let aggregated = aggregate_findings_by_directory(&findings);
    assert_eq!(aggregated.len(), 1);
    assert_eq!(aggregated[0].id, "execution/shell");
    assert_eq!(aggregated[0].crit, Criticality::Hostile);
    // Should have both trait IDs in trait_refs
    assert_eq!(aggregated[0].trait_refs.len(), 2);
}

#[test]
fn test_aggregate_findings_same_directory_keeps_highest_confidence() {
    let findings = vec![
        Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "execution/shell::bash-variant".to_string().into(),
            desc: "Execute bash".to_string().into(),
            conf: 0.6,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        },
        Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "execution/shell::sh-variant".to_string().into(),
            desc: "Execute sh".to_string().into(),
            conf: 0.9,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        },
    ];
    let aggregated = aggregate_findings_by_directory(&findings);
    assert_eq!(aggregated.len(), 1);
    assert_eq!(aggregated[0].id, "execution/shell");
    assert_eq!(aggregated[0].conf, 0.9);
}

#[test]
fn terminal_lists_a_location_less_finding() {
    let findings = vec![Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: "micro-behaviors/process/create/shell::bash"
            .to_string()
            .into(),
        desc: "Execute shell commands".to_string().into(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        evidence: vec![Evidence {
            method: "symbol".to_string(),
            source: "test".to_string(),
            value: "bash\nwith\twhitespace".to_string(),
            location: None,
            ..Default::default()
        }],
        match_count: 1,
        source_file: None,
        downgraded: false,
    }];
    let report = create_test_report(findings, vec![]);

    // No capture pass ran here, so the finding has no context window; the
    // terminal view still lists it as a location-less note.
    let term = format_context(&report, &TinyOpts::terminal());
    assert!(term.contains("Execute shell commands"), "{term}");
}

#[test]
fn tiny_path_basenames_root_and_archive_relativizes_members() {
    // Members are always archive-relative; the `!!` delimiter becomes `/`.
    assert_eq!(
        tiny_path("/tmp/a.zip!!lib/foo.so", false),
        "a.zip/lib/foo.so"
    );
    assert_eq!(
        tiny_path("/tmp/a.zip!!b.zip!!deep", true),
        "a.zip/b.zip/deep"
    );
    // A standalone/root path is basenamed only on request (the card layout).
    assert_eq!(tiny_path("/tmp/triage/x.bin", true), "x.bin");
    assert_eq!(tiny_path("/tmp/triage/x.bin", false), "/tmp/triage/x.bin");
}

#[test]
fn select_ids_terminal_keeps_composites() {
    let mut composite = finding_with("objectives/loader::matched", Criticality::Suspicious);
    composite.trait_refs = vec![
        "micro-behaviors/fs/read::open".to_string().into(),
        "objectives/loader::fragment".to_string().into(),
    ];
    let file = file_with_findings(vec![
        finding_with("micro-behaviors/fs/read::open", Criticality::Baseline),
        finding_with("objectives/loader::fragment", Criticality::Component),
        finding_with("objectives/loader::unused", Criticality::Component),
        composite,
    ]);

    // A human wants the conclusion.
    let term = select_ids(&file, &TinyOpts::terminal());
    assert!(term.contains(&"objectives/loader::matched"), "{term:?}");
}

#[test]
fn select_ids_keeps_cross_file_composites_on_a_container() {
    // A cross-file composite carries source provenance (`composite_sources`)
    // but is native to no member — it exists only on the container. Treating
    // it as an inherited copy dropped it from every rendered view while it
    // stayed in the JSON.
    let mut composite = finding_with("objectives/impact::launch", Criticality::Suspicious);
    composite.src = Some(7);
    let mut file = file_with_findings(vec![composite]);
    file.composite_sources.insert(
        "objectives/impact::launch".to_string(),
        vec![crate::types::file_analysis::CompositeSource {
            file: 7,
            line: None,
            offset: None,
        }],
    );

    let term = select_ids(&file, &TinyOpts::terminal());
    assert!(term.contains(&"objectives/impact::launch"), "{term:?}");

    // An ordinary inherited copy — `src` set, no composite provenance — is
    // still rendered by its origin member, not here.
    let mut inherited = finding_with("objectives/impact::other", Criticality::Suspicious);
    inherited.src = Some(7);
    let plain = file_with_findings(vec![inherited]);
    let term = select_ids(&plain, &TinyOpts::terminal());
    assert!(!term.contains(&"objectives/impact::other"), "{term:?}");
}

#[test]
fn terminal_does_not_resurrect_dominated_finding_location_less() {
    // A finding that *has* a byte offset but is missing from the windows was
    // dominated by a stronger overlapping match at that span — already
    // represented there. The view must not bring it back as a location-less
    // note (it would read as a separate, anchorless finding and duplicate what
    // shows at the offset).
    use crate::types::{ContextLine, Evidence, Note};
    let finding = |id: &str, crit: Criticality| Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: id.to_string().into(),
        desc: format!("{id} desc").into(),
        conf: 0.9,
        crit,
        mbc: None,
        attack: None,
        evidence: vec![],
        match_count: 0,
        source_file: None,
        downgraded: false,
    };
    // `b/dominated` matched at byte 0 (same span as `a/win`), so it has a local
    // offset — the mark of a dominated finding, not a location-less one.
    let mut dominated = finding("b/dominated", Criticality::Suspicious);
    dominated.evidence = vec![Evidence::new("m", "s", "x").with_offset(0)];
    let report = create_test_report(
        vec![finding("a/win", Criticality::Hostile), dominated],
        vec![],
    );
    let mut report = report;
    // Only `a/win` won a window; `b/dominated` was dropped by the overlap pass.
    annotate(
        &mut report.files[0],
        vec![Win {
            line: ContextLine {
                loc: 0,
                line: Some(7),
                col: Some(1),
                data: b"winner()".to_vec(),
            },
            notes: vec![Note {
                crit: Criticality::Hostile,
                id: "a/win".to_string().into(),
                desc: "a/win desc".to_string().into(),
                off: 0,
                len: 6,
                conf: 0.9,
            }],
        }],
    );
    // A dominated finding is suppressed everywhere, never resurrected as a
    // location-less gutter note.
    let term = format_context(&report, &TinyOpts::terminal());
    assert!(!term.contains("dominated desc"), "{term:?}");
}
