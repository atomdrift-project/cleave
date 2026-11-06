use super::*;

/// An Outlook attachment is analyzed as a nested member named after its
/// filename, typed from its bytes plus that name, and an attached
/// message recurses one level down.
#[test]
fn msg_attachments_attach_as_named_members() {
    use ole2::tests::{build_cfb, utf16};
    let a0 = "/__attach_version1.0_#00000000";
    let a1 = "/__attach_version1.0_#00000001";
    let inner = format!("{a1}/__substg1.0_3701000D");
    let msg = build_cfb(&[
        ("/__substg1.0_0037001F", &utf16("subject")),
        (
            &format!("{a0}/__substg1.0_37010102"),
            b"<html><body><script>document.write('x')</script></body></html>",
        ),
        (&format!("{a0}/__substg1.0_3707001F"), &utf16("lure.html")),
        (&format!("{a1}/__substg1.0_3001001F"), &utf16("Fwd")),
        (&format!("{inner}/__substg1.0_0037001F"), &utf16("inner")),
        (
            &format!("{inner}/__attach_version1.0_#00000000/__substg1.0_37010102"),
            b"#!/bin/sh\necho hi\n",
        ),
        (
            &format!("{inner}/__attach_version1.0_#00000000/__substg1.0_3707001F"),
            &utf16("run.sh"),
        ),
    ]);

    let report = OfficeAnalyzer::new().analyze_office(
        Path::new("/samples/mail.msg"),
        &msg,
        &FileType::OleDoc,
        0,
        None,
    );
    assert_eq!(report.target.file_type, "msg");
    let files: Vec<(&str, &str, u32)> = report
        .files
        .iter()
        .map(|f| (f.path.as_str(), f.file_type.as_str(), f.depth))
        .collect();
    assert!(
        files.contains(&("mail.msg!!lure.html", "html", 1)),
        "html attachment missing: {files:?}"
    );
    assert!(
        files.contains(&("mail.msg!!Fwd.msg", "msg", 1)),
        "attached message missing: {files:?}"
    );
    assert!(
        files.contains(&("mail.msg!!Fwd.msg!!run.sh", "shell", 2)),
        "attached message's attachment missing: {files:?}"
    );
}

#[test]
fn template_target_remoteness() {
    // Remote injection vectors.
    assert!(target_is_remote("http://attacker.example/x.dotm"));
    assert!(target_is_remote("HTTPS://Attacker.example/x.dotm"));
    assert!(target_is_remote("\\\\10.0.0.1\\share\\x.dotm"));
    assert!(target_is_remote("//host/share/x.dotm"));
    assert!(target_is_remote("file://server/share/x.dot"));
    // Benign local-template back-references and in-package paths.
    assert!(!target_is_remote(
        "file:///C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Templates\\Report.dot"
    ));
    assert!(!target_is_remote(
        "file://localhost/Users/me/Templates/Report.dot"
    ));
    assert!(!target_is_remote("C:\\Users\\me\\Templates\\Report.dot"));
    assert!(!target_is_remote("../templates/base.dotx"));
    assert!(!target_is_remote("Normal.dotm"));
}

#[test]
fn test_office_analyzer_can_analyze() {
    let analyzer = OfficeAnalyzer::new();
    assert!(analyzer.can_analyze(Path::new("test.doc")));
    assert!(analyzer.can_analyze(Path::new("test.docx")));
    assert!(analyzer.can_analyze(Path::new("test.xls")));
    assert!(analyzer.can_analyze(Path::new("test.xlsx")));
    assert!(analyzer.can_analyze(Path::new("test.ppt")));
    assert!(analyzer.can_analyze(Path::new("test.pptx")));
    assert!(analyzer.can_analyze(Path::new("test.docm")));
    assert!(analyzer.can_analyze(Path::new("test.xlsm")));
    assert!(analyzer.can_analyze(Path::new("test.msg")));
    assert!(!analyzer.can_analyze(Path::new("test.pdf")));
    assert!(!analyzer.can_analyze(Path::new("test.rtf")));
    assert!(!analyzer.can_analyze(Path::new("test.txt")));
}

/// Per-module shape stats (logical-line count, random-name
/// heuristic) thread through `populate_vba_symbols_and_metrics`
/// even when no `AnalysisContext` is provided — symbol-side
/// aggregates require filefacts, but the shape side is cleave-only
/// and runs from raw module source.
#[test]
fn populate_vba_threads_shape_stats_without_ctx() {
    let analyzer = OfficeAnalyzer::new();
    let target = TargetInfo {
        path: "evil.docm".into(),
        file_type: "docm".into(),
        size_bytes: 4096,
        sha256: "0".repeat(64),
        architectures: None,
    };
    let mut report = AnalysisReport::new(target);

    let modules = vec![
        vba::VbaModule {
            name: "ThisDocument".into(),
            source_code: "Sub Document_Open()\n  ' comment\n  x = 1\nEnd Sub\n".into(),
        },
        vba::VbaModule {
            name: "qWeRty12Ab".into(), // matches random-name heuristic
            source_code: "Sub Helper()\n  y = 2\nEnd Sub\n".into(),
        },
    ];

    // No AnalysisContext — symbol-side aggregates stay default
    // but the shape pass still runs.
    analyzer.populate_vba_symbols_and_metrics(&mut report, Path::new("evil.docm"), &modules, None);

    use crate::types::MetricsExt;
    let flat = report
        .filefacts_metrics
        .as_ref()
        .expect("filefacts_metrics populated");
    assert_eq!(
        flat.as_bool("office.is_macro_enabled_extension"),
        Some(true)
    );
    assert_eq!(flat.as_bool("office.has_macros"), Some(true));
    assert_eq!(flat.as_u64("office.vba_module_count"), Some(2));

    assert!(flat.as_u64("office.vba.total_logical_lines").unwrap_or(0) >= 6);
    assert!(flat.as_u64("office.vba.comment_lines").unwrap_or(0) >= 1);
    assert_eq!(
        flat.as_u64("office.vba.random_named_module_count"),
        Some(1),
        "qWeRty12Ab should match the random-name heuristic",
    );
}

/// Verify `populate_structure_metrics` threads sub-struct metrics
/// and cross-format counts onto the flat `office.*` keys in
/// `filefacts_metrics`.
#[test]
fn populate_structure_metrics_wires_subobjects_and_cross_counts() {
    let analyzer = OfficeAnalyzer::new();
    let target = TargetInfo {
        path: "evil.docx".into(),
        file_type: "docx".into(),
        size_bytes: 1024,
        sha256: "0".repeat(64),
        architectures: None,
    };
    let mut report = AnalysisReport::new(target);

    let cross = OfficeCrossCounts {
        embedded_executable_count: 0,
        external_ref_count: 4,
        external_template_count: 1,
        external_oleobject_count: 1,
        external_frame_count: 1,
        external_image_count: 1,
        dde_link_count: 2,
        is_encrypted: true,
    };
    let xlm = XlmMetrics {
        char_count: 250,
        ..Default::default()
    };
    let ooxml = OoxmlMetrics {
        entry_count: 18,
        declares_macro_enabled: true,
        ..Default::default()
    };
    let ole = OleMetrics {
        stream_count: 9,
        dangerous_clsid_count: 1,
        ..Default::default()
    };

    analyzer.populate_structure_metrics(
        &mut report,
        Some(ole.clone()),
        Some(ooxml.clone()),
        Some(xlm.clone()),
        cross,
        /* embedded_executable_count = */ 2,
    );

    use crate::types::MetricsExt;
    let flat = report
        .filefacts_metrics
        .as_ref()
        .expect("filefacts_metrics populated");
    assert_eq!(flat.as_u64("office.embedded_executable_count"), Some(2));
    assert_eq!(flat.as_u64("office.external_ref_count"), Some(4));
    assert_eq!(flat.as_u64("office.external_template_count"), Some(1));
    assert_eq!(flat.as_u64("office.external_oleobject_count"), Some(1));
    assert_eq!(flat.as_u64("office.external_frame_count"), Some(1));
    assert_eq!(flat.as_u64("office.external_image_count"), Some(1));
    assert_eq!(flat.as_u64("office.dde_link_count"), Some(2));
    assert_eq!(flat.as_bool("office.is_encrypted"), Some(true));
    // Sub-struct fields flattened into dotted keys.
    assert_eq!(flat.as_u64("office.ole.stream_count"), Some(9));
    assert_eq!(flat.as_u64("office.ooxml.entry_count"), Some(18));
    assert_eq!(flat.as_u64("office.xlm.char_count"), Some(250));
}

#[test]
fn test_finding_ids_follow_taxonomy() {
    // Verify all finding IDs use the taxonomy :: separator format
    let ids = [
        "metadata/format/macro::ole2-has-vba",
        "metadata/format/macro::ooxml-has-vba",
        "metadata/format/properties::doc-properties",
        "objectives/execution/interpreter::template-injection",
        "objectives/execution/interpreter::dde-execution",
        "objectives/command-and-control/dropper/payload::embedded-executable",
    ];
    for id in &ids {
        assert!(id.contains("::"), "Finding ID missing :: separator: {id}");
        assert!(
            id.starts_with("metadata/")
                || id.starts_with("objectives/")
                || id.starts_with("micro-behaviors/"),
            "Finding ID not in taxonomy tier: {id}"
        );
    }
}
