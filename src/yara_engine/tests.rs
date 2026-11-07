use super::*;
use crate::analyzers::{FileType, FileTypeExt};

/// Metadata reaches findings as the rule author wrote it: no Debug
/// escaping of quotes or non-ASCII, and numbers without a type wrapper.
#[test]
fn metadata_values_are_plain_text() {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(r#"rule r { meta: d = "say \"hi\" — café" n = 5 b = true condition: true }"#)
        .unwrap();
    let rules = compiler.build();
    let rule = rules.iter().next().unwrap();
    let meta: Vec<(String, String)> = rule
        .metadata()
        .map(|(k, v)| (k.to_string(), meta_text(&v)))
        .collect();
    assert_eq!(
        meta,
        [
            ("d".to_string(), "say \"hi\" — café".to_string()),
            ("n".to_string(), "5".to_string()),
            ("b".to_string(), "true".to_string()),
        ]
    );
}

fn load_test_bucket(engine: &mut YaraEngine, bucket: &str, sources: &[(&str, &str)]) {
    let mut compiler = yara_x::Compiler::new();
    for (namespace, source) in sources {
        compiler.new_namespace(namespace);
        compiler.add_source(source.as_bytes()).unwrap();
        if namespace.starts_with("inline.") {
            engine
                .compiled_inline_namespaces
                .push(namespace.to_string());
        }
    }
    engine
        .tiers
        .entry(bucket.to_string())
        .or_default()
        .set(Some(Arc::new(compiler.build())))
        .unwrap();
    engine.populated_tiers.insert(bucket.to_string());
    engine.rule_counts.0 += sources.len();
}

#[test]
fn late_pattern_candidates_are_evaluated_before_evidence_is_capped() {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(
            r#"rule late_candidate {
            strings: $a = "marker"
            condition: #a == 32 and @a[25] == 144
        }"#,
        )
        .unwrap();
    let rules = Arc::new(compiler.build());
    let matched = YaraEngine::run_scanner(&rules, b"marker".repeat(32).as_slice()).unwrap();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].patterns[0].1.len(), MAX_PATTERN_MATCHES);
    for count in [8, 24, 31, 33] {
        assert!(
            YaraEngine::run_scanner(&rules, b"marker".repeat(count).as_slice())
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn yara_scan_preserves_both_channels_with_file_type_filters() {
    let mut engine = YaraEngine::new_for_test();
    for bucket in ["class", "pe", FALLBACK_BUCKET] {
        load_test_bucket(
            &mut engine,
            bucket,
            &[
                (
                    &format!("test.{bucket}"),
                    r#"rule regular_marker { strings: $a = "REG" condition: $a }"#,
                ),
                (
                    &format!("inline.test/{bucket}::marker"),
                    r#"rule inline_marker { strings: $a = "INLINE" condition: $a }"#,
                ),
            ],
        );
    }
    let cases: &[(Option<&[&str]>, &[&str])] = &[
        (Some(&["class"]), &["class", FALLBACK_BUCKET]),
        (Some(&["pe"]), &["pe", FALLBACK_BUCKET]),
        (Some(&[]), &[FALLBACK_BUCKET]),
        (None, &["class", "pe", FALLBACK_BUCKET]),
    ];
    for &(filter, buckets) in cases {
        for (data, regular, inline, offset) in [
            (b"xx REG INLINE".as_slice(), true, true, 7),
            (b"xx REG".as_slice(), true, false, 0),
            (b"xx INLINE".as_slice(), false, true, 3),
            (b"xx absent".as_slice(), false, false, 0),
        ] {
            let scan = engine.scan_bytes(data, filter).unwrap();
            let mut actual: Vec<_> = scan.matches.iter().map(|m| m.namespace.clone()).collect();
            let mut expected: Vec<_> = buckets
                .iter()
                .filter(|_| regular)
                .map(|bucket| format!("test.{bucket}"))
                .collect();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected, "filter={filter:?}, data={data:?}");
            let mut actual: Vec<_> = scan.inline_traits.keys().cloned().collect();
            let mut expected: Vec<_> = buckets
                .iter()
                .filter(|_| inline)
                .map(|bucket| format!("inline.test/{bucket}::marker"))
                .collect();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected, "filter={filter:?}, data={data:?}");
            for evidence in scan.inline_traits.values() {
                let location = format!("offset:0x{offset:x}");
                assert!(evidence.iter().any(|e| {
                    e.value == "INLINE" && e.location.as_deref() == Some(location.as_str())
                }));
            }
        }
    }
}

/// A class-format fixture, not executable code: one extra UTF-8 constant
/// supplies the marker, and there are no methods or initializers.
fn marker_class(marker: &str) -> Vec<u8> {
    let mut bytes = b"\xca\xfe\xba\xbe\0\0\0\x34\0\x06".to_vec();
    for name in ["Control", "java/lang/Object"] {
        bytes.push(1);
        bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&[7, 0, if name == "Control" { 1 } else { 3 }]);
    }
    bytes.push(1);
    bytes.extend_from_slice(&(marker.len() as u16).to_be_bytes());
    bytes.extend_from_slice(marker.as_bytes());
    bytes.extend_from_slice(b"\0\x21\0\x02\0\x04\0\0\0\0\0\0\0\0");
    bytes
}

#[test]
fn yara_scan_jar_retains_inline_alerts_outside_sample_in_both_extraction_modes() {
    use crate::analyzers::Analyzer;
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("traits.yaml"),
        r#"
defaults:
  for: [class]
traits:
  - id: test/jar::alert
    desc: Inline alert marker
    crit: suspicious
    if: {type: yara, source: 'rule marker { strings: $a = "ALERT_MARKER" condition: $a }'}
  - id: test/jar::quiet
    desc: Informational marker
    crit: notable
    if: {type: yara, source: 'rule marker { strings: $a = "QUIET_MARKER" condition: $a }'}
"#,
    )
    .unwrap();
    let mapper = CapabilityMapper::from_directory_with_options(
        dir.path(),
        crate::LoadOptions {
            min_hostile_precision: 0.0,
            min_suspicious_precision: 0.0,
            ..crate::LoadOptions::default()
        },
    )
    .unwrap();
    let mut yara = YaraEngine::new_for_test();
    load_test_bucket(
        &mut yara,
        FileType::JavaClass.label(),
        &[
            (
                "inline.test/jar::alert",
                r#"rule marker { strings: $a = "ALERT_MARKER" condition: $a }"#,
            ),
            (
                "inline.test/jar::quiet",
                r#"rule marker { strings: $a = "QUIET_MARKER" condition: $a }"#,
            ),
            (
                "test.jar.regular",
                r#"rule marker { strings: $a = "REGULAR_MARKER" condition: $a }"#,
            ),
        ],
    );
    let engine = crate::Engine::new(Arc::new(mapper), Some(Arc::new(yara)), Default::default());
    let archive = dir.path().join("selection.jar");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for index in 0..25 {
        zip.start_file(format!("padding/Decoy{index}.class"), options)
            .unwrap();
        zip.write_all(&marker_class(
            "java/lang/ProcessBuilder java/net/HttpURLConnection",
        ))
        .unwrap();
    }
    for (name, marker) in [
        ("hidden/Alert.class", "ALERT_MARKER"),
        ("hidden/Quiet.class", "QUIET_MARKER"),
        ("hidden/Regular.class", "REGULAR_MARKER"),
    ] {
        zip.start_file(name, options).unwrap();
        zip.write_all(&marker_class(marker)).unwrap();
    }
    zip.finish().unwrap();
    // The memory budget, not a process-global override, selects the path.
    for memory_limit in [100 * 1024 * 1024, 0] {
        let report = crate::analyzers::archive::ArchiveAnalyzer::new()
            .with_engine(engine.clone())
            .with_yara_arc(engine.yara().unwrap().clone())
            .with_max_memory_file_size(memory_limit)
            .analyze(&archive)
            .unwrap();
        let alert = report
            .files
            .iter()
            .find(|f| f.path.ends_with("hidden/Alert.class"))
            .expect("inline alert must survive outside the top-20 sample");
        assert!(alert.findings.iter().any(|f| f.id == "test/jar::alert"));
        assert!(report.findings.iter().any(|f| f.id == "test/jar::alert"));
        assert!(
            report
                .files
                .iter()
                .any(|f| f.path.ends_with("hidden/Regular.class"))
        );
        assert!(
            !report
                .files
                .iter()
                .any(|f| f.path.ends_with("hidden/Quiet.class"))
        );
    }
}

#[test]
fn upx_child_preserves_inline_yara_and_dependent_composites() {
    if !crate::upx::UPXDecompressor::is_available() {
        eprintln!("UPX unavailable; packed child regression skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let source = "rule pe_marker { strings: $a = \"UPXInlineYaraFixture\" condition: uint16(0) == 0x5a4d and $a }";
    std::fs::write(
        dir.path().join("traits.yaml"),
        format!(
            r#"
defaults:
  platforms: [windows]
  for: [pe]
traits:
  - id: test/pe::marker
    desc: Packed child inline marker
    crit: notable
    if:
      type: yara
      source: '{source}'
composite_rules:
  - id: test/pe::combined
    desc: Packed child marker composite
    crit: suspicious
    all:
      - id: test/pe::marker
"#
        ),
    )
    .unwrap();
    let mapper = CapabilityMapper::from_directory_with_options(
        dir.path(),
        crate::LoadOptions {
            min_hostile_precision: 0.0,
            min_suspicious_precision: 0.0,
            ..crate::LoadOptions::default()
        },
    )
    .unwrap();
    let mut compiler = yara_x::Compiler::new();
    let ns = "inline.test/pe::marker";
    compiler.new_namespace(ns);
    compiler.add_source(source.as_bytes()).unwrap();
    compiler.new_namespace("test.upx.regular");
    compiler.add_source(source.as_bytes()).unwrap();
    let mut yara = YaraEngine::new_for_test();
    yara.tiers
        .entry(FALLBACK_BUCKET.to_string())
        .or_default()
        .set(Some(Arc::new(compiler.build())))
        .unwrap();
    yara.populated_tiers.insert(FALLBACK_BUCKET.to_string());
    yara.compiled_inline_namespaces.push(ns.to_string());
    yara.rule_counts = (2, 0);
    let yara = Arc::new(yara);
    let engine = crate::Engine::new(Arc::new(mapper), Some(yara.clone()), Default::default());
    let analyzer = crate::analyzers::pe::PEAnalyzer::new()
        .with_engine(engine)
        .with_yara_arc(yara);
    let fixture =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test.exe"))
            .unwrap();
    for (name, marker, expected) in [
        ("positive.exe", b"UPXInlineYaraFixture".as_slice(), true),
        ("negative.exe", b"UPXAbsentYaraFixture".as_slice(), false),
    ] {
        let path = dir.path().join(name);
        let mut bytes = fixture.clone();
        bytes.extend_from_slice(marker);
        std::fs::write(&path, bytes).unwrap();
        let output = std::process::Command::new("upx")
            .args(["--overlay=copy", "--force", "-q"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let packed = std::fs::read(&path).unwrap();
        assert!(crate::upx::UPXDecompressor::is_upx_packed(&packed));
        let report = analyzer.analyze_structural(&path, &packed, None);
        let child = report
            .files
            .iter()
            .find(|f| {
                f.encoding
                    .as_ref()
                    .is_some_and(|e| e.iter().any(|s| s == "upx"))
            })
            .expect("UPX child must be analyzed");
        for id in ["test/pe::marker", "test/pe::combined"] {
            assert_eq!(
                child.findings.iter().any(|f| f.id == id),
                expected,
                "{name}: {id}: {:?}",
                child.findings
            );
        }
        assert_eq!(
            child
                .yara_matches
                .iter()
                .any(|m| m.namespace == "test.upx.regular"),
            expected
        );
    }
}

fn native_inline_test_engine(dir: &Path) -> crate::Engine {
    let source = "rule native_marker { strings: $a = \"NativeInlineYaraFixture\" condition: $a }";
    std::fs::write(
        dir.join("traits.yaml"),
        format!(
            r#"
defaults:
  platforms: [windows, linux, macos]
  for: [pe, elf, macho, applescript]
traits:
  - id: test/native::marker
    desc: Native inline marker
    crit: notable
    if:
      type: yara
      source: '{source}'
composite_rules:
  - id: test/native::combined
    desc: Native inline marker composite
    crit: suspicious
    all:
      - id: test/native::marker
"#
        ),
    )
    .unwrap();
    let mapper = CapabilityMapper::from_directory_with_options(
        dir,
        crate::LoadOptions {
            min_hostile_precision: 0.0,
            min_suspicious_precision: 0.0,
            ..crate::LoadOptions::default()
        },
    )
    .unwrap();
    let mut compiler = yara_x::Compiler::new();
    let ns = "inline.test/native::marker";
    compiler.new_namespace(ns);
    compiler.add_source(source.as_bytes()).unwrap();
    compiler.new_namespace("test.native.regular");
    compiler.add_source(source.as_bytes()).unwrap();
    let mut yara = YaraEngine::new_for_test();
    yara.tiers
        .entry(FALLBACK_BUCKET.to_string())
        .or_default()
        .set(Some(Arc::new(compiler.build())))
        .unwrap();
    yara.populated_tiers.insert(FALLBACK_BUCKET.to_string());
    yara.compiled_inline_namespaces.push(ns.to_string());
    yara.rule_counts = (2, 0);
    crate::Engine::new(
        Arc::new(mapper),
        Some(Arc::new(yara)),
        crate::engine::Settings::default(),
    )
}

fn native_fixture_cases() -> Vec<(String, crate::FileType, Vec<u8>, bool)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cases = Vec::new();
    for (name, ft, fixture) in [
        ("pe.exe", crate::FileType::Pe, "tests/fixtures/test.exe"),
        ("elf.so", crate::FileType::Elf, "tests/fixtures/test.elf"),
        (
            "thin.macho",
            crate::FileType::MachO,
            "tests/fixtures/test.macho",
        ),
        (
            "fat.macho",
            crate::FileType::MachO,
            "testdata/xor/gapi-update.macho",
        ),
        (
            "script.scpt",
            crate::FileType::AppleScript,
            "tests/fixtures/scpt-base64.scpt",
        ),
    ] {
        let fixture = if fixture.starts_with("testdata/xor/") {
            crate::test_samples::read(fixture)
        } else {
            std::fs::read(root.join(fixture)).unwrap()
        };
        for (label, marker, expected) in [
            ("positive", b"NativeInlineYaraFixture".as_slice(), true),
            ("negative", b"NativeAbsentYaraFixture".as_slice(), false),
        ] {
            let mut bytes = fixture.clone();
            bytes.extend_from_slice(marker);
            cases.push((format!("{label}-{name}"), ft, bytes, expected));
        }
    }
    cases
}

fn assert_native_marker(findings: &[crate::types::Finding], expected: bool, name: &str) {
    for id in ["test/native::marker", "test/native::combined"] {
        assert_eq!(
            findings.iter().any(|f| f.id == id),
            expected,
            "{name}: {id}: {findings:?}"
        );
    }
}

#[test]
fn native_children_preserve_inline_yara_and_composites_across_formats() {
    use crate::analyzers::AnalysisInput;
    let dir = tempfile::tempdir().unwrap();
    let engine = native_inline_test_engine(dir.path());
    for (name, ft, bytes, expected) in native_fixture_cases() {
        let backing = dir.path().join(&name);
        std::fs::write(&backing, &bytes).unwrap();
        let logical = Path::new("archive-member").join(&name);
        let input = AnalysisInput::new(&logical, &bytes, ft)
            .with_backing_path(&backing)
            .at_depth(1);
        let analyzer = crate::analyzers::analyzer_for_file_type_arc(&ft, &engine).unwrap();
        let report = analyzer.analyze_input(&input).unwrap();
        assert_eq!(report.target.path, logical.display().to_string());
        assert_native_marker(&report.findings, expected, &name);
        assert_eq!(
            report
                .yara_matches
                .iter()
                .any(|m| m.namespace == "test.native.regular"),
            expected
        );
    }
}

#[test]
fn archives_preserve_native_inline_yara_and_composites() {
    use crate::analyzers::Analyzer;
    let dir = tempfile::tempdir().unwrap();
    let engine = native_inline_test_engine(dir.path());
    let cases = native_fixture_cases();
    let archive = dir.path().join("native-fixtures.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
    for (name, _, bytes, _) in &cases {
        zip.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut zip, bytes).unwrap();
    }
    zip.finish().unwrap();
    let report = crate::analyzers::archive::ArchiveAnalyzer::new()
        .with_engine(engine.clone())
        .with_yara_arc(engine.yara().unwrap().clone())
        .analyze(&archive)
        .unwrap();
    for (name, _, _, expected) in cases {
        let child = report
            .files
            .iter()
            .find(|f| f.path.ends_with(&name))
            .expect("archive child");
        assert_native_marker(&child.findings, expected, &name);
        assert_eq!(
            child.findings.iter().any(|f| f.id == "test/native/regular"),
            expected
        );
    }
}

#[test]
fn archive_container_evaluates_inline_yara_on_original_bytes() {
    use crate::analyzers::Analyzer;
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let source = "rule archive_marker { strings: $a = \"ArchiveInlineMarker123\" condition: $a }";
    std::fs::write(
        dir.path().join("traits.yaml"),
        format!(
            r#"
defaults:
  platforms: [windows, linux, macos]
  for: [tar]
traits:
  - id: test/archive::marker
    desc: Archive inline marker
    crit: notable
    if:
      type: yara
      source: '{source}'
composite_rules:
  - id: test/archive::combined
    desc: Archive inline marker composite
    crit: suspicious
    all:
      - id: test/archive::marker
"#
        ),
    )
    .unwrap();
    let mapper = CapabilityMapper::from_directory_with_options(
        dir.path(),
        crate::LoadOptions {
            min_hostile_precision: 0.0,
            min_suspicious_precision: 0.0,
            ..crate::LoadOptions::default()
        },
    )
    .unwrap();
    let mut compiler = yara_x::Compiler::new();
    let ns = "inline.test/archive::marker";
    compiler.new_namespace(ns);
    compiler.add_source(source.as_bytes()).unwrap();
    let mut yara = YaraEngine::new_for_test();
    yara.tiers
        .entry(FALLBACK_BUCKET.to_string())
        .or_default()
        .set(Some(Arc::new(compiler.build())))
        .unwrap();
    yara.populated_tiers.insert(FALLBACK_BUCKET.to_string());
    yara.compiled_inline_namespaces.push(ns.to_string());
    yara.rule_counts = (1, 0);
    let yara = Arc::new(yara);
    let engine = crate::Engine::new(Arc::new(mapper), Some(yara.clone()), Default::default());

    for (name, body, expected) in [
        ("positive.tar", b"ArchiveInlineMarker123".as_slice(), true),
        ("negative.tar", b"ArchiveAbsentMarker123".as_slice(), false),
    ] {
        let path = dir.path().join(name);
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "item.txt", body).unwrap();
        let data = tar.into_inner().unwrap();
        std::fs::write(&path, &data).unwrap();
        for enabled in [false, true] {
            let mut analyzer =
                crate::analyzers::archive::ArchiveAnalyzer::new().with_engine(engine.clone());
            if enabled {
                analyzer = analyzer.with_yara_arc(yara.clone());
            }
            let report = analyzer.analyze(&path).unwrap();
            for id in ["test/archive::marker", "test/archive::combined"] {
                assert_eq!(
                    report.findings.iter().any(|f| f.id.as_ref() == id),
                    expected && enabled,
                    "{name}, enabled={enabled}, {id}"
                );
            }
        }
        let zip_path = dir.path().join(format!("{name}.zip"));
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path).unwrap());
        zip.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&data).unwrap();
        zip.finish().unwrap();
        let report = crate::analyzers::archive::ArchiveAnalyzer::new()
            .with_engine(engine.clone())
            .with_yara_arc(yara.clone())
            .analyze(&zip_path)
            .unwrap();
        let nested = report
            .files
            .iter()
            .find(|f| f.path.ends_with(name))
            .expect("nested tar");
        assert_eq!(
            nested
                .findings
                .iter()
                .any(|f| f.id.as_ref() == "test/archive::marker"),
            expected
        );
    }
}

#[test]
fn upx_elf_children_preserve_inline_yara_and_composites() {
    use crate::analyzers::{AnalysisInput, FileType};
    if !crate::upx::UPXDecompressor::is_available() {
        eprintln!("UPX unavailable; ELF regression skipped");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let engine = native_inline_test_engine(dir.path());
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lang_strings/go_linux_amd64");
    let original = std::fs::read(&fixture).unwrap();
    for (name, marker, expected) in [
        ("positive.elf", b"NativeInlineYaraFixture".as_slice(), true),
        ("negative.elf", b"NativeAbsentYaraFixture".as_slice(), false),
    ] {
        let backing = dir.path().join(name);
        let mut bytes = original.clone();
        bytes.extend_from_slice(marker);
        std::fs::write(&backing, bytes).unwrap();
        std::fs::set_permissions(&backing, std::fs::metadata(&fixture).unwrap().permissions())
            .unwrap();
        let packed = std::process::Command::new("upx")
            .args(["--overlay=copy", "--force", "-q"])
            .arg(&backing)
            .output()
            .unwrap();
        assert!(
            packed.status.success(),
            "{}",
            String::from_utf8_lossy(&packed.stderr)
        );
        let bytes = std::fs::read(&backing).unwrap();
        let logical = Path::new("archive-member").join(name);
        let input = AnalysisInput::new(&logical, &bytes, FileType::Elf)
            .with_backing_path(&backing)
            .at_depth(1);
        let report = crate::analyzers::analyzer_for_file_type_arc(&FileType::Elf, &engine)
            .unwrap()
            .analyze_input(&input)
            .unwrap();
        assert_eq!(report.target.path, logical.display().to_string());
        let child = report
            .files
            .iter()
            .find(|f| {
                f.encoding
                    .as_ref()
                    .is_some_and(|e| e.iter().any(|s| s == "upx"))
            })
            .expect("ELF UPX child");
        assert_native_marker(&child.findings, expected, name);
        assert_eq!(
            child
                .yara_matches
                .iter()
                .any(|m| m.namespace == "test.native.regular"),
            expected
        );
    }
}

#[test]
fn engine_yara_entry_honors_prefetch_disabled_rules_and_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let engine = native_inline_test_engine(dir.path());
    let bytes =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test.exe"))
            .unwrap();
    let mut bytes = bytes;
    bytes.extend_from_slice(b"NativeInlineYaraFixture");
    let empty = std::collections::HashMap::new();
    let cancelled = std::sync::atomic::AtomicBool::new(true);
    for (name, selected_engine, prefetched, cancellation, expected) in [
        ("fresh.exe", engine.clone(), None, None, true),
        (
            "prefetched-empty.exe",
            engine.clone(),
            Some(&empty),
            None,
            false,
        ),
        (
            "disabled.exe",
            crate::Engine::from_rules(engine.rules().clone()),
            None,
            None,
            false,
        ),
        (
            "cancelled.exe",
            engine.clone(),
            None,
            Some(&cancelled),
            false,
        ),
        ("rule.yar", engine.clone(), None, None, false),
    ] {
        let path = dir.path().join(name);
        let ctx = crate::analysis_context::AnalysisContext::open_with(
            selected_engine.filefacts_options(),
            &path,
            &bytes,
        );
        let mut report = crate::types::AnalysisReport::new(crate::types::TargetInfo {
            path: path.display().to_string(),
            file_type: "pe".to_string(),
            size_bytes: bytes.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        selected_engine.evaluate_and_merge_findings_with_precomputed(
            &mut report,
            &bytes,
            crate::capabilities::AnalysisBorrow::with_filefacts(None, Some(&ctx)),
            prefetched,
            None,
            None,
            cancellation,
        );
        assert_native_marker(&report.findings, expected, name);
        assert_eq!(
            report
                .yara_matches
                .iter()
                .any(|m| m.namespace == "test.native.regular"),
            expected
        );
    }
}

#[test]
fn opaque_data_evaluates_inline_yara_and_composites_on_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = dir.path().join("traits.yaml");
    let source = "rule binary_marker { strings: $a = { FF 00 FE 41 } condition: $a at 12 }";
    std::fs::write(
        &yaml,
        format!(
            r#"
defaults:
  platforms: [windows]
traits:
  - id: test/data::marker
    desc: Binary marker
    crit: notable
    for: [data]
    if:
      type: yara
      source: '{source}'
composite_rules:
  - id: test/data::combined
    desc: Binary marker composite
    crit: suspicious
    for: [data]
    all:
      - id: test/data::marker
"#
        ),
    )
    .unwrap();
    let mapper = CapabilityMapper::from_directory_with_options(
        dir.path(),
        crate::LoadOptions {
            min_hostile_precision: 0.0,
            min_suspicious_precision: 0.0,
            ..crate::LoadOptions::default()
        },
    )
    .unwrap();
    let ns = "inline.test/data::marker";
    let mut compiler = yara_x::Compiler::new();
    compiler.new_namespace(ns);
    compiler.add_source(source.as_bytes()).unwrap();
    let mut yara = YaraEngine::new_for_test();
    let cell = yara.tiers.entry(FALLBACK_BUCKET.to_string()).or_default();
    cell.set(Some(Arc::new(compiler.build()))).unwrap();
    yara.populated_tiers.insert(FALLBACK_BUCKET.to_string());
    yara.compiled_inline_namespaces.push(ns.to_string());
    yara.rule_counts = (1, 0);
    assert!(mapper.find_trait("test/data::marker").is_some());
    assert!(format!("{:?}", mapper.find_trait("test/data::marker").unwrap().r#if).contains(ns));
    let engine = crate::Engine::new(Arc::new(mapper), Some(Arc::new(yara)), Default::default());
    let analyzer =
        crate::analyzers::generic::GenericAnalyzer::new(FileType::Data).with_engine(engine.clone());
    use crate::analyzers::Analyzer;
    for (tail, expected) in [(0x41, true), (0x42, false)] {
        let mut bytes = b"RIFF\x08\0\0\0ACON\xff\0\xfe".to_vec();
        bytes.push(tail);
        let inline = engine
            .yara()
            .unwrap()
            .scan_bytes(&bytes, None)
            .unwrap()
            .inline_traits;
        assert_eq!(
            inline.get(ns).is_some_and(|e| !e.is_empty()),
            expected,
            "{inline:?}"
        );
        let input =
            crate::analyzers::AnalysisInput::new(Path::new("payload.bin"), &bytes, FileType::Data);
        let report = analyzer.analyze_input(&input).unwrap();
        for id in ["test/data::marker", "test/data::combined"] {
            assert_eq!(
                report.findings.iter().any(|f| f.id == id),
                expected,
                "{id}: {:?}",
                report
            );
        }
        assert!(
            report
                .metadata
                .tools_used
                .iter()
                .any(|tool| tool == "yara-x")
        );
    }
}

#[test]
fn legacy_source_evaluates_inline_yara_and_composites_on_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = dir.path().join("traits.yaml");
    let source = "rule binary_marker { strings: $a = { FF 00 FE 41 } condition: $a at 12 }";
    std::fs::write(
        &yaml,
        format!(
            r#"
defaults:
  platforms: [windows]
traits:
  - id: test/data::marker
    desc: Binary marker
    crit: notable
    for: [batch, php]
    if:
      type: yara
      source: '{source}'
  - id: test/source::php-ascii-call
    desc: PHP ASCII call after legacy bytes
    crit: notable
    for: [php]
    if:
      type: tree-sitter
      language: php
      query: '(function_call_expression function: (name) @fn (#eq? @fn "strlen"))'
composite_rules:
  - id: test/data::combined
    desc: Binary marker composite
    crit: suspicious
    for: [batch, php]
    all:
      - id: test/data::marker
"#
        ),
    )
    .unwrap();
    let mapper = CapabilityMapper::from_directory_with_options(
        dir.path(),
        crate::LoadOptions {
            min_hostile_precision: 0.0,
            min_suspicious_precision: 0.0,
            ..crate::LoadOptions::default()
        },
    )
    .unwrap();
    let ns = "inline.test/data::marker";
    let mut compiler = yara_x::Compiler::new();
    compiler.new_namespace(ns);
    compiler.add_source(source.as_bytes()).unwrap();
    let mut yara = YaraEngine::new_for_test();
    let cell = yara.tiers.entry(FALLBACK_BUCKET.to_string()).or_default();
    cell.set(Some(Arc::new(compiler.build()))).unwrap();
    yara.populated_tiers.insert(FALLBACK_BUCKET.to_string());
    yara.compiled_inline_namespaces.push(ns.to_string());
    yara.rule_counts = (1, 0);
    assert!(mapper.find_trait("test/data::marker").is_some());
    assert!(format!("{:?}", mapper.find_trait("test/data::marker").unwrap().r#if).contains(ns));
    let engine = crate::Engine::new(Arc::new(mapper), Some(Arc::new(yara)), Default::default());
    use crate::analyzers::Analyzer;
    for (file_type, prefix) in [
        (FileType::Batch, &b"@REM        "[..]),
        (FileType::Php, &b"<?php //    "[..]),
    ] {
        assert_eq!(prefix.len(), 12);
        let analyzer: Box<dyn Analyzer> = if file_type == FileType::Batch {
            Box::new(
                crate::analyzers::generic::GenericAnalyzer::new(file_type)
                    .with_engine(engine.clone()),
            )
        } else {
            Box::new(
                crate::analyzers::unified::UnifiedSourceAnalyzer::for_file_type(&file_type)
                    .unwrap()
                    .with_engine(engine.clone()),
            )
        };
        for (tail, expected) in [(0x41, true), (0x42, false)] {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(b"\xff\0\xfe");
            bytes.push(tail);
            bytes.extend_from_slice(if file_type == FileType::Php {
                b"\r\nstrlen('OK');\r\n".as_slice()
            } else {
                b"\r\n@echo ok\r\n".as_slice()
            });
            let inline = engine
                .yara()
                .unwrap()
                .scan_bytes(&bytes, None)
                .unwrap()
                .inline_traits;
            assert_eq!(
                inline.get(ns).is_some_and(|e| !e.is_empty()),
                expected,
                "{inline:?}"
            );
            let input =
                crate::analyzers::AnalysisInput::new(Path::new("payload.bat"), &bytes, file_type);
            let report = analyzer.analyze_input(&input).unwrap();
            assert_eq!(report.target.size_bytes, bytes.len() as u64);
            assert_eq!(
                report.target.sha256,
                crate::analyzers::utils::calculate_sha256(&bytes)
            );
            if file_type == FileType::Php {
                let call = report
                    .findings
                    .iter()
                    .find(|f| f.id == "test/source::php-ascii-call")
                    .expect("ASCII AST call remains visible after non-UTF8 bytes");
                assert!(
                    call.evidence.iter().any(|e| e.offsets.contains(&18)),
                    "{:?}",
                    call.evidence
                );
            }
            for id in ["test/data::marker", "test/data::combined"] {
                assert_eq!(
                    report.findings.iter().any(|f| f.id == id),
                    expected,
                    "{id}: {:?}",
                    report
                );
            }
            assert!(
                report
                    .metadata
                    .tools_used
                    .iter()
                    .any(|tool| tool == "yara-x")
            );
        }
        // A documentation fixture containing YARA syntax must not self-detect.
        let bytes = b"@REM        \xff\0\xfeA\r\n";
        let input =
            crate::analyzers::AnalysisInput::new(Path::new("document.yar"), bytes, file_type);
        let report = analyzer.analyze_input(&input).unwrap();
        assert!(!report.findings.iter().any(|f| f.id == "test/data::marker"));
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id == "test/data::combined")
        );
    }
}

#[test]
fn rule_sources_yara_snapshot_matches_discovery_and_freezes_edits() {
    let root = tempfile::tempdir().unwrap();
    let third_party = root.path().join("third-party");
    fs::create_dir_all(third_party.join("vendor")).unwrap();
    fs::write(
        root.path().join("builtin.yar"),
        "rule builtin { condition: true }",
    )
    .unwrap();
    fs::write(
        third_party.join("vendor/rule.yar"),
        "rule vendor { condition: true }",
    )
    .unwrap();
    fs::write(root.path().join("inline.yaml"),
        "traits:\n  - id: visible-inline\n    for: [text]\n    if:\n      type: yara\n      source: 'rule visible { condition: true }'\n").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("third-party/vendor", root.path().join("linked-dir")).unwrap();
        std::os::unix::fs::symlink("builtin.yar", root.path().join("linked-file.yar")).unwrap();
    }
    let sources = crate::rule_sources::RuleSources::fresh(root.path()).unwrap();
    let collect = |snapshot| {
        let (sources, contexts, mut namespaces, builtin, third_party_count) =
            YaraEngine::collect_all_sources_with_sources(root.path(), &third_party, true, snapshot);
        let mut sources: Vec<_> = sources
            .into_iter()
            .map(|(tier, mut rules)| {
                rules.sort();
                (tier, rules)
            })
            .collect();
        sources.sort();
        let mut ids: Vec<_> = contexts.into_keys().collect();
        ids.sort();
        namespaces.sort();
        (sources, ids, namespaces, builtin, third_party_count)
    };
    let before = collect(Some(&sources));
    assert_eq!(before, collect(None));
    fs::write(
        root.path().join("builtin.yar"),
        "rule edited { condition: false }",
    )
    .unwrap();
    fs::remove_file(root.path().join("inline.yaml")).unwrap();
    fs::write(
        root.path().join("added.yar"),
        "rule added { condition: true }",
    )
    .unwrap();
    fs::remove_dir_all(&third_party).unwrap();
    assert_eq!(
        before,
        collect(Some(&sources)),
        "all loaders must use the frozen source set"
    );
    assert_ne!(before, collect(None));
}

#[test]
fn rule_discovery_excludes_build_fixtures_and_separates_third_party() {
    let cwd = std::env::current_dir().unwrap();
    let root = tempfile::Builder::new()
        .prefix(".yara-source-root-")
        .tempdir_in(&cwd)
        .unwrap();
    let builtin = "rule builtin { condition: true }";
    fs::write(root.path().join("builtin.yar"), builtin).unwrap();
    let inline = "traits:\n  - id: visible-inline\n    for: [text]\n    if:\n      type: yara\n      source: 'rule visible { condition: true }'\n";
    fs::write(root.path().join("inline.yaml"), inline).unwrap();
    for dir in [".local-build/dependency/tests", "_testdata"] {
        let path = root.path().join(dir);
        fs::create_dir_all(&path).unwrap();
        fs::write(
            path.join("included.yar"),
            "rule included { condition: true }",
        )
        .unwrap();
        fs::write(
            path.join("fixture.yaml"),
            inline.replace("visible-inline", "fixture-inline"),
        )
        .unwrap();
    }
    let third_party = root.path().join("third-party/vendor");
    fs::create_dir_all(&third_party).unwrap();
    fs::write(
        third_party.join("vendor.yar"),
        "rule vendor { condition: true }",
    )
    .unwrap();

    // A relative traits override must exclude third-party sources just as
    // an absolute one does; comparing it with an absolute cache path fails.
    for path in [root.path(), root.path().strip_prefix(&cwd).unwrap()] {
        let (_, contexts, count) = YaraEngine::collect_builtin_sources_tiered(path);
        assert_eq!(count, 1);
        assert_eq!(contexts.len(), 1);
        let (_, ids) = YaraEngine::collect_inline_trait_sources_tiered(path);
        assert_eq!(ids, ["inline.visible-inline"]);
    }
}

/// A file the prefilter skips must hold no scalar equal to `yara`; every
/// way YAML can build that scalar must keep the file.
#[test]
fn may_spell_yara_keeps_every_spelling() {
    let spelled = [
        "traits:\n  - id: t\n    if:\n      type: yara\n",
        "traits:\n  - id: t\n    if: {type: 'yara'}\n",
        "t: \"\\x79ara\"\n",
        "t: \"\\u0079ara\"\n",
        "t: \"\\U00000079ara\"\n",
        "t: \"ya\\\n  ra\"\n",
        "t: \"ya\\\r\n  ra\"\n",
    ];
    for doc in spelled {
        let value: serde_json::Value = crate::yaml::from_str(doc).unwrap();
        let has = |v: &serde_json::Value| serde_saphyr::to_string(v).unwrap().contains("yara");
        assert!(has(&value), "fixture must really spell yara: {doc:?}");
        assert!(may_spell_yara(doc), "prefilter dropped {doc:?}");
    }
    for doc in [
        "traits:\n  - id: t\n    if:\n      type: text\n      regex: '\\d+'\n",
        "t: \"ya\n  ra\"\n",
        "t: ya ra\n",
    ] {
        assert!(!may_spell_yara(doc), "prefilter kept {doc:?}");
        let value: serde_json::Value = crate::yaml::from_str(doc).unwrap();
        assert!(
            !serde_saphyr::to_string(&value).unwrap().contains("yara"),
            "{doc:?}"
        );
    }
}

#[test]
fn test_simple_rule() {
    let rule = r#"
rule test_rule {
    meta:
        description = "Test rule"
        risk = "notable"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"#;

    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();

    let test_data = b"This contains TESTPATTERN in the data";
    let matches = engine.scan_bytes(test_data, None).unwrap().matches;

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule, "test_rule");
    assert!(!matches[0].matched_strings.is_empty());
}

/// Whole vendor rule sets label their rules with `threat_name` and no
/// `description` — Elastic's ships 3084 of the former and fewer than half
/// as many of the latter. Third-party rules are graded hostile by default,
/// so those findings reached the analyst as a red verdict over a blank
/// line. Fall back to whatever label the rule does carry.
#[test]
fn test_description_falls_back_to_threat_name() {
    let rule = r#"
rule threat_named_rule {
    meta:
        threat_name = "Windows.Generic.Threat"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"#;
    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();
    let matches = engine
        .scan_bytes(b"This contains TESTPATTERN", None)
        .unwrap()
        .matches;
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].desc, "Detects Windows.Generic.Threat");
}

/// With no label at all, name the rule: still more than an empty string.
#[test]
fn test_description_falls_back_to_rule_name() {
    let rule = r#"
rule unlabelled_rule {
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"#;
    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();
    let matches = engine
        .scan_bytes(b"This contains TESTPATTERN", None)
        .unwrap()
        .matches;
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].desc, "YARA rule unlabelled_rule");
}

/// An explicit description always wins over the fallbacks.
#[test]
fn test_explicit_description_wins_over_threat_name() {
    let rule = r#"
rule described_rule {
    meta:
        description = "Detects a specific loader stage"
        threat_name = "Windows.Generic.Threat"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"#;
    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();
    let matches = engine
        .scan_bytes(b"This contains TESTPATTERN", None)
        .unwrap()
        .matches;
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].desc, "Detects a specific loader stage");
}

#[test]
fn test_no_match() {
    let rule = r#"
rule test_rule {
    strings:
        $test = "NOTFOUND"
    condition:
        $test
}
"#;

    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();

    let test_data = b"This does not contain the pattern";
    let matches = engine.scan_bytes(test_data, None).unwrap().matches;

    assert_eq!(matches.len(), 0);
}

#[test]
fn test_new() {
    let engine = YaraEngine::new_for_test();
    assert!(!engine.is_loaded());
}

#[test]
fn test_default() {
    let engine = YaraEngine::new_for_test();
    assert!(!engine.is_loaded());
}

#[test]
fn test_is_loaded() {
    let mut engine = YaraEngine::new_for_test();
    assert!(!engine.is_loaded());

    engine
        .load_rule_source(r#"rule test { strings: $a = "test" condition: $a }"#)
        .unwrap();

    assert!(engine.is_loaded());
}

#[test]
fn test_scan_without_rules() {
    let engine = YaraEngine::new_for_test();
    let result = engine.scan_bytes(b"test data", None);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("No YARA rules loaded")
    );
}

#[test]
fn test_risk_metadata_is_parsed_not_string_matched() {
    let mut engine = YaraEngine::new_for_test();
    let source: String = [("upper", "Hostile"), ("synonym", "malicious"), ("typo", "hostlie")]
        .iter()
        .map(|(name, risk)| {
            format!(
                "rule risk_{name} {{ meta: risk = \"{risk}\" strings: $a = \"RISK-{name}\" condition: $a }}\n"
            )
        })
        .collect();
    engine.load_rule_source(&source).unwrap();
    let crit_of = |name: &str| {
        let data = format!("xx RISK-{name} xx");
        engine.scan_bytes(data.as_bytes(), None).unwrap().matches[0].crit
    };
    assert_eq!(crit_of("upper"), crate::types::Criticality::Hostile);
    assert_eq!(crit_of("synonym"), crate::types::Criticality::Hostile);
    // A typo keeps the default and is logged, rather than being mistaken
    // for a deliberate baseline grade.
    assert_eq!(crit_of("typo"), crate::types::Criticality::Baseline);
}

#[test]
fn test_rule_with_metadata() {
    let rule = r#"
rule test_rule {
    meta:
        description = "Test description"
        risk = "hostile"
        capability = "true"
        mbc = "B0001"
        attack = "T1059"
    strings:
        $test = "PATTERN"
    condition:
        $test
}
"#;

    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();

    let test_data = b"This contains PATTERN in the data";
    let matches = engine.scan_bytes(test_data, None).unwrap().matches;

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].desc, "Test description");
    assert_eq!(matches[0].crit, crate::types::Criticality::Hostile);
    assert!(matches[0].is_capability);
    assert_eq!(matches[0].mbc, Some("B0001".to_string()));
    assert_eq!(matches[0].attack, Some("T1059".to_string()));
}

#[test]
fn test_rule_with_tags() {
    let rule = r#"
rule test_rule : suspicious {
    strings:
        $test = "TAGGED"
    condition:
        $test
}
"#;

    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();

    let test_data = b"TAGGED data";
    let matches = engine.scan_bytes(test_data, None).unwrap().matches;

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].crit, crate::types::Criticality::Suspicious);
}

#[test]
fn test_yara_match_to_evidence() {
    let engine = YaraEngine::new_for_test();

    let yara_match = YaraMatch {
        rule: "test_rule".to_string(),
        namespace: "test.namespace".to_string(),
        crit: crate::types::Criticality::Hostile,
        desc: "Test".to_string(),
        matched_strings: vec![MatchedString {
            identifier: "$pattern".to_string(),
            offset: 0x1000,
            value: "test".to_string(),
        }],
        is_capability: false,
        mbc: None,
        attack: None,
        trait_id: None,
        arch_context: None,
    };

    let evidence = engine.yara_match_to_evidence(&yara_match);

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].method, "yara");
    assert_eq!(evidence[0].source, "yara-x");
    assert_eq!(evidence[0].value, "test"); // Uses actual matched value
    assert_eq!(evidence[0].location, Some("offset:0x1000".to_string()));
}

#[test]
fn test_yara_match_to_evidence_no_strings() {
    let engine = YaraEngine::new_for_test();

    let yara_match = YaraMatch {
        rule: "test_rule".to_string(),
        namespace: "test.namespace".to_string(),
        crit: crate::types::Criticality::Hostile,
        desc: "Test".to_string(),
        matched_strings: vec![],
        is_capability: false,
        mbc: None,
        attack: None,
        trait_id: None,
        arch_context: None,
    };

    let evidence = engine.yara_match_to_evidence(&yara_match);

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].value, "test_rule");
    assert_eq!(evidence[0].location, Some("test.namespace".to_string()));
}

#[test]
fn test_multiple_patterns() {
    let rule = r#"
rule test_rule {
    strings:
        $a = "FIRST"
        $b = "SECOND"
    condition:
        any of them
}
"#;

    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();

    let test_data = b"FIRST and SECOND patterns";
    let matches = engine.scan_bytes(test_data, None).unwrap().matches;

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_strings.len(), 2);
}

#[test]
fn test_long_match_truncation() {
    let rule = r#"
rule test_rule {
    strings:
        $long = /A{200}/
    condition:
        $long
}
"#;

    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();

    let test_data = vec![b'A'; 200];
    let matches = engine.scan_bytes(&test_data, None).unwrap().matches;

    assert_eq!(matches.len(), 1);
    assert!(matches[0].matched_strings[0].value.contains("200 bytes"));
}

#[test]
fn test_capability_inference_from_mbc() {
    let rule = r#"
rule test_rule {
    meta:
        mbc = "B0015.001"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();

    let test_data = b"TEST";
    let matches = engine.scan_bytes(test_data, None).unwrap().matches;

    assert_eq!(matches.len(), 1);
    assert!(matches[0].is_capability); // Inferred from MBC presence
}

#[test]
fn test_capability_inference_from_attack() {
    let rule = r#"
rule test_rule {
    meta:
        attack = "T1059.004"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

    let mut engine = YaraEngine::new_for_test();
    engine.load_rule_source(rule).unwrap();

    let test_data = b"TEST";
    let matches = engine.scan_bytes(test_data, None).unwrap().matches;

    assert_eq!(matches.len(), 1);
    assert!(matches[0].is_capability); // Inferred from ATT&CK presence
}

#[test]
fn test_filter_disabled_rules() {
    let source = r#"
rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}

rule AlsoKeep {
    strings:
        $c = "also"
    condition:
        $c
}
"#;

    let mut disabled = std::collections::HashSet::new();
    // derive_trait_id("3p.test.file", "DisableMe") -> "third_party/test/file/disableme"
    disabled.insert("third_party/test/file/disableme".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 1);
    assert!(filtered.contains("rule KeepMe"));
    assert!(!filtered.contains("rule DisableMe"));
    assert!(filtered.contains("rule AlsoKeep"));

    // Verify filtered source is valid YARA
    let mut compiler = yara_x::Compiler::new();
    assert!(compiler.add_source(filtered.as_bytes()).is_ok());
}

#[test]
fn test_filter_disabled_rules_no_match() {
    let source = r#"
rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}
"#;

    let mut disabled = std::collections::HashSet::new();
    // Different namespace - won't match rules in test.file
    disabled.insert("third_party/other/file/somerule".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 0);
    assert_eq!(filtered, source);
}

#[test]
fn test_filter_disabled_rules_with_tags() {
    let source = r#"
rule KeepMe : tag1 tag2 {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe : hostile malware {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/disableme".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 1);
    assert!(filtered.contains("rule KeepMe : tag1 tag2"));
    assert!(!filtered.contains("rule DisableMe"));

    // Verify filtered source is valid YARA
    let mut compiler = yara_x::Compiler::new();
    assert!(compiler.add_source(filtered.as_bytes()).is_ok());
}

#[test]
fn test_filter_disabled_rules_private_global() {
    let source = r#"
private rule PrivateKeep {
    strings:
        $a = "keep"
    condition:
        $a
}

global rule GlobalDisable {
    strings:
        $b = "disable"
    condition:
        $b
}

private global rule PrivateGlobalKeep {
    strings:
        $c = "keep2"
    condition:
        $c
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/globaldisable".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 1);
    assert!(filtered.contains("private rule PrivateKeep"));
    assert!(!filtered.contains("global rule GlobalDisable"));
    assert!(filtered.contains("private global rule PrivateGlobalKeep"));

    // Verify filtered source is valid YARA
    let mut compiler = yara_x::Compiler::new();
    assert!(compiler.add_source(filtered.as_bytes()).is_ok());
}

#[test]
fn test_filter_disabled_rules_first_rule() {
    let source = r#"rule FirstDisabled {
    strings:
        $a = "first"
    condition:
        $a
}

rule Second {
    strings:
        $b = "second"
    condition:
        $b
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/firstdisabled".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 1);
    assert!(!filtered.contains("rule FirstDisabled"));
    assert!(filtered.contains("rule Second"));

    // Verify filtered source is valid YARA
    let mut compiler = yara_x::Compiler::new();
    assert!(compiler.add_source(filtered.as_bytes()).is_ok());
}

#[test]
fn test_filter_disabled_rules_last_rule() {
    let source = r#"
rule First {
    strings:
        $a = "first"
    condition:
        $a
}

rule LastDisabled {
    strings:
        $b = "last"
    condition:
        $b
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/lastdisabled".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 1);
    assert!(filtered.contains("rule First"));
    assert!(!filtered.contains("rule LastDisabled"));

    // Verify filtered source is valid YARA
    let mut compiler = yara_x::Compiler::new();
    assert!(compiler.add_source(filtered.as_bytes()).is_ok());
}

#[test]
fn test_filter_disabled_rules_multiple() {
    let source = r#"
rule Keep1 {
    strings:
        $a = "keep1"
    condition:
        $a
}

rule Disable1 {
    strings:
        $b = "disable1"
    condition:
        $b
}

rule Keep2 {
    strings:
        $c = "keep2"
    condition:
        $c
}

rule Disable2 {
    strings:
        $d = "disable2"
    condition:
        $d
}

rule Keep3 {
    strings:
        $e = "keep3"
    condition:
        $e
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/disable1".to_string());
    disabled.insert("third_party/test/file/disable2".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 2);
    assert!(filtered.contains("rule Keep1"));
    assert!(!filtered.contains("rule Disable1"));
    assert!(filtered.contains("rule Keep2"));
    assert!(!filtered.contains("rule Disable2"));
    assert!(filtered.contains("rule Keep3"));

    // Verify filtered source is valid YARA
    let mut compiler = yara_x::Compiler::new();
    assert!(compiler.add_source(filtered.as_bytes()).is_ok());
}

#[test]
fn test_filter_disabled_rules_with_imports() {
    let source = r#"import "pe"
import "math"

rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/disableme".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 1);
    assert!(filtered.contains("import \"pe\""));
    assert!(filtered.contains("import \"math\""));
    assert!(filtered.contains("rule KeepMe"));
    assert!(!filtered.contains("rule DisableMe"));
}

#[test]
fn test_filter_disabled_rules_complex_condition() {
    let source = r#"
rule KeepComplex {
    meta:
        description = "Complex rule"
    strings:
        $a = "pattern1"
        $b = "pattern2"
        $c = /regex[0-9]+/
    condition:
        ($a and $b) or
        ($c and filesize < 1MB) or
        (
            for any i in (0..10) : (
                uint32(i) == 0x12345678
            )
        )
}

rule DisableMe {
    strings:
        $x = "disable"
    condition:
        $x
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/disableme".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 1);
    assert!(filtered.contains("rule KeepComplex"));
    assert!(filtered.contains("for any i in"));
    assert!(!filtered.contains("rule DisableMe"));

    // Verify filtered source is valid YARA
    let mut compiler = yara_x::Compiler::new();
    assert!(compiler.add_source(filtered.as_bytes()).is_ok());
}

#[test]
fn test_filter_disabled_rules_all_disabled() {
    let source = r#"
rule Disable1 {
    strings:
        $a = "d1"
    condition:
        $a
}

rule Disable2 {
    strings:
        $b = "d2"
    condition:
        $b
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/disable1".to_string());
    disabled.insert("third_party/test/file/disable2".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 2);
    assert!(!filtered.contains("rule Disable1"));
    assert!(!filtered.contains("rule Disable2"));
    // Should be essentially empty (just whitespace)
    assert!(filtered.trim().is_empty());
}

#[test]
fn test_filter_disabled_rules_preserves_comments() {
    let source = r#"
// This is a file-level comment
/* Multi-line
   comment */

rule KeepMe {
    // Rule comment
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

    let mut disabled = std::collections::HashSet::new();
    disabled.insert("third_party/test/file/disableme".to_string());

    let (filtered, count) = YaraEngine::filter_disabled_rules(
        source,
        "3p.test.file",
        &disabled,
        rule_start_re().expect("valid test regex"),
    );

    assert_eq!(count, 1);
    assert!(filtered.contains("// This is a file-level comment"));
    assert!(filtered.contains("/* Multi-line"));
    assert!(filtered.contains("rule KeepMe"));
    assert!(!filtered.contains("rule DisableMe"));
}

/// Test YARA rule tier classification against fixture files.
///
/// Fixtures live in `tests/yara_tier_fixtures/{platforms}/{filetypes}/rule.yar`.
/// The `{filetypes}` directory name determines the expected `YaraTier`.
/// Platforms are sorted alphabetically, comma-separated (e.g. `linux,windows`).
/// Filetypes are sorted alphabetically, comma-separated (e.g. `elf,pe`).
///
/// To add a regression test for a misclassified rule, just drop the `.yar` file
/// into the appropriate directory.
#[test]
fn test_tier_classification_fixtures() {
    let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("yara_tier_fixtures");

    if !fixtures_dir.exists() {
        // Skip if fixtures not present (e.g., CI without test data)
        return;
    }

    let mut tested = 0;
    let mut failures: Vec<String> = Vec::new();

    // Walk: {fixtures_dir}/{platform_dir}/{filetype_dir}/*.yar
    for platform_entry in std::fs::read_dir(&fixtures_dir).unwrap() {
        let platform_entry = platform_entry.unwrap();
        if !platform_entry.file_type().unwrap().is_dir() {
            continue;
        }
        let platform_dir = platform_entry.file_name().to_string_lossy().to_string();

        for filetype_entry in std::fs::read_dir(platform_entry.path()).unwrap() {
            let filetype_entry = filetype_entry.unwrap();
            if !filetype_entry.file_type().unwrap().is_dir() {
                continue;
            }
            let filetype_dir = filetype_entry.file_name().to_string_lossy().to_string();

            // Map the filetype directory to the expected YaraTier.
            // The first filetype token determines the tier.
            let expected_tier = match filetype_dir.split(',').next().unwrap_or("") {
                "pe" | "dll" | "exe" => YaraTier::Pe,
                "elf" | "so" => YaraTier::Elf,
                "macho" | "dylib" => YaraTier::MachO,
                "js" | "ts" | "script-js" => YaraTier::ScriptJs,
                "script" => YaraTier::Script,
                "doc" => YaraTier::Doc,
                "archive" => YaraTier::Archive,
                "generic" => YaraTier::CrossFormat,
                other => {
                    failures.push(format!(
                        "Unknown filetype directory: {}/{}",
                        platform_dir, other
                    ));
                    continue;
                }
            };

            for rule_file in std::fs::read_dir(filetype_entry.path()).unwrap() {
                let rule_file = rule_file.unwrap();
                let path = rule_file.path();
                if path.extension().and_then(|e| e.to_str()) != Some("yar") {
                    continue;
                }

                let source = std::fs::read_to_string(&path).unwrap();
                let rule_name = extract_rule_name(&source)
                    .unwrap_or_else(|| path.file_stem().unwrap().to_string_lossy().to_string());

                // Use a plausible namespace for third-party rules
                let ns = format!("3p.test.{}", platform_dir);
                let actual_tier = YaraTier::classify_rule(&rule_name, &source, &ns);

                if actual_tier != expected_tier {
                    failures.push(format!(
                        "FAIL: {}/{}/{} — rule '{}': expected {:?}, got {:?}",
                        platform_dir,
                        filetype_dir,
                        path.file_name().unwrap().to_string_lossy(),
                        rule_name,
                        expected_tier,
                        actual_tier,
                    ));
                }
                tested += 1;
            }
        }
    }

    eprintln!(
        "Tier classification: {tested} rules tested, {} failures",
        failures.len()
    );
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("  {f}");
        }
        panic!(
            "{} of {} tier classification tests failed:\n{}",
            failures.len(),
            tested,
            failures.join("\n"),
        );
    }
    assert!(tested > 0, "No fixture files found");
}

#[test]
fn test_classify_rule_uses_description_and_source_url_hints() {
    let source = r#"
rule DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23 : FILE
{
    meta:
        description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
        source_url = "https://github.com/delivr-to/detections/blob/main/yara-rules/onenote_windows_script_encoding_file.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23",
            source,
            "3p.YARAForge.delivrto"
        ),
        YaraTier::Doc
    );
}

#[test]
fn test_classify_rule_uses_webshell_metadata_hints() {
    let source = r#"
rule SIGNATURE_BASE_WEBSHELL_PHP_By_String_Known_Webshell : FILE
{
    meta:
        description = "Known PHP Webshells which contain unique strings"
        source_url = "https://github.com/Neo23x0/signature-base/blob/main/yara/thor-webshells.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_WEBSHELL_PHP_By_String_Known_Webshell",
            source,
            "3p.YARAForge.signature_base"
        ),
        YaraTier::Script
    );
}

#[test]
fn test_classify_rule_uses_javascript_metadata_hints() {
    let source = r#"
rule suspicious_node_implant : FILE
{
    meta:
        description = "JavaScript credential stealer for Electron and Node.js applications"
        source_url = "https://example.invalid/node_stealer_javascript.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule("suspicious_node_implant", source, "3p.test.javascript"),
        YaraTier::ScriptJs
    );
}

#[test]
fn test_classify_rule_uses_lnk_description_hint() {
    let source = r#"
rule APT10_ChChes_lnk {
    meta:
        description = "LNK malware ChChes downloader"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule("APT10_ChChes_lnk", source, "3p.JPCERT.apt10"),
        YaraTier::Doc
    );
}

#[test]
fn test_rule_context_marks_unix_shell_payload_without_shell_script_filetype() {
    let source = r#"
rule SIGNATURE_BASE_MAL_Payload_F5_BIG_IP_Exploitations_Jul20_1 : CVE_2020_5902 FILE
{
    meta:
        description = "Detects code found in report on exploits against CVE-2020-5902 F5 BIG-IP vulnerability by NCC group"
    strings:
        $x1 = "rm -f /etc/ld.so.preload" ascii fullword
        $x2 = "chmod +x /var/log/F5-logcheck" ascii
        $x3 = ".sh | sh" ascii
    condition:
        1 of them
}
"#;
    let ctx = YaraEngine::derive_rule_context(
        "SIGNATURE_BASE_MAL_Payload_F5_BIG_IP_Exploitations_Jul20_1",
        source,
        "3p.YARAForge.yara-rules-full",
    );
    assert!(ctx.filetypes.is_empty());
    assert_eq!(ctx.platforms, vec!["unix".to_string()]);
}

#[test]
fn test_rule_context_keeps_shell_script_filetype_for_bash_rule_names() {
    let source = r#"
rule Linux_Backdoor_Bash_e427876d : FILE
{
    condition:
        true
}
"#;
    let ctx = YaraEngine::derive_rule_context(
        "Linux_Backdoor_Bash_e427876d",
        source,
        "3p.elastic.Linux_Backdoor_Bash",
    );
    // sh/bash/zsh tags all name the canonical shell type.
    assert_eq!(ctx.filetypes, vec!["shell".to_string()]);
    assert_eq!(ctx.platforms, vec!["linux".to_string()]);
}

#[test]
fn test_rule_context_marks_tinyshell_shell_snippet_as_unix_platform() {
    let source = r#"
rule SEKOIA_Malware_Tinyshell_Strings : FILE
{
    strings:
        $ = "_tsh_runshell"
        $ = "exec bash --login"
    condition:
        all of them
}
"#;
    let ctx = YaraEngine::derive_rule_context(
        "SEKOIA_Malware_Tinyshell_Strings",
        source,
        "3p.YARAForge.yara-rules-full",
    );
    assert!(ctx.filetypes.is_empty());
    assert_eq!(ctx.platforms, vec!["unix".to_string()]);
}

#[test]
fn test_rule_context_preserves_arch_context_metadata() {
    let source = r#"
rule ELASTIC_Windows_Generic_Threat : FILE
{
    meta:
        os = "windows"
        arch_context = "x64"
    condition:
        true
}
"#;
    let ctx = YaraEngine::derive_rule_context(
        "ELASTIC_Windows_Generic_Threat",
        source,
        "3p.elastic.windows",
    );
    assert_eq!(ctx.arch_context.as_deref(), Some("x64"));
    assert_eq!(ctx.platforms, vec!["windows".to_string()]);
}

#[test]
fn test_manifest_roundtrip_preserves_rule_contexts() {
    let dir = tempfile::tempdir().unwrap();
    let mut rule_contexts = HashMap::new();
    rule_contexts.insert(
        rule_context_key("", "test_rule"),
        RuleContext {
            filetypes: vec!["sh".to_string(), "bash".to_string(), "zsh".to_string()],
            filetype_source: "manifest-roundtrip".to_string(),
            platforms: vec!["unix".to_string()],
            os_meta: Some("linux".to_string()),
            arch_context: Some("x64".to_string()),
        },
    );
    let manifest = YaraManifest {
        builtin_count: 7,
        third_party_count: 11,
        inline_namespaces: vec!["ns1".to_string()],
        rule_contexts,
        populated_tiers: vec!["pe".to_string(), FALLBACK_BUCKET.to_string()],
        source_tag: Some(format!("{:016x}", 0xdead_beef_u64)),
        engine_tag: Some(format!("{:016x}", engine_tag())),
        cleave_version: None,
        bucket_tags: std::collections::BTreeMap::new(),
    };
    YaraEngine::write_manifest(dir.path(), &manifest);

    let restored = YaraEngine::read_manifest(dir.path()).expect("manifest restored");
    assert_eq!(
        (restored.builtin_count, restored.third_party_count),
        (7, 11)
    );
    let ctx = restored
        .rule_contexts
        .get(&rule_context_key("", "test_rule"))
        .expect("cached rule context restored");
    assert_eq!(
        ctx.filetypes,
        vec!["sh".to_string(), "bash".to_string(), "zsh".to_string()]
    );
    assert_eq!(ctx.filetype_source, "manifest-roundtrip");
    assert_eq!(ctx.platforms, vec!["unix".to_string()]);
    assert_eq!(ctx.os_meta.as_deref(), Some("linux"));
    assert_eq!(ctx.arch_context.as_deref(), Some("x64"));
    assert_eq!(
        restored.populated_tiers,
        vec!["pe".to_string(), FALLBACK_BUCKET.to_string()]
    );
}

#[test]
fn compressed_compiled_bucket_is_read_without_an_unpacked_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("php.yrc");
    let bytes = b"compiled YARA bytes";
    std::fs::write(
        path.with_extension("yrc.zst"),
        zstd::encode_all(&bytes[..], 3).unwrap(),
    )
    .unwrap();
    assert!(!path.exists());
    assert_eq!(YaraEngine::read_compiled_bucket(&path).unwrap(), bytes);
}

#[test]

fn test_lazy_tier_compiles_then_loads_from_per_tier_cache() {
    let dir = tempfile::tempdir().unwrap();
    let bucket = "pe";
    let mut sources = HashMap::new();
    sources.insert(
        bucket.to_string(),
        vec![(
            "test_ns".to_string(),
            r#"rule r { strings: $a = "abc" condition: $a }"#.to_string(),
        )],
    );
    let cell = OnceLock::new();
    let _ = cell.set(sources);

    let mut engine = YaraEngine::new_for_test();
    engine.populated_tiers.insert(bucket.to_string());
    engine.tiers = YaraEngine::tier_cells([bucket]);
    engine.source = TierSource::Lazy {
        cache_dir: Some(dir.path().to_path_buf()),
        bucket_tags: [(bucket.to_string(), "0123456789abcdef".to_string())].into(),
        traits_dir: dir.path().to_path_buf(),
        third_party_dir: dir.path().to_path_buf(),
        enable_third_party: false,
        sources: cell,
    };
    // First access compiles from source and writes the per-bucket cache file.
    assert!(engine.tier_rules(bucket).is_some());
    assert!(
        compiled_path(dir.path(), bucket, "0123456789abcdef").exists(),
        "compiling a bucket must write its per-bucket cache file"
    );

    // A fresh engine with NO sources must load that bucket straight from the
    // per-bucket cache file — the warm path that never touches rule text.
    let mut warm = YaraEngine::new_for_test();
    warm.populated_tiers.insert(bucket.to_string());
    warm.tiers = YaraEngine::tier_cells([bucket]);
    warm.source = TierSource::Lazy {
        cache_dir: Some(dir.path().to_path_buf()),
        bucket_tags: [(bucket.to_string(), "0123456789abcdef".to_string())].into(),
        traits_dir: dir.path().to_path_buf(),
        third_party_dir: dir.path().to_path_buf(),
        enable_third_party: false,
        sources: OnceLock::new(),
    };
    assert!(
        warm.tier_rules(bucket).is_some(),
        "warm engine must load the bucket from its per-bucket cache without sources"
    );
}

#[test]
fn test_lazy_tier_does_not_cache_empty_rules() {
    let dir = tempfile::tempdir().unwrap();
    let bucket = "empty";
    let mut sources = HashMap::new();
    sources.insert(
        bucket.to_string(),
        vec![("empty_ns".to_string(), "// no rules".to_string())],
    );
    let cell = OnceLock::new();
    let _ = cell.set(sources);

    let mut engine = YaraEngine::new_for_test();
    engine.populated_tiers.insert(bucket.to_string());
    engine.tiers = YaraEngine::tier_cells([bucket]);
    engine.source = TierSource::Lazy {
        cache_dir: Some(dir.path().to_path_buf()),
        bucket_tags: [(bucket.to_string(), "0123456789abcdef".to_string())].into(),
        traits_dir: dir.path().to_path_buf(),
        third_party_dir: dir.path().to_path_buf(),
        enable_third_party: false,
        sources: cell,
    };

    assert!(engine.tier_rules(bucket).is_none());
    assert!(
        !compiled_path(dir.path(), bucket, "0123456789abcdef").exists(),
        "empty buckets must not create cache files"
    );
}

fn cache_manifest(source_tag: u64, bucket_tags: &[(&str, &str)]) -> YaraManifest {
    YaraManifest {
        builtin_count: 1,
        third_party_count: 0,
        inline_namespaces: Vec::new(),
        rule_contexts: HashMap::new(),
        populated_tiers: bucket_tags.iter().map(|(b, _)| (*b).to_string()).collect(),
        source_tag: Some(format!("{source_tag:016x}")),
        engine_tag: Some(format!("{:016x}", engine_tag())),
        cleave_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        bucket_tags: bucket_tags
            .iter()
            .map(|(b, t)| ((*b).to_string(), (*t).to_string()))
            .collect(),
    }
}

/// A cache manifest is trusted only for the sources on disk, this build,
/// and this engine; a missing field vouches for nothing.
#[test]
fn test_validated_manifest_requires_sources_build_and_engine() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = cache_manifest(0xabcd, &[("pe", "t")]);
    YaraEngine::write_manifest(dir.path(), &manifest);
    assert!(YaraEngine::validated_manifest(dir.path(), Some(0xabcd)).is_some());
    assert!(YaraEngine::validated_manifest(dir.path(), Some(0x1234)).is_none());
    assert!(YaraEngine::validated_manifest(dir.path(), None).is_none());

    manifest.source_tag = None;
    YaraEngine::write_manifest(dir.path(), &manifest);
    assert!(YaraEngine::validated_manifest(dir.path(), Some(0xabcd)).is_none());

    manifest = cache_manifest(0xabcd, &[("pe", "t")]);
    manifest.cleave_version = Some("0.0.0-other".to_string());
    YaraEngine::write_manifest(dir.path(), &manifest);
    assert!(YaraEngine::validated_manifest(dir.path(), Some(0xabcd)).is_none());

    manifest = cache_manifest(0xabcd, &[("pe", "t")]);
    manifest.cleave_version = None;
    YaraEngine::write_manifest(dir.path(), &manifest);
    assert!(YaraEngine::validated_manifest(dir.path(), Some(0xabcd)).is_none());
}

/// The engine tag rejects on its own axis: rules built from exactly the
/// right sources are still refused when another build compiled them.
#[test]
fn test_validated_manifest_engine_tag() {
    let dir = tempfile::tempdir().unwrap();
    let mut manifest = cache_manifest(0xabcd, &[("pe", "t")]);
    YaraEngine::write_manifest(dir.path(), &manifest);
    assert!(YaraEngine::validated_manifest(dir.path(), Some(0xabcd)).is_some());

    manifest.engine_tag = Some(format!("{:016x}", engine_tag() ^ 0xffff_ffff_u64));
    YaraEngine::write_manifest(dir.path(), &manifest);
    assert!(YaraEngine::validated_manifest(dir.path(), Some(0xabcd)).is_none());

    manifest.engine_tag = None;
    YaraEngine::write_manifest(dir.path(), &manifest);
    assert!(YaraEngine::validated_manifest(dir.path(), Some(0xabcd)).is_none());
}

/// A rule update recompiles only what it touched: a bucket whose tag
/// changed, or that is gone, loses its compiled file; the rest keep theirs,
/// nested (MIME-named) buckets included.
#[test]
fn test_retire_stale_buckets_keeps_unchanged_buckets() {
    let dir = tempfile::tempdir().unwrap();
    let file = |bucket: &str, tag: &str| compiled_path(dir.path(), bucket, tag);
    for (bucket, tag) in [
        ("pe", "same"),
        ("js", "old"),
        ("gone", "x"),
        ("application/x-zsh", "same"),
    ] {
        let path = file(bucket, tag);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"compiled").unwrap();
    }
    std::fs::write(dir.path().join("manifest.json"), b"{}").unwrap();
    let now = [("pe", "same"), ("js", "new"), ("application/x-zsh", "same")]
        .iter()
        .map(|(b, t)| ((*b).to_string(), (*t).to_string()))
        .collect();
    YaraEngine::retire_stale_buckets(dir.path(), &now);
    assert!(file("pe", "same").exists(), "unchanged bucket kept");
    assert!(
        file("application/x-zsh", "same").exists(),
        "nested bucket kept"
    );
    assert!(!file("js", "old").exists(), "changed bucket retired");
    assert!(!file("gone", "x").exists(), "removed bucket retired");
    assert!(
        dir.path().join("manifest.json").exists(),
        "only compiled files are retired"
    );
}

/// Two buckets with the same sources but different names, or the same name
/// and different sources, never share a tag.
#[test]
fn test_bucket_tag_covers_name_and_sources() {
    let src = |text: &str| vec![("ns".to_string(), text.to_string())];
    assert_eq!(bucket_tag("pe", &src("a")), bucket_tag("pe", &src("a")));
    assert_ne!(bucket_tag("pe", &src("a")), bucket_tag("pe", &src("b")));
    assert_ne!(bucket_tag("pe", &src("a")), bucket_tag("elf", &src("a")));
}

/// The probe must actually produce a usable fingerprint; `u64::MAX` is the
/// sentinel for "this build cannot serialize at all", which would silently
/// turn every load into a from-source compile.
#[test]
fn test_engine_tag_is_usable_and_stable() {
    assert_ne!(engine_tag(), u64::MAX, "probe rule failed to compile here");
    assert_eq!(engine_tag(), engine_tag(), "engine tag must be stable");
}

#[test]
fn test_js_scan_selection_includes_fallback() {
    let mut engine = YaraEngine::new_for_test();
    for bucket in ["js", "ts", "ps1", "pe", FALLBACK_BUCKET] {
        engine.populated_tiers.insert(bucket.to_string());
    }

    // A concrete filter loads the named filetype buckets plus the always-on
    // fallback bucket, intersected with the populated set (results sorted).
    assert_eq!(
        engine.buckets_to_scan(Some(&["ts", "tsx", "js"])),
        vec![
            FALLBACK_BUCKET.to_string(),
            "js".to_string(),
            "ts".to_string()
        ]
    );
    assert_eq!(
        engine.buckets_to_scan(Some(&["ps1"])),
        vec![FALLBACK_BUCKET.to_string(), "ps1".to_string()]
    );
    // A filter naming an unpopulated bucket still always gets the fallback.
    assert_eq!(
        engine.buckets_to_scan(Some(&["docx"])),
        vec![FALLBACK_BUCKET.to_string()]
    );

    // An unfiltered scan loads every populated bucket.
    let mut all = engine.buckets_to_scan(None);
    all.sort();
    assert_eq!(
        all,
        vec![
            FALLBACK_BUCKET.to_string(),
            "js".to_string(),
            "pe".to_string(),
            "ps1".to_string(),
            "ts".to_string()
        ]
    );
}

#[test]
fn test_classify_inline_trait_yara_uses_declared_for_labels() {
    let tiers = |declared: &[&str]| {
        let declared: Vec<String> = declared.iter().copied().map(String::from).collect();
        YaraEngine::classify_inline_trait_yara_tiers(&declared)
    };
    // `for:` parses like a trait `for:` and buckets by the canonical label of
    // every identified type it admits — the key a scan of that type loads.
    assert!(tiers(&["ts"]).contains(&"javascript".to_string()));
    let archives = tiers(&["jar", "zip"]);
    assert!(archives.contains(&"jar".to_string()) && archives.contains(&"zip".to_string()));
    assert_eq!(tiers(&["shellcode"]), ["shellcode"]);
    assert_eq!(tiers(&["wasm"]), ["wasm"]);
    for declared in [
        &["ts"][..],
        &["jar", "zip"],
        &["ps1"],
        &["binaries"],
        &["shellcode"],
    ] {
        for bucket in tiers(declared) {
            let ft = FileType::from_label(&bucket)
                .unwrap_or_else(|| panic!("{declared:?} routed to non-label bucket {bucket}"));
            assert_eq!(ft.yara_filetypes(), [bucket.as_str()], "{declared:?}");
        }
    }
}

#[test]
fn test_classify_inline_trait_yara_without_types_uses_fallback() {
    // No concrete `for:` means the trait applies everywhere; the rule name is
    // never consulted (a "php"/"x64"/"donut" name must not narrow routing).
    for declared in [vec![], vec!["all".to_string()], vec!["none".to_string()]] {
        assert_eq!(
            YaraEngine::classify_inline_trait_yara_tiers(&declared),
            vec![FALLBACK_BUCKET.to_string()],
            "{declared:?}"
        );
    }
}

/// Every type that identification can produce must scan a bucket that its
/// own rules can route to, and every legacy alias must route somewhere.
#[test]
fn test_every_file_type_and_alias_routes_to_a_scanned_bucket() {
    for ft in FileType::ALL {
        if matches!(ft, FileType::Unknown) {
            continue;
        }
        let scanned = ft.yara_filetypes();
        assert!(
            crate::analyzers::yara_buckets_for_tags(&[ft.label()])
                .contains(&ft.label().to_string()),
            "label {} misses {ft:?}",
            ft.label()
        );
        assert!(
            scanned.contains(&ft.label()),
            "{ft:?} does not scan its own bucket"
        );
        for alias in ft.yara_aliases() {
            let routed = crate::analyzers::yara_buckets_for_tags(&[alias]);
            assert!(
                routed.contains(&ft.label().to_string()),
                "alias {alias} misses {ft:?}"
            );
        }
    }
    assert!(crate::analyzers::yara_buckets_for_tags(&["no-such-type"]).is_empty());
}

#[test]
fn test_split_monolithic_buckets_built_in_rules_by_filetype() {
    let source = r#"
rule builtin_js_rule {
    meta:
        description = "JavaScript credential stealer for Node.js applications"
    condition:
        true
}

rule builtin_pe_rule {
    condition:
        uint16(0) == 0x5A4D
}

rule builtin_generic_rule {
    condition:
        true
}
"#;
    // Mirror the collectors: inject filetype hints from magic conditions
    // before splitting (so the PE magic rule gets a "pe" filetype).
    let injected = yara_classify::inject_condition_filetype_hints(source);

    let split = YaraEngine::split_monolithic_by_tier(
        &injected,
        "traits",
        rule_start_re().expect("valid test regex"),
    );

    // The JS rule lands in each of its inferred filetype buckets.
    let js_bucket = split
        .tiers
        .get("javascript")
        .expect("js rule bucketed into the javascript label");
    assert!(js_bucket.contains("builtin_js_rule"));

    let pe_bucket = split
        .tiers
        .get("pe")
        .expect("pe rule bucketed into pe filetype");
    assert!(pe_bucket.contains("builtin_pe_rule"));

    // A rule with no filetype constraint lands in the always-scanned fallback.
    let fallback = split
        .tiers
        .get(FALLBACK_BUCKET)
        .expect("generic rule bucketed into fallback");
    assert!(fallback.contains("builtin_generic_rule"));
}

/// Extract the rule name from YARA source text.
fn extract_rule_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("rule ") {
            // "rule NAME {" or "rule NAME : TAG {"
            let name = rest.split_whitespace().next()?.trim_end_matches('{');
            return Some(name.to_string());
        }
    }
    None
}

/// Diagnostic test: classify all third-party YARA rules and print distribution.
/// Run with: cargo test --lib test_classify_all_third_party -- --nocapture --ignored
#[test]
#[ignore = "diagnostic: prints the tier distribution of the installed third-party rules"]
fn test_classify_all_third_party() {
    use std::collections::HashMap;

    let rule_re = regex::Regex::new(r"(?m)^((private\s+)?rule\s+)(\w+)").unwrap();

    let traits_dir = dirs::data_dir()
        .unwrap_or_default()
        .join("atomdrift")
        .join("cleave")
        .join("traits")
        .join("third-party");

    let mut tier_counts: HashMap<YaraTier, usize> = HashMap::new();
    let mut cross_format_names: Vec<String> = Vec::new();
    let mut unknown_names: Vec<String> = Vec::new();

    // Walk all .yar files
    for entry in walkdir::WalkDir::new(&traits_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "yar" || ext == "yara")
                .unwrap_or(false)
        })
    {
        let path = entry.path();
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };

        // Derive namespace from path
        let rel = path.strip_prefix(&traits_dir).unwrap_or(path);
        let ns = format!(
            "3p.{}",
            rel.with_extension("").to_string_lossy().replace('/', ".")
        );

        for cap in rule_re.captures_iter(&source) {
            let name = cap.get(3).unwrap().as_str();
            let is_private = cap
                .get(2)
                .map(|m| m.as_str().contains("private"))
                .unwrap_or(false);
            if is_private {
                continue;
            }

            let start = cap.get(0).unwrap().start();
            // Find rule body end (next rule start or EOF)
            let body_end = rule_re
                .find_at(&source, start + 1)
                .map(|m| m.start())
                .unwrap_or(source.len());
            let rule_text = &source[start..body_end];

            let tier = YaraTier::classify_rule(name, rule_text, &ns);
            *tier_counts.entry(tier).or_default() += 1;
            match tier {
                YaraTier::CrossFormat => {
                    cross_format_names.push(format!("{} (ns={})", name, ns));
                }
                YaraTier::Unknown => {
                    unknown_names.push(format!("{} (ns={})", name, ns));
                }
                _ => {}
            }
        }
    }

    eprintln!("\n=== YARA Tier Distribution ===");
    let mut total = 0;
    for tier in YaraTier::ALL {
        let count = tier_counts.get(tier).copied().unwrap_or(0);
        total += count;
        eprintln!("  {:8}: {}", tier.label(), count);
    }
    eprintln!("  {:8}: {}", "TOTAL", total);

    cross_format_names.sort();
    eprintln!(
        "\n=== Cross-Format Rules ({}) ===",
        cross_format_names.len()
    );
    for name in &cross_format_names {
        eprintln!("  {name}");
    }

    unknown_names.sort();
    eprintln!("\n=== Unknown Rules ({}) ===", unknown_names.len());
    for name in &unknown_names {
        eprintln!("  {name}");
    }
}

/// Diagnostic test: print the full runtime rule-name sets per tier as loaded by the engine.
/// Includes built-in rules, inline trait YARA, and third-party rules after tier classification.
///
/// Run with:
/// `cargo test --lib test_dump_runtime_rule_sets_by_tier -- --nocapture --ignored`
#[test]
#[ignore = "diagnostic: dumps the installed rule sets by tier"]
fn test_dump_runtime_rule_sets_by_tier() {
    use std::collections::HashMap;

    fn extract_rule_names(source: &str) -> Vec<String> {
        let Some(rule_re) = super::rule_start_re() else {
            return Vec::new();
        };

        let mut names = Vec::new();
        for cap in rule_re.captures_iter(source) {
            let name = cap.get(3).map(|m| m.as_str()).unwrap_or_default();
            let modifiers = cap.get(2).map(|m| m.as_str()).unwrap_or_default();
            if modifiers.contains("private") {
                continue;
            }
            names.push(name.to_string());
        }
        names
    }

    let traits_dir = crate::cache::traits_path();
    let third_party_dir = crate::cache::third_party_path();

    let (inline_tier_sources, _inline_namespaces) = if traits_dir.exists() {
        YaraEngine::collect_inline_trait_sources_tiered(&traits_dir)
    } else {
        (HashMap::new(), Vec::new())
    };
    let (builtin_tier_sources, _, _) = if traits_dir.exists() {
        YaraEngine::collect_builtin_sources_tiered(&traits_dir)
    } else {
        (HashMap::new(), HashMap::new(), 0)
    };
    let (mut third_party_sources, _, _, _, _) = if third_party_dir.exists() {
        YaraEngine::collect_third_party_sources_tiered(&third_party_dir)
    } else {
        (HashMap::new(), HashMap::new(), 0, 0, 0)
    };

    let mut tier_names: HashMap<String, Vec<String>> = HashMap::new();

    for (bucket, sources) in inline_tier_sources {
        for (namespace, source) in sources {
            for name in extract_rule_names(&source) {
                tier_names
                    .entry(bucket.clone())
                    .or_default()
                    .push(format!("{name} (ns={namespace})"));
            }
        }
    }

    for (bucket, sources) in builtin_tier_sources {
        for (namespace, source) in sources {
            for name in extract_rule_names(&source) {
                tier_names
                    .entry(bucket.clone())
                    .or_default()
                    .push(format!("{name} (ns={namespace})"));
            }
        }
    }

    for (bucket, sources) in third_party_sources.drain() {
        for (namespace, source) in sources {
            for name in extract_rule_names(&source) {
                tier_names
                    .entry(bucket.clone())
                    .or_default()
                    .push(format!("{name} (ns={namespace})"));
            }
        }
    }

    eprintln!("\n=== Runtime Rule Sets By Bucket ===");
    let mut buckets: Vec<String> = tier_names.keys().cloned().collect();
    buckets.sort();
    for bucket in buckets {
        let mut names = tier_names.remove(&bucket).unwrap_or_default();
        names.sort();
        names.dedup();
        eprintln!("\n=== {} ({}) ===", bucket, names.len());
        for name in names {
            eprintln!("  {name}");
        }
    }
}

/// A rule whose condition holds without any string hit is still a match:
/// both the combined-engine channel and per-condition evidence record it.
#[test]
fn stringless_inline_rule_match_is_recorded() {
    let ns = "inline.test/shellcode::stringless";
    let source = "rule stringless { condition: uint8(0) == 0xE8 and filesize > 4 }";
    let mut compiler = yara_x::Compiler::new();
    compiler.new_namespace(ns);
    compiler.add_source(source).unwrap();
    let rules = compiler.build();
    let mut yara = YaraEngine::new_for_test();
    let cell = yara
        .tiers
        .entry(FileType::Shellcode.label().to_string())
        .or_default();
    cell.set(Some(Arc::new(rules))).unwrap();
    yara.populated_tiers
        .insert(FileType::Shellcode.label().to_string());
    yara.compiled_inline_namespaces.push(ns.to_string());
    yara.rule_counts = (1, 0);
    let filter = FileType::Shellcode.yara_filetypes();
    let hit = yara
        .scan_bytes(b"\xE8\x00\x10\x00\x00\x90", Some(&filter))
        .unwrap();
    let evidence = hit.inline_traits.get(ns).expect("stringless rule matched");
    assert!(!evidence.is_empty());
    let miss = yara
        .scan_bytes(b"\x90\x90\x90\x90\x90\x90", Some(&filter))
        .unwrap();
    assert!(miss.inline_traits.get(ns).is_none_or(Vec::is_empty));

    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(source).unwrap();
    let rules = compiler.build();
    let data = b"\xE8\x00\x10\x00\x00\x90";
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = scanner.scan(data).unwrap();
    let evidence = crate::composite_rules::evaluators::yara::collect_yara_evidence(&results, data);
    assert_eq!(evidence.len(), 1);
}
