//! Compound-assignment provenance must reach ordinary YAML call predicates.
//! Source strings are analyzed as data, never compiled or executed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn compound_assignment_operands_reach_call_rules_without_stale_overwrites() {
    let repo = tempfile::tempdir().unwrap();
    let directory = repo.path().join("micro-behaviors/data/string/append");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("calls.yaml"),
        r#"
defaults:
  for: [javascript, typescript, python, go, rust, c]
  platforms: [unix, windows]
  crit: notable
  conf: 1.0
traits:
  - id: left-origin
    desc: Sink receives left call result
    if:
      type: symbol
      kind: call
      exact: send
      arg:
        index: 0
        from:
          call: '^left$'
  - id: right-origin
    desc: Sink receives right call result
    if:
      type: symbol
      kind: call
      exact: send
      arg:
        index: 0
        from:
          call: '^right$'
"#,
    )
    .unwrap();
    cleave::traits_repo::set_override_dir(Some(repo.path().to_path_buf()));
    let options = cleave::AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    };
    for (path, prefix, initial, suffix) in [
        ("a.js", "function run(){", "let value=left();", "}"),
        ("a.ts", "function run(){", "let value=left();", "}"),
        ("a.py", "def run():\n ", "value=left();", "\n"),
        ("a.go", "package p\nfunc run(){", "value:=left();", "}"),
        ("a.rs", "fn run(){", "let mut value=left();", "}"),
        ("a.c", "void run(){", "int value=left();", "}"),
    ] {
        for (tail, expected) in [
            ("value+=right();send(value);", [true, true]),
            ("value=right();send(value);", [false, true]),
            ("value+=right();value=0;send(value);", [false, false]),
            ("value+=right();send(0);", [false, false]),
            ("value+=opaque(right());send(value);", [true, false]),
        ] {
            let source = format!("{prefix}{initial}{tail}{suffix}");
            let report = cleave::analyze_bytes(source.as_bytes(), path, &options).unwrap();
            for (id, expected) in ["left-origin", "right-origin"].into_iter().zip(expected) {
                let full_id = format!("micro-behaviors/data/string/append::{id}");
                let matched = report.findings.iter().any(|f| f.id.as_str() == full_id);
                assert_eq!(matched, expected, "{path}: {source}: {id}");
            }
        }
    }
    cleave::traits_repo::set_override_dir(None);
}
