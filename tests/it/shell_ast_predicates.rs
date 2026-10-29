//! Compound-capture predicates must survive scalar early pruning in ordinary
//! batched scans and independent measured validation.
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::process::Command;

#[test]
fn shell_compound_predicates_are_checked_after_structure_in_scan_and_validation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let rules = root.join("metadata/test/query");
    std::fs::create_dir_all(&rules).unwrap();
    let queries = [
        (
            "pipe",
            r#"((pipeline . (command name: (command_name (word) @producer)) . (command name: (command_name (word) @consumer)) .) @pipeline
            (#eq? @producer "printf") (#eq? @consumer "cat")
            (#match? @pipeline "^printf (allow|permit) [|] cat$")
            (#not-match? @pipeline "reject|deny"))"#,
        ),
        (
            "command",
            r#"((command name: (command_name (word) @name) argument: (word)) @command
            (#eq? @name "printf") (#match? @command "^printf (allow|permit)$"))"#,
        ),
        (
            "equal",
            r#"((pipeline . (command) @left . (command) @right .)
            (#eq? @left @right) (#match? @left "^printf"))"#,
        ),
        (
            "redirect",
            r#"((redirected_statement body: (command name: (command_name (word) @name))) @statement
            (#eq? @name "printf") (#match? @statement "^printf (allow|permit) > /dev/null$"))"#,
        ),
        (
            "group",
            r#"((compound_statement (command name: (command_name (word) @name))) @group
            (#eq? @name "printf") (#match? @group "^\\{ printf (allow|permit); \\}$"))"#,
        ),
        (
            "join",
            r#"((_ (command name: (command_name (word)) . argument: (word) @created .) @creation
            (command name: (command_name (word) @consumer) . argument: (word) @used .))
            (#match? @creation "^mkfifo ") (#eq? @consumer "cat") (#eq? @created @used))"#,
        ),
    ];
    let traits: Vec<_> = queries.iter().map(|(id, query)| json!({
        "id":id,"desc":format!("Shell {id} predicate"),"if":{"type":"tree-sitter","language":"shell","query":query}
    })).collect();
    std::fs::write(rules.join("query.yaml"), serde_saphyr::to_string(&json!({
        "defaults":{"for":["shell"],"platforms":["unix"],"crit":"notable","conf":1.0},"traits":traits
    })).unwrap()).unwrap();
    let cases: &[(&str, &[&str])] = &[
        ("printf allow | cat", &["command", "pipe"]),
        ("printf permit | cat", &["command", "pipe"]),
        ("printf reject | cat", &[]),
        ("echo allow | cat", &[]),
        ("printf allow | sort", &["command"]),
        ("printf allow | printf reject", &["command"]),
        ("printf allow | printf allow", &["command", "equal"]),
        ("printf allow > /dev/null", &["command", "redirect"]),
        ("printf reject > /dev/null", &[]),
        ("{ printf allow; }", &["command", "group"]),
        ("{ printf reject; }", &[]),
        ("mkfifo fifo; cat fifo", &["join"]),
    ];
    for (i, (source, expected)) in cases.iter().enumerate() {
        let severity = if expected.is_empty() {
            "baseline"
        } else {
            "notable"
        };
        let input = root.join(format!("testdata/{severity}/case-{i}.sh"));
        std::fs::create_dir_all(input.parent().unwrap()).unwrap();
        std::fs::write(&input, format!("{source}\n")).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
            .args([
                "--traits-dir",
                root.to_str().unwrap(),
                "--disable",
                "yara,radare2,upx",
                "--json",
                "analyze",
                input.to_str().unwrap(),
            ])
            .env("CLEAVE_SKIP_CACHE", "1")
            .env("CLEAVE_NO_UPDATE_CHECK", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let actual: BTreeSet<_> = report["files"][0]["traits"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| t["id"].as_str()?.strip_prefix("metadata/test/query::"))
            .collect();
        assert_eq!(actual, expected.iter().copied().collect(), "{source}");
    }
    // A creation-command capture with no local scalar guard must retain
    // early filtering. Otherwise this harmless input makes the sibling join
    // enumerate millions of unrelated command pairs before rejecting them.
    let wide = format!(
        "# mkfifo demo\n{}cat tail\n",
        (0..1500)
            .map(|i| format!("printf x{i}\n"))
            .collect::<String>()
    );
    let wide_path = root.join("testdata/baseline/wide.sh.xz");
    std::fs::create_dir_all(wide_path.parent().unwrap()).unwrap();
    use std::io::Write;
    let mut compressed = xz2::write::XzEncoder::new(Vec::new(), 6);
    compressed.write_all(wide.as_bytes()).unwrap();
    std::fs::write(wide_path, compressed.finish().unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
        .args([
            "--traits-dir",
            root.to_str().unwrap(),
            "--slow-rule-ms",
            "100",
            "validate",
            "--exclude",
            "validation",
        ])
        .env("CLEAVE_SKIP_CACHE", "1")
        .env("CLEAVE_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("notable 8/8"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("baseline 5/5"));
}
