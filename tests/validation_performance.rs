//! Regression from the VSIX investigation: the original table query enumerated
//! unrelated sibling pairs. Compare its real query with the fixed definition.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::{Value, json};
use std::process::{Command, Output};

fn run(root: &std::path::Path, threshold: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cleave"))
        .env("CLEAVE_CACHE_DIR", root.join("cache"))
        .env("CLEAVE_RAYON_THREADS", "4")
        .env("CLEAVE_VALIDATE_SOFT", "0")
        .env("RUST_LOG", "warn")
        .args([
            "--no-update-check",
            "--slow-rule-ms",
            threshold,
            "--traits-dir",
        ])
        .arg(root.join("rules"))
        .arg("validate")
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn original_slow_query_is_a_soft_outlier_and_fixed_queries_pass() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let rules = root.join("rules");
    for sub in [
        "testdata/hostile",
        "testdata/benign",
        "testdata/performance",
        "objectives/impact/dos/resource",
    ] {
        std::fs::create_dir_all(rules.join(sub)).unwrap();
    }
    std::fs::write(
        rules.join("testdata/expectations.toml"),
        "hostile=[]\nbenign=[]\nwalked_hostile=[]\n[does_nothing]\ndefault_cap=0\n",
    )
    .unwrap();
    let queries: std::collections::BTreeMap<String, String> =
        serde_json::from_str(include_str!("fixtures/rule-performance/queries.json")).unwrap();
    let traits: Vec<Value> = queries
        .into_iter()
        .map(|(id, query)| {
            json!({
                "id": id, "desc": format!("Cost regression for {id}"), "count_min": 3,
                "if": {"type":"tree-sitter", "language":"javascript", "query":query}
            })
        })
        .collect();
    let mut bundle = json!({"defaults":{
        "for":["javascript"], "platforms":["unix","windows"], "crit":"notable", "conf":0.95
    }, "traits":traits});
    let rule_file = rules.join("objectives/impact/dos/resource/queries.yaml");
    std::fs::write(&rule_file, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let properties = (0..150)
        .map(|i| format!("p{i}:{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "var alias=String.fromCharCode; const table={{{properties}}};\nfor(var i=0;i<1;i++){{output+=String(bytes[i]^1);}}\n/*{}*/\n",
        "fixture ".repeat(600)
    );
    std::fs::write(rules.join("testdata/performance/wide-object.js"), &source).unwrap();

    // A partial rule bundle cannot satisfy the repository-wide allowlist lint.
    // Exclude only that legacy lint; rule-performance remains fully enabled.
    let strict = run(root, "60000", &["--exclude", "validation"]);
    let errors = String::from_utf8_lossy(&strict.stderr);
    assert!(!strict.status.success(), "{errors}");
    assert!(
        errors.contains("::old-tables'") && errors.contains("extreme outlier"),
        "{errors}"
    );
    assert!(
        !errors.contains("rule 'objectives/impact/dos/resource::fixed-"),
        "{errors}"
    );
    assert!(
        !errors.contains("exhausted its CPU budget"),
        "must fail by relative cost before the safety deadline: {errors}"
    );

    let soft = run(root, "60000", &["--exclude", "validation", "--soft"]);
    let errors = String::from_utf8_lossy(&soft.stderr);
    assert!(soft.status.success(), "{errors}");
    assert!(
        errors.contains("extreme outlier") && errors.contains("::old-tables'"),
        "{errors}"
    );

    let excluded = run(root, "60000", &["--exclude", "validation,rule-performance"]);
    assert!(
        excluded.status.success(),
        "{}",
        String::from_utf8_lossy(&excluded.stderr)
    );

    // A safety cutoff is still a soft performance issue, even if the caller
    // raises the ordinary slow-rule ceiling above the query's CPU budget.
    #[cfg(all(unix, not(target_os = "illumos"), not(target_os = "solaris")))]
    {
        let wide = (0..1500)
            .map(|i| format!("p{i}:{i}"))
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(rules.join("testdata/performance/wide-object.js"),
            format!("var alias=String.fromCharCode; const table={{{wide}}}; for(var i=0;i<1;i++){{output+=String(bytes[i]^1);}}" )).unwrap();
        let bounded = run(root, "60000", &["--exclude", "validation"]);
        let errors = String::from_utf8_lossy(&bounded.stderr);
        assert!(
            !bounded.status.success() && errors.contains("AST query exhausted its"),
            "{errors}"
        );
        let bounded_soft = run(root, "60000", &["--exclude", "validation", "--soft"]);
        let errors = String::from_utf8_lossy(&bounded_soft.stderr);
        assert!(
            bounded_soft.status.success() && errors.contains("AST query exhausted its"),
            "budget exhaustion must remain advisory in soft mode: {errors}"
        );
        std::fs::write(rules.join("testdata/performance/wide-object.js"), &source).unwrap();
    }

    // Keep the fixed queries and all peers. They must pass, and a cached pass
    // at this threshold must not mask a subsequent stricter threshold.
    bundle["traits"]
        .as_array_mut()
        .unwrap()
        .retain(|t| !t["id"].as_str().unwrap().starts_with("old-"));
    std::fs::write(&rule_file, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let fixed = run(root, "60000", &["--exclude", "validation"]);
    assert!(
        fixed.status.success(),
        "{}",
        String::from_utf8_lossy(&fixed.stderr)
    );
    let tighter = run(root, "0", &["--exclude", "validation"]);
    let errors = String::from_utf8_lossy(&tighter.stderr);
    assert!(
        !tighter.status.success() && errors.contains("slow-rule threshold 0ms"),
        "{errors}"
    );
    let tighter_soft = run(root, "0", &["--exclude", "validation", "--soft"]);
    let errors = String::from_utf8_lossy(&tighter_soft.stderr);
    assert!(
        tighter_soft.status.success() && errors.contains("slow-rule threshold 0ms"),
        "the whole-rule deadline must remain advisory in soft mode: {errors}"
    );
}
