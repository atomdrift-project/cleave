//! Regression test for nondeterministic finding loss during parallel archive
//! member analysis.
//!
//! Symptom (observed on the `realworld-small` benchmark, May 2026): analyzing
//! the same archive repeatedly yields a *varying* finding count. The drift
//! concentrates in `type: tree-sitter` `query:` traits with `count_min`
//! thresholds (e.g. `js-date-loop`) on source-code members, and toggles
//! all-or-nothing across all members at once — pointing at a shared,
//! process-global resource raced during the parallel member fan-out rather
//! than per-member logic. A single file analyzed alone is deterministic; only
//! the in-archive, parallel path drifts.
//!
//! This test reproduces it deterministically-fails by analyzing a zip of many
//! `.ts` members (each triggering `js-date-loop` via 3+ `new Date()`) a number
//! of times and asserting the finding count is identical every run.

use std::io::Write;
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn num_cpus_guess() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4)
}

/// A TypeScript source whose body contains several `new Date()` constructions,
/// which the `js-date-loop` trait (`count_min: 3`) matches.
fn ts_member_source(i: usize) -> String {
    format!(
        r#"// module {i}
export function elapsed{i}(): number {{
    const t0 = new Date();
    doWork();
    const t1 = new Date();
    doWork();
    const t2 = new Date();
    const t3 = new Date();
    return t3.getTime() - t0.getTime() + t1.getTime() - t2.getTime();
}}
function doWork(): void {{
    for (let k = 0; k < 10; k++) {{ /* spin */ }}
}}
"#
    )
}

/// Minimal but valid sources in several languages. The point is to make many
/// *distinct* tree-sitter AST queries run (one set per file type), pressuring
/// the process-global compiled-query LRU (`QUERY_CACHE`, 256 entries) past its
/// eviction threshold — the condition the real multi-language archive hit and a
/// pure-`.ts` archive does not.
fn polyglot_members() -> Vec<(&'static str, String)> {
    vec![
        ("a.go", "package main\nimport \"os\"\nfunc main() { os.Getpid(); _, _ = os.Hostname(); os.Remove(\"x\") }\n".into()),
        ("b.py", "import os\nos.remove('x')\nos.getpid()\nfor i in range(3):\n    print(i)\n".into()),
        ("c.rb", "require 'json'\nJSON.parse('{}')\n[1,2,3].each { |x| puts x }\n".into()),
        ("d.java", "class C { void m() { for (int i=0;i<3;i++) { System.out.println(i); } } }\n".into()),
        ("e.c", "#include <stdio.h>\nint main(){ for(int i=0;i<3;i++) printf(\"%d\", i); return 0; }\n".into()),
        ("f.js", "const x = fetch('http://h/'); JSON.parse('{}'); Math.random();\n".into()),
        ("g.rs", "fn main() { for i in 0..3 { println!(\"{}\", i); } }\n".into()),
        ("h.sh", "#!/bin/sh\nfetch -o out http://h/\nfor i in 1 2 3; do echo $i; done\n".into()),
    ]
}

fn build_zip(path: &std::path::Path, ts_members: usize) -> anyhow::Result<()> {
    let file = std::fs::File::create(path)?;
    let mut zip = zip::ZipWriter::new(file);
    let opts = zip::write::FileOptions::<()>::default();
    // The js-date-loop canary members.
    for i in 0..ts_members {
        zip.start_file(format!("src/store/module{i}.ts"), opts)?;
        zip.write_all(ts_member_source(i).as_bytes())?;
    }
    // Polyglot members to pressure the shared compiled-query cache.
    let poly = polyglot_members();
    for rep in 0..16 {
        for (name, src) in &poly {
            zip.start_file(format!("lib{rep}/{name}"), opts)?;
            zip.write_all(src.as_bytes())?;
        }
    }
    zip.finish()?;
    Ok(())
}

/// Count findings whose id is the `js-date-loop` trait, across all member files.
fn js_date_loop_count(report: &cleave::AnalysisReport) -> usize {
    report
        .files
        .iter()
        .flat_map(|f| f.findings.iter())
        .filter(|finding| finding.id.ends_with("::js-date-loop"))
        .count()
}

fn total_findings(report: &cleave::AnalysisReport) -> usize {
    report.files.iter().map(|f| f.findings.len()).sum()
}

#[test]
fn archive_member_findings_are_deterministic() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .map_err(|e| anyhow::anyhow!("env lock poisoned: {e}"))?;

    let work = tempfile::tempdir()?;
    let zip_path = work.path().join("ts-modules.zip");
    const MEMBERS: usize = 120;
    build_zip(&zip_path, MEMBERS)?;

    // Saturate the CPU with background spinners so the rayon member pool is
    // contended — the observed drift was timing/scheduling sensitive (worse
    // under load / on battery). This makes the wall-clock-deadline and any
    // order-dependent shared state far more likely to surface.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spinners: Vec<_> = (0..usize::max(2, num_cpus_guess()))
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut x = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                    std::hint::black_box(x);
                }
            })
        })
        .collect();

    // Each analyze_file call must do real work — a cache hit would mask the race.
    cleave::cache::set_skip_cache_override(Some(true));

    // YARA/radare2 are irrelevant to the AST-query drift and only slow the test;
    // the tree-sitter path stays enabled.
    let options = cleave::AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    };

    const RUNS: usize = 40;
    let mut jdl_counts = std::collections::BTreeSet::new();
    let mut total_counts = std::collections::BTreeSet::new();
    let mut first_jdl = None;

    for run in 0..RUNS {
        let report = cleave::analyze_file(&zip_path, &options)?;
        let jdl = js_date_loop_count(&report);
        let total = total_findings(&report);
        if first_jdl.is_none() {
            first_jdl = Some(jdl);
            // Sanity: the trait must actually fire, or the test proves nothing.
            assert!(
                jdl > 0,
                "js-date-loop did not match any member on run {run}; \
                 test fixture no longer triggers the trait (got 0)"
            );
        }
        jdl_counts.insert(jdl);
        total_counts.insert(total);
    }

    cleave::cache::set_skip_cache_override(None);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for s in spinners {
        let _ = s.join();
    }

    assert_eq!(
        jdl_counts.len(),
        1,
        "js-date-loop finding count drifted across {RUNS} runs of the same archive: \
         observed counts {jdl_counts:?} (expected all {MEMBERS}). Nondeterministic \
         finding loss in parallel member analysis."
    );
    assert_eq!(
        total_counts.len(),
        1,
        "total member finding count drifted across {RUNS} runs: {total_counts:?}"
    );

    Ok(())
}
