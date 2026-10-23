//! Offline design probe, not a production retention algorithm.
//! Read a raw cached AnalysisReport, finalize it, and accept context edits only
//! when the existing tiny renderer returns byte-identical output. Check both
//! the joined report and each file viewed independently.
use cleave::{AnalysisReport, FileAnalysis};
use cleave::output::format_tiny;
use cleave::types::ContextLine;
use std::{env, fs, path::Path};

fn standalone(template: &AnalysisReport, file: &FileAnalysis) -> AnalysisReport {
    let mut report = template.clone();
    report.files.clear();
    let mut file = file.clone();
    file.parent_id = None;
    file.depth = 0;
    report.files.push(file);
    report
}

fn slice(original: &ContextLine, start: usize, end: usize) -> ContextLine {
    let mut c = original.clone();
    c.loc += start as u64;
    c.data = original.data[start..end].to_vec();
    if let Some(line) = original.line {
        let prefix = &original.data[..start];
        let lines = prefix.iter().filter(|&&b| b == b'\n').count();
        c.line = Some(line + lines as u64);
        c.col = Some(match prefix.iter().rposition(|&b| b == b'\n') {
            Some(i) => (start - i) as u64,
            None => original.col.unwrap_or(1) + start as u64,
        });
    }
    c
}

fn trim(report: &mut AnalysisReport, expected: &str, calls: &mut usize) {
    let mut w = 0;
    while w < report.files[0].context.len() {
        let original = report.files[0].context.remove(w);
        *calls += 1;
        if format_tiny(report) == expected { continue; }
        report.files[0].context.insert(w, original);
        for leading in [true, false] {
            let original = report.files[0].context[w].clone();
            let n = original.data.len();
            let (mut good, mut bad) = (0, n);
            while good + 1 < bad {
                let k = (good + bad) / 2;
                report.files[0].context[w] = if leading {
                    slice(&original, k, n)
                } else {
                    slice(&original, 0, n - k)
                };
                *calls += 1;
                if format_tiny(report) == expected { good = k; } else { bad = k; }
            }
            report.files[0].context[w] = if leading {
                slice(&original, good, n)
            } else {
                slice(&original, 0, n - good)
            };
        }
        w += 1;
    }
    assert_eq!(format_tiny(report), expected);
}

fn stats(report: &AnalysisReport) -> serde_json::Value {
    let compact = serde_json::to_value(cleave::types::compact_from_files(&report.files)).unwrap();
    serde_json::json!({
        "report_json_bytes": serde_json::to_vec(&compact).unwrap().len(),
        "context_json_bytes": compact["files"].as_array().unwrap().iter()
            .filter_map(|f| f.get("ctx")).map(|v| serde_json::to_vec(v).unwrap().len()).sum::<usize>(),
        "context_decoded_bytes": report.files.iter().flat_map(|f| &f.context).map(|c| c.data.len()).sum::<usize>(),
        "windows": report.files.iter().map(|f| f.context.len()).sum::<usize>(),
        "files": report.files.len(),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    let out = Path::new(&args[2]);
    fs::create_dir_all(out)?;
    let mut report: AnalysisReport = serde_json::from_slice(&fs::read(&args[1])?)?;
    report.finalize();
    report.strip_unmatched_traits();
    let before = stats(&report);
    fs::write(out.join("before.json"), serde_json::to_vec(&cleave::types::compact_from_files(&report.files))?)?;
    let joined = format_tiny(&report);
    fs::write(out.join("before.tiny.txt"), &joined)?;
    let mut calls = 0;
    let mut changed = 0;
    let mut reverted = 0;
    let mut per_file = Vec::new();
    let mut context_edits = Vec::new();
    for i in 0..report.files.len() {
        let original = report.files[i].clone();
        let mut solo = standalone(&report, &original);
        let expected = format_tiny(&solo);
        let bytes_before: usize = original.context.iter().map(|c| c.data.len()).sum();
        trim(&mut solo, &expected, &mut calls);
        let bytes_after: usize = solo.files[0].context.iter().map(|c| c.data.len()).sum();
        if bytes_before == bytes_after { continue; }
        report.files[i].context = solo.files[0].context.clone();
        calls += 1;
        if format_tiny(&report) != joined {
            report.files[i] = original;
            reverted += 1;
        } else {
            changed += 1;
            context_edits.push(serde_json::json!({"before":original.context,
                "after":report.files[i].context}));
            per_file.push(serde_json::json!({"id":original.id,"path":original.path,
                "before":bytes_before,"after":bytes_after}));
        }
    }
    assert_eq!(format_tiny(&report), joined);
    fs::write(out.join("after.json"), serde_json::to_vec(&cleave::types::compact_from_files(&report.files))?)?;
    fs::write(out.join("after.tiny.txt"), format_tiny(&report))?;
    fs::write(out.join("context-edits.json"), serde_json::to_vec(&context_edits)?)?;
    let result = serde_json::json!({"before":before,"after":stats(&report),
        "joined_tiny_equal":true,"standalone_tiny_equal":true,"render_calls":calls,
        "changed_files":changed,"reverted_files":reverted,"per_file":per_file,
        "scope":"greedy whole-window removal and boundary trimming; retained in-memory notes; not compact JSON decode parity or complete scan interpretation pipeline"});
    fs::write(out.join("measurements.json"), serde_json::to_vec_pretty(&result)?)?;
    println!("{}", result);
    Ok(())
}
