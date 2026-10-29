//! A single worker makes explicit-path admission observable through real reports.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cleave::{AnalysisOptions, ScanEvent};
use std::sync::Mutex;

#[test]
fn explicit_paths_start_with_largest_input() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("traits/metadata");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(rules.join("test.yaml"), "traits:\n  - id: harmless\n    desc: Harmless fixture marker\n    crit: notable\n    if: {type: raw, substr: harmless}\n").unwrap();
    cleave::traits_repo::set_override_dir(Some(dir.path().join("traits")));
    let paths: Vec<_> = [1, 32, 8]
        .into_iter()
        .map(|n| {
            let path = dir.path().join(format!("{n}.txt"));
            std::fs::write(&path, "harmless fixture text\n".repeat(n)).unwrap();
            path
        })
        .collect();
    let completed = Mutex::new(Vec::new());
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let summary = pool
        .install(|| {
            cleave::scan_files(&paths, &AnalysisOptions::default(), |event| {
                if let ScanEvent::File { path, result } = event {
                    assert!(result.is_ok());
                    completed.lock().unwrap().push(path);
                }
            })
        })
        .unwrap();
    assert_eq!(summary.analyzed, 3);
    assert_eq!(summary.errors, 0);
    assert_eq!(
        *completed.lock().unwrap(),
        vec![paths[1].clone(), paths[2].clone(), paths[0].clone()]
    );
    cleave::traits_repo::set_override_dir(None);
}
