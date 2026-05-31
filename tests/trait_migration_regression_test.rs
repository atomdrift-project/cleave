//! Regression tests for `query:` → `type: symbol` trait migrations.
//!
//! Each migrated trait must keep firing on the same positives its original
//! tree-sitter query matched, and (where the migration also tightened the rule)
//! must reject the noise the broad query used to flag. These synthetic fixtures
//! are the "no loss of functionality" proof the migration requires — see the
//! `cleave facts` symbol/call/member projections that replace the per-member
//! tree-sitter cursor walk.

use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// The sibling `cleave-traits` checkout (this crate is `<workspace>/cleave`).
fn traits_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../cleave-traits")
}

/// Analyze `src` as a file named `name` against the local traits checkout and
/// report whether any fired trait id ends with `id_suffix` (e.g. `::mss-grab`).
/// The traits-dir override is process-wide, so the env lock serializes access.
#[allow(clippy::expect_used)]
fn fires(id_suffix: &str, name: &str, src: &str) -> bool {
    let _guard = env_lock().lock().expect("env lock poisoned");
    let td = traits_dir();
    if !td.is_dir() {
        // No local traits checkout (e.g. packaged-crate CI) — skip rather than
        // fail; the migration is exercised wherever the checkout is present.
        eprintln!("skipping: traits dir {} not found", td.display());
        return true;
    }
    cleave::traits_repo::set_override_dir(Some(td));
    let opts = cleave::AnalysisOptions::default();
    let report = cleave::analyze_bytes(src.as_bytes(), name, &opts).expect("analyze");
    cleave::traits_repo::set_override_dir(None);
    report.findings.iter().any(|f| f.id.ends_with(id_suffix))
}

/// `mss-grab` migrated from `(call (attribute attribute:(identifier) @method)
/// (#eq? @method "grab"))` to `type: symbol, kind: call` against the pre-extracted
/// call fact — and tightened to known screen-capture receivers so generic
/// `.grab()` calls no longer false-positive.
#[test]
fn mss_grab_migration_preserves_positives_and_drops_noise() {
    // Positives — real screen-capture grabs still fire.
    assert!(
        fires(
            "::mss-grab",
            "cap_mss.py",
            "import mss\nwith mss.mss() as sct:\n    img = sct.grab(monitor)\n",
        ),
        "mss `sct.grab(monitor)` must still fire mss-grab",
    );
    assert!(
        fires(
            "::mss-grab",
            "cap_pil.py",
            "from PIL import ImageGrab\nImageGrab.grab()\n",
        ),
        "PIL `ImageGrab.grab()` must still fire mss-grab",
    );

    // Negatives — the tightened rule drops generic `.grab()` noise the old
    // query flagged (queue/lock/grabber/arbitrary receivers).
    assert!(
        !fires("::mss-grab", "noise1.py", "q.grab()\nlock.grab()\n"),
        "generic `.grab()` (queue/lock) must NOT fire the tightened mss-grab",
    );
    assert!(
        !fires(
            "::mss-grab",
            "noise2.py",
            "x.grabber()\nresult = data.grab()\n"
        ),
        "near-misses (`.grabber()`, arbitrary `.grab()`) must NOT fire mss-grab",
    );
}
