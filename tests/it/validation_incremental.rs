//! `cleave validate` re-analyzes only the fixtures an edit can have changed:
//! a rule reaches fixtures through the file types its `for:` admits, and
//! through every rule that references it. These tests pin which fixtures
//! each kind of edit re-analyzes, and that the edits it must see are seen.
//! Reuse that quietly stopped happening would only show as a slow run, and
//! reuse that quietly widened would only show as a missed regression, so
//! both directions are asserted.
use std::path::PathBuf;
use std::process::{Command, Output};

struct Tree {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Tree {
    fn rules(&self) -> PathBuf {
        self.root.join("rules")
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.rules().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn run(&self) -> Run {
        self.run_with(&[])
    }

    /// A validation run with `extra` arguments after `validate`'s own.
    fn run_with(&self, extra: &[&str]) -> Run {
        static INVOCATION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let invocation = INVOCATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
            .env(
                "CODEX_TOOL_CALL_ID",
                format!("incremental-test-{invocation}"),
            )
            .env_remove("CLEAVE_SKIP_CACHE")
            .env_remove("CLEAVE_SKIP_MAPPER_CACHE")
            .env_remove("CLEAVE_SKIP_CLEAN_MARK")
            .env_remove("CLEAVE_TRAIT_TIMING")
            .env_remove("CLEAVE_PHASE_STATS")
            .env("CLEAVE_CACHE_DIR", self.root.join("cache"))
            .env("CLEAVE_RAYON_THREADS", "4")
            .env("CLEAVE_VALIDATE_SOFT", "0")
            .env("RUST_LOG", "cleave=info")
            .env("CLEAVE_NO_UPDATE_CHECK", "1")
            .args(["--slow-rule-ms", "60000", "--traits-dir"])
            .arg(self.rules())
            // A partial rule bundle cannot satisfy the repository-wide
            // allowlist lint, and a rule for every type trips the file-type
            // cap; everything else stays enabled.
            .args(["validate", "--exclude", "validation,ft-cap"])
            .args(extra)
            .output()
            .unwrap();
        Run::from(output)
    }
}

struct Run {
    output: Output,
    stdout: String,
    stderr: String,
}

impl From<Output> for Run {
    fn from(output: Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        Self {
            output,
            stdout,
            stderr,
        }
    }
}

impl Run {
    fn ok(&self) -> bool {
        self.output.status.success()
    }

    fn field(&self, line_marker: &str, field: &str) -> Option<usize> {
        let line = self.stderr.lines().find(|l| l.contains(line_marker))?;
        let value = line.split(&format!("{field}=")).nth(1)?;
        value
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()
    }

    /// How many fixtures this run analyzed and how many it reused.
    fn analyzed_and_reused(&self) -> (usize, usize) {
        let marker = "validation phase timings";
        let count = |field: &str| {
            self.field(marker, field).unwrap_or_else(|| {
                panic!(
                    "no {field} count in the log:
{}",
                    self.stderr
                )
            })
        };
        (count("analyzed"), count("reused"))
    }

    fn cache_hit(&self) -> bool {
        self.stderr.contains("full validation cache hit")
    }
}

fn trait_file(for_types: &str, id: &str, crit: &str, substr: &str) -> String {
    format!(
        "defaults:\n  for: [{for_types}]\n  platforms: [unix, windows]\n  crit: {crit}\n  conf: 0.9\ntraits:\n  - id: {id}\n    desc: Marker {id}\n    if: {{type: text, substr: {substr}}}\n"
    )
}

/// Four fixtures of three types, and a rule per type. The composite in
/// `objectives/` references the JavaScript and Python markers and applies
/// to both types, so each marker file's scope reaches the other's fixtures.
fn tree() -> Tree {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let tree = Tree { _dir: dir, root };
    for sub in [
        "testdata/hostile",
        "testdata/suspicious",
        "testdata/notable/js",
        "testdata/notable/py",
        "testdata/baseline/sh",
        "testdata/baseline/js",
    ] {
        std::fs::create_dir_all(tree.rules().join(sub)).unwrap();
    }
    tree.write(
        "metadata/lang/source/shape/js.yaml",
        &trait_file("javascript", "js-marker", "notable", "js_marker"),
    );
    tree.write(
        "metadata/lang/source/shape/py.yaml",
        &trait_file("python", "py-marker", "notable", "py_marker"),
    );
    tree.write(
        "metadata/lang/source/shape/sh.yaml",
        &trait_file("shell", "sh-marker", "notable", "sh_marker"),
    );
    tree.write(
        "objectives/impact/dos/resource/combo.yaml",
        "defaults:\n  for: [javascript, python]\n  platforms: [unix, windows]\n  crit: notable\n  conf: 0.9\ncomposite_rules:\n  - id: scripted-marker\n    desc: A marker in a script\n    any:\n      - id: metadata/lang/source/shape::js-marker\n      - id: metadata/lang/source/shape::py-marker\n",
    );
    tree.write("testdata/notable/js/a.js", "console.log('js_marker');\n");
    tree.write("testdata/notable/py/a.py", "print('py_marker')\n");
    tree.write("testdata/baseline/sh/a.sh", "#!/bin/sh\necho ready\n");
    tree.write("testdata/baseline/js/b.js", "console.log('nothing');\n");
    tree
}

#[test]
fn edits_reanalyze_only_the_fixtures_their_scope_reaches() {
    let tree = tree();
    let first = tree.run();
    assert!(first.ok(), "{}", first.stderr);
    assert_eq!(first.analyzed_and_reused(), (4, 0), "{}", first.stderr);

    // Nothing changed: the result is replayed without analysis.
    let replay = tree.run();
    assert!(replay.ok() && replay.cache_hit(), "{}", replay.stderr);

    // A shell rule reaches the one shell fixture and nothing else.
    tree.write(
        "metadata/lang/source/shape/sh.yaml",
        &format!(
            "{}  - id: sh-other\n    desc: Another shell marker\n    if: {{type: text, substr: never_present}}\n",
            trait_file("shell", "sh-marker", "notable", "sh_marker")
        ),
    );
    let shell_edit = tree.run();
    assert!(shell_edit.ok(), "{}", shell_edit.stderr);
    assert_eq!(
        shell_edit.analyzed_and_reused(),
        (1, 3),
        "{}",
        shell_edit.stderr
    );

    // The Python marker feeds a composite that applies to JavaScript too, but
    // that composite can only change where the marker's own findings do: a
    // Python edit reaches the Python fixture alone.
    tree.write(
        "metadata/lang/source/shape/py.yaml",
        &format!(
            "{}  - id: py-other\n    desc: Another Python marker\n    if: {{type: text, substr: never_present}}\n",
            trait_file("python", "py-marker", "notable", "py_marker")
        ),
    );
    let python_edit = tree.run();
    assert!(python_edit.ok(), "{}", python_edit.stderr);
    assert_eq!(
        python_edit.analyzed_and_reused(),
        (1, 3),
        "{}",
        python_edit.stderr
    );

    // Editing the composite itself reaches the types it applies to.
    tree.write(
        "objectives/impact/dos/resource/combo.yaml",
        "defaults:\n  for: [javascript, python]\n  platforms: [unix, windows]\n  crit: notable\n  conf: 0.9\ncomposite_rules:\n  - id: scripted-marker\n    desc: A marker in a script file\n    any:\n      - id: metadata/lang/source/shape::js-marker\n      - id: metadata/lang/source/shape::py-marker\n",
    );
    let composite_edit = tree.run();
    assert!(composite_edit.ok(), "{}", composite_edit.stderr);
    assert_eq!(
        composite_edit.analyzed_and_reused(),
        (3, 1),
        "{}",
        composite_edit.stderr
    );

    // A fixture's own bytes changing re-analyzes that fixture alone.
    tree.write("testdata/baseline/sh/a.sh", "#!/bin/sh\necho still ready\n");
    let fixture_edit = tree.run();
    assert!(fixture_edit.ok(), "{}", fixture_edit.stderr);
    assert_eq!(
        fixture_edit.analyzed_and_reused(),
        (1, 3),
        "{}",
        fixture_edit.stderr
    );
}

#[test]
fn edits_that_change_a_verdict_are_seen() {
    let tree = tree();
    assert!(tree.run().ok());

    // A trait added to an existing file fires on a fixture of its type.
    tree.write(
        "metadata/lang/source/shape/js.yaml",
        &format!(
            "{}  - id: js-nothing\n    desc: Logs nothing\n    if: {{type: text, substr: nothing}}\n",
            trait_file("javascript", "js-marker", "notable", "js_marker")
        ),
    );
    let added = tree.run();
    assert!(!added.ok(), "{}", added.stderr);
    assert!(
        added.stderr.contains("b.js: expected B, found N"),
        "{}",
        added.stderr
    );
    // Only the JavaScript fixtures had a part in it.
    assert_eq!(added.analyzed_and_reused(), (2, 2), "{}", added.stderr);

    // Put the file back: the tree is byte for byte the one that passed, and
    // that pass is replayed; the failure is replayed from nowhere.
    tree.write(
        "metadata/lang/source/shape/js.yaml",
        &trait_file("javascript", "js-marker", "notable", "js_marker"),
    );
    let restored = tree.run();
    assert!(restored.ok() && restored.cache_hit(), "{}", restored.stderr);

    // A severity change on an existing trait changes a verdict (a lone
    // atomic trait is not let be hostile, but it is no longer baseline).
    tree.write(
        "metadata/lang/source/shape/sh.yaml",
        &trait_file("shell", "sh-marker", "hostile", "sh_marker"),
    );
    tree.write("testdata/baseline/sh/a.sh", "#!/bin/sh\necho sh_marker\n");
    let hostile = tree.run();
    assert!(!hostile.ok(), "{}", hostile.stderr);
    assert!(
        hostile.stderr.contains("a.sh: expected B, found"),
        "{}",
        hostile.stderr
    );

    // A rule file that goes away takes its scope with it: the shell fixture
    // is analyzed again and passes without the rule.
    std::fs::remove_file(tree.rules().join("metadata/lang/source/shape/sh.yaml")).unwrap();
    let removed = tree.run();
    assert!(removed.ok(), "{}", removed.stderr);
    assert_eq!(removed.analyzed_and_reused(), (1, 3), "{}", removed.stderr);

    // A new rule file applying to every fixture's type reaches them all.
    tree.write(
        "metadata/lang/source/shape/any.yaml",
        &trait_file(
            "javascript, python, shell",
            "any-marker",
            "notable",
            "never_present_anywhere",
        ),
    );
    let everywhere = tree.run();
    assert!(everywhere.ok(), "{}", everywhere.stderr);
    assert_eq!(
        everywhere.analyzed_and_reused(),
        (4, 0),
        "{}",
        everywhere.stderr
    );
}

#[test]
fn a_different_engine_or_settings_analyzes_everything() {
    let tree = tree();
    assert!(tree.run().ok());
    // The recorded state is keyed on the build and the run's settings; a
    // state written for other settings is not consulted.
    let state: Vec<PathBuf> = std::fs::read_dir(tree.root.join("cache"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("validate-fixtures-"))
        })
        .collect();
    assert_eq!(state.len(), 1, "{state:?}");
    let slow = Command::new(env!("CARGO_BIN_EXE_cleave"))
        .env("CLEAVE_CACHE_DIR", tree.root.join("cache"))
        .env("CLEAVE_RAYON_THREADS", "4")
        .env("RUST_LOG", "cleave=info")
        .env("CLEAVE_NO_UPDATE_CHECK", "1")
        .args(["--slow-rule-ms", "30000", "--traits-dir"])
        .arg(tree.rules())
        .args(["validate", "--exclude", "validation,ft-cap"])
        .output()
        .unwrap();
    let slow = Run::from(slow);
    assert!(slow.ok(), "{}", slow.stderr);
    assert_eq!(slow.analyzed_and_reused(), (4, 0), "{}", slow.stderr);
}

/// `--slow-rules` audits a full, uncached validation: it neither replays a
/// cached verdict nor reuses unchanged fixtures, lists the costliest rules
/// with the shape of their conditions, and leaves the caches of ordinary
/// runs as they were.
#[test]
fn slow_rule_audit_measures_every_fixture_without_disturbing_the_cache() {
    let tree = tree();
    let first = tree.run();
    assert!(first.ok(), "{}", first.stderr);

    let audit = tree.run_with(&["--slow-rules", "50"]);
    assert!(audit.ok(), "{}", audit.stderr);
    assert!(!audit.cache_hit(), "{}", audit.stderr);
    assert_eq!(audit.analyzed_and_reused(), (4, 0), "{}", audit.stderr);
    assert!(
        audit
            .stdout
            .contains("Slowest rules by total evaluation time"),
        "{}",
        audit.stdout
    );
    for (id, shape) in [
        (
            "metadata/lang/source/shape::js-marker",
            "for: javascript  if: text/substr",
        ),
        (
            "objectives/impact/dos/resource::scripted-marker",
            "if: any(trait)",
        ),
    ] {
        let at = audit.stdout.find(id).unwrap_or_else(|| {
            panic!(
                "{id} missing from the audit:
{}",
                audit.stdout
            )
        });
        assert!(
            audit.stdout[at..]
                .lines()
                .nth(1)
                .is_some_and(|l| l.contains(shape)),
            "{id} should read `{shape}`:
{}",
            audit.stdout
        );
    }

    let replay = tree.run();
    assert!(replay.ok() && replay.cache_hit(), "{}", replay.stderr);
}
