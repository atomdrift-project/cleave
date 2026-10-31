//! A low-tier trait survives only when a composite that had it in scope cites
//! it. A sibling member's composite never read the member, so it must not
//! decide what the member's analysis keeps: the same bytes would otherwise
//! analyze differently depending on what shipped beside them.
use std::process::Command;

const TRAITS: &str = r#"
defaults:
  for: [text, php, javascript]
  platforms: [unix, windows]
  conf: 1.0
traits:
  - id: leg
    desc: Shared building block
    crit: component
    if: {type: text, word: sharedleg}
  - id: wrap-leg
    desc: Leg of the bare wrapper
    crit: notable
    if: {type: text, word: wrapleg}
  - id: note
    desc: Ordinary signal
    crit: notable
    if: {type: text, word: notesignal}
  - id: marker-a
    desc: Marker only one member carries
    crit: notable
    if: {type: text, word: markera}
  - id: marker-c
    desc: Marker only the other member carries
    crit: notable
    if: {type: text, word: markerc}
  - id: marker-php
    desc: Marker inside a carved PHP block
    crit: notable
    if: {type: text, word: markerphp}
composite_rules:
  - id: wrap
    desc: Bare wrapper over its leg
    crit: notable
    any:
      - id: wrap-leg
  - id: in-member
    desc: Fires inside one member only
    crit: suspicious
    all:
      - id: marker-a
      - id: leg
      - id: wrap
  - id: in-view
    desc: Fires inside a PHP block carved from JavaScript
    for: [php]
    crit: suspicious
    all:
      - id: marker-php
      - id: wrap
  - id: across-members
    desc: Pools one member's marker with another's leg and wrapper
    for: [all]
    scope: archive
    crit: suspicious
    all:
      - id: marker-c
      - id: leg
      - id: wrap
"#;

/// Each file of the tar of `members`, by path, with the trait ids it keeps.
fn analyze(members: &[(&str, &str)]) -> Vec<(String, Vec<String>)> {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules/micro-behaviors/data/scope");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(rules.join("traits.yaml"), TRAITS).unwrap();
    let archive_path = dir.path().join("members.tar");
    let mut archive = tar::Builder::new(std::fs::File::create(&archive_path).unwrap());
    for (name, body) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, body.as_bytes())
            .unwrap();
    }
    archive.finish().unwrap();
    drop(archive);
    let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
        .env("CLEAVE_TRAITS_DIR", dir.path().join("rules"))
        .env("CLEAVE_SKIP_CACHE", "1")
        .env("FILEFACTS_CACHE", "0")
        .env("STNG_STRING_CACHE", "0")
        .env("CLEAVE_NO_UPDATE_CHECK", "1")
        .args([
            "--disable",
            "yara,radare2,upx",
            "--format",
            "json",
            "analyze",
        ])
        .arg(&archive_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| {
            let ids = file["traits"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t["id"].as_str())
                .map(|id| id.rsplit("::").next().unwrap_or(id).to_string())
                .collect();
            (file["path"].as_str().unwrap_or_default().to_string(), ids)
        })
        .collect()
}

/// The ids kept by the one file whose path ends with `suffix`.
fn kept<'a>(files: &'a [(String, Vec<String>)], suffix: &str) -> &'a [String] {
    let found: Vec<_> = files
        .iter()
        .filter(|(path, _)| path.ends_with(suffix))
        .collect();
    assert_eq!(found.len(), 1, "one file ending {suffix}: {files:?}");
    &found[0].1
}

fn has(ids: &[String], id: &str) -> bool {
    ids.iter().any(|kept| kept == id)
}

#[test]
fn a_sibling_members_composite_keeps_nothing_in_another_member() {
    let files = analyze(&[
        ("a.txt", "markera sharedleg wrapleg notesignal\n"),
        ("b.txt", "sharedleg wrapleg notesignal\n"),
    ]);
    let a = kept(&files, "!!a.txt");
    assert!(
        has(a, "in-member") && has(a, "wrap") && has(a, "leg"),
        "{files:?}"
    );
    let b = kept(&files, "!!b.txt");
    assert!(has(b, "note"), "{files:?}");
    assert!(
        !has(b, "wrap"),
        "the bare wrapper a.txt's composite cited: {files:?}"
    );
    assert!(
        !has(b, "leg"),
        "the component a.txt's composite cited: {files:?}"
    );
}

#[test]
fn an_archive_scoped_composite_keeps_what_it_cites_in_its_members() {
    let files = analyze(&[
        ("b.txt", "sharedleg wrapleg notesignal\n"),
        ("c.txt", "markerc notesignal\n"),
    ]);
    assert!(
        has(kept(&files, "members.tar"), "across-members"),
        "{files:?}"
    );
    let b = kept(&files, "!!b.txt");
    assert!(has(b, "wrap") && has(b, "leg"), "{files:?}");
}

#[test]
fn a_composite_in_a_carved_php_block_keeps_nothing_in_a_sibling() {
    // OpenX 2.8.10, reduced: a backdoor in a bundled player's string literal,
    // which PHP's include runs, beside an ordinary PHP member.
    const PLAYER: &str = "var undefinedType = \"<?php $markerphp = 'wrapleg'; ?>\";\nplay();\n";
    let files = analyze(&[
        ("player.js", PLAYER),
        ("init.php", "<?php\n// wrapleg notesignal\necho 1;\n"),
    ]);
    let at = PLAYER.find("<?php").unwrap();
    let view = kept(&files, &format!("!!player.js##embedded-php@{at}"));
    assert!(has(view, "in-view") && has(view, "wrap"), "{files:?}");
    let member = kept(&files, "!!init.php");
    assert!(has(member, "note"), "{files:?}");
    assert!(
        !has(member, "wrap"),
        "cited only inside the carved block: {files:?}"
    );
}
