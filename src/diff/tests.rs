use super::*;

#[test]
fn versioned_archive_roots_pair_before_scope_diffing() {
    let mut old = vec![DiffUnit::empty("<root>!!openx-2.8.9/adg.js".to_string())];
    let mut new = vec![DiffUnit::empty("<root>!!openx-2.8.10/adg.js".to_string())];
    old[0].sha = "same-bytes".to_string();
    new[0].sha = "same-bytes".to_string();

    normalize_versioned_archive_roots(&mut old, &mut new);

    assert_eq!(old[0].path, "<root>!!openx/adg.js");
    assert_eq!(old[0].path, new[0].path);
    let pairs = pair_units(old, new);
    assert_eq!(pairs.len(), 1);
    let entry = diff_pair(pairs.into_iter().next().unwrap(), ScopeMask::all(), 100);
    assert_eq!(entry.status, FileStatus::Unchanged);
}

#[test]
fn ambiguous_or_literal_archive_roots_are_not_collapsed() {
    let mut old = vec![
        DiffUnit::empty("<root>!!sdk-1.0/a.js".to_string()),
        DiffUnit::empty("<root>!!sdk-2.0/b.js".to_string()),
    ];
    let mut new = vec![DiffUnit::empty("<root>!!sdk-3.0/a.js".to_string())];
    normalize_versioned_archive_roots(&mut old, &mut new);
    assert_eq!(old[0].path, "<root>!!sdk-1.0/a.js");
    assert_eq!(new[0].path, "<root>!!sdk-3.0/a.js");

    let mut old = vec![
        DiffUnit::empty("<root>!!pkg/a.js".to_string()),
        DiffUnit::empty("<root>!!pkg-1.0/b.js".to_string()),
    ];
    let mut new = vec![DiffUnit::empty("<root>!!pkg-1.1/b.js".to_string())];
    normalize_versioned_archive_roots(&mut old, &mut new);
    assert_eq!(old[1].path, "<root>!!pkg-1.0/b.js");
    assert_eq!(new[0].path, "<root>!!pkg-1.1/b.js");
}

#[test]
fn stable_versioned_archive_name_matches_isomer_detection() {
    assert_eq!(
        stable_versioned_name("openx-2.8.10").as_deref(),
        Some("openx")
    );
    assert_eq!(
        stable_versioned_name("node-ipc-12.0.1").as_deref(),
        Some("node-ipc")
    );
    // durabletask's sdists: a development release beside a final one.
    for root in [
        "durabletask-1.4.0.dev34",
        "durabletask-1.4.1",
        "durabletask-2.0.0rc1",
        "durabletask-2.0.0b2",
        "durabletask-2.0.0.post1",
        "durabletask-2.0.0-beta.1",
    ] {
        assert_eq!(
            stable_versioned_name(root).as_deref(),
            Some("durabletask"),
            "{root}"
        );
    }
    // A trailing word is part of the name, not a qualifier.
    assert_eq!(stable_versioned_name("sdk-1.0-b").as_deref(), Some("sdk-b"));
    assert_eq!(
        stable_versioned_name("sdk-1.0-src").as_deref(),
        Some("sdk-src")
    );
    assert_eq!(stable_versioned_name("index.js"), None);
    // A leading pure version has no package identity to pair safely.
    assert_eq!(stable_versioned_name("1.2.3"), None);
}

/// `.git` is skipped because it is thousands of files of object store, not
/// because it starts with a dot. The distinction is load-bearing: a prefix
/// match on `.git` also swallowed `.github`, so every CI workflow — where a
/// supply-chain change to the build lands — was invisible to a directory
/// diff, along with `.gitignore` and `.gitattributes`.
#[test]
fn walk_skips_the_git_store_but_not_dot_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for (path, body) in [
        (".github/workflows/ci.yml", "uses: actions/checkout@v4\n"),
        (".git/objects/ab/cdef", "object store\n"),
        (".git/config", "[core]\n"),
        (".gitignore", "target/\n"),
        (".config/tool.toml", "k = 1\n"),
        ("src/main.rs", "fn main() {}\n"),
    ] {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(&full, body).unwrap();
    }

    let found: Vec<String> = walk_files(root)
        .unwrap()
        .into_iter()
        .map(|(_, rel)| rel.replace('\\', "/"))
        .collect();

    assert!(
        !found.iter().any(|p| p.starts_with(".git/")),
        "the object store must stay out of the diff: {found:?}"
    );
    for expected in [
        ".github/workflows/ci.yml",
        ".gitignore",
        ".config/tool.toml",
        "src/main.rs",
    ] {
        assert!(
            found.iter().any(|p| p == expected),
            "{expected} must be analyzed, got {found:?}"
        );
    }
}

#[test]
fn scope_mask_parse_default() {
    assert!(ScopeMask::parse("").unwrap().traits);
    assert!(ScopeMask::parse("all").unwrap().sections);
}

#[test]
fn scope_mask_parse_subset() {
    let m = ScopeMask::parse("traits,value").unwrap();
    assert!(m.traits);
    assert!(m.kv);
    assert!(!m.metrics);
    assert!(!m.symbols);
    assert!(!m.strings);
    assert!(!m.sections);
}

#[test]
fn scope_mask_parse_unknown() {
    assert!(ScopeMask::parse("traits,bogus").is_err());
}

#[test]
fn pair_units_orders_by_path() {
    let old = vec![DiffUnit::empty("b".into()), DiffUnit::empty("a".into())];
    let new = vec![DiffUnit::empty("c".into())];
    let pairs = pair_units(old, new);
    assert_eq!(
        pairs.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
        vec!["a", "b", "c"]
    );
}

#[test]
fn unchanged_hostile_file_retains_formula_and_visibility() {
    let hostile = Finding {
        id: "objectives/supply-chain/install-hook/build/autotools::loader".into(),
        desc: "Persistent hostile loader".into(),
        conf: 0.99,
        crit: crate::types::Criticality::Hostile,
        ..Finding::default()
    };
    let mut old = DiffUnit::empty("m4/loader.m4".into());
    old.findings.push(hostile.clone());
    let mut new = DiffUnit::empty("m4/loader.m4".into());
    new.findings.push(hostile);

    let entry = diff_pair(
        UnitPair {
            path: "m4/loader.m4".into(),
            old: Some(old),
            new: Some(new),
        },
        ScopeMask::all(),
        DEFAULT_LIMIT_CHANGES,
    );

    assert_eq!(entry.status, FileStatus::Unchanged);
    assert!(entry.old_formula.is_some());
    assert_eq!(entry.old_formula, entry.new_formula);
    assert!(visible_diff_file(&entry));
}

#[test]
fn aggregate_trait_cap_keeps_high_signal_from_later_files() {
    let mut noisy = DiffUnit::empty("a-noisy.c".into());
    noisy.findings = (0..100)
        .map(|i| Finding {
            id: format!("metadata/noise/{i:03}").into(),
            desc: "baseline noise".into(),
            crit: crate::types::Criticality::Baseline,
            ..Finding::default()
        })
        .collect();
    let mut hostile = DiffUnit::empty("z-payload.c".into());
    hostile.findings.push(Finding {
        id: "objectives/command-and-control/remote-shell".into(),
        desc: "hostile remote shell".into(),
        conf: 0.99,
        crit: crate::types::Criticality::Hostile,
        ..Finding::default()
    });

    let entries = vec![
        diff_pair(
            UnitPair {
                path: noisy.path.clone(),
                old: None,
                new: Some(noisy),
            },
            ScopeMask::all(),
            DEFAULT_LIMIT_CHANGES,
        ),
        diff_pair(
            UnitPair {
                path: hostile.path.clone(),
                old: None,
                new: Some(hostile),
            },
            ScopeMask::all(),
            DEFAULT_LIMIT_CHANGES,
        ),
    ];

    let scopes = aggregate_scopes(&entries, ScopeMask::all(), DEFAULT_LIMIT_CHANGES);
    let traits = scopes.traits.unwrap();
    assert_eq!(traits.added.len(), DEFAULT_LIMIT_CHANGES);
    assert!(traits.truncated);
    assert_eq!(traits.added[0].crit, crate::types::Criticality::Hostile);
    assert!(
        traits
            .added
            .iter()
            .any(|finding| finding.id.ends_with("remote-shell"))
    );
}

#[test]
fn ordinary_unchanged_file_stays_hidden() {
    let entry = diff_pair(
        UnitPair {
            path: "README".into(),
            old: Some(DiffUnit::empty("README".into())),
            new: Some(DiffUnit::empty("README".into())),
        },
        ScopeMask::all(),
        DEFAULT_LIMIT_CHANGES,
    );
    assert_eq!(entry.status, FileStatus::Unchanged);
    assert!(!visible_diff_file(&entry));
}

#[test]
fn diff_entry_keeps_content_detected_file_type() {
    let mut new = DiffUnit::empty("payload".into());
    new.file_type = "elf".into();
    new.findings.push(Finding {
        id: "metadata/binary/format::elf".into(),
        crit: crate::types::Criticality::Notable,
        ..Finding::default()
    });

    let entry = diff_pair(
        UnitPair {
            path: new.path.clone(),
            old: None,
            new: Some(new),
        },
        ScopeMask::all(),
        DEFAULT_LIMIT_CHANGES,
    );

    assert_eq!(entry.file_type.as_deref(), Some("elf"));
}
