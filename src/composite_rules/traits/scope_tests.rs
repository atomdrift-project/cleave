//! Unit tests for the composite-rule `scope:` field.
//!
//! Two layers are exercised:
//!
//! 1. [`Scope::key`] — pure function; covers every value × every
//!    `Evidence.location` shape cleave produces today.
//! 2. [`CompositeTrait::apply_scope_filter`] — given fixture
//!    evidence + tagged_locations, asserts which scope bucket the
//!    filter selects and that evidence outside that bucket is
//!    dropped.

use super::*;

fn tag(condition_index: usize, location: &str) -> TaggedLocation {
    TaggedLocation {
        byte_offset: None,
        location: Some(location.to_string()),
        condition_index,
    }
}

fn ev(location: &str) -> Evidence {
    Evidence {
        method: "test".to_string(),
        source: String::new(),
        value: String::new(),
        location: Some(location.to_string()),
        offsets: Vec::new(),
        count: 0,
        match_len: None,
        alt_value: None,
    }
}

/// Build a minimal CompositeTrait fixture for filter tests. The
/// dummy `all:` slot of length `n_conditions` ensures
/// `min_distinct_conditions()` returns `n_conditions`.
fn composite_with(n_conditions: usize, scope: Option<Scope>) -> CompositeTrait {
    let conds = (0..n_conditions)
        .map(|_| {
            Condition::Symbol(SymbolQuery {
                exact: Some("x".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
                module_level: false,
                receiver: None,
            })
        })
        .collect();
    CompositeTrait {
        id: "t".to_string(),
        desc: String::new(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: default_platforms(),
        arch: default_architectures(),
        r#for: default_file_types(),
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(conds),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope,
        unless: None,
        not: None,
        downgrade: None,
        exempt: Box::default(),
        defined_in: std::path::PathBuf::new(),
        precision: None,
        required_trait_indices: Vec::new(),
        ..Default::default()
    }
}

// ----- Scope::key -------------------------------------------------------

#[test]
fn outer_collapses_every_location_to_empty_string() {
    for loc in [
        None,
        Some("archive:foo.zip!bar.so"),
        Some("encoding_chain:base64+zlib"),
        Some("0x1234"),
    ] {
        assert_eq!(Scope::Outer.key(loc, &[], ""), "");
    }
}

/// Minimal `ArchiveEntry` for `parent_package` tests — only `path` and
/// `file_type` matter to the lookup.
fn archive_entry(path: &str, file_type: &str) -> crate::types::ArchiveEntry {
    crate::types::ArchiveEntry {
        path: path.to_string(),
        file_type: file_type.to_string(),
        ..Default::default()
    }
}

#[test]
fn package_binds_to_nearest_enclosing_package_ancestor() {
    // outer.zip!pkg.tgz!lib/x.js — pkg.tgz is npm-typed, outer.zip is not.
    // Package skips past the plain zip wrapper to the npm boundary, even
    // though outer.zip is the nearer archive in the generic sense.
    let contents = [archive_entry("outer.zip!pkg.tgz", "npm")];
    assert_eq!(
        Scope::Package.key(Some("archive:outer.zip!pkg.tgz!lib/x.js"), &contents, ""),
        "archive:outer.zip!pkg.tgz"
    );
}

#[test]
fn package_ignores_non_package_archive_ancestors() {
    // pkg.tgz!inner.zip!x.js — inner.zip is a plain zip, pkg.tgz is npm.
    // Package must not stop at inner.zip just because it's the nearer
    // archive; it keeps walking outward to the actual package boundary.
    let contents = [
        archive_entry("pkg.tgz", "npm"),
        archive_entry("pkg.tgz!inner.zip", "zip"),
    ];
    assert_eq!(
        Scope::Package.key(Some("archive:pkg.tgz!inner.zip!x.js"), &contents, ""),
        "archive:pkg.tgz"
    );
}

#[test]
fn package_binds_to_the_top_level_file_when_it_is_itself_a_package() {
    // A bare .whl scanned directly, no nesting at all: the member never
    // appears in archive_contents, so the top-level file's own type is
    // what Package must consult.
    assert_eq!(
        Scope::Package.key(Some("archive:setup.py"), &[], "whl"),
        "archive:"
    );
}

#[test]
fn package_falls_back_to_file_scope_with_no_package_ancestor_anywhere() {
    // Plain zip, no npm/gem/whl/... ancestor at any level and the
    // top-level file isn't a package type either — same fall-back-to-file
    // rule as Archive, never a global pool.
    let contents = [archive_entry("outer.zip", "zip")];
    assert_eq!(
        Scope::Package.key(Some("archive:outer.zip!x.js"), &contents, "zip"),
        Scope::File.key(Some("archive:outer.zip!x.js"), &contents, "zip")
    );
    assert_eq!(Scope::Package.key(None, &[], ""), "");
}

fn composite_for(types: Vec<FileType>) -> CompositeTrait {
    CompositeTrait {
        id: "t::x".to_string(),
        desc: "d".to_string(),
        conf: 1.0,
        r#for: types,
        ..Default::default()
    }
}

/// The default-scope table. An omitted `scope:` is the common case, so
/// what it resolves to is part of the rule language, not an implementation
/// detail.
#[test]
fn default_scope_follows_the_for_list() {
    // An ecosystem package means the package boundary...
    for ft in [
        FileType::Npm,
        FileType::Deb,
        FileType::Whl,
        FileType::VsixArchive,
    ] {
        assert_eq!(
            composite_for(vec![ft]).effective_scope(),
            Scope::Package,
            "{ft:?} should default to package scope"
        );
    }
    // ...and wins the tie against a generic container in the same list,
    // which is the whole point: `pkg.tgz!vendor.zip!x.js` keys to the
    // package, not to the wrapper that happens to sit closer.
    assert_eq!(
        composite_for(vec![FileType::Zip, FileType::Npm]).effective_scope(),
        Scope::Package
    );
    // A generic container still gets archive scope.
    for ft in [FileType::Zip, FileType::Tar, FileType::Jar, FileType::Iso] {
        assert_eq!(
            composite_for(vec![ft]).effective_scope(),
            Scope::Archive,
            "{ft:?} should default to archive scope"
        );
    }
    // Registry metadata has no location, so only `outer` can join it to
    // the artifact.
    assert_eq!(
        composite_for(vec![FileType::Registry]).effective_scope(),
        Scope::Outer
    );
    // Everything else stays file-scoped.
    for ft in [FileType::JavaScript, FileType::Pe, FileType::PackageJson] {
        assert_eq!(
            composite_for(vec![ft]).effective_scope(),
            Scope::File,
            "{ft:?} should default to file scope"
        );
    }
}

/// An explicit `scope:` always wins; the table is consulted only when the
/// field is omitted.
#[test]
fn an_explicit_scope_overrides_the_default() {
    let mut rule = composite_for(vec![FileType::Npm]);
    assert_eq!(rule.effective_scope(), Scope::Package);
    rule.scope = Some(Scope::File);
    assert_eq!(rule.effective_scope(), Scope::File);
}

/// `for: [registry, javascript]` -- the artifact↔registry join -- must not
/// be dragged to `file` by the javascript half.
#[test]
fn registry_mixed_with_a_leaf_type_still_defaults_to_outer() {
    assert_eq!(
        composite_for(vec![FileType::Registry, FileType::JavaScript]).effective_scope(),
        Scope::Outer
    );
}

#[test]
fn package_scope_round_trips_through_yaml() {
    // `scope: package` parses via the serde rename, alongside the other
    // variants, and serializes back to the same lowercase token.
    let scope: Scope = crate::yaml::from_str("package").expect("parse scope");
    assert_eq!(scope, Scope::Package);
    let token = serde_saphyr::to_string(&Scope::Package).expect("serialize scope");
    assert_eq!(token.trim(), "package");
}

#[test]
fn leaf_returns_exact_location() {
    assert_eq!(
        Scope::Leaf.key(Some("value:source.execution.module_http"), &[], ""),
        ""
    );
    assert_eq!(
        Scope::Leaf.key(
            Some("archive:a.zip!!pkg/index.js:value:source.execution.module_http"),
            &[],
            ""
        ),
        "archive:a.zip!!pkg/index.js"
    );
    assert_ne!(
        Scope::Leaf.key(Some("archive:a.zip!!one.js:value:x"), &[], ""),
        Scope::Leaf.key(Some("archive:a.zip!!two.js:value:x"), &[], "")
    );
    assert_eq!(Scope::Leaf.key(None, &[], ""), "");
    assert_eq!(
        Scope::Leaf.key(Some("archive:foo.so"), &[], ""),
        "archive:foo.so"
    );
    assert_eq!(
        Scope::Leaf.key(Some("encoding_chain:base64+zlib"), &[], ""),
        "encoding_chain:base64+zlib"
    );
}

#[test]
fn leaf_collapses_byte_offset_locations_to_containing_unit() {
    // Byte offsets identify where evidence was found inside the
    // leaf; they are not separate analysis-tree leaves.
    assert_eq!(Scope::Leaf.key(Some("0x10"), &[], ""), "");
    assert_eq!(Scope::Leaf.key(Some("offset:16"), &[], ""), "");
    assert_eq!(
        Scope::Leaf.key(Some("archive:pkg.zip!bin/payload:0x10"), &[], ""),
        "archive:pkg.zip!bin/payload"
    );
    assert_eq!(
        Scope::Leaf.key(Some("archive:pkg.zip!bin/payload:offset:16"), &[], ""),
        "archive:pkg.zip!bin/payload"
    );
}

#[test]
fn file_keeps_archive_path_drops_decoded_layers() {
    // Archive entry: file-level == leaf-level.
    assert_eq!(
        Scope::File.key(Some("archive:foo.so"), &[], ""),
        "archive:foo.so"
    );
    assert_eq!(
        Scope::File.key(Some("archive:foo.so:0x10"), &[], ""),
        "archive:foo.so"
    );
    // Encoded payloads collapse to the input-wide key.
    assert_eq!(
        Scope::File.key(Some("encoding_chain:base64+zlib"), &[], ""),
        ""
    );
    assert_eq!(Scope::File.key(None, &[], ""), "");
}

#[test]
fn file_collapses_positional_only_locations() {
    // AST evidence carries pure "row:col" strings. Under
    // `scope: file` these must collapse to the input-wide key so
    // AST evidence pools with text/symbol/encoded evidence in
    // the same analyzed unit. Regression for the bug where every
    // AST match landed in its own bucket and composites with
    // `scope: file` never satisfied `min_distinct_conditions`.
    assert_eq!(Scope::File.key(Some("6:14"), &[], ""), "");
    assert_eq!(Scope::File.key(Some("1:1"), &[], ""), "");
    assert_eq!(Scope::File.key(Some("123:456"), &[], ""), "");
    // Three-coord form (some evaluators may extend with a third
    // numeric coordinate) also collapses.
    assert_eq!(Scope::File.key(Some("7:1:42"), &[], ""), "");
}

#[test]
fn file_keeps_file_prefixed_locations() {
    // Anything that carries actual file identity must keep it so two
    // unrelated files in an archive don't get pooled. The position
    // after the path is not identity: it is dropped, as it is for a
    // bare `row:col`, so evidence elsewhere in the same file still pools.
    assert_eq!(
        Scope::File.key(Some("Analytics.php:10:5"), &[], ""),
        "Analytics.php"
    );
    assert_eq!(
        Scope::File.key(Some("src/main.rs:42:1"), &[], ""),
        "src/main.rs"
    );
    assert_ne!(
        Scope::File.key(Some("Analytics.php:10:5"), &[], ""),
        Scope::File.key(Some("src/main.rs:10:5"), &[], "")
    );
    assert_eq!(Scope::File.key(Some("file:foo"), &[], ""), "file:foo");
    // Edge cases that look numeric but aren't `row:col`.
    assert_eq!(Scope::File.key(Some("1:"), &[], ""), "1:");
    assert_eq!(Scope::File.key(Some(":"), &[], ""), ":");
    assert_eq!(Scope::File.key(Some("1:abc"), &[], ""), "1:abc");
    assert_eq!(Scope::File.key(Some("abc:1"), &[], ""), "abc:1");
    assert_eq!(Scope::File.key(Some(""), &[], ""), "");
}

#[test]
fn file_pools_embedded_code_findings_in_same_parent() {
    // Embedded-code findings (shell extracted from a Dockerfile
    // RUN block, a YAML `run:` step, etc.) prefix evidence
    // locations with `embedded@<parent-offset>:<inner>`. Under
    // `scope: file`, all such evidence within the same parent
    // file must pool — otherwise composites like
    // `chmod-arms-hidden-stage` and `stealth-fetch-hidden-stage`
    // never fire on Dockerfile/GitHub Actions fixtures where
    // each shell command lands in its own extracted snippet.
    assert_eq!(Scope::File.key(Some("embedded@0x3f:1:5"), &[], ""), "");
    assert_eq!(Scope::File.key(Some("embedded@0xd2:2:10"), &[], ""), "");
    // Offset-only inner location (no row:col).
    assert_eq!(Scope::File.key(Some("embedded@0x3f:0x10"), &[], ""), "");
    // Older `embedded:<kind>@<offset>` form (used by base64 binary
    // payload detection and office/ole extractors) also pools.
    assert_eq!(Scope::File.key(Some("embedded:base64@0x100"), &[], ""), "");
}

#[test]
fn embedded_parent_offsets_map_to_parent_lines() {
    let line_starts = build_line_index(b"zero\none\ntwo\n");

    let embedded = ev("embedded@0x6:unknown");
    assert_eq!(evidence_to_byte_offset(&embedded), Some(0x6));
    assert_eq!(evidence_to_line(&embedded, &line_starts), Some(2));

    let legacy = ev("embedded:shell@0xb:1:5");
    assert_eq!(evidence_to_byte_offset(&legacy), Some(0xb));
    assert_eq!(evidence_to_line(&legacy, &line_starts), Some(3));

    let tagged = tag(0, "embedded@0x6:unknown");
    assert_eq!(tagged_to_line(&tagged, &line_starts), Some(2));
    assert_eq!(tagged_to_byte_offset(&tagged), Some(0x6));
}

#[test]
fn near_lines_accepts_embedded_findings_in_same_parent_window() {
    let mut rule = composite_with(2, None);
    rule.near_lines = Some(1);

    let evidence = vec![ev("embedded@0x1:unknown"), ev("embedded@0x6:unknown")];
    let tags = vec![
        tag(0, "embedded@0x1:unknown"),
        tag(1, "embedded@0x6:unknown"),
    ];

    let filtered = rule
        .check_proximity_constraints(evidence, &tags, b"aaaa\nbbbb\ncccc\n")
        .expect("embedded findings are on adjacent parent lines");
    assert_eq!(filtered.len(), 2);
}

#[test]
fn near_lines_rejects_embedded_findings_outside_parent_window() {
    let mut rule = composite_with(2, None);
    rule.near_lines = Some(1);

    let evidence = vec![ev("embedded@0x1:unknown"), ev("embedded@0xb:unknown")];
    let tags = vec![
        tag(0, "embedded@0x1:unknown"),
        tag(1, "embedded@0xb:unknown"),
    ];

    assert!(
        rule.check_proximity_constraints(evidence, &tags, b"aaaa\nbbbb\ncccc\n")
            .is_none()
    );
}

/// A symbol condition for building `any:` legs in the group-proximity tests.
fn symbol_cond(name: &str) -> Condition {
    Condition::Symbol(SymbolQuery {
        exact: Some(name.to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        kind: None,
        arg: None,
        args: None,
        alias: None,
        not: None,
        module_level: false,
        receiver: None,
    })
}

#[test]
fn near_lines_requires_all_leg_not_just_any_group() {
    // Regression: `all: [x]` + `any: [y, z]` + `near_lines: 1`. The two
    // co-located `any:` legs alone must NOT satisfy proximity while the
    // `all:` leg is far away — otherwise a "fetch here, hidden path 60 lines
    // below" pair fires hostile (the trailofbits/skills devcontainer FP).
    let mut rule = composite_with(1, None); // all: [x] -> condition index 0
    rule.any = Some(vec![symbol_cond("y"), symbol_cond("z")]);
    rule.needs = None; // any needs 1 of 2
    rule.near_lines = Some(1);

    // all-leg (idx 0) at line 1; both any-legs (idx 1, 2) at line 3.
    let evidence = vec![
        ev("embedded@0x1:unknown"),
        ev("embedded@0xb:unknown"),
        ev("embedded@0xb:unknown"),
    ];
    let tags = vec![
        tag(0, "embedded@0x1:unknown"),
        tag(1, "embedded@0xb:unknown"),
        tag(2, "embedded@0xb:unknown"),
    ];

    assert!(
        rule.check_proximity_constraints(evidence, &tags, b"aaaa\nbbbb\ncccc\n")
            .is_none(),
        "two co-located any-legs must not satisfy near_lines with the all-leg 2 lines away"
    );
}

#[test]
fn near_lines_accepts_all_leg_beside_one_any_leg() {
    // Same rule shape, but now the all-leg (line 1) and one any-leg (line 2)
    // are within the 1-line window — a genuine adjacency that must match.
    let mut rule = composite_with(1, None);
    rule.any = Some(vec![symbol_cond("y"), symbol_cond("z")]);
    rule.needs = None;
    rule.near_lines = Some(1);

    let evidence = vec![ev("embedded@0x1:unknown"), ev("embedded@0x6:unknown")];
    let tags = vec![
        tag(0, "embedded@0x1:unknown"),
        tag(1, "embedded@0x6:unknown"),
    ];

    let filtered = rule
        .check_proximity_constraints(evidence, &tags, b"aaaa\nbbbb\ncccc\n")
        .expect("all-leg and an any-leg on adjacent lines satisfy near_lines");
    assert_eq!(filtered.len(), 2);
}

#[test]
fn leaf_keys_a_position_to_the_unit_that_holds_it() {
    // AST evidence is located by `row:col`, text evidence by a byte
    // offset. Both are positions inside one analyzed unit, so `leaf`
    // keys them alike -- otherwise an AST leg and a text leg in the
    // same file could never satisfy one leaf-scoped rule.
    for (ast, text, unit) in [
        ("6:14", "0x1a", ""),
        (
            "archive:pkg/a.py:12:5",
            "archive:pkg/a.py:0x1a",
            "archive:pkg/a.py",
        ),
        ("Analytics.php:10:5", "Analytics.php:0x40", "Analytics.php"),
    ] {
        assert_eq!(Scope::Leaf.key(Some(ast), &[], ""), unit, "{ast}");
        assert_eq!(Scope::Leaf.key(Some(text), &[], ""), unit, "{text}");
    }
}

#[test]
fn leaf_keeps_each_unit_apart() {
    // What `leaf` still separates: a decoded layer from its host and
    // from other layers, and one archive member from another.
    let host = Scope::Leaf.key(Some("6:14"), &[], "");
    let layer = Scope::Leaf.key(Some("encoding_chain:base64:6:14"), &[], "");
    let other_layer = Scope::Leaf.key(Some("encoding_chain:hex:6:14"), &[], "");
    assert_eq!(layer, "encoding_chain:base64");
    assert_ne!(host, layer);
    assert_ne!(layer, other_layer);
    assert_ne!(
        Scope::Leaf.key(Some("archive:a.py:3:1"), &[], ""),
        Scope::Leaf.key(Some("archive:b.py:3:1"), &[], "")
    );
}

#[test]
fn file_keys_an_archive_member_position_to_the_member() {
    assert_eq!(
        Scope::File.key(Some("archive:pkg/a.py:12:5"), &[], ""),
        Scope::File.key(Some("archive:pkg/a.py:0x1a"), &[], "")
    );
}

#[test]
fn is_positional_only_edge_cases() {
    // Two-component all-digit forms are positional.
    assert!(is_positional_only("1:2"));
    assert!(is_positional_only("0:0"));
    assert!(is_positional_only("123:456"));
    // Trailing components are tolerated as long as the first two
    // are all-digit.
    assert!(is_positional_only("1:2:3"));
    assert!(is_positional_only("10:20:trailing"));
    // Anything with a non-digit component in the first or second
    // position is not positional-only.
    assert!(!is_positional_only(""));
    assert!(!is_positional_only(":"));
    assert!(!is_positional_only("1:"));
    assert!(!is_positional_only(":1"));
    assert!(!is_positional_only("1:abc"));
    assert!(!is_positional_only("abc:1"));
    assert!(!is_positional_only("Analytics.php:10:5"));
    assert!(!is_positional_only("archive:foo.zip"));
    assert!(!is_positional_only("encoding_chain:base64"));
}

#[test]
fn archive_returns_parent_archive_for_nested() {
    assert_eq!(
        Scope::Archive.key(Some("archive:outer.zip!inner.zip!bar.so"), &[], ""),
        "archive:outer.zip!inner.zip"
    );
    assert_eq!(
        Scope::Archive.key(Some("archive:outer.zip!bar.so"), &[], ""),
        "archive:outer.zip"
    );
}

#[test]
fn archive_skips_an_ancestor_that_is_not_an_archive() {
    // A GitHub Actions `run:` step is lifted out of action.yml as a child
    // (`action.yml!/runs/steps/0/run`), but action.yml encloses nothing:
    // the step belongs to the archive that holds action.yml.
    let contents = [archive_entry("pkg/action.yml", "github_actions")];
    assert_eq!(
        Scope::Archive.key(
            Some("archive:pkg/action.yml!/runs/steps/0/run"),
            &contents,
            ""
        ),
        "archive:"
    );
    assert_eq!(
        Scope::Archive.key(Some("archive:pkg/action.yml"), &contents, ""),
        "archive:"
    );
}

#[test]
fn archive_keeps_a_nested_archive_as_a_boundary() {
    // A class in a jar inside the scanned zip stays apart from the zip's
    // direct members, whether or not the entry list names the jar.
    let contents = [archive_entry("lib/plugin.jar", "jar")];
    for listed in [&contents[..], &[]] {
        assert_eq!(
            Scope::Archive.key(Some("archive:lib/plugin.jar!com/A.class"), listed, ""),
            "archive:lib/plugin.jar"
        );
    }
}

#[test]
fn archive_returns_bare_prefix_for_single_level() {
    assert_eq!(
        Scope::Archive.key(Some("archive:foo.so"), &[], ""),
        "archive:"
    );
    assert_eq!(
        Scope::Archive.key(Some("archive:bar.so"), &[], ""),
        "archive:"
    );
}

#[test]
fn nest_joins_a_class_with_its_nestmates() {
    let host = Scope::Nest.key(Some("archive:com/github/Tls.class"), &[], "");
    assert_eq!(host, "archive:com/github/Tls");
    for member in [
        "archive:com/github/Tls$Trust.class",
        "archive:com/github/Tls$1.class",
        "archive:com/github/Tls$Trust$Inner.class",
        "archive:com/github/Tls$Trust.class:0x40",
        "archive:com/github/Tls$Trust.class:12:5",
    ] {
        assert_eq!(Scope::Nest.key(Some(member), &[], ""), host, "{member}");
    }
}

#[test]
fn nest_keeps_unrelated_classes_apart() {
    let key = |loc| Scope::Nest.key(Some(loc), &[], "");
    // Same package, different class: not nestmates.
    assert_ne!(
        key("archive:com/github/Tls.class"),
        key("archive:com/github/Loader.class")
    );
    // A name that merely extends another's is a different class.
    assert_ne!(key("archive:a/Tls.class"), key("archive:a/TlsX.class"));
    // The same class name in two JARs is two nests.
    assert_ne!(
        key("archive:x.jar!a/Tls.class"),
        key("archive:y.jar!a/Tls.class")
    );
    // A leading `$` is part of the simple name.
    assert_eq!(key("archive:a/$Proxy1.class"), "archive:a/$Proxy1");
}

#[test]
fn nest_falls_back_to_file_scope_for_non_class_locations() {
    for loc in [
        "archive:lib/foo.so",
        "archive:a/classes.txt",
        "0x1234",
        "encoding_chain:base64",
    ] {
        assert_eq!(
            Scope::Nest.key(Some(loc), &[], ""),
            Scope::File.key(Some(loc), &[], ""),
            "{loc}"
        );
    }
    assert_eq!(Scope::Nest.key(None, &[], ""), "");
}

#[test]
fn pools_members_is_every_scope_wider_than_a_file() {
    for s in [Scope::Outer, Scope::Package, Scope::Archive, Scope::Nest] {
        assert!(s.pools_members(), "{s:?}");
    }
    for s in [Scope::File, Scope::Leaf, Scope::Parent, Scope::FileOrParent] {
        assert!(!s.pools_members(), "{s:?}");
    }
}

#[test]
fn archive_falls_back_to_file_scope_for_non_archive_locations() {
    // No degradation: not being inside an archive means the same-node
    // (File-scope) key, never the empty (pool-everything) key.
    assert_eq!(
        Scope::Archive.key(Some("encoding_chain:base64+zlib"), &[], ""),
        Scope::File.key(Some("encoding_chain:base64+zlib"), &[], "")
    );
    assert_eq!(
        Scope::Archive.key(Some("0x1234"), &[], ""),
        Scope::File.key(Some("0x1234"), &[], "")
    );
    assert_eq!(Scope::Archive.key(None, &[], ""), "");
}

// ----- apply_scope_filter -----------------------------------------------

#[test]
fn outer_scope_is_a_no_op_passthrough() {
    let rule = composite_with(2, Some(Scope::Outer));
    let evidence = vec![ev("archive:a.so"), ev("archive:b.so")];
    let tags = vec![tag(0, "archive:a.so"), tag(1, "archive:b.so")];

    let (filtered_ev, filtered_tags) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("outer never rejects");
    assert_eq!(filtered_ev.len(), 2);
    assert_eq!(filtered_tags.len(), 2);
}

#[test]
fn leaf_scope_rejects_when_conditions_span_two_leaves() {
    let rule = composite_with(2, Some(Scope::Leaf));
    let evidence = vec![ev("archive:a.so"), ev("archive:b.so")];
    let tags = vec![tag(0, "archive:a.so"), tag(1, "archive:b.so")];

    assert!(rule.apply_scope_filter(evidence, tags, &[], "").is_none());
}

#[test]
fn leaf_scope_accepts_when_both_conditions_in_one_leaf() {
    let rule = composite_with(2, Some(Scope::Leaf));
    let evidence = vec![ev("archive:a.so"), ev("archive:a.so")];
    let tags = vec![tag(0, "archive:a.so"), tag(1, "archive:a.so")];

    let (filtered_ev, _) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("both in same leaf");
    assert_eq!(filtered_ev.len(), 2);
}

#[test]
fn leaf_scope_pools_byte_offsets_in_same_raw_input() {
    let rule = composite_with(2, Some(Scope::Leaf));
    let evidence = vec![ev("0x10"), ev("0x30")];
    let tags = vec![tag(0, "0x10"), tag(1, "0x30")];

    let (filtered_ev, _) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("byte offsets share the raw input leaf");
    assert_eq!(filtered_ev.len(), 2);
}

#[test]
fn leaf_scope_keeps_archive_member_identity_for_byte_offsets() {
    let rule = composite_with(2, Some(Scope::Leaf));
    let evidence = vec![ev("archive:a.bin:0x10"), ev("archive:b.bin:0x30")];
    let tags = vec![tag(0, "archive:a.bin:0x10"), tag(1, "archive:b.bin:0x30")];

    assert!(rule.apply_scope_filter(evidence, tags, &[], "").is_none());
}

#[test]
fn leaf_scope_drops_evidence_from_losing_buckets() {
    // Condition 0 has evidence in two leaves; condition 1 has
    // evidence only in `a.so`. Only the `a.so` bucket has both
    // conditions; evidence in `b.so` is dropped.
    let rule = composite_with(2, Some(Scope::Leaf));
    let evidence = vec![ev("archive:a.so"), ev("archive:b.so"), ev("archive:a.so")];
    let tags = vec![
        tag(0, "archive:a.so"),
        tag(0, "archive:b.so"),
        tag(1, "archive:a.so"),
    ];

    let (filtered_ev, filtered_tags) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("a.so bucket wins");
    assert_eq!(filtered_ev.len(), 2);
    assert!(
        filtered_ev
            .iter()
            .all(|e| e.location.as_deref() == Some("archive:a.so"))
    );
    assert_eq!(filtered_tags.len(), 2);
}

#[test]
fn archive_scope_accepts_two_entries_in_same_archive() {
    let rule = composite_with(2, Some(Scope::Archive));
    let evidence = vec![ev("archive:a.so"), ev("archive:b.so")];
    let tags = vec![tag(0, "archive:a.so"), tag(1, "archive:b.so")];

    let (filtered_ev, _) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("same archive");
    assert_eq!(filtered_ev.len(), 2);
}

#[test]
fn archive_scope_rejects_two_entries_in_different_nested_archives() {
    let rule = composite_with(2, Some(Scope::Archive));
    let evidence = vec![
        ev("archive:outer.zip!inner1.zip!a.so"),
        ev("archive:outer.zip!inner2.zip!b.so"),
    ];
    let tags = vec![
        tag(0, "archive:outer.zip!inner1.zip!a.so"),
        tag(1, "archive:outer.zip!inner2.zip!b.so"),
    ];

    assert!(rule.apply_scope_filter(evidence, tags, &[], "").is_none());
}

/// The container pass hands `nest` each member's evidence twice: prefixed
/// with its `archive:` member path, and bare. The bare copies all key to
/// "", which spans every class; it must not satisfy a nest on its own.
#[test]
fn nest_scope_ignores_unlocated_evidence_from_unrelated_classes() {
    let rule = composite_with(2, Some(Scope::Nest));
    let evidence = vec![
        ev("archive:com/x/Tls.class:0x30"),
        ev("0x30"),
        ev("archive:com/x/Other$T.class:value:class.strings[*]"),
        ev("value:class.strings[*]"),
    ];
    let tags = vec![
        tag(0, "archive:com/x/Tls.class:0x30"),
        tag(0, "0x30"),
        tag(1, "archive:com/x/Other$T.class:value:class.strings[*]"),
        tag(1, "value:class.strings[*]"),
    ];
    assert!(rule.apply_scope_filter(evidence, tags, &[], "").is_none());
}

#[test]
fn nest_scope_pools_a_class_with_its_inner_class() {
    let rule = composite_with(2, Some(Scope::Nest));
    let evidence = vec![
        ev("archive:com/x/Tls.class:0x30"),
        ev("0x30"),
        ev("archive:com/x/Tls$T.class:value:class.strings[*]"),
        ev("value:class.strings[*]"),
    ];
    let tags = vec![
        tag(0, "archive:com/x/Tls.class:0x30"),
        tag(0, "0x30"),
        tag(1, "archive:com/x/Tls$T.class:value:class.strings[*]"),
        tag(1, "value:class.strings[*]"),
    ];
    let (kept, _) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("nestmates pool");
    assert_eq!(kept.len(), 2, "only the located nest evidence is kept");
}

#[test]
fn archive_scope_pools_entries_in_same_nested_archive() {
    let rule = composite_with(2, Some(Scope::Archive));
    let evidence = vec![
        ev("archive:outer.zip!inner.zip!a.so"),
        ev("archive:outer.zip!inner.zip!b.so"),
    ];
    let tags = vec![
        tag(0, "archive:outer.zip!inner.zip!a.so"),
        tag(1, "archive:outer.zip!inner.zip!b.so"),
    ];

    let (filtered_ev, _) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("same nested archive");
    assert_eq!(filtered_ev.len(), 2);
}

#[test]
fn file_scope_pools_decoded_layers_with_their_input() {
    // `scope: file` collapses encoded-payload layers down to the
    // input level, so two decoded-layer pieces of evidence pool
    // together under the same file-level key.
    let rule = composite_with(2, Some(Scope::File));
    let evidence = vec![
        ev("encoding_chain:base64"),
        ev("encoding_chain:base64+zlib"),
    ];
    let tags = vec![
        tag(0, "encoding_chain:base64"),
        tag(1, "encoding_chain:base64+zlib"),
    ];

    let (filtered_ev, _) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("file scope pools input + decoded layers");
    assert_eq!(filtered_ev.len(), 2);
}

#[test]
fn leaf_scope_separates_decoded_layers_from_each_other() {
    let rule = composite_with(2, Some(Scope::Leaf));
    let evidence = vec![
        ev("encoding_chain:base64"),
        ev("encoding_chain:base64+zlib"),
    ];
    let tags = vec![
        tag(0, "encoding_chain:base64"),
        tag(1, "encoding_chain:base64+zlib"),
    ];

    assert!(rule.apply_scope_filter(evidence, tags, &[], "").is_none());
}

#[test]
fn single_condition_rule_satisfies_any_scope() {
    // 1 condition → min_distinct == 1 → any single bucket
    // satisfies, but the filter still pins to exactly one bucket.
    let rule = composite_with(1, Some(Scope::Leaf));
    let evidence = vec![ev("archive:a.so"), ev("archive:b.so")];
    let tags = vec![tag(0, "archive:a.so"), tag(0, "archive:b.so")];

    let (filtered_ev, _) = rule
        .apply_scope_filter(evidence, tags, &[], "")
        .expect("single condition is trivially in-scope");
    assert_eq!(filtered_ev.len(), 1);
}

#[test]
fn file_scope_requires_every_all_condition_in_the_same_file() {
    // The first required leg is on the parent; the second required leg
    // and both optional alternatives are on one extracted child. The old
    // aggregate threshold (all_count + any_required) let the child's
    // second `all:` leg plus both `any:` legs stand in for the missing
    // first `all:` leg.
    let mut rule = composite_with(2, Some(Scope::File));
    rule.any = Some(rule.all.as_ref().expect("two all conditions").clone());
    rule.needs = Some(1);
    let evidence = vec![
        ev("parent.exe"),
        ev("parent.exe!!child.dll"),
        ev("parent.exe!!child.dll"),
        ev("parent.exe!!child.dll"),
    ];
    let tags = vec![
        tag(0, "parent.exe"),
        tag(1, "parent.exe!!child.dll"),
        tag(2, "parent.exe!!child.dll"),
        tag(3, "parent.exe!!child.dll"),
    ];

    assert!(rule.apply_scope_filter(evidence, tags, &[], "").is_none());
}
