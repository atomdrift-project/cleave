//! Archive-level findings: extraction notes, hostile members and symlinks.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Drain the guard's non-fatal extraction notes into `metadata.errors` and
/// flag the report [`AnalysisGap::ExtractionPartial`] when any were recorded.
///
/// An archive we could only read part of is worth surfacing — truncating a
/// container is a cheap way past a scanner that bails on a bad member — but it
/// is also the everyday shape of an interrupted download. It reports archive
/// readability, not intent, so it is a state of the analysis, not a finding.
pub(super) fn drain_extraction_notes(report: &mut AnalysisReport, guard: &ExtractionGuard) {
    let notes = guard.take_extraction_notes();
    if notes.is_empty() {
        return;
    }
    report
        .analysis_gaps
        .record(crate::types::AnalysisGap::ExtractionPartial);
    report.metadata.errors.extend(notes);
}

/// Record what the extraction guards observed, for traits to judge: the
/// `archive_guard` values (`path_traversals[]`, `symlink_escapes[]`,
/// `large_files[]`, `long_entry_names[]`, `zip_bomb`) and the
/// `archive.guard.*` metrics (`compression_ratio`, `total_size`,
/// `longest_entry_name`, `member_limit_reached`).
///
/// Only what defines the observation is decided here: an entry that names
/// the extraction root is not a traversal, and an OS package's absolute
/// member names are its format, not an escape (`suppress_path_traversal`).
/// Severity, thresholds and known-benign link shapes are traits
/// (`objectives/anti-analysis/anti-tampering/archive-guard.yaml`).
pub(super) fn push_archive_hostile_findings(
    report: &mut AnalysisReport,
    hostile_reasons: Vec<HostileArchiveReason>,
    _archive_path: &Path,
    _source: &str,
    suppress_path_traversal: bool,
) {
    use serde_json::{Value, json};
    let mut traversals = Vec::new();
    let mut traversal_count = 0usize;
    let mut symlinks = Vec::new();
    let mut large_files = Vec::new();
    let mut entry_names = Vec::new();
    let mut zip_bomb = None;
    let mut metrics: Vec<(&str, f64)> = Vec::new();

    for reason in hostile_reasons {
        match reason {
            HostileArchiveReason::PathTraversal(path) => {
                // Extractors reject an entry resolving to the extraction root
                // as they reject `../`, but every `tar -cf x.tar .` has one.
                if suppress_path_traversal || names_extraction_root(&path) {
                    continue;
                }
                traversal_count += 1;
                if traversals.len() < MAX_ARCHIVE_PATH_TRAVERSAL_EVIDENCE {
                    traversals.push(Value::String(path));
                }
            }
            HostileArchiveReason::ZipBomb {
                compressed,
                uncompressed,
            } => {
                let ratio = uncompressed / compressed.max(1);
                metrics.push(("archive.guard.compression_ratio", ratio as f64));
                zip_bomb = Some(json!({
                    "compressed": compressed,
                    "uncompressed": uncompressed,
                    "ratio": ratio,
                }));
            }
            HostileArchiveReason::ExcessiveFileCount(count) => {
                metrics.push(("archive.guard.member_limit_reached", count as f64));
            }
            HostileArchiveReason::ExcessiveTotalSize(size) => {
                metrics.push(("archive.guard.total_size", size as f64));
            }
            HostileArchiveReason::ExcessiveFileSize { file, size } => {
                large_files.push(json!({"file": file, "size": size}));
            }
            HostileArchiveReason::ExcessiveEntryName { len, preview } => {
                entry_names.push(json!({"length": len, "preview": preview}));
                let longest = metrics
                    .iter_mut()
                    .find(|(key, _)| *key == "archive.guard.longest_entry_name");
                match longest {
                    Some((_, value)) => *value = value.max(len as f64),
                    None => metrics.push(("archive.guard.longest_entry_name", len as f64)),
                }
            }
            HostileArchiveReason::SymlinkEscape(path) => symlinks.push(Value::String(path)),
        }
    }

    let mut guard = serde_json::Map::new();
    for (key, list) in [
        ("path_traversals", traversals),
        ("symlink_escapes", symlinks),
        ("large_files", large_files),
        ("long_entry_names", entry_names),
    ] {
        if !list.is_empty() {
            guard.insert(key.into(), Value::Array(list));
        }
    }
    if traversal_count > 0 {
        metrics.push(("archive.guard.path_traversal_count", traversal_count as f64));
    }
    if let Some(bomb) = zip_bomb {
        guard.insert("zip_bomb".into(), bomb);
    }
    if !guard.is_empty() {
        report.merge_kv_subtree("archive_guard", Value::Object(guard));
    }
    if !metrics.is_empty() {
        let map = report
            .filefacts_metrics
            .get_or_insert_with(Default::default);
        for (key, value) in metrics {
            map.insert(key.to_string(), value);
        }
    }
}

/// Whether this archive is a kind whose contents routinely link out of the
/// extraction root: an OS package's `usr/lib/libfoo.so -> /usr/lib/libfoo.so.1`,
/// a container image layer's root filesystem. Decided by content, never by the
/// file name, which whoever built the archive chooses.
pub(super) fn carries_system_symlinks(archive_type: FileType, contents: &[ArchiveEntry]) -> bool {
    match archive_type {
        FileType::PkgArch => is_system_package(archive_type, contents),
        // Alpine/Wolfi packages install into `/` as root and routinely ship
        // absolute links (`usr/bin/foo -> /usr/lib/foo/bin`). Require the
        // control segment's `.PKGINFO`, not just the apk magic.
        FileType::ApkAlpine => has_root_member(contents, ".PKGINFO"),
        // Detected from content only: an OCI layout or a `docker save` manifest.
        FileType::OciImage => true,
        // A root filesystem export (`docker export`, a WSL or podman machine
        // image): its absolute links resolve inside the image once it is the
        // root, e.g. Fedora's `etc/pam.d/system-auth -> /etc/authselect/...`.
        FileType::Tar | FileType::TarGz | FileType::TarBz2 | FileType::TarXz | FileType::TarZst => {
            is_os_root_filesystem(contents)
        }
        _ => false,
    }
}

/// Members a root filesystem export needs under each FHS tree before the
/// archive counts as one; an os-release next to a handful of files is not.
const MIN_ROOTFS_TREE_MEMBERS: usize = 16;

/// Whether the archive is an OS root filesystem by content: a root-level
/// `etc/os-release` or `usr/lib/os-release` beside populated `etc/`,
/// `usr/bin/` and `usr/lib*/` trees.
fn is_os_root_filesystem(contents: &[ArchiveEntry]) -> bool {
    if !(has_root_member(contents, "etc/os-release")
        || has_root_member(contents, "usr/lib/os-release"))
    {
        return false;
    }
    let tree_members = |prefixes: &[&str]| {
        contents
            .iter()
            .filter(|entry| {
                // The member's path inside this archive, read the way
                // `has_root_member` reads it: a nested archive's entries
                // carry their parent's `outer!` prefix.
                let leaf = entry.path.rsplit('!').next().unwrap_or(&entry.path);
                let path = leaf.trim_start_matches("./");
                prefixes.iter().any(|prefix| path.starts_with(prefix))
            })
            .take(MIN_ROOTFS_TREE_MEMBERS)
            .count()
            >= MIN_ROOTFS_TREE_MEMBERS
    };
    tree_members(&["etc/"])
        && tree_members(&["usr/bin/"])
        && tree_members(&["usr/lib/", "usr/lib64/"])
}

fn has_root_member(contents: &[ArchiveEntry], name: &str) -> bool {
    contents.iter().any(|entry| {
        let leaf = entry.path.rsplit('!').next().unwrap_or(&entry.path);
        leaf.trim_start_matches("./") == name
    })
}

/// Whether this archive is an OS package by content: it carries the metadata
/// members its format is detected by. filefacts also types an archive as a
/// package from a `.pkg` / `.pkg.tar.*` *name* when that metadata is absent,
/// and the name is the archive author's choice.
pub(super) fn is_system_package(archive_type: FileType, contents: &[ArchiveEntry]) -> bool {
    let has_member = |name: &str| has_root_member(contents, name);
    match archive_type {
        FileType::PkgArch => {
            has_member(".PKGINFO") && (has_member(".MTREE") || has_member(".BUILDINFO"))
        }
        FileType::PkgFreebsd => has_member("+COMPACT_MANIFEST") || has_member("+MANIFEST"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(paths: &[&str]) -> Vec<ArchiveEntry> {
        paths
            .iter()
            .map(|p| ArchiveEntry {
                path: (*p).to_string(),
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn alpine_apk_with_pkginfo_carries_system_symlinks() {
        let pkg = entries(&[".SIGN.RSA.wolfi.rsa.pub", ".PKGINFO", "usr/bin/placement"]);
        assert!(carries_system_symlinks(FileType::ApkAlpine, &pkg));
        // apk magic alone, without the control segment, is not an OS package.
        let bare = entries(&["usr/bin/placement"]);
        assert!(!carries_system_symlinks(FileType::ApkAlpine, &bare));
        // A nested member called .PKGINFO does not count.
        let nested = entries(&["data/.PKGINFO"]);
        assert!(!carries_system_symlinks(FileType::ApkAlpine, &nested));
        // A tarball gets the allowance only as a whole root filesystem.
        assert!(!carries_system_symlinks(FileType::Tar, &pkg));
    }

    #[test]
    fn root_filesystem_tar_carries_system_symlinks() {
        let mut paths: Vec<String> = vec!["etc/os-release".to_string()];
        for i in 0..MIN_ROOTFS_TREE_MEMBERS {
            paths.push(format!("etc/conf{i}"));
            paths.push(format!("usr/bin/tool{i}"));
            paths.push(format!("usr/lib64/lib{i}.so"));
        }
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let rootfs = entries(&refs);
        assert!(carries_system_symlinks(FileType::TarZst, &rootfs));
        // Nested inside an installer, entries carry the parent's prefix.
        let prefixed: Vec<String> = refs
            .iter()
            .map(|p| format!("assets/podman-image.zst!{p}"))
            .collect();
        let prefixed_refs: Vec<&str> = prefixed.iter().map(String::as_str).collect();
        assert!(carries_system_symlinks(
            FileType::TarZst,
            &entries(&prefixed_refs)
        ));
        assert!(carries_system_symlinks(FileType::Tar, &rootfs));
        // Same members in a non-tar container: no allowance.
        assert!(!carries_system_symlinks(FileType::Zip, &rootfs));

        // An os-release beside a few files is not a root filesystem.
        let thin = entries(&[
            "etc/os-release",
            "etc/passwd",
            "usr/bin/sh",
            "usr/lib/libc.so",
        ]);
        assert!(!carries_system_symlinks(FileType::Tar, &thin));
        // Nor is a full tree without os-release, or with it only nested.
        let no_release: Vec<&str> = refs
            .iter()
            .copied()
            .filter(|p| *p != "etc/os-release")
            .collect();
        assert!(!carries_system_symlinks(
            FileType::Tar,
            &entries(&no_release)
        ));
        let mut nested = no_release.clone();
        nested.push("payload/etc/os-release");
        assert!(!carries_system_symlinks(FileType::Tar, &entries(&nested)));
    }
}
