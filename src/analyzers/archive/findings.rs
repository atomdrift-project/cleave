//! Archive-level findings: extraction notes, hostile members and symlinks.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn archive_finding(
    id: &str,
    desc: String,
    _source: &str,
    evidence: Vec<Evidence>,
    match_count: usize,
) -> Finding {
    let crit = if id.starts_with("metadata/archive/")
        || id == "anti-analysis/archive/excessive-size"
        || id == "anti-analysis/archive/long-entry-name"
        || id == "anti-analysis/archive/excessive-nesting"
    {
        Criticality::Notable
    } else {
        Criticality::Suspicious
    };

    Finding {
        precomputed_spans: None,
        src: None,
        kind: if id.starts_with("metadata/archive/") {
            FindingKind::Structural
        } else {
            FindingKind::Capability
        },
        trait_refs: vec![],
        id: id.into(),
        desc: desc.into(),
        conf: 0.9,
        crit,
        mbc: None,
        attack: None,
        evidence,
        match_count,
        source_file: None,
        downgraded: false,
    }
}

pub(super) fn has_builtin_anti_analysis_finding(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| {
        finding.id.starts_with("anti-analysis/archive/")
            || finding
                .id
                .starts_with("objectives/anti-analysis/pe-tampering/")
    })
}

/// Drain the guard's non-fatal extraction notes into the report, raising one
/// finding when any were recorded.
///
/// An archive we could only read part of is worth surfacing — truncating a
/// container is a cheap way past a scanner that bails on a bad member, which is
/// exactly the failure this recovery path exists for — but it is also the
/// everyday shape of an interrupted download. So it lands at `Notable`
/// ([`Criticality::score_weight`] 1, against 40 for suspicious): visible in the
/// trait list and the LLM render, without nudging a benign sample's verdict.
///
/// Partial extraction reports archive readability, not anti-analysis intent.
/// Keep this structural finding outside `anti-analysis/archive/`, whose
/// retroactive-suppression pass handles hostile-container findings rather
/// than missing bytes.
pub(super) fn drain_extraction_notes(report: &mut AnalysisReport, guard: &ExtractionGuard) {
    let notes = guard.take_extraction_notes();
    if notes.is_empty() {
        return;
    }

    let evidence = notes
        .iter()
        .take(MAX_INCOMPLETE_ARCHIVE_EVIDENCE)
        .map(|note| Evidence {
            method: "archive_extraction".to_string(),
            source: "archive_analyzer".to_string(),
            value: note.clone(),
            location: None,
            ..Default::default()
        })
        .collect();

    report.findings.push(Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Structural,
        trait_refs: vec![],
        id: "metadata/archive/parsing::partial-extraction"
            .to_string()
            .into(),
        desc: format!(
            "Archive could only be read in part ({} extraction {})",
            notes.len(),
            if notes.len() == 1 {
                "problem"
            } else {
                "problems"
            }
        )
        .into(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        evidence,
        match_count: notes.len(),
        source_file: None,
        downgraded: false,
    });

    report.metadata.errors.extend(notes);
}

pub(super) fn push_archive_hostile_findings(
    report: &mut AnalysisReport,
    hostile_reasons: Vec<HostileArchiveReason>,
    _archive_path: &Path,
    source: &str,
    suppress_path_traversal: bool,
) {
    let mut path_evidence = Vec::new();

    for reason in hostile_reasons {
        match reason {
            HostileArchiveReason::PathTraversal(path) => {
                if suppress_path_traversal {
                    continue;
                }

                // An entry that resolves to the extraction root is not an
                // escape. Extractors reject it for the same reason they reject
                // `../`, so it arrives here as the same variant -- but every
                // `tar -cf x.tar .` produces one, and reporting it as zip-slip
                // flags a large share of ordinary source tarballs.
                if names_extraction_root(&path) {
                    continue;
                }

                path_evidence.push(Evidence {
                    method: "archive_extraction".to_string(),
                    source: source.to_string(),
                    value: format!("path:{}", path),
                    location: None,
                    ..Default::default()
                });
            }
            HostileArchiveReason::ZipBomb {
                compressed,
                uncompressed,
            } => {
                report.findings.push(archive_finding(
                    "anti-analysis/archive/zip-bomb",
                    "Archive has suspicious compression ratio (potential zip bomb)".to_string(),
                    source,
                    vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!(
                            "ratio:{}:1 ({}B -> {}B)",
                            uncompressed / compressed.max(1),
                            compressed,
                            uncompressed
                        ),
                        location: None,
                        ..Default::default()
                    }],
                    1,
                ));
            }
            HostileArchiveReason::ExcessiveFileCount(count) => {
                // Reaching a configured analysis bound is structural telemetry,
                // not anti-analysis intent. Keep the guard and visible count,
                // without package-name exemptions or a malware severity.
                report.findings.push(archive_finding(
                    "metadata/archive/layout::archive-member-limit-reached",
                    "Archive analysis reached member-count limit".to_string(),
                    source,
                    vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!("count:{} limit:{}", count, MAX_FILE_COUNT),
                        location: None,
                        ..Default::default()
                    }],
                    1,
                ));
            }
            HostileArchiveReason::ExcessiveTotalSize(size) => {
                report.findings.push(archive_finding(
                    "anti-analysis/archive/excessive-size",
                    "Archive expands to excessive total size".to_string(),
                    source,
                    vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!("size:{} bytes (limit:{})", size, MAX_TOTAL_SIZE),
                        location: None,
                        ..Default::default()
                    }],
                    1,
                ));
            }
            HostileArchiveReason::ExcessiveFileSize { file, size } => {
                report.findings.push(Finding {
                    precomputed_spans: None,
                    src: None,
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/archive/large-file".to_string().into(),
                    desc: "Archive contains excessively large file".to_string().into(),
                    conf: 0.9,
                    crit: Criticality::Notable,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!("file:{} size:{} (limit:{})", file, size, MAX_FILE_SIZE),
                        location: None,
                        ..Default::default()
                    }],
                    match_count: 1,
                    source_file: None,
                    downgraded: false,
                });
            }
            HostileArchiveReason::ExcessiveEntryName { len, preview } => {
                let (id, desc) = if len > 1024 {
                    (
                        "anti-analysis/archive/hostile-entry-name",
                        format!("Archive entry has hostile-length name ({len} bytes)"),
                    )
                } else {
                    (
                        "anti-analysis/archive/long-entry-name",
                        format!("Archive entry has excessively long name ({len} bytes)"),
                    )
                };
                report.findings.push(archive_finding(
                    id,
                    desc,
                    source,
                    vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!("name_len:{len} preview:{preview}"),
                        location: None,
                        ..Default::default()
                    }],
                    1,
                ));
            }
            HostileArchiveReason::SymlinkEscape(path) => {
                if !is_benign_archive_symlink_escape(&path) {
                    report.findings.push(archive_finding(
                        "anti-analysis/archive/symlink-escape",
                        "Archive contains symlink that may escape extraction directory".to_string(),
                        source,
                        vec![Evidence {
                            method: "archive_extraction".to_string(),
                            source: source.to_string(),
                            value: format!("symlink:{}", path),
                            location: None,
                            ..Default::default()
                        }],
                        1,
                    ));
                }
            }
        }
    }

    if !path_evidence.is_empty() {
        let match_count = path_evidence.len();
        path_evidence.truncate(MAX_ARCHIVE_PATH_TRAVERSAL_EVIDENCE);
        report.findings.push(archive_finding(
            "anti-analysis/archive/path-traversal",
            "Archive contains path traversal entries (zip slip)".to_string(),
            source,
            path_evidence,
            match_count,
        ));
    }
}

/// Whether a symlink escape (`path` is `link -> target`) has a known-benign
/// shape: a Python interpreter shim (node-gyp's `node_gyp_bins`, a virtualenv's
/// `bin/`), or a system location linking to a system target.
///
/// Judged on the link alone. Where the archive or member sits (a `testdata/`
/// directory, a `.pkg.tar.zst` or `docker.io_` file name) is chosen by whoever
/// built the archive, so it must not excuse an escape; whole-container
/// allowances key on the content-detected type instead, see
/// [`carries_system_symlinks`].
pub(super) fn is_benign_archive_symlink_escape(path: &str) -> bool {
    let path = path.trim();

    if let Some((link_name, target)) = path.split_once("->") {
        let link_name = link_name.trim().trim_start_matches("./");
        let target = target.trim();
        let interpreter_shim = matches!(link_name.rsplit('/').next(), Some("python" | "python3"))
            && matches!(target, "/usr/bin/python" | "/usr/bin/python3");
        if interpreter_shim {
            return true;
        }
        // Shared-library development links and loader shims in rootfs exports.
        // Keep both sides constrained; a user-data link to a system library is
        // still an escape, as is a library path pointing to a sensitive file.
        let library_link = [
            "usr/lib/",
            "usr/lib32/",
            "usr/lib64/",
            "usr/libx32/",
            "lib/",
            "lib32/",
            "lib64/",
            "libx32/",
        ]
        .iter()
        .any(|prefix| link_name.starts_with(prefix));
        let library_target = ["/lib/", "/lib32/", "/lib64/", "/libx32/"]
            .iter()
            .any(|prefix| target.starts_with(prefix));
        let normal_library_path = !link_name.split('/').any(|part| part == "..")
            && !target.split('/').any(|part| part == "..");
        if library_link && library_target && normal_library_path {
            return true;
        }
        let standard_system_link = matches!(
            (link_name, target),
            ("bin/pidof" | "usr/bin/pidof", "/sbin/killall5")
                | ("dev/core", "/proc/kcore")
                | ("dev/fd", "/proc/self/fd")
                | ("etc/sgml/catalog", "/var/lib/sgml-base/supercatalog")
                | ("usr/share/locale/locale.alias", "/etc/locale.alias")
        );
        let masked_service = link_name.starts_with("lib/systemd/system/")
            && link_name.ends_with(".service")
            && target == "/dev/null"
            && !link_name.split('/').any(|part| part == "..");
        if standard_system_link || masked_service {
            return true;
        }
        let system_link = link_name.starts_with("etc/")
            || ["lib/", "lib32/", "lib64/", "libx32/"]
                .iter()
                .any(|dir| link_name.starts_with(dir))
            || link_name.starts_with("bin/")
            || link_name.starts_with("sbin")
            || link_name.starts_with("usr/")
            || link_name == "var/lock"
            || link_name.starts_with("var/run");
        let system_target = target.starts_with("/usr/share/")
            || target.starts_with("/usr/bin/")
            || target.starts_with("/usr/sbin/")
            // Locally installed tools: `usr/local/bin/yarn -> /opt/yarn/bin/yarn`.
            || target.starts_with("/usr/local/bin/")
            || target.starts_with("/usr/local/sbin/")
            || (target.starts_with("/opt/") && !target.split('/').any(|part| part == ".."))
            || target.starts_with("/bin/")
            || target.starts_with("/lib/systemd/")
            || target.starts_with("/etc/alternatives/")
            || target.starts_with("/etc/ssl/")
            || target.starts_with("/etc/dpkg/")
            || target == "/etc/localtime"
            || target == "/run"
            || target == "/run/lock";
        if system_link && system_target {
            return true;
        }
    }

    false
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
        _ => false,
    }
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
        // Plain tarballs never get the allowance, whatever they contain.
        assert!(!carries_system_symlinks(FileType::Tar, &pkg));
    }

    #[test]
    fn local_tool_links_into_opt_are_benign() {
        assert!(is_benign_archive_symlink_escape(
            "usr/local/bin/yarn -> /opt/yarn-v1.22.22/bin/yarn"
        ));
        assert!(is_benign_archive_symlink_escape(
            "usr/local/bin/nodejs -> /usr/local/bin/node"
        ));
        assert!(!is_benign_archive_symlink_escape(
            "usr/local/bin/x -> /opt/../etc/shadow"
        ));
        assert!(!is_benign_archive_symlink_escape(
            "data/evil -> /opt/app/key"
        ));
    }
}
