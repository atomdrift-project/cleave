#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Nested archives draw on their parent's extraction budget, so the
/// total-size and file-count limits cover the whole tree.
#[test]
fn nested_archives_share_the_extraction_budget() {
    use super::ArchiveAnalyzer;
    use std::sync::Arc;
    let outer = ArchiveAnalyzer::new();
    let nested = outer.nested_archive_analyzer("inner.zip");
    assert!(Arc::ptr_eq(&outer.budget, &nested.budget));
    let child = outer.child_archive_config().apply(ArchiveAnalyzer::new());
    assert!(Arc::ptr_eq(&outer.budget, &child.budget));
    assert!(Arc::ptr_eq(
        &outer.budget,
        &outer.clone_for_member_analysis().budget
    ));
}

#[test]
#[allow(clippy::panic)] // An empty queue must never invoke its callback.
fn priority_members_preserve_queue_order_and_visit_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let indices: Vec<_> = (0..97).rev().collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let visited = std::sync::Mutex::new(Vec::new());
    pool.install(|| {
        super::for_each_priority_member(&indices, |i| {
            visited.lock().unwrap().push(i);
        })
    });
    assert_eq!(visited.into_inner().unwrap(), indices);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    let counts: Vec<_> = (0..indices.len()).map(|_| AtomicUsize::new(0)).collect();
    pool.install(|| {
        super::for_each_priority_member(&indices, |i| {
            counts[i].fetch_add(1, Ordering::Relaxed);
            std::thread::yield_now();
        })
    });
    assert!(counts.iter().all(|n| n.load(Ordering::Relaxed) == 1));
    pool.install(|| super::for_each_priority_member(&[], |_| panic!("empty queue")));
}

#[test]
#[allow(clippy::panic)] // An empty group must never invoke its callback.
fn isolated_group_starts_while_the_only_scan_worker_is_busy() {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::sync_channel,
    };
    use std::time::Duration;
    let (started, ready) = sync_channel(2);
    let (done, release) = sync_channel(2);
    let ready = Mutex::new(ready);
    let release = Mutex::new(release);
    let visits = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    pool.install(|| {
        super::for_each_group_with_isolated_members(
            &[0, 1, 2, 3],
            |i| match i {
                0 => Some(super::MemberDispatch::WholeMember(2)),
                1 => Some(super::MemberDispatch::SourceAnalysis),
                _ => None,
            },
            |i| {
                visits[i].fetch_add(1, Ordering::Relaxed);
                if i < 2 {
                    if i == 0 {
                        assert!(crate::rayon_nest::on_isolated_leaf_pool());
                        assert_eq!(rayon::current_num_threads(), 2);
                        let analyzer = super::ArchiveAnalyzer::new();
                        analyzer
                            .lane_thread
                            .store(rayon::current_thread_index().unwrap(), Ordering::Relaxed);
                        assert!(
                            !analyzer.member_may_wait(),
                            "private worker indices must not be treated as scan lanes"
                        );
                    } else {
                        assert!(
                            rayon::current_thread_index().is_none(),
                            "source admission must allow off-pool duplicate waits"
                        );
                        crate::rayon_nest::with_isolated_leaf_pool(3, || {
                            assert!(crate::rayon_nest::on_isolated_leaf_pool());
                            assert_eq!(rayon::current_num_threads(), 3);
                        });
                    }
                    started.send(()).unwrap();
                    release
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                } else if i == 2 {
                    assert_eq!(rayon::current_num_threads(), 1);
                    for _ in 0..2 {
                        ready
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap();
                    }
                    for _ in 0..2 {
                        done.send(()).unwrap();
                    }
                }
            },
        )
    });
    assert!(
        visits
            .iter()
            .all(|count| count.load(Ordering::Relaxed) == 1)
    );
    pool.install(|| {
        super::for_each_group_with_isolated_members(
            &[],
            |_| Some(super::MemberDispatch::WholeMember(2)),
            |_| panic!("empty group"),
        )
    });
}

#[test]
fn owned_members_release_inputs_before_ordered_fold() {
    use super::par_filter_fold_owned_members;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Input {
        index: usize,
        dropped: Arc<Vec<AtomicUsize>>,
    }
    impl Drop for Input {
        fn drop(&mut self) {
            self.dropped[self.index].fetch_add(1, Ordering::SeqCst);
        }
    }
    for parallel in [false, true] {
        let dropped = Arc::new((0..32).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
        let inputs = (0..32).map(|index| Input {
            index,
            dropped: Arc::clone(&dropped),
        });
        let mut folded = Vec::new();
        par_filter_fold_owned_members(
            inputs,
            parallel,
            |input| {
                (input.index % 3 == 0).then_some(super::MemberPriority {
                    native: false,
                    bytes: input.index,
                    dispatch: None,
                })
            },
            |input| {
                assert_eq!(input.dropped[input.index].load(Ordering::SeqCst), 0);
                // A skipped or failed member still releases its buffer.
                (input.index % 5 != 0).then_some(input.index)
            },
            |index| {
                assert_eq!(dropped[index].load(Ordering::SeqCst), 1);
                folded.push(index);
            },
        );
        assert_eq!(folded, (0..32).filter(|i| i % 5 != 0).collect::<Vec<_>>());
        assert!(dropped.iter().all(|n| n.load(Ordering::SeqCst) == 1));
    }
}

use super::{
    ArchiveAnalyzer, archive_entry_json, archive_entry_metadata, is_interesting_jar_resource,
    jar_class_triage_score, jar_inline_alert_ids, jar_nest_companion_indices,
    jar_should_retain_class, keep_top_ranked, rebase_nested_archive_entry_path,
    rebase_nested_file_path,
};
use crate::analyzers::FileType;
use std::sync::Arc;

/// Slimming retains local spans, so releasing matcher evidence must not
/// resurrect a dominated finding as an unanchored note, live or stored.
#[test]
fn slim_member_retained_spans_preserve_rendering() {
    use crate::output::{TinyOpts, format_context, format_tiny};
    use crate::types::{ContextLine, Criticality, Evidence, Facts, FindingKind};
    use crate::{AnalysisReport, FileAnalysis, Finding, TargetInfo};

    let finding = |id: &str, desc: &str, crit| {
        Finding::new(id, FindingKind::Capability, desc, 0.95)
            .with_criticality(crit)
            .with_evidence(vec![
                Evidence::new("string", "fixture", "evil").with_offset(0),
            ])
    };
    let winner = finding(
        "micro-behaviors/process/execute::winner",
        "Winning behavior",
        Criticality::Hostile,
    );
    let dominated = finding(
        "micro-behaviors/fs/read::dominated",
        "Overlapping behavior",
        Criticality::Notable,
    );
    let file = FileAnalysis {
        path: "member.py".into(),
        file_type: "python".into(),
        size: 11,
        context: vec![ContextLine {
            loc: 0,
            line: Some(1),
            col: Some(1),
            data: b"evil(data)\n".to_vec(),
        }],
        findings: vec![winner, dominated],
        ..FileAnalysis::default()
    };
    let slim = super::rebuild_slim_member(file.clone(), &crate::Engine::empty());
    assert!(file.finding_has_local_offset(1));
    assert!(slim.finding_has_local_offset(1));
    assert_eq!(
        crate::types::traits_findings::finding_spans(&file.findings[1]),
        crate::types::traits_findings::finding_spans(&slim.findings[1])
    );

    let report = |file| {
        let mut report = AnalysisReport::new(TargetInfo::default());
        report.files.push(file);
        report
    };
    let full = report(file);
    let slim = report(slim);
    assert!(!format_tiny(&full).contains("Overlapping behavior"));
    assert_eq!(format_tiny(&full), format_tiny(&slim));
    assert_eq!(
        format_context(&full, &TinyOpts::terminal()),
        format_context(&slim, &TinyOpts::terminal())
    );
    for report in [&full, &slim] {
        let stored = crate::types::compact_from_files(&report.files, Facts::Full);
        let decoded = crate::report_input::decode(&serde_json::to_vec(&stored).unwrap()).unwrap();
        assert_eq!(format_tiny(&decoded.report), format_tiny(report));
    }
}

#[test]
fn jar_inline_yara_selection_requires_an_alert_definition() {
    use crate::composite_rules::TraitDefinition;
    use crate::types::Criticality;
    let definitions: Vec<_> = [
        ("quiet", Criticality::Notable),
        ("baseline", Criticality::Baseline),
        ("exception", Criticality::Exception),
        ("review", Criticality::Suspicious),
        ("attack", Criticality::Hostile),
    ]
    .into_iter()
    .map(|(id, crit)| TraitDefinition {
        id: id.to_string(),
        crit,
        ..Default::default()
    })
    .collect();
    let ids = jar_inline_alert_ids(&definitions);
    assert_eq!(ids.len(), 2);
    for (namespaces, regular_match, expected) in [
        (vec!["inline.review"], false, true),
        (vec!["inline.attack"], false, true),
        (
            vec!["inline.quiet", "inline.baseline", "inline.exception"],
            false,
            false,
        ),
        (vec!["inline.unknown", "review"], false, false),
        (vec![], false, false),
        (vec![], true, true),
        (vec!["inline.quiet"], true, true),
    ] {
        let mut scan = crate::yara_engine::YaraScan {
            inline_traits: namespaces
                .into_iter()
                .map(|ns| (ns.to_string(), vec![]))
                .collect(),
            ..Default::default()
        };
        if regular_match {
            scan.matches.push(serde_json::from_value(serde_json::json!({
                "rule": "regular", "namespace": "test.regular", "crit": "notable", "desc": "Marker"
            })).unwrap());
        }
        assert_eq!(jar_should_retain_class(&scan, &ids), expected, "{scan:?}");
    }
}

#[test]
fn jar_selection_retains_low_scoring_nest_companions_only() {
    let paths: Vec<String> = [
        "p/Client.class",
        "p/Client$Trust.class",
        "p/Client$Trust$1.class",
        "p/ClientExtra.class",
        "other/Client$Trust.class",
        "p/$Proxy1.class",
        "p/$Proxy1$Handler.class",
        "p/Unrelated.class",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(
        jar_nest_companion_indices(&paths, ["p/Client.class"].into_iter()),
        [2, 1]
    );
    // Selecting an inner class restores its outer class and siblings.
    assert_eq!(
        jar_nest_companion_indices(&paths, ["p/Client$Trust.class"].into_iter()),
        [2, 0]
    );
    // Duplicate seeds do not duplicate companions; a leading '$' is legal.
    assert_eq!(
        jar_nest_companion_indices(&paths, ["p/$Proxy1.class", "p/$Proxy1.class"].into_iter()),
        [6]
    );
    assert!(jar_nest_companion_indices(&paths, std::iter::empty()).is_empty());
    assert!(jar_nest_companion_indices(&paths, ["p/ClientExtra.class"].into_iter()).is_empty());
}

#[test]
fn jar_class_triage_prioritizes_salient_apis_over_archive_padding() {
    let padding = b"ordinary/application/Padding java/lang/Object";
    let payload = b"java/lang/ProcessBuilder okhttp3/MultipartBody com/sun/jna/Pointer";

    assert_eq!(jar_class_triage_score(padding), 0);
    assert_eq!(jar_class_triage_score(payload), 3);
    assert!(jar_class_triage_score(payload) > jar_class_triage_score(padding));

    let session_stage = b"getAccessToken java/util/jar/JarInputStream java/lang/reflect/Method";
    let ordinary_io = b"java/io/FileOutputStream java/nio/file/Files";
    let raw_tls =
        b"javax/net/ssl/SSLSocket javax/net/ssl/SNIHostName /dns-query?name= Content-Length:";
    assert!(jar_class_triage_score(session_stage) > jar_class_triage_score(ordinary_io));
    assert!(jar_class_triage_score(raw_tls) > jar_class_triage_score(ordinary_io));

    let mut ranked = vec![1, 5, 2, 4, 3];
    keep_top_ranked(&mut ranked, 3, |left, right| right.cmp(left));
    assert_eq!(ranked, [5, 4, 3]);
}

#[test]
fn archive_member_yara_filetypes_use_detected_binary_type() {
    assert_eq!(
        ArchiveAnalyzer::archive_member_yara_filetypes(&FileType::Elf),
        vec!["elf", "so", "ko"]
    );
    assert_eq!(
        ArchiveAnalyzer::archive_member_yara_filetypes(&FileType::Pe),
        vec!["pe", "exe", "dll", "bat", "ps1"]
    );
    assert_eq!(
        ArchiveAnalyzer::archive_member_yara_filetypes(&FileType::Data),
        vec!["dat", "bin", "payload", "raw", "map"]
    );
    assert!(ArchiveAnalyzer::archive_member_yara_filetypes(&FileType::Unknown).is_empty());
}

#[test]
fn archive_member_yara_skip_skips_yara_rule_sources() {
    // A rule file lists the very strings the rules match on, so scanning it
    // with YARA self-detects and reports the rule's subject as a hostile hit
    // on the corpus that merely documents it.
    for path in [
        "rules/apt_cryptominer.yar",
        "rules/APT_Cryptominer.YARA",
        "third_party/elastic/Multi_Cryptominer_Xmrig.yara",
    ] {
        assert_eq!(
            ArchiveAnalyzer::archive_member_yara_skip_reason(path, &FileType::Python, 4096),
            Some("YARA rule source"),
            "{path} should skip the YARA pass",
        );
    }
    // Not a rule file: `.yarn` and a name merely containing "yara" are scanned.
    for path in ["app/.yarnrc", "docs/yara-tutorial.py"] {
        assert_eq!(
            ArchiveAnalyzer::archive_member_yara_skip_reason(path, &FileType::Python, 4096),
            None,
            "{path} should still be scanned",
        );
    }
}

#[test]
fn archive_member_yara_skip_skips_members_without_targeted_tier() {
    // Members with no filetype→tier mapping (unidentified blobs, lockfiles,
    // and types like Clojure/Beam/ODF that carry no targeted tier) would scan
    // against every tier, so the YARA pass is skipped — their string / trait /
    // payload analysis still runs. Members with a targeted tier are scanned.
    for ft in [
        FileType::Unknown,
        FileType::YarnLock,
        FileType::CargoLock,
        FileType::RequirementsTxt,
        FileType::Clojure,
    ] {
        assert_eq!(
            ArchiveAnalyzer::archive_member_yara_skip_reason("member", &ft, 1024),
            Some("no targeted YARA tier for file type"),
            "{ft:?} should skip YARA",
        );
    }
    for ft in [FileType::Python, FileType::Elf, FileType::Pe] {
        assert_eq!(
            ArchiveAnalyzer::archive_member_yara_skip_reason("member", &ft, 1024),
            None,
            "{ft:?} should be scanned",
        );
    }
}

#[test]
fn archive_member_analysis_skip_matches_all_files_policy() {
    let default_analyzer = ArchiveAnalyzer::new();
    assert_eq!(
        default_analyzer.archive_member_analysis_skip_reason(&FileType::Unknown, "member"),
        Some("non-program archive member and all_files is false")
    );
    for path in [
        "go.work",
        "package/go.work.sum",
        "package/vendor/modules.txt",
    ] {
        assert_eq!(
            default_analyzer.archive_member_analysis_skip_reason(&FileType::Unknown, path),
            None
        );
    }
    // HTML members are analyzed by default: they carry inline <script> and
    // are the whole payload of the npm-as-CDN phishing packages.
    assert_eq!(
        default_analyzer.archive_member_analysis_skip_reason(&FileType::Html, "member"),
        None
    );
    assert_eq!(
        default_analyzer.archive_member_analysis_skip_reason(&FileType::Pe, "member"),
        None
    );
    assert_eq!(
        default_analyzer
            .archive_member_analysis_skip_reason(&FileType::Data, "package/parse.ts.map"),
        None
    );

    let all_files_analyzer =
        ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
            all_files: true,
            ..crate::AnalysisOptions::default()
        }));
    assert_eq!(
        all_files_analyzer.archive_member_analysis_skip_reason(&FileType::Unknown, "member"),
        None
    );
    assert_eq!(
        all_files_analyzer.archive_member_analysis_skip_reason(&FileType::Html, "member"),
        None
    );
}

#[test]
fn unknown_archive_member_with_embedded_pe_is_analyzed_by_default() {
    let mut data = vec![0u8; 4106];
    data[..2].copy_from_slice(b"MZ");
    let offset = 10;
    data[offset..offset + 2].copy_from_slice(b"MZ");
    data[offset + 0x3c..offset + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe = offset + 0x80;
    data[pe..pe + 4].copy_from_slice(b"PE\0\0");
    data[pe + 4..pe + 6].copy_from_slice(&0x14cu16.to_le_bytes());
    data[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
    data[pe + 20..pe + 22].copy_from_slice(&0xe0u16.to_le_bytes());
    data[pe + 24..pe + 26].copy_from_slice(&0x10bu16.to_le_bytes());
    let section = pe + 24 + 0xe0;
    data[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
    data[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
    let analyzer = ArchiveAnalyzer::new();
    let hash = crate::analyzers::utils::calculate_sha256(&data);
    let report = analyzer
        .analyze_extracted_member_on_current_pool(
            std::path::Path::new("wrapper.bin"),
            "wrapper.bin",
            &data,
            &FileType::Unknown,
            &hash,
        )
        .unwrap()
        .unwrap();
    assert!(report.files.iter().any(|file| file.file_type == "pe"));

    data[pe] = 0;
    let hash = crate::analyzers::utils::calculate_sha256(&data);
    assert!(
        analyzer
            .analyze_extracted_member_on_current_pool(
                std::path::Path::new("wrapper.bin"),
                "wrapper.bin",
                &data,
                &FileType::Unknown,
                &hash,
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn nested_archive_stack_preserves_owner_and_stack_headroom() {
    let counters = crate::rayon_nest::isolate_counters();
    let first = crate::rayon_nest::enter_toplevel_analysis_on(false);
    let second = crate::rayon_nest::enter_toplevel_analysis_on(false);
    assert_eq!(counters.toplevel_in_flight(), 2);
    assert!(crate::rayon_nest::inner_work_parallel());
    assert_eq!(counters.inner_owners(), 1);
    let caller = std::thread::current().id();
    super::with_nested_archive_stack(|| {
        assert_eq!(std::thread::current().id(), caller);
        assert!(crate::rayon_nest::inner_work_parallel());
        assert_eq!(counters.inner_owners(), 1, "must borrow the existing owner");
        assert!(stacker::remaining_stack().is_some_and(|bytes| bytes >= 8 * 1024 * 1024));
        Ok(())
    })
    .expect("nested stack boundary");
    assert_eq!(counters.inner_owners(), 1);
    drop(second);
    drop(first);
    assert_eq!(counters.inner_owners(), 0);
    assert_eq!(counters.toplevel_in_flight(), 0);
}

#[test]
#[allow(clippy::panic, reason = "exercise the nested analyzer panic boundary")]
fn nested_archive_stack_keeps_panic_as_an_analysis_error() {
    let error = super::with_nested_archive_stack::<()>(|| panic!("nested stack fixture"))
        .expect_err("nested panic must not escape the analysis boundary");
    assert_eq!(
        error.to_string(),
        "Nested archive analysis panicked: nested stack fixture"
    );
}

#[test]
fn jar_resource_selector_keeps_nested_archives_under_meta_inf() {
    let nested = std::path::Path::new("META-INF/jars/loader.jar");
    assert!(is_interesting_jar_resource(nested, Some(&FileType::Jar)));
    // The extracted-directory path has no precomputed member type, so the
    // extension fallback must preserve the same nested archive.
    assert!(is_interesting_jar_resource(nested, None));

    let service = std::path::Path::new("META-INF/services/example.Service");
    assert!(!is_interesting_jar_resource(service, Some(&FileType::Text)));
    assert!(is_interesting_jar_resource(
        std::path::Path::new("META-INF/MANIFEST.MF"),
        Some(&FileType::Text)
    ));
}

#[test]
fn nested_file_paths_retain_the_complete_provenance_chain() {
    assert_eq!(
        rebase_nested_file_path("bundle.zip!!setup.exe", "setup.exe!!app/bin/payload.dll"),
        "bundle.zip!!setup.exe!!app/bin/payload.dll"
    );
    assert_eq!(
        rebase_nested_file_path(
            "bundle.zip!!setup.exe",
            "bundle.zip!!setup.exe!!app/bin/payload.dll"
        ),
        "bundle.zip!!setup.exe!!app/bin/payload.dll"
    );
    assert_eq!(
        rebase_nested_file_path("bundle.zip!!setup.exe", "payload.dll"),
        "bundle.zip!!setup.exe!!payload.dll"
    );
    assert_eq!(
        rebase_nested_file_path("bundle.zip!!setup.exe", "setup.exe##base64@123"),
        "bundle.zip!!setup.exe##base64@123"
    );
    assert_eq!(
        rebase_nested_file_path(
            "bundle.zip!!src/setup.exe",
            "src/setup.exe##unicode-escape@16"
        ),
        "bundle.zip!!src/setup.exe##unicode-escape@16"
    );
    assert_eq!(
        rebase_nested_file_path("bundle.zip!setup.exe", "setup.exe!!payload.dll"),
        "bundle.zip!!setup.exe!!payload.dll"
    );
}

#[test]
fn nested_archive_entry_paths_keep_the_inventory_separator() {
    assert_eq!(
        rebase_nested_archive_entry_path("inner.tar.gz", "inner.tar.gz!script.sh"),
        "inner.tar.gz!script.sh"
    );
    assert_eq!(
        rebase_nested_archive_entry_path("bundle.zip!setup.exe", "setup.exe!!app/bin/payload.dll"),
        "bundle.zip!setup.exe!app/bin/payload.dll"
    );
}

#[test]
fn archive_entry_metadata_records_extension_type_mismatch() {
    let data = b"not a valid PE";
    let entry = archive_entry_metadata(
        "stage/uusd.exe".to_string(),
        std::path::Path::new("stage/uusd.exe"),
        &FileType::Unknown,
        "sha".to_string(),
        data,
        Some("binary".to_string()),
    );

    assert_eq!(entry.declared_type.as_deref(), Some("pe"));
    assert!(entry.extension_type_mismatch);
    assert_eq!(entry.magic_prefix.as_deref(), Some("6e6f742061207661"));
    assert_eq!(entry.container_kind.as_deref(), Some("binary"));
    assert!(entry.entropy.is_some());

    let value = archive_entry_json(&entry);
    assert_eq!(value["declared_type"], "pe");
    assert_eq!(value["extension_type_mismatch"], true);
    assert_eq!(value["container_kind"], "binary");
}

/// What the extracted-tree walk cannot reach is recorded, not dropped: a
/// payload buried past the depth limit shows up as a gap in the report.
#[test]
fn extracted_files_records_entries_past_the_depth_limit() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("top.js"), b"1").unwrap();
    let mut deep = root.path().to_path_buf();
    for i in 0..=crate::analyzers::archive::guards::MAX_ARCHIVE_MEMBER_DEPTH {
        deep.push(format!("d{i}"));
    }
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("payload.js"), b"require('child_process')").unwrap();

    let mut report = crate::types::AnalysisReport::new(crate::types::TargetInfo {
        path: "x.zip".into(),
        file_type: "zip".into(),
        size_bytes: 0,
        sha256: String::new(),
        architectures: None,
    });
    let files = super::tempdir::extracted_files(root.path(), &mut report);
    assert_eq!(files.len(), 1);
    assert!(
        report
            .metadata
            .errors
            .iter()
            .any(|e| e.contains("deeper than")),
        "{:?}",
        report.metadata.errors
    );
    assert!(!report.analysis_gaps.is_empty());
}
