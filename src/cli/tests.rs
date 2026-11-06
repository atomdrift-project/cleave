use super::*;
use clap::ValueEnum;

#[test]
fn full_facts_flag_is_not_accepted() {
    let error = Args::try_parse_from(["cleave", "--full-facts", "file.bin"]).unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn render_accepts_local_format_and_output_options() {
    let args = Args::try_parse_from([
        "cleave",
        "render",
        "before.json",
        "--format",
        "toc",
        "-o",
        "view.txt",
    ])
    .unwrap();
    assert_eq!(args.format(), OutputFormat::Toc);
    assert_eq!(args.output.as_deref(), Some("view.txt"));
    assert!(matches!(args.command, Some(Command::Render { args })
        if args.input == "before.json"));
}

#[test]
fn test_reject_removed_extract_dir_flag() {
    let error =
        Args::try_parse_from(["cleave", "--extract-dir", "samples", "file.bin"]).unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn test_parse_paths_without_subcommand() {
    let args = Args::try_parse_from(["cleave", "file1.bin", "file2.bin", "dir1"]).unwrap();

    assert!(args.command.is_none());
    assert_eq!(args.paths, vec!["file1.bin", "file2.bin", "dir1"]);
}

#[test]
fn test_parse_single_path_without_subcommand() {
    let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();

    assert!(args.command.is_none());
    assert_eq!(args.paths, vec!["file.bin"]);
}

#[test]
fn test_parse_analyze_command() {
    let args = Args::try_parse_from(["cleave", "analyze", "file.bin"]).unwrap();

    assert!(matches!(args.command, Some(Command::Analyze { .. })));
    if let Some(Command::Analyze { targets }) = args.command {
        assert_eq!(targets, vec!["file.bin"]);
    }
}

#[test]
fn test_detect_file_type_prefers_systemd_name() {
    assert_eq!(
        DetectFileType::from_str("systemd", false).unwrap(),
        DetectFileType::SystemdService
    );
    assert_eq!(
        DetectFileType::from_str("systemd-service", false).unwrap(),
        DetectFileType::SystemdService
    );
}

#[test]
fn test_parse_analyze_multiple_targets() {
    let args =
        Args::try_parse_from(["cleave", "analyze", "file1.bin", "file2.bin", "dir1"]).unwrap();

    if let Some(Command::Analyze { targets }) = args.command {
        assert_eq!(targets, vec!["file1.bin", "file2.bin", "dir1"]);
    }
}

#[test]
fn test_parse_diff_command() {
    let args = Args::try_parse_from(["cleave", "diff", "old.bin", "new.bin"]).unwrap();

    assert!(matches!(args.command, Some(Command::Diff { .. })));
    if let Some(Command::Diff {
        old,
        new,
        scope,
        limit_changes,
    }) = args.command
    {
        assert_eq!(old, "old.bin");
        assert_eq!(new, "new.bin");
        assert_eq!(scope, "all");
        assert_eq!(limit_changes, 100);
    }
}

#[test]
fn test_parse_diff_command_with_scope() {
    let args = Args::try_parse_from([
        "cleave",
        "diff",
        "--scope=traits,value",
        "--limit-changes=0",
        "a",
        "b",
    ])
    .unwrap();
    if let Some(Command::Diff {
        scope,
        limit_changes,
        ..
    }) = args.command
    {
        assert_eq!(scope, "traits,value");
        assert_eq!(limit_changes, 0);
    } else {
        panic!("expected diff command");
    }
}

#[test]
fn test_parse_strings_command() {
    let args = Args::try_parse_from(["cleave", "strings", "file.bin"]).unwrap();

    assert!(matches!(args.command, Some(Command::Strings { .. })));
    if let Some(Command::Strings {
        target,
        min_length,
        layer,
    }) = args.command
    {
        assert_eq!(target, "file.bin");
        assert_eq!(min_length, 4); // Default value
        assert!(layer.is_none());
    }
}

#[test]
fn test_parse_strings_command_with_min_length() {
    let args = Args::try_parse_from(["cleave", "strings", "file.bin", "-m", "10"]).unwrap();

    if let Some(Command::Strings {
        target,
        min_length,
        layer,
    }) = args.command
    {
        assert_eq!(target, "file.bin");
        assert_eq!(min_length, 10);
        assert!(layer.is_none());
    }
}

#[test]
fn test_parse_strings_command_with_layer() {
    let args = Args::try_parse_from(["cleave", "strings", "file.bin", "--layer", "upx@0"]).unwrap();

    if let Some(Command::Strings {
        target,
        min_length,
        layer,
    }) = args.command
    {
        assert_eq!(target, "file.bin");
        assert_eq!(min_length, 4);
        assert_eq!(layer, Some("upx@0".to_string()));
    }
}

#[test]
fn test_parse_symbols_command() {
    let args = Args::try_parse_from(["cleave", "symbols", "file.bin"]).unwrap();

    assert!(matches!(args.command, Some(Command::Symbols { .. })));
    if let Some(Command::Symbols { target, layer }) = args.command {
        assert_eq!(target, "file.bin");
        assert!(layer.is_none());
    }
}

#[test]
fn test_parse_symbols_command_with_layer() {
    let args = Args::try_parse_from(["cleave", "symbols", "file.bin", "--layer", "upx@0"]).unwrap();

    if let Some(Command::Symbols { target, layer }) = args.command {
        assert_eq!(target, "file.bin");
        assert_eq!(layer, Some("upx@0".to_string()));
    }
}

#[test]
fn test_parse_json_flag() {
    let args = Args::try_parse_from(["cleave", "--json", "file.bin"]).unwrap();
    assert!(args.json);
    assert!(matches!(args.format(), OutputFormat::Json));
}

#[test]
fn test_parse_no_json_flag() {
    let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
    assert!(!args.json);
    assert!(matches!(args.format(), OutputFormat::Annotate));
}

#[test]
fn test_parse_format_json() {
    let args = Args::try_parse_from(["cleave", "--format", "json", "file.bin"]).unwrap();
    assert!(matches!(args.format(), OutputFormat::Json));
}

#[test]
fn format_shorthands_last_one_wins() {
    let parse = |args: &[&str]| {
        let mut argv = vec!["cleave"];
        argv.extend_from_slice(args);
        argv.push("file.bin");
        Args::try_parse_from(argv).unwrap().format()
    };
    assert_eq!(parse(&["--toc"]), OutputFormat::Toc);
    assert_eq!(parse(&["--annotate"]), OutputFormat::Annotate);
    assert_eq!(parse(&["--json"]), OutputFormat::Json);
    assert_eq!(parse(&["--format", "toc", "--json"]), OutputFormat::Json);
    assert_eq!(parse(&["--json", "--format", "toc"]), OutputFormat::Toc);
    assert_eq!(parse(&["--json", "--annotate"]), OutputFormat::Annotate);
    assert_eq!(parse(&["--toc", "--json"]), OutputFormat::Json);
    // Global: accepted after a subcommand too.
    let args = Args::try_parse_from(["cleave", "render", "r.json", "--toc"]).unwrap();
    assert_eq!(args.format(), OutputFormat::Toc);
}

#[test]
fn retired_formats_alias_or_fail() {
    let parse = |f| Args::try_parse_from(["cleave", "--format", f, "file.bin"]);
    assert_eq!(parse("jsonl").unwrap().format(), OutputFormat::Json);
    assert_eq!(parse("terminal").unwrap().format(), OutputFormat::Annotate);
    for retired in ["tiny", "snapshot"] {
        let error = parse(retired).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }
}

#[test]
fn test_parse_output_file() {
    let args = Args::try_parse_from(["cleave", "-o", "results.json", "file.bin"]).unwrap();
    assert_eq!(args.output, Some("results.json".to_string()));
}

#[test]
fn test_parse_verbose() {
    let args = Args::try_parse_from(["cleave", "-v", "file.bin"]).unwrap();
    assert!(args.verbose);
}

#[test]
fn test_parse_no_verbose() {
    let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
    assert!(!args.verbose);
}

#[test]
fn test_parse_all_options_together() {
    let args = Args::try_parse_from([
        "cleave",
        "--json",
        "-o",
        "output.json",
        "-v",
        "file1.bin",
        "file2.bin",
    ])
    .unwrap();

    assert!(args.json);
    assert!(matches!(args.format(), OutputFormat::Json));
    assert_eq!(args.output, Some("output.json".to_string()));
    assert!(args.verbose);
    assert_eq!(args.paths, vec!["file1.bin", "file2.bin"]);
}

#[test]
fn test_parse_no_args_succeeds_with_empty_paths() {
    // Running without args is now valid (will show help or error at runtime)
    let result = Args::try_parse_from(["cleave"]);
    assert!(result.is_ok());
    assert!(result.unwrap().paths.is_empty());
}

#[test]
fn test_disabled_components_default() {
    let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
    let disabled = args.disabled_components();
    // Nothing is disabled by default
    assert!(!disabled.third_party);
    assert!(!disabled.yara);
    assert!(!disabled.upx);
}

#[test]
fn test_disabled_components_custom() {
    let args = Args::try_parse_from(["cleave", "--disable", "yara", "file.bin"]).unwrap();
    let disabled = args.disabled_components();
    assert!(disabled.yara);
    assert!(!disabled.upx);
    assert!(!disabled.third_party);
}

#[test]
fn test_disabled_components_all() {
    let args =
        Args::try_parse_from(["cleave", "--disable", "yara,upx,third-party", "file.bin"]).unwrap();
    let disabled = args.disabled_components();
    assert!(disabled.yara);
    assert!(disabled.upx);
    assert!(disabled.third_party);
}

#[test]
fn test_disabled_components_from_str() {
    let disabled = Args::try_parse_from(["cleave", "--disable", "yara,upx", "f"])
        .unwrap()
        .disabled_components();
    assert!(disabled.yara);
    assert!(disabled.upx);
    assert!(!disabled.third_party);
}

#[test]
fn test_disabled_components_from_str_with_spaces() {
    let disabled = Args::try_parse_from(["cleave", "--disable", "yara,upx", "f"])
        .unwrap()
        .disabled_components();
    assert!(disabled.yara);
    assert!(disabled.upx);
    assert!(!disabled.third_party);
}

#[test]
fn test_disable_rejects_unknown_components() {
    assert!(Args::try_parse_from(["cleave", "--disable", "yarra", "f"]).is_err());
    // rizin is gone; binary recovery cannot be turned off.
    assert!(Args::try_parse_from(["cleave", "--disable", "rizin", "f"]).is_err());
}

#[test]
fn test_nothing_disabled_by_default() {
    let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
    let disabled = args.disabled_components();
    assert!(!disabled.yara);
    assert!(!disabled.upx);
    assert!(!disabled.third_party);
}

#[test]
fn test_parse_metrics_command() {
    let args = Args::try_parse_from(["cleave", "metrics", "file.bin"]).unwrap();

    assert!(matches!(args.command, Some(Command::Metrics { .. })));
    if let Some(Command::Metrics { target, layer }) = args.command {
        assert_eq!(target, "file.bin");
        assert!(layer.is_none());
    }
}

#[test]
fn test_parse_metrics_command_with_layer() {
    let args = Args::try_parse_from(["cleave", "metrics", "file.bin", "--layer", "upx@0"]).unwrap();

    if let Some(Command::Metrics { target, layer }) = args.command {
        assert_eq!(target, "file.bin");
        assert_eq!(layer, Some("upx@0".to_string()));
    }
}

#[test]
fn test_parse_test_match_metrics() {
    let args = Args::try_parse_from([
        "cleave",
        "test-match",
        "file.bin",
        "--type",
        "metrics",
        "--pattern",
        "binary.avg_complexity",
        "--value-min",
        "10.0",
        "--value-max",
        "50.0",
    ])
    .unwrap();

    if let Some(Command::TestMatch {
        target,
        r#type,
        pattern,
        value_min,
        value_max,
        ..
    }) = args.command
    {
        assert_eq!(target, "file.bin");
        assert_eq!(r#type, SearchType::Metrics);
        assert_eq!(pattern, Some("binary.avg_complexity".to_string()));
        assert_eq!(value_min, Some(10.0));
        assert_eq!(value_max, Some(50.0));
    } else {
        panic!("Expected TestMatch command");
    }
}

#[test]
fn test_parse_test_match_metrics_with_size_constraints() {
    let args = Args::try_parse_from([
        "cleave",
        "test-match",
        "file.bin",
        "--type",
        "metrics",
        "--pattern",
        "binary.import_count",
        "--value-min",
        "5.0",
        "--min-size",
        "1024",
        "--max-size",
        "1048576",
    ])
    .unwrap();

    if let Some(Command::TestMatch {
        target,
        r#type,
        pattern,
        value_min,
        min_size,
        max_size,
        ..
    }) = args.command
    {
        assert_eq!(target, "file.bin");
        assert_eq!(r#type, SearchType::Metrics);
        assert_eq!(pattern, Some("binary.import_count".to_string()));
        assert_eq!(value_min, Some(5.0));
        assert_eq!(min_size, Some(1024));
        assert_eq!(max_size, Some(1048576));
    } else {
        panic!("Expected TestMatch command");
    }
}

#[test]
fn test_search_type_metrics_copy() {
    let search_type = SearchType::Metrics;
    let copied = search_type; // Copy, not Clone
    assert_eq!(copied, SearchType::Metrics);
}

#[test]
fn test_search_type_metrics_debug() {
    let search_type = SearchType::Metrics;
    let debug_str = format!("{:?}", search_type);
    assert!(debug_str.contains("Metrics"));
}

// ==================== Criticality filter flag tests ====================

#[test]
fn test_parse_min_crit() {
    let args = Args::try_parse_from(["cleave", "--min-crit", "notable", "file.bin"]).unwrap();
    assert_eq!(args.min_crit, Some(crate::types::Criticality::Notable));
}

#[test]
fn test_parse_crit_case_insensitive() {
    let args = Args::try_parse_from(["cleave", "--min-crit", "HOSTILE", "file.bin"]).unwrap();
    assert_eq!(args.min_crit, Some(crate::types::Criticality::Hostile));
}

#[test]
fn test_parse_crit_all_levels() {
    for (name, expected) in [
        ("filtered", crate::types::Criticality::Filtered),
        ("component", crate::types::Criticality::Component),
        ("baseline", crate::types::Criticality::Baseline),
        ("notable", crate::types::Criticality::Notable),
        ("suspicious", crate::types::Criticality::Suspicious),
        ("hostile", crate::types::Criticality::Hostile),
    ] {
        let args = Args::try_parse_from(["cleave", "--min-crit", name, "file.bin"]).unwrap();
        assert_eq!(args.min_crit, Some(expected), "Failed for {}", name);
    }
}

#[test]
fn test_parse_crit_invalid() {
    let result = Args::try_parse_from(["cleave", "--min-crit", "unknown", "file.bin"]);
    assert!(result.is_err());
}

#[test]
fn test_parse_no_crit_flags() {
    let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
    assert!(args.min_crit.is_none());
}

#[test]
fn test_parse_repeated_zip_passwords() {
    let args = Args::try_parse_from([
        "cleave",
        "--zip-password",
        "first",
        "--zip-password",
        "second",
        "file.bin",
    ])
    .unwrap();

    assert_eq!(args.zip_passwords, ["first", "second"]);
}

#[test]
fn extra_zip_passwords_are_appended_without_duplicates() {
    let args = Args::try_parse_from([
        "cleave",
        "--zip-password",
        "infected",
        "--zip-password",
        "sample-key",
        "--zip-password",
        "sample-key",
        "file.bin",
    ])
    .unwrap();
    let passwords = args.archive_passwords();

    assert_eq!(passwords.last().map(String::as_str), Some("sample-key"));
    assert_eq!(passwords.iter().filter(|p| *p == "sample-key").count(), 1);
    assert_eq!(passwords.iter().filter(|p| *p == "infected").count(), 1);
}
