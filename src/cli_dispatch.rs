use anyhow::{Context, Result};
use cleave::cli;
use cleave::commands::{
    AnalyzeConfig, IterFilesConfig, analyze_command, diff_command, expand_paths,
    extract_exports_command, extract_functions_command, extract_imports_command,
    extract_kv_command, extract_metrics_command, extract_sections_command, extract_strings_command,
    extract_symbols_command, inspect_command, iter_files_command, test_match, test_rules,
    validate_command,
};
use std::fs;

struct AnalyzeDispatchContext<'a> {
    format: &'a cli::OutputFormat,
    disabled: &'a cli::DisabledComponents,
    zip_passwords: &'a [String],
    enable_third_party_global: bool,
    sample_extraction: Option<&'a cleave::SampleExtractionConfig>,
    platforms: &'a [cleave::Platform],
    slow_rule_ms: u64,
    output_to_file: bool,
    output_path: Option<&'a str>,
    max_memory_file_size: u64,
    max_scan_file_size: u64,
    min_crit: Option<cleave::Criticality>,
    max_crit: Option<cleave::Criticality>,
    min_file_crit: Option<cleave::Criticality>,
    max_file_crit: Option<cleave::Criticality>,
    all_files: bool,
}

pub(crate) struct DispatchContext<'a> {
    format: &'a cli::OutputFormat,
    disabled: &'a cli::DisabledComponents,
    analyze: AnalyzeDispatchContext<'a>,
}

struct TestMatchRequest<'a> {
    target: &'a str,
    kind: cli::SearchType,
    method: cli::MatchMethod,
    pattern: Option<&'a str>,
    kv_path: Option<&'a str>,
    exists: Option<bool>,
    size_min: Option<usize>,
    size_max: Option<usize>,
    file_type: Option<cli::DetectFileType>,
    count_min: usize,
    count_max: Option<usize>,
    per_kb_min: Option<f64>,
    per_kb_max: Option<f64>,
    case_insensitive: bool,
    section: Option<&'a str>,
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
    is_check: Option<cleave::composite_rules::StringValidator>,
    encoding: Option<&'a str>,
    entropy_min: Option<f64>,
    entropy_max: Option<f64>,
    length_min: Option<u64>,
    length_max: Option<u64>,
    value_min: Option<f64>,
    value_max: Option<f64>,
    min_size: Option<u64>,
    max_size: Option<u64>,
}

fn analyze_targets(targets: &[String], ctx: &AnalyzeDispatchContext<'_>) -> Result<String> {
    let mut results = Vec::with_capacity(targets.len());
    for target in targets {
        results.push(analyze_command(&AnalyzeConfig {
            target,
            enable_third_party: ctx.enable_third_party_global,
            format: ctx.format,
            zip_passwords: ctx.zip_passwords,
            disabled: ctx.disabled,
            all_files: ctx.all_files,
            sample_extraction: ctx.sample_extraction,
            platforms: ctx.platforms,
            min_hostile_precision: cleave::CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            min_suspicious_precision: cleave::CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            max_memory_file_size: ctx.max_memory_file_size,
            enable_full_validation: false,
            slow_rule_ms: ctx.slow_rule_ms,
            output_to_file: ctx.output_to_file,
            output_path: ctx.output_path,
            max_scan_file_size: ctx.max_scan_file_size,
            min_crit: ctx.min_crit,
            max_crit: ctx.max_crit,
            min_file_crit: ctx.min_file_crit,
            max_file_crit: ctx.max_file_crit,
        })?);
    }
    Ok(results.join(""))
}

fn run_analyze_paths(
    raw_paths: Vec<String>,
    ctx: &AnalyzeDispatchContext<'_>,
    empty_input_message: &'static str,
) -> Result<String> {
    if raw_paths.is_empty() {
        anyhow::bail!(empty_input_message);
    }

    let expanded = expand_paths(raw_paths, ctx.format);
    if expanded.is_empty() {
        anyhow::bail!("No valid paths found (stdin was empty or contained only comments)");
    }

    analyze_targets(&expanded, ctx)
}

fn run_version() {
    use std::time::SystemTime;

    let info = cleave::version_info();

    println!("cleave {}", env!("CARGO_PKG_VERSION"));

    let traits_ver = info.traits_version.as_deref().unwrap_or("unknown");
    let mtime_str = info
        .traits_mtime
        .and_then(|t| {
            t.duration_since(SystemTime::UNIX_EPOCH).ok().map(|d| {
                let secs = d.as_secs() as i64;
                let dt = chrono::DateTime::from_timestamp(secs, 0)?;
                Some(dt.format("%Y-%m-%d %H:%M UTC").to_string())
            })
        })
        .flatten()
        .unwrap_or_else(|| "unknown".into());
    println!("traits  {} ({})", traits_ver, mtime_str);
    println!(
        "rules   {} atomic, {} composite",
        info.trait_count, info.composite_count
    );
    println!("yara    {} rules", info.yara_rules);
    let total = info.trait_count + info.composite_count + info.yara_rules;
    println!("total   {} rules", total);
}

fn run_update_rules(force: bool, check: bool, pin: Option<String>) -> Result<()> {
    let dir = cleave::traits_repo::install_target();
    if let Some(commit) = pin {
        cleave::rule_update::pin(&dir, &commit).map_err(anyhow::Error::msg)?;
    } else if check {
        cleave::rule_update::check(&dir).map_err(anyhow::Error::msg)?;
    } else {
        cleave::rule_update::update(&dir, force).map_err(anyhow::Error::msg)?;
    }

    Ok(())
}

fn run_server(
    bind: &str,
    qps: u32,
    max_size_mb: u64,
    max_rss_gb: Option<u64>,
    dangerous_local_file_paths: Option<String>,
    extract_dir: Option<String>,
) -> Result<()> {
    let bind_addr: std::net::SocketAddr = bind.parse().context(format!(
        "Invalid bind address '{}'. Expected format: IP:PORT (e.g., 127.0.0.1:8080)",
        bind
    ))?;

    let mut allowed_local_paths: Vec<std::path::PathBuf> = dangerous_local_file_paths
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| {
                    std::path::Path::new(p)
                        .canonicalize()
                        .unwrap_or_else(|_| std::path::PathBuf::from(p))
                })
                .collect()
        })
        .unwrap_or_default();

    let extract_dir_path = extract_dir.map(|p| {
        let path = std::path::PathBuf::from(&p);
        if !path.exists() {
            std::fs::create_dir_all(&path).ok();
        }
        path.canonicalize().unwrap_or(path)
    });

    if let Some(ref extract_path) = extract_dir_path
        && !allowed_local_paths.contains(extract_path)
    {
        allowed_local_paths.push(extract_path.clone());
    }

    let config = cleave::server::ServerConfig {
        bind: bind_addr,
        qps,
        max_body_size: (max_size_mb * 1024 * 1024) as usize,
        max_rss_bytes: max_rss_gb
            .map(|gb| gb * 1024 * 1024 * 1024)
            .unwrap_or_else(sysmem::memory_limit),
        allowed_local_paths,
        extract_dir: extract_dir_path,
    };

    let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;
    rt.block_on(cleave::server::run(config))?;
    Ok(())
}

fn run_test_match_command(
    req: &TestMatchRequest<'_>,
    disabled: &cli::DisabledComponents,
    platforms: &[cleave::Platform],
) -> Result<String> {
    test_match(
        req.target,
        req.kind,
        req.method,
        req.pattern,
        req.kv_path,
        req.exists,
        req.size_min,
        req.size_max,
        req.file_type,
        req.count_min,
        req.count_max,
        req.per_kb_min,
        req.per_kb_max,
        req.case_insensitive,
        req.section,
        req.offset,
        req.offset_range,
        req.section_offset,
        req.section_offset_range,
        req.is_check,
        req.encoding,
        req.entropy_min,
        req.entropy_max,
        req.length_min,
        req.length_max,
        req.value_min,
        req.value_max,
        req.min_size,
        req.max_size,
        disabled,
        platforms,
        cleave::CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
        cleave::CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
    )
}

fn run_test_rules_command(
    target: &str,
    rules: &str,
    disabled: &cli::DisabledComponents,
    platforms: &[cleave::Platform],
) -> Result<String> {
    test_rules(
        target,
        rules,
        disabled,
        platforms.to_vec(),
        cleave::CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
        cleave::CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
    )
}

pub(crate) struct DispatchOptions<'a> {
    pub format: &'a cli::OutputFormat,
    pub disabled: &'a cli::DisabledComponents,
    pub zip_passwords: &'a [String],
    pub sample_extraction: Option<&'a cleave::SampleExtractionConfig>,
    pub platforms: &'a [cleave::Platform],
    pub slow_rule_ms: u64,
    pub output_to_file: bool,
    pub output_path: Option<&'a str>,
    pub max_memory_file_size: u64,
    pub max_scan_file_size: u64,
    pub min_crit: Option<cleave::Criticality>,
    pub max_crit: Option<cleave::Criticality>,
    pub min_file_crit: Option<cleave::Criticality>,
    pub max_file_crit: Option<cleave::Criticality>,
    pub all_files: bool,
}

pub(crate) fn build_dispatch_context<'a>(opts: &DispatchOptions<'a>) -> DispatchContext<'a> {
    DispatchContext {
        format: opts.format,
        disabled: opts.disabled,
        analyze: AnalyzeDispatchContext {
            format: opts.format,
            disabled: opts.disabled,
            zip_passwords: opts.zip_passwords,
            enable_third_party_global: !opts.disabled.third_party,
            sample_extraction: opts.sample_extraction,
            platforms: opts.platforms,
            slow_rule_ms: opts.slow_rule_ms,
            output_to_file: opts.output_to_file,
            output_path: opts.output_path,
            max_memory_file_size: opts.max_memory_file_size,
            max_scan_file_size: opts.max_scan_file_size,
            min_crit: opts.min_crit,
            max_crit: opts.max_crit,
            min_file_crit: opts.min_file_crit,
            max_file_crit: opts.max_file_crit,
            all_files: opts.all_files,
        },
    }
}

pub(crate) fn dispatch_command(
    args: cli::Args,
    ctx: &DispatchContext<'_>,
) -> Result<Option<String>> {
    let result = match args.command {
        Some(cli::Command::Analyze { targets }) => run_analyze_paths(
            targets,
            &ctx.analyze,
            "No valid paths found (stdin was empty or contained only comments)",
        )?,
        Some(cli::Command::IterFiles { targets }) => {
            iter_files_command(&IterFilesConfig {
                targets: &targets,
                max_file_size: ctx.analyze.max_scan_file_size,
            })?;
            return Ok(None);
        }
        Some(cli::Command::Version) => {
            run_version();
            return Ok(None);
        }
        Some(cli::Command::Validate { exclude }) => {
            validate_command(ctx.format, exclude.as_deref())?
        }
        Some(cli::Command::Diff {
            old,
            new,
            scope,
            limit_changes,
        }) => diff_command(&old, &new, &scope, limit_changes, ctx.format)?,
        Some(cli::Command::Strings {
            target,
            min_length,
            layer,
        }) => extract_strings_command(&target, min_length, layer.as_deref(), ctx.format)?,
        Some(cli::Command::Symbols { target, layer }) => {
            extract_symbols_command(&target, layer.as_deref(), ctx.format)?
        }
        Some(cli::Command::Imports { target, layer }) => {
            extract_imports_command(&target, layer.as_deref(), ctx.format)?
        }
        Some(cli::Command::Exports { target, layer }) => {
            extract_exports_command(&target, layer.as_deref(), ctx.format)?
        }
        Some(cli::Command::Functions { target, layer }) => {
            extract_functions_command(&target, layer.as_deref(), ctx.format)?
        }
        Some(cli::Command::Sections { target, layer }) => {
            extract_sections_command(&target, layer.as_deref(), ctx.format)?
        }
        Some(cli::Command::Metrics { target, layer }) => {
            extract_metrics_command(&target, layer.as_deref(), ctx.format, ctx.disabled)?
        }
        Some(cli::Command::Facts { tree, targets }) => {
            // Subtree subcommand carries its own targets; the parent
            // `targets` is used only when no subtree is selected.
            let resolved: &[String] = match &tree {
                Some(t) => t.targets(),
                None => &targets,
            };
            if resolved.is_empty() {
                anyhow::bail!(
                    "cleave facts: at least one target file required \
                     (e.g., `cleave facts <file>` or `cleave facts imports <file>`)"
                );
            }
            inspect_command(resolved, tree.as_ref(), ctx.format)?
        }
        Some(cli::Command::Value {
            target,
            path,
            path_flag,
        }) => {
            let path = path.as_deref().or(path_flag.as_deref());
            extract_kv_command(&target, path, ctx.format)?
        }
        Some(cli::Command::TestRules { target, rules }) => {
            run_test_rules_command(&target, &rules, ctx.disabled, ctx.analyze.platforms)?
        }
        Some(cli::Command::TestMatch {
            target,
            r#type,
            method,
            pattern,
            kv_path,
            exists,
            size_min,
            size_max,
            file_type,
            count_min,
            count_max,
            per_kb_min,
            per_kb_max,
            case_insensitive,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            is,
            encoding,
            entropy_min,
            entropy_max,
            length_min,
            length_max,
            value_min,
            value_max,
            min_size,
            max_size,
        }) => run_test_match_command(
            &TestMatchRequest {
                target: &target,
                kind: r#type,
                method,
                pattern: pattern.as_deref(),
                kv_path: kv_path.as_deref(),
                exists,
                size_min,
                size_max,
                file_type,
                count_min,
                count_max,
                per_kb_min,
                per_kb_max,
                case_insensitive,
                section: section.as_deref(),
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                is_check: is,
                encoding: encoding.as_deref(),
                entropy_min,
                entropy_max,
                length_min,
                length_max,
                value_min,
                value_max,
                min_size,
                max_size,
            },
            ctx.disabled,
            ctx.analyze.platforms,
        )?,
        Some(cli::Command::UpdateRules { force, check, pin }) => {
            run_update_rules(force, check, pin)?;
            return Ok(None);
        }
        Some(cli::Command::Serve {
            bind,
            qps,
            max_size_mb,
            max_rss_gb,
            dangerous_local_file_paths,
            extract_dir,
        }) => {
            run_server(
                &bind,
                qps,
                max_size_mb,
                max_rss_gb,
                dangerous_local_file_paths,
                extract_dir,
            )?;
            return Ok(None);
        }
        None => run_analyze_paths(
            args.paths,
            &ctx.analyze,
            "No paths specified. Usage: cleave <path>... or cleave <command>",
        )?,
    };

    Ok(Some(result))
}

pub(crate) fn write_output(
    result: &str,
    output_path: Option<String>,
    format: cli::OutputFormat,
) -> Result<()> {
    if let Some(output_path) = output_path {
        // An empty result in --output mode means the command already streamed
        // its output to the file (directory scans open and write through a
        // BufWriter inside analyze::run to avoid buffering the full report).
        // Skip the write so we don't clobber the streamed file with "".
        if !result.is_empty() {
            fs::write(&output_path, result)
                .context(format!("Failed to write output to {}", output_path))?;
        }
        if format == cli::OutputFormat::Terminal {
            eprintln!("Results written to: {}", output_path);
        }
    } else {
        print!("{}", result);
        use std::io::Write;
        if let Err(e) = std::io::stdout().flush()
            && e.kind() == std::io::ErrorKind::BrokenPipe
        {
            tracing::info!("stdout pipe closed");
        }
    }
    Ok(())
}
