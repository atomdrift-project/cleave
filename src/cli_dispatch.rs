use anyhow::{Context, Result};
use cleave::cli;
use cleave::commands::{
    AnalyzeConfig, IterFilesConfig, diff_command, expand_paths, extract_exports_command,
    extract_functions_command, extract_imports_command, extract_kv_command,
    extract_metrics_command, extract_sections_command, extract_strings_command,
    extract_symbols_command, inspect_command, iter_files_command,
};
#[cfg(feature = "lint")]
use cleave::commands::{MatchRequest, test_match, test_rules};
use std::fs;

struct AnalyzeDispatchContext<'a> {
    format: &'a cli::OutputFormat,
    disabled: &'a cli::DisabledComponents,
    zip_passwords: &'a [String],
    enable_third_party_global: bool,
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
    facts: cleave::types::Facts,
    all_files: bool,
}

pub(crate) struct DispatchContext<'a> {
    format: &'a cli::OutputFormat,
    disabled: &'a cli::DisabledComponents,
    analyze: AnalyzeDispatchContext<'a>,
}

/// The analysis settings the global flags select, for `target`.
fn analyze_config<'a>(ctx: &'a AnalyzeDispatchContext<'a>, target: &'a str) -> AnalyzeConfig<'a> {
    AnalyzeConfig {
        target,
        enable_third_party: ctx.enable_third_party_global,
        format: ctx.format,
        zip_passwords: ctx.zip_passwords,
        disabled: ctx.disabled,
        all_files: ctx.all_files,
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
        facts: ctx.facts,
    }
}

fn analyze_targets(targets: &[String], ctx: &AnalyzeDispatchContext<'_>) -> Result<String> {
    cleave::commands::analyze_targets(&analyze_config(ctx, ""), targets)
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

fn run_update_rules(force: bool, check: bool, pin: Option<String>) -> Result<()> {
    let dir = cleave::traits_repo::install_target();
    if let Some(commit) = pin {
        cleave::rule_update::pin(&dir, &commit)?;
    } else if check {
        cleave::rule_update::check(&dir)?;
    } else {
        cleave::rule_update::refresh(force, false)?;
    }

    Ok(())
}

#[cfg(feature = "lint")]
fn run_test_match_command(
    req: &MatchRequest<'_>,
    disabled: &cli::DisabledComponents,
    platforms: &[cleave::Platform],
) -> Result<String> {
    test_match(
        req,
        disabled,
        platforms,
        cleave::CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
        cleave::CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
    )
}

#[cfg(feature = "lint")]
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
    pub facts: cleave::types::Facts,
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
            facts: opts.facts,
            all_files: opts.all_files,
        },
    }
}

pub(crate) fn dispatch_command(
    args: cli::Args,
    ctx: &DispatchContext<'_>,
) -> Result<Option<String>> {
    let result = match args.command {
        Some(cli::Command::Render { .. }) => {
            anyhow::bail!("render must run before analysis bootstrap")
        }
        Some(cli::Command::Analyze { targets }) => run_analyze_paths(
            targets,
            &ctx.analyze,
            "No valid paths found (stdin was empty or contained only comments)",
        )?,
        Some(cli::Command::IterFiles {
            targets,
            newer_than,
        }) => {
            let config = IterFilesConfig {
                targets: &targets,
                max_file_size: ctx.analyze.max_scan_file_size,
                newer_than,
            };
            // Stream straight to the destination: a large tree's listing is
            // never buffered, and write_output skips the empty result.
            match ctx.analyze.output_path {
                Some(path) => iter_files_command(
                    &config,
                    fs::File::create(path)
                        .with_context(|| format!("Failed to create output file {path}"))?,
                )?,
                None => iter_files_command(&config, std::io::stdout().lock())?,
            }
            String::new()
        }
        Some(cli::Command::Version) => format!(
            "{}\n",
            cleave::version_report("cleave", env!("CARGO_PKG_VERSION"))
        ),
        #[cfg(feature = "lint")]
        Some(cli::Command::RegexCost { case_insensitive }) => {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let pat = line?;
                if pat.is_empty() {
                    continue;
                }
                if cleave::regex_explodes(&pat, case_insensitive) {
                    println!("explode");
                } else {
                    println!("ok");
                }
            }
            return Ok(None);
        }
        #[cfg(feature = "lint")]
        Some(cli::Command::Validate { exclude, soft }) => {
            cleave::commands::validate::run_with_options(
                ctx.format,
                exclude.as_deref(),
                args.verbose,
                soft,
                ctx.analyze.slow_rule_ms,
            )?
        }
        Some(cli::Command::Diff {
            old,
            new,
            scope,
            limit_changes,
        }) => diff_command(
            &old,
            &new,
            &scope,
            limit_changes,
            ctx.format,
            &cleave::commands::analysis_options(&analyze_config(&ctx.analyze, "")),
        )?,
        Some(cli::Command::Strings {
            target,
            min_length,
            layer,
        }) => extract_strings_command(
            &target,
            min_length,
            layer.as_deref(),
            ctx.format,
            ctx.disabled,
        )?,
        Some(cli::Command::Symbols { target, layer }) => {
            extract_symbols_command(&target, layer.as_deref(), ctx.format, ctx.disabled)?
        }
        Some(cli::Command::Imports { target, layer }) => {
            extract_imports_command(&target, layer.as_deref(), ctx.format, ctx.disabled)?
        }
        Some(cli::Command::Exports { target, layer }) => {
            extract_exports_command(&target, layer.as_deref(), ctx.format, ctx.disabled)?
        }
        Some(cli::Command::Functions { target, layer }) => {
            extract_functions_command(&target, layer.as_deref(), ctx.format, ctx.disabled)?
        }
        Some(cli::Command::Sections { target, layer }) => {
            extract_sections_command(&target, layer.as_deref(), ctx.format, ctx.disabled)?
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
            inspect_command(resolved, tree.as_ref(), ctx.format, ctx.disabled)?
        }
        Some(cli::Command::Value {
            target,
            path,
            path_flag,
        }) => {
            let path = path.as_deref().or(path_flag.as_deref());
            extract_kv_command(&target, path, ctx.format, ctx.disabled)?
        }
        #[cfg(feature = "lint")]
        Some(cli::Command::TestRules { target, rules }) => {
            run_test_rules_command(&target, &rules, ctx.disabled, ctx.analyze.platforms)?
        }
        #[cfg(feature = "lint")]
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
            &MatchRequest {
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
        #[cfg(not(feature = "lint"))]
        Some(
            cli::Command::Validate { .. }
            | cli::Command::TestRules { .. }
            | cli::Command::TestMatch { .. }
            | cli::Command::RegexCost { .. },
        ) => anyhow::bail!(
            "this cleave was built without the `lint` feature, which provides the rule linter"
        ),
        Some(cli::Command::UpdateRules { force, check, pin }) => {
            run_update_rules(force, check, pin)?;
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
    // Every command eventually crosses this boundary, including developer and
    // extraction commands whose rows contain sample-derived strings, symbol
    // names, section names, and structured values. Keep JSON byte-for-byte
    // machine-readable; terminal formats retain renderer SGR colors while all
    // other control sequences become visible text.
    let safe_result = (format != cli::OutputFormat::Json)
        .then(|| cleave::output::sanitize_terminal_output(result));
    let result = safe_result.as_deref().unwrap_or(result);

    if let Some(output_path) = output_path {
        // An empty result in --output mode means the command already streamed
        // its output to the file (directory scans open and write through a
        // BufWriter inside analyze::run to avoid buffering the full report).
        // Skip the write so we don't clobber the streamed file with "".
        if !result.is_empty() {
            fs::write(&output_path, result)
                .context(format!("Failed to write output to {}", output_path))?;
        }
        if format != cli::OutputFormat::Json {
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
