//! Test pattern matching conditions against files.
//!
//! This module provides the `test-match` command implementation, which validates
//! search patterns, count constraints, and location filters with detailed diagnostics.

use crate::analyzers::{FileType, detect_file_type};
use crate::commands::shared::{cli_file_type_to_internal, create_analysis_report, dev_engine};
use crate::commands::test::{build_test_capability_mapper, evaluation_data, prepare_test_analysis};
use crate::composite_rules::condition::StringValidator;
use crate::composite_rules::context::StringParams;
use crate::composite_rules::evaluators::symbol_string::validate_match;
use crate::test_rules::{RuleDebugger, find_matching_strings, find_matching_symbols};
use crate::{cli, composite_rules, types};
use anyhow::Result;
use colored::Colorize;
use std::path::Path;

mod searches;
mod suggestions;

/// One `test-match` invocation: what to search a file for, how, and where.
#[derive(Debug, Clone, Copy)]
pub struct MatchRequest<'a> {
    /// Path to the file to test.
    pub target: &'a str,
    /// Type of search (text, string_literal, string_value, symbol, raw, kv, hex,
    /// encoded, section, metrics).
    pub kind: cli::SearchType,
    /// Match method (exact, contains, regex, word).
    pub method: cli::MatchMethod,
    /// Pattern to search for.
    pub pattern: Option<&'a str>,
    /// Key-value path for structured data searches.
    pub kv_path: Option<&'a str>,
    /// For value searches: require the path to exist (or not).
    pub exists: Option<bool>,
    /// For value searches: the value's minimum size.
    pub size_min: Option<usize>,
    /// For value searches: the value's maximum size.
    pub size_max: Option<usize>,
    /// Override the detected file type.
    pub file_type: Option<cli::DetectFileType>,
    /// Minimum number of matches.
    pub count_min: usize,
    /// Maximum number of matches.
    pub count_max: Option<usize>,
    /// Minimum match density (matches per KB).
    pub per_kb_min: Option<f64>,
    /// Maximum match density (matches per KB).
    pub per_kb_max: Option<f64>,
    /// Match case-insensitively.
    pub case_insensitive: bool,
    /// Limit the search to one section.
    pub section: Option<&'a str>,
    /// Search at this file offset.
    pub offset: Option<i64>,
    /// Search within this file offset range.
    pub offset_range: Option<(i64, Option<i64>)>,
    /// Search at this offset relative to `section`.
    pub section_offset: Option<i64>,
    /// Search within this offset range relative to `section`.
    pub section_offset_range: Option<(i64, Option<i64>)>,
    /// A high-fidelity validator each match must pass.
    pub is_check: Option<StringValidator>,
    /// Encoding filter for encoded string searches.
    pub encoding: Option<&'a str>,
    /// Minimum section entropy.
    pub entropy_min: Option<f64>,
    /// Maximum section entropy.
    pub entropy_max: Option<f64>,
    /// Minimum section or string length.
    pub length_min: Option<u64>,
    /// Maximum section or string length.
    pub length_max: Option<u64>,
    /// Minimum metric value.
    pub value_min: Option<f64>,
    /// Maximum metric value.
    pub value_max: Option<f64>,
    /// Minimum file size (for metrics).
    pub min_size: Option<u64>,
    /// Maximum file size (for metrics).
    pub max_size: Option<u64>,
}

/// Test pattern matching against a file with alternative suggestions.
///
/// This function performs comprehensive pattern matching tests against a target file,
/// showing detailed diagnostics about matches, constraints, and suggestions for
/// alternative search strategies.
///
/// # Arguments
///
/// * `request` - What to search for, how, and where
/// * `disabled` - Components `--disable` turned off (UPX unpacking applies here)
/// * `platforms` - Platform filters for evaluation
/// * `min_hostile_precision` - Minimum precision for hostile rules
/// * `min_suspicious_precision` - Minimum precision for suspicious rules
pub fn run(
    request: &MatchRequest<'_>,
    disabled: &cli::DisabledComponents,
    platforms: &[composite_rules::Platform],
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) -> Result<String> {
    let MatchRequest {
        target,
        kind: search_type,
        pattern,
        kv_path,
        file_type: file_type_override,
        count_min,
        count_max,
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        entropy_min,
        entropy_max,
        length_min,
        length_max,
        value_min,
        value_max,
        ..
    } = *request;
    // Validate arguments based on search type
    if search_type == cli::SearchType::Kv {
        if kv_path.is_none() {
            anyhow::bail!("--path is required for value searches");
        }
    } else if search_type == cli::SearchType::Section {
        // Section searches don't require pattern (can search by length or entropy alone)
        let has_constraints = count_min > 1
            || count_max.is_some()
            || length_min.is_some()
            || length_max.is_some()
            || entropy_min.is_some()
            || entropy_max.is_some();
        if pattern.is_none() && !has_constraints {
            anyhow::bail!(
                "--pattern is required for section searches unless using size/entropy constraints (--count-min/max, --length-min/max, --entropy-min/max)"
            );
        }
    } else if search_type == cli::SearchType::Metrics {
        if pattern.is_none() {
            anyhow::bail!(
                "--pattern is required for metrics searches (use field path like 'binary.avg_complexity')"
            );
        }
        if value_min.is_none() && value_max.is_none() {
            anyhow::bail!(
                "At least one of --value-min or --value-max is required for metrics searches"
            );
        }
    } else if pattern.is_none() {
        anyhow::bail!("--pattern is required for {:?} searches", search_type);
    }

    // Validate location constraints
    if offset.is_some() && offset_range.is_some() {
        anyhow::bail!("--offset and --offset-range are mutually exclusive");
    }
    if section_offset.is_some() && section_offset_range.is_some() {
        anyhow::bail!("--section-offset and --section-offset-range are mutually exclusive");
    }
    if (section_offset.is_some() || section_offset_range.is_some()) && section.is_none() {
        anyhow::bail!("--section-offset and --section-offset-range require --section");
    }

    let pattern = pattern.unwrap_or("");

    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    // Use specified file type or auto-detect
    let file_type = if let Some(ft) = file_type_override {
        cli_file_type_to_internal(ft)
    } else {
        detect_file_type(path)?
    };

    // Load capability mapper with full validation (test-match is a developer command)
    // Allow skipping for faster tests with CLEAVE_SKIP_TRAITS
    let engine = dev_engine(
        build_test_capability_mapper(
            platforms.to_owned(),
            min_hostile_precision,
            min_suspicious_precision,
        )?,
        disabled,
    );
    let capability_mapper = engine.rules();

    let prepared = prepare_test_analysis(path, file_type, &engine)?;
    if prepared.is_fat_macho {
        eprintln!("Note: FAT binary detected, using full file for evaluation");
    }
    let is_fat = prepared.is_fat_macho;
    let binary_data = &prepared.preferred_binary_data;
    let report = &prepared.report;

    // Evaluation data: full file for FAT binaries, slice otherwise
    let eval_data = evaluation_data(&prepared.full_data, binary_data, is_fat);

    // Create debugger to access search functions
    // Note: test-match doesn't use YARA results since it tests individual conditions
    // For FAT binaries, use full file so string offsets are file-relative
    let debugger = RuleDebugger::with_parsed(
        capability_mapper,
        report,
        eval_data,
        platforms.to_owned(),
        None, // test-match evaluates conditions directly, not via full rule path
        engine.filefacts_options().path(path).open(eval_data),
    );
    let context_info = debugger.context_info();

    // Create section map for location constraint resolution
    let section_map = composite_rules::SectionMap::from_binary(eval_data);

    let internal_file_type = match file_type {
        FileType::Pe => composite_rules::FileType::Pe,
        FileType::Elf => composite_rules::FileType::Elf,
        FileType::MachO => composite_rules::FileType::Macho,
        FileType::JavaScript => composite_rules::FileType::JavaScript,
        FileType::Python => composite_rules::FileType::Python,
        FileType::Java => composite_rules::FileType::Java,
        FileType::Go => composite_rules::FileType::Go,
        FileType::Rust => composite_rules::FileType::Rust,
        FileType::Ruby => composite_rules::FileType::Ruby,
        FileType::Shell => composite_rules::FileType::Shell,
        FileType::Jcl => composite_rules::FileType::Jcl,
        FileType::PowerShell => composite_rules::FileType::PowerShell,
        FileType::Php => composite_rules::FileType::Php,
        FileType::TypeScript => composite_rules::FileType::TypeScript,
        FileType::C => composite_rules::FileType::C,
        FileType::CSharp => composite_rules::FileType::CSharp,
        FileType::Lua => composite_rules::FileType::Lua,
        FileType::Perl => composite_rules::FileType::Perl,
        FileType::Swift => composite_rules::FileType::Swift,
        FileType::ObjectiveC => composite_rules::FileType::ObjectiveC,
        FileType::Groovy => composite_rules::FileType::Groovy,
        FileType::Scala => composite_rules::FileType::Scala,
        FileType::Zig => composite_rules::FileType::Zig,
        FileType::Elixir => composite_rules::FileType::Elixir,
        FileType::Html => composite_rules::FileType::Html,
        FileType::Jsp => composite_rules::FileType::Jsp,
        FileType::Asp => composite_rules::FileType::Asp,
        FileType::Cfml => composite_rules::FileType::Cfml,
        FileType::Tex => composite_rules::FileType::Tex,
        FileType::Yara => composite_rules::FileType::Yara,
        FileType::PostScript => composite_rules::FileType::PostScript,
        FileType::DosCom => composite_rules::FileType::DosCom,
        FileType::Shellcode => composite_rules::FileType::Shellcode,
        FileType::Mirc => composite_rules::FileType::Mirc,
        FileType::IrcII => composite_rules::FileType::IrcII,
        FileType::Markdown => composite_rules::FileType::Markdown,
        FileType::Makefile => composite_rules::FileType::Makefile,
        FileType::Dockerfile => composite_rules::FileType::Dockerfile,
        FileType::Text => composite_rules::FileType::Text,
        FileType::Data => composite_rules::FileType::Data,
        FileType::Wasm => composite_rules::FileType::Wasm,
        FileType::Dex => composite_rules::FileType::Dex,
        FileType::OleDoc => composite_rules::FileType::OleDoc,
        FileType::Msi => composite_rules::FileType::Msi,
        FileType::Json => composite_rules::FileType::Json,
        FileType::PackageJson => composite_rules::FileType::PackageJson,
        FileType::PackageLockJson => composite_rules::FileType::PackageLockJson,
        FileType::ChromeManifest => composite_rules::FileType::ChromeManifest,
        FileType::VsixManifest => composite_rules::FileType::VsixManifest,
        FileType::SystemdService => composite_rules::FileType::SystemdService,
        FileType::Plist => composite_rules::FileType::Plist,
        FileType::Nib => composite_rules::FileType::Nib,
        FileType::PkgInfo => composite_rules::FileType::PkgInfo,
        _ => composite_rules::FileType::All,
    };

    // Resolve effective byte range from location constraints
    // Returns (start, end, effective_size) where effective_size is used for density calculations

    // Check if any location constraints are specified
    let has_location_constraints = section.is_some()
        || offset.is_some()
        || offset_range.is_some()
        || section_offset.is_some()
        || section_offset_range.is_some();

    // Perform the requested search
    let ctx = MatchCtx {
        request: *request,
        pattern,
        file_type,
        internal_file_type,
        capability_mapper,
        prepared: &prepared,
        binary_data,
        report,
        context_info: &context_info,
        section_map: &section_map,
        has_location_constraints,
        engine: &engine,
        path,
        platforms,
    };
    let outcome = match search_type {
        cli::SearchType::StringValue => searches::string_value(&ctx),
        cli::SearchType::Text => searches::text(&ctx),
        cli::SearchType::StringLiteral => searches::string_literal(&ctx),
        cli::SearchType::Symbol => searches::symbol(&ctx),
        cli::SearchType::Raw => searches::raw(&ctx),
        cli::SearchType::Kv => searches::kv(&ctx),
        cli::SearchType::Hex => searches::hex(&ctx),
        cli::SearchType::Encoded => searches::encoded(&ctx),
        cli::SearchType::Section => searches::section(&ctx),
        cli::SearchType::Metrics => searches::metrics(&ctx),
    };
    let (matched, _match_count, mut output) = match outcome {
        Outcome::Done(out) => return Ok(out),
        Outcome::Searched(matched, count, out) => (matched, count, out),
    };

    // If not matched, provide suggestions
    if !matched {
        suggestions::suggest_alternatives(&ctx, &mut output);
    }

    Ok(output)
}

/// What `run` computed before searching, shared by every search.
#[derive(Clone, Copy)]
pub(super) struct MatchCtx<'a> {
    pub(super) request: MatchRequest<'a>,
    pub(super) pattern: &'a str,
    pub(super) file_type: FileType,
    pub(super) internal_file_type: composite_rules::FileType,
    pub(super) capability_mapper: &'a crate::capabilities::CapabilityMapper,
    pub(super) prepared: &'a super::PreparedTestAnalysis,
    pub(super) binary_data: &'a [u8],
    pub(super) report: &'a crate::types::AnalysisReport,
    pub(super) context_info: &'a crate::test_rules::ContextInfo,
    pub(super) section_map: &'a composite_rules::SectionMap,
    pub(super) has_location_constraints: bool,
    pub(super) engine: &'a crate::Engine,
    pub(super) path: &'a Path,
    pub(super) platforms: &'a [composite_rules::Platform],
}

/// How a search ended: with output to print as is, or with a result the
/// suggestions may extend.
pub(super) enum Outcome {
    Done(String),
    Searched(bool, usize, String),
}

impl MatchCtx<'_> {
    /// The byte range location constraints select: `(start, end)`.
    fn effective_range(
        &self,
        section: Option<&str>,
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> Result<(usize, usize), String> {
        let prepared = self.prepared;
        let section_map = self.section_map;
        let file_size = prepared.preferred_binary_data.len();

        if let Some(sec) = section {
            if let Some(bounds) = section_map.bounds(sec) {
                let sec_start = bounds.0 as usize;
                let sec_end = bounds.1 as usize;
                let sec_size = sec_end - sec_start;

                if let Some(sec_off) = section_offset {
                    let abs_off = if sec_off >= 0 {
                        sec_start + sec_off as usize
                    } else {
                        sec_end.saturating_sub((-sec_off) as usize)
                    };
                    Ok((abs_off, abs_off.saturating_add(1).min(sec_end)))
                } else if let Some((start, end_opt)) = section_offset_range {
                    let rel_start = if start >= 0 {
                        start as usize
                    } else {
                        sec_size.saturating_sub((-start) as usize)
                    };
                    let rel_end = end_opt
                        .map(|e| {
                            if e >= 0 {
                                e as usize
                            } else {
                                sec_size.saturating_sub((-e) as usize)
                            }
                        })
                        .unwrap_or(sec_size);
                    Ok((
                        (sec_start + rel_start).min(sec_end),
                        (sec_start + rel_end).min(sec_end),
                    ))
                } else {
                    Ok((sec_start, sec_end))
                }
            } else {
                Err(format!("Section '{}' not found", sec))
            }
        } else if let Some(off) = offset {
            let abs_off = if off >= 0 {
                off as usize
            } else {
                file_size.saturating_sub((-off) as usize)
            };
            Ok((abs_off, abs_off.saturating_add(1).min(file_size)))
        } else if let Some((start, end_opt)) = offset_range {
            let abs_start = if start >= 0 {
                start as usize
            } else {
                file_size.saturating_sub((-start) as usize)
            };
            let abs_end = end_opt
                .map(|e| {
                    if e >= 0 {
                        e as usize
                    } else {
                        file_size.saturating_sub((-e) as usize)
                    }
                })
                .unwrap_or(file_size);
            Ok((abs_start.min(file_size), abs_end.min(file_size)))
        } else {
            Ok((0, file_size))
        }
    }
}
