//! Test pattern matching conditions against files.
//!
//! This module provides the `test-match` command implementation, which validates
//! search patterns, count constraints, and location filters with detailed diagnostics.

use crate::analyzers::{detect_file_type, macho::MachOAnalyzer, FileType};
use crate::commands::shared::{cli_file_type_to_internal, create_analysis_report};
use crate::{cli, composite_rules, ip_validator, test_rules, types};
use anyhow::Result;
use colored::Colorize;
use std::fs;
use std::path::Path;

/// Test pattern matching against a file with alternative suggestions.
///
/// This function performs comprehensive pattern matching tests against a target file,
/// showing detailed diagnostics about matches, constraints, and suggestions for
/// alternative search strategies.
///
/// # Arguments
///
/// * `target` - Path to the file to test
/// * `search_type` - Type of search (string, symbol, raw, kv, hex, encoded, section, metrics)
/// * `method` - Match method (exact, contains, regex, word)
/// * `pattern` - Pattern to search for
/// * `kv_path` - Key-value path for structured data searches
/// * `file_type_override` - Override detected file type
/// * `count_min` - Minimum number of matches required
/// * `count_max` - Maximum number of matches allowed
/// * `per_kb_min` - Minimum match density (matches per KB)
/// * `per_kb_max` - Maximum match density (matches per KB)
/// * `case_insensitive` - Enable case-insensitive matching
/// * `section` - Limit search to specific section
/// * `offset` - Search at specific file offset
/// * `offset_range` - Search within offset range
/// * `section_offset` - Offset relative to section
/// * `section_offset_range` - Range relative to section
/// * `external_ip` - Filter for external IP addresses
/// * `encoding` - Encoding filter for encoded string searches
/// * `entropy_min` - Minimum entropy (for sections)
/// * `entropy_max` - Maximum entropy (for sections)
/// * `length_min` - Minimum length (for sections/strings)
/// * `length_max` - Maximum length (for sections/strings)
/// * `value_min` - Minimum value (for metrics)
/// * `value_max` - Maximum value (for metrics)
/// * `min_size` - Minimum file size (for metrics)
/// * `max_size` - Maximum file size (for metrics)
/// * `_disabled` - Disabled components configuration
/// * `platforms` - Platform filters for evaluation
/// * `min_hostile_precision` - Minimum precision for hostile rules
/// * `min_suspicious_precision` - Minimum precision for suspicious rules
///
/// # Returns
///
/// A formatted string containing the test results with matches, diagnostics, and suggestions.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    target: &str,
    search_type: cli::SearchType,
    method: cli::MatchMethod,
    pattern: Option<&str>,
    kv_path: Option<&str>,
    kv_exists: Option<bool>,
    kv_size_min: Option<usize>,
    kv_size_max: Option<usize>,
    file_type_override: Option<cli::DetectFileType>,
    count_min: usize,
    count_max: Option<usize>,
    per_kb_min: Option<f64>,
    per_kb_max: Option<f64>,
    case_insensitive: bool,
    section: Option<&str>,
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
    external_ip: bool,
    encoding: Option<&str>,
    entropy_min: Option<f64>,
    entropy_max: Option<f64>,
    length_min: Option<u64>,
    length_max: Option<u64>,
    value_min: Option<f64>,
    value_max: Option<f64>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    _disabled: &cli::DisabledComponents,
    platforms: Vec<composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) -> Result<String> {
    // Validate arguments based on search type
    if search_type == cli::SearchType::Kv {
        if kv_path.is_none() {
            anyhow::bail!("--kv-path is required for kv searches");
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
            anyhow::bail!("--pattern is required for section searches unless using size/entropy constraints (--count-min/max, --length-min/max, --entropy-min/max)");
        }
    } else if search_type == cli::SearchType::Metrics {
        if pattern.is_none() {
            anyhow::bail!("--pattern is required for metrics searches (use field path like 'binary.avg_complexity')");
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
    use test_rules::{find_matching_strings, find_matching_symbols, RuleDebugger};

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
    let capability_mapper = if std::env::var("CLEAVE_SKIP_TRAITS").is_ok() {
        tracing::info!("Traits skipped (CLEAVE_SKIP_TRAITS set)");
        crate::capabilities::CapabilityMapper::empty()
    } else {
        crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
            min_hostile_precision,
            min_suspicious_precision,
            true, // Always enable full validation for test-match
        )
        .with_platforms(platforms.clone())
    };

    // Read file data
    let full_data = fs::read(path)?;

    // For Mach-O FAT binaries, use the full file for evaluation so string offsets are file-relative.
    // This ensures offset_range constraints (like [-2200, -100]) work correctly.
    let (binary_data, is_fat): (Vec<u8>, bool) = if file_type == FileType::MachO {
        let analyzer = MachOAnalyzer::new();
        let range = analyzer.preferred_arch_range(&full_data);
        let is_fat = range != (0..full_data.len());
        if is_fat {
            eprintln!("Note: FAT binary detected, using full file for evaluation");
        }
        (full_data[range].to_vec(), is_fat)
    } else {
        (full_data.clone(), false)
    };

    // Create a basic report by analyzing the file
    let mut report = create_analysis_report(path, &file_type, &binary_data, &capability_mapper)?;

    // For FAT binaries, re-extract strings from the full file so offsets are file-relative
    if is_fat {
        let string_extractor = crate::strings::StringExtractor::default();
        report.strings = string_extractor.extract_smart(&full_data, None);
    }

    // Evaluation data: full file for FAT binaries, slice otherwise
    let eval_data = if is_fat {
        &full_data[..]
    } else {
        &binary_data[..]
    };

    // Create debugger to access search functions
    // Note: test-match doesn't use YARA results since it tests individual conditions
    // For FAT binaries, use full file so string offsets are file-relative
    let debugger = RuleDebugger::new(
        &capability_mapper,
        &report,
        eval_data,
        &capability_mapper.composite_rules,
        capability_mapper.trait_definitions(),
        platforms.clone(),
        None, // test-match evaluates conditions directly, not via full rule path
    );
    let context_info = debugger.context_info();

    // Create section map for location constraint resolution
    let section_map = composite_rules::SectionMap::from_binary(eval_data);

    // Resolve effective byte range from location constraints
    // Returns (start, end, effective_size) where effective_size is used for density calculations
    let resolve_effective_range = |section: Option<&str>,
                                   offset: Option<i64>,
                                   offset_range: Option<(i64, Option<i64>)>,
                                   section_offset: Option<i64>,
                                   section_offset_range: Option<(i64, Option<i64>)>|
     -> Result<(usize, usize), String> {
        let file_size = binary_data.len();

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
    };

    // Check if any location constraints are specified
    let has_location_constraints = section.is_some()
        || offset.is_some()
        || offset_range.is_some()
        || section_offset.is_some()
        || section_offset_range.is_some();

    // Perform the requested search
    let (matched, _match_count, mut output): (bool, usize, String) = match search_type {
        cli::SearchType::String => {
            // Resolve effective range for filtering strings by offset
            let effective_range = resolve_effective_range(
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            );

            let (range_start, range_end) = match effective_range {
                Ok((s, e)) => (s, e),
                Err(msg) => {
                    let mut out = String::new();
                    out.push_str("Search: strings\n");
                    out.push_str(&format!("Pattern: {}\n", pattern));
                    out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                    out.push_str(&format!("{}\n", msg));
                    if section_map.has_sections() {
                        out.push_str(&format!(
                            "Available sections: {}\n",
                            section_map.section_names().join(", ")
                        ));
                    }
                    return Ok(out);
                }
            };

            // Filter strings by offset range if location constraints are specified
            let filtered_strings: Vec<&types::StringInfo> = if has_location_constraints {
                report
                    .strings
                    .iter()
                    .filter(|s| {
                        if let Some(off) = s.offset {
                            let off = off as usize;
                            off >= range_start && off < range_end
                        } else {
                            false // Skip strings without offset info
                        }
                    })
                    .collect()
            } else {
                report.strings.iter().collect()
            };

            let strings: Vec<&str> = filtered_strings.iter().map(|s| s.value.as_str()).collect();

            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let contains = if method == cli::MatchMethod::Contains {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };
            let word = if method == cli::MatchMethod::Word {
                Some(pattern.to_string())
            } else {
                None
            };

            let matched_strings =
                find_matching_strings(&strings, &exact, &contains, &regex, &word, case_insensitive);

            // Filter by external IP if required
            let matched_strings: Vec<&str> = if external_ip {
                matched_strings
                    .into_iter()
                    .filter(|s| ip_validator::contains_external_ip(s))
                    .collect()
            } else {
                matched_strings
            };
            let match_count = matched_strings.len();

            // Use effective range size for density calculations when location constraints apply
            let effective_size = if has_location_constraints {
                range_end.saturating_sub(range_start)
            } else {
                binary_data.len()
            };
            let effective_size_kb = effective_size as f64 / 1024.0;
            let density = if effective_size_kb > 0.0 {
                match_count as f64 / effective_size_kb
            } else {
                0.0
            };

            // Check all constraints
            let count_min_ok = match_count >= count_min;
            let count_max_ok = count_max.is_none_or(|max| match_count <= max);
            let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
            let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
            let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

            let mut out = String::new();
            out.push_str("Search: strings\n");
            out.push_str(&format!("  count_min: {}", count_min));
            if let Some(max) = count_max {
                out.push_str(&format!(", count_max: {}", max));
            }
            if let Some(min) = per_kb_min {
                out.push_str(&format!(", per_kb_min: {:.2}", min));
            }
            if let Some(max) = per_kb_max {
                out.push_str(&format!(", per_kb_max: {:.2}", max));
            }
            if external_ip {
                out.push_str(", external_ip: true");
            }
            out.push('\n');
            out.push_str(&format!("Pattern: {}\n", pattern));

            // Show location constraints if specified
            if has_location_constraints {
                out.push_str(&format!(
                    "Search range: [{:#x}, {:#x}) of {} bytes\n",
                    range_start,
                    range_end,
                    binary_data.len()
                ));
            }

            out.push_str(&format!(
                "Context: file_type={:?}, strings={} (filtered from {})\n",
                file_type,
                filtered_strings.len(),
                report.strings.len()
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} matches, {:.3}/KB in search range)\n",
                    "MATCHED".green().bold(),
                    match_count,
                    density
                ));
                let display_count = match_count.min(10);
                for s in matched_strings.iter().take(display_count) {
                    out.push_str(&format!("  \"{}\"\n", s));
                }
                if match_count > display_count {
                    out.push_str(&format!("  ... and {} more\n", match_count - display_count));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Found {} matches ({:.3}/KB in search range)\n",
                    match_count, density
                ));
                // Show which constraints failed
                if !count_min_ok {
                    out.push_str(&format!(
                        "  count_min: {} < {} (FAILED)\n",
                        match_count, count_min
                    ));
                }
                if !count_max_ok {
                    if let Some(max) = count_max {
                        out.push_str(&format!(
                            "  count_max: {} > {} (FAILED)\n",
                            match_count, max
                        ));
                    }
                }
                if !per_kb_min_ok {
                    if let Some(min) = per_kb_min {
                        out.push_str(&format!(
                            "  per_kb_min: {:.3} < {:.3} (FAILED)\n",
                            density, min
                        ));
                    }
                }
                if !per_kb_max_ok {
                    if let Some(max) = per_kb_max {
                        out.push_str(&format!(
                            "  per_kb_max: {:.3} > {:.3} (FAILED)\n",
                            density, max
                        ));
                    }
                }
            }

            (matched, match_count, out)
        }
        cli::SearchType::Symbol => {
            let symbols: Vec<&str> = report
                .imports
                .iter()
                .map(|i| i.symbol.as_str())
                .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                .chain(report.functions.iter().map(|f| f.name.as_str()))
                .collect();

            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };

            let matched_symbols =
                find_matching_symbols(&symbols, &exact, &None, &regex, case_insensitive);
            let matched = !matched_symbols.is_empty();

            let mut out = String::new();
            out.push_str("Search: symbols\n");
            if case_insensitive {
                out.push_str("  case_insensitive: true\n");
            }
            out.push_str(&format!("Pattern: {}\n", pattern));
            out.push_str(&format!(
                "Context: file_type={:?}, strings={}, symbols={}\n",
                file_type, context_info.string_count, context_info.symbol_count
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} matches)\n",
                    "MATCHED".green().bold(),
                    matched_symbols.len()
                ));
                let display_count = matched_symbols.len().min(10);
                for s in matched_symbols.iter().take(display_count) {
                    out.push_str(&format!("  \"{}\"\n", s));
                }
                if matched_symbols.len() > display_count {
                    out.push_str(&format!(
                        "  ... and {} more\n",
                        matched_symbols.len() - display_count
                    ));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Total symbols: {} ({} imports, {} exports)\n",
                    symbols.len(),
                    report.imports.len(),
                    report.exports.len()
                ));
            }

            (matched, matched_symbols.len(), out)
        }
        cli::SearchType::Raw => {
            // Resolve effective range for content search
            let effective_range = resolve_effective_range(
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            );

            let (range_start, range_end) = match effective_range {
                Ok((s, e)) => (s, e),
                Err(msg) => {
                    let mut out = String::new();
                    out.push_str("Search: content\n");
                    out.push_str(&format!("Pattern: {}\n", pattern));
                    out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                    out.push_str(&format!("{}\n", msg));
                    if section_map.has_sections() {
                        out.push_str(&format!(
                            "Available sections: {}\n",
                            section_map.section_names().join(", ")
                        ));
                    }
                    return Ok(out);
                }
            };

            // Slice binary data to effective range
            let search_data = &binary_data[range_start..range_end];
            let content = String::from_utf8_lossy(search_data);

            // Count all matches for density calculation
            // When external_ip is set, only count matches that contain external IPs
            let match_count = match method {
                // Exact: entire content slice must equal the pattern
                cli::MatchMethod::Exact => {
                    let matched = &*content == pattern;
                    if matched && external_ip {
                        if ip_validator::contains_external_ip(pattern) {
                            1
                        } else {
                            0
                        }
                    } else if matched {
                        1
                    } else {
                        0
                    }
                }
                cli::MatchMethod::Contains => {
                    if external_ip {
                        // For external_ip, we need to check context around each match
                        let mut count = 0;
                        let mut start = 0;
                        while let Some(pos) = content[start..].find(pattern) {
                            let abs_pos = start + pos;
                            // Get context around match to check for IP
                            let context_start = abs_pos.saturating_sub(50);
                            let context_end = (abs_pos + pattern.len() + 50).min(content.len());
                            let context = &content[context_start..context_end];
                            if ip_validator::contains_external_ip(context) {
                                count += 1;
                            }
                            start = abs_pos + 1;
                        }
                        count
                    } else {
                        content.matches(pattern).count()
                    }
                }
                cli::MatchMethod::Regex => regex::Regex::new(pattern)
                    .map(|re| {
                        if external_ip {
                            re.find_iter(&content)
                                .filter(|m| ip_validator::contains_external_ip(m.as_str()))
                                .count()
                        } else {
                            re.find_iter(&content).count()
                        }
                    })
                    .unwrap_or(0),
                cli::MatchMethod::Word => {
                    let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                    regex::Regex::new(&word_pattern)
                        .map(|re| {
                            if external_ip {
                                re.find_iter(&content)
                                    .filter(|m| ip_validator::contains_external_ip(m.as_str()))
                                    .count()
                            } else {
                                re.find_iter(&content).count()
                            }
                        })
                        .unwrap_or(0)
                }
            };

            // Use effective range size for density calculations
            let effective_size = range_end.saturating_sub(range_start);
            let effective_size_kb = effective_size as f64 / 1024.0;
            let density = if effective_size_kb > 0.0 {
                match_count as f64 / effective_size_kb
            } else {
                0.0
            };

            // Check all constraints
            let count_min_ok = match_count >= count_min;
            let count_max_ok = count_max.is_none_or(|max| match_count <= max);
            let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
            let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
            let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

            let mut out = String::new();
            out.push_str("Search: content\n");
            out.push_str(&format!("  count_min: {}", count_min));
            if let Some(max) = count_max {
                out.push_str(&format!(", count_max: {}", max));
            }
            if let Some(min) = per_kb_min {
                out.push_str(&format!(", per_kb_min: {:.2}", min));
            }
            if let Some(max) = per_kb_max {
                out.push_str(&format!(", per_kb_max: {:.2}", max));
            }
            if external_ip {
                out.push_str(", external_ip: true");
            }
            out.push('\n');
            out.push_str(&format!("Pattern: {}\n", pattern));

            // Show location constraints if specified
            if has_location_constraints {
                out.push_str(&format!(
                    "Search range: [{:#x}, {:#x}) of {} bytes\n",
                    range_start,
                    range_end,
                    binary_data.len()
                ));
            }

            out.push_str(&format!(
                "Context: file_type={:?}, search_size={} bytes\n",
                file_type, effective_size
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} matches, {:.3}/KB in search range)\n",
                    "MATCHED".green().bold(),
                    match_count,
                    density
                ));
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Found {} matches ({:.3}/KB in search range)\n",
                    match_count, density
                ));
                // Show which constraints failed
                if !count_min_ok {
                    out.push_str(&format!(
                        "  count_min: {} < {} (FAILED)\n",
                        match_count, count_min
                    ));
                }
                if !count_max_ok {
                    if let Some(max) = count_max {
                        out.push_str(&format!(
                            "  count_max: {} > {} (FAILED)\n",
                            match_count, max
                        ));
                    }
                }
                if !per_kb_min_ok {
                    if let Some(min) = per_kb_min {
                        out.push_str(&format!(
                            "  per_kb_min: {:.3} < {:.3} (FAILED)\n",
                            density, min
                        ));
                    }
                }
                if !per_kb_max_ok {
                    if let Some(max) = per_kb_max {
                        out.push_str(&format!(
                            "  per_kb_max: {:.3} > {:.3} (FAILED)\n",
                            density, max
                        ));
                    }
                }
            }

            (matched, match_count, out)
        }
        cli::SearchType::Kv => {
            let kv_path_str = kv_path.unwrap_or_default();

            // Build the kv condition
            let exact = if method == cli::MatchMethod::Exact && !pattern.is_empty() {
                Some(pattern.to_string())
            } else {
                None
            };
            let substr = if method == cli::MatchMethod::Contains && !pattern.is_empty() {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex_str = if method == cli::MatchMethod::Regex && !pattern.is_empty() {
                Some(pattern.to_string())
            } else {
                None
            };
            let compiled_regex = regex_str.as_ref().and_then(|r| regex::Regex::new(r).ok());

            let condition = composite_rules::Condition::Kv {
                path: kv_path_str.to_string(),
                exact: exact.clone(),
                substr: substr.clone(),
                regex: regex_str.clone(),
                case_insensitive,
                exists: kv_exists,
                size_min: kv_size_min,
                size_max: kv_size_max,
                compiled_regex,
            };

            // Create minimal context for kv evaluation
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
                FileType::PowerShell => composite_rules::FileType::PowerShell,
                FileType::Php => composite_rules::FileType::Php,
                _ => composite_rules::FileType::All,
            };
            let eval_ctx = composite_rules::EvaluationContext::new(
                &report,
                &binary_data,
                internal_file_type,
                platforms.clone(),
                None,
                None,
            );

            // Use the actual kv evaluator with caching
            let evidence = composite_rules::evaluators::evaluate_kv(&condition, &eval_ctx);
            let _matched = evidence.is_some();

            let mut out = String::new();
            out.push_str("Search: kv (structured data)\n");
            out.push_str(&format!("Path: {}\n", kv_path_str));
            if !pattern.is_empty() {
                out.push_str(&format!(
                    "Pattern: {} ({})\n",
                    pattern,
                    format!("{:?}", method).to_lowercase()
                ));
            } else {
                out.push_str("Pattern: (existence check)\n");
            }
            out.push_str(&format!(
                "Context: file_type={:?}, file_size={} bytes\n",
                file_type,
                binary_data.len()
            ));

            if let Some(ev) = evidence {
                out.push_str(&format!("\n{}\n", "MATCHED".green().bold()));
                out.push_str(&format!("  Value: {}\n", ev.value));
                if let Some(loc) = &ev.location {
                    out.push_str(&format!("  Location: {}\n", loc));
                }
                (true, 1, out)
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));

                // Try to parse and show available keys
                if let Ok(content) = std::str::from_utf8(&binary_data) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                        if let Some(obj) = json.as_object() {
                            let keys: Vec<_> = obj.keys().take(15).collect();
                            out.push_str(&format!("Available top-level keys: {:?}\n", keys));
                        }
                    } else if let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(content) {
                        if let Some(obj) = yaml.as_object() {
                            let keys: Vec<_> = obj.keys().take(15).collect();
                            out.push_str(&format!("Available top-level keys: {:?}\n", keys));
                        }
                    }
                }

                (false, 0, out)
            }
        }
        cli::SearchType::Hex => {
            use composite_rules::evaluators::eval_hex;
            use composite_rules::SectionMap;

            // Create section map for location constraints
            let section_map = SectionMap::from_binary(&binary_data);

            // Resolve effective search range and convert to offset/offset_range for eval_hex
            let (effective_start, effective_end, _resolved_offset, _resolved_offset_range) =
                if let Some(sec) = section {
                    if let Some(bounds) = section_map.bounds(sec) {
                        // Apply section-relative offsets if specified
                        if let Some(sec_off) = section_offset {
                            let abs_off = if sec_off >= 0 {
                                bounds.0 + sec_off as u64
                            } else {
                                bounds.1.saturating_sub((-sec_off) as u64)
                            };
                            (
                                abs_off as usize,
                                (abs_off + 1) as usize,
                                Some(abs_off as i64),
                                None,
                            )
                        } else if let Some((start, end_opt)) = section_offset_range {
                            let section_size = bounds.1 - bounds.0;
                            let rel_start = if start >= 0 {
                                start as u64
                            } else {
                                section_size.saturating_sub((-start) as u64)
                            };
                            let rel_end = end_opt
                                .map(|e| {
                                    if e >= 0 {
                                        e as u64
                                    } else {
                                        section_size.saturating_sub((-e) as u64)
                                    }
                                })
                                .unwrap_or(section_size);
                            let abs_start = (bounds.0 + rel_start) as usize;
                            let abs_end = (bounds.0 + rel_end).min(bounds.1) as usize;
                            (
                                abs_start,
                                abs_end,
                                None,
                                Some((abs_start as i64, Some(abs_end as i64))),
                            )
                        } else {
                            // Entire section
                            (
                                bounds.0 as usize,
                                bounds.1 as usize,
                                None,
                                Some((bounds.0 as i64, Some(bounds.1 as i64))),
                            )
                        }
                    } else {
                        let mut out = String::new();
                        out.push_str("Search: hex\n");
                        out.push_str(&format!("Pattern: {}\n", pattern));
                        out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                        out.push_str(&format!("Section '{}' not found in binary\n", sec));
                        if section_map.has_sections() {
                            out.push_str(&format!(
                                "Available sections: {}\n",
                                section_map.section_names().join(", ")
                            ));
                        }
                        return Ok(out);
                    }
                } else if let Some(off) = offset {
                    let file_size = binary_data.len();
                    let abs_off = if off >= 0 {
                        off as usize
                    } else {
                        file_size.saturating_sub((-off) as usize)
                    };
                    (abs_off, abs_off + 1, offset, None)
                } else if let Some((start, end_opt)) = offset_range {
                    let file_size = binary_data.len();
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
                    (abs_start, abs_end.min(file_size), None, offset_range)
                } else {
                    (0, binary_data.len(), None, None)
                };

            // Create evaluation context
            let ctx = composite_rules::EvaluationContext::new(
                &report,
                &binary_data,
                composite_rules::FileType::All,
                platforms.clone(),
                None,
                None,
            );

            // Evaluate hex pattern with resolved location constraints
            let result = eval_hex(
                pattern,
                &composite_rules::evaluators::ContentLocationParams {
                    section: section.map(std::string::ToString::to_string),
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                },
                &ctx,
            );

            let match_count = result.evidence.len();
            let effective_size = effective_end.saturating_sub(effective_start);
            let effective_size_kb = effective_size as f64 / 1024.0;
            let density = if effective_size_kb > 0.0 {
                match_count as f64 / effective_size_kb
            } else {
                0.0
            };

            let mut out = String::new();
            out.push_str("Search: hex\n");
            out.push_str(&format!("Pattern: {}\n", pattern));

            // Show location constraints
            if let Some(sec) = section {
                out.push_str(&format!("Section: {}\n", sec));
            }
            if let Some(off) = offset {
                out.push_str(&format!("Offset: {:#x}\n", off));
            }
            if let Some((start, end_opt)) = offset_range {
                if let Some(end) = end_opt {
                    out.push_str(&format!("Offset range: [{:#x}, {:#x})\n", start, end));
                } else {
                    out.push_str(&format!("Offset range: [{:#x}, end)\n", start));
                }
            }

            out.push_str(&format!(
                "Context: file_type={:?}, file_size={} bytes",
                file_type,
                binary_data.len()
            ));
            if effective_size != binary_data.len() {
                out.push_str(&format!(
                    ", search_range=[{:#x},{:#x}) ({} bytes)",
                    effective_start, effective_end, effective_size
                ));
            }
            if section_map.has_sections() {
                out.push_str(&format!(", sections={}", section_map.section_names().len()));
            }
            out.push('\n');

            if result.matched {
                out.push_str(&format!(
                    "\n{} ({} matches, {:.3}/KB)\n",
                    "MATCHED".green().bold(),
                    match_count,
                    density
                ));
                let display_count = match_count.min(10);
                for ev in result.evidence.iter().take(display_count) {
                    out.push_str(&format!(
                        "  {} @ {}\n",
                        ev.value,
                        ev.location.as_deref().unwrap_or("?")
                    ));
                }
                if match_count > display_count {
                    out.push_str(&format!("  ... and {} more\n", match_count - display_count));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Found {} matches ({:.3}/KB)\n",
                    match_count, density
                ));

                // Show available sections as suggestion
                if section_map.has_sections() && section.is_none() {
                    out.push_str(&format!(
                        "\nBinary has sections: {} - try --section for targeted search\n",
                        section_map.section_names().join(", ")
                    ));
                }
            }

            (result.matched, match_count, out)
        }
        cli::SearchType::Encoded => {
            // Search in encoded/decoded strings with optional encoding filter
            // Parse encoding parameter: single ("base64"), multiple ("base64,hex"), or None (all)
            let encoding_filter: Option<Vec<String>> =
                encoding.map(|enc_str| enc_str.split(',').map(|s| s.trim().to_string()).collect());

            // Filter strings by encoding_chain
            let encoded_strings: Vec<&str> = report
                .strings
                .iter()
                .filter(|s| {
                    if s.encoding_chain.is_empty() {
                        return false; // Not an encoded string
                    }
                    match &encoding_filter {
                        None => true, // No filter: accept all encoded strings
                        Some(filters) => {
                            // Accept if ANY filter matches (OR logic)
                            filters.iter().any(|enc| s.encoding_chain.contains(enc))
                        }
                    }
                })
                .map(|s| s.value.as_str())
                .collect();

            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let contains = if method == cli::MatchMethod::Contains {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };
            let word = if method == cli::MatchMethod::Word {
                Some(pattern.to_string())
            } else {
                None
            };

            let matched_strings = find_matching_strings(
                &encoded_strings,
                &exact,
                &contains,
                &regex,
                &word,
                case_insensitive,
            );

            // Filter by external IP if required
            let matched_strings: Vec<&str> = if external_ip {
                matched_strings
                    .into_iter()
                    .filter(|s| ip_validator::contains_external_ip(s))
                    .collect()
            } else {
                matched_strings
            };
            let match_count = matched_strings.len();

            let file_size_kb = binary_data.len() as f64 / 1024.0;
            let density = if file_size_kb > 0.0 {
                match_count as f64 / file_size_kb
            } else {
                0.0
            };

            let count_min_ok = match_count >= count_min;
            let count_max_ok = count_max.is_none_or(|max| match_count <= max);
            let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
            let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
            let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

            let mut out = String::new();
            if let Some(ref filters) = encoding_filter {
                out.push_str(&format!("Search: encoded ({})\n", filters.join(", ")));
            } else {
                out.push_str("Search: encoded (all encodings)\n");
            }
            out.push_str(&format!("  count_min: {}", count_min));
            if let Some(max) = count_max {
                out.push_str(&format!(", count_max: {}", max));
            }
            if let Some(min) = per_kb_min {
                out.push_str(&format!(", per_kb_min: {:.2}", min));
            }
            if let Some(max) = per_kb_max {
                out.push_str(&format!(", per_kb_max: {:.2}", max));
            }
            if external_ip {
                out.push_str(", external_ip: true");
            }
            out.push('\n');
            out.push_str(&format!("Pattern: {}\n", pattern));
            out.push_str(&format!(
                "Context: file_type={:?}, encoded_strings={} (from {} total strings)\n",
                file_type,
                encoded_strings.len(),
                report.strings.len()
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} matches, {:.3}/KB)\n",
                    "MATCHED".green().bold(),
                    match_count,
                    density
                ));
                let display_count = match_count.min(10);
                for s in matched_strings.iter().take(display_count) {
                    out.push_str(&format!("  \"{}\"\n", s));
                }
                if match_count > display_count {
                    out.push_str(&format!("  ... and {} more\n", match_count - display_count));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Found {} matches ({:.3}/KB)\n",
                    match_count, density
                ));
                if encoded_strings.is_empty() {
                    out.push_str("  No encoded strings found in this file\n");
                    if encoding_filter.is_some() {
                        out.push_str("  Try removing --encoding to search all encoded strings\n");
                    }
                    out.push_str("  Try `--type string` or `--type raw` instead\n");
                }
            }

            (matched, match_count, out)
        }
        cli::SearchType::Section => {
            // Search for sections by name, size, and/or entropy
            // count_min/count_max = number of matching sections
            // length_min/length_max = size of each section in bytes
            let sections: Vec<&types::Section> = report.sections.iter().collect();

            // Helper function to check if a section name matches the pattern
            let name_matches = |section_name: &str| -> bool {
                if pattern.is_empty() {
                    return true; // No pattern = match all names
                }

                let name = if case_insensitive {
                    section_name.to_lowercase()
                } else {
                    section_name.to_string()
                };
                let pat = if case_insensitive {
                    pattern.to_lowercase()
                } else {
                    pattern.to_string()
                };

                match method {
                    cli::MatchMethod::Exact => name == pat,
                    cli::MatchMethod::Contains => name.contains(&pat),
                    cli::MatchMethod::Regex => {
                        if let Ok(re) = regex::Regex::new(&pat) {
                            re.is_match(&name)
                        } else {
                            false
                        }
                    }
                    cli::MatchMethod::Word => {
                        // Word boundary match
                        let word_pattern = format!(r"\b{}\b", regex::escape(&pat));
                        if let Ok(re) = regex::Regex::new(&word_pattern) {
                            re.is_match(&name)
                        } else {
                            false
                        }
                    }
                }
            };

            // Filter sections by name pattern, length constraints, and entropy
            let matched_sections: Vec<&types::Section> = sections
                .into_iter()
                .filter(|sec| {
                    // Check name match
                    if !name_matches(&sec.name) {
                        return false;
                    }

                    // Check length constraints
                    if let Some(min) = length_min {
                        if sec.size < min {
                            return false;
                        }
                    }
                    if let Some(max) = length_max {
                        if sec.size > max {
                            return false;
                        }
                    }

                    // Check entropy constraints
                    if let Some(min) = entropy_min {
                        if sec.entropy < min {
                            return false;
                        }
                    }
                    if let Some(max) = entropy_max {
                        if sec.entropy > max {
                            return false;
                        }
                    }

                    true
                })
                .collect();

            let match_count = matched_sections.len();

            // Check count constraints (number of matching sections)
            let count_ok =
                match_count >= count_min && count_max.is_none_or(|max| match_count <= max);
            let matched = count_ok;

            let mut out = String::new();
            out.push_str("Search: sections\n");
            let mut constraints = Vec::new();
            if count_min > 1 {
                constraints.push(format!("count_min: {}", count_min));
            }
            if let Some(max) = count_max {
                constraints.push(format!("count_max: {}", max));
            }
            if let Some(min) = length_min {
                constraints.push(format!("length_min: {}", min));
            }
            if let Some(max) = length_max {
                constraints.push(format!("length_max: {}", max));
            }
            if let Some(min) = entropy_min {
                constraints.push(format!("entropy_min: {:.2}", min));
            }
            if let Some(max) = entropy_max {
                constraints.push(format!("entropy_max: {:.2}", max));
            }
            if !constraints.is_empty() {
                out.push_str(&format!("  {}\n", constraints.join(", ")));
            }
            if !pattern.is_empty() {
                out.push_str(&format!("Pattern: {}\n", pattern));
            }
            out.push_str(&format!(
                "Context: file_type={:?}, total_sections={}\n",
                file_type,
                report.sections.len()
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} sections matched)\n",
                    "MATCHED".green().bold(),
                    match_count
                ));
                for sec in matched_sections.iter().take(10) {
                    let addr_str = sec
                        .address
                        .map(|a| format!("0x{:x}", a))
                        .unwrap_or_else(|| "-".to_string());
                    out.push_str(&format!(
                        "  {} (addr: {}, size: {}, entropy: {:.2})\n",
                        sec.name, addr_str, sec.size, sec.entropy
                    ));
                }
                if match_count > 10 {
                    out.push_str(&format!("  ... and {} more\n", match_count - 10));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                if report.sections.is_empty() {
                    out.push_str("  No sections found (not a binary file?)\n");
                    out.push_str("  Section search only works on ELF, PE, and Mach-O binaries\n");
                } else {
                    out.push_str(&format!(
                        "Found 0 matching sections (out of {} total)\n",
                        report.sections.len()
                    ));
                    if !pattern.is_empty() {
                        out.push_str(&format!(
                            "  Available sections: {}\n",
                            report
                                .sections
                                .iter()
                                .map(|s| s.name.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                }
            }

            (matched, match_count, out)
        }
        cli::SearchType::Metrics => {
            // Test metrics conditions using eval_metrics
            let field = pattern;

            let mut out = String::new();
            out.push_str("Search: metrics\n");
            out.push_str(&format!("Field: {}\n", field));
            if let Some(min) = value_min {
                out.push_str(&format!("Min value: {}\n", min));
            }
            if let Some(max) = value_max {
                out.push_str(&format!("Max value: {}\n", max));
            }
            if let Some(min) = min_size {
                out.push_str(&format!("Min file size: {} bytes\n", min));
            }
            if let Some(max) = max_size {
                out.push_str(&format!("Max file size: {} bytes\n", max));
            }

            // Create evaluation context
            let ctx = composite_rules::EvaluationContext::new(
                &report,
                &binary_data,
                composite_rules::FileType::All, // FileType doesn't matter for metrics
                platforms,
                None, // No additional findings
                None, // No cached AST
            );

            // Use eval_metrics from the composite_rules module
            let result = composite_rules::evaluators::eval_metrics(
                field, value_min, value_max, min_size, max_size, &ctx,
            );

            let matched = result.matched;
            let match_count = if matched { 1 } else { 0 };

            if matched {
                out.push_str(&format!("\n{}\n", "MATCHED".green().bold()));

                // Try to extract and display the actual metric value
                if let Some(metrics) = &report.metrics {
                    let value = types::scores::get_metric_value(metrics, field);
                    if let Some(val) = value {
                        out.push_str(&format!("  Current value: {:.2}\n", val));
                    }
                }

                out.push_str(&format!(
                    "  File size: {} bytes\n",
                    report.target.size_bytes
                ));

                if !result.warnings.is_empty() {
                    out.push_str("\n  Warnings:\n");
                    for warning in &result.warnings {
                        out.push_str(&format!("    - {:?}\n", warning));
                    }
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));

                // Show current value for debugging
                if let Some(metrics) = &report.metrics {
                    let value = types::scores::get_metric_value(metrics, field);
                    if let Some(val) = value {
                        out.push_str(&format!("  Current value: {:.2}\n", val));
                        if let Some(min) = value_min {
                            if val < min {
                                out.push_str(&format!(
                                    "  Value {:.2} is below minimum {:.2}\n",
                                    val, min
                                ));
                            }
                        }
                        if let Some(max) = value_max {
                            if val > max {
                                out.push_str(&format!(
                                    "  Value {:.2} exceeds maximum {:.2}\n",
                                    val, max
                                ));
                            }
                        }
                    } else {
                        out.push_str(&format!(
                            "  Metric field '{}' not found or not applicable to this file type\n",
                            field
                        ));
                    }
                } else {
                    out.push_str("  No metrics available for this file\n");
                }

                // Show file size constraint failures
                let file_size = report.target.size_bytes;
                if let Some(min) = min_size {
                    if file_size < min {
                        out.push_str(&format!(
                            "  File size {} bytes is below minimum {} bytes\n",
                            file_size, min
                        ));
                    }
                }
                if let Some(max) = max_size {
                    if file_size > max {
                        out.push_str(&format!(
                            "  File size {} bytes exceeds maximum {} bytes\n",
                            file_size, max
                        ));
                    }
                }
            }

            (matched, match_count, out)
        }
    };

    // If not matched, provide suggestions
    if !matched {
        output.push_str("\nSuggestions:\n");

        // Check alternative search types
        match search_type {
            cli::SearchType::String => {
                // Check if pattern exists in symbols
                let symbols: Vec<&str> = report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let exact = if method == cli::MatchMethod::Exact {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let regex = if method == cli::MatchMethod::Regex {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let symbol_matches = find_matching_symbols(&symbols, &exact, &None, &regex, false);
                if !symbol_matches.is_empty() {
                    output.push_str(&format!(
                        "  Found in symbols ({} matches) - try `--type symbol`\n",
                        symbol_matches.len()
                    ));
                }

                // Check if pattern exists in content
                let content = String::from_utf8_lossy(&binary_data);
                let content_matched = match method {
                    cli::MatchMethod::Exact | cli::MatchMethod::Contains => {
                        content.contains(pattern)
                    }
                    cli::MatchMethod::Regex => {
                        regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                    }
                    cli::MatchMethod::Word => {
                        let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                        regex::Regex::new(&word_pattern).is_ok_and(|re| re.is_match(&content))
                    }
                };
                if content_matched {
                    output.push_str("  Found in content - try `--type raw`\n");
                }
            }
            cli::SearchType::Symbol => {
                // Check if pattern exists in strings (try exact first, then contains)
                let strings: Vec<&str> = report.strings.iter().map(|s| s.value.as_str()).collect();
                let exact = if method == cli::MatchMethod::Exact {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let contains = if method == cli::MatchMethod::Contains {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let regex = if method == cli::MatchMethod::Regex {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let word = if method == cli::MatchMethod::Word {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let string_matches = find_matching_strings(
                    &strings,
                    &exact,
                    &contains,
                    &regex,
                    &word,
                    case_insensitive,
                );
                if !string_matches.is_empty() {
                    output.push_str(&format!(
                        "  Found in strings ({} matches) - try `--type string`\n",
                        string_matches.len()
                    ));
                } else if method == cli::MatchMethod::Exact {
                    // Also try contains for exact searches
                    let contains_matches = find_matching_strings(
                        &strings,
                        &None,
                        &Some(pattern.to_string()),
                        &None,
                        &None,
                        case_insensitive,
                    );
                    if !contains_matches.is_empty() {
                        output.push_str(&format!(
                            "  Found in strings ({} substring matches) - try `--type string --method contains`\n",
                            contains_matches.len()
                        ));
                    }
                }

                // Check if pattern exists in content
                let content = String::from_utf8_lossy(&binary_data);
                let content_matched = match method {
                    cli::MatchMethod::Exact | cli::MatchMethod::Contains => {
                        content.contains(pattern)
                    }
                    cli::MatchMethod::Regex => {
                        regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                    }
                    cli::MatchMethod::Word => {
                        let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                        regex::Regex::new(&word_pattern).is_ok_and(|re| re.is_match(&content))
                    }
                };
                if content_matched {
                    output.push_str("  Found in content - try `--type raw`\n");
                }
            }
            cli::SearchType::Raw => {
                // Check if pattern exists in strings
                let strings: Vec<&str> = report.strings.iter().map(|s| s.value.as_str()).collect();
                let exact = if method == cli::MatchMethod::Exact {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let contains = if method == cli::MatchMethod::Contains {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let regex = if method == cli::MatchMethod::Regex {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let word = if method == cli::MatchMethod::Word {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let string_matches = find_matching_strings(
                    &strings,
                    &exact,
                    &contains,
                    &regex,
                    &word,
                    case_insensitive,
                );
                if !string_matches.is_empty() {
                    output.push_str(&format!(
                        "  Found in strings ({} matches) - try `--type string`\n",
                        string_matches.len()
                    ));
                }

                // Check if pattern exists in symbols
                let symbols: Vec<&str> = report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let symbol_matches = find_matching_symbols(&symbols, &exact, &None, &regex, false);
                if !symbol_matches.is_empty() {
                    output.push_str(&format!(
                        "  Found in symbols ({} matches) - try `--type symbol`\n",
                        symbol_matches.len()
                    ));
                }
            }
            cli::SearchType::Kv => {
                // No cross-search suggestions for kv - it's a different paradigm
                output.push_str("  Check that the path exists in the file structure\n");
                output.push_str("  Try without a pattern for existence check\n");
            }
            cli::SearchType::Hex => {
                // Suggest content search as alternative
                output.push_str("  Try --type raw for string-based search\n");
                output.push_str("  Ensure hex pattern has correct format: \"7F 45 4C 46\"\n");
                output.push_str("  Try --offset or --offset-range to target specific locations\n");
            }
            cli::SearchType::Encoded => {
                output.push_str(
                    "  Encoded search looks for decoded strings (base64, hex, xor, etc.)\n",
                );
                output.push_str("  Use --encoding to filter by type: --encoding base64\n");
                output.push_str("  Try `--type string` for regular strings\n");
                output.push_str("  Try `--type raw` for raw content search\n");
            }
            cli::SearchType::Section => {
                output.push_str("  Section search matches binary section metadata\n");
                if pattern.is_empty()
                    && entropy_min.is_none()
                    && entropy_max.is_none()
                    && length_min.is_none()
                    && length_max.is_none()
                    && count_min <= 1
                    && count_max.is_none()
                {
                    output.push_str("  Specify --pattern for name matching\n");
                    output.push_str("  Use --entropy-min/--entropy-max for entropy constraints\n");
                    output
                        .push_str("  Use --length-min/--length-max for section size constraints\n");
                    output.push_str(
                        "  Use --count-min/--count-max for number of matching sections\n",
                    );
                }
                if !report.sections.is_empty() {
                    output.push_str(&format!(
                        "  Available sections: {}\n",
                        report
                            .sections
                            .iter()
                            .map(|s| s.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            cli::SearchType::Metrics => {
                output
                    .push_str("  Metrics search tests computed file metrics against thresholds\n");
                output.push_str("  Use --pattern for field path (e.g., 'binary.avg_complexity')\n");
                output.push_str("  Use --value-min/--value-max for thresholds\n");
                output.push_str("  Use --min-size/--max-size for file size constraints\n");
                if let Some(metrics) = &report.metrics {
                    output.push_str("\n  Available metric fields:\n");
                    if metrics.binary.is_some() {
                        output.push_str("    binary.overall_entropy, binary.avg_complexity, binary.import_count, ...\n");
                    }
                    if metrics.text.is_some() {
                        output.push_str("    text.char_entropy, text.avg_line_length, ...\n");
                    }
                    if metrics.functions.is_some() {
                        output.push_str("    functions.total, functions.avg_params, functions.max_nesting_depth, ...\n");
                    }
                    if metrics.identifiers.is_some() {
                        output.push_str(
                            "    identifiers.avg_entropy, identifiers.reuse_ratio, ...\n",
                        );
                    }
                    output.push_str("  Run `cleave metrics <file>` to see all available fields\n");
                } else {
                    output.push_str("  No metrics available for this file type\n");
                }
            }
        }

        // Suggest alternative match methods
        output.push_str("\n  Try different match methods:\n");
        match method {
            cli::MatchMethod::Exact | cli::MatchMethod::Word => {
                output.push_str("    --method contains (substring match)\n");
                output.push_str("    --method regex (pattern match)\n");
            }
            cli::MatchMethod::Contains => {
                output.push_str("    --method exact (exact match)\n");
                output.push_str("    --method regex (pattern match)\n");
            }
            cli::MatchMethod::Regex => {
                output.push_str("    --method contains (substring match)\n");
                output.push_str("    --method exact (exact match)\n");
            }
        }

        // Check if pattern would match with different file types
        output.push_str("\n  File type analysis:\n");
        output.push_str(&format!("    Current file type: {:?}\n", file_type));

        // Try analyzing as different file types
        let alternative_types = vec![
            ("ELF", FileType::Elf),
            ("PE", FileType::Pe),
            ("Mach-O", FileType::MachO),
            ("JavaScript", FileType::JavaScript),
            ("Python", FileType::Python),
            ("Go", FileType::Go),
        ];

        for (type_name, alt_type) in alternative_types {
            if alt_type != file_type {
                // Try to create a report with alternative file type
                if let Ok(alt_report) =
                    create_analysis_report(path, &alt_type, &binary_data, &capability_mapper)
                {
                    let alt_debugger = RuleDebugger::new(
                        &capability_mapper,
                        &alt_report,
                        &binary_data,
                        &capability_mapper.composite_rules,
                        capability_mapper.trait_definitions(),
                        vec![composite_rules::Platform::All], // Check all platforms for alt file types
                        None, // test-match evaluates conditions directly
                    );
                    let alt_context = alt_debugger.context_info();

                    // Quick check if search would work with this type
                    let would_match = match search_type {
                        cli::SearchType::String => {
                            let strings: Vec<&str> = alt_report
                                .strings
                                .iter()
                                .map(|s| s.value.as_str())
                                .collect();
                            let exact = if method == cli::MatchMethod::Exact {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let contains = if method == cli::MatchMethod::Contains {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let regex = if method == cli::MatchMethod::Regex {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let word = if method == cli::MatchMethod::Word {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let matches = find_matching_strings(
                                &strings,
                                &exact,
                                &contains,
                                &regex,
                                &word,
                                case_insensitive,
                            );
                            !matches.is_empty()
                        }
                        cli::SearchType::Symbol => {
                            let symbols: Vec<&str> = alt_report
                                .imports
                                .iter()
                                .map(|i| i.symbol.as_str())
                                .chain(alt_report.exports.iter().map(|e| e.symbol.as_str()))
                                .chain(alt_report.functions.iter().map(|f| f.name.as_str()))
                                .collect();
                            let exact = if method == cli::MatchMethod::Exact {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let regex = if method == cli::MatchMethod::Regex {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let matches =
                                find_matching_symbols(&symbols, &exact, &None, &regex, false);
                            !matches.is_empty()
                        }
                        cli::SearchType::Raw => {
                            let content = String::from_utf8_lossy(&binary_data);
                            match method {
                                cli::MatchMethod::Exact | cli::MatchMethod::Contains => {
                                    content.contains(pattern)
                                }
                                cli::MatchMethod::Regex => {
                                    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                                }
                                cli::MatchMethod::Word => {
                                    let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                                    regex::Regex::new(&word_pattern)
                                        .is_ok_and(|re| re.is_match(&content))
                                }
                            }
                        }
                        cli::SearchType::Kv
                        | cli::SearchType::Hex
                        | cli::SearchType::Encoded
                        | cli::SearchType::Section
                        | cli::SearchType::Metrics => false,
                    };

                    if would_match {
                        output.push_str(&format!(
                            "    Would match if file type was: {} (strings: {}, symbols: {})\n",
                            type_name, alt_context.string_count, alt_context.symbol_count
                        ));
                    }
                }
            }
        }
    }

    Ok(output)
}
