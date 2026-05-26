//! Directory-based YAML file loading for capability mapper.
//!
//! This module handles loading capability definitions from a directory of YAML files,
//! performing comprehensive validation and building optimized indexes for fast evaluation.
//! This is the primary loading method used in production.

use crate::capabilities::error_formatting::enhance_yaml_error;
use crate::capabilities::indexes::{
    RawContentRegexIndex, StringMatchIndex, SymbolMatchIndex, TraitIndex,
};
use crate::capabilities::models::{TraitInfo, TraitMappings};
use crate::capabilities::parsing::{apply_composite_defaults, apply_trait_defaults};
use crate::capabilities::validation::{
    BROAD_FILETYPE_ALLOWLIST, BROAD_PLATFORM_ALLOWLIST, MAX_TRAITS_PER_DIRECTORY,
    ObjectivesWellknownViolation, autoprefix_trait_refs, check_basename_pattern_duplicates,
    check_exact_contained_by_substr, check_overlapping_regex_patterns,
    check_regex_alternative_subsets, check_regex_or_overlapping_exact, check_regex_should_be_exact,
    check_same_string_different_types, collect_trait_refs_from_rule,
    find_alternation_merge_candidates, find_ast_function_call_should_use_symbol,
    find_atomic_logic_duplicates, find_banned_directory_segments, find_broad_filetype_traits,
    find_broad_platform_traits, find_cap_obj_violations, find_cap_wellknown_violations,
    find_case_insensitive_overlap_issues, find_composite_only_wellknown_files,
    find_condition_scope_violations, find_depth_violations, find_duplicate_atomic_traits,
    find_duplicate_composite_rules, find_duplicate_second_level_directories,
    find_empty_condition_clauses, find_excessive_file_types, find_excessive_skip_conditions,
    find_for_only_duplicates, find_generic_wellknown_leaf_dirs, find_hex_binary_missing_section,
    find_hostile_cap_rules, find_hostile_meta_rules, find_impossible_count_constraints,
    find_impossible_needs, find_impossible_size_constraints, find_invalid_not_usage,
    find_invalid_trait_ids, find_kv_exists_with_matcher, find_line_number,
    find_malware_subcategory_violations, find_many_directory_refs,
    find_meta_missing_section_filter, find_metadata_cross_tier_refs, find_missing_search_patterns,
    find_needs_without_any, find_needs_zero, find_non_capturing_groups,
    find_none_only_with_proximity, find_objectives_wellknown_violations, find_orphaned_components,
    find_overlapping_conditions, find_oversized_trait_directories, find_parent_duplicate_segments,
    find_platform_named_directories, find_pure_alias_traits, find_pure_directory_alias_composites,
    find_raw_should_use_text, find_redundant_any_refs, find_redundant_explicit_defaults,
    find_redundant_needs_one, find_redundant_unix_platforms, find_regex_literal_overlap_issues,
    find_self_referencing_traits, find_short_pattern_warnings, find_should_use_defaults,
    find_single_item_clauses, find_slow_regex_patterns, find_string_content_collisions,
    find_string_literal_should_use_text, find_string_pattern_duplicates,
    find_structural_regex_duplicates, find_too_short_patterns,
    find_unanchored_wellknown_composites, find_wellknown_category_violations,
    find_wellknown_missing_section_filter, find_wellknown_missing_size_filter,
    precalculate_all_composite_precisions, simple_rule_to_composite_rule,
    validate_composite_trait_only, validate_directory_structure,
    validate_hostile_composite_precision, validate_hostile_trait_precision,
};
use crate::composite_rules::{
    CompositeTrait, Condition, FileType as RuleFileType, Platform, TraitDefinition,
};
use crate::types::Criticality;
use anyhow::{Context, Result};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

/// Serializable cache data for the capability mapper.
/// Contains only the data that round-trips through serde.
/// Indexes (TraitIndex, StringMatchIndex, RawContentRegexIndex) are rebuilt after load.
#[derive(Serialize, Deserialize)]
struct MapperCacheData {
    symbol_map: HashMap<String, TraitInfo>,
    trait_definitions: Vec<TraitDefinition>,
    composite_rules: Vec<CompositeTrait>,
}

#[derive(Debug, Clone)]
struct FileStemReferenceHint {
    filename_stem: String,
    directory_ref: String,
    available_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct BrokenTraitReference {
    rule_id: String,
    ref_id: String,
    source_file: String,
    line_hint: Option<usize>,
    suggestion: Option<String>,
}

fn push_parsing_warning(
    warnings: &mut crate::validation_controls::ValidationIssues,
    path_str: &str,
    warning: String,
) {
    if warning.starts_with("Unknown file type") {
        warnings.push_id("unknown-file-type", format!("{path_str}: {warning}"));
    } else if warning.starts_with("Invalid file type") {
        warnings.push_id("invalid-file-type", format!("{path_str}: {warning}"));
    } else if warning.contains("regex pattern exceeds") {
        let message = if warning.contains(" (in ") {
            warning
        } else {
            format!("{warning} (in {path_str})")
        };
        warnings.push_id("regex-length", message);
    } else if warning.contains("too many '|' symbols")
        || warning.contains("simple alphanumeric alternation chain")
    {
        warnings.push_id(
            "simple-alternation-chain",
            format!("{warning} (in {path_str})"),
        );
    } else {
        warnings.push_legacy(warning);
    }
}

fn find_non_leaf_yaml_files(yaml_files: &[std::path::PathBuf], root: &Path) -> Vec<String> {
    let mut yaml_dirs: Vec<_> = yaml_files
        .iter()
        .filter_map(|path| path.parent())
        .map(Path::to_path_buf)
        .collect();
    yaml_dirs.sort_unstable();
    yaml_dirs.dedup();

    let mut violations = Vec::new();
    for file in yaml_files {
        let Some(dir) = file.parent() else {
            continue;
        };
        let has_yaml_descendant = yaml_dirs
            .iter()
            .any(|child| child != dir && child.starts_with(dir));
        if has_yaml_descendant {
            let display = file
                .strip_prefix(root)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string();
            violations.push(display);
        }
    }
    violations.sort_unstable();
    violations
}

fn trait_local_id(id: &str) -> &str {
    if let Some((_, local_id)) = id.rsplit_once("::") {
        local_id
    } else {
        id.rsplit('/').next().unwrap_or(id)
    }
}

fn normalize_ref_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn format_reference_choices(ids: &[String]) -> String {
    const MAX_CHOICES: usize = 4;
    let mut rendered: Vec<String> = ids
        .iter()
        .take(MAX_CHOICES)
        .map(|id| format!("'{id}'"))
        .collect();
    if ids.len() > MAX_CHOICES {
        rendered.push(format!("... and {} more", ids.len() - MAX_CHOICES));
    }
    rendered.join(", ")
}

fn build_file_stem_reference_hints(
    dir_path: &Path,
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> FxHashMap<String, FileStemReferenceHint> {
    let mut hints = FxHashMap::default();

    let mut register = |id: &str, defined_in: &Path| {
        let Ok(relative_path) = defined_in.strip_prefix(dir_path) else {
            return;
        };
        let file_stem_path = relative_path.with_extension("");
        let file_stem_ref = normalize_ref_path(&file_stem_path);
        if file_stem_ref.is_empty() {
            return;
        }

        let filename_stem = file_stem_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let directory_ref = relative_path
            .parent()
            .map(normalize_ref_path)
            .unwrap_or_default();

        let entry = hints
            .entry(file_stem_ref)
            .or_insert_with(|| FileStemReferenceHint {
                filename_stem,
                directory_ref,
                available_ids: Vec::new(),
            });
        if !entry.available_ids.iter().any(|existing| existing == id) {
            entry.available_ids.push(id.to_string());
        }
    };

    for trait_def in trait_definitions {
        register(&trait_def.id, &trait_def.defined_in);
    }
    for rule in composite_rules {
        register(&rule.id, &rule.defined_in);
    }

    for hint in hints.values_mut() {
        hint.available_ids.sort();
    }

    hints
}

fn build_filename_reference_suggestion(
    ref_id: &str,
    file_stem_hints: &FxHashMap<String, FileStemReferenceHint>,
) -> Option<String> {
    let (path_part, local_id) = if let Some((path_part, local_id)) = ref_id.split_once("::") {
        (path_part.trim_end_matches('/'), Some(local_id))
    } else {
        (ref_id.trim_end_matches('/'), None)
    };

    let hint = file_stem_hints.get(path_part)?;

    match local_id {
        Some(local_id) => {
            if let Some(suggested) = hint
                .available_ids
                .iter()
                .find(|candidate| trait_local_id(candidate) == local_id)
            {
                Some(format!(
                    "Hint: '{ref_id}' includes YAML filename '{}'. Filenames are never part of trait IDs. Use '{suggested}' instead.",
                    hint.filename_stem
                ))
            } else if !hint.available_ids.is_empty() {
                Some(format!(
                    "Hint: '{ref_id}' includes YAML filename '{}'. Filenames are never part of trait IDs. Drop the filename segment and use one of: {}.",
                    hint.filename_stem,
                    format_reference_choices(&hint.available_ids)
                ))
            } else {
                None
            }
        }
        None => {
            if hint.available_ids.is_empty() {
                return None;
            }

            let specific_rule_hint = if hint.available_ids.len() == 1 {
                format!(
                    "Use {} for the specific rule.",
                    format_reference_choices(&hint.available_ids)
                )
            } else {
                format!(
                    "Use one of {} for specific rules.",
                    format_reference_choices(&hint.available_ids)
                )
            };

            if hint.directory_ref.is_empty() {
                Some(format!(
                    "Hint: '{ref_id}' points to YAML file '{}.yaml', not a trait ID. Filenames are never part of trait IDs. {specific_rule_hint}",
                    hint.filename_stem
                ))
            } else {
                Some(format!(
                    "Hint: '{ref_id}' points to YAML file '{}.yaml', not a trait directory. Filenames are never part of trait IDs. {specific_rule_hint} If you intended a directory reference, use '{}'.",
                    hint.filename_stem, hint.directory_ref
                ))
            }
        }
    }
}

impl super::CapabilityMapper {
    /// Load capability mappings from directory of YAML files (recursively)
    #[allow(dead_code)] // Used in tests
    pub(crate) fn from_directory<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        Self::from_directory_with_options(
            dir_path,
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            true,
            false,
        )
    }

    /// Load capability mappings from a directory of YAML files with explicit precision thresholds
    #[allow(dead_code)] // Compatibility wrapper used by tests and targeted call sites
    pub(crate) fn from_directory_with_precision_thresholds<P: AsRef<Path>>(
        dir_path: P,
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
    ) -> Result<Self> {
        Self::from_directory_with_options(
            dir_path,
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
            false,
        )
    }

    /// Load capability mappings from a directory of YAML files with explicit load options.
    pub(crate) fn from_directory_with_options<P: AsRef<Path>>(
        dir_path: P,
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
        enable_precision_scoring: bool,
    ) -> Result<Self> {
        let _span = tracing::info_span!("load_capabilities").entered();
        let debug = std::env::var("CLEAVE_DEBUG").is_ok();
        let dir_path = dir_path.as_ref();
        let _t_start = std::time::Instant::now();

        // Check for CLEAVE_VALIDATE env var - it can override the CLI flag in either direction
        let enable_full_validation = match std::env::var("CLEAVE_VALIDATE").ok().as_deref() {
            Some("0") | Some("false") => false, // Env var explicitly disables
            Some("1") | Some("true") => true,   // Env var explicitly enables
            _ => enable_full_validation,        // Use CLI flag
        };

        tracing::info!("Loading trait definitions from {}", dir_path.display());
        if enable_full_validation {
            tracing::info!("Full validation enabled (this may take 60+ seconds)");
        } else {
            tracing::info!("Fast validation mode (run 'cleave validate' for full validation)");
        }
        if debug {
            eprintln!("🔍 Loading capabilities from: {}", dir_path.display());
        }

        // Try to load from cache (skip validation when loading from cache).
        // Mapper cache is decoupled from the per-file analysis cache: it's a
        // pure function of the traits dir, mtime-invalidated, and safe to
        // share across test invocations that set CLEAVE_SKIP_CACHE=1.
        let skip_cache = crate::cache::skip_mapper_cache();
        if !enable_full_validation
            && !skip_cache
            && let Ok(cache_path) = crate::cache::mapper_cache_path()
        {
            if cache_path.exists() {
                tracing::trace!("Attempting to load mapper from cache: {:?}", cache_path);
                match fs::read(&cache_path) {
                    Ok(mut bytes) => {
                        match simd_json::from_slice::<MapperCacheData>(&mut bytes) {
                            Ok(mut cache_data) => {
                                tracing::info!(
                                    "Loaded mapper from cache ({} traits, {} composites)",
                                    cache_data.trait_definitions.len(),
                                    cache_data.composite_rules.len()
                                );

                                // Re-compile regexes in parallel (not serialized due to #[serde(skip)])
                                // Use rayon to parallelize regex compilation across traits and composites
                                let t0 = std::time::Instant::now();
                                rayon::join(
                                    || {
                                        cache_data
                                                .trait_definitions
                                                .par_iter_mut()
                                                .for_each(|trait_def| {
                                                    if let Err(e) = trait_def.precompile_regexes() {
                                                        tracing::warn!(
                                                            "Failed to compile regex for cached trait {}: {}",
                                                            trait_def.id,
                                                            e
                                                        );
                                                    }
                                                });
                                    },
                                    || {
                                        cache_data
                                                .composite_rules
                                                .par_iter_mut()
                                                .for_each(|rule| {
                                                    if let Err(e) = rule.precompile_regexes() {
                                                        tracing::warn!(
                                                            "Failed to compile regex for cached composite {}: {}",
                                                            rule.id,
                                                            e
                                                        );
                                                    }
                                                });
                                    },
                                );
                                let t1 = std::time::Instant::now();
                                tracing::trace!(
                                    "Regex precompilation took {:?} ({} traits, {} composites)",
                                    t1.duration_since(t0),
                                    cache_data.trait_definitions.len(),
                                    cache_data.composite_rules.len()
                                );

                                // Rebuild indexes from cached trait definitions (in parallel)
                                let (
                                    ((trait_index, string_match_index), symbol_match_index),
                                    raw_regex_result,
                                ) = rayon::join(
                                    || {
                                        rayon::join(
                                            || {
                                                rayon::join(
                                                    || {
                                                        TraitIndex::build(
                                                            &cache_data.trait_definitions,
                                                        )
                                                    },
                                                    || {
                                                        StringMatchIndex::build(
                                                            &cache_data.trait_definitions,
                                                        )
                                                    },
                                                )
                                            },
                                            || {
                                                SymbolMatchIndex::build(
                                                    &cache_data.trait_definitions,
                                                )
                                            },
                                        )
                                    },
                                    || {
                                        RawContentRegexIndex::build(&cache_data.trait_definitions)
                                            .map_err(|errors| anyhow::anyhow!(errors.join("\n")))
                                    },
                                );
                                let t2 = std::time::Instant::now();
                                tracing::trace!(
                                    "Index building took {:?} (StringMatchIndex: {} patterns, RawContentRegexIndex: {} patterns)",
                                    t2.duration_since(t1),
                                    string_match_index.total_patterns,
                                    raw_regex_result
                                        .as_ref()
                                        .map(|i| i.total_patterns)
                                        .unwrap_or(0),
                                );
                                let raw_content_regex_index = raw_regex_result?;

                                // Ensure rule stats are up-to-date for banner display
                                let _ = crate::cache::save_rule_stats(
                                    cache_data.trait_definitions.len(),
                                    cache_data.composite_rules.len(),
                                );

                                // Populate trait_id_map from cached data
                                let mut trait_id_map = std::collections::HashMap::with_capacity(
                                    cache_data.trait_definitions.len(),
                                );
                                for (idx, trait_def) in
                                    cache_data.trait_definitions.iter().enumerate()
                                {
                                    trait_id_map.insert(trait_def.id.clone(), idx);
                                }

                                // Initialize composite rule dependencies
                                for rule in &mut cache_data.composite_rules {
                                    rule.populate_required_traits(&trait_id_map);
                                }

                                return Ok(Self {
                                    symbol_map: cache_data.symbol_map,
                                    trait_definitions: cache_data.trait_definitions,
                                    composite_rules: cache_data.composite_rules,
                                    trait_index,
                                    string_match_index,
                                    symbol_match_index,
                                    raw_content_regex_index,
                                    trait_id_map,
                                    platforms: vec![Platform::All],
                                    slow_rule_ms: Self::DEFAULT_SLOW_RULE_MS,
                                });
                            }
                            Err(e) => {
                                eprintln!("⏳ Trait cache is out of date, regenerating...");
                                tracing::debug!(
                                    cache = %cache_path.display(),
                                    error = %e,
                                    "Mapper cache deserialization failed"
                                );
                                if let Err(rm_err) = std::fs::remove_file(&cache_path) {
                                    tracing::debug!(
                                        cache = %cache_path.display(),
                                        error = %rm_err,
                                        "Failed to remove stale mapper cache"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("⏳ Trait cache is out of date, regenerating...");
                        tracing::debug!(
                            cache = %cache_path.display(),
                            error = %e,
                            "Mapper cache read failed"
                        );
                        if let Err(rm_err) = std::fs::remove_file(&cache_path) {
                            tracing::debug!(
                                cache = %cache_path.display(),
                                error = %rm_err,
                                "Failed to remove stale mapper cache"
                            );
                        }
                    }
                }
            } else {
                tracing::info!(
                    expected = %cache_path.display(),
                    "Trait mapper cache miss — expected file not found"
                );
                match crate::cache::most_recent_yaml_file() {
                    Ok((mtime, path)) => {
                        let age = mtime.elapsed().map(|d| d.as_secs()).unwrap_or(0);
                        tracing::info!(
                            newest_trait = %path.display(),
                            modified_ago = %crate::cache::format_age(age),
                            "Cache key derived from newest .yaml/.yml trait file"
                        );
                    }
                    Err(_) => {
                        tracing::info!("No .yaml/.yml files found in traits directory");
                    }
                }
            }
        }

        // First, collect all YAML file paths
        tracing::trace!("Scanning directory for YAML files");
        let mut yaml_files: Vec<_> = walkdir::WalkDir::new(dir_path)
            .follow_links(true)
            .into_iter()
            .filter_entry(|entry| {
                // Don't descend into hidden dirs (`.git`, `.devcontainer`) or
                // dirs Go conventionally treats as ignored (`_examples`,
                // `_testdata`). The traits dir is the root, so its own name is
                // never matched here.
                if entry.depth() == 0 || !entry.file_type().is_dir() {
                    return true;
                }
                let name = entry.file_name().to_string_lossy();
                !name.starts_with('.') && !name.starts_with('_')
            })
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                if !path.is_file() || !path.extension().map(|e| e == "yaml").unwrap_or(false) {
                    return false;
                }
                // Skip third-party YARA config (not trait definitions)
                if path.components().any(|c| c.as_os_str() == "third-party") {
                    return false;
                }
                let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                !filename.to_lowercase().contains("readme") && !filename.starts_with("EXAMPLE")
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        // Sort files deterministically by path string to ensure consistent loading order across OSes
        // Using string comparison instead of PathBuf comparison for true cross-platform consistency
        yaml_files.sort_unstable_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

        if yaml_files.is_empty() {
            anyhow::bail!("No YAML files found in {}", dir_path.display());
        }

        tracing::info!("Found {} YAML files to parse", yaml_files.len());
        let _t_parse = std::time::Instant::now();

        // Load all YAML files in parallel, preserving path for prefix calculation
        // Use indexed_map to preserve sorted order
        tracing::trace!("Parsing YAML files in parallel");
        let results: Vec<_> = yaml_files
            .par_iter()
            .enumerate()
            .map(|(idx, path)| {
                if debug {
                    eprintln!("   📄 Loading: {}", path.display());
                }

                let bytes = fs::read(path).with_context(|| format!("Failed to read {:?}", path))?;
                let content = String::from_utf8_lossy(&bytes);

                // Check for meaningless YAML patterns before parsing
                let yaml_warnings = super::helpers::check_yaml_patterns(&content, path);

                let mappings: TraitMappings = serde_yaml::from_str(&content).map_err(|e| {
                    // Enhance YAML parsing errors with context and suggestions
                    let enhanced = enhance_yaml_error(&e.into(), path, &content);
                    anyhow::anyhow!("{}", enhanced)
                })?;

                Ok::<_, anyhow::Error>((idx, path.clone(), mappings, yaml_warnings))
            })
            .collect();

        // Sort results back to original order since par_iter doesn't preserve order
        let mut sorted_results: Vec<_> = results;
        sorted_results.sort_by_key(|r| match r {
            Ok((idx, _, _, _)) => *idx,
            Err(_) => usize::MAX,
        });

        tracing::trace!("Parsing complete");
        let _t_merge = std::time::Instant::now();

        // Merge all results, collecting errors to report all at once
        tracing::trace!("Merging trait definitions and composite rules");
        let mut symbol_map = HashMap::new();
        // Use HashMaps during loading for O(1) duplicate detection (will convert to Vec later)
        let mut trait_definitions_map: HashMap<String, TraitDefinition> = HashMap::new();
        let mut composite_rules_map: HashMap<String, CompositeTrait> = HashMap::new();
        let mut trait_source_files: HashMap<String, String> = HashMap::new(); // trait_id -> file_path
        let mut rule_source_files: HashMap<String, String> = HashMap::new(); // rule_id -> file_path
        let mut files_processed = 0;
        let mut warnings = crate::validation_controls::ValidationIssues::new();
        let mut parse_errors: Vec<String> = Vec::new();

        for result in sorted_results {
            let (path, mappings, yaml_warnings) = match result {
                Ok((_idx, p, m, w)) => (p, m, w),
                Err(e) => {
                    // Format error with full chain (includes filename from context)
                    parse_errors.push(format!("{:#}", e));
                    continue;
                }
            };
            files_processed += 1;

            // Collect YAML pattern warnings
            warnings.extend_legacy(yaml_warnings);

            // Calculate the prefix from the directory path relative to traits/
            // e.g., traits/credential/java/traits.yaml -> credential/java
            let trait_prefix = path
                .strip_prefix(dir_path)
                .ok()
                .and_then(|p| p.parent())
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .filter(|s| !s.is_empty());

            let before_symbols = symbol_map.len();
            let before_traits = trait_definitions_map.len();
            let before_composites = composite_rules_map.len();

            // Merge symbols
            for mapping in mappings.symbols {
                symbol_map.insert(
                    mapping.symbol.clone(),
                    TraitInfo {
                        id: mapping.capability,
                        desc: mapping.desc,
                        conf: mapping.conf,
                        crit: Criticality::Baseline, // Legacy format defaults to baseline
                        mbc: None,                   // Legacy format has no mbc field
                        attack: None,                // Legacy format has no attack field
                    },
                );
            }

            // Merge simple_rules
            let mut parsing_warnings = Vec::new();
            for rule in mappings.simple_rules {
                // If rule has platform or file_type constraints, convert to composite rule
                if !rule.platforms.is_empty() || !rule.file_types.is_empty() {
                    let mut composite = simple_rule_to_composite_rule(rule, &mut parsing_warnings);
                    // Pre-compile regexes for this composite rule
                    if let Err(e) = composite.precompile_regexes() {
                        return Err(anyhow::anyhow!(
                            "Failed to compile regex for simple rule '{}': {}",
                            composite.id,
                            e
                        ));
                    }
                    composite_rules_map.insert(composite.id.clone(), composite);
                } else {
                    // No constraints - add to symbol map for fast lookup
                    symbol_map.insert(
                        rule.symbol.clone(),
                        TraitInfo {
                            id: rule.capability,
                            desc: rule.desc,
                            conf: rule.conf,
                            crit: Criticality::Baseline, // Simple rules default to baseline
                            mbc: None,                   // Simple rules have no mbc field
                            attack: None,                // Simple rules have no attack field
                        },
                    );
                }
            }

            // Add file path to file-type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                push_parsing_warning(&mut warnings, &path_str, warning);
            }

            // Per-file: check for values that should use defaults, and values redundant with defaults
            if enable_full_validation
                && !crate::validation_controls::is_validator_disabled("defaults-hoist")
            {
                let path_str = path.display().to_string();
                for (field, value) in find_should_use_defaults(
                    &mappings.traits,
                    &mappings.composite_rules,
                    &mappings.defaults,
                ) {
                    warnings.push_id("defaults-hoist", format!(
                        "{path_str}: all {} items set '{field}' to {value} — move to 'defaults: {field}: {value}'",
                        mappings.traits.len() + mappings.composite_rules.len(),
                    ));
                }
                for (id, field) in find_redundant_explicit_defaults(
                    &mappings.traits,
                    &mappings.composite_rules,
                    &mappings.defaults,
                ) {
                    warnings.push_id("defaults-hoist", format!(
                        "'{id}' in {path_str}: '{field}' matches the file default — remove the explicit '{field}:' from this item",
                    ));
                }
            }

            // Merge trait definitions with auto-prefixed IDs, applying file-level defaults
            let mut parsing_warnings = Vec::new();
            for raw_trait in mappings.traits {
                // Convert raw trait to final trait, applying file-level defaults
                let mut trait_def = apply_trait_defaults(
                    raw_trait,
                    &mappings.defaults,
                    &mut parsing_warnings,
                    &path,
                    enable_precision_scoring,
                );

                // Auto-prefix trait ID if it doesn't already have the path prefix
                // Uses :: as delimiter between directory path and trait name
                if let Some(ref prefix) = trait_prefix
                    && !trait_def.id.starts_with(prefix)
                    && !trait_def.id.contains("::")
                    && !trait_def.id.contains('/')
                {
                    trait_def.id = format!("{}::{}", prefix, trait_def.id);
                }
                // Validate YARA/AST conditions at load time
                trait_def
                    .r#if
                    .validate(enable_full_validation)
                    .map_err(|e| anyhow::anyhow!("{}", e))
                    .with_context(|| {
                        format!(
                            "invalid condition in trait '{}' from {:?}",
                            trait_def.id, path
                        )
                    })?;
                // Per-trait validation checks - skip when validation is disabled
                if enable_full_validation {
                    // Check for greedy regex patterns
                    if !crate::validation_controls::is_validator_disabled("nested-quantifier")
                        && let Some(warning) = trait_def.r#if.check_greedy_patterns()
                    {
                        warnings.push_id(
                            "nested-quantifier",
                            format!("trait '{}' in {:?}: {}", trait_def.id, path, warning),
                        );
                    }
                    // Check for word boundary regex patterns that should use type: word
                    if !crate::validation_controls::is_validator_disabled(
                        "simple-word-boundary-regex",
                    ) && let Some(warning) = trait_def.r#if.check_word_boundary_regex()
                    {
                        warnings.push_id(
                            "simple-word-boundary-regex",
                            format!("trait '{}' in {:?}: {}", trait_def.id, path, warning),
                        );
                    }

                    // Check for short case-insensitive patterns (high collision risk)
                    if let Some(warning) = trait_def
                        .r#if
                        .check_short_case_insensitive(trait_def.r#for.len())
                    {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for improper use of not: field
                    if let Some(warning) = trait_def.check_not_field_usage() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid criticality level
                    if let Some(warning) = trait_def.check_criticality() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid confidence value
                    if let Some(warning) = trait_def.check_confidence() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid size constraints
                    if let Some(warning) = trait_def.check_size_constraints() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid entropy constraints
                    if let Some(warning) = trait_def.check_entropy_constraints() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid count constraints
                    if let Some(warning) = trait_def.check_count_constraints() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid density constraints
                    if let Some(warning) = trait_def.check_density_constraints() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for mutually exclusive match types in condition
                    if let Some(warning) = trait_def.r#if.check_match_exclusivity() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for empty patterns
                    if let Some(warning) = trait_def.r#if.check_empty_patterns() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for overly short patterns
                    if let Some(warning) = trait_def.r#if.check_short_patterns() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for symbol regex patterns with whitespace or word boundaries
                    if let Some(warning) = trait_def.r#if.check_symbol_regex_whitespace() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for literal strings used as regex
                    if let Some(warning) = trait_def.r#if.check_literal_regex() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for useless case_insensitive
                    if !crate::validation_controls::is_validator_disabled(
                        "case-insensitive-no-effect",
                    ) && let Some(warning) = trait_def.r#if.check_case_insensitive_on_non_alpha()
                    {
                        warnings.push_id(
                            "case-insensitive-no-effect",
                            format!("trait '{}' in {:?}: {}", trait_def.id, path, warning),
                        );
                    }

                    // Check for count_min: 0
                    if let Some(warning) = trait_def.check_count_min_value() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for description quality
                    if let Some(warning) = trait_def.check_description_quality() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for empty not: array
                    if let Some(warning) = trait_def.check_empty_not_array() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for empty unless: array
                    if let Some(warning) = trait_def.check_empty_unless_array() {
                        warnings.push_legacy(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }
                }

                // Check for ID conflicts with previously loaded traits (cross-file duplicates)
                if trait_definitions_map.contains_key(&trait_def.id)
                    && !crate::validation_controls::is_validator_disabled("duplicate-composites")
                {
                    warnings.push_id(
                        "duplicate-composites",
                        format!(
                            "Trait ID '{}' defined in multiple files - last definition wins",
                            trait_def.id
                        ),
                    );
                    // HashMap insert will automatically replace the old one
                }

                // Check for ID conflicts with composite rules
                if composite_rules_map.contains_key(&trait_def.id) {
                    warnings.push_legacy(format!(
                        "Rule ID '{}' defined as both trait and composite rule - trait will be used",
                        trait_def.id
                    ));
                    if let Some(comp_file) = rule_source_files.get(&trait_def.id) {
                        warnings.push_legacy(format!("  Trait: {}", path.display()));
                        warnings
                            .push_legacy(format!("  Composite (will be replaced): {}", comp_file));
                    }
                    // Remove the composite rule
                    composite_rules_map.remove(&trait_def.id);
                }

                // Extract symbol mappings from trait definitions with symbol conditions.
                // Only add to the fast symbol_map when the trait applies to all file types —
                // traits with restrictive `for:` constraints must go through the full
                // evaluation pipeline which respects file type filtering.
                let is_universal = trait_def
                    .r#for
                    .contains(&crate::composite_rules::FileType::All)
                    || trait_def.r#for.is_empty();
                if is_universal
                    && let Condition::Symbol {
                        exact,
                        substr: _,
                        regex,
                        platforms: _,
                        compiled_regex: _,
                        ..
                    } = &trait_def.r#if
                {
                    // If exact is specified, add it directly
                    if let Some(exact_val) = exact {
                        symbol_map
                            .entry(exact_val.clone())
                            .or_insert_with(|| TraitInfo {
                                id: trait_def.id.clone(),
                                desc: trait_def.desc.clone(),
                                conf: trait_def.conf,
                                crit: trait_def.crit,
                                mbc: trait_def.mbc.clone(),
                                attack: trait_def.attack.clone(),
                            });
                    }

                    // For each regex pattern (may contain "|" for alternatives)
                    if let Some(regex_val) = regex {
                        for symbol_pattern in regex_val.split('|') {
                            let symbol: String = symbol_pattern.trim().to_string();

                            // Only add if not already present (first match wins)
                            symbol_map.entry(symbol).or_insert_with(|| TraitInfo {
                                id: trait_def.id.clone(),
                                desc: trait_def.desc.clone(),
                                conf: trait_def.conf,
                                crit: trait_def.crit,
                                mbc: trait_def.mbc.clone(),
                                attack: trait_def.attack.clone(),
                            });
                        }
                    }
                } // is_universal

                // Pre-compile regexes for this trait
                if let Err(e) = trait_def.precompile_regexes() {
                    return Err(anyhow::anyhow!(
                        "Failed to compile regex for trait '{}' in {:?}: {:#}",
                        trait_def.id,
                        path,
                        e
                    ));
                }

                // Track source file for error reporting
                let source_path = path.display().to_string();
                trait_source_files.insert(trait_def.id.clone(), source_path.clone());
                rule_source_files.insert(trait_def.id.clone(), source_path);
                trait_definitions_map.insert(trait_def.id.clone(), trait_def);
            }

            // Add file path to file-type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                push_parsing_warning(&mut warnings, &path_str, warning);
            }

            // Merge composite_rules with auto-prefixed IDs, applying file-level defaults
            let mut parsing_warnings = Vec::new();
            for raw_rule in mappings.composite_rules {
                // Convert raw rule to final rule, applying file-level defaults
                let mut rule = apply_composite_defaults(
                    raw_rule,
                    &mappings.defaults,
                    &mut parsing_warnings,
                    &path,
                );

                // Auto-prefix composite rule ID if it doesn't already have the path prefix
                if let Some(ref prefix) = trait_prefix {
                    // Auto-prefix composite rule ID using :: delimiter
                    if !rule.id.starts_with(prefix)
                        && !rule.id.contains("::")
                        && !rule.id.contains('/')
                    {
                        rule.id = format!("{}::{}", prefix, rule.id);
                    }
                    // Also auto-prefix trait references within the rule's conditions
                    autoprefix_trait_refs(&mut rule, prefix);
                }

                // Check for duplicate rule ID with other composite rules
                if composite_rules_map.contains_key(&rule.id)
                    && !crate::validation_controls::is_validator_disabled("duplicate-composites")
                {
                    warnings.push_id(
                        "duplicate-composites",
                        format!(
                            "Composite rule '{}' defined in multiple files - last definition wins",
                            rule.id
                        ),
                    );
                    // HashMap insert will automatically replace the old one
                }

                // Check for ID conflicts with trait definitions
                if trait_definitions_map.contains_key(&rule.id) {
                    warnings.push_legacy(format!(
                        "Rule ID '{}' defined as both trait and composite rule - composite will be used",
                        rule.id
                    ));
                    warnings
                        .push_legacy("  Trait (will be replaced): (already loaded)".to_string());
                    warnings.push_legacy(format!("  Composite: {}", path.display()));
                    // Remove the trait definition
                    trait_definitions_map.remove(&rule.id);
                }

                // Pre-compile regexes for this composite rule
                if let Err(e) = rule.precompile_regexes() {
                    return Err(anyhow::anyhow!(
                        "Failed to compile regex for composite '{}' in {:?}: {}",
                        rule.id,
                        path,
                        e
                    ));
                }

                // Track source file for error reporting
                rule_source_files.insert(rule.id.clone(), path.display().to_string());
                composite_rules_map.insert(rule.id.clone(), rule);
            }

            // Add file path to file-type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                push_parsing_warning(&mut warnings, &path_str, warning);
            }

            if debug {
                eprintln!(
                    "      +{} symbols, +{} traits, +{} composite rules",
                    symbol_map.len() - before_symbols,
                    trait_definitions_map.len() - before_traits,
                    composite_rules_map.len() - before_composites
                );
            }
        }

        // Check for structurally invalid file types (empty for:) — always fatal.
        // Trait-level for: [none] is intentionally allowed to unset inherited defaults.
        let invalid_ft_errors: Vec<&crate::validation_controls::ValidationIssue> = warnings
            .iter()
            .filter(|w| w.validator_id == "invalid-file-type")
            .collect();
        if !invalid_ft_errors.is_empty() {
            let mut sorted_errors: Vec<&str> = invalid_ft_errors
                .iter()
                .map(|e| e.message.as_str())
                .collect();
            sorted_errors.sort();

            return Err(anyhow::anyhow!(
                "Invalid file types found in trait files:\n  {}\n\nPlease fix these file type names in the YAML files.",
                sorted_errors.join("\n  ")
            ));
        }

        // Check for unrecognized file types (forward-compat: newer traits, older binary)
        // In validation mode these are errors; otherwise just log at info and continue
        let unknown_ft_warnings: Vec<&crate::validation_controls::ValidationIssue> = warnings
            .iter()
            .filter(|w| w.validator_id == "unknown-file-type")
            .collect();
        if !unknown_ft_warnings.is_empty() {
            if enable_full_validation {
                let mut sorted_errors: Vec<&str> = unknown_ft_warnings
                    .iter()
                    .map(|e| e.message.as_str())
                    .collect();
                sorted_errors.sort();

                return Err(anyhow::anyhow!(
                    "Unknown file types found in trait files:\n  {}\n\nUpdate cleave or fix these 'for:' values.",
                    sorted_errors.join("\n  ")
                ));
            }
            for w in &unknown_ft_warnings {
                tracing::info!("{} — skipping rule (update cleave for support)", w.message);
            }
        }

        if debug {
            eprintln!("   ✅ Processed {} YAML files", files_processed);
        }

        let _t_yara = std::time::Instant::now();

        // Convert HashMaps to Vecs now that loading is complete
        // This was kept as HashMap during loading for O(1) duplicate detection
        let mut trait_definitions: Vec<TraitDefinition> =
            trait_definitions_map.into_values().collect();
        let mut composite_rules: Vec<CompositeTrait> = composite_rules_map.into_values().collect();

        // Register the combined-engine namespace for atomic traits whose top-level `if`
        // condition is `type: yara`.  These rules are compiled into the shared YaraEngine
        // (see `yara_engine::load_inline_trait_rules`), so we only need to record the
        // namespace here — actual compilation and scanning happen in the engine.
        let yara_count_traits = trait_definitions
            .iter()
            .filter(|t| matches!(t.r#if, Condition::Yara { .. }))
            .count();

        trait_definitions.par_iter_mut().for_each(|t| {
            if matches!(t.r#if, Condition::Yara { .. }) {
                // Set namespace for the combined engine; also compiles any `unless` YARA conditions.
                t.set_yara_if_namespace();
            }
        });

        // Composite rules still use per-condition compilation (they are rare and have
        // complex condition trees that are not currently in the combined engine).
        let yara_count_composite = composite_rules.len();
        composite_rules.par_iter_mut().for_each(|r| {
            r.compile_yara();
        });

        if debug && (yara_count_traits > 0 || yara_count_composite > 0) {
            eprintln!(
                "   ⚡ Registered {} inline YARA namespaces, compiled {} composite rules",
                yara_count_traits, yara_count_composite
            );
        }

        let _t_validate = std::time::Instant::now();

        // Track whether any fatal errors occurred (for deferred exit)
        let mut has_fatal_errors = false;

        if enable_precision_scoring {
            let precision_warning_start = warnings.len();

            warnings.collect_as("precision", |warnings| {
                validate_hostile_trait_precision(
                    &mut trait_definitions,
                    warnings,
                    min_hostile_precision,
                    min_suspicious_precision,
                );
            });
            precalculate_all_composite_precisions(&mut composite_rules, &trait_definitions);
            warnings.collect_as("precision", |warnings| {
                validate_hostile_composite_precision(
                    &mut composite_rules,
                    &trait_definitions,
                    warnings,
                    min_hostile_precision,
                    min_suspicious_precision,
                );
            });

            if !enable_full_validation {
                for warning in &warnings.as_slice()[precision_warning_start..] {
                    eprintln!("Warning: {}", warning.compact_message());
                }
                warnings.truncate(precision_warning_start);
            }
        }

        // Pre-calculate precision for ALL composite rules once
        // Atomic trait precisions are already calculated during parsing
        tracing::trace!("Validating trait definitions and composite rules");
        if enable_full_validation {
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1c/15: Detecting duplicate traits and composites");
            if !crate::validation_controls::is_validator_disabled("dupe-atomic") {
                warnings.collect_as("dupe-atomic", |warnings| {
                    find_duplicate_atomic_traits(&trait_definitions, warnings);
                });
            }
            if !crate::validation_controls::is_validator_disabled("duplicate-composites") {
                warnings.collect_as("duplicate-composites", |warnings| {
                    find_duplicate_composite_rules(&composite_rules, warnings);
                });
            }
            tracing::trace!("Step 1c completed in {:?}", step_start.elapsed());

            // Detect string pattern duplicates and overlaps
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1d/15: Detecting string pattern duplicates and overlaps");
            if !crate::validation_controls::is_validator_disabled("duplicate-patterns") {
                warnings.collect_as("duplicate-patterns", |warnings| {
                    find_string_pattern_duplicates(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1d completed in {:?}", step_start.elapsed());

            // Check for regex OR patterns overlapping with exact matches
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1e/15: Checking for regex OR patterns overlapping exact matches");
            if !crate::validation_controls::is_validator_disabled("regex-or-literal-overlap") {
                warnings.collect_as("regex-or-literal-overlap", |warnings| {
                    check_regex_or_overlapping_exact(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1e completed in {:?}", step_start.elapsed());

            let step_start = std::time::Instant::now();
            tracing::trace!(
                "Step 1e2/15: Checking for overlapping regex patterns with same filetype coverage"
            );
            if !crate::validation_controls::is_validator_disabled("overlapping-regex-patterns") {
                warnings.collect_as("overlapping-regex-patterns", |warnings| {
                    check_overlapping_regex_patterns(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1e2 completed in {:?}", step_start.elapsed());

            // Catch structurally-identical regex pairs (e.g. only the inside of
            // a character class differs) — common copy/paste duplication.
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1e3/15: Checking for structurally duplicate regex patterns");
            if !crate::validation_controls::is_validator_disabled("redundant-patterns") {
                warnings.collect_as("redundant-patterns", |warnings| {
                    find_structural_regex_duplicates(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1e3 completed in {:?}", step_start.elapsed());

            // Check for simple regex that should be exact
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1f/15: Checking for regex patterns that should be exact");
            if !crate::validation_controls::is_validator_disabled("exact-regex-canonicalization") {
                warnings.collect_as("exact-regex-canonicalization", |warnings| {
                    check_regex_should_be_exact(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1f completed in {:?}", step_start.elapsed());

            // Check for same pattern with different types
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1g/15: Checking for patterns with conflicting types");
            if !crate::validation_controls::is_validator_disabled("cross-type-canonicalization") {
                warnings.collect_as("cross-type-canonicalization", |warnings| {
                    check_same_string_different_types(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1g completed in {:?}", step_start.elapsed());

            // Detect regex patterns that are costly for broad raw/text scans.
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1h/15: Detecting potentially slow regex patterns");
            if !crate::validation_controls::is_validator_disabled("regex-performance") {
                warnings.collect_as("regex-performance", |warnings| {
                    find_slow_regex_patterns(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1h completed in {:?}", step_start.elapsed());

            // Detect unnecessary non-capturing groups in regex patterns
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1h2/15: Detecting non-capturing groups in regex patterns");
            if !crate::validation_controls::is_validator_disabled("unnecessary-non-capturing-group")
            {
                warnings.collect_as("unnecessary-non-capturing-group", |warnings| {
                    find_non_capturing_groups(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1h2 completed in {:?}", step_start.elapsed());

            // Detect raw patterns on binary types that would be faster as text
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1h3/15: Detecting raw patterns that should use text");
            warnings.collect_as("raw-should-use-text", |warnings| {
                find_raw_should_use_text(&trait_definitions, warnings);
            });
            tracing::trace!("Step 1h3 completed in {:?}", step_start.elapsed());

            // Detect string_literal patterns that should use text
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1h4/15: Detecting literal-only text mismatches");
            warnings.collect_as("string-literal-should-use-text", |warnings| {
                find_string_literal_should_use_text(&trait_definitions, warnings);
            });
            tracing::trace!("Step 1h4 completed in {:?}", step_start.elapsed());

            // Detect text/raw function-call patterns on AST source types — these
            // should use `type: symbol` for performance and accuracy.
            let step_start = std::time::Instant::now();
            tracing::trace!(
                "Step 1h5/15: Detecting text function-call patterns that should use symbol"
            );
            if !crate::validation_controls::is_validator_disabled("ast-text-call-performance") {
                warnings.collect_as("ast-text-call-performance", |warnings| {
                    find_ast_function_call_should_use_symbol(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1h5 completed in {:?}", step_start.elapsed());

            // Check for exact patterns contained by substr patterns (redundancy)
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1i/15: Checking for exact ⊂ substr containment");
            if !crate::validation_controls::is_validator_disabled("redundant-patterns") {
                warnings.collect_as("redundant-patterns", |warnings| {
                    check_exact_contained_by_substr(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1i completed in {:?}", step_start.elapsed());

            // Check for case-insensitive overlaps and subsumption
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1j/15: Checking for case-insensitive overlaps");
            if !crate::validation_controls::is_validator_disabled("regex-case-subsumption")
                || !crate::validation_controls::is_validator_disabled("case-subsumption")
                || !crate::validation_controls::is_validator_disabled("duplicate-case-only")
            {
                for (validator_id, message) in
                    find_case_insensitive_overlap_issues(&trait_definitions)
                {
                    if !crate::validation_controls::is_validator_disabled(validator_id) {
                        warnings.push_id(validator_id, message);
                    }
                }
            }
            tracing::trace!("Step 1j completed in {:?}", step_start.elapsed());

            // Check for regex vs literal overlaps (cross-type and containment)
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1k/15: Checking for regex vs literal overlaps");
            if !crate::validation_controls::is_validator_disabled("regex-contains-literal")
                || !crate::validation_controls::is_validator_disabled("regex-vs-literal-duplicate")
            {
                for (validator_id, message) in find_regex_literal_overlap_issues(&trait_definitions)
                {
                    if !crate::validation_controls::is_validator_disabled(validator_id) {
                        warnings.push_id(validator_id, message);
                    }
                }
            }
            tracing::trace!("Step 1k completed in {:?}", step_start.elapsed());

            // Check for regex alternative subsets and case-insensitive regex overlaps
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1l/15: Checking for regex alternative subsets");
            if !crate::validation_controls::is_validator_disabled("regex-alternative-subset") {
                warnings.collect_as("regex-alternative-subset", |warnings| {
                    check_regex_alternative_subsets(&trait_definitions, warnings);
                });
            }
            tracing::trace!("Step 1l completed in {:?}", step_start.elapsed());

            // Check for basename pattern duplicates
            let step_start = std::time::Instant::now();
            tracing::trace!("Step 1m/15: Checking for basename pattern duplicates");
            warnings.collect_as("basename-duplicate", |warnings| {
                check_basename_pattern_duplicates(&trait_definitions, warnings);
            });
            tracing::trace!("Step 1m completed in {:?}", step_start.elapsed());
        } else {
            tracing::trace!(
                "Step 1/15: Skipping precision validation (run 'cleave validate' to enable)"
            );
        }

        // Validate trait references in composite rules
        // Cross-directory references must match an existing directory prefix
        // Include both trait definition prefixes AND composite rule prefixes (rules can reference rules)
        tracing::trace!("Step 2/15: Building known prefixes");
        let mut known_prefixes: std::collections::HashSet<String> = trait_definitions
            .iter()
            .filter_map(|t| {
                // Extract the directory prefix from trait IDs
                // New format: everything before '::' (e.g., "micro-behaviors/communications/http::curl" -> "micro-behaviors/communications/http")
                // Legacy format: everything before last '/' (e.g., "micro-behaviors/communications/http/curl" -> "micro-behaviors/communications/http")
                if let Some(idx) = t.id.find("::") {
                    Some(t.id[..idx].to_string())
                } else {
                    t.id.rfind('/').map(|idx| t.id[..idx].to_string())
                }
            })
            .collect();

        // Also add composite rule prefixes (composite rules can reference other composite rules)
        for rule in &composite_rules {
            if let Some(idx) = rule.id.find("::") {
                known_prefixes.insert(rule.id[..idx].to_string());
            } else if let Some(idx) = rule.id.rfind('/') {
                known_prefixes.insert(rule.id[..idx].to_string());
            }
        }

        // Pre-compute all parent paths for O(1) prefix matching
        // This avoids O(n) iteration for every trait reference check
        let mut prefix_hierarchy = known_prefixes.clone();
        for prefix in &known_prefixes {
            // Add all parent paths: "micro-behaviors/fs/write" -> ["cap", "micro-behaviors/fs", "micro-behaviors/fs/write"]
            let parts: Vec<&str> = prefix.split('/').collect();
            for i in 1..parts.len() {
                prefix_hierarchy.insert(parts[..i].join("/"));
            }
        }
        tracing::trace!(
            "Built prefix hierarchy with {} entries from {} base prefixes",
            prefix_hierarchy.len(),
            known_prefixes.len()
        );

        // Steps 3-7: Taxonomy and naming validation (skip when validation disabled)
        let dir_list: Vec<String> = known_prefixes.iter().cloned().collect();
        if enable_full_validation {
            // Check for unknown subdirectories in taxonomy tiers
            // According to TAXONOMY.md, only specific subdirectories are allowed
            tracing::trace!("Step 2b/15: Validating directory whitelist");
            if let Err(errors) = validate_directory_structure(dir_path) {
                eprintln!(
                    "\n❌ ERROR: {} unknown subdirectories found in taxonomy tiers",
                    errors.len()
                );
                for error in &errors {
                    eprintln!("   {}", error);
                }
                eprintln!();
                for error in &errors {
                    warnings.push(format!("unknown subdirectory: {error}"));
                }
                has_fatal_errors = true;
            }

            // Check for YAML files above leaf directories.
            tracing::trace!("Step 2c/15: Checking for non-leaf YAML files");
            let non_leaf_yaml_files = find_non_leaf_yaml_files(&yaml_files, dir_path);
            if !non_leaf_yaml_files.is_empty()
                && !crate::validation_controls::is_validator_disabled("leaf-yaml")
            {
                eprintln!(
                    "\n❌ ERROR: {} YAML files are not in leaf directories",
                    non_leaf_yaml_files.len()
                );
                eprintln!(
                    "   A directory with YAML files must not also have YAML-bearing child directories."
                );
                eprintln!(
                    "   Choose one taxonomy level: move parent YAML into a leaf named for the shared technique,"
                );
                eprintln!(
                    "   or flatten child YAML up when the extra directory adds no ML-visible technique signal."
                );
                eprintln!(
                    "   Prefer language/platform-neutral technique names; use platform directories only when"
                );
                eprintln!("   the technique itself is platform-specific. Keep depth reasonable.\n");
                for file in &non_leaf_yaml_files {
                    eprintln!("   {file}");
                }
                eprintln!();
                warnings.push_id(
                    "leaf-yaml",
                    format!(
                        "{} YAML files are above YAML-bearing child directories",
                        non_leaf_yaml_files.len()
                    ),
                );
            }

            // Check for taxonomy violations: platform/language names as directories
            // According to TAXONOMY.md, languages should be YAML filenames, not directories
            tracing::trace!("Step 3/15: Checking for platform-named directories");
            let platform_dir_violations = find_platform_named_directories(&dir_list);
            if !platform_dir_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} directories are named after platforms/languages (TAXONOMY.md violation)",
                    platform_dir_violations.len()
                );
                eprintln!(
                    "   Languages and platforms should be YAML filenames, not directories:\n"
                );
                for (dir_path, platform_name) in &platform_dir_violations {
                    eprintln!(
                        "   {}: contains platform directory '{}'",
                        dir_path, platform_name
                    );
                }
                eprintln!(
                    "\n   Example: Instead of 'micro-behaviors/execution/python/runtime.yaml',"
                );
                eprintln!("   use 'micro-behaviors/execution/runtime/python.yaml'\n");
                warnings.push(format!(
                    "{} directories named after platforms (should be YAML filenames)",
                    platform_dir_violations.len()
                ));
            }

            // Check for duplicate second-level directories across namespaces
            // According to TAXONOMY.md, directories should not be repeated across metadata/, micro-behaviors/, objectives/, known/
            tracing::trace!("Step 3b/15: Checking for duplicate second-level directories");
            let duplicate_dirs = find_duplicate_second_level_directories(&dir_list);
            if !duplicate_dirs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} second-level directories are duplicated across namespaces (TAXONOMY.md violation)",
                    duplicate_dirs.len()
                );
                eprintln!(
                    "   Second-level directories should not be repeated across metadata/, micro-behaviors/, objectives/, known/:"
                );
                eprintln!(
                    "   This indicates traits are misplaced - objectives should only be in objectives/, capabilities in micro-behaviors/.\n"
                );
                for (dir_name, namespaces) in &duplicate_dirs {
                    eprintln!(
                        "   '{}' appears in: {}/{}/ ",
                        dir_name,
                        namespaces.join("/, "),
                        dir_name
                    );
                }
                eprintln!("\n   Examples:");
                eprintln!(
                    "   - micro-behaviors/command-and-control/ and objectives/command-and-control/ → C2 is an objective, should only be in objectives/"
                );
                eprintln!(
                    "   - micro-behaviors/discovery/ and objectives/discovery/ → Discovery is an objective, should only be in objectives/"
                );
                eprintln!(
                    "   - micro-behaviors/malware/ and known/malware/ → Malware detection should not be in micro-behaviors/\n"
                );
                warnings.push(format!(
                    "{} second-level directories duplicated across namespaces",
                    duplicate_dirs.len()
                ));
                has_fatal_errors = true;
            }

            // Check for banned meaningless directory segments
            tracing::trace!("Step 4/15: Checking for banned directory segments");
            let banned_segment_violations = find_banned_directory_segments(&dir_list);
            if !banned_segment_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} directories contain meaningless segment names",
                    banned_segment_violations.len()
                );
                eprintln!("   These segments add no semantic value and hurt taxonomy clarity:\n");
                for (dir_path, segment) in &banned_segment_violations {
                    eprintln!("   {}: contains banned segment '{}'", dir_path, segment);
                }
                eprintln!("\n   Use specific, descriptive names instead.\n");
                warnings.push(format!(
                    "{} directories contain meaningless segments",
                    banned_segment_violations.len()
                ));
            }

            // Check for duplicate words in path - REMOVED
            // This check had too many false positives (e.g., httpx library name)

            // Check for directory names that duplicate their parent
            tracing::trace!("Step 5/15: Checking for parent duplicate segments");
            let parent_dup_violations = find_parent_duplicate_segments(&dir_list);
            if !parent_dup_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} directories duplicate their parent segment",
                    parent_dup_violations.len()
                );
                eprintln!("   Child directories should not repeat parent names:\n");
                for (dir_path, segment) in &parent_dup_violations {
                    eprintln!("   {}: segment '{}' duplicates parent", dir_path, segment);
                }
                eprintln!();
                warnings.push(format!(
                    "{} directories duplicate parent segment",
                    parent_dup_violations.len()
                ));
            }

            // Check for depth violations: micro-behaviors/ and objectives/ files must be 3-4 subdirectories deep
            tracing::trace!("Step 6/15: Checking for depth violations");
            let relative_paths: Vec<String> = yaml_files
                .iter()
                .filter_map(|p| {
                    p.strip_prefix(dir_path)
                        .ok()
                        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                })
                .collect();
            let depth_violations = find_depth_violations(&relative_paths);
            if !depth_violations.is_empty() {
                let shallow: Vec<_> = depth_violations
                    .iter()
                    .filter(|(_, _, kind)| *kind == "shallow")
                    .collect();
                let deep: Vec<_> = depth_violations
                    .iter()
                    .filter(|(_, _, kind)| *kind == "deep")
                    .collect();

                if !shallow.is_empty() {
                    eprintln!(
                        "\n❌ ERROR: {} files are too shallow (need 2-4 subdirectories in micro-behaviors/obj)",
                        shallow.len()
                    );
                    eprintln!(
                        "   Add technique-bearing directories, not filler names; filenames can carry language/platform."
                    );
                    for (path, depth, _) in &shallow {
                        eprintln!("   {} ({} subdirs, need 2-4)", path, depth);
                    }
                }
                if !deep.is_empty() {
                    eprintln!(
                        "\n❌ ERROR: {} files are too deep (max 4 subdirectories in micro-behaviors/obj)",
                        deep.len()
                    );
                    eprintln!(
                        "   Collapse language/platform or filler levels into filenames; keep paths focused on technique."
                    );
                    for (path, depth, _) in &deep {
                        eprintln!("   {} ({} subdirs, max 4)", path, depth);
                    }
                }
                warnings.push(format!(
                    "{} files at wrong depth (need 2-4 subdirectories in micro-behaviors/obj)",
                    depth_violations.len()
                ));
            }

            // Check for invalid characters in trait/rule IDs
            tracing::trace!("Step 7/15: Checking for invalid trait IDs");
            let invalid_ids =
                find_invalid_trait_ids(&trait_definitions, &composite_rules, &rule_source_files);
            if !invalid_ids.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} trait/rule IDs contain invalid characters",
                    invalid_ids.len()
                );
                if debug {
                    eprintln!("   IDs must be a bare local identifier using only [a-zA-Z0-9_-].");
                    eprintln!("   The taxonomy hierarchy comes from the file's directory on disk,");
                    eprintln!("   so '/' and ':' are not allowed inside an `id:` declaration.\n");
                    for (id, invalid_char, source_file) in &invalid_ids {
                        let line_hint = find_line_number(source_file, id);
                        if let Some(line) = line_hint {
                            eprintln!(
                                "   {}:{}: ID '{}' contains invalid char '{}'",
                                source_file, line, id, invalid_char
                            );
                        } else {
                            eprintln!(
                                "   {}: ID '{}' contains invalid char '{}'",
                                source_file, id, invalid_char
                            );
                        }
                    }
                    eprintln!("\n   Allowed in id: [a-zA-Z0-9_-] only.");
                    eprintln!(
                        "   Reference format (in if/all/any/none): <local_id> or <subdirectory>::<local_id>\n"
                    );
                } else {
                    eprintln!("   Set CLEAVE_DEBUG=1 to see details\n");
                }
                warnings.push(format!(
                    "{} trait/rule IDs contain invalid characters",
                    invalid_ids.len()
                ));
            }

            // Self-referencing traits — `if: type: trait, id: <self>`
            // never fires because the runtime resolves the reference
            // by checking the findings table, but the trait itself
            // hasn't been added yet. Silent failure → every composite
            // depending on it is silently dead.
            tracing::trace!("Step 7b/15: Checking for self-referencing traits");
            let self_refs = find_self_referencing_traits(&trait_definitions);
            if !self_refs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} traits self-reference (will never fire)",
                    self_refs.len()
                );
                eprintln!(
                    "   `if: type: trait, id: <self>` queries the findings table for the\n   \
                     trait being evaluated, which hasn't been added yet — the lookup is\n   \
                     always false. Composites that depend on this trait silently fail.\n"
                );
                for trait_def in &self_refs {
                    let source_file = rule_source_files
                        .get(&trait_def.id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source_file, &trait_def.id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Trait '{}' references itself",
                            source_file, line, trait_def.id
                        );
                    } else {
                        eprintln!(
                            "   {}: Trait '{}' references itself",
                            source_file, trait_def.id
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} self-referencing traits (will never fire)",
                    self_refs.len()
                ));
            }
        } // End of enable_full_validation block for steps 3-7

        tracing::trace!("Step 8/15: Validating trait references in composite rules");
        let mut invalid_refs = Vec::new();
        for rule in &composite_rules {
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, rule_id) in trait_refs {
                // Only validate cross-directory references (those with slashes or ::)
                let is_cross_dir = ref_id.contains("::") || ref_id.contains('/');
                if is_cross_dir {
                    // Skip validation for metadata/ paths - these are dynamically generated
                    if ref_id.starts_with("metadata/import/")
                        || ref_id.starts_with("metadata/dylib/")
                        || ref_id.starts_with("metadata/signed/")
                    {
                        continue;
                    }

                    // Extract the directory part for validation
                    let dir_part = if let Some(idx) = ref_id.find("::") {
                        &ref_id[..idx]
                    } else if let Some(idx) = ref_id.rfind('/') {
                        &ref_id[..idx]
                    } else {
                        &ref_id[..]
                    };

                    // Check if this matches any known prefix (O(1) lookup instead of O(n) iteration)
                    // Check exact match or any parent path exists in hierarchy
                    let matches_prefix = prefix_hierarchy.contains(dir_part)
                        || dir_part.split('/').enumerate().skip(1).any(|(i, _)| {
                            let parent = dir_part.split('/').take(i).collect::<Vec<_>>().join("/");
                            prefix_hierarchy.contains(&parent)
                        });
                    if !matches_prefix {
                        let source_file = rule_source_files
                            .get(&rule_id)
                            .map(std::string::String::as_str)
                            .unwrap_or("unknown");
                        invalid_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                    }
                }
            }
        }

        if !invalid_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} invalid trait references found in composite rules",
                invalid_refs.len()
            );
            if debug {
                for (rule_id, ref_id, source_file) in &invalid_refs {
                    // Try to find line number by searching the file
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references unknown path: '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references unknown path: '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!(
                    "\n   Cross-directory references must use directory paths (e.g., 'discovery/system')"
                );
                eprintln!("   that match existing trait directories, not exact trait IDs.\n");
            } else {
                eprintln!("   Set CLEAVE_DEBUG=1 to see details\n");
            }
        }

        // Skip regex precompilation - regexes will be compiled on demand during evaluation
        // This saves ~150ms at startup
        tracing::trace!("Step 9/15: Skipping regex precompilation (lazy mode)");

        // Validate exact trait ID references
        // Build set of all valid trait IDs (both atomic traits and composite rules)
        tracing::trace!("Step 10/15: Building valid trait IDs set");
        let mut valid_trait_ids: FxHashSet<String> =
            trait_definitions.iter().map(|t| t.id.clone()).collect();
        for rule in &composite_rules {
            valid_trait_ids.insert(rule.id.clone());
        }
        let file_stem_hints =
            build_file_stem_reference_hints(dir_path, &trait_definitions, &composite_rules);

        // Debug: Print sample of valid trait IDs
        if std::env::var("CLEAVE_DEBUG").is_ok() {
            let mut sample_ids: Vec<_> = valid_trait_ids
                .iter()
                .filter(|id| {
                    id.contains("tiny-elf")
                        || id.contains("small-elf")
                        || id.contains("setup-py")
                        || id.contains("pkginfo")
                })
                .collect();
            sample_ids.sort();
            for id in sample_ids {
                eprintln!("[DEBUG] Valid trait ID: {}", id);
            }
        }

        // Steps 11-15: Additional validation checks (skip when validation disabled)
        if enable_full_validation {
            // Validate that composite rules don't reference the
            // retired `metadata/internal/symbols::*` namespace. The
            // auto-emit was removed because it dominated diff/output
            // noise for binaries with many imports; YAML rules that
            // need to gate on a specific symbol/function call should
            // use inline `type: symbol, exact: <name>` conditions.
            tracing::trace!("Step 11/15: Checking for retired internal/symbols references");
            let mut internal_refs = Vec::new();
            for rule in &composite_rules {
                let trait_refs = collect_trait_refs_from_rule(rule);
                for (ref_id, rule_id) in trait_refs {
                    if ref_id.starts_with("metadata/internal/") {
                        let source_file = rule_source_files
                            .get(&rule_id)
                            .map(std::string::String::as_str)
                            .unwrap_or("unknown");
                        internal_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                    }
                }
            }

            if !internal_refs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules reference the retired metadata/internal/ namespace",
                    internal_refs.len()
                );
                eprintln!(
                    "   The metadata/internal/symbols::* auto-emit was removed; replace each reference with an inline `type: symbol, exact: <name>` condition.\n"
                );
                for (rule_id, ref_id, source_file) in &internal_refs {
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references retired path: '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references retired path: '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules reference retired metadata/internal/ paths",
                    internal_refs.len()
                ));
            }

            // Validate that micro-behaviors/ rules do not reference objectives/ rules
            // Cap contains micro-behaviors, obj contains larger behaviors
            // Cap rules should be independent of obj rules
            tracing::trace!("Step 12/15: Checking for micro-behaviors/obj violations");
            let cap_obj_violations =
                find_cap_obj_violations(&trait_definitions, &composite_rules, &rule_source_files);

            if !cap_obj_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} micro-behaviors/ rules reference objectives/ rules",
                    cap_obj_violations.len()
                );
                eprintln!(
                    "   Cap rules (micro-behaviors) should not depend on obj rules (larger behaviors):\n"
                );
                for (rule_id, ref_id, source_file) in &cap_obj_violations {
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references obj rule: '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references obj rule: '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!("\n   Cap rules should only reference other cap rules or meta rules.");
                warnings.push(format!(
                "{} micro-behaviors/ rules reference objectives/ rules (cap should not depend on obj)",
                cap_obj_violations.len()
            ));
            }

            // Validate that micro-behaviors/ rules are never hostile
            // Hostile criticality requires objective-level evidence and belongs in objectives/
            tracing::trace!("Step 13/15: Checking for hostile cap rules");
            let hostile_cap_rules =
                find_hostile_cap_rules(&trait_definitions, &composite_rules, &rule_source_files);

            if !hostile_cap_rules.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} micro-behaviors/ rules have hostile criticality",
                    hostile_cap_rules.len()
                );
                eprintln!(
                    "   Cap contains micro-behaviors (atomic capabilities) which are generally neutral."
                );
                eprintln!(
                    "   Hostile rules require intent inference and should be in objectives/ where they can be"
                );
                eprintln!(
                    "   categorized properly by attacker objective (C2, exfil, impact, etc.):\n"
                );
                for (rule_id, source_file) in &hostile_cap_rules {
                    let line_hint = find_line_number(source_file, "crit: hostile");
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: Rule '{}'", source_file, line, rule_id);
                    } else {
                        eprintln!("   {}: Rule '{}'", source_file, rule_id);
                    }
                }
                eprintln!(
                    "\n   Cap rules max criticality: suspicious (rarely legitimate but still a capability)"
                );
                eprintln!(
                    "   Move hostile rules to objectives/command-and-control/, objectives/exfiltration/, objectives/impact/, etc. based on objective."
                );
                warnings.push(format!(
                    "{} micro-behaviors/ rules have hostile criticality (should be in objectives/)",
                    hostile_cap_rules.len()
                ));
            }

            // Validate that metadata/ rules are never hostile
            // Hostile criticality requires intent inference and belongs in objectives/
            tracing::trace!("Step 13a/15: Checking for hostile metadata rules");
            let hostile_meta_rules =
                find_hostile_meta_rules(&trait_definitions, &composite_rules, &rule_source_files);

            if !hostile_meta_rules.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} metadata/ rules have hostile criticality",
                    hostile_meta_rules.len()
                );
                eprintln!("   Metadata rules are purely informational file-level properties.");
                eprintln!(
                    "   Hostile rules require intent inference and should be in objectives/:\n"
                );
                for (rule_id, source_file) in &hostile_meta_rules {
                    let line_hint = find_line_number(source_file, "crit: hostile");
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: Rule '{}'", source_file, line, rule_id);
                    } else {
                        eprintln!("   {}: Rule '{}'", source_file, rule_id);
                    }
                }
                eprintln!("\n   Metadata rules should have baseline criticality only.");
                eprintln!(
                    "   Move hostile composites to objectives/lateral-movement/supply-chain/ or similar."
                );
                warnings.push(format!(
                    "{} metadata/ rules have hostile criticality (should be in objectives/)",
                    hostile_meta_rules.len()
                ));
                has_fatal_errors = true;
            }

            // Validate that metadata/ rules do not reference non-metadata tiers
            tracing::trace!("Step 13b/15: Checking for metadata cross-tier references");
            let meta_cross_tier = find_metadata_cross_tier_refs(
                &trait_definitions,
                &composite_rules,
                &rule_source_files,
            );

            if !meta_cross_tier.is_empty() {
                tracing::info!(
                    "{} metadata/ rules reference non-metadata tiers (allowed for composite aggregation)",
                    meta_cross_tier.len()
                );
            }

            // Validate that micro-behaviors/ rules do not improperly reference well-known/ rules.
            // - well-known/malware/ refs are forbidden in any clause.
            // - well-known/{tool,app,lib,game}/ refs are allowed only in unless/downgrade
            //   (benign-context suppression), not as positive evidence.
            tracing::trace!("Step 13c/15: Checking for micro-behaviors/well-known violations");
            let cap_wk_violations = find_cap_wellknown_violations(
                &trait_definitions,
                &composite_rules,
                &rule_source_files,
            );

            if !cap_wk_violations.is_empty() {
                let malware_count = cap_wk_violations
                    .iter()
                    .filter(|(_, _, _, r)| *r == ObjectivesWellknownViolation::MalwareRef)
                    .count();
                let positive_count = cap_wk_violations.len() - malware_count;
                eprintln!(
                    "\n❌ ERROR: {} micro-behaviors/ → well-known/ references violate the tier policy",
                    cap_wk_violations.len()
                );
                if malware_count > 0 {
                    eprintln!(
                        "   - {} reference well-known/malware/ (never allowed in micro-behaviors/)",
                        malware_count
                    );
                }
                if positive_count > 0 {
                    eprintln!(
                        "   - {} use well-known/{{tool,app,lib,game}}/ as positive evidence \
                         (only allowed inside `unless:` / `downgrade:`)",
                        positive_count
                    );
                }
                eprintln!();
                for (rule_id, ref_id, source_file, reason) in &cap_wk_violations {
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references '{}' — micro-behaviors/ {}",
                            source_file,
                            line,
                            rule_id,
                            ref_id,
                            reason.as_str()
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references '{}' — micro-behaviors/ {}",
                            source_file,
                            rule_id,
                            ref_id,
                            reason.as_str()
                        );
                    }
                }
                warnings.push(format!(
                    "{} micro-behaviors/ → well-known/ references violate the tier policy",
                    cap_wk_violations.len()
                ));
            }

            // Validate that objectives/ rules do not improperly reference well-known/ rules.
            // - well-known/malware/ refs are forbidden in any clause.
            // - well-known/{tool,app,lib,game}/ refs are allowed only in unless/downgrade
            //   (benign-context suppression), not as positive evidence for hostile intent.
            tracing::trace!("Step 13d/15: Checking for objectives/well-known violations");
            let obj_wk_violations = find_objectives_wellknown_violations(
                &trait_definitions,
                &composite_rules,
                &rule_source_files,
            );

            if !obj_wk_violations.is_empty() {
                let malware_count = obj_wk_violations
                    .iter()
                    .filter(|(_, _, _, r)| *r == ObjectivesWellknownViolation::MalwareRef)
                    .count();
                let positive_count = obj_wk_violations.len() - malware_count;
                eprintln!(
                    "\n❌ ERROR: {} objectives/ → well-known/ references violate the tier policy",
                    obj_wk_violations.len()
                );
                if malware_count > 0 {
                    eprintln!(
                        "   - {} reference well-known/malware/ (never allowed in objectives/)",
                        malware_count
                    );
                }
                if positive_count > 0 {
                    eprintln!(
                        "   - {} use well-known/{{tool,app,lib,game}}/ as positive evidence \
                         (only allowed inside `unless:` / `downgrade:`)",
                        positive_count
                    );
                }
                eprintln!();
                for (rule_id, ref_id, source_file, reason) in &obj_wk_violations {
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references '{}' — objectives/ {}",
                            source_file,
                            line,
                            rule_id,
                            ref_id,
                            reason.as_str()
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references '{}' — objectives/ {}",
                            source_file,
                            rule_id,
                            ref_id,
                            reason.as_str()
                        );
                    }
                }
                warnings.push(format!(
                    "{} objectives/ → well-known/ references violate the tier policy",
                    obj_wk_violations.len()
                ));
            }

            // NOTE: baseline traits are now allowed in objectives/ - they serve as building blocks
            // for composite rules and can be useful even without direct analytical signal.

            // Validate that malware/ is not used as a subcategory of objectives/ or micro-behaviors/
            // Malware-specific signatures belong in known/malware/ per TAXONOMY.md
            tracing::trace!("Step 13b/15: Checking for misplaced malware/ subcategories");
            let malware_violations = find_malware_subcategory_violations(
                &trait_definitions,
                &composite_rules,
                &rule_source_files,
            );

            if !malware_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} rules use malware/ as a subcategory of objectives/ or micro-behaviors/",
                    malware_violations.len()
                );
                eprintln!(
                    "   Malware-specific signatures belong in known/malware/, not objectives/ or micro-behaviors/."
                );
                eprintln!("   See TAXONOMY.md for the correct taxonomy structure:\n");
                for (rule_id, source_file) in &malware_violations {
                    eprintln!("   {}: Rule '{}'", source_file, rule_id);
                }
                eprintln!("\n   Move these rules to known/malware/<family>/ instead.");
                warnings.push(format!(
                "{} rules misuse malware/ as a subcategory of objectives/ or micro-behaviors/ (see TAXONOMY.md)",
                malware_violations.len()
            ));
                has_fatal_errors = true;
            }

            // Validate well-known/ category whitelist
            tracing::trace!("Checking well-known/ category whitelist");
            let wk_category_violations = find_wellknown_category_violations(&dir_list);
            if !wk_category_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} unknown categories under well-known/",
                    wk_category_violations.len()
                );
                eprintln!(
                    "   Only whitelisted subcategories are allowed under well-known/malware/ and well-known/tool/:\n"
                );
                for (dir_path, category) in &wk_category_violations {
                    eprintln!("   {}: unknown category '{}'", dir_path, category);
                }
                eprintln!(
                    "\n   Add the category to WELL_KNOWN_MALWARE_CATEGORIES or WELL_KNOWN_TOOL_CATEGORIES in taxonomy.rs if legitimate."
                );
                warnings.push(format!(
                    "{} unknown categories under well-known/",
                    wk_category_violations.len()
                ));
            }

            // Validate well-known/ leaf directory names for generic technique words
            tracing::trace!("Checking well-known/ leaf directory names");
            let generic_leaf_violations = find_generic_wellknown_leaf_dirs(&dir_list);
            if !generic_leaf_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ directories use generic technique names",
                    generic_leaf_violations.len()
                );
                eprintln!(
                    "   well-known/ directories should be named after specific malware families/tools:\n"
                );
                for (dir_path, word) in &generic_leaf_violations {
                    eprintln!("   {}: generic technique word '{}'", dir_path, word);
                }
                eprintln!(
                    "\n   Rename to a specific family name, or move generic detection to objectives/."
                );
                warnings.push(format!(
                    "{} well-known/ directories use generic technique names instead of family names",
                    generic_leaf_violations.len()
                ));
            }

            // Validate well-known/ composites have local anchoring (family-specific refs)
            tracing::trace!("Checking well-known/ composite anchoring");
            let unanchored =
                find_unanchored_wellknown_composites(&composite_rules, &rule_source_files);
            if !unanchored.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ composites have no family-specific anchoring",
                    unanchored.len()
                );
                eprintln!(
                    "   well-known/ composites should reference at least one local or well-known/ trait:"
                );
                eprintln!(
                    "   Composites that only combine micro-behaviors/ or objectives/ refs belong in objectives/.\n"
                );
                for (rule_id, source_file) in &unanchored {
                    let line_hint = find_line_number(source_file, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Composite '{}' has no well-known/ anchoring",
                            source_file, line, rule_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Composite '{}' has no well-known/ anchoring",
                            source_file, rule_id
                        );
                    }
                }
                warnings.push(format!(
                    "{} well-known/ composites have no family-specific anchoring (move to objectives/)",
                    unanchored.len()
                ));
            }

            // Validate well-known/ files are not composite-only (should have atomic traits)
            tracing::trace!("Checking for composite-only well-known/ files");
            let composite_only =
                find_composite_only_wellknown_files(&trait_definitions, &composite_rules);
            if !composite_only.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ directories contain only composites (no atomic traits in directory)",
                    composite_only.len()
                );
                eprintln!(
                    "   well-known/ directories should define family-specific fingerprints (atomic traits)."
                );
                eprintln!("   Possible fixes:");
                eprintln!(
                    "   - Move composite-only rules to objectives/ if they detect generic behaviors"
                );
                eprintln!(
                    "   - Move family-specific traits from micro-behaviors/ into well-known/ if they were misplaced\n"
                );
                for (source_file, count) in &composite_only {
                    eprintln!(
                        "   {}: {} composite(s), 0 atomic traits in directory",
                        source_file, count
                    );
                }
                warnings.push(format!(
                    "{} well-known/ directories are composite-only (add family-specific atomic traits or move to objectives/)",
                    composite_only.len()
                ));
            }

            // Validate: traits with 4+ effective platforms must be in an allowlisted directory
            tracing::trace!("Checking for over-broad platform scope (4+ effective platforms)");
            let broad_plat = find_broad_platform_traits(&trait_definitions, &rule_source_files);
            if !broad_plat.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} traits target {} or more platforms",
                    broad_plat.len(),
                    4
                );
                eprintln!("   Narrow the platform scope or move to an allowlisted directory:");
                for prefix in BROAD_PLATFORM_ALLOWLIST {
                    eprintln!("     {prefix}");
                }
                eprintln!();
                for (trait_id, source_file, count) in &broad_plat {
                    let line_hint = find_line_number(source_file, "platforms:");
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: '{}' ({} platforms)",
                            source_file, line, trait_id, count
                        );
                    } else {
                        eprintln!("   {}: '{}' ({} platforms)", source_file, trait_id, count);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits target 4+ platforms (narrow scope or move to allowlisted directory)",
                    broad_plat.len()
                ));
                has_fatal_errors = true;
            }

            // Validate: traits listing unix alongside linux or macos (redundant — unix is the superset)
            tracing::trace!("Checking for redundant unix+linux/macos platform combinations");
            let redundant_unix =
                find_redundant_unix_platforms(&trait_definitions, &rule_source_files);
            if !redundant_unix.is_empty() {
                eprintln!(
                    "\n⚠️  WARNING: {} traits list 'unix' with redundant specific platforms",
                    redundant_unix.len()
                );
                eprintln!(
                    "   'unix' already covers linux and macos. Use [unix, windows] instead of [linux, macos, unix, windows]."
                );
                eprintln!();
                for (trait_id, source_file, redundant) in &redundant_unix {
                    let line_hint = find_line_number(source_file, "platforms:");
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: '{}' (redundant: {})",
                            source_file, line, trait_id, redundant
                        );
                    } else {
                        eprintln!(
                            "   {}: '{}' (redundant: {})",
                            source_file, trait_id, redundant
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits list 'unix' with redundant linux/macos (unix is the superset)",
                    redundant_unix.len()
                ));
            }

            // Validate: traits with too many file types (10+ multi-platform, 12+ single-platform)
            tracing::trace!("Checking for over-broad file type scope");
            let broad_ft = find_broad_filetype_traits(&trait_definitions, &rule_source_files);
            if !broad_ft.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} traits target too many file types (23+ types — exceeds 2-group threshold)",
                    broad_ft.len()
                );
                eprintln!("   Narrow the file type scope or move to an allowlisted directory:");
                for prefix in BROAD_FILETYPE_ALLOWLIST {
                    eprintln!("     {prefix}");
                }
                eprintln!();
                for (trait_id, source_file, count, matched_types) in &broad_ft {
                    let line_hint = find_line_number(source_file, "for:");
                    let count_str = if *count == usize::MAX {
                        "all".to_string()
                    } else {
                        count.to_string()
                    };
                    let types_str = matched_types
                        .iter()
                        .map(|ft| format!("{ft:?}").to_lowercase())
                        .collect::<Vec<_>>()
                        .join(", ");
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: '{}' ({} types: {})",
                            source_file, line, trait_id, count_str, types_str
                        );
                    } else {
                        eprintln!(
                            "   {}: '{}' ({} types: {})",
                            source_file, trait_id, count_str, types_str
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits target 6+ file types (narrow scope or move to allowlisted directory)",
                    broad_ft.len()
                ));
                has_fatal_errors = true;
            }

            // Validate: condition-type-specific filetype scope limits
            // ast: ≤2 types, symbol/hex/yara: ≤4 types
            tracing::trace!("Checking condition-type filetype scope limits");
            let cond_scope =
                find_condition_scope_violations(&trait_definitions, &rule_source_files);
            if !cond_scope.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} traits exceed the filetype limit for their condition type",
                    cond_scope.len()
                );
                eprintln!("   ast: ≤2 types  |  symbol/hex/yara: ≤4 types\n");
                for (trait_id, source_file, kind, count, max) in &cond_scope {
                    let count_str = if *count == usize::MAX {
                        "all".to_string()
                    } else {
                        count.to_string()
                    };
                    let line_hint = find_line_number(source_file, "for:");
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: '{}' (type:{} has {} types, max {})",
                            source_file, line, trait_id, kind, count_str, max
                        );
                    } else {
                        eprintln!(
                            "   {}: '{}' (type:{} has {} types, max {})",
                            source_file, trait_id, kind, count_str, max
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits exceed filetype limit for condition type (ast≤2, symbol/hex/yara≤4)",
                    cond_scope.len()
                ));
                has_fatal_errors = true;
            }

            let disable_wellknown_size_filter_validation =
                crate::validation_controls::is_validator_disabled("wellknown-size-filter");
            let disable_binary_section_filter_validation =
                crate::validation_controls::is_validator_disabled("binary-section-filter");

            // Validate well-known/ atomic traits have file size bounds
            tracing::trace!("Checking well-known/ for missing size filters");
            let wk_no_size =
                find_wellknown_missing_size_filter(&trait_definitions, &rule_source_files);
            if !disable_wellknown_size_filter_validation && !wk_no_size.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ traits have no file size filter",
                    wk_no_size.len()
                );
                eprintln!(
                    "   well-known/ traits should include size_min/size_max to avoid false positives:\n"
                );
                for (trait_id, source_file) in &wk_no_size {
                    eprintln!("   {}: Trait '{}'", source_file, trait_id);
                }
                eprintln!(
                    "\n   Add 'size_min:' and/or 'size_max:' bounds appropriate to the malware family."
                );
                warnings.push(format!(
                    "{} well-known/ traits lack file size filters (add size_min/size_max)",
                    wk_no_size.len()
                ));
            }

            // Validate well-known/ binary-targeting traits have a section filter
            tracing::trace!("Checking well-known/ binary traits for missing section filters");
            let wk_no_section =
                find_wellknown_missing_section_filter(&trait_definitions, &rule_source_files);
            if !disable_binary_section_filter_validation && !wk_no_section.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ binary traits lack a section filter",
                    wk_no_section.len()
                );
                eprintln!(
                    "   Binary-targeting traits in well-known/ should scope string/raw/hex matches to a section:"
                );
                eprintln!(
                    "   Use 'section: .text' or 'section: .data' on the condition, or use 'type: section'.\n"
                );
                for (trait_id, source_file) in &wk_no_section {
                    eprintln!("   {}: Trait '{}'", source_file, trait_id);
                }
                eprintln!();
                warnings.push(format!(
                    "{} well-known/ binary traits lack section filters (add section: field to condition)",
                    wk_no_section.len()
                ));
            }

            // Recommend section filters for metadata/ binary-targeting traits
            tracing::trace!("Checking metadata/ binary traits for missing section filters");
            let meta_no_section =
                find_meta_missing_section_filter(&trait_definitions, &rule_source_files);
            if !disable_binary_section_filter_validation && !meta_no_section.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} metadata/ binary traits lack a section filter",
                    meta_no_section.len()
                );
                eprintln!(
                    "   Binary-targeting traits in metadata/ should scope string/raw/hex matches to a section:"
                );
                eprintln!(
                    "   Use 'section: .text' or 'section: .data' on the condition, or use 'type: section'.\n"
                );
                for (trait_id, source_file) in &meta_no_section {
                    eprintln!("   {}: Trait '{}'", source_file, trait_id);
                }
                eprintln!();
                warnings.push(format!(
                    "{} metadata/ binary traits lack section filters (add section: field to condition)",
                    meta_no_section.len()
                ));
            }

            // Validate that all hex conditions targeting binary file types specify a section
            tracing::trace!("Checking hex conditions targeting binaries for missing section");
            let hex_no_section = find_hex_binary_missing_section(&trait_definitions);
            if !hex_no_section.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} hex condition(s) target binary file types without a section filter",
                    hex_no_section.len()
                );
                eprintln!(
                    "   Hex patterns on binary targets must scope the search with 'section:'"
                );
                eprintln!(
                    "   (use 'section: text', 'section: data', etc., or add 'offset:' to pin location)\n"
                );
                for trait_id in &hex_no_section {
                    let source_file = rule_source_files
                        .get(trait_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    eprintln!("   {}: Trait '{}'", source_file, trait_id);
                }
                eprintln!();
                warnings.push(format!(
                    "{} hex condition(s) target binaries without a section filter (add section: to condition)",
                    hex_no_section.len()
                ));
            }

            // Validate that `any:` clauses don't have 3+ traits from the same external directory
            // Recommend using directory references instead for better maintainability
            tracing::trace!("Step 14/15: Checking for redundant any refs");
            let mut redundant_any_refs = Vec::new();
            for rule in &composite_rules {
                let violations = find_redundant_any_refs(rule);
                for (rule_id, dir, count, trait_ids) in violations {
                    let source_file = rule_source_files
                        .get(&rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    redundant_any_refs.push((
                        rule_id,
                        dir,
                        count,
                        trait_ids,
                        source_file.to_string(),
                    ));
                }
            }

            if !redundant_any_refs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have redundant any: clauses",
                    redundant_any_refs.len()
                );
                eprintln!(
                    "   Rules with 4+ trait references from the same directory should use directory notation:\n"
                );
                for (rule_id, dir, count, trait_ids, source_file) in &redundant_any_refs {
                    let line_hint = find_line_number(source_file, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references {} traits from '{}'",
                            source_file, line, rule_id, count, dir
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references {} traits from '{}'",
                            source_file, rule_id, count, dir
                        );
                    }
                    eprintln!("      Traits: {}", trait_ids.join(", "));
                    eprintln!(
                        "      Recommendation: Use 'id: {}', or create a new subdirectory within it to hold common traits instead.\n",
                        dir
                    );
                }
                warnings.push(format!(
                    "{} composite rules have redundant any: clauses (use directory notation)",
                    redundant_any_refs.len()
                ));
            }

            // Validate that any:/all: clauses don't hand-maintain many refs to one directory.
            // `any:` should use directory notation; `all:` should be split only for clear sub-techniques.
            tracing::trace!("Checking for many directory references in composite clauses");
            let mut dir_traits: HashMap<String, HashSet<String>> = HashMap::new();
            let disable_many_directory_references =
                crate::validation_controls::is_validator_disabled("many-directory-references");
            let disable_dir_alias_composite =
                crate::validation_controls::is_validator_disabled("directory-alias-composite");
            if !disable_many_directory_references || !disable_dir_alias_composite {
                for trait_def in &trait_definitions {
                    if let Some(idx) = trait_def.id.find("::") {
                        dir_traits
                            .entry(trait_def.id[..idx].to_string())
                            .or_default()
                            .insert(trait_def.id.clone());
                    }
                }
            }
            let mut many_dir_ref_clauses = Vec::new();
            if !disable_many_directory_references {
                for rule in &composite_rules {
                    let violations = find_many_directory_refs(rule, &dir_traits);
                    for (rule_id, clause, dir, count, trait_ids) in violations {
                        let source_file = rule_source_files
                            .get(&rule_id)
                            .map(std::string::String::as_str)
                            .unwrap_or("unknown");
                        many_dir_ref_clauses.push((
                            rule_id,
                            clause,
                            dir,
                            count,
                            trait_ids,
                            source_file.to_string(),
                        ));
                    }
                }
            }

            if !many_dir_ref_clauses.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules hand-maintain many refs to one directory",
                    many_dir_ref_clauses.len()
                );
                eprintln!(
                    "   A composite should not hand-maintain long lists of atomic traits from one directory:\n"
                );
                for (rule_id, clause, dir, count, trait_ids, source_file) in &many_dir_ref_clauses {
                    let line_hint = find_line_number(source_file, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' {}: clause covers all {} traits in '{}'",
                            source_file, line, rule_id, clause, count, dir
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' {}: clause covers all {} traits in '{}'",
                            source_file, rule_id, clause, count, dir
                        );
                    }
                    eprintln!("      Traits: {}", trait_ids.join(", "));
                    if *clause == "any" {
                        eprintln!(
                            "      Recommendation: Replace the explicit list with 'id: {}'.\n",
                            dir
                        );
                    } else {
                        eprintln!(
                            "      Recommendation: Keep small intentional bundles together; split only when there are clear sub-techniques.\n"
                        );
                    }
                }
                warnings.push_count(
                    "many-directory-references",
                    many_dir_ref_clauses.len(),
                    format!(
                        "{} composite rules hand-maintain many refs to one directory",
                        many_dir_ref_clauses.len()
                    ),
                );
            }

            let dir_alias_composites = if disable_dir_alias_composite {
                Vec::new()
            } else {
                find_pure_directory_alias_composites(&composite_rules, &dir_traits)
            };
            if !dir_alias_composites.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composites are pure directory aliases",
                    dir_alias_composites.len()
                );
                eprintln!(
                    "   These composites add no logic beyond matching any trait in a directory."
                );
                eprintln!("   Delete the composite and reference the directory directly:\n");
                for (rule_id, dir, count, trait_ids) in &dir_alias_composites {
                    let source_file = rule_source_files
                        .get(rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source_file, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' is equivalent to '{}'",
                            source_file, line, rule_id, dir
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' is equivalent to '{}'",
                            source_file, rule_id, dir
                        );
                    }
                    eprintln!("      Traits ({}): {}", count, trait_ids.join(", "));
                    eprintln!(
                        "      Recommendation: Remove the composite and use 'id: {}'.\n",
                        dir
                    );
                }
                warnings.push_count(
                    "directory-alias-composite",
                    dir_alias_composites.len(),
                    format!(
                        "{} composites are pure directory aliases",
                        dir_alias_composites.len()
                    ),
                );
            }

            // Validate that `any:` and `all:` clauses don't have exactly 1 item
            // Single-item clauses are pointless wrappers that add complexity
            tracing::trace!("Step 15/15: Checking for single-item clauses");
            let mut single_item_clauses = Vec::new();
            for rule in &composite_rules {
                let violations = find_single_item_clauses(rule);
                for (rule_id, clause_type, trait_id) in violations {
                    let source_file = rule_source_files
                        .get(&rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    single_item_clauses.push((
                        rule_id,
                        clause_type,
                        trait_id,
                        source_file.to_string(),
                    ));
                }
            }

            if !single_item_clauses.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have single-item any:/all: clauses",
                    single_item_clauses.len()
                );
                eprintln!(
                    "   Single-item clauses add no value - reference the trait directly instead:\n"
                );
                for (rule_id, clause_type, trait_id, source_file) in &single_item_clauses {
                    let line_hint = find_line_number(source_file, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' has single-item {}: clause referencing '{}'",
                            source_file, line, rule_id, clause_type, trait_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' has single-item {}: clause referencing '{}'",
                            source_file, rule_id, clause_type, trait_id
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules have single-item any:/all: clauses",
                    single_item_clauses.len()
                ));
            }

            // Validate that all:/any: clauses don't contain overlapping IDs.
            // A directory reference subsumes any specific trait from that directory.
            let mut overlapping = Vec::new();
            for rule in &composite_rules {
                for (rule_id, clause, dir_ref, specific_ref) in find_overlapping_conditions(rule) {
                    let source_file = rule_source_files
                        .get(&rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    overlapping.push((
                        rule_id,
                        clause,
                        dir_ref,
                        specific_ref,
                        source_file.to_string(),
                    ));
                }
            }
            if !overlapping.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have overlapping all:/any: conditions",
                    overlapping.len()
                );
                eprintln!(
                    "   A directory reference already includes all traits within it;\n   remove the specific trait reference:\n"
                );
                for (rule_id, clause, dir_ref, specific_ref, source_file) in &overlapping {
                    let line_hint = find_line_number(source_file, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' {}: clause - '{}' is subsumed by '{}'",
                            source_file, line, rule_id, clause, specific_ref, dir_ref
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' {}: clause - '{}' is subsumed by '{}'",
                            source_file, rule_id, clause, specific_ref, dir_ref
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules have overlapping all:/any: conditions",
                    overlapping.len()
                ));
                has_fatal_errors = true;
            }

            // Validate: string vs raw type collisions (same pattern at same criticality)
            // These should be merged to just `raw` (which is broader)
            let collisions = find_string_content_collisions(&trait_definitions);
            if !collisions.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} trait pairs have deprecated string_value/raw type collisions",
                    collisions.len()
                );
                eprintln!(
                    "   When both deprecated `type: text` and `type: raw` exist for the same pattern,"
                );
                eprintln!(
                    "   remove the legacy `string_value` rule. Keep `raw` only for byte-precise matching; otherwise prefer a single `text` rule:\n"
                );
                for (string_id, raw_id, pattern) in &collisions {
                    let string_source = rule_source_files
                        .get(string_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(string_source, string_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: string trait '{}' duplicates raw trait '{}'",
                            string_source, line, string_id, raw_id
                        );
                    } else {
                        eprintln!(
                            "   {}: string trait '{}' duplicates raw trait '{}'",
                            string_source, string_id, raw_id
                        );
                    }
                    eprintln!("      Pattern: {}", pattern);
                    eprintln!("      Action: Delete the string trait, keep the raw trait\n");
                }
                warnings.push(format!(
                    "{} string/raw type collisions (merge to raw only)",
                    collisions.len()
                ));
            }

            // Validate: traits that differ only in `for:` field should be merged
            let for_duplicates = find_for_only_duplicates(&trait_definitions);
            if !for_duplicates.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} trait groups differ only in `for:` field",
                    for_duplicates.len()
                );
                eprintln!(
                    "   These traits have identical logic (same criticality, condition, etc.) but different file types."
                );
                eprintln!("   Merge them into a single trait with combined `for:` values:\n");
                for (trait_ids, _pattern) in &for_duplicates {
                    // Find source file for the first trait
                    let first_id = &trait_ids[0];
                    let source = rule_source_files
                        .get(first_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, first_id);
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: {}", source, line, trait_ids.join(", "));
                    } else {
                        eprintln!("   {}: {}", source, trait_ids.join(", "));
                    }
                    eprintln!(
                        "      Action: Merge into single trait with `for: [combined file types]`\n"
                    );
                }
                warnings.push(format!(
                    "{} trait groups differ only in `for:` field (should be merged)",
                    for_duplicates.len()
                ));
            }

            // Validate: traits with identical matching logic but different metadata
            let logic_duplicates = find_atomic_logic_duplicates(&trait_definitions);
            if !logic_duplicates.is_empty() {
                eprintln!(
                    "\n⚠️  WARNING: {} trait pairs have identical matching logic but different metadata",
                    logic_duplicates.len()
                );
                eprintln!(
                    "   Same detection with inconsistent criticality/confidence/platforms:\n"
                );
                for (id_a, id_b, desc) in &logic_duplicates {
                    let source_a = rule_source_files
                        .get(id_a)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let source_b = rule_source_files
                        .get(id_b)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_a = find_line_number(source_a, id_a);
                    let line_b = find_line_number(source_b, id_b);

                    let loc_a = if let Some(line) = line_a {
                        format!("{}:{}", source_a, line)
                    } else {
                        source_a.to_string()
                    };
                    let loc_b = if let Some(line) = line_b {
                        format!("{}:{}", source_b, line)
                    } else {
                        source_b.to_string()
                    };

                    eprintln!("   {} vs {}", id_a, id_b);
                    eprintln!("      {}", loc_a);
                    eprintln!("      {}", loc_b);
                    eprintln!("      {}\n", desc);
                }
                warnings.push(format!(
                    "{} trait pairs have identical matching but different metadata",
                    logic_duplicates.len()
                ));
            }

            // Validate: regex patterns that could be merged with alternation (case-only differences)
            // e.g., `nc\s+-e` and `NC\s+-e` -> `(nc|NC)\s+-e`
            let alternation_candidates =
                find_alternation_merge_candidates(&trait_definitions, &trait_source_files);
            if !alternation_candidates.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} trait groups have regex patterns that should use alternation",
                    alternation_candidates.len()
                );
                eprintln!(
                    "   These traits have identical criticality and regex patterns where the first token differs only in case."
                );
                eprintln!("   Merge them into a single trait using alternation syntax:\n");
                for (trait_ids, _suffix, suggested) in &alternation_candidates {
                    let first_id = &trait_ids[0];
                    let source = rule_source_files
                        .get(first_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, first_id);
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: {}", source, line, trait_ids.join(", "));
                    } else {
                        eprintln!("   {}: {}", source, trait_ids.join(", "));
                    }
                    eprintln!("      Suggested regex: {}\n", suggested);
                }
                warnings.push(format!(
                    "{} trait groups should use regex alternation",
                    alternation_candidates.len()
                ));
            }

            // Validate: `needs` value exceeds number of potential matches in `any:` (impossible to satisfy)
            // Directory references can match multiple traits, so we count potential matches
            let all_trait_ids: Vec<String> = valid_trait_ids.iter().cloned().collect();
            let impossible_needs = find_impossible_needs(&composite_rules, &all_trait_ids);
            if !impossible_needs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have impossible `needs` values",
                    impossible_needs.len()
                );
                eprintln!(
                    "   The `needs` value exceeds the number of potential matches in `any:`:\n"
                );
                for (rule_id, needs, potential) in &impossible_needs {
                    let source = rule_source_files
                        .get(rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: '{}' has needs: {} but only {} potential matches",
                            source, line, rule_id, needs, potential
                        );
                    } else {
                        eprintln!(
                            "   {}: '{}' has needs: {} but only {} potential matches",
                            source, rule_id, needs, potential
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules have impossible `needs` values",
                    impossible_needs.len()
                ));
            }

            // Validate: size_min > size_max (impossible constraint)
            let impossible_sizes =
                find_impossible_size_constraints(&trait_definitions, &composite_rules);
            if !impossible_sizes.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} rules have impossible size constraints (size_min > size_max)",
                    impossible_sizes.len()
                );
                for (id, min, max, is_composite) in &impossible_sizes {
                    let kind = if *is_composite { "composite" } else { "trait" };
                    let source = rule_source_files
                        .get(id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: {} '{}' has size_min: {} > size_max: {}",
                            source, line, kind, id, min, max
                        );
                    } else {
                        eprintln!(
                            "   {}: {} '{}' has size_min: {} > size_max: {}",
                            source, kind, id, min, max
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} rules have impossible size constraints",
                    impossible_sizes.len()
                ));
            }

            // Validate: count_min > count_max (impossible constraint)
            let impossible_counts = find_impossible_count_constraints(&trait_definitions);
            if !impossible_counts.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} traits have impossible count constraints (count_min > count_max)",
                    impossible_counts.len()
                );
                for (id, min, max) in &impossible_counts {
                    let source = rule_source_files
                        .get(id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: '{}' has count_min: {} > count_max: {}",
                            source, line, id, min, max
                        );
                    } else {
                        eprintln!(
                            "   {}: '{}' has count_min: {} > count_max: {}",
                            source, id, min, max
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits have impossible count constraints",
                    impossible_counts.len()
                ));
            }

            // Validate: empty any:/all: clauses with no other conditions
            let empty_clauses = find_empty_condition_clauses(&composite_rules);
            if !empty_clauses.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have empty condition clauses",
                    empty_clauses.len()
                );
                eprintln!("   Empty `any:` or `all:` clauses make rules meaningless:\n");
                for (rule_id, clause_type) in &empty_clauses {
                    let source = rule_source_files
                        .get(rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: '{}' has empty `{}:` clause",
                            source, line, rule_id, clause_type
                        );
                    } else {
                        eprintln!(
                            "   {}: '{}' has empty `{}:` clause",
                            source, rule_id, clause_type
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules have empty condition clauses",
                    empty_clauses.len()
                ));
            }

            // Validate: `needs` without `any:` (silently ignored, likely authoring mistake)
            let needs_without_any = find_needs_without_any(&composite_rules);
            if !needs_without_any.is_empty() {
                eprintln!(
                    "\n⚠️  WARNING: {} composite rules have `needs` without `any:`",
                    needs_without_any.len()
                );
                eprintln!(
                    "   `needs` only applies to `any:` conditions and is ignored on `all:`-only rules:\n"
                );
                for rule_id in &needs_without_any {
                    let source = rule_source_files
                        .get(rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: '{}'", source, line, rule_id);
                    } else {
                        eprintln!("   {}: '{}'", source, rule_id);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules have `needs` without `any:`",
                    needs_without_any.len()
                ));
            }

            // Validate: needs: 0 vacuously matches (any: clause is meaningless)
            let needs_zero = find_needs_zero(&composite_rules);
            if !needs_zero.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have `needs: 0`",
                    needs_zero.len()
                );
                eprintln!("   `needs: 0` vacuously matches regardless of `any:` conditions:\n");
                for rule_id in &needs_zero {
                    let source = rule_source_files
                        .get(rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, "needs:");
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: '{}'", source, line, rule_id);
                    } else {
                        eprintln!("   {}: '{}'", source, rule_id);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules have `needs: 0` (vacuous match)",
                    needs_zero.len()
                ));
            }

            // Validate: string/content conditions with no search pattern
            let missing_patterns = find_missing_search_patterns(&trait_definitions);
            if !missing_patterns.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} traits have no search pattern",
                    missing_patterns.len()
                );
                eprintln!(
                    "   String/content conditions need at least one of: exact, substr, regex, word:\n"
                );
                for id in &missing_patterns {
                    let source = rule_source_files
                        .get(id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, id);
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: '{}'", source, line, id);
                    } else {
                        eprintln!("   {}: '{}'", source, id);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits have no search pattern",
                    missing_patterns.len()
                ));
            }

            // Validate: patterns too short to be useful (1-2 concrete chars/bytes)
            let too_short = find_too_short_patterns(&trait_definitions);
            if !too_short.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} traits have patterns too short to be useful (<3 concrete chars/bytes)",
                    too_short.len()
                );
                eprintln!(
                    "   Short patterns must bound their search space (~8KB ideal). Add one of:"
                );
                eprintln!("   - offset or small closed offset_range (absolute file position)");
                eprintln!("   - section + section_offset or small closed section_offset_range");
                eprintln!("   - section + size_max (bound total file size)\n");
                for (id, pattern, kind) in &too_short {
                    let source = rule_source_files
                        .get(id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: '{}' ({}: \"{}\")",
                            source, line, id, kind, pattern
                        );
                    } else {
                        eprintln!("   {}: '{}' ({}: \"{}\")", source, id, kind, pattern);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits have patterns too short (<3 concrete chars/bytes)",
                    too_short.len()
                ));
            }

            // Validate: `not:` only used with `regex:` patterns
            let invalid_not = find_invalid_not_usage(&trait_definitions);
            if !invalid_not.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} traits use `not:` without `regex:`",
                    invalid_not.len()
                );
                eprintln!(
                    "   `not:` filters individual matches and only makes sense with `regex:` patterns:\n"
                );
                for msg in &invalid_not {
                    eprintln!("   {}", msg);
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits use `not:` without `regex:`",
                    invalid_not.len()
                ));
            }

            // Validate: KV `exists` alongside value matcher is redundant
            let kv_exists = find_kv_exists_with_matcher(&trait_definitions, &composite_rules);
            if !kv_exists.is_empty() {
                eprintln!(
                    "\n⚠ WARNING: {} rules have KV `exists` alongside a value matcher",
                    kv_exists.len()
                );
                eprintln!("   `exists` is redundant when `exact`, `substr`, or `regex` is set:");
                eprintln!(
                    "   - `exists: true` is implied (a value matcher requires the field to exist)"
                );
                eprintln!(
                    "   - `exists: false` is contradictory (a non-existent field can't have a value)\n"
                );
                for rule_id in &kv_exists {
                    let source = rule_source_files
                        .get(rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, "exists:");
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: '{}'", source, line, rule_id);
                    } else {
                        eprintln!("   {}: '{}'", source, rule_id);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} rules have KV `exists` alongside a value matcher (redundant)",
                    kv_exists.len()
                ));
            }

            // Validate: none-only rules with proximity constraints (always fail silently)
            let none_prox = find_none_only_with_proximity(&composite_rules);
            if !none_prox.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have proximity on none-only rules",
                    none_prox.len()
                );
                eprintln!(
                    "   `near_lines`/`near_bytes` requires positive conditions (`all:`/`any:`)."
                );
                eprintln!(
                    "   A rule without positive conditions and with proximity can never match:\n"
                );
                for rule_id in &none_prox {
                    let source = rule_source_files
                        .get(rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    eprintln!("   {}: '{}'", source, rule_id);
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules have proximity on none-only rules (can never match)",
                    none_prox.len()
                ));
            }

            // Validate: redundant `needs: 1` when only `any:` exists
            let redundant_needs = find_redundant_needs_one(&composite_rules);
            if !redundant_needs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have redundant `needs: 1`",
                    redundant_needs.len()
                );
                eprintln!("   `needs: 1` is the default when only `any:` exists - remove it:\n");
                for rule_id in &redundant_needs {
                    let source = rule_source_files
                        .get(rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: '{}'", source, line, rule_id);
                    } else {
                        eprintln!("   {}: '{}'", source, rule_id);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} composite rules have redundant `needs: 1`",
                    redundant_needs.len()
                ));
            }

            let disable_excessive_suppression_validation =
                crate::validation_controls::is_validator_disabled("excessive-suppression");

            // Validate: excessive unless:/downgrade: suppressions (8+ combined)
            let excessive_skips =
                find_excessive_skip_conditions(&trait_definitions, &composite_rules);
            if !disable_excessive_suppression_validation && !excessive_skips.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} rules have 8+ combined unless:/downgrade: clauses",
                    excessive_skips.len()
                );
                eprintln!(
                    "   Either improve the rule precision or refactor with a more appropriate"
                );
                eprintln!(
                    "   taxonomy and criticality. If the rule is so broad that it provides no"
                );
                eprintln!("   signal to humans or ML pipelines, consider removing it:\n");
                for (id, unless_count, downgrade_count, is_composite) in &excessive_skips {
                    let source = rule_source_files
                        .get(id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, id);
                    let kind = if *is_composite { "composite" } else { "trait" };
                    let combined = unless_count + downgrade_count;
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: {} '{}' ({} unless + {} downgrade = {} total)",
                            source, line, kind, id, unless_count, downgrade_count, combined
                        );
                    } else {
                        eprintln!(
                            "   {}: {} '{}' ({} unless + {} downgrade = {} total)",
                            source, kind, id, unless_count, downgrade_count, combined
                        );
                    }
                }
                eprintln!();
                warnings.push_count(
                    "excessive-suppression",
                    excessive_skips.len(),
                    format!(
                        "{} rules have excessive unless:/downgrade: clauses",
                        excessive_skips.len()
                    ),
                );
            }

            // Validate: traits/rules with 7+ explicit file types (suggest a named group instead)
            let excessive_for = find_excessive_file_types(&trait_definitions, &composite_rules);
            if !excessive_for.is_empty() {
                eprintln!(
                    "\n⚠️  WARNING: {} traits/rules specify 7+ explicit file types",
                    excessive_for.len()
                );
                eprintln!(
                    "   Enumerating many types is fragile and hard to maintain — use a named group:"
                );
                eprintln!(
                    "   binaries, scripts, source, manifests, documents, media, data, or all\n"
                );
                for (id, count, suggestion, is_composite) in &excessive_for {
                    let source = rule_source_files
                        .get(id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, id);
                    let kind = if *is_composite { "composite" } else { "trait" };
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: {} '{}' ({} types — {})",
                            source, line, kind, id, count, suggestion
                        );
                    } else {
                        eprintln!(
                            "   {}: {} '{}' ({} types — {})",
                            source, kind, id, count, suggestion
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits/rules specify 7+ explicit file types (use a named group)",
                    excessive_for.len()
                ));
            }

            // Validate: pure alias traits that add no value
            let pure_aliases = find_pure_alias_traits(&trait_definitions);
            if !pure_aliases.is_empty() {
                eprintln!(
                    "\n⚠️  WARNING: {} traits are pure aliases with no added value",
                    pure_aliases.len()
                );
                eprintln!(
                    "   These traits reference another trait via `if: id:` but add no constraints:"
                );
                eprintln!("   - No filtering (count_min, count_max, section, etc.)");
                eprintln!("   - Same criticality as referenced trait");
                eprintln!("   - No unless/not/downgrade modifiers");
                eprintln!(
                    "   Either add constraints/modifiers or reference the original trait directly:\n"
                );
                for (trait_id, ref_id) in &pure_aliases {
                    let source = rule_source_files
                        .get(trait_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    let line_hint = find_line_number(source, trait_id);
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: '{}' -> '{}'", source, line, trait_id, ref_id);
                    } else {
                        eprintln!("   {}: '{}' -> '{}'", source, trait_id, ref_id);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits are pure aliases with no added value",
                    pure_aliases.len()
                ));
            }

            // Validate: orphaned component traits not referenced by any rule
            let disable_orphaned_components_validation =
                crate::validation_controls::is_validator_disabled("orphaned-components");
            let orphaned_components =
                find_orphaned_components(&trait_definitions, &composite_rules, &rule_source_files);
            if !disable_orphaned_components_validation && !orphaned_components.is_empty() {
                eprintln!(
                    "\n⚠️  WARNING: {} component traits are never referenced",
                    orphaned_components.len()
                );
                eprintln!(
                    "   Component traits (crit: component) are building blocks that should only exist"
                );
                eprintln!(
                    "   to be referenced by composite rules or via `if: id:` in other traits."
                );
                eprintln!("   These components are orphaned and serve no purpose:\n");
                for (trait_id, source_file) in &orphaned_components {
                    let line_hint = find_line_number(source_file, trait_id);
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: '{}'", source_file, line, trait_id);
                    } else {
                        eprintln!("   {}: '{}'", source_file, trait_id);
                    }
                }
                eprintln!();
                eprintln!(
                    "   Add it as a dependent trait within a composite rule, or delete the rule."
                );
                eprintln!();
                warnings.push(format!(
                    "{} component traits are orphaned (not referenced by any rule)",
                    orphaned_components.len()
                ));
            }

            // Validate: short patterns that are likely to produce too many false positives
            let short_pattern_warnings =
                find_short_pattern_warnings(&trait_definitions, &trait_source_files);
            if !short_pattern_warnings.is_empty() {
                eprintln!(
                    "\n⚠️  WARNING: {} traits have open-ended short patterns",
                    short_pattern_warnings.len()
                );
                eprintln!("   Open-ended short patterns are too likely to create false positives.");
                eprintln!("   Try to create a more specific trait; see RULES.md for details.\n");
                for (trait_id, pattern, pattern_type, source_file) in &short_pattern_warnings {
                    let line_hint = find_line_number(source_file, pattern);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Trait '{}' uses {} pattern '{}'",
                            source_file, line, trait_id, pattern_type, pattern
                        );
                    } else {
                        eprintln!(
                            "   {}: Trait '{}' uses {} pattern '{}'",
                            source_file, trait_id, pattern_type, pattern
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} traits have open-ended short patterns",
                    short_pattern_warnings.len()
                ));
            }

            // Validate: directories with too many traits (should be split)
            let oversized_dirs = find_oversized_trait_directories(&trait_definitions);
            if !oversized_dirs.is_empty()
                && !crate::validation_controls::is_validator_disabled("oversized-dir")
            {
                eprintln!(
                    "\n❌ ERROR: {} directories have more than {} traits",
                    oversized_dirs.len(),
                    MAX_TRAITS_PER_DIRECTORY
                );
                eprintln!(
                    "   Why: the ML pipeline sees directory structure, not trait IDs; broad directories hide shared behavior."
                );
                eprintln!(
                    "   Split by language/platform-neutral technique so similar behavior groups across implementations."
                );
                eprintln!(
                    "   Use platform directories only when the technique itself is platform-specific."
                );
                eprintln!(
                    "   Keep depth reasonable; prefer one meaningful subdirectory level over a deep taxonomy.\n"
                );
                for (dir_path, count) in &oversized_dirs {
                    eprintln!("   {}: {} traits", dir_path, count);
                }
                eprintln!();
                warnings.push_id(
                    "oversized-dir",
                    format!(
                        "{} directories exceed {} traits (split by portable technique; keep depth reasonable)",
                        oversized_dirs.len(),
                        MAX_TRAITS_PER_DIRECTORY
                    ),
                );
            }

            let mut broken_refs = Vec::new();
            for rule in &composite_rules {
                let trait_refs = collect_trait_refs_from_rule(rule);
                for (ref_id, rule_id) in trait_refs {
                    // Skip validation for directory-level references (intentional loose coupling)
                    // e.g., "discovery/system" matches any trait in that directory
                    // Also allow parent directory refs like "micro-behaviors/fs/write/" when traits exist in subdirs
                    let ref_without_slash = ref_id.trim_end_matches('/');
                    // O(1) prefix hierarchy lookup instead of O(n) iteration
                    let is_directory_ref = prefix_hierarchy.contains(&ref_id)
                        || prefix_hierarchy.contains(ref_without_slash);

                    // Skip validation for dynamically generated metadata/* references
                    // - metadata/import/ and metadata/dylib/ are generated from binary imports
                    // - metadata/signed/ is generated from code signature parsing
                    let is_dynamic_or_internal = ref_id.starts_with("metadata/import/")
                        || ref_id.starts_with("metadata/dylib/")
                        || ref_id.starts_with("metadata/signed/");

                    // Check if the exact trait ID exists (unless it's an intentional directory ref)
                    // Note: We require exact matches. References like "micro-behaviors/foo/bar/filename" where
                    // "filename" is a YAML file (not a directory) are invalid - filenames are never
                    // part of trait IDs, only the directory path is used for prefixing.
                    if !is_directory_ref
                        && !is_dynamic_or_internal
                        && !valid_trait_ids.contains(&ref_id)
                    {
                        // Debug: Print broken reference details
                        if std::env::var("CLEAVE_DEBUG").is_ok()
                            && (ref_id.contains("tiny-elf")
                                || ref_id.contains("small-elf")
                                || ref_id.contains("setup-py")
                                || ref_id.contains("pkginfo"))
                        {
                            eprintln!(
                                "[DEBUG] Broken reference: '{}' (from rule '{}')",
                                ref_id, rule_id
                            );
                        }
                        let source_file = rule_source_files
                            .get(&rule_id)
                            .map(std::string::String::as_str)
                            .unwrap_or("unknown");
                        let line_hint = find_line_number(source_file, &ref_id);
                        let suggestion =
                            build_filename_reference_suggestion(&ref_id, &file_stem_hints);
                        broken_refs.push(BrokenTraitReference {
                            rule_id: rule_id.clone(),
                            ref_id,
                            source_file: source_file.to_string(),
                            line_hint,
                            suggestion,
                        });
                    }
                }
            }

            if !broken_refs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} broken trait references found in composite rules",
                    broken_refs.len()
                );
                eprintln!("   Composite rules reference trait IDs that don't exist:\n");
                for broken_ref in &broken_refs {
                    if let Some(line) = broken_ref.line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references non-existent trait: '{}'",
                            broken_ref.source_file, line, broken_ref.rule_id, broken_ref.ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references non-existent trait: '{}'",
                            broken_ref.source_file, broken_ref.rule_id, broken_ref.ref_id
                        );
                    }
                    if let Some(suggestion) = &broken_ref.suggestion {
                        eprintln!("      {}", suggestion);
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} broken trait references in composite rules",
                    broken_refs.len()
                ));
                for broken_ref in &broken_refs {
                    let location = if let Some(line) = broken_ref.line_hint {
                        format!("{}:{}", broken_ref.source_file, line)
                    } else {
                        broken_ref.source_file.clone()
                    };
                    let mut detail = format!(
                        "{location}: Rule '{}' references non-existent trait '{}'",
                        broken_ref.rule_id, broken_ref.ref_id
                    );
                    if let Some(suggestion) = &broken_ref.suggestion {
                        detail.push_str(&format!(" — {suggestion}"));
                    }
                    warnings.push(detail);
                }
                has_fatal_errors = true;
            }

            // Validate metric field references
            let valid_metric_fields: rustc_hash::FxHashSet<String> =
                crate::types::field_paths::all_valid_metric_paths()
                    .into_iter()
                    .collect();
            let mut invalid_metric_refs = Vec::new();

            // Metric paths emitted by filefacts live in cleave's flat
            // `filefacts_metrics` map (`BTreeMap<String, f64>`). The set
            // of valid keys is open — filefacts adds new ones as
            // extractors grow — so we accept any path under the
            // namespaces filefacts owns. The strict-whitelist check
            // below only fires for paths that don't match an
            // filefacts-owned prefix AND aren't in the explicit
            // language/encoding manifest.
            const EXPOSE_PREFIXES: &[&str] = &[
                "binary.",
                "pe.",
                "elf.",
                "macho.",
                "java_class.",
                "sections.",
                "strings.",
                "imports.",
                "exports.",
                "functions.",
                "dependencies.",
                "parse.",
            ];
            let in_filefacts_namespace = |f: &str| EXPOSE_PREFIXES.iter().any(|p| f.starts_with(p));

            for trait_def in &trait_definitions {
                if let crate::composite_rules::Condition::Metrics { field, .. } = &trait_def.r#if
                    && !valid_metric_fields.contains(field)
                    && !in_filefacts_namespace(field)
                {
                    let source_file = trait_source_files
                        .get(&trait_def.id)
                        .map(String::as_str)
                        .unwrap_or("unknown");
                    invalid_metric_refs.push((
                        trait_def.id.clone(),
                        field.clone(),
                        source_file.to_string(),
                    ));
                }
            }

            if !invalid_metric_refs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} unknown metric field references found in traits",
                    invalid_metric_refs.len()
                );
                eprintln!("   Traits reference metric fields that don't exist:\n");
                for (trait_id, field, source_file) in &invalid_metric_refs {
                    let line_hint = find_line_number(source_file, field);
                    let suggestion =
                        super::helpers::suggest_metric_field(&valid_metric_fields, field);
                    if let Some(line) = line_hint {
                        if let Some(suggested) = suggestion {
                            eprintln!(
                                "   {}:{}: Trait '{}' references unknown metric '{}' (did you mean '{}'?)",
                                source_file, line, trait_id, field, suggested
                            );
                        } else {
                            eprintln!(
                                "   {}:{}: Trait '{}' references unknown metric '{}'",
                                source_file, line, trait_id, field
                            );
                        }
                    } else if let Some(suggested) = suggestion {
                        eprintln!(
                            "   {}: Trait '{}' references unknown metric '{}' (did you mean '{}'?)",
                            source_file, trait_id, field, suggested
                        );
                    } else {
                        eprintln!(
                            "   {}: Trait '{}' references unknown metric '{}'",
                            source_file, trait_id, field
                        );
                    }
                }
                eprintln!("\n   Valid metric fields:");
                let mut sorted_fields: Vec<&String> = valid_metric_fields.iter().collect();
                sorted_fields.sort();
                for field in sorted_fields.iter().take(10) {
                    eprintln!("     - {}", field);
                }
                if sorted_fields.len() > 10 {
                    eprintln!("     ... and {} more", sorted_fields.len() - 10);
                }
                eprintln!();
                warnings.push(format!(
                    "{} unknown metric field references in traits",
                    invalid_metric_refs.len()
                ));
                has_fatal_errors = true;
            }

            // Validate that composite rules only contain trait references (not inline primitives)
            // Strict mode is the default - composite rules must only reference traits
            let mut inline_errors = Vec::new();
            for rule in &composite_rules {
                let source = rule_source_files
                    .get(&rule.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                inline_errors.extend(validate_composite_trait_only(rule, source));
            }

            if !inline_errors.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite rules have inline primitives\n",
                    inline_errors.len()
                );
                for err in &inline_errors {
                    eprintln!("   {}", err);
                }
                eprintln!("\n   Composite rules must only reference traits (type: trait).");
                eprintln!(
                    "   Convert inline conditions (string, symbol, yara, etc.) to atomic traits.\n"
                );
                warnings.push(format!(
                    "{} composite rules have inline primitives",
                    inline_errors.len()
                ));
                has_fatal_errors = true;
            }

            // Validate single-rule composites with identical file types
            // Build map of trait_id -> file_types for quick lookup
            let mut trait_file_types: FxHashMap<String, Vec<RuleFileType>> = FxHashMap::default();
            for trait_def in &trait_definitions {
                trait_file_types.insert(trait_def.id.clone(), trait_def.r#for.clone());
            }
            for rule in &composite_rules {
                trait_file_types.insert(rule.id.clone(), rule.r#for.clone());
            }

            // Build metadata lookup for traits and composites
            let mut trait_metadata: FxHashMap<
                String,
                (Criticality, f32, Option<String>, Option<String>),
            > = FxHashMap::default();
            for trait_def in &trait_definitions {
                trait_metadata.insert(
                    trait_def.id.clone(),
                    (
                        trait_def.crit,
                        trait_def.conf,
                        trait_def.attack.clone(),
                        trait_def.mbc.clone(),
                    ),
                );
            }
            for rule in &composite_rules {
                trait_metadata.insert(
                    rule.id.clone(),
                    (rule.crit, rule.conf, rule.attack.clone(), rule.mbc.clone()),
                );
            }

            let mut redundant_composites = Vec::new();
            let mut unless_only_composites = Vec::new();

            for rule in &composite_rules {
                // Check if this is a single-rule composite
                let mut total_conditions = 0;
                if let Some(ref all) = rule.all {
                    total_conditions += all.len();
                }
                if let Some(ref any) = rule.any {
                    total_conditions += any.len();
                }

                // If it's a single-rule composite, check file types
                if total_conditions == 1 {
                    let trait_refs = collect_trait_refs_from_rule(rule);
                    if trait_refs.len() == 1 {
                        let (ref_id, _) = &trait_refs[0];

                        // Look up the referenced trait's file types
                        if let Some(ref_file_types) = trait_file_types.get(ref_id) {
                            // Compare file types - warn if identical
                            if rule.r#for == *ref_file_types {
                                let source_file = rule_source_files
                                    .get(&rule.id)
                                    .map(std::string::String::as_str)
                                    .unwrap_or("unknown");

                                // Check if this composite only adds an 'unless' clause
                                // If so, it might be better expressed as a downgrade
                                let has_unless =
                                    rule.unless.as_ref().is_some_and(|u| !u.is_empty());
                                let has_downgrade = rule.downgrade.is_some();

                                // Check if metadata is being changed
                                let metadata_changed =
                                    if let Some((ref_crit, ref_conf, ref_attack, ref_mbc)) =
                                        trait_metadata.get(ref_id)
                                    {
                                        rule.crit != *ref_crit
                                            || (rule.conf - ref_conf).abs() > 0.001
                                            || rule.attack != *ref_attack
                                            || rule.mbc != *ref_mbc
                                    } else {
                                        false
                                    };

                                if has_unless && !has_downgrade && !metadata_changed {
                                    // Only adds unless, no metadata changes - suggest downgrade pattern
                                    unless_only_composites.push((
                                        rule.id.clone(),
                                        ref_id.clone(),
                                        source_file.to_string(),
                                    ));
                                } else if !has_unless && !has_downgrade && !metadata_changed {
                                    // Truly useless - no unless, no downgrade, no metadata changes, same file types
                                    redundant_composites.push((
                                        rule.id.clone(),
                                        ref_id.clone(),
                                        source_file.to_string(),
                                    ));
                                }
                                // If metadata_changed is true, this is a legitimate composite
                                // that's creating a distinct finding with different properties
                            }
                        }
                    }
                }
            }

            if !redundant_composites.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} single-trait composites add no value",
                    redundant_composites.len()
                );
                eprintln!(
                    "   These composites only reference one trait with identical file types and no unless/downgrade clauses.\n"
                );
                eprintln!("   Consider removing them or adding more conditions:\n");
                for (rule_id, ref_id, source_file) in &redundant_composites {
                    let line_hint = find_line_number(source_file, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Composite '{}' only references '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Composite '{}' only references '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} single-trait composites add no value",
                    redundant_composites.len()
                ));
                has_fatal_errors = true;
            }

            if !unless_only_composites.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} single-trait composites only add 'unless' clauses",
                    unless_only_composites.len()
                );
                eprintln!("   Instead of creating a composite with only an unless clause:");
                eprintln!("   1. Increase the criticality of the base trait");
                eprintln!(
                    "   2. Add a downgrade clause to the base trait for the unless conditions\n"
                );
                for (rule_id, ref_id, source_file) in &unless_only_composites {
                    let line_hint = find_line_number(source_file, rule_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Composite '{}' only adds unless to '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Composite '{}' only adds unless to '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!();
                warnings.push(format!(
                    "{} single-trait composites only add unless clauses",
                    unless_only_composites.len()
                ));
                has_fatal_errors = true;
            }
        } // End of enable_full_validation block for steps 11-15 and post-step validations

        tracing::trace!("Validation complete");

        // Build all indexes in parallel for better performance
        tracing::trace!("Building trait indexes (parallel)");
        let (((trait_index, string_match_index), symbol_match_index), raw_regex_result) =
            rayon::join(
                || {
                    rayon::join(
                        || {
                            rayon::join(
                                || TraitIndex::build(&trait_definitions),
                                || StringMatchIndex::build(&trait_definitions),
                            )
                        },
                        || SymbolMatchIndex::build(&trait_definitions),
                    )
                },
                || {
                    RawContentRegexIndex::build(&trait_definitions)
                        .map_err(|errors| anyhow::anyhow!(errors.join("\n")))
                },
            );
        let raw_content_regex_index = raw_regex_result?;
        tracing::trace!("Indexes built successfully");

        // Parse errors are fatal - print all and exit if any exist
        if !parse_errors.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} YAML parsing error(s) found:\n",
                parse_errors.len()
            );
            for error in &parse_errors {
                eprintln!("   {}", error);
            }
            eprintln!("\n   Fix these issues in the YAML files before continuing.\n");
            has_fatal_errors = true;
        }

        if enable_full_validation && !warnings.is_empty() {
            use crate::validation_controls::ValidationOutputFormat;
            let rendered = match crate::validation_controls::validation_output_format() {
                Some(ValidationOutputFormat::Tiny) => {
                    crate::validation_controls::format_validation_issues_tiny(warnings.as_slice())
                }
                Some(ValidationOutputFormat::Json) => {
                    crate::validation_controls::format_validation_issues_json(warnings.as_slice())
                }
                Some(ValidationOutputFormat::Terminal) | None => {
                    crate::validation_controls::format_validation_issues_terminal(
                        warnings.as_slice(),
                    )
                }
            };
            eprintln!("{rendered}");
            has_fatal_errors = true;
        }

        // Bail if any fatal errors occurred (parse errors, validation failures, etc.)
        if has_fatal_errors {
            eprintln!("\n==> Fix all validation errors before continuing.\n");
            let mut details = Vec::new();
            for e in &parse_errors {
                details.push(format!("parse error: {e}"));
            }
            for issue in warnings.iter() {
                details.push(format!("validation: {}", issue.compact_message()));
            }
            anyhow::bail!(
                "Trait loading failed due to {} validation error(s):\n{}",
                details.len(),
                details.join("\n")
            );
        }

        // Save to cache for future runs (only if not in validation mode)
        if !enable_full_validation
            && !skip_cache
            && let Ok(cache_path) = crate::cache::mapper_cache_path()
        {
            let cache_data = MapperCacheData {
                symbol_map: symbol_map.clone(),
                trait_definitions: trait_definitions.clone(),
                composite_rules: composite_rules.clone(),
            };
            match serde_json::to_vec(&cache_data) {
                Ok(bytes) => {
                    if let Err(e) = fs::write(&cache_path, &bytes) {
                        tracing::warn!("Failed to write mapper cache: {}", e);
                    } else {
                        tracing::info!(
                            "Saved mapper cache ({} bytes): {:?}",
                            bytes.len(),
                            cache_path
                        );
                        // Also save rule stats for fast banner display
                        if let Err(e) = crate::cache::save_rule_stats(
                            trait_definitions.len(),
                            composite_rules.len(),
                        ) {
                            tracing::warn!("Failed to save rule stats: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to serialize mapper cache: {}", e);
                }
            }
        }

        // Populate trait_id_map
        let mut trait_id_map = std::collections::HashMap::with_capacity(trait_definitions.len());
        for (idx, trait_def) in trait_definitions.iter().enumerate() {
            trait_id_map.insert(trait_def.id.clone(), idx);
        }

        // Initialize composite rule dependencies
        for rule in &mut composite_rules {
            rule.populate_required_traits(&trait_id_map);
        }

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
            trait_index,
            string_match_index,
            symbol_match_index,
            raw_content_regex_index,
            trait_id_map,
            platforms: vec![Platform::All],
            slow_rule_ms: Self::DEFAULT_SLOW_RULE_MS,
        })
    }
}
