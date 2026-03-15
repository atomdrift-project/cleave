//! Directory-based YAML file loading for capability mapper.
//!
//! This module handles loading capability definitions from a directory of YAML files,
//! performing comprehensive validation and building optimized indexes for fast evaluation.
//! This is the primary loading method used in production.

use crate::capabilities::error_formatting::enhance_yaml_error;
use crate::capabilities::indexes::{RawContentRegexIndex, StringMatchIndex, TraitIndex};
use crate::capabilities::models::{TraitInfo, TraitMappings};
use crate::capabilities::parsing::{apply_composite_defaults, apply_trait_defaults};
use crate::capabilities::validation::{
    autoprefix_trait_refs, check_basename_pattern_duplicates, check_case_insensitive_overlaps,
    check_exact_contained_by_substr, check_overlapping_regex_patterns,
    check_regex_alternative_subsets, check_regex_contains_literal,
    check_regex_or_overlapping_exact, check_regex_should_be_exact,
    check_same_string_different_types, collect_trait_refs_from_rule,
    find_alternation_merge_candidates, find_atomic_logic_duplicates,
    find_banned_directory_segments, find_cap_obj_violations, find_cap_wellknown_violations,
    find_composite_only_wellknown_files, find_depth_violations,
    find_duplicate_second_level_directories, find_duplicate_traits_and_composites,
    find_empty_condition_clauses, find_excessive_file_types, find_excessive_skip_conditions,
    find_for_only_duplicates, find_generic_wellknown_leaf_dirs, find_hex_binary_missing_section,
    find_hostile_cap_rules, find_hostile_meta_rules, find_impossible_count_constraints,
    find_impossible_needs, find_impossible_size_constraints, find_invalid_not_usage,
    find_invalid_trait_ids, find_kv_exists_with_matcher, find_line_number,
    find_malware_subcategory_violations, find_meta_missing_section_filter,
    find_metadata_cross_tier_refs, find_missing_search_patterns, find_needs_without_any,
    find_needs_zero, find_non_capturing_groups, find_none_only_with_proximity,
    find_orphaned_components, find_overlapping_conditions, find_oversized_trait_directories,
    find_parent_duplicate_segments, find_platform_named_directories, find_pure_alias_traits,
    find_redundant_any_refs, find_redundant_explicit_defaults, find_redundant_needs_one,
    find_raw_should_use_string_value, find_short_pattern_warnings, find_should_use_defaults,
    find_single_item_clauses, find_slow_regex_patterns, find_string_content_collisions,
    find_string_pattern_duplicates, find_string_value_should_use_raw,
    find_too_short_patterns, find_unanchored_wellknown_composites,
    find_wellknown_category_violations, find_wellknown_missing_section_filter,
    find_wellknown_missing_size_filter, find_wellknown_unscoped_filetypes,
    find_wellknown_unscoped_platforms, precalculate_all_composite_precisions,
    simple_rule_to_composite_rule, validate_composite_trait_only, validate_directory_structure,
    validate_hostile_composite_precision, MAX_TRAITS_PER_DIRECTORY,
};
use crate::composite_rules::{
    CompositeTrait, Condition, FileType as RuleFileType, Platform, TraitDefinition,
};
use crate::types::Criticality;
use anyhow::{Context, Result};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

impl super::CapabilityMapper {
    /// Load capability mappings from directory of YAML files (recursively)
    #[allow(dead_code)] // Used in tests
    pub(crate) fn from_directory<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        Self::from_directory_with_precision_thresholds(
            dir_path,
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            true,
        )
    }

    /// Load capability mappings from a directory of YAML files with explicit precision thresholds
    pub(crate) fn from_directory_with_precision_thresholds<P: AsRef<Path>>(
        dir_path: P,
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
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

        // Try to load from cache (skip validation when loading from cache)
        let skip_cache = std::env::var("CLEAVE_SKIP_CACHE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !enable_full_validation && !skip_cache {
            if let Ok(cache_path) = crate::cache::mapper_cache_path() {
                if cache_path.exists() {
                    tracing::debug!("Attempting to load mapper from cache: {:?}", cache_path);
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
                                    tracing::debug!(
                                        "Regex precompilation took {:?} ({} traits, {} composites)",
                                        t1.duration_since(t0),
                                        cache_data.trait_definitions.len(),
                                        cache_data.composite_rules.len()
                                    );

                                    // Rebuild indexes from cached trait definitions (in parallel)
                                    let ((trait_index, string_match_index), raw_regex_result) =
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
                                                RawContentRegexIndex::build(
                                                    &cache_data.trait_definitions,
                                                )
                                            },
                                        );
                                    let t2 = std::time::Instant::now();
                                    tracing::debug!(
                                        "Index building took {:?} (StringMatchIndex: {} patterns, RawContentRegexIndex: {} patterns)",
                                        t2.duration_since(t1),
                                        string_match_index.total_patterns,
                                        raw_regex_result.as_ref().map(|i| i.total_patterns).unwrap_or(0),
                                    );
                                    let raw_content_regex_index =
                                        raw_regex_result.map_err(|errs| {
                                            anyhow::anyhow!("Regex errors: {:?}", errs)
                                        })?;

                                    // Ensure rule stats are up-to-date for banner display
                                    let _ = crate::cache::save_rule_stats(
                                        cache_data.trait_definitions.len(),
                                        cache_data.composite_rules.len(),
                                    );

                                    return Ok(Self {
                                        symbol_map: cache_data.symbol_map,
                                        trait_definitions: cache_data.trait_definitions,
                                        composite_rules: cache_data.composite_rules,
                                        trait_index,
                                        string_match_index,
                                        raw_content_regex_index,
                                        platforms: vec![Platform::All],
                                        slow_rule_ms: Self::DEFAULT_SLOW_RULE_MS,
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to deserialize mapper cache: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to read mapper cache: {}", e);
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
        }

        // First, collect all YAML file paths
        tracing::debug!("Scanning directory for YAML files");
        let mut yaml_files: Vec<_> = walkdir::WalkDir::new(dir_path)
            .follow_links(true)
            .into_iter()
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
        yaml_files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

        if yaml_files.is_empty() {
            anyhow::bail!("No YAML files found in {}", dir_path.display());
        }

        tracing::info!("Found {} YAML files to parse", yaml_files.len());
        let _t_parse = std::time::Instant::now();

        // Load all YAML files in parallel, preserving path for prefix calculation
        // Use indexed_map to preserve sorted order
        tracing::debug!("Parsing YAML files in parallel");
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

        tracing::debug!("Parsing complete");
        let _t_merge = std::time::Instant::now();

        // Merge all results, collecting errors to report all at once
        tracing::debug!("Merging trait definitions and composite rules");
        let mut symbol_map = HashMap::new();
        // Use HashMaps during loading for O(1) duplicate detection (will convert to Vec later)
        let mut trait_definitions_map: HashMap<String, TraitDefinition> = HashMap::new();
        let mut composite_rules_map: HashMap<String, CompositeTrait> = HashMap::new();
        let mut trait_source_files: HashMap<String, String> = HashMap::new(); // trait_id -> file_path
        let mut rule_source_files: HashMap<String, String> = HashMap::new(); // rule_id -> file_path
        let mut files_processed = 0;
        let mut warnings: Vec<String> = Vec::new();
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
            warnings.extend(yaml_warnings);

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

            // Add file path to unknown file type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                if warning.starts_with("Unknown file type") {
                    warnings.push(format!("{}: {}", path_str, warning));
                } else {
                    warnings.push(warning);
                }
            }

            // Per-file: check for values that should use defaults, and values redundant with defaults
            if enable_full_validation {
                let path_str = path.display().to_string();
                for (field, value) in find_should_use_defaults(
                    &mappings.traits,
                    &mappings.composite_rules,
                    &mappings.defaults,
                ) {
                    warnings.push(format!(
                        "{path_str}: all {} items set '{field}' to {value} — move to 'defaults: {field}: {value}'",
                        mappings.traits.len() + mappings.composite_rules.len(),
                    ));
                }
                for (id, field) in find_redundant_explicit_defaults(
                    &mappings.traits,
                    &mappings.composite_rules,
                    &mappings.defaults,
                ) {
                    warnings.push(format!(
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
                );

                // Auto-prefix trait ID if it doesn't already have the path prefix
                // Uses :: as delimiter between directory path and trait name
                if let Some(ref prefix) = trait_prefix {
                    if !trait_def.id.starts_with(prefix)
                        && !trait_def.id.contains("::")
                        && !trait_def.id.contains('/')
                    {
                        trait_def.id = format!("{}::{}", prefix, trait_def.id);
                    }
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
                    if let Some(warning) = trait_def.r#if.check_greedy_patterns() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }
                    // Check for word boundary regex patterns that should use type: word
                    if let Some(warning) = trait_def.r#if.check_word_boundary_regex() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for short case-insensitive patterns (high collision risk)
                    if let Some(warning) = trait_def
                        .r#if
                        .check_short_case_insensitive(trait_def.r#for.len())
                    {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for improper use of not: field
                    if let Some(warning) = trait_def.check_not_field_usage() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid criticality level
                    if let Some(warning) = trait_def.check_criticality() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid confidence value
                    if let Some(warning) = trait_def.check_confidence() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid size constraints
                    if let Some(warning) = trait_def.check_size_constraints() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid entropy constraints
                    if let Some(warning) = trait_def.check_entropy_constraints() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid count constraints
                    if let Some(warning) = trait_def.check_count_constraints() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for invalid density constraints
                    if let Some(warning) = trait_def.check_density_constraints() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for mutually exclusive match types in condition
                    if let Some(warning) = trait_def.r#if.check_match_exclusivity() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for empty patterns
                    if let Some(warning) = trait_def.r#if.check_empty_patterns() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for overly short patterns
                    if let Some(warning) = trait_def.r#if.check_short_patterns() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for symbol regex patterns with whitespace or word boundaries
                    if let Some(warning) = trait_def.r#if.check_symbol_regex_whitespace() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for literal strings used as regex
                    if let Some(warning) = trait_def.r#if.check_literal_regex() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for useless case_insensitive
                    if let Some(warning) = trait_def.r#if.check_case_insensitive_on_non_alpha() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for count_min: 0
                    if let Some(warning) = trait_def.check_count_min_value() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for description quality
                    if let Some(warning) = trait_def.check_description_quality() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for empty not: array
                    if let Some(warning) = trait_def.check_empty_not_array() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }

                    // Check for empty unless: array
                    if let Some(warning) = trait_def.check_empty_unless_array() {
                        warnings.push(format!(
                            "trait '{}' in {:?}: {}",
                            trait_def.id, path, warning
                        ));
                    }
                }

                // Check for ID conflicts with previously loaded traits (cross-file duplicates)
                if trait_definitions_map.contains_key(&trait_def.id) {
                    warnings.push(format!(
                        "Trait ID '{}' defined in multiple files - last definition wins",
                        trait_def.id
                    ));
                    // HashMap insert will automatically replace the old one
                }

                // Check for ID conflicts with composite rules
                if composite_rules_map.contains_key(&trait_def.id) {
                    warnings.push(format!(
                        "Rule ID '{}' defined as both trait and composite rule - trait will be used",
                        trait_def.id
                    ));
                    if let Some(comp_file) = rule_source_files.get(&trait_def.id) {
                        warnings.push(format!("  Trait: {}", path.display()));
                        warnings.push(format!("  Composite (will be replaced): {}", comp_file));
                    }
                    // Remove the composite rule
                    composite_rules_map.remove(&trait_def.id);
                }

                // Extract symbol mappings from trait definitions with symbol conditions
                // (Do this before inserting to avoid borrowing issues)
                if let Condition::Symbol {
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
                }

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

            // Add file path to unknown file type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                if warning.starts_with("Unknown file type") {
                    warnings.push(format!("{}: {}", path_str, warning));
                } else {
                    warnings.push(warning);
                }
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
                if composite_rules_map.contains_key(&rule.id) {
                    warnings.push(format!(
                        "Composite rule '{}' defined in multiple files - last definition wins",
                        rule.id
                    ));
                    // HashMap insert will automatically replace the old one
                }

                // Check for ID conflicts with trait definitions
                if trait_definitions_map.contains_key(&rule.id) {
                    warnings.push(format!(
                        "Rule ID '{}' defined as both trait and composite rule - composite will be used",
                        rule.id
                    ));
                    warnings.push("  Trait (will be replaced): (already loaded)".to_string());
                    warnings.push(format!("  Composite: {}", path.display()));
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

            // Add file path to unknown file type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                if warning.starts_with("Unknown file type") {
                    warnings.push(format!("{}: {}", path_str, warning));
                } else {
                    warnings.push(warning);
                }
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

        // Check for unknown file types across all files
        let file_type_errors: Vec<&String> = warnings
            .iter()
            .filter(|w| w.contains("Unknown file type"))
            .collect();
        if !file_type_errors.is_empty() {
            // Sort and display errors (already include file paths)
            let mut sorted_errors: Vec<&str> =
                file_type_errors.iter().map(|e| e.as_str()).collect();
            sorted_errors.sort();

            return Err(anyhow::anyhow!(
                "Invalid file types found in trait files:\n  {}\n\nPlease fix these file type names in the YAML files.",
                sorted_errors.join("\n  ")
            ));
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

        // Pre-calculate precision for ALL composite rules once
        // Atomic trait precisions are already calculated during parsing
        tracing::debug!("Validating trait definitions and composite rules");
        if enable_full_validation {
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1/15: Pre-calculating composite rule precision");
            precalculate_all_composite_precisions(&mut composite_rules, &trait_definitions);
            tracing::debug!("Step 1 completed in {:?}", step_start.elapsed());

            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1b/15: Validating hostile composite precision");
            validate_hostile_composite_precision(
                &mut composite_rules,
                &trait_definitions,
                &mut warnings,
                min_hostile_precision,
                min_suspicious_precision,
            );
            tracing::debug!("Step 1b completed in {:?}", step_start.elapsed());

            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1c/15: Detecting duplicate traits and composites");
            find_duplicate_traits_and_composites(
                &trait_definitions,
                &composite_rules,
                &mut warnings,
            );
            tracing::debug!("Step 1c completed in {:?}", step_start.elapsed());

            // Detect string pattern duplicates and overlaps
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1d/15: Detecting string pattern duplicates and overlaps");
            find_string_pattern_duplicates(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1d completed in {:?}", step_start.elapsed());

            // Check for regex OR patterns overlapping with exact matches
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1e/15: Checking for regex OR patterns overlapping exact matches");
            check_regex_or_overlapping_exact(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1e completed in {:?}", step_start.elapsed());

            let step_start = std::time::Instant::now();
            tracing::debug!(
                "Step 1e2/15: Checking for overlapping regex patterns with same filetype coverage"
            );
            check_overlapping_regex_patterns(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1e2 completed in {:?}", step_start.elapsed());

            // Check for simple regex that should be exact
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1f/15: Checking for regex patterns that should be exact");
            check_regex_should_be_exact(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1f completed in {:?}", step_start.elapsed());

            // Check for same pattern with different types
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1g/15: Checking for patterns with conflicting types");
            check_same_string_different_types(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1g completed in {:?}", step_start.elapsed());

            // Detect potentially slow regex patterns that could cause catastrophic backtracking
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1h/15: Detecting potentially slow regex patterns");
            find_slow_regex_patterns(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1h completed in {:?}", step_start.elapsed());

            // Detect unnecessary non-capturing groups in regex patterns
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1h2/15: Detecting non-capturing groups in regex patterns");
            find_non_capturing_groups(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1h2 completed in {:?}", step_start.elapsed());

            // Detect raw patterns on binary types that would be faster as string_value
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1h3/15: Detecting raw patterns that should use string_value");
            find_raw_should_use_string_value(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1h3 completed in {:?}", step_start.elapsed());

            // Detect string_value patterns on source types that should use raw
            let step_start = std::time::Instant::now();
            tracing::debug!(
                "Step 1h4/15: Detecting string_value patterns that should use raw"
            );
            find_string_value_should_use_raw(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1h4 completed in {:?}", step_start.elapsed());

            // Check for exact patterns contained by substr patterns (redundancy)
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1i/15: Checking for exact ⊂ substr containment");
            check_exact_contained_by_substr(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1i completed in {:?}", step_start.elapsed());

            // Check for case-insensitive overlaps and subsumption
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1j/15: Checking for case-insensitive overlaps");
            check_case_insensitive_overlaps(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1j completed in {:?}", step_start.elapsed());

            // Check for regex vs literal overlaps (cross-type and containment)
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1k/15: Checking for regex vs literal overlaps");
            check_regex_contains_literal(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1k completed in {:?}", step_start.elapsed());

            // Check for regex alternative subsets and case-insensitive regex overlaps
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1l/15: Checking for regex alternative subsets");
            check_regex_alternative_subsets(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1l completed in {:?}", step_start.elapsed());

            // Check for basename pattern duplicates
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1m/15: Checking for basename pattern duplicates");
            check_basename_pattern_duplicates(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1m completed in {:?}", step_start.elapsed());
        } else {
            tracing::debug!(
                "Step 1/15: Skipping precision validation (run 'cleave validate' to enable)"
            );
        }

        // Validate trait references in composite rules
        // Cross-directory references must match an existing directory prefix
        // Include both trait definition prefixes AND composite rule prefixes (rules can reference rules)
        tracing::debug!("Step 2/15: Building known prefixes");
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
        tracing::debug!(
            "Built prefix hierarchy with {} entries from {} base prefixes",
            prefix_hierarchy.len(),
            known_prefixes.len()
        );

        // Steps 3-7: Taxonomy and naming validation (skip when validation disabled)
        let dir_list: Vec<String> = known_prefixes.iter().cloned().collect();
        if enable_full_validation {
            // Check for unknown subdirectories in taxonomy tiers
            // According to TAXONOMY.md, only specific subdirectories are allowed
            tracing::debug!("Step 2b/15: Validating directory whitelist");
            if let Err(errors) = validate_directory_structure(dir_path) {
                eprintln!(
                    "\n❌ ERROR: {} unknown subdirectories found in taxonomy tiers",
                    errors.len()
                );
                for error in &errors {
                    eprintln!("   {}", error);
                }
                eprintln!();
                has_fatal_errors = true;
            }

            // Check for taxonomy violations: platform/language names as directories
            // According to TAXONOMY.md, languages should be YAML filenames, not directories
            tracing::debug!("Step 3/15: Checking for platform-named directories");
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
            tracing::debug!("Step 3b/15: Checking for duplicate second-level directories");
            let duplicate_dirs = find_duplicate_second_level_directories(&dir_list);
            if !duplicate_dirs.is_empty() {
                eprintln!(
                "\n❌ ERROR: {} second-level directories are duplicated across namespaces (TAXONOMY.md violation)",
                duplicate_dirs.len()
            );
                eprintln!("   Second-level directories should not be repeated across metadata/, micro-behaviors/, objectives/, known/:");
                eprintln!("   This indicates traits are misplaced - objectives should only be in objectives/, capabilities in micro-behaviors/.\n");
                for (dir_name, namespaces) in &duplicate_dirs {
                    eprintln!(
                        "   '{}' appears in: {}/{}/ ",
                        dir_name,
                        namespaces.join("/, "),
                        dir_name
                    );
                }
                eprintln!("\n   Examples:");
                eprintln!("   - micro-behaviors/command-and-control/ and objectives/command-and-control/ → C2 is an objective, should only be in objectives/");
                eprintln!("   - micro-behaviors/discovery/ and objectives/discovery/ → Discovery is an objective, should only be in objectives/");
                eprintln!(
                "   - micro-behaviors/malware/ and known/malware/ → Malware detection should not be in micro-behaviors/\n"
            );
                has_fatal_errors = true;
            }

            // Check for banned meaningless directory segments
            tracing::debug!("Step 4/15: Checking for banned directory segments");
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
            tracing::debug!("Step 5/15: Checking for parent duplicate segments");
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
            tracing::debug!("Step 6/15: Checking for depth violations");
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
                    "\n❌ ERROR: {} files are too shallow (need 3-4 subdirectories in micro-behaviors/obj)",
                    shallow.len()
                );
                    for (path, depth, _) in &shallow {
                        eprintln!("   {} ({} subdirs, need 3-4)", path, depth);
                    }
                }
                if !deep.is_empty() {
                    eprintln!(
                    "\n❌ ERROR: {} files are too deep (max 4 subdirectories in micro-behaviors/obj)",
                    deep.len()
                );
                    for (path, depth, _) in &deep {
                        eprintln!("   {} ({} subdirs, max 4)", path, depth);
                    }
                }
                warnings.push(format!(
                    "{} files at wrong depth (need 3-4 subdirectories in micro-behaviors/obj)",
                    depth_violations.len()
                ));
            }

            // Check for invalid characters in trait/rule IDs
            tracing::debug!("Step 7/15: Checking for invalid trait IDs");
            let invalid_ids =
                find_invalid_trait_ids(&trait_definitions, &composite_rules, &rule_source_files);
            if !invalid_ids.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} trait/rule IDs contain invalid characters",
                    invalid_ids.len()
                );
                if debug {
                    eprintln!("   IDs must only contain alphanumerics, dashes, and underscores:\n");
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
                    eprintln!("\n   Use only [a-zA-Z0-9_-] in trait IDs. No slashes allowed.\n");
                } else {
                    eprintln!("   Set CLEAVE_DEBUG=1 to see details\n");
                }
                warnings.push(format!(
                    "{} trait/rule IDs contain invalid characters",
                    invalid_ids.len()
                ));
            }
        } // End of enable_full_validation block for steps 3-7

        tracing::debug!("Step 8/15: Validating trait references in composite rules");
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
                        || ref_id.starts_with("metadata/internal/")
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
                eprintln!("\n   Cross-directory references must use directory paths (e.g., 'discovery/system')");
                eprintln!("   that match existing trait directories, not exact trait IDs.\n");
            } else {
                eprintln!("   Set CLEAVE_DEBUG=1 to see details\n");
            }
        }

        // Skip regex precompilation - regexes will be compiled on demand during evaluation
        // This saves ~150ms at startup
        tracing::debug!("Step 9/15: Skipping regex precompilation (lazy mode)");

        // Validate exact trait ID references
        // Build set of all valid trait IDs (both atomic traits and composite rules)
        tracing::debug!("Step 10/15: Building valid trait IDs set");
        let mut valid_trait_ids: FxHashSet<String> =
            trait_definitions.iter().map(|t| t.id.clone()).collect();
        for rule in &composite_rules {
            valid_trait_ids.insert(rule.id.clone());
        }

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
            // Validate that composite rules don't reference metadata/internal/ paths
            // Internal paths are for ML usage only and must not be used in composite rules
            tracing::debug!("Step 11/15: Checking for internal path references");
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
                    "\n❌ ERROR: {} composite rules reference internal paths",
                    internal_refs.len()
                );
                eprintln!("   Internal paths (metadata/internal/) are for ML usage only and cannot be used in composite rules:\n");
                for (rule_id, ref_id, source_file) in &internal_refs {
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references internal path: '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references internal path: '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!("\n   Use metadata/import/ or metadata/dylib/ for import-based detection instead.");
                warnings.push(format!(
                    "{} composite rules reference internal paths (metadata/internal/)",
                    internal_refs.len()
                ));
            }

            // Validate that micro-behaviors/ rules do not reference objectives/ rules
            // Cap contains micro-behaviors, obj contains larger behaviors
            // Cap rules should be independent of obj rules
            tracing::debug!("Step 12/15: Checking for micro-behaviors/obj violations");
            let cap_obj_violations =
                find_cap_obj_violations(&trait_definitions, &composite_rules, &rule_source_files);

            if !cap_obj_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} micro-behaviors/ rules reference objectives/ rules",
                    cap_obj_violations.len()
                );
                eprintln!("   Cap rules (micro-behaviors) should not depend on obj rules (larger behaviors):\n");
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
            tracing::debug!("Step 13/15: Checking for hostile cap rules");
            let hostile_cap_rules =
                find_hostile_cap_rules(&trait_definitions, &composite_rules, &rule_source_files);

            if !hostile_cap_rules.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} micro-behaviors/ rules have hostile criticality",
                    hostile_cap_rules.len()
                );
                eprintln!("   Cap contains micro-behaviors (atomic capabilities) which are generally neutral.");
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
                eprintln!("\n   Cap rules max criticality: suspicious (rarely legitimate but still a capability)");
                eprintln!("   Move hostile rules to objectives/command-and-control/, objectives/exfiltration/, objectives/impact/, etc. based on objective.");
                warnings.push(format!(
                    "{} micro-behaviors/ rules have hostile criticality (should be in objectives/)",
                    hostile_cap_rules.len()
                ));
            }

            // Validate that metadata/ rules are never hostile
            // Hostile criticality requires intent inference and belongs in objectives/
            tracing::debug!("Step 13a/15: Checking for hostile metadata rules");
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
                eprintln!("   Move hostile composites to objectives/lateral-movement/supply-chain/ or similar.");
                warnings.push(format!(
                    "{} metadata/ rules have hostile criticality (should be in objectives/)",
                    hostile_meta_rules.len()
                ));
                has_fatal_errors = true;
            }

            // Validate that metadata/ rules do not reference non-metadata tiers
            tracing::debug!("Step 13b/15: Checking for metadata cross-tier references");
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

            // Validate that micro-behaviors/ rules do not reference well-known/ rules
            tracing::debug!("Step 13c/15: Checking for micro-behaviors/well-known violations");
            let cap_wk_violations = find_cap_wellknown_violations(
                &trait_definitions,
                &composite_rules,
                &rule_source_files,
            );

            if !cap_wk_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} micro-behaviors/ rules reference well-known/ rules",
                    cap_wk_violations.len()
                );
                eprintln!("   Cap rules should only reference other cap or metadata rules:\n");
                for (rule_id, ref_id, source_file) in &cap_wk_violations {
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                warnings.push(format!(
                    "{} micro-behaviors/ rules reference well-known/ rules",
                    cap_wk_violations.len()
                ));
            }

            // NOTE: baseline traits are now allowed in objectives/ - they serve as building blocks
            // for composite rules and can be useful even without direct analytical signal.

            // Validate that malware/ is not used as a subcategory of objectives/ or micro-behaviors/
            // Malware-specific signatures belong in known/malware/ per TAXONOMY.md
            tracing::debug!("Step 13b/15: Checking for misplaced malware/ subcategories");
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
                eprintln!("   Malware-specific signatures belong in known/malware/, not objectives/ or micro-behaviors/.");
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
            tracing::debug!("Checking well-known/ category whitelist");
            let wk_category_violations = find_wellknown_category_violations(&dir_list);
            if !wk_category_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} unknown categories under well-known/",
                    wk_category_violations.len()
                );
                eprintln!("   Only whitelisted malware categories are allowed (apt, backdoor, botnet, etc.):\n");
                for (dir_path, category) in &wk_category_violations {
                    eprintln!("   {}: unknown category '{}'", dir_path, category);
                }
                eprintln!("\n   Add the category to WELL_KNOWN_MALWARE_CATEGORIES or WELL_KNOWN_TOOLS_CATEGORIES in taxonomy.rs if legitimate.");
                warnings.push(format!(
                    "{} unknown categories under well-known/",
                    wk_category_violations.len()
                ));
            }

            // Validate well-known/ leaf directory names for generic technique words
            tracing::debug!("Checking well-known/ leaf directory names");
            let generic_leaf_violations = find_generic_wellknown_leaf_dirs(&dir_list);
            if !generic_leaf_violations.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ directories use generic technique names",
                    generic_leaf_violations.len()
                );
                eprintln!("   well-known/ directories should be named after specific malware families/tools:\n");
                for (dir_path, word) in &generic_leaf_violations {
                    eprintln!("   {}: generic technique word '{}'", dir_path, word);
                }
                eprintln!("\n   Rename to a specific family name, or move generic detection to objectives/.");
                warnings.push(format!(
                    "{} well-known/ directories use generic technique names instead of family names",
                    generic_leaf_violations.len()
                ));
            }

            // Validate well-known/ composites have local anchoring (family-specific refs)
            tracing::debug!("Checking well-known/ composite anchoring");
            let unanchored =
                find_unanchored_wellknown_composites(&composite_rules, &rule_source_files);
            if !unanchored.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ composites have no family-specific anchoring",
                    unanchored.len()
                );
                eprintln!("   well-known/ composites should reference at least one local or well-known/ trait:");
                eprintln!("   Composites that only combine micro-behaviors/ or objectives/ refs belong in objectives/.\n");
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
            tracing::debug!("Checking for composite-only well-known/ files");
            let composite_only =
                find_composite_only_wellknown_files(&trait_definitions, &composite_rules);
            if !composite_only.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ directories contain only composites (no atomic traits in directory)",
                    composite_only.len()
                );
                eprintln!("   well-known/ directories should define family-specific fingerprints (atomic traits).");
                eprintln!("   Possible fixes:");
                eprintln!("   - Move composite-only rules to objectives/ if they detect generic behaviors");
                eprintln!("   - Move family-specific traits from micro-behaviors/ into well-known/ if they were misplaced\n");
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

            // Validate well-known/ atomic traits have specific file type filters (not just `all`)
            tracing::debug!("Checking well-known/ for over-broad file type filters");
            let wk_unscoped_ft =
                find_wellknown_unscoped_filetypes(&trait_definitions, &rule_source_files);
            if !wk_unscoped_ft.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ traits use over-broad file type filter (for: all)",
                    wk_unscoped_ft.len()
                );
                eprintln!("   well-known/ traits must target specific file types (e.g., pe, elf, python):\n");
                for (trait_id, source_file) in &wk_unscoped_ft {
                    let line_hint = find_line_number(source_file, "for:");
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: Trait '{}'", source_file, line, trait_id);
                    } else {
                        eprintln!("   {}: Trait '{}'", source_file, trait_id);
                    }
                }
                eprintln!(
                    "\n   Add a specific 'for:' field, e.g., 'for: [pe]' or 'for: [elf, macho]'."
                );
                warnings.push(format!(
                    "{} well-known/ traits use over-broad file type filter (add specific 'for:' field)",
                    wk_unscoped_ft.len()
                ));
            }

            // Validate well-known/ atomic traits have specific platform filters (not just `all`)
            tracing::debug!("Checking well-known/ for over-broad platform filters");
            let wk_unscoped_plat =
                find_wellknown_unscoped_platforms(&trait_definitions, &rule_source_files);
            if !wk_unscoped_plat.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ traits use over-broad platform filter (platforms: all)",
                    wk_unscoped_plat.len()
                );
                eprintln!("   well-known/ traits must target specific platforms (e.g., windows, linux, macos):\n");
                for (trait_id, source_file) in &wk_unscoped_plat {
                    let line_hint = find_line_number(source_file, "platforms:");
                    if let Some(line) = line_hint {
                        eprintln!("   {}:{}: Trait '{}'", source_file, line, trait_id);
                    } else {
                        eprintln!("   {}: Trait '{}'", source_file, trait_id);
                    }
                }
                eprintln!("\n   Add a specific 'platforms:' field, e.g., 'platforms: [windows]' or 'platforms: [linux, macos]'.");
                warnings.push(format!(
                    "{} well-known/ traits use over-broad platform filter (add specific 'platforms:' field)",
                    wk_unscoped_plat.len()
                ));
            }

            // Validate well-known/ atomic traits have file size bounds
            tracing::debug!("Checking well-known/ for missing size filters");
            let wk_no_size =
                find_wellknown_missing_size_filter(&trait_definitions, &rule_source_files);
            if !wk_no_size.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ traits have no file size filter",
                    wk_no_size.len()
                );
                eprintln!("   well-known/ traits should include size_min/size_max to avoid false positives:\n");
                for (trait_id, source_file) in &wk_no_size {
                    eprintln!("   {}: Trait '{}'", source_file, trait_id);
                }
                eprintln!("\n   Add 'size_min:' and/or 'size_max:' bounds appropriate to the malware family.");
                warnings.push(format!(
                    "{} well-known/ traits lack file size filters (add size_min/size_max)",
                    wk_no_size.len()
                ));
            }

            // Validate well-known/ binary-targeting traits have a section filter
            tracing::debug!("Checking well-known/ binary traits for missing section filters");
            let wk_no_section =
                find_wellknown_missing_section_filter(&trait_definitions, &rule_source_files);
            if !wk_no_section.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} well-known/ binary traits lack a section filter",
                    wk_no_section.len()
                );
                eprintln!("   Binary-targeting traits in well-known/ should scope string/raw/hex matches to a section:");
                eprintln!("   Use 'section: .text' or 'section: .data' on the condition, or use 'type: section'.\n");
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
            tracing::debug!("Checking metadata/ binary traits for missing section filters");
            let meta_no_section =
                find_meta_missing_section_filter(&trait_definitions, &rule_source_files);
            if !meta_no_section.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} metadata/ binary traits lack a section filter",
                    meta_no_section.len()
                );
                eprintln!("   Binary-targeting traits in metadata/ should scope string/raw/hex matches to a section:");
                eprintln!("   Use 'section: .text' or 'section: .data' on the condition, or use 'type: section'.\n");
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
            tracing::debug!("Checking hex conditions targeting binaries for missing section");
            let hex_no_section = find_hex_binary_missing_section(&trait_definitions);
            if !hex_no_section.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} hex condition(s) target binary file types without a section filter",
                    hex_no_section.len()
                );
                eprintln!(
                    "   Hex patterns on binary targets must scope the search with 'section:'"
                );
                eprintln!("   (use 'section: text', 'section: data', etc., or add 'offset:' to pin location)\n");
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
            tracing::debug!("Step 14/15: Checking for redundant any refs");
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
                eprintln!("   Rules with 4+ trait references from the same directory should use directory notation:\n");
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
                    eprintln!("      Recommendation: Use 'id: {}', or create a new subdirectory within it to hold common traits instead.\n", dir);
                }
                warnings.push(format!(
                    "{} composite rules have redundant any: clauses (use directory notation)",
                    redundant_any_refs.len()
                ));
            }

            // Validate that `any:` and `all:` clauses don't have exactly 1 item
            // Single-item clauses are pointless wrappers that add complexity
            tracing::debug!("Step 15/15: Checking for single-item clauses");
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
                eprintln!("   A directory reference already includes all traits within it;\n   remove the specific trait reference:\n");
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
                    "\n❌ ERROR: {} trait pairs have string/raw type collisions",
                    collisions.len()
                );
                eprintln!(
                    "   When both `type: string` and `type: raw` exist for the same pattern,"
                );
                eprintln!("   merge to `raw` only (it's broader and includes string matches):\n");
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
                eprintln!("   These traits have identical logic (same criticality, condition, etc.) but different file types.");
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
                eprintln!("   These traits have identical criticality and regex patterns where the first token differs only in case.");
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
                eprintln!("   `needs` only applies to `any:` conditions and is ignored on `all:`-only rules:\n");
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
                eprintln!("   - offset or offset_range (absolute file position)");
                eprintln!(
                    "   - section + section_offset/section_offset_range (pinpoint within section)"
                );
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
                eprintln!("   A `none:`-only rule with proximity can never match:\n");
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

            // Validate: excessive unless:/downgrade: clauses (8+ combined)
            let excessive_skips =
                find_excessive_skip_conditions(&trait_definitions, &composite_rules);
            if !excessive_skips.is_empty() {
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
                warnings.push(format!(
                    "{} rules have excessive unless:/downgrade: clauses",
                    excessive_skips.len()
                ));
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
                eprintln!("   Either add constraints/modifiers or reference the original trait directly:\n");
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
            let orphaned_components =
                find_orphaned_components(&trait_definitions, &composite_rules, &rule_source_files);
            if !orphaned_components.is_empty() {
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
            if !oversized_dirs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} directories have more than {} traits",
                    oversized_dirs.len(),
                    MAX_TRAITS_PER_DIRECTORY
                );
                eprintln!("   Consider splitting these into subdirectories:\n");
                for (dir_path, count) in &oversized_dirs {
                    eprintln!("   {}: {} traits", dir_path, count);
                }
                eprintln!();
                warnings.push(format!(
                    "{} directories exceed {} traits (consider splitting)",
                    oversized_dirs.len(),
                    MAX_TRAITS_PER_DIRECTORY
                ));
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
                    // - metadata/internal/ is validated separately (forbidden in composite rules)
                    let is_dynamic_or_internal = ref_id.starts_with("metadata/import/")
                        || ref_id.starts_with("metadata/dylib/")
                        || ref_id.starts_with("metadata/signed/")
                        || ref_id.starts_with("metadata/internal/");

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
                        broken_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                    }
                }
            }

            if !broken_refs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} broken trait references found in composite rules",
                    broken_refs.len()
                );
                eprintln!("   Composite rules reference trait IDs that don't exist:\n");
                for (rule_id, ref_id, source_file) in &broken_refs {
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references non-existent trait: '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references non-existent trait: '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!();
                has_fatal_errors = true;
            }

            // Validate metric field references
            let valid_metric_fields = super::helpers::get_valid_metric_fields();
            let mut invalid_metric_refs = Vec::new();

            for trait_def in &trait_definitions {
                let metric_fields = super::helpers::collect_metric_refs_from_trait(trait_def);
                for field in metric_fields {
                    if !valid_metric_fields.contains(&field) {
                        let source_file = trait_source_files
                            .get(&trait_def.id)
                            .map(std::string::String::as_str)
                            .unwrap_or("unknown");
                        invalid_metric_refs.push((
                            trait_def.id.clone(),
                            field,
                            source_file.to_string(),
                        ));
                    }
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
                if let Some(ref none) = rule.none {
                    total_conditions += none.len();
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
                has_fatal_errors = true;
            }
        } // End of enable_full_validation block for steps 11-15 and post-step validations

        tracing::debug!("Validation complete");

        // Build all indexes in parallel for better performance
        tracing::debug!("Building trait indexes (parallel)");
        let ((trait_index, string_match_index), raw_regex_result) = rayon::join(
            || {
                rayon::join(
                    || TraitIndex::build(&trait_definitions),
                    || StringMatchIndex::build(&trait_definitions),
                )
            },
            || RawContentRegexIndex::build(&trait_definitions),
        );
        let raw_content_regex_index = match raw_regex_result {
            Ok(index) => index,
            Err(errors) => {
                return Err(anyhow::anyhow!(errors.join("\n")));
            }
        };
        tracing::debug!("Indexes built successfully");

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
            eprintln!(
                "\n⚠️  ERROR: {} trait configuration validation issue(s) found:\n",
                warnings.len()
            );
            for warning in &warnings {
                eprintln!("   ⚠️  {}", warning);
            }
            eprintln!("\n   Fix these issues in the YAML files before continuing.\n");
            has_fatal_errors = true;
        }

        // Bail if any fatal errors occurred (parse errors, validation failures, etc.)
        if has_fatal_errors {
            eprintln!("\n==> Fix all validation errors before continuing.\n");
            anyhow::bail!("Trait loading failed due to validation errors");
        }

        // Save to cache for future runs (only if not in validation mode)
        if !enable_full_validation && !skip_cache {
            if let Ok(cache_path) = crate::cache::mapper_cache_path() {
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
        }

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
            trait_index,
            string_match_index,
            raw_content_regex_index,
            platforms: vec![Platform::All],
            slow_rule_ms: Self::DEFAULT_SLOW_RULE_MS,
        })
    }
}
