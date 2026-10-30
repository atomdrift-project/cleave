//! Directory-based YAML file loading for capability mapper.
//!
//! This module handles loading capability definitions from a directory of YAML files,
//! performing comprehensive validation and building optimized indexes for fast evaluation.
//! This is the primary loading method used in production.
//!
//! The trait-rule linter that full validation runs lives in `load_validators`.

use crate::capabilities::error_formatting::enhance_yaml_error;
use crate::capabilities::models::TraitMappings;
use crate::capabilities::parsing::{
    apply_composite_defaults, apply_trait_defaults, autoprefix_trait_refs,
};
use crate::capabilities::precision::{
    precalculate_all_composite_precisions, validate_hostile_composite_precision,
    validate_hostile_trait_precision,
};
#[cfg(feature = "lint")]
use crate::capabilities::validation::{find_redundant_explicit_defaults, find_should_use_defaults};
use crate::composite_rules::{CompositeTrait, Condition, Platform, TraitDefinition};
use crate::validation_controls::ValidationIssues;
use anyhow::{Context, Result};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Cache data for the capability mapper: only the data that round-trips
/// through serde. Indexes (TraitIndex, StringMatchIndex, RawContentRegexIndex)
/// are rebuilt after load.
///
/// Stored as JSON lines: a [`MapperCacheHeader`], then one line per trait and
/// one per composite rule. As a single document, deserializing its ~118k rules
/// took ~0.4 s on one thread in every process before its first analysis; one
/// document per rule lets [`Self::parse`] spread that across the pool. Compact
/// JSON escapes every newline inside a string, so each line is exactly one
/// value, and the header's counts make a file cut short at a line boundary
/// fail to load rather than load short.
struct MapperCacheData {
    trait_definitions: Vec<TraitDefinition>,
    composite_rules: Vec<CompositeTrait>,
    /// Files the load that produced this cache could not parse, already
    /// rendered for display.
    ///
    /// Carried through the cache because the rules in those files are missing
    /// from `trait_definitions` — and stay missing on every cache hit. Without
    /// this the warning is printed exactly once, on the run that happens to
    /// rebuild the cache, and detection is quietly degraded from then on with
    /// nothing on stderr to say so.
    parse_errors: Vec<String>,
}

/// The first line of a mapper cache file.
#[derive(Serialize, Deserialize)]
struct MapperCacheHeader {
    traits: usize,
    composites: usize,
    parse_errors: Vec<String>,
}

impl MapperCacheData {
    fn to_json_lines(
        traits: &[TraitDefinition],
        composites: &[CompositeTrait],
        parse_errors: &[String],
    ) -> serde_json::Result<Vec<u8>> {
        let header = MapperCacheHeader {
            traits: traits.len(),
            composites: composites.len(),
            parse_errors: parse_errors.to_vec(),
        };
        // Each line is `[defined_in, rule]`: `defined_in` is `#[serde(skip)]`
        // on the rule types (it is load provenance, not YAML), yet evaluation
        // reads it (the tiny DOS `.com` allowlists), so a hit must restore it.
        let rules: Vec<Vec<u8>> = traits
            .par_iter()
            .map(|t| serde_json::to_vec(&(&t.defined_in, t)))
            .chain(
                composites
                    .par_iter()
                    .map(|c| serde_json::to_vec(&(&c.defined_in, c))),
            )
            .collect::<serde_json::Result<_>>()?;
        let mut out = serde_json::to_vec(&header)?;
        for rule in rules {
            out.push(b'\n');
            out.extend_from_slice(&rule);
        }
        Ok(out)
    }

    fn parse(bytes: &mut [u8]) -> Result<Self> {
        fn parse_lines<T: serde::de::DeserializeOwned + Send>(
            lines: &mut [&mut [u8]],
            set_defined_in: fn(&mut T, std::path::PathBuf),
        ) -> simd_json::Result<Vec<T>> {
            lines
                .par_iter_mut()
                .map_init(simd_json::Buffers::default, |buffers, line| {
                    let (defined_in, mut rule): (std::path::PathBuf, T) =
                        simd_json::serde::from_slice_with_buffers(line, buffers)?;
                    set_defined_in(&mut rule, defined_in);
                    Ok(rule)
                })
                .collect()
        }

        // Split with memchr: a byte-at-a-time `split_mut` over the ~70 MB
        // file was the slowest serial step left.
        let mut lines: Vec<&mut [u8]> = Vec::new();
        let mut rest = bytes;
        while let Some(at) = memchr::memchr(b'\n', rest) {
            let (line, tail) = std::mem::take(&mut rest).split_at_mut(at);
            lines.push(line);
            rest = &mut tail[1..];
        }
        lines.push(rest);
        let (header, rules) = lines.split_first_mut().context("empty mapper cache")?;
        let header: MapperCacheHeader = simd_json::serde::from_slice(header)?;
        anyhow::ensure!(
            rules.len() == header.traits + header.composites,
            "mapper cache holds {} rules; its header says {} traits and {} composites",
            rules.len(),
            header.traits,
            header.composites
        );
        let (traits, composites) = rules.split_at_mut(header.traits);
        Ok(Self {
            trait_definitions: parse_lines(traits, |t: &mut TraitDefinition, p| {
                t.defined_in = p;
                // Runtime YARA bindings are deliberately absent from the cache
                // representation. Restore the same bindings as a YAML load.
                if matches!(t.r#if, Condition::Yara { .. }) {
                    t.set_yara_if_namespace();
                }
            })?,
            composite_rules: parse_lines(composites, |c: &mut CompositeTrait, p| {
                c.defined_in = p;
                c.compile_yara();
            })?,
            parse_errors: header.parse_errors,
        })
    }
}

/// Print the analysis-time warning for trait files this build could not parse.
///
/// Unparseable files are fatal under `cleave validate` but only a warning here
/// (forward compatibility — a rule pack using newer condition fields must not
/// brick an older build): the remaining rules still load and run, and the
/// skipped ones simply don't fire until the tool is upgraded.
fn warn_unparseable_traits(parse_errors: &[String]) {
    if parse_errors.is_empty() {
        return;
    }
    let prog = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "cleave".to_string());
    tracing::warn!(
        skipped_files = parse_errors.len(),
        "skipped trait file(s) this build of {prog} could not parse"
    );
    eprintln!(
        "\n\u{26a0}\u{fe0f}  WARNING: skipped {} trait file(s) this build of {prog} could not parse; \
         their rules will not run.\n   If they use newer rule features, upgrade {prog} \
         to the latest version.\n",
        parse_errors.len()
    );
    for error in parse_errors {
        eprintln!("   {error}");
    }
    eprintln!();
}

fn push_parsing_warning(
    warnings: &mut crate::validation_controls::ValidationIssues,
    path_str: &str,
    warning: String,
) {
    if warning.starts_with("Unknown file type") {
        warnings.push_id("unknown-file-type", format!("{path_str}: {warning}"));
    } else if warning.starts_with(crate::capabilities::parsing::EMPTY_RESOLVED_FOR) {
        warnings.push_id("empty-file-type", format!("{path_str}: {warning}"));
    } else if warning.contains("for: [all] is not allowed") {
        warnings.push_id("for-all", format!("{path_str}: {warning}"));
    } else if warning.starts_with("Invalid file type") {
        warnings.push_id("invalid-file-type", format!("{path_str}: {warning}"));
    } else if warning.contains("regex pattern exceeds") {
        let message = if warning.contains(" (in ") {
            warning
        } else {
            format!("{warning} (in {path_str})")
        };
        warnings.push_id("regex-length", message);
    } else if warning.contains("count_min with regex alternation") {
        let message = if warning.contains(" (in ") {
            warning
        } else {
            format!("{warning} (in {path_str})")
        };
        warnings.push_id("count-min-regex-alternation", message);
    } else if warning.contains("too many '|' symbols")
        || warning.contains("simple alphanumeric alternation chain")
    {
        let message = if warning.contains(" (in ") {
            warning
        } else {
            format!("{warning} (in {path_str})")
        };
        warnings.push_id("simple-alternation-chain", message);
    } else {
        warnings.push_legacy(warning);
    }
}

/// The merged trait set: every trait and composite, sorted by id, and the
/// file each was defined in.
pub(super) struct MergedRules {
    pub(super) trait_definitions: Vec<TraitDefinition>,
    pub(super) composite_rules: Vec<CompositeTrait>,
    /// Trait id to the file that defines it.
    pub(super) trait_source_files: HashMap<String, String>,
    /// Rule id to the file that defines it, for traits and composites alike.
    pub(super) rule_source_files: HashMap<String, String>,
}

/// One parsed trait file, with its position in load order and the warnings
/// found in its text before parsing.
type ParsedFile = (usize, PathBuf, TraitMappings, Vec<String>);

/// Decide whether this load runs full validation, and the clean mark that
/// records a tree this build already validated clean.
fn resolve_full_validation(
    dir_path: &Path,
    enable_full_validation: bool,
    precision: Option<(f32, f32)>,
) -> (bool, Option<crate::traits_fingerprint::CleanMark>) {
    // A tree this build already validated clean skips the checks. The mark
    // is keyed on the tree's content, so an edited tree validates in full;
    // see `traits_fingerprint::CleanMark`.
    let clean_mark = enable_full_validation
        .then(|| crate::traits_fingerprint::CleanMark::for_traits(dir_path, precision))
        .flatten();
    let validated_clean = clean_mark
        .as_ref()
        .is_some_and(crate::traits_fingerprint::CleanMark::is_set);
    let enable_full_validation = enable_full_validation && !validated_clean;
    // Full validation is the linter; a build without it loads in fast mode.
    #[cfg(not(feature = "lint"))]
    let enable_full_validation = {
        if enable_full_validation {
            tracing::warn!(
                "full trait validation requested, but cleave was built without the `lint` feature; loading in fast mode"
            );
        }
        false
    };
    (enable_full_validation, clean_mark)
}

/// Every trait YAML file under `dir_path`, sorted by path.
fn find_trait_files(
    sources: &crate::rule_sources::RuleSources,
    dir_path: &Path,
) -> Result<Vec<PathBuf>> {
    // First, collect all YAML file paths
    tracing::trace!("Scanning directory for YAML files");
    let mut yaml_files: Vec<_> = sources
        .files()
        .iter()
        .filter(|file| file.relative_path.extension().is_some_and(|e| e == "yaml"))
        .map(|file| dir_path.join(&file.relative_path))
        .filter(|path| {
            if path.components().any(|c| c.as_os_str() == "third-party") {
                return false;
            }
            let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
            !filename.to_lowercase().contains("readme") && !filename.starts_with("EXAMPLE")
        })
        .collect();

    // Sort files deterministically by path string to ensure consistent loading order across OSes
    // Using string comparison instead of PathBuf comparison for true cross-platform consistency
    yaml_files.sort_unstable_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

    if yaml_files.is_empty() {
        anyhow::bail!("No YAML files found in {}", dir_path.display());
    }

    tracing::info!("Found {} YAML files to parse", yaml_files.len());
    Ok(yaml_files)
}

/// Parse every trait file in parallel. The results keep load order, with
/// files that failed to parse after all the rest.
fn parse_trait_files(
    sources: &crate::rule_sources::RuleSources,
    yaml_files: &[PathBuf],
    dir_path: &Path,
) -> Vec<Result<ParsedFile>> {
    // Load all YAML files in parallel, preserving path for prefix calculation
    // Use indexed_map to preserve sorted order
    tracing::trace!("Parsing YAML files in parallel");
    let results: Vec<_> = yaml_files
        .par_iter()
        .enumerate()
        .map(|(idx, path)| {
            let bytes = &sources
                .file(path.strip_prefix(dir_path)?)
                .with_context(|| format!("Missing snapshotted trait {}", path.display()))?
                .bytes;
            let content = String::from_utf8_lossy(bytes);

            // Check for meaningless YAML patterns before parsing
            let yaml_warnings = super::helpers::check_yaml_patterns(&content, path);

            let mappings: TraitMappings = crate::yaml::from_str(&content).map_err(|e| {
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
    sorted_results
}

/// Merge the parsed files in load order into one trait set, collecting every
/// warning the files raise along the way.
///
/// Returns the merged rules, the warnings, and the files that failed to
/// parse, already rendered for display.
fn merge_trait_files(
    parsed: Vec<Result<ParsedFile>>,
    dir_path: &Path,
    enable_full_validation: bool,
    enable_precision_scoring: bool,
) -> Result<(MergedRules, ValidationIssues, Vec<String>)> {
    // Merge all results, collecting errors to report all at once
    tracing::trace!("Merging trait definitions and composite rules");

    // Everything a file contributes that does not depend on the files
    // before it -- defaults, id prefixes, condition checks, per-trait
    // warnings, regex precompilation -- is prepared for all files at
    // once. The ordered pass below then does only what does: id conflicts
    // and the maps, replaying each file's warnings and first error at the
    // point the serial merge produced them.
    let prepared: Vec<Result<PreparedFile>> = parsed
        .into_par_iter()
        .map(|result| {
            result.map(|(_idx, path, mappings, yaml_warnings)| {
                prepare_trait_file(
                    &path,
                    mappings,
                    yaml_warnings,
                    dir_path,
                    enable_full_validation,
                    enable_precision_scoring,
                )
            })
        })
        .collect();

    // Use HashMaps during loading for O(1) duplicate detection (will
    // convert to Vec later), sized up front so they never grow. The
    // definition maps are sorted out by id below, so their hasher is
    // free to be the fast one.
    let (n_traits, n_rules) = prepared.iter().flatten().fold((0, 0), |(t, r), file| {
        (t + file.traits.len(), r + file.rules.len())
    });
    let mut trait_definitions_map: FxHashMap<String, TraitDefinition> =
        FxHashMap::with_capacity_and_hasher(n_traits, Default::default());
    let mut composite_rules_map: FxHashMap<String, CompositeTrait> =
        FxHashMap::with_capacity_and_hasher(n_rules, Default::default());
    let mut trait_source_files: HashMap<String, String> = HashMap::with_capacity(n_traits); // trait_id -> file_path
    let mut rule_source_files: HashMap<String, String> = HashMap::with_capacity(n_traits + n_rules); // rule_id -> file_path
    let mut warnings = crate::validation_controls::ValidationIssues::new();
    let mut parse_errors: Vec<String> = Vec::new();

    for result in prepared {
        let file = match result {
            Ok(file) => file,
            Err(e) => {
                // Format error with full chain (includes filename from context)
                parse_errors.push(format!("{:#}", e));
                continue;
            }
        };
        let path = file.path;
        let path_str = path.display().to_string();
        // Collect YAML pattern warnings
        warnings.extend_legacy(file.yaml_warnings);
        for message in file.hoist {
            warnings.push_id("defaults-hoist", message);
        }

        for prepared_trait in file.traits {
            let PreparedTrait {
                def: trait_def,
                issues,
                precompiled,
            } = prepared_trait;
            issues.replay(&mut warnings);

            // Check for ID conflicts with previously loaded traits (cross-file duplicates)
            // Duplicate trait id — two atomic traits resolving to the same
            // `directory::id`. The runtime stores traits in a HashMap keyed
            // by id, so the second silently overwrites the first and every
            // reference resolves to whichever loaded last. This is never
            // acceptable: report it as an ungated hard error (cannot be
            // silenced via a validator override) so the tree is forced to
            // keep every id unique.
            if trait_definitions_map.contains_key(&trait_def.id) {
                let prior = trait_source_files
                    .get(&trait_def.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("(already loaded)");
                warnings.push_id(
                        "duplicate-trait-id",
                        format!(
                            "Duplicate trait id '{}' — defined in both {} and {}; each directory::id must be unique",
                            trait_def.id,
                            prior,
                            path.display()
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
                    warnings.push_legacy(format!("  Composite (will be replaced): {}", comp_file));
                }
                // Remove the composite rule
                composite_rules_map.remove(&trait_def.id);
            }

            // Pre-compile regexes for this trait
            if let Err(e) = precompiled {
                return Err(anyhow::anyhow!(
                    "Failed to compile regex for trait '{}' in {:?}: {:#}",
                    trait_def.id,
                    path,
                    e
                ));
            }

            // Track source file for error reporting
            trait_source_files.insert(trait_def.id.clone(), path_str.clone());
            rule_source_files.insert(trait_def.id.clone(), path_str.clone());
            trait_definitions_map.insert(trait_def.id.clone(), trait_def);
        }

        if let Some(error) = file.trait_failure {
            return Err(error);
        }

        // Add file path to file-type warnings, append others as-is
        for warning in file.trait_parsing_warnings {
            push_parsing_warning(&mut warnings, &path_str, warning);
        }

        for prepared_rule in file.rules {
            let PreparedRule { rule, precompiled } = prepared_rule;

            // Duplicate composite id — two composites resolving to the same
            // `directory::id`. Same hazard as duplicate atomic ids: the
            // second silently overwrites the first. Ungated hard error.
            if composite_rules_map.contains_key(&rule.id) {
                let prior = rule_source_files
                    .get(&rule.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("(already loaded)");
                warnings.push_id(
                        "duplicate-trait-id",
                        format!(
                            "Duplicate composite id '{}' — defined in both {} and {}; each directory::id must be unique",
                            rule.id,
                            prior,
                            path.display()
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
                warnings.push_legacy("  Trait (will be replaced): (already loaded)".to_string());
                warnings.push_legacy(format!("  Composite: {}", path.display()));
                // Remove the trait definition
                trait_definitions_map.remove(&rule.id);
            }

            // Pre-compile regexes for this composite rule
            if let Err(e) = precompiled {
                return Err(anyhow::anyhow!(
                    "Failed to compile regex for composite '{}' in {:?}: {}",
                    rule.id,
                    path,
                    e
                ));
            }

            // Track source file for error reporting
            rule_source_files.insert(rule.id.clone(), path_str.clone());
            composite_rules_map.insert(rule.id.clone(), rule);
        }

        // Add file path to file-type warnings, append others as-is
        for warning in file.rule_parsing_warnings {
            push_parsing_warning(&mut warnings, &path_str, warning);
        }
    }

    // Convert HashMaps to Vecs now that loading is complete
    // This was kept as HashMap during loading for O(1) duplicate detection
    let mut trait_definitions: Vec<TraitDefinition> = trait_definitions_map.into_values().collect();
    let mut composite_rules: Vec<CompositeTrait> = composite_rules_map.into_values().collect();
    // Canonical order. `HashMap` iteration is seeded per process, so without
    // this every mapper build handed out a different trait/composite order,
    // the on-disk mapper cache then froze that order, and evaluation on
    // large members is order-sensitive (composite crediting / `unless`
    // interplay): the same archive produced different findings after a
    // cache rebuild, and two identical copies of one rule bundle
    // disagreed. Sorting by id makes the order a pure function of the
    // rule set — reproducible across rebuilds, machines and bundle copies.
    trait_definitions.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    composite_rules.sort_unstable_by(|a, b| a.id.cmp(&b.id));
    Ok((
        MergedRules {
            trait_definitions,
            composite_rules,
            trait_source_files,
            rule_source_files,
        },
        warnings,
        parse_errors,
    ))
}

/// Fail the load on file types no rule may name: an empty `for:` always, and
/// one this build does not recognise when validating.
fn check_file_types(warnings: &ValidationIssues, enable_full_validation: bool) -> Result<()> {
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
        // `unknown-file-type` is a Soft problem: a trait targeting a type this
        // (older) engine doesn't recognise is forward-compat degradation. It is
        // fatal for `validate` but not for `validate --soft`, where the rule is
        // skipped rather than failing the whole bundle load — decided on the same
        // severity axis as everything else.
        let fatal = crate::validation_controls::validator_severity("unknown-file-type")
            >= crate::validation_controls::fatal_severity_threshold();
        if enable_full_validation
            && fatal
            && !crate::validation_controls::is_validator_disabled("unknown-file-type")
        {
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
    Ok(())
}

/// Register the YARA conditions of the merged rules with their engines.
fn register_yara(rules: &mut MergedRules) {
    // Register the combined-engine namespace for atomic traits whose top-level `if`
    // condition is `type: yara`.  These rules are compiled into the shared YaraEngine
    // (see `yara_engine::load_inline_trait_rules`), so we only need to record the
    // namespace here — actual compilation and scanning happen in the engine.
    rules.trait_definitions.par_iter_mut().for_each(|t| {
        if matches!(t.r#if, Condition::Yara { .. }) {
            // Set namespace for the combined engine; also compiles any `unless` YARA conditions.
            t.set_yara_if_namespace();
        }
    });

    // Composite rules still use per-condition compilation (they are rare and have
    // complex condition trees that are not currently in the combined engine).
    rules.composite_rules.par_iter_mut().for_each(|r| {
        r.compile_yara();
    });
}

/// Score every rule's precision and report hostile or suspicious rules below
/// their thresholds. Outside full validation the issues are printed and
/// dropped rather than failing the load.
fn score_precision(
    rules: &mut MergedRules,
    warnings: &mut ValidationIssues,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
    enable_full_validation: bool,
) {
    let MergedRules {
        trait_definitions,
        composite_rules,
        ..
    } = rules;
    let precision_warning_start = warnings.len();

    warnings.collect_as("precision", |warnings| {
        validate_hostile_trait_precision(
            trait_definitions,
            warnings,
            min_hostile_precision,
            min_suspicious_precision,
        );
    });
    precalculate_all_composite_precisions(composite_rules, trait_definitions);
    warnings.collect_as("precision", |warnings| {
        validate_hostile_composite_precision(
            composite_rules,
            trait_definitions,
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

/// Print what the load found and fail it on any problem at or above the
/// fatal severity, or on any file that failed to parse.
fn report_validation(
    warnings: &mut ValidationIssues,
    parse_errors: &[String],
    enable_full_validation: bool,
) -> Result<()> {
    // Unparseable files are fatal during validation but only a warning at
    // analysis time (forward compatibility — see the else branch).
    if !parse_errors.is_empty() {
        if enable_full_validation {
            // Authoring/validation: an unparseable file is a hard error so
            // typos and malformed rules never ship.
            eprintln!(
                "\n❌ ERROR: {} YAML parsing error(s) found:\n",
                parse_errors.len()
            );
            for error in parse_errors {
                eprintln!("   {}", error);
            }
            eprintln!("\n   Fix these issues in the YAML files before continuing.\n");
        } else {
            warn_unparseable_traits(parse_errors);
        }
    }

    // `--exclude` is the only switch that silences a validator; drop those
    // issues before deciding anything. No validator is disabled by default.
    warnings.retain(|w| !crate::validation_controls::is_validator_disabled(w.validator_id));

    // One axis decides pass/fail: severity. `validate` rejects any problem;
    // `validate --soft` rejects only Hard ones — those mean a rule won't load
    // or won't fire (detection lost or wrong). Soft problems are still
    // reported, just not fatal under --soft. Unparseable YAML is always Hard
    // (printed above); invalid/unknown file types and uncompilable regex are
    // handled earlier and bail before reaching here.
    let threshold = crate::validation_controls::fatal_severity_threshold();
    let fatal_warnings = warnings.iter().filter(|w| w.severity >= threshold).count();

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
                crate::validation_controls::format_validation_issues_terminal(warnings.as_slice())
            }
        };
        eprintln!("{rendered}");
    }

    // Bail only on problems that meet the threshold. Parse errors are Hard, so
    // they fail in both `validate` and `validate --soft`.
    if enable_full_validation && (fatal_warnings > 0 || !parse_errors.is_empty()) {
        eprintln!("\n==> Fix all validation errors before continuing.\n");
        let mut details = Vec::new();
        for e in parse_errors {
            details.push(format!("parse error: {e}"));
        }
        for issue in warnings.iter().filter(|w| w.severity >= threshold) {
            details.push(format!("validation: {}", issue.compact_message()));
        }
        anyhow::bail!(
            "Trait loading failed due to {} validation error(s):\n{}",
            details.len(),
            details.join("\n")
        );
    }
    Ok(())
}

/// Save the loaded rules for the next process that loads this tree.
fn save_mapper_cache(
    cache_path: &Path,
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    parse_errors: &[String],
) {
    match MapperCacheData::to_json_lines(trait_definitions, composite_rules, parse_errors) {
        Ok(bytes) => {
            // Atomic write: a reader on another thread or process (a
            // concurrently running `cleave`, or nextest's isolated
            // processes sharing a non-isolated cache dir) can
            // `fs::read` this exact path at any time. A direct write
            // truncates in place, so a reader racing it can see a
            // truncated or empty file — `simd_json` then either
            // fails to parse (a spurious rebuild) or, worse, silently
            // accepts a partial document. See `cache::atomic_write`.
            if let Err(e) = crate::cache::atomic_write(cache_path, &bytes) {
                tracing::warn!("Failed to write mapper cache: {}", e);
            } else {
                tracing::info!(
                    "Saved mapper cache ({} bytes): {:?}",
                    bytes.len(),
                    cache_path
                );
                // Also save rule stats for fast banner display
                if let Err(e) =
                    crate::cache::save_rule_stats(trait_definitions.len(), composite_rules.len())
                {
                    tracing::warn!("Failed to save rule stats: {}", e);
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to serialize mapper cache: {}", e);
        }
    }
}

/// Warnings recorded while a file is prepared, replayed in order by the merge.
/// Mirrors the two `ValidationIssues` pushes the per-trait checks make, so the
/// checks read the same wherever they run.
#[derive(Default)]
struct PendingIssues(Vec<(Option<&'static str>, String)>);

impl PendingIssues {
    fn push_legacy(&mut self, message: String) {
        self.0.push((None, message));
    }

    fn push_id(&mut self, validator_id: &'static str, message: String) {
        self.0.push((Some(validator_id), message));
    }

    fn replay(self, warnings: &mut crate::validation_controls::ValidationIssues) {
        for (validator_id, message) in self.0 {
            match validator_id {
                Some(id) => warnings.push_id(id, message),
                None => warnings.push_legacy(message),
            }
        }
    }
}

/// A trait ready to merge: its per-trait warnings and precompilation outcome
/// travel with it so the ordered pass reports them in place.
struct PreparedTrait {
    def: TraitDefinition,
    issues: PendingIssues,
    precompiled: Result<()>,
}

/// A composite ready to merge, with its precompilation outcome.
struct PreparedRule {
    rule: CompositeTrait,
    precompiled: Result<()>,
}

/// Everything one trait file contributes that does not depend on any other
/// file. `trait_failure` is the first trait whose condition does not validate:
/// the serial merge stopped there, so `traits` holds only those before it and
/// no composites were prepared.
struct PreparedFile {
    path: std::path::PathBuf,
    yaml_warnings: Vec<String>,
    hoist: Vec<String>,
    traits: Vec<PreparedTrait>,
    trait_failure: Option<anyhow::Error>,
    trait_parsing_warnings: Vec<String>,
    rules: Vec<PreparedRule>,
    rule_parsing_warnings: Vec<String>,
}

/// Prepare one parsed trait file for the merge: apply its defaults and id
/// prefixes, validate conditions, run the per-trait checks and precompile
/// regexes. It depends on no other file, so files are prepared in parallel.
fn prepare_trait_file(
    path: &Path,
    mappings: TraitMappings,
    yaml_warnings: Vec<String>,
    dir_path: &Path,
    enable_full_validation: bool,
    enable_precision_scoring: bool,
) -> PreparedFile {
    let mut file = PreparedFile {
        path: path.to_path_buf(),
        yaml_warnings,
        hoist: Vec::new(),
        traits: Vec::with_capacity(mappings.traits.len()),
        trait_failure: None,
        trait_parsing_warnings: Vec::new(),
        rules: Vec::with_capacity(mappings.composite_rules.len()),
        rule_parsing_warnings: Vec::new(),
    };
    // Calculate the prefix from the directory path relative to traits/
    // e.g., traits/credential/java/traits.yaml -> credential/java
    let trait_prefix = path
        .strip_prefix(dir_path)
        .ok()
        .and_then(|p| p.parent())
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .filter(|s| !s.is_empty());

    // Per-file: check for values that should use defaults, and values redundant with defaults
    #[cfg(feature = "lint")]
    if enable_full_validation
        && !crate::validation_controls::is_validator_disabled("defaults-hoist")
    {
        let path_str = path.display().to_string();
        for (field, value) in find_should_use_defaults(
            &mappings.traits,
            &mappings.composite_rules,
            &mappings.defaults,
        ) {
            file.hoist.push(format!(
                "{path_str}: all {} items set '{field}' to {value} — move to 'defaults: {field}: {value}'",
                mappings.traits.len() + mappings.composite_rules.len(),
            ));
        }
        for (id, field) in find_redundant_explicit_defaults(
            &mappings.traits,
            &mappings.composite_rules,
            &mappings.defaults,
        ) {
            file.hoist.push(format!(
                "'{id}' in {path_str}: '{field}' matches the file default — remove the explicit '{field}:' from this item",
            ));
        }
    }

    // Unknown names in `defaults: for:` are reported once for the file, even
    // when no rule inherits the default.
    file.trait_parsing_warnings
        .extend(crate::capabilities::parsing::default_file_type_warnings(
            &mappings.defaults,
            path,
        ));

    for raw_trait in mappings.traits {
        // Convert raw trait to final trait, applying file-level defaults
        let mut trait_def = apply_trait_defaults(
            raw_trait,
            &mappings.defaults,
            &mut file.trait_parsing_warnings,
            path,
            enable_precision_scoring,
        );

        // Auto-prefix trait ID if it doesn't already have the path prefix
        // Uses :: as delimiter between directory path and trait name
        trait_def.id = crate::traits_repo::qualify_trait_id(&trait_def.id, trait_prefix.as_deref());
        // Validate YARA/AST conditions at load time
        let validated = trait_def
            .r#if
            .validate()
            .map_err(|e| anyhow::anyhow!("{}", e))
            .with_context(|| {
                format!(
                    "invalid condition in trait '{}' from {:?}",
                    trait_def.id, path
                )
            });
        if let Err(error) = validated {
            file.trait_failure = Some(error);
            return file;
        }
        let issues = if enable_full_validation {
            trait_issues(&trait_def, path)
        } else {
            PendingIssues::default()
        };
        let precompiled = trait_def.precompile_regexes();
        file.traits.push(PreparedTrait {
            def: trait_def,
            issues,
            precompiled,
        });
    }

    for mut raw_rule in mappings.composite_rules {
        // Parsing-time policy checks need the canonical ID, not the local YAML ID.
        if let Some(ref prefix) = trait_prefix
            && !raw_rule.id.starts_with(prefix)
            && !raw_rule.id.contains("::")
            && !raw_rule.id.contains('/')
        {
            raw_rule.id = format!("{}::{}", prefix, raw_rule.id);
        }
        // Convert raw rule to final rule, applying file-level defaults
        let mut rule = apply_composite_defaults(
            raw_rule,
            &mappings.defaults,
            &mut file.rule_parsing_warnings,
            path,
        );

        // Auto-prefix composite rule ID if it doesn't already have the path prefix
        if let Some(ref prefix) = trait_prefix {
            // Auto-prefix composite rule ID using :: delimiter
            if !rule.id.starts_with(prefix) && !rule.id.contains("::") && !rule.id.contains('/') {
                rule.id = format!("{}::{}", prefix, rule.id);
            }
            // Also auto-prefix trait references within the rule's conditions
            autoprefix_trait_refs(&mut rule, prefix);
        }

        let precompiled = rule.precompile_regexes();
        file.rules.push(PreparedRule { rule, precompiled });
    }
    file
}

/// The per-trait checks the merge reports for one trait, in report order.
fn trait_issues(trait_def: &TraitDefinition, path: &Path) -> PendingIssues {
    let mut warnings = PendingIssues::default();
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
    if !crate::validation_controls::is_validator_disabled("simple-word-boundary-regex")
        && let Some(warning) = trait_def.r#if.check_word_boundary_regex()
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
    if !crate::validation_controls::is_validator_disabled("case-insensitive-no-effect")
        && let Some(warning) = trait_def.r#if.check_case_insensitive_on_non_alpha()
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
    warnings
}

impl super::CapabilityMapper {
    /// Load capability mappings from directory of YAML files (recursively)
    #[allow(dead_code)] // Used in tests
    pub(crate) fn from_directory<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        Self::from_directory_with_options(
            dir_path,
            crate::LoadOptions {
                full_validation: true,
                ..crate::LoadOptions::default()
            },
        )
    }

    /// Load capability mappings from a directory of YAML files with explicit load options.
    ///
    /// `CLEAVE_VALIDATE=1` turns full validation on; it never turns off
    /// validation a caller asked for.
    pub(crate) fn from_directory_with_options<P: AsRef<Path>>(
        dir_path: P,
        options: super::LoadOptions,
    ) -> Result<Self> {
        Self::from_directory_exact(
            dir_path,
            super::LoadOptions {
                full_validation: options.full_validation || crate::env::flag("CLEAVE_VALIDATE"),
                ..options
            },
        )
    }

    /// [`Self::from_directory_with_options`] with `full_validation` taken
    /// exactly as given: `CLEAVE_VALIDATE` is not consulted.
    ///
    /// Tests that need validation on or off call this rather than setting the
    /// env var. The environment is process-wide, so a test that set
    /// `CLEAVE_VALIDATE=1` turned full validation on for every mapper any other
    /// test thread loaded meanwhile -- `test_for_all_is_soft_and_does_not_fail_load`
    /// then failed on the very soft issue it asserts is not fatal.
    pub(crate) fn from_directory_exact<P: AsRef<Path>>(
        dir_path: P,
        options: super::LoadOptions,
    ) -> Result<Self> {
        let super::LoadOptions {
            min_hostile_precision,
            min_suspicious_precision,
            full_validation: enable_full_validation,
            precision_scoring: enable_precision_scoring,
        } = options;
        let _span = tracing::info_span!("load_capabilities").entered();
        let dir_path = dir_path.as_ref();
        let sources = crate::rule_sources::shared(dir_path)?;
        let (enable_full_validation, clean_mark) = resolve_full_validation(
            dir_path,
            enable_full_validation,
            enable_precision_scoring.then_some((min_hostile_precision, min_suspicious_precision)),
        );
        // Facts this validation derives from patterns are kept for the next
        // one (see `facts_cache`). The last run's are read on their own thread
        // while the files below are found and parsed; the session saves them
        // when the load ends.
        #[cfg(feature = "lint")]
        let _facts = if enable_full_validation {
            crate::capabilities::validation::facts_cache::begin()
        } else {
            None
        };

        let load_started = std::time::Instant::now();
        tracing::info!("Loading trait definitions from {}", dir_path.display());
        if enable_full_validation {
            tracing::info!("Full trait validation enabled");
        } else {
            tracing::info!("Fast validation mode (run 'cleave validate' for full validation)");
        }

        // Try to load from cache (skip validation when loading from cache).
        // Mapper cache is decoupled from the per-file analysis cache: it's a
        // pure function of the traits dir, mtime-invalidated, and safe to
        // share across test invocations that set CLEAVE_SKIP_CACHE=1.
        let skip_cache = crate::cache::skip_mapper_cache();
        if !enable_full_validation
            && !skip_cache
            && let Some(mapper) = Self::from_mapper_cache(dir_path)
        {
            return Ok(mapper);
        }

        let yaml_files = find_trait_files(&sources, dir_path)?;
        let discovery_ms = load_started.elapsed().as_millis();
        let parse_started = std::time::Instant::now();
        let parsed = parse_trait_files(&sources, &yaml_files, dir_path);
        let parse_ms = parse_started.elapsed().as_millis();
        let prepare_started = std::time::Instant::now();

        let (mut rules, mut warnings, parse_errors) = merge_trait_files(
            parsed,
            dir_path,
            enable_full_validation,
            enable_precision_scoring,
        )?;
        check_file_types(&warnings, enable_full_validation)?;
        register_yara(&mut rules);
        if enable_precision_scoring {
            score_precision(
                &mut rules,
                &mut warnings,
                min_hostile_precision,
                min_suspicious_precision,
                enable_full_validation,
            );
        }

        tracing::trace!("Validating trait definitions and composite rules");
        tracing::info!(
            discovery_ms,
            parse_ms,
            prepare_ms = prepare_started.elapsed().as_millis(),
            load_ms = load_started.elapsed().as_millis(),
            "trait loading phase timings"
        );
        let lint_started = std::time::Instant::now();
        #[cfg(feature = "lint")]
        {
            super::load_validators::run(
                dir_path,
                &yaml_files,
                &rules,
                enable_full_validation,
                &mut warnings,
            );
            crate::capabilities::validation::facts_cache::completed();
        }
        tracing::info!(
            lint_ms = lint_started.elapsed().as_millis(),
            "trait lint complete"
        );

        report_validation(&mut warnings, &parse_errors, enable_full_validation)?;
        if enable_full_validation
            && warnings.is_empty()
            && parse_errors.is_empty()
            && let Some(mark) = &clean_mark
        {
            mark.set_if_unchanged(dir_path);
        }

        let MergedRules {
            mut trait_definitions,
            composite_rules,
            ..
        } = rules;
        // Pruned before the snapshot is saved, so a cache hit need not prune.
        super::drop_unreferenced_support_rules(&mut trait_definitions, &composite_rules);

        // Save to cache for future runs (only if not in validation mode)
        if !enable_full_validation
            && !skip_cache
            && let Ok(cache_path) = crate::cache::mapper_cache_path_for(dir_path)
        {
            save_mapper_cache(
                &cache_path,
                &trait_definitions,
                &composite_rules,
                &parse_errors,
            );
        }

        Ok(Self::from_loaded_rules(
            trait_definitions,
            composite_rules,
            dir_path,
        ))
    }

    /// The mapper the last load of `dir_path` saved, or `None` when there is
    /// none or it no longer reads.
    fn from_mapper_cache(dir_path: &Path) -> Option<Self> {
        let cache_path = crate::cache::mapper_cache_path_for(dir_path).ok()?;
        if cache_path.exists() {
            tracing::trace!("Attempting to load mapper from cache: {:?}", cache_path);
            match fs::read(&cache_path) {
                Ok(mut bytes) => {
                    match MapperCacheData::parse(&mut bytes) {
                        Ok(mut cache_data) => {
                            tracing::info!(
                                "Loaded mapper from cache ({} traits, {} composites)",
                                cache_data.trait_definitions.len(),
                                cache_data.composite_rules.len()
                            );

                            // `precompile_regexes` is deliberately NOT re-run here. On this
                            // path every pattern already passed it when the cache was written
                            // (the YAML load fails on invalid patterns before serializing),
                            // and its regex compiles are validation-only — eval resolves
                            // compiled regexes lazily through the shared caches (see
                            // `cached_regex`), so the compiled objects were discarded.
                            // Re-validating 58k+ traits burned ~2.6 s wall (~40 CPU-s) per
                            // process start. The one piece of real state it rebuilt is the
                            // `not:` exceptions' pre-lowered memo (#[serde(skip)]), which is
                            // cheap string work — kept below.
                            // The cached trait set is missing whatever the
                            // producing load could not parse, so say so on
                            // every hit — not just on the run that rebuilt it.
                            warn_unparseable_traits(&cache_data.parse_errors);

                            for trait_def in &mut cache_data.trait_definitions {
                                if let Some(ref mut exceptions) = trait_def.not {
                                    for exc in exceptions.iter_mut() {
                                        exc.precompile();
                                    }
                                }
                            }

                            // Ensure rule stats are up-to-date for banner display
                            let _ = crate::cache::save_rule_stats(
                                cache_data.trait_definitions.len(),
                                cache_data.composite_rules.len(),
                            );

                            // No `drop_unreferenced_support_rules`: the
                            // snapshot was stored after it, and it runs to a
                            // fixpoint, so it would drop nothing more.
                            return Some(Self::from_loaded_rules(
                                cache_data.trait_definitions,
                                cache_data.composite_rules,
                                dir_path,
                            ));
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
        None
    }

    /// Build the mapper over a finished rule set. The match indexes build
    /// lazily on the first analysis (see `match_indexes`), so a scan that only
    /// evaluates composites or reads counts never pays for them.
    fn from_loaded_rules(
        trait_definitions: Vec<TraitDefinition>,
        mut composite_rules: Vec<CompositeTrait>,
        dir_path: &Path,
    ) -> Self {
        // Populate trait_id_map
        let mut trait_id_map = std::collections::HashMap::with_capacity(trait_definitions.len());
        for (idx, trait_def) in trait_definitions.iter().enumerate() {
            trait_id_map.insert(trait_def.id.clone(), idx);
        }

        // Initialize composite rule dependencies
        for rule in &mut composite_rules {
            rule.populate_required_traits(&trait_id_map);
        }

        Self {
            trait_definitions,
            composite_rules,
            indexes: std::sync::Arc::new(std::sync::OnceLock::new()),
            unless_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            kv_sibling_basenames: std::sync::Arc::default(),
            trait_ref_index: std::sync::Arc::default(),
            path_inputs: std::sync::Arc::default(),
            container_ref_index: std::sync::Arc::default(),
            doomed_skip: std::sync::Arc::default(),
            composite_worklists: std::sync::Arc::default(),
            trait_worklists: std::sync::Arc::default(),
            trait_eval_flags: std::sync::Arc::default(),
            boolean_ast_queries: std::sync::Arc::default(),
            trait_ref_ids_memo: std::sync::Arc::default(),
            composite_id_index: std::sync::Arc::default(),
            trait_id_map,
            platforms: vec![Platform::All],
            slow_rule_ms: Self::DEFAULT_SLOW_RULE_MS,
            // Pinned at load: every result this mapper produces is stored
            // under this revision, even if a concurrent reload has already
            // replaced the process-global traits scan.
            traits_revision: crate::cache::traits_revision_fingerprint_for(dir_path),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;

    #[test]
    fn registry_policy_is_identified_before_parsing_local_rule_id() {
        let yaml = r#"defaults:
  for: [registry]
  platforms: [all]
composite_rules:
  - id: registry-security-held-package
    desc: Registry reports security hold
    crit: hostile
    scope: file
    any:
      - id: metadata/registry::registry-security-hold
      - id: metadata/registry::registry-security-hold-record
"#;
        let mappings = crate::yaml::from_str(yaml).unwrap();
        let root = Path::new("traits");
        let path = root.join("objectives/supply-chain/security-hold/withdrawn.yaml");
        let file = super::prepare_trait_file(&path, mappings, Vec::new(), root, false, false);
        assert!(
            file.rule_parsing_warnings.is_empty(),
            "{:?}",
            file.rule_parsing_warnings
        );
        assert_eq!(file.rules[0].rule.crit, crate::types::Criticality::Hostile);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn full_validation_rejects_new_metadata_file_string_definition() {
        let dir = tempfile::tempdir().expect("create temporary trait tree");
        let string_dir = dir.path().join("metadata/file/string");
        std::fs::create_dir_all(&string_dir).expect("create string directory");
        std::fs::write(
            string_dir.join("new.yaml"),
            r#"defaults:
  for: [pe]
  platforms: [windows]
traits:
- id: new-string
  desc: New generic file string
  crit: baseline
  conf: 0.5
  if: {type: text, exact: a new generic file string}
"#,
        )
        .expect("write temporary string rule");

        let error = super::super::CapabilityMapper::from_directory_exact(
            dir.path(),
            crate::LoadOptions {
                full_validation: true,
                ..crate::LoadOptions::default()
            },
        )
        .expect_err("new metadata/file/string definitions must fail validation");
        let message = format!("{error:#}");
        assert!(
            message.contains("new rule IDs under legacy metadata/file/string/"),
            "unexpected validation error: {message}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn full_validation_rejects_new_metadata_file_literal_definition() {
        let dir = tempfile::tempdir().expect("create temporary trait tree");
        let literal_dir = dir.path().join("metadata/file/literal");
        std::fs::create_dir_all(&literal_dir).expect("create literal directory");
        std::fs::write(
            literal_dir.join("new.yaml"),
            r#"defaults:
  for: [pe]
  platforms: [windows]
traits:
- id: new-literal
  desc: New context literal
  crit: baseline
  conf: 0.5
  if: {type: text, exact: a new context literal}
"#,
        )
        .expect("write temporary literal rule");

        let error = super::super::CapabilityMapper::from_directory_exact(
            dir.path(),
            crate::LoadOptions {
                full_validation: true,
                ..crate::LoadOptions::default()
            },
        )
        .expect_err("new metadata/file/literal definitions must fail validation");
        let message = format!("{error:#}");
        assert!(
            message.contains("new rule IDs under legacy metadata/file/literal/"),
            "unexpected validation error: {message}"
        );
    }

    /// Issues `prepare_trait_file` + `push_parsing_warning` raise for one file.
    #[allow(clippy::expect_used)]
    fn file_type_issues(yaml: &str) -> Vec<(&'static str, String)> {
        let mappings: crate::capabilities::models::TraitMappings =
            crate::yaml::from_str(yaml).expect("valid trait YAML");
        let dir = Path::new("traits");
        let path = dir.join("x/y.yaml");
        let file = super::prepare_trait_file(&path, mappings, Vec::new(), dir, false, false);
        let mut issues = crate::validation_controls::ValidationIssues::new();
        for w in file
            .trait_parsing_warnings
            .into_iter()
            .chain(file.rule_parsing_warnings)
        {
            super::push_parsing_warning(&mut issues, "traits/x/y.yaml", w);
        }
        issues
            .iter()
            .filter(|i| i.validator_id.ends_with("file-type"))
            .map(|i| (i.validator_id, i.message.clone()))
            .collect()
    }

    /// A mapper-cache hit must restore each rule's `defined_in`: the field is
    /// `#[serde(skip)]` on the rule types, yet evaluation filters on it, so a
    /// warm run would otherwise drop rules a cold run keeps.
    #[test]
    #[allow(clippy::expect_used)]
    fn mapper_cache_round_trip_keeps_defined_in() {
        let trait_path = Path::new("/traits/metadata/binary/layout/msdos.yaml");
        let rule_path = Path::new("/traits/objectives/impact/infect/virus/msdos-binary.yaml");
        let t = super::TraitDefinition {
            id: "metadata/binary/layout::msdos".into(),
            defined_in: trait_path.to_path_buf(),
            ..Default::default()
        };
        let c = super::CompositeTrait {
            id: "objectives/impact/infect/virus::msdos".into(),
            defined_in: rule_path.to_path_buf(),
            ..Default::default()
        };

        let mut bytes =
            super::MapperCacheData::to_json_lines(&[t], &[c], &[]).expect("encode cache");
        let data = super::MapperCacheData::parse(&mut bytes).expect("decode cache");
        assert_eq!(data.trait_definitions[0].defined_in, trait_path);
        assert_eq!(data.composite_rules[0].defined_in, rule_path);
    }

    /// Cached rules must regain the runtime YARA state omitted by serde.
    /// Otherwise inline support traits and YARA composite legs silently stop
    /// matching after the first process warms the mapper cache.
    #[test]
    #[allow(clippy::expect_used)]
    fn mapper_cache_round_trip_restores_yara_runtime_state() {
        let source = "rule cache_probe { strings: $a = \"QACACHE\" condition: $a }";
        let mut atomic = super::TraitDefinition {
            id: "objectives/test::inline-yara".into(),
            r#if: super::Condition::Yara {
                source: source.into(),
                compiled: None,
                namespace: None,
            },
            ..Default::default()
        };
        atomic.set_yara_if_namespace();
        let mut composite = super::CompositeTrait {
            id: "objectives/test::composite-yara".into(),
            all: Some(vec![super::Condition::Yara {
                source: source.into(),
                compiled: None,
                namespace: None,
            }]),
            ..Default::default()
        };
        composite.compile_yara();
        let mut bytes = super::MapperCacheData::to_json_lines(&[atomic], &[composite], &[])
            .expect("encode cache");
        let cached = super::MapperCacheData::parse(&mut bytes).expect("decode cache");
        assert!(
            matches!(
                &cached.trait_definitions[0].r#if,
                super::Condition::Yara { namespace, .. }
                    if namespace.as_deref() == Some("inline.objectives/test::inline-yara")
            ),
            "cached atomic YARA namespace must be restored"
        );
        let conditions = cached.composite_rules[0]
            .all
            .as_ref()
            .expect("all conditions");
        assert!(
            matches!(
                &conditions[0],
                super::Condition::Yara {
                    compiled: Some(_),
                    ..
                }
            ),
            "cached composite YARA must be compiled again"
        );
    }

    /// An unknown name in `defaults: for:` is reported once for the file, under
    /// the same validator as a rule's own `for:`, even when every rule
    /// overrides `for:` and nothing inherits the default.
    #[test]
    fn unknown_default_for_is_reported_once_per_file() {
        let issues = file_type_issues(
            "defaults:\n  for: [archive-typo, zip]\n  platforms: [linux]\n\
             traits:\n\
             - {id: a, desc: first trait here, for: [zip], if: {type: text, substr: aaaa}}\n\
             - {id: b, desc: second trait here, for: [zip], if: {type: text, substr: bbbb}}\n",
        );
        assert_eq!(issues.len(), 1, "{issues:?}");
        let (id, message) = &issues[0];
        assert_eq!(*id, "unknown-file-type");
        assert!(message.contains("'archive-typo'"), "{message}");
        assert!(message.contains("defaults: for:"), "{message}");
        assert!(message.contains("traits/x/y.yaml"), "{message}");
    }

    /// Inheriting the bad default does not repeat the unknown-type issue per
    /// rule; a rule left with no file type at all is its own hard issue.
    #[test]
    fn default_for_resolving_to_nothing_is_empty_file_type() {
        let issues = file_type_issues(
            "defaults:\n  for: [archive-typo]\n  platforms: [linux]\n\
             traits:\n\
             - {id: a, desc: first trait here, if: {type: text, substr: aaaa}}\n\
             - {id: b, desc: second trait here, if: {type: text, substr: bbbb}}\n\
             composite_rules:\n\
             - {id: c, desc: composite rule here, all: [{id: a}, {id: b}]}\n",
        );
        let unknown = issues
            .iter()
            .filter(|(id, _)| *id == "unknown-file-type")
            .count();
        assert_eq!(unknown, 1, "{issues:?}");
        let empty: Vec<&String> = issues
            .iter()
            .filter(|(id, _)| *id == "empty-file-type")
            .map(|(_, m)| m)
            .collect();
        assert_eq!(empty.len(), 3, "{issues:?}");
        assert!(empty.iter().any(|m| m.contains("composite rule 'c'")));
        assert_eq!(
            crate::validation_controls::validator_severity("empty-file-type"),
            crate::validation_controls::Severity::Hard
        );
    }
}
