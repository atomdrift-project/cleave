//! Single YAML file loading for capability mapper.
//!
//! This module handles loading capability definitions from a single YAML file,
//! which is primarily used in tests and for simple configurations.

use crate::capabilities::indexes::{RawContentRegexIndex, StringMatchIndex, TraitIndex};
use crate::capabilities::models::{TraitInfo, TraitMappings};
use crate::capabilities::parsing::{apply_composite_defaults, apply_trait_defaults};
use crate::capabilities::validation::{
    find_duplicate_traits_and_composites, precalculate_all_composite_precisions,
    validate_hostile_composite_precision,
};
use crate::composite_rules::Platform;
use crate::types::Criticality;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

impl super::CapabilityMapper {
    /// Load capability mappings from a single YAML file with default precision thresholds
    #[allow(dead_code)] // Used in tests
    pub(crate) fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_yaml_with_precision_thresholds(
            path,
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            true, // from_yaml always enables full validation (used in tests)
        )
    }

    /// Load capability mappings from a single YAML file with explicit precision thresholds
    pub(crate) fn from_yaml_with_precision_thresholds<P: AsRef<Path>>(
        path: P,
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
    ) -> Result<Self> {
        let bytes = fs::read(path.as_ref()).context("Failed to read capabilities YAML file")?;
        let content = String::from_utf8_lossy(&bytes);

        let mappings: TraitMappings =
            serde_yaml::from_str(&content).context("Failed to parse capabilities YAML")?;

        let mut symbol_map = HashMap::new();

        // Load legacy "symbols" format
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

        // Load "simple_rules" format
        for rule in mappings.simple_rules {
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

        // Convert raw traits to final traits with defaults applied
        let mut warnings: Vec<String> = Vec::new();
        let mut trait_definitions: Vec<_> = mappings
            .traits
            .into_iter()
            .map(|raw| apply_trait_defaults(raw, &mappings.defaults, &mut warnings, path.as_ref()))
            .collect();

        // Pre-compile all regexes for performance
        for trait_def in &mut trait_definitions {
            if let Err(e) = trait_def.precompile_regexes() {
                return Err(anyhow::anyhow!("Regex compilation error: {:#}", e));
            }
        }

        // Convert raw composite rules to final rules with defaults applied
        let mut composite_rules = Vec::new();
        for raw in mappings.composite_rules {
            composite_rules.push(apply_composite_defaults(
                raw,
                &mappings.defaults,
                &mut warnings,
                path.as_ref(),
            ));
        }

        // Print any warnings from parsing
        for warning in &warnings {
            eprintln!("Warning: {}", warning);
        }

        // Structurally invalid file types (for: [], for: [none]) are always fatal
        let invalid_ft_errors: Vec<&str> = warnings
            .iter()
            .filter(|w| w.contains("Invalid file type"))
            .map(String::as_str)
            .collect();
        if !invalid_ft_errors.is_empty() {
            anyhow::bail!(
                "Invalid file types in trait file:\n  {}\n\nFix these 'for:' values in the YAML file.",
                invalid_ft_errors.join("\n  ")
            );
        }

        // Unrecognized file types (forward-compat) — log info and continue
        for w in warnings
            .iter()
            .filter(|w| w.contains("Unknown file type"))
        {
            tracing::info!("{} — skipping rule (update cleave for support)", w);
        }

        // Pre-compile all composite rule regexes
        for rule in &mut composite_rules {
            if let Err(e) = rule.precompile_regexes() {
                return Err(anyhow::anyhow!("Regex compilation error: {:#}", e));
            }
        }

        // Pre-calculate precision for all composite rules
        precalculate_all_composite_precisions(&mut composite_rules, &trait_definitions);

        // Validate HOSTILE composite precision
        validate_hostile_composite_precision(
            &mut composite_rules,
            &trait_definitions,
            &mut warnings,
            min_hostile_precision,
            min_suspicious_precision,
        );

        // Detect duplicate traits and composites
        find_duplicate_traits_and_composites(&trait_definitions, &composite_rules, &mut warnings);

        // Validate trait and composite conditions and warn about problematic patterns
        if enable_full_validation {
            let has_validation_errors = super::helpers::validate_conditions(
                &trait_definitions,
                &composite_rules,
                path.as_ref(),
            );

            if has_validation_errors {
                eprintln!("\n==> Fix all validation errors before continuing.\n");
                anyhow::bail!("Trait loading failed due to validation errors");
            }
        }

        // Build trait index for fast lookup by file type
        let trait_index = TraitIndex::build(&trait_definitions);

        // Build string match index for batched AC matching
        let string_match_index = StringMatchIndex::build(&trait_definitions);

        // Build raw content regex index for batched regex matching
        let raw_content_regex_index = match RawContentRegexIndex::build(&trait_definitions) {
            Ok(index) => index,
            Err(errors) => {
                return Err(anyhow::anyhow!(errors.join("\n")));
            }
        };

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
