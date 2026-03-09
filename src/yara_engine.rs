//! YARA rule engine integration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! This module provides YARA pattern matching for malware detection.
//! It loads and compiles YARA rules from:
//! - Built-in rules (traits/yara/)
//! - Third-party rules (if enabled)
//!
//! Rules are compiled once at startup for performance.

use crate::capabilities::CapabilityMapper;
use crate::types::{
    deduplicate_evidence, Evidence, MatchedString, YaraMatch, MAX_EVIDENCE_PER_TRAIT,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// YARA-X engine for pattern-based detection
#[derive(Debug)]
pub(crate) struct YaraEngine {
    rules: Option<yara_x::Rules>,
    /// Namespaces compiled into the combined engine from inline trait YARA conditions.
    /// Used to split scan results: inline matches (keyed here) go to trait evaluation;
    /// all other matches are returned as regular YARA findings.
    compiled_inline_namespaces: Vec<String>,
}

impl YaraEngine {
    /// Create a new YARA engine without rules loaded
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            rules: None,
            compiled_inline_namespaces: Vec::new(),
        }
    }

    /// Create a new YARA engine with a pre-existing capability mapper (avoids duplicate loading)
    #[must_use]
    #[allow(dead_code)] // Used by binary target (commands/analyze.rs) and tests
    pub(crate) fn new_with_mapper(_capability_mapper: CapabilityMapper) -> Self {
        Self {
            rules: None,
            compiled_inline_namespaces: Vec::new(),
        }
    }

    /// Create a new YARA engine for testing (without validation)
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_for_test() -> Self {
        Self {
            rules: None,
            compiled_inline_namespaces: Vec::new(),
        }
    }

    /// Load all YARA rules (built-in from traits/ + optionally third-party from third_party/)
    /// Uses cache if available and valid
    ///
    /// Environment variables:
    /// - `CLEAVE_SKIP_YARA=1`: Skip YARA entirely (for fast unit tests)
    /// - `CLEAVE_BUILTIN_YARA_ONLY=1`: Load only built-in rules, skip third-party (~500 vs 14k)
    /// - `CLEAVE_MINIMAL_RULES=1`: Load only essential rules (~100 instead of 14k)
    pub(crate) fn load_all_rules(&mut self, enable_third_party: bool) -> (usize, usize) {
        let _span = tracing::info_span!("load_yara_rules").entered();

        // Fast path: skip YARA entirely for tests that don't need it
        if std::env::var("CLEAVE_SKIP_YARA").is_ok() {
            tracing::info!("YARA skipped (CLEAVE_SKIP_YARA set)");
            return (0, 0);
        }

        // Override third-party setting via environment (for tests that need YARA but not 14k rules)
        let enable_third_party =
            enable_third_party && std::env::var("CLEAVE_BUILTIN_YARA_ONLY").is_err();

        tracing::info!("Loading YARA rules");

        // Try to load from cache
        if let Ok(cache_path) = crate::cache::yara_cache_path(enable_third_party) {
            if cache_path.exists() {
                tracing::debug!("Attempting to load from cache");
                match self.load_from_cache(&cache_path) {
                    Ok((builtin, third_party)) => {
                        tracing::info!("Loaded YARA rules from cache");
                        // No eprintln needed - rule count is shown in header banner
                        return (builtin, third_party);
                    }
                    Err(e) => {
                        tracing::warn!("Cache load failed: {}, recompiling", e);
                        eprintln!("⚠️  Cache invalid, recompiling...");
                    }
                }
            } else {
                tracing::debug!("No cache found");
            }
        }

        // Cache miss or invalid - compile from source
        tracing::info!("Compiling YARA rules from source");

        let traits_dir = crate::cache::traits_path();
        let third_party_dir = crate::cache::third_party_path();

        let mut compiler = yara_x::Compiler::new();
        let mut builtin_count = 0;
        let mut third_party_count = 0;
        let mut inline_count = 0;

        // 0. Load inline YARA from trait YAML files
        if traits_dir.exists() {
            self.compiled_inline_namespaces =
                Self::load_inline_trait_rules(&mut compiler, &traits_dir);
            inline_count = self.compiled_inline_namespaces.len();
        }

        // 1. Load built-in YARA rules from traits directory
        if traits_dir.exists() {
            match self.load_rules_into_compiler(&mut compiler, &traits_dir, "traits") {
                Ok(count) => builtin_count = count,
                Err(e) => {
                    let err_str = e.to_string();
                    if !err_str.contains("No YARA rules found") {
                        tracing::warn!("Failed to load built-in sources: {}", e);
                    }
                }
            }
        }

        // 2. Optionally load third-party YARA rules
        if enable_third_party && third_party_dir.exists() {
            third_party_count = self.load_third_party_rules(&mut compiler, &third_party_dir);
        }

        let total_count = builtin_count + third_party_count + inline_count;
        if total_count == 0 {
            eprintln!("\n⚠️  No YARA rules loaded");
            return (0, 0);
        }

        // Compile all rules (JIT optimization)
        let rules = compiler.build();

        // Count actual compiled rules (not source files)
        let actual_rule_count = rules.iter().count();

        self.rules = Some(rules);

        // Save to cache for next time
        if let Ok(cache_path) = crate::cache::yara_cache_path(enable_third_party) {
            if let Err(e) = self.save_to_cache(
                &cache_path,
                builtin_count,
                third_party_count,
                actual_rule_count,
            ) {
                eprintln!("⚠️  Failed to save cache: {}", e);
            } else {
                // Clean up old caches silently
                let _ = crate::cache::cleanup_old_caches(&cache_path);
            }
        }

        (builtin_count, third_party_count)
    }

    /// Parse trait YAML files and add all `type: yara` conditions to the compiler.
    ///
    /// Each rule is added under namespace `inline.{trait_id}` so that scan results
    /// can be mapped back to the originating trait during evaluation.
    /// Returns the list of namespaces successfully added.
    fn load_inline_trait_rules<'a>(
        compiler: &mut yara_x::Compiler<'a>,
        traits_dir: &Path,
    ) -> Vec<String> {
        let mut namespaces = Vec::new();

        let yaml_files: Vec<PathBuf> = WalkDir::new(traits_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let p = e.path();
                p.is_file()
                    && p.extension()
                        .map(|ext| ext == "yaml" || ext == "yml")
                        .unwrap_or(false)
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        for path in &yaml_files {
            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };
            let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
                continue;
            };

            // YAML files may have a top-level `traits:` list or be a bare list
            let items = match &doc {
                serde_yaml::Value::Mapping(m) => m
                    .get("traits")
                    .and_then(|v| v.as_sequence())
                    .map(Vec::as_slice),
                serde_yaml::Value::Sequence(s) => Some(s.as_slice()),
                _ => None,
            };

            let Some(items) = items else { continue };

            for item in items {
                let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(if_cond) = item.get("if") else {
                    continue;
                };

                // Only handle `type: yara` conditions
                if if_cond.get("type").and_then(|v| v.as_str()) != Some("yara") {
                    continue;
                }

                let Some(source) = if_cond.get("source").and_then(|v| v.as_str()) else {
                    continue;
                };

                let ns = format!("inline.{}", id);
                compiler.new_namespace(&ns);
                match compiler.add_source(source.as_bytes()) {
                    Ok(_) => {
                        tracing::trace!("Loaded inline YARA rule for trait {}", id);
                        namespaces.push(ns);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to compile inline YARA for trait {}: {:?}", id, e);
                    }
                }
            }
        }

        namespaces
    }

    /// Scan binary data and split results into regular YARA matches and inline trait results.
    ///
    /// Regular matches (non-`inline.*` namespaces) are returned as `Vec<YaraMatch>` for
    /// inclusion in the analysis report. Inline matches are returned as a
    /// `HashMap<String, Vec<Evidence>>` keyed by namespace (`"inline.{trait_id}"`), for use
    /// by trait evaluation via `EvaluationContext::inline_yara_results`.
    pub(crate) fn scan_bytes_with_inline(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<(Vec<YaraMatch>, HashMap<String, Vec<Evidence>>)> {
        use std::time::Duration;

        let rules = self.rules.as_ref().context("No YARA rules loaded")?;
        let inline_ns_set: std::collections::HashSet<&str> = self
            .compiled_inline_namespaces
            .iter()
            .map(String::as_str)
            .collect();

        let mut scanner = yara_x::Scanner::new(rules);
        scanner.set_timeout(Duration::from_secs(30));
        let scan_results = scanner
            .scan(data)
            .map_err(|e| anyhow::anyhow!("YARA scan failed: {:?}", e))?;

        struct RawRule {
            name: String,
            namespace: String,
            tags: Vec<String>,
            metadata: Vec<(String, String)>,
            patterns: Vec<(String, Vec<(usize, usize)>)>,
        }

        /// Maximum pattern match ranges to collect per pattern.
        /// Patterns matching more than this are truncated to prevent memory exhaustion.
        /// Set high enough to allow accurate counts and density measurements.
        const MAX_PATTERN_MATCHES: usize = 100_000;

        let raw_rules: Vec<RawRule> = scan_results
            .matching_rules()
            .map(|rule| {
                let patterns: Vec<_> = rule
                    .patterns()
                    .map(|pat| {
                        let total_matches = pat.matches().count();
                        if total_matches > MAX_PATTERN_MATCHES {
                            let trait_info = if rule.namespace().starts_with("inline.") {
                                format!(" [{}]", &rule.namespace()[7..])
                            } else {
                                String::new()
                            };
                            eprintln!(
                                "WARNING: Hit match limit of {} matches for YARA pattern '{}.{}'{}, stopping early",
                                MAX_PATTERN_MATCHES,
                                rule.identifier(),
                                pat.identifier(),
                                trait_info
                            );
                            tracing::warn!(
                                rule = %rule.identifier(),
                                namespace = %rule.namespace(),
                                pattern = %pat.identifier(),
                                matches = total_matches,
                                limit = MAX_PATTERN_MATCHES,
                                "Pattern has excessive matches, truncating to prevent memory exhaustion"
                            );
                        }
                        let ranges: Vec<_> = pat
                            .matches()
                            .take(MAX_PATTERN_MATCHES)
                            .map(|m| (m.range().start, m.range().end))
                            .collect();
                        (pat.identifier().to_string(), ranges)
                    })
                    .collect();
                RawRule {
                    name: rule.identifier().to_string(),
                    namespace: rule.namespace().to_string(),
                    tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                    metadata: rule
                        .metadata()
                        .map(|(k, v)| (k.to_string(), format!("{:?}", v)))
                        .collect(),
                    patterns,
                }
            })
            .collect();

        // scan_results is dropped here, releasing the scanner borrow

        // Report top 20 slowest rules
        let slowest = scanner.slowest_rules(20);
        if !slowest.is_empty() {
            eprintln!("\n⏱️  Top 20 slowest YARA rules:");
            for (i, profiling_data) in slowest.iter().enumerate() {
                let total =
                    profiling_data.condition_exec_time + profiling_data.pattern_matching_time;
                let trait_id = crate::third_party_yara::derive_trait_id(
                    profiling_data.namespace,
                    profiling_data.rule,
                    None,
                );
                eprintln!("  {}. {:>6}ms  {}", i + 1, total.as_millis(), trait_id);
            }
            eprintln!();
        }

        let mut yara_matches = Vec::new();
        let mut inline_results: HashMap<String, Vec<Evidence>> = HashMap::new();

        for raw in raw_rules {
            // Inline namespace: collect evidence for trait evaluation, not YARA output
            if inline_ns_set.contains(raw.namespace.as_str()) {
                let evidence: Vec<Evidence> = raw
                    .patterns
                    .iter()
                    .flat_map(|(_pattern_id, ranges)| {
                        ranges.iter().map(|(start, end)| {
                            let match_len = end - start;
                            let value = if match_len <= 100 {
                                String::from_utf8_lossy(&data[*start..*end]).to_string()
                            } else {
                                format!("<{} bytes>", match_len)
                            };
                            Evidence {
                                method: "yara".to_string(),
                                source: "yara-x".to_string(),
                                value,
                                location: Some(format!("offset:0x{:x}", start)),
                                ..Default::default()
                            }
                        })
                    })
                    .take(MAX_EVIDENCE_PER_TRAIT)
                    .collect();
                // Even if empty (condition match without string patterns), record the hit
                let entry = inline_results.entry(raw.namespace).or_default();
                let remaining = MAX_EVIDENCE_PER_TRAIT.saturating_sub(entry.len());
                entry.extend(evidence.into_iter().take(remaining));
                continue;
            }

            // Regular match: build YaraMatch
            let yara_match = self.build_yara_match(
                raw.name,
                raw.namespace,
                &raw.tags,
                &raw.metadata,
                &raw.patterns,
                data,
                file_type_filter,
            );
            if let Some(m) = yara_match {
                yara_matches.push(m);
            }
        }

        // Deduplicate evidence in inline results
        let inline_results: HashMap<String, Vec<Evidence>> = inline_results
            .into_iter()
            .map(|(k, v)| (k, deduplicate_evidence(v)))
            .collect();

        Ok((yara_matches, inline_results))
    }

    /// Load YARA rules from a directory into a compiler, skipping individual files that fail to compile
    fn load_rules_into_compiler<'a>(
        &mut self,
        compiler: &mut yara_x::Compiler<'a>,
        dir: &Path,
        namespace_prefix: &str,
    ) -> Result<usize> {
        // First, collect all YARA rule file paths
        tracing::trace!("Scanning {} for YARA rule files", dir.display());
        let third_party_dir = crate::cache::third_party_path();
        let rule_files: Vec<PathBuf> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                // Skip the third-party subdirectory (loaded separately with per-file namespaces)
                if path.starts_with(&third_party_dir) {
                    return false;
                }
                path.is_file()
                    && path
                        .extension()
                        .map(|ext| ext == "yar" || ext == "yara")
                        .unwrap_or(false)
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        if rule_files.is_empty() {
            anyhow::bail!("No YARA rules found in {}", dir.display());
        }

        let file_count = rule_files.len();
        tracing::debug!("Found {} YARA rule files", file_count);

        // Read all files in parallel (I/O bound operation)
        tracing::trace!("Reading {} YARA rule files in parallel", file_count);
        let sources: Vec<_> = rule_files
            .par_iter()
            .filter_map(|path| {
                let bytes = fs::read(path).ok()?;
                let source = String::from_utf8_lossy(&bytes).into_owned();
                Some((path.clone(), source))
            })
            .collect();

        tracing::debug!("Read {} rule files successfully", sources.len());

        compiler.new_namespace(namespace_prefix);

        // Compile all sources (separate calls for better error reporting)
        tracing::debug!("Adding {} YARA rule sources to compiler", sources.len());
        let mut count = 0;
        let mut failed = 0;
        for (path, source) in sources {
            tracing::trace!("Adding {}", path.display());
            match compiler.add_source(source.as_bytes()) {
                Ok(_) => count += 1,
                Err(e) => {
                    failed += 1;
                    tracing::warn!("Failed to add {}: {:?}", path.display(), e);
                }
            }
        }

        if failed > 0 {
            tracing::warn!("{} built-in file(s) failed to compile", failed);
        }

        tracing::debug!("Successfully added {} YARA rule sources", count);

        if count == 0 {
            anyhow::bail!("Failed to compile any YARA rules from {}", dir.display());
        }

        Ok(count)
    }

    /// Load third-party YARA rules with per-file namespaces (3p.{vendor}.{subdir}.{filename})
    fn load_third_party_rules<'a>(
        &mut self,
        compiler: &mut yara_x::Compiler<'a>,
        dir: &Path,
    ) -> usize {
        // Get disabled rules from config
        let disabled_rules = crate::third_party_config::disabled_rule_ids();

        // Collect all YARA files
        let rule_files: Vec<PathBuf> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                path.is_file()
                    && path
                        .extension()
                        .map(|e| e == "yar" || e == "yara")
                        .unwrap_or(false)
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        let total_files = rule_files.len();
        tracing::debug!("Found {} third-party YARA files", total_files);

        // Read all files in parallel
        let sources: Vec<_> = rule_files
            .par_iter()
            .filter_map(|path| fs::read(path).ok().map(|b| (path.clone(), b)))
            .collect();

        let mut total = 0;
        let mut failed = 0;
        let mut vt_skipped = 0;
        let mut disabled_count = 0;

        for (path, bytes) in sources {
            // Create unique namespace per file: 3p.{vendor}.{subdir}.{filename}
            let namespace = path
                .strip_prefix(dir)
                .ok()
                .and_then(|rel| rel.to_str())
                .map(|s| {
                    let parts: Vec<&str> = s
                        .split(std::path::MAIN_SEPARATOR)
                        .filter(|p| !p.is_empty())
                        .collect();
                    // Include filename (without extension) in namespace
                    let mut ns_parts = parts.to_vec();
                    if let Some(last) = ns_parts.last_mut() {
                        // Remove .yar/.yara extension
                        *last = last.trim_end_matches(".yar").trim_end_matches(".yara");
                    }
                    format!("3p.{}", ns_parts.join("."))
                })
                .unwrap_or_else(|| "3p".to_string());

            let raw_source = String::from_utf8_lossy(&bytes);

            // Skip files that reference the VirusTotal module (requires VT context)
            if raw_source.contains("vt.") {
                vt_skipped += 1;
                tracing::debug!("{}: skipped (requires VirusTotal context)", path.display());
                continue;
            }

            // Inject filetype metadata inferred from magic byte conditions
            // (e.g. uint16(0) == 0x5A4D → filetype = "pe") so compiled rules carry
            // type-filter hints even when the author didn't add them explicitly.
            let source =
                crate::third_party_yara::inject_condition_filetype_hints(&raw_source);
            let source = source.as_str();

            compiler.new_namespace(&namespace);

            // Filter out disabled rules from the source
            let (filtered_source, removed) =
                Self::filter_disabled_rules(&source, &namespace, &disabled_rules);
            disabled_count += removed;

            if filtered_source.trim().is_empty() {
                // All rules in this file were disabled
                continue;
            }

            match compiler.add_source(filtered_source.as_bytes()) {
                Ok(_) => total += 1,
                Err(e) => {
                    failed += 1;
                    tracing::warn!("{}: {}", path.display(), e);
                }
            }
        }

        if disabled_count > 0 {
            tracing::info!("{} third-party rule(s) disabled via config", disabled_count);
        }
        if vt_skipped > 0 {
            tracing::info!(
                "{} third-party rule(s) skipped (require VirusTotal context)",
                vt_skipped
            );
        }
        if failed > 0 {
            tracing::warn!("{} third-party file(s) failed to compile", failed);
        }

        tracing::debug!("Successfully added {} third-party YARA rule sources", total);
        total
    }

    /// Filter out disabled rules from YARA source.
    /// Returns the filtered source and the count of removed rules.
    fn filter_disabled_rules(
        source: &str,
        namespace: &str,
        disabled_rules: &std::collections::HashSet<String>,
    ) -> (String, usize) {
        use regex::Regex;

        // Quick check: if no disabled rules, return as-is
        if disabled_rules.is_empty() {
            return (source.to_string(), 0);
        }

        // Regex to match YARA rule definitions: `rule RuleName` or `rule RuleName : tags`
        // Captures the rule name
        let rule_start_re =
            Regex::new(r"(?m)^(\s*)((?:private\s+|global\s+)*)rule\s+(\w+)").unwrap();

        let mut result = String::with_capacity(source.len());
        let mut last_end = 0;
        let mut removed = 0;

        // Find all rule starts and their positions
        let mut rule_ranges: Vec<(usize, usize, &str)> = Vec::new();
        for cap in rule_start_re.captures_iter(source) {
            let rule_name = cap.get(3).unwrap().as_str();
            let rule_start = cap.get(0).unwrap().start();
            rule_ranges.push((rule_start, 0, rule_name)); // end will be filled later
        }

        // Fill in rule end positions (start of next rule or end of source)
        for i in 0..rule_ranges.len() {
            let end = if i + 1 < rule_ranges.len() {
                rule_ranges[i + 1].0
            } else {
                source.len()
            };
            rule_ranges[i].1 = end;
        }

        // Build filtered source
        for (start, end, rule_name) in rule_ranges {
            // Use trait_id format (third_party/vendor/...) for consistency with config
            let trait_id = crate::third_party_yara::derive_trait_id(namespace, rule_name, None);
            if disabled_rules.contains(&trait_id) {
                // Skip this rule - add any content before it that hasn't been added yet
                if start > last_end {
                    result.push_str(&source[last_end..start]);
                }
                last_end = end;
                removed += 1;
                tracing::debug!("Filtered disabled rule: {}", trait_id);
            }
        }

        // Add remaining content
        if last_end < source.len() {
            result.push_str(&source[last_end..]);
        }

        // If nothing was removed, return original to avoid allocation
        if removed == 0 {
            return (source.to_string(), 0);
        }

        (result, removed)
    }

    /// Extract namespace from file path with prefix
    #[allow(dead_code)] // Used by tests
    fn extract_namespace_with_prefix(&self, path: &Path, prefix: &str) -> String {
        let path_str = path.to_string_lossy();

        // Find the base directory (traits/ or third-party/)
        let search_str = if prefix == "third_party" {
            "third-party/"
        } else {
            "traits/"
        };

        if let Some(idx) = path_str.find(search_str) {
            let relative = &path_str[idx + search_str.len()..];

            // Remove filename and extension
            if let Some(parent) = Path::new(relative).parent() {
                let namespace_path = parent.to_string_lossy().replace('/', ".");
                return if namespace_path.is_empty() {
                    prefix.to_string()
                } else {
                    format!("{}.{}", prefix, namespace_path)
                };
            }
        }

        prefix.to_string()
    }

    /// Normalize a filetype string for use as a cache suffix
    /// Simplifies types like "application/x-sh" to "sh"
    #[allow(dead_code)] // Used by tests
    fn normalize_filetype_for_cache(filetype: &str) -> &str {
        // Remove MIME type prefixes
        if let Some(suffix) = filetype.strip_prefix("application/x-") {
            return suffix;
        }
        if let Some(suffix) = filetype.strip_prefix("text/x-") {
            return suffix;
        }
        // Return as-is for simple types
        filetype
    }

    /// Check if a YARA rule matches the given file types
    /// Parses the metadata section for "filetype" or "filetypes" fields
    #[allow(dead_code)] // Used by tests
    fn rule_matches_filetypes(source: &str, filter_types: &[&str]) -> bool {
        // If no metadata section, include the rule (no type restriction)
        if !source.contains("meta:") {
            return true;
        }

        // Simple text-based parsing for filetype metadata
        // Look for: filetype = "value" or filetypes = "value1,value2"
        for line in source.lines() {
            let trimmed = line.trim();

            // Single filetype
            if trimmed.starts_with("filetype") && trimmed.contains('=') {
                if let Some(value_part) = trimmed.split('=').nth(1) {
                    let value = value_part
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_lowercase();

                    // Check if any filter type matches
                    for filter_type in filter_types {
                        if value == filter_type.to_lowercase() {
                            return true;
                        }
                    }
                }
            }

            // Multiple filetypes (comma-separated)
            if trimmed.starts_with("filetypes") && trimmed.contains('=') {
                if let Some(value_part) = trimmed.split('=').nth(1) {
                    let value = value_part.trim().trim_matches('"').trim_matches('\'');

                    // Split by comma and check each type
                    for rule_type in value.split(',') {
                        let rule_type = rule_type.trim().to_lowercase();
                        for filter_type in filter_types {
                            if rule_type == filter_type.to_lowercase() {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // No matching filetype found, exclude the rule
        false
    }

    /// Scan a file with loaded YARA rules
    pub(crate) fn scan_file(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        let _rules = self.rules.as_ref().context("No YARA rules loaded")?;

        let data =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;

        self.scan_bytes(&data)
    }

    /// Scan byte data with loaded YARA rules
    /// Optionally filter results by file type
    pub(crate) fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        self.scan_bytes_filtered(data, None)
    }

    /// Scan byte data with optional file type filtering.
    /// Inline YARA results (namespace `inline.*`) are silently discarded; use
    /// `scan_bytes_with_inline` when you need them for trait evaluation.
    pub(crate) fn scan_bytes_filtered(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<Vec<YaraMatch>> {
        let (matches, _inline) = self.scan_bytes_with_inline(data, file_type_filter)?;
        Ok(matches)
    }

    /// Build a `YaraMatch` from raw match data collected during scanning.
    /// Returns `None` if the rule is an inline trait rule (those go into `inline_results`).
    #[allow(clippy::too_many_arguments)]
    fn build_yara_match(
        &self,
        rule_name: String,
        namespace: String,
        tags: &[String],
        metadata: &[(String, String)],
        patterns: &[(String, Vec<(usize, usize)>)],
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Option<YaraMatch> {
        let mut description = String::new();
        let mut crit = "baseline".to_string();
        let mut capability_flag = false;
        let mut mbc_code: Option<String> = None;
        let mut attack_code: Option<String> = None;
        let mut rule_filetypes: Vec<String> = Vec::new();
        let mut os_meta: Option<String> = None;
        let mut arch_context_meta: Option<String> = None;

        for tag_name in tags {
            if matches!(
                tag_name.as_str(),
                "baseline" | "notable" | "suspicious" | "hostile"
            ) {
                crit = tag_name.clone();
                break;
            }
        }

        let is_third_party = namespace.starts_with("3p.");
        if is_third_party {
            crit = "suspicious".to_string();
        }

        for (key, value_str) in metadata {
            let value_str = if value_str.starts_with("String(\"") && value_str.ends_with("\")") {
                value_str[8..value_str.len() - 2].to_string()
            } else {
                value_str.trim_matches('"').to_string()
            };

            match key.as_str() {
                "description" => description = value_str,
                "risk" => {
                    if !is_third_party {
                        crit = value_str;
                    }
                }
                "capability" => {
                    capability_flag = value_str.to_lowercase() == "true" || value_str == "1";
                }
                "mbc" => mbc_code = Some(value_str),
                "attack" => attack_code = Some(value_str),
                "filetype" | "filetypes" => {
                    rule_filetypes = value_str
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .collect();
                }
                "os" => os_meta = Some(value_str.to_lowercase()),
                "arch_context" => arch_context_meta = Some(value_str.to_lowercase()),
                _ => {}
            }
        }

        // Infer filetypes from tags (e.g., `: PE`, `: ELF`, `: MACHO`)
        if rule_filetypes.is_empty() {
            for tag_name in tags {
                match tag_name.to_uppercase().as_str() {
                    "PE" | "EXE" | "DLL" => {
                        rule_filetypes = vec!["pe".to_string(), "dll".to_string()];
                        break;
                    }
                    "ELF" => {
                        rule_filetypes = vec!["elf".to_string(), "so".to_string()];
                        break;
                    }
                    "MACHO" | "MACH_O" | "MACH-O" => {
                        rule_filetypes = vec!["macho".to_string(), "dylib".to_string()];
                        break;
                    }
                    _ => {}
                }
            }
        }

        if rule_filetypes.is_empty() {
            let inferred = crate::third_party_yara::infer_filetypes(&rule_name, os_meta.as_deref());
            rule_filetypes = inferred
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
        }

        // For third-party rules: if still no filetype, try the namespace filename component.
        // e.g. namespace "3p.RussianPanda95.VanillaTempest.win_mal_TextShell" → "win_mal_TextShell"
        // → "win" token → Windows → ["pe", "dll"]
        if rule_filetypes.is_empty() && is_third_party {
            let inferred = crate::third_party_yara::infer_filetypes_from_namespace(
                &namespace,
                os_meta.as_deref(),
            );
            rule_filetypes = inferred
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
        }

        if let Some(filter_types) = file_type_filter {
            if !rule_filetypes.is_empty() {
                let matches_filter = rule_filetypes.iter().any(|rule_type| {
                    filter_types
                        .iter()
                        .any(|ft| rule_type == &ft.to_lowercase())
                });
                if !matches_filter {
                    tracing::warn!(
                        rule = %rule_name,
                        rule_targets = ?rule_filetypes,
                        scanning = ?filter_types,
                        "YARA rule filtered: targets {:?}, not applicable to {:?}",
                        rule_filetypes,
                        filter_types,
                    );
                    return None;
                }
            }
        }

        let mut matched_strings = Vec::new();
        'outer: for (pattern_id, ranges) in patterns {
            for (start, end) in ranges {
                if matched_strings.len() >= MAX_EVIDENCE_PER_TRAIT {
                    break 'outer;
                }
                let match_len = end - start;
                let value = if match_len <= 100 {
                    String::from_utf8_lossy(&data[*start..*end]).to_string()
                } else {
                    format!("<{} bytes>", match_len)
                };
                matched_strings.push(MatchedString {
                    identifier: pattern_id.clone(),
                    offset: *start as u64,
                    value,
                });
            }
        }

        let is_capability = capability_flag || mbc_code.is_some() || attack_code.is_some();
        let trait_id = if is_third_party {
            Some(crate::third_party_yara::derive_trait_id(
                &namespace,
                &rule_name,
                os_meta.as_deref(),
            ))
        } else {
            None
        };

        // Apply config-based criticality for third-party rules
        // Returns None if the rule is disabled via config
        if is_third_party {
            match crate::third_party_config::third_party_criticality(
                &namespace,
                trait_id.as_deref(),
            ) {
                Some(config_crit) => crit = config_crit,
                None => return None, // Rule disabled
            }
        }

        Some(YaraMatch {
            rule: rule_name,
            namespace,
            crit,
            desc: description,
            matched_strings,
            is_capability,
            mbc: mbc_code,
            attack: attack_code,
            trait_id,
            arch_context: arch_context_meta,
        })
    }

    /// Check if rules are loaded
    #[must_use]
    pub(crate) fn is_loaded(&self) -> bool {
        self.rules.is_some()
    }

    /// Map YARA match to capability evidence
    #[must_use]
    pub(crate) fn yara_match_to_evidence(&self, yara_match: &YaraMatch) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        for matched_str in &yara_match.matched_strings {
            // Use actual matched value if printable, otherwise use identifier
            let is_printable = matched_str
                .value
                .bytes()
                .all(|b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t');
            let evidence_value = if is_printable && !matched_str.value.is_empty() {
                matched_str.value.clone()
            } else {
                matched_str.identifier.clone()
            };

            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: evidence_value,
                location: Some(format!("offset:0x{:x}", matched_str.offset)),
                ..Default::default()
            });
        }

        // If no specific strings matched, add general evidence
        if evidence.is_empty() {
            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: yara_match.rule.clone(),
                location: Some(yara_match.namespace.clone()),
                ..Default::default()
            });
        }

        evidence
    }

    /// Map YARA namespace to capability ID
    /// Returns the capability ID if the namespace maps to a known capability
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn namespace_to_capability(&self, namespace: &str) -> Option<String> {
        // YARA namespace format: exec.cmd, anti-static.obfuscation, etc.
        // Convert to capability ID: execution/command, anti-analysis/obfuscation
        let parts: Vec<&str> = namespace.split('.').collect();

        match parts.as_slice() {
            ["exec", "cmd"] | ["exec", "shell"] => Some("execution/command/shell".to_string()),
            ["exec", "program"] => Some("execution/command/direct".to_string()),
            ["net", sub] => Some(format!("net/{}", sub)),
            ["crypto", sub] => Some(format!("crypto/{}", sub)),
            ["fs", sub] => Some(format!("fs/{}", sub)),
            ["anti-static", "obfuscation"] => Some("anti-analysis/obfuscation".to_string()),
            ["process", sub] => Some(format!("process/{}", sub)),
            ["credential", sub] => Some(format!("credential/{}", sub)),
            // For third-party rules, use the namespace directly as the capability
            _ if !namespace.is_empty() => Some(namespace.replace('.', "/")),
            _ => None,
        }
    }

    /// Scan a file and return both YARA matches and derived findings
    /// This is the main entry point for universal YARA scanning
    #[allow(dead_code)]
    pub(crate) fn scan_file_to_findings(
        &self,
        file_path: &Path,
        file_type_filter: Option<&[&str]>,
    ) -> Result<(Vec<YaraMatch>, Vec<crate::types::Finding>)> {
        use crate::types::{Criticality, Finding, FindingKind};

        let data =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;

        let matches = self.scan_bytes_filtered(&data, file_type_filter)?;
        let mut findings = Vec::new();

        for yara_match in &matches {
            // Skip filtered matches
            if yara_match.crit == "filtered" {
                continue;
            }

            // Use derived trait_id for third-party rules, otherwise map namespace to capability
            let finding_id = yara_match
                .trait_id
                .clone()
                .or_else(|| self.namespace_to_capability(&yara_match.namespace));

            if let Some(cap_id) = finding_id {
                let evidence = self.yara_match_to_evidence(yara_match);

                let criticality = match yara_match.crit.as_str() {
                    "hostile" => Criticality::Hostile,
                    "suspicious" => Criticality::Suspicious,
                    "notable" => Criticality::Notable,
                    _ => Criticality::Baseline,
                };

                findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: cap_id,
                    desc: yara_match.desc.clone(),
                    conf: 0.9,
                    crit: criticality,
                    mbc: yara_match.mbc.clone(),
                    attack: yara_match.attack.clone(),
                    evidence,
                    match_count: 0,
                    source_file: None,
                });
            }
        }

        Ok((matches, findings))
    }

    /// Save compiled YARA rules to cache using zero-copy format
    fn save_to_cache(
        &self,
        cache_path: &Path,
        builtin_count: usize,
        third_party_count: usize,
        rule_count: usize,
    ) -> Result<()> {
        use std::io::Write;

        let rules = self.rules.as_ref().context("No rules to cache")?;

        // Serialize the rules using the YARA-X serialization
        let rules_data = rules
            .serialize()
            .context("Failed to serialize YARA rules")?;

        // Serialize namespaces as JSON (small, simple)
        let namespaces_data =
            serde_json::to_vec(&self.compiled_inline_namespaces).unwrap_or_default();

        // Calculate rules offset (header + namespaces + padding to 8-byte alignment)
        let unpadded_offset = CACHE_HEADER_SIZE + namespaces_data.len();
        let rules_offset = (unpadded_offset + 7) & !7; // Align to 8 bytes
        let padding_len = rules_offset - unpadded_offset;

        // Build the cache file
        let mut file = fs::File::create(cache_path).context("Failed to create cache file")?;

        // Write header (v5 format)
        file.write_all(CACHE_MAGIC)?;
        file.write_all(&CACHE_VERSION.to_le_bytes())?;
        file.write_all(&(builtin_count as u64).to_le_bytes())?;
        file.write_all(&(third_party_count as u64).to_le_bytes())?;
        file.write_all(&(rule_count as u64).to_le_bytes())?;
        file.write_all(&(namespaces_data.len() as u64).to_le_bytes())?;
        file.write_all(&(rules_offset as u64).to_le_bytes())?;
        file.write_all(&(rules_data.len() as u64).to_le_bytes())?;

        // Write namespaces
        file.write_all(&namespaces_data)?;

        // Write padding
        if padding_len > 0 {
            file.write_all(&vec![0u8; padding_len])?;
        }

        // Write rules data
        file.write_all(&rules_data)?;

        Ok(())
    }

    /// Load compiled YARA rules from cache using zero-copy memory-mapped I/O
    #[allow(clippy::unwrap_used)] // Slice-to-array conversions are safe after size check
    fn load_from_cache(&mut self, cache_path: &Path) -> Result<(usize, usize)> {
        let t0 = std::time::Instant::now();

        // Memory-map the cache file for zero-copy access
        let file = fs::File::open(cache_path).context("Failed to open cache file")?;
        let mmap = unsafe { memmap2::Mmap::map(&file) }.context("Failed to mmap cache file")?;

        // Check minimum size and magic
        if mmap.len() < CACHE_HEADER_SIZE {
            anyhow::bail!("Cache file too small");
        }
        if &mmap[0..4] != CACHE_MAGIC {
            anyhow::bail!("Invalid cache magic");
        }

        // Parse header
        let version = u32::from_le_bytes(mmap[4..8].try_into().unwrap());
        if version != CACHE_VERSION {
            anyhow::bail!(
                "Cache version mismatch: expected {}, got {}",
                CACHE_VERSION,
                version
            );
        }

        let builtin_count = u64::from_le_bytes(mmap[8..16].try_into().unwrap()) as usize;
        let third_party_count = u64::from_le_bytes(mmap[16..24].try_into().unwrap()) as usize;
        let _rule_count = u64::from_le_bytes(mmap[24..32].try_into().unwrap()) as usize;
        let namespaces_len = u64::from_le_bytes(mmap[32..40].try_into().unwrap()) as usize;
        let rules_offset = u64::from_le_bytes(mmap[40..48].try_into().unwrap()) as usize;
        let rules_len = u64::from_le_bytes(mmap[48..56].try_into().unwrap()) as usize;

        let t1 = std::time::Instant::now();

        // Parse namespaces (small JSON)
        let namespaces_end = CACHE_HEADER_SIZE + namespaces_len;
        let inline_namespaces: Vec<String> = if namespaces_len > 0 {
            serde_json::from_slice(&mmap[CACHE_HEADER_SIZE..namespaces_end]).unwrap_or_default()
        } else {
            Vec::new()
        };

        let t2 = std::time::Instant::now();

        // Zero-copy access to rules data - pass slice directly to deserialize
        let rules_end = rules_offset + rules_len;
        if rules_end > mmap.len() {
            anyhow::bail!("Cache file truncated");
        }
        let rules = yara_x::Rules::deserialize(&mmap[rules_offset..rules_end])
            .context("Failed to deserialize YARA rules")?;

        let t3 = std::time::Instant::now();

        tracing::debug!(
            "YARA cache load timing: mmap+header={:?}, namespaces={:?}, yara_deserialize={:?}",
            t1.duration_since(t0),
            t2.duration_since(t1),
            t3.duration_since(t2)
        );

        self.rules = Some(rules);
        self.compiled_inline_namespaces = inline_namespaces;
        Ok((builtin_count, third_party_count))
    }
}

/// Zero-copy cache format header (v5 - adds rule_count for fast header display)
/// Layout: MAGIC(4) + VERSION(4) + builtin(8) + third_party(8) + rule_count(8) + namespaces_len(8) + rules_offset(8) + rules_len(8) + namespaces_data + padding + rules_data
const CACHE_MAGIC: &[u8; 4] = b"YARC";
const CACHE_VERSION: u32 = 5;
const CACHE_HEADER_SIZE: usize = 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8; // 56 bytes

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl YaraEngine {
    /// Compile YARA rules from source text. For tests only.
    fn load_rule_source(&mut self, source: &str) -> Result<()> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source.as_bytes())
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        self.rules = Some(compiler.build());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_simple_rule() {
        let rule = r#"
rule test_rule {
    meta:
        description = "Test rule"
        risk = "notable"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This contains TESTPATTERN in the data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "test_rule");
        assert!(!matches[0].matched_strings.is_empty());
    }

    #[test]
    fn test_no_match() {
        let rule = r#"
rule test_rule {
    strings:
        $test = "NOTFOUND"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This does not contain the pattern";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_new() {
        let engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());
    }

    #[test]
    fn test_default() {
        let engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());
    }

    #[test]
    fn test_is_loaded() {
        let mut engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());

        engine
            .load_rule_source(r#"rule test { strings: $a = "test" condition: $a }"#)
            .unwrap();

        assert!(engine.is_loaded());
    }

    #[test]
    fn test_scan_without_rules() {
        let engine = YaraEngine::new_for_test();
        let result = engine.scan_bytes(b"test data");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No YARA rules loaded"));
    }

    #[test]
    fn test_extract_namespace_with_prefix() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/traits/execution/shell/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits.execution.shell");
    }

    #[test]
    fn test_extract_namespace_with_prefix_third_party() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/third-party/malware/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "third_party");
        assert_eq!(namespace, "third_party.malware");
    }

    #[test]
    fn test_extract_namespace_with_prefix_no_subdirs() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/traits/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits");
    }

    #[test]
    fn test_rule_with_metadata() {
        let rule = r#"
rule test_rule {
    meta:
        description = "Test description"
        risk = "hostile"
        capability = "true"
        mbc = "B0001"
        attack = "T1059"
    strings:
        $test = "PATTERN"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This contains PATTERN in the data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].desc, "Test description");
        assert_eq!(matches[0].crit, "hostile");
        assert!(matches[0].is_capability);
        assert_eq!(matches[0].mbc, Some("B0001".to_string()));
        assert_eq!(matches[0].attack, Some("T1059".to_string()));
    }

    #[test]
    fn test_rule_with_tags() {
        let rule = r#"
rule test_rule : suspicious {
    strings:
        $test = "TAGGED"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TAGGED data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].crit, "suspicious");
    }

    #[test]
    fn test_yara_match_to_evidence() {
        let engine = YaraEngine::new_for_test();

        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "test.namespace".to_string(),
            crit: "hostile".to_string(),
            desc: "Test".to_string(),
            matched_strings: vec![MatchedString {
                identifier: "$pattern".to_string(),
                offset: 0x1000,
                value: "test".to_string(),
            }],
            is_capability: false,
            mbc: None,
            attack: None,
            trait_id: None,
            arch_context: None,
        };

        let evidence = engine.yara_match_to_evidence(&yara_match);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].method, "yara");
        assert_eq!(evidence[0].source, "yara-x");
        assert_eq!(evidence[0].value, "test"); // Uses actual matched value
        assert_eq!(evidence[0].location, Some("offset:0x1000".to_string()));
    }

    #[test]
    fn test_yara_match_to_evidence_no_strings() {
        let engine = YaraEngine::new_for_test();

        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "test.namespace".to_string(),
            crit: "hostile".to_string(),
            desc: "Test".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
            trait_id: None,
            arch_context: None,
        };

        let evidence = engine.yara_match_to_evidence(&yara_match);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].value, "test_rule");
        assert_eq!(evidence[0].location, Some("test.namespace".to_string()));
    }

    #[test]
    fn test_multiple_patterns() {
        let rule = r#"
rule test_rule {
    strings:
        $a = "FIRST"
        $b = "SECOND"
    condition:
        any of them
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"FIRST and SECOND patterns";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_strings.len(), 2);
    }

    #[test]
    fn test_long_match_truncation() {
        let rule = r#"
rule test_rule {
    strings:
        $long = /A{200}/
    condition:
        $long
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = vec![b'A'; 200];
        let matches = engine.scan_bytes(&test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched_strings[0].value.contains("200 bytes"));
    }

    #[test]
    fn test_capability_inference_from_mbc() {
        let rule = r#"
rule test_rule {
    meta:
        mbc = "B0015.001"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from MBC presence
    }

    #[test]
    fn test_capability_inference_from_attack() {
        let rule = r#"
rule test_rule {
    meta:
        attack = "T1059.004"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from ATT&CK presence
    }

    #[test]
    fn test_filter_disabled_rules() {
        let source = r#"
rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}

rule AlsoKeep {
    strings:
        $c = "also"
    condition:
        $c
}
"#;

        let mut disabled = std::collections::HashSet::new();
        // derive_trait_id("3p.test.file", "DisableMe", None) -> "third_party/test/file/disableme"
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
        assert!(filtered.contains("rule AlsoKeep"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_no_match() {
        let source = r#"
rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}
"#;

        let mut disabled = std::collections::HashSet::new();
        // Different namespace - won't match rules in test.file
        disabled.insert("third_party/other/file/somerule".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 0);
        assert_eq!(filtered, source);
    }

    #[test]
    fn test_filter_disabled_rules_with_tags() {
        let source = r#"
rule KeepMe : tag1 tag2 {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe : hostile malware {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepMe : tag1 tag2"));
        assert!(!filtered.contains("rule DisableMe"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_private_global() {
        let source = r#"
private rule PrivateKeep {
    strings:
        $a = "keep"
    condition:
        $a
}

global rule GlobalDisable {
    strings:
        $b = "disable"
    condition:
        $b
}

private global rule PrivateGlobalKeep {
    strings:
        $c = "keep2"
    condition:
        $c
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/globaldisable".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 1);
        assert!(filtered.contains("private rule PrivateKeep"));
        assert!(!filtered.contains("global rule GlobalDisable"));
        assert!(filtered.contains("private global rule PrivateGlobalKeep"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_first_rule() {
        let source = r#"rule FirstDisabled {
    strings:
        $a = "first"
    condition:
        $a
}

rule Second {
    strings:
        $b = "second"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/firstdisabled".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 1);
        assert!(!filtered.contains("rule FirstDisabled"));
        assert!(filtered.contains("rule Second"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_last_rule() {
        let source = r#"
rule First {
    strings:
        $a = "first"
    condition:
        $a
}

rule LastDisabled {
    strings:
        $b = "last"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/lastdisabled".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 1);
        assert!(filtered.contains("rule First"));
        assert!(!filtered.contains("rule LastDisabled"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_multiple() {
        let source = r#"
rule Keep1 {
    strings:
        $a = "keep1"
    condition:
        $a
}

rule Disable1 {
    strings:
        $b = "disable1"
    condition:
        $b
}

rule Keep2 {
    strings:
        $c = "keep2"
    condition:
        $c
}

rule Disable2 {
    strings:
        $d = "disable2"
    condition:
        $d
}

rule Keep3 {
    strings:
        $e = "keep3"
    condition:
        $e
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disable1".to_string());
        disabled.insert("third_party/test/file/disable2".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 2);
        assert!(filtered.contains("rule Keep1"));
        assert!(!filtered.contains("rule Disable1"));
        assert!(filtered.contains("rule Keep2"));
        assert!(!filtered.contains("rule Disable2"));
        assert!(filtered.contains("rule Keep3"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_with_imports() {
        let source = r#"import "pe"
import "math"

rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 1);
        assert!(filtered.contains("import \"pe\""));
        assert!(filtered.contains("import \"math\""));
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
    }

    #[test]
    fn test_filter_disabled_rules_complex_condition() {
        let source = r#"
rule KeepComplex {
    meta:
        description = "Complex rule"
    strings:
        $a = "pattern1"
        $b = "pattern2"
        $c = /regex[0-9]+/
    condition:
        ($a and $b) or
        ($c and filesize < 1MB) or
        (
            for any i in (0..10) : (
                uint32(i) == 0x12345678
            )
        )
}

rule DisableMe {
    strings:
        $x = "disable"
    condition:
        $x
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepComplex"));
        assert!(filtered.contains("for any i in"));
        assert!(!filtered.contains("rule DisableMe"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_all_disabled() {
        let source = r#"
rule Disable1 {
    strings:
        $a = "d1"
    condition:
        $a
}

rule Disable2 {
    strings:
        $b = "d2"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disable1".to_string());
        disabled.insert("third_party/test/file/disable2".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 2);
        assert!(!filtered.contains("rule Disable1"));
        assert!(!filtered.contains("rule Disable2"));
        // Should be essentially empty (just whitespace)
        assert!(filtered.trim().is_empty());
    }

    #[test]
    fn test_filter_disabled_rules_preserves_comments() {
        let source = r#"
// This is a file-level comment
/* Multi-line
   comment */

rule KeepMe {
    // Rule comment
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) =
            YaraEngine::filter_disabled_rules(source, "3p.test.file", &disabled);

        assert_eq!(count, 1);
        assert!(filtered.contains("// This is a file-level comment"));
        assert!(filtered.contains("/* Multi-line"));
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
    }
}
