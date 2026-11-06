//! Collecting and classifying YARA rule sources: built-in, third-party and inline.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl YaraEngine {
    /// Collect built-in YARA rule sources from the traits directory, bucketing
    /// each rule by filetype with the same splitter used for third-party
    /// collections.
    ///
    /// Returns `(tier_sources, rule_contexts, builtin_file_count)`.
    #[cfg(test)]
    pub(super) fn collect_builtin_sources_tiered(
        dir: &Path,
    ) -> (
        HashMap<String, Vec<(String, String)>>,
        HashMap<String, RuleContext>,
        usize,
    ) {
        Self::collect_builtin_sources_tiered_with_sources(dir, None)
    }

    pub(super) fn collect_builtin_sources_tiered_with_sources(
        dir: &Path,
        sources: Option<&crate::rule_sources::RuleSources>,
    ) -> (
        HashMap<String, Vec<(String, String)>>,
        HashMap<String, RuleContext>,
        usize,
    ) {
        let rule_files: Vec<PathBuf> = if let Some(sources) = sources {
            sources
                .files()
                .iter()
                .filter(|file| {
                    !file.follows_directory_symlink()
                        && !file
                            .relative_path
                            .components()
                            .any(|c| c.as_os_str() == "third-party")
                        && matches!(
                            file.relative_path.extension().and_then(|e| e.to_str()),
                            Some("yar" | "yara")
                        )
                })
                .map(|file| dir.join(&file.relative_path))
                .collect()
        } else {
            WalkDir::new(dir)
                .follow_links(false)
                .into_iter()
                .filter_entry(|entry| {
                    crate::traits_repo::is_rule_source_entry(entry)
                        && (entry.depth() == 0 || entry.file_name() != "third-party")
                })
                .filter_map(std::result::Result::ok)
                .filter(|entry| {
                    let path = entry.path();
                    path.is_file()
                        && path
                            .extension()
                            .map(|ext| ext == "yar" || ext == "yara")
                            .unwrap_or(false)
                })
                .map(|entry| entry.path().to_path_buf())
                .collect()
        };

        tracing::debug!("Found {} built-in YARA rule files", rule_files.len());

        let Some(re) = rule_start_re() else {
            tracing::warn!(
                "failed to compile YARA rule-start regex; skipping built-in YARA preprocessing"
            );
            return (HashMap::new(), HashMap::new(), 0);
        };

        let process_one = |path: &PathBuf| {
            let bytes = Self::read_source(sources, dir, path)?;
            let raw_source = String::from_utf8_lossy(&bytes);
            let source = yara_classify::inject_condition_filetype_hints(&raw_source);
            let split = Self::split_monolithic_by_tier(&source, "traits", re);
            tracing::trace!(
                path = %path.display(),
                buckets = ?split.tiers.keys().collect::<Vec<_>>(),
                "Collected built-in YARA source"
            );
            Some(split)
        };

        let processed: Vec<SplitSource> = off_pool_flat_map(&rule_files, |f| {
            process_one(f).into_iter().collect::<Vec<_>>()
        });

        let mut tier_sources: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut rule_contexts: HashMap<String, RuleContext> = HashMap::new();
        let mut tier_counts: HashMap<String, usize> = HashMap::new();
        // Count actual public rules, not files: a single .yar file holds many rules.
        let mut rule_count = 0usize;

        for split in processed {
            rule_count += split.contexts.len();
            rule_contexts.extend(split.contexts);
            for (bucket, source) in split.tiers {
                *tier_counts.entry(bucket.clone()).or_insert(0) += 1;
                tier_sources
                    .entry(bucket)
                    .or_default()
                    .push(("traits".to_string(), source));
            }
        }

        for (bucket, count) in &tier_counts {
            tracing::info!("Built-in bucket {bucket}: {count} source(s)");
        }

        (tier_sources, rule_contexts, rule_count)
    }

    /// Collect third-party YARA rule sources, bucketing each rule by filetype.
    ///
    /// Small files (single-rule or few rules from one vendor) are classified as a whole.
    /// Large monolithic files (like YARAForge's single .yar with ~11K rules) are split
    /// per-rule so each rule goes to the correct bucket(s).
    ///
    /// Returns `(tier_sources, rule_contexts, total_source_count, vt_skipped, disabled_count)`.
    /// `tier_sources` maps each filetype bucket (or [`FALLBACK_BUCKET`]) to its
    /// list of `(namespace, source)` pairs.
    #[cfg(test)]
    pub(super) fn collect_third_party_sources_tiered(
        dir: &Path,
    ) -> (
        HashMap<String, Vec<(String, String)>>,
        HashMap<String, RuleContext>,
        usize,
        usize,
        usize,
    ) {
        Self::collect_third_party_sources_tiered_with_sources(dir, None)
    }

    pub(super) fn collect_third_party_sources_tiered_with_sources(
        dir: &Path,
        sources: Option<&crate::rule_sources::RuleSources>,
    ) -> (
        HashMap<String, Vec<(String, String)>>,
        HashMap<String, RuleContext>,
        usize,
        usize,
        usize,
    ) {
        let disabled_rules = crate::third_party_config::disabled_rule_ids();

        let rule_files: Vec<PathBuf> = if let Some(sources) = sources {
            sources
                .files()
                .iter()
                .filter(|file| {
                    !file.follows_directory_symlink()
                        && true
                        && matches!(
                            file.relative_path.extension().and_then(|e| e.to_str()),
                            Some("yar" | "yara")
                        )
                })
                .map(|file| dir.join(&file.relative_path))
                .collect()
        } else {
            WalkDir::new(dir)
                .follow_links(false)
                .into_iter()
                .filter_entry(crate::traits_repo::is_rule_source_entry)
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
                .collect()
        };

        tracing::debug!("Found {} third-party YARA files", rule_files.len());

        let Some(re) = rule_start_re() else {
            tracing::warn!(
                "failed to compile YARA rule-start regex; skipping third-party YARA preprocessing"
            );
            return (HashMap::new(), HashMap::new(), 0, 0, 0);
        };

        struct Processed {
            path: PathBuf,
            namespace: String,
            split: SplitSource,
            vt_stripped: usize,
            disabled_stripped: usize,
        }

        let process_one = |path: &PathBuf| {
            let bytes = Self::read_source(sources, dir, path)?;

            let namespace = path
                .strip_prefix(dir)
                .ok()
                .and_then(|rel| rel.to_str())
                .map(|s| {
                    let parts: Vec<&str> = s
                        .split(std::path::MAIN_SEPARATOR)
                        .filter(|p| !p.is_empty())
                        .collect();
                    let mut ns_parts = parts.to_vec();
                    if let Some(last) = ns_parts.last_mut() {
                        *last = last.trim_end_matches(".yar").trim_end_matches(".yara");
                    }
                    format!("3p.{}", ns_parts.join("."))
                })
                .unwrap_or_else(|| "3p".to_string());

            let raw_source = String::from_utf8_lossy(&bytes);

            let (raw_source, vt_stripped) = if raw_source.contains("vt.") {
                let (filtered, count) = Self::filter_vt_rules(&raw_source, re);
                (std::borrow::Cow::Owned(filtered), count)
            } else {
                (raw_source, 0)
            };

            if raw_source.trim().is_empty() {
                return None;
            }

            let source = yara_classify::inject_condition_filetype_hints(&raw_source);

            let (filtered_source, disabled_stripped) =
                Self::filter_disabled_rules(&source, &namespace, &disabled_rules, re);

            if filtered_source.trim().is_empty() {
                return None;
            }

            let split = Self::split_monolithic_by_tier(&filtered_source, &namespace, re);
            Some(Processed {
                path: path.clone(),
                namespace,
                split,
                vt_stripped,
                disabled_stripped,
            })
        };

        // Read and preprocess in parallel unless already on a rayon worker.
        // The transform is pure, but nested rayon here can deadlock cold YARA
        // initialization when other workers are waiting on the singleton.
        let processed: Vec<Processed> = off_pool_flat_map(&rule_files, |f| {
            process_one(f).into_iter().collect::<Vec<_>>()
        });

        let mut tier_sources: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut rule_contexts: HashMap<String, RuleContext> = HashMap::new();
        // `fragments` counts per-bucket source splits (for diagnostics);
        // `rule_count` counts actual public rules — a monolithic pack holds
        // thousands per file.
        let mut fragments = 0;
        let mut rule_count = 0;
        let mut vt_skipped = 0;
        let mut disabled_count = 0;
        let mut tier_counts: HashMap<String, usize> = HashMap::new();

        for p in processed {
            if p.vt_stripped > 0 {
                tracing::debug!(
                    "{}: stripped {} rule(s) requiring VirusTotal context",
                    p.path.display(),
                    p.vt_stripped,
                );
            }
            vt_skipped += p.vt_stripped;
            disabled_count += p.disabled_stripped;
            rule_count += p.split.contexts.len();
            rule_contexts.extend(p.split.contexts);

            for (bucket, tier_source) in p.split.tiers {
                fragments += 1;
                *tier_counts.entry(bucket.clone()).or_insert(0) += 1;
                tier_sources
                    .entry(bucket)
                    .or_default()
                    .push((p.namespace.clone(), tier_source));
            }
        }

        for (bucket, count) in &tier_counts {
            tracing::info!("Third-party bucket {bucket}: {count} source(s)");
        }
        tracing::debug!(
            "Successfully added {} third-party YARA source(s) across {} bucket(s)",
            fragments,
            tier_counts.len().max(1),
        );

        (
            tier_sources,
            rule_contexts,
            rule_count,
            vt_skipped,
            disabled_count,
        )
    }

    pub(super) fn derive_rule_context(
        rule_name: &str,
        rule_text: &str,
        namespace: &str,
    ) -> RuleContext {
        let lower = rule_text.to_ascii_lowercase();
        let tags = extract_header_tags_from_source(rule_text);
        let mut filetypes: Vec<String> = Vec::new();
        let mut filetype_source = "none".to_string();
        let mut os_meta: Option<String> = None;
        let mut arch_context: Option<String> = None;
        let mut metadata_hint_text = String::new();

        for line in lower.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with("filetype") || trimmed.starts_with("filetypes"))
                && trimmed.contains('=')
                && let Some(val) = trimmed.split('=').nth(1)
            {
                filetypes = val
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !filetypes.is_empty() {
                    filetype_source = "metadata".to_string();
                }
            }
            if trimmed.starts_with("os") && trimmed.contains('=') {
                let after_os = &trimmed[2..];
                if (after_os.starts_with(' ') || after_os.starts_with('='))
                    && let Some(val) = trimmed.split('=').nth(1)
                {
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    if !val.is_empty() {
                        os_meta = Some(val.to_string());
                    }
                }
            }
            if trimmed.starts_with("arch_context")
                && trimmed.contains('=')
                && let Some(val) = trimmed.split('=').nth(1)
            {
                let val = val.trim().trim_matches('"').trim_matches('\'');
                if !val.is_empty() {
                    arch_context = Some(val.to_string());
                }
            }
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                if matches!(
                    key,
                    "description"
                        | "source_url"
                        | "reference"
                        | "category"
                        | "classification"
                        | "threat_name"
                        | "scan_context"
                        | "tags"
                ) {
                    if !metadata_hint_text.is_empty() {
                        metadata_hint_text.push(' ');
                    }
                    metadata_hint_text.push_str(val.trim().trim_matches('"').trim_matches('\''));
                }
            }
        }

        // Strongest signal: the rule's own condition. A magic-byte check
        // (MZ / ELF / Mach-O / PDF / OLE / ZIP) or a YARA module reference
        // (`pe.` / `elf.` / `macho.` / `dotnet.`) pins the filetype regardless
        // of name or metadata, and catches rules with no naming signal at all.
        if filetypes.is_empty()
            && let Some(ft) = yara_classify::filetype_from_magic(&lower)
        {
            filetypes = vec![ft.to_string()];
            filetype_source = "condition".to_string();
        }
        // High-confidence string markers in the body (e.g. the `_CorExeMain`
        // .NET entry-point symbol) when there is no magic/module signal.
        if filetypes.is_empty() {
            let inferred = yara_classify::infer_filetypes_from_string_markers(&lower);
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "string-marker".to_string();
            }
        }
        if filetypes.is_empty() {
            let inferred = yara_classify::infer_filetypes_from_tags(&tags);
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "tag".to_string();
            }
        }
        if filetypes.is_empty() {
            let inferred = yara_classify::infer_filetypes_from_metadata_text(&metadata_hint_text);
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "metadata-text".to_string();
            }
        }
        if filetypes.is_empty() {
            let inferred = yara_classify::infer_filetypes(rule_name, os_meta.as_deref());
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "rule-name".to_string();
            }
        }
        if filetypes.is_empty() {
            let inferred =
                yara_classify::infer_filetypes_from_namespace(namespace, os_meta.as_deref());
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "namespace".to_string();
            }
        }
        // Last resort: curated rule-name → filetype overrides for known families
        // with no inferable signal. Anything still empty stays in `fallback`.
        if filetypes.is_empty() {
            let inferred = yara_classify::filetypes_from_override(rule_name);
            if !inferred.is_empty() {
                filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "override-table".to_string();
            }
        }

        // Collapse binary-format aliases (dll/exe -> pe, so/ko -> elf,
        // dylib/kext -> macho) so each rule lands in exactly one bucket. A scan
        // loads every alias of a detected type together, so separate alias
        // buckets would only duplicate the rule.
        for ft in &mut filetypes {
            let canon = yara_classify::canonical_binary_filetype(ft);
            if canon != ft.as_str() {
                *ft = canon.to_string();
            }
        }
        {
            let mut seen = std::collections::HashSet::new();
            filetypes.retain(|ft| seen.insert(ft.clone()));
        }

        let mut platforms: Vec<String> =
            crate::third_party_yara::platforms_from_name_and_os(rule_name, os_meta.as_deref())
                .iter()
                .map(platform_label)
                .map(std::string::ToString::to_string)
                .collect();

        if platforms.is_empty()
            && filetypes
                .iter()
                .any(|ft| matches!(ft.as_str(), "sh" | "bash" | "zsh"))
        {
            platforms.push("unix".to_string());
        }
        if platforms.is_empty() && looks_like_unix_shell_payload(&lower) {
            platforms.push("unix".to_string());
        }

        RuleContext {
            filetypes,
            filetype_source,
            platforms,
            os_meta,
            arch_context,
        }
    }

    /// Split a large monolithic YARA source into per-filetype-bucket chunks.
    ///
    /// Extracts import statements and private rules, then buckets each public
    /// rule by the filetype strings of its derived [`RuleContext`] (drawn from
    /// the same vocabulary as
    /// [`crate::analyzers::FileTypeExt::yara_filetypes`]). A rule with no
    /// filetype constraint lands in [`FALLBACK_BUCKET`] (always scanned). Private
    /// rules are duplicated into every bucket that has dependents (simplest
    /// approach since there are typically <30 private rules).
    pub(super) fn split_monolithic_by_tier(
        source: &str,
        namespace: &str,
        rule_re: &regex::Regex,
    ) -> SplitSource {
        // Extract imports from top of file
        let mut imports = String::new();
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") {
                imports.push_str(line);
                imports.push('\n');
            }
            // Stop scanning for imports once we hit a rule
            if trimmed.starts_with("rule ") || trimmed.starts_with("private rule") {
                break;
            }
        }

        // Parse rule boundaries
        struct RuleInfo<'a> {
            start: usize,
            end: usize,
            name: &'a str,
            is_private: bool,
        }

        let mut rules: Vec<RuleInfo<'_>> = Vec::new();
        for cap in rule_re.captures_iter(source) {
            let (Some(name_match), Some(start_match)) = (cap.get(3), cap.get(0)) else {
                continue;
            };
            let name = name_match.as_str();
            let start = start_match.start();
            let is_private = cap
                .get(2)
                .map(|m| m.as_str().contains("private"))
                .unwrap_or(false);
            rules.push(RuleInfo {
                start,
                end: 0,
                name,
                is_private,
            });
        }

        // Fill end positions: each rule ends where the next begins
        let starts: Vec<usize> = rules.iter().map(|r| r.start).collect();
        for (i, rule) in rules.iter_mut().enumerate() {
            rule.end = starts.get(i + 1).copied().unwrap_or(source.len());
        }

        // Collect private rules (included in every tier)
        let private_chunk: String = rules
            .iter()
            .filter(|r| r.is_private)
            .map(|r| &source[r.start..r.end])
            .collect::<Vec<_>>()
            .join("\n");

        // Bucket each public rule into each of its filetype strings, or the
        // fallback bucket when it carries no filetype constraint.
        let mut tier_rules: HashMap<String, Vec<&str>> = HashMap::new();
        let mut contexts: HashMap<String, RuleContext> = HashMap::new();
        for r in &rules {
            if r.is_private {
                continue;
            }
            let rule_text = &source[r.start..r.end];
            let context = Self::derive_rule_context(r.name, rule_text, namespace);
            if context.filetypes.is_empty() {
                tier_rules
                    .entry(FALLBACK_BUCKET.to_string())
                    .or_default()
                    .push(rule_text);
            } else {
                for ft in &context.filetypes {
                    tier_rules
                        .entry(ft.to_ascii_lowercase())
                        .or_default()
                        .push(rule_text);
                }
            }
            contexts.insert(rule_context_key(namespace, r.name), context);
        }

        // Build per-bucket source strings
        let mut result: HashMap<String, String> = HashMap::new();
        for (bucket, rule_texts) in tier_rules {
            let mut s = String::with_capacity(imports.len() + private_chunk.len() + 4096);
            s.push_str(&imports);
            s.push('\n');
            if !private_chunk.is_empty() {
                s.push_str(&private_chunk);
                s.push('\n');
            }
            for text in rule_texts {
                s.push_str(text);
            }
            result.insert(bucket, s);
        }

        SplitSource {
            tiers: result,
            contexts,
        }
    }

    /// Filter out disabled rules from YARA source.
    /// Returns the filtered source and the count of removed rules.
    pub(super) fn filter_disabled_rules(
        source: &str,
        namespace: &str,
        disabled_rules: &std::collections::HashSet<String>,
        re: &regex::Regex,
    ) -> (String, usize) {
        // Quick check: if no disabled rules, return as-is
        if disabled_rules.is_empty() {
            return (source.to_string(), 0);
        }

        let mut result = String::with_capacity(source.len());
        let mut last_end = 0;
        let mut removed = 0;

        // Find all rule starts and their positions
        let mut rule_ranges: Vec<(usize, usize, &str)> = Vec::new();
        for cap in re.captures_iter(source) {
            let (Some(rule_name_match), Some(rule_start_match)) = (cap.get(3), cap.get(0)) else {
                continue;
            };
            let rule_name = rule_name_match.as_str();
            let rule_start = rule_start_match.start();
            rule_ranges.push((rule_start, 0, rule_name)); // end will be filled later
        }

        // Fill in rule end positions (start of next rule or end of source)
        let range_starts: Vec<usize> = rule_ranges.iter().map(|r| r.0).collect();
        for (i, range) in rule_ranges.iter_mut().enumerate() {
            range.1 = range_starts.get(i + 1).copied().unwrap_or(source.len());
        }

        // Build filtered source
        for (start, end, rule_name) in rule_ranges {
            // Use trait_id format (third_party/vendor/...) for consistency with config
            let trait_id = crate::third_party_yara::derive_trait_id(namespace, rule_name);
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

    /// Strip individual rules that reference the VirusTotal module (`vt.`) from source.
    ///
    /// Returns the filtered source and the count of removed rules. Rules that don't
    /// reference `vt.` are preserved. This replaces the old whole-file skip which
    /// incorrectly dropped the entire YARAForge monolithic collection.
    pub(super) fn filter_vt_rules(source: &str, re: &regex::Regex) -> (String, usize) {
        let mut rule_ranges: Vec<(usize, usize)> = Vec::new();
        for cap in re.captures_iter(source) {
            let Some(rule_start_match) = cap.get(0) else {
                continue;
            };
            let rule_start = rule_start_match.start();
            rule_ranges.push((rule_start, 0));
        }

        if rule_ranges.is_empty() {
            return (source.to_string(), 0);
        }

        // Fill end positions: each rule ends where the next begins
        let vt_starts: Vec<usize> = rule_ranges.iter().map(|r| r.0).collect();
        for (i, range) in rule_ranges.iter_mut().enumerate() {
            range.1 = vt_starts.get(i + 1).copied().unwrap_or(source.len());
        }

        let mut result = String::with_capacity(source.len());
        let mut last_end = 0;
        let mut removed = 0;

        for (start, end) in &rule_ranges {
            let rule_text = &source[*start..*end];
            if rule_text.contains("vt.") {
                // Skip this rule, keep content before it
                if *start > last_end {
                    result.push_str(&source[last_end..*start]);
                }
                last_end = *end;
                removed += 1;
            }
        }

        if removed == 0 {
            return (source.to_string(), 0);
        }

        if last_end < source.len() {
            result.push_str(&source[last_end..]);
        }

        (result, removed)
    }
}
