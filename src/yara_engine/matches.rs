//! Building findings from yara-x matches.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl YaraEngine {
    /// Build a `YaraMatch` from raw match data collected during scanning.
    /// Returns `None` if the rule is an inline trait rule (those go into `inline_results`).
    pub(super) fn build_yara_match(
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
        let mut crit = crate::types::Criticality::Baseline;
        let mut capability_flag = false;
        let mut mbc_code: Option<String> = None;
        let mut attack_code: Option<String> = None;
        let mut rule_filetypes: Vec<String> = Vec::new();
        let mut filetype_source = "none".to_string(); // tracks where the filetype came from
        let mut os_meta: Option<String> = None;
        let mut arch_context_meta: Option<String> = None;
        let mut metadata_hint_text = String::new();
        // Kept for the description fallback below: whole rule sets carry a
        // family label but no `description` meta.
        let mut threat_name_meta: Option<String> = None;
        let mut family_meta: Option<String> = None;

        for tag_name in tags {
            if matches!(
                tag_name.as_str(),
                "baseline" | "notable" | "suspicious" | "hostile"
            ) && let Ok(tagged) = tag_name.parse::<crate::types::Criticality>()
            {
                crit = tagged;
                break;
            }
        }

        let is_third_party = namespace.starts_with("3p.");
        if is_third_party {
            crit = crate::types::Criticality::Suspicious;
        }

        for (key, value_str) in metadata {
            let value_str = value_str.clone();

            match key.as_str() {
                "description" => description = value_str,
                "risk" if !is_third_party => match value_str.parse::<crate::types::Criticality>() {
                    Ok(risk) => crit = risk,
                    Err(error) => tracing::warn!(
                        rule = %rule_name,
                        %namespace,
                        %error,
                        "ignoring invalid YARA risk metadata"
                    ),
                },
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
                    filetype_source = "metadata".to_string();
                }
                "os" => os_meta = Some(value_str.to_lowercase()),
                "arch_context" => arch_context_meta = Some(value_str.to_lowercase()),
                "source_url" | "reference" | "category" | "classification" | "threat_name"
                | "scan_context" | "tags" => {
                    if key == "threat_name" {
                        threat_name_meta = Some(value_str.clone());
                    }
                    if !metadata_hint_text.is_empty() {
                        metadata_hint_text.push(' ');
                    }
                    metadata_hint_text.push_str(&value_str);
                }
                "malware_family" | "family" => {
                    family_meta = Some(value_str);
                }
                _ => {}
            }
        }

        let context_key = rule_context_key(&namespace, &rule_name);
        let precompiled_context = self.rule_contexts.get(&context_key);

        if let Some(ctx) = precompiled_context {
            if !ctx.filetypes.is_empty() {
                rule_filetypes = ctx.filetypes.clone();
                filetype_source = format!("precompiled-{}", ctx.filetype_source);
            }
            if arch_context_meta.is_none() {
                arch_context_meta = ctx.arch_context.clone();
            }
            if !ctx.platforms.is_empty() {
                tracing::debug!(
                    rule = %rule_name,
                    namespace = %namespace,
                    platforms = ?ctx.platforms,
                    "YARA rule platform association"
                );
            }
        } else {
            // Infer filetypes from explicit rule tags (e.g., `: PE`, `: ELF`, `: PHP`)
            if rule_filetypes.is_empty() {
                let inferred = yara_classify::infer_filetypes_from_tags(tags);
                if !inferred.is_empty() {
                    rule_filetypes = inferred
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    filetype_source = "tag".to_string();
                }
            }

            if rule_filetypes.is_empty() {
                let inferred =
                    yara_classify::infer_filetypes_from_metadata_text(&metadata_hint_text);
                if !inferred.is_empty() {
                    rule_filetypes = inferred
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    filetype_source = "metadata-text".to_string();
                }
            }

            if rule_filetypes.is_empty() {
                let inferred = yara_classify::infer_filetypes(&rule_name, os_meta.as_deref());
                if !inferred.is_empty() {
                    rule_filetypes = inferred
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    filetype_source = "rule-name".to_string();
                }
            }

            // For third-party rules: if still no filetype, try the namespace filename component.
            if rule_filetypes.is_empty() && is_third_party {
                let inferred =
                    yara_classify::infer_filetypes_from_namespace(&namespace, os_meta.as_deref());
                if !inferred.is_empty() {
                    rule_filetypes = inferred
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect();
                    filetype_source = "namespace".to_string();
                }
            }
        }

        // Log filetype association for verbose output
        crate::third_party_yara::log_filetype_association(
            &rule_name,
            &namespace,
            &rule_filetypes,
            &filetype_source,
        );

        if let Some(filter_types) = file_type_filter
            && !rule_filetypes.is_empty()
        {
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
                &namespace, &rule_name,
            ))
        } else {
            None
        };

        // Apply config-based criticality for third-party rules
        // Returns None if the rule is disabled via config
        if is_third_party {
            // Returns None (via `?`) if the rule is disabled via config.
            crit = crate::third_party_config::third_party_criticality(
                &namespace,
                trait_id.as_deref(),
            )?;
            if let Some(desc) = trait_id
                .as_deref()
                .and_then(crate::third_party_config::third_party_description)
            {
                description = desc.to_owned();
            }
        }

        // Not every rule set writes a `description`. Elastic's, for one, labels
        // 3084 rules with `threat_name` and gives fewer than half of them a
        // description — and third-party rules are graded hostile by default, so
        // the rest surfaced as a red verdict above a blank line, which is the
        // least useful thing a triage tool can print. Fall back through the
        // labels a rule set does carry, and last of all name the rule itself:
        // any of these tells the reader more than nothing.
        if description.trim().is_empty() {
            description = match (&threat_name_meta, &family_meta) {
                (Some(t), _) if !t.trim().is_empty() => format!("Detects {t}"),
                (_, Some(f)) if !f.trim().is_empty() => format!("Detects {f}"),
                _ => format!("YARA rule {rule_name}"),
            };
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
}
