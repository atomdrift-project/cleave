//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for validation module.
//!
//! Tests are organized by submodule to match the module structure.

#[cfg(test)]
mod precision_tests;

#[cfg(test)]
mod duplicate_tests;

#[cfg(test)]
mod composite_tests;

#[cfg(test)]
mod pattern_tests;

#[cfg(test)]
mod taxonomy_tests;

#[cfg(test)]
mod constraint_tests;

#[cfg(test)]
mod autoprefix_tests;

#[cfg(test)]
mod excessive_skip_tests;

#[cfg(test)]
mod orphan_tests;

#[cfg(test)]
mod excessive_file_types_tests;

mod defaults_tests {
    use crate::capabilities::models::{RawCompositeRule, RawTraitDefinition, TraitDefaults};
    use crate::capabilities::validation::constraints::{
        find_redundant_explicit_defaults, find_should_use_defaults,
    };

    fn raw_trait(
        id: &str,
        platforms: Option<Vec<&str>>,
        file_types: Option<Vec<&str>>,
        mbc: Option<&str>,
        attack: Option<&str>,
    ) -> RawTraitDefinition {
        RawTraitDefinition {
            id: id.to_string(),
            desc: "test trait".to_string(),
            conf: None,
            crit: None,
            mbc: mbc.map(str::to_string),
            attack: attack.map(str::to_string),
            platforms: platforms.map(|v| v.into_iter().map(str::to_string).collect()),
            arch: None,
            file_types: file_types.map(|v| v.into_iter().map(str::to_string).collect()),
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            condition: None,
            not: None,
            unless: None,
            downgrade: None,
            ..Default::default()
        }
    }

    fn raw_composite(
        id: &str,
        platforms: Option<Vec<&str>>,
        file_types: Option<Vec<&str>>,
        mbc: Option<&str>,
        attack: Option<&str>,
    ) -> RawCompositeRule {
        RawCompositeRule {
            id: id.to_string(),
            desc: "test composite".to_string(),
            conf: None,
            crit: None,
            mbc: mbc.map(str::to_string),
            attack: attack.map(str::to_string),
            platforms: platforms.map(|v| v.into_iter().map(str::to_string).collect()),
            arch: None,
            file_types: file_types.map(|v| v.into_iter().map(str::to_string).collect()),
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            condition: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            unless: None,
            not: None,
            downgrade: None,
            ..Default::default()
        }
    }

    fn defaults(
        platforms: Option<Vec<&str>>,
        file_types: Option<Vec<&str>>,
        mbc: Option<&str>,
        attack: Option<&str>,
    ) -> TraitDefaults {
        TraitDefaults {
            exempt: Default::default(),
            r#for: file_types.map(|v| v.into_iter().map(str::to_string).collect()),
            platforms: platforms.map(|v| v.into_iter().map(str::to_string).collect()),
            arch: None,
            crit: None,
            conf: None,
            mbc: mbc.map(str::to_string),
            attack: attack.map(str::to_string),
            size_min: None,
            size_max: None,
            entropy_min: None,
            entropy_max: None,
        }
    }

    // --- find_should_use_defaults ---

    #[test]
    fn test_suggest_platforms_when_all_agree() {
        let traits = vec![
            raw_trait("t/a", Some(vec!["windows"]), None, None, None),
            raw_trait("t/b", Some(vec!["windows"]), None, None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert_eq!(result, vec![("platforms", "[windows]".to_string())]);
    }

    #[test]
    fn test_suggest_for_when_all_agree() {
        let traits = vec![
            raw_trait("t/a", None, Some(vec!["elf", "pe"]), None, None),
            raw_trait("t/b", None, Some(vec!["pe", "elf"]), None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        // Order-independent: both have [elf, pe] even though written in different order
        let fields: Vec<&str> = result.iter().map(|(f, _)| *f).collect();
        assert!(fields.contains(&"for"), "should suggest 'for' field");
    }

    #[test]
    fn test_suggest_mbc_when_all_agree() {
        let traits = vec![
            raw_trait("t/a", None, None, Some("OB0001"), None),
            raw_trait("t/b", None, None, Some("OB0001"), None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert_eq!(result, vec![("mbc", "OB0001".to_string())]);
    }

    #[test]
    fn test_suggest_attack_when_all_agree() {
        let traits = vec![
            raw_trait("t/a", None, None, None, Some("T1003")),
            raw_trait("t/b", None, None, None, Some("T1003")),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert_eq!(result, vec![("attack", "T1003".to_string())]);
    }

    #[test]
    fn test_no_suggestion_when_values_differ() {
        let traits = vec![
            raw_trait("t/a", Some(vec!["windows"]), None, None, None),
            raw_trait("t/b", Some(vec!["linux"]), None, None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_suggestion_when_one_trait_missing_field() {
        // t/b has no platforms → not all items agree
        let traits = vec![
            raw_trait("t/a", Some(vec!["windows"]), None, None, None),
            raw_trait("t/b", None, None, None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_suggestion_when_default_already_set() {
        let traits = vec![
            raw_trait("t/a", Some(vec!["windows"]), None, None, None),
            raw_trait("t/b", Some(vec!["windows"]), None, None, None),
        ];
        // Default already covers platforms — no suggestion needed
        let result = find_should_use_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_suggestion_for_single_item() {
        let traits = vec![raw_trait("t/a", Some(vec!["windows"]), None, None, None)];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert!(result.is_empty());
    }

    #[test]
    fn test_suggest_includes_composites() {
        let traits = vec![raw_trait("t/a", Some(vec!["windows"]), None, None, None)];
        let composites = vec![raw_composite(
            "c/a",
            Some(vec!["windows"]),
            None,
            None,
            None,
        )];
        let result =
            find_should_use_defaults(&traits, &composites, &defaults(None, None, None, None));
        assert_eq!(result, vec![("platforms", "[windows]".to_string())]);
    }

    #[test]
    fn test_suggest_platforms_case_insensitive() {
        // "Windows" and "windows" should be treated as the same value
        let traits = vec![
            raw_trait("t/a", Some(vec!["Windows"]), None, None, None),
            raw_trait("t/b", Some(vec!["windows"]), None, None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        let fields: Vec<&str> = result.iter().map(|(f, _)| *f).collect();
        assert!(
            fields.contains(&"platforms"),
            "case-insensitive match should still suggest"
        );
    }

    // --- find_redundant_explicit_defaults ---

    #[test]
    fn test_redundant_platforms_flagged() {
        let traits = vec![raw_trait("t/a", Some(vec!["windows"]), None, None, None)];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert_eq!(result, vec![("t/a".to_string(), "platforms")]);
    }

    #[test]
    fn test_redundant_for_flagged() {
        let traits = vec![raw_trait("t/a", None, Some(vec!["elf", "pe"]), None, None)];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(None, Some(vec!["pe", "elf"]), None, None),
        );
        assert_eq!(result, vec![("t/a".to_string(), "for")]);
    }

    #[test]
    fn test_redundant_mbc_flagged() {
        let traits = vec![raw_trait("t/a", None, None, Some("OB0001"), None)];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(None, None, Some("OB0001"), None),
        );
        assert_eq!(result, vec![("t/a".to_string(), "mbc")]);
    }

    #[test]
    fn test_redundant_attack_flagged() {
        let traits = vec![raw_trait("t/a", None, None, None, Some("T1003"))];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(None, None, None, Some("T1003")),
        );
        assert_eq!(result, vec![("t/a".to_string(), "attack")]);
    }

    #[test]
    fn test_not_redundant_when_value_differs() {
        let traits = vec![raw_trait("t/a", Some(vec!["linux"]), None, None, None)];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_not_redundant_when_no_default() {
        let traits = vec![raw_trait("t/a", Some(vec!["windows"]), None, None, None)];
        let result =
            find_redundant_explicit_defaults(&traits, &[], &defaults(None, None, None, None));
        assert!(result.is_empty());
    }

    #[test]
    fn test_redundant_composite_flagged() {
        let composites = vec![raw_composite(
            "c/a",
            Some(vec!["windows"]),
            None,
            None,
            None,
        )];
        let result = find_redundant_explicit_defaults(
            &[],
            &composites,
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert_eq!(result, vec![("c/a".to_string(), "platforms")]);
    }

    #[test]
    fn test_redundant_platforms_order_independent() {
        // Trait sets [linux, windows], default is [windows, linux] — same, so redundant
        let traits = vec![raw_trait(
            "t/a",
            Some(vec!["linux", "windows"]),
            None,
            None,
            None,
        )];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows", "linux"]), None, None, None),
        );
        assert_eq!(result, vec![("t/a".to_string(), "platforms")]);
    }

    #[test]
    fn test_only_redundant_traits_flagged_not_compliant_ones() {
        let traits = vec![
            raw_trait("t/redundant", Some(vec!["windows"]), None, None, None),
            raw_trait("t/different", Some(vec!["linux"]), None, None, None),
        ];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "t/redundant");
    }
}

#[cfg(test)]
mod section_filter_validation_tests;

#[cfg(test)]
mod string_literal_should_use_text_tests;

#[cfg(test)]
mod ast_function_call_should_use_symbol_tests;

#[cfg(test)]
mod brittle_path_pattern_tests;

#[cfg(test)]
mod exception_validation_tests;

#[cfg(test)]
mod wide_directory_tests;

/// Tests for [`find_bare_or_crit_escalations`]: a bare `any:` composite that
/// adds no filtering must agree with its legs about how serious a match is.
mod bare_or_crit_escalation_tests {
    use crate::capabilities::validation::find_bare_or_crit_escalations;
    use crate::composite_rules::traits::DowngradeConditions;
    use crate::composite_rules::{CompositeTrait, Condition, FileType, Platform, TraitDefinition};
    use crate::types::Criticality;

    /// A leaf trait at `crit`, scoped to `for_types` (empty = every type).
    fn leg(id: &str, crit: Criticality, for_types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leg".to_string(),
            crit,
            r#for: for_types,
            platforms: vec![Platform::All],
            ..Default::default()
        }
    }

    /// A composite whose whole logic is `any:` over `legs`.
    fn bare_or(id: &str, crit: Criticality, legs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "or".to_string(),
            crit,
            r#for: vec![],
            platforms: vec![Platform::All],
            any: Some(
                legs.iter()
                    .map(|l| Condition::Trait {
                        id: (*l).to_string(),
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    fn flagged_legs(
        traits: &[TraitDefinition],
        rules: &[CompositeTrait],
    ) -> Vec<(String, Criticality)> {
        let violations = find_bare_or_crit_escalations(traits, rules);
        assert!(violations.len() <= 1, "one rule under test: {violations:?}");
        violations
            .into_iter()
            .next()
            .map(|(_, _, l)| l)
            .unwrap_or_default()
    }

    #[test]
    fn under_ranked_legs_of_a_pure_relabelling_or_are_reported() {
        // The `offensive-tool-pdb` shape: one leg already carries the tier, the
        // other is promoted to it purely by being listed.
        let traits = vec![
            leg("d::metasploit", Criticality::Suspicious, vec![]),
            leg("d::cobalt", Criticality::Notable, vec![]),
        ];
        let rules = vec![bare_or(
            "d::offensive-pdb",
            Criticality::Suspicious,
            &["d::metasploit", "d::cobalt"],
        )];
        assert_eq!(
            flagged_legs(&traits, &rules),
            vec![("d::cobalt".to_string(), Criticality::Notable)],
            "only the leg below the composite is reported"
        );
    }

    #[test]
    fn legs_that_agree_with_the_composite_are_clean() {
        let traits = vec![
            leg("d::a", Criticality::Suspicious, vec![]),
            leg("d::b", Criticality::Suspicious, vec![]),
        ];
        let rules = vec![bare_or("d::or", Criticality::Suspicious, &["d::a", "d::b"])];
        assert!(flagged_legs(&traits, &rules).is_empty());
    }

    #[test]
    fn a_leg_above_the_composite_is_not_an_escalation() {
        // Demotion is a deliberate, separate choice; this validator is only
        // about a wrapper claiming more than its legs.
        let traits = vec![leg("d::a", Criticality::Hostile, vec![])];
        let rules = vec![bare_or("d::or", Criticality::Notable, &["d::a"])];
        assert!(flagged_legs(&traits, &rules).is_empty());
    }

    #[test]
    fn filtering_clauses_exempt_the_composite() {
        // `unless:`, `all:`, `needs:`, size and scope bounds all mean the
        // composite decides something its legs do not.
        let traits = vec![
            leg("d::a", Criticality::Component, vec![]),
            leg("d::b", Criticality::Component, vec![]),
        ];
        let base = bare_or("d::or", Criticality::Suspicious, &["d::a", "d::b"]);
        assert!(
            !flagged_legs(&traits, std::slice::from_ref(&base)).is_empty(),
            "the unfiltered form must flag, or the exemptions below prove nothing"
        );

        let with_unless = CompositeTrait {
            unless: Some(vec![Condition::Trait {
                id: "d::benign".to_string(),
            }]),
            ..base.clone()
        };
        assert!(
            flagged_legs(&traits, &[with_unless]).is_empty(),
            "unless: exempts"
        );

        let with_needs = CompositeTrait {
            needs: Some(2),
            ..base.clone()
        };
        assert!(
            flagged_legs(&traits, &[with_needs]).is_empty(),
            "needs: exempts"
        );

        let with_size = CompositeTrait {
            size_max: Some(4096),
            ..base.clone()
        };
        assert!(
            flagged_legs(&traits, &[with_size]).is_empty(),
            "size_max: exempts"
        );

        let with_downgrade = CompositeTrait {
            downgrade: Some(DowngradeConditions {
                any: Some(vec![Condition::Trait {
                    id: "d::benign".to_string(),
                }]),
                all: None,
                needs: None,
                scope: None,
            }),
            ..base.clone()
        };
        assert!(
            flagged_legs(&traits, &[with_downgrade]).is_empty(),
            "downgrade: exempts"
        );

        let with_all = CompositeTrait {
            all: Some(vec![Condition::Trait {
                id: "d::a".to_string(),
            }]),
            ..base
        };
        assert!(
            flagged_legs(&traits, &[with_all]).is_empty(),
            "all: exempts"
        );
    }

    #[test]
    fn a_different_for_scope_exempts_the_composite() {
        // Deciding *where* a leg counts is real work, and can earn a tier the
        // leg does not have everywhere. Exact agreement is required, so a
        // composite scoped differently from its leg — wider or narrower — is
        // left alone.
        let traits = vec![leg("d::a", Criticality::Notable, vec![])];
        let narrowed = CompositeTrait {
            r#for: vec![FileType::Elf],
            ..bare_or("d::or", Criticality::Suspicious, &["d::a"])
        };
        assert!(flagged_legs(&traits, &[narrowed]).is_empty());
    }

    #[test]
    fn a_rules_own_regex_split_legs_are_judged_like_any_other() {
        // Splitting an alternation into `--rx-N` legs is meant to give each
        // alternative a meaning of its own. A leg matching therefore says what
        // the reassembled composite says, so demoting the fragments below it is
        // the same laundering, arrived at mechanically.
        let traits = vec![
            leg("d::term--rx-1", Criticality::Component, vec![]),
            leg("d::term--rx-2", Criticality::Component, vec![]),
        ];
        let rules = vec![bare_or(
            "d::term",
            Criticality::Notable,
            &["d::term--rx-1", "d::term--rx-2"],
        )];
        assert_eq!(
            flagged_legs(&traits, &rules),
            vec![
                ("d::term--rx-1".to_string(), Criticality::Component),
                ("d::term--rx-2".to_string(), Criticality::Component),
            ]
        );
    }

    #[test]
    fn a_directory_leg_skips_the_whole_rule() {
        // "Raise every trait under this directory" is not a fix worth
        // prescribing, so the rule is not judged at all.
        let traits = vec![leg("d::a", Criticality::Component, vec![])];
        let rules = vec![bare_or(
            "d::or",
            Criticality::Suspicious,
            &["d::a", "d/sub"],
        )];
        assert!(flagged_legs(&traits, &rules).is_empty());
    }
}

/// `find_uncallable_symbol_matchers` — a `type: symbol` literal that no
/// extracted symbol can equal.
mod uncallable_symbol_matchers {
    use crate::capabilities::validation::find_uncallable_symbol_matchers;
    use crate::composite_rules::condition::{Condition, SymbolQuery};
    use crate::composite_rules::traits::TraitDefinition;
    use std::path::PathBuf;

    fn symbol_trait(id: &str, exact: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.8,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Symbol(SymbolQuery {
                exact: Some(exact.to_string()),
                ..Default::default()
            }),
            defined_in: PathBuf::from("test.yml"),
            ..Default::default()
        }
    }

    fn flagged(exact: &str) -> bool {
        !find_uncallable_symbol_matchers(&[symbol_trait("t", exact)], &[]).is_empty()
    }

    /// A symbol is a dotted path of identifiers, so any spelling of the call
    /// itself is dead on arrival — including the trailing `()` that reads as
    /// the natural way to write a call.
    #[test]
    fn call_syntax_is_flagged() {
        assert!(flagged(".system()"), "trailing call marker");
        assert!(flagged("open().read"), "inner call marker");
        assert!(flagged("open(\"/tmp/x\").read"), "argument text");
        assert!(flagged(".eval("), "half-open call");
    }

    /// `exact:`/`substr:` compare literally, so a regex there matches nothing.
    #[test]
    fn regex_in_a_literal_field_is_flagged() {
        assert!(flagged("os\\.environ"), "escaped dot");
        assert!(flagged("os\\.environ\\[.{0,50}\\]"), "character class");
        assert!(flagged("clone|rename"), "alternation");
        assert!(flagged("^setup"), "anchor");
    }

    /// Names that really do occur must not be flagged. Go binaries export the
    /// receiver form; PE ordinal imports are named `ORDINAL <n>`; C++ has
    /// `operator delete`; and `$` is a legal JavaScript identifier character.
    #[test]
    fn real_symbol_names_are_left_alone() {
        for name in [
            "net.(*Dialer).Dial",
            "exec.(*Cmd).Run",
            "ORDINAL 187",
            "operator delete",
            "platform.system",
            "Date.getTimezoneOffset",
            "$",
            "jQuery$",
            "__import__.decompress",
            "s.replace.replace",
        ] {
            assert!(
                !flagged(name),
                "{name:?} is a real symbol and must not flag"
            );
        }
    }
}

/// `find_stale_filetype_allowlist_entries` — an allowlist entry whose
/// directory prefix matches no trait.
mod stale_filetype_allowlist {
    use crate::capabilities::validation::find_stale_filetype_allowlist_entries;
    use crate::capabilities::validation::taxonomy::BROAD_FILETYPE_ALLOWLIST;
    use std::collections::HashMap;

    /// Every shipped entry must match a real directory. When one does not, the
    /// exemption it encodes is silently gone -- the usual cause is a directory
    /// renamed without updating the entry, and the symptom is a pile of
    /// file-type cap violations nowhere near the rename.
    #[test]
    fn shipped_entries_all_match_a_real_directory() {
        // Stand in for the loaded taxonomy: one source path per entry prefix.
        let sources: HashMap<String, String> = BROAD_FILETYPE_ALLOWLIST
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                e.split_once(':').map(|(_, p)| {
                    (
                        format!("t{i}"),
                        if p.ends_with(".yaml") || p.ends_with(".yml") {
                            format!("./{p}")
                        } else {
                            format!("./{p}traits.yaml")
                        },
                    )
                })
            })
            .collect();
        assert!(
            find_stale_filetype_allowlist_entries(&sources).is_empty(),
            "every entry should match when each prefix has a source file"
        );
    }

    /// With no traits at all, every entry is stale — the check is actually
    /// looking at the sources rather than always passing.
    #[test]
    fn every_entry_is_stale_when_nothing_matches() {
        let empty: HashMap<String, String> = HashMap::new();
        assert_eq!(
            find_stale_filetype_allowlist_entries(&empty).len(),
            BROAD_FILETYPE_ALLOWLIST.len()
        );
    }

    /// A prefix that no longer exists is reported while its neighbours are not.
    /// Entries are type-qualified, so one path can appear under several
    /// matcher types; dropping the path makes every one of them stale.
    #[test]
    fn only_the_unmatched_prefix_is_reported() {
        let prefix_of = |e: &str| e.split_once(':').map(|(_, prefix)| prefix.to_owned());
        let dropped = BROAD_FILETYPE_ALLOWLIST
            .iter()
            .find_map(|e| prefix_of(e))
            .expect("at least one entry");
        let mut sources: HashMap<String, String> = HashMap::new();
        for (i, e) in BROAD_FILETYPE_ALLOWLIST.iter().enumerate() {
            let Some(prefix) = prefix_of(e).filter(|p| *p != dropped) else {
                continue;
            };
            sources.insert(
                format!("t{i}"),
                if prefix.ends_with(".yaml") || prefix.ends_with(".yml") {
                    format!("./{prefix}")
                } else {
                    format!("./{prefix}traits.yaml")
                },
            );
        }
        let stale = find_stale_filetype_allowlist_entries(&sources);
        let expected: Vec<&str> = BROAD_FILETYPE_ALLOWLIST
            .iter()
            .copied()
            .filter(|e| prefix_of(e).as_deref() == Some(dropped.as_str()))
            .collect();
        assert_eq!(
            stale, expected,
            "only the dropped prefix {dropped} must be flagged"
        );
    }
}

#[cfg(test)]
mod archive_filetype_mix_tests;

#[cfg(test)]
mod dead_composite_tests;

#[cfg(test)]
mod unbindable_package_scope_tests;

#[cfg(test)]
mod pooling_scope_container_tests;

#[cfg(test)]
mod legs_outside_for_tests;

#[cfg(test)]
mod leg_role_tests;

#[cfg(test)]
mod one_fact_conviction_tests;

#[cfg(test)]
mod one_fact_evidence_boundary_tests;

#[cfg(test)]
mod reference_index_tests;

#[cfg(test)]
mod convictions_without_content_tests;

#[cfg(test)]
mod platform_breadth_review_tests;

#[cfg(test)]
mod all_platform_directory_tests;
