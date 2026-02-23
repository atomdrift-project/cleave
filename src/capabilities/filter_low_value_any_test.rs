//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for filtering low-value composite "any" rules.

#[cfg(test)]
mod tests {
    use crate::capabilities::CapabilityMapper;
    use crate::composite_rules::{CompositeTrait, Condition};
    use crate::types::{Criticality, Evidence, Finding, FindingKind};

    /// Helper to create a test mapper with specific composite rules
    fn create_test_mapper_with_rules(rules: Vec<CompositeTrait>) -> CapabilityMapper {
        let mut mapper = CapabilityMapper::empty();
        mapper.composite_rules = rules;
        mapper
    }

    /// Helper to create a composite rule with `any` and optional `needs`
    fn create_any_rule(
        id: &str,
        conditions: Vec<Condition>,
        needs: Option<usize>,
    ) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "Test rule".to_string(),
            conf: 0.9,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            size_min: None,
            size_max: None,
            all: None,
            any: Some(conditions),
            needs,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        }
    }

    /// Helper to create a composite rule with `all` clause (not an "any" rule)
    fn create_all_rule(id: &str, conditions: Vec<Condition>) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "Test rule".to_string(),
            conf: 0.9,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            size_min: None,
            size_max: None,
            all: Some(conditions),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        }
    }

    /// Helper to create a test finding
    fn create_finding(id: &str) -> Finding {
        Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: id.to_string(),
            desc: "Test finding".to_string(),
            conf: 0.9,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            evidence: vec![],
            source_file: None,
        }
    }

    /// Helper to create a simple trait reference condition
    fn trait_ref(id: &str) -> Condition {
        Condition::Trait { id: id.to_string() }
    }

    #[test]
    fn test_is_low_value_any_rule_with_single_condition() {
        // Rule with only 1 condition in `any` should be filtered (low-value)
        let rules = vec![create_any_rule(
            "rule-single",
            vec![trait_ref("trait-a")],
            None, // needs unset, defaults to 1
        )];
        let mapper = create_test_mapper_with_rules(rules);

        assert!(
            mapper.is_low_value_any_rule("rule-single"),
            "Rule with single condition in `any` should be low-value"
        );
    }

    #[test]
    fn test_is_low_value_any_rule_with_needs_one() {
        // Rule with needs=1 should be filtered (low-value)
        let rules = vec![create_any_rule(
            "rule-needs-one",
            vec![
                trait_ref("trait-a"),
                trait_ref("trait-b"),
                trait_ref("trait-c"),
            ],
            Some(1),
        )];
        let mapper = create_test_mapper_with_rules(rules);

        assert!(
            mapper.is_low_value_any_rule("rule-needs-one"),
            "Rule with needs=1 should be low-value"
        );
    }

    #[test]
    fn test_is_low_value_any_rule_with_implicit_needs_one() {
        // Rule with multiple conditions but no `needs` (defaults to 1) should be filtered
        let rules = vec![create_any_rule(
            "rule-implicit-needs-one",
            vec![trait_ref("trait-a"), trait_ref("trait-b")],
            None, // defaults to 1
        )];
        let mapper = create_test_mapper_with_rules(rules);

        assert!(
            mapper.is_low_value_any_rule("rule-implicit-needs-one"),
            "Rule with implicit needs=1 should be low-value"
        );
    }

    #[test]
    fn test_is_not_low_value_any_rule_with_needs_two() {
        // Rule with needs=2 should NOT be filtered (adds value)
        let rules = vec![create_any_rule(
            "rule-needs-two",
            vec![
                trait_ref("trait-a"),
                trait_ref("trait-b"),
                trait_ref("trait-c"),
            ],
            Some(2),
        )];
        let mapper = create_test_mapper_with_rules(rules);

        assert!(
            !mapper.is_low_value_any_rule("rule-needs-two"),
            "Rule with needs=2 should NOT be low-value"
        );
    }

    #[test]
    fn test_is_not_low_value_any_rule_with_needs_three() {
        // Rule with needs=3 should NOT be filtered (adds value)
        let rules = vec![create_any_rule(
            "rule-needs-three",
            vec![
                trait_ref("trait-a"),
                trait_ref("trait-b"),
                trait_ref("trait-c"),
                trait_ref("trait-d"),
            ],
            Some(3),
        )];
        let mapper = create_test_mapper_with_rules(rules);

        assert!(
            !mapper.is_low_value_any_rule("rule-needs-three"),
            "Rule with needs=3 should NOT be low-value"
        );
    }

    #[test]
    fn test_is_not_low_value_all_rule() {
        // Rule with `all` clause (not `any`) should NOT be filtered
        let rules = vec![create_all_rule(
            "rule-all",
            vec![trait_ref("trait-a"), trait_ref("trait-b")],
        )];
        let mapper = create_test_mapper_with_rules(rules);

        assert!(
            !mapper.is_low_value_any_rule("rule-all"),
            "Rule with `all` clause should NOT be low-value"
        );
    }

    #[test]
    fn test_is_not_low_value_nonexistent_rule() {
        // Non-existent rule should NOT be filtered
        let rules = vec![create_any_rule(
            "rule-exists",
            vec![trait_ref("trait-a")],
            None,
        )];
        let mapper = create_test_mapper_with_rules(rules);

        assert!(
            !mapper.is_low_value_any_rule("rule-does-not-exist"),
            "Non-existent rule should NOT be filtered"
        );
    }

    #[test]
    fn test_filter_low_value_any_rules_removes_single_condition() {
        let rules = vec![create_any_rule(
            "low-value-single",
            vec![trait_ref("trait-a")],
            None,
        )];
        let mapper = create_test_mapper_with_rules(rules);

        let findings = vec![
            create_finding("low-value-single"),
            create_finding("other-finding"),
        ];

        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "other-finding");
    }

    #[test]
    fn test_filter_low_value_any_rules_removes_needs_one() {
        let rules = vec![create_any_rule(
            "low-value-needs-one",
            vec![trait_ref("trait-a"), trait_ref("trait-b")],
            Some(1),
        )];
        let mapper = create_test_mapper_with_rules(rules);

        let findings = vec![
            create_finding("low-value-needs-one"),
            create_finding("other-finding"),
        ];

        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "other-finding");
    }

    #[test]
    fn test_filter_low_value_any_rules_keeps_needs_two() {
        let rules = vec![create_any_rule(
            "valuable-needs-two",
            vec![
                trait_ref("trait-a"),
                trait_ref("trait-b"),
                trait_ref("trait-c"),
            ],
            Some(2),
        )];
        let mapper = create_test_mapper_with_rules(rules);

        let findings = vec![
            create_finding("valuable-needs-two"),
            create_finding("other-finding"),
        ];

        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|f| f.id == "valuable-needs-two"));
        assert!(filtered.iter().any(|f| f.id == "other-finding"));
    }

    #[test]
    fn test_filter_low_value_any_rules_keeps_all_rules() {
        let rules = vec![create_all_rule(
            "valuable-all",
            vec![trait_ref("trait-a"), trait_ref("trait-b")],
        )];
        let mapper = create_test_mapper_with_rules(rules);

        let findings = vec![
            create_finding("valuable-all"),
            create_finding("other-finding"),
        ];

        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|f| f.id == "valuable-all"));
        assert!(filtered.iter().any(|f| f.id == "other-finding"));
    }

    #[test]
    fn test_filter_low_value_any_rules_mixed_findings() {
        let rules = vec![
            create_any_rule("low-value-1", vec![trait_ref("trait-a")], None),
            create_any_rule(
                "low-value-2",
                vec![trait_ref("trait-b"), trait_ref("trait-c")],
                Some(1),
            ),
            create_any_rule(
                "valuable-1",
                vec![
                    trait_ref("trait-d"),
                    trait_ref("trait-e"),
                    trait_ref("trait-f"),
                ],
                Some(2),
            ),
            create_all_rule("valuable-2", vec![trait_ref("trait-g")]),
        ];
        let mapper = create_test_mapper_with_rules(rules);

        let findings = vec![
            create_finding("low-value-1"),
            create_finding("low-value-2"),
            create_finding("valuable-1"),
            create_finding("valuable-2"),
            create_finding("unrelated-finding"),
        ];

        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 3);
        assert!(!filtered.iter().any(|f| f.id == "low-value-1"));
        assert!(!filtered.iter().any(|f| f.id == "low-value-2"));
        assert!(filtered.iter().any(|f| f.id == "valuable-1"));
        assert!(filtered.iter().any(|f| f.id == "valuable-2"));
        assert!(filtered.iter().any(|f| f.id == "unrelated-finding"));
    }

    #[test]
    fn test_filter_low_value_any_rules_empty_findings() {
        let rules = vec![create_any_rule(
            "low-value",
            vec![trait_ref("trait-a")],
            None,
        )];
        let mapper = create_test_mapper_with_rules(rules);

        let findings = vec![];
        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_filter_low_value_any_rules_preserves_order() {
        let rules = vec![
            create_any_rule("low-value", vec![trait_ref("trait-a")], None),
            create_any_rule(
                "valuable",
                vec![trait_ref("trait-b"), trait_ref("trait-c")],
                Some(2),
            ),
        ];
        let mapper = create_test_mapper_with_rules(rules);

        let findings = vec![
            create_finding("finding-1"),
            create_finding("low-value"),
            create_finding("finding-2"),
            create_finding("valuable"),
            create_finding("finding-3"),
        ];

        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 4);
        assert_eq!(filtered[0].id, "finding-1");
        assert_eq!(filtered[1].id, "finding-2");
        assert_eq!(filtered[2].id, "valuable");
        assert_eq!(filtered[3].id, "finding-3");
    }

    #[test]
    fn test_filter_low_value_any_rules_handles_duplicates() {
        let rules = vec![create_any_rule(
            "low-value",
            vec![trait_ref("trait-a")],
            None,
        )];
        let mapper = create_test_mapper_with_rules(rules);

        // Multiple findings with same ID (shouldn't happen in practice, but test robustness)
        let findings = vec![
            create_finding("low-value"),
            create_finding("low-value"),
            create_finding("other-finding"),
        ];

        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "other-finding");
    }

    #[test]
    fn test_is_low_value_boundary_case_needs_zero() {
        // Edge case: needs=0 should be filtered (meaningless, but check it's handled)
        let rules = vec![create_any_rule(
            "rule-needs-zero",
            vec![trait_ref("trait-a"), trait_ref("trait-b")],
            Some(0),
        )];
        let mapper = create_test_mapper_with_rules(rules);

        assert!(
            mapper.is_low_value_any_rule("rule-needs-zero"),
            "Rule with needs=0 should be low-value"
        );
    }

    #[test]
    fn test_filter_preserves_finding_properties() {
        let rules = vec![create_any_rule(
            "valuable",
            vec![trait_ref("trait-a"), trait_ref("trait-b")],
            Some(2),
        )];
        let mapper = create_test_mapper_with_rules(rules);

        let original_finding = Finding {
            kind: FindingKind::Indicator,
            trait_refs: vec!["ref1".to_string(), "ref2".to_string()],
            id: "valuable".to_string(),
            desc: "Important finding".to_string(),
            conf: 0.95,
            crit: Criticality::Hostile,
            mbc: Some("B0030".to_string()),
            attack: Some("T1505".to_string()),
            evidence: vec![Evidence {
                method: "test".to_string(),
                source: "test".to_string(),
                value: "test-value".to_string(),
                location: None,
            }],
            source_file: Some("test.yaml".to_string()),
        };

        let findings = vec![original_finding.clone()];
        let filtered = mapper.filter_low_value_any_rules(findings);

        assert_eq!(filtered.len(), 1);
        let preserved = &filtered[0];
        assert_eq!(preserved.kind, original_finding.kind);
        assert_eq!(preserved.trait_refs, original_finding.trait_refs);
        assert_eq!(preserved.id, original_finding.id);
        assert_eq!(preserved.desc, original_finding.desc);
        assert_eq!(preserved.conf, original_finding.conf);
        assert_eq!(preserved.crit, original_finding.crit);
        assert_eq!(preserved.mbc, original_finding.mbc);
        assert_eq!(preserved.attack, original_finding.attack);
        assert_eq!(preserved.evidence.len(), original_finding.evidence.len());
        assert_eq!(preserved.source_file, original_finding.source_file);
    }
}
