use super::TraitDefinition;

#[test]
fn ceiling_filters_need_every_match() {
    let t = TraitDefinition {
        count_min: Some(3),
        count_max: Some(10),
        ..Default::default()
    };
    assert_eq!(t.match_count_bound(4096), usize::MAX);
    let t = TraitDefinition {
        per_kb_max: Some(1.0),
        ..Default::default()
    };
    assert_eq!(t.match_count_bound(4096), usize::MAX);
}

#[test]
fn floor_filters_bound_at_the_largest_floor() {
    let t = TraitDefinition::default();
    assert_eq!(t.match_count_bound(4096), 0);
    let mut t = TraitDefinition {
        count_min: Some(3),
        ..Default::default()
    };
    assert_eq!(t.match_count_bound(4096), 3);
    // 2.5 per KB over 4 KB needs 10; the density check must pass at the bound.
    t.per_kb_min = Some(2.5);
    let bound = t.match_count_bound(4096);
    assert_eq!(bound, 10);
    assert!((bound as f64) / 4.0 >= 2.5);
    assert!(((bound - 1) as f64) / 4.0 < 2.5);
    // A zero-byte file skips the density filter.
    assert_eq!(t.match_count_bound(0), 3);
}
