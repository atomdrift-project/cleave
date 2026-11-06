use super::*;
use crate::types::{Criticality, MetricChange, ScopeDiff};

#[test]
fn metric_direction_arrows() {
    let scope: ScopeDiff<MetricChange> = ScopeDiff {
        changed: vec![
            Changed {
                old: MetricChange {
                    path: "x".into(),
                    value: Value::from(10),
                },
                new: MetricChange {
                    path: "x".into(),
                    value: Value::from(20),
                },
            },
            Changed {
                old: MetricChange {
                    path: "y".into(),
                    value: Value::from(20),
                },
                new: MetricChange {
                    path: "y".into(),
                    value: Value::from(10),
                },
            },
        ],
        old_count: 2,
        new_count: 2,
        old_weight: 2.0,
        new_weight: 2.0,
        change_weight: 0.5,
        roc: 0.25,
        truncated: false,
        ..Default::default()
    };
    let _ = Criticality::Baseline; // silence unused import (tests/imports stay tidy)
    let mut out = String::new();
    write_metrics(&mut out, &scope);
    assert!(out.contains('↑'));
    assert!(out.contains('↓'));
    assert!(!out.contains(" ~ "));
}
