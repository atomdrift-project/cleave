//! The slow-rule audit of `cleave validate --slow-rules`: the rules that cost
//! the most evaluation time over a full, uncached validation, with the shape
//! of their conditions, so a cheaper equivalent can be chosen.

use crate::composite_rules::trait_timing;
use cleave::CapabilityMapper;
use serde::Serialize;
use std::fmt::Write as _;

#[derive(Serialize)]
pub(super) struct Audit {
    /// Distinct rules that were evaluated at least once.
    pub(super) rules_timed: usize,
    /// Rule time over every rule, in milliseconds of thread time.
    pub(super) total_ms: u64,
    pub(super) slowest: Vec<SlowRule>,
}

#[derive(Serialize)]
pub(super) struct SlowRule {
    pub(super) id: String,
    pub(super) total_ms: u64,
    pub(super) evals: u64,
    pub(super) mean_us: u64,
    pub(super) max_ms: u64,
    /// Share of all rule time, in percent.
    pub(super) share: f64,
    pub(super) r#for: String,
    pub(super) conditions: String,
    pub(super) defined_in: String,
}

/// The top `n` rules by total evaluation time recorded so far.
pub(super) fn audit(mapper: &CapabilityMapper, n: usize) -> Audit {
    let totals = trait_timing::totals();
    let shapes = mapper.rule_shapes();
    let total_nanos: u64 = totals.iter().map(|(_, t)| t.nanos).sum();
    let slowest = totals
        .iter()
        .take(n)
        .map(|(id, total)| {
            let shape = shapes.get(id);
            SlowRule {
                id: id.clone(),
                total_ms: total.nanos / 1_000_000,
                evals: total.evals,
                mean_us: total.nanos / total.evals.max(1) / 1_000,
                max_ms: total.max_nanos / 1_000_000,
                share: if total_nanos == 0 {
                    0.0
                } else {
                    total.nanos as f64 * 100.0 / total_nanos as f64
                },
                r#for: shape.map_or_else(|| "?".to_owned(), |s| s.r#for.clone()),
                conditions: shape.map_or_else(|| "?".to_owned(), |s| s.conditions.clone()),
                defined_in: shape.map_or_else(|| "?".to_owned(), |s| s.defined_in.clone()),
            }
        })
        .collect();
    Audit {
        rules_timed: totals.len(),
        total_ms: total_nanos / 1_000_000,
        slowest,
    }
}

impl Audit {
    /// A terminal table, slowest first.
    pub(super) fn table(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Slowest rules by total evaluation time ({} rules timed, {:.1}s of rule time):",
            self.rules_timed,
            self.total_ms as f64 / 1000.0
        );
        out.push_str(
            "   #  total_ms   evals  mean_us   max_ms  share  rule
",
        );
        for (i, rule) in self.slowest.iter().enumerate() {
            let _ = writeln!(
                out,
                "{:>4} {:>9} {:>7} {:>8} {:>8} {:>5.1}%  {}",
                i + 1,
                rule.total_ms,
                rule.evals,
                rule.mean_us,
                rule.max_ms,
                rule.share,
                rule.id
            );
            let _ = writeln!(
                out,
                "{:>4} {:>9} for: {}  if: {}",
                "", "", rule.r#for, rule.conditions
            );
            let _ = writeln!(out, "{:>4} {:>9} {}", "", "", rule.defined_in);
        }
        out
    }
}
