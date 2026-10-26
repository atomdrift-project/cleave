//! Measured rule costs during fresh validation. Normal scans only check a flag.
use crate::analyzers::ast_walker::thread_cpu_time;
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
use crate::validation_controls::{self, ValidationIssue};
use parking_lot::Mutex;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) const VALIDATOR: &str = "rule-performance";
static ACTIVE: AtomicBool = AtomicBool::new(false);
static ISSUES: Mutex<BTreeMap<(String, String), ValidationIssue>> = Mutex::new(BTreeMap::new());

static QUERY_COSTS: Mutex<BTreeMap<(String, bool), BTreeMap<String, Duration>>> =
    Mutex::new(BTreeMap::new());
thread_local! {
    static QUERY_RUNS: Cell<u64> = const { Cell::new(0) };
    static QUERY_EXECUTION_COST: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static PROBING_AST: Cell<bool> = const { Cell::new(false) };
    static PROBE_COST: Cell<Option<Duration>> = const { Cell::new(None) };
    static PROBE_CPU: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

/// Time only cursor execution for relative comparisons. Cold compilation and
/// literal/kind gates have different costs across query shapes; the whole-rule
/// deadline still includes them, but they must not distort execution peers.
pub(crate) fn ast_execution_started() -> Option<ExecutionTimer> {
    active().then(|| {
        if !PROBING_AST.with(Cell::get) {
            QUERY_RUNS.with(|n| n.set(n.get().wrapping_add(1)));
        }
        ExecutionTimer {
            cpu: thread_cpu_time(),
            wall: Instant::now(),
        }
    })
}

pub(crate) struct ExecutionTimer {
    cpu: Duration,
    wall: Instant,
}
impl Drop for ExecutionTimer {
    fn drop(&mut self) {
        let elapsed = if self.cpu.is_zero() {
            self.wall.elapsed()
        } else {
            thread_cpu_time().saturating_sub(self.cpu)
        };
        if PROBING_AST.with(Cell::get) {
            PROBE_COST.with(|cost| cost.set(Some(elapsed)));
        } else {
            QUERY_EXECUTION_COST.with(|cost| cost.set(cost.get().saturating_add(elapsed)));
        }
    }
}

/// Relative timing uses confirmed execution cost. One cold allocation or
/// contended cache lookup must not turn an otherwise identical query into an
/// outlier. Confirmation never replaces the original detection result.
pub(crate) fn ast_cost_snapshot() -> Option<Duration> {
    (active() && !PROBING_AST.with(Cell::get)).then(|| QUERY_EXECUTION_COST.with(Cell::get))
}

pub(crate) fn ast_confirmation_fence(path: &str) -> Option<Duration> {
    let mode = crate::composite_rules::evaluators::symbol_string::match_count_needed();
    QUERY_COSTS
        .lock()
        .get(&(path.to_owned(), mode))
        .and_then(outlier_fence)
        .map(|(_, fence)| fence)
}

pub(crate) fn confirm_ast_cost(original: Duration, confirmed: Duration) {
    QUERY_EXECUTION_COST.with(|cost| {
        cost.set(
            cost.get()
                .saturating_sub(original.saturating_sub(confirmed)),
        )
    });
}

pub(crate) struct AstProbe {
    cpu: Duration,
    wall: Instant,
    previous: bool,
}
impl AstProbe {
    pub(crate) fn begin() -> Self {
        PROBE_COST.with(|cost| cost.set(None));
        Self {
            cpu: thread_cpu_time(),
            wall: Instant::now(),
            previous: PROBING_AST.with(|flag| flag.replace(true)),
        }
    }
    pub(crate) fn cost(&self) -> Option<Duration> {
        PROBE_COST.with(Cell::get)
    }
}
impl Drop for AstProbe {
    fn drop(&mut self) {
        let elapsed = if self.cpu.is_zero() {
            self.wall.elapsed()
        } else {
            thread_cpu_time().saturating_sub(self.cpu)
        };
        PROBE_CPU.with(|cost| cost.set(cost.get().saturating_add(elapsed)));
        PROBING_AST.with(|flag| flag.set(self.previous));
    }
}

pub(crate) struct QueryTimer<'a> {
    id: &'a str,
    path: &'a str,
    runs: u64,
    full_count: bool,
    execution_cost: Duration,
}
impl<'a> QueryTimer<'a> {
    pub(crate) fn start(id: &'a str, ctx: &'a EvaluationContext<'_>) -> Option<Self> {
        active().then(|| Self {
            id,
            path: &ctx.report.target.path,
            runs: QUERY_RUNS.with(Cell::get),
            full_count: crate::composite_rules::evaluators::symbol_string::match_count_needed(),
            execution_cost: QUERY_EXECUTION_COST.with(Cell::get),
        })
    }
}
impl Drop for QueryTimer<'_> {
    fn drop(&mut self) {
        if self.runs == QUERY_RUNS.with(Cell::get) {
            return;
        }
        let elapsed = QUERY_EXECUTION_COST
            .with(Cell::get)
            .saturating_sub(self.execution_cost);
        let mut costs = QUERY_COSTS.lock();
        let cost = costs
            .entry((self.path.to_owned(), self.full_count))
            .or_default()
            .entry(self.id.to_owned())
            .or_default();
        *cost = (*cost).max(elapsed);
        drop(costs);
    }
}

/// A conservative relative fence: at least eight executed queries on the same
/// fixture and with the same boolean/full-count mode, and both 20 times their median and 20 median absolute deviations.
/// No elapsed-time constant: scaling every query equally preserves the verdict.
fn outlier_fence(costs: &BTreeMap<String, Duration>) -> Option<(Duration, Duration)> {
    if costs.len() < 8 {
        return None;
    }
    let mut ns: Vec<_> = costs.values().map(Duration::as_nanos).collect();
    ns.sort_unstable();
    let median = ns[ns.len() / 2];
    let mut deviations: Vec<_> = ns.iter().map(|n| n.abs_diff(median)).collect();
    deviations.sort_unstable();
    let mad = deviations[deviations.len() / 2];
    let fence = (median.saturating_mul(20)).max(median.saturating_add(mad.saturating_mul(20)));
    let duration = |n: u128| Duration::from_nanos(n.min(u128::from(u64::MAX)) as u64);
    Some((duration(median), duration(fence)))
}

pub(crate) fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Full-validation cache hits may reuse a previously measured pass. Fresh
/// validation must execute rules, including queries otherwise hidden by a batch.
pub(crate) struct Session;
impl Session {
    pub(crate) fn begin() -> Self {
        ISSUES.lock().clear();
        QUERY_COSTS.lock().clear();
        ACTIVE.store(
            !validation_controls::is_validator_disabled(VALIDATOR),
            Ordering::Relaxed,
        );
        Self
    }

    pub(crate) fn issues(&self) -> Vec<ValidationIssue> {
        let mut issues = ISSUES.lock().clone();
        for ((path, _full_count), costs) in QUERY_COSTS.lock().iter() {
            let Some((median, fence)) = outlier_fence(costs) else {
                continue;
            };
            for (id, &cost) in costs {
                if cost > fence {
                    issues.entry((id.clone(), path.clone())).or_insert_with(|| issue(id, path,
                        &format!("AST query cost is an extreme outlier: {}us; peer median {}us, relative fence {}us ({} executed queries)",
                            cost.as_micros(), median.as_micros(), fence.as_micros(), costs.len())));
                }
            }
        }
        issues.into_values().collect()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Relaxed);
        ISSUES.lock().clear();
        QUERY_COSTS.lock().clear();
    }
}

fn issue(id: &str, path: &str, detail: &str) -> ValidationIssue {
    let mut issue = ValidationIssue::new(VALIDATOR, format!("rule '{id}' on '{path}': {detail}"));
    issue.rule_id = Some(id.to_owned());
    issue
}

fn record(id: &str, path: &str, issue: ValidationIssue) {
    ISSUES
        .lock()
        .insert((id.to_owned(), path.to_owned()), issue);
}

/// Covers positive, unless, downgrade, and early-return paths. CPU time avoids
/// charging a rule for OS descheduling; unsupported clocks fall back to wall time.
pub(crate) struct RuleTimer<'a> {
    id: &'a str,
    path: &'a str,
    source: &'a Path,
    threshold: Duration,
    probe_cpu: Duration,
    cpu: Duration,
    wall: Instant,
}
impl<'a> RuleTimer<'a> {
    pub(crate) fn start(
        id: &'a str,
        source: &'a Path,
        ctx: &'a EvaluationContext<'_>,
    ) -> Option<Self> {
        active().then(|| Self {
            id,
            path: &ctx.report.target.path,
            source,
            threshold: Duration::from_millis(ctx.slow_rule_ms),
            probe_cpu: PROBE_CPU.with(Cell::get),
            cpu: thread_cpu_time(),
            wall: Instant::now(),
        })
    }
}
impl Drop for RuleTimer<'_> {
    fn drop(&mut self) {
        let elapsed = if self.cpu.is_zero() {
            self.wall.elapsed()
        } else {
            thread_cpu_time().saturating_sub(self.cpu)
        };
        let elapsed =
            elapsed.saturating_sub(PROBE_CPU.with(Cell::get).saturating_sub(self.probe_cpu));
        if elapsed > self.threshold {
            let problem = issue(
                self.id,
                self.path,
                &format!(
                    "evaluation took {}ms (slow-rule threshold {}ms)",
                    elapsed.as_millis(),
                    self.threshold.as_millis()
                ),
            )
            .with_location(self.source.display().to_string(), None);
            record(self.id, self.path, problem);
        }
    }
}

pub(crate) fn observe_result(id: &str, path: &str, result: &ConditionResult) {
    if !active() {
        return;
    }
    // A bounded query must not appear fast simply because its safety ceiling
    // cut the work short, even when that ceiling is below --slow-rule-ms.
    for warning in &result.warnings {
        let reason = match warning {
            AnalysisWarning::AstTooDeep { max_depth: 0 } => "AST query exhausted its CPU budget",
            AnalysisWarning::AstQueryLimited { .. } => {
                "AST query exhausted its match/state/capture budget"
            }
            _ => continue,
        };
        record(id, path, issue(id, path, reason));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn outliers_are_relative_and_require_comparable_peers() {
        let costs = |scale: u64| {
            (0..9)
                .map(|i| {
                    (
                        i.to_string(),
                        Duration::from_nanos(scale * if i == 8 { 1000 } else { 10 + i }),
                    )
                })
                .collect()
        };
        for scale in [1, 1000, 1_000_000] {
            let values = costs(scale);
            let (_, fence) = outlier_fence(&values).unwrap();
            let flagged: Vec<_> = values
                .iter()
                .filter(|(_, cost)| **cost > fence)
                .map(|(id, _)| id.as_str())
                .collect();
            assert_eq!(flagged, ["8"]);
        }
        assert!(outlier_fence(&BTreeMap::new()).is_none());
        let uniform = (0..9)
            .map(|i| (i.to_string(), Duration::from_secs(1)))
            .collect();
        let (_, fence) = outlier_fence(&uniform).unwrap();
        assert!(uniform.values().all(|cost| *cost <= fence));
    }

    #[test]
    fn performance_is_soft_and_uses_standard_severity_policy() {
        let p = issue("rule", "fixture.js", "too slow");
        assert_eq!(p.severity, validation_controls::Severity::Soft);
        assert!(p.severity >= validation_controls::Severity::Soft);
        assert!(p.severity < validation_controls::Severity::Hard);
    }
}
