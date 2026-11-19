//! Measured rule costs during fresh validation. Normal scans only check a flag.
use crate::analyzers::ast_walker::thread_cpu_time;
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
#[cfg(feature = "lint")]
use crate::validation_controls;
use crate::validation_controls::ValidationIssue;
use parking_lot::Mutex;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

pub(crate) const VALIDATOR: &str = "rule-performance";
/// Read by every condition evaluation of every scan, so it gets a cache line
/// of its own: the statics linked next to it include per-member counters
/// that other workers write.
#[repr(align(128))]
struct ActiveFlag(AtomicBool);
static ACTIVE: ActiveFlag = ActiveFlag(AtomicBool::new(false));
static ISSUES: Mutex<BTreeMap<(String, String), ValidationIssue>> = Mutex::new(BTreeMap::new());

/// A peer group: each rule's costliest AST query is judged only against the
/// other queries in its group (see [`outlier_fence`]).
///
/// A file is its path and content hash: archive members are named by their
/// path inside the archive, and two fixtures can both hold an
/// `extension/out/extension.js` that share nothing else -- keyed by path
/// alone, one fixture's cold cost landed on the other's confirmed record and
/// its peers became the other file's queries.
///
/// Anchored and unanchored queries are separate groups. An anchored query
/// runs only at the few nodes its literal occurs under and costs tens of
/// microseconds; an unanchored one visits the whole tree, about 2ms on a
/// 100KB bundle. Pooled, the anchored majority set the median and every
/// unanchored query sat at the 40x fence, so which of them failed was
/// decided by machine load.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CostKey {
    path: String,
    sha256: String,
    full_count: bool,
    anchored: bool,
}

/// Per peer group, each rule's costliest AST query: the query text, so the
/// file's outliers can be run again (see [`confirm_outliers`]), and what it
/// cost.
type CostGroups = BTreeMap<CostKey, BTreeMap<Arc<str>, QueryCost>>;

#[derive(Default)]
struct QueryCosts {
    groups: CostGroups,
    // Every fixture normally measures many of the same rules. Keep the text
    // once and retain only references alongside each fixture's timings.
    names: rustc_hash::FxHashSet<Arc<str>>,
}

static QUERY_COSTS: LazyLock<Mutex<QueryCosts>> = LazyLock::new(Mutex::default);

fn intern(names: &mut rustc_hash::FxHashSet<Arc<str>>, text: &str) -> Arc<str> {
    if let Some(name) = names.get(text) {
        return Arc::clone(name);
    }
    let name: Arc<str> = text.into();
    names.insert(Arc::clone(&name));
    name
}

struct QueryCost {
    cost: Duration,
    query: Arc<str>,
    /// Run again under [`confirm_outliers`]; `cost` is the lowest seen.
    confirmed: bool,
}

/// What the outlier fence reads from a recorded cost.
trait MeasuredCost {
    fn cost(&self) -> Duration;
}
impl MeasuredCost for QueryCost {
    fn cost(&self) -> Duration {
        self.cost
    }
}
impl MeasuredCost for Duration {
    fn cost(&self) -> Duration {
        *self
    }
}
thread_local! {
    static QUERY_RUNS: Cell<u64> = const { Cell::new(0) };
    /// Query runs that visited the tree without anchored roots.
    static UNANCHORED_RUNS: Cell<u64> = const { Cell::new(0) };
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

/// Note that the query run under way visits the tree without anchored roots,
/// so its cost is judged among the file's other unanchored queries.
pub(crate) fn note_unanchored_run() {
    if active() && !PROBING_AST.with(Cell::get) {
        UNANCHORED_RUNS.with(|n| n.set(n.get().wrapping_add(1)));
    }
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
    query: &'a str,
    path: &'a str,
    sha256: &'a str,
    runs: u64,
    unanchored_runs: u64,
    full_count: bool,
    execution_cost: Duration,
}
impl<'a> QueryTimer<'a> {
    pub(crate) fn start(
        id: &'a str,
        query: &'a str,
        ctx: &'a EvaluationContext<'_>,
    ) -> Option<Self> {
        judges(query, ctx).then(|| Self {
            id,
            query,
            path: &ctx.report.target.path,
            sha256: &ctx.report.target.sha256,
            runs: QUERY_RUNS.with(Cell::get),
            unanchored_runs: UNANCHORED_RUNS.with(Cell::get),
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
        let key = CostKey {
            path: self.path.to_owned(),
            sha256: self.sha256.to_owned(),
            full_count: self.full_count,
            anchored: self.unanchored_runs == UNANCHORED_RUNS.with(Cell::get),
        };
        record_cost(&mut QUERY_COSTS.lock(), key, self.id, self.query, elapsed);
    }
}

/// Keep `id`'s costliest query in its peer group.
fn record_cost(costs: &mut QueryCosts, key: CostKey, id: &str, query: &str, elapsed: Duration) {
    let rules = costs.groups.entry(key).or_default();
    match rules.get_mut(id) {
        Some(cost) if cost.cost >= elapsed => {}
        Some(cost) => {
            cost.cost = elapsed;
            cost.query = intern(&mut costs.names, query);
            cost.confirmed = false;
        }
        None => {
            rules.insert(
                intern(&mut costs.names, id),
                QueryCost {
                    cost: elapsed,
                    query: intern(&mut costs.names, query),
                    confirmed: false,
                },
            );
        }
    }
}

/// How many times an outlier is run again before its cost stands.
const CONFIRMATION_RUNS: usize = 3;
/// Confirming an outlier can lower the median and expose another; the pass
/// repeats, but a fixture that keeps producing new ones stops here.
const CONFIRMATION_ROUNDS: usize = 4;

/// Confirm a fixture's AST cost outliers while its evaluation context can
/// still run them. Callers check [`active`] first.
///
/// Every query ran once as the fixture was evaluated. A cost over the peer
/// fence may be the query's, or may be whatever happened to run cold under
/// it: the comment-stripped reparse the next query reuses, a page fault.
/// `remeasure(query, full_count)` runs the query again on the same fixture
/// in the same count mode and returns its cost, or `None` when the run was
/// cut short; the lowest cost seen stands. Running only the outliers again,
/// rather than every query three times as the fixture is evaluated, is what
/// keeps a bundle-sized source from costing minutes in validation.
///
/// The peers' median was recorded earlier, under whatever load the machine
/// had then. Each rerun is paired with a rerun of the median query itself,
/// so a rerun slowed by a contended or efficiency core is scaled back by the
/// same factor: an outlier must stay slow relative to its peers, not merely
/// slower than they were a moment ago. The scaling only ever lowers a cost.
pub(crate) fn confirm_outliers(
    path: &str,
    sha256: &str,
    mut remeasure: impl FnMut(&str, bool) -> Option<Duration>,
) {
    let groups: Vec<CostKey> = [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .map(|(full_count, anchored)| CostKey {
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            full_count,
            anchored,
        })
        .collect();
    for _ in 0..CONFIRMATION_ROUNDS {
        // Snapshot the candidates: the lock is not held while queries run.
        let candidates: Vec<Candidate> = groups
            .iter()
            .flat_map(|key| {
                let state = QUERY_COSTS.lock();
                let costs = &state.groups;
                let over_fence: Option<Vec<_>> = costs.get(key).and_then(|rules| {
                    if !rules
                        .values()
                        .any(|cost| cost.cost > AST_OUTLIER_NOISE_ALLOWANCE)
                    {
                        return None;
                    }
                    let (median, fence) = group_fence(costs, key)?;
                    let reference = median_query(rules)?;
                    Some(
                        rules
                            .iter()
                            .filter(|(_, c)| c.cost > fence && !c.confirmed)
                            .map(|(id, c)| Candidate {
                                key: key.clone(),
                                id: id.clone(),
                                query: c.query.clone(),
                                cost: c.cost,
                                reference: reference.clone(),
                                median,
                            })
                            .collect(),
                    )
                });
                drop(state);
                over_fence.unwrap_or_default()
            })
            .collect();
        if candidates.is_empty() {
            return;
        }
        for c in candidates {
            // The first sample ran beside the peers and stands as recorded;
            // each rerun is restated at the speed of the median query timed
            // right after it, while the thread is likely on the same core.
            let mut best = c.cost;
            for _ in 0..CONFIRMATION_RUNS {
                let Some(cost) = remeasure(&c.query, c.key.full_count) else {
                    break;
                };
                let now = remeasure(&c.reference, c.key.full_count);
                best = best.min(match now {
                    Some(now) if now > c.median => scale(cost, c.median, now),
                    _ => cost,
                });
            }
            let mut costs = QUERY_COSTS.lock();
            if let Some(cost) = costs
                .groups
                .get_mut(&c.key)
                .and_then(|rules| rules.get_mut(&c.id))
            {
                cost.cost = cost.cost.min(best);
                cost.confirmed = true;
            }
        }
    }
}

/// An outlier awaiting confirmation, with its peer group's median query to
/// time beside it.
struct Candidate {
    key: CostKey,
    id: Arc<str>,
    query: Arc<str>,
    cost: Duration,
    reference: Arc<str>,
    median: Duration,
}

/// The query whose recorded cost is the peers' median.
fn median_query(rules: &BTreeMap<Arc<str>, QueryCost>) -> Option<Arc<str>> {
    let mut by_cost: Vec<_> = rules.values().collect();
    by_cost.sort_unstable_by_key(|c| c.cost);
    by_cost.get(by_cost.len() / 2).map(|c| c.query.clone())
}

/// `cost * recorded / now`: a cost measured while the machine ran the median
/// query in `now`, restated at the speed the peers were recorded at.
fn scale(cost: Duration, recorded: Duration, now: Duration) -> Duration {
    let nanos = cost.as_nanos() * recorded.as_nanos() / now.as_nanos().max(1);
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

// Cheap queries vary by many peer multiples while costing less than a
// millisecond. Keep that variation out of the failure gate, and allow headroom
// above the relative fence for query shapes that perform different work.
const AST_OUTLIER_NOISE_ALLOWANCE: Duration = Duration::from_millis(1);
const AST_OUTLIER_MULTIPLIER: u128 = 40;

/// The median and fence of `key`'s peer group, from [`outlier_fence`].
///
/// An anchored query's fence is never below the file's median unanchored
/// cost plus the allowance. An anchor whose literal is everywhere (`"0"`)
/// roots the query at most of the tree; it then costs a walk, and a walk is
/// what the rule would cost written with no literal at all, which passes.
fn group_fence(groups: &CostGroups, key: &CostKey) -> Option<(Duration, Duration)> {
    let (median, fence) = outlier_fence(groups.get(key)?)?;
    if !key.anchored {
        return Some((median, fence));
    }
    let walks = CostKey {
        anchored: false,
        ..key.clone()
    };
    let walk_floor = groups
        .get(&walks)
        .and_then(outlier_fence)
        .map(|(walk_median, _)| walk_median.saturating_add(AST_OUTLIER_NOISE_ALLOWANCE));
    Some((median, walk_floor.map_or(fence, |floor| fence.max(floor))))
}

/// Require eight executed queries in the same peer group (see [`CostKey`]):
/// same fixture, count mode, and anchoring. Require at least 1ms of excess
/// cost above both 40 times the peer median and the median plus 40 median
/// absolute deviations. The absolute allowance prevents tiny overruns of the
/// relative boundary from failing validation.
fn outlier_fence<C: MeasuredCost>(costs: &BTreeMap<impl Ord, C>) -> Option<(Duration, Duration)> {
    if costs.len() < 8 {
        return None;
    }
    let mut ns: Vec<_> = costs.values().map(|c| c.cost().as_nanos()).collect();
    let mid = ns.len() / 2;
    let median = *ns.select_nth_unstable(mid).1;
    let mut deviations: Vec<_> = ns.iter().map(|n| n.abs_diff(median)).collect();
    let mad = *deviations.select_nth_unstable(mid).1;
    let fence = median
        .saturating_mul(AST_OUTLIER_MULTIPLIER)
        .max(median.saturating_add(mad.saturating_mul(AST_OUTLIER_MULTIPLIER)))
        .saturating_add(AST_OUTLIER_NOISE_ALLOWANCE.as_nanos());
    let duration = |n: u128| Duration::from_nanos(n.min(u128::from(u64::MAX)) as u64);
    Some((duration(median), duration(fence)))
}

static FIXTURE_SESSION: AtomicBool = AtomicBool::new(false);

pub(crate) fn running_fixtures() -> bool {
    FIXTURE_SESSION.load(Ordering::Relaxed)
}

pub(crate) fn active() -> bool {
    ACTIVE.0.load(Ordering::Relaxed)
}

/// Whether validation judges `query`'s cost on the file `ctx` evaluates:
/// every query, unless the file's batch came from a mapper scoped to an
/// edit (see `EvaluationContext::measured_ast_queries`).
pub(crate) fn judges(query: &str, ctx: &EvaluationContext<'_>) -> bool {
    active()
        && ctx
            .measured_ast_queries
            .is_none_or(|measured| measured.contains(query))
}

/// Full-validation cache hits may reuse a previously measured pass. Fresh
/// validation must execute rules, including queries otherwise hidden by a batch.
#[cfg(feature = "lint")]
pub(crate) struct Session;
#[cfg(feature = "lint")]
impl Session {
    pub(crate) fn begin() -> Self {
        FIXTURE_SESSION.store(true, Ordering::Relaxed);
        ISSUES.lock().clear();
        *QUERY_COSTS.lock() = QueryCosts::default();
        ACTIVE.0.store(
            !validation_controls::is_validator_disabled(VALIDATOR),
            Ordering::Relaxed,
        );
        Self
    }

    #[cfg(feature = "lint")]
    pub(crate) fn issues(&self) -> Vec<ValidationIssue> {
        let mut issues = ISSUES.lock().clone();
        let outliers = outlier_issues(&QUERY_COSTS.lock().groups);
        for (key, problem) in outliers {
            issues.entry(key).or_insert(problem);
        }
        issues.into_values().collect()
    }
}

/// Each peer group's costs over its fence, keyed like [`ISSUES`].
#[cfg(any(test, feature = "lint"))]
fn outlier_issues(groups: &CostGroups) -> Vec<((String, String), ValidationIssue)> {
    let mut issues = Vec::new();
    for (key, costs) in groups {
        if !costs
            .values()
            .any(|cost| cost.cost > AST_OUTLIER_NOISE_ALLOWANCE)
        {
            continue;
        }
        let Some((median, fence)) = group_fence(groups, key) else {
            continue;
        };
        let peers = if key.anchored {
            "anchored"
        } else {
            "unanchored"
        };
        for (id, QueryCost { cost, .. }) in costs {
            if *cost > fence {
                let detail = format!(
                    "AST query cost is an extreme outlier: {}us; {peers} peer median {}us, effective fence {}us (1ms excess allowance, 40x peer margin; {} executed {peers} queries)",
                    cost.as_micros(),
                    median.as_micros(),
                    fence.as_micros(),
                    costs.len()
                );
                let problem = issue(id, &key.path, &detail);
                issues.push(((id.to_string(), key.path.clone()), problem));
            }
        }
    }
    issues
}
#[cfg(feature = "lint")]
impl Drop for Session {
    fn drop(&mut self) {
        FIXTURE_SESSION.store(false, Ordering::Relaxed);
        ACTIVE.0.store(false, Ordering::Relaxed);
        ISSUES.lock().clear();
        *QUERY_COSTS.lock() = QueryCosts::default();
    }
}

fn issue(id: &str, path: &str, detail: &str) -> ValidationIssue {
    let mut issue = ValidationIssue::new(VALIDATOR, format!("rule '{id}' on '{path}': {detail}"));
    issue.rule_id = Some(id.to_owned());
    issue
}

/// Run `check` outside every measurement: not counted as a query run, not
/// charged to the rule's time. `None` while a probe is already measuring,
/// since a nested probe would overwrite the cost it is taking.
pub(crate) fn unmeasured<T>(check: impl FnOnce() -> T) -> Option<T> {
    if PROBING_AST.with(Cell::get) {
        return None;
    }
    let _probe = AstProbe::begin();
    Some(check())
}

/// Record that anchored evaluation of `query` on `path` found different
/// matches than the whole-tree walk (see `ast_gate::Anchors`).
pub(crate) fn anchoring_diverged(query: &str, path: &str, detail: &str) {
    let query = query.split_whitespace().collect::<Vec<_>>().join(" ");
    let shown: String = query.chars().take(160).collect();
    let issue = ValidationIssue::new(
        "ast-anchor-soundness",
        format!(
            "anchored evaluation diverged from the whole-tree walk on '{path}': {detail}; query `{shown}`"
        ),
    );
    record(&query, path, issue);
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
        // A thread spends no more CPU than the wall time that passed, so a
        // rule within the threshold by the wall clock is within it: skip the
        // thread-CPU read, a kernel call that every rule on every file made.
        let wall = self.wall.elapsed();
        if wall <= self.threshold {
            return;
        }
        let elapsed = if self.cpu.is_zero() {
            wall
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
    fn measured_costs(peer_us: u64, candidate: Duration) -> BTreeMap<String, Duration> {
        (0..9)
            .map(|i| {
                (
                    i.to_string(),
                    if i == 8 {
                        candidate
                    } else {
                        Duration::from_micros(peer_us)
                    },
                )
            })
            .collect()
    }

    #[test]
    fn outliers_require_comparable_peers() {
        assert!(outlier_fence(&BTreeMap::<String, Duration>::new()).is_none());
        let mut few = measured_costs(10, Duration::from_millis(5));
        few.remove("0");
        few.remove("1");
        assert!(outlier_fence(&few).is_none());
        let uniform = (0..9)
            .map(|i| (i.to_string(), Duration::from_secs(1)))
            .collect();
        let (_, fence) = outlier_fence(&uniform).unwrap();
        assert!(uniform.values().all(|cost| *cost <= fence));
    }

    #[test]
    fn cheap_queries_tolerate_submillisecond_variation() {
        // These cover the observed 49us, 155us, 308us, 855us and 879us failures.
        for candidate_us in [49, 155, 308, 855, 879, 999, 1000] {
            let costs = measured_costs(2, Duration::from_micros(candidate_us));
            let (_, fence) = outlier_fence(&costs).unwrap();
            assert_eq!(fence, Duration::from_micros(1080));
            assert!(costs.values().all(|cost| *cost <= fence));
        }
    }

    #[test]
    fn relative_margin_ignores_small_crossings_of_the_old_fence() {
        let costs = measured_costs(55, Duration::from_micros(1142));
        let (_, fence) = outlier_fence(&costs).unwrap();
        assert_eq!(fence, Duration::from_micros(3200));
        assert!(costs.values().all(|cost| *cost <= fence));
    }

    #[test]
    fn absolute_excess_allowance_still_catches_material_relative_outliers() {
        let costs = measured_costs(10, Duration::from_micros(1400) + Duration::from_nanos(1));
        let (_, fence) = outlier_fence(&costs).unwrap();
        let flagged: Vec<_> = costs
            .iter()
            .filter(|(_, cost)| **cost > fence)
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(flagged, ["8"]);
    }

    #[test]
    fn tiny_overruns_of_a_millisecond_relative_boundary_do_not_fail() {
        let costs = measured_costs(25, Duration::from_micros(1044));
        let (_, fence) = outlier_fence(&costs).unwrap();
        assert_eq!(fence, Duration::from_millis(2));
        assert!(costs.values().all(|cost| *cost <= fence));
    }

    #[test]
    fn excess_boundary_is_inclusive() {
        let costs = measured_costs(10, Duration::from_micros(1400));
        let (_, fence) = outlier_fence(&costs).unwrap();
        assert_eq!(fence, Duration::from_micros(1400));
        assert!(costs.values().all(|cost| *cost <= fence));
    }

    #[test]
    fn material_outliers_scale_with_their_peers() {
        for scale in [10_000, 1_000_000] {
            let costs = (0..9)
                .map(|i| {
                    (
                        i.to_string(),
                        Duration::from_nanos(scale * if i == 8 { 1000 } else { 10 + i }),
                    )
                })
                .collect();
            let (_, fence) = outlier_fence(&costs).unwrap();
            let flagged: Vec<_> = costs
                .iter()
                .filter(|(_, cost)| **cost > fence)
                .map(|(id, _)| id.as_str())
                .collect();
            assert_eq!(flagged, ["8"]);
        }
    }

    /// Record eight 30us peers and one 2.6ms candidate (fence 2.2ms) for
    /// `path`, confirm them with reruns that cost `candidate_rerun` and a
    /// median query that now costs `reference_rerun`, and return the
    /// candidate's confirmed cost.
    fn confirmed_cost(path: &str, candidate_rerun: u64, reference_rerun: u64) -> Duration {
        let rules = (0..9)
            .map(|i| {
                let (query, us) = if i == 8 {
                    ("candidate".to_owned(), 2600)
                } else {
                    (format!("peer{i}"), 30)
                };
                (
                    i.to_string().into(),
                    QueryCost {
                        cost: Duration::from_micros(us),
                        query: query.into(),
                        confirmed: false,
                    },
                )
            })
            .collect();
        let key = CostKey {
            path: path.to_owned(),
            sha256: "sha".to_owned(),
            full_count: false,
            anchored: true,
        };
        QUERY_COSTS.lock().groups.insert(key.clone(), rules);
        confirm_outliers(path, "sha", |query, full_count| {
            (!full_count).then(|| {
                Duration::from_micros(if query == "candidate" {
                    candidate_rerun
                } else {
                    reference_rerun
                })
            })
        });
        QUERY_COSTS.lock().groups.remove(&key).unwrap()["8"].cost
    }

    #[test]
    fn a_rerun_on_a_slower_core_is_judged_against_its_peers_at_that_speed() {
        // The machine ran the median query 3x slower during the reruns.
        assert_eq!(
            confirmed_cost("zz-slow-core.js", 3000, 90),
            Duration::from_micros(1000)
        );
    }

    #[test]
    fn a_query_slow_beside_its_peers_stays_an_outlier() {
        // The median query ran at its recorded speed: nothing to scale.
        assert_eq!(
            confirmed_cost("zz-real-outlier.js", 3000, 30),
            Duration::from_micros(2600)
        );
        // A faster machine never raises a recorded cost.
        assert_eq!(
            confirmed_cost("zz-fast-core.js", 2400, 10),
            Duration::from_micros(2400)
        );
    }

    fn group(path: &str, anchored: bool) -> CostKey {
        CostKey {
            path: path.to_owned(),
            sha256: "sha".to_owned(),
            full_count: false,
            anchored,
        }
    }

    fn costs<S: AsRef<str>>(entries: &[(S, u64)]) -> BTreeMap<Arc<str>, QueryCost> {
        entries
            .iter()
            .map(|(id, us)| {
                let id = id.as_ref();
                let cost = QueryCost {
                    cost: Duration::from_micros(*us),
                    query: format!("q-{id}").into(),
                    confirmed: false,
                };
                (id.into(), cost)
            })
            .collect()
    }

    /// The 2026-11-17 `extension/dist/extension.js` measurements: 70
    /// anchored queries of 23-31us, and 18 unanchored whole-tree walks
    /// around 2ms, including the three that failed on different runs
    /// (2121us, 2127us and 2163us). Pooled, the 88 have the observed 28us
    /// median and a 2120us fence.
    fn bundle_costs() -> (Vec<(String, u64)>, Vec<(String, u64)>) {
        let anchored = (0..70)
            .map(|i| (format!("anchored{i}"), 23 + i % 9))
            .collect();
        let mut unanchored: Vec<_> = (0..15)
            .map(|i| (format!("walk{i}"), 1800 + 20 * i))
            .collect();
        unanchored.extend([
            ("async-iife-invoke".to_owned(), 2121),
            ("js-var-sequence-init-ast".to_owned(), 2127),
            ("same-path-computed-operations-helper".to_owned(), 2163),
        ]);
        (anchored, unanchored)
    }

    fn bundle_groups(anchored: &[(String, u64)], unanchored: &[(String, u64)]) -> CostGroups {
        BTreeMap::from([
            (group("bundle.js", true), costs(anchored)),
            (group("bundle.js", false), costs(unanchored)),
        ])
    }

    fn flagged(groups: &CostGroups) -> Vec<String> {
        let mut ids: Vec<_> = outlier_issues(groups)
            .into_iter()
            .map(|((id, _), _)| id)
            .collect();
        ids.sort();
        ids
    }

    #[test]
    fn whole_tree_walks_pooled_with_anchored_peers_sit_on_the_fence() {
        // The old single pool, kept as the failure the grouping removes: a
        // walk's ordinary cost crosses 40x the anchored median.
        let (anchored, unanchored) = bundle_costs();
        let pooled: Vec<_> = anchored.into_iter().chain(unanchored).collect();
        let groups = BTreeMap::from([(group("bundle.js", true), costs(&pooled))]);
        assert_eq!(
            flagged(&groups),
            [
                "async-iife-invoke",
                "js-var-sequence-init-ast",
                "same-path-computed-operations-helper"
            ]
        );
    }

    #[test]
    fn whole_tree_walks_are_judged_among_themselves() {
        let (anchored, unanchored) = bundle_costs();
        assert!(flagged(&bundle_groups(&anchored, &unanchored)).is_empty());
    }

    #[test]
    fn a_pathological_walk_still_fails_among_walks() {
        let (anchored, mut unanchored) = bundle_costs();
        unanchored.push(("runaway-walk".to_owned(), 250_000));
        let issues = outlier_issues(&bundle_groups(&anchored, &unanchored));
        assert_eq!(issues.len(), 1);
        let ((id, path), problem) = &issues[0];
        assert_eq!((id.as_str(), path.as_str()), ("runaway-walk", "bundle.js"));
        assert!(
            problem.message.contains("unanchored peer median"),
            "{}",
            problem.message
        );
    }

    /// The 2026-11-17 `analytics-stage.js` measurement: anchored on `"0"`,
    /// `browser-long-loop-string-doubling` roots at most of the tree and
    /// costs 1581us beside a 12us anchored median -- no more than the file's
    /// own whole-tree walks.
    #[test]
    fn an_anchored_query_that_costs_a_walk_passes() {
        let mut anchored: Vec<_> = (0..54).map(|i| (format!("a{i}"), 8 + i % 9)).collect();
        anchored.push(("browser-long-loop-string-doubling".to_owned(), 1581));
        let walks: Vec<_> = (0..23).map(|i| (format!("w{i}"), 1400 + 45 * i)).collect();
        assert!(flagged(&bundle_groups(&anchored, &walks)).is_empty());
    }

    #[test]
    fn an_anchored_query_costlier_than_a_walk_still_fails() {
        let (mut anchored, unanchored) = bundle_costs();
        anchored.push(("broad-anchor".to_owned(), 25_000));
        assert_eq!(
            flagged(&bundle_groups(&anchored, &unanchored)),
            ["broad-anchor"]
        );
    }

    #[test]
    fn without_walks_an_anchored_outlier_fails_among_anchored_peers() {
        let (mut anchored, _) = bundle_costs();
        anchored.push(("broad-anchor".to_owned(), 2600));
        assert_eq!(flagged(&bundle_groups(&anchored, &[])), ["broad-anchor"]);
    }

    #[test]
    fn recorded_costs_stay_in_their_peer_group() {
        let mut groups = QueryCosts::default();
        let us = Duration::from_micros;
        record_cost(&mut groups, group("f.js", true), "rule", "anchored", us(30));
        record_cost(&mut groups, group("f.js", false), "rule", "walk", us(2000));
        record_cost(
            &mut groups,
            group("f.js", false),
            "rule",
            "cheaper",
            us(1500),
        );
        assert_eq!(groups.groups[&group("f.js", true)]["rule"].cost, us(30));
        let walk = &groups.groups[&group("f.js", false)]["rule"];
        assert_eq!((walk.cost, walk.query.as_ref()), (us(2000), "walk"));
        record_cost(
            &mut groups,
            group("f.js", false),
            "rule",
            "costlier",
            us(2500),
        );
        let walk = &groups.groups[&group("f.js", false)]["rule"];
        assert_eq!((walk.cost, walk.query.as_ref()), (us(2500), "costlier"));
    }

    /// An unanchored candidate is rerun beside its own group's median query:
    /// restated against the anchored median, a walk slowed by load would be
    /// scaled by the wrong factor.
    #[test]
    fn confirmation_times_the_candidates_own_group_median() {
        let path = "zz-group-reference.js";
        let anchored: Vec<_> = (0..9).map(|i| (format!("a{i}"), 30)).collect();
        let mut walks: Vec<_> = (0..8).map(|i| (format!("w{i}"), 2000)).collect();
        walks.push(("candidate".to_owned(), 90_000));
        QUERY_COSTS
            .lock()
            .groups
            .insert(group(path, true), costs(&anchored));
        QUERY_COSTS
            .lock()
            .groups
            .insert(group(path, false), costs(&walks));
        let mut references = Vec::new();
        confirm_outliers(path, "sha", |query, full_count| {
            if full_count {
                return None;
            }
            // The machine runs 2x slower during the reruns.
            if query == "q-candidate" {
                return Some(Duration::from_micros(180_000));
            }
            references.push(query.to_owned());
            Some(Duration::from_micros(4000))
        });
        let anchored = QUERY_COSTS
            .lock()
            .groups
            .remove(&group(path, true))
            .unwrap();
        let walks = QUERY_COSTS
            .lock()
            .groups
            .remove(&group(path, false))
            .unwrap();
        assert!(!references.is_empty());
        assert!(
            references.iter().all(|q| q.starts_with("q-w")),
            "{references:?}"
        );
        assert!(!anchored.values().any(|c| c.confirmed));
        let candidate = &walks["candidate"];
        assert!(candidate.confirmed);
        assert_eq!(candidate.cost, Duration::from_micros(90_000));
    }

    #[test]
    fn performance_is_soft_and_uses_standard_severity_policy() {
        let p = issue("rule", "fixture.js", "too slow");
        assert_eq!(p.severity, validation_controls::Severity::Soft);
        assert!(p.severity >= validation_controls::Severity::Soft);
        assert!(p.severity < validation_controls::Severity::Hard);
    }

    /// A divergence between anchored and whole-tree evaluation drops or
    /// invents detections: it is recorded under its own registered validator,
    /// which fails even `validate --soft`.
    #[test]
    #[allow(clippy::expect_used)]
    fn anchoring_divergence_is_a_hard_registered_issue() {
        assert!(validation_controls::validator_spec("ast-anchor-soundness").is_some());
        let query = "((identifier) @i (#eq? @i \"zz-anchor-test\"))";
        anchoring_diverged(
            query,
            "zz-anchor-test.js",
            "1 anchored matches, 2 whole-tree matches",
        );
        let recorded = ISSUES
            .lock()
            .remove(&(
                query.split_whitespace().collect::<Vec<_>>().join(" "),
                "zz-anchor-test.js".to_owned(),
            ))
            .expect("recorded");
        assert_eq!(recorded.validator_id, "ast-anchor-soundness");
        assert_eq!(recorded.severity, validation_controls::Severity::Hard);
        assert!(
            recorded
                .message
                .contains("1 anchored matches, 2 whole-tree matches")
        );
    }
}
