//! Bounded per-file analysis diagnostics, separate from malware findings.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
/// Why an analysis query could not establish complete evidence.
pub enum AnalysisGap {
    /// No flow producer was available for a requested query.
    FlowUnavailable,
    /// The producer's graph schema is newer or unsupported.
    FlowSchemaUnsupported,
    /// The producer reported a parse, syntax, or resource limitation.
    FlowGraphLimited,
    /// A symbol call or argument could not be associated with the graph.
    FlowCallUnavailable,
    /// A requested object field could not be fully resolved.
    FlowFieldUnavailable,
    /// Value traversal encountered unknown evidence or exhausted a budget.
    FlowQueryIncomplete,
    /// Additional diagnostic-only member records were elided from compact output.
    ReportRetentionLimited,
}

const ALL: [AnalysisGap; 7] = [
    AnalysisGap::FlowUnavailable,
    AnalysisGap::FlowSchemaUnsupported,
    AnalysisGap::FlowGraphLimited,
    AnalysisGap::FlowCallUnavailable,
    AnalysisGap::FlowFieldUnavailable,
    AnalysisGap::FlowQueryIncomplete,
    AnalysisGap::ReportRetentionLimited,
];

impl AnalysisGap {
    /// Stable diagnostic label, independent of taxonomy identifiers.
    pub fn label(self) -> &'static str {
        match self {
            Self::FlowUnavailable => "flow-unavailable",
            Self::FlowSchemaUnsupported => "flow-schema-unsupported",
            Self::FlowGraphLimited => "flow-graph-limited",
            Self::FlowCallUnavailable => "flow-call-unavailable",
            Self::FlowFieldUnavailable => "flow-field-unavailable",
            Self::FlowQueryIncomplete => "flow-query-incomplete",
            Self::ReportRetentionLimited => "report-retention-limited",
        }
    }
}

/// Parallel evaluators share their report, not a process-global warning sink.
/// Clone takes a snapshot: subsequent scans cannot contaminate a cached copy.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(from = "Vec<AnalysisGap>", into = "Vec<AnalysisGap>")]
pub struct AnalysisGaps(AtomicU8);

impl AnalysisGaps {
    /// Record a gap without allocating or duplicating diagnostics.
    pub fn record(&self, gap: AnalysisGap) {
        self.0.fetch_or(1 << gap as u8, Ordering::Relaxed);
    }
    /// Whether no gaps have been recorded; this is not a safety verdict.
    pub fn is_empty(&self) -> bool {
        self.0.load(Ordering::Relaxed) == 0
    }
    /// Iterate over a stable snapshot of the recorded gaps.
    pub fn iter(&self) -> impl Iterator<Item = AnalysisGap> {
        let bits = self.0.load(Ordering::Relaxed);
        ALL.into_iter()
            .filter(move |gap| bits & (1 << *gap as u8) != 0)
    }
}
impl Clone for AnalysisGaps {
    fn clone(&self) -> Self {
        Self(AtomicU8::new(self.0.load(Ordering::Relaxed)))
    }
}
impl From<Vec<AnalysisGap>> for AnalysisGaps {
    fn from(gaps: Vec<AnalysisGap>) -> Self {
        let result = Self::default();
        for gap in gaps {
            result.record(gap);
        }
        result
    }
}
impl From<AnalysisGaps> for Vec<AnalysisGap> {
    fn from(gaps: AnalysisGaps) -> Self {
        gaps.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parallel_gaps_are_bounded_serializable_and_snapshot_cloned() {
        let gaps = AnalysisGaps::default();
        std::thread::scope(|s| {
            for gap in ALL {
                let gaps = &gaps;
                s.spawn(move || {
                    for _ in 0..100 {
                        gaps.record(gap);
                    }
                });
            }
        });
        assert_eq!(gaps.iter().count(), ALL.len());
        let json = serde_json::to_string(&gaps).unwrap();
        let restored: AnalysisGaps = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&restored).unwrap(), json);
        let empty = AnalysisGaps::default();
        let copy = empty.clone();
        empty.record(AnalysisGap::FlowUnavailable);
        assert!(copy.is_empty());
    }
}
