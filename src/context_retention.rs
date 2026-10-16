//! Opt-in context retention and a replayable JSON prototype.
//!
//! `context-1` is a diagnostic wire profile, not the proposed final schema 9.
//! Each file retains its compact facts/findings and local replay metadata, so
//! split leaves never need a shared, mutable trait catalog.
use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::AnalysisReport;
use crate::report_input::LoadedReport;
use crate::types::file_analysis::CompositeSource;
use crate::types::traits_findings::finding_spans;
use crate::types::{CompactFile, CompactReport, Criticality, Finding, Note};

/// Context-byte measurements, before and after the conservative padding pass.
#[derive(Debug, Default, Serialize)]
pub struct RetentionStats {
    /// Sum of original decoded window lengths.
    pub before: usize,
    /// Sum of retained decoded window lengths.
    pub after: usize,
    /// Windows whose byte bounds changed.
    pub changed_windows: usize,
    /// Capture annotations whose finding was removed by final output filtering.
    pub orphan_notes: usize,
}

/// Keep the shared lean-render plan's bounding range for every binary window.
/// Live notes, window ordering, and original budget costs survive. Orphan
/// annotations left by final finding filtering cannot be selected by either
/// select_ids or evidence_legs, so their bytes may be emptied without removing
/// the window (whose presence still affects dominance). Source windows with
/// live notes remain whole. No report render or archive selection runs.
pub fn trim(report: &mut AnalysisReport) -> RetentionStats {
    let mut stats = RetentionStats::default();
    for file in &mut report.files {
        let binary = crate::output::is_binary_file_type(&file.file_type);
        let live: std::collections::HashSet<&str> =
            file.findings.iter().map(|f| f.id.as_str()).collect();
        let costs: Vec<usize> = file
            .context
            .iter()
            .enumerate()
            .map(|(i, c)| file.context_costs.get(i).copied().unwrap_or(c.data.len()))
            .collect();
        let mut changed = false;
        for line in &mut file.context {
            stats.before += line.data.len();
            let count = line.notes.len();
            line.notes.retain(|n| live.contains(n.id.as_str()));
            stats.orphan_notes += count - line.notes.len();
            if line.notes.is_empty() && !line.data.is_empty() {
                line.data.clear();
                line.data.shrink_to_fit();
                changed = true;
                stats.changed_windows += 1;
            } else if binary {
                let range = crate::output::binary_retained_bounds(line);
                if range.start != 0 || range.end != line.data.len() {
                    if let Some(number) = line.line {
                        let prefix = &line.data[..range.start];
                        line.line =
                            Some(number + prefix.iter().filter(|&&b| b == b'\n').count() as u64);
                        line.col = Some(match prefix.iter().rposition(|&b| b == b'\n') {
                            Some(i) => (range.start - i) as u64,
                            None => line.col.unwrap_or(1) + range.start as u64,
                        });
                    }
                    line.loc += range.start as u64;
                    line.data = line.data[range].to_vec();
                    changed = true;
                    stats.changed_windows += 1;
                }
            }
            stats.after += line.data.len();
        }
        if changed {
            file.context_costs = costs;
        }
    }
    stats
}

/// Replayable compact JSON, with all metadata local to its file.
#[derive(Debug, Serialize, Deserialize)]
pub struct RetainedReport {
    v: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    rev: Option<String>,
    files: Vec<RetainedFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RetainedFile {
    #[serde(flatten)]
    base: CompactFile,
    rp: Replay,
}

#[derive(Debug, Serialize, Deserialize)]
struct Replay {
    /// Original finding order/multiplicity and information compact v8 folds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    f: Vec<FindingState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    order: Option<Vec<usize>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    local: Vec<usize>,
    /// Capture's exact notes, by window. Definitions reference local traits.
    n: Vec<Vec<NoteState>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    w: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cs: Vec<(usize, Vec<CompositeSource>)>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    kv: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FindingState {
    t: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    s: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    u: Option<Vec<TraitRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    e: Option<Vec<[u64; 2]>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    o: Option<NoteOverride>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum TraitRef {
    Index(usize),
    Id(String),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NoteOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    c: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    f: Option<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum NoteState {
    Plain((usize, u64, u32)),
    Adjusted((usize, u64, u32, NoteOverride)),
}

fn grade(c: Criticality) -> u8 {
    match c {
        Criticality::Filtered => 0,
        Criticality::Component => 1,
        Criticality::Baseline => 2,
        Criticality::Notable => 3,
        Criticality::Suspicious => 4,
        Criticality::Hostile => 5,
        Criticality::Exception => 6,
    }
}

fn criticality(n: u8) -> Result<Criticality> {
    Ok(match n {
        0 => Criticality::Filtered,
        1 => Criticality::Component,
        2 => Criticality::Baseline,
        3 => Criticality::Notable,
        4 => Criticality::Suspicious,
        5 => Criticality::Hostile,
        6 => Criticality::Exception,
        _ => anyhow::bail!("invalid replay criticality {n}"),
    })
}

fn overrides(c: u8, d: &str, f: f32, base: (u8, &str, f32)) -> Option<NoteOverride> {
    let o = NoteOverride {
        c: (c != base.0).then_some(c),
        d: (d != base.1).then(|| d.to_string()),
        f: (f.to_bits() != base.2.to_bits()).then_some(f),
    };
    (o.c.is_some() || o.d.is_some() || o.f.is_some()).then_some(o)
}

/// Encode compact fields plus the rendering information v8 omitted. This
/// preserves facts; fact retention and final schema-9 encodings are separate.
pub fn encode(report: &AnalysisReport) -> Result<RetainedReport> {
    let compact = crate::types::compact_from_files(&report.files);
    let mut files = Vec::with_capacity(report.files.len());
    for (file, base) in report.files.iter().zip(compact.files) {
        let positions: HashMap<&str, usize> = base
            .findings
            .iter()
            .enumerate()
            .map(|(i, t)| (t.id.as_str(), i))
            .collect();
        let mut states = Vec::new();
        let mut order = Vec::with_capacity(file.findings.len());
        let mut local = Vec::new();
        for (at, f) in file.findings.iter().enumerate() {
            let &t = positions
                .get(f.id.as_str())
                .context("finding missing from compact projection")?;
            order.push(t);
            let b = &base.findings[t];
            let same_refs = f.trait_refs.len() == b.uses.len()
                && f.trait_refs
                    .iter()
                    .zip(&b.uses)
                    .all(|(id, &i)| id.as_str() == base.findings[i as usize].id);
            let spans = finding_spans(f);
            if file.finding_has_local_offset(at) {
                local.push(at);
            }
            let state = FindingState {
                t: at,
                s: f.src,
                u: (!same_refs).then(|| {
                    f.trait_refs
                        .iter()
                        .map(|id| {
                            positions.get(id.as_str()).map_or_else(
                                || TraitRef::Id(id.to_string()),
                                |&i| TraitRef::Index(i),
                            )
                        })
                        .collect()
                }),
                e: (spans != b.ev).then_some(spans),
                o: overrides(
                    grade(f.crit),
                    &f.desc,
                    f.conf,
                    (b.criticality, &b.description, b.confidence),
                ),
            };
            if state.s.is_some() || state.u.is_some() || state.e.is_some() || state.o.is_some() {
                states.push(state);
            }
        }
        let order = (order.len() != base.findings.len()
            || order.iter().enumerate().any(|(i, &t)| i != t))
        .then_some(order);
        let mut notes = Vec::with_capacity(file.context.len());
        for line in &file.context {
            let mut row = Vec::with_capacity(line.notes.len());
            for note in &line.notes {
                if !positions.contains_key(note.id.as_str()) {
                    continue;
                }
                let &index = positions
                    .get(note.id.as_str())
                    .context("missing live note definition")?;
                let definition = &base.findings[index];
                let definition = (
                    definition.criticality,
                    definition.description.as_str(),
                    definition.confidence,
                );
                let state = match overrides(grade(note.crit), &note.desc, note.conf, definition) {
                    None => NoteState::Plain((index, note.off, note.len)),
                    Some(o) => NoteState::Adjusted((index, note.off, note.len, o)),
                };
                row.push(state);
            }
            notes.push(row);
        }
        let mut sources = Vec::new();
        for (id, list) in &file.composite_sources {
            if let Some(&i) = positions.get(id.as_str()) {
                sources.push((i, list.clone()));
            }
        }
        files.push(RetainedFile {
            base,
            rp: Replay {
                f: states,
                order,
                local,
                n: notes,
                w: file.context_costs.clone(),
                cs: sources,
                kv: file
                    .kv
                    .iter()
                    .filter(|(k, _)| k.starts_with("registry."))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            },
        });
    }
    // A raw snapshot does not carry a trustworthy rules revision. Do not stamp
    // the machine's current mutable rules onto an older saved analysis.
    Ok(RetainedReport {
        v: "context-1".into(),
        rev: None,
        files,
    })
}

/// Decode a presentation view. Preserve locality as explicit renderer metadata
/// rather than inventing matcher evidence; keep the complete emission spans.
pub(crate) fn decode(value: serde_json::Value) -> Result<LoadedReport> {
    let wire: RetainedReport = serde_json::from_value(value)?;
    ensure!(wire.v == "context-1", "unsupported context profile");
    let (bases, replay): (Vec<_>, Vec<_>) = wire.files.into_iter().map(|f| (f.base, f.rp)).unzip();
    let mut loaded = crate::report_input::from_compact(
        CompactReport {
            files: bases,
            traits_version: wire.rev,
            ..CompactReport::default()
        },
        false,
    )?;
    for (file, meta) in loaded.report.files.iter_mut().zip(replay) {
        ensure!(
            meta.n.len() == file.context.len(),
            "replay note/window count mismatch"
        );
        ensure!(
            meta.w.is_empty() || meta.w.len() == file.context.len(),
            "replay cost/window count mismatch"
        );
        let base = std::mem::take(&mut file.findings);
        let mut findings: Vec<Finding> = match meta.order {
            None => base.clone(),
            Some(order) => order
                .into_iter()
                .map(|i| {
                    base.get(i)
                        .cloned()
                        .context("invalid replay finding order index")
                })
                .collect::<Result<_>>()?,
        };
        for f in &mut findings {
            f.src = None;
        }
        let mut seen = std::collections::HashSet::new();
        for state in meta.f {
            ensure!(seen.insert(state.t), "duplicate replay finding override");
            let f = findings
                .get_mut(state.t)
                .context("invalid replay finding index")?;
            f.src = state.s;
            if let Some(refs) = state.u {
                f.trait_refs = refs
                    .into_iter()
                    .map(|r| match r {
                        TraitRef::Index(i) => base
                            .get(i)
                            .map(|b| b.id.clone())
                            .context("invalid replay trait reference"),
                        TraitRef::Id(id) => Ok(id.into()),
                    })
                    .collect::<Result<_>>()?;
            }
            if let Some(spans) = state.e {
                f.precomputed_spans = Some(spans);
            }
            apply(f, state.o)?;
        }
        let mut locality = vec![false; findings.len()];
        for index in meta.local {
            *locality
                .get_mut(index)
                .context("invalid replay locality index")? = true;
        }
        file.render_locality = locality;
        for (line, notes) in file.context.iter_mut().zip(meta.n) {
            let mut decoded = Vec::with_capacity(notes.len());
            for state in notes {
                let (index, off, len, o) = match state {
                    NoteState::Plain((i, off, len)) => (i, off, len, None),
                    NoteState::Adjusted((i, off, len, o)) => (i, off, len, Some(o)),
                };
                let f = base.get(index).context("invalid replay note index")?;
                let mut note = Note {
                    id: f.id.clone(),
                    desc: f.desc.clone(),
                    crit: f.crit,
                    conf: f.conf,
                    off,
                    len,
                };
                if let Some(o) = o {
                    if let Some(c) = o.c {
                        note.crit = criticality(c)?;
                    }
                    if let Some(d) = o.d {
                        note.desc = d.into();
                    }
                    if let Some(cf) = o.f {
                        note.conf = cf;
                    }
                }
                ensure!(note.conf.is_finite(), "non-finite replay note confidence");
                decoded.push(note);
            }
            line.notes = decoded;
        }
        file.findings = findings;
        file.context_costs = meta.w;
        file.composite_sources.clear();
        for (i, sources) in meta.cs {
            let f = base.get(i).context("invalid composite definition index")?;
            file.composite_sources.insert(f.id.to_string(), sources);
        }
        file.kv = meta.kv;
    }
    Ok(loaded)
}

fn apply(f: &mut Finding, o: Option<NoteOverride>) -> Result<()> {
    if let Some(o) = o {
        if let Some(c) = o.c {
            f.crit = criticality(c)?;
        }
        if let Some(d) = o.d {
            f.desc = d.into();
        }
        if let Some(cf) = o.f {
            f.conf = cf;
        }
    }
    ensure!(f.conf.is_finite(), "non-finite replay confidence");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::Evidence;
    use crate::output::format_tiny;
    use crate::types::{ContextLine, FileAnalysis, TargetInfo};

    fn fixture() -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo::default());
        let mut file = FileAnalysis {
            id: 0,
            path: "budget.exe".into(),
            file_type: "pe".into(),
            sha256: "a".repeat(64),
            size: 32_000,
            score: 100,
            ..FileAnalysis::default()
        };
        for i in 0..24 {
            let off = i * 1024;
            let mut f = Finding::new(
                format!("micro-behaviors/family{i}/action::match"),
                crate::FindingKind::Capability,
                format!("Behavior {i}"),
                0.99,
            );
            f.crit = Criticality::Suspicious;
            f.evidence
                .push(Evidence::new("hex", "fixture", "TEST").with_offset(off + 128));
            file.context.push(ContextLine {
                loc: off,
                line: None,
                col: None,
                data: vec![b'A' + i as u8; 700],
                notes: vec![Note {
                    id: f.id.clone(),
                    desc: f.desc.clone(),
                    crit: f.crit,
                    conf: f.conf,
                    off: off + 128,
                    len: 4,
                }],
            });
            file.findings.push(f);
        }
        report.files.push(file);
        report
    }

    #[test]
    fn budget_selection_and_json_replay_survive_padding_removal() {
        let mut report = fixture();
        let before = format_tiny(&report);
        let stats = trim(&mut report);
        assert_eq!(stats.before, 24 * 700);
        assert_eq!(stats.after, 24 * 68);
        assert_eq!(stats.changed_windows, 24);
        assert_eq!(format_tiny(&report), before);
        let bytes = serde_json::to_vec(&encode(&report).unwrap()).unwrap();
        let decoded = crate::report_input::decode(&bytes).unwrap();
        assert!(decoded.warnings.is_empty());
        assert!(
            decoded.report.files[0]
                .findings
                .iter()
                .all(|f| f.evidence.is_empty()),
            "replay must not invent matcher evidence"
        );
        assert_eq!(format_tiny(&decoded.report), before);
        let mut wrong = report.clone();
        wrong.files[0].context_costs.clear();
        assert_ne!(
            format_tiny(&wrong),
            before,
            "fixture must exercise the original byte budget"
        );
        assert_eq!(
            trim(&mut report).changed_windows,
            0,
            "retention is idempotent"
        );
    }

    #[test]
    fn composite_relabeling_orphan_notes_and_source_windows_roundtrip() {
        let mut report = fixture();
        report.files[0].context.truncate(1);
        report.files[0].findings.truncate(1);
        let mut leg = report.files[0].findings[0].clone();
        leg.crit = Criticality::Component;
        let mut composite = Finding::new(
            "objectives/execution::composite",
            crate::FindingKind::Capability,
            "Composite conclusion",
            0.99,
        );
        composite.crit = Criticality::Hostile;
        composite.trait_refs = vec![leg.id.clone(), "missing/leg::kept".into()];
        report.files[0].context[0].notes[0] = Note {
            id: composite.id.clone(),
            desc: composite.desc.clone(),
            crit: composite.crit,
            conf: composite.conf,
            off: 128,
            len: 4,
        };
        report.files[0].context[0].notes.push(Note {
            id: "capture/removed::annotation".into(),
            desc: "Historical capture".into(),
            crit: Criticality::Baseline,
            conf: 0.8,
            off: 256,
            len: 3,
        });
        report.files[0].findings = vec![composite, leg];
        let mut source_finding = Finding::new(
            "micro-behaviors/process::eval",
            crate::FindingKind::Capability,
            "Source evaluation",
            0.95,
        );
        source_finding.crit = Criticality::Notable;
        report.files.push(FileAnalysis {
            id: 1,
            path: "source.js".into(),
            file_type: "javascript".into(),
            sha256: "b".repeat(64),
            size: 12,
            score: 1,
            context: vec![ContextLine {
                loc: 0,
                line: Some(1),
                col: Some(1),
                data: b"eval(data);\n".to_vec(),
                notes: vec![Note {
                    id: source_finding.id.clone(),
                    desc: source_finding.desc.clone(),
                    crit: source_finding.crit,
                    conf: source_finding.conf,
                    off: 0,
                    len: 4,
                }],
            }],
            findings: vec![source_finding],
            ..FileAnalysis::default()
        });
        let source = report.files[1].context[0].data.clone();
        let before = format_tiny(&report);
        trim(&mut report);
        assert_eq!(report.files[1].context[0].data, source);
        let loaded =
            crate::report_input::decode(&serde_json::to_vec(&encode(&report).unwrap()).unwrap())
                .unwrap();
        assert_eq!(format_tiny(&loaded.report), before);
        assert_eq!(
            loaded.report.files[0].findings[0].trait_refs[1].as_str(),
            "missing/leg::kept"
        );
        assert_eq!(loaded.report.files[0].context[0].notes.len(), 1);
    }

    #[test]
    fn invalid_replay_references_and_budget_costs_are_errors() {
        let mut report = fixture();
        trim(&mut report);
        let mut value = serde_json::to_value(encode(&report).unwrap()).unwrap();
        value["files"][0]["rp"]["f"] = serde_json::json!([{"t":999}]);
        assert!(crate::report_input::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["files"][0]["rp"]["f"][0]["t"] = serde_json::json!(0);
        value["files"][0]["rp"]["w"] = serde_json::json!([1]);
        assert!(crate::report_input::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn folded_spans_survive_raw_snapshot_serialization() {
        let mut report = fixture();
        let finding = &mut report.files[0].findings[0];
        finding.evidence.clear();
        finding.precomputed_spans = Some(vec![[128, 4], [256, 12]]);
        let decoded = crate::report_input::decode(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(
            finding_spans(&decoded.report.files[0].findings[0]),
            vec![[128, 4], [256, 12]]
        );
    }
}
