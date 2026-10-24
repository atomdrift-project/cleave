//! Offline report decoding for the text renderers.
//!
//! Dispatch on the wire version before deserializing: CompactReport's version
//! field deliberately ignores input and must not be used for version detection.
//! Notes are not stored; the renderers derive them (`context::notes`), so a
//! stored report renders as its live analysis did.
use std::collections::{HashMap, HashSet};
use std::io::Read;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use crate::types::file_analysis::CompositeSource;
use crate::types::{CompactReport, Finding, FindingKind, TargetInfo};
use crate::{AnalysisReport, Criticality, FileAnalysis};

/// Arguments shared by the cleave and scan offline render commands.
#[derive(Debug, clap::Args)]
pub struct RenderArgs {
    /// Saved report, or - to read one JSON document from stdin.
    pub input: String,
}

/// A decoded report and the limits of reproducing its original live render.
#[derive(Debug)]
pub struct LoadedReport {
    /// The finalized presentation model. Do not finalize or re-evaluate it again.
    pub report: AnalysisReport,
    /// Fetch observations from a compact report, for package-aware readers.
    pub fetched: Vec<Value>,
    /// Historical rules revision carried by the wire envelope, when known.
    pub traits_version: Option<String>,
    /// The fact profile the report was reduced to (`fp`), when it was.
    pub fact_profile: Option<String>,
    /// Ways this render may differ from the report's live analysis.
    pub warnings: Vec<String>,
}

/// Read a single document without opening any original artifact or loading rules.
pub fn read(input: &str) -> Result<LoadedReport> {
    let bytes = if input == "-" {
        let mut bytes = Vec::new();
        std::io::stdin().lock().read_to_end(&mut bytes)?;
        bytes
    } else {
        std::fs::read(input).with_context(|| format!("reading report {input}"))?
    };
    decode(&bytes).with_context(|| format!("decoding report {input}"))
}

/// Decode supported reports or a scan envelope without a whole-document DOM.
/// Version dispatch borrows only the envelope's raw JSON, then parses directly
/// into the selected typed format. Unknown versions fail explicitly.
pub fn decode(bytes: &[u8]) -> Result<LoadedReport> {
    #[derive(serde::Deserialize)]
    struct Header<'a> {
        #[serde(default, borrow)]
        raw: Option<&'a serde_json::value::RawValue>,
        v: Option<String>,
        version: Option<String>,
        schema_version: Option<String>,
    }
    let mut header: Header<'_> = serde_json::from_slice(bytes).context("invalid JSON document")?;
    let raw_string;
    let document = if let Some(raw) = header.raw {
        if raw.get().starts_with('"') {
            raw_string =
                serde_json::from_str::<String>(raw.get()).context("invalid JSON in raw report")?;
            raw_string.as_bytes()
        } else {
            raw.get().as_bytes()
        }
    } else {
        bytes
    };
    if header.raw.is_some() {
        header = serde_json::from_slice(document).context("invalid JSON in raw report")?;
    }
    let version = header.v.or(header.version).or(header.schema_version);
    let loaded = match version.as_deref() {
        Some("8" | "9") => from_compact(serde_json::from_slice(document)?)?,
        Some("3" | "3.0") => {
            let mut report: AnalysisReport = serde_json::from_slice(document)?;
            let mut warnings = Vec::new();
            // Raw analysis-cache snapshots have not folded their root yet.
            // Finalized snapshots clear target.path and already contain it.
            if !report.target.path.is_empty() {
                report.finalize();
                report.strip_unmatched_traits();
                warnings.push("raw analysis-cache report required finalization; use --format snapshot for an exact baseline".into());
            }
            LoadedReport {
                report,
                fetched: Vec::new(),
                traits_version: None,
                fact_profile: None,
                warnings,
            }
        }
        _ => bail!("unsupported report version {version:?}; expected compact v8 or v9, or raw v3"),
    };
    validate(&loaded.report)?;
    Ok(loaded)
}

fn from_compact(compact: CompactReport) -> Result<LoadedReport> {
    let mut files = Vec::with_capacity(compact.files.len());
    for f in compact.files {
        let mut file = FileAnalysis {
            id: f.id,
            path: f.path,
            file_type: f.file_type,
            sha256: f.sha,
            size: f.size,
            score: u32::try_from(f.risk.max(0)).context("risk exceeds u32")?,
            depth: f.depth,
            parent_id: f.parent,
            rel: f.rel,
            via: f.via,
            role: f.role,
            formula: f.formula,
            identity: f.identity,
            analysis_gaps: f.analysis_gaps,
            suppressions: f.suppressions,
            context: f.context,
            precompact_facts: Some(f.facts),
            precompact_refs: Some(f.refs),
            ..FileAnalysis::default()
        };
        for t in &f.findings {
            let crit = criticality(t.criticality)?;
            ensure!(
                t.confidence.is_finite(),
                "non-finite confidence for {}",
                t.id
            );
            let mut finding = Finding::new(
                t.id.clone(),
                FindingKind::Indicator,
                t.description.clone(),
                t.confidence,
            );
            finding.crit = crit;
            finding.mbc = t.mbc.clone().map(Into::into);
            finding.attack = t.attack.clone().map(Into::into);
            finding.precomputed_spans = Some(t.ev.clone());
            for &index in &t.uses {
                let leg = f
                    .findings
                    .get(index as usize)
                    .with_context(|| format!("dangling uses index {index} in {}", t.id))?;
                finding.trait_refs.push(leg.id.clone().into());
            }
            if t.from.len() == 1 && t.from[0].line.is_none() && t.from[0].offset.is_none() {
                finding.src = Some(t.from[0].file);
            } else if !t.from.is_empty() {
                file.composite_sources.insert(
                    t.id.clone(),
                    t.from
                        .iter()
                        .map(|s| CompositeSource {
                            file: s.file,
                            line: s.line,
                            offset: s.offset,
                        })
                        .collect(),
                );
            }
            file.findings.push(finding);
        }
        files.push(file);
    }
    let mut report = AnalysisReport::new(TargetInfo::default());
    report.files = files;
    Ok(LoadedReport {
        report,
        fetched: compact.fetched,
        traits_version: compact.traits_version,
        fact_profile: compact.fp,
        warnings: Vec::new(),
    })
}

fn criticality(value: u8) -> Result<Criticality> {
    Ok(match value {
        0 => Criticality::Filtered,
        1 => Criticality::Component,
        2 => Criticality::Baseline,
        3 => Criticality::Notable,
        4 => Criticality::Suspicious,
        5 => Criticality::Hostile,
        _ => bail!("invalid criticality {value}"),
    })
}

pub(crate) fn validate(report: &AnalysisReport) -> Result<()> {
    ensure!(!report.files.is_empty(), "report has no files to render");
    let mut by_id = HashMap::new();
    for file in &report.files {
        for finding in &file.findings {
            ensure!(finding.conf.is_finite(), "non-finite finding confidence");
            for [offset, length] in crate::types::traits_findings::finding_spans(finding) {
                offset
                    .checked_add(length.max(1))
                    .context("finding span overflow")?;
            }
        }
        ensure!(
            by_id.insert(file.id, file).is_none(),
            "duplicate file id {}",
            file.id
        );
        for context in &file.context {
            context
                .loc
                .checked_add(context.data.len() as u64)
                .context("context byte range overflow")?;
        }
    }
    // A reference to an absent file is expected, not an error: a stored report
    // drops members no one will read again (scan's retention) while findings
    // and members still name them, and every reader resolves ids fallibly. A
    // parent chain still must not loop.
    let mut checked = HashSet::new();
    for file in &report.files {
        let mut visiting = HashSet::new();
        let mut at = Some(file.id);
        while let Some(id) = at {
            if checked.contains(&id) {
                break;
            }
            ensure!(visiting.insert(id), "cycle in file parents at {id}");
            at = by_id.get(&id).and_then(|parent| parent.parent_id);
        }
        checked.extend(visiting);
    }
    Ok(())
}

/// Load and render one document. Warnings go to stderr so stdout can be diffed.
pub fn run(
    args: &RenderArgs,
    render: impl FnOnce(&mut LoadedReport) -> Result<String>,
) -> Result<String> {
    let mut loaded = read(&args.input)?;
    for warning in &loaded.warnings {
        eprintln!("Warning: {}: {warning}", args.input);
    }
    render(&mut loaded)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::output::format_tiny;
    use crate::types::{Facts, compact_from_files};

    fn report() -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo::default());
        let mut atom = Finding::new(
            "micro-behaviors/process::eval",
            FindingKind::Indicator,
            "Evaluates received code",
            0.95,
        );
        atom.crit = Criticality::Notable;
        atom.precomputed_spans = Some(vec![[0, 4]]);
        let mut composite = Finding::new(
            "objectives/execution::remote",
            FindingKind::Indicator,
            "Executes remote code",
            0.99,
        );
        composite.crit = Criticality::Hostile;
        composite.trait_refs.push(atom.id.clone());
        report.files.push(FileAnalysis {
            id: 0,
            path: "/unavailable/payload.js".into(),
            file_type: "javascript".into(),
            sha256: "a".repeat(64),
            size: 12,
            score: 100,
            context: vec![crate::types::ContextLine {
                loc: 0,
                line: Some(1),
                col: Some(1),
                data: b"eval(data);\n".to_vec(),
            }],
            findings: vec![composite, atom],
            ..FileAnalysis::default()
        });
        report
    }

    #[test]
    fn raw_replay_preserves_context_and_composite_without_original_file() {
        let report = report();
        let loaded = decode(&serde_json::to_vec(&report).expect("encode")).expect("decode");
        assert!(loaded.warnings.is_empty());
        assert_eq!(format_tiny(&report), format_tiny(&loaded.report));
        assert!(format_tiny(&loaded.report).contains("eval(data)"));
    }

    #[test]
    fn compact_and_scan_envelope_render_like_the_live_report() {
        let report = report();
        let compact = compact_from_files(&report.files, Facts::Model);
        let loaded =
            decode(&serde_json::to_vec(&serde_json::json!({"raw":compact})).expect("encode"))
                .expect("decode");
        assert!(loaded.warnings.is_empty());
        assert_eq!(
            loaded.fact_profile.as_deref(),
            Some(crate::model_facts::profile_id())
        );
        assert_eq!(
            loaded.report.files[0].findings[0].trait_refs[0].as_str(),
            "micro-behaviors/process::eval"
        );
        assert_eq!(format_tiny(&report), format_tiny(&loaded.report));
    }

    #[test]
    fn rejects_unknown_versions_bad_references_and_parent_cycles() {
        let mut value =
            serde_json::to_value(compact_from_files(&report().files, Facts::Full)).expect("encode");
        value["v"] = Value::String("10".into());
        assert!(decode(&serde_json::to_vec(&value).expect("encode")).is_err());
        value["v"] = Value::String("9".into());
        value["files"][0]["traits"][0]["uses"] = serde_json::json!([99]);
        assert!(decode(&serde_json::to_vec(&value).expect("encode")).is_err());
        value["files"][0]["traits"][0]["uses"] = serde_json::json!([1]);
        value["files"][0]["pid"] = serde_json::json!(0);
        assert!(decode(&serde_json::to_vec(&value).expect("encode")).is_err());
    }

    #[test]
    fn accepts_references_to_files_retention_dropped() {
        // scan stores reports without the members no one will read again, but
        // the survivors still name them as parent and finding source.
        let mut value =
            serde_json::to_value(compact_from_files(&report().files, Facts::Full)).expect("encode");
        value["files"][0]["pid"] = serde_json::json!(77);
        value["files"][0]["traits"][0]["from"] = serde_json::json!([{"file": 78}]);
        let loaded = decode(&serde_json::to_vec(&value).expect("encode")).expect("decodes");
        validate(&loaded.report).expect("renderable");
        assert_eq!(loaded.report.files[0].findings[0].src, Some(78));
    }
}
