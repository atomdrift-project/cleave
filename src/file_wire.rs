//! A typed, self-contained file-format candidate. Not the final schema 9.
//!
//! Findings have one canonical order. Context owns its annotation references
//! and optional original budget cost. No replay overlay or report dictionary.
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::report_input::LoadedReport;
use crate::types::compact::{CompactRef, facts_from_file, refs_from_file};
use crate::types::file_analysis::{CompositeSource, Rel, Role};
use crate::types::traits_findings::{crit_ordinal, finding_spans};
use crate::types::{AnalysisGaps, CompactFacts, ContextLine, Finding, FindingKind, Istr, Note};
use crate::{AnalysisReport, Criticality, FileAnalysis, TargetInfo};

mod canonical;
pub mod features;
pub mod shared;

/// Candidate wire version. Production analysis still emits schema 8.
pub const VERSION: &str = "file-1";

/// Typed report envelope. Each file owns its trait and annotation definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report<'a> {
    /// Explicit schema discriminator, checked before conversion.
    pub v: String,
    /// Historical rules revision, when known by the producer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    /// Explicit model-input retention contract; absent means full facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// Ordered file occurrences. Analysis/placement splitting is a separate step.
    pub files: Vec<File<'a>>,
    /// Fetch observations owned by the fetching layer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fetched: Vec<serde_json::Value>,
}

/// One file's metadata, facts, findings and annotated context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct File<'a> {
    id: u32,
    path: String,
    #[serde(rename = "type")]
    file_type: String,
    sha: String,
    size: u64,
    #[serde(default, skip_serializing_if = "crate::types::is_zero_u32")]
    risk: u32,
    #[serde(default, skip_serializing_if = "crate::types::is_zero_u32")]
    depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Rel::is_member")]
    rel: Rel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    via: Option<String>,
    #[serde(default, skip_serializing_if = "Role::is_content")]
    role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ident: Option<filefacts::Identity>,
    #[serde(default, skip_serializing_if = "AnalysisGaps::is_empty")]
    analysis_gaps: AnalysisGaps,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    traits: Vec<Trait>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    supp: Vec<crate::types::Suppression>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    refs: Vec<CompactRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ctx: Vec<Context<'a>>,
    #[serde(default, skip_serializing_if = "CompactFacts::is_empty")]
    #[serde(serialize_with = "canonical::facts")]
    facts: Cow<'a, CompactFacts>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(serialize_with = "canonical::registry")]
    registry: BTreeMap<String, serde_json::Value>,
}

/// Actual finding, in its original order and with its own historical values.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Trait {
    id: Istr,
    #[serde(with = "crit_ordinal")]
    crit: Criticality,
    #[serde(default, skip_serializing_if = "Istr::is_empty")]
    desc: Istr,
    // Confidence is required. Absence must not invent a threshold decision.
    conf: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mbc: Option<Istr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    atk: Option<Istr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    spans: Vec<[u64; 2]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    uses: Vec<TraitRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    src: Option<u32>,
    // None and Some([]) differ: the latter records explicit composite provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<Vec<CompositeSource>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    local: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum TraitRef {
    Index(u32),
    // A component absent after filtering remains an explicit unresolved ID.
    Missing(Istr),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Context<'a> {
    ln: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    line: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    col: Option<u64>,
    #[serde(with = "cow_z85")]
    b: Cow<'a, [u8]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    n: Vec<Annotation>,
    // Original captured length only when different from b.len().
    #[serde(default, skip_serializing_if = "Option::is_none")]
    w: Option<usize>,
}

// A trailing caption is present only if capture and final finding disagree.
// Derive handles the optional tuple tail directly, without an untagged retry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Annotation(
    u32,
    u64,
    u32,
    #[serde(default, skip_serializing_if = "Option::is_none")] Option<Caption>,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Caption(#[serde(with = "crit_ordinal")] Criticality, Istr, f32);

mod cow_z85 {
    use serde::{Deserializer, Serializer};
    use std::borrow::Cow;
    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        crate::types::z85::serde_z85::serialize(bytes, serializer)
    }
    pub(super) fn deserialize<'de, 'a, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Cow<'a, [u8]>, D::Error> {
        crate::types::z85::serde_z85::deserialize(deserializer).map(Cow::Owned)
    }
}

impl<'a> Report<'a> {
    /// Build typed wire records directly from finalized analysis, without v8
    /// serialization or deduplication followed by replay overrides.
    pub fn from_analysis(report: &'a AnalysisReport) -> Result<Self> {
        Self::build(report, false)
    }

    /// Select model facts during projection, before copying exhaustive inventories.
    pub fn for_model(report: &'a AnalysisReport) -> Result<Self> {
        Self::build(report, true)
    }

    fn build(report: &'a AnalysisReport, retain_model: bool) -> Result<Self> {
        let mut files = Vec::with_capacity(report.files.len());
        for file in &report.files {
            let mut positions = HashMap::with_capacity(file.findings.len());
            for (i, f) in file.findings.iter().enumerate() {
                positions.entry(f.id.as_str()).or_insert(u32::try_from(i)?);
            }
            let traits = file
                .findings
                .iter()
                .enumerate()
                .map(|(i, f)| Trait {
                    id: f.id.clone(),
                    crit: f.crit,
                    desc: f.desc.clone(),
                    conf: f.conf,
                    mbc: f.mbc.clone(),
                    atk: f.attack.clone(),
                    spans: finding_spans(f),
                    uses: f
                        .trait_refs
                        .iter()
                        .map(|id| {
                            positions.get(id.as_str()).map_or_else(
                                || TraitRef::Missing(id.clone()),
                                |&j| TraitRef::Index(j),
                            )
                        })
                        .collect(),
                    src: f.src,
                    from: file.composite_sources.get(f.id.as_str()).cloned(),
                    local: file.finding_has_local_offset(i),
                })
                .collect();
            let ctx = file
                .context
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let n = c
                        .notes
                        .iter()
                        .filter_map(|n| {
                            // Final filtering can remove a note's finding. Such a note
                            // cannot participate in lean selection or composite legs.
                            let &index = positions.get(n.id.as_str())?;
                            let f = &file.findings[index as usize];
                            let caption = (n.crit != f.crit
                                || n.desc != f.desc
                                || n.conf.to_bits() != f.conf.to_bits())
                            .then(|| Caption(n.crit, n.desc.clone(), n.conf));
                            Some(Annotation(index, n.off, n.len, caption))
                        })
                        .collect();
                    Context {
                        ln: c.loc,
                        line: c.line,
                        col: c.col,
                        b: Cow::Borrowed(&c.data),
                        n,
                        w: file
                            .context_costs
                            .get(i)
                            .copied()
                            .filter(|&cost| cost != c.data.len()),
                    }
                })
                .collect();
            let mol = file.formula.clone().or_else(|| {
                let findings = crate::output::filter_findings_for_formula(&file.findings);
                let mol = crate::malecule_bridge::formula_from_findings(&findings);
                (!mol.is_empty()).then_some(mol)
            });
            files.push(File {
                id: file.id,
                path: file.path.clone(),
                file_type: file.file_type.clone(),
                sha: file.sha256.clone(),
                size: file.size,
                risk: file.score,
                depth: file.depth,
                pid: file.parent_id,
                rel: file.rel,
                via: file.via.clone(),
                role: file.role,
                mol,
                ident: file.identity.clone(),
                analysis_gaps: file.analysis_gaps.clone(),
                traits,
                supp: file.suppressions.clone(),
                refs: refs_from_file(file),
                ctx,
                facts: if retain_model {
                    Cow::Owned(crate::model_facts::from_file(file))
                } else {
                    match &file.precompact_facts {
                        Some(facts)
                            if facts.metrics.is_some() || file.filefacts_metrics.is_none() =>
                        {
                            Cow::Borrowed(facts)
                        }
                        _ => Cow::Owned(facts_from_file(file)),
                    }
                },
                registry: file
                    .kv
                    .iter()
                    .filter(|(k, _)| k.starts_with("registry."))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            });
        }
        Ok(Self {
            v: VERSION.into(),
            rev: None,
            fp: retain_model.then(|| crate::model_facts::profile_id().into()),
            files,
            fetched: Vec::new(),
        })
    }

    /// Retain the audited union of shipping model inputs, preserving evidence.
    pub fn retain_model_facts(&mut self) {
        for file in &mut self.files {
            file.facts = Cow::Owned(crate::model_facts::project(&file.facts));
        }
        self.fp = Some(crate::model_facts::profile_id().into());
    }

    /// Convert to the existing presentation model. No rules or matcher evidence
    /// are reconstructed. This compatibility allocation is included in timings.
    pub fn into_loaded(self) -> Result<LoadedReport> {
        ensure!(self.v == VERSION, "unsupported file profile {}", self.v);
        if let Some(fp) = &self.fp {
            crate::model_facts::supports(fp, &[])?;
        }
        let mut report = AnalysisReport::new(TargetInfo::default());
        report.files.reserve(self.files.len());
        for wire in self.files {
            let mut file = FileAnalysis {
                id: wire.id,
                path: wire.path,
                file_type: wire.file_type,
                sha256: wire.sha,
                size: wire.size,
                score: wire.risk,
                depth: wire.depth,
                parent_id: wire.pid,
                rel: wire.rel,
                via: wire.via,
                role: wire.role,
                formula: wire.mol,
                identity: wire.ident,
                analysis_gaps: wire.analysis_gaps,
                suppressions: wire.supp,
                precompact_facts: Some(wire.facts.into_owned()),
                precompact_refs: Some(wire.refs),
                kv: wire.registry,
                ..FileAnalysis::default()
            };
            let ids: Vec<_> = wire.traits.iter().map(|f| f.id.clone()).collect();
            for t in wire.traits {
                ensure!(t.conf.is_finite(), "non-finite finding confidence");
                let mut f = Finding::new(t.id, FindingKind::Indicator, t.desc, t.conf);
                f.crit = t.crit;
                f.mbc = t.mbc;
                f.attack = t.atk;
                f.src = t.src;
                f.precomputed_spans = Some(t.spans);
                f.trait_refs = t
                    .uses
                    .into_iter()
                    .map(|r| match r {
                        TraitRef::Index(i) => {
                            ids.get(i as usize).cloned().context("invalid trait index")
                        }
                        TraitRef::Missing(id) => Ok(id),
                    })
                    .collect::<Result<_>>()?;
                if let Some(sources) = t.from
                    && let Some(existing) = file
                        .composite_sources
                        .insert(f.id.to_string(), sources.clone())
                {
                    ensure!(
                        existing == sources,
                        "conflicting composite provenance for {}",
                        f.id
                    );
                }

                file.render_locality.push(t.local);
                file.findings.push(f);
            }
            let has_costs = wire.ctx.iter().any(|c| c.w.is_some());
            for c in wire.ctx {
                if has_costs {
                    file.context_costs.push(c.w.unwrap_or(c.b.len()));
                }
                let mut notes = Vec::with_capacity(c.n.len());
                for Annotation(i, off, len, caption) in c.n {
                    let f = file
                        .findings
                        .get(i as usize)
                        .context("invalid annotation index")?;
                    let Caption(crit, desc, conf) =
                        caption.unwrap_or_else(|| Caption(f.crit, f.desc.clone(), f.conf));
                    ensure!(conf.is_finite(), "non-finite annotation confidence");
                    notes.push(Note {
                        id: f.id.clone(),
                        crit,
                        desc,
                        conf,
                        off,
                        len,
                    });
                }
                file.context.push(ContextLine {
                    loc: c.ln,
                    line: c.line,
                    col: c.col,
                    data: c.b.into_owned(),
                    notes,
                });
            }
            report.files.push(file);
        }
        crate::report_input::validate(&report)?;
        Ok(LoadedReport {
            report,
            fetched: self.fetched,
            traits_version: self.rev,
            fact_profile: self.fp,
            warnings: Vec::new(),
        })
    }
}

/// Decode directly into typed records, then the compatibility presentation view.
pub fn decode(bytes: &[u8]) -> Result<LoadedReport> {
    serde_json::from_slice::<Report<'_>>(bytes)?.into_loaded()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::output::format_tiny;
    use crate::types::compact_from_files;

    fn fixture() -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo::default());
        let mut first = Finding::new(
            "micro-behaviors/eval::call",
            FindingKind::Capability,
            "Evaluates code",
            0.5,
        );
        first.crit = Criticality::Notable;
        first.precomputed_spans = Some(vec![[0, 0]]);
        first.trait_refs = vec![
            first.id.clone(),
            "filtered::missing".into(),
            first.id.clone(),
        ];
        let mut second = first.clone();
        second.crit = Criticality::Hostile;
        second.conf = 0.99;
        second.desc = "Different historical description".into();
        second.src = Some(1);
        let mut file = FileAnalysis {
            id: 0,
            path: "fixture.exe".into(),
            file_type: "pe".into(),
            sha256: "a".repeat(64),
            size: 4096,
            score: 100,
            findings: vec![first.clone(), second],
            render_locality: vec![true, false],
            context_costs: vec![1024],
            context: vec![ContextLine {
                loc: 0,
                line: None,
                col: None,
                data: b"eval(data);".to_vec(),
                notes: vec![Note {
                    id: first.id,
                    desc: "Capture-time caption".into(),
                    crit: Criticality::Suspicious,
                    conf: 0.65,
                    off: 0,
                    len: 4,
                }],
            }],
            precompact_refs: Some(vec![CompactRef {
                locator: "https://example.invalid/dep".into(),
                kind: "url_fetch".into(),
                offset: Some(0),
                target_file: Some(1),
            }]),
            ..FileAnalysis::default()
        };
        file.composite_sources.insert(
            file.findings[0].id.to_string(),
            vec![CompositeSource {
                file: 1,
                line: Some(1),
                offset: Some(0),
            }],
        );
        report.files = vec![
            file,
            FileAnalysis {
                id: 1,
                path: "child".into(),
                parent_id: Some(0),
                depth: 1,
                ..FileAnalysis::default()
            },
        ];
        report
    }

    #[test]
    fn canonical_fields_preserve_duplicates_captions_references_and_model_inputs() {
        let report = fixture();
        let bytes = serde_json::to_vec(&Report::from_analysis(&report).unwrap()).unwrap();
        let loaded = decode(&bytes).unwrap();
        assert_eq!(format_tiny(&loaded.report), format_tiny(&report));
        assert_eq!(loaded.report.files[0].findings.len(), 2);
        assert_eq!(
            loaded.report.files[0].findings[1].desc.as_str(),
            "Different historical description"
        );
        assert_eq!(
            loaded.report.files[0].findings[0].trait_refs,
            report.files[0].findings[0].trait_refs
        );
        assert_eq!(loaded.report.files[0].render_locality, vec![true, false]);
        assert!(
            loaded.report.files[0]
                .findings
                .iter()
                .all(|f| f.evidence.is_empty())
        );
        assert_eq!(
            serde_json::to_value(compact_from_files(&report.files)).unwrap(),
            serde_json::to_value(compact_from_files(&loaded.report.files)).unwrap()
        );
        assert_eq!(
            bytes,
            serde_json::to_vec(&Report::from_analysis(&loaded.report).unwrap()).unwrap(),
            "canonical re-encode must be stable"
        );
    }

    #[test]
    fn tuple_tail_and_direct_envelope_dispatch() {
        let a: Annotation = serde_json::from_str("[0,0,0]").unwrap();
        assert!(a.3.is_none());
        assert_eq!(serde_json::to_string(&a).unwrap(), "[0,0,0]");
        let report = fixture();
        let mut wire = Report::from_analysis(&report).unwrap();
        wire.fetched.push(serde_json::json!({"status":"pending"}));
        wire.rev = Some("historical-revision".into());
        for raw in [
            serde_json::to_value(&wire).unwrap(),
            serde_json::Value::String(serde_json::to_string(&wire).unwrap()),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({"ml":{"v":"7"},"raw":raw})).unwrap();
            let loaded = crate::report_input::decode(&bytes).unwrap();
            assert_eq!(format_tiny(&loaded.report), format_tiny(&report));
            assert_eq!(loaded.fetched.len(), 1);
            assert_eq!(
                loaded.traits_version.as_deref(),
                Some("historical-revision")
            );
            assert!(loaded.warnings.is_empty());
        }
    }

    #[test]
    fn invalid_indices_costs_versions_and_missing_confidence_fail() {
        let value = serde_json::to_value(Report::from_analysis(&fixture()).unwrap()).unwrap();
        let mut bad = value.clone();
        bad["files"][0]["traits"][0]["uses"] = serde_json::json!([999]);
        assert!(decode(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = value.clone();
        bad["files"][0]["ctx"][0]["n"][0][0] = serde_json::json!(999);
        assert!(decode(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = value.clone();
        bad["files"][0]["ctx"][0]["w"] = serde_json::json!(1);
        assert!(decode(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = value.clone();
        bad["files"][0]["traits"][0]
            .as_object_mut()
            .unwrap()
            .remove("conf");
        assert!(decode(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = value.clone();
        bad["files"][0]["traits"][0]["crit"] = serde_json::json!(99);
        assert!(decode(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = value;
        bad["v"] = serde_json::json!("9");
        assert!(decode(&serde_json::to_vec(&bad).unwrap()).is_err());
    }

    #[test]
    fn borrows_captured_bytes_and_retains_model_facts_without_render_changes() {
        let report = fixture();
        let mut wire = Report::from_analysis(&report).unwrap();
        assert!(matches!(wire.files[0].ctx[0].b, Cow::Borrowed(_)));
        assert_eq!(
            wire.files[0].ctx[0].b.as_ptr(),
            report.files[0].context[0].data.as_ptr()
        );
        wire.retain_model_facts();
        let bytes = serde_json::to_vec(&wire).unwrap();
        let loaded = decode(&bytes).unwrap();
        assert_eq!(
            loaded.fact_profile.as_deref(),
            Some(crate::model_facts::profile_id())
        );
        assert_eq!(format_tiny(&loaded.report), format_tiny(&report));
        let mut again = Report::from_analysis(&loaded.report).unwrap();
        again.retain_model_facts();
        assert_eq!(serde_json::to_vec(&again).unwrap(), bytes);
    }
}
