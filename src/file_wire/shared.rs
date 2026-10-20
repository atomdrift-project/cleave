//! Report-local sharing of exactly equal canonical analyses, with placements
//! kept separately. Split leaves use the same standalone file record type.
use super::{File, Report};
use crate::types::file_analysis::{Rel, Role};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Diagnostic joined format; no shared catalog outside this JSON document.
pub const VERSION: &str = "joined-2";
/// Previous candidate, retaining explicit locality on its analyses.
pub const LEGACY_VERSION: &str = "joined-1";

fn profiles(joined: &str) -> Result<(&'static str, &'static str)> {
    match joined {
        VERSION => Ok((super::VERSION, "split-2")),
        LEGACY_VERSION => Ok((super::LEGACY_VERSION, "split-1")),
        _ => anyhow::bail!("unsupported shared profile {joined}"),
    }
}

/// A complete occurrence. `a` addresses this document's canonical analysis list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Placement {
    /// Original report-local file identity.
    pub id: u32,
    /// Exact original display path.
    pub path: String,
    /// Canonical analysis index, independent of the occurrence ID.
    pub a: usize,
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
}

/// Joined analyses and complete ordered occurrences. Equal SHA is only a
/// candidate for sharing; the entire canonical analysis must also be equal.
#[derive(Debug, Serialize, Deserialize)]
pub struct SharedReport<'a> {
    v: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fp: Option<String>,
    files: Vec<Placement>,
    a: Vec<File<'a>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fetched: Vec<serde_json::Value>,
}

/// The small snapshot manifest stored alongside independent canonical leaves.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    v: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fp: Option<String>,
    files: Vec<Placement>,
    a: Vec<Summary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fetched: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Summary {
    key: String,
    sha: String,
    #[serde(rename = "type")]
    file_type: String,
    size: u64,
    risk: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mol: Option<String>,
    #[serde(default, skip_serializing_if = "crate::types::AnalysisGaps::is_empty")]
    analysis_gaps: crate::types::AnalysisGaps,
}

fn leaf_bytes(
    file: &File<'_>,
    v: &'static str,
    rev: Option<&str>,
    fp: Option<&str>,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Leaf<'a, 'b> {
        v: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        rev: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fp: Option<&'a str>,
        files: [&'a File<'b>; 1],
    }
    Ok(serde_json::to_vec(&Leaf {
        v,
        rev,
        fp,
        files: [file],
    })?)
}

fn summary(file: &File<'_>, bytes: &[u8]) -> Summary {
    Summary {
        key: hex::encode(Sha256::digest(bytes)),
        sha: file.sha.clone(),
        file_type: file.file_type.clone(),
        size: file.size,
        risk: file.risk,
        mol: file.mol.clone(),
        analysis_gaps: file.analysis_gaps.clone(),
    }
}

impl<'a> Report<'a> {
    /// Move records into a shared joined representation. Hash/serialize only
    /// records whose nonempty SHA repeats; do not pay that cost on unique files.
    pub fn into_shared(self) -> Result<SharedReport<'a>> {
        let version = match self.v.as_str() {
            super::VERSION => VERSION,
            super::LEGACY_VERSION => LEGACY_VERSION,
            _ => anyhow::bail!("unsupported file profile {}", self.v),
        };
        let mut seen = HashSet::new();
        let mut repeated = HashSet::new();
        for f in &self.files {
            if !f.sha.is_empty() && !seen.insert(f.sha.as_str()) {
                repeated.insert(f.sha.clone());
            }
        }
        let mut lookup: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut files = Vec::with_capacity(self.files.len());
        let mut analyses = Vec::with_capacity(self.files.len());
        for mut f in self.files {
            let mut place = Placement {
                id: f.id,
                path: std::mem::take(&mut f.path),
                a: 0,
                depth: f.depth,
                pid: f.pid,
                rel: f.rel,
                via: f.via.take(),
                role: f.role,
            };
            f.id = 0;
            f.depth = 0;
            f.pid = None;
            f.rel = Rel::Member;
            f.role = Role::Content;
            let index = if repeated.contains(&f.sha) {
                let canonical = serde_json::to_vec(&f)?;
                if let Some(&index) = lookup.get(&canonical) {
                    index
                } else {
                    let index = analyses.len();
                    lookup.insert(canonical, index);
                    analyses.push(f);
                    index
                }
            } else {
                let index = analyses.len();
                analyses.push(f);
                index
            };
            place.a = index;
            files.push(place);
        }
        Ok(SharedReport {
            v: version.into(),
            rev: self.rev,
            fp: self.fp,
            files,
            a: analyses,
            fetched: self.fetched,
        })
    }
}

impl<'a> SharedReport<'a> {
    /// Number of stored canonical analyses, not the number of occurrences.
    #[must_use]
    pub fn analysis_count(&self) -> usize {
        self.a.len()
    }

    /// Split by exact analysis identity. No SHA-only deduplication or data loss.
    /// Durable analysis IDs/renewal transactions remain a hopper storage concern.
    pub fn split(self) -> Result<(Manifest, Vec<File<'a>>)> {
        let (flat, split) = profiles(&self.v)?;
        let summaries = self
            .a
            .iter()
            .map(|a| {
                Ok(summary(
                    a,
                    &leaf_bytes(a, flat, self.rev.as_deref(), self.fp.as_deref())?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok((
            Manifest {
                v: split.into(),
                rev: self.rev,
                fp: self.fp,
                files: self.files,
                a: summaries,
                fetched: self.fetched,
            },
            self.a,
        ))
    }

    /// Rejoin a pinned list of canonical leaves with its occurrence manifest.
    pub fn join(manifest: Manifest, analyses: Vec<File<'a>>) -> Result<Self> {
        let version = match manifest.v.as_str() {
            "split-2" => VERSION,
            "split-1" => LEGACY_VERSION,
            _ => anyhow::bail!("unsupported split profile {}", manifest.v),
        };
        let (flat, _) = profiles(version)?;
        anyhow::ensure!(manifest.a.len() == analyses.len(), "missing split analyses");
        for (s, a) in manifest.a.iter().zip(&analyses) {
            let actual = summary(
                a,
                &leaf_bytes(a, flat, manifest.rev.as_deref(), manifest.fp.as_deref())?,
            );
            anyhow::ensure!(
                s.key == actual.key
                    && s.sha == actual.sha
                    && s.file_type == actual.file_type
                    && s.size == actual.size
                    && s.risk == actual.risk
                    && s.mol == actual.mol
                    && s.analysis_gaps.iter().eq(actual.analysis_gaps.iter()),
                "split analysis does not match pinned manifest"
            );
        }
        for p in &manifest.files {
            anyhow::ensure!(p.a < analyses.len(), "invalid analysis index {}", p.a);
        }
        Ok(Self {
            v: version.into(),
            rev: manifest.rev,
            fp: manifest.fp,
            files: manifest.files,
            a: analyses,
            fetched: manifest.fetched,
        })
    }

    /// Materialize only for the existing renderer/legacy compatibility path.
    /// Direct feature readers keep analyses shared and skip all context bytes.
    pub fn into_loaded(self) -> Result<crate::report_input::LoadedReport> {
        let (flat, _) = profiles(&self.v)?;
        let mut files = Vec::with_capacity(self.files.len());
        let mut remaining = vec![0usize; self.a.len()];
        for p in &self.files {
            *remaining.get_mut(p.a).context("invalid analysis index")? += 1;
        }
        let mut analyses: Vec<_> = self.a.into_iter().map(Some).collect();
        for p in self.files {
            remaining[p.a] -= 1;
            let a = &mut analyses[p.a];
            let mut f = if remaining[p.a] == 0 {
                a.take()
            } else {
                a.clone()
            }
            .context("missing analysis")?;
            f.id = p.id;
            f.path = p.path;
            f.depth = p.depth;
            f.pid = p.pid;
            f.rel = p.rel;
            f.via = p.via;
            f.role = p.role;
            files.push(f);
        }
        Report {
            v: flat.into(),
            rev: self.rev,
            fp: self.fp,
            files,
            fetched: self.fetched,
        }
        .into_loaded()
    }

    /// Native JSONB split benchmark rows: one manifest and one row per exact
    /// analysis, including schema/profile metadata on each independent leaf.
    pub fn storage_rows(&self) -> Result<Vec<Vec<u8>>> {
        let (flat, split) = profiles(&self.v)?;
        // A standalone file needs no separate placement/leaf transaction.
        if self.files.len() == 1 {
            return Ok(vec![serde_json::to_vec(self)?]);
        }
        #[derive(Serialize)]
        struct ManifestRef<'a> {
            v: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            rev: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            fp: Option<&'a str>,
            files: &'a [Placement],
            a: Vec<Summary>,
            #[serde(skip_serializing_if = "<[serde_json::Value]>::is_empty")]
            fetched: &'a [serde_json::Value],
        }
        let mut rows = Vec::with_capacity(self.a.len() + 1);
        let mut summaries = Vec::with_capacity(self.a.len());
        for a in &self.a {
            let bytes = leaf_bytes(a, flat, self.rev.as_deref(), self.fp.as_deref())?;
            summaries.push(summary(a, &bytes));
            rows.push(bytes);
        }
        let manifest = ManifestRef {
            v: split,
            rev: self.rev.as_deref(),
            fp: self.fp.as_deref(),
            files: &self.files,
            a: summaries,
            fetched: &self.fetched,
        };
        rows.insert(0, serde_json::to_vec(&manifest)?);

        Ok(rows)
    }
}

/// Decode the complete joined snapshot without fetching anything externally.
pub fn decode(bytes: &[u8]) -> Result<crate::report_input::LoadedReport> {
    serde_json::from_slice::<SharedReport<'_>>(bytes)?.into_loaded()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::output::format_tiny;
    use crate::{AnalysisReport, Criticality, FileAnalysis, Finding, TargetInfo};

    fn fixture() -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo::default());
        let mut f = Finding::capability(
            "micro-behaviors/sample::one".into(),
            "A historical behavior".into(),
            0.75,
        );
        f.crit = Criticality::Notable;
        let first = FileAnalysis {
            id: 0,
            path: "root".into(),
            sha256: "a".repeat(64),
            file_type: "pe".into(),
            size: 100,
            findings: vec![f],
            ..FileAnalysis::default()
        };
        let mut second = first.clone();
        second.id = 9;
        second.path = "root!!duplicate".into();
        second.depth = 1;
        second.parent_id = Some(0);
        let mut third = second.clone();
        third.id = 7;
        third.path = "root!!different".into();
        third.findings[0].conf = 0.95;
        report.files = vec![first, second, third];
        report
    }

    #[test]
    fn shares_equal_analyses_but_not_sha_only_and_preserves_placements() {
        let report = fixture();
        let wire = Report::from_analysis(&report)
            .unwrap()
            .into_shared()
            .unwrap();
        assert_eq!(wire.analysis_count(), 2);
        assert_eq!(
            wire.files.iter().map(|p| p.a).collect::<Vec<_>>(),
            vec![0, 0, 1]
        );
        let bytes = serde_json::to_vec(&wire).unwrap();
        let loaded = decode(&bytes).unwrap();
        assert_eq!(format_tiny(&loaded.report), format_tiny(&report));
        assert_eq!(
            loaded.report.files.iter().map(|f| f.id).collect::<Vec<_>>(),
            vec![0, 9, 7]
        );
        assert_eq!(loaded.report.files[1].parent_id, Some(0));
        let direct = crate::file_wire::features::FeatureReport::from_slice(&bytes).unwrap();
        assert_eq!(direct.analyses.len(), 2);
        assert_eq!(direct.files.len(), 3);
    }

    #[test]
    fn split_roundtrip_pins_full_payload_and_rejects_renewed_or_missing_leaves() {
        let report = fixture();
        let wire = Report::from_analysis(&report)
            .unwrap()
            .into_shared()
            .unwrap();
        let expected = serde_json::to_vec(&wire).unwrap();
        let (manifest, analyses) = wire.split().unwrap();
        let stored = serde_json::to_vec(&manifest).unwrap();
        let leaves = serde_json::to_vec(&analyses).unwrap();
        let restored = SharedReport::join(
            serde_json::from_slice(&stored).unwrap(),
            serde_json::from_slice(&leaves).unwrap(),
        )
        .unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), expected);
        let (manifest, mut analyses) = restored.split().unwrap();
        analyses[0].traits[0].conf = 0.99;
        assert!(
            SharedReport::join(manifest, analyses).is_err(),
            "new analysis must not change a pinned snapshot"
        );
        let analyses: Vec<File<'_>> = serde_json::from_slice(&leaves).unwrap();
        assert!(
            SharedReport::join(
                serde_json::from_slice(&stored).unwrap(),
                analyses.into_iter().take(1).collect()
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_shared_and_split_keep_versions_locality_and_leaf_hashes() {
        let report = fixture();
        let mut flat = Report::from_analysis(&report).unwrap();
        flat.v = super::super::LEGACY_VERSION.into();
        for file in &mut flat.files {
            file.traits[0].legacy_local = Some(true);
            file.traits[0].spans = vec![[0, 4]];
        }
        let shared = flat.into_shared().unwrap();
        let expected = serde_json::to_vec(&shared).unwrap();
        assert_eq!(shared.v, LEGACY_VERSION);
        let rows = shared.storage_rows().unwrap();
        let manifest: Manifest = serde_json::from_slice(&rows[0]).unwrap();
        assert_eq!(manifest.v, "split-1");
        for (summary, bytes) in manifest.a.iter().zip(&rows[1..]) {
            assert_eq!(summary.key, hex::encode(Sha256::digest(bytes)));
            let leaf: Report<'_> = serde_json::from_slice(bytes).unwrap();
            assert_eq!(leaf.v, super::super::LEGACY_VERSION);
        }
        let (manifest, analyses) = shared.split().unwrap();
        let joined = SharedReport::join(manifest, analyses).unwrap();
        assert_eq!(serde_json::to_vec(&joined).unwrap(), expected);
        let decoded = crate::report_input::decode(&expected).unwrap();
        assert!(
            decoded
                .report
                .files
                .iter()
                .all(|f| f.render_locality == vec![true])
        );
        assert!(crate::file_wire::features::FeatureReport::from_slice(&expected).is_ok());
    }

    #[test]
    fn split_keys_ignore_nested_object_order_like_jsonb() {
        fn reverse_objects(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(map) => {
                    let entries = std::mem::take(map);
                    for (k, mut v) in entries.into_iter().rev() {
                        reverse_objects(&mut v);
                        map.insert(k, v);
                    }
                }
                serde_json::Value::Array(values) => {
                    for v in values {
                        reverse_objects(v);
                    }
                }
                _ => {}
            }
        }
        let report = fixture();
        let mut wire = Report::from_analysis(&report).unwrap();
        wire.files[0].facts=std::borrow::Cow::Owned(serde_json::from_value(serde_json::json!({
            "metrics":{"binary":{"code_entropy":6.38,"code_to_data_ratio":0.99},"file":{"size":100}}
        })).unwrap());
        wire.files[0].registry.insert(
            "registry.object".into(),
            serde_json::json!({"z":1,"a":[{"zz":2,"bb":3}]}),
        );
        let (manifest, files) = wire.into_shared().unwrap().split().unwrap();
        let mut value = serde_json::to_value(&files).unwrap();
        reverse_objects(&mut value);
        let restored =
            SharedReport::join(manifest, serde_json::from_value(value).unwrap()).unwrap();
        assert_eq!(restored.analysis_count(), 3);
    }
}
