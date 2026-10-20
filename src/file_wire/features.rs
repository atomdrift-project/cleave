//! Selective model reader: context, descriptions and suppression evidence are
//! skipped by serde rather than decoded and expanded into a rendering report.
use crate::types::CompactFacts;
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::collections::HashMap;

/// Only the finding fields that model extraction consumes.
#[derive(Debug, Deserialize)]
struct Finding {
    id: String,
    crit: u8,
    conf: f32,
    #[serde(default)]
    mbc: Option<String>,
    #[serde(default)]
    atk: Option<String>,
}

/// Coalesced model view: first confidence/codes and maximum severity per ID,
/// exactly matching compact v8's historical duplicate-finding semantics.
#[derive(Debug, Clone, Copy)]
pub struct ModelFinding<'a> {
    /// Historical trait identifier.
    pub id: &'a str,
    /// Historical first confidence, without rounding/defaulting.
    pub conf: f32,
    /// Maximum severity for this ID in the file.
    pub crit: u8,
    /// Historical behavior code.
    pub mbc: Option<&'a str>,
    /// Historical ATT&CK code.
    pub atk: Option<&'a str>,
}

/// A model-facing canonical analysis. No decoded context or descriptions.
#[derive(Debug, Deserialize)]
pub struct FeatureAnalysis {
    /// Original content identity.
    pub sha: String,
    /// Routing type.
    #[serde(rename = "type")]
    pub file_type: String,
    /// Exact file size.
    pub size: u64,
    /// Existing score semantics.
    #[serde(default)]
    pub risk: i64,
    /// Historical formula.
    #[serde(default)]
    pub mol: Option<String>,
    #[serde(default)]
    traits: Vec<Finding>,
    /// Full facts or facts covered by the explicit retention profile.
    #[serde(default)]
    pub facts: CompactFacts,
}

impl FeatureAnalysis {
    /// Borrow model inputs without constructing compact traits or matcher data.
    pub fn findings(&self) -> Result<Vec<ModelFinding<'_>>> {
        let mut positions = HashMap::with_capacity(self.traits.len());
        let mut out: Vec<ModelFinding<'_>> = Vec::with_capacity(self.traits.len());
        for f in &self.traits {
            ensure!(
                f.crit <= 6 && f.conf.is_finite(),
                "invalid finding grade/confidence"
            );
            let crit = if f.crit == 6 { 0 } else { f.crit };
            if let Some(&i) = positions.get(f.id.as_str()) {
                let existing: &mut ModelFinding<'_> = &mut out[i];
                existing.crit = existing.crit.max(crit);
            } else {
                positions.insert(f.id.as_str(), out.len());
                out.push(ModelFinding {
                    id: &f.id,
                    crit,
                    conf: f.conf,
                    mbc: f.mbc.as_deref(),
                    atk: f.atk.as_deref(),
                });
            }
        }
        Ok(out)
    }
}

/// One occurrence; model aggregates preserve its multiplicity and order.
#[derive(Debug, Deserialize)]
pub struct FeatureOccurrence {
    /// Display path used by existing structural features.
    pub path: String,
    /// Root selection follows the existing depth semantics.
    #[serde(default)]
    pub depth: u32,
    /// Canonical analysis index.
    pub a: usize,
}

#[derive(Deserialize)]
struct FlatFile {
    path: String,
    #[serde(default)]
    depth: u32,
    sha: String,
    #[serde(rename = "type")]
    file_type: String,
    size: u64,
    #[serde(default)]
    risk: i64,
    #[serde(default)]
    mol: Option<String>,
    #[serde(default)]
    traits: Vec<Finding>,
    #[serde(default)]
    facts: CompactFacts,
}

/// Parsed once per report; route extractors read these shared analyses directly.
#[derive(Debug)]
pub struct FeatureReport {
    /// Required retention contract, when facts were intentionally reduced.
    pub fp: Option<String>,
    /// All occurrences, including repeats of the same analysis.
    pub files: Vec<FeatureOccurrence>,
    /// Canonical inputs parsed once, without context allocations.
    pub analyses: Vec<FeatureAnalysis>,
}

impl FeatureReport {
    /// Parse diagnostic flat or joined JSON directly; unsupported profiles fail.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Header {
            v: String,
        }
        let header: Header = serde_json::from_slice(bytes)?;
        let report = match header.v.as_str() {
            super::VERSION | super::LEGACY_VERSION => {
                #[derive(Deserialize)]
                struct Flat {
                    #[serde(default)]
                    fp: Option<String>,
                    files: Vec<FlatFile>,
                }
                let flat: Flat = serde_json::from_slice(bytes)?;
                let mut files = Vec::with_capacity(flat.files.len());
                let mut analyses = Vec::with_capacity(flat.files.len());
                for f in flat.files {
                    files.push(FeatureOccurrence {
                        path: f.path,
                        depth: f.depth,
                        a: analyses.len(),
                    });
                    analyses.push(FeatureAnalysis {
                        sha: f.sha,
                        file_type: f.file_type,
                        size: f.size,
                        risk: f.risk,
                        mol: f.mol,
                        traits: f.traits,
                        facts: f.facts,
                    });
                }
                Self {
                    fp: flat.fp,
                    files,
                    analyses,
                }
            }
            super::shared::VERSION | super::shared::LEGACY_VERSION => {
                #[derive(Deserialize)]
                struct Joined {
                    #[serde(default)]
                    fp: Option<String>,
                    files: Vec<FeatureOccurrence>,
                    a: Vec<FeatureAnalysis>,
                }
                let joined: Joined = serde_json::from_slice(bytes)?;
                Self {
                    fp: joined.fp,
                    files: joined.files,
                    analyses: joined.a,
                }
            }
            _ => anyhow::bail!("unsupported feature wire version {}", header.v),
        };
        if let Some(fp) = &report.fp {
            crate::model_facts::supports(fp, &[])?;
        }
        for f in &report.files {
            ensure!(
                f.a < report.analyses.len(),
                "invalid feature analysis index"
            );
        }
        Ok(report)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn skips_context_and_preserves_legacy_duplicate_semantics() {
        let bytes = serde_json::to_vec(&serde_json::json!({"v":"file-1","files":[{
            "id":0,"path":"sample","type":"pe","sha":"a","size":42,
            "ctx":[{"b":"invalid Z85 deliberately ignored"}],
            "traits":[{"id":"a","crit":3,"conf":0.5,"mbc":"first"},
                {"id":"a","crit":6,"conf":0.99,"mbc":"last"},
                {"id":"a","crit":4,"conf":1.0}]
        }]}))
        .unwrap();
        let report = FeatureReport::from_slice(&bytes).unwrap();
        let fs = report.analyses[0].findings().unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].crit, 4);
        assert_eq!(fs[0].conf, 0.5);
        assert_eq!(fs[0].mbc, Some("first"));
        assert!(
            crate::file_wire::decode(&bytes).is_err(),
            "full evidence reader must still validate context"
        );
    }
}
