//! Explicit retention contract for the audited shipping Azoth inputs.
use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use anyhow::{Result, ensure};
use serde::Deserialize;

use crate::types::{CompactFacts, RoundedMetrics};

#[derive(Debug, Deserialize)]
struct Manifest {
    id: String,
    metrics: HashSet<String>,
    gap_tokens: HashSet<String>,
    families: HashSet<String>,
    parameterized_families: HashSet<String>,
    fixed_features: HashSet<String>,
    #[serde(skip)]
    fields: HashMap<String, HashSet<String>>,
}

#[allow(clippy::expect_used)]
fn manifest() -> &'static Manifest {
    static MANIFEST: OnceLock<Manifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        // The bundled manifest is generated and checked with the codec tests.
        let mut manifest: Manifest =
            serde_json::from_str(include_str!("model_facts_manifest.json"))
                .expect("invalid bundled model-facts manifest");
        for name in &manifest.metrics {
            if let Some((group, field)) = name.split_once('_') {
                manifest
                    .fields
                    .entry(group.into())
                    .or_default()
                    .insert(field.into());
            }
        }
        manifest
    })
}

/// Immutable input-contract identifier; independent of hourly trait revisions.
#[must_use]
pub fn profile_id() -> &'static str {
    &manifest().id
}

/// Reject a feature layout that requires data omitted by this profile.
pub fn supports(profile: &str, features: &[String]) -> Result<()> {
    ensure!(profile == profile_id(), "unknown fact profile {profile}");
    let m = manifest();
    for name in features {
        let (family, key) = name.split_once(':').unwrap_or((name, ""));
        ensure!(
            m.families.contains(family),
            "fact profile {profile} does not support {name}"
        );
        if family == "metrics" {
            ensure!(
                m.metrics.contains(key),
                "fact profile {profile} omits {name}"
            );
        } else if !m.parameterized_families.contains(family) {
            ensure!(
                m.fixed_features.contains(name),
                "fact profile {profile} has no dependency audit for {name}"
            );
        }
    }
    Ok(())
}

pub(crate) fn needed_symbol(raw: &str) -> bool {
    let tokens = &manifest().gap_tokens;
    // Scan's gap check uses original import tokens; collimator normalizes
    // whitespace first. Keep the union, without changing either reader.
    tokens.contains(raw)
        || (raw.chars().any(char::is_whitespace)
            && tokens.contains(
                raw.split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .as_str(),
            ))
}

/// Keep exact metric values/missingness and symbol rows needed by either
/// shipping extractor. Sections and unrelated exhaustive inventories are omitted.
#[must_use]
pub fn project(facts: &CompactFacts) -> CompactFacts {
    let metrics = facts.metrics.as_ref().and_then(|metrics| {
        let mut groups = serde_json::Map::new();
        if let Some(source) = metrics.0.as_object() {
            for (group, fields) in source {
                let Some(fields) = fields.as_object() else {
                    continue;
                };
                let kept: serde_json::Map<_, _> = fields
                    .iter()
                    .filter(|(field, _)| {
                        manifest()
                            .fields
                            .get(group)
                            .is_some_and(|keys| keys.contains(field.as_str()))
                    })
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if !kept.is_empty() {
                    groups.insert(group.clone(), kept.into());
                }
            }
        }
        (!groups.is_empty()).then(|| RoundedMetrics(groups.into()))
    });
    CompactFacts {
        metrics,
        imports: facts
            .imports
            .iter()
            .filter(|r| needed_symbol(&r.name) || (r.name.is_empty() && needed_symbol(&r.library)))
            .cloned()
            .collect(),
        exports: facts
            .exports
            .iter()
            .filter(|r| needed_symbol(&r.name))
            .cloned()
            .collect(),
        functions: facts
            .functions
            .iter()
            .filter(|r| needed_symbol(&r.name))
            .cloned()
            .collect(),
        targets: facts
            .targets
            .iter()
            .filter(|r| needed_symbol(r))
            .cloned()
            .collect(),
        members: facts
            .members
            .iter()
            .filter(|r| needed_symbol(r))
            .cloned()
            .collect(),
        sections: Vec::new(),
    }
}

/// Project raw metrics before constructing the nested JSON tree.
pub(crate) fn flat_metrics(
    source: Option<&std::collections::BTreeMap<String, f64>>,
) -> Option<RoundedMetrics> {
    let mut groups = serde_json::Map::new();
    for (key, value) in source.into_iter().flatten() {
        let (group, field) = key.split_once('.').unwrap_or(("default", key));
        if !manifest()
            .fields
            .get(group)
            .is_some_and(|fields| fields.contains(field))
        {
            continue;
        }
        let Some(number) = serde_json::Number::from_f64(*value) else {
            continue;
        };
        let fields = groups
            .entry(group.to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(fields) = fields.as_object_mut() {
            fields.insert(
                field.to_owned(),
                crate::types::compact::round_json_floats(number.into()),
            );
        }
    }
    (!groups.is_empty()).then(|| RoundedMetrics(groups.into()))
}

/// Preserve the legacy caps and rounding while selecting raw rows before copy.
pub(crate) fn from_file(file: &crate::FileAnalysis) -> CompactFacts {
    if let Some(pre) = &file.precompact_facts {
        let mut facts = project(pre);
        if pre.metrics.is_none() {
            facts.metrics = flat_metrics(file.filefacts_metrics.as_ref());
        }
        facts
    } else {
        crate::types::compact::compact_facts_selected(file, true, true)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[test]
    fn profile_preserves_missingness_values_and_both_gap_semantics() {
        let facts: CompactFacts = serde_json::from_value(serde_json::json!({
            "metrics":{"binary":{"overall_entropy":0,"unneeded":23},"text":{"total_lines":null,"lines":7},"file":{"entropy":2.28},"unused":{"x":1}},
            "imp":[["lib","socket"],["hashlib",""],["lib","  requests  "],["lib","not_used"]],
            "funcs":[["subprocess",12],["not_used",24]],"tgt":["os.system","no"],
            "sec":[[".text",0,42,1.0,"x"]]
        })).unwrap();
        let projected = project(&facts);
        assert_eq!(projected.imports.len(), 3);
        assert_eq!(projected.functions.len(), 1);
        assert_eq!(projected.targets, vec!["os.system"]);
        assert!(projected.sections.is_empty());
        let metrics = &projected.metrics.as_ref().unwrap().0;
        assert_eq!(metrics["binary"]["overall_entropy"], 0);
        assert!(metrics["text"]["total_lines"].is_null());
        // Models name these by their old keys and collimator back-fills them
        // from the renamed report keys, so the report keys must survive.
        assert_eq!(metrics["text"]["lines"], 7);
        assert_eq!(metrics["file"]["entropy"], 2.28);
        assert!(metrics["binary"].get("unneeded").is_none());
        assert!(supports(profile_id(), &["metrics:binary_overall_entropy".into()]).is_ok());
        assert!(supports(profile_id(), &["symbol:new".into()]).is_err());
        assert!(supports(profile_id(), &["metrics:new_input".into()]).is_err());
        assert!(supports(profile_id(), &["struct:unaudited_section_count".into()]).is_err());
        assert!(supports(profile_id(), &["present:a/new/trait".into()]).is_ok());
        assert!(supports(profile_id(), &["filetype:new".into(), "ghost:a/b".into()]).is_ok());
    }

    #[test]
    fn early_selection_matches_full_projection_including_caps_and_rounding() {
        let mut file = crate::FileAnalysis {
            imports: (0..4096)
                .map(|_| crate::types::Import::new("unneeded", None))
                .collect(),
            ..Default::default()
        };
        file.imports.push(crate::types::Import::new("socket", None));
        file.filefacts_metrics = Some(std::collections::BTreeMap::from([
            ("binary.overall_entropy".into(), 7.2345),
            ("text.total_lines".into(), 0.0),
            ("unused.count".into(), 123.0),
        ]));
        let old = project(&crate::types::compact::facts_from_file(&file));
        let early = from_file(&file);
        assert!(
            early.imports.is_empty(),
            "do not pull a match past the legacy cap"
        );
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            serde_json::to_value(&early).unwrap()
        );
        file.imports[0] = crate::types::Import::new("socket", None);
        let old = project(&crate::types::compact::facts_from_file(&file));
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            serde_json::to_value(from_file(&file)).unwrap()
        );
        file.precompact_facts = Some(crate::types::compact::compact_facts_from_parts(
            &file, false,
        ));
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            serde_json::to_value(from_file(&file)).unwrap()
        );
    }
}
