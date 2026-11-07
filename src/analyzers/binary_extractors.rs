//! Byte-level extractors that still augment the binary kv tree from
//! cleave: builder paths and usernames, and the PE version-info key scan.
//! Both are slated to move into filefacts (see `FILEFACTS_TODO.md`).

use crate::types::AnalysisReport;

// ---------------------------------------------------------------------------
// Aggregate hook: layer extracted data onto the binary kv tree
// ---------------------------------------------------------------------------

/// Run all post-analysis extractors and merge their results into
/// `report.values_tree`. Idempotent: safe to call multiple times.
pub(crate) fn augment_report(report: &mut AnalysisReport, raw_data: &[u8]) {
    use serde_json::{Value, json};

    // Build the augmenting Value first so we don't have to worry
    // about partial-update consistency.
    let mut augment = serde_json::Map::new();

    // Builder-path / username recovery.  Cross-format byte scan
    // for `/home/<u>/`, `/Users/<u>/`, and `C:\Users\<u>\` —
    // these leak the build host's filesystem layout and the
    // developer's username (strong attribution signal that
    // survives stripping).
    //
    // Naming: when exactly one canonical username is recovered we
    // expose the singular `username`; otherwise we expose the
    // array `usernames` (mutually exclusive shapes).  Trait authors
    // target one or the other based on cardinality; the
    // `username_from` field carries provenance.
    let bp = super::builder_paths::extract(raw_data);
    if !bp.usernames.is_empty() || !bp.source_dirs.is_empty() || !bp.full_paths.is_empty() {
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            match bp.usernames.len() {
                0 => {}
                1 => {
                    obj.insert("username".into(), json!(bp.usernames[0].clone()));
                    if let Some(home) = bp.source_dirs.first() {
                        obj.insert("user_home".into(), json!(home.clone()));
                    }
                    obj.insert("username_from".into(), json!("byte_scan"));
                }
                _ => {
                    obj.insert("usernames".into(), json!(bp.usernames.clone()));
                }
            }
            if !bp.full_paths.is_empty() {
                obj.insert("source_paths".into(), json!(bp.full_paths.clone()));
            }
            // Build-root: longest common ancestor of discovered
            // builder-anchored paths.
            if let Some(root) = super::builder_paths::find_build_root(&bp.full_paths) {
                obj.insert("build_root".into(), json!(root));
            }
        }
    }

    // PDB-derived username for PE binaries (when filefacts surfaced the
    // PDB path). The `.pdb` filename in the PE Debug Directory is a
    // single canonical reference, not subject to scan noise — preferred
    // when present.
    let pdb_path_from_filefacts = report
        .filefacts
        .as_ref()
        .and_then(|e| e.values.get("pe"))
        .and_then(|pe| pe.get("debug"))
        .and_then(|d| d.get("pdb"))
        .and_then(|p| p.get("path"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if let Some(pdb) = pdb_path_from_filefacts.as_deref()
        && let Some(user) = super::builder_paths::extract_username_from_pdb(pdb)
    {
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            // PDB is high-confidence; supersede byte-scan
            // results.  Drop `usernames[]` if PDB gave us a
            // canonical answer.
            obj.remove("usernames");
            obj.insert("username".into(), json!(user.clone()));
            obj.insert("username_from".into(), json!("pdb_path"));
        }
    }

    let mut augment = Value::Object(augment);
    if report.target.file_type == "pe"
        && let Some(resource_data) = report.sections.iter().find_map(|section| {
            if !section
                .name
                .trim_start_matches('.')
                .eq_ignore_ascii_case("rsrc")
            {
                return None;
            }
            let start = section.offset? as usize;
            let end = start.checked_add(section.size as usize)?;
            raw_data.get(start..end)
        })
    {
        super::pe_extractors::augment_version_info_tree(&mut augment, resource_data);
    }

    if augment.as_object().is_none_or(serde_json::Map::is_empty) {
        return;
    }

    // Merge `augment` into the existing values_tree (or create one).
    let existing = report
        .values_tree
        .take()
        .map(|b| *b)
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let merged = deep_merge(existing, augment);
    report.values_tree = Some(Box::new(merged));
}

/// Merge two JSON values, with `b` taking precedence at leaves.
/// Object keys union; arrays from `b` replace arrays from `a`.
fn deep_merge(a: serde_json::Value, b: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(mut am), Value::Object(bm)) => {
            for (k, bv) in bm {
                let av = am.remove(&k).unwrap_or(Value::Null);
                am.insert(k, deep_merge(av, bv));
            }
            Value::Object(am)
        }
        (_, b) => b,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn deep_merge_unions_objects() {
        use serde_json::json;
        let a = json!({"build": {"is_pie": true}, "elf": {"foo": 1}});
        let b = json!({"build": {"distro": "ubuntu"}});
        let m = deep_merge(a, b);
        assert_eq!(m["build"]["is_pie"], true);
        assert_eq!(m["build"]["distro"], "ubuntu");
        assert_eq!(m["elf"]["foo"], 1);
    }
}
