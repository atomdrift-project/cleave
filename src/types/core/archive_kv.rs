//! Report-level helpers for archive members and the values tree.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl AnalysisReport {
    /// Drop directory entries from `archive_contents`. They carry no
    /// analyzable content and the extraction paths recorded them
    /// inconsistently (the in-memory and zip/iso paths filtered them, the tar
    /// disk-extraction path kept them), so the member inventory of
    /// byte-identical archives depended on the path taken. The archive's
    /// `archive.*` facts are filefacts', from the archive's own bytes.
    pub(crate) fn prune_archive_directories(&mut self) {
        self.archive_contents
            .retain(|entry| entry.entry_type.as_deref() != Some("directory"));
    }

    /// Merge a per-format kv subtree into `values_tree` under `namespace`.
    /// Preserves existing namespaces; pre-existing non-object trees
    /// are stashed under `_legacy` so we never lose data. Used by
    /// every per-format kv attacher (`png`, `jpeg`, `class`, `pyc`,
    /// `pickle`, `jar`, `rpm`, …).
    pub(crate) fn merge_kv_subtree(&mut self, namespace: &str, value: serde_json::Value) {
        let mut root = match self.values_tree.take().map(|b| *b) {
            Some(serde_json::Value::Object(m)) => m,
            Some(other) => {
                let mut m = serde_json::Map::new();
                m.insert("_legacy".into(), other);
                m
            }
            None => serde_json::Map::new(),
        };
        // Deep-merge into any existing namespace value when both
        // sides are objects, so multiple contributors coexist instead
        // of clobbering.
        // Falls back to outright replace for non-object values.
        let merged = match (root.remove(namespace), value) {
            (Some(serde_json::Value::Object(existing)), serde_json::Value::Object(incoming)) => {
                serde_json::Value::Object(deep_merge_objects(existing, incoming))
            }
            (_, v) => v,
        };
        root.insert(namespace.into(), merged);
        self.values_tree = Some(Box::new(serde_json::Value::Object(root)));
    }
}
