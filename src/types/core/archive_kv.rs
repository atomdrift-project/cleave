//! Sealing archive metadata into the report's values tree.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl AnalysisReport {
    /// Materialize an `archive.*` kv subtree from `archive_contents`.
    ///
    /// Emits one entry per member (with all forensic fields the extractors
    /// captured) plus aggregate subtrees that traits can match on without
    /// iterating the array themselves:
    ///
    /// - `archive.members[]` — full per-member objects (paths, sha256,
    ///   sizes, mode bits, mtime, uid/gid/uname/gname, link targets).
    /// - `archive.member_count` — total entries surfaced.
    /// - `archive.compression.{methods, method_counts, ratio}` — choice of
    ///   compressor across members and the aggregate ratio.
    /// - `archive.timing.{mtime_min, mtime_max, mtime_spread_seconds,
    ///   mtime_unique_count}` — temporal fingerprint useful for supply-chain
    ///   triage (genuine builds cluster, replays smear, reproducible builds
    ///   pin to one or two epochs).
    /// - `archive.security.{setuid_count, setgid_count, sticky_count,
    ///   world_writable_count, symlink_count, external_symlink_count}` —
    ///   permission/symlink shapes that gate supply-chain risk traits.
    /// - `archive.format.{entry_types, regular_count, symlink_count}` —
    ///   entry-type histogram (directories excluded; see below).
    /// - `archive.builder.{unames, gnames}` — POSIX ownership strings tar
    ///   often leaks (real usernames frequently appear in supply-chain samples).
    ///
    /// Directory entries are dropped up front. They carry no analyzable content,
    /// and the archive-analysis paths recorded them inconsistently — the
    /// in-memory and zip/iso paths already filter them, the tar disk-extraction
    /// path kept them — so every `archive.*` fact (member_count, members[], the
    /// security/timing aggregates) silently depended on which path an archive
    /// took. That made byte-identical archives diff as changed. Excluding
    /// directories here, once, makes the whole subtree files-only and
    /// path-independent, matching the dominant in-memory/zip behavior.
    ///
    /// Idempotent: callers may invoke this multiple times; the last call
    /// wins. No-op when `archive_contents` holds no file members.
    pub(crate) fn seal_archive_metadata_kv(&mut self) {
        self.archive_contents
            .retain(|entry| entry.entry_type.as_deref() != Some("directory"));
        if self.archive_contents.is_empty() {
            return;
        }

        use std::collections::BTreeMap;
        let mut method_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut entry_type_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut unames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut gnames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut mtimes: Vec<i64> = Vec::new();
        let mut total_uncompressed: u64 = 0;
        let mut total_compressed: u64 = 0;
        let mut setuid_count: u64 = 0;
        let mut setgid_count: u64 = 0;
        let mut sticky_count: u64 = 0;
        let mut world_writable_count: u64 = 0;
        let mut symlink_count: u64 = 0;
        let mut external_symlink_count: u64 = 0;

        let mut members = Vec::with_capacity(self.archive_contents.len());
        for entry in &self.archive_contents {
            let mut obj = serde_json::Map::new();
            obj.insert("path".into(), serde_json::Value::String(entry.path.clone()));
            obj.insert(
                "type".into(),
                serde_json::Value::String(entry.file_type.clone()),
            );
            obj.insert(
                "sha256".into(),
                serde_json::Value::String(entry.sha256.clone()),
            );
            obj.insert(
                "size_bytes".into(),
                serde_json::Value::Number(entry.size_bytes.into()),
            );
            if let Some(ref declared) = entry.declared_type {
                obj.insert(
                    "declared_type".into(),
                    serde_json::Value::String(declared.clone()),
                );
            }
            if entry.extension_type_mismatch {
                obj.insert(
                    "extension_type_mismatch".into(),
                    serde_json::Value::Bool(true),
                );
            }
            if let Some(entropy) = entry.entropy
                && let Some(number) = serde_json::Number::from_f64(entropy)
            {
                obj.insert("entropy".into(), serde_json::Value::Number(number));
            }
            if let Some(ref magic) = entry.magic_prefix {
                obj.insert(
                    "magic_prefix".into(),
                    serde_json::Value::String(magic.clone()),
                );
            }
            if let Some(ref kind) = entry.container_kind {
                obj.insert(
                    "container_kind".into(),
                    serde_json::Value::String(kind.clone()),
                );
            }
            if let Some(v) = entry.compressed_size {
                obj.insert(
                    "compressed_size".into(),
                    serde_json::Value::Number(v.into()),
                );
                total_compressed = total_compressed.saturating_add(v);
            }
            total_uncompressed = total_uncompressed.saturating_add(entry.size_bytes);
            if let Some(ref m) = entry.compression_method {
                obj.insert(
                    "compression_method".into(),
                    serde_json::Value::String(m.clone()),
                );
                *method_counts.entry(m.clone()).or_insert(0) += 1;
            }
            if let Some(t) = entry.mtime_unix {
                obj.insert("mtime_unix".into(), serde_json::Value::Number(t.into()));
                mtimes.push(t);
            }
            if let Some(m) = entry.mode_octal {
                obj.insert("mode_octal".into(), serde_json::Value::Number(m.into()));
                if m & 0o4000 != 0 {
                    setuid_count += 1;
                }
                if m & 0o2000 != 0 {
                    setgid_count += 1;
                }
                if m & 0o1000 != 0 {
                    sticky_count += 1;
                }
                if m & 0o002 != 0 {
                    world_writable_count += 1;
                }
            }
            if let Some(u) = entry.uid {
                obj.insert("uid".into(), serde_json::Value::Number(u.into()));
            }
            if let Some(g) = entry.gid {
                obj.insert("gid".into(), serde_json::Value::Number(g.into()));
            }
            if let Some(ref u) = entry.uname {
                obj.insert("uname".into(), serde_json::Value::String(u.clone()));
                unames.insert(u.clone());
            }
            if let Some(ref g) = entry.gname {
                obj.insert("gname".into(), serde_json::Value::String(g.clone()));
                gnames.insert(g.clone());
            }
            if let Some(ref t) = entry.entry_type {
                obj.insert("entry_type".into(), serde_json::Value::String(t.clone()));
                *entry_type_counts.entry(t.clone()).or_insert(0) += 1;
                if t == "symlink" {
                    symlink_count += 1;
                    if let Some(ref link) = entry.linkname
                        && (link.starts_with('/') || link.contains(".."))
                    {
                        external_symlink_count += 1;
                    }
                }
            }
            if let Some(ref link) = entry.linkname {
                obj.insert("linkname".into(), serde_json::Value::String(link.clone()));
            }
            if let Some(ref os) = entry.host_os {
                obj.insert("host_os".into(), serde_json::Value::String(os.clone()));
            }
            if let Some(v) = entry.header_offset {
                obj.insert("header_offset".into(), serde_json::Value::Number(v.into()));
            }
            if let Some(v) = entry.data_offset {
                obj.insert("data_offset".into(), serde_json::Value::Number(v.into()));
            }
            if let Some(v) = entry.central_header_offset {
                obj.insert(
                    "central_header_offset".into(),
                    serde_json::Value::Number(v.into()),
                );
            }
            if let Some(v) = entry.crc32 {
                obj.insert(
                    "crc32".into(),
                    serde_json::Value::Number(u64::from(v).into()),
                );
            }
            if entry.encrypted {
                obj.insert("encrypted".into(), serde_json::Value::Bool(true));
            }
            members.push(serde_json::Value::Object(obj));
        }

        let mut root = serde_json::Map::new();
        root.insert("members".into(), serde_json::Value::Array(members));
        root.insert(
            "member_count".into(),
            serde_json::Value::Number((self.archive_contents.len() as u64).into()),
        );

        if !method_counts.is_empty() || total_compressed > 0 {
            let mut comp = serde_json::Map::new();
            let methods: Vec<serde_json::Value> = method_counts
                .keys()
                .map(|k| serde_json::Value::String(k.clone()))
                .collect();
            let counts: serde_json::Map<String, serde_json::Value> = method_counts
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::Number((*v).into())))
                .collect();
            comp.insert("methods".into(), serde_json::Value::Array(methods));
            comp.insert("method_counts".into(), serde_json::Value::Object(counts));
            if total_uncompressed > 0 && total_compressed > 0 {
                let ratio = total_compressed as f64 / total_uncompressed as f64;
                if let Some(n) = serde_json::Number::from_f64(ratio) {
                    comp.insert("ratio".into(), serde_json::Value::Number(n));
                }
            }
            root.insert("compression".into(), serde_json::Value::Object(comp));
        }

        if !mtimes.is_empty() {
            let mut timing = serde_json::Map::new();
            let min = *mtimes.iter().min().unwrap_or(&0);
            let max = *mtimes.iter().max().unwrap_or(&0);
            let unique: std::collections::BTreeSet<i64> = mtimes.iter().copied().collect();
            timing.insert("mtime_min".into(), serde_json::Value::Number(min.into()));
            timing.insert("mtime_max".into(), serde_json::Value::Number(max.into()));
            timing.insert(
                "mtime_spread_seconds".into(),
                serde_json::Value::Number((max - min).into()),
            );
            timing.insert(
                "mtime_unique_count".into(),
                serde_json::Value::Number((unique.len() as u64).into()),
            );
            root.insert("timing".into(), serde_json::Value::Object(timing));
        }

        let mut security = serde_json::Map::new();
        security.insert(
            "setuid_count".into(),
            serde_json::Value::Number(setuid_count.into()),
        );
        security.insert(
            "setgid_count".into(),
            serde_json::Value::Number(setgid_count.into()),
        );
        security.insert(
            "sticky_count".into(),
            serde_json::Value::Number(sticky_count.into()),
        );
        security.insert(
            "world_writable_count".into(),
            serde_json::Value::Number(world_writable_count.into()),
        );
        security.insert(
            "symlink_count".into(),
            serde_json::Value::Number(symlink_count.into()),
        );
        security.insert(
            "external_symlink_count".into(),
            serde_json::Value::Number(external_symlink_count.into()),
        );
        root.insert("security".into(), serde_json::Value::Object(security));

        if !entry_type_counts.is_empty() {
            let mut fmt = serde_json::Map::new();
            let types: Vec<serde_json::Value> = entry_type_counts
                .keys()
                .map(|k| serde_json::Value::String(k.clone()))
                .collect();
            fmt.insert("entry_types".into(), serde_json::Value::Array(types));
            for (k, v) in &entry_type_counts {
                fmt.insert(
                    format!("{}_count", k.replace('-', "_")),
                    serde_json::Value::Number((*v).into()),
                );
            }
            root.insert("format".into(), serde_json::Value::Object(fmt));
        }

        if !unames.is_empty() || !gnames.is_empty() {
            let mut builder = serde_json::Map::new();
            if !unames.is_empty() {
                builder.insert(
                    "unames".into(),
                    serde_json::Value::Array(
                        unames
                            .iter()
                            .map(|s| serde_json::Value::String(s.clone()))
                            .collect(),
                    ),
                );
            }
            if !gnames.is_empty() {
                builder.insert(
                    "gnames".into(),
                    serde_json::Value::Array(
                        gnames
                            .iter()
                            .map(|s| serde_json::Value::String(s.clone()))
                            .collect(),
                    ),
                );
            }
            root.insert("builder".into(), serde_json::Value::Object(builder));
        }

        self.merge_kv_subtree("archive", serde_json::Value::Object(root));
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
        // sides are objects, so multiple contributors (e.g. filefacts
        // adds `build.toolchain.*` while cleave's binary_extractors
        // adds `build.username`) coexist instead of clobbering.
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
