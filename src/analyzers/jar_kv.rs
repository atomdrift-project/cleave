//! JAR (and WAR / EAR / Spring Boot fat-jar) kv-tree synthesis.
//!
//! Surfaces structural and attribution metadata from an extracted JAR
//! as a `jar.*` kv subtree so YAML traits can target it precisely.
//!
//! # Why these fields
//!
//! Java `META-INF/MANIFEST.MF` files routinely embed strong build-host
//! attribution leaks that are invaluable for supply-chain swap
//! detection:
//!
//! ```text
//! Manifest-Version: 1.0
//! Created-By: Apache Maven 3.9.4         <- build tool fingerprint
//! Built-By: EC2AMAZ-GED9SG5$              <- builder hostname/user
//! Build-Jdk: 17.0.8                       <- compiler version
//! Build-Time: 2024-11-25T08:28:28+0000    <- exact build timestamp
//! Implementation-Build: d03cce270…        <- often a git commit SHA
//! ```
//!
//! When a JAR is recompiled by an attacker, these fields routinely
//! flip in ways that simple `Implementation-Version` checks miss
//! (e.g. `Built-By: jenkins-prod` → `Built-By: rogue-laptop`).
//!
//! Also captures structural signals (signed?, multi-release layout,
//! bundled native libraries, embedded JARs) that point at non-obvious
//! capability surface.
//!
//! # Schema
//!
//! ```text
//! jar:
//!   manifest:
//!     <key>: <value>           verbatim header → snake_case key
//!   signed             bool    META-INF/*.SF present
//!   sig_count          int     number of signers (.SF files)
//!   multi_release      bool    META-INF/versions/<n>/ present
//!   has_native_libs    bool    .so / .dll / .dylib bundled
//!   has_embedded_jars  bool    nested .jar / .war / .ear
//!   embedded_jar_count int
//!   entry_count        int     total file entries
//!   class_count        int     .class file count
//!   pom:
//!     group_id         str     META-INF/maven/<g>/<a>/pom.properties
//!     artifact_id      str
//!     version          str
//! ```

use serde_json::{json, Map, Value};
use std::fs;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

use crate::types::AnalysisReport;

/// MANIFEST.MF headers worth surfacing as `jar.manifest.<snake_key>`.
/// Limiting to a known set keeps trait authors targeting stable names
/// and prevents JAR-specific or vendor-custom keys (which can be
/// arbitrary) from polluting the kv namespace.
const TRACKED_MANIFEST_HEADERS: &[(&str, &str)] = &[
    ("Manifest-Version", "manifest_version"),
    ("Main-Class", "main_class"),
    ("Created-By", "created_by"),
    ("Built-By", "built_by"),
    ("Build-Jdk", "build_jdk"),
    ("Build-Jdk-Spec", "build_jdk_spec"),
    ("Build-Time", "build_time"),
    ("Build-Date", "build_date"),
    ("Archiver-Version", "archiver_version"),
    ("Class-Path", "class_path"),
    ("Implementation-Title", "implementation_title"),
    ("Implementation-Version", "implementation_version"),
    ("Implementation-Vendor", "implementation_vendor"),
    ("Implementation-Vendor-Id", "implementation_vendor_id"),
    ("Implementation-Build", "implementation_build"),
    ("Implementation-Build-Date", "implementation_build_date"),
    ("Specification-Title", "specification_title"),
    ("Specification-Version", "specification_version"),
    ("Specification-Vendor", "specification_vendor"),
    ("Bundle-Name", "bundle_name"),
    ("Bundle-SymbolicName", "bundle_symbolic_name"),
    ("Bundle-Version", "bundle_version"),
    ("Bundle-Vendor", "bundle_vendor"),
    (
        "Bundle-RequiredExecutionEnvironment",
        "bundle_required_execution_environment",
    ),
    ("Sealed", "sealed"),
    ("Permissions", "permissions"),
    ("Application-Name", "application_name"),
    (
        "Application-Library-Allowable-Codebase",
        "application_library_allowable_codebase",
    ),
    ("Codebase", "codebase"),
    ("Trusted-Only", "trusted_only"),
    ("Trusted-Library", "trusted_library"),
    ("Start-Class", "start_class"),
    ("Spring-Boot-Version", "spring_boot_version"),
    ("Spring-Boot-Classes", "spring_boot_classes"),
    ("Spring-Boot-Lib", "spring_boot_lib"),
];

/// Aggregator threaded through both the on-disk and in-memory paths.
/// Each visit feeds it one entry; `finish` produces the final kv map.
#[derive(Default)]
struct Aggregator {
    entry_count: u32,
    class_count: u32,
    sig_count: u32,
    native_libs: bool,
    multi_release: bool,
    embedded_jar_count: u32,
    pom_group: Option<String>,
    pom_artifact: Option<String>,
    pom_version: Option<String>,
    manifest: Option<Map<String, Value>>,
}

impl Aggregator {
    fn visit(&mut self, rel: &str, read_text: impl FnOnce() -> Option<String>) {
        self.entry_count = self.entry_count.saturating_add(1);
        let lower_ext = rel.rsplit('.').next().map(str::to_ascii_lowercase);
        match lower_ext.as_deref() {
            Some("class") => self.class_count = self.class_count.saturating_add(1),
            Some("so" | "dll" | "dylib" | "jnilib") => self.native_libs = true,
            Some("jar" | "war" | "ear") => {
                self.embedded_jar_count = self.embedded_jar_count.saturating_add(1);
            }
            _ => {}
        }
        if rel.starts_with("META-INF/") && rel.ends_with(".SF") {
            self.sig_count = self.sig_count.saturating_add(1);
        }
        if rel.starts_with("META-INF/versions/") {
            self.multi_release = true;
        }
        if rel == "META-INF/MANIFEST.MF" {
            if let Some(text) = read_text() {
                self.manifest = Some(parse_manifest(&text));
            }
        } else if self.pom_group.is_none() && rel.ends_with("/pom.properties") {
            if let Some(text) = read_text() {
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(v) = line.strip_prefix("groupId=") {
                        self.pom_group = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("artifactId=") {
                        self.pom_artifact = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("version=") {
                        self.pom_version = Some(v.trim().to_string());
                    }
                }
            }
        }
    }

    fn finish(self) -> Option<Value> {
        let manifest_present = self.manifest.as_ref().is_some_and(|m| !m.is_empty());
        if self.entry_count == 0 && !manifest_present {
            return None;
        }
        let mut out = Map::new();
        if let Some(m) = self.manifest {
            if !m.is_empty() {
                out.insert("manifest".into(), Value::Object(m));
            }
        }
        out.insert("entry_count".into(), json!(self.entry_count));
        out.insert("class_count".into(), json!(self.class_count));
        out.insert("signed".into(), json!(self.sig_count > 0));
        if self.sig_count > 0 {
            out.insert("sig_count".into(), json!(self.sig_count));
        }
        if self.multi_release {
            out.insert("multi_release".into(), json!(true));
        }
        if self.native_libs {
            out.insert("has_native_libs".into(), json!(true));
        }
        if self.embedded_jar_count > 0 {
            out.insert("has_embedded_jars".into(), json!(true));
            out.insert("embedded_jar_count".into(), json!(self.embedded_jar_count));
        }
        if self.pom_group.is_some() || self.pom_artifact.is_some() || self.pom_version.is_some() {
            let mut pom = Map::new();
            if let Some(v) = self.pom_group {
                pom.insert("group_id".into(), json!(v));
            }
            if let Some(v) = self.pom_artifact {
                pom.insert("artifact_id".into(), json!(v));
            }
            if let Some(v) = self.pom_version {
                pom.insert("version".into(), json!(v));
            }
            out.insert("pom".into(), Value::Object(pom));
        }
        Some(Value::Object(out))
    }
}

/// Build the `jar.*` kv subtree from an already-extracted JAR
/// directory. Cheap — single walk with bounded depth, no class parsing.
#[must_use]
pub(crate) fn build_jar_kv(temp_dir: &Path) -> Option<Value> {
    let mut agg = Aggregator::default();
    let walk = WalkDir::new(temp_dir)
        .min_depth(1)
        .max_depth(20)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file());
    for entry in walk {
        let rel = entry
            .path()
            .strip_prefix(temp_dir)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();
        let path = entry.path().to_path_buf();
        agg.visit(&rel, || fs::read_to_string(&path).ok());
    }
    agg.finish()
}

/// Build the `jar.*` kv subtree directly from raw JAR bytes via the
/// `zip` crate. Used by `cleave kv` so JAR metadata is discoverable
/// without going through the full archive analysis pipeline.
///
/// Caps the in-memory expansion of MANIFEST.MF / pom.properties at
/// 1 MiB each — enough for any plausible legitimate file, hostile
/// inputs that zip-bomb these names get an early bail.
#[must_use]
pub(crate) fn extract_jar_kv(content: &[u8]) -> Option<Value> {
    use std::io::Cursor;
    const MAX_TEXT_BYTES: u64 = 1024 * 1024;
    let cursor = Cursor::new(content);
    let mut zip = ::zip::ZipArchive::new(cursor).ok()?;
    let mut agg = Aggregator::default();
    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();
    for name in names {
        if name.ends_with('/') {
            continue;
        }
        agg.visit(&name, || {
            let mut entry = zip.by_name(&name).ok()?;
            if entry.size() > MAX_TEXT_BYTES {
                return None;
            }
            let mut s = String::new();
            entry.read_to_string(&mut s).ok()?;
            Some(s)
        });
    }
    agg.finish()
}

/// Parse a `MANIFEST.MF` text body and return the tracked headers.
/// The JAR manifest format wraps long values onto continuation lines
/// that start with a single space — handled here so values like
/// `Plugin-Description: Code Analyzer for C#` survive intact.
fn parse_manifest(text: &str) -> Map<String, Value> {
    let mut joined: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some(stripped) = line.strip_prefix(' ') {
            if let Some(last) = joined.last_mut() {
                last.push_str(stripped);
                continue;
            }
        }
        joined.push(line.to_string());
    }
    let mut out = Map::new();
    for line in joined {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Some((_, snake)) = TRACKED_MANIFEST_HEADERS
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
        {
            out.insert((*snake).into(), json!(value));
        }
    }
    out
}

/// Stash the synthesized `jar.*` subtree on `report.kv_tree`.
/// Idempotent and namespaced — calling for a non-JAR temp directory
/// (no MANIFEST, no entries) leaves `report.kv_tree` untouched.
pub(crate) fn attach_to_report(report: &mut AnalysisReport, temp_dir: &Path) {
    let Some(jar_value) = build_jar_kv(temp_dir) else {
        return;
    };
    let mut root = match report.kv_tree.take().map(|b| *b) {
        Some(Value::Object(m)) => m,
        Some(v) => {
            let mut m = Map::new();
            m.insert("_legacy".into(), v);
            m
        }
        None => Map::new(),
    };
    root.insert("jar".into(), jar_value);
    report.kv_tree = Some(Box::new(Value::Object(root)));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write(td: &Path, rel: &str, contents: &[u8]) {
        let p = td.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents).unwrap();
    }

    #[test]
    fn empty_dir_yields_none() {
        let td = TempDir::new().unwrap();
        assert!(build_jar_kv(td.path()).is_none());
    }

    #[test]
    fn manifest_attribution_fields_surface() {
        let td = TempDir::new().unwrap();
        write(
            td.path(),
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\n\
              Created-By: Apache Maven 3.9.4\n\
              Built-By: build-host\n\
              Build-Jdk: 17.0.8\n\
              Main-Class: com.example.Main\n",
        );
        let v = build_jar_kv(td.path()).unwrap();
        assert_eq!(v["manifest"]["created_by"], "Apache Maven 3.9.4");
        assert_eq!(v["manifest"]["built_by"], "build-host");
        assert_eq!(v["manifest"]["build_jdk"], "17.0.8");
        assert_eq!(v["manifest"]["main_class"], "com.example.Main");
    }

    #[test]
    fn manifest_continuation_lines_join() {
        // Construct explicitly so the literal-newline / single-space
        // continuation marker survives Rust's line-continuation rules.
        let mut text = String::new();
        text.push_str("Manifest-Version: 1.0\n");
        text.push_str("Implementation-Title: A long title that spans\n");
        text.push_str(" continuation lines per JAR spec\n");
        let td = TempDir::new().unwrap();
        write(td.path(), "META-INF/MANIFEST.MF", text.as_bytes());
        let v = build_jar_kv(td.path()).unwrap();
        assert_eq!(
            v["manifest"]["implementation_title"],
            "A long title that spanscontinuation lines per JAR spec"
        );
    }

    #[test]
    fn structural_signals_detected() {
        let td = TempDir::new().unwrap();
        write(
            td.path(),
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\n",
        );
        write(td.path(), "com/example/Foo.class", b"\xca\xfe\xba\xbe");
        write(td.path(), "META-INF/SIG.SF", b"Signature-Version: 1.0\n");
        write(td.path(), "lib/native.so", b"\x7fELF");
        write(td.path(), "BOOT-INF/lib/dep.jar", b"PK\x03\x04");
        write(
            td.path(),
            "META-INF/versions/11/com/example/Foo.class",
            b"\xca\xfe\xba\xbe",
        );
        let v = build_jar_kv(td.path()).unwrap();
        assert_eq!(v["class_count"], 2);
        assert_eq!(v["signed"], true);
        assert_eq!(v["sig_count"], 1);
        assert_eq!(v["has_native_libs"], true);
        assert_eq!(v["has_embedded_jars"], true);
        assert_eq!(v["embedded_jar_count"], 1);
        assert_eq!(v["multi_release"], true);
    }

    #[test]
    fn pom_properties_surface() {
        let td = TempDir::new().unwrap();
        write(
            td.path(),
            "META-INF/maven/com.example/myartifact/pom.properties",
            b"version=1.2.3\n\
              groupId=com.example\n\
              artifactId=myartifact\n",
        );
        let v = build_jar_kv(td.path()).unwrap();
        assert_eq!(v["pom"]["group_id"], "com.example");
        assert_eq!(v["pom"]["artifact_id"], "myartifact");
        assert_eq!(v["pom"]["version"], "1.2.3");
    }
}
