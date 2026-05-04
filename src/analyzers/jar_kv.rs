//! `jar.*` kv subtree — JAR / WAR / EAR / Spring Boot fat-jar
//! manifest attribution (Built-By, Created-By, Build-Jdk, …) plus
//! structural signals (signed, multi-release, native libs, embedded
//! jars, pom coordinates).
//!
//! Schema is the [`JarKv`] struct. Both temp-dir and in-memory
//! analysis paths funnel through the same [`Aggregator`].

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

use crate::types::AnalysisReport;

/// `jar.*` kv tree.
#[derive(Default, Serialize)]
struct JarKv {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    manifest: BTreeMap<String, String>,
    entry_count: u32,
    class_count: u32,
    signed: bool,
    #[serde(skip_serializing_if = "is_zero_u32")]
    sig_count: u32,
    #[serde(skip_serializing_if = "is_false")]
    multi_release: bool,
    #[serde(skip_serializing_if = "is_false")]
    has_native_libs: bool,
    #[serde(skip_serializing_if = "is_false")]
    has_embedded_jars: bool,
    #[serde(skip_serializing_if = "is_zero_u32")]
    embedded_jar_count: u32,
    #[serde(skip_serializing_if = "PomKv::is_empty")]
    pom: PomKv,
}

#[derive(Default, Serialize)]
struct PomKv {
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

impl PomKv {
    fn is_empty(&self) -> bool {
        self.group_id.is_none() && self.artifact_id.is_none() && self.version.is_none()
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

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

/// Threaded through both the on-disk and in-memory paths. Each
/// `visit` feeds it one entry; `finish` produces the final kv tree.
#[derive(Default)]
struct Aggregator {
    kv: JarKv,
}

impl Aggregator {
    fn visit(&mut self, rel: &str, read_text: impl FnOnce() -> Option<String>) {
        self.kv.entry_count = self.kv.entry_count.saturating_add(1);
        match rel
            .rsplit('.')
            .next()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("class") => self.kv.class_count = self.kv.class_count.saturating_add(1),
            Some("so" | "dll" | "dylib" | "jnilib") => self.kv.has_native_libs = true,
            Some("jar" | "war" | "ear") => {
                self.kv.embedded_jar_count = self.kv.embedded_jar_count.saturating_add(1);
                self.kv.has_embedded_jars = true;
            }
            _ => {}
        }
        if rel.starts_with("META-INF/") && rel.ends_with(".SF") {
            self.kv.sig_count = self.kv.sig_count.saturating_add(1);
            self.kv.signed = true;
        }
        if rel.starts_with("META-INF/versions/") {
            self.kv.multi_release = true;
        }
        if rel == "META-INF/MANIFEST.MF" {
            if let Some(text) = read_text() {
                self.kv.manifest = parse_manifest(&text);
            }
        } else if self.kv.pom.group_id.is_none() && rel.ends_with("/pom.properties") {
            if let Some(text) = read_text() {
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(v) = line.strip_prefix("groupId=") {
                        self.kv.pom.group_id = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("artifactId=") {
                        self.kv.pom.artifact_id = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("version=") {
                        self.kv.pom.version = Some(v.trim().to_string());
                    }
                }
            }
        }
    }

    fn finish(self) -> Option<Value> {
        if self.kv.entry_count == 0 && self.kv.manifest.is_empty() {
            return None;
        }
        serde_json::to_value(self.kv).ok()
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
fn parse_manifest(text: &str) -> BTreeMap<String, String> {
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
    let mut out = BTreeMap::new();
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
            out.insert((*snake).to_string(), value.to_string());
        }
    }
    out
}

/// Stash the synthesized `jar.*` subtree on `report.kv_tree`.
/// Idempotent and namespaced — calling for a non-JAR temp directory
/// (no MANIFEST, no entries) leaves `report.kv_tree` untouched.
pub(crate) fn attach_to_report(report: &mut AnalysisReport, temp_dir: &Path) {
    if let Some(jar_value) = build_jar_kv(temp_dir) {
        report.merge_kv_subtree("jar", jar_value);
    }
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
