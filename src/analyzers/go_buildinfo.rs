//! Go build-info access.
//!
//! Go build metadata (version, module path, dependency list, build
//! settings/VCS) plus attribution facts (build id, GoRoot, developer
//! source root, dependency-provenance counts) are parsed by filefacts
//! and surfaced under `<format>.go.*` (e.g. `elf.go`, `macho.go`,
//! `pe.go`). cleave reads those facts here and reshapes them into the
//! `go.*` kv subtree consumed by trait rules and the ML pipeline; the
//! parsing itself lives in filefacts.

use std::collections::BTreeMap;

/// Parsed Go build info, reshaped from filefacts' `<format>.go` facts.
#[derive(Debug, Clone, Default)]
pub(crate) struct GoBuildInfo {
    pub version: String,
    pub main_path: String,
    pub main_module: Option<GoModuleRef>,
    pub dependencies: Vec<GoModuleRef>,
    pub build_settings: BTreeMap<String, String>,
    pub build_id: Option<String>,
    pub go_root: Option<String>,
    pub main_root: Option<String>,
    pub deps_std: u32,
    pub deps_replaced: u32,
    pub deps_vendored: u32,
    pub deps_thirdparty: u32,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GoModuleRef {
    pub path: String,
    pub version: String,
    pub sum: String,
    pub replaced_by: Option<Box<GoModuleRef>>,
}

/// Build a [`GoBuildInfo`] from filefacts' `<format>.go` value object.
///
/// Inverts filefacts' split of build settings / VCS so the existing
/// serializer reproduces the canonical `go.*` shape unchanged.
pub(crate) fn from_go_value(go: &serde_json::Value) -> GoBuildInfo {
    let str_field = |key: &str| go.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let module_ref = |v: &serde_json::Value| GoModuleRef {
        path: v
            .get("path")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        version: v
            .get("version")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        sum: v
            .get("sum")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        replaced_by: None,
    };

    let main_module = go.get("module").map(&module_ref);

    // filefacts' `deps[]` is flat with `kind:"replace"` entries following
    // the dependency they replace; fold those back into `replaced_by`.
    let mut dependencies: Vec<GoModuleRef> = Vec::new();
    if let Some(deps) = go.get("deps").and_then(|v| v.as_array()) {
        for entry in deps {
            if entry.get("kind").and_then(|k| k.as_str()) == Some("replace") {
                if let Some(last) = dependencies.last_mut() {
                    last.replaced_by = Some(Box::new(module_ref(entry)));
                }
                continue;
            }
            dependencies.push(module_ref(entry));
        }
    }

    // Reconstruct the flat original-key build-settings map the serializer
    // expects: build flags keep their keys; VCS fields re-acquire the
    // `vcs.`/`vcs` prefixes filefacts stripped.
    let mut build_settings: BTreeMap<String, String> = BTreeMap::new();
    if let Some(b) = go.get("build_settings").and_then(|v| v.as_object()) {
        for (k, v) in b {
            if let Some(s) = v.as_str() {
                build_settings.insert(k.clone(), s.to_string());
            }
        }
    }
    if let Some(vcs) = go.get("vcs").and_then(|v| v.as_object()) {
        for (k, v) in vcs {
            let Some(s) = v.as_str() else { continue };
            let key = if k == "system" {
                "vcs".to_string()
            } else {
                format!("vcs.{k}")
            };
            build_settings.insert(key, s.to_string());
        }
    }

    let count = |key: &str| go.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0) as u32;

    GoBuildInfo {
        version: str_field("version").unwrap_or_default(),
        main_path: str_field("path").unwrap_or_default(),
        main_module,
        dependencies,
        build_settings,
        build_id: str_field("build_id"),
        go_root: str_field("go_root"),
        main_root: str_field("main_root"),
        deps_std: count("deps_std"),
        deps_replaced: count("deps_replaced"),
        deps_vendored: count("deps_vendored"),
        deps_thirdparty: count("deps_thirdparty"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reshapes_filefacts_go_value() {
        // Shape mirrors filefacts' `<format>.go` object.
        let go = json!({
            "version": "go1.21.5",
            "path": "example.com/main",
            "module": { "path": "example.com/main", "version": "(devel)" },
            "deps": [
                { "path": "github.com/foo/bar", "version": "v1.2.3", "sum": "h1:aaa=" },
                { "path": "example.com/old", "version": "v1.0.0" },
                { "path": "example.com/new", "version": "v2.0.0", "kind": "replace" },
            ],
            "build_settings": { "-buildmode": "exe", "GOOS": "linux", "CGO_ENABLED": "0" },
            "vcs": { "system": "git", "revision": "abc123", "modified": "true" },
            "build_id": "act/cont",
            "go_root": "/usr/local/go",
            "main_root": "/home/dev/project",
            "deps_std": 4,
            "deps_thirdparty": 1,
            "deps_replaced": 1,
            "deps_vendored": 0,
        });

        let info = from_go_value(&go);
        assert_eq!(info.version, "go1.21.5");
        assert_eq!(info.main_path, "example.com/main");
        assert_eq!(info.build_id.as_deref(), Some("act/cont"));
        assert_eq!(info.go_root.as_deref(), Some("/usr/local/go"));
        assert_eq!(info.main_root.as_deref(), Some("/home/dev/project"));
        assert_eq!(
            (info.deps_std, info.deps_thirdparty, info.deps_replaced),
            (4, 1, 1)
        );
        // The `=>` entry folds into the preceding dep's `replaced_by`.
        assert_eq!(info.dependencies.len(), 2);
        assert_eq!(info.dependencies[1].path, "example.com/old");
        assert_eq!(
            info.dependencies[1]
                .replaced_by
                .as_ref()
                .map(|r| r.path.as_str()),
            Some("example.com/new")
        );
        // VCS fields re-acquire their `vcs.`/`vcs` prefixes for the serializer.
        assert_eq!(
            info.build_settings.get("vcs").map(String::as_str),
            Some("git")
        );
        assert_eq!(
            info.build_settings.get("vcs.revision").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(
            info.build_settings.get("-buildmode").map(String::as_str),
            Some("exe")
        );
    }
}
