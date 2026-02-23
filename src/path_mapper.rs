//! File path classification and analysis.
//!
//! Maps file paths to security-relevant categories (tmp files, config, etc).

use crate::types::*;
use std::collections::HashMap;

/// Extract paths from strings and categorize them
#[must_use]
pub(crate) fn extract_paths_from_strings(strings: &[StringInfo]) -> Vec<PathInfo> {
    let mut paths = Vec::new();

    for string_info in strings {
        if string_info.string_type == StringType::Path {
            let path_info = analyze_path(&string_info.value, "strings");
            paths.push(path_info);
        }
    }

    paths
}

/// Analyze a single path string and categorize it
fn analyze_path(path_str: &str, source: &str) -> PathInfo {
    let path_type = classify_path_type(path_str);
    let category = classify_path_category(path_str);
    let access_type = None; // Would need function analysis to determine

    PathInfo {
        path: path_str.to_string(),
        path_type,
        category,
        access_type,
        source: source.to_string(),
        evidence: vec![Evidence {
            method: "string_pattern".to_string(),
            source: source.to_string(),
            value: path_str.to_string(),
            location: None,
        }],
        referenced_by_traits: Vec::new(),
    }
}

/// Classify path type (absolute, relative, dynamic)
fn classify_path_type(path: &str) -> PathType {
    // Check for format strings (%s, %d, ${VAR})
    if path.contains("%s") || path.contains("%d") || path.contains("${") || path.contains("$HOME") {
        return PathType::Dynamic;
    }

    // Check for relative paths
    if path.starts_with("./") || path.starts_with("../") || path.contains("/../") {
        return PathType::Relative;
    }

    // Default to absolute
    PathType::Absolute
}

/// Classify path category based on common patterns
fn classify_path_category(path: &str) -> PathCategory {
    // Hidden files: dot-prefixed filenames like ".bashrc" or "/path/.hidden"
    // But NOT relative path components like "/../" or "/./"
    if path.starts_with('.') && !path.starts_with("./") && !path.starts_with("../") {
        return PathCategory::Hidden;
    }
    // Check for hidden files in paths (e.g., /home/user/.bashrc)
    // Exclude relative path components: /../ and /./
    if let Some(filename) = path.rsplit('/').next() {
        if filename.starts_with('.') && !filename.is_empty() && filename != "." && filename != ".."
        {
            return PathCategory::Hidden;
        }
    }

    // System paths
    if path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/lib/")
        || path.starts_with("/usr/lib/")
    {
        return PathCategory::System;
    }

    // Config paths
    if path.starts_with("/etc/")
        || path.ends_with(".conf")
        || path.contains("/.config/")
        || path.contains("/Config/")
    {
        return PathCategory::Config;
    }

    // Temp paths
    if path.starts_with("/tmp/") || path.starts_with("/var/tmp/") || path.starts_with("/dev/shm/") {
        return PathCategory::Temp;
    }

    // Log paths
    if path.starts_with("/var/log/") || path.ends_with(".log") {
        return PathCategory::Log;
    }

    // Home paths
    if path.starts_with("/home/")
        || path.starts_with("~/")
        || path == "$HOME"
        || path.contains("${HOME}")
    {
        return PathCategory::Home;
    }

    // Device/mount paths
    if path.starts_with("/dev/")
        || path.starts_with("/mnt/")
        || path.starts_with("/proc/")
        || path.starts_with("/sys/")
    {
        return PathCategory::Device;
    }

    // Runtime paths
    if path.starts_with("/var/run/") || path.starts_with("/run/") {
        return PathCategory::Runtime;
    }

    // Network config
    if path == "/etc/hosts"
        || path == "/etc/resolv.conf"
        || path == "/etc/hostname"
        || path.starts_with("/etc/network/")
    {
        return PathCategory::Network;
    }

    PathCategory::Other
}

/// Group paths by directory
#[must_use]
pub(crate) fn group_into_directories(paths: &[PathInfo]) -> Vec<DirectoryAccess> {
    let mut dir_map: HashMap<String, Vec<&PathInfo>> = HashMap::new();

    // Group paths by directory
    for path_info in paths {
        if let Some(parent) = parent_directory(&path_info.path) {
            dir_map.entry(parent).or_default().push(path_info);
        }
    }

    let mut directory_accesses = Vec::new();

    for (dir, dir_paths) in dir_map {
        // Skip if only 1 file (not a pattern)
        if dir_paths.len() < 2 {
            continue;
        }

        let files: Vec<String> = dir_paths
            .iter()
            .map(|p| {
                p.path
                    .trim_start_matches(&dir)
                    .trim_start_matches('/')
                    .to_string()
            })
            .collect();

        let file_count = files.len();

        let categories: Vec<PathCategory> = dir_paths
            .iter()
            .map(|p| p.category)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let access_pattern = determine_access_pattern(&files, &dir_paths);

        directory_accesses.push(DirectoryAccess {
            directory: dir.clone(),
            files,
            file_count,
            access_pattern,
            categories,
            enumerated: false, // Would need function analysis
            generated_traits: Vec::new(),
        });
    }

    directory_accesses
}

/// Extract parent directory from path
fn parent_directory(path: &str) -> Option<String> {
    let path = path.trim_end_matches('/');

    if let Some(last_slash) = path.rfind('/') {
        if last_slash == 0 {
            // Root directory files like /etc/passwd -> /
            return Some("/".to_string());
        }
        Some(format!("{}/", &path[..last_slash]))
    } else {
        None
    }
}

/// Determine access pattern from file list
fn determine_access_pattern(files: &[String], paths: &[&PathInfo]) -> DirectoryAccessPattern {
    // Check for user enumeration pattern
    if paths
        .iter()
        .any(|p| p.path_type == PathType::Dynamic && p.path.contains("/home/"))
    {
        return DirectoryAccessPattern::UserEnumeration;
    }

    // Check for batch operations (all same operation)
    let access_types: std::collections::HashSet<_> = paths
        .iter()
        .filter_map(|p| p.access_type.as_ref())
        .collect();

    if access_types.len() == 1 && files.len() > 2 {
        if let Some(op_type) = access_types.iter().next() {
            return DirectoryAccessPattern::BatchOperation {
                operation: format!("{:?}", op_type),
                count: files.len(),
            };
        }
    }

    DirectoryAccessPattern::MultipleSpecific { count: files.len() }
}

/// Generate traits from path patterns
#[must_use]
pub(crate) fn generate_traits_from_paths(paths: &[PathInfo]) -> Vec<Finding> {
    let mut traits = Vec::new();

    // Platform detection from paths
    traits.extend(detect_platform_from_paths(paths));

    // Anomalous path detection
    traits.extend(detect_anomalous_paths(paths));

    // Privilege requirements
    traits.extend(detect_privilege_requirements(paths));

    traits
}

/// Detect platform based on path patterns
/// NOTE: MTD and Android platform detection moved to YAML:
/// - traits/micro-behaviors/os/platform/embedded/mtd-device.yaml
/// - traits/micro-behaviors/os/platform/mobile/android.yaml
fn detect_platform_from_paths(_paths: &[PathInfo]) -> Vec<Finding> {
    Vec::new()
}

/// Detect anomalous paths (hidden files in system directories, etc.)
/// NOTE: Hidden file detection moved to YAML:
/// - traits/objectives/persistence/hidden-files/system-dir.yaml (uses unless: for exclusions)
fn detect_anomalous_paths(_paths: &[PathInfo]) -> Vec<Finding> {
    Vec::new()
}

/// Detect privilege requirements from paths
/// NOTE: Root-only path detection moved to YAML:
/// - traits/micro-behaviors/os/privilege/paths/root-only.yaml
fn detect_privilege_requirements(_paths: &[PathInfo]) -> Vec<Finding> {
    Vec::new()
}

/// Generate traits from directory patterns
/// NOTE: The following detections moved to YAML with count_min:
/// - Credential file enumeration: traits/objectives/credential-access/files/config-directory.yaml
/// - Log file access: traits/micro-behaviors/fs/path/log/multiple-access.yaml
#[must_use]
pub(crate) fn generate_traits_from_directories(_directories: &[DirectoryAccess]) -> Vec<Finding> {
    Vec::new()
}

/// Main entry point: analyze paths and link to traits
pub(crate) fn analyze_and_link_paths(report: &mut AnalysisReport) {
    // Step 1: Extract paths from strings
    let mut paths = extract_paths_from_strings(&report.strings);

    // Step 2: Group into directories
    let directories = group_into_directories(&paths);

    // Step 3: Generate traits from patterns
    let mut new_traits = Vec::new();

    // Generate traits from individual paths
    new_traits.extend(generate_traits_from_paths(&paths));

    // Generate traits from directory patterns
    new_traits.extend(generate_traits_from_directories(&directories));

    // Step 4: Add back-references using evidence
    for trait_obj in &new_traits {
        // Mark paths that contributed to this trait based on evidence
        for path in &mut paths {
            if trait_obj.evidence.iter().any(|e| e.value == path.path) {
                path.referenced_by_traits.push(trait_obj.id.clone());
            }
        }
    }

    // Step 5: Update directories with generated trait IDs
    let mut updated_directories = directories;
    for dir in &mut updated_directories {
        for trait_obj in &new_traits {
            if trait_obj
                .evidence
                .iter()
                .any(|e| e.location.as_ref() == Some(&dir.directory))
            {
                dir.generated_traits.push(trait_obj.id.clone());
            }
        }
    }

    // Store results
    report.paths = paths;
    report.directories = updated_directories;
    report.findings.extend(new_traits);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_path_type_absolute() {
        assert_eq!(classify_path_type("/etc/passwd"), PathType::Absolute);
        assert_eq!(classify_path_type("/bin/sh"), PathType::Absolute);
        assert_eq!(classify_path_type("/home/user/.bashrc"), PathType::Absolute);
    }

    #[test]
    fn test_classify_path_type_relative() {
        assert_eq!(classify_path_type("./file.txt"), PathType::Relative);
        assert_eq!(classify_path_type("../config"), PathType::Relative);
        assert_eq!(classify_path_type("foo/../bar"), PathType::Relative);
    }

    #[test]
    fn test_classify_path_type_dynamic() {
        assert_eq!(classify_path_type("/home/%s/.config"), PathType::Dynamic);
        assert_eq!(classify_path_type("/tmp/file-%d"), PathType::Dynamic);
        assert_eq!(classify_path_type("${HOME}/.bashrc"), PathType::Dynamic);
        assert_eq!(classify_path_type("$HOME/.profile"), PathType::Dynamic);
    }

    #[test]
    fn test_classify_path_category_system() {
        assert_eq!(classify_path_category("/bin/bash"), PathCategory::System);
        assert_eq!(classify_path_category("/sbin/init"), PathCategory::System);
        assert_eq!(
            classify_path_category("/usr/bin/python"),
            PathCategory::System
        );
        assert_eq!(classify_path_category("/lib/libc.so"), PathCategory::System);
    }

    #[test]
    fn test_classify_path_category_config() {
        assert_eq!(classify_path_category("/etc/passwd"), PathCategory::Config);
        assert_eq!(classify_path_category("/etc/hosts"), PathCategory::Config);
        assert_eq!(classify_path_category("app.conf"), PathCategory::Config);
        // Note: /home/user/.config/app is classified as Hidden due to the dot
    }

    #[test]
    fn test_classify_path_category_temp() {
        assert_eq!(classify_path_category("/tmp/file"), PathCategory::Temp);
        assert_eq!(classify_path_category("/var/tmp/data"), PathCategory::Temp);
        assert_eq!(
            classify_path_category("/dev/shm/buffer"),
            PathCategory::Temp
        );
    }

    #[test]
    fn test_classify_path_category_log() {
        assert_eq!(classify_path_category("/var/log/syslog"), PathCategory::Log);
        assert_eq!(classify_path_category("app.log"), PathCategory::Log);
    }

    #[test]
    fn test_classify_path_category_home() {
        assert_eq!(
            classify_path_category("/home/user/file"),
            PathCategory::Home
        );
        // Note: ~ and $HOME are classified as Dynamic, not Home
    }

    #[test]
    fn test_classify_path_category_device() {
        assert_eq!(classify_path_category("/dev/null"), PathCategory::Device);
        assert_eq!(
            classify_path_category("/proc/self/maps"),
            PathCategory::Device
        );
        assert_eq!(
            classify_path_category("/sys/class/net"),
            PathCategory::Device
        );
    }

    #[test]
    fn test_classify_path_category_runtime() {
        assert_eq!(
            classify_path_category("/var/run/app.pid"),
            PathCategory::Runtime
        );
        assert_eq!(
            classify_path_category("/run/lock/file"),
            PathCategory::Runtime
        );
    }

    #[test]
    fn test_classify_path_category_hidden() {
        // Actual hidden files
        assert_eq!(classify_path_category(".hidden"), PathCategory::Hidden);
        assert_eq!(
            classify_path_category("/path/.hidden"),
            PathCategory::Hidden
        );
        assert_eq!(
            classify_path_category("/home/user/.bashrc"),
            PathCategory::Hidden
        );

        // NOT hidden: relative path components in debug info / DWARF paths
        // These are absolute paths with /../ that resolve to normal files
        assert_ne!(
            classify_path_category("/usr/xenocara/lib/mesa/mk/libEGL/../../src/egl/main/eglapi.c"),
            PathCategory::Hidden
        );
        assert_ne!(
            classify_path_category("/usr/src/../lib/file.c"),
            PathCategory::Hidden
        );
        // ./ relative paths are not hidden
        assert_ne!(classify_path_category("./file.txt"), PathCategory::Hidden);
        assert_ne!(classify_path_category("../file.txt"), PathCategory::Hidden);
    }

    #[test]
    fn test_parent_directory() {
        assert_eq!(parent_directory("/etc/passwd"), Some("/etc/".to_string()));
        assert_eq!(
            parent_directory("/etc/network/interfaces"),
            Some("/etc/network/".to_string())
        );
        assert_eq!(parent_directory("/etc"), Some("/".to_string()));
        assert_eq!(parent_directory("file.txt"), None);
    }

    #[test]
    fn test_extract_paths_from_strings() {
        let strings = vec![
            StringInfo {
                value: "/etc/passwd".to_string(),
                string_type: StringType::Path,
                offset: None,
                encoding: "ascii".to_string(),
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            },
            StringInfo {
                value: "/bin/sh".to_string(),
                string_type: StringType::Path,
                offset: None,
                encoding: "ascii".to_string(),
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            },
            StringInfo {
                value: "not a path".to_string(),
                string_type: StringType::Const,
                offset: None,
                encoding: "ascii".to_string(),
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            },
        ];

        let paths = extract_paths_from_strings(&strings);

        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|p| p.path == "/etc/passwd"));
        assert!(paths.iter().any(|p| p.path == "/bin/sh"));
    }

    #[test]
    fn test_analyze_path() {
        let path_info = analyze_path("/etc/passwd", "strings");

        assert_eq!(path_info.path, "/etc/passwd");
        assert_eq!(path_info.path_type, PathType::Absolute);
        assert_eq!(path_info.category, PathCategory::Config);
        assert_eq!(path_info.source, "strings");
        assert!(!path_info.evidence.is_empty());
    }

    // NOTE: test_detect_platform_from_paths_mtd and test_detect_privilege_requirements
    // were removed because the underlying functions (detect_platform_from_paths,
    // detect_privilege_requirements) have been stubbed out. The functionality has
    // moved to YAML-based trait definitions.

    // NOTE: test_detect_anomalous_paths_excludes_debug_paths and
    // test_detect_anomalous_paths_detects_real_hidden_files were removed because
    // detect_anomalous_paths has been stubbed out. The functionality has moved
    // to YAML-based trait definitions in traits/objectives/persistence/hidden-files/
}
