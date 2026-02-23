//! Container and archive metrics (tar, npm packages, etc.)

use flayer_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32, is_zero_u64};

// =============================================================================
// CONTAINER/ARCHIVE METRICS
// =============================================================================

/// Archive metrics (ZIP, TAR, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ArchiveMetrics {
    // === Structure ===
    /// File count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_count: u32,
    /// Directory count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub directory_count: u32,
    /// Total uncompressed size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_uncompressed: u64,
    /// Total compressed size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_compressed: u64,
    /// Compression ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub compression_ratio: f32,

    // === Suspicious Patterns ===
    /// Path traversal attempts (../)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub path_traversal_count: u32,
    /// Symlink count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symlink_count: u32,
    /// Symlinks targeting outside archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symlink_escape_count: u32,
    /// Hidden files (.dotfiles)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hidden_files: u32,
    /// Executable files
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub executable_count: u32,
    /// Script files
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_count: u32,

    // === Filename Analysis ===
    /// Maximum filename length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_filename_length: u32,
    /// Unicode filenames
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_filenames: u32,
    /// Homoglyph filenames (lookalike chars)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub homoglyph_filenames: u32,
    /// Double extension files (file.txt.exe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub double_extension_count: u32,
    /// Right-to-left override chars
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rtlo_filenames: u32,

    // === Content Analysis ===
    /// Nested archives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_archive_count: u32,
    /// Executables in unexpected locations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub misplaced_executables: u32,
    /// High entropy files
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_files: u32,

    // === ZIP-specific ===
    /// Encrypted entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub encrypted_entries: u32,
    /// Zip bomb indicator (extreme ratio)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub zip_bomb_ratio: f32,
    /// ZIP64 format
    #[serde(default, skip_serializing_if = "is_false")]
    pub zip64_format: bool,
    /// Comment present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_comment: bool,
    /// Extra field total size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub extra_field_size: u64,
}

/// package.json metrics for npm supply chain analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PackageJsonMetrics {
    // === Dependencies ===
    /// Dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dependency_count: u32,
    /// Dev dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dev_dependency_count: u32,
    /// Peer dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub peer_dependency_count: u32,
    /// Optional dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub optional_dependency_count: u32,

    // === Lifecycle Scripts (high risk) ===
    /// Has preinstall script
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_preinstall: bool,
    /// Has postinstall script
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_postinstall: bool,
    /// Has preuninstall script
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_preuninstall: bool,
    /// Total script count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_count: u32,
    /// Scripts with curl/wget
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_download: u32,
    /// Scripts with eval
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_eval: u32,
    /// Scripts with base64
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_base64: u32,
    /// Total script character count
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub script_total_chars: u64,
    /// High entropy scripts (obfuscated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub obfuscated_scripts: u32,

    // === Non-Registry Dependencies ===
    /// Git URL dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub git_dependencies: u32,
    /// GitHub shorthand dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub github_dependencies: u32,
    /// HTTP URL dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_dependencies: u32,
    /// Local file dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_dependencies: u32,
    /// No semver ("*" or "latest")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wildcard_dependencies: u32,

    // === Suspicious Patterns ===
    /// Typosquat likelihood score (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub typosquat_score: f32,
    /// Package name entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub name_entropy: f32,
    /// Missing author
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_author: bool,
    /// Missing repository
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_repository: bool,
    /// Missing license
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_license: bool,
    /// Suspicious bin names
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub suspicious_bin_names: u32,
}

// =============================================================================
// COMPOSITE SCORES
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== ArchiveMetrics Tests ====================

    #[test]
    fn test_archive_metrics_default() {
        let metrics = ArchiveMetrics::default();
        assert_eq!(metrics.file_count, 0);
        assert_eq!(metrics.directory_count, 0);
        assert!(!metrics.zip64_format);
    }

    #[test]
    fn test_archive_metrics_structure() {
        let metrics = ArchiveMetrics {
            file_count: 100,
            directory_count: 20,
            total_uncompressed: 1024 * 1024,
            total_compressed: 512 * 1024,
            compression_ratio: 0.5,
            ..Default::default()
        };
        assert_eq!(metrics.file_count, 100);
        assert_eq!(metrics.directory_count, 20);
    }

    #[test]
    fn test_archive_metrics_suspicious() {
        let metrics = ArchiveMetrics {
            path_traversal_count: 5,
            symlink_count: 10,
            symlink_escape_count: 2,
            hidden_files: 15,
            ..Default::default()
        };
        assert_eq!(metrics.path_traversal_count, 5);
        assert_eq!(metrics.symlink_escape_count, 2);
    }

    #[test]
    fn test_archive_metrics_filenames() {
        let metrics = ArchiveMetrics {
            max_filename_length: 255,
            unicode_filenames: 5,
            homoglyph_filenames: 2,
            double_extension_count: 3,
            rtlo_filenames: 1,
            ..Default::default()
        };
        assert_eq!(metrics.double_extension_count, 3);
        assert_eq!(metrics.rtlo_filenames, 1);
    }

    #[test]
    fn test_archive_metrics_zip_specific() {
        let metrics = ArchiveMetrics {
            encrypted_entries: 10,
            zip_bomb_ratio: 1000.0,
            zip64_format: true,
            has_comment: true,
            extra_field_size: 1024,
            ..Default::default()
        };
        assert!(metrics.zip64_format);
        assert!(metrics.has_comment);
        assert!((metrics.zip_bomb_ratio - 1000.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_archive_metrics_content() {
        let metrics = ArchiveMetrics {
            nested_archive_count: 3,
            misplaced_executables: 2,
            high_entropy_files: 5,
            executable_count: 10,
            script_count: 15,
            ..Default::default()
        };
        assert_eq!(metrics.nested_archive_count, 3);
        assert_eq!(metrics.executable_count, 10);
    }

    // ==================== PackageJsonMetrics Tests ====================

    #[test]
    fn test_package_json_metrics_default() {
        let metrics = PackageJsonMetrics::default();
        assert_eq!(metrics.dependency_count, 0);
        assert!(!metrics.has_postinstall);
    }

    #[test]
    fn test_package_json_metrics_dependencies() {
        let metrics = PackageJsonMetrics {
            dependency_count: 50,
            dev_dependency_count: 30,
            peer_dependency_count: 5,
            optional_dependency_count: 3,
            ..Default::default()
        };
        assert_eq!(metrics.dependency_count, 50);
        assert_eq!(metrics.dev_dependency_count, 30);
    }

    #[test]
    fn test_package_json_metrics_lifecycle_scripts() {
        let metrics = PackageJsonMetrics {
            has_preinstall: true,
            has_postinstall: true,
            has_preuninstall: false,
            script_count: 10,
            scripts_with_download: 2,
            scripts_with_eval: 1,
            ..Default::default()
        };
        assert!(metrics.has_preinstall);
        assert!(metrics.has_postinstall);
        assert_eq!(metrics.scripts_with_download, 2);
    }

    #[test]
    fn test_package_json_metrics_non_registry() {
        let metrics = PackageJsonMetrics {
            git_dependencies: 5,
            github_dependencies: 3,
            url_dependencies: 2,
            local_dependencies: 1,
            wildcard_dependencies: 4,
            ..Default::default()
        };
        assert_eq!(metrics.git_dependencies, 5);
        assert_eq!(metrics.wildcard_dependencies, 4);
    }

    #[test]
    fn test_package_json_metrics_suspicious() {
        let metrics = PackageJsonMetrics {
            typosquat_score: 0.85,
            name_entropy: 3.5,
            missing_author: true,
            missing_repository: true,
            missing_license: false,
            suspicious_bin_names: 2,
            ..Default::default()
        };
        assert!(metrics.missing_author);
        assert!(metrics.missing_repository);
        assert!(!metrics.missing_license);
        assert!((metrics.typosquat_score - 0.85).abs() < f32::EPSILON);
    }

    #[test]
    fn test_package_json_metrics_obfuscation() {
        let metrics = PackageJsonMetrics {
            scripts_with_base64: 3,
            script_total_chars: 10000,
            obfuscated_scripts: 2,
            ..Default::default()
        };
        assert_eq!(metrics.scripts_with_base64, 3);
        assert_eq!(metrics.obfuscated_scripts, 2);
    }
}

// =============================================================================
// VALID FIELD PATHS FOR YAML VALIDATION
// =============================================================================

// Stub implementations - return empty for now
