//! Container and archive metrics (tar, npm packages, etc.)

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32, is_zero_u64};

// =============================================================================
// CONTAINER/ARCHIVE METRICS
// =============================================================================

/// Archive metrics (ZIP, TAR, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ArchiveMetrics {
    // === Structure ===
    /// Total number of files in the archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_count: u32,
    /// Total number of directories in the archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub directory_count: u32,
    /// Total uncompressed size of all entries
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_uncompressed: u64,
    /// Total compressed size of all entries
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_compressed: u64,
    /// Overall compression ratio (compressed/uncompressed)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub compression_ratio: f32,

    // === Suspicious Patterns ===
    /// Path traversal attempts (../)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub path_traversal_count: u32,
    /// Number of symbolic links in the archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symlink_count: u32,
    /// Symlinks targeting outside archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symlink_escape_count: u32,
    /// Number of hidden files (dotfiles) in the archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hidden_files: u32,
    /// Number of executable files in the archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub executable_count: u32,
    /// Number of script files in the archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_count: u32,

    // === Filename Analysis ===
    /// Longest filename length across all entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_filename_length: u32,
    /// Number of entries with Unicode filenames
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
    /// Number of nested archives within the archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_archive_count: u32,
    /// Executables in unexpected locations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub misplaced_executables: u32,
    /// Number of high-entropy files (possibly encrypted)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_files: u32,

    // === ZIP-specific ===
    /// Number of password-encrypted entries in the archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub encrypted_entries: u32,
    /// Zip bomb indicator (extreme ratio)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub zip_bomb_ratio: f32,
    /// Whether the archive uses ZIP64 extensions
    #[serde(default, skip_serializing_if = "is_false")]
    pub zip64_format: bool,
    /// Whether the archive has a ZIP comment block
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_comment: bool,
    /// Total size of all extra field data in bytes
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub extra_field_size: u64,
}

/// CHM (Compiled HTML Help) container metrics.
///
/// Holds the *computed* / *derived* numbers — anything that requires
/// extrapolation from raw fields (sums, ratios, mismatch flags) lives
/// here. Direct ITSF/ITSP/`#SYSTEM` field values are surfaced as kv
/// (`chm.*`) instead.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ChmMetrics {
    // === Size/shape ratios ===
    /// LZX compression ratio for `MSCompressed/Content`
    ///
    /// (uncompressed_size / compressed_size). Below ~1.5 on text-only
    /// CHMs is unusually low (suggests already-encoded / encrypted
    /// payload masquerading as help content).
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub lzx_compression_ratio: f32,
    /// Fraction of total file bytes occupied by user-visible content
    ///
    /// (HTML topics, images, scripts) — vs. CHM control records,
    /// tables, and trailing slack. Tiny droppers often score very low
    /// because most of the CHM is overhead.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub user_byte_ratio: f32,

    // === Per-entry size aggregates ===
    /// Largest user-visible entry size in bytes
    ///
    /// A 1-entry CHM whose only payload is < 4 KB is almost always a
    /// hand-rolled dropper.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub max_user_entry_size: u64,
    /// Sum of user-visible entry sizes (uncompressed)
    ///
    /// Compare with the total CHM file size and `lzx_uncompressed_size`
    /// (kv) for a "what's the rest of this file doing here" signal.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_user_entry_size: u64,

    // === Counts ===
    /// Number of user-visible directory entries
    ///
    /// (`help.html`, `Topic.htm`, etc.). Use
    /// `field: chm.user_entry_count, max: N` from a trait to gate on
    /// dropper shape.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub user_entry_count: u32,
    /// Number of CHM-internal control entries
    ///
    /// (`#SYSTEM`, `$OBJINST`, `::DataSpace/...`, etc.). Useful as a
    /// denominator alongside `user_entry_count`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub control_entry_count: u32,
    /// Number of `InfoType` records in `#SYSTEM`
    ///
    /// HHA "subset" / information-type tagging. Most attack CHMs have 0;
    /// legitimate help typically has several.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub infotype_count: u32,
    /// Number of LZX reset points in the MSCompressed stream
    ///
    /// A value of 1 means the entire content fits in a single 32 KB-or-less
    /// frame — characteristic of small payload-only CHMs.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lzx_reset_count: u32,
    /// Number of user-visible HTML topic entries
    ///
    /// Entries whose name ends in `.html` or `.htm`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub html_entry_count: u32,
    /// Number of user-visible script entries
    ///
    /// Entries whose name ends in `.js`, `.vbs`, or `.wsh`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_entry_count: u32,
    /// Number of user-visible entries whose name suggests an image.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub image_entry_count: u32,

    // === Mismatch / consistency flags ===
    /// True when the declared default topic is absent
    ///
    /// Set when `#SYSTEM` declares a `default_topic` that does not
    /// appear in the directory entries — common in
    /// stripped-down/repackaged CHMs.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default_topic_missing: bool,
    /// True when title and default topic disagree
    ///
    /// Set when `#SYSTEM.title` and `#SYSTEM.default_topic` are both
    /// set but disagree about which `*.html`/`*.hhc` the help opens
    /// to. Genuine HHA-Workshop output picks one and reuses it; mixed
    /// values appear in scratch-built droppers.
    #[serde(default, skip_serializing_if = "is_false")]
    pub title_topic_mismatch: bool,
    /// True when no compiler-version record is present
    ///
    /// Most legitimate CHMs carry an `HHA Version` `#SYSTEM` record;
    /// hand-built droppers often don't.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_compiler_version: bool,
}

/// package.json metrics for npm supply chain analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PackageJsonMetrics {
    // === Dependencies ===
    /// Number of runtime dependencies declared
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dependency_count: u32,
    /// Number of development-only dependencies declared
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dev_dependency_count: u32,
    /// Number of peer dependencies declared
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub peer_dependency_count: u32,
    /// Number of optional dependencies declared
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub optional_dependency_count: u32,

    // === Lifecycle Scripts (high risk) ===
    /// Whether a preinstall lifecycle script is present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_preinstall: bool,
    /// Whether a postinstall lifecycle script is present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_postinstall: bool,
    /// Whether a preuninstall lifecycle script is present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_preuninstall: bool,
    /// Total number of lifecycle scripts defined
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_count: u32,
    /// Number of scripts invoking curl or wget
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_download: u32,
    /// Number of scripts containing eval expressions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_eval: u32,
    /// Number of scripts using base64 encoding
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_base64: u32,
    /// Total script character count
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub script_total_chars: u64,
    /// High entropy scripts (obfuscated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub obfuscated_scripts: u32,

    // === Non-Registry Dependencies ===
    /// Number of dependencies pointing to a git URL
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub git_dependencies: u32,
    /// GitHub shorthand dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub github_dependencies: u32,
    /// Number of dependencies pointing to an HTTP URL
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_dependencies: u32,
    /// Number of dependencies pointing to local file paths
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_dependencies: u32,
    /// No semver ("*" or "latest")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wildcard_dependencies: u32,

    // === Suspicious Patterns ===
    /// Typosquat likelihood score (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub typosquat_score: f32,
    /// Shannon entropy of the package name string
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub name_entropy: f32,
    /// Whether the author field is absent or empty
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_author: bool,
    /// Whether the repository field is absent or empty
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_repository: bool,
    /// Whether the license field is absent or empty
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_license: bool,
    /// Number of bin entries with suspicious names
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
