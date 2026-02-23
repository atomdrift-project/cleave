//! Path and environment variable analysis types
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde::{Deserialize, Serialize};

use super::is_false;
use super::traits_findings::Evidence;

/// File system path discovered in binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    /// The path string as found
    pub path: String,

    /// Classification of path format
    #[serde(rename = "type")]
    pub path_type: PathType,

    /// Semantic category
    pub category: PathCategory,

    /// How the path is accessed (if determinable)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access_type: Option<PathAccessType>,

    /// Where discovered (strings, yara, function_analysis)
    pub source: String,

    /// Evidence for this path
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,

    /// Trait IDs that reference this path (back-reference)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub referenced_by_traits: Vec<String>,
}

/// Path type classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PathType {
    /// Absolute path (/etc/passwd)
    Absolute,
    /// Relative path (../../etc/passwd)
    Relative,
    /// Dynamic path with variables (/home/%s, /tmp/file-%d, ${HOME}/.config)
    Dynamic,
}

/// Semantic category of path
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PathCategory {
    /// System directories (/bin/, /sbin/, /usr/bin/)
    System,
    /// Configuration files (/etc/, *.conf, .config/)
    Config,
    /// Temporary files (/tmp/, /var/tmp/, /dev/shm/)
    Temp,
    /// Log files (/var/log/)
    Log,
    /// Home directories (/home/, ~/)
    Home,
    /// Device/mount points (/dev/, /mnt/, /proc/, /sys/)
    Device,
    /// Runtime files (/var/run/, /run/)
    Runtime,
    /// Hidden files (.* files/directories)
    Hidden,
    /// Network configuration (/etc/hosts, /etc/resolv.conf)
    Network,
    /// Other/unknown
    Other,
}

/// How a path is accessed
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PathAccessType {
    /// File was read (open, fopen, read, etc.)
    Read,
    /// File was written (write, fwrite, etc.)
    Write,
    /// File was executed (exec, execve, etc.)
    Execute,
    /// File was deleted (unlink, remove, etc.)
    Delete,
    /// File was created (creat, open with O_CREAT, etc.)
    Create,
    /// Access type could not be determined
    Unknown,
}

/// Directory with multiple file accesses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryAccess {
    /// The directory path
    pub directory: String,

    /// Files within this directory (just filenames)
    pub files: Vec<String>,

    /// Number of files
    pub file_count: usize,

    /// Pattern of access
    pub access_pattern: DirectoryAccessPattern,

    /// Categories of files in this directory
    pub categories: Vec<PathCategory>,

    /// Whether directory itself was enumerated (opendir/readdir)
    #[serde(default, skip_serializing_if = "is_false")]
    pub enumerated: bool,

    /// Trait IDs generated from this directory pattern
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub generated_traits: Vec<String>,
}

/// Pattern of directory access
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryAccessPattern {
    /// Single hardcoded file
    SingleFile,

    /// Multiple specific files (hardcoded list)
    MultipleSpecific {
        /// Number of distinct files accessed
        count: usize,
    },

    /// Directory enumeration (opendir/readdir/glob)
    Enumeration {
        /// Optional glob pattern used for enumeration
        pattern: Option<String>,
    },

    /// Batch operations (multiple files, same operation)
    BatchOperation {
        /// The operation performed (e.g., "read", "write", "delete")
        operation: String,
        /// Number of files affected by the batch operation
        count: usize,
    },

    /// User enumeration (/home/* pattern)
    UserEnumeration,
}

/// Environment variable discovered in binary or script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarInfo {
    /// Environment variable name (e.g., "PATH", "HOME")
    pub name: String,

    /// How the env var is accessed
    pub access_type: EnvVarAccessType,

    /// Where discovered (getenv, setenv, strings, ast)
    pub source: String,

    /// Semantic category
    pub category: EnvVarCategory,

    /// Evidence for this environment variable access
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,

    /// Trait IDs that reference this env var (back-reference)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub referenced_by_traits: Vec<String>,
}

/// How environment variable is accessed
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EnvVarAccessType {
    /// Reading variable value (getenv)
    Read,
    /// Setting variable value (setenv, putenv)
    Write,
    /// Removing variable (unsetenv)
    Delete,
    /// Unknown access type
    Unknown,
}

/// Semantic category of environment variable
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EnvVarCategory {
    /// System paths (PATH, LD_LIBRARY_PATH, PYTHONPATH)
    Path,
    /// User information (USER, USERNAME, HOME, USERPROFILE)
    User,
    /// System information (HOSTNAME, SHELL, TERM)
    System,
    /// Temporary directories (TEMP, TMP, TMPDIR)
    Temp,
    /// Display/UI (DISPLAY, WAYLAND_DISPLAY)
    Display,
    /// Security/credentials (API_KEY, TOKEN, PASSWORD, AWS_*, GITHUB_TOKEN)
    Credential,
    /// Language runtimes (PYTHONPATH, NODE_PATH, RUBYLIB, GOPATH)
    Runtime,
    /// Platform-specific (ANDROID_*, IOS_*)
    Platform,
    /// Injection/evasion (LD_PRELOAD, DYLD_INSERT_LIBRARIES)
    Injection,
    /// Locale/language (LANG, LC_*, LANGUAGE)
    Locale,
    /// Network (http_proxy, https_proxy, no_proxy)
    Network,
    /// Other/unknown
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== PathType Tests ====================

    #[test]
    fn test_path_type_equality() {
        assert_eq!(PathType::Absolute, PathType::Absolute);
        assert_ne!(PathType::Absolute, PathType::Relative);
        assert_ne!(PathType::Relative, PathType::Dynamic);
    }

    #[test]
    fn test_path_type_copy() {
        let pt = PathType::Absolute;
        let pt2 = pt; // Copy
        assert_eq!(pt, pt2);
    }

    // ==================== PathCategory Tests ====================

    #[test]
    fn test_path_category_equality() {
        assert_eq!(PathCategory::System, PathCategory::System);
        assert_ne!(PathCategory::System, PathCategory::Config);
    }

    #[test]
    fn test_path_category_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PathCategory::System);
        set.insert(PathCategory::Config);
        set.insert(PathCategory::System); // Duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_path_category_all_variants_distinct() {
        let variants = vec![
            PathCategory::System,
            PathCategory::Config,
            PathCategory::Temp,
            PathCategory::Log,
            PathCategory::Home,
            PathCategory::Device,
            PathCategory::Runtime,
            PathCategory::Hidden,
            PathCategory::Network,
            PathCategory::Other,
        ];
        for (i, v1) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v1, v2);
                } else {
                    assert_ne!(v1, v2);
                }
            }
        }
    }

    // ==================== PathAccessType Tests ====================

    #[test]
    fn test_path_access_type_equality() {
        assert_eq!(PathAccessType::Read, PathAccessType::Read);
        assert_ne!(PathAccessType::Read, PathAccessType::Write);
    }

    #[test]
    fn test_path_access_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PathAccessType::Read);
        set.insert(PathAccessType::Write);
        set.insert(PathAccessType::Execute);
        assert_eq!(set.len(), 3);
    }

    // ==================== DirectoryAccessPattern Tests ====================

    #[test]
    fn test_directory_access_pattern_single_file() {
        let pattern = DirectoryAccessPattern::SingleFile;
        assert_eq!(pattern, DirectoryAccessPattern::SingleFile);
    }

    #[test]
    fn test_directory_access_pattern_multiple_specific() {
        let pattern = DirectoryAccessPattern::MultipleSpecific { count: 5 };
        if let DirectoryAccessPattern::MultipleSpecific { count } = pattern {
            assert_eq!(count, 5);
        } else {
            panic!("Expected MultipleSpecific");
        }
    }

    #[test]
    fn test_directory_access_pattern_enumeration() {
        let pattern = DirectoryAccessPattern::Enumeration {
            pattern: Some("*.txt".to_string()),
        };
        if let DirectoryAccessPattern::Enumeration { pattern: p } = pattern {
            assert_eq!(p, Some("*.txt".to_string()));
        } else {
            panic!("Expected Enumeration");
        }
    }

    #[test]
    fn test_directory_access_pattern_batch_operation() {
        let pattern = DirectoryAccessPattern::BatchOperation {
            operation: "delete".to_string(),
            count: 10,
        };
        if let DirectoryAccessPattern::BatchOperation { operation, count } = pattern {
            assert_eq!(operation, "delete");
            assert_eq!(count, 10);
        } else {
            panic!("Expected BatchOperation");
        }
    }

    #[test]
    fn test_directory_access_pattern_user_enumeration() {
        let pattern = DirectoryAccessPattern::UserEnumeration;
        assert_eq!(pattern, DirectoryAccessPattern::UserEnumeration);
    }

    // ==================== EnvVarAccessType Tests ====================

    #[test]
    fn test_env_var_access_type_equality() {
        assert_eq!(EnvVarAccessType::Read, EnvVarAccessType::Read);
        assert_ne!(EnvVarAccessType::Read, EnvVarAccessType::Write);
    }

    #[test]
    fn test_env_var_access_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(EnvVarAccessType::Read);
        set.insert(EnvVarAccessType::Write);
        set.insert(EnvVarAccessType::Delete);
        set.insert(EnvVarAccessType::Unknown);
        assert_eq!(set.len(), 4);
    }

    // ==================== EnvVarCategory Tests ====================

    #[test]
    fn test_env_var_category_equality() {
        assert_eq!(EnvVarCategory::Path, EnvVarCategory::Path);
        assert_ne!(EnvVarCategory::Path, EnvVarCategory::User);
    }

    #[test]
    fn test_env_var_category_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(EnvVarCategory::Path);
        set.insert(EnvVarCategory::User);
        set.insert(EnvVarCategory::Credential);
        set.insert(EnvVarCategory::Injection);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_env_var_category_all_variants_distinct() {
        let variants = vec![
            EnvVarCategory::Path,
            EnvVarCategory::User,
            EnvVarCategory::System,
            EnvVarCategory::Temp,
            EnvVarCategory::Display,
            EnvVarCategory::Credential,
            EnvVarCategory::Runtime,
            EnvVarCategory::Platform,
            EnvVarCategory::Injection,
            EnvVarCategory::Locale,
            EnvVarCategory::Network,
            EnvVarCategory::Other,
        ];
        for (i, v1) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v1, v2);
                } else {
                    assert_ne!(v1, v2);
                }
            }
        }
    }

    // ==================== PathInfo Tests ====================

    #[test]
    fn test_path_info_creation() {
        let path_info = PathInfo {
            path: "/etc/passwd".to_string(),
            path_type: PathType::Absolute,
            category: PathCategory::System,
            access_type: Some(PathAccessType::Read),
            source: "strings".to_string(),
            evidence: vec![],
            referenced_by_traits: vec![],
        };

        assert_eq!(path_info.path, "/etc/passwd");
        assert_eq!(path_info.path_type, PathType::Absolute);
        assert_eq!(path_info.category, PathCategory::System);
        assert_eq!(path_info.access_type, Some(PathAccessType::Read));
    }

    #[test]
    fn test_path_info_with_evidence() {
        let evidence = Evidence {
            method: "string".to_string(),
            source: "strings".to_string(),
            value: "/etc/passwd".to_string(),
            location: Some("0x1000".to_string()),
        };

        let path_info = PathInfo {
            path: "/etc/passwd".to_string(),
            path_type: PathType::Absolute,
            category: PathCategory::System,
            access_type: None,
            source: "strings".to_string(),
            evidence: vec![evidence],
            referenced_by_traits: vec!["fs/read/etc".to_string()],
        };

        assert_eq!(path_info.evidence.len(), 1);
        assert_eq!(path_info.referenced_by_traits.len(), 1);
    }

    // ==================== DirectoryAccess Tests ====================

    #[test]
    fn test_directory_access_creation() {
        let dir_access = DirectoryAccess {
            directory: "/etc".to_string(),
            files: vec!["passwd".to_string(), "shadow".to_string()],
            file_count: 2,
            access_pattern: DirectoryAccessPattern::MultipleSpecific { count: 2 },
            categories: vec![PathCategory::System],
            enumerated: false,
            generated_traits: vec![],
        };

        assert_eq!(dir_access.directory, "/etc");
        assert_eq!(dir_access.file_count, 2);
        assert!(!dir_access.enumerated);
    }

    #[test]
    fn test_directory_access_enumerated() {
        let dir_access = DirectoryAccess {
            directory: "/home".to_string(),
            files: vec![],
            file_count: 0,
            access_pattern: DirectoryAccessPattern::UserEnumeration,
            categories: vec![PathCategory::Home],
            enumerated: true,
            generated_traits: vec!["fs/enum/home".to_string()],
        };

        assert!(dir_access.enumerated);
        assert_eq!(dir_access.generated_traits.len(), 1);
    }

    // ==================== EnvVarInfo Tests ====================

    #[test]
    fn test_env_var_info_creation() {
        let env_var = EnvVarInfo {
            name: "PATH".to_string(),
            access_type: EnvVarAccessType::Read,
            source: "getenv".to_string(),
            category: EnvVarCategory::Path,
            evidence: vec![],
            referenced_by_traits: vec![],
        };

        assert_eq!(env_var.name, "PATH");
        assert_eq!(env_var.access_type, EnvVarAccessType::Read);
        assert_eq!(env_var.category, EnvVarCategory::Path);
    }

    #[test]
    fn test_env_var_info_credential() {
        let env_var = EnvVarInfo {
            name: "AWS_SECRET_ACCESS_KEY".to_string(),
            access_type: EnvVarAccessType::Read,
            source: "ast".to_string(),
            category: EnvVarCategory::Credential,
            evidence: vec![Evidence {
                method: "ast".to_string(),
                source: "tree-sitter".to_string(),
                value: "os.getenv('AWS_SECRET_ACCESS_KEY')".to_string(),
                location: Some("line:42".to_string()),
            }],
            referenced_by_traits: vec!["credential/aws".to_string()],
        };

        assert_eq!(env_var.category, EnvVarCategory::Credential);
        assert_eq!(env_var.evidence.len(), 1);
    }

    #[test]
    fn test_env_var_info_injection() {
        let env_var = EnvVarInfo {
            name: "LD_PRELOAD".to_string(),
            access_type: EnvVarAccessType::Write,
            source: "setenv".to_string(),
            category: EnvVarCategory::Injection,
            evidence: vec![],
            referenced_by_traits: vec![],
        };

        assert_eq!(env_var.category, EnvVarCategory::Injection);
        assert_eq!(env_var.access_type, EnvVarAccessType::Write);
    }
}
