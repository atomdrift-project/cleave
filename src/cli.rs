//! Command-line interface definitions and parsing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! This module defines the CLI structure using clap, including:
//! - Main command arguments
//! - Subcommands (diff, etc.)
//! - Component disable flags
//! - Output formatting options
//!
//! Note: Uses unwrap/expect for argument parsing where clap guarantees validity.
//!
//! # Component Control
//!
//! cleave supports disabling expensive analysis components:
//! - `--disable yara` - Skip YARA pattern matching
//! - `--disable radare2` - Skip binary disassembly
//! - `--disable upx` - Skip UPX unpacking attempts
//! - `--disable third-party` - Skip third-party YARA rules

use clap::{Parser, Subcommand};

/// Parse comma-separated platforms string into a vector of Platform values
/// Returns vec![Platform::All] if input is empty or "all"
#[allow(dead_code)] // Used by binary target
#[must_use]
pub(crate) fn parse_platforms(s: &str) -> Vec<crate::composite_rules::Platform> {
    use crate::composite_rules::Platform;

    if s.is_empty() {
        return vec![Platform::All];
    }

    let platforms: Vec<Platform> = s
        .split(',')
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
        .filter_map(|p| match p.as_str() {
            "all" => Some(Platform::All),
            "linux" => Some(Platform::Linux),
            "macos" | "darwin" => Some(Platform::MacOS),
            "windows" | "win" => Some(Platform::Windows),
            "unix" => Some(Platform::Unix),
            "android" => Some(Platform::Android),
            "ios" => Some(Platform::Ios),
            unknown => {
                eprintln!("⚠️  Unknown platform '{}', ignoring", unknown);
                None
            }
        })
        .collect();

    if platforms.is_empty() || platforms.contains(&Platform::All) {
        vec![Platform::All]
    } else {
        platforms
    }
}

/// Default passwords to try for encrypted zip files (common malware sample passwords)
pub(crate) const DEFAULT_ZIP_PASSWORDS: &[&str] =
    &["infected", "infect3d", "malware", "virus", "password"];

/// Tracks which components are disabled
#[allow(dead_code)] // Used by binary target
#[derive(Debug, Clone, Default)]
pub(crate) struct DisabledComponents {
    /// Whether YARA scanning is disabled
    pub yara: bool,
    /// Whether radare2 analysis is disabled
    pub radare2: bool,
    /// Whether UPX unpacking is disabled
    pub upx: bool,
    /// Whether third-party YARA rules are disabled
    pub third_party: bool,
}

impl DisabledComponents {
    /// Parse comma-separated list of components to disable
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn parse(s: &str) -> Self {
        let mut disabled = Self::default();
        for component in s.split(',').map(|c| c.trim().to_lowercase()) {
            match component.as_str() {
                "yara" => disabled.yara = true,
                "radare2" => disabled.radare2 = true,
                "upx" => disabled.upx = true,
                "third-party" => disabled.third_party = true,
                _ => {} // Ignore unknown components
            }
        }
        disabled
    }
}

/// Command-line arguments for the cleave tool
#[derive(Parser, Debug)]
#[command(name = "cleave")]
#[command(
    about = "Deep static analysis tool for extracting features from binaries and source code"
)]
#[command(version)]
pub(crate) struct Args {
    /// Subcommand to run (analyze, search, diff, etc.)
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Files or directories to analyze (when no subcommand is specified)
    #[arg(value_name = "PATH")]
    pub paths: Vec<String>,

    /// Output as JSONL (machine-readable, streaming). Shorthand for --format jsonl.
    #[arg(long)]
    pub json: bool,

    /// Output format: terminal (default), json, or jsonl (streaming)
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,

    /// Write output to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Write logs to file (in addition to stderr)
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<String>,

    /// Enable full trait validation (expensive, ~60s+). Disabled by default.
    /// Use --validate=true to enable. Can also set CLEAVE_VALIDATE=1 to enable.
    #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
    pub validate: bool,

    /// Additional password to try for encrypted zip files (can be specified multiple times)
    #[arg(long = "zip-password", value_name = "PASSWORD")]
    pub zip_passwords: Vec<String>,

    /// Disable automatic password guessing for encrypted zip files
    #[arg(long)]
    pub no_zip_passwords: bool,

    /// Disable specific components (comma-separated: yara,radare2,upx,third-party)
    #[arg(long, value_name = "COMPONENTS", default_value = "")]
    pub disable: String,

    /// Enable all components (overrides --disable default)
    #[arg(long)]
    pub enable_all: bool,

    /// Exit with error if top-level file has highest trait criticality matching these levels
    /// (comma-separated: filtered,baseline,notable,suspicious,hostile)
    /// Example: --error-if=suspicious,hostile (for sweeping known-good data)
    /// Example: --error-if=baseline,notable (for sweeping known-bad data for weak detections)
    #[arg(long, value_name = "LEVELS")]
    pub error_if: Option<String>,

    /// Include all files in directory scans, even unknown types
    /// By default, only recognized code/binary files are analyzed
    #[arg(long)]
    pub all_files: bool,

    /// Randomize file order when scanning directories
    /// Useful for trait-basher to ensure diverse sampling across runs
    #[arg(long)]
    pub shuffle: bool,

    /// Filter rules by target platform(s) (comma-separated, default: all)
    /// Examples: --platforms linux,macos or --platforms windows
    /// Valid values: all, linux, macos, windows, unix, android, ios
    #[arg(long, value_name = "PLATFORMS", default_value = "all")]
    pub platforms: String,

    /// Directory to extract all analyzed files for external tools or review.
    /// Files are written to <dir>/<sha256>/<original-path> preserving structure.
    /// When set, disables in-memory extraction (all files written to disk).
    #[arg(long, value_name = "DIR")]
    pub extract_dir: Option<String>,

    /// Custom traits directory (overrides CLEAVE_TRAITS_DIR env var and default "traits")
    #[arg(long, value_name = "DIR")]
    pub traits_dir: Option<String>,

    /// Minimum recursive precision required for HOSTILE composite traits.
    /// Rules below this threshold are downgraded to SUSPICIOUS.
    #[arg(long, default_value_t = 3.5)]
    pub min_hostile_precision: f32,

    /// Minimum recursive precision required for SUSPICIOUS composite traits.
    /// Rules below this threshold are downgraded to NOTABLE.
    #[arg(long, default_value_t = 1.5)]
    pub min_suspicious_precision: f32,

    /// Maximum file size (in MB) to keep in memory during archive analysis.
    /// Files larger than this are written to temp files. Default: 100 MB.
    #[arg(long, value_name = "MB", default_value_t = 100)]
    pub max_file_mem: u64,

    /// Generate malecule MOL file and JSON sidecar for 3D visualization.
    /// Writes <path>.mol and <path>.json with molecular representation of findings.
    #[arg(long, value_name = "PATH")]
    pub mol: Option<String>,

    /// Layout algorithm for malecule visualization (requires --mol).
    /// Options: spherical (default), force, tree, spiral
    #[arg(long, value_enum, default_value = "spherical")]
    pub mol_layout: MolLayout,
}

/// Layout algorithm for malecule visualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum MolLayout {
    /// Concentric spherical shells by hierarchy depth (default)
    #[default]
    Spherical,
    /// Spring-based force simulation
    Force,
    /// Radial tree from center
    Tree,
    /// Logarithmic spiral arrangement
    Spiral,
}

impl Args {
    /// Get the disabled components based on --disable and --enable-all flags
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn disabled_components(&self) -> DisabledComponents {
        if self.enable_all {
            DisabledComponents::default()
        } else {
            DisabledComponents::parse(&self.disable)
        }
    }

    /// Get the output format based on --json and --format flags
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn format(&self) -> OutputFormat {
        // --format takes precedence over --json
        if let Some(format) = self.format {
            return format;
        }
        if self.json {
            OutputFormat::Jsonl
        } else {
            OutputFormat::Terminal
        }
    }

    /// Parse --error-if flag into a set of criticality levels
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn error_if_levels(&self) -> Option<Vec<crate::types::Criticality>> {
        self.error_if.as_ref().map(|s| {
            s.split(',')
                .map(|level| parse_criticality_level(level.trim()))
                .collect()
        })
    }

    /// Parse --platforms flag into a vector of Platform values
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn platforms(&self) -> Vec<crate::composite_rules::Platform> {
        parse_platforms(&self.platforms)
    }
}

/// Parse a criticality level string (case-insensitive)
#[allow(dead_code)] // Used by binary target
fn parse_criticality_level(s: &str) -> crate::types::Criticality {
    match s.to_lowercase().as_str() {
        "filtered" => crate::types::Criticality::Filtered,
        "component" => crate::types::Criticality::Component,
        "baseline" => crate::types::Criticality::Baseline,
        "notable" => crate::types::Criticality::Notable,
        "suspicious" => crate::types::Criticality::Suspicious,
        "hostile" | "malicious" => crate::types::Criticality::Hostile,
        _ => {
            eprintln!(
                "⚠️  Unknown criticality level '{}', treating as 'baseline'",
                s
            );
            crate::types::Criticality::Baseline
        }
    }
}

/// Available cleave subcommands
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Command {
    /// Analyze files or directories
    Analyze {
        /// Target files or directories to analyze
        #[arg(required = true)]
        targets: Vec<String>,
    },

    /// Compare two versions (diff mode) for supply chain attack detection
    Diff {
        /// Old/baseline version (file or directory)
        old: String,

        /// New/target version (file or directory)
        new: String,
    },

    /// Extract language-specific strings from a binary
    Strings {
        /// Target binary file
        #[arg(required = true)]
        target: String,

        /// Minimum string length
        #[arg(short, long, default_value = "4")]
        min_length: usize,

        /// Filter to a specific layer (e.g., "upx@0" for UPX-unpacked content)
        #[arg(short = 'L', long)]
        layer: Option<String>,
    },

    /// Extract symbols (imports, exports, functions) from a binary or source file
    Symbols {
        /// Target file (binary or source)
        #[arg(required = true)]
        target: String,

        /// Filter to a specific layer (e.g., "upx@0" for UPX-unpacked content)
        #[arg(short = 'L', long)]
        layer: Option<String>,
    },

    /// Extract section information (name, address, size, entropy) from a binary
    Sections {
        /// Target binary file
        #[arg(required = true)]
        target: String,

        /// Filter to a specific layer (e.g., "upx@0" for UPX-unpacked content)
        #[arg(short = 'L', long)]
        layer: Option<String>,
    },

    /// Extract computed metrics from a binary or source file
    Metrics {
        /// Target file (binary or source)
        #[arg(required = true)]
        target: String,

        /// Filter to a specific layer (e.g., "upx@0" for UPX-unpacked content)
        #[arg(short = 'L', long)]
        layer: Option<String>,
    },

    /// Debug rule evaluation - trace through how rules match or fail
    TestRules {
        /// Target file to analyze
        #[arg(required = true)]
        target: String,

        /// Comma-separated list of rule/trait IDs to debug
        /// (e.g., "lateral-movement/supply-chain/npm/obfuscated-trojan,anti-static/obfuscation/code-metrics")
        #[arg(short, long, value_name = "RULE_IDS")]
        rules: String,
    },

    /// Test pattern matching against a file
    TestMatch {
        /// Target file to analyze
        #[arg(required = true)]
        target: String,

        /// Type of search to perform (string, symbol, raw, kv, hex, encoded, metrics)
        #[arg(short, long, value_enum, default_value = "string")]
        r#type: SearchType,

        /// Match method: exact, contains, regex, or word
        #[arg(short, long, value_enum, default_value = "contains")]
        method: MatchMethod,

        /// Pattern to search for (for kv: the value to match, or omit for existence check, for metrics: the field path)
        #[arg(short, long)]
        pattern: Option<String>,

        /// Path expression for kv searches (e.g., "scripts.postinstall", "permissions[*]")
        #[arg(long)]
        kv_path: Option<String>,

        /// Require field to exist (true) or not exist (false) for kv searches
        #[arg(long)]
        exists: Option<bool>,

        /// Minimum collection size for kv searches (array elements or object keys)
        #[arg(long)]
        size_min: Option<usize>,

        /// Maximum collection size for kv searches (array elements or object keys)
        #[arg(long)]
        size_max: Option<usize>,

        /// File type to use for analysis (auto-detected if not specified)
        #[arg(short, long, value_enum)]
        file_type: Option<DetectFileType>,

        /// Minimum number of matches required (for string/raw/encoded searches)
        #[arg(long, default_value = "1")]
        count_min: usize,

        /// Maximum number of matches allowed (for string/raw/encoded searches)
        #[arg(long)]
        count_max: Option<usize>,

        /// Minimum matches per kilobyte (density floor)
        #[arg(long)]
        per_kb_min: Option<f64>,

        /// Maximum matches per kilobyte (density ceiling)
        #[arg(long)]
        per_kb_max: Option<f64>,

        /// Case-insensitive matching
        #[arg(short, long)]
        case_insensitive: bool,

        /// Restrict search to named section (e.g., "text", ".data", "__TEXT,__text")
        #[arg(long)]
        section: Option<String>,

        /// Search only at exact file offset (hex or decimal, negative = from end)
        #[arg(long)]
        offset: Option<i64>,

        /// Search within byte range [start,end) - use "start," for open-ended (e.g., "0,4096" or "-1024,")
        #[arg(long, value_parser = parse_offset_range)]
        offset_range: Option<(i64, Option<i64>)>,

        /// Section-relative offset (requires --section)
        #[arg(long)]
        section_offset: Option<i64>,

        /// Section-relative byte range [start,end) (requires --section)
        #[arg(long, value_parser = parse_offset_range)]
        section_offset_range: Option<(i64, Option<i64>)>,

        /// Filter by encoding method(s) for 'encoded' search type
        /// Examples: "base64", "xor,hex", "xor+base64"
        /// Use comma for OR, plus for chain sequence
        #[arg(long)]
        encoding: Option<String>,

        /// Require matches to contain a valid external IP (not private/loopback/reserved)
        #[arg(long)]
        external_ip: bool,

        /// Minimum entropy for section searches (0.0-8.0)
        #[arg(long)]
        entropy_min: Option<f64>,

        /// Maximum entropy for section searches (0.0-8.0)
        #[arg(long)]
        entropy_max: Option<f64>,

        /// Minimum section length in bytes (for section searches)
        #[arg(long)]
        length_min: Option<u64>,

        /// Maximum section length in bytes (for section searches)
        #[arg(long)]
        length_max: Option<u64>,

        /// Minimum value threshold (for metrics searches)
        #[arg(long)]
        value_min: Option<f64>,

        /// Maximum value threshold (for metrics searches)
        #[arg(long)]
        value_max: Option<f64>,

        /// Minimum file size in bytes (for metrics searches)
        #[arg(long)]
        min_size: Option<u64>,

        /// Maximum file size in bytes (for metrics searches)
        #[arg(long)]
        max_size: Option<u64>,
    },

    /// Profile YARA rule performance per rule file against a target.
    /// Compiles each .yar file individually, scans the target, and reports
    /// timing sorted slowest-first so you can identify rules to disable.
    #[command(name = "yara-profile")]
    YaraProfile {
        /// Target file to scan
        #[arg(required = true)]
        target: String,

        /// Only show rule files taking longer than this many milliseconds
        #[arg(short, long, default_value = "10")]
        min_ms: u64,
    },

    /// Generate a map visualization of trait relationships
    Map {
        /// Directory depth level (2 = micro-behaviors/comm, 3 = micro-behaviors/communications/socket, etc.)
        #[arg(short, long, default_value = "3")]
        depth: usize,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Minimum reference count to show edge (filters weak relationships)
        #[arg(short, long, default_value = "1")]
        min_refs: usize,

        /// Show only these top-level namespaces (comma-separated: objectives,micro-behaviors,well-known,metadata)
        #[arg(long)]
        namespaces: Option<String>,

        /// Build map from JSONL findings (file path or "-" for stdin)
        #[arg(long, value_name = "PATH")]
        from_findings: Option<String>,

        /// Output format: dot (default), ascii
        #[arg(short = 'f', long, default_value = "dot")]
        format: MapFormat,

        /// Minimum criticality to include (baseline, notable, suspicious, hostile)
        #[arg(long, default_value = "baseline")]
        min_crit: String,

        /// Show low-value composite rules (any with needs<=1)
        #[arg(long)]
        show_low_value: bool,
    },
}

/// Parse an offset range like "0,4096" or "-1024," into (start, Option<end>)
fn parse_offset_range(s: &str) -> Result<(i64, Option<i64>), String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 2 {
        return Err("offset_range must be 'start,end' or 'start,' for open-ended".to_string());
    }
    let start: i64 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("invalid start offset: {}", parts[0]))?;
    let end = if parts[1].trim().is_empty() {
        None
    } else {
        Some(
            parts[1]
                .trim()
                .parse()
                .map_err(|_| format!("invalid end offset: {}", parts[1]))?,
        )
    };
    Ok((start, end))
}

/// Type of content to search in
#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
pub(crate) enum SearchType {
    /// Search in extracted strings
    String,
    /// Search in symbols (imports/exports)
    Symbol,
    /// Search in raw file content
    Raw,
    /// Search in structured data (JSON/YAML/TOML manifests)
    Kv,
    /// Search for hex byte patterns
    Hex,
    /// Search in decoded strings (base64, xor, hex, url, etc.) - optionally filter by encoding
    Encoded,
    /// Search for sections by name (supports entropy/size constraints via count_min/max and per_kb_min/max)
    Section,
    /// Test metrics conditions (pattern is field path like "binary.avg_complexity", use --value-min/max for thresholds)
    Metrics,
}

/// How to match a search pattern against content
#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
pub(crate) enum MatchMethod {
    /// Exact match
    Exact,
    /// Contains substring
    Contains,
    /// Regular expression match
    Regex,
    /// Whole word match
    Word,
}

/// File type to use for analysis context override
#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
pub(crate) enum DetectFileType {
    /// ELF binary
    Elf,
    /// PE/Windows executable
    Pe,
    /// Mach-O binary
    Macho,
    /// JavaScript source
    JavaScript,
    /// Python source
    Python,
    /// Go source
    Go,
    /// Shell script
    Shell,
    /// Raw/binary content
    Raw,
}

/// Output format for the diff command
#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
pub(crate) enum OutputFormat {
    /// JSONL output (newline-delimited JSON) for streaming
    Jsonl,
    /// Human-readable terminal output
    Terminal,
}

/// Output format for map visualization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum MapFormat {
    /// Graphviz DOT format
    #[default]
    Dot,
    /// ASCII terminal art
    Ascii,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_paths_without_subcommand() {
        let args = Args::try_parse_from(["cleave", "file1.bin", "file2.bin", "dir1"]).unwrap();

        assert!(args.command.is_none());
        assert_eq!(args.paths, vec!["file1.bin", "file2.bin", "dir1"]);
    }

    #[test]
    fn test_parse_single_path_without_subcommand() {
        let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();

        assert!(args.command.is_none());
        assert_eq!(args.paths, vec!["file.bin"]);
    }

    #[test]
    fn test_parse_analyze_command() {
        let args = Args::try_parse_from(["cleave", "analyze", "file.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Analyze { .. })));
        if let Some(Command::Analyze { targets }) = args.command {
            assert_eq!(targets, vec!["file.bin"]);
        }
    }

    #[test]
    fn test_parse_analyze_multiple_targets() {
        let args =
            Args::try_parse_from(["cleave", "analyze", "file1.bin", "file2.bin", "dir1"]).unwrap();

        if let Some(Command::Analyze { targets }) = args.command {
            assert_eq!(targets, vec!["file1.bin", "file2.bin", "dir1"]);
        }
    }

    #[test]
    fn test_parse_diff_command() {
        let args = Args::try_parse_from(["cleave", "diff", "old.bin", "new.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Diff { .. })));
        if let Some(Command::Diff { old, new }) = args.command {
            assert_eq!(old, "old.bin");
            assert_eq!(new, "new.bin");
        }
    }

    #[test]
    fn test_parse_strings_command() {
        let args = Args::try_parse_from(["cleave", "strings", "file.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Strings { .. })));
        if let Some(Command::Strings {
            target,
            min_length,
            layer,
        }) = args.command
        {
            assert_eq!(target, "file.bin");
            assert_eq!(min_length, 4); // Default value
            assert!(layer.is_none());
        }
    }

    #[test]
    fn test_parse_strings_command_with_min_length() {
        let args = Args::try_parse_from(["cleave", "strings", "file.bin", "-m", "10"]).unwrap();

        if let Some(Command::Strings {
            target,
            min_length,
            layer,
        }) = args.command
        {
            assert_eq!(target, "file.bin");
            assert_eq!(min_length, 10);
            assert!(layer.is_none());
        }
    }

    #[test]
    fn test_parse_strings_command_with_layer() {
        let args =
            Args::try_parse_from(["cleave", "strings", "file.bin", "--layer", "upx@0"]).unwrap();

        if let Some(Command::Strings {
            target,
            min_length,
            layer,
        }) = args.command
        {
            assert_eq!(target, "file.bin");
            assert_eq!(min_length, 4);
            assert_eq!(layer, Some("upx@0".to_string()));
        }
    }

    #[test]
    fn test_parse_symbols_command() {
        let args = Args::try_parse_from(["cleave", "symbols", "file.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Symbols { .. })));
        if let Some(Command::Symbols { target, layer }) = args.command {
            assert_eq!(target, "file.bin");
            assert!(layer.is_none());
        }
    }

    #[test]
    fn test_parse_symbols_command_with_layer() {
        let args =
            Args::try_parse_from(["cleave", "symbols", "file.bin", "--layer", "upx@0"]).unwrap();

        if let Some(Command::Symbols { target, layer }) = args.command {
            assert_eq!(target, "file.bin");
            assert_eq!(layer, Some("upx@0".to_string()));
        }
    }

    #[test]
    fn test_parse_json_flag() {
        let args = Args::try_parse_from(["cleave", "--json", "file.bin"]).unwrap();
        assert!(args.json);
        assert!(matches!(args.format(), OutputFormat::Jsonl));
    }

    #[test]
    fn test_parse_no_json_flag() {
        let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
        assert!(!args.json);
        assert!(matches!(args.format(), OutputFormat::Terminal));
    }

    #[test]
    fn test_parse_output_file() {
        let args = Args::try_parse_from(["cleave", "-o", "results.json", "file.bin"]).unwrap();
        assert_eq!(args.output, Some("results.json".to_string()));
    }

    #[test]
    fn test_parse_verbose() {
        let args = Args::try_parse_from(["cleave", "-v", "file.bin"]).unwrap();
        assert!(args.verbose);
    }

    #[test]
    fn test_parse_no_verbose() {
        let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
        assert!(!args.verbose);
    }

    #[test]
    fn test_parse_all_options_together() {
        let args = Args::try_parse_from([
            "cleave",
            "--json",
            "-o",
            "output.json",
            "-v",
            "file1.bin",
            "file2.bin",
        ])
        .unwrap();

        assert!(args.json);
        assert!(matches!(args.format(), OutputFormat::Jsonl));
        assert_eq!(args.output, Some("output.json".to_string()));
        assert!(args.verbose);
        assert_eq!(args.paths, vec!["file1.bin", "file2.bin"]);
    }

    #[test]
    fn test_parse_no_args_succeeds_with_empty_paths() {
        // Running without args is now valid (will show help or error at runtime)
        let result = Args::try_parse_from(["cleave"]);
        assert!(result.is_ok());
        assert!(result.unwrap().paths.is_empty());
    }

    #[test]
    fn test_precision_threshold_defaults() {
        let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
        assert_eq!(args.min_hostile_precision, 3.5);
        assert_eq!(args.min_suspicious_precision, 1.5);
    }

    #[test]
    fn test_precision_threshold_flags() {
        let args = Args::try_parse_from([
            "cleave",
            "--min-hostile-precision",
            "5.5",
            "--min-suspicious-precision",
            "2.7",
            "file.bin",
        ])
        .unwrap();
        assert_eq!(args.min_hostile_precision, 5.5);
        assert_eq!(args.min_suspicious_precision, 2.7);
    }

    #[test]
    fn test_output_format_clone() {
        let format = OutputFormat::Jsonl;
        let cloned = format;
        assert!(matches!(cloned, OutputFormat::Jsonl));
    }

    #[test]
    fn test_output_format_debug() {
        let format = OutputFormat::Terminal;
        let debug_str = format!("{:?}", format);
        assert!(debug_str.contains("Terminal"));
    }

    #[test]
    fn test_parse_zip_password_single() {
        let args =
            Args::try_parse_from(["cleave", "--zip-password", "secret", "analyze", "file.zip"])
                .unwrap();
        assert_eq!(args.zip_passwords, vec!["secret"]);
        assert!(!args.no_zip_passwords);
    }

    #[test]
    fn test_parse_zip_password_multiple() {
        let args = Args::try_parse_from([
            "cleave",
            "--zip-password",
            "pass1",
            "--zip-password",
            "pass2",
            "--zip-password",
            "pass3",
            "analyze",
            "file.zip",
        ])
        .unwrap();
        assert_eq!(args.zip_passwords, vec!["pass1", "pass2", "pass3"]);
    }

    #[test]
    fn test_parse_no_zip_passwords() {
        let args =
            Args::try_parse_from(["cleave", "--no-zip-passwords", "analyze", "file.zip"]).unwrap();
        assert!(args.no_zip_passwords);
        assert!(args.zip_passwords.is_empty());
    }

    #[test]
    fn test_parse_zip_password_default_empty() {
        let args = Args::try_parse_from(["cleave", "analyze", "file.zip"]).unwrap();
        assert!(args.zip_passwords.is_empty());
        assert!(!args.no_zip_passwords);
    }

    #[test]
    fn test_default_zip_passwords_content() {
        // Verify the default passwords are what we expect
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"infected"));
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"infect3d"));
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"malware"));
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"virus"));
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"password"));
        assert_eq!(DEFAULT_ZIP_PASSWORDS.len(), 5);
    }

    #[test]
    fn test_disabled_components_default() {
        let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
        let disabled = args.disabled_components();
        // Nothing is disabled by default
        assert!(!disabled.third_party);
        assert!(!disabled.yara);
        assert!(!disabled.radare2);
        assert!(!disabled.upx);
    }

    #[test]
    fn test_disabled_components_custom() {
        let args =
            Args::try_parse_from(["cleave", "--disable", "yara,radare2", "file.bin"]).unwrap();
        let disabled = args.disabled_components();
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(!disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_all() {
        let args = Args::try_parse_from([
            "cleave",
            "--disable",
            "yara,radare2,upx,third-party",
            "file.bin",
        ])
        .unwrap();
        let disabled = args.disabled_components();
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(disabled.upx);
        assert!(disabled.third_party);
    }

    #[test]
    fn test_enable_all_overrides_disable() {
        let args = Args::try_parse_from(["cleave", "--enable-all", "file.bin"]).unwrap();
        let disabled = args.disabled_components();
        // --enable-all should override the default --disable=third-party
        assert!(!disabled.third_party);
        assert!(!disabled.yara);
        assert!(!disabled.radare2);
        assert!(!disabled.upx);
    }

    #[test]
    fn test_disabled_components_from_str() {
        let disabled = DisabledComponents::parse("yara,upx");
        assert!(disabled.yara);
        assert!(disabled.upx);
        assert!(!disabled.radare2);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_from_str_with_spaces() {
        let disabled = DisabledComponents::parse("yara, radare2 , upx");
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_from_str_ignores_unknown() {
        let disabled = DisabledComponents::parse("yara,unknown,radare2");
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(!disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disable_empty_string() {
        let args = Args::try_parse_from(["cleave", "--disable", "", "file.bin"]).unwrap();
        let disabled = args.disabled_components();
        // Empty string means nothing disabled
        assert!(!disabled.yara);
        assert!(!disabled.radare2);
        assert!(!disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_error_if_single_level() {
        let args =
            Args::try_parse_from(["cleave", "--error-if", "suspicious", "file.bin"]).unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], crate::types::Criticality::Suspicious);
    }

    #[test]
    fn test_error_if_multiple_levels() {
        let args = Args::try_parse_from(["cleave", "--error-if", "suspicious,hostile", "file.bin"])
            .unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 2);
        assert!(levels.contains(&crate::types::Criticality::Suspicious));
        assert!(levels.contains(&crate::types::Criticality::Hostile));
    }

    #[test]
    fn test_error_if_all_levels() {
        let args = Args::try_parse_from([
            "cleave",
            "--error-if",
            "filtered,baseline,notable,suspicious,hostile",
            "file.bin",
        ])
        .unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 5);
        assert!(levels.contains(&crate::types::Criticality::Filtered));
        assert!(levels.contains(&crate::types::Criticality::Baseline));
        assert!(levels.contains(&crate::types::Criticality::Notable));
        assert!(levels.contains(&crate::types::Criticality::Suspicious));
        assert!(levels.contains(&crate::types::Criticality::Hostile));
    }

    #[test]
    fn test_error_if_with_spaces() {
        let args = Args::try_parse_from([
            "cleave",
            "--error-if",
            "suspicious, hostile , notable",
            "file.bin",
        ])
        .unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 3);
        assert!(levels.contains(&crate::types::Criticality::Suspicious));
        assert!(levels.contains(&crate::types::Criticality::Hostile));
        assert!(levels.contains(&crate::types::Criticality::Notable));
    }

    #[test]
    fn test_error_if_none() {
        let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
        assert!(args.error_if_levels().is_none());
    }

    #[test]
    fn test_error_if_case_insensitive() {
        let args = Args::try_parse_from([
            "cleave",
            "--error-if",
            "SUSPICIOUS,Hostile,NoTabLe",
            "file.bin",
        ])
        .unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 3);
        assert!(levels.contains(&crate::types::Criticality::Suspicious));
        assert!(levels.contains(&crate::types::Criticality::Hostile));
        assert!(levels.contains(&crate::types::Criticality::Notable));
    }

    // Platform parsing tests
    #[test]
    fn test_parse_platforms_default() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms("all");
        assert_eq!(platforms, vec![Platform::All]);
    }

    #[test]
    fn test_parse_platforms_empty() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms("");
        assert_eq!(platforms, vec![Platform::All]);
    }

    #[test]
    fn test_parse_platforms_single() {
        use crate::composite_rules::Platform;
        assert_eq!(parse_platforms("linux"), vec![Platform::Linux]);
        assert_eq!(parse_platforms("macos"), vec![Platform::MacOS]);
        assert_eq!(parse_platforms("darwin"), vec![Platform::MacOS]);
        assert_eq!(parse_platforms("windows"), vec![Platform::Windows]);
        assert_eq!(parse_platforms("win"), vec![Platform::Windows]);
        assert_eq!(parse_platforms("unix"), vec![Platform::Unix]);
        assert_eq!(parse_platforms("android"), vec![Platform::Android]);
        assert_eq!(parse_platforms("ios"), vec![Platform::Ios]);
    }

    #[test]
    fn test_parse_platforms_multiple() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms("linux,macos");
        assert_eq!(platforms.len(), 2);
        assert!(platforms.contains(&Platform::Linux));
        assert!(platforms.contains(&Platform::MacOS));
    }

    #[test]
    fn test_parse_platforms_with_spaces() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms(" linux , macos , windows ");
        assert_eq!(platforms.len(), 3);
        assert!(platforms.contains(&Platform::Linux));
        assert!(platforms.contains(&Platform::MacOS));
        assert!(platforms.contains(&Platform::Windows));
    }

    #[test]
    fn test_parse_platforms_case_insensitive() {
        use crate::composite_rules::Platform;
        assert_eq!(parse_platforms("LINUX"), vec![Platform::Linux]);
        assert_eq!(parse_platforms("MacOS"), vec![Platform::MacOS]);
        assert_eq!(parse_platforms("Windows"), vec![Platform::Windows]);
    }

    #[test]
    fn test_parse_platforms_all_overrides() {
        use crate::composite_rules::Platform;
        // If "all" is in the list, it should return just [All]
        let platforms = parse_platforms("linux,all,macos");
        assert_eq!(platforms, vec![Platform::All]);
    }

    #[test]
    fn test_parse_platforms_unknown_ignored() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms("linux,freebsd,macos");
        // freebsd should be ignored, only linux and macos
        assert_eq!(platforms.len(), 2);
        assert!(platforms.contains(&Platform::Linux));
        assert!(platforms.contains(&Platform::MacOS));
    }

    #[test]
    fn test_platforms_cli_flag() {
        let args =
            Args::try_parse_from(["cleave", "--platforms", "linux,macos", "file.bin"]).unwrap();
        assert_eq!(args.platforms, "linux,macos");
    }

    #[test]
    fn test_platforms_default_value() {
        let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
        assert_eq!(args.platforms, "all");
    }

    #[test]
    fn test_parse_metrics_command() {
        let args = Args::try_parse_from(["cleave", "metrics", "file.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Metrics { .. })));
        if let Some(Command::Metrics { target, layer }) = args.command {
            assert_eq!(target, "file.bin");
            assert!(layer.is_none());
        }
    }

    #[test]
    fn test_parse_metrics_command_with_layer() {
        let args =
            Args::try_parse_from(["cleave", "metrics", "file.bin", "--layer", "upx@0"]).unwrap();

        if let Some(Command::Metrics { target, layer }) = args.command {
            assert_eq!(target, "file.bin");
            assert_eq!(layer, Some("upx@0".to_string()));
        }
    }

    #[test]
    fn test_parse_test_match_metrics() {
        let args = Args::try_parse_from([
            "cleave",
            "test-match",
            "file.bin",
            "--type",
            "metrics",
            "--pattern",
            "binary.avg_complexity",
            "--value-min",
            "10.0",
            "--value-max",
            "50.0",
        ])
        .unwrap();

        if let Some(Command::TestMatch {
            target,
            r#type,
            pattern,
            value_min,
            value_max,
            ..
        }) = args.command
        {
            assert_eq!(target, "file.bin");
            assert_eq!(r#type, SearchType::Metrics);
            assert_eq!(pattern, Some("binary.avg_complexity".to_string()));
            assert_eq!(value_min, Some(10.0));
            assert_eq!(value_max, Some(50.0));
        } else {
            panic!("Expected TestMatch command");
        }
    }

    #[test]
    fn test_parse_test_match_metrics_with_size_constraints() {
        let args = Args::try_parse_from([
            "cleave",
            "test-match",
            "file.bin",
            "--type",
            "metrics",
            "--pattern",
            "binary.import_count",
            "--value-min",
            "5.0",
            "--min-size",
            "1024",
            "--max-size",
            "1048576",
        ])
        .unwrap();

        if let Some(Command::TestMatch {
            target,
            r#type,
            pattern,
            value_min,
            min_size,
            max_size,
            ..
        }) = args.command
        {
            assert_eq!(target, "file.bin");
            assert_eq!(r#type, SearchType::Metrics);
            assert_eq!(pattern, Some("binary.import_count".to_string()));
            assert_eq!(value_min, Some(5.0));
            assert_eq!(min_size, Some(1024));
            assert_eq!(max_size, Some(1048576));
        } else {
            panic!("Expected TestMatch command");
        }
    }

    #[test]
    fn test_search_type_metrics_copy() {
        let search_type = SearchType::Metrics;
        let copied = search_type; // Copy, not Clone
        assert_eq!(copied, SearchType::Metrics);
    }

    #[test]
    fn test_search_type_metrics_debug() {
        let search_type = SearchType::Metrics;
        let debug_str = format!("{:?}", search_type);
        assert!(debug_str.contains("Metrics"));
    }
}
