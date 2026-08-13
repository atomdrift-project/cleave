//! Command-line interface definitions and parsing.
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
pub fn parse_platforms(s: &str) -> Vec<crate::composite_rules::Platform> {
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
            "aix" => Some(Platform::Aix),
            "solaris" => Some(Platform::Solaris),
            "freebsd" => Some(Platform::FreeBsd),
            "openbsd" => Some(Platform::OpenBsd),
            "netbsd" => Some(Platform::NetBsd),
            "dragonflybsd" | "dragonfly" => Some(Platform::DragonFlyBsd),
            "openwrt" => Some(Platform::OpenWrt),
            "qnx" => Some(Platform::Qnx),
            "esxi" => Some(Platform::Esxi),
            "zos" | "z/os" => Some(Platform::Zos),
            "appliance" | "network-appliance" => Some(Platform::Appliance),
            "routeros" => Some(Platform::RouterOs),
            "fortios" => Some(Platform::FortiOs),
            "panos" | "pan-os" => Some(Platform::PanOs),
            "iosxe" | "ios-xe" => Some(Platform::IosXe),
            "junos" => Some(Platform::Junos),
            "netscaler" => Some(Platform::Netscaler),
            "ivanti" => Some(Platform::Ivanti),
            "vxworks" => Some(Platform::VxWorks),
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
pub const DEFAULT_ZIP_PASSWORDS: &[&str] = &[
    "infected",
    "infect3d",
    "malware",
    "virus",
    "password",
    "virussign",
];

/// Tracks which components are disabled
#[allow(dead_code)] // Used by binary target
#[derive(Debug, Clone, Default)]
pub struct DisabledComponents {
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
    pub fn parse(s: &str) -> Self {
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
    about = "Deep static analysis tool for extracting features from binaries and source code",
    version
)]
pub struct Args {
    /// Subcommand to run (analyze, search, diff, etc.)
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Files or directories to analyze (when no subcommand is specified)
    #[arg(value_name = "PATH")]
    pub paths: Vec<String>,

    /// Output as JSONL (machine-readable, streaming). Shorthand for --format jsonl.
    #[arg(long)]
    pub json: bool,

    /// Output format: terminal (default), json (single object), or jsonl (streaming)
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,

    /// Write output to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Disable the periodic update notice (also: CLEAVE_NO_UPDATE_CHECK=1)
    #[arg(long)]
    pub no_update_check: bool,

    /// Write logs to file (in addition to stderr)
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<String>,

    /// Disable specific components (comma-separated: yara,radare2,upx,third-party)
    #[arg(long, value_name = "COMPONENTS", default_value = "")]
    pub disable: String,

    /// Enable all components (overrides --disable default)
    #[arg(long)]
    pub enable_all: bool,

    /// Include all files in directory scans, even unknown types
    /// By default, only recognized code/binary files are analyzed
    #[arg(long)]
    pub all_files: bool,

    /// Additional passwords to try for encrypted ZIP/7z archives.
    /// Repeat the option to provide more than one password; built-in common
    /// sample passwords are always tried as well.
    #[arg(long = "zip-password", value_name = "PASSWORD", global = true)]
    pub zip_passwords: Vec<String>,

    /// Filter rules by target platform(s) (comma-separated, default: all)
    /// Examples: --platforms linux,macos or --platforms windows
    /// Valid values: all, linux, macos, windows, unix, android, ios, appliance, routeros, fortios, freebsd, openbsd, netbsd, aix, solaris
    #[arg(long, value_name = "PLATFORMS", default_value = "all")]
    pub platforms: String,

    /// Directory to extract all analyzed files for external tools or review.
    /// Files are written to `<dir>/<sha256>/<original-path>` preserving structure.
    /// When set, disables in-memory extraction (all files written to disk).
    #[arg(long, value_name = "DIR")]
    pub extract_dir: Option<String>,

    /// Custom traits directory (overrides CLEAVE_TRAITS_DIR env var and default "traits")
    #[arg(long, value_name = "DIR")]
    pub traits_dir: Option<String>,

    /// Maximum file size (in MB) to keep in memory during archive analysis.
    /// Files larger than this are written to temp files. Default: 100 MB.
    #[arg(long, value_name = "MB", default_value_t = 100)]
    pub max_file_mem: u64,

    /// Maximum file size (in MB) to scan during directory analysis.
    /// Files larger than this are skipped. Default: 20480 MB / 20 GB (0 = no limit).
    /// Sized to admit full OS images (ISO/UDF, DMG) from the os-image feed.
    #[arg(long, value_name = "MB", default_value_t = 20480)]
    pub max_file_size: u64,

    /// Warn when a single rule takes longer than this many milliseconds to evaluate.
    /// Rules >1000ms are always logged at debug level (visible via --verbose).
    #[arg(long, value_name = "MS", default_value_t = 4000)]
    pub slow_rule_ms: u64,

    /// Minimum criticality level to include in output
    /// (filtered, component, baseline, notable, suspicious, hostile)
    #[arg(long, value_name = "LEVEL", value_parser = parse_criticality)]
    pub min_crit: Option<crate::types::Criticality>,

    /// Maximum criticality level to include in output
    /// (filtered, component, baseline, notable, suspicious, hostile)
    #[arg(long, value_name = "LEVEL", value_parser = parse_criticality)]
    pub max_crit: Option<crate::types::Criticality>,

    /// Minimum file criticality (based on highest trait) to include in output.
    /// Files whose highest-criticality trait is below this level are excluded entirely.
    #[arg(long, value_name = "LEVEL", value_parser = parse_criticality)]
    pub min_file_crit: Option<crate::types::Criticality>,

    /// Maximum file criticality (based on highest trait) to include in output.
    /// Files whose highest-criticality trait is above this level are excluded entirely.
    #[arg(long, value_name = "LEVEL", value_parser = parse_criticality)]
    pub max_file_crit: Option<crate::types::Criticality>,
}

impl Args {
    /// Get the disabled components based on --disable and --enable-all flags
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub fn disabled_components(&self) -> DisabledComponents {
        if self.enable_all {
            DisabledComponents::default()
        } else {
            DisabledComponents::parse(&self.disable)
        }
    }

    /// Get the output format based on --format flag, --json flag, or CLEAVE_FORMAT env var.
    /// Precedence: --format > --json > CLEAVE_FORMAT > Terminal (default)
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub fn format(&self) -> OutputFormat {
        // --format takes precedence over everything
        if let Some(format) = self.format {
            return format;
        }
        if self.json {
            return OutputFormat::Jsonl;
        }
        // Fall back to CLEAVE_FORMAT env var
        if let Ok(val) = std::env::var("CLEAVE_FORMAT") {
            match val.to_lowercase().as_str() {
                "json" => return OutputFormat::Json,
                "jsonl" => return OutputFormat::Jsonl,
                "tiny" => return OutputFormat::Tiny,
                "terminal" => return OutputFormat::Terminal,
                _ => {
                    eprintln!("warning: unknown CLEAVE_FORMAT '{val}', using terminal");
                }
            }
        }
        OutputFormat::Terminal
    }

    /// Parse --platforms flag into a vector of Platform values
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub fn platforms(&self) -> Vec<crate::composite_rules::Platform> {
        parse_platforms(&self.platforms)
    }

    /// Return the built-in archive passwords followed by unique CLI additions.
    #[must_use]
    pub fn archive_passwords(&self) -> Vec<String> {
        let mut passwords: Vec<String> = DEFAULT_ZIP_PASSWORDS
            .iter()
            .copied()
            .map(str::to_string)
            .collect();
        for password in &self.zip_passwords {
            if !passwords.contains(password) {
                passwords.push(password.clone());
            }
        }
        passwords
    }
}

/// Available cleave subcommands
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Analyze files or directories
    Analyze {
        /// Target files or directories to analyze
        /// File paths to inspect (1+ required).

        #[arg(required = true)]
        targets: Vec<String>,
    },

    /// Enumerate recognized files as JSONL (for ingest pipelines).
    ///
    /// Walks the given targets and emits one JSON line per recognized file:
    /// `{"path":"...","type":"elf","sz":12345}`. No hashing, no analysis —
    /// the caller (e.g. hopper) does its own hashing via its own cache.
    /// Files whose magic bytes do not match a recognized program type are
    /// silently skipped. Honors `--max-file-size` for the size ceiling.
    #[command(name = "iter-files")]
    IterFiles {
        /// Target files or directories to enumerate
        /// File paths to inspect (1+ required).

        #[arg(required = true)]
        targets: Vec<String>,

        /// Only emit files modified at or after this Unix timestamp (seconds).
        /// Omitted means a full enumeration. Lets an incremental caller (e.g.
        /// hopper) skip unchanged files by their mtime before cleave reads
        /// their magic bytes — the expensive step on a cold file cache.
        #[arg(long, value_name = "UNIX_SECS")]
        newer_than: Option<i64>,
    },

    /// Show version, traits revision, and loaded resource counts
    Version,

    /// Validate all trait definitions for correctness and quality issues.
    /// Runs the full suite of validation checks (~60s+) and exits with a non-zero
    /// status code if any errors are found.
    /// Can also enable validation during scans via CLEAVE_VALIDATE=1.
    Validate {
        /// Override excluded validators for this validation run.
        ///
        /// Comma-separated validator IDs or short display IDs. By default,
        /// cleave uses the built-in temporary disabled set. Pass an empty
        /// string (`--exclude ""`) to enable every validator.
        #[arg(long, value_name = "IDS")]
        exclude: Option<String>,

        /// Fail only on flaws that break detection, not authoring hygiene.
        ///
        /// Soft mode keeps the load-correctness errors (unparseable YAML, regex
        /// that won't compile, invalid/unknown file types, duplicate trait ids)
        /// and the testdata fixture scoring, but downgrades taxonomy, size,
        /// dedup/reuse, regex-style, and precision issues to non-fatal. Intended
        /// for trait-bundle gates that must accept hygiene debt yet reject a
        /// bundle that won't load or silently loses detections.
        #[arg(long)]
        soft: bool,
    },

    /// Compare two versions for supply-chain attack detection.
    ///
    /// Computes a differential analysis across six scopes — traits, metrics,
    /// kv, symbols, strings, sections — between an old and new file or
    /// directory. Both inputs are run through the cached analyze pipeline,
    /// so a re-run after a fresh analyze is essentially free.
    Diff {
        /// Old/baseline version (file or directory)
        old: String,

        /// New/target version (file or directory)
        new: String,

        /// Comma-separated list of scopes to include
        /// (`traits`, `metrics`, `kv`, `symbols`, `strings`, `sections`, or `all`).
        #[arg(long, default_value = "all")]
        scope: String,

        /// Maximum number of items per `added`/`removed`/`changed` list.
        /// `0` disables the cap. Counts and rates of change are unaffected.
        #[arg(long, default_value_t = 100)]
        limit_changes: usize,
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

    /// Extract imported foreign symbols
    Imports {
        /// Target file (binary or source)
        #[arg(required = true)]
        target: String,

        /// Filter to a specific layer (e.g., "upx@0" for UPX-unpacked content)
        #[arg(short = 'L', long)]
        layer: Option<String>,
    },

    /// Extract exported symbols
    Exports {
        /// Target file (binary or source)
        #[arg(required = true)]
        target: String,

        /// Filter to a specific layer (e.g., "upx@0" for UPX-unpacked content)
        #[arg(short = 'L', long)]
        layer: Option<String>,
    },

    /// Extract functions / methods defined in the file
    Functions {
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

    /// Dump raw file facts for one or more files.
    ///
    /// `cleave facts <file> [<file>...]` dumps every top-level view
    /// (`fileid`, `values`, `strings`, `metrics`, `ast`, `sections`,
    /// `imports`, `exports`, `functions`, `errors`). A single file
    /// produces a pretty JSON object; multiple files produce JSONL
    /// keyed by `path`.
    ///
    /// Pick a subcommand to filter to a single view:
    /// `cleave facts imports <file> [<file>...]`.
    #[command(name = "facts", alias = "inspect")]
    Facts {
        /// Optional tree filter
        #[command(subcommand)]
        tree: Option<InspectTree>,

        /// One or more target files (when no tree subcommand is given)
        targets: Vec<String>,
    },

    /// Dump or query the structural values tree.
    #[command(name = "value")]
    Value {
        /// Target file (package.json, Cargo.toml, manifest.json, *.plist, *.lnk, *.service,
        /// *.doc/.docx/.xls/.xlsx/.ppt/.pptx, etc.)
        #[arg(required = true)]
        target: String,

        /// Optional value path filter (e.g., "scripts.postinstall", "content_scripts\[*\].matches",
        /// or "core.creator" / "ole.compobj.app_version" for office documents)
        path: Option<String>,

        /// Compatibility spelling for `cleave value <file> --path <path>`.
        #[arg(short, long = "path", hide = true)]
        path_flag: Option<String>,
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

        /// Type of search to perform (text, string-literal, string-value \[deprecated\], symbol, raw, value, hex, encoded, section, metrics)
        #[arg(short, long, value_enum, default_value = "text")]
        r#type: SearchType,

        /// Match method: exact, contains, regex, or word
        #[arg(short, long, value_enum, default_value = "contains")]
        method: MatchMethod,

        /// Pattern to search for (for value: the value to match, or omit for existence check, for metrics: the field path)
        #[arg(short, long)]
        pattern: Option<String>,

        /// Path expression for value searches (e.g., "scripts.postinstall", "permissions\[*\]")
        #[arg(long = "path")]
        kv_path: Option<String>,

        /// Require field to exist (true) or not exist (false) for value searches
        #[arg(long)]
        exists: Option<bool>,

        /// Minimum collection size for value searches (array elements or object keys)
        #[arg(long)]
        size_min: Option<usize>,

        /// Maximum collection size for value searches (array elements or object keys)
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

        /// Optional high-fidelity validator (e.g., external_ip, bitcoin_addr)
        #[arg(long, rename_all = "snake_case")]
        is: Option<crate::composite_rules::condition::StringValidator>,

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

    /// Update trait rules from the upstream repository
    #[command(name = "update-rules")]
    UpdateRules {
        /// Force update (fetch + hard reset, discarding local changes)
        #[arg(long)]
        force: bool,

        /// Check for updates without applying them
        #[arg(long)]
        check: bool,

        /// Pin traits to a specific git commit
        #[arg(long, value_name = "COMMIT")]
        pin: Option<String>,
    },

    /// Start HTTP API server for file analysis
    #[command(alias = "server")]
    Serve {
        /// Address to bind to (default: 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,

        /// Max requests per second per IP (default: 100)
        #[arg(long, default_value = "100")]
        qps: u32,

        /// Max upload size in MB (default: 100)
        #[arg(long, default_value = "100")]
        max_size_mb: u64,

        /// Max memory usage (RSS) in GB before rejecting requests (default: 25% of system RAM)
        #[arg(long, env = "CLEAVE_MAX_RSS_GB")]
        max_rss_gb: Option<u64>,

        /// DANGEROUS: Allow analyzing local file paths via /analyze-path endpoint.
        /// Comma-separated list of directories to allow access to (e.g., "/data/samples,/tmp/test").
        /// Only paths within these directories can be analyzed.
        #[arg(long)]
        dangerous_local_file_paths: Option<String>,

        /// Directory for extracting archive contents.
        /// When set, archive members are extracted here and paths are included in responses.
        /// This directory is automatically added to allowed local paths.
        #[arg(long)]
        extract_dir: Option<String>,
    },
}

/// Parse a criticality level string into a Criticality enum value
fn parse_criticality(s: &str) -> Result<crate::types::Criticality, String> {
    match s.to_lowercase().as_str() {
        "filtered" => Ok(crate::types::Criticality::Filtered),
        "component" => Ok(crate::types::Criticality::Component),
        "baseline" => Ok(crate::types::Criticality::Baseline),
        "notable" => Ok(crate::types::Criticality::Notable),
        "suspicious" => Ok(crate::types::Criticality::Suspicious),
        "hostile" => Ok(crate::types::Criticality::Hostile),
        _ => Err(format!(
            "unknown criticality '{}': expected one of filtered, component, baseline, notable, suspicious, hostile",
            s
        )),
    }
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
        .map_err(|e| format!("invalid start offset {}: {e}", parts[0]))?;
    let end = if parts[1].trim().is_empty() {
        None
    } else {
        Some(
            parts[1]
                .trim()
                .parse()
                .map_err(|e| format!("invalid end offset {}: {e}", parts[1]))?,
        )
    };
    Ok((start, end))
}

/// View filter for `cleave facts`. Each variant maps 1:1 onto an
/// accessor on `filefacts::ParsedFile` (or a `symbols()` filter for
/// the per-kind convenience variants).
#[derive(Debug, Clone, clap::Subcommand)]
pub enum InspectTree {
    /// File identification — file type + detection source
    Fileid {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Structural values tree (paths usable by `type: value` rules)
    Values {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Byte-scan extracted text runs (ascii / utf16le partitions)
    Text {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Parser-extracted string literals (the precise tier — no
    /// comment/code false positives)
    Literals {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Flat metric map (`text.char_entropy`, `pe.import_count`, …)
    Metrics {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Binary sections — name, extents, entropy, flag vocabulary
    Sections {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Unified named-entity facts: imports, exports, functions, calls,
    /// members, binds, identifiers, tagged by `kind`.
    Symbols {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Imported foreign symbols (convenience alias for `symbols`
    /// filtered to `kind: import`).
    Imports {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Locally-defined exported symbols (convenience for `kind: export`).
    Exports {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Function definitions (convenience for `kind: function`).
    Functions {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Per-call-site records (convenience for `kind: call`).
    Calls {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Dotted member-access chains (convenience for `kind: member`).
    Members {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Static name = value bindings (convenience for `kind: bind`).
    Binds {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///Bare identifiers (convenience for `kind: identifier`).
    Identifiers {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    ///External references (PURL/URL) the file points at, with relation
    /// and fetch-target flag.
    References {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Recoverable parser diagnostics
    Errors {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
}

impl InspectTree {
    /// File targets carried by this subtree subcommand.
    #[must_use]
    pub fn targets(&self) -> &[String] {
        match self {
            Self::Fileid { targets }
            | Self::Values { targets }
            | Self::Text { targets }
            | Self::Literals { targets }
            | Self::Metrics { targets }
            | Self::Sections { targets }
            | Self::Symbols { targets }
            | Self::Imports { targets }
            | Self::Exports { targets }
            | Self::Functions { targets }
            | Self::Calls { targets }
            | Self::Members { targets }
            | Self::Binds { targets }
            | Self::Identifiers { targets }
            | Self::References { targets }
            | Self::Errors { targets } => targets,
        }
    }

    /// Stable kebab-style identifier used as a JSON key when emitting
    /// per-file subtree dumps.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Fileid { .. } => "fileid",
            Self::Values { .. } => "values",
            Self::Text { .. } => "text",
            Self::Literals { .. } => "literals",
            Self::Metrics { .. } => "metrics",
            Self::Sections { .. } => "sections",
            Self::Symbols { .. } => "symbols",
            Self::Imports { .. } => "imports",
            Self::Exports { .. } => "exports",
            Self::Functions { .. } => "functions",
            Self::Calls { .. } => "calls",
            Self::Members { .. } => "members",
            Self::Binds { .. } => "binds",
            Self::Identifiers { .. } => "identifiers",
            Self::References { .. } => "references",
            Self::Errors { .. } => "errors",
        }
    }
}

/// Type of content to search in
#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
pub enum SearchType {
    /// Search using deprecated string_value semantics
    StringValue,
    /// Search human-readable text (strings for binaries, raw text for source/text files)
    Text,
    /// Search AST-backed string literals only
    StringLiteral,
    /// Search in symbols (imports/exports)
    Symbol,
    /// Search in raw file content
    Raw,
    /// Search structural values by path
    #[value(name = "value")]
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
pub enum MatchMethod {
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
pub enum DetectFileType {
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
    /// IBM z/OS Job Control Language batch script
    Jcl,
    /// Makefile / GNU Make build file
    Makefile,
    /// systemd service unit file
    #[value(
        name = "systemd",
        alias("systemd-service"),
        alias("systemd_service"),
        alias("service"),
        alias(".service")
    )]
    SystemdService,
    /// freedesktop.org Desktop Entry (.desktop)
    #[value(
        name = "desktop",
        alias("desktop-entry"),
        alias("desktop_entry"),
        alias(".desktop"),
        alias("xdg-desktop")
    )]
    DesktopEntry,
    /// Generic XML document (MSBuild csproj, XAML, SVG, XML config)
    #[value(
        name = "xml",
        alias("csproj"),
        alias("xaml"),
        alias("svg"),
        alias("msbuild")
    )]
    Xml,
    /// Raw/binary content
    Raw,
}

/// Output format for the diff command
#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
pub enum OutputFormat {
    /// JSON output (single object), matching server mode response shape
    Json,
    /// JSONL output (newline-delimited JSON) for streaming
    Jsonl,
    /// Human-readable terminal output
    Terminal,
    /// Compact one-line-per-finding text output for small LLMs
    Tiny,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::ValueEnum;

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
    fn test_detect_file_type_prefers_systemd_name() {
        assert_eq!(
            DetectFileType::from_str("systemd", false).unwrap(),
            DetectFileType::SystemdService
        );
        assert_eq!(
            DetectFileType::from_str("systemd-service", false).unwrap(),
            DetectFileType::SystemdService
        );
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
        if let Some(Command::Diff {
            old,
            new,
            scope,
            limit_changes,
        }) = args.command
        {
            assert_eq!(old, "old.bin");
            assert_eq!(new, "new.bin");
            assert_eq!(scope, "all");
            assert_eq!(limit_changes, 100);
        }
    }

    #[test]
    fn test_parse_diff_command_with_scope() {
        let args = Args::try_parse_from([
            "cleave",
            "diff",
            "--scope=traits,value",
            "--limit-changes=0",
            "a",
            "b",
        ])
        .unwrap();
        if let Some(Command::Diff {
            scope,
            limit_changes,
            ..
        }) = args.command
        {
            assert_eq!(scope, "traits,value");
            assert_eq!(limit_changes, 0);
        } else {
            panic!("expected diff command");
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
    fn test_parse_format_json() {
        let args = Args::try_parse_from(["cleave", "--format", "json", "file.bin"]).unwrap();
        assert!(matches!(args.format(), OutputFormat::Json));
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
        let platforms = parse_platforms("linux,unknown,macos");
        // unknown should be ignored, only linux and macos
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

    // ==================== Criticality filter flag tests ====================

    #[test]
    fn test_parse_min_crit() {
        let args = Args::try_parse_from(["cleave", "--min-crit", "notable", "file.bin"]).unwrap();
        assert_eq!(args.min_crit, Some(crate::types::Criticality::Notable));
    }

    #[test]
    fn test_parse_max_crit() {
        let args =
            Args::try_parse_from(["cleave", "--max-crit", "suspicious", "file.bin"]).unwrap();
        assert_eq!(args.max_crit, Some(crate::types::Criticality::Suspicious));
    }

    #[test]
    fn test_parse_min_and_max_crit() {
        let args = Args::try_parse_from([
            "cleave",
            "--min-crit",
            "notable",
            "--max-crit",
            "suspicious",
            "file.bin",
        ])
        .unwrap();
        assert_eq!(args.min_crit, Some(crate::types::Criticality::Notable));
        assert_eq!(args.max_crit, Some(crate::types::Criticality::Suspicious));
    }

    #[test]
    fn test_parse_crit_case_insensitive() {
        let args = Args::try_parse_from(["cleave", "--min-crit", "HOSTILE", "file.bin"]).unwrap();
        assert_eq!(args.min_crit, Some(crate::types::Criticality::Hostile));
    }

    #[test]
    fn test_parse_crit_all_levels() {
        for (name, expected) in [
            ("filtered", crate::types::Criticality::Filtered),
            ("component", crate::types::Criticality::Component),
            ("baseline", crate::types::Criticality::Baseline),
            ("notable", crate::types::Criticality::Notable),
            ("suspicious", crate::types::Criticality::Suspicious),
            ("hostile", crate::types::Criticality::Hostile),
        ] {
            let args = Args::try_parse_from(["cleave", "--min-crit", name, "file.bin"]).unwrap();
            assert_eq!(args.min_crit, Some(expected), "Failed for {}", name);
        }
    }

    #[test]
    fn test_parse_crit_invalid() {
        let result = Args::try_parse_from(["cleave", "--min-crit", "unknown", "file.bin"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_no_crit_flags() {
        let args = Args::try_parse_from(["cleave", "file.bin"]).unwrap();
        assert!(args.min_crit.is_none());
        assert!(args.max_crit.is_none());
    }

    #[test]
    fn test_parse_repeated_zip_passwords() {
        let args = Args::try_parse_from([
            "cleave",
            "--zip-password",
            "first",
            "--zip-password",
            "second",
            "file.bin",
        ])
        .unwrap();

        assert_eq!(args.zip_passwords, ["first", "second"]);
    }

    #[test]
    fn extra_zip_passwords_are_appended_without_duplicates() {
        let args = Args::try_parse_from([
            "cleave",
            "--zip-password",
            "infected",
            "--zip-password",
            "sample-key",
            "--zip-password",
            "sample-key",
            "file.bin",
        ])
        .unwrap();
        let passwords = args.archive_passwords();

        assert_eq!(passwords.last().map(String::as_str), Some("sample-key"));
        assert_eq!(passwords.iter().filter(|p| *p == "sample-key").count(), 1);
        assert_eq!(passwords.iter().filter(|p| *p == "infected").count(), 1);
    }
}
