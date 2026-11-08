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
//! - `--disable upx` - Skip UPX unpacking attempts
//! - `--disable third-party` - Skip third-party YARA rules

use clap::{Parser, Subcommand};

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
#[derive(Debug, Clone, Default)]
pub struct DisabledComponents {
    /// Whether YARA scanning is disabled
    pub yara: bool,
    /// Whether UPX unpacking is disabled
    pub upx: bool,
    /// Whether third-party YARA rules are disabled
    pub third_party: bool,
}

/// A component `--disable` can turn off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Component {
    /// YARA pattern matching
    Yara,
    /// UPX unpacking
    Upx,
    /// Third-party YARA rules
    ThirdParty,
}

impl DisabledComponents {
    /// The components named in `components` disabled, the rest enabled.
    #[must_use]
    pub fn from_components(components: &[Component]) -> Self {
        Self {
            yara: components.contains(&Component::Yara),
            upx: components.contains(&Component::Upx),
            third_party: components.contains(&Component::ThirdParty),
        }
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

    /// Output format: annotate (default), index, or json. The last of --format,
    /// --annotate, --index, and --json wins.
    #[arg(long, value_enum, global = true, overrides_with_all = ["annotate", "index", "json"])]
    pub format: Option<OutputFormat>,

    /// Shorthand for --format annotate.
    #[arg(long, global = true, overrides_with_all = ["format", "index", "json"])]
    pub annotate: bool,

    /// Shorthand for --format index.
    #[arg(long, global = true, overrides_with_all = ["format", "annotate", "json"])]
    pub index: bool,

    /// Shorthand for --format json.
    #[arg(long, global = true, overrides_with_all = ["format", "annotate", "index"])]
    pub json: bool,

    /// Write output to file
    #[arg(short, long, global = true)]
    pub output: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Disable specific components (comma-separated)
    #[arg(long, value_name = "COMPONENTS", value_enum, value_delimiter = ',')]
    pub disable: Vec<Component>,

    /// Include all files in directory scans, even unknown types
    /// By default, only recognized code/binary files are analyzed
    #[arg(long)]
    pub all_files: bool,

    /// Additional passwords to try for encrypted ZIP/7z archives.
    /// Repeat the option to provide more than one password; built-in common
    /// sample passwords are always tried as well.
    #[arg(long = "zip-password", value_name = "PASSWORD", global = true)]
    pub zip_passwords: Vec<String>,

    /// Traits directory to load rules from (overrides CLEAVE_TRAITS_DIR and the installed rules)
    #[arg(long, value_name = "DIR")]
    pub traits_dir: Option<String>,

    /// Insist on Atomdrift Uplink: zero-hour rules, the moment they clear QA.
    /// A computer that holds a token (ISOTOPE13_TOKEN, or the one saved when
    /// it was connected) uses them without this flag. With it, a computer that
    /// holds none is connected — a terminal shows a code to approve at
    /// dash.isotope13.io — and a refused token stops the run instead of
    /// falling back to the open-source rules. Env: ATOMDRIFT_UPLINK=1; =0
    /// keeps the open-source rules. Hidden from `--help` until Uplink is
    /// generally available.
    #[arg(long, hide = true)]
    pub uplink: bool,

    /// Warn when a single rule takes longer than this many milliseconds to evaluate.
    /// During validation this is a soft rule-performance failure (CPU time where available).
    /// Extreme AST cost outliers and exhausted query budgets are also soft failures.
    /// Rules >500ms are always logged at info level (visible via RUST_LOG=cleave=info).
    #[arg(long, value_name = "MS", default_value_t = 4000)]
    pub slow_rule_ms: u64,

    /// Minimum criticality level to include in output
    /// (filtered, component, baseline, notable, suspicious, hostile)
    #[arg(long, value_name = "LEVEL", value_parser = parse_criticality)]
    pub min_crit: Option<crate::types::Criticality>,

    /// Minimum file criticality (based on highest trait) to include in output.
    /// Files whose highest-criticality trait is below this level are excluded entirely.
    #[arg(long, value_name = "LEVEL", value_parser = parse_criticality)]
    pub min_file_crit: Option<crate::types::Criticality>,
}

impl Args {
    /// The components `--disable` turned off.
    #[must_use]
    pub fn disabled_components(&self) -> DisabledComponents {
        DisabledComponents::from_components(&self.disable)
    }

    /// The output format from --format or its shorthands, else the
    /// CLEAVE_FORMAT env var, else annotate. Clap keeps only the last of
    /// --format, --annotate, --index, and --json.
    #[must_use]
    pub fn format(&self) -> OutputFormat {
        if let Some(format) = self.format {
            return format;
        }
        if self.json {
            return OutputFormat::Json;
        }
        if self.index {
            return OutputFormat::Index;
        }
        if self.annotate {
            return OutputFormat::Annotate;
        }
        if let Ok(val) = std::env::var("CLEAVE_FORMAT") {
            match <OutputFormat as clap::ValueEnum>::from_str(&val, true) {
                Ok(format) => return format,
                Err(_) => eprintln!("warning: unknown CLEAVE_FORMAT '{val}', using annotate"),
            }
        }
        OutputFormat::Annotate
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
    /// Experimental: render a saved report without analyzing files or loading rules.
    Render {
        /// Saved report input.
        #[command(flatten)]
        args: crate::report_input::RenderArgs,
    },
    /// Analyze files or directories
    Analyze {
        /// Target files or directories to analyze
        /// File paths to inspect (1+ required).

        #[arg(required = true)]
        targets: Vec<String>,
    },

    /// Probe regex patterns for lazy-DFA explosion (reads stdin, one per line).
    ///
    /// Prints `ok` or `explode:<reason>` per line, using the same haystack and
    /// give-up thresholds as the `regex-explosion` validator. Exists so a
    /// pattern can be checked without a full `validate` run over the tree.
    #[command(name = "regex-cost")]
    RegexCost {
        /// Treat patterns as case-insensitive (as `type: text` with (?i) does).
        #[arg(long)]
        case_insensitive: bool,
    },

    /// Enumerate recognized files as JSONL (for ingest pipelines).
    ///
    /// Walks the given targets and emits one JSON line per recognized file:
    /// `{"path":"...","type":"elf","sz":12345}`. No hashing, no analysis —
    /// the caller (e.g. a report store) does its own hashing via its own cache.
    /// Files whose magic bytes do not match a recognized program type are
    /// silently skipped. Honors the directory-scan size ceiling.
    #[command(name = "iter-files")]
    IterFiles {
        /// Target files or directories to enumerate
        /// File paths to inspect (1+ required).

        #[arg(required = true)]
        targets: Vec<String>,

        /// Only emit files modified at or after this Unix timestamp (seconds).
        /// Omitted means a full enumeration. Lets an incremental caller (e.g.
        /// a report store) skip unchanged files by their mtime before cleave reads
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

        /// Audit the slowest rules: analyze every fixture without any cache
        /// and list the N rules with the highest total evaluation time.
        ///
        /// Each row gives the rule's total and slowest single evaluation,
        /// how many times it ran, its share of all rule time, its `for:` list
        /// and the shape of its conditions (`text/regex`, `tree-sitter/query`,
        /// ...), so a cheaper equivalent can be chosen. N defaults to 25.
        #[arg(long, value_name = "N", num_args = 0..=1, default_missing_value = "25")]
        slow_rules: Option<usize>,
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
    /// `cleave facts <file> [<file>...]` dumps every view filefacts
    /// extracts (`fileid`, `values`, `text`, `literals`, `comments`,
    /// `metrics`, `sections`, `symbols`, `flow`, `identity`,
    /// `references`, `archive_members`, `errors`). A single file
    /// produces a pretty JSON object; multiple files produce JSONL
    /// keyed by `path`.
    ///
    /// Pick a subcommand to filter to a single view:
    /// `cleave facts imports <file> [<file>...]`.
    #[command(name = "facts")]
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
        /// Use comma for OR, plus for chain sequence.
        /// For 'text' searches, "none" restricts the scan to the undecoded
        /// layer (the trait option `encoding: none`) and "any" is the default.
        #[arg(long)]
        encoding: Option<String>,

        /// Optional high-fidelity validator (e.g., external_ip, bitcoin_addr,
        /// typo_of:top-npm-packages)
        #[arg(long)]
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
    },
}

fn parse_criticality(s: &str) -> Result<crate::types::Criticality, String> {
    s.parse()
}

/// Parse an offset range like "0,4096" or "-1024," into `(start, Option<end>)`.
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
    /// Source comments (what `literals` deliberately leaves out)
    Comments {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Value-flow graph behind `arg.from` provenance: calls with their
    /// argument and receiver inputs, member reads, literals, helper
    /// functions, and the producer's limitations
    Flow {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Normalized identity claims (name, version, publisher, signature)
    Identity {
        /// File paths to inspect (1+ required).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Archive member listing (name, size, kind)
    ArchiveMembers {
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
            | Self::Errors { targets }
            | Self::Comments { targets }
            | Self::Flow { targets }
            | Self::Identity { targets }
            | Self::ArchiveMembers { targets } => targets,
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
            Self::Comments { .. } => "comments",
            Self::Flow { .. } => "flow",
            Self::Identity { .. } => "identity",
            Self::ArchiveMembers { .. } => "archive_members",
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

/// Output format for analysis and extraction commands.
#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
pub enum OutputFormat {
    /// Source context around each finding, annotated with what matched
    #[value(alias("terminal"))]
    Annotate,
    /// Index of findings: one row per finding, grouped by namespace
    Index,
    /// One JSON object per line, one line per file target
    #[value(alias("jsonl"))]
    Json,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
