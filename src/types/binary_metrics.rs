//! Binary format-specific metrics (ELF, PE, Mach-O, Java class files)
//!
//! # Metric Semantics
//!
//! ## Code vs Data Classification
//!
//! Different binary formats classify sections differently:
//!
//! - **Mach-O**: Only sections named `__text`, `__stubs`, and `__stub_helper` are considered code.
//!   Other sections in the `__TEXT` segment (like `__const`, `__cstring`) are read-only data.
//!
//! - **ELF**: Sections with the `SHF_EXECINSTR` flag (0x4) are considered code.
//!   Typically `.text`, `.plt`, and `.init`/`.fini` sections.
//!
//! - **PE**: Sections with the `IMAGE_SCN_MEM_EXECUTE` characteristic (0x20000000) are considered code.
//!   Typically `.text` sections, but packed/obfuscated binaries may have unusual names.
//!
//! ## Key Metrics
//!
//! - **code_size**: Total bytes of executable code sections (bytes)
//! - **code_to_data_ratio**: `code_size / (file_size - code_size)` (dimensionless)
//!   - Low ratio (< 0.1): Packed binary or data-heavy file (e.g., dropper with embedded payload)
//!   - Normal ratio (0.2-2.0): Typical executables
//!   - High ratio (> 10): Code-heavy utility or library
//!
//! - **Density metrics** (per KB of code):
//!   - `import_density = import_count / (code_size / 1024)`
//!   - `string_density = string_count / (code_size / 1024)`
//!   - `function_density = function_count / (code_size / 1024)`
//!   - High density may indicate unpacked/decompressed code or shellcode
//!
//! - **Normalized metrics** (size-independent):
//!   - `normalized_import_count = import_count / sqrt(code_size)`
//!   - Allows comparison across different file sizes
//!
//! - **Entropy** (range 0-8 bits):
//!   - 0-4: Highly compressible (text, zeros)
//!   - 5-6: Normal compiled code
//!   - 7-8: Encrypted or compressed data
//!

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32, is_zero_u64};

// =============================================================================
// BINARY-SPECIFIC METRICS
// =============================================================================

/// Metrics extracted from binary file formats (ELF, PE, Mach-O, Java class files)
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct BinaryMetrics {
    // === Entropy ===
    /// Overall file entropy (0-8 bits, higher = more random/compressed)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub overall_entropy: f32,
    /// Code section average entropy (executable sections only)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_entropy: f32,
    /// Data section average entropy (non-executable sections only)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub data_entropy: f32,
    /// Entropy variance across sections
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub entropy_variance: f32,
    /// High entropy regions (>7.5)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_regions: u32,

    // === Size ===
    /// Total file size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub file_size: u64,

    /// Total executable code size in bytes (sum of all executable sections)
    /// - Mach-O: __text + __stubs + __stub_helper
    /// - ELF: sections with SHF_EXECINSTR flag
    /// - PE: sections with IMAGE_SCN_MEM_EXECUTE characteristic
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub code_size: u64,

    /// Ratio of code to data: `code_size / (file_size - code_size)`
    /// - < 0.1: Packed/dropper (small code, large payload)
    /// - 0.2-2.0: Normal executable
    /// - > 10: Code-heavy (utilities, libraries)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_to_data_ratio: f32,

    // === Binary Properties ===
    /// The structural parser failed to read this binary cleanly — either by
    /// returning an error or by panicking on a malformed header. When set,
    /// the structure-derived fields below were populated from the rizin
    /// fallback analysis rather than the primary parser, and may be less
    /// complete than usual. The exact failure message lives in
    /// `report.metadata.errors`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_malformed_structure: bool,
    /// Has debug information
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_debug_info: bool,
    /// Is stripped (no symbols)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_stripped: bool,
    /// Position Independent Executable
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_pie: bool,
    /// Raw format-native entry point value
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub entry_point: u64,
    /// Entry point is expressed as a relative virtual address
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_point_is_rva: bool,
    /// Entry point is outside the primary expected code section
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_nonstandard_section: bool,
    /// Relocation count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub relocation_count: u32,
    /// Linked dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dependency_count: u32,
    /// Runtime library search path count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub runtime_search_path_count: u32,
    /// Debug-reference count across format-specific debug tables/sections
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_reference_count: u32,
    /// Stable build/provenance identifier present
    #[serde(default, skip_serializing_if = "is_false")]
    pub provenance_id_present: bool,
    /// Stable build/provenance identifier length in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub provenance_id_length: u32,
    /// Has embedded signature metadata
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_signature: bool,
    /// Embedded signature validates successfully, if checked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,

    // === Sections ===
    /// Total section count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_count: u32,
    /// Executable sections
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub executable_sections: u32,
    /// Writable sections
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub writable_sections: u32,
    /// W+X sections (self-modifying)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wx_sections: u32,
    /// Section name entropy (random names = packer)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub section_name_entropy: f32,
    /// Largest section ratio to file size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub largest_section_ratio: f32,
    /// Segment count (Mach-O) or program headers (ELF)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub segment_count: u32,
    /// Count of nonstandard section names for the file format
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nonstandard_section_name_count: u32,
    /// Average section size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_section_size: f32,

    // === Imports/Exports ===
    /// Import count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub import_count: u32,
    /// Export count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_count: u32,
    /// Number of exports sharing an address with another export
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub aliased_exports: u32,
    /// Import name entropy (randomness)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_entropy: f32,

    // === Strings ===
    /// String count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_count: u32,
    /// Average string entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_entropy: f32,
    /// High entropy strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_strings: u32,
    /// Strings in code sections (unusual)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub strings_in_code: u32,
    /// Wide/UTF-16 string count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wide_string_count: u32,
    /// Sentence-like string count (multi-word printable strings)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sentence_string_count: u32,
    /// Ratio of sentence-like strings to all strings
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub sentence_string_ratio: f32,
    /// Average string length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_length: f32,
    /// Maximum string length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_string_length: u32,
    /// Standard deviation of string lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_length_stddev: f32,

    // === Functions ===
    /// Function count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub function_count: u32,
    /// Average function size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_function_size: f32,
    /// Tiny functions (<16 bytes)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tiny_functions: u32,
    /// Huge functions (>64KB)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub huge_functions: u32,
    /// Indirect call instructions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_calls: u32,
    /// Indirect jump instructions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_jumps: u32,

    // === Complexity (from radare2 analysis) ===
    /// Average cyclomatic complexity
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_complexity: f32,
    /// Maximum cyclomatic complexity
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_complexity: u32,
    /// Functions with high complexity (>50)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_complexity_functions: u32,
    /// Names of high complexity functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub high_complexity_function_names: Vec<String>,
    /// Functions with very high complexity (>100)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_high_complexity_functions: u32,
    /// Names of very high complexity functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub very_high_complexity_function_names: Vec<String>,

    // === Control Flow ===
    /// Total basic blocks across all functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_basic_blocks: u32,
    /// Average basic blocks per function
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_basic_blocks: f32,
    /// Linear functions (no branches)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linear_functions: u32,
    /// Recursive functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_functions: u32,
    /// Non-returning functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub noreturn_functions: u32,
    /// Leaf functions (make no calls)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub leaf_functions: u32,

    // === Stack ===
    /// Average stack frame size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_stack_frame: f32,
    /// Maximum stack frame size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_stack_frame: u32,
    /// Functions with large stack (>4KB)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub large_stack_functions: u32,
    /// Names of large stack functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub large_stack_function_names: Vec<String>,

    // === Overlay ===
    /// Has overlay data
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_overlay: bool,
    /// Overlay size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub overlay_size: u64,
    /// Overlay ratio to file size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub overlay_ratio: f32,
    /// Overlay entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub overlay_entropy: f32,

    // === Density Ratios (ML-oriented) ===
    /// Import density: imports per KB of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_density: f32,
    /// String density: strings per KB of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_density: f32,
    /// Function density: functions per KB of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub function_density: f32,
    /// Export to import ratio (DLLs=high, EXEs=low)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub export_to_import_ratio: f32,
    /// Ratio of curated operational imports to all imports
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub behavioral_import_ratio: f32,
    /// Relocation density: relocations per KB
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub relocation_density: f32,

    // === Normalized Metrics (Size-independent) ===
    /// Normalized import count: imports / sqrt(file_size)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub normalized_import_count: f32,
    /// Normalized export count: exports / sqrt(file_size)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub normalized_export_count: f32,
    /// Normalized section count: sections / log2(file_size)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub normalized_section_count: f32,
    /// Normalized string count: strings / sqrt(code_size)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub normalized_string_count: f32,
    /// Code section ratio: executable_sections / total_sections
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_section_ratio: f32,
    /// Complexity per KB: avg_complexity * 1024 / code_size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub complexity_per_kb: f32,
}

impl BinaryMetrics {
    /// Validate metric ranges and log warnings for out-of-range values.
    /// `path` is included in messages to identify which file triggered the warning.
    pub(crate) fn validate(&self, path: &str) {
        // Entropy checks (valid range: 0-8 bits)
        if self.overall_entropy > 8.0 || self.overall_entropy < 0.0 {
            tracing::warn!(
                path,
                overall_entropy = self.overall_entropy,
                "overall_entropy outside valid range [0, 8]"
            );
        }
        if self.code_entropy > 8.0 || self.code_entropy < 0.0 {
            tracing::warn!(
                path,
                code_entropy = self.code_entropy,
                "code_entropy outside valid range [0, 8]"
            );
        }
        if self.data_entropy > 8.0 || self.data_entropy < 0.0 {
            tracing::warn!(
                path,
                data_entropy = self.data_entropy,
                "data_entropy outside valid range [0, 8]"
            );
        }
        if self.overlay_entropy > 8.0 || self.overlay_entropy < 0.0 {
            tracing::warn!(
                path,
                overlay_entropy = self.overlay_entropy,
                "overlay_entropy outside valid range [0, 8]"
            );
        }

        // Size checks — inflated section headers are a common anti-analysis trick,
        // so these are INFO (expected for tampered PEs), not WARN.
        if self.code_size > self.file_size {
            tracing::info!(
                path,
                code_size = self.code_size,
                file_size = self.file_size,
                "code_size > file_size (inflated section headers)"
            );
        }
        if self.overlay_size > self.file_size {
            tracing::info!(
                path,
                overlay_size = self.overlay_size,
                file_size = self.file_size,
                "overlay_size > file_size"
            );
        }

        // Ratio checks
        if self.code_to_data_ratio < 0.0 {
            tracing::warn!(
                path,
                code_to_data_ratio = self.code_to_data_ratio,
                "code_to_data_ratio is negative"
            );
        }
        if self.export_to_import_ratio < 0.0 {
            tracing::warn!(
                path,
                export_to_import_ratio = self.export_to_import_ratio,
                "export_to_import_ratio is negative"
            );
        }
        if self.code_section_ratio < 0.0 || self.code_section_ratio > 1.0 {
            tracing::warn!(
                path,
                code_section_ratio = self.code_section_ratio,
                "code_section_ratio outside valid range [0, 1]"
            );
        }
        if self.largest_section_ratio < 0.0 || self.largest_section_ratio > 1.0 {
            tracing::info!(
                path,
                largest_section_ratio = self.largest_section_ratio,
                "largest_section_ratio outside valid range [0, 1] (inflated section headers)"
            );
        }
        if self.overlay_ratio < 0.0 || self.overlay_ratio > 1.0 {
            tracing::warn!(
                path,
                overlay_ratio = self.overlay_ratio,
                "overlay_ratio outside valid range [0, 1]"
            );
        }

        // Density checks
        if self.import_density < 0.0 {
            tracing::warn!(
                path,
                import_density = self.import_density,
                "import_density is negative"
            );
        }
        if self.string_density < 0.0 {
            tracing::warn!(
                path,
                string_density = self.string_density,
                "string_density is negative"
            );
        }
        if self.function_density < 0.0 {
            tracing::warn!(
                path,
                function_density = self.function_density,
                "function_density is negative"
            );
        }

        // Section counts should be consistent
        if self.executable_sections > self.section_count {
            tracing::warn!(
                path,
                executable_sections = self.executable_sections,
                section_count = self.section_count,
                "executable_sections > section_count"
            );
        }
        if self.writable_sections > self.section_count {
            tracing::warn!(
                path,
                writable_sections = self.writable_sections,
                section_count = self.section_count,
                "writable_sections > section_count"
            );
        }
        if self.wx_sections > self.executable_sections {
            tracing::warn!(
                path,
                wx_sections = self.wx_sections,
                executable_sections = self.executable_sections,
                "wx_sections > executable_sections"
            );
        }
    }
}

/// ELF-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ElfMetrics {
    // === Header ===
    /// ELF file type (header.e_type)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub e_type: u32,
    /// ELF machine type (header.e_machine)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub e_machine: u32,
    /// ELF class in bits (32 or 64)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_bits: u32,
    /// Little endian encoding
    #[serde(default, skip_serializing_if = "is_false")]
    pub little_endian: bool,
    /// Entry point address
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub entry_point: u64,
    /// Program header count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub program_header_count: u32,
    /// Section header count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_header_count: u32,
    /// Entry point not in .text
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_not_in_text: bool,
    /// Entry point section name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_section: Option<String>,

    // === Dynamic Linking ===
    /// Number of needed libraries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub needed_libs: u32,
    /// Interpreter present (PT_INTERP)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_interpreter: bool,
    /// SONAME present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_soname: bool,
    /// RPATH set
    #[serde(default, skip_serializing_if = "is_false")]
    pub rpath_set: bool,
    /// Number of RPATH entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rpath_count: u32,
    /// RUNPATH set
    #[serde(default, skip_serializing_if = "is_false")]
    pub runpath_set: bool,
    /// Number of RUNPATH entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub runpath_count: u32,
    /// DT_INIT_ARRAY count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub init_array_count: u32,
    /// DT_FINI_ARRAY count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fini_array_count: u32,

    // === Symbols ===
    /// Hidden visibility symbols
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hidden_symbols: u32,
    /// Dynamic symbol table count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynsym_count: u32,
    /// Static symbol table count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symtab_count: u32,
    /// GNU hash present
    #[serde(default, skip_serializing_if = "is_false")]
    pub gnu_hash_present: bool,

    // === Structural Anomalies ===
    /// Maximum p_filesz across all LOAD segments
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub load_segment_max_p_filesz: u64,
    /// Maximum p_memsz across all LOAD segments
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub load_segment_max_p_memsz: u64,
    /// Dynamic RELA relocation count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynrela_count: u32,
    /// Dynamic REL relocation count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynrel_count: u32,
    /// PLT relocation count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pltreloc_count: u32,
    /// Section relocation groups count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_relocation_group_count: u32,

    // === Security Features ===
    /// RELRO status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relro: Option<String>,
    /// TEXTREL present (bad)
    #[serde(default, skip_serializing_if = "is_false")]
    pub textrel_present: bool,
    /// Stack canary
    #[serde(default, skip_serializing_if = "is_false")]
    pub stack_canary: bool,
    /// NX (non-executable stack)
    #[serde(default, skip_serializing_if = "is_false")]
    pub nx_enabled: bool,

    // === Special Sections ===
    /// Has .plt
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_plt: bool,
    /// Has .got
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_got: bool,
    /// Has .eh_frame
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_eh_frame: bool,
    /// Has .note section
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_note: bool,
    /// Total ELF note count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub note_count: u32,
    /// GNU build-id note present
    #[serde(default, skip_serializing_if = "is_false")]
    pub build_id_present: bool,
    /// GNU build-id length in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub build_id_length: u32,
    /// .gnu_debuglink section present
    #[serde(default, skip_serializing_if = "is_false")]
    pub debuglink_present: bool,
    /// Number of debug-related sections
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_section_count: u32,
}

/// PE-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PeMetrics {
    // === Raw Header Fields (ML / anomaly-friendly) ===
    /// COFF timestamp as Unix epoch seconds
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub timestamp: u32,
    /// Timestamp calendar year in UTC
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub timestamp_year: u32,
    /// Timestamp month in UTC (1-12)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub timestamp_month: u32,
    /// Timestamp day of month in UTC (1-31)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub timestamp_day: u32,
    /// PE machine type (COFF header)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub machine: u32,
    /// COFF characteristics bitfield
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub characteristics: u32,
    /// Number of sections from the COFF header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub number_of_sections: u32,
    /// Entry point RVA
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub entry_point_rva: u32,
    /// Section containing the entry point RVA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_section: Option<String>,
    /// Optional header checksum value
    #[serde(default)]
    pub checksum: u32,
    /// Whether the optional header checksum field is populated
    #[serde(default)]
    pub checksum_present: bool,
    /// Checksum field is zero / absent
    #[serde(default, skip_serializing_if = "is_false")]
    pub checksum_missing: bool,
    /// Recomputed PE checksum
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_checksum: u32,
    /// Stored checksum matches recomputed checksum
    #[serde(default, skip_serializing_if = "is_false")]
    pub checksum_matches: bool,
    /// Stored checksum does not match recomputed checksum
    #[serde(default, skip_serializing_if = "is_false")]
    pub checksum_mismatch: bool,
    /// File alignment from the optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_alignment: u32,
    /// Section alignment from the optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_alignment: u32,
    /// Windows subsystem value
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub subsystem: u32,
    /// DLL characteristics bitfield
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dll_characteristics: u32,
    /// Preferred image base
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub image_base: u64,
    /// SizeOfImage from optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub size_of_image: u32,
    /// SizeOfHeaders from optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub size_of_headers: u32,
    /// Major linker version
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linker_major_version: u32,
    /// Minor linker version
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linker_minor_version: u32,
    /// Number of distinct imported DLLs
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub import_dll_count: u32,
    /// Number of debug directory entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_directory_entries: u32,
    /// PDB path from CodeView debug info, if present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb_path: Option<String>,
    /// Number of attribute certificates
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub certificate_count: u32,
    /// Certificate table size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub certificate_table_size: u64,
    /// Export directory timestamp as Unix epoch seconds
    #[serde(default)]
    pub export_timestamp: u32,
    /// Export timestamp field is populated
    #[serde(default)]
    pub export_timestamp_present: bool,
    /// Export timestamp calendar year in UTC
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_timestamp_year: u32,
    /// Export timestamp month in UTC (1-12)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_timestamp_month: u32,
    /// Export timestamp day of month in UTC (1-31)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_timestamp_day: u32,
    /// Resource directory timestamp as Unix epoch seconds
    #[serde(default)]
    pub resource_timestamp: u32,
    /// Resource timestamp field is populated
    #[serde(default)]
    pub resource_timestamp_present: bool,
    /// Resource timestamp calendar year in UTC
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub resource_timestamp_year: u32,
    /// Resource timestamp month in UTC (1-12)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub resource_timestamp_month: u32,
    /// Resource timestamp day of month in UTC (1-31)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub resource_timestamp_day: u32,
    /// Number of non-zero debug directory timestamps
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_timestamp_nonzero_count: u32,
    /// Number of unique non-zero debug timestamps
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_timestamp_unique_count: u32,
    /// Minimum non-zero debug timestamp
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_timestamp_min: u32,
    /// Maximum non-zero debug timestamp
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_timestamp_max: u32,
    /// All non-zero debug timestamps are identical
    #[serde(default, skip_serializing_if = "is_false")]
    pub debug_timestamp_consistent: bool,
    /// Authenticode signing time as Unix epoch seconds, if present
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub signing_time: u64,
    /// Signing time calendar year in UTC
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub signing_time_year: u32,
    /// Signing time month in UTC (1-12)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub signing_time_month: u32,
    /// Signing time day of month in UTC (1-31)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub signing_time_day: u32,

    // === Header Anomalies ===
    /// Timestamp anomaly (future or ancient)
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_anomaly: bool,
    /// Timestamp field is zero
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_is_zero: bool,
    /// Timestamp is before year 2000
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_pre_2000: bool,
    /// Timestamp is more than one year in the future
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_in_future: bool,
    /// Checksum valid
    #[serde(default, skip_serializing_if = "is_false")]
    pub checksum_valid: bool,
    /// Rich header present
    #[serde(default, skip_serializing_if = "is_false")]
    pub rich_header_present: bool,
    /// DOS stub modified
    #[serde(default, skip_serializing_if = "is_false")]
    pub dos_stub_modified: bool,
    /// Signing time occurs before the PE COFF timestamp
    #[serde(default, skip_serializing_if = "is_false")]
    pub signing_time_before_timestamp: bool,

    // === Sections ===
    /// Resource section size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub rsrc_size: u64,
    /// Resource section entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub rsrc_entropy: f32,
    /// Unusual section alignment
    #[serde(default, skip_serializing_if = "is_false")]
    pub unusual_alignment: bool,
    /// Entry point not in a standard code section name
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_nonstandard_section: bool,

    // === Imports ===
    /// Delay-load imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub delay_load_imports: u32,
    /// Ordinal-only imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ordinal_imports: u32,
    /// API hashing indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub api_hashing_indicators: u32,
    /// Suspicious import combo (VirtualAlloc+Write+Protect)
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspicious_import_combo: bool,

    // === Exports ===
    /// Export forwarders
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_forwarders: u32,

    // === Resources ===
    /// Resource count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub resource_count: u32,
    /// Embedded PE files
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_pe_count: u32,
    /// Version info present
    #[serde(default, skip_serializing_if = "is_false")]
    pub version_info_present: bool,
    /// Manifest present
    #[serde(default, skip_serializing_if = "is_false")]
    pub manifest_present: bool,
    /// Icon count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub icon_count: u32,

    // === .NET ===
    /// Is .NET assembly
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_dotnet: bool,
    /// CLR version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clr_version: Option<String>,
    /// Mixed mode (native + .NET)
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_mode: bool,

    // === TLS ===
    /// TLS callback count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tls_callbacks: u32,

    // === Authenticode ===
    /// Has digital signature
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_signature: bool,
    /// Signature valid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
    /// Signature type (platform, developer, adhoc)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<String>,
    /// Common name of the signer certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// Mach-O specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct MachoMetrics {
    // === Structure ===
    /// Mach-O file type (header.filetype)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_type: u32,
    /// CPU type (header.cputype)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cpu_type: u32,
    /// CPU subtype (header.cpusubtype)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cpu_subtype: u32,
    /// Header flags bitfield
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub flags: u32,
    /// Mach-O class in bits (32 or 64)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_bits: u32,
    /// Little endian encoding
    #[serde(default, skip_serializing_if = "is_false")]
    pub little_endian: bool,
    /// Universal (fat) binary
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_universal: bool,
    /// Slice count (for universal)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub slice_count: u32,
    /// Virtual entry point address
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub entry_point: u64,
    /// Entry point came from legacy LC_UNIXTHREAD
    #[serde(default, skip_serializing_if = "is_false")]
    pub old_style_entry: bool,

    // === Load Commands ===
    /// Load command count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub load_command_count: u32,
    /// Header sizeofcmds value
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub load_commands_size: u32,
    /// Has code signature
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_code_signature: bool,
    /// Signature valid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
    /// UUID load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub uuid_present: bool,
    /// Build-version load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub build_version_present: bool,
    /// Source-version load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub source_version_present: bool,
    /// Main entrypoint command present (LC_MAIN)
    #[serde(default, skip_serializing_if = "is_false")]
    pub main_command_present: bool,
    /// Legacy LC_UNIXTHREAD entrypoint present
    #[serde(default, skip_serializing_if = "is_false")]
    pub unixthread_command_present: bool,
    /// Code signature blob size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_signature_size: u32,

    // === Segments ===
    /// __LINKEDIT size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub linkedit_size: u64,
    /// __TEXT segment entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub text_entropy: f32,

    // === Symbols ===
    /// Symbol count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symbol_count: u32,
    /// Indirect symbol count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_symbol_count: u32,

    // === Code Signing ===
    /// Signature type (adhoc, developer-id, platform, app-store)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<String>,
    /// Team identifier from certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_identifier: Option<String>,

    // === Entitlements ===
    /// Has entitlements
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_entitlements: bool,
    /// Dangerous entitlement count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dangerous_entitlements: u32,

    // === dyld ===
    /// dylib dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dylib_count: u32,
    /// Re-exported dylib count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reexport_dylib_count: u32,
    /// Weak dylib count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub weak_dylib_count: u32,
    /// Upward dylib count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub upward_dylib_count: u32,
    /// Lazy-loaded dylib count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lazy_dylib_count: u32,
    /// @rpath count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rpath_count: u32,
    /// Install name present (LC_ID_DYLIB)
    #[serde(default, skip_serializing_if = "is_false")]
    pub install_name_present: bool,
    /// Dynamic linker load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub dylinker_present: bool,

    // === Build Metadata ===
    /// Build platform from LC_BUILD_VERSION
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub build_platform: u32,
    /// Minimum OS major version
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_os_major: u32,
    /// Minimum OS minor version
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_os_minor: u32,
    /// Minimum OS patch version
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_os_patch: u32,
    /// SDK major version
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sdk_major: u32,
    /// SDK minor version
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sdk_minor: u32,
    /// SDK patch version
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sdk_patch: u32,
    /// Build tool version entry count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub build_tool_count: u32,
    /// Encoded source version value
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub source_version: u64,

    // === Hardened Runtime ===
    /// Hardened runtime enabled
    #[serde(default, skip_serializing_if = "is_false")]
    pub hardened_runtime: bool,
    /// Allow unsigned executable memory
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_jit: bool,
}

/// Java class file metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct JavaClassMetrics {
    // === Version ===
    /// Major version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub major_version: u32,
    /// Minor version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub minor_version: u32,
    /// Java version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_version: Option<String>,

    // === Constant Pool ===
    /// Constant pool size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub constant_pool_size: u32,
    /// UTF8 constants
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub utf8_constants: u32,
    /// Class references
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_refs: u32,
    /// Method references
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_refs: u32,
    /// String constant entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_constant_entropy: f32,
    /// Obfuscated string count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub obfuscated_strings: u32,

    // === Methods ===
    /// Method count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_count: u32,
    /// Native methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub native_methods: u32,
    /// Synthetic (compiler-generated) methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub synthetic_methods: u32,
    /// Average method size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_method_size: f32,
    /// Maximum method size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_method_size: u32,

    // === Bytecode ===
    /// invokedynamic count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invokedynamic_count: u32,
    /// Reflection patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflection_patterns: u32,

    // === Debug Info ===
    /// Has source file attribute
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_source_file: bool,
    /// Has line numbers
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_line_numbers: bool,
    /// Has local variable info
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_local_vars: bool,
    /// Inner class count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub inner_class_count: u32,
}

// =============================================================================
// CONTAINER/ARCHIVE METRICS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== BinaryMetrics Default Tests ====================

    #[test]
    fn test_binary_metrics_default() {
        let metrics = BinaryMetrics::default();
        assert_eq!(metrics.overall_entropy, 0.0);
        assert_eq!(metrics.section_count, 0);
        assert_eq!(metrics.import_count, 0);
        assert_eq!(metrics.function_count, 0);
        assert!(!metrics.has_overlay);
    }

    #[test]
    fn test_binary_metrics_creation() {
        let metrics = BinaryMetrics {
            overall_entropy: 7.5,
            code_entropy: 6.8,
            section_count: 5,
            executable_sections: 2,
            import_count: 150,
            function_count: 50,
            ..Default::default()
        };
        assert!((metrics.overall_entropy - 7.5).abs() < f32::EPSILON);
        assert_eq!(metrics.section_count, 5);
        assert_eq!(metrics.import_count, 150);
    }

    #[test]
    fn test_binary_metrics_high_entropy_regions() {
        let metrics = BinaryMetrics {
            high_entropy_regions: 3,
            entropy_variance: 1.5,
            ..Default::default()
        };
        assert_eq!(metrics.high_entropy_regions, 3);
    }

    #[test]
    fn test_binary_metrics_wx_sections() {
        let metrics = BinaryMetrics {
            wx_sections: 1,
            writable_sections: 2,
            executable_sections: 3,
            ..Default::default()
        };
        assert_eq!(metrics.wx_sections, 1);
    }

    #[test]
    fn test_binary_metrics_complexity() {
        let metrics = BinaryMetrics {
            avg_complexity: 15.5,
            max_complexity: 100,
            high_complexity_functions: 5,
            high_complexity_function_names: vec!["process_data".to_string()],
            ..Default::default()
        };
        assert_eq!(metrics.max_complexity, 100);
        assert_eq!(metrics.high_complexity_function_names.len(), 1);
    }

    #[test]
    fn test_binary_metrics_overlay() {
        let metrics = BinaryMetrics {
            has_overlay: true,
            overlay_size: 65536,
            overlay_ratio: 0.25,
            overlay_entropy: 7.9,
            ..Default::default()
        };
        assert!(metrics.has_overlay);
        assert_eq!(metrics.overlay_size, 65536);
    }

    // ==================== ElfMetrics Default Tests ====================

    #[test]
    fn test_elf_metrics_default() {
        let metrics = ElfMetrics::default();
        assert_eq!(metrics.e_type, 0);
        assert!(!metrics.entry_not_in_text);
        assert!(metrics.entry_section.is_none());
    }

    #[test]
    fn test_elf_metrics_creation() {
        let metrics = ElfMetrics {
            e_type: 2, // ET_EXEC
            needed_libs: 15,
            nx_enabled: true,
            ..Default::default()
        };
        assert_eq!(metrics.e_type, 2);
        assert!(metrics.nx_enabled);
    }

    #[test]
    fn test_elf_metrics_security_features() {
        let metrics = ElfMetrics {
            relro: Some("full".to_string()),
            stack_canary: true,
            nx_enabled: true,
            ..Default::default()
        };
        assert_eq!(metrics.relro, Some("full".to_string()));
        assert!(metrics.stack_canary);
    }

    #[test]
    fn test_elf_metrics_dynamic_linking() {
        let metrics = ElfMetrics {
            rpath_set: true,
            runpath_set: false,
            init_array_count: 3,
            fini_array_count: 1,
            ..Default::default()
        };
        assert!(metrics.rpath_set);
        assert_eq!(metrics.init_array_count, 3);
    }

    #[test]
    fn test_elf_metrics_special_sections() {
        let metrics = ElfMetrics {
            has_plt: true,
            has_got: true,
            has_eh_frame: true,
            gnu_hash_present: true,
            ..Default::default()
        };
        assert!(metrics.has_plt);
        assert!(metrics.has_got);
    }

    // ==================== PeMetrics Default Tests ====================

    #[test]
    fn test_pe_metrics_default() {
        let metrics = PeMetrics::default();
        assert!(!metrics.timestamp_anomaly);
        assert!(!metrics.is_dotnet);
        assert!(metrics.clr_version.is_none());
    }

    #[test]
    fn test_pe_metrics_creation() {
        let metrics = PeMetrics {
            timestamp_anomaly: true,
            checksum_valid: false,
            rich_header_present: true,
            resource_count: 10,
            ..Default::default()
        };
        assert!(metrics.timestamp_anomaly);
        assert!(metrics.rich_header_present);
    }

    #[test]
    fn test_pe_metrics_imports() {
        let metrics = PeMetrics {
            delay_load_imports: 5,
            ordinal_imports: 3,
            suspicious_import_combo: true,
            api_hashing_indicators: 2,
            ..Default::default()
        };
        assert!(metrics.suspicious_import_combo);
        assert_eq!(metrics.delay_load_imports, 5);
    }

    #[test]
    fn test_pe_metrics_dotnet() {
        let metrics = PeMetrics {
            is_dotnet: true,
            clr_version: Some("4.0.30319".to_string()),
            mixed_mode: false,
            ..Default::default()
        };
        assert!(metrics.is_dotnet);
        assert_eq!(metrics.clr_version, Some("4.0.30319".to_string()));
    }

    #[test]
    fn test_pe_metrics_signature() {
        let metrics = PeMetrics {
            has_signature: true,
            signature_valid: Some(true),
            ..Default::default()
        };
        assert!(metrics.has_signature);
        assert_eq!(metrics.signature_valid, Some(true));
    }

    #[test]
    fn test_pe_metrics_resources() {
        let metrics = PeMetrics {
            rsrc_size: 102400,
            rsrc_entropy: 5.2,
            embedded_pe_count: 2,
            icon_count: 5,
            version_info_present: true,
            manifest_present: true,
            ..Default::default()
        };
        assert_eq!(metrics.rsrc_size, 102400);
        assert_eq!(metrics.embedded_pe_count, 2);
    }

    // ==================== MachoMetrics Default Tests ====================

    #[test]
    fn test_macho_metrics_default() {
        let metrics = MachoMetrics::default();
        assert_eq!(metrics.file_type, 0);
        assert!(!metrics.is_universal);
        assert!(!metrics.hardened_runtime);
    }

    #[test]
    fn test_macho_metrics_creation() {
        let metrics = MachoMetrics {
            file_type: 2, // MH_EXECUTE
            load_command_count: 25,
            dylib_count: 15,
            ..Default::default()
        };
        assert_eq!(metrics.file_type, 2);
        assert_eq!(metrics.load_command_count, 25);
    }

    #[test]
    fn test_macho_metrics_universal() {
        let metrics = MachoMetrics {
            is_universal: true,
            slice_count: 2,
            ..Default::default()
        };
        assert!(metrics.is_universal);
        assert_eq!(metrics.slice_count, 2);
    }

    #[test]
    fn test_macho_metrics_code_signing() {
        let metrics = MachoMetrics {
            has_code_signature: true,
            signature_valid: Some(true),
            signature_type: Some("developer-id".to_string()),
            team_identifier: Some("ABC123DEF".to_string()),
            ..Default::default()
        };
        assert!(metrics.has_code_signature);
        assert_eq!(metrics.signature_type, Some("developer-id".to_string()));
    }

    #[test]
    fn test_macho_metrics_entitlements() {
        let metrics = MachoMetrics {
            has_entitlements: true,
            dangerous_entitlements: 2,
            ..Default::default()
        };
        assert!(metrics.has_entitlements);
        assert_eq!(metrics.dangerous_entitlements, 2);
    }

    #[test]
    fn test_macho_metrics_hardened_runtime() {
        let metrics = MachoMetrics {
            hardened_runtime: true,
            allow_jit: false,
            ..Default::default()
        };
        assert!(metrics.hardened_runtime);
        assert!(!metrics.allow_jit);
    }

    // ==================== JavaClassMetrics Default Tests ====================

    #[test]
    fn test_java_class_metrics_default() {
        let metrics = JavaClassMetrics::default();
        assert_eq!(metrics.major_version, 0);
        assert_eq!(metrics.method_count, 0);
        assert!(metrics.java_version.is_none());
    }

    #[test]
    fn test_java_class_metrics_creation() {
        let metrics = JavaClassMetrics {
            major_version: 55, // Java 11
            minor_version: 0,
            java_version: Some("11".to_string()),
            method_count: 25,
            constant_pool_size: 150,
            ..Default::default()
        };
        assert_eq!(metrics.major_version, 55);
        assert_eq!(metrics.java_version, Some("11".to_string()));
    }

    #[test]
    fn test_java_class_metrics_constant_pool() {
        let metrics = JavaClassMetrics {
            constant_pool_size: 500,
            utf8_constants: 200,
            class_refs: 50,
            method_refs: 100,
            string_constant_entropy: 4.5,
            ..Default::default()
        };
        assert_eq!(metrics.constant_pool_size, 500);
        assert_eq!(metrics.utf8_constants, 200);
    }

    #[test]
    fn test_java_class_metrics_methods() {
        let metrics = JavaClassMetrics {
            method_count: 50,
            native_methods: 3,
            synthetic_methods: 10,
            avg_method_size: 150.5,
            max_method_size: 5000,
            ..Default::default()
        };
        assert_eq!(metrics.method_count, 50);
        assert_eq!(metrics.native_methods, 3);
    }

    #[test]
    fn test_java_class_metrics_debug_info() {
        let metrics = JavaClassMetrics {
            has_source_file: true,
            has_line_numbers: true,
            has_local_vars: true,
            inner_class_count: 5,
            ..Default::default()
        };
        assert!(metrics.has_source_file);
        assert!(metrics.has_line_numbers);
        assert_eq!(metrics.inner_class_count, 5);
    }

    #[test]
    fn test_java_class_metrics_obfuscation() {
        let metrics = JavaClassMetrics {
            obfuscated_strings: 10,
            invokedynamic_count: 5,
            reflection_patterns: 15,
            ..Default::default()
        };
        assert_eq!(metrics.obfuscated_strings, 10);
        assert_eq!(metrics.reflection_patterns, 15);
    }
}
