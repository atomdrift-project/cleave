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
//!   - `func_density = func_count / (code_size / 1024)`
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

use super::{is_false, is_zero_f32, is_zero_f64, is_zero_u32, is_zero_u64};

// =============================================================================
// BINARY-SPECIFIC METRICS
// =============================================================================

/// Metrics extracted from binary file formats (ELF, PE, Mach-O, Java class files)
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct BinaryMetrics {
    // === Entropy ===
    /// Shannon entropy of the entire file (0–8 scale)
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
    /// Total executable code size across all sections
    ///
    /// - Mach-O: __text + __stubs + __stub_helper
    /// - ELF: sections with SHF_EXECINSTR flag
    /// - PE: sections with IMAGE_SCN_MEM_EXECUTE characteristic
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub code_size: u64,

    /// Ratio of executable code bytes to non-code bytes
    ///
    /// - < 0.1: Packed/dropper (small code, large payload)
    /// - 0.2-2.0: Normal executable
    /// - > 10: Code-heavy (utilities, libraries)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_to_data_ratio: f32,

    // === Binary Properties ===
    /// Structural parser encountered an error or panic
    ///
    /// returning an error or by panicking on a malformed header. When set,
    /// the structure-derived fields below were populated from the rizin
    /// fallback analysis rather than the primary parser, and may be less
    /// complete than usual. The exact failure message lives in
    /// `report.metadata.errors`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_malformed_structure: bool,
    /// Binary contains debug symbols or DWARF data
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_debug_info: bool,
    /// Binary has been stripped of symbol information
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_stripped: bool,
    /// Position Independent Executable
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_pie: bool,
    /// Total number of relocations in the binary
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub relocation_count: u32,
    /// Number of linked library dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dependency_count: u32,
    /// Runtime library search path count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub runtime_search_path_count: u32,
    /// Debug-reference count in format-specific tables
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_reference_count: u32,
    /// Stable build/provenance identifier present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_provenance_id: bool,
    /// Stable build/provenance identifier length in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub provenance_id_length: u32,
    /// Has embedded signature metadata
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_signature: bool,

    // === Sections ===
    /// Total number of sections in the binary
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_count: u32,
    /// Number of sections with execute permission set
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub executable_section_count: u32,
    /// Number of sections with write permission set
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub writable_section_count: u32,
    /// W+X sections (self-modifying)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wx_section_count: u32,
    /// Section name entropy (random names = packer)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub section_name_entropy: f32,
    /// Largest section ratio to file size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub largest_section_ratio: f32,
    /// Ratio of executable code section bytes to file size
    ///
    /// Covers `.text` on PE/ELF, `__TEXT,__text` on Mach-O.
    /// Low values on non-packed binaries indicate compressed or hidden code.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub text_to_file_ratio: f32,
    /// Ratio of writable data section bytes to file size
    ///
    /// Covers `.data` on PE/ELF, `__DATA,__data` on Mach-O.
    /// High values are a strong packer/obfuscator signal.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub data_to_file_ratio: f32,
    /// Ratio of resource section bytes to total file size
    ///
    /// PE `.rsrc` only; 0 elsewhere. High values indicate resource carriers.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub rsrc_to_file_ratio: f32,
    /// Segment count (Mach-O) or program headers (ELF)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub segment_count: u32,
    /// Count of nonstandard section names for the file format
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nonstandard_section_count: u32,
    /// Mean size of binary sections in bytes
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_section_size: f32,

    // === Imports/Exports ===
    /// Total number of imported symbols
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub import_count: u32,
    /// Number of exported symbols
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_count: u32,
    /// Number of exports sharing an address with another export
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub aliased_exports: u32,
    /// Import name entropy (randomness)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_entropy: f32,

    // === Strings ===
    /// Count of extractable printable strings (len ≥ 4)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_count: u32,
    /// Mean Shannon entropy across extracted strings
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_entropy: f32,
    /// Strings with Shannon entropy above 4.5 bits
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_string_count: u32,
    /// Strings in code sections (unusual)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub strings_in_code: u32,
    /// Count of wide (UTF-16) strings extracted
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wide_string_count: u32,
    /// Sentence-like string count (multi-word printable strings)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sentence_string_count: u32,
    /// Ratio of sentence-like strings to all strings
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub sentence_string_ratio: f32,
    /// Mean length of extracted printable strings
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_length: f32,
    /// Length of the longest extracted printable string
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_string_length: u32,
    /// Standard deviation of string lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_length_stddev: f32,

    // === Functions ===
    /// Rizin function analysis depth: 0=skipped, 1=light, 2=full
    ///
    /// metrics-driven detections based on the analysis budget:
    /// - `0` = skipped (`func_count` etc. are 0; function-count
    ///   thresholds should be ignored)
    /// - `1` = light (`aa` only; entry-point analysis, no prologue scan)
    /// - `2` = full (`aa;aap`; entry-point + prologue scan, richest metrics)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub func_analysis_depth: u32,
    /// Total number of functions found by disassembly
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub func_count: u32,
    /// FUNC and IFUNC entries in the dynamic symbol table
    ///
    /// public ABI surface. Compare with `func_count` to detect
    /// hidden-code growth between releases.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynsym_func_count: u32,
    /// Functions absent from the dynamic symbol table
    ///
    /// dynsym entry (internal helpers). Disproportionate growth in
    /// this number with little change to `dynsym_func_count` between
    /// releases is the xz-class supply-chain signal: 99% of the new
    /// code is hidden from the public ABI.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub internal_func_count: u32,
    /// Unnamed complex functions not in the dynamic symbol table
    ///
    /// complexity > 50 (matches `high_complexity_func_count` threshold).
    /// The full ranked list lives at `binary.top_complex_unnamed[]`
    /// kv; this metric is the single-number trait target — drift
    /// between releases reveals hidden complex code added without
    /// ABI tie.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unnamed_complex_func_count: u32,
    /// Mean size of disassembled functions in bytes
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_func_size: f32,
    /// Tiny functions (<16 bytes)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tiny_func_count: u32,
    /// Functions larger than 64KB of code bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub huge_func_count: u32,
    /// Indirect call instructions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_call_count: u32,
    /// Indirect jump instructions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_jump_count: u32,

    // === Complexity (from radare2 analysis) ===
    /// Average cyclomatic complexity
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_complexity: f32,
    /// Maximum cyclomatic complexity
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_complexity: u32,
    /// Functions with high complexity (>50)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_complexity_func_count: u32,
    /// Names of high complexity functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub high_complexity_func_names: Vec<String>,
    /// Functions with very high complexity (>100)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_high_complexity_func_count: u32,
    /// Names of very high complexity functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub very_high_complexity_func_names: Vec<String>,

    // === Control Flow ===
    /// Total basic blocks across all functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_basic_blocks: u32,
    /// Average basic blocks per function
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_basic_blocks: f32,
    /// Linear functions (no branches)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linear_func_count: u32,
    /// Functions that call themselves directly
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_func_count: u32,
    /// Functions that never return to their caller
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub noreturn_func_count: u32,
    /// Leaf functions (make no calls)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub leaf_func_count: u32,

    // === Stack ===
    /// Mean stack frame size across all functions
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_stack_frame: f32,
    /// Largest single stack frame seen during analysis
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_stack_frame: u32,
    /// Functions with large stack (>4KB)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub large_stack_func_count: u32,
    /// Names of large stack functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub large_stack_func_names: Vec<String>,

    // === Overlay ===
    /// Binary has bytes appended after the last section
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_overlay: bool,
    /// Byte count of data appended after sections
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub overlay_size: u64,
    /// Overlay ratio to file size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub overlay_ratio: f32,
    /// Shannon entropy of the post-section overlay
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub overlay_entropy: f32,

    // === Embedded content ===
    /// Count of embedded executable files detected inside binary
    ///
    /// Source-agnostic — counts any validated embedded binary regardless of
    /// which detector found it (byte-scan, overlay, SFX extraction, …).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_binary_count: u32,
    /// Count of embedded archive files detected inside binary
    ///
    /// zstd, bz2, cab, lzh, iso, cpio, and SFX installer containers).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_archive_count: u32,
    /// Total embedded files across all detector types
    ///
    /// plus any other carved artifacts (images, scripts, …) future detectors
    /// report. Kept as a stable aggregate feature so the ML pipeline does not
    /// need to re-sum as new kinds are added.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_file_count: u32,

    // === Cross-format security signals (Tier C) ===
    /// Cert leaf CN looks like a person's name
    ///
    /// Signed binary whose leaf cert subject CN matches FIRSTNAME LASTNAME
    /// (no `O=` org). Catches the BEACH JOHN WILLIAM / cert-theft pattern
    /// observed in supply-chain malware. Set during cert extraction for
    /// any signed binary (PE Authenticode, Mach-O Developer ID).
    #[serde(default, skip_serializing_if = "is_false")]
    pub signed_with_individual_cert: bool,
    /// Executable stack permitted by loader
    ///
    /// Stack permissions allow execution. Cross-format equivalent of
    /// PE's NX-disabled scenario: ELF PT_GNU_STACK with PF_X, Mach-O
    /// MH_ALLOW_STACK_EXECUTION flag, etc. Counterpart to NX (ELF
    /// `nx_enabled`) so trait authors can write one rule.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_executable_stack: bool,
    /// Entry point in writable loadable region
    ///
    /// Cross-format: derives from `pe.entry_in_writable_section`,
    /// `elf.entry_in_writable_segment`, or
    /// `macho.entry_in_writable_segment`. Lets trait authors write a
    /// single rule for "EP in writable region" regardless of format.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_writable_region: bool,
    /// Count of overlapping sections/segments
    ///
    /// Cross-format sum of `pe.section_overlap_count`,
    /// `elf.segment_overlap_count`, and
    /// `macho.segment_overlap_count` (whichever applies).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub overlap_count: u32,

    // === Density Ratios (ML-oriented) ===
    /// Import density: imports per KB of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_density: f32,
    /// String density: strings per KB of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_density: f32,
    /// Function density: functions per KB of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub func_density: f32,
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
    /// Code section ratio (exec sections / total sections)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_section_ratio: f32,
    /// Complexity per KB: avg_complexity * 1024 / code_size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub complexity_per_kb: f32,
}

impl BinaryMetrics {
    /// Validate metric ranges and log warnings for out-of-range values.
    /// `path` is included in messages to identify which file triggered the warning.
    pub(crate) fn validate(&self, path: &str, file_size: u64) {
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
        if self.code_size > file_size {
            tracing::info!(
                path,
                code_size = self.code_size,
                file_size,
                "code_size > file_size (inflated section headers)"
            );
        }
        if self.overlay_size > file_size {
            tracing::info!(
                path,
                overlay_size = self.overlay_size,
                file_size,
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
        if self.func_density < 0.0 {
            tracing::warn!(
                path,
                func_density = self.func_density,
                "func_density is negative"
            );
        }

        // Section counts should be consistent
        if self.executable_section_count > self.section_count {
            tracing::warn!(
                path,
                executable_section_count = self.executable_section_count,
                section_count = self.section_count,
                "executable_section_count > section_count"
            );
        }
        if self.writable_section_count > self.section_count {
            tracing::warn!(
                path,
                writable_section_count = self.writable_section_count,
                section_count = self.section_count,
                "writable_section_count > section_count"
            );
        }
        if self.wx_section_count > self.executable_section_count {
            tracing::warn!(
                path,
                wx_section_count = self.wx_section_count,
                executable_section_count = self.executable_section_count,
                "wx_section_count > executable_section_count"
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
    /// Binary uses little-endian byte order
    #[serde(default, skip_serializing_if = "is_false")]
    pub little_endian: bool,
    /// Virtual address of the ELF entry point.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub entry: u64,
    /// Number of ELF program header entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub program_header_count: u32,
    /// Number of ELF section header entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_count: u32,
    /// Entry point falls outside the .text section
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_not_in_text: bool,
    /// Name of the section containing the entry point
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_section: Option<String>,

    // === Dynamic Linking ===
    /// Number of needed libraries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub needed_libs: u32,
    /// Interpreter present (PT_INTERP)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_interpreter: bool,
    /// Binary declares a shared-library SONAME
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_soname: bool,
    /// Binary has at least one RPATH entry
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_rpath: bool,
    /// Number of RPATH directory entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rpath_count: u32,
    /// Binary has at least one RUNPATH entry
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_runpath: bool,
    /// Number of RUNPATH entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub runpath_count: u32,
    /// SONAME string (DT_SONAME), e.g. `"libfoo.so.1"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soname: Option<String>,
    /// Count of DT_NEEDED shared library dependencies
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needed: Vec<String>,
    /// RPATH entries (DT_RPATH), one string per `:`-separated path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpaths: Vec<String>,
    /// RUNPATH entries as a colon-separated string
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runpaths: Vec<String>,
    /// Number of DT_INIT_ARRAY function pointers
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub init_array_count: u32,
    /// Number of DT_FINI_ARRAY function pointers
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fini_array_count: u32,

    // === Symbols ===
    /// Hidden visibility symbols
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hidden_symbol_count: u32,
    /// Dynamic symbol table count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynsym_count: u32,
    /// Static symbol table count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symtab_count: u32,
    /// GNU hash section is present in the binary
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_gnu_hash: bool,

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
    /// Number of PLT relocation entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pltreloc_count: u32,
    /// Section relocation groups count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_relocation_group_count: u32,

    // === Security Features ===
    /// GNU_RELRO protection level (none/partial/full)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relro: Option<String>,
    /// Binary has text relocations (TEXTREL flag set)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_textrel: bool,
    /// Binary uses stack-smashing protection canary
    #[serde(default, skip_serializing_if = "is_false")]
    pub stack_canary: bool,
    /// NX (non-executable stack)
    #[serde(default, skip_serializing_if = "is_false")]
    pub nx_enabled: bool,

    // === Special Sections ===
    /// Binary contains a .plt section
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_plt: bool,
    /// Binary contains a .got section
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_got: bool,
    /// Binary contains a .eh_frame unwind section
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_eh_frame: bool,
    /// Binary contains at least one .note section
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_note: bool,
    /// Total number of ELF note entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub note_count: u32,
    /// GNU build-id note present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_build_id: bool,
    /// GNU build-id length in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub build_id_length: u32,
    /// GNU build-id hex string for this ELF binary
    ///
    /// In-memory carrier only — surfaced to consumers via the
    /// cross-format `debug.build_id` kv path. Skipped from JSON so
    /// it doesn't show up twice (once as `elf.build_id` metric and
    /// once as `debug.build_id` kv) in analysis and diff output.
    #[serde(default, skip_serializing)]
    pub build_id: Option<String>,
    /// Number of DWARF compilation units in .debug_info
    ///
    /// lives on metrics; trait authors target `elf.dwarf_cu_count`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dwarf_cu_count: u32,
    /// .gnu_debuglink section present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_debuglink: bool,
    /// `.rustc` section present (Rust metadata marker)
    ///
    /// Explicit Rust-crate-metadata marker. Independent signal from
    /// import-based Rust runtime detection.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_rustc_section: bool,
    /// Number of debug-related sections
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_section_count: u32,

    /// Total NUL-separated entries in the .comment section
    ///
    /// One per input object file. Distinct entries with different toolchain
    /// banners signal a mixed-toolchain build (xz-class tampering).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comment_entry_count: u32,
    /// Distinct toolchain banner strings in .comment section
    ///
    /// A value greater than 1 means at least one input object was
    /// built with a different banner than the rest of the binary.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comment_distinct_count: u32,
    /// Count of standard metadata sections stripped from binary
    ///
    /// Canonical sections absent from a normally-toolchain-output ELF
    /// (.comment, .note.GNU-stack, .note.gnu.property, .note.ABI-tag,
    /// .symtab, .strtab). Aggressive stripping is itself a signal —
    /// distro releases usually keep `.comment`, only `strip --strip-all`
    /// removes it.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stripped_metadata_section_count: u32,
    /// Count of STT_GNU_IFUNC entries in .dynsym
    ///
    /// Trait authors match individual names via `elf.ifunc_symbols[]` kv;
    /// this metric supports min/max queries.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ifunc_count: u32,

    // === Segment / EP anomalies (Tier A — PE-equivalent signals) ===
    /// Entry point in writable PT_LOAD (PF_W set)
    ///
    /// Loadable writable+executable regions containing the EP are the
    /// textbook self-modifying / unpacker-stub fingerprint.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_writable_segment: bool,
    /// Entry point RVA outside all PT_LOAD segments
    ///
    /// Strong header-tampering signal — the loader will fail or jump to
    /// unmapped memory.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_outside_segments: bool,
    /// Entry point in last PT_LOAD (highest p_vaddr)
    ///
    /// Benign on UPX-style packed binaries (the unpacker stub appends
    /// itself); suspicious on otherwise-normal vendor binaries.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_last_segment: bool,
    /// Count of W+X PT_LOAD segments
    ///
    /// PT_LOAD segments with both PF_W and PF_X — directly loadable
    /// writable+executable regions. Modern toolchains emit zero.
    /// Counterpart to PE's `wx_section_count`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wx_segment_count: u32,
    /// PT_GNU_STACK marks stack as executable
    ///
    /// `PT_GNU_STACK` present with PF_X set. Modern toolchains emit
    /// RW-only stack; X-stack on a recent build is hand-crafted or
    /// extremely old.
    #[serde(default, skip_serializing_if = "is_false")]
    pub executable_stack: bool,
    /// Count of overlapping PT_LOAD segment pairs
    ///
    /// Number of PT_LOAD pairs with overlapping virtual address ranges.
    /// Legitimate ELFs never overlap; pefile-style parser confusion.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub segment_overlap_count: u32,
    /// Names of overlapping PT_LOAD segments
    ///
    /// Names ("PT_LOAD#N") of segments involved in any overlap.
    /// Carrier — surfaced via kv `elf.overlapping_segments[]`.
    #[serde(default, skip_serializing)]
    pub overlapping_segments: Vec<String>,
    /// Gap between program headers and first PT_LOAD
    ///
    /// Bytes between (ELF header + program headers) end and the first
    /// PT_LOAD's p_offset. Non-zero gap is a "header cave" — empty
    /// space the loader maps but tools may skip.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub first_segment_gap: u32,
    /// `e_shnum` disagrees with walked section count
    ///
    /// Either the header lies or the parser truncated; both indicate
    /// header tampering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub section_header_count_mismatch: bool,
    /// Multiple PT_INTERP segments (malformed)
    ///
    /// More than one PT_INTERP segment is malformed per ELF spec.
    /// A strict tampering signal — should always be 0 or 1.
    #[serde(default, skip_serializing_if = "is_false")]
    pub multiple_pt_interp: bool,

    // === Dynamic-section anomalies (Tier B) ===
    /// DT_NEEDED names the dynamic loader directly
    ///
    /// `DT_NEEDED` references `ld-linux-*`, `ld-musl-*`, `ld.so`, or
    /// `ld64.so`. Loader libs are normally pulled in transitively by
    /// libc; an explicit dependency is rare outside statically-linked
    /// glibc internals and the xz 5.6.0 backdoor.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_direct_loader_dep: bool,
    /// DT_AUDIT present (LD_AUDIT pre-main hooks)
    ///
    /// Installs LD_AUDIT-style hooks that execute before main().
    /// Classic library-injection persistence vector.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dt_audit: bool,
    /// DT_DEPAUDIT present (audit hooks for deps)
    ///
    /// Same as `has_dt_audit` but for the binary's dependencies.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dt_depaudit: bool,
    /// DT_RUNPATH begins with `$ORIGIN`
    ///
    /// Common on portable binaries but worth surfacing for trait
    /// authors writing portability / supply-chain rules.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dt_runpath_uses_origin: bool,
    /// Count of DT_NEEDED entries with absolute paths
    ///
    /// DT_NEEDED entries whose name starts with `/` (absolute path).
    /// Bare names are the norm; absolute paths are deliberate
    /// redirection of the dynamic loader.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dt_needed_abs_path_count: u32,
    /// Count of DT_NEEDED entries with `..` traversal
    ///
    /// Strong indicator of an attempt to escape rpath sandboxing.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dt_needed_traversal_count: u32,
    /// Raw DT_FLAGS_1 dynamic-section bitfield
    ///
    /// Common bits: NOW, GLOBAL, NODELETE, NOOPEN, ORIGIN, INITFIRST,
    /// NODEFLIB, PIE, NODIRECT, SYMINTPOSE. Decoded named flags
    /// surface via kv `elf.dt_flags_1.*`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dt_flags_1: u32,

    // === Section name / flag anomalies ===
    /// `.note.GNU-stack` section absent
    ///
    /// Modern toolchains emit it to mark stack permissions; absence on
    /// a recent build = old toolchain or hand-crafted ELF.
    #[serde(default, skip_serializing_if = "is_false")]
    pub gnu_stack_section_absent: bool,
    /// Both `.gnu.hash` and `.hash` sections present
    ///
    /// Modern binaries use one or the other; both is unusual (legacy
    /// compatibility linker option, rare in shipped binaries).
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_both_hash_tables: bool,
    /// Count of duplicate section names
    ///
    /// Number of section names that appear more than once in the
    /// section table. Duplicates are deliberate parser confusion.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub duplicate_section_name_count: u32,

    // === Modern hardening markers (NT_GNU_PROPERTY_TYPE_0) ===
    /// Intel CET indirect-branch tracking (IBT) set
    ///
    /// `GNU_PROPERTY_X86_FEATURE_1_AND` IBT bit set. Modern x86_64
    /// toolchains (gcc/clang ≥9) emit this; absence on a recent build
    /// = old toolchain or hand-crafted ELF. Counterpart of PE's
    /// `pe.dll_characteristics.guard_cf`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_cet_ibt: bool,
    /// Intel CET shadow stack (SHSTK) bit set
    ///
    /// `GNU_PROPERTY_X86_FEATURE_1_AND` SHSTK bit set. Same
    /// toolchain-recency signal as `has_cet_ibt`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_cet_shstk: bool,
    /// ARM Branch Target Identification (BTI) set
    ///
    /// `GNU_PROPERTY_AARCH64_FEATURE_1_AND` BTI bit set. Required on
    /// Apple Silicon shipping binaries and modern Linux arm64 builds.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_aarch64_bti: bool,
    /// ARM Pointer Authentication (PAC) bit set
    ///
    /// `GNU_PROPERTY_AARCH64_FEATURE_1_AND` PAC bit set. Required on
    /// Apple Silicon; modern arm64 Linux.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_aarch64_pac: bool,
    /// Minimum kernel version from NT_GNU_ABI_TAG
    ///
    /// E.g. `"3.2.0"`, `"4.4.0"`. Claiming compatibility with very old
    /// kernels on a recent build is a portable-malware indicator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gnu_abi_min_kernel: Option<String>,

    // === Tier A extensions (modern toolchain / hardening posture) ===
    /// DT_RELR present (compressed relocations)
    ///
    /// `DT_RELR` / `DT_RELRSZ` present. glibc 2.36+, lld 13+,
    /// gcc/binutils 2.38+ feature. Strong "modern toolchain" marker;
    /// absent on hand-crafted ELF or static glibc.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dt_relr: bool,
    /// Count of DT_PREINIT_ARRAY functions
    ///
    /// `DT_PREINIT_ARRAYSZ` / pointer-size — number of preinit
    /// functions. Run BEFORE `init_array`; legitimate binaries rarely
    /// use this beyond glibc itself, so non-zero values on user code
    /// are a common malware injection vector.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dt_preinit_array_count: u32,
    /// DT_DEBUG carries non-zero rtld_db pointer
    ///
    /// `DT_DEBUG` present with non-zero `d_un` value. Should be 0 on a
    /// binary read from disk; a non-zero value in a static dump is
    /// unusual.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dt_debug: bool,
    /// Count of DT_VERSYM versioned-symbol entries
    ///
    /// Modern glibc binaries always have versioned symbols; absence on
    /// a dynamically-linked Linux binary points to musl, custom static
    /// link, or hand-crafted ELF.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dt_versym_count: u32,
    /// Minimum x86 ISA level required
    ///
    /// Decoded from `GNU_PROPERTY_X86_ISA_1_NEEDED` into `"x86-64"`,
    /// `"x86-64-v2"`, `"x86-64-v3"`, `"x86-64-v4"`. Catches "this
    /// binary requires AVX2" detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x86_isa_level: Option<String>,
    /// AArch64 pointer-auth scheme name
    ///
    /// `GNU_PROPERTY_AARCH64_FEATURE_PAUTH` decoded — pointer-auth
    /// scheme platform/version (`"llvm.0"`, `"darwin"`, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pauth_scheme: Option<String>,
    /// Count of SHF_COMPRESSED sections
    ///
    /// Usually compressed debug info. Presence = recent toolchain.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub compressed_sections_count: u32,
    /// Count of imported `__*_chk` (FORTIFY_SOURCE) symbols
    ///
    /// E.g. `__memcpy_chk`, `__sprintf_chk`, `__strcpy_chk`.
    /// FORTIFY_SOURCE instrumentation. High counts indicate
    /// `-D_FORTIFY_SOURCE=2` builds; absence on an otherwise-modern
    /// binary suggests downgraded security.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fortify_source_used: u32,
    /// DT_RELACOUNT — relative relocation count
    ///
    /// Non-zero on PIE binaries; absence on an ostensibly-PIE binary
    /// is unusual.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub relacount: u32,
    /// Detected linker family (gnu_ld/gold/lld/mold)
    ///
    /// Inferred from `.comment` content + dynamic-tag shape, or `None`
    /// when the binary lacks a `.comment` section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linker_family: Option<String>,

    // === Structured kv carriers (kv-only — surfaced via binary_kv.rs) ===
    /// Per-segment summary (PT_LOAD focused)
    ///
    /// Carrier — surfaced via kv `elf.segments[]` so trait authors can
    /// match individual segment permissions / extents.
    #[serde(default, skip_serializing)]
    pub segment_entries: Vec<ElfSegmentEntry>,
    /// `.text` section marked SHF_WRITE
    ///
    /// Section was deliberately marked writable. Modern toolchains
    /// never emit this.
    #[serde(default, skip_serializing_if = "is_false")]
    pub text_section_writable: bool,
    /// `.rodata` section marked SHF_WRITE
    ///
    /// Read-only data section is in fact writable. Strong
    /// flag-tampering signal.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rodata_writable: bool,
    /// Stripped binary still carries `.symtab`
    ///
    /// `strip --strip-all` removes both; default `strip` keeps
    /// `.symtab`. Presence on a "stripped"-looking release binary
    /// indicates inconsistent stripping by the build pipeline.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stripped_but_symtab_present: bool,
    /// Multiple distinct DW_AT_producer strings
    ///
    /// More than one compiler contributed to a single output. Normal
    /// in some legitimate cases (Rust calling C); suspicious for
    /// vendor release binaries.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dwarf_mixed_producers: bool,
    /// Multiple distinct DW_AT_comp_dir directories
    ///
    /// CUs were compiled from different source roots. Suspicious in
    /// vendor releases that should have a single canonical build root.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dwarf_mixed_comp_dirs: bool,
    /// Distro + toolchain combination implausible
    ///
    /// `build.distro` plus observed `build.toolchain` is a combination
    /// that doesn't exist as default in any released distro version.
    /// Strong "the .comment was tampered with" signal.
    #[serde(default, skip_serializing_if = "is_false")]
    pub distro_toolchain_implausible: bool,
}

/// PE-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PeMetrics {
    // === Raw Header Fields (ML / anomaly-friendly) ===
    /// COFF timestamp as Unix epoch seconds
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub timestamp: u32,
    /// PE machine type (COFF header)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub machine: u32,
    /// COFF characteristics bitfield
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub characteristics: u32,
    /// Entry point as a relative virtual address.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub entry: u32,
    /// Section containing the entry point RVA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_section: Option<String>,
    /// Optional header checksum value
    #[serde(default)]
    pub checksum: u32,
    /// Whether the optional header checksum field is populated
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_checksum: bool,
    /// Checksum recomputed from file bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_checksum: u32,
    /// File alignment from the optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_alignment: u32,
    /// Section alignment from the optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_alignment: u32,
    /// Windows subsystem value from optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub subsystem: u32,
    /// DLL characteristics bitfield
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dll_characteristics: u32,
    /// Preferred virtual base address for loading
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub image_base: u64,
    /// SizeOfImage from optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub size_of_image: u32,
    /// SizeOfHeaders from optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub size_of_headers: u32,
    /// Linker major version from optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linker_major_version: u32,
    /// Linker minor version from optional header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linker_minor_version: u32,
    /// Number of distinct imported DLLs
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub import_dll_count: u32,
    /// Number of debug directory entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_directory_entries: u32,
    /// Sorted list of IMAGE_DEBUG_TYPE values present
    ///
    /// Deduplicated list from the Debug Directory. Surfaced verbatim so trait
    /// authors / ML can learn arbitrary patterns; derived booleans below name the
    /// supply-chain-relevant ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub debug_directory_types: Vec<u32>,
    /// REPRO debug entry present; deterministic build
    ///
    /// Vendor explicitly opted into reproducible builds. A vendor that previously
    /// set this and stops is a supply-chain swap signal.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_reproducible_build: bool,
    /// POGO debug entry present; PGO data is embedded
    ///
    /// Profile-Guided Optimization trained data leaked into the binary.
    /// Characteristic of release MSVC builds with `/LTCG /PGO`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_pogo: bool,
    /// ILTCG debug entry present; incremental LTCG was used
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_iltcg: bool,
    /// VC_FEATURE debug entry present; MSVC feature counts
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_vc_feature: bool,
    /// PDB path from CodeView debug info, if present
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb_path: Option<String>,
    /// CodeView PDB GUID linking PE to its PDB file
    ///
    /// (RSDS / NB10) — the per-build identifier. Hex string, no separators.
    /// Different per build even for the same source; rotates on every link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codeview_guid: Option<String>,
    /// CodeView PDB age — incremented per-edit by some toolchains.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub codeview_age: u32,
    /// Number of attribute certificates
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub certificate_count: u32,
    /// Certificate table size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub certificate_table_size: u64,
    /// Security directory offset exceeds actual file length
    ///
    /// Any non-zero value that exceeds the file length is impossible in a valid PE
    /// and indicates header tampering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub security_directory_out_of_bounds: bool,
    /// Export directory timestamp as Unix epoch seconds
    #[serde(default)]
    pub export_timestamp: u32,
    /// Export timestamp field is populated
    #[serde(default)]
    pub has_export_timestamp: bool,
    /// Resource directory timestamp as Unix epoch seconds
    #[serde(default)]
    pub resource_timestamp: u32,
    /// Resource timestamp field is populated
    #[serde(default)]
    pub has_resource_timestamp: bool,
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

    // === Header Anomalies ===
    /// Timestamp anomaly (future or ancient)
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_anomaly: bool,
    /// COFF timestamp field is set to zero
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_is_zero: bool,
    /// Timestamp is before year 2000
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_pre_2000: bool,
    /// Timestamp is more than one year in the future
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_in_future: bool,
    /// Stored PE checksum matches computed value
    #[serde(default, skip_serializing_if = "is_false")]
    pub checksum_valid: bool,
    /// Rich header found in the DOS-PE gap region
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_rich_header: bool,
    /// Standard DOS stub message is absent
    #[serde(default, skip_serializing_if = "is_false")]
    pub dos_stub_modified: bool,
    /// DOS stub region bytes are all zero
    ///
    /// Legitimate compilers leave the standard "This program cannot be
    /// run in DOS mode" message there; zeroing it is a low-cost anti-
    /// static technique to defeat heuristics that scan that region.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dos_stub_zeroed: bool,
    /// Signing time occurs before the PE COFF timestamp
    #[serde(default, skip_serializing_if = "is_false")]
    pub signing_time_before_timestamp: bool,

    // === Sections ===
    /// Size in bytes of the resource section
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub rsrc_size: u64,
    /// Shannon entropy of the resource section contents
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub rsrc_entropy: f32,
    /// Entry point not in a standard code section name
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_nonstandard_section: bool,
    /// Entry point is in a writable section
    ///
    /// Falls inside a section with `IMAGE_SCN_MEM_WRITE` (0x80000000). Legitimate
    /// code sections are read+execute only; a writable EP section is the textbook
    /// self-modifying / unpacker stub fingerprint. Orthogonal to the existing
    /// `wx_section_count` count — this metric isolates the section the loader
    /// will actually start executing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_writable_section: bool,
    /// Entry point RVA falls inside the PE header region
    ///
    /// RVA is below `SizeOfHeaders`. pefile flags this as "cannot run under
    /// Windows 8" — it's an old loader-confusion / anti-static trick.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_header: bool,
    /// Entry point RVA falls outside all section extents
    ///
    /// Stricter than `entry_in_nonstandard_section`: that flag
    /// fires when the EP section name is unusual; this one fires when
    /// no section claims the EP at all. Strong header-tampering signal.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_outside_sections: bool,
    /// Sections whose raw extent exceeds the file length
    ///
    /// Number of sections whose `PointerToRawData + SizeOfRawData`
    /// exceeds the file length. Each such section claims to contain
    /// data past the end of the file — a malformation pefile flags as
    /// "Error parsing section: SizeOfRawData is larger than file".
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_raw_overflow_count: u32,
    /// Names of sections extending past end of file
    ///
    /// In-memory carrier — surfaced via kv `pe.overflowing_sections[]`
    /// so trait authors can match section names directly.
    #[serde(default, skip_serializing)]
    pub overflowing_sections: Vec<String>,
    /// Sections whose raw pointer is not file-aligned
    ///
    /// Number of sections whose `PointerToRawData` is not a multiple
    /// of `FileAlignment`. pefile calls this out as deliberate parser-
    /// confusion ("trying to confuse tools which parse this incorrectly").
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub misaligned_section_count: u32,
    /// Names of file-misaligned sections as a carrier field
    ///
    /// In-memory carrier — surfaced via kv `pe.misaligned_sections[]`.
    #[serde(default, skip_serializing)]
    pub misaligned_sections: Vec<String>,
    /// COFF symbol table fields are non-zero
    ///
    /// (`PointerToSymbolTable != 0` and `NumberOfSymbols != 0`). Modern
    /// toolchains zero these fields (debug info goes in PDBs, not the COFF
    /// symbol table); when set, usually a build-pipeline outlier or hand-crafted PE.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_coff_symbols: bool,
    /// NumberOfRvaAndSizes from the optional header
    ///
    /// pefile flags values > 0x10 as suspicious; values < 0x10 may also indicate
    /// artificially-reduced directory tables. Raw value kept as a
    /// metric so trait authors can pick their own thresholds.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub number_of_rva_and_sizes: u32,

    // === Section/header arithmetic anomalies ===
    /// Parsed section count differs from NumberOfSections
    ///
    /// Parsed section count disagrees with FILE_HEADER NumberOfSections.
    /// Either the header lies about how many sections exist or the
    /// parser had to truncate — both indicate header tampering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub section_count_mismatch: bool,
    /// Number of sections with overlapping virtual address ranges
    ///
    /// Number of sections whose virtual address ranges intersect another
    /// section. Legitimate PEs never overlap; pefile flags this as a
    /// deliberate parser-confusion / shellcode-hiding technique.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_overlap_count: u32,
    /// Names of sections with overlapping address ranges
    ///
    /// Carrier — surfaced via kv `pe.overlapping_sections[]`.
    #[serde(default, skip_serializing)]
    pub overlapping_sections: Vec<String>,
    /// Bytes between SizeOfHeaders and first section raw data
    ///
    /// A non-zero gap is a "section cave" — empty
    /// space available for shellcode insertion that the loader will
    /// map but tools may skip.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub first_section_gap: u32,
    /// Entry point falls inside the last section by file order
    ///
    /// Benign on packed UPX-style binaries (the unpacker stub appends
    /// itself); suspicious for ostensibly-normal vendor binaries where
    /// EP should be in `.text` near the start.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_last_section: bool,
    /// Sections with no file backing but positive virtual size
    ///
    /// Sections with SizeOfRawData == 0 and VirtualSize > 0 — BSS-style
    /// sections that consume virtual memory without file backing.
    /// Counterpart to `max_section_inflation_ratio`; high counts (>1)
    /// indicate runtime-allocated decompression buffers.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bss_like_section_count: u32,
    /// .NET assembly carries a native pre-CLR entry point
    ///
    /// .NET assembly carries a native entry point in addition to the
    /// managed CLR header. Stronger signal than `mixed_mode` alone —
    /// a true native EP means unmanaged code runs before the CLR boots.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dotnet_has_native_entry: bool,

    // === Data-directory bounds ===
    /// Import directory RVA falls outside all sections
    #[serde(default, skip_serializing_if = "is_false")]
    pub import_dir_outside_section: bool,
    /// Export directory RVA falls outside all sections
    #[serde(default, skip_serializing_if = "is_false")]
    pub export_dir_outside_section: bool,
    /// Resource directory walker hit an out-of-range offset
    ///
    /// Resource directory walker observed an out-of-range read while
    /// traversing the .rsrc tree. Promoted from the existing internal
    /// panic-catch into an explicit metric so trait authors can target
    /// it without scraping log output.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rsrc_dir_overruns_section: bool,
    /// TLS callbacks pointing into non-executable sections
    ///
    /// Number of TLS callback RVAs that land in non-executable
    /// sections. TLS callbacks fire before the entry point; a callback
    /// in a writable / data section is the textbook anti-debug trick.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tls_callbacks_outside_code: u32,

    // === x509 / Authenticode enrichment ===
    /// Leaf cert includes the codeSigning extended key usage
    ///
    /// Leaf cert's ExtendedKeyUsage extension includes the codeSigning
    /// OID 1.3.6.1.5.5.7.3.3. When false on a signed PE, the leaf cert
    /// is not authorized for code signing — common when a stolen TLS
    /// server cert (serverAuth EKU) is repurposed as a fake Authenticode
    /// signature. Catches the Remus botnet sample (May 2026):
    /// `itunes.apple.com` is a TLS leaf with serverAuth.
    #[serde(default, skip_serializing_if = "is_false")]
    pub leaf_eku_code_signing: bool,
    /// Leaf cert signature algorithm friendly name
    ///
    /// Leaf cert's signature algorithm OID resolved to a friendly name
    /// (e.g. `sha256WithRSAEncryption`, `ecdsa-with-SHA256`).
    /// `sha1WithRSAEncryption` on a recent build is a deprecated-
    /// algorithm signal — Microsoft removed SHA-1 trust in 2020.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_signature_algorithm: Option<String>,
    /// Authenticode SignedData carries a nested signature
    ///
    /// Authenticode SignedData carries a NestedSignature attribute
    /// (Microsoft OID 1.3.6.1.4.1.311.2.4.1). Indicates a dual-signed
    /// binary — typically SHA-1 + SHA-256 during the SHA-2 transition
    /// era; sometimes a forged or backdated counter-sig.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_nested_signature: bool,
    /// Signed with a leaf cert lacking codeSigning EKU
    ///
    /// Derived from `has_signature && leaf_subject.is_some() && !leaf_eku_code_signing` —
    /// the same shape as `cert_chain_truncated`, atomic-trait friendly.
    /// Catches the Remus pattern (signed PE with a TLS server leaf
    /// stolen from another vendor).
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_codesign_leaf: bool,

    // === Authentihash + signature padding ===
    /// SHA-256 Authenticode hash excluding cert table data
    ///
    /// SHA-256 Authenticode hash per Microsoft's PE/COFF spec — hash
    /// of the file with the optional-header checksum, the cert table
    /// data directory entry, and the cert table data itself excluded.
    /// Two binaries with identical Authenticode hash are byte-equal in
    /// their signed regions even if re-signed with different certs;
    /// useful for detecting "same body, different cert" supply-chain
    /// swaps. Lowercase hex, no separators. Carrier for kv emission;
    /// surfaces as `hash.authenti`, never in the metrics output.
    #[serde(skip)]
    pub authentihash: Option<String>,
    /// Padding bytes between last section and cert table
    ///
    /// Bytes between the end of the last section's raw data and the
    /// start of the cert table (the "overlay" excluding the cert
    /// itself). Legitimate signers leave this at zero; non-zero values
    /// indicate appended payload that ships under the signature.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub overlay_padding: u64,

    // === Authenticode signature verification (LIEF-equivalent coverage) ===
    /// Digest algorithm name claimed by the SignedData structure
    ///
    /// Friendly name (e.g. `"sha256"`). Read from
    /// SpcIndirectDataContent.messageDigest.digestAlgorithm. None when
    /// the SPC structure couldn't be parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_digest_algorithm: Option<String>,
    /// Hex digest the SignedData claims was computed over the file
    ///
    /// Read from SpcIndirectDataContent.messageDigest.digest. Compare
    /// against the matching `authentihash_<alg>` to detect tampering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_digest: Option<String>,
    /// SignedData digest does not match the recomputed Authentihash
    ///
    /// Strong tampering signal — the file was modified after signing
    /// while the signature blob was kept. Catches the "drop a backdoor
    /// into a previously-signed binary" attack pattern.
    #[serde(default, skip_serializing_if = "is_false")]
    pub signature_digest_mismatch: bool,
    /// SHA-1 Authentihash (legacy Authenticode)
    ///
    /// Used internally for digest-mismatch verification when the
    /// signature claims SHA-1; never serialized.
    #[serde(skip)]
    pub authentihash_sha1: Option<String>,
    /// SHA-384 Authentihash (internal verification only)
    #[serde(skip)]
    pub authentihash_sha384: Option<String>,
    /// SHA-512 Authentihash (internal verification only)
    #[serde(skip)]
    pub authentihash_sha512: Option<String>,
    /// SignerInfo issuer CN identifying the actual signing cert
    ///
    /// Authoritative reference to which cert in the SignedData certs
    /// SET actually signed the binary. Distinct from `leaf_issuer`
    /// (which uses cleave's heuristic leaf-finder).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_info_issuer: Option<String>,
    /// SignerInfo serial number of the cert that signed the binary
    ///
    /// SignerInfo.IssuerAndSerialNumber.serialNumber as lowercase hex.
    /// Authoritative serial of the cert that actually signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_info_serial: Option<String>,
    /// SignerInfo issuer/serial matches the heuristic leaf cert
    ///
    /// False when the bag of certs in the SignedData doesn't match
    /// the SignerInfo IssuerAndSerialNumber reference.
    #[serde(default, skip_serializing_if = "is_false")]
    pub signer_info_matches_leaf: bool,
    /// Cryptographic result of verifying the SignerInfo signature
    ///
    /// None when algorithm isn't supported; Some(true) when valid;
    /// Some(false) when the signature doesn't match the public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_verified: Option<bool>,
    /// Signature algorithm is not supported for verification
    ///
    /// Currently true for ECDSA, RSA-PSS, etc. Distinguishes
    /// "verification failed" from "verification not attempted".
    #[serde(default, skip_serializing_if = "is_false")]
    pub sig_algorithm_unsupported: bool,
    /// Subject CN of the nested NestedSignature leaf certificate
    ///
    /// Microsoft NestedSignature attribute OID 1.3.6.1.4.1.311.2.4.1.
    /// When `has_nested_signature` is true, these `nested_*` fields
    /// describe the nested signer separately from the primary one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_leaf_subject: Option<String>,
    /// Issuer CN of the nested signature's leaf cert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_leaf_issuer: Option<String>,
    /// SHA-1 thumbprint of the nested signature's leaf cert DER.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_leaf_thumbprint_sha1: Option<String>,
    /// Nested signature leaf cert includes codeSigning EKU
    ///
    /// Mirrors `leaf_eku_code_signing` for the nested signer.
    #[serde(default, skip_serializing_if = "is_false")]
    pub nested_leaf_eku_code_signing: bool,
    /// Nested signature leaf cert signature algorithm name
    ///
    /// Mirrors `leaf_signature_algorithm` for the nested signer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_leaf_signature_algorithm: Option<String>,
    /// Nested signature digest mismatches recomputed Authentihash
    ///
    /// The digest the nested signature was made over does NOT match
    /// the recomputed Authentihash with that algorithm.
    #[serde(default, skip_serializing_if = "is_false")]
    pub nested_signature_digest_mismatch: bool,
    /// SignerInfo signature failed verification
    ///
    /// `has_signature && signature_verified == Some(false)` — the
    /// SignerInfo signature exists but doesn't validate against the
    /// leaf cert pubkey. Atomic-trait friendly (avoids `max: 0`
    /// false-positive on unsigned binaries).
    #[serde(default, skip_serializing_if = "is_false")]
    pub signature_verification_failed: bool,
    /// SignerInfo cert disagrees with heuristic leaf
    ///
    /// SignerInfo's IssuerAndSerialNumber points at a cert that
    /// disagrees with the leaf cleave's heuristic picked. Atomic-trait
    /// friendly counterpart of `signer_info_matches_leaf`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub signer_info_mismatches_leaf: bool,
    /// Nested-signature leaf lacks codeSigning EKU
    ///
    /// Nested signature is present but its leaf cert isn't authorized
    /// for code signing. Mirrors `non_codesign_leaf`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub nested_leaf_no_codesign_eku: bool,

    // === Structured kv carriers (kv-only — surfaced via binary_kv.rs) ===
    /// Per-section header summary as a carrier field
    ///
    /// Carrier — surfaced via kv `pe.section_characteristics[]`.
    #[serde(default, skip_serializing)]
    pub section_characteristics_entries: Vec<SectionCharacteristics>,
    /// Count of non-zero data directory slot entries
    ///
    /// Per-data-directory summary, only the slots with non-zero RVA.
    /// Carrier — surfaced via kv `pe.data_directories[]`.
    #[serde(default, skip_serializing)]
    pub data_directory_entries: Vec<DataDirectoryEntry>,
    /// Rich Header CompID tuples as a carrier field
    ///
    /// Parsed Rich Header CompID + count + product-name tuples. Build-
    /// toolchain fingerprint — vendor releases ship with stable Rich
    /// tuple sets; drift across releases is a build-pipeline change
    /// signal. Carrier — surfaced via kv `pe.rich_header_compids[]`.
    #[serde(default, skip_serializing)]
    pub rich_header_compids: Vec<RichCompId>,
    /// TLS callback addresses (RVAs)
    ///
    /// Carrier — surfaced via kv `pe.tls_callback_addresses[]` so
    /// trait authors can match individual callback locations.
    #[serde(default, skip_serializing)]
    pub tls_callback_addresses: Vec<u32>,

    // === Tier A: Load Config v2 fields (Win10+ hardening) ===
    /// GuardEHContinuationTable count (Load Config v2)
    ///
    /// Modern hardened binaries have non-zero values for
    /// EH-continuation CFG.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub guard_eh_cont_count: u32,
    /// GuardLongJumpTargetTable count (Load Config v2)
    ///
    /// Same "modern hardening" indicator as `cfg_func_count` was for
    /// v1.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub guard_long_jump_target_count: u32,
    /// DynamicValueRelocTable present (Win10+ relocs)
    ///
    /// `DynamicValueRelocTable` present in Load Config v2 — Win10+
    /// dynamic-relocation feature.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dynamic_value_reloc_table: bool,

    // === Cross-field consistency anomalies (formerly consistency.*) ===
    /// Signing cert issued after the build timestamp
    ///
    /// Authenticode signing cert was *issued* after the binary's COFF
    /// build timestamp (`leaf_not_before > pe.timestamp`). Almost
    /// always means an older binary was repackaged and re-signed with
    /// a newer cert — supply-chain swap signal. Filtered against
    /// deterministic-build (REPRO) timestamps which can legitimately
    /// appear in the future.
    #[serde(default, skip_serializing_if = "is_false")]
    pub cert_issued_after_build: bool,
    /// Cert org name absent from PDB path
    ///
    /// No word from the Authenticode `primary_signer` organization
    /// appears as a path component in the PDB path. Vendor binaries
    /// share a brand name between build environment and signing
    /// identity; divergence (e.g. "Ubisoft" cert signing a binary
    /// whose PDB path says "Unity Technologies") is a strong
    /// supply-chain swap signal. Only set when both fields are present
    /// and the signer is non-platform (not Microsoft/Windows).
    #[serde(default, skip_serializing_if = "is_false")]
    pub cert_org_pdb_mismatch: bool,
    /// Manifest version vs VERSIONINFO mismatch
    ///
    /// PE side-by-side manifest assembly version disagrees with the
    /// VERSIONINFO ProductVersion. Indicates manifest tampering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub manifest_version_mismatch: bool,

    // === Imports ===
    /// Count of delay-loaded import DLL entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub delay_load_import_count: u32,
    /// Number of imports resolved by ordinal only
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ordinal_import_count: u32,
    /// Count of API-hashing obfuscation indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub api_hashing_indicator_count: u32,

    // === Exports ===
    /// Number of forwarded (re-exported) symbol entries
    ///
    /// Export entry points into the export directory and names another
    /// `DLL.function` rather than a body in this binary. Proxy sideload DLLs
    /// approach a 1:1 forward-to-export ratio.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_forwarder_count: u32,
    /// Forwarded exports targeting Microsoft system DLLs
    ///
    /// Target DLL is a well-known Microsoft-shipped library (kernel32, ntdll,
    /// user32, etc.). A high value combined with a near-unity forward_ratio is
    /// the archetypal proxy-sideload fingerprint.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_dll_forward_count: u32,
    /// Ratio of forwarded exports to total named exports
    ///
    /// Range 0.0–1.0. Values near 1.0 on a non-system DLL indicate a stub
    /// binary whose public surface is almost entirely re-exports of another DLL.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub forward_ratio: f32,
    /// All exports forward to a version-suffixed sibling DLL
    ///
    /// All exports forward to a single DLL whose basename is a
    /// version-suffixed variant of this DLL's basename — e.g.
    /// `python3.dll` → `python312.dll`, `msvcp.dll` → `msvcp140.dll`.
    /// This is the canonical benign stable-ABI / version-shim forwarder
    /// pattern (CPython's python3.dll, MSVC runtime shims, VC redist).
    #[serde(default, skip_serializing_if = "is_false")]
    pub self_versioned_forwarder: bool,

    // === Resources ===
    /// Total number of resources in .rsrc directory
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub resource_count: u32,
    /// PE contains VS_VERSIONINFO resource data
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_version_info: bool,
    /// PE contains an embedded side-by-side manifest
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_manifest: bool,
    /// Number of icons in the resource section
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub icon_count: u32,

    // === .NET ===
    /// PE contains a .NET CLR header
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_dotnet: bool,
    /// CLR version string from the .NET metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clr_version: Option<String>,
    /// Mixed mode (native + .NET)
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_mode: bool,

    // === TLS ===
    /// Number of TLS callback function pointers
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tls_callback_count: u32,
    /// Maximum virtual-to-raw-size ratio across sections
    ///
    /// Maximum `virtual_size / raw_size` ratio across sections
    /// (excluding rsize=0 / BSS-style). >4 indicates a runtime-
    /// decompressed payload — classic packer fingerprint.
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub max_section_inflation_ratio: f64,

    // === Authenticode ===
    /// Binary carries an Authenticode signature
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_signature: bool,
    /// Authenticode signature passed local verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
    /// Signature type (platform, developer, adhoc)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<String>,
    /// Common name of the signer certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Organization or CN of the actual code signer
    ///
    /// Leaf-signer organization / CN chosen from the Authenticode chain by
    /// filtering out well-known CA and timestamp authority entries. This is
    /// the "who actually signed this" identity — e.g. `Python Software
    /// Foundation`, `Microsoft Corporation` — as opposed to the root/
    /// intermediate CAs that appear alongside it in the certificate chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_signer: Option<String>,
    /// Subject CN of the leaf Authenticode certificate
    ///
    /// The cert at the bottom of the Authenticode chain — the cert that
    /// actually signed the binary, distinct from issuer CAs above it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_subject: Option<String>,
    /// Issuer CN of the leaf Authenticode certificate
    ///
    /// Names the immediate CA above the leaf. Stable across a vendor's releases;
    /// a sudden change is a reliable supply-chain swap signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_issuer: Option<String>,
    /// SHA-1 thumbprint of the leaf cert DER bytes
    ///
    /// Lowercase hex, no separators. What `certutil -hashfile <pfx>` and
    /// Windows' "View Certificate" dialog show in the "Thumbprint" field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_thumbprint_sha1: Option<String>,
    /// Leaf cert serial number (lowercase hex, no separators).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_serial: Option<String>,
    /// Leaf cert NotBefore as Unix epoch seconds.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub leaf_not_before: i64,
    /// Leaf cert NotAfter as Unix epoch seconds.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub leaf_not_after: i64,
    /// Total certificate count in the Authenticode chain
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cert_chain_depth: u32,
    /// Leaf cert validity window in days
    ///
    /// (`leaf_not_after - leaf_not_before` / 86400). Derived count →
    /// metric. Useful for spotting anomalously long-validity code-
    /// signing certs (typical CSR is 1-3 years; >5 years is unusual).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cert_validity_days: u32,
    /// Leaf cert subject DN equals its issuer DN
    ///
    /// Both common names present and equal. Pure naming check — does NOT verify
    /// the signature against the leaf's own public key, so this is "self-issued"
    /// in the X.509 sense, not "self-signed". Self-issued leaves are normal for
    /// root CAs and dev test certs but anomalous for shipping software.
    #[serde(default, skip_serializing_if = "is_false")]
    pub leaf_self_issued: bool,
    /// Authenticode chain is truncated; intermediates are missing
    ///
    /// Signature is present and `cert_chain_depth == 1` but the leaf is NOT
    /// self-issued — the intermediate CA(s) above the leaf are missing. Distinct
    /// from a legitimate self-signed cert (depth 1 + self-issued). The Remus
    /// botnet sample (May 2026) embedded a stolen `itunes.apple.com`
    /// TLS leaf with no intermediates, producing this exact shape.
    #[serde(default, skip_serializing_if = "is_false")]
    pub cert_chain_truncated: bool,

    // === Load Config Directory ===
    /// Address of the /GS security cookie variable (0 if absent).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub security_cookie: u64,
    /// SafeSEH handler-table count (32-bit only; 0 on x64).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub se_handler_count: u32,
    /// CFG (Control Flow Guard) target-function table count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cfg_func_count: u32,
    /// Raw CFG GuardFlags bitfield from load config
    ///
    /// Common bits: 0x100 = INSTRUMENTED, 0x200 = WRITE_INSTRUMENTED,
    /// 0x400 = FUNCTION_TABLE_PRESENT, 0x800 = EXPORT_SUPPRESSION_INFO,
    /// 0x4000 = LONGJUMP_TABLE_PRESENT, 0x10000 = RF_INSTRUMENTED.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cfg_guard_flags: u32,
    /// CFG check-function pointer (the `__guard_check_icall_fptr`).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub cfg_check_func: u64,

    // === Resource Directory tree ===
    /// Sorted list of RT_* resource type names present
    ///
    /// Sorted, deduplicated list of canonical RT_* resource type
    /// names present in the .rsrc directory. Useful for
    /// visual-identity diffing (icons vs. versioninfo vs. dialogs vs.
    /// HTML resources etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_types: Vec<String>,

    // === Bound Import Directory ===
    /// Bound-import DLL count with host-timestamp bindings
    ///
    /// Each entry maps a DLL to the timestamp of the DLL file it was bound
    /// against on the build host. The closest thing to a build-host hardware
    /// fingerprint in any binary format — pre-resolved against the linker host's
    /// specific WinSxS state. Rare on modern PE; more common on
    /// legacy MSVC and embedded Windows tools.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bound_imports: Vec<BoundImportDescriptor>,
    /// CRC-32 fingerprint of the bound-import set
    ///
    /// Sorted by DLL name to be order-independent. Single u32 fingerprint
    /// for "same build-host WinSxS state" diffing — equality test
    /// across binaries replaces a per-element compare. Non-crypto;
    /// only meant for clustering / equality, not security.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bound_imports_checksum: u32,
}

#[allow(dead_code)]
const fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// One PE Bound Import Descriptor — names a linked DLL plus the
/// build-host timestamp the linker pre-bound it against. Build-host
/// fingerprint when present.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BoundImportDescriptor {
    /// Linked DLL name (e.g. `"KERNEL32.DLL"`).
    pub name: String,
    /// Unix epoch seconds — matches the timestamp of the DLL file on
    /// the build host at link time.
    pub time_date_stamp: u32,
    /// Number of bound forwarder references following this descriptor.
    pub forwarder_ref_count: u32,
}

/// One PE section header summary — name plus the loader-relevant
/// fields. Surfaced via kv `pe.section_characteristics[]`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SectionCharacteristics {
    /// Section name (NUL-trimmed; PE sections are 8 bytes max).
    pub name: String,
    /// `Characteristics` bitfield as lowercase hex (e.g. `"60000020"`).
    pub characteristics_hex: String,
    /// VirtualAddress (RVA) of the section.
    pub virtual_address: u32,
    /// VirtualSize — bytes the section occupies in memory.
    pub virtual_size: u32,
    /// SizeOfRawData — bytes the section occupies on disk.
    pub raw_size: u32,
}

/// One PE Data Directory slot — the 16-entry table at the end of the
/// optional header, naming the RVA + size of well-known directories
/// (Import, Export, Resource, Cert, Debug, TLS, …). Surfaced via kv
/// `pe.data_directories[]` so trait authors can write proximity
/// rules across them.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataDirectoryEntry {
    /// Canonical directory name (`"import"`, `"export"`, `"resource"`,
    /// `"certificate"`, `"debug"`, `"tls"`, …).
    pub name: String,
    /// VirtualAddress / file offset of the directory data.
    pub rva: u32,
    /// Size in bytes of the directory data.
    pub size: u32,
}

/// One Rich Header CompID + occurrence count + resolved product name.
/// Build-toolchain fingerprint material; vendor releases ship with
/// stable Rich tuple sets, so drift across releases is a build-pipeline
/// change signal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RichCompId {
    /// Raw 32-bit CompID (high 16 bits = build number, low 16 bits =
    /// product / tool ID).
    pub compid: u32,
    /// Number of object files contributed by this tool to the link.
    pub count: u32,
    /// Resolved product name (`"MSVC C++ compiler"`, `"Linker"`,
    /// `"MASM"`, `"Resource compiler"`, …) when the product ID is
    /// recognized; `None` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
}

/// One ELF program-header entry. Surfaced via kv `elf.segments[]`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ElfSegmentEntry {
    /// Symbolic name for the program-header type (`"PT_LOAD"`,
    /// `"PT_INTERP"`, `"PT_GNU_STACK"`, …) or `"PT_<hex>"` when
    /// unknown.
    pub p_type: String,
    /// Virtual address (`p_vaddr`).
    pub p_vaddr: u64,
    /// File offset (`p_offset`).
    pub p_offset: u64,
    /// File-resident bytes (`p_filesz`).
    pub p_filesz: u64,
    /// Memory-resident bytes (`p_memsz`).
    pub p_memsz: u64,
    /// `p_flags` bitfield as lowercase hex.
    pub flags_hex: String,
    /// Decoded permission string (`"r-x"`, `"rw-"`, `"rwx"`, `"---"`).
    pub perms: String,
}

/// One Mach-O segment summary (LC_SEGMENT / LC_SEGMENT_64).
/// Surfaced via kv `macho.segments[]`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MachoSegmentEntry {
    /// Segment name (e.g. `"__TEXT"`, `"__DATA"`, `"__LINKEDIT"`).
    pub name: String,
    /// Virtual address (`vmaddr`).
    pub vmaddr: u64,
    /// Virtual size (`vmsize`).
    pub vmsize: u64,
    /// File offset (`fileoff`).
    pub fileoff: u64,
    /// File-resident size (`filesize`).
    pub filesize: u64,
    /// Maximum VM protection (`maxprot`) as lowercase hex.
    pub maxprot_hex: String,
    /// Initial VM protection (`initprot`) as lowercase hex.
    pub initprot_hex: String,
    /// Decoded initial permission string (`"r-x"`, `"rw-"`, `"rwx"`,
    /// `"---"`).
    pub perms: String,
}

/// One Mach-O LC_LOAD_DYLIB-family entry.
/// Surfaced via kv `macho.dylibs[]`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MachoDylibEntry {
    /// Install name (e.g. `"/usr/lib/libSystem.B.dylib"`,
    /// `"@rpath/libfoo.dylib"`).
    pub name: String,
    /// Current version (encoded as a packed u32, format `XXXX.XX.XX`
    /// when decoded).
    pub current_version: u32,
    /// Compatibility version (same encoding).
    pub compatibility_version: u32,
    /// Load kind: `"regular"` (LC_LOAD_DYLIB), `"weak"`
    /// (LC_LOAD_WEAK_DYLIB), `"lazy"` (LC_LAZY_LOAD_DYLIB),
    /// `"upward"` (LC_LOAD_UPWARD_DYLIB), `"reexport"`
    /// (LC_REEXPORT_DYLIB).
    pub kind: String,
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
    /// Raw Mach-O header flags bitfield
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub flags: u32,
    /// Mach-O class in bits (32 or 64)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_bits: u32,
    /// Binary uses little-endian byte order
    #[serde(default, skip_serializing_if = "is_false")]
    pub little_endian: bool,
    /// Binary is a fat/universal multi-arch file
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_universal: bool,
    /// Slice count (for universal)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub slice_count: u32,
    /// Virtual entry point address.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub entry: u64,
    /// Entry point came from legacy LC_UNIXTHREAD
    #[serde(default, skip_serializing_if = "is_false")]
    pub old_style_entry: bool,

    // === Load Commands ===
    /// Number of load commands in the header
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub load_command_count: u32,
    /// Total byte size of all load commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub load_commands_size: u32,
    /// Binary carries an LC_CODE_SIGNATURE blob
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_code_signature: bool,
    /// Code signature passed local verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
    /// UUID load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_uuid: bool,
    /// Build-version load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_build_version: bool,
    /// Source-version load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_source_version: bool,
    /// Main entrypoint command present (LC_MAIN)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_main_command: bool,
    /// Legacy LC_UNIXTHREAD entrypoint present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_unixthread_command: bool,
    /// Code signature blob size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_signature_size: u32,

    // === Segments ===
    /// Size in bytes of the __LINKEDIT segment
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub linkedit_size: u64,
    /// Shannon entropy of the __TEXT segment
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub text_entropy: f32,

    // === Symbols ===
    /// Total number of symbols in the symbol table
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symbol_count: u32,
    /// Number of indirect symbol table entries
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
    /// Binary carries entitlements in its signature
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_entitlements: bool,
    /// Dangerous entitlement count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dangerous_entitlements: u32,

    // === dyld ===
    /// Number of dylib dependencies in load commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dylib_count: u32,
    /// Number of LC_REEXPORT_DYLIB load commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reexport_dylib_count: u32,
    /// Number of LC_LOAD_WEAK_DYLIB commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub weak_dylib_count: u32,
    /// Number of LC_LOAD_UPWARD_DYLIB commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub upward_dylib_count: u32,
    /// Number of lazy-loaded dylib load commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lazy_dylib_count: u32,
    /// Number of LC_RPATH run-path entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rpath_count: u32,
    /// Install name present (LC_ID_DYLIB)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_install_name: bool,
    /// Dynamic linker load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dylinker: bool,

    // === Build Metadata ===
    /// Build platform from LC_BUILD_VERSION
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub build_platform: u32,
    /// Minimum required OS major version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_os_major: u32,
    /// Minimum required OS minor version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_os_minor: u32,
    /// Minimum required OS patch version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_os_patch: u32,
    /// SDK major version used to build the binary
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sdk_major: u32,
    /// SDK minor version used to build the binary
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sdk_minor: u32,
    /// SDK patch version used to build the binary
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sdk_patch: u32,
    /// Build tool version entry count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub build_tool_count: u32,
    /// Encoded source version value
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub source_version: u64,

    // === Hardened Runtime ===
    /// Hardened runtime entitlement is enabled
    #[serde(default, skip_serializing_if = "is_false")]
    pub hardened_runtime: bool,
    /// Allow unsigned executable memory
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_jit: bool,
    /// Notarized proxy: has_entitlements && hardened_runtime
    ///
    /// Proxy for the notarization ticket presence; the ticket itself isn't always
    /// embedded. Boolean interpretation lives on metrics.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_notarized: bool,
    /// Count of __swift5_* sections in __TEXT
    ///
    /// >0 indicates Swift code; the specific subset present narrows Swift version.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub swift_section_count: u32,
    /// LC_FUNCTION_STARTS entry count known to dyld
    ///
    /// Independent of disassembled `func_count`;
    /// drift across releases of an otherwise-stable binary is a
    /// linker/build-pipeline change signal.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub function_starts_count: u32,

    // === Segment / EP anomalies (Tier A — PE-equivalent signals) ===
    /// Entry point in writable segment (VM_PROT_WRITE)
    ///
    /// Same self-modifying / unpacker-stub fingerprint as PE's
    /// `entry_in_writable_section`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_writable_segment: bool,
    /// Entry point outside all LC_SEGMENTs
    ///
    /// Entry point virtual address does not fall in any LC_SEGMENT.
    /// Header tampering signal.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_outside_segments: bool,
    /// Entry point in last segment (highest vmaddr)
    ///
    /// UPX-style packers produce this; suspicious otherwise.
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_last_segment: bool,
    /// Count of W+X segments (VM_PROT_WRITE|EXECUTE)
    ///
    /// Segments with both VM_PROT_WRITE and VM_PROT_EXECUTE. Modern
    /// Mach-O has zero. Counterpart to PE's `wx_section_count`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wx_segment_count: u32,
    /// Encrypted region present (LC_ENCRYPTION_INFO)
    ///
    /// `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` with `cryptid !=
    /// 0` — the binary carries an encrypted region. Only legitimate in
    /// iOS App Store binaries (FairPlay DRM); on macOS this is
    /// extremely unusual and indicates a binary that shouldn't be
    /// where it is.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_encrypted_section: bool,
    /// `__PAGEZERO` segment size in bytes
    ///
    /// Architecture default is `0x1_0000_0000` (4 GB) on x86_64/arm64
    /// and `0x1000` (4 KB) on i386. Wrong size = tampered or
    /// hand-crafted Mach-O — trait authors compare against the
    /// expected value rather than reading a derived bool.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub pagezero_size: u64,
    /// Count of overlapping segment pairs
    ///
    /// Number of segments whose virtual address ranges intersect
    /// another segment's range. Legitimate Mach-O never has
    /// overlapping segments; same parser-confusion signal as PE / ELF.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub segment_overlap_count: u32,
    /// Names of overlapping segments
    ///
    /// Carrier — surfaced via kv `macho.overlapping_segments[]`.
    #[serde(default, skip_serializing)]
    pub overlapping_segments: Vec<String>,

    // === Dylib path anomalies (Tier B/C) ===
    /// Count of unrooted dylib install_names
    ///
    /// LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB entries whose install_name
    /// doesn't start with `/`, `@executable_path`, `@loader_path`, or
    /// `@rpath`. Bare names are unusual and indicate a non-standard
    /// dylib search.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dylib_path_unrooted_count: u32,
    /// `@executable_path` used inside an MH_DYLIB
    ///
    /// Wrong direction — `@executable_path` only resolves in
    /// executables. Strong indicator of mishandled or tampered dylib.
    #[serde(default, skip_serializing_if = "is_false")]
    pub executable_path_in_dylib: bool,
    /// `@loader_path` used inside an MH_EXECUTE
    ///
    /// Wrong direction — `@loader_path` only meaningfully resolves in
    /// dylibs (resolves to the dylib's own directory).
    #[serde(default, skip_serializing_if = "is_false")]
    pub loader_path_in_executable: bool,
    /// Count of duplicate LC_LOAD_DYLIB entries
    ///
    /// Same install_name loaded twice. Packing / injection artifact.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub duplicate_dylib_count: u32,

    // === Modern vs legacy markers ===
    /// LC_DYLD_CHAINED_FIXUPS present (modern dyld)
    ///
    /// macOS 12+ dyld format. Counterpart to legacy LC_DYLD_INFO.
    /// Cross-release drift between these two on the same vendor binary
    /// is a build-pipeline change.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_chained_fixups: bool,
    /// LC_DYLD_INFO or LC_DYLD_INFO_ONLY present (legacy format).
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dyld_info_legacy: bool,
    /// Uses legacy LC_VERSION_MIN_* instead of LC_BUILD_VERSION
    ///
    /// Indicates an old SDK or hand-crafted binary — Apple deprecated
    /// LC_VERSION_MIN_* in favor of LC_BUILD_VERSION in macOS 10.14
    /// (2018).
    #[serde(default, skip_serializing_if = "is_false")]
    pub uses_legacy_version_min: bool,
    /// Adhoc signature on a release-shaped binary
    ///
    /// `signature_type = "adhoc"` on a binary with non-zero
    /// `source_version` or non-test `team_identifier` — i.e. a
    /// release-shaped binary signed without a real Developer ID.
    #[serde(default, skip_serializing_if = "is_false")]
    pub adhoc_on_release_binary: bool,
    /// Count of LC_DATA_IN_CODE entries
    ///
    /// Embedded data within executable sections (jump tables, string
    /// tables, …). High counts can indicate jump-table-heavy code or
    /// obfuscation.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub data_in_code_count: u32,

    // === Structured kv carriers (kv-only — surfaced via binary_kv.rs) ===
    /// Per-segment summary (LC_SEGMENT / LC_SEGMENT_64)
    ///
    /// Carrier — surfaced via kv `macho.segments[]`.
    #[serde(default, skip_serializing)]
    pub segment_entries: Vec<MachoSegmentEntry>,
    /// Per-dylib load command summary
    ///
    /// Carrier — surfaced via kv `macho.dylibs[]`.
    #[serde(default, skip_serializing)]
    pub dylib_entries: Vec<MachoDylibEntry>,

    // === Similarity hashes (machofile-inspired, supply-chain diff) ===
    // Carriers for kv emission only — surface under `hash.{dylib, sym,
    // export, entitlement}`, never in the metrics output. Hashes are
    // values for trait `regex:` / cluster diffing, not ML features.
    /// SHA-256 of sorted dylib names (Mach-O imphash)
    ///
    /// Counterpart of PE's `imphash`.
    #[serde(skip)]
    pub dylib_hash: Option<String>,
    /// sha256 of sorted imported symbol names.
    #[serde(skip)]
    pub symhash: Option<String>,
    /// sha256 of sorted exported symbol names.
    #[serde(skip)]
    pub export_hash: Option<String>,
    /// sha256 of sorted entitlement keys.
    #[serde(skip)]
    pub entitlement_hash: Option<String>,

    // === Tier A extensions (header flags, CodeDir flags, modern hardening) ===
    /// MH_ALLOW_STACK_EXECUTION flag set
    ///
    /// Stack execution explicitly allowed. Counterpart of ELF's
    /// `executable_stack`; bridged into the cross-format
    /// `binary.has_executable_stack` signal.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_stack_execution: bool,
    /// MH_NO_HEAP_EXECUTION flag set (heap NX)
    ///
    /// Modern hardening (no executable heap allocations). Most modern
    /// binaries set it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_heap_execution: bool,
    /// MH_APP_EXTENSION_SAFE flag set
    ///
    /// App extension can use this binary.
    #[serde(default, skip_serializing_if = "is_false")]
    pub app_extension_safe: bool,
    /// MH_DYLIB_IN_CACHE flag set
    ///
    /// Slice belongs to `dyld_shared_cache`. On a binary read from
    /// disk (not the cache itself) this is anomalous and indicates a
    /// copy-out or extraction artifact.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dylib_in_cache: bool,
    /// Raw CodeDirectory flags bitfield
    ///
    /// Decoded named bits surface via kv `macho.cs_flags.*` (runtime,
    /// library_validation, linker_signed, adhoc, kill, hard, …). Bit
    /// values from Apple's `<Security/CSCommon.h>` / XNU `cs_blobs.h`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cs_flags: u32,
    /// CodeDirectory `runtime` min OS version
    ///
    /// `major.minor.patch` string. Distinct from `LC_BUILD_VERSION`
    /// `min_os_*`; discrepancy = re-signing artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cs_runtime_version: Option<String>,
    /// `__DATA_CONST` segment present
    ///
    /// Modern macOS hardening (immutable after dyld processing).
    /// Standard on macOS 10.13+; absence on a recent build is
    /// anomalous.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_data_const_segment: bool,
    /// Count of Objective-C classes
    ///
    /// Entries in `__objc_classlist`. Build-fingerprint material;
    /// vendor releases share stable counts.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub objc_class_count: u32,
    /// Count of Swift protocol conformances
    ///
    /// Entries in `__swift5_proto`. Same use case as
    /// `objc_class_count`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub swift_protocol_count: u32,

    // === Cross-field consistency anomalies (formerly consistency.*) ===
    /// CodeDirectory ID vs CFBundleIdentifier mismatch
    ///
    /// Code-signature CodeDirectory identifier disagrees with the
    /// embedded `__TEXT,__info_plist` `CFBundleIdentifier`. Indicates
    /// the binary was re-signed with a different identity (replay
    /// attack / supply-chain swap).
    #[serde(default, skip_serializing_if = "is_false")]
    pub bundle_identifier_mismatch: bool,
    /// Universal slices disagree on code signing
    ///
    /// Universal Mach-O where some slices carry an LC_CODE_SIGNATURE
    /// blob and others don't. Vendors sign all slices uniformly; a
    /// mixed state almost always means tampering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub slice_signing_divergence: bool,
    /// __TEXT segment carries VM_PROT_WRITE
    ///
    /// __TEXT carries write permission in maxprot or initprot. __TEXT
    /// should always be R+X only; W on __TEXT is tampering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub text_segment_writable: bool,
    /// LC_ID_DYLIB install_name basename mismatch
    ///
    /// install_name doesn't match the file's actual path. Used in
    /// supply-chain dylib attacks where a malicious dylib claims to be
    /// a system library.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dylib_install_name_mismatch: bool,
}

/// Java class file metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct JavaClassMetrics {
    // === Version ===
    /// Class file format major version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub major_version: u32,
    /// Class file format minor version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub minor_version: u32,
    /// Decoded Java version string from class file
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_version: Option<String>,

    // === Constant Pool ===
    /// Number of entries in the constant pool
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub constant_pool_size: u32,
    /// Number of UTF8 entries in the constant pool
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub utf8_constants: u32,
    /// Number of class references in constant pool
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_refs: u32,
    /// Number of method references in constant pool
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_refs: u32,
    /// Mean entropy across string constant pool entries
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_constant_entropy: f32,
    /// Count of strings with obfuscation characteristics
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub obfuscated_strings: u32,

    // === Methods ===
    /// Total number of methods in the class file
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_count: u32,
    /// Number of native-declared method entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub native_methods: u32,
    /// Synthetic (compiler-generated) methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub synthetic_methods: u32,
    /// Mean bytecode size across all class methods
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_method_size: f32,
    /// Largest bytecode size among all class methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_method_size: u32,

    // === Bytecode ===
    /// Number of invokedynamic bytecode instructions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invokedynamic_count: u32,
    /// Count of reflection API usage patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflection_patterns: u32,

    // === Debug Info ===
    /// Has source file attribute
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_source_file: bool,
    /// Class file contains LineNumberTable attributes
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_line_numbers: bool,
    /// Class file contains LocalVariableTable attributes
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_local_vars: bool,
    /// Number of inner and anonymous class declarations
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
        assert_eq!(metrics.func_count, 0);
        assert!(!metrics.has_overlay);
    }

    #[test]
    fn test_binary_metrics_creation() {
        let metrics = BinaryMetrics {
            overall_entropy: 7.5,
            code_entropy: 6.8,
            section_count: 5,
            executable_section_count: 2,
            import_count: 150,
            func_count: 50,
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
            wx_section_count: 1,
            writable_section_count: 2,
            executable_section_count: 3,
            ..Default::default()
        };
        assert_eq!(metrics.wx_section_count, 1);
    }

    #[test]
    fn test_binary_metrics_complexity() {
        let metrics = BinaryMetrics {
            avg_complexity: 15.5,
            max_complexity: 100,
            high_complexity_func_count: 5,
            high_complexity_func_names: vec!["process_data".to_string()],
            ..Default::default()
        };
        assert_eq!(metrics.max_complexity, 100);
        assert_eq!(metrics.high_complexity_func_names.len(), 1);
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
            has_rpath: true,
            has_runpath: false,
            init_array_count: 3,
            fini_array_count: 1,
            ..Default::default()
        };
        assert!(metrics.has_rpath);
        assert_eq!(metrics.init_array_count, 3);
    }

    #[test]
    fn test_elf_metrics_special_sections() {
        let metrics = ElfMetrics {
            has_plt: true,
            has_got: true,
            has_eh_frame: true,
            has_gnu_hash: true,
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
            has_rich_header: true,
            resource_count: 10,
            ..Default::default()
        };
        assert!(metrics.timestamp_anomaly);
        assert!(metrics.has_rich_header);
    }

    #[test]
    fn test_pe_metrics_imports() {
        let metrics = PeMetrics {
            delay_load_import_count: 5,
            ordinal_import_count: 3,
            api_hashing_indicator_count: 2,
            ..Default::default()
        };
        assert_eq!(metrics.delay_load_import_count, 5);
        assert_eq!(metrics.api_hashing_indicator_count, 2);
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
            icon_count: 5,
            has_version_info: true,
            has_manifest: true,
            ..Default::default()
        };
        assert_eq!(metrics.rsrc_size, 102400);
        assert_eq!(metrics.icon_count, 5);
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

    #[test]
    fn test_pe_metrics_new_anomaly_fields_default_false() {
        let metrics = PeMetrics::default();
        assert!(!metrics.dos_stub_zeroed);
        assert!(!metrics.security_directory_out_of_bounds);
        assert!(!metrics.leaf_self_issued);
        assert!(!metrics.cert_chain_truncated);
        assert!(!metrics.entry_in_writable_section);
        assert!(!metrics.entry_in_header);
        assert!(!metrics.entry_outside_sections);
        assert_eq!(metrics.section_raw_overflow_count, 0);
        assert!(metrics.overflowing_sections.is_empty());
        assert_eq!(metrics.misaligned_section_count, 0);
        assert!(metrics.misaligned_sections.is_empty());
        assert!(!metrics.has_coff_symbols);
        assert_eq!(metrics.number_of_rva_and_sizes, 0);
    }

    #[test]
    fn test_pe_metrics_leaf_self_issued_set() {
        let metrics = PeMetrics {
            leaf_self_issued: true,
            cert_chain_truncated: true,
            ..Default::default()
        };
        assert!(metrics.leaf_self_issued);
        assert!(metrics.cert_chain_truncated);
    }

    #[test]
    fn test_pe_metrics_entry_anomalies_set() {
        let metrics = PeMetrics {
            entry_in_writable_section: true,
            entry_in_header: true,
            entry_outside_sections: true,
            ..Default::default()
        };
        assert!(metrics.entry_in_writable_section);
        assert!(metrics.entry_in_header);
        assert!(metrics.entry_outside_sections);
    }

    #[test]
    fn test_pe_metrics_signature_verification_defaults() {
        let m = PeMetrics::default();
        assert!(m.signature_digest_algorithm.is_none());
        assert!(m.signature_digest.is_none());
        assert!(!m.signature_digest_mismatch);
        assert!(m.authentihash_sha1.is_none());
        assert!(m.authentihash_sha384.is_none());
        assert!(m.authentihash_sha512.is_none());
        assert!(m.signer_info_issuer.is_none());
        assert!(m.signer_info_serial.is_none());
        assert!(!m.signer_info_matches_leaf);
        assert!(m.signature_verified.is_none());
        assert!(!m.sig_algorithm_unsupported);
        assert!(m.nested_leaf_subject.is_none());
        assert!(m.nested_leaf_issuer.is_none());
        assert!(m.nested_leaf_thumbprint_sha1.is_none());
        assert!(!m.nested_leaf_eku_code_signing);
        assert!(m.nested_leaf_signature_algorithm.is_none());
        assert!(!m.nested_signature_digest_mismatch);
    }

    #[test]
    fn test_pe_metrics_signature_verification_set() {
        let m = PeMetrics {
            signature_digest_algorithm: Some("sha256".into()),
            signature_digest: Some("abc123".into()),
            signature_digest_mismatch: true,
            authentihash_sha1: Some("def456".into()),
            signer_info_matches_leaf: true,
            signature_verified: Some(true),
            nested_leaf_eku_code_signing: true,
            ..Default::default()
        };
        assert!(m.signature_digest_mismatch);
        assert_eq!(m.signature_verified, Some(true));
        assert!(m.signer_info_matches_leaf);
        assert!(m.nested_leaf_eku_code_signing);
    }

    #[test]
    fn test_pe_metrics_batch_defaults_false_or_zero() {
        let m = PeMetrics::default();
        assert!(!m.section_count_mismatch);
        assert_eq!(m.section_overlap_count, 0);
        assert!(m.overlapping_sections.is_empty());
        assert_eq!(m.first_section_gap, 0);
        assert!(!m.entry_in_last_section);
        assert_eq!(m.bss_like_section_count, 0);
        assert!(!m.dotnet_has_native_entry);
        assert!(!m.import_dir_outside_section);
        assert!(!m.export_dir_outside_section);
        assert!(!m.rsrc_dir_overruns_section);
        assert_eq!(m.tls_callbacks_outside_code, 0);
        assert!(!m.leaf_eku_code_signing);
        assert!(m.leaf_signature_algorithm.is_none());
        assert!(!m.has_nested_signature);
        assert!(m.authentihash.is_none());
        assert_eq!(m.overlay_padding, 0);
        assert!(m.section_characteristics_entries.is_empty());
        assert!(m.data_directory_entries.is_empty());
        assert!(m.rich_header_compids.is_empty());
    }

    #[test]
    fn test_section_characteristics_carrier() {
        let s = SectionCharacteristics {
            name: ".text".into(),
            characteristics_hex: "60000020".into(),
            virtual_address: 0x1000,
            virtual_size: 0x4000,
            raw_size: 0x4000,
        };
        assert_eq!(s.name, ".text");
        assert_eq!(s.characteristics_hex, "60000020");
    }

    #[test]
    fn test_data_directory_entry_carrier() {
        let d = DataDirectoryEntry {
            name: "import".into(),
            rva: 0x5000,
            size: 200,
        };
        assert_eq!(d.name, "import");
        assert_eq!(d.size, 200);
    }

    #[test]
    fn test_rich_compid_carrier() {
        let r = RichCompId {
            compid: 0x1A2B_0040,
            count: 5,
            product: Some("MSVC 14.0 C compiler".into()),
        };
        assert_eq!(r.count, 5);
        assert_eq!(r.product.as_deref(), Some("MSVC 14.0 C compiler"));
    }

    #[test]
    fn test_pe_metrics_section_anomaly_carriers() {
        let metrics = PeMetrics {
            section_raw_overflow_count: 2,
            overflowing_sections: vec![".text".into(), ".data".into()],
            misaligned_section_count: 1,
            misaligned_sections: vec![".rsrc".into()],
            ..Default::default()
        };
        assert_eq!(metrics.section_raw_overflow_count, 2);
        assert_eq!(metrics.overflowing_sections.len(), 2);
        assert_eq!(metrics.misaligned_section_count, 1);
        assert_eq!(metrics.misaligned_sections, vec![".rsrc".to_string()]);
    }

    #[test]
    fn test_pe_cert_org_pdb_mismatch_default_false() {
        let metrics = PeMetrics::default();
        assert!(!metrics.cert_org_pdb_mismatch);
    }

    #[test]
    fn test_security_directory_out_of_bounds_field() {
        let metrics = PeMetrics {
            security_directory_out_of_bounds: true,
            ..Default::default()
        };
        assert!(metrics.security_directory_out_of_bounds);
    }
}
