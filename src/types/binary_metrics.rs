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
    /// Raw format-native entry point value
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub entry_point: u64,
    /// Entry point is expressed as a relative virtual address
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_point_is_rva: bool,
    /// Entry point is outside the primary expected code section
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_nonstandard_section: bool,
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
    /// Total number of sections in the binary
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_count: u32,
    /// Number of sections with execute permission set
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub executable_sections: u32,
    /// Number of sections with write permission set
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
    pub nonstandard_section_name_count: u32,
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
    pub high_entropy_strings: u32,
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
    /// complexity > 50 (matches `high_complexity_funcs` threshold).
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
    pub tiny_funcs: u32,
    /// Functions larger than 64KB of code bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub huge_funcs: u32,
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
    pub high_complexity_funcs: u32,
    /// Names of high complexity functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub high_complexity_func_names: Vec<String>,
    /// Functions with very high complexity (>100)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_high_complexity_funcs: u32,
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
    pub linear_funcs: u32,
    /// Functions that call themselves directly
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_funcs: u32,
    /// Functions that never return to their caller
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub noreturn_funcs: u32,
    /// Leaf functions (make no calls)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub leaf_funcs: u32,

    // === Stack ===
    /// Mean stack frame size across all functions
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_stack_frame: f32,
    /// Largest single stack frame seen during analysis
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_stack_frame: u32,
    /// Functions with large stack (>4KB)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub large_stack_funcs: u32,
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
    /// Binary uses little-endian byte order
    #[serde(default, skip_serializing_if = "is_false")]
    pub little_endian: bool,
    /// Virtual address of the ELF entry point
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub entry_point: u64,
    /// Number of ELF program header entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub program_header_count: u32,
    /// Number of ELF section header entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_header_count: u32,
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
    pub rpath_set: bool,
    /// Number of RPATH directory entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rpath_count: u32,
    /// Binary has at least one RUNPATH entry
    #[serde(default, skip_serializing_if = "is_false")]
    pub runpath_set: bool,
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
    pub hidden_symbols: u32,
    /// Dynamic symbol table count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynsym_count: u32,
    /// Static symbol table count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symtab_count: u32,
    /// GNU hash section is present in the binary
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
    pub textrel_present: bool,
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
    pub build_id_present: bool,
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
    pub debuglink_present: bool,
    /// Number of debug-related sections
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_section_count: u32,

    /// Total NUL-separated entries in the .comment section
    ///
    /// One per input object file. Distinct entries with different toolchain
    /// banners signal a mixed-toolchain build (xz-class tampering).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comment_entry_count: u32,
    /// Distinct toolchain banner strings in .comment section.
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
    /// Entry point relative virtual address
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
    /// Checksum recomputed from file bytes
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
    pub rich_header_present: bool,
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
    /// Unusual section alignment
    #[serde(default, skip_serializing_if = "is_false")]
    pub unusual_alignment: bool,
    /// Entry point not in a standard code section name
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_in_nonstandard_section: bool,
    /// Entry point is in a writable section
    ///
    /// Falls inside a section with `IMAGE_SCN_MEM_WRITE` (0x80000000). Legitimate
    /// code sections are read+execute only; a writable EP section is the textbook
    /// self-modifying / unpacker stub fingerprint. Orthogonal to the existing
    /// `wx_sections` count — this metric isolates the section the loader
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
    pub coff_symbol_table_present: bool,
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
    pub first_section_gap_bytes: u32,
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
    pub import_directory_outside_section: bool,
    /// Export directory RVA falls outside all sections
    #[serde(default, skip_serializing_if = "is_false")]
    pub export_directory_outside_section: bool,
    /// Resource directory walker hit an out-of-range offset
    ///
    /// Resource directory walker observed an out-of-range read while
    /// traversing the .rsrc tree. Promoted from the existing internal
    /// panic-catch into an explicit metric so trait authors can target
    /// it without scraping log output.
    #[serde(default, skip_serializing_if = "is_false")]
    pub resource_directory_overruns_section: bool,
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
    pub signed_with_non_code_signing_leaf: bool,

    // === Authentihash + signature padding ===
    /// SHA-256 Authenticode hash excluding cert table data
    ///
    /// SHA-256 Authenticode hash per Microsoft's PE/COFF spec — hash
    /// of the file with the optional-header checksum, the cert table
    /// data directory entry, and the cert table data itself excluded.
    /// Two binaries with identical Authenticode hash are byte-equal in
    /// their signed regions even if re-signed with different certs;
    /// useful for detecting "same body, different cert" supply-chain
    /// swaps. Lowercase hex, no separators.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentihash: Option<String>,
    /// Padding bytes between last section and cert table
    ///
    /// Bytes between the end of the last section's raw data and the
    /// start of the cert table (the "overlay" excluding the cert
    /// itself). Legitimate signers leave this at zero; non-zero values
    /// indicate appended payload that ships under the signature.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub signature_overlay_padding_bytes: u64,

    // === Authenticode signature verification (LIEF-equivalent coverage) ===
    /// Friendly name of the digest algorithm the SignedData claims the
    /// file was hashed with (e.g. `"sha256"`). Read from
    /// SpcIndirectDataContent.messageDigest.digestAlgorithm. None when
    /// the SPC structure couldn't be parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_digest_algorithm: Option<String>,
    /// Hex string of the file digest the SignedData claims (the value
    /// the signature was actually made over). Read from
    /// SpcIndirectDataContent.messageDigest.digest. Compare against
    /// the matching `authentihash_<alg>` to detect tampering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_digest: Option<String>,
    /// The digest the SignedData was made over does NOT match the
    /// recomputed Authentihash. Strong tampering signal — the file
    /// was modified after signing while the signature blob was kept.
    /// Catches the "drop a backdoor into a previously-signed binary"
    /// attack pattern that bare cert-chain validity checks miss.
    #[serde(default, skip_serializing_if = "is_false")]
    pub signature_digest_mismatch: bool,
    /// Authentihash computed with SHA-1 (legacy Authenticode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentihash_sha1: Option<String>,
    /// Authentihash computed with SHA-384.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentihash_sha384: Option<String>,
    /// Authentihash computed with SHA-512.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentihash_sha512: Option<String>,
    /// Common Name from SignerInfo.IssuerAndSerialNumber.issuer — the
    /// authoritative reference to which cert in the SignedData certs
    /// SET actually signed the binary. Distinct from `leaf_issuer`
    /// (which uses cleave's heuristic leaf-finder); when these
    /// disagree, the heuristic picked the wrong cert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_info_issuer: Option<String>,
    /// SignerInfo.IssuerAndSerialNumber.serialNumber as lowercase hex.
    /// Authoritative serial of the cert that actually signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_info_serial: Option<String>,
    /// SignerInfo's IssuerAndSerialNumber matches the leaf cert that
    /// `find_leaf_signer` heuristically picked. False when the bag of
    /// certs in the SignedData doesn't match the SignerInfo reference.
    #[serde(default, skip_serializing_if = "is_false")]
    pub signer_info_matches_leaf: bool,
    /// Result of cryptographically verifying the SignerInfo signature
    /// against the leaf cert's public key. None when the signature
    /// algorithm isn't supported (currently only RSA-PKCS1v15);
    /// Some(true) when the signature is mathematically valid;
    /// Some(false) when verification fails (the signature blob was
    /// not produced by the holder of the leaf cert's private key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_verified: Option<bool>,
    /// SignerInfo signature algorithm isn't one cleave can verify.
    /// Currently true for ECDSA, RSA-PSS, etc. Lets traits distinguish
    /// "verification failed" from "verification not attempted".
    #[serde(default, skip_serializing_if = "is_false")]
    pub signature_algorithm_unsupported: bool,
    /// Subject CN of the *nested* signature's leaf cert (Microsoft
    /// NestedSignature attribute, OID 1.3.6.1.4.1.311.2.4.1).
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
    /// Nested signature's leaf cert ExtendedKeyUsage includes
    /// codeSigning OID. Mirrors `leaf_eku_code_signing`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub nested_leaf_eku_code_signing: bool,
    /// Friendly name of the nested signature's leaf cert signature
    /// algorithm. Mirrors `leaf_signature_algorithm`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nested_leaf_signature_algorithm: Option<String>,
    /// The digest the *nested* signature was made over does NOT match
    /// the recomputed Authentihash with that algorithm.
    #[serde(default, skip_serializing_if = "is_false")]
    pub nested_signature_digest_mismatch: bool,

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

    // === Imports ===
    /// Count of delay-loaded import DLL entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub delay_load_imports: u32,
    /// Number of imports resolved by ordinal only
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ordinal_imports: u32,
    /// Count of API-hashing obfuscation indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub api_hashing_indicators: u32,
    /// Suspicious import combo (VirtualAlloc+Write+Protect)
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspicious_import_combo: bool,

    // === Exports ===
    /// Number of forwarded (re-exported) symbol entries
    ///
    /// Export entry points into the export directory and names another
    /// `DLL.function` rather than a body in this binary. Proxy sideload DLLs
    /// approach a 1:1 forward-to-export ratio.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_forwarders: u32,
    /// Forwarded exports targeting Microsoft system DLLs
    ///
    /// Target DLL is a well-known Microsoft-shipped library (kernel32, ntdll,
    /// user32, etc.). A high value combined with a near-unity forward_ratio is
    /// the archetypal proxy-sideload fingerprint.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub forwards_to_system_dll_count: u32,
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
    pub version_info_present: bool,
    /// PE contains an embedded side-by-side manifest
    #[serde(default, skip_serializing_if = "is_false")]
    pub manifest_present: bool,
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
    pub tls_callbacks: u32,
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

/// Cross-format internal-consistency flags. Each boolean is a
/// derived interpretation: cleave compared two fields populated
/// from independent sources within the same binary and they
/// disagreed. Raw structural reads stay in the kv tree; these
/// derived judgments live here so trait authors can target them
/// uniformly via `type: metrics, field: consistency.<name>, min: 1`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ConsistencyMetrics {
    /// Mach-O re-signed with mismatched bundle identifier
    ///
    /// The CodeDirectory identifier doesn't match the embedded
    /// `__TEXT,__info_plist` `CFBundleIdentifier`.
    /// Indicates the binary was re-signed with a different identity
    /// (replay attack / supply-chain swap).
    #[serde(default, skip_serializing_if = "is_false")]
    pub bundle_identifier_mismatch: bool,
    /// PE manifest version differs from VERSIONINFO ProductVersion
    ///
    /// Indicates manifest tampering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub manifest_product_version_mismatch: bool,
    /// Distro and toolchain version never shipped together
    ///
    /// The `build.distro` plus observed `build.toolchain` is a
    /// combination that doesn't exist as default in any released
    /// distro version. Strong "the .comment was tampered with"
    /// signal.
    #[serde(default, skip_serializing_if = "is_false")]
    pub distro_toolchain_implausible: bool,
    /// Multiple DW_AT_producer strings; mixed compiler toolchains
    ///
    /// More than one distinct DW_AT_producer string in the binary —
    /// multiple compilers contributed to a single output. Normal in
    /// some legitimate cases (Rust calling C); suspicious for vendor
    /// release binaries.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dwarf_mixed_producers: bool,
    /// Multiple DW_AT_comp_dir roots; mixed source directories
    ///
    /// More than one distinct DW_AT_comp_dir directory in the binary —
    /// CUs were compiled from different source roots. Suspicious in
    /// vendor releases that should have a single canonical build root.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dwarf_mixed_comp_dirs: bool,
    /// Fat binary slices differ in code-signature presence
    ///
    /// Mach-O fat binary where some slices carry an LC_CODE_SIGNATURE
    /// blob and others don't. Vendors sign all slices uniformly; a
    /// mixed state almost always means tampering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub macho_slice_signing_divergence: bool,
    /// Authenticode cert issued after the COFF build timestamp
    ///
    /// The PE signing cert was *issued* after the binary's
    /// COFF build timestamp (`leaf_not_before > pe.timestamp`).
    /// Almost always means an older binary was repackaged and re-
    /// signed with a newer cert — supply-chain swap signal. Filtered
    /// against deterministic-build (REPRO) timestamps which can
    /// legitimately appear in the future.
    #[serde(default, skip_serializing_if = "is_false")]
    pub cert_issued_after_build: bool,
    /// Cert signer org absent from PDB path components
    ///
    /// No word from the Authenticode `primary_signer` organization
    /// appears as a path component in the PDB path. For vendor
    /// binaries the build environment and the signing identity share
    /// a common brand name; divergence (e.g. "Ubisoft" cert signing
    /// a binary whose PDB path says "Unity Technologies") is a strong
    /// supply-chain swap signal.  Only set when both fields are
    /// present and the signer is non-platform (not Microsoft/Windows).
    #[serde(default, skip_serializing_if = "is_false")]
    pub cert_org_pdb_mismatch: bool,
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
    /// Virtual entry point address
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub entry_point: u64,
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
    pub install_name_present: bool,
    /// Dynamic linker load command present
    #[serde(default, skip_serializing_if = "is_false")]
    pub dylinker_present: bool,

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
            executable_sections: 2,
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
            high_complexity_funcs: 5,
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
            icon_count: 5,
            version_info_present: true,
            manifest_present: true,
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
        assert!(!metrics.coff_symbol_table_present);
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
    fn test_pe_metrics_batch_defaults_false_or_zero() {
        let m = PeMetrics::default();
        assert!(!m.section_count_mismatch);
        assert_eq!(m.section_overlap_count, 0);
        assert!(m.overlapping_sections.is_empty());
        assert_eq!(m.first_section_gap_bytes, 0);
        assert!(!m.entry_in_last_section);
        assert_eq!(m.bss_like_section_count, 0);
        assert!(!m.dotnet_has_native_entry);
        assert!(!m.import_directory_outside_section);
        assert!(!m.export_directory_outside_section);
        assert!(!m.resource_directory_overruns_section);
        assert_eq!(m.tls_callbacks_outside_code, 0);
        assert!(!m.leaf_eku_code_signing);
        assert!(m.leaf_signature_algorithm.is_none());
        assert!(!m.has_nested_signature);
        assert!(m.authentihash.is_none());
        assert_eq!(m.signature_overlay_padding_bytes, 0);
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
    fn test_consistency_cert_org_pdb_mismatch_default_false() {
        let metrics = ConsistencyMetrics::default();
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
