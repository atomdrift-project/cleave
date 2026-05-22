//! Microsoft Office document derived metrics.
//!
//! Cross-format metrics live on [`OfficeMetrics`]; container-specific counts
//! live on [`OleMetrics`] (legacy OLE2/CFBF) and [`OoxmlMetrics`] (modern
//! OOXML/ZIP). Macro-language aggregates live on [`VbaMetrics`] and
//! [`XlmMetrics`]. All sub-structs are queryable via
//! `type: metrics, field: office.*` etc., mirroring how `binary.*`, `lnk.*`,
//! and `archive.*` are exposed today.
//!
//! Population is incremental — analyzer hooks land in later phases and
//! progressively fill these fields. Consumers must tolerate any field being
//! zero/false (the `skip_serializing_if` helpers already drop empties from
//! JSON output).

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32, is_zero_u64};

// `OfficeMetrics` retired — cross-format office fields
// (`doc_type`, `has_macros`, `external_*_count`, etc.) flow through
// `AnalysisReport::filefacts_metrics` under `office.*` dotted keys.
// The container-format sub-structs (Ole/Ooxml/Vba/Xlm) below
// remain as crate-internal data carriers that analyzer parsers
// build then flatten via `flatten_into_metrics`.

/// OLE2 / Compound File Binary specific metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub(crate) struct OleMetrics {
    // === Stream topology ===
    /// Total number of OLE streams in the document
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_count: u32,
    /// Total OLE storage (directory) count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub storage_count: u32,
    /// Largest stream size in bytes.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub max_stream_size: u64,
    /// Storages with a dangerous CLSID (e.g. Equation Editor)
    ///
    /// (Equation Editor 3.0, Package, Forms2, etc.).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dangerous_clsid_count: u32,

    // === CompObj (\x01CompObj stream) ===
    /// CompObj user_type string from OLE CompObj stream
    ///
    /// (e.g., `Microsoft Office Excel Worksheet`). High-value fake-extension signal when
    /// it disagrees with the file extension.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compobj_user_type: String,
    /// `clipboard_format` from CompObj (e.g., `Biff8`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compobj_clipboard_format: String,
    /// `app_version` ProgID from CompObj (e.g., `Excel.Sheet.8`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compobj_app_version: String,

    // === SummaryInformation ===
    /// Page count from PIDSI_PAGECOUNT summary property
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub page_count: u32,
    /// `PIDSI_WORDCOUNT` — word count. Low values on lures.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub word_count: u32,
    /// `PIDSI_CHARCOUNT` — character count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_count: u32,
    /// Revision number from PIDSI_REVNUMBER summary property
    ///
    /// (Word stores this as a string; we parse the leading integer). Zero when missing or
    /// unparseable.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub revision_number: u32,
    /// Total edit time in minutes from PIDSI_EDITTIME
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_edit_time_minutes: u64,

    // === DocumentSummaryInformation ===
    /// PIDDSI_SECURITY protection flag bitfield
    ///
    /// Bit 0 = password protected, bit 1 = recommend read-only, bit 2 = enforced
    /// read-only, bit 3 = locked.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub security_flag: u32,
    /// Custom property count from DocumentSummaryInformation
    ///
    /// User-defined dictionary (sometimes used as C2 config storage).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub custom_property_count: u32,
    /// Hyperlink count from `OleReservedProperties.pid_hlinks`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hyperlink_count: u32,
}

/// OOXML / ZIP container metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub(crate) struct OoxmlMetrics {
    // === ZIP topology ===
    /// Total number of ZIP entries in the OOXML package
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub entry_count: u32,
    /// Maximum uncompressed entry size in bytes.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub max_entry_size: u64,
    /// Image part count (ppt/media/, word/media/, xl/media/).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub image_part_count: u32,
    /// Embedded binary part count (`*/embeddings/*.bin`).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_part_count: u32,
    /// ZIP entries with suspicious extensions in document
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub suspicious_extension_count: u32,

    // === Content-Types declarations ===
    /// Content_Types.xml declares macro-enabled content
    #[serde(default, skip_serializing_if = "is_false")]
    pub declares_macro_enabled: bool,
    /// `application/vnd.ms-office.vbaProject` declared.
    #[serde(default, skip_serializing_if = "is_false")]
    pub declares_vba_project: bool,
    /// `application/vnd.ms-excel.macrosheet+xml` (XLM) declared.
    #[serde(default, skip_serializing_if = "is_false")]
    pub declares_macrosheet: bool,
    /// Word document with vbaProject.bin present
    ///
    /// `word/vbaProject.bin` is present in the package. Distinct from generic
    /// `office.has_macros` because it's specific to .doc/.docm/.dotm (vs Excel/PowerPoint).
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_word_vba_document: bool,
    /// Document references an external template URL
    ///
    /// Distinct from `office.external_template_count > 0` because some external-template
    /// references are legitimate.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_template_injection: bool,
    /// Document contains a DDE field invoking external commands
    ///
    /// Distinct from generic `office.dde_link_count > 0` because not every DDE link is an
    /// exec command.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_dde_execution: bool,
}

/// VBA project aggregate counts.
///
/// Populated by the VBA symbol extractor (Phase 1) by walking the decoded
/// modules and tallying Declare imports, CreateObject calls, and trigger
/// handlers. The structure mirrors maldoca's `VbaFeature` proto in spirit
/// but uses fixed-name fields instead of enum-keyed maps so the
/// `type: metrics, field: office.vba.<name>` syntax works.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub(crate) struct VbaMetrics {
    // === Declare statements ===
    /// Total `Declare [PtrSafe] Function|Sub` count across modules.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub declare_count: u32,
    /// Declare statements with non-literal Lib clause
    ///
    /// `Declare` statements whose `Lib` clause is not a string literal (string-built at
    /// runtime — strong obfuscation signal).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub declare_non_literal_count: u32,
    /// Distinct DLL names referenced via `Declare ... Lib`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub distinct_dll_count: u32,

    // === Per-DLL reference counts (high-risk subset only) ===
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub kernel32_ref_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub user32_ref_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub advapi32_ref_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub urlmon_ref_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wininet_ref_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ws2_32_ref_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ole32_ref_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell32_ref_count: u32,

    // === CreateObject / GetObject ===
    /// Count of CreateObject calls in VBA modules
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub createobject_count: u32,
    /// `CreateObject` calls whose argument is not a string literal.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub createobject_non_literal_count: u32,
    /// Total `GetObject(...)` invocations.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub getobject_count: u32,
    /// `GetObject` calls with non-literal moniker arg.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub getobject_non_literal_count: u32,
    /// Distinct ProgID strings in CreateObject calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub distinct_progid_count: u32,

    // === Trigger handlers (Auto_*, Document_*, Workbook_*, UserForm_*) ===
    /// Count of auto-execution trigger handler subs
    ///
    /// Auto_Open, AutoOpen, Auto_Close, Document_Open, Document_New, Document_Close,
    /// Workbook_Open, Workbook_BeforeClose, Workbook_Activate, UserForm_Activate, etc.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trigger_handler_count: u32,
    /// Count of distinct auto-exec trigger event types
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub distinct_trigger_count: u32,

    // === Module-shape signals ===
    /// Modules with randomly generated name patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub random_named_module_count: u32,
    /// Total VBA logical lines after joining continuations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_logical_lines: u32,
    /// Comment lines across all modules.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comment_lines: u32,
    /// Mean character length of VBA identifier names
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub mean_identifier_length: f32,
    /// Shannon entropy of identifier characters across VBA
    ///
    /// High values indicate randomized renaming.
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub identifier_entropy: f32,
}

/// Excel 4.0 (XLM) macrosheet metrics.
///
/// Populated when an `xl/macrosheets/sheet*.xml` part is present (OOXML)
/// or when an OLE2 workbook contains `XLEXCEL_*MACRO*` sheets. Fields
/// match the substring-count heuristics already inlined in
/// `office/mod.rs` so traits can express thresholds via `type: metrics,
/// field: office.xlm.*` instead of hard-coded conditionals.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub(crate) struct XlmMetrics {
    /// Count of FORMULA.FILL cell-write XLM calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub formula_fill_count: u32,
    /// `RUN(` occurrences — XLM dispatch chains.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub run_count: u32,
    /// `CHAR(` occurrences — dense character-code obfuscation.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_count: u32,
    /// Count of GET.CELL style-keyed branching calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub get_cell_count: u32,
    /// `DAY(NOW())` occurrences — date-keyed payload gating.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub day_now_count: u32,
    /// `EXEC(` occurrences — direct command execution.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// `REGISTER(` occurrences — DLL function registration.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub register_count: u32,
    /// `CALL(` occurrences — direct DLL invocation.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_count: u32,
    /// Sheets with `state="veryHidden"` attribute.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_hidden_sheet_count: u32,
    /// `_xlnm.Auto_open` defined-name occurrences.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub auto_open_name_count: u32,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The remaining sub-struct carriers (Ole/Ooxml/Vba/Xlm) still
    /// round-trip through serde producing empty JSON for the
    /// default value — every field is `skip_serializing_if`-guarded.
    /// Cross-format `office.*` lifecycle moved to
    /// `analyzers/office/mod.rs::populate_*_metrics` tests.
    #[test]
    fn default_sub_structs_serialize_empty() {
        assert_eq!(serde_json::to_string(&OleMetrics::default()).unwrap(), "{}");
        assert_eq!(
            serde_json::to_string(&OoxmlMetrics::default()).unwrap(),
            "{}"
        );
        assert_eq!(serde_json::to_string(&VbaMetrics::default()).unwrap(), "{}");
        assert_eq!(serde_json::to_string(&XlmMetrics::default()).unwrap(), "{}");
    }

    /// Populated XLM serializes the populated field.
    #[test]
    fn populated_xlm_serializes() {
        let xlm = XlmMetrics {
            char_count: 250,
            ..Default::default()
        };
        let json = serde_json::to_value(&xlm).unwrap();
        assert_eq!(json["char_count"], 250);
    }
}
