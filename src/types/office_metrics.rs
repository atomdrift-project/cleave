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

/// Cross-format Microsoft Office metrics.
///
/// Populated for both legacy OLE2 (`.doc`/`.xls`/`.ppt`) and OOXML
/// (`.docx`/`.xlsx`/`.pptx` and their `*m` macro-enabled variants).
/// The `ole`/`ooxml` sub-structs hold container-format-specific counts; the
/// fields directly on `OfficeMetrics` are valid for either.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct OfficeMetrics {
    // === Type discrimination ===
    /// File-extension-derived document type (e.g., `docm`, `xlsb`, `pps`).
    /// Distinct from `target.file_type`, which collapses macro-enabled
    /// variants. Empty when the analyzer could not classify the extension.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub doc_type: String,

    /// True when the file extension implies macro support (`*m`, `xla`,
    /// `xll`, `xlsb`). Independent of whether macros are actually present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_macro_enabled_extension: bool,

    /// True when macros (VBA modules or XLM macrosheets) are present.
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_macros: bool,

    /// True when the document is encrypted (OLE EncryptionInfo or OOXML
    /// /EncryptionInfo).
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_encrypted: bool,

    // === Top-level VBA presence ===
    /// Number of decompressed VBA modules across all macro projects.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub vba_module_count: u32,
    /// Total VBA source size in bytes after MS-OVBA decompression.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub vba_source_size: u64,

    // === Embedded payloads ===
    /// Embedded PE/ELF executables found in OLE streams or OOXML entries.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_executable_count: u32,
    /// OLE10Native embedded objects (file droppers).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ole10_native_count: u32,
    /// Embedded OLE objects (Equation Editor, Packager, Excel workbooks).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_ole_count: u32,

    // === External references ===
    /// External relationships of any kind (template, image, OLE, frame…).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub external_ref_count: u32,
    /// External attachedTemplate relationships (template-injection vector).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub external_template_count: u32,
    /// External oleObject relationships (remote OLE link).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub external_oleobject_count: u32,
    /// External frame/subDocument relationships.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub external_frame_count: u32,
    /// External image relationships (HTTP-fetched lure imagery).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub external_image_count: u32,

    // === DDE ===
    /// DDE field codes detected in document body XML.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dde_link_count: u32,

    // === Sub-metrics (container-format-specific) ===
    /// OLE2-specific metrics (CompObj, SummaryInformation, stream stats).
    /// Populated for legacy formats (`.doc`, `.xls`, `.ppt`, `.msg`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ole: Option<OleMetrics>,

    /// OOXML-specific metrics (ZIP entry stats, content-type flags).
    /// Populated for modern formats (`.docx`, `.xlsx`, `.pptx` and `*m`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ooxml: Option<OoxmlMetrics>,

    /// VBA project aggregate counts (Declare/CreateObject frequency).
    /// Populated when one or more VBA modules are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vba: Option<VbaMetrics>,

    /// Excel 4.0 (XLM) macrosheet counts.
    /// Populated when an XLM macrosheet is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xlm: Option<XlmMetrics>,
}

/// OLE2 / Compound File Binary specific metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct OleMetrics {
    // === Stream topology ===
    /// Total OLE stream count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_count: u32,
    /// Total OLE storage (directory) count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub storage_count: u32,
    /// Largest stream size in bytes.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub max_stream_size: u64,
    /// Storages bearing a CLSID matched against the dangerous-CLSID list
    /// (Equation Editor 3.0, Package, Forms2, etc.).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dangerous_clsid_count: u32,

    // === CompObj (\x01CompObj stream) ===
    /// `user_type` from CompObj (e.g., `Microsoft Office Excel Worksheet`).
    /// High-value fake-extension signal when it disagrees with the file
    /// extension.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compobj_user_type: String,
    /// `clipboard_format` from CompObj (e.g., `Biff8`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compobj_clipboard_format: String,
    /// `app_version` ProgID from CompObj (e.g., `Excel.Sheet.8`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compobj_app_version: String,

    // === SummaryInformation ===
    /// `PIDSI_PAGECOUNT` — page count. Zero on freshly-built lures.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub page_count: u32,
    /// `PIDSI_WORDCOUNT` — word count. Low values on lures.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub word_count: u32,
    /// `PIDSI_CHARCOUNT` — character count.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_count: u32,
    /// `PIDSI_REVNUMBER` — revision number (Word stores this as a string;
    /// we parse the leading integer). Zero when missing or unparseable.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub revision_number: u32,
    /// `PIDSI_EDITTIME` — total edit time in minutes. Lures often have 0.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_edit_time_minutes: u64,

    // === DocumentSummaryInformation ===
    /// `PIDDSI_SECURITY` — security flag. Bit 0 = password protected, bit 1
    /// = recommend read-only, bit 2 = enforced read-only, bit 3 = locked.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub security_flag: u32,
    /// Custom property count from DocumentSummaryInformation user-defined
    /// dictionary (sometimes used as C2 config storage).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub custom_property_count: u32,
    /// Hyperlink count from `OleReservedProperties.pid_hlinks`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hyperlink_count: u32,
}

/// OOXML / ZIP container metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct OoxmlMetrics {
    // === ZIP topology ===
    /// Total ZIP entry count.
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
    /// ZIP entries whose extension is suspicious in an Office document
    /// (`.exe`, `.dll`, `.hta`, `.lnk`, `.bat`, `.js`, `.scr`, `.vbs`).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub suspicious_extension_count: u32,

    // === Content-Types declarations ===
    /// `application/vnd.ms-*.macroEnabled.*` declared in `[Content_Types].xml`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub declares_macro_enabled: bool,
    /// `application/vnd.ms-office.vbaProject` declared.
    #[serde(default, skip_serializing_if = "is_false")]
    pub declares_vba_project: bool,
    /// `application/vnd.ms-excel.macrosheet+xml` (XLM) declared.
    #[serde(default, skip_serializing_if = "is_false")]
    pub declares_macrosheet: bool,
}

/// VBA project aggregate counts.
///
/// Populated by the VBA symbol extractor (Phase 1) by walking the decoded
/// modules and tallying Declare imports, CreateObject calls, and trigger
/// handlers. The structure mirrors maldoca's `VbaFeature` proto in spirit
/// but uses fixed-name fields instead of enum-keyed maps so the
/// `type: metrics, field: office.vba.<name>` syntax works.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct VbaMetrics {
    // === Declare statements ===
    /// Total `Declare [PtrSafe] Function|Sub` count across modules.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub declare_count: u32,
    /// `Declare` statements whose `Lib` clause is not a string literal
    /// (string-built at runtime — strong obfuscation signal).
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
    /// Total `CreateObject(...)` invocations (literal or non-literal).
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
    /// Distinct ProgID strings observed in `CreateObject`/`GetObject`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub distinct_progid_count: u32,

    // === Trigger handlers (Auto_*, Document_*, Workbook_*, UserForm_*) ===
    /// Auto-execution trigger sub count (Auto_Open, AutoOpen, Auto_Close,
    /// Document_Open, Document_New, Document_Close, Workbook_Open,
    /// Workbook_BeforeClose, Workbook_Activate, UserForm_Activate, etc.).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trigger_handler_count: u32,
    /// Distinct trigger event types observed (>=3 mixes lifecycle paths,
    /// a known dropper pattern).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub distinct_trigger_count: u32,

    // === Module-shape signals ===
    /// Modules whose names look randomly generated
    /// (`[A-Za-z][A-Za-z0-9]{7,}` with high digit/case mixing).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub random_named_module_count: u32,
    /// Total VBA logical lines (after joining `_` continuations, before
    /// stripping comments).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_logical_lines: u32,
    /// Comment lines across all modules.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comment_lines: u32,
    /// Mean character count of declared identifiers (Sub/Function/Dim).
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub mean_identifier_length: f32,
    /// Shannon entropy (bits) of identifier characters across all modules
    /// — high values indicate randomized renaming.
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
pub struct XlmMetrics {
    /// `FORMULA.FILL(` occurrences — runtime cell-write obfuscation.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub formula_fill_count: u32,
    /// `RUN(` occurrences — XLM dispatch chains.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub run_count: u32,
    /// `CHAR(` occurrences — dense character-code obfuscation.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_count: u32,
    /// `GET.CELL(` occurrences — style-keyed branching / sandbox detection.
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

    /// `OfficeMetrics::default()` must round-trip through serde producing an
    /// empty JSON object — every field is `skip_serializing_if`-guarded.
    #[test]
    fn default_serializes_empty() {
        let metrics = OfficeMetrics::default();
        let json = serde_json::to_string(&metrics).unwrap();
        assert_eq!(json, "{}");
    }

    /// Populating one nested struct serializes only that path.
    #[test]
    fn populated_xlm_only_serializes_xlm() {
        let metrics = OfficeMetrics {
            xlm: Some(XlmMetrics {
                char_count: 250,
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_value(&metrics).unwrap();
        assert!(json.get("xlm").is_some());
        assert!(json.get("ole").is_none());
        assert!(json.get("ooxml").is_none());
        assert!(json.get("vba").is_none());
        assert_eq!(json["xlm"]["char_count"], 250);
    }

    /// Doc-type discrimination round-trips.
    #[test]
    fn doc_type_string_roundtrip() {
        let metrics = OfficeMetrics {
            doc_type: "docm".into(),
            is_macro_enabled_extension: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let back: OfficeMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.doc_type, "docm");
        assert!(back.is_macro_enabled_extension);
    }
}
