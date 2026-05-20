//! Composite scoring metrics and unified metrics container

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::binary_metrics::{BinaryMetrics, ElfMetrics, JavaClassMetrics, MachoMetrics, PeMetrics};
use super::{is_zero_f32, is_zero_u32};

// =============================================================================
// UNIFIED METRICS SYSTEM
// =============================================================================

/// Unified metrics container - all measurements in one place
/// Sections are only present when applicable to the file type
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct Metrics {
    // File-level metrics (`file.size`) flow through
    // `AnalysisReport::expose_metrics` rather than a typed sub-struct.

    // === Universal text metrics (all text files) ===
    // `text.*`, `identifiers.*`, `strings.*`, `comments.*`, `functions.*`,
    // `statements.*`, `imports.*`, `encoded.*` all flow through
    // `AnalysisReport::expose_metrics` (the flat metric map). The typed
    // sub-fields were dropped in #41 — `analyzers::unified` flattens
    // its in-memory builders into expose_metrics directly. The struct
    // definitions (`TextMetrics`, `IdentifierMetrics`, …) survive as
    // producer-side builders and as the canonical field-path manifest
    // surfaced through `field_paths::all_valid_metric_paths`.

    // Language-specific metric sub-fields (`python`, `javascript`,
    // `powershell`, `shell`, `php`, `ruby`, `perl`, `go_metrics`,
    // `rust_metrics`, `c_metrics`, `java`, `lua`, `csharp`) retired
    // — all were typed marker structs with zero production
    // producers (#41). If language-specific metrics get wired,
    // they flow through `AnalysisReport::expose_metrics` under
    // `<language>.*` keys.

    // === Binary-specific metrics ===
    /// Cross-format binary metrics (entropy, imports, strings)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<BinaryMetrics>,
    /// ELF-specific metrics (only for ELF files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elf: Option<ElfMetrics>,
    /// PE-specific metrics (only for PE files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeMetrics>,
    /// Mach-O-specific metrics (only for Mach-O files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macho: Option<MachoMetrics>,
    /// Java class file-specific metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_class: Option<JavaClassMetrics>,
    // Container/Archive metrics (`archive.*`, `chm.*`,
    // `package_json.*`) flow through `AnalysisReport::expose_metrics`.
    // ArchiveMetrics is populated by `analyzers::archive::zip::inspect_zip_metadata_from_reader`;
    // chm and package_json metrics come from expose's emission.

    // Image metrics (pixel entropy, histogram, edge density, per-channel
    // entropy, JPEG/PNG format-specific counts) flow through
    // `AnalysisReport::expose_metrics` under `image.*` / `jpeg.*` /
    // `png.*` keys. Populated by analyzers/jpeg.rs and
    // analyzers/png.rs through their `analyze_jpeg_data` /
    // `analyze_png_data` helpers.

    // === Document metrics ===
    // LNK whitespace/presence metrics flow through
    // `AnalysisReport::expose_metrics` under `lnk.*` keys — no typed
    // sub-struct because expose's flat metric map is the source of
    // truth for that surface.
    // Office metrics (cross-format + per-container `ole.*`/`ooxml.*`/
    // `vba.*`/`xlm.*` sub-fields) flow through
    // `AnalysisReport::expose_metrics` under `office.*` dotted keys.
    // Populated by `analyzers/office/mod.rs::populate_*_metrics`.
    // PDF metrics flow through `AnalysisReport::expose_metrics`
    // under `pdf.*` keys — populated by analyzers/pdf via
    // `populate_pdf_metrics`. No typed sub-struct here.

    // `obfuscation`, `packing`, `supply_chain` composite scores
    // retired — they were declared as typed marker structs with
    // zero production producers (#41). If/when composite scoring
    // gets wired, the per-component values flow through
    // `AnalysisReport::expose_metrics` under `obfuscation.*` /
    // `packing.*` / `supply_chain.*` keys.
}

/// Embedded code counts by decoded language and encoding.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct EncodedMetrics {
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xor_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_escape_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub python: Option<EncodedLanguageMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub javascript: Option<EncodedLanguageMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub php: Option<EncodedLanguageMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<EncodedLanguageMetrics>,
}

/// Encoded embedded-code counts for one decoded language.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct EncodedLanguageMetrics {
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xor_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_escape_count: u32,
}

impl EncodedMetrics {
    pub fn increment(&mut self, language: &str, encoding: &str) {
        self.total_count = self.total_count.saturating_add(1);
        self.increment_encoding(encoding);

        let bucket = match language {
            "python" => &mut self.python,
            "javascript" | "typescript" => &mut self.javascript,
            "php" => &mut self.php,
            "shell" => &mut self.shell,
            _ => return,
        };
        let language_metrics = bucket.get_or_insert_with(EncodedLanguageMetrics::default);
        language_metrics.increment(encoding);
    }

    fn increment_encoding(&mut self, encoding: &str) {
        match normalize_encoding(encoding) {
            "base64" => self.base64_count = self.base64_count.saturating_add(1),
            "hex" => self.hex_count = self.hex_count.saturating_add(1),
            "xor" => self.xor_count = self.xor_count.saturating_add(1),
            "url" => self.url_count = self.url_count.saturating_add(1),
            "unicode-escape" => {
                self.unicode_escape_count = self.unicode_escape_count.saturating_add(1)
            }
            _ => {}
        }
    }
}

impl EncodedLanguageMetrics {
    fn increment(&mut self, encoding: &str) {
        self.total_count = self.total_count.saturating_add(1);
        match normalize_encoding(encoding) {
            "base64" => self.base64_count = self.base64_count.saturating_add(1),
            "hex" => self.hex_count = self.hex_count.saturating_add(1),
            "xor" => self.xor_count = self.xor_count.saturating_add(1),
            "url" => self.url_count = self.url_count.saturating_add(1),
            "unicode-escape" => {
                self.unicode_escape_count = self.unicode_escape_count.saturating_add(1)
            }
            _ => {}
        }
    }
}

fn normalize_encoding(encoding: &str) -> &str {
    match encoding {
        "base64-obf" => "base64",
        other => other,
    }
}

// =============================================================================
// COMPOSITE SCORES
// =============================================================================

/// Composite obfuscation score for source code
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct ObfuscationScore {
    /// Overall obfuscation score (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub score: f32,
    /// Confidence in the overall obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Identifier naming obfuscation component score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub naming_score: f32,
    /// String literal obfuscation component score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_score: f32,
    /// Structure obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub structure_score: f32,
    /// Encoding obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub encoding_score: f32,
    /// Dynamic code execution component score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub dynamic_score: f32,

    /// Human-readable contributing signals
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

/// Composite packing score for binaries
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct PackingScore {
    /// Overall packing score (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub score: f32,
    /// Confidence in the overall packing score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Section entropy component score for packing
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub entropy_score: f32,
    /// Import table analysis component score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_score: f32,
    /// String population analysis component score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_score: f32,
    /// Section layout analysis component score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub section_score: f32,

    /// Known packer name if detected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_packer: Option<String>,
    /// Human-readable contributing signals
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

/// Supply chain risk score for packages/archives
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct SupplyChainScore {
    /// Overall risk score (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub score: f32,
    /// Confidence in the overall supply chain score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Risk score from install lifecycle scripts
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub install_script_score: f32,
    /// Risk score from non-registry dependencies
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub dependency_score: f32,
    /// Metadata completeness score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub metadata_score: f32,
    /// Likelihood score for typosquatting attack
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub typosquat_score: f32,

    /// Human-readable contributing signals
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

// =============================================================================
// METRIC VALUE ACCESSOR
// =============================================================================

/// Get a metric value by field path (e.g., "binary.string_count", "text.total_lines")
/// Returns None if the metric doesn't exist or the field path is invalid
///
/// Uses serde_json for dynamic field access instead of hardcoded match statements.
/// A leaf missing from the serialized JSON due to `skip_serializing_if` is treated as 0.0
/// when its parent container exists (common for numeric fields with `is_zero` skips).
#[must_use]
pub(crate) fn get_metric_value(report: &crate::types::AnalysisReport, field: &str) -> Option<f64> {
    if let Some(metrics) = report.metrics.as_ref() {
        if let Some(v) = typed_metric_value(metrics, field) {
            return Some(v);
        }
    }
    // Fall back to expose's flat metric map — see the docstring on
    // `AnalysisReport::expose_metrics` for why this isn't merged into
    // the typed struct above.
    report
        .expose_metrics
        .as_ref()
        .and_then(|m| m.get(field).copied())
}

fn typed_metric_value(metrics: &Metrics, field: &str) -> Option<f64> {
    // Convert metrics to JSON value for dynamic access
    let value = serde_json::to_value(metrics).ok()?;

    // Split field path into components (e.g., "binary.string_count" -> ["binary", "string_count"])
    let parts: Vec<&str> = field.split('.').collect();

    // Navigate through all but the last component — parent path must exist.
    let (last, parents) = parts.split_last()?;
    let mut current = &value;
    for part in parents {
        current = current.get(part)?;
    }

    // Leaf lookup: a missing leaf under an existing object parent means the numeric
    // field was skipped by `skip_serializing_if = "is_zero_*"` — treat it as 0.0
    // only when the parent struct itself is present and non-empty (so we don't
    // shadow expose's flat-map fallback for namespaces cleave never populates).
    match current.get(last) {
        Some(serde_json::Value::Number(n)) => n.as_f64(),
        Some(serde_json::Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
        None if current.is_object() && current.as_object().is_some_and(|o| !o.is_empty()) => {
            Some(0.0)
        }
        Some(_) | None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Metrics Default Tests ====================

    #[test]
    fn test_metrics_default() {
        let metrics = Metrics::default();
        assert!(metrics.binary.is_none());
    }

    #[test]
    fn test_metrics_with_binary() {
        let metrics = Metrics {
            binary: Some(BinaryMetrics::default()),
            elf: Some(ElfMetrics::default()),
            ..Default::default()
        };
        assert!(metrics.binary.is_some());
        assert!(metrics.elf.is_some());
        assert!(metrics.pe.is_none());
    }

    // ==================== ObfuscationScore Default Tests ====================

    #[test]
    fn test_obfuscation_score_default() {
        let score = ObfuscationScore::default();
        assert_eq!(score.score, 0.0);
        assert_eq!(score.conf, 0.0);
        assert!(score.signals.is_empty());
    }

    #[test]
    fn test_obfuscation_score_creation() {
        let score = ObfuscationScore {
            score: 0.75,
            conf: 0.9,
            naming_score: 0.8,
            string_score: 0.6,
            structure_score: 0.5,
            encoding_score: 0.9,
            dynamic_score: 0.7,
            signals: vec!["high entropy identifiers".to_string()],
        };
        assert!((score.score - 0.75).abs() < f32::EPSILON);
        assert!((score.conf - 0.9).abs() < f32::EPSILON);
        assert_eq!(score.signals.len(), 1);
    }

    #[test]
    fn test_obfuscation_score_component_scores() {
        let score = ObfuscationScore {
            naming_score: 0.9,
            string_score: 0.8,
            dynamic_score: 0.95,
            ..Default::default()
        };
        assert!((score.naming_score - 0.9).abs() < f32::EPSILON);
        assert!((score.dynamic_score - 0.95).abs() < f32::EPSILON);
    }

    // ==================== PackingScore Default Tests ====================

    #[test]
    fn test_packing_score_default() {
        let score = PackingScore::default();
        assert_eq!(score.score, 0.0);
        assert!(score.known_packer.is_none());
        assert!(score.signals.is_empty());
    }

    #[test]
    fn test_packing_score_creation() {
        let score = PackingScore {
            score: 0.95,
            conf: 0.85,
            entropy_score: 0.9,
            import_score: 0.8,
            string_score: 0.95,
            section_score: 0.85,
            known_packer: Some("UPX".to_string()),
            signals: vec!["high entropy".to_string(), "few imports".to_string()],
        };
        assert!((score.score - 0.95).abs() < f32::EPSILON);
        assert_eq!(score.known_packer, Some("UPX".to_string()));
        assert_eq!(score.signals.len(), 2);
    }

    #[test]
    fn test_packing_score_without_known_packer() {
        let score = PackingScore {
            score: 0.6,
            conf: 0.5,
            entropy_score: 0.7,
            ..Default::default()
        };
        assert!(score.known_packer.is_none());
    }

    // ==================== SupplyChainScore Default Tests ====================

    #[test]
    fn test_supply_chain_score_default() {
        let score = SupplyChainScore::default();
        assert_eq!(score.score, 0.0);
        assert!(score.signals.is_empty());
    }

    #[test]
    fn test_supply_chain_score_creation() {
        let score = SupplyChainScore {
            score: 0.8,
            conf: 0.9,
            install_script_score: 0.95,
            dependency_score: 0.6,
            metadata_score: 0.3,
            typosquat_score: 0.7,
            signals: vec!["suspicious install script".to_string()],
        };
        assert!((score.score - 0.8).abs() < f32::EPSILON);
        assert!((score.install_script_score - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_supply_chain_score_component_scores() {
        let score = SupplyChainScore {
            install_script_score: 0.9,
            dependency_score: 0.5,
            typosquat_score: 0.85,
            ..Default::default()
        };
        assert!((score.typosquat_score - 0.85).abs() < f32::EPSILON);
        assert_eq!(score.metadata_score, 0.0);
    }

    #[test]
    fn test_supply_chain_score_signals() {
        let score = SupplyChainScore {
            signals: vec![
                "postinstall script".to_string(),
                "typosquat candidate".to_string(),
                "missing repository".to_string(),
            ],
            ..Default::default()
        };
        assert_eq!(score.signals.len(), 3);
    }
}
