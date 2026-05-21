//! Composite scoring metrics and the encoded-payload counter.
//!
//! The unified `Metrics` container retired with the typed
//! PE/ELF/Mach-O/Binary metric projections — every numeric metric
//! now flows through `AnalysisReport::expose_metrics` under its
//! dotted-key namespace.

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::{is_zero_f32, is_zero_u32};

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

/// Get a metric value by field path (e.g., "binary.string_count", "text.total_lines").
/// Returns `None` if the metric doesn't exist. Reads exclusively from expose's
/// flat metric map; cleave-side typed metric projections have been retired.
#[must_use]
pub(crate) fn get_metric_value(report: &crate::types::AnalysisReport, field: &str) -> Option<f64> {
    report
        .expose_metrics
        .as_ref()
        .and_then(|m| m.get(field).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

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
