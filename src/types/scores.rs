//! Composite scoring metrics and unified metrics container

use cleave_macros::ValidFieldPaths;
use serde::{Deserialize, Serialize};

use super::binary_metrics::{BinaryMetrics, ElfMetrics, JavaClassMetrics, MachoMetrics, PeMetrics};
use super::container_metrics::{ArchiveMetrics, PackageJsonMetrics};
use super::is_zero_f32;
use super::jpeg_metrics::JpegMetrics;
use super::language_metrics::{
    CMetrics, CSharpMetrics, GoMetrics, JavaScriptMetrics, JavaSourceMetrics, LuaMetrics,
    PerlMetrics, PhpMetrics, PowerShellMetrics, PythonMetrics, RubyMetrics, RustMetrics,
    ShellMetrics,
};
use super::png_metrics::PngMetrics;
use super::text_metrics::{
    CommentMetrics, FunctionMetrics, IdentifierMetrics, ImportMetrics, StatementMetrics,
    StringMetrics, TextMetrics,
};

// =============================================================================
// UNIFIED METRICS SYSTEM
// =============================================================================

/// Unified metrics container - all measurements in one place
/// Sections are only present when applicable to the file type
#[derive(Debug, Clone, Serialize, Deserialize, Default, ValidFieldPaths)]
pub struct Metrics {
    // === Universal text metrics (all text files) ===
    /// Line counts and basic text statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextMetrics>,
    /// Identifier (variable/function name) statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifiers: Option<IdentifierMetrics>,
    /// String literal statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<StringMetrics>,
    /// Comment density and coverage metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<CommentMetrics>,
    /// Function complexity and size metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<FunctionMetrics>,
    /// Statement type distribution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statements: Option<StatementMetrics>,
    /// Import/dependency metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<ImportMetrics>,

    // === Language-specific metrics (mutually exclusive) ===
    /// Python-specific metrics (only for Python files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub python: Option<PythonMetrics>,
    /// JavaScript-specific metrics (only for JS/TS files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub javascript: Option<JavaScriptMetrics>,
    /// PowerShell-specific metrics (only for PS1 files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub powershell: Option<PowerShellMetrics>,
    /// Shell script-specific metrics (only for shell scripts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<ShellMetrics>,
    /// PHP-specific metrics (only for PHP files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub php: Option<PhpMetrics>,
    /// Ruby-specific metrics (only for Ruby files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruby: Option<RubyMetrics>,
    /// Perl-specific metrics (only for Perl files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perl: Option<PerlMetrics>,
    /// Go-specific metrics (only for Go files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_metrics: Option<GoMetrics>,
    /// Rust-specific metrics (only for Rust files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rust_metrics: Option<RustMetrics>,
    /// C-specific metrics (only for C files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_metrics: Option<CMetrics>,
    /// Java source-specific metrics (only for Java source files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java: Option<JavaSourceMetrics>,
    /// Lua-specific metrics (only for Lua files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lua: Option<LuaMetrics>,
    /// C#-specific metrics (only for C# files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csharp: Option<CSharpMetrics>,

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

    // === Container/Archive metrics ===
    /// Archive file metrics (zip, tar, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<ArchiveMetrics>,
    /// npm package.json metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_json: Option<PackageJsonMetrics>,

    // === Image metrics ===
    /// JPEG image metrics for steganography detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jpeg: Option<JpegMetrics>,
    /// PNG image metrics for steganography detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub png: Option<PngMetrics>,

    // === Composite scores ===
    /// Composite obfuscation score with component breakdown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<ObfuscationScore>,
    /// Composite packing score with component breakdown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packing: Option<PackingScore>,
    /// Composite supply chain risk score with component breakdown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supply_chain: Option<SupplyChainScore>,
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
    /// Confidence in the score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Naming obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub naming_score: f32,
    /// String obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_score: f32,
    /// Structure obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub structure_score: f32,
    /// Encoding obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub encoding_score: f32,
    /// Dynamic execution score
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
    /// Confidence in the score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Entropy-based score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub entropy_score: f32,
    /// Import analysis score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_score: f32,
    /// String analysis score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_score: f32,
    /// Section analysis score
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
    /// Confidence in the score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Install script risk
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub install_script_score: f32,
    /// Dependency risk
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub dependency_score: f32,
    /// Metadata completeness score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub metadata_score: f32,
    /// Typosquatting risk
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
/// Uses serde_json for dynamic field access instead of hardcoded match statements
#[allow(dead_code)] // Used by binary target
#[must_use]
pub(crate) fn get_metric_value(metrics: &Metrics, field: &str) -> Option<f64> {
    // Convert metrics to JSON value for dynamic access
    let value = serde_json::to_value(metrics).ok()?;

    // Split field path into components (e.g., "binary.string_count" -> ["binary", "string_count"])
    let parts: Vec<&str> = field.split('.').collect();

    // Navigate through the JSON structure
    let mut current = &value;
    for part in parts {
        current = current.get(part)?;
    }

    // Convert to f64 based on JSON type
    match current {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Metrics Default Tests ====================

    #[test]
    fn test_metrics_default() {
        let metrics = Metrics::default();
        assert!(metrics.text.is_none());
        assert!(metrics.binary.is_none());
        assert!(metrics.python.is_none());
        assert!(metrics.obfuscation.is_none());
    }

    #[test]
    fn test_metrics_with_text() {
        let metrics = Metrics {
            text: Some(TextMetrics::default()),
            ..Default::default()
        };
        assert!(metrics.text.is_some());
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

    #[test]
    fn test_metrics_with_language() {
        let metrics = Metrics {
            python: Some(PythonMetrics::default()),
            ..Default::default()
        };
        assert!(metrics.python.is_some());
        assert!(metrics.javascript.is_none());
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
