//! Code structure metrics and idioms

use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_f64, is_zero_u32, is_zero_u64};

/// Binary-wide properties for ML analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryProperties {
    /// Security features present/absent
    pub security: SecurityFeatures,
    /// Linking and dependencies
    pub linking: LinkingInfo,
    /// Anomalies detected
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<BinaryAnomaly>,
}

/// Security hardening features
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityFeatures {
    /// Stack canary present
    #[serde(default, skip_serializing_if = "is_false")]
    pub canary: bool,
    /// No-execute (NX/DEP) enabled
    #[serde(default, skip_serializing_if = "is_false")]
    pub nx: bool,
    /// Position independent code
    #[serde(default, skip_serializing_if = "is_false")]
    pub pic: bool,
    /// RELRO protection level (none, partial, full)
    #[serde(default)]
    pub relro: String,
    /// Binary is stripped
    #[serde(default, skip_serializing_if = "is_false")]
    pub stripped: bool,
    /// Uses cryptographic functions
    #[serde(default, skip_serializing_if = "is_false")]
    pub uses_crypto: bool,
    /// Code signature present
    #[serde(default, skip_serializing_if = "is_false")]
    pub signed: bool,
}

/// Binary linking information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinkingInfo {
    /// Statically linked
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_static: bool,
    /// Dynamic libraries used
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libraries: Vec<String>,
    /// RPATH/RUNPATH settings
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpath: Vec<String>,
}

/// Structural anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryAnomaly {
    /// Anomaly type (no_section_header, overlapping_functions, etc)
    pub anomaly_type: String,
    /// Description
    pub desc: String,
    /// Severity (low, medium, high)
    pub severity: String,
}

/// Overlay/appended data metrics for supply chain attack detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OverlayMetrics {
    /// Size of overlay in bytes
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub size_bytes: u64,
    /// Overlay as ratio of total file size (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub ratio_of_file: f64,
    /// Average entropy of overlay data
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub avg_entropy: f64,
    /// Variance in entropy across chunks (indicates mixed content)
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub entropy_variance: f64,
    /// Count of embedded files found via magic bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_file_count: u32,
    /// Types of embedded files found (zstd, gzip, elf, etc)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedded_for: Vec<String>,
    /// Offset where overlay begins
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub overlay_start: u64,
    /// Suspicion score (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub suspicion_score: f64,
}

/// Aggregate code metrics across entire binary
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeMetrics {
    /// Total number of functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_functions: u32,
    /// Total basic blocks across all functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_basic_blocks: u32,
    /// Average cyclomatic complexity
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_complexity: f32,
    /// Maximum complexity seen
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_complexity: u32,
    /// Total instruction count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_instructions: u32,
    /// Code-to-data ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_density: f32,
    /// Functions with loops
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub functions_with_loops: u32,
    /// Functions with unusual patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub functions_with_anomalies: u32,
}

/// Source code metrics for scripts (Python, JavaScript, etc.)
/// Useful for ML analysis and behavioral profiling
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceCodeMetrics {
    /// Total lines in file
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_lines: u32,
    /// Lines of code (excluding blanks and comments)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_lines: u32,
    /// Comment lines (including inline and block comments)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comment_lines: u32,
    /// Blank lines
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub blank_lines: u32,
    /// Docstring lines
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub docstring_lines: u32,

    // Comment density metrics
    /// Ratio of comments to code (comment_lines / code_lines)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub comment_to_code_ratio: f32,
    /// Ratio of comments to total lines
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub comment_density: f32,

    // String metrics
    /// Total number of string literals
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_count: u32,
    /// Average string length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_length: f32,
    /// Maximum string length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_string_length: u32,
    /// Average string entropy (0.0-8.0, higher = more random/obfuscated)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_entropy: f32,
    /// String density (strings per line of code)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_density: f32,

    // Function metrics
    /// Total number of functions/methods defined
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub function_count: u32,
    /// Average function size in lines
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_function_size: f32,
    /// Maximum function size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_function_size: u32,

    // Import metrics
    /// Total import statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub import_count: u32,
    /// Standard library imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stdlib_imports: u32,
    /// Third-party imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub third_party_imports: u32,
    /// Local/relative imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_imports: u32,

    // Complexity indicators
    /// Lines with eval/execution/compile
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynamic_execution_count: u32,
    /// Obfuscation indicators (base64, hex strings, etc.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub obfuscation_indicators: u32,
    /// High-entropy strings (entropy > 5.0)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_strings: u32,

    // Code structure (Phase 2)
    /// Code structure metrics
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code_structure: Option<CodeStructureMetrics>,

    // Language-specific idioms (Phase 3)
    /// Python-specific idioms
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub python_idioms: Option<PythonIdioms>,

    /// JavaScript-specific idioms
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub javascript_idioms: Option<JavaScriptIdioms>,

    /// Shell script idioms
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub shell_idioms: Option<ShellIdioms>,

    /// Go idioms
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub go_idioms: Option<GoIdioms>,
}

/// Code structure metrics for ML analysis (Phase 2)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeStructureMetrics {
    /// Global variables defined
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub global_var_count: u32,
    /// Class definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Maximum inheritance depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_inheritance_depth: u32,
    /// Try/except blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exception_handler_count: u32,
    /// Empty except blocks (suspicious - error suppression)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_except_count: u32,
    /// Assert statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assert_count: u32,
    /// Main guard present (if __name__ == "__main__":)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_main_guard: bool,
    /// Assignment statements (variable definitions)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assignment_count: u32,
}

/// Python-specific language idioms (Phase 3)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PythonIdioms {
    /// List/dict/set comprehensions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comprehension_count: u32,
    /// Generator expressions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub generator_expression_count: u32,
    /// Context managers (with statements)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub context_manager_count: u32,
    /// Lambda functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lambda_count: u32,
    /// Async/await usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub async_count: u32,
    /// Yield statements (generators)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub yield_count: u32,
    /// Class definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Dunder methods (__init__, __str__, etc.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dunder_method_count: u32,
    /// Total decorator usage (all contexts)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_decorator_count: u32,
    /// F-strings (formatted string literals)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fstring_count: u32,
    /// Walrus operator usage (:=)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub walrus_operator_count: u32,
}

/// JavaScript-specific language idioms
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JavaScriptIdioms {
    /// Arrow functions (=>)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arrow_function_count: u32,
    /// Promise usage (new Promise, .then, .catch)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub promise_count: u32,
    /// Async/await usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub async_await_count: u32,
    /// Template literals (`string ${expr}`)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub template_literal_count: u32,
    /// Destructuring assignments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub destructuring_count: u32,
    /// Spread operator usage (...)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub spread_operator_count: u32,
    /// Class definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Callback patterns (function passed as argument)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub callback_count: u32,
    /// IIFE (Immediately Invoked Function Expression)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub iife_count: u32,
    /// Object literal shorthand
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub object_shorthand_count: u32,
    /// Optional chaining (?.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub optional_chaining_count: u32,
    /// Nullish coalescing (??)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nullish_coalescing_count: u32,
}

/// Shell script specific idioms
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShellIdioms {
    /// Pipe usage (|)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pipe_count: u32,
    /// Output redirections (>, >>)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub redirect_count: u32,
    /// Input redirections (<, <<)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub input_redirect_count: u32,
    /// Command substitutions ($(), backticks)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub command_substitution_count: u32,
    /// Here documents (<<EOF)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub heredoc_count: u32,
    /// Case statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub case_statement_count: u32,
    /// Test expressions ([ ], [[ ]], test)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub test_expression_count: u32,
    /// While read loops
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub while_read_count: u32,
    /// Subshells (commands in parentheses)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub subshell_count: u32,
    /// For loops
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub for_loop_count: u32,
    /// Background jobs (&)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub background_job_count: u32,
    /// Process substitution (<(), >())
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub process_substitution_count: u32,
}

/// Go-specific language idioms
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GoIdioms {
    /// Goroutine launches (go keyword)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub goroutine_count: u32,
    /// Channel operations (chan, <-)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub channel_count: u32,
    /// Defer statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub defer_count: u32,
    /// Select statements (channel multiplexing)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub select_statement_count: u32,
    /// Interface type assertions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_assertion_count: u32,
    /// Method declarations (with receivers)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_count: u32,
    /// Interface definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub interface_count: u32,
    /// Range loops (for...range)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub range_loop_count: u32,
    /// Error handling returns (func ... error)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub error_return_count: u32,
    /// Panic/recover usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub panic_recover_count: u32,
    /// CGo usage (import "C")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cgo_count: u32,
    /// Unsafe pointer operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== SecurityFeatures Tests ====================

    #[test]
    fn test_security_features_default() {
        let features = SecurityFeatures::default();
        assert!(!features.canary);
        assert!(!features.nx);
        assert!(!features.stripped);
    }

    #[test]
    fn test_security_features_creation() {
        let features = SecurityFeatures {
            canary: true,
            nx: true,
            pic: true,
            relro: "full".to_string(),
            stripped: false,
            uses_crypto: true,
            signed: true,
        };
        assert!(features.canary);
        assert!(features.nx);
        assert_eq!(features.relro, "full");
    }

    // ==================== LinkingInfo Tests ====================

    #[test]
    fn test_linking_info_default() {
        let info = LinkingInfo::default();
        assert!(!info.is_static);
        assert!(info.libraries.is_empty());
    }

    #[test]
    fn test_linking_info_creation() {
        let info = LinkingInfo {
            is_static: false,
            libraries: vec!["libc.so.6".to_string(), "libm.so.6".to_string()],
            rpath: vec!["/usr/lib".to_string()],
        };
        assert_eq!(info.libraries.len(), 2);
        assert_eq!(info.rpath.len(), 1);
    }

    // ==================== BinaryAnomaly Tests ====================

    #[test]
    fn test_binary_anomaly_default() {
        let anomaly = BinaryAnomaly::default();
        assert!(anomaly.anomaly_type.is_empty());
    }

    #[test]
    fn test_binary_anomaly_creation() {
        let anomaly = BinaryAnomaly {
            anomaly_type: "overlapping_sections".to_string(),
            desc: "Sections overlap in memory".to_string(),
            severity: "high".to_string(),
        };
        assert_eq!(anomaly.anomaly_type, "overlapping_sections");
        assert_eq!(anomaly.severity, "high");
    }

    // ==================== BinaryProperties Tests ====================

    #[test]
    fn test_binary_properties_default() {
        let props = BinaryProperties::default();
        assert!(props.anomalies.is_empty());
    }

    #[test]
    fn test_binary_properties_creation() {
        let props = BinaryProperties {
            security: SecurityFeatures {
                nx: true,
                canary: true,
                ..Default::default()
            },
            linking: LinkingInfo {
                is_static: false,
                libraries: vec!["libc.so.6".to_string()],
                ..Default::default()
            },
            anomalies: vec![],
        };
        assert!(props.security.nx);
        assert_eq!(props.linking.libraries.len(), 1);
    }

    // ==================== OverlayMetrics Tests ====================

    #[test]
    fn test_overlay_metrics_default() {
        let metrics = OverlayMetrics::default();
        assert_eq!(metrics.size_bytes, 0);
        assert_eq!(metrics.embedded_file_count, 0);
    }

    #[test]
    fn test_overlay_metrics_creation() {
        let metrics = OverlayMetrics {
            size_bytes: 65536,
            ratio_of_file: 0.25,
            avg_entropy: 7.5,
            entropy_variance: 0.5,
            embedded_file_count: 2,
            embedded_for: vec!["zstd".to_string(), "gzip".to_string()],
            overlay_start: 100000,
            suspicion_score: 0.8,
        };
        assert_eq!(metrics.size_bytes, 65536);
        assert_eq!(metrics.embedded_file_count, 2);
        assert!((metrics.suspicion_score - 0.8).abs() < f64::EPSILON);
    }

    // ==================== CodeMetrics Tests ====================

    #[test]
    fn test_code_metrics_default() {
        let metrics = CodeMetrics::default();
        assert_eq!(metrics.total_functions, 0);
        assert_eq!(metrics.total_instructions, 0);
    }

    #[test]
    fn test_code_metrics_creation() {
        let metrics = CodeMetrics {
            total_functions: 100,
            total_basic_blocks: 500,
            avg_complexity: 8.5,
            max_complexity: 50,
            total_instructions: 10000,
            code_density: 0.75,
            functions_with_loops: 30,
            functions_with_anomalies: 5,
        };
        assert_eq!(metrics.total_functions, 100);
        assert_eq!(metrics.max_complexity, 50);
    }

    // ==================== SourceCodeMetrics Tests ====================

    #[test]
    fn test_source_code_metrics_default() {
        let metrics = SourceCodeMetrics::default();
        assert_eq!(metrics.total_lines, 0);
        assert!(metrics.python_idioms.is_none());
    }

    #[test]
    fn test_source_code_metrics_creation() {
        let metrics = SourceCodeMetrics {
            total_lines: 500,
            code_lines: 400,
            comment_lines: 50,
            blank_lines: 50,
            function_count: 20,
            import_count: 15,
            ..Default::default()
        };
        assert_eq!(metrics.total_lines, 500);
        assert_eq!(metrics.function_count, 20);
    }

    // ==================== CodeStructureMetrics Tests ====================

    #[test]
    fn test_code_structure_metrics_default() {
        let metrics = CodeStructureMetrics::default();
        assert_eq!(metrics.global_var_count, 0);
        assert!(!metrics.has_main_guard);
    }

    #[test]
    fn test_code_structure_metrics_creation() {
        let metrics = CodeStructureMetrics {
            global_var_count: 10,
            class_count: 5,
            max_inheritance_depth: 3,
            exception_handler_count: 20,
            empty_except_count: 2,
            assert_count: 15,
            has_main_guard: true,
            assignment_count: 100,
        };
        assert_eq!(metrics.class_count, 5);
        assert!(metrics.has_main_guard);
    }

    // ==================== PythonIdioms Tests ====================

    #[test]
    fn test_python_idioms_default() {
        let idioms = PythonIdioms::default();
        assert_eq!(idioms.comprehension_count, 0);
        assert_eq!(idioms.lambda_count, 0);
    }

    #[test]
    fn test_python_idioms_creation() {
        let idioms = PythonIdioms {
            comprehension_count: 25,
            generator_expression_count: 10,
            context_manager_count: 15,
            lambda_count: 8,
            async_count: 5,
            yield_count: 3,
            class_count: 10,
            dunder_method_count: 20,
            total_decorator_count: 30,
            fstring_count: 50,
            walrus_operator_count: 5,
        };
        assert_eq!(idioms.comprehension_count, 25);
        assert_eq!(idioms.fstring_count, 50);
    }

    // ==================== JavaScriptIdioms Tests ====================

    #[test]
    fn test_javascript_idioms_default() {
        let idioms = JavaScriptIdioms::default();
        assert_eq!(idioms.arrow_function_count, 0);
        assert_eq!(idioms.promise_count, 0);
    }

    #[test]
    fn test_javascript_idioms_creation() {
        let idioms = JavaScriptIdioms {
            arrow_function_count: 50,
            promise_count: 20,
            async_await_count: 15,
            template_literal_count: 30,
            destructuring_count: 25,
            spread_operator_count: 10,
            class_count: 8,
            callback_count: 40,
            iife_count: 5,
            object_shorthand_count: 20,
            optional_chaining_count: 12,
            nullish_coalescing_count: 8,
        };
        assert_eq!(idioms.arrow_function_count, 50);
        assert_eq!(idioms.optional_chaining_count, 12);
    }

    // ==================== ShellIdioms Tests ====================

    #[test]
    fn test_shell_idioms_default() {
        let idioms = ShellIdioms::default();
        assert_eq!(idioms.pipe_count, 0);
        assert_eq!(idioms.heredoc_count, 0);
    }

    #[test]
    fn test_shell_idioms_creation() {
        let idioms = ShellIdioms {
            pipe_count: 30,
            redirect_count: 20,
            input_redirect_count: 5,
            command_substitution_count: 25,
            heredoc_count: 3,
            case_statement_count: 2,
            test_expression_count: 40,
            while_read_count: 5,
            subshell_count: 10,
            for_loop_count: 15,
            background_job_count: 3,
            process_substitution_count: 2,
        };
        assert_eq!(idioms.pipe_count, 30);
        assert_eq!(idioms.command_substitution_count, 25);
    }

    // ==================== GoIdioms Tests ====================

    #[test]
    fn test_go_idioms_default() {
        let idioms = GoIdioms::default();
        assert_eq!(idioms.goroutine_count, 0);
        assert_eq!(idioms.channel_count, 0);
    }

    #[test]
    fn test_go_idioms_creation() {
        let idioms = GoIdioms {
            goroutine_count: 20,
            channel_count: 15,
            defer_count: 30,
            select_statement_count: 5,
            type_assertion_count: 10,
            method_count: 50,
            interface_count: 8,
            range_loop_count: 25,
            error_return_count: 40,
            panic_recover_count: 3,
            cgo_count: 2,
            unsafe_count: 5,
        };
        assert_eq!(idioms.goroutine_count, 20);
        assert_eq!(idioms.defer_count, 30);
        assert_eq!(idioms.error_return_count, 40);
    }
}
