//! ML-ready feature extraction structures for binary analysis

use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32};

/// Maximum size for string values (4KB)
const MAX_STRING_VALUE_SIZE: usize = 4096;

/// Serialize string value, truncating to MAX_STRING_VALUE_SIZE
fn serialize_truncated_string<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if value.len() <= MAX_STRING_VALUE_SIZE {
        serializer.serialize_str(value)
    } else {
        // Truncate at a valid UTF-8 boundary
        let truncated = truncate_str_at_boundary(value, MAX_STRING_VALUE_SIZE - 12);
        let with_marker = format!("{}...[truncated]", truncated);
        serializer.serialize_str(&with_marker)
    }
}

/// Truncate a string at a valid UTF-8 char boundary
fn truncate_str_at_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ========================================================================
// ML-Ready Feature Extraction Structures
// ========================================================================

// ========================================================================
// ML-Ready Feature Extraction Structures
// ========================================================================

/// Control flow graph metrics for a function
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlFlowMetrics {
    /// Number of basic blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub basic_blocks: u32,
    /// Number of control flow edges
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub edges: u32,
    /// Cyclomatic complexity (McCabe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cyclomatic_complexity: u32,
    /// Maximum instructions in any basic block
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_block_size: u32,
    /// Average instructions per basic block
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_block_size: f32,
    /// Whether function has linear control flow (no branches)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_linear: bool,
    /// Number of loops detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loop_count: u32,
    /// Branch density (branches per instruction)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub branch_density: f32,
    /// Call graph in-degree (callers)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub in_degree: u32,
    /// Call graph out-degree (callees)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub out_degree: u32,
}

/// Instruction-level analysis for ML features
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstructionAnalysis {
    /// Total instruction count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_instructions: u32,
    /// CPU cycle cost estimate
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub instruction_cost: u32,
    /// Instruction density (instructions per byte)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub instruction_density: f32,
    /// Instruction categories and counts
    pub categories: InstructionCategories,
    /// Top 5 most used opcodes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_opcodes: Vec<OpcodeFrequency>,
    /// Unusual/suspicious instructions detected
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unusual_instructions: Vec<String>,
}

/// Categorized instruction counts for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstructionCategories {
    /// Arithmetic operations (add, sub, mul, div, inc, dec)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arithmetic: u32,
    /// Logical operations (and, or, xor, not, test)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub logic: u32,
    /// Memory operations (mov, lea, push, pop, load, store)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub memory: u32,
    /// Control flow (jmp, jne, call, ret, loop)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub control: u32,
    /// System calls and interrupts (syscall, int, sysenter)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system: u32,
    /// FPU/SIMD operations (fadd, fmul, xmm, etc)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fpu_simd: u32,
    /// String operations (movs, cmps, scas, stos)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_ops: u32,
    /// Privileged instructions (cli, sti, hlt, in, out)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub privileged: u32,
    /// Crypto-related instructions (aes, sha, etc)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub crypto: u32,
}

/// Opcode frequency for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpcodeFrequency {
    /// Mnemonic name of the opcode (e.g., "mov", "xor", "call")
    pub opcode: String,
    /// Absolute occurrence count in the analyzed code region
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub count: u32,
    /// Fraction of total instructions this opcode represents (0.0–1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub percentage: f32,
}

/// Register usage patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterUsage {
    /// Registers read in function
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// Registers written in function
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub written: Vec<String>,
    /// Registers preserved across call
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserved: Vec<String>,
    /// Registers used in function (legacy, kept for compatibility)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registers_used: Vec<String>,
    /// Non-standard register usage (unusual for the architecture)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub non_standard_usage: Vec<String>,
    /// Stack pointer manipulation detected
    #[serde(default, skip_serializing_if = "is_false")]
    pub stack_pointer_manipulation: bool,
    /// Frame pointer usage
    #[serde(default, skip_serializing_if = "is_false")]
    pub uses_frame_pointer: bool,
    /// Maximum local variables (Java bytecode)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_locals: Option<u32>,
    /// Maximum operand stack depth (Java bytecode)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_stack: Option<u32>,
}

/// Embedded constant with decoded information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmbeddedConstant {
    /// Raw value as hex string
    #[serde(serialize_with = "serialize_truncated_string")]
    pub value: String,
    /// Constant type (qword, dword, word, byte)
    pub constant_type: String,
    /// Possible decoded interpretations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decoded: Vec<DecodedValue>,
}

/// Decoded constant value interpretations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecodedValue {
    /// Type of decoded value (ip_address, port, url, key, etc)
    pub value_type: String,
    /// Human-readable decoded value
    #[serde(serialize_with = "serialize_truncated_string")]
    pub decoded_value: String,
    /// Confidence in this interpretation (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,
}

/// Function-level properties
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionProperties {
    /// Function is side-effect free (pure)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_pure: bool,
    /// Function never returns
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_noreturn: bool,
    /// Function is recursive
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_recursive: bool,
    /// Stack frame size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stack_frame: u32,
    /// Number of local variables
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_vars: u32,
    /// Number of arguments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args: u32,
    /// Function is a leaf (calls nothing)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_leaf: bool,
}

/// Function signature analysis (source code languages)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionSignature {
    /// Parameter count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub param_count: u32,
    /// Parameters with default values
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub default_param_count: u32,
    /// Has *args (variadic positional)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_var_positional: bool,
    /// Has **kwargs (variadic keyword)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_var_keyword: bool,
    /// Has type annotations/hints
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_type_hints: bool,
    /// Return type annotation present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_return_type: bool,
    /// Decorators applied
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decorators: Vec<String>,
    /// Is async function
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_async: bool,
    /// Is generator (contains yield)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_generator: bool,
    /// Is lambda/anonymous
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_lambda: bool,
}

/// Nesting depth metrics for control structures
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NestingMetrics {
    /// Maximum nesting depth in function
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_depth: u32,
    /// Average nesting depth
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_depth: f32,
    /// Locations with deep nesting (depth > 4)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub deep_nest_count: u32,
    /// Depth limit was hit during analysis (potential anti-analysis)
    #[serde(default, skip_serializing_if = "is_false")]
    pub depth_limit_hit: bool,
}

/// Call pattern analysis for source code
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CallPatternMetrics {
    /// Total function calls in this function
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_count: u32,
    /// Unique functions called
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_callees: u32,
    /// Chained method calls (e.g., obj.a().b().c())
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chained_calls: u32,
    /// Maximum chain length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_chain_length: u32,
    /// Recursive calls (self-reference)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_calls: u32,
    /// Dynamic calls (eval, exec, __import__, getattr)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynamic_calls: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== truncate_str_at_boundary Tests ====================

    #[test]
    fn test_truncate_str_at_boundary_short() {
        assert_eq!(truncate_str_at_boundary("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_exact() {
        assert_eq!(truncate_str_at_boundary("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_truncate() {
        assert_eq!(truncate_str_at_boundary("hello world", 5), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_utf8() {
        // café has 'é' which is 2 bytes in UTF-8
        assert_eq!(truncate_str_at_boundary("café", 4), "caf");
    }

    // ==================== ControlFlowMetrics Tests ====================

    #[test]
    fn test_control_flow_metrics_default() {
        let metrics = ControlFlowMetrics::default();
        assert_eq!(metrics.basic_blocks, 0);
        assert!(!metrics.is_linear);
    }

    #[test]
    fn test_control_flow_metrics_creation() {
        let metrics = ControlFlowMetrics {
            basic_blocks: 15,
            edges: 20,
            cyclomatic_complexity: 8,
            max_block_size: 50,
            avg_block_size: 12.5,
            is_linear: false,
            loop_count: 3,
            ..Default::default()
        };
        assert_eq!(metrics.basic_blocks, 15);
        assert_eq!(metrics.cyclomatic_complexity, 8);
    }

    // ==================== InstructionCategories Tests ====================

    #[test]
    fn test_instruction_categories_default() {
        let cats = InstructionCategories::default();
        assert_eq!(cats.arithmetic, 0);
        assert_eq!(cats.memory, 0);
    }

    #[test]
    fn test_instruction_categories_creation() {
        let cats = InstructionCategories {
            arithmetic: 100,
            logic: 50,
            memory: 200,
            control: 30,
            system: 5,
            fpu_simd: 10,
            string_ops: 15,
            privileged: 2,
            crypto: 3,
        };
        assert_eq!(cats.arithmetic, 100);
        assert_eq!(cats.memory, 200);
    }

    // ==================== InstructionAnalysis Tests ====================

    #[test]
    fn test_instruction_analysis_default() {
        let analysis = InstructionAnalysis::default();
        assert_eq!(analysis.total_instructions, 0);
        assert!(analysis.top_opcodes.is_empty());
    }

    #[test]
    fn test_instruction_analysis_creation() {
        let analysis = InstructionAnalysis {
            total_instructions: 500,
            instruction_cost: 1000,
            instruction_density: 0.8,
            categories: InstructionCategories::default(),
            top_opcodes: vec![OpcodeFrequency {
                opcode: "mov".to_string(),
                count: 150,
                percentage: 30.0,
            }],
            unusual_instructions: vec!["rdtsc".to_string()],
        };
        assert_eq!(analysis.total_instructions, 500);
        assert_eq!(analysis.top_opcodes.len(), 1);
    }

    // ==================== OpcodeFrequency Tests ====================

    #[test]
    fn test_opcode_frequency_default() {
        let freq = OpcodeFrequency::default();
        assert!(freq.opcode.is_empty());
        assert_eq!(freq.count, 0);
    }

    #[test]
    fn test_opcode_frequency_creation() {
        let freq = OpcodeFrequency {
            opcode: "call".to_string(),
            count: 50,
            percentage: 10.0,
        };
        assert_eq!(freq.opcode, "call");
        assert_eq!(freq.count, 50);
    }

    // ==================== RegisterUsage Tests ====================

    #[test]
    fn test_register_usage_default() {
        let usage = RegisterUsage::default();
        assert!(usage.read.is_empty());
        assert!(!usage.stack_pointer_manipulation);
    }

    #[test]
    fn test_register_usage_creation() {
        let usage = RegisterUsage {
            read: vec!["rax".to_string(), "rbx".to_string()],
            written: vec!["rcx".to_string()],
            preserved: vec!["rbp".to_string()],
            registers_used: vec!["rax".to_string(), "rbx".to_string(), "rcx".to_string()],
            non_standard_usage: vec![],
            stack_pointer_manipulation: true,
            uses_frame_pointer: true,
            max_locals: Some(10),
            max_stack: Some(5),
        };
        assert_eq!(usage.read.len(), 2);
        assert!(usage.stack_pointer_manipulation);
        assert_eq!(usage.max_locals, Some(10));
    }

    // ==================== EmbeddedConstant Tests ====================

    #[test]
    fn test_embedded_constant_default() {
        let constant = EmbeddedConstant::default();
        assert!(constant.value.is_empty());
        assert!(constant.decoded.is_empty());
    }

    #[test]
    fn test_embedded_constant_creation() {
        let constant = EmbeddedConstant {
            value: "0xDEADBEEF".to_string(),
            constant_type: "dword".to_string(),
            decoded: vec![DecodedValue {
                value_type: "ip_address".to_string(),
                decoded_value: "222.173.190.239".to_string(),
                conf: 0.8,
            }],
        };
        assert_eq!(constant.constant_type, "dword");
        assert_eq!(constant.decoded.len(), 1);
    }

    // ==================== DecodedValue Tests ====================

    #[test]
    fn test_decoded_value_default() {
        let val = DecodedValue::default();
        assert!(val.value_type.is_empty());
        assert_eq!(val.conf, 0.0);
    }

    #[test]
    fn test_decoded_value_creation() {
        let val = DecodedValue {
            value_type: "port".to_string(),
            decoded_value: "8080".to_string(),
            conf: 0.95,
        };
        assert_eq!(val.value_type, "port");
        assert!((val.conf - 0.95).abs() < f32::EPSILON);
    }

    // ==================== FunctionProperties Tests ====================

    #[test]
    fn test_function_properties_default() {
        let props = FunctionProperties::default();
        assert!(!props.is_pure);
        assert!(!props.is_recursive);
    }

    #[test]
    fn test_function_properties_creation() {
        let props = FunctionProperties {
            is_pure: true,
            is_noreturn: false,
            is_recursive: true,
            stack_frame: 256,
            local_vars: 10,
            args: 3,
            is_leaf: false,
        };
        assert!(props.is_pure);
        assert!(props.is_recursive);
        assert_eq!(props.stack_frame, 256);
    }

    // ==================== FunctionSignature Tests ====================

    #[test]
    fn test_function_signature_default() {
        let sig = FunctionSignature::default();
        assert_eq!(sig.param_count, 0);
        assert!(!sig.is_async);
    }

    #[test]
    fn test_function_signature_creation() {
        let sig = FunctionSignature {
            param_count: 5,
            default_param_count: 2,
            has_var_positional: true,
            has_var_keyword: true,
            has_type_hints: true,
            has_return_type: true,
            decorators: vec!["async".to_string(), "cached".to_string()],
            is_async: true,
            is_generator: false,
            is_lambda: false,
        };
        assert_eq!(sig.param_count, 5);
        assert!(sig.is_async);
        assert_eq!(sig.decorators.len(), 2);
    }

    // ==================== NestingMetrics Tests ====================

    #[test]
    fn test_nesting_metrics_default() {
        let nest = NestingMetrics::default();
        assert_eq!(nest.max_depth, 0);
        assert!(!nest.depth_limit_hit);
    }

    #[test]
    fn test_nesting_metrics_creation() {
        let nest = NestingMetrics {
            max_depth: 8,
            avg_depth: 3.5,
            deep_nest_count: 5,
            depth_limit_hit: true,
        };
        assert_eq!(nest.max_depth, 8);
        assert!(nest.depth_limit_hit);
    }

    // ==================== CallPatternMetrics Tests ====================

    #[test]
    fn test_call_pattern_metrics_default() {
        let patterns = CallPatternMetrics::default();
        assert_eq!(patterns.call_count, 0);
        assert_eq!(patterns.dynamic_calls, 0);
    }

    #[test]
    fn test_call_pattern_metrics_creation() {
        let patterns = CallPatternMetrics {
            call_count: 50,
            unique_callees: 20,
            chained_calls: 10,
            max_chain_length: 5,
            recursive_calls: 2,
            dynamic_calls: 3,
        };
        assert_eq!(patterns.call_count, 50);
        assert_eq!(patterns.dynamic_calls, 3);
    }
}
