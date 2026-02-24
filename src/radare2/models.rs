//! Data models for radare2/rizin analysis results.
//!
//! This module contains the data structures used to deserialize JSON output from
//! radare2/rizin commands, as well as conversions to cleave's internal types.
//!
//! # Structure Naming
//! - `R2*` structs are direct deserializations from rizin JSON output
//! - Conversions to cleave types (e.g., `Function`) are implemented via `From` traits
//!
//! # Key Types
//! - `R2Function` - Function information from `aflj` command
//! - `R2String` - String information from `izj` command
//! - `R2Import` - Import information from `iij` command
//! - `R2Export` - Export information from `iEj` command
//! - `R2Symbol` - Symbol information from `isj` command
//! - `R2Section` - Section information from `iSj` command

use crate::types::{ControlFlowMetrics, Function, FunctionProperties, InstructionAnalysis};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct R2Function {
    pub name: String,
    /// Function address (rizin uses "offset", radare2 used "addr")
    #[serde(alias = "addr")]
    pub offset: u64,
    pub size: Option<u64>,
    #[serde(rename = "cc")]
    pub complexity: Option<u32>, // Cyclomatic complexity
    #[serde(default)]
    pub calls: Vec<R2Call>,

    // Additional fields from aflj (Phase 1: Free features!)
    #[serde(default)]
    pub nbbs: Option<u32>, // Number of basic blocks
    #[serde(default)]
    pub edges: Option<u32>, // Control flow edges
    #[serde(default)]
    pub ninstrs: Option<u32>, // Total instructions
    #[serde(default)]
    pub recursive: Option<bool>, // Is recursive
    #[serde(default)]
    pub noreturn: Option<bool>, // Doesn't return
    #[serde(default)]
    pub stackframe: Option<i32>, // Stack frame size
    #[serde(rename = "is-lineal", default)]
    pub is_lineal: Option<bool>, // No branches (straight-line code)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct R2Call {
    pub name: String,
}

impl From<R2Function> for Function {
    fn from(r2_func: R2Function) -> Self {
        use crate::types::InstructionCategories;

        // Build control flow metrics from aflj data
        let control_flow = if r2_func.nbbs.is_some() || r2_func.edges.is_some() {
            let nbbs = r2_func.nbbs.unwrap_or(1);
            let edges = r2_func.edges.unwrap_or(0);
            let ninstr = r2_func.ninstrs.unwrap_or(0);

            Some(ControlFlowMetrics {
                basic_blocks: nbbs,
                edges,
                cyclomatic_complexity: r2_func.complexity.unwrap_or(1),
                max_block_size: if nbbs > 0 { ninstr / nbbs } else { 0 },
                avg_block_size: if nbbs > 0 {
                    ninstr as f32 / nbbs as f32
                } else {
                    0.0
                },
                is_linear: r2_func.is_lineal.unwrap_or(false),
                loop_count: if edges >= nbbs { edges - nbbs + 1 } else { 0 },
                branch_density: if ninstr > 0 {
                    edges as f32 / ninstr as f32
                } else {
                    0.0
                },
                in_degree: 0, // Not available without call graph
                out_degree: r2_func.calls.len() as u32,
            })
        } else {
            None
        };

        // Build instruction analysis from aflj data
        let instruction_analysis = if r2_func.ninstrs.is_some() {
            Some(InstructionAnalysis {
                total_instructions: r2_func.ninstrs.unwrap_or(0),
                instruction_cost: r2_func.ninstrs.unwrap_or(0), // Rough estimate
                instruction_density: if let Some(size) = r2_func.size {
                    if size > 0 {
                        r2_func.ninstrs.unwrap_or(0) as f32 / size as f32
                    } else {
                        0.0
                    }
                } else {
                    0.0
                },
                categories: InstructionCategories {
                    arithmetic: 0,
                    logic: 0,
                    memory: 0,
                    control: r2_func.edges.unwrap_or(0),
                    system: 0,
                    fpu_simd: 0,
                    string_ops: 0,
                    privileged: 0,
                    crypto: 0,
                },
                top_opcodes: Vec::new(),          // Would need pdfj
                unusual_instructions: Vec::new(), // Would need pdfj
            })
        } else {
            None
        };

        // Build function properties from aflj data
        let properties = Some(FunctionProperties {
            is_pure: false, // Not in aflj
            is_noreturn: r2_func.noreturn.unwrap_or(false),
            is_recursive: r2_func.recursive.unwrap_or(false),
            stack_frame: r2_func.stackframe.unwrap_or(0).max(0) as u32,
            local_vars: 0, // Not in aflj
            args: 0,       // Not in aflj
            is_leaf: r2_func.calls.is_empty(),
        });

        Function {
            name: r2_func.name.trim_start_matches('_').to_string(),
            offset: Some(format!("0x{:x}", r2_func.offset)),
            size: r2_func.size,
            complexity: r2_func.complexity,
            calls: r2_func.calls.into_iter().map(|c| c.name).collect(),
            source: "radare2".to_string(),
            control_flow,
            instruction_analysis,
            register_usage: None,  // Would need pdfj
            constants: Vec::new(), // Would need pdfj
            properties,
            call_patterns: None,
            nesting: None,
            signature: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct R2String {
    pub vaddr: u64,
    pub paddr: u64,
    pub length: u32,
    pub size: u32,
    pub string: String,
    #[serde(rename = "type")]
    pub string_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct R2Import {
    pub name: String,
    #[serde(rename = "libname")]
    pub lib_name: Option<String>,
    pub ordinal: Option<u32>,
}

#[allow(dead_code)] // Deserialized from JSON
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct R2Export {
    pub name: String,
    pub vaddr: u64,
    pub paddr: u64,
    #[serde(rename = "type")]
    pub export_type: Option<String>,
}

#[allow(dead_code)] // Deserialized from JSON
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct R2Symbol {
    pub name: String,
    pub vaddr: u64,
    pub paddr: u64,
    pub size: u64,
    #[serde(rename = "type")]
    pub symbol_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct R2Section {
    pub name: String,
    pub size: u64,
    pub vsize: Option<u64>,
    pub perm: Option<String>,
    #[serde(default)]
    pub entropy: f64,
}
