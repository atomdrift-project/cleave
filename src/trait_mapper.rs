//! Trait and capability mapping.
//!
//! This module maps low-level analysis results (imports, strings, syscalls)
//! to high-level capability traits using YAML rule definitions.
//!
//! Traits represent observable behaviors (e.g., "opens network socket").

use crate::types::{
    BinaryProperties, ControlFlowMetrics, Criticality, Evidence, Finding, FindingKind, Function,
    InstructionAnalysis,
};

/// Analyze function traits and generate behavioral capabilities
#[must_use]
pub fn analyze_function(func: &Function) -> Vec<Finding> {
    let mut capabilities = Vec::new();

    // Analyze control flow metrics
    if let Some(ref cf) = func.control_flow {
        capabilities.extend(analyze_control_flow(cf, &func.name));
    }

    // Analyze instruction patterns
    if let Some(ref instr) = func.instruction_analysis {
        capabilities.extend(analyze_instructions(instr, &func.name));
    }

    // Analyze constants for C2
    if !func.constants.is_empty() {
        capabilities.extend(analyze_constants(&func.constants, &func.name));
    }

    // Analyze function properties
    if let Some(ref props) = func.properties {
        if props.is_noreturn {
            capabilities.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "execution/terminate".to_string(),
                desc: "Function terminates execution".to_string(),
                conf: 0.7,
                crit: Criticality::Baseline,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: "noreturn".to_string(),
                    location: Some(func.name.clone()),
                }],
                source_file: None,
            });
        }
    }

    capabilities
}

/// Analyze control flow metrics for behavioral patterns
fn analyze_control_flow(cf: &ControlFlowMetrics, func_name: &str) -> Vec<Finding> {
    let mut capabilities = Vec::new();

    // High complexity with loops -> potential crypto/packing
    if cf.cyclomatic_complexity > 10 && cf.loop_count > 0 {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "complexity/high".to_string(),
            desc: "High cyclomatic complexity with loops".to_string(),
            conf: 0.7,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: format!(
                    "complexity={}, loops={}",
                    cf.cyclomatic_complexity, cf.loop_count
                ),
                location: Some(func_name.to_string()),
            }],
            source_file: None,
        });

        // If very high complexity, could be obfuscation
        if cf.cyclomatic_complexity > 20 {
            capabilities.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "anti-analysis/obfuscation/control-flow".to_string(),
                desc: "Control flow obfuscation detected".to_string(),
                conf: 0.6,
                crit: Criticality::Baseline,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "trait".to_string(),
                    source: "radare2".to_string(),
                    value: format!("complexity={}", cf.cyclomatic_complexity),
                    location: Some(func_name.to_string()),
                }],
                source_file: None,
            });
        }
    }

    // Multiple loops -> potential crypto operation
    if cf.loop_count >= 2 {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "data/encode".to_string(),
            desc: "Multiple nested loops suggest encoding/crypto".to_string(),
            conf: 0.5,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: format!("loops={}", cf.loop_count),
                location: Some(func_name.to_string()),
            }],
            source_file: None,
        });
    }

    capabilities
}

/// Analyze instruction patterns for behaviors
fn analyze_instructions(instr: &InstructionAnalysis, func_name: &str) -> Vec<Finding> {
    let mut capabilities = Vec::new();

    // Anti-debug instructions
    for unusual_inst in &instr.unusual_instructions {
        match unusual_inst.as_str() {
            "int1" | "int 1" | "icebp" => {
                capabilities.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/anti-debug/debugger-detect".to_string(),
                    desc: "Debug trap instruction detected".to_string(),
                    conf: 0.9,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "trait".to_string(),
                        source: "radare2".to_string(),
                        value: unusual_inst.clone(),
                        location: Some(func_name.to_string()),
                    }],
                    source_file: None,
                });
            },
            "int3" | "int 3" => {
                capabilities.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/anti-debug/breakpoint".to_string(),
                    desc: "Breakpoint instruction detected".to_string(),
                    conf: 0.8,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "trait".to_string(),
                        source: "radare2".to_string(),
                        value: unusual_inst.clone(),
                        location: Some(func_name.to_string()),
                    }],
                    source_file: None,
                });
            },
            "rdtsc" | "rdtscp" => {
                capabilities.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/anti-debug/timing".to_string(),
                    desc: "Timing check via RDTSC".to_string(),
                    conf: 0.8,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "trait".to_string(),
                        source: "radare2".to_string(),
                        value: unusual_inst.clone(),
                        location: Some(func_name.to_string()),
                    }],
                    source_file: None,
                });
            },
            s if s.contains("cpuid") => {
                capabilities.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/anti-vm/cpu-detect".to_string(),
                    desc: "CPU detection via CPUID".to_string(),
                    conf: 0.7,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "trait".to_string(),
                        source: "radare2".to_string(),
                        value: unusual_inst.clone(),
                        location: Some(func_name.to_string()),
                    }],
                    source_file: None,
                });
            },
            s if s.starts_with("fx") => {
                // FPU instructions in suspicious context
                capabilities.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/fpu".to_string(),
                    desc: "FPU instructions used for obfuscation".to_string(),
                    conf: 0.6,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "trait".to_string(),
                        source: "radare2".to_string(),
                        value: unusual_inst.clone(),
                        location: Some(func_name.to_string()),
                    }],
                    source_file: None,
                });
            },
            _ => {},
        }
    }

    // High ratio of XOR operations -> encoding/crypto
    let xor_ratio = instr.categories.logic as f32 / instr.total_instructions as f32;
    if xor_ratio > 0.2 && instr.total_instructions > 10 {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "crypto/xor".to_string(),
            desc: "High XOR operation density suggests encoding".to_string(),
            conf: 0.6,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: format!("xor_ratio={:.2}", xor_ratio),
                location: Some(func_name.to_string()),
            }],
            source_file: None,
        });
    }

    // Crypto instructions
    if instr.categories.crypto > 0 {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "crypto/encrypt".to_string(),
            desc: "Hardware crypto instructions detected".to_string(),
            conf: 0.9,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: format!("crypto_instructions={}", instr.categories.crypto),
                location: Some(func_name.to_string()),
            }],
            source_file: None,
        });
    }

    // String operations with loops -> data manipulation
    if instr.categories.string_ops > 3 {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "data/encoding/string-ops".to_string(),
            desc: "String operations for data manipulation".to_string(),
            conf: 0.6,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: format!("string_ops={}", instr.categories.string_ops),
                location: Some(func_name.to_string()),
            }],
            source_file: None,
        });
    }

    // System calls
    if instr.categories.system > 0 {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "os/syscall".to_string(),
            desc: "Direct system call usage".to_string(),
            conf: 0.8,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: format!("syscalls={}", instr.categories.system),
                location: Some(func_name.to_string()),
            }],
            source_file: None,
        });
    }

    // Privileged instructions -> rootkit behavior
    if instr.categories.privileged > 0 {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "privilege/escalate".to_string(),
            desc: "Privileged instructions detected".to_string(),
            conf: 0.7,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: format!("privileged={}", instr.categories.privileged),
                location: Some(func_name.to_string()),
            }],
            source_file: None,
        });
    }

    capabilities
}

/// Analyze embedded constants for C2 indicators
fn analyze_constants(
    constants: &[crate::types::EmbeddedConstant],
    func_name: &str,
) -> Vec<Finding> {
    let mut capabilities = Vec::new();

    for constant in constants {
        for decoded in &constant.decoded {
            match decoded.value_type.as_str() {
                "ip_address" | "ip_port" => {
                    capabilities.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "net/command-and-control/address".to_string(),
                        desc: format!("Embedded C2 address: {}", decoded.decoded_value),
                        conf: decoded.conf,
                        crit: Criticality::Baseline,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "constant_decode".to_string(),
                            source: "radare2".to_string(),
                            value: decoded.decoded_value.clone(),
                            location: Some(func_name.to_string()),
                        }],
                        source_file: None,
                    });
                },
                "port" => {
                    capabilities.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "net/socket/listen".to_string(),
                        desc: format!("Embedded port number: {}", decoded.decoded_value),
                        conf: decoded.conf * 0.7, // Lower confidence for ports alone
                        crit: Criticality::Notable,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "constant_decode".to_string(),
                            source: "radare2".to_string(),
                            value: decoded.decoded_value.clone(),
                            location: Some(func_name.to_string()),
                        }],
                        source_file: None,
                    });
                },
                _ => {},
            }
        }
    }

    capabilities
}

/// Analyze binary-wide properties for capabilities
#[must_use]
pub fn analyze_binary_properties(props: &BinaryProperties) -> Vec<Finding> {
    let mut capabilities = Vec::new();

    // No security features -> suspicious
    if !props.security.canary && !props.security.nx && !props.security.pic {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "binary/security/none".to_string(),
            desc: "No security hardening features present".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: "no_canary,no_nx,no_pic".to_string(),
                location: None,
            }],
            source_file: None,
        });
    }

    // Stripped binary -> anti-analysis
    if props.security.stripped {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "anti-analysis/stripped".to_string(),
            desc: "Binary symbols stripped".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: "stripped".to_string(),
                location: None,
            }],
            source_file: None,
        });
    }

    // Static linking -> evasion
    if props.linking.is_static {
        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "binary/linking/static".to_string(),
            desc: "Statically linked binary".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: "static".to_string(),
                location: None,
            }],
            source_file: None,
        });
    }

    // Anomalies
    for anomaly in &props.anomalies {
        let capability_id = match anomaly.anomaly_type.as_str() {
            "no_section_header" => "anti-analysis/format/no-sections",
            "overlapping_functions" => "anti-analysis/format/overlapping",
            "unusual_entry_point" => "anti-analysis/format/entry-point",
            _ => "binary/anomaly",
        };

        capabilities.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: capability_id.to_string(),
            desc: anomaly.desc.clone(),
            conf: 0.8,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "trait".to_string(),
                source: "radare2".to_string(),
                value: anomaly.anomaly_type.clone(),
                location: None,
            }],
            source_file: None,
        });
    }

    capabilities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn create_test_function(name: &str) -> Function {
        Function {
            name: name.to_string(),
            offset: Some("0x1000".to_string()),
            size: Some(100),
            complexity: None,
            calls: Vec::new(),
            source: "test".to_string(),
            control_flow: None,
            instruction_analysis: None,
            register_usage: None,
            constants: Vec::new(),
            properties: None,
            signature: None,
            nesting: None,
            call_patterns: None,
        }
    }

    #[test]
    fn test_analyze_control_flow_high_complexity() {
        let cf = ControlFlowMetrics {
            basic_blocks: 20,
            edges: 25,
            cyclomatic_complexity: 15,
            max_block_size: 50,
            avg_block_size: 15.0,
            is_linear: false,
            loop_count: 3,
            branch_density: 0.3,
            in_degree: 1,
            out_degree: 2,
        };

        let caps = analyze_control_flow(&cf, "test_func");

        // Should detect high complexity
        assert!(caps.iter().any(|c| c.id == "complexity/high"));

        // Should detect potential encoding
        assert!(caps.iter().any(|c| c.id == "data/encode"));
    }

    #[test]
    fn test_analyze_control_flow_obfuscation() {
        let cf = ControlFlowMetrics {
            basic_blocks: 30,
            edges: 40,
            cyclomatic_complexity: 25,
            max_block_size: 60,
            avg_block_size: 20.0,
            is_linear: false,
            loop_count: 2,
            branch_density: 0.4,
            in_degree: 1,
            out_degree: 3,
        };

        let caps = analyze_control_flow(&cf, "obfuscated_func");

        // Should detect obfuscation
        assert!(caps.iter().any(|c| c.id == "anti-analysis/obfuscation/control-flow"));
        assert_eq!(
            caps.iter()
                .find(|c| c.id == "anti-analysis/obfuscation/control-flow")
                .unwrap()
                .conf,
            0.6
        );
    }

    #[test]
    fn test_analyze_control_flow_low_complexity() {
        let cf = ControlFlowMetrics {
            basic_blocks: 5,
            edges: 4,
            cyclomatic_complexity: 3,
            max_block_size: 20,
            avg_block_size: 10.0,
            is_linear: false,
            loop_count: 0,
            branch_density: 0.1,
            in_degree: 2,
            out_degree: 1,
        };

        let caps = analyze_control_flow(&cf, "simple_func");

        // Should not detect anything suspicious
        assert!(caps.is_empty());
    }

    #[test]
    fn test_analyze_instructions_anti_debug_int1() {
        let instr = InstructionAnalysis {
            total_instructions: 100,
            instruction_cost: 500,
            instruction_density: 1.5,
            categories: InstructionCategories {
                arithmetic: 20,
                logic: 10,
                memory: 30,
                control: 15,
                system: 0,
                fpu_simd: 0,
                string_ops: 5,
                privileged: 0,
                crypto: 0,
            },
            top_opcodes: vec![],
            unusual_instructions: vec!["int1".to_string()],
        };

        let caps = analyze_instructions(&instr, "debug_trap");

        // Should detect debug trap
        assert!(caps.iter().any(|c| c.id == "anti-analysis/anti-debug/debugger-detect"));
        let cap = caps
            .iter()
            .find(|c| c.id == "anti-analysis/anti-debug/debugger-detect")
            .unwrap();
        assert_eq!(cap.conf, 0.9);
    }

    #[test]
    fn test_analyze_instructions_anti_debug_int3() {
        let instr = InstructionAnalysis {
            total_instructions: 50,
            instruction_cost: 250,
            instruction_density: 1.2,
            categories: InstructionCategories {
                arithmetic: 10,
                logic: 5,
                memory: 20,
                control: 10,
                system: 0,
                fpu_simd: 0,
                string_ops: 0,
                privileged: 0,
                crypto: 0,
            },
            top_opcodes: vec![],
            unusual_instructions: vec!["int3".to_string()],
        };

        let caps = analyze_instructions(&instr, "breakpoint_func");

        // Should detect breakpoint
        assert!(caps.iter().any(|c| c.id == "anti-analysis/anti-debug/breakpoint"));
        let cap = caps.iter().find(|c| c.id == "anti-analysis/anti-debug/breakpoint").unwrap();
        assert_eq!(cap.conf, 0.8);
    }

    #[test]
    fn test_analyze_instructions_rdtsc_timing() {
        let instr = InstructionAnalysis {
            total_instructions: 40,
            instruction_cost: 200,
            instruction_density: 1.3,
            categories: InstructionCategories {
                arithmetic: 10,
                logic: 5,
                memory: 15,
                control: 8,
                system: 0,
                fpu_simd: 0,
                string_ops: 0,
                privileged: 0,
                crypto: 0,
            },
            top_opcodes: vec![],
            unusual_instructions: vec!["rdtsc".to_string()],
        };

        let caps = analyze_instructions(&instr, "timing_check");

        // Should detect timing check
        assert!(caps.iter().any(|c| c.id == "anti-analysis/anti-debug/timing"));
        assert_eq!(
            caps.iter().find(|c| c.id == "anti-analysis/anti-debug/timing").unwrap().conf,
            0.8
        );
    }

    #[test]
    fn test_analyze_instructions_cpuid_vm_detect() {
        let instr = InstructionAnalysis {
            total_instructions: 60,
            instruction_cost: 300,
            instruction_density: 1.4,
            categories: InstructionCategories {
                arithmetic: 15,
                logic: 10,
                memory: 20,
                control: 12,
                system: 0,
                fpu_simd: 0,
                string_ops: 0,
                privileged: 0,
                crypto: 0,
            },
            top_opcodes: vec![],
            unusual_instructions: vec!["cpuid".to_string()],
        };

        let caps = analyze_instructions(&instr, "vm_detect");

        // Should detect VM detection
        assert!(caps.iter().any(|c| c.id == "anti-analysis/anti-vm/cpu-detect"));
        assert_eq!(
            caps.iter().find(|c| c.id == "anti-analysis/anti-vm/cpu-detect").unwrap().conf,
            0.7
        );
    }

    #[test]
    fn test_analyze_instructions_xor_encoding() {
        let instr = InstructionAnalysis {
            total_instructions: 50,
            instruction_cost: 250,
            instruction_density: 1.3,
            categories: InstructionCategories {
                arithmetic: 5,
                logic: 15, // High logic operations
                memory: 10,
                control: 8,
                system: 0,
                fpu_simd: 0,
                string_ops: 0,
                privileged: 0,
                crypto: 0,
            },
            top_opcodes: vec![],
            unusual_instructions: Vec::new(),
        };

        let caps = analyze_instructions(&instr, "xor_loop");

        // Should detect XOR encoding (15/50 = 0.3 > 0.2)
        assert!(caps.iter().any(|c| c.id == "crypto/xor"));
        assert_eq!(
            caps.iter().find(|c| c.id == "crypto/xor").unwrap().conf,
            0.6
        );
    }

    #[test]
    fn test_analyze_instructions_hardware_crypto() {
        let instr = InstructionAnalysis {
            total_instructions: 40,
            instruction_cost: 200,
            instruction_density: 1.2,
            categories: InstructionCategories {
                arithmetic: 10,
                logic: 5,
                memory: 15,
                control: 8,
                system: 0,
                fpu_simd: 0,
                string_ops: 0,
                privileged: 0,
                crypto: 5,
            },
            top_opcodes: vec![],
            unusual_instructions: Vec::new(),
        };

        let caps = analyze_instructions(&instr, "aes_encrypt");

        // Should detect hardware crypto
        assert!(caps.iter().any(|c| c.id == "crypto/encrypt"));
        assert_eq!(
            caps.iter().find(|c| c.id == "crypto/encrypt").unwrap().conf,
            0.9
        );
    }

    #[test]
    fn test_analyze_instructions_syscalls() {
        let instr = InstructionAnalysis {
            total_instructions: 30,
            instruction_cost: 150,
            instruction_density: 1.1,
            categories: InstructionCategories {
                arithmetic: 5,
                logic: 3,
                memory: 10,
                control: 7,
                system: 3,
                fpu_simd: 0,
                string_ops: 0,
                privileged: 0,
                crypto: 0,
            },
            top_opcodes: vec![],
            unusual_instructions: Vec::new(),
        };

        let caps = analyze_instructions(&instr, "syscall_func");

        // Should detect system calls
        assert!(caps.iter().any(|c| c.id == "os/syscall"));
        assert_eq!(
            caps.iter().find(|c| c.id == "os/syscall").unwrap().conf,
            0.8
        );
    }

    #[test]
    fn test_analyze_instructions_privileged() {
        let instr = InstructionAnalysis {
            total_instructions: 25,
            instruction_cost: 125,
            instruction_density: 1.0,
            categories: InstructionCategories {
                arithmetic: 5,
                logic: 3,
                memory: 8,
                control: 6,
                system: 0,
                fpu_simd: 0,
                string_ops: 0,
                privileged: 2,
                crypto: 0,
            },
            top_opcodes: vec![],
            unusual_instructions: Vec::new(),
        };

        let caps = analyze_instructions(&instr, "privileged_func");

        // Should detect privileged instructions
        assert!(caps.iter().any(|c| c.id == "privilege/escalate"));
        assert_eq!(
            caps.iter().find(|c| c.id == "privilege/escalate").unwrap().conf,
            0.7
        );
    }

    #[test]
    fn test_analyze_constants_ip_address() {
        let constants = vec![EmbeddedConstant {
            value: "0xc0a80101".to_string(),
            constant_type: "dword".to_string(),
            decoded: vec![DecodedValue {
                value_type: "ip_address".to_string(),
                decoded_value: "192.168.1.1".to_string(),
                conf: 0.7,
            }],
        }];

        let caps = analyze_constants(&constants, "c2_func");

        // Should detect C2 address
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].id, "net/command-and-control/address");
        assert!(caps[0].desc.contains("192.168.1.1"));
        assert_eq!(caps[0].conf, 0.7);
    }

    #[test]
    fn test_analyze_constants_port() {
        let constants = vec![EmbeddedConstant {
            value: "0x1bb".to_string(),
            constant_type: "word".to_string(),
            decoded: vec![DecodedValue {
                value_type: "port".to_string(),
                decoded_value: "443".to_string(),
                conf: 0.8,
            }],
        }];

        let caps = analyze_constants(&constants, "listen_func");

        // Should detect port
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].id, "net/socket/listen");
        assert!(caps[0].desc.contains("443"));
        assert_eq!(caps[0].conf, 0.8 * 0.7); // Port confidence is reduced
        assert_eq!(caps[0].crit, Criticality::Notable);
    }

    #[test]
    fn test_analyze_binary_properties_no_security() {
        let props = BinaryProperties {
            security: SecurityFeatures {
                canary: false,
                nx: false,
                pic: false,
                relro: "none".to_string(),
                stripped: false,
                uses_crypto: false,
                signed: false,
            },
            linking: LinkingInfo {
                is_static: false,
                libraries: Vec::new(),
                rpath: Vec::new(),
            },
            anomalies: Vec::new(),
        };

        let caps = analyze_binary_properties(&props);

        // Should detect no security features
        assert!(caps.iter().any(|c| c.id == "binary/security/none"));
        assert_eq!(
            caps.iter().find(|c| c.id == "binary/security/none").unwrap().conf,
            1.0
        );
    }

    #[test]
    fn test_analyze_binary_properties_stripped() {
        let props = BinaryProperties {
            security: SecurityFeatures {
                canary: true,
                nx: true,
                pic: true,
                relro: "full".to_string(),
                stripped: true,
                uses_crypto: false,
                signed: false,
            },
            linking: LinkingInfo {
                is_static: false,
                libraries: Vec::new(),
                rpath: Vec::new(),
            },
            anomalies: Vec::new(),
        };

        let caps = analyze_binary_properties(&props);

        // Should detect stripped binary
        assert!(caps.iter().any(|c| c.id == "anti-analysis/stripped"));
        assert_eq!(
            caps.iter().find(|c| c.id == "anti-analysis/stripped").unwrap().conf,
            1.0
        );
    }

    #[test]
    fn test_analyze_binary_properties_static_linking() {
        let props = BinaryProperties {
            security: SecurityFeatures {
                canary: true,
                nx: true,
                pic: false,
                relro: "none".to_string(),
                stripped: false,
                uses_crypto: false,
                signed: false,
            },
            linking: LinkingInfo {
                is_static: true,
                libraries: Vec::new(),
                rpath: Vec::new(),
            },
            anomalies: Vec::new(),
        };

        let caps = analyze_binary_properties(&props);

        // Should detect static linking
        assert!(caps.iter().any(|c| c.id == "binary/linking/static"));
    }

    #[test]
    fn test_analyze_binary_properties_anomalies() {
        let props = BinaryProperties {
            security: SecurityFeatures {
                canary: true,
                nx: true,
                pic: true,
                relro: "full".to_string(),
                stripped: false,
                uses_crypto: false,
                signed: false,
            },
            linking: LinkingInfo {
                is_static: false,
                libraries: Vec::new(),
                rpath: Vec::new(),
            },
            anomalies: vec![BinaryAnomaly {
                anomaly_type: "overlapping_functions".to_string(),
                desc: "Functions overlap in memory".to_string(),
                severity: "medium".to_string(),
            }],
        };

        let caps = analyze_binary_properties(&props);

        // Should detect anomaly
        assert!(caps.iter().any(|c| c.id == "anti-analysis/format/overlapping"));
        assert_eq!(
            caps.iter().find(|c| c.id == "anti-analysis/format/overlapping").unwrap().conf,
            0.8
        );
    }

    #[test]
    fn test_analyze_function_with_noreturn() {
        let mut func = create_test_function("exit_wrapper");
        func.properties = Some(FunctionProperties {
            is_pure: false,
            is_noreturn: true,
            is_recursive: false,
            stack_frame: 0,
            local_vars: 0,
            args: 0,
            is_leaf: false,
        });

        let caps = analyze_function(&func);

        // Should detect noreturn
        assert!(caps.iter().any(|c| c.id == "execution/terminate"));
    }

    #[test]
    fn test_analyze_function_integration() {
        let mut func = create_test_function("malicious_func");

        // Add control flow
        func.control_flow = Some(ControlFlowMetrics {
            basic_blocks: 15,
            edges: 20,
            cyclomatic_complexity: 12,
            max_block_size: 40,
            avg_block_size: 12.0,
            is_linear: false,
            loop_count: 2,
            branch_density: 0.25,
            in_degree: 1,
            out_degree: 4,
        });

        // Add instruction analysis
        func.instruction_analysis = Some(InstructionAnalysis {
            total_instructions: 100,
            instruction_cost: 500,
            instruction_density: 1.5,
            categories: InstructionCategories {
                arithmetic: 20,
                logic: 25,
                memory: 30,
                control: 15,
                system: 2,
                fpu_simd: 0,
                string_ops: 5,
                privileged: 0,
                crypto: 0,
            },
            top_opcodes: vec![],
            unusual_instructions: vec!["rdtsc".to_string()],
        });

        // Add constants
        func.constants = vec![EmbeddedConstant {
            value: "0x08080808".to_string(),
            constant_type: "dword".to_string(),
            decoded: vec![DecodedValue {
                value_type: "ip_address".to_string(),
                decoded_value: "8.8.8.8".to_string(),
                conf: 0.8,
            }],
        }];

        let caps = analyze_function(&func);

        // Should detect multiple capabilities
        assert!(caps.len() >= 5); // complexity/high, data/encode, timing, xor, syscall, c2
        assert!(caps.iter().any(|c| c.id == "complexity/high"));
        assert!(caps.iter().any(|c| c.id == "anti-analysis/anti-debug/timing"));
        assert!(caps.iter().any(|c| c.id == "crypto/xor"));
        assert!(caps.iter().any(|c| c.id == "net/command-and-control/address"));
    }
}
