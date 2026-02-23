//! Parsing utilities for radare2/rizin output.
//!
//! This module contains helper functions for parsing various formats of output
//! from radare2/rizin commands, including:
//! - Disassembly output parsing
//! - Search result parsing
//! - Syscall number extraction from assembly

pub(super) fn calculate_char_entropy(chars: &[char]) -> f32 {
    if chars.is_empty() {
        return 0.0;
    }

    let mut freq: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    for &c in chars {
        *freq.entry(c).or_insert(0) += 1;
    }

    let total = chars.len() as f32;
    let mut entropy: f32 = 0.0;
    for &count in freq.values() {
        let p = count as f32 / total;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}
