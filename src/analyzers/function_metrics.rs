//! Function/method metrics analyzer
//!
//! Analyzes function definitions for structural anomalies and obfuscation detection.
//! Works with AST-extracted function information.

use crate::types::FunctionMetrics;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Information about a single function for metrics computation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct FunctionInfo {
    pub name: String,
    pub line_count: u32,
    pub param_count: u32,
    pub param_names: Vec<String>,
    pub start_line: u32,
    pub end_line: u32,
    pub is_anonymous: bool,
    pub is_async: bool,
    pub is_generator: bool,
    pub nesting_depth: u32,
    pub contains_nested_functions: bool,
}

/// Analyze a collection of functions and compute metrics
#[must_use]
pub(crate) fn analyze_functions(functions: &[FunctionInfo], total_lines: u32) -> FunctionMetrics {
    let mut metrics = FunctionMetrics::default();

    if functions.is_empty() {
        return metrics;
    }

    metrics.total = functions.len() as u32;

    // Collect statistics
    let mut lengths: Vec<u32> = Vec::with_capacity(functions.len());
    let mut param_counts: Vec<u32> = Vec::with_capacity(functions.len());
    let mut name_lengths: Vec<usize> = Vec::with_capacity(functions.len());
    let mut nesting_depths: Vec<u32> = Vec::with_capacity(functions.len());
    let mut total_lines_in_functions: u32 = 0;
    let mut all_param_names: Vec<String> = Vec::new();

    for func in functions {
        lengths.push(func.line_count);
        param_counts.push(func.param_count);
        nesting_depths.push(func.nesting_depth);
        total_lines_in_functions += func.line_count;

        if !func.name.is_empty() {
            name_lengths.push(func.name.len());
        }

        all_param_names.extend(func.param_names.clone());

        // Counts
        if func.is_anonymous {
            metrics.anonymous += 1;
        }
        if func.is_async {
            metrics.async_count += 1;
        }
        if func.is_generator {
            metrics.generator_count += 1;
        }
        if func.contains_nested_functions {
            metrics.nested_functions += 1;
        }

        // Length thresholds
        if func.line_count > 100 {
            metrics.over_100_lines += 1;
        }
        if func.line_count > 500 {
            metrics.over_500_lines += 1;
        }
        if func.line_count <= 1 {
            metrics.one_liners += 1;
        }

        // Parameter thresholds
        if func.param_count == 0 {
            metrics.no_params_count += 1;
        }
        if func.param_count > 7 {
            metrics.many_params_count += 1;
        }

        // Name analysis
        if !func.name.is_empty() {
            if func.name.len() == 1 {
                metrics.single_char_names += 1;
            }
            if calculate_entropy(&func.name) > 3.5 {
                metrics.high_entropy_names += 1;
            }
            if has_numeric_suffix(&func.name) {
                metrics.numeric_suffix_names += 1;
            }
        }
    }

    // === Size Analysis ===
    if !lengths.is_empty() {
        let sum: u32 = lengths.iter().sum();
        metrics.avg_length_lines = sum as f32 / lengths.len() as f32;
        metrics.max_length_lines = *lengths.iter().max().unwrap_or(&0);
        metrics.min_length_lines = *lengths.iter().min().unwrap_or(&0);

        // Standard deviation
        let mean = metrics.avg_length_lines;
        let variance: f32 = lengths
            .iter()
            .map(|&len| {
                let diff = len as f32 - mean;
                diff * diff
            })
            .sum::<f32>()
            / lengths.len() as f32;
        metrics.length_stddev = variance.sqrt();
    }

    // === Parameter Analysis ===
    if !param_counts.is_empty() {
        let sum: u32 = param_counts.iter().sum();
        metrics.avg_params = sum as f32 / param_counts.len() as f32;
        metrics.max_params = *param_counts.iter().max().unwrap_or(&0);
    }

    // Parameter name analysis
    if !all_param_names.is_empty() {
        let total_len: usize = all_param_names.iter().map(std::string::String::len).sum();
        metrics.avg_param_name_length = total_len as f32 / all_param_names.len() as f32;
        metrics.single_char_params = all_param_names.iter().filter(|s| s.len() == 1).count() as u32;
    }

    // === Naming Analysis ===
    if !name_lengths.is_empty() {
        let sum: usize = name_lengths.iter().sum();
        metrics.avg_name_length = sum as f32 / name_lengths.len() as f32;
    }

    // === Nesting Analysis ===
    if !nesting_depths.is_empty() {
        metrics.max_nesting_depth = *nesting_depths.iter().max().unwrap_or(&0);
        let sum: u32 = nesting_depths.iter().sum();
        metrics.avg_nesting_depth = sum as f32 / nesting_depths.len() as f32;
    }

    // === Density ===
    if total_lines > 0 {
        metrics.density_per_100_lines = (metrics.total as f32 / total_lines as f32) * 100.0;
        metrics.code_in_functions_ratio = total_lines_in_functions as f32 / total_lines as f32;
    }

    // Detect recursive functions (simple heuristic: name appears in its own body)
    // This would require body analysis, so we'll leave it for language-specific analyzers

    metrics
}

/// Calculate Shannon entropy of a string
fn calculate_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let total = s.chars().count();

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    freq.values()
        .map(|&count| {
            let p = count as f32 / total as f32;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

/// Check if name has numeric suffix (func1, handler2, etc.)
fn has_numeric_suffix(name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    if chars.len() < 2 {
        return false;
    }
    let last = chars[chars.len() - 1];
    let second_last = chars[chars.len() - 2];
    last.is_ascii_digit() && second_last.is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_functions() {
        let metrics = analyze_functions(&[], 100);
        assert_eq!(metrics.total, 0);
    }

    #[test]
    fn test_basic_functions() {
        let functions = vec![
            FunctionInfo {
                name: "hello".to_string(),
                line_count: 10,
                param_count: 2,
                param_names: vec!["name".to_string(), "age".to_string()],
                ..Default::default()
            },
            FunctionInfo {
                name: "world".to_string(),
                line_count: 20,
                param_count: 1,
                param_names: vec!["x".to_string()],
                ..Default::default()
            },
        ];
        let metrics = analyze_functions(&functions, 100);
        assert_eq!(metrics.total, 2);
        assert_eq!(metrics.avg_length_lines, 15.0);
        assert_eq!(metrics.max_length_lines, 20);
        assert_eq!(metrics.avg_params, 1.5);
    }

    #[test]
    fn test_anonymous_functions() {
        let functions = vec![
            FunctionInfo {
                name: String::new(),
                is_anonymous: true,
                line_count: 5,
                ..Default::default()
            },
            FunctionInfo {
                name: "named".to_string(),
                line_count: 10,
                ..Default::default()
            },
        ];
        let metrics = analyze_functions(&functions, 50);
        assert_eq!(metrics.anonymous, 1);
    }

    #[test]
    fn test_long_functions() {
        let functions = vec![
            FunctionInfo {
                name: "small".to_string(),
                line_count: 10,
                ..Default::default()
            },
            FunctionInfo {
                name: "medium".to_string(),
                line_count: 150,
                ..Default::default()
            },
            FunctionInfo {
                name: "huge".to_string(),
                line_count: 600,
                ..Default::default()
            },
        ];
        let metrics = analyze_functions(&functions, 1000);
        assert_eq!(metrics.over_100_lines, 2);
        assert_eq!(metrics.over_500_lines, 1);
    }

    #[test]
    fn test_function_density() {
        let functions = vec![
            FunctionInfo {
                name: "a".to_string(),
                line_count: 10,
                ..Default::default()
            },
            FunctionInfo {
                name: "b".to_string(),
                line_count: 10,
                ..Default::default()
            },
        ];
        let metrics = analyze_functions(&functions, 100);
        assert_eq!(metrics.density_per_100_lines, 2.0);
        assert_eq!(metrics.code_in_functions_ratio, 0.2);
    }

    #[test]
    fn test_single_char_params() {
        let functions = vec![FunctionInfo {
            name: "func".to_string(),
            param_count: 4,
            param_names: vec![
                "x".to_string(),
                "y".to_string(),
                "name".to_string(),
                "a".to_string(),
            ],
            line_count: 10,
            ..Default::default()
        }];
        let metrics = analyze_functions(&functions, 50);
        assert_eq!(metrics.single_char_params, 3);
    }

    #[test]
    fn test_numeric_suffix_detection() {
        assert!(has_numeric_suffix("func1"));
        assert!(has_numeric_suffix("handler2"));
        assert!(!has_numeric_suffix("func"));
        assert!(!has_numeric_suffix("1func"));
        assert!(!has_numeric_suffix("a"));
    }
}
