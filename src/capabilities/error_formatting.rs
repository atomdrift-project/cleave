//! Enhanced error formatting for YAML parsing errors.
//!
//! Provides user-friendly error messages with context, suggestions, and clear guidance.

use anyhow::Error;
use std::path::Path;

/// Enhance a YAML parsing error with context, suggestions, and clear guidance
pub(crate) fn enhance_yaml_error(error: &Error, file_path: &Path, yaml_content: &str) -> String {
    let error_string = format!("{:#}", error);

    // Extract line and column from serde_yaml error messages
    // Pattern: "at line X column Y"
    let (line_num, col_num) = extract_line_column(&error_string);

    let mut enhanced = String::new();
    enhanced.push_str(&format!("Failed to parse YAML in {:?}", file_path));

    // If we found line info, show context
    if let Some(line) = line_num {
        enhanced.push_str(&format!("\n\n   Error at line {}:", line));

        // Show context lines
        if let Some(context) = extract_yaml_context(yaml_content, line, col_num, &error_string) {
            enhanced.push('\n');
            enhanced.push_str(&context);
        }

        // Analyze error and provide guidance
        if let Some(guidance) = provide_error_guidance(&error_string, yaml_content, line) {
            enhanced.push('\n');
            enhanced.push_str(&guidance);
        }
    } else {
        // No line info, just show the cleaned error
        enhanced.push_str(": ");
        enhanced.push_str(&clean_error_message(&error_string));
    }

    enhanced
}

/// Extract line and column numbers from error message
fn extract_line_column(error_msg: &str) -> (Option<usize>, Option<usize>) {
    fn line_regex() -> Option<&'static regex::Regex> {
        static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"at line (\d+) column (\d+)").ok())
            .as_ref()
    }

    if let Some(caps) = line_regex().and_then(|regex| regex.captures(error_msg)) {
        let line = caps.get(1).and_then(|m| m.as_str().parse().ok());
        let col = caps.get(2).and_then(|m| m.as_str().parse().ok());
        return (line, col);
    }

    (None, None)
}

/// Extract and format YAML context around the error line
fn extract_yaml_context(
    yaml_content: &str,
    error_line: usize,
    error_col: Option<usize>,
    error_msg: &str,
) -> Option<String> {
    let lines: Vec<&str> = yaml_content.lines().collect();

    if error_line == 0 || error_line > lines.len() {
        return None;
    }

    // Try to find the actual problematic line (field with error, not struct start)
    let actual_error_line = find_actual_error_line(&lines, error_line, error_msg);

    let mut context = String::from("\n");

    // Show 2 lines before, error line, and 1 line after
    let start = actual_error_line.saturating_sub(3);
    let end = (actual_error_line + 1).min(lines.len());

    for i in start..end {
        let line_num = i + 1;
        let line_content = lines.get(i)?;

        if line_num == actual_error_line {
            // This is the error line - highlight it
            context.push_str(&format!("   {:>3}│{}", line_num, line_content));

            // Add error marker
            if let Some(col) = error_col {
                context.push('\n');
                let spaces = " ".repeat(7 + col);
                context.push_str(&format!("      │{}← Error here", spaces));
            } else {
                context.push_str("  ← Error here");
            }
        } else {
            context.push_str(&format!("   {:>3}│{}", line_num, line_content));
        }
        context.push('\n');
    }

    Some(context)
}

/// Detect invalid field in YAML context by checking against known valid fields for each type
fn detect_invalid_field_in_context(context: &str) -> Option<String> {
    // Detect condition type
    let condition_type = if context.contains("type: raw") {
        "raw"
    } else if context.contains("type: string_literal") {
        "string_literal"
    } else if context.contains("type: text") {
        "text"
    } else if context.contains("type: symbol")
        || context.contains("type: import")
        || context.contains("type: export")
        || context.contains("type: function")
    {
        "symbol"
    } else if context.contains("type: hex") {
        "hex"
    } else if context.contains("type: encoded") {
        "encoded"
    } else if context.contains("type: syscall") {
        "syscall"
    } else if context.contains("type: ast") {
        "ast"
    } else if context.contains("type: value") {
        "value"
    } else {
        return None;
    };

    // Define valid fields for each condition type
    let valid_fields: &[&str] = match condition_type {
        "symbol" => &[
            "type",
            "exact",
            "substr",
            "regex",
            "platforms",
            "count_min",
            "count_max",
            "per_kb_min",
            "per_kb_max",
        ],
        "text" | "string_literal" => &[
            "type",
            "exact",
            "substr",
            "regex",
            "word",
            "case_insensitive",
            "is",
            "not",
            "platforms",
            "count_min",
            "count_max",
            "per_kb_min",
            "per_kb_max",
            "section",
            "offset",
            "offset_range",
            "section_offset",
            "section_offset_range",
        ],
        "raw" => &[
            "type",
            "exact",
            "substr",
            "regex",
            "word",
            "case_insensitive",
            "is",
            "not",
            "count_min",
            "count_max",
            "per_kb_min",
            "per_kb_max",
            "external_ip",
            "section",
            "offset",
            "offset_range",
            "section_offset",
            "section_offset_range",
        ],
        "hex" => &[
            "type",
            "pattern",
            "count_min",
            "count_max",
            "per_kb_min",
            "per_kb_max",
            "section",
            "offset",
            "offset_range",
            "section_offset",
            "section_offset_range",
        ],
        "encoded" => &[
            "type",
            "exact",
            "substr",
            "regex",
            "word",
            "case_insensitive",
            "encoding",
        ],
        "syscall" => &[
            "type",
            "name",
            "number",
            "arch",
            "count_min",
            "count_max",
            "per_kb_min",
            "per_kb_max",
        ],
        "ast" => &[
            "type",
            "kind",
            "node",
            "exact",
            "substr",
            "regex",
            "query",
            "language",
            "case_insensitive",
        ],
        "value" => &[
            "type", "path", "is", "exact", "substr", "regex", "exists", "size_min", "size_max",
        ],
        _ => return None,
    };

    // Check each line for field names
    for line in context.lines() {
        let trimmed = line.trim_start();
        if let Some(colon_pos) = trimmed.find(':') {
            let field_name = trimmed[..colon_pos].trim();

            // Skip common non-field keys
            if field_name == "if"
                || field_name == "id"
                || field_name == "desc"
                || field_name == "crit"
                || field_name == "conf"
                || field_name == "platforms"
                || field_name == "for"
                || field_name.is_empty()
            {
                continue;
            }

            // Check if this field is invalid for the condition type
            if !valid_fields.contains(&field_name) {
                return Some(match field_name {
                    "needs" => "needs".to_string(),
                    "pattern" if condition_type != "hex" && condition_type != "ast" => {
                        "pattern".to_string()
                    }
                    "match" => "match".to_string(),
                    "value" if condition_type != "value" => "value".to_string(),
                    "search" => "search".to_string(),
                    "case_sensitive" => "case_sensitive".to_string(),
                    "match_type" => "match_type".to_string(),
                    other => {
                        // Return the field name if it's clearly not a valid field
                        if other.ends_with("_min")
                            || other.ends_with("_max")
                            || other.ends_with("_count")
                        {
                            return Some(other.to_string());
                        }
                        continue;
                    }
                });
            }
        }
    }

    None
}

/// Find the actual error line by searching for problematic fields within the trait definition
fn find_actual_error_line(lines: &[&str], reported_line: usize, error_msg: &str) -> usize {
    let start_idx = reported_line.saturating_sub(1);

    // For unknown field errors, try to find the field
    if error_msg.contains("unknown field") || error_msg.contains("Unknown field") {
        if let Some(field_start) = error_msg.find("`") {
            if let Some(field_end) = error_msg[field_start + 1..].find("`") {
                let field_name = &error_msg[field_start + 1..field_start + 1 + field_end];
                // Search for the field in nearby lines
                for (i, &line) in lines
                    .iter()
                    .enumerate()
                    .skip(start_idx)
                    .take(15.min(lines.len().saturating_sub(start_idx)))
                {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with(&format!("{}:", field_name)) {
                        return i + 1; // Return 1-indexed line number
                    }
                }
            }
        }
    }

    // Search next 15 lines for "type:" field
    for (i, &line) in lines
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(15.min(lines.len().saturating_sub(start_idx)))
    {
        let line = line.trim_start();
        if line.starts_with("type:") {
            let invalid_string_type =
                line.starts_with("type: string") && !line.starts_with("type: string_literal");
            // Check if this is an invalid type
            if line.contains("type: word") || invalid_string_type || line.contains("type: regex") {
                return i + 1; // Return 1-indexed line number
            }
        }
    }

    // If not found, return original line
    reported_line
}

/// Clean up technical error messages for user consumption
fn clean_error_message(error_msg: &str) -> String {
    // Extract unknown field name if present
    if error_msg.contains("unknown field") {
        if let Some(field_start) = error_msg.find("`") {
            if let Some(field_end) = error_msg[field_start + 1..].find("`") {
                let field_name = &error_msg[field_start + 1..field_start + 1 + field_end];
                return format!("Unknown field '{}' in condition.", field_name);
            }
        }
        return "Unknown field in condition.".to_string();
    }

    // Check for invalid variant errors (wrong condition type)
    if error_msg.contains("unknown variant") {
        if let Some(variant_start) = error_msg.find("`") {
            if let Some(variant_end) = error_msg[variant_start + 1..].find("`") {
                let variant_name = &error_msg[variant_start + 1..variant_start + 1 + variant_end];
                return format!("Invalid condition type '{}'.", variant_name);
            }
        }
    }

    // Replace technical jargon with plain language
    let msg = error_msg
        .replace(
            "data did not match any variant of untagged enum ConditionDeser",
            "Invalid condition format",
        )
        .replace("unknown variant", "Invalid condition type")
        .replace("expected", "Expected");

    // Extract the most useful part
    if let Some(start) = msg.find("Invalid") {
        if let Some(end) = msg[start..].find(" at line") {
            return msg[start..start + end].to_string();
        }
        return msg[start..].split('\n').next().unwrap_or(&msg).to_string();
    }

    msg
}

/// Provide intelligent guidance based on the error type and context
fn provide_error_guidance(
    error_msg: &str,
    yaml_content: &str,
    error_line: usize,
) -> Option<String> {
    let lines: Vec<&str> = yaml_content.lines().collect();
    let error_line_idx = error_line.saturating_sub(1);

    let mut guidance = String::new();

    // Check for unknown field errors first (higher priority)
    // Search the context for field names that might be unknown
    let search_start = error_line_idx;
    let search_end = (error_line_idx + 10).min(lines.len());
    let context_lines: Vec<&str> = lines[search_start..search_end].to_vec();
    let context = context_lines.join("\n");

    // Extract the actual field name from the error message if present
    let unknown_field = if error_msg.contains("unknown field") {
        if let Some(field_start) = error_msg.find("`") {
            error_msg[field_start + 1..].find("`").map(|field_end| {
                error_msg[field_start + 1..field_start + 1 + field_end].to_string()
            })
        } else {
            None
        }
    } else if error_msg.contains("ConditionDeser") {
        // For untagged enum errors, parse the YAML to find invalid fields
        detect_invalid_field_in_context(&context)
    } else {
        None
    };

    // Check for common hallucinated field names in conditions
    let hallucinated_fields = [
        ("pattern:", "regex"),
        ("match_type:", "exact/substr/regex"),
        ("case_sensitive:", "case_insensitive"),
        ("match:", "exact/substr/regex"),
        ("value:", "exact"),
        ("search:", "substr/regex"),
    ];

    let mut found_hallucination = false;
    for (hallucinated, suggestion) in &hallucinated_fields {
        if context.contains(hallucinated) {
            guidance.push_str(&format!(
                "\n   Unknown field '{}' in condition.\n",
                hallucinated.trim_end_matches(':')
            ));
            guidance.push_str(&format!("   💡 Did you mean '{}'?\n", suggestion));
            found_hallucination = true;
            break;
        }
    }

    // Check for specific invalid fields based on condition type and field name
    if !found_hallucination {
        if let Some(field) = unknown_field {
            // Detect condition type from context
            let condition_type = if context.contains("type: raw") {
                Some("raw")
            } else if context.contains("type: string_literal") {
                Some("string_literal")
            } else if context.contains("type: text") {
                Some("text")
            } else if context.contains("type: symbol") {
                Some("symbol")
            } else if context.contains("type: hex") {
                Some("hex")
            } else if context.contains("type: encoded") {
                Some("encoded")
            } else if context.contains("type: ast") {
                Some("ast")
            } else if context.contains("type: syscall") {
                Some("syscall")
            } else {
                None
            };

            // Provide specific guidance based on field and condition type
            match (field.as_str(), condition_type) {
                ("needs", _) => {
                    guidance.push_str(&format!(
                        "\n   Field '{}' is not valid in atomic trait conditions.\n",
                        field
                    ));
                    guidance.push_str("   💡 The 'needs' field only works in composite rules (with 'any:' clauses).\n");
                    guidance.push_str(
                        "   💡 For atomic traits, use 'count_min' to require multiple matches.\n",
                    );
                    found_hallucination = true;
                }
                (field_name, Some(cond_type)) => {
                    guidance.push_str(&format!(
                        "\n   Field '{}' is not valid for 'type: {}'.\n",
                        field_name, cond_type
                    ));
                    guidance.push_str(&format!(
                        "   💡 Check the valid fields for 'type: {}' conditions.\n",
                        cond_type
                    ));
                    found_hallucination = true;
                }
                (field_name, None) => {
                    guidance.push_str(&format!(
                        "\n   Unknown field '{}' in condition.\n",
                        field_name
                    ));
                    found_hallucination = true;
                }
            }
        }
    }

    // Check for fields used with wrong condition type (value doesn't support count/density)
    if !found_hallucination
        && context.contains("type: value")
        && (context.contains("count_min:")
            || context.contains("count_max:")
            || context.contains("per_kb_min:")
            || context.contains("per_kb_max:"))
    {
        guidance.push_str("\n   Count/density fields are not valid for 'type: value'.\n");
        guidance.push_str("   💡 These fields only work with 'type: text', 'type: string_literal', 'type: raw', 'type: hex', 'type: symbol', or 'type: encoded'.\n");
        guidance.push_str("   💡 Value searches query structured data and return boolean results, not frequency counts.\n");
        found_hallucination = true;
    }

    // If no specific field error detected, check for ConditionDeser error - means invalid condition type
    // But only show this if it's not an "unknown field" error (which we handled above)
    if !found_hallucination
        && !error_msg.contains("unknown field")
        && (error_msg.contains("ConditionDeser") || error_msg.contains("Invalid condition type"))
    {
        guidance.push_str("\n   Valid condition types:\n");
        guidance.push_str("   • symbol     - Match symbol names (functions, methods)\n");
        guidance
            .push_str("   • text       - Match human-readable text (binary strings or raw text)\n");
        guidance.push_str("   • string_literal - Match AST-backed string literals only\n");
        guidance.push_str("   • raw        - Match raw file content (across boundaries)\n");
        guidance.push_str("   • hex        - Match hex patterns with wildcards\n");
        guidance.push_str("   • encoded    - Match encoded content (base64, hex, etc.)\n");
        guidance.push_str("   • trait      - Reference another trait by ID\n");
        guidance.push_str("   • ast        - Match AST patterns (requires tree-sitter)\n");
        guidance.push_str("   • yara       - Match YARA rule results\n");
        guidance.push_str("   • syscall    - Match system calls\n");
        guidance.push_str("   • section    - Section analysis (size/entropy ratio checks via compare_to + size_ratio_*/entropy_ratio_*)\n");
        guidance.push_str("   • import, export, function, metrics, basename, value\n");

        // Check for common mistakes in context
        if context.contains("type: word") {
            guidance.push_str(
                "\n   💡 Did you mean 'type: text' with a 'word:' field instead of 'type: word'?\n",
            );
        } else if context.contains("type: string_value") {
            guidance.push_str(
                "\n   💡 `type: string_value` was removed. Use 'type: text' for general text search, or 'type: string_literal' for AST-backed literal-only search.\n",
            );
        } else if context.contains("type: string") && !context.contains("type: string_literal") {
            guidance.push_str(
                "\n   💡 `type: string` was removed. Use 'type: text' for general text search, or 'type: string_literal' for AST-backed literal-only search.\n",
            );
        } else if context.contains("type: section_ratio") {
            guidance.push_str(
                "\n   💡 `type: section_ratio` was folded into `type: section`. Use `compare_to:` + `size_ratio_min:`/`size_ratio_max:` on a section condition.\n",
            );
        } else if context.contains("type: exports_count") {
            guidance.push_str(
                "\n   💡 `type: exports_count` was removed. Use `type: metrics, field: binary.export_count`.\n",
            );
        } else if context.contains("type: string_count")
            || context.contains("type: string_value_count")
        {
            guidance.push_str(
                "\n   💡 `type: string_count` was removed. Use `type: metrics, field: binary.string_count`, or count regex matches via `count_min`/`count_max` on a trait with a `type: text` condition.\n",
            );
        } else if context.contains("type: structure") {
            guidance.push_str(
                "\n   💡 `type: structure` was removed. Express file-format and architecture gates via the trait-level `for:` and `arch:` filters, or a `type: metrics` check against the relevant header field (e.g. `field: elf.e_machine`).\n",
            );
        } else if context.contains("type: import_combination") {
            guidance.push_str(
                "\n   💡 `type: import_combination` was removed. Use `type: import` and chain multiple atoms through a composite rule's `all:`/`any:`/`needs:`.\n",
            );
        } else if context.contains("type: regex") {
            guidance
                .push_str("\n   💡 Use 'type: text' with a 'regex:' field, not 'type: regex'\n");
        }
    }

    // Check for missing 'type' field
    if error_msg.contains("missing field") && error_msg.contains("`type`") {
        guidance.push_str("\n   Missing 'type' field in condition.\n");
        guidance.push_str("\n   Either:\n");
        guidance.push_str("   • Add 'type:' field (text, symbol, raw, trait, etc.)\n");
        guidance.push_str("   • Use shorthand format with just 'id:' for trait references\n");
    }

    // Check for invalid field names
    if error_msg.contains("unknown field") {
        if let Some(field_start) = error_msg.find("`") {
            if let Some(field_end) = error_msg[field_start + 1..].find("`") {
                let field_name = &error_msg[field_start + 1..field_start + 1 + field_end];
                guidance.push_str(&format!(
                    "\n   Unknown field '{}' in condition.\n",
                    field_name
                ));

                // Suggest corrections
                match field_name {
                    "match" => {
                        guidance.push_str("   💡 Did you mean 'exact', 'substr', or 'regex'?\n")
                    }
                    "pattern" => guidance.push_str("   💡 Did you mean 'regex' or 'substr'?\n"),
                    "value" => guidance.push_str("   💡 Did you mean 'exact' or 'word'?\n"),
                    "name" => guidance.push_str("   💡 Did you mean 'id' for trait references?\n"),
                    _ => {}
                }
            }
        }
    }

    if guidance.is_empty() {
        None
    } else {
        Some(guidance)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_line_column() {
        let error = "some error at line 149 column 5";
        let (line, col) = extract_line_column(error);
        assert_eq!(line, Some(149));
        assert_eq!(col, Some(5));
    }

    #[test]
    fn test_clean_error_message() {
        let error = "data did not match any variant of untagged enum ConditionDeser at line 10";
        let cleaned = clean_error_message(error);
        assert!(cleaned.contains("Invalid condition format"));
        assert!(!cleaned.contains("untagged enum"));
    }
}
