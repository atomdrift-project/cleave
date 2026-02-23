//! Universal text metrics for all text files

use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32, is_zero_u64};

// =============================================================================
// UNIVERSAL TEXT METRICS (All text files)
// =============================================================================

// =============================================================================

/// Text-level metrics computed on raw file content
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TextMetrics {
    // === Character Distribution ===
    /// Shannon entropy of character distribution (0-8, normal code ~4.5)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub char_entropy: f32,
    /// Number of distinct characters used
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_chars: u32,
    /// Most frequent non-whitespace character
    #[serde(skip_serializing_if = "Option::is_none")]
    pub most_common_char: Option<char>,
    /// Ratio of most common char to total (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub most_common_ratio: f32,

    // === Byte-Level Analysis ===
    /// Ratio of non-ASCII bytes (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub non_ascii_ratio: f32,
    /// Ratio of non-printable control characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub non_printable_ratio: f32,
    /// Count of null bytes (binary in text file?)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub null_byte_count: u32,
    /// Ratio of bytes > 0x7F
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub high_byte_ratio: f32,

    // === Line Statistics ===
    /// Total lines in file
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_lines: u32,
    /// Average line length in characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_line_length: f32,
    /// Maximum line length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_line_length: u32,
    /// Standard deviation of line lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub line_length_stddev: f32,
    /// Lines over 200 characters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_200: u32,
    /// Lines over 500 characters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_500: u32,
    /// Lines over 1000 characters (strong obfuscation signal)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_1000: u32,
    /// Ratio of empty lines to total
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub empty_line_ratio: f32,

    // === Whitespace Forensics ===
    /// Ratio of whitespace to total characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub whitespace_ratio: f32,
    /// Tab characters count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tab_count: u32,
    /// Space characters count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub space_count: u32,
    /// Mixed tabs and spaces for indentation
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_indent: bool,
    /// Lines with trailing whitespace
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trailing_whitespace_lines: u32,
    /// Unicode whitespace chars (zero-width, non-breaking, etc.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unusual_whitespace: u32,

    // === Escape Sequences ===
    /// Hex escape sequences (\xNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_escape_count: u32,
    /// Unicode escapes (\uNNNN, \UNNNNNNNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_escape_count: u32,
    /// Octal escapes (\NNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub octal_escape_count: u32,
    /// Escape sequences per 100 characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub escape_density: f32,

    // === Suspicious Text Patterns ===
    /// Tokens over 100 chars without spaces
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub long_token_count: u32,
    /// Repeated character sequences (>10 same char)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub repeated_char_sequences: u32,
    /// Ratio of digits to alphanumeric characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub digit_ratio: f32,
    /// Visible ASCII art or banner patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ascii_art_lines: u32,

    // === Ratio Metrics (ML-oriented, zero-cost from existing counters) ===

    // Cross-component ratios
    /// String literals per function (malware: >20, normal: 2-10)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub strings_to_functions_ratio: f32,
    /// Unique identifiers per function (obfuscated: <3 or >50, normal: 5-20)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub identifiers_to_functions_ratio: f32,
    /// Imports per function (thin wrapper: >2, normal: 0.1-0.5)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub imports_to_functions_ratio: f32,

    // Per-line density
    /// Identifiers per line (minified: >15, normal: 3-8)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub identifier_density: f32,
    /// String literals per line (payload-heavy: >2, normal: 0.1-0.5)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_density: f32,
    /// Imports per 100 lines (normal: 0.5-5)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_density: f32,

    // Obfuscation indicators
    /// Ratio of suspicious identifier patterns (obfuscated: >0.3, normal: <0.05)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub suspicious_identifier_ratio: f32,
    /// Ratio of encoded strings (malware: >0.3, normal: <0.1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub encoded_string_ratio: f32,
    /// Ratio of code/commands in strings (malicious: >0.2, normal: <0.05)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub suspicious_string_ratio: f32,
    /// Ratio of high-entropy/base64 in comments (malware: >0.1, normal: ~0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub suspicious_comment_ratio: f32,

    // Normalized (size-independent)
    /// Functions / sqrt(lines) - structural complexity independent of size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub normalized_function_count: f32,
    /// Imports / sqrt(lines) - dependency complexity independent of size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub normalized_import_count: f32,
    /// Strings / sqrt(lines) - literal usage independent of size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub normalized_string_count: f32,
    /// Unique identifiers / log2(lines) - vocabulary richness independent of size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub normalized_unique_identifiers: f32,

    // Construction patterns
    /// Ratio of dynamically constructed strings (obfuscated: >0.5, normal: <0.2)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub dynamic_string_ratio: f32,
    /// Ratio of dynamic/conditional imports (evasive: >0.3, normal: <0.1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub dynamic_import_ratio: f32,
    /// Ratio of anonymous functions (minified: >0.7, normal: 0.1-0.4)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub anonymous_function_ratio: f32,
}

/// Identifier/naming metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentifierMetrics {
    // === Counts ===
    /// Total identifier occurrences
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Unique identifier count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_count: u32,
    /// Reuse ratio (unique/total, low = repetitive)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub reuse_ratio: f32,

    // === Length Analysis ===
    /// Average identifier length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length: f32,
    /// Minimum identifier length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_length: u32,
    /// Maximum identifier length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length: u32,
    /// Standard deviation of lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub length_stddev: f32,
    /// Single-character identifiers (a, b, x, i)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_count: u32,
    /// Ratio of single-char to total (high = obfuscation)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub single_char_ratio: f32,

    // === Entropy/Randomness ===
    /// Average entropy per identifier name
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_entropy: f32,
    /// Identifiers with entropy > 3.5 (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_count: u32,
    /// Ratio of high-entropy identifiers
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub high_entropy_ratio: f32,

    // === Naming Patterns ===
    /// All lowercase identifiers ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub all_lowercase_ratio: f32,
    /// All uppercase identifiers ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub all_uppercase_ratio: f32,
    /// Identifiers containing digits
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub has_digit_ratio: f32,
    /// Underscore-prefixed identifiers (_var, __var)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub underscore_prefix_count: u32,
    /// Double-underscore identifiers (__dunder__)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub double_underscore_count: u32,
    /// Numeric suffix patterns (var1, var2, var3)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub numeric_suffix_count: u32,

    // === Suspicious Patterns ===
    /// Names that look like hex (deadbeef, cafebabe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_like_names: u32,
    /// Names matching base64 character set
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_like_names: u32,
    /// Sequential patterns (a, b, c or var1, var2)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sequential_names: u32,
    /// Keyboard patterns (qwerty, asdf)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub keyboard_pattern_names: u32,
    /// Names that are just repeated chars (aaa, xxx)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub repeated_char_names: u32,
}

/// String literal metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringMetrics {
    // === Counts & Sizes ===
    /// Total string literals
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Total bytes in all strings
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_bytes: u64,
    /// Average string length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length: f32,
    /// Maximum string length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length: u32,
    /// Empty string count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_count: u32,

    // === Entropy Analysis ===
    /// Average entropy across all strings
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_entropy: f32,
    /// Standard deviation of string entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub entropy_stddev: f32,
    /// Strings with entropy > 5.0
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_count: u32,
    /// Strings with entropy > 6.5 (encrypted/compressed)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_high_entropy_count: u32,

    // === Encoding Patterns ===
    /// Strings matching base64 pattern
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_candidates: u32,
    /// Pure hexadecimal strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_strings: u32,
    /// URL-encoded strings (%XX patterns)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_encoded_strings: u32,
    /// Strings with many unicode escapes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_heavy_strings: u32,

    // === Content Categories ===
    /// URL strings detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_count: u32,
    /// File path strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub path_count: u32,
    /// IP address strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ip_count: u32,
    /// Email address strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub email_count: u32,
    /// Domain name strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub domain_count: u32,

    // === Construction Patterns (from AST) ===
    /// String concatenation operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub concat_operations: u32,
    /// Format strings (f-strings, .format, sprintf)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub format_strings: u32,
    /// Character-by-character construction (chr/fromCharCode)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_construction: u32,
    /// Array join construction ([].join)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub array_join_construction: u32,

    // === Suspicious Patterns ===
    /// Very long strings (> 1000 chars)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_long_strings: u32,
    /// Strings containing code-like patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_code_candidates: u32,
    /// Strings with shell command patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_command_strings: u32,
    /// Strings with SQL patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sql_strings: u32,
}

/// Comment and documentation metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommentMetrics {
    /// Total comment count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Lines that are comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines: u32,
    /// Total characters in comments
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub chars: u64,
    /// Comment to code ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub to_code_ratio: f32,

    // === Comment Patterns ===
    /// TODO comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub todo_count: u32,
    /// FIXME comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fixme_count: u32,
    /// HACK comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hack_count: u32,
    /// XXX comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xxx_count: u32,
    /// Empty comments (// or /* */)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_comments: u32,

    // === Suspicious Patterns ===
    /// High-entropy comments (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_comments: u32,
    /// Comments containing code
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_in_comments: u32,
    /// URLs in comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_in_comments: u32,
    /// Base64 in comments (hidden payloads)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_in_comments: u32,
}

/// Function/method metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionMetrics {
    // === Counts ===
    /// Total functions/methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Anonymous functions (lambdas, closures)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub anonymous: u32,
    /// Async functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub async_count: u32,
    /// Generator functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub generator_count: u32,

    // === Size Analysis ===
    /// Average function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length_lines: f32,
    /// Maximum function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length_lines: u32,
    /// Minimum function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_length_lines: u32,
    /// Standard deviation of function lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub length_stddev: f32,
    /// Functions over 100 lines
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub over_100_lines: u32,
    /// Functions over 500 lines (very suspicious)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub over_500_lines: u32,
    /// One-liner functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub one_liners: u32,

    // === Parameter Analysis ===
    /// Average parameter count
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_params: f32,
    /// Maximum parameter count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_params: u32,
    /// Functions with no parameters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub no_params_count: u32,
    /// Functions with many parameters (>7)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub many_params_count: u32,
    /// Average parameter name length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_param_name_length: f32,
    /// Single-char parameter names (x, y, a)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_params: u32,

    // === Naming Analysis ===
    /// Average function name length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_name_length: f32,
    /// Single-char function names
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_names: u32,
    /// High entropy function names (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_names: u32,
    /// Numeric-suffix function names (func1, func2)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub numeric_suffix_names: u32,

    // === Nesting & Complexity ===
    /// Maximum nesting depth across all functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_nesting_depth: u32,
    /// Average nesting depth
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_nesting_depth: f32,
    /// Nested function definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_functions: u32,
    /// Recursive functions detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_count: u32,

    // === Density ===
    /// Functions per 100 lines of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub density_per_100_lines: f32,
    /// Code to function ratio (lines in functions / total lines)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_in_functions_ratio: f32,
}

/// Statement-level metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatementMetrics {
    // === Counts ===
    /// Total statements in file
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Expression statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub expression_statements: u32,
    /// Assignment statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assignment_statements: u32,
    /// Return statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub return_statements: u32,
    /// Control flow statements (if/while/for/switch)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub control_flow_statements: u32,
    /// Try/catch/exception handling statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exception_statements: u32,

    // === Density ===
    /// Average statements per function
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub per_function: f32,
    /// Average statements per line (>1.5 = minified/obfuscated)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub per_line: f32,
    /// Maximum statements on one line (>5 = red flag)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_per_line: u32,

    // === Ratios ===
    /// Ratio of assignments to total statements
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub assignment_ratio: f32,
    /// Ratio of control flow to total statements
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub control_flow_ratio: f32,
    /// Ratio of return statements to total statements
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub return_ratio: f32,
}

/// Import/dependency metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportMetrics {
    // === Counts ===
    /// Total import statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Unique modules imported
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_modules: u32,
    /// Standard library imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stdlib_count: u32,
    /// Third-party/external imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub third_party_count: u32,
    /// Local/relative imports (., .., relative paths)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub relative_imports: u32,

    // === Suspicious Patterns ===
    /// Wildcard imports (from x import *)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wildcard_imports: u32,
    /// Dynamic imports (__import__, importlib, require with variables)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynamic_imports: u32,
    /// Aliased imports (import x as y)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub aliased_imports: u32,
    /// Conditional imports (inside if/try blocks)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub conditional_imports: u32,

    // === Ratios ===
    /// Ratio of stdlib to total imports
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub stdlib_ratio: f32,
    /// Ratio of third-party to total imports
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub third_party_ratio: f32,
    /// Ratio of relative to total imports
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub relative_ratio: f32,
}

// =============================================================================
// LANGUAGE-SPECIFIC METRICS
// =============================================================================

// =============================================================================
// VALID FIELD PATHS FOR YAML VALIDATION
// =============================================================================

use super::field_paths::ValidFieldPaths;

impl ValidFieldPaths for TextMetrics {
    fn valid_field_paths() -> Vec<&'static str> {
        vec![
            // Character Distribution
            "char_entropy",
            "unique_chars",
            "most_common_char",
            "most_common_ratio",
            // Byte-Level Analysis
            "non_ascii_ratio",
            "non_printable_ratio",
            "null_byte_count",
            "high_byte_ratio",
            // Line Statistics
            "total_lines",
            "avg_line_length",
            "max_line_length",
            "line_length_stddev",
            "lines_over_200",
            "lines_over_500",
            "lines_over_1000",
            "empty_line_ratio",
            // Whitespace Forensics
            "whitespace_ratio",
            "tab_count",
            "space_count",
            "mixed_indent",
            "trailing_whitespace_lines",
            "unusual_whitespace",
            // Escape Sequences
            "hex_escape_count",
            "unicode_escape_count",
            "octal_escape_count",
            "escape_density",
            // Suspicious Text Patterns
            "long_token_count",
            "repeated_char_sequences",
            "digit_ratio",
            "ascii_art_lines",
            // Ratio Metrics
            "strings_to_functions_ratio",
            "identifiers_to_functions_ratio",
            "imports_to_functions_ratio",
            "identifier_density",
            "string_density",
            "import_density",
            "suspicious_identifier_ratio",
            "encoded_string_ratio",
            "suspicious_string_ratio",
            "suspicious_comment_ratio",
            "normalized_function_count",
            "normalized_import_count",
            "normalized_string_count",
            "normalized_unique_identifiers",
            "dynamic_string_ratio",
            "dynamic_import_ratio",
            "anonymous_function_ratio",
        ]
    }
}

impl ValidFieldPaths for IdentifierMetrics {
    fn valid_field_paths() -> Vec<&'static str> {
        vec![
            "total",
            "unique_count",
            "reuse_ratio",
            "avg_length",
            "min_length",
            "max_length",
            "length_stddev",
            "single_char_count",
            "single_char_ratio",
            "avg_entropy",
            "high_entropy_count",
            "high_entropy_ratio",
            "all_lowercase_ratio",
            "all_uppercase_ratio",
            "has_digit_ratio",
            "underscore_prefix_count",
            "double_underscore_count",
            "numeric_suffix_count",
            "hex_like_names",
            "base64_like_names",
            "sequential_names",
            "keyboard_pattern_names",
            "repeated_char_names",
        ]
    }
}

impl ValidFieldPaths for StringMetrics {
    fn valid_field_paths() -> Vec<&'static str> {
        vec![
            "total",
            "total_bytes",
            "avg_length",
            "max_length",
            "empty_count",
            "avg_entropy",
            "entropy_stddev",
            "high_entropy_count",
            "very_high_entropy_count",
            "base64_candidates",
            "hex_strings",
            "url_encoded_strings",
            "unicode_heavy_strings",
            "url_count",
            "path_count",
            "ip_count",
            "email_count",
            "domain_count",
            "concat_operations",
            "format_strings",
            "char_construction",
            "array_join_construction",
            "very_long_strings",
            "embedded_code_candidates",
            "shell_command_strings",
            "sql_strings",
        ]
    }
}

impl ValidFieldPaths for CommentMetrics {
    fn valid_field_paths() -> Vec<&'static str> {
        vec![
            "total",
            "lines",
            "chars",
            "to_code_ratio",
            "todo_count",
            "fixme_count",
            "hack_count",
            "xxx_count",
            "empty_comments",
            "high_entropy_comments",
            "code_in_comments",
            "url_in_comments",
            "base64_in_comments",
        ]
    }
}

impl ValidFieldPaths for FunctionMetrics {
    fn valid_field_paths() -> Vec<&'static str> {
        vec![
            "total",
            "anonymous",
            "async_count",
            "generator_count",
            "avg_length_lines",
            "max_length_lines",
            "min_length_lines",
            "length_stddev",
            "over_100_lines",
            "over_500_lines",
            "one_liners",
            "avg_params",
            "max_params",
            "no_params_count",
            "many_params_count",
            "avg_param_name_length",
            "single_char_params",
            "avg_name_length",
            "single_char_names",
            "high_entropy_names",
            "numeric_suffix_names",
            "max_nesting_depth",
            "avg_nesting_depth",
            "nested_functions",
            "recursive_count",
            "density_per_100_lines",
            "code_in_functions_ratio",
        ]
    }
}

impl ValidFieldPaths for StatementMetrics {
    fn valid_field_paths() -> Vec<&'static str> {
        vec![
            "total",
            "expression_statements",
            "assignment_statements",
            "return_statements",
            "control_flow_statements",
            "exception_statements",
            "per_function",
            "per_line",
            "max_per_line",
            "assignment_ratio",
            "control_flow_ratio",
            "return_ratio",
        ]
    }
}

impl ValidFieldPaths for ImportMetrics {
    fn valid_field_paths() -> Vec<&'static str> {
        vec![
            "total",
            "unique_modules",
            "stdlib_count",
            "third_party_count",
            "relative_imports",
            "wildcard_imports",
            "dynamic_imports",
            "aliased_imports",
            "conditional_imports",
            "stdlib_ratio",
            "third_party_ratio",
            "relative_ratio",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== TextMetrics Tests ====================

    #[test]
    fn test_text_metrics_default() {
        let metrics = TextMetrics::default();
        assert_eq!(metrics.char_entropy, 0.0);
        assert_eq!(metrics.total_lines, 0);
        assert!(metrics.most_common_char.is_none());
        assert!(!metrics.mixed_indent);
    }

    #[test]
    fn test_text_metrics_creation() {
        let metrics = TextMetrics {
            char_entropy: 4.5,
            unique_chars: 75,
            total_lines: 100,
            avg_line_length: 45.0,
            max_line_length: 200,
            ..Default::default()
        };
        assert!((metrics.char_entropy - 4.5).abs() < f32::EPSILON);
        assert_eq!(metrics.total_lines, 100);
    }

    #[test]
    fn test_text_metrics_escape_sequences() {
        let metrics = TextMetrics {
            hex_escape_count: 50,
            unicode_escape_count: 25,
            octal_escape_count: 10,
            escape_density: 1.5,
            ..Default::default()
        };
        assert_eq!(metrics.hex_escape_count, 50);
        assert!((metrics.escape_density - 1.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_text_metrics_whitespace() {
        let metrics = TextMetrics {
            whitespace_ratio: 0.15,
            tab_count: 100,
            space_count: 500,
            mixed_indent: true,
            unusual_whitespace: 5,
            ..Default::default()
        };
        assert!(metrics.mixed_indent);
        assert_eq!(metrics.unusual_whitespace, 5);
    }

    #[test]
    fn test_text_metrics_long_lines() {
        let metrics = TextMetrics {
            lines_over_200: 10,
            lines_over_500: 3,
            lines_over_1000: 1,
            ..Default::default()
        };
        assert_eq!(metrics.lines_over_200, 10);
        assert_eq!(metrics.lines_over_1000, 1);
    }

    // ==================== IdentifierMetrics Tests ====================

    #[test]
    fn test_identifier_metrics_default() {
        let metrics = IdentifierMetrics::default();
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.unique_count, 0);
        assert_eq!(metrics.avg_length, 0.0);
    }

    #[test]
    fn test_identifier_metrics_creation() {
        let metrics = IdentifierMetrics {
            total: 500,
            unique_count: 150,
            reuse_ratio: 0.3,
            avg_length: 8.5,
            min_length: 1,
            max_length: 25,
            ..Default::default()
        };
        assert_eq!(metrics.total, 500);
        assert_eq!(metrics.unique_count, 150);
    }

    #[test]
    fn test_identifier_metrics_entropy() {
        let metrics = IdentifierMetrics {
            avg_entropy: 3.2,
            high_entropy_count: 20,
            high_entropy_ratio: 0.15,
            ..Default::default()
        };
        assert!((metrics.high_entropy_ratio - 0.15).abs() < f32::EPSILON);
    }

    #[test]
    fn test_identifier_metrics_suspicious() {
        let metrics = IdentifierMetrics {
            hex_like_names: 5,
            base64_like_names: 3,
            sequential_names: 10,
            keyboard_pattern_names: 2,
            repeated_char_names: 1,
            ..Default::default()
        };
        assert_eq!(metrics.hex_like_names, 5);
        assert_eq!(metrics.sequential_names, 10);
    }

    #[test]
    fn test_identifier_metrics_single_char() {
        let metrics = IdentifierMetrics {
            single_char_count: 50,
            single_char_ratio: 0.1,
            ..Default::default()
        };
        assert_eq!(metrics.single_char_count, 50);
    }

    // ==================== StringMetrics Tests ====================

    #[test]
    fn test_string_metrics_default() {
        let metrics = StringMetrics::default();
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.total_bytes, 0);
    }

    #[test]
    fn test_string_metrics_creation() {
        let metrics = StringMetrics {
            total: 200,
            total_bytes: 5000,
            avg_length: 25.0,
            max_length: 500,
            empty_count: 5,
            ..Default::default()
        };
        assert_eq!(metrics.total, 200);
        assert_eq!(metrics.total_bytes, 5000);
    }

    #[test]
    fn test_string_metrics_entropy() {
        let metrics = StringMetrics {
            avg_entropy: 4.5,
            entropy_stddev: 1.2,
            high_entropy_count: 15,
            very_high_entropy_count: 3,
            ..Default::default()
        };
        assert_eq!(metrics.high_entropy_count, 15);
        assert_eq!(metrics.very_high_entropy_count, 3);
    }

    #[test]
    fn test_string_metrics_encoding() {
        let metrics = StringMetrics {
            base64_candidates: 10,
            hex_strings: 5,
            url_encoded_strings: 3,
            unicode_heavy_strings: 2,
            ..Default::default()
        };
        assert_eq!(metrics.base64_candidates, 10);
    }

    #[test]
    fn test_string_metrics_content() {
        let metrics = StringMetrics {
            url_count: 20,
            path_count: 30,
            ip_count: 5,
            email_count: 2,
            domain_count: 15,
            ..Default::default()
        };
        assert_eq!(metrics.url_count, 20);
        assert_eq!(metrics.path_count, 30);
    }

    #[test]
    fn test_string_metrics_construction() {
        let metrics = StringMetrics {
            concat_operations: 50,
            format_strings: 20,
            char_construction: 10,
            array_join_construction: 5,
            ..Default::default()
        };
        assert_eq!(metrics.concat_operations, 50);
        assert_eq!(metrics.char_construction, 10);
    }

    // ==================== CommentMetrics Tests ====================

    #[test]
    fn test_comment_metrics_default() {
        let metrics = CommentMetrics::default();
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.lines, 0);
    }

    #[test]
    fn test_comment_metrics_creation() {
        let metrics = CommentMetrics {
            total: 100,
            lines: 150,
            chars: 5000,
            to_code_ratio: 0.2,
            ..Default::default()
        };
        assert_eq!(metrics.total, 100);
        assert_eq!(metrics.chars, 5000);
    }

    #[test]
    fn test_comment_metrics_patterns() {
        let metrics = CommentMetrics {
            todo_count: 10,
            fixme_count: 5,
            hack_count: 2,
            xxx_count: 1,
            empty_comments: 3,
            ..Default::default()
        };
        assert_eq!(metrics.todo_count, 10);
        assert_eq!(metrics.fixme_count, 5);
    }

    #[test]
    fn test_comment_metrics_suspicious() {
        let metrics = CommentMetrics {
            high_entropy_comments: 3,
            code_in_comments: 5,
            url_in_comments: 10,
            base64_in_comments: 2,
            ..Default::default()
        };
        assert_eq!(metrics.high_entropy_comments, 3);
        assert_eq!(metrics.base64_in_comments, 2);
    }

    // ==================== FunctionMetrics Tests ====================

    #[test]
    fn test_function_metrics_default() {
        let metrics = FunctionMetrics::default();
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.anonymous, 0);
    }

    #[test]
    fn test_function_metrics_creation() {
        let metrics = FunctionMetrics {
            total: 50,
            anonymous: 10,
            async_count: 5,
            generator_count: 2,
            ..Default::default()
        };
        assert_eq!(metrics.total, 50);
        assert_eq!(metrics.anonymous, 10);
    }

    #[test]
    fn test_function_metrics_size() {
        let metrics = FunctionMetrics {
            avg_length_lines: 25.5,
            max_length_lines: 200,
            min_length_lines: 1,
            length_stddev: 15.0,
            over_100_lines: 5,
            over_500_lines: 1,
            one_liners: 10,
            ..Default::default()
        };
        assert_eq!(metrics.max_length_lines, 200);
        assert_eq!(metrics.over_100_lines, 5);
    }

    #[test]
    fn test_function_metrics_params() {
        let metrics = FunctionMetrics {
            avg_params: 3.5,
            max_params: 15,
            no_params_count: 10,
            many_params_count: 2,
            single_char_params: 20,
            ..Default::default()
        };
        assert_eq!(metrics.max_params, 15);
        assert_eq!(metrics.single_char_params, 20);
    }

    #[test]
    fn test_function_metrics_nesting() {
        let metrics = FunctionMetrics {
            max_nesting_depth: 10,
            avg_nesting_depth: 3.5,
            nested_functions: 5,
            recursive_count: 2,
            ..Default::default()
        };
        assert_eq!(metrics.max_nesting_depth, 10);
        assert_eq!(metrics.recursive_count, 2);
    }

    #[test]
    fn test_function_metrics_naming() {
        let metrics = FunctionMetrics {
            avg_name_length: 12.5,
            single_char_names: 3,
            high_entropy_names: 5,
            numeric_suffix_names: 10,
            ..Default::default()
        };
        assert_eq!(metrics.single_char_names, 3);
        assert_eq!(metrics.numeric_suffix_names, 10);
    }
}
