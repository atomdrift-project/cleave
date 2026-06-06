//! Module-shape helpers for the office analyzer.
//!
//! VBA *symbol extraction* (Declare / CreateObject / GetObject / Sub /
//! Function) lives entirely in filefacts and flows into cleave through
//! the typed `Imports` / `Functions` views on
//! [`crate::analysis_context::AnalysisContext`]. This module retains
//! only the cleave-side helpers the office analyzer uses alongside
//! those symbols:
//!
//! - [`compute_module_shape`] / [`looks_random_module_name`] —
//!   per-module logical-line and identifier-randomness heuristics.
//!
//! Anything that looks like "where do imports come from?" is in
//! `filefacts/src/formats/vba_symbols.rs`.

// ---------------------------------------------------------------------------
// Per-module shape statistics
// ---------------------------------------------------------------------------

/// Per-module logical-line / comment-line counts and identifier-shape
/// signals. Computed once per VBA module by [`compute_module_shape`];
/// the office analyzer aggregates across modules into `VbaMetrics`.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct VbaModuleShape {
    /// Logical lines (after `_` continuation join, before comment strip).
    /// Approximates "non-empty source lines" — empty lines are skipped.
    pub logical_lines: u32,
    /// Lines that are wholly comments (start with `'` or `Rem`).
    pub comment_lines: u32,
}

/// Walk a VBA module's raw source and tally shape stats. Cheap —
/// single byte-level scan; no regex.
#[must_use]
pub(crate) fn compute_module_shape(source: &str) -> VbaModuleShape {
    let mut shape = VbaModuleShape::default();
    let bytes = source.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        // Skip leading whitespace on this line.
        let mut j = i;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        // Pure-blank line — skip without counting.
        if j >= bytes.len() || bytes[j] == b'\n' || bytes[j] == b'\r' {
            i = next_line(bytes, j);
            continue;
        }

        shape.logical_lines = shape.logical_lines.saturating_add(1);

        // Comment-line detection: `'` at first non-whitespace, OR
        // case-insensitive `Rem` followed by whitespace/EOL.
        let is_apostrophe_comment = bytes[j] == b'\'';
        let is_rem_comment = j + 3 <= bytes.len()
            && bytes[j..j + 3].eq_ignore_ascii_case(b"Rem")
            && (bytes.get(j + 3).copied().unwrap_or(b'\n') == b' '
                || bytes.get(j + 3).copied().unwrap_or(b'\n') == b'\t'
                || bytes.get(j + 3).copied().unwrap_or(b'\n') == b'\r'
                || bytes.get(j + 3).copied().unwrap_or(b'\n') == b'\n');
        if is_apostrophe_comment || is_rem_comment {
            shape.comment_lines = shape.comment_lines.saturating_add(1);
        }

        i = next_line(bytes, j);
    }

    shape
}

fn next_line(bytes: &[u8], from: usize) -> usize {
    let mut j = from;
    while j < bytes.len() && bytes[j] != b'\n' {
        j += 1;
    }
    if j < bytes.len() { j + 1 } else { j }
}

// ---------------------------------------------------------------------------
// Module-name "looks randomly generated" heuristic
// ---------------------------------------------------------------------------

/// Returns true when a VBA module name looks mechanically generated —
/// length ≥ 8 plus a mix of upper/lower/digit characters. Real-world
/// human-authored module names rarely hit this combination
/// (`Module1`, `Sheet1`, `ThisDocument`, `clsLogger`); IcedID/Emotet
/// droppers routinely use names like `qWeRty12Ab`/`xKpL7m8sWq`.
#[must_use]
pub(crate) fn looks_random_module_name(name: &str) -> bool {
    if name.len() < 8 {
        return false;
    }
    let has_upper = name.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = name.chars().any(|c| c.is_ascii_digit());
    has_upper && has_lower && has_digit
}

// ---------------------------------------------------------------------------
// Identifier-entropy aggregation
// ---------------------------------------------------------------------------

/// Streaming accumulator for identifier shape stats — fed every
/// declared Sub/Function name and the imported-API names extracted
/// from a module. Yields the mean identifier length and the Shannon
/// entropy of the character distribution across all identifiers.
///
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Module-name heuristic: short names, all-letters names, and
    /// canonical Office module names are not flagged; mixed
    /// upper/lower/digit names of length ≥ 8 are.
    #[test]
    fn looks_random_module_name_classifies_correctly() {
        assert!(!looks_random_module_name("Module1"));
        assert!(!looks_random_module_name("ThisDocument"));
        assert!(!looks_random_module_name("clsLogger"));
        assert!(!looks_random_module_name("Sheet1"));
        assert!(!looks_random_module_name("Short"));
        assert!(looks_random_module_name("qWeRty12Ab"));
        assert!(looks_random_module_name("xKpL7m8sWq"));
    }

    /// Logical-line / comment-line accounting: blanks skipped,
    /// `'` comments and `Rem` lines counted as both logical and
    /// comment, code lines counted as logical only.
    #[test]
    fn module_shape_counts_lines_and_comments() {
        let src = "\
Sub Main()
  ' first comment line
  Dim x As Long
  Rem second comment line

  x = 1
End Sub
";
        let shape = compute_module_shape(src);
        assert_eq!(shape.logical_lines, 6, "shape: {:?}", shape);
        assert_eq!(shape.comment_lines, 2);
    }
}
