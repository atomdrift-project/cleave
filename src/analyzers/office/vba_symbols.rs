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
//!   per-module logical-line and identifier-randomness heuristics
//!   (not symbol extraction)
//! - [`IdentifierStats`] — streaming entropy/mean-length accumulator
//!   the office analyzer feeds filefacts-emitted names into
//! - [`is_trigger_handler`] — closed-set predicate over VBA's
//!   auto-execution vocabulary
//! - [`NON_LITERAL_SENTINEL`] — re-export of filefacts's sentinel so
//!   callers can compare `imp.library` against it
//!
//! Anything that looks like "where do imports come from?" is in
//! `filefacts/src/formats/vba_symbols.rs`.

/// Sentinel library/argument value emitted when a Declare's `Lib`
/// clause or a CreateObject/GetObject argument is not a string
/// literal. Re-exported from filefacts so cleave-side consumers don't
/// have to import the filefacts-public path.
pub(crate) const NON_LITERAL_SENTINEL: &str = filefacts::VBA_NON_LITERAL_SENTINEL;

// Trigger-handler vocabulary kept in cleave so the office analyzer's
// distinct-trigger aggregation runs without round-tripping through
// filefacts's typed views. The list mirrors filefacts's internal
// `TRIGGER_NAMES`; the two must stay in sync.
const TRIGGER_NAMES: &[&str] = &[
    "Auto_Open",
    "AutoOpen",
    "Auto_Close",
    "AutoClose",
    "AutoExec",
    "AutoExit",
    "AutoNew",
    "Document_Open",
    "Document_New",
    "Document_Close",
    "Document_BeforeClose",
    "Document_BeforePrint",
    "Document_BeforeSave",
    "Document_ContentControlOnEnter",
    "Workbook_Open",
    "Workbook_Activate",
    "Workbook_Deactivate",
    "Workbook_BeforeClose",
    "Workbook_BeforeSave",
    "Workbook_BeforePrint",
    "Worksheet_Activate",
    "Worksheet_Calculate",
    "Worksheet_Change",
    "Worksheet_SelectionChange",
    "UserForm_Activate",
    "UserForm_Initialize",
    "UserForm_Click",
    "UserForm_Layout",
    "Chart_Activate",
    "Chart_Calculate",
    "App_NewMail",
];

/// Public-facing wrapper used by the office analyzer to count distinct
/// triggers across modules.
#[must_use]
pub(crate) fn is_trigger_handler(name: &str) -> bool {
    TRIGGER_NAMES.iter().any(|t| t.eq_ignore_ascii_case(name))
}

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
/// Entropy is in bits; randomly-renamed identifier sets typically run
/// 4.0–4.7 (close to log2(26+10+_) for an alphanumeric+underscore
/// alphabet), while human-authored names cluster 3.0–3.8.
#[derive(Debug)]
pub(crate) struct IdentifierStats {
    counts: [u32; 256],
    total_chars: u64,
    total_idents: u32,
}

impl Default for IdentifierStats {
    fn default() -> Self {
        Self {
            counts: [0u32; 256],
            total_chars: 0,
            total_idents: 0,
        }
    }
}

impl IdentifierStats {
    pub(crate) fn record(&mut self, name: &str) {
        if name.is_empty() {
            return;
        }
        self.total_idents = self.total_idents.saturating_add(1);
        for b in name.bytes() {
            self.counts[b as usize] = self.counts[b as usize].saturating_add(1);
            self.total_chars = self.total_chars.saturating_add(1);
        }
    }

    /// Mean identifier length in characters (0 when no identifiers).
    pub(crate) fn mean_length(&self) -> f32 {
        if self.total_idents == 0 {
            return 0.0;
        }
        (self.total_chars as f64 / self.total_idents as f64) as f32
    }

    /// Shannon entropy in bits over the byte-frequency distribution
    /// across every identifier observed.
    pub(crate) fn entropy_bits(&self) -> f32 {
        if self.total_chars == 0 {
            return 0.0;
        }
        let total = self.total_chars as f64;
        let mut e = 0.0f64;
        for &c in &self.counts {
            if c == 0 {
                continue;
            }
            let p = c as f64 / total;
            e -= p * p.log2();
        }
        e as f32
    }
}

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

    #[test]
    fn identifier_stats_computes_mean_and_entropy() {
        let mut s = IdentifierStats::default();
        s.record("Document_Open");
        s.record("VirtualAlloc");
        s.record("RtlMoveMemory");
        let mean = s.mean_length();
        assert!((mean - 12.666_667).abs() < 0.001, "got {mean}");
        let e = s.entropy_bits();
        assert!(e > 3.0 && e < 5.0, "entropy {e} out of expected range");
    }

    #[test]
    fn identifier_stats_empty_produces_zero() {
        let s = IdentifierStats::default();
        assert_eq!(s.mean_length(), 0.0);
        assert_eq!(s.entropy_bits(), 0.0);
    }

    /// `is_trigger_handler` matches case-insensitively against the
    /// trigger vocabulary.
    #[test]
    fn trigger_handler_matches_case_insensitively() {
        assert!(is_trigger_handler("Document_Open"));
        assert!(is_trigger_handler("DOCUMENT_OPEN"));
        assert!(is_trigger_handler("workbook_open"));
        assert!(!is_trigger_handler("regularSub"));
    }
}
