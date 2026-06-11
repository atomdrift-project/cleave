//! Context capture: turn a file's findings into a merged, render-ready
//! [`ContextLine`] list — the matched content shown once, in file order,
//! annotated with the findings that touch it.
//!
//! This is the output surface that replaces raw per-finding [`Evidence`]. Each
//! finding contributes up to [`MAX_MATCHES`] anchored windows (the first match
//! gets the most context, later ones less — [`MIN_HEIGHTS`]); all windows are
//! then merged so a line two traits share is emitted once with two notes, and a
//! composite spanning regions just annotates several lines.
//!
//! [`Evidence`]: crate::types::Evidence

use filefacts::FileType;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::types::{AnalysisReport, ContextLine, Criticality, Finding, Note};

/// Maximum match windows kept per finding (the rest are dropped). A composite
/// shows only its first location; an atomic trait up to [`ATOMIC_MAX_MATCHES`].
const MAX_MATCHES: usize = 4;
/// Locations shown for an atomic trait that matches in several places.
const ATOMIC_MAX_MATCHES: usize = 3;
/// Minimum source-line window height per match, richest first: match 1 gets 5
/// lines (±2), match 2 gets 3 (±1), match 3 gets 2, match 4 gets 1. Merging can
/// grow a window beyond these minima.
const MIN_HEIGHTS: [u32; MAX_MATCHES] = [5, 3, 2, 1];
/// Max rendered characters for a minified slice (clipped, `…`-elided).
const LINE_CLIP: usize = 120;
/// Max raw bytes stored per source line; the renderer clips to terminal width.
const LINE_STORE_MAX: usize = 1024;
/// Raw bytes captured on each side of a binary match — roughly one hex row, the
/// byte analogue of the source view's single line of context. The renderer wraps
/// the window (`16 + match + 16`) into hex|ascii rows at the terminal's width.
const HEX_CONTEXT: u64 = 16;

/// Half-width (bytes) of a minified one-liner slice; the rendered slice is then
/// clipped to [`LINE_CLIP`] characters, so this just needs to exceed it.
const MINIFIED_HALF: u64 = 80;
/// A file whose average line exceeds this is treated as minified: line numbers
/// are meaningless, so matches anchor by byte offset and render as clipped
/// slices instead of numbered lines.
const MINIFIED_AVG_LINE: usize = 2000;

/// Populate `report.context` from `report.findings`, slicing windows out of
/// `data`. Source vs. binary rendering is chosen from `file_type`.
pub(crate) fn capture(report: &mut AnalysisReport, data: &[u8], file_type: FileType) {
    if report.findings.is_empty() || data.is_empty() {
        return;
    }

    // Only capture context for findings that will be shown: skip Filtered noise
    // and Component building blocks unless a composite references them. Mirrors
    // the output `tiny_should_show` policy so context and rendering agree.
    let referenced: FxHashSet<&str> = report
        .findings
        .iter()
        .flat_map(|f| f.trait_refs.iter().map(String::as_str))
        .collect();
    let by_id = index_by_id(&report.findings);
    let shown: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| should_show(f, &referenced))
        .collect();
    if shown.is_empty() {
        return;
    }

    // Source code renders as numbered lines; compiled binaries as hex|ascii.
    // Anything else (manifests, config, unknown text) follows the content: a
    // mostly-printable file renders as text, otherwise hex.
    let textual = file_type.is_source_code() || (!file_type.is_binary() && looks_textual(data));
    let context = if textual && !is_minified(data) {
        capture_source_lines(&shown, &by_id, data)
    } else if textual {
        capture_byte_slices(&shown, &by_id, data, Render::Text)
    } else {
        capture_byte_slices(&shown, &by_id, data, Render::Hex)
    };
    report.context = context;
}

/// Whether a finding contributes context: Filtered is hidden; a Component is
/// shown only when a composite references it.
fn should_show(finding: &Finding, referenced: &FxHashSet<&str>) -> bool {
    match finding.crit {
        Criticality::Filtered => false,
        Criticality::Component => referenced.contains(finding.id.as_str()),
        _ => true,
    }
}

/// How a byte-anchored window renders its content.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Render {
    /// Clipped UTF-8 slice (minified source).
    Text,
    /// `hex  ascii` rows (binaries).
    Hex,
}

/// One match window before merging, in the unit space of its mode (line numbers
/// for source, byte offsets for binary/minified).
struct Window {
    /// Inclusive start of the window.
    lo: u64,
    /// Inclusive end of the window.
    hi: u64,
    /// Position of the matched line / byte (where the note attaches).
    at: u64,
    /// The annotation for this match.
    note: Note,
}

/// Collect a finding's anchor offsets: its own evidence, plus — for composites —
/// the offsets of the component findings it references (their evidence may carry
/// offsets the merged composite evidence lost to truncation). Deduped by offset,
/// file-ordered. A composite shows only its first location; an atomic trait
/// shows up to its first three.
fn finding_anchors(finding: &Finding, by_id: &FxHashMap<&str, &Finding>) -> Vec<(u64, u32)> {
    let composite = !finding.trait_refs.is_empty();
    let mut anchors: Vec<(u64, u32)> = finding
        .evidence
        .iter()
        .filter_map(local_anchor)
        .collect();

    for ref_id in &finding.trait_refs {
        if let Some(component) = by_id.get(ref_id.as_str()) {
            anchors.extend(component.evidence.iter().filter_map(local_anchor));
        }
    }

    anchors.sort_unstable_by_key(|(off, _)| *off);
    anchors.dedup_by_key(|(off, _)| *off);
    anchors.truncate(if composite { 1 } else { ATOMIC_MAX_MATCHES });
    anchors
}

/// A byte anchor `(offset, len)` for evidence whose offset is in *this* file's
/// byte space. Evidence carried up from an embedded archive member is tagged
/// with an `archive:` location and its offsets index the member's (decompressed)
/// bytes, not the bytes being captured here — anchoring it would render garbage,
/// so it is skipped. Such findings still appear (description-only), and the
/// member that owns them renders its own context.
fn local_anchor(e: &crate::types::Evidence) -> Option<(u64, u32)> {
    if e.location
        .as_deref()
        .is_some_and(|l| l.starts_with("archive:"))
    {
        return None;
    }
    e.byte_offset().map(|o| (o, len_of(e)))
}

/// Byte length of an evidence match (the matched value), clamped to u32.
fn len_of(e: &crate::types::Evidence) -> u32 {
    u32::try_from(e.value.len()).unwrap_or(u32::MAX)
}

/// Build a per-finding id index for composite component lookup.
fn index_by_id(findings: &[Finding]) -> FxHashMap<&str, &Finding> {
    let mut by_id = FxHashMap::default();
    for f in findings {
        by_id.entry(f.id.as_str()).or_insert(f);
    }
    by_id
}

/// A note attached to a finding's match (without position).
fn note_for(finding: &Finding, off: u64, len: u32) -> Note {
    Note {
        crit: finding.crit,
        id: finding.id.clone(),
        desc: finding.desc.clone(),
        off,
        len,
        conf: finding.conf,
    }
}

// ========================================================================
// Source line mode
// ========================================================================

/// Index of line-start byte offsets, for offset→line and line slicing.
struct LineIndex<'a> {
    data: &'a [u8],
    /// `starts[i]` = byte offset of line `i` (0-based).
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(data: &'a [u8]) -> Self {
        let mut starts = vec![0usize];
        for (i, b) in data.iter().enumerate() {
            if *b == b'\n' {
                starts.push(i + 1);
            }
        }
        Self { data, starts }
    }

    /// Number of lines.
    fn len(&self) -> usize {
        self.starts.len()
    }

    /// Byte offset where line `i` (0-based) begins.
    fn byte_start(&self, i: u64) -> u64 {
        self.starts.get(i as usize).copied().unwrap_or(0) as u64
    }

    /// 0-based line index containing byte `off`.
    fn line_of(&self, off: u64) -> usize {
        let off = off as usize;
        match self.starts.binary_search(&off) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        }
    }

    /// Raw bytes of line `i` (0-based) without its newline, bounded to
    /// [`LINE_STORE_MAX`] so a pathological long line can't bloat the report.
    /// The renderer clips this to the terminal width at display time.
    fn raw_line(&self, i: usize) -> &[u8] {
        let start = self.starts.get(i).copied().unwrap_or(self.data.len());
        let end = self
            .starts
            .get(i + 1)
            .map_or(self.data.len(), |n| n.saturating_sub(1));
        let end = end.max(start).min(start + LINE_STORE_MAX);
        self.data.get(start..end).unwrap_or(&[])
    }
}

fn capture_source_lines(
    shown: &[&Finding],
    by_id: &FxHashMap<&str, &Finding>,
    data: &[u8],
) -> Vec<ContextLine> {
    let index = LineIndex::new(data);

    let mut windows: Vec<Window> = Vec::new();
    for finding in shown {
        for (slot, (off, len)) in finding_anchors(finding, by_id).into_iter().enumerate() {
            let line = index.line_of(off) as u64;
            let height = MIN_HEIGHTS[slot.min(MAX_MATCHES - 1)];
            let before = u64::from((height - 1) / 2);
            let after = u64::from(height - 1) - before;
            let last = index.len().saturating_sub(1) as u64;
            windows.push(Window {
                lo: line.saturating_sub(before),
                hi: (line + after).min(last),
                at: line,
                note: note_for(finding, off, len),
            });
        }
    }

    merge(windows, |seg| render_line_segment(&index, seg))
}

/// Render a merged line segment: one [`ContextLine`] per line in `[lo, hi]`,
/// notes attached to their matched line.
fn render_line_segment(index: &LineIndex<'_>, seg: &Segment) -> Vec<ContextLine> {
    (seg.lo..=seg.hi)
        .map(|line| {
            let notes = seg.notes_at(line);
            ContextLine {
                loc: line + 1, // 1-based for humans
                addr: Some(index.byte_start(line)),
                data: index.raw_line(line as usize).to_vec(),
                hex: false,
                notes,
            }
        })
        .collect()
}

// ========================================================================
// Byte mode (binary hex rows, or minified-source slices)
// ========================================================================

fn capture_byte_slices(
    shown: &[&Finding],
    by_id: &FxHashMap<&str, &Finding>,
    data: &[u8],
    render: Render,
) -> Vec<ContextLine> {
    let total = data.len() as u64;

    let mut windows: Vec<Window> = Vec::new();
    for finding in shown {
        for (off, len) in finding_anchors(finding, by_id) {
            let (lo, hi, at) = match render {
                Render::Hex => {
                    // Capture 32 bytes either side of the match; overlapping
                    // windows merge into one segment, which `render_hex_segment`
                    // emits as a single raw-byte unit. `at` is the match offset.
                    let lo = off.saturating_sub(HEX_CONTEXT);
                    let hi = (off + u64::from(len) + HEX_CONTEXT).min(total);
                    (lo, hi, off)
                }
                Render::Text => {
                    let lo = off.saturating_sub(MINIFIED_HALF);
                    (lo, (off + MINIFIED_HALF).min(total), off)
                }
            };
            windows.push(Window {
                lo,
                hi,
                at,
                note: note_for(finding, off, len),
            });
        }
    }

    merge(windows, |seg| match render {
        Render::Hex => render_hex_segment(data, seg),
        Render::Text => render_text_segment(data, seg),
    })
}

/// Emit a merged byte segment as one raw-byte unit: the contiguous slice
/// `[lo, hi)` with every match note attached at its absolute offset. The
/// renderer wraps it into hex|ascii rows at the terminal's width and inserts a
/// break before the next unit when their offsets aren't contiguous.
fn render_hex_segment(data: &[u8], seg: &Segment) -> Vec<ContextLine> {
    let total = data.len() as u64;
    let lo = seg.lo.min(total);
    let hi = seg.hi.min(total);
    if lo >= hi {
        return Vec::new();
    }
    vec![ContextLine {
        loc: lo,
        addr: None, // loc is already the byte offset
        data: data[lo as usize..hi as usize].to_vec(),
        hex: true,
        notes: seg.all_notes(),
    }]
}

/// Render a merged byte segment of minified source as a single clipped slice.
fn render_text_segment(data: &[u8], seg: &Segment) -> Vec<ContextLine> {
    let start = seg.lo as usize;
    let end = (seg.hi as usize).min(data.len());
    let raw = data.get(start..end.max(start)).unwrap_or(&[]);
    let text = String::from_utf8_lossy(raw);
    // Anchor the clip on the first match's offset within the slice.
    let mut notes = seg.all_notes();
    notes.sort_unstable_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));
    let col = notes
        .first()
        .map(|n| (n.off as usize).saturating_sub(start));
    vec![ContextLine {
        loc: seg.lo,
        addr: None, // loc is already the byte offset
        // Minified source is byte-addressed but textual: render as a clipped
        // string, not a hex dump.
        data: clip(&text, col, LINE_CLIP).into_bytes(),
        hex: false,
        notes,
    }]
}

// ========================================================================
// Merge
// ========================================================================

/// A merged run of overlapping/adjacent windows plus their positioned notes.
struct Segment {
    lo: u64,
    hi: u64,
    /// `(position, note)` pairs, where position is the line/row the note hits.
    notes: Vec<(u64, Note)>,
}

impl Segment {
    /// Notes whose match falls on unit `pos`, deduped by id (highest crit
    /// wins) and sorted by severity desc then id.
    fn notes_at(&self, pos: u64) -> Vec<Note> {
        let mut notes: Vec<Note> = self
            .notes
            .iter()
            .filter(|(p, _)| *p == pos)
            .map(|(_, n)| n.clone())
            .collect();
        dedup_notes(&mut notes);
        notes
    }

    /// All notes in the segment, deduped + sorted.
    fn all_notes(&self) -> Vec<Note> {
        let mut notes: Vec<Note> = self.notes.iter().map(|(_, n)| n.clone()).collect();
        dedup_notes(&mut notes);
        notes
    }
}

/// Reduce a line's notes to the set worth showing:
/// 1. dedup by finding id (keep highest crit);
/// 2. dedup overlapping byte spans — two traits matching the same location are
///    redundant, so keep the strongest (`conf × crit`), greedily;
/// 3. order by severity desc, id asc — stable, deterministic output.
fn dedup_notes(notes: &mut Vec<Note>) {
    notes.sort_unstable_by(|a, b| a.id.cmp(&b.id).then_with(|| b.crit.cmp(&a.crit)));
    notes.dedup_by(|a, b| a.id == b.id);

    // Strongest-first, then keep a note only if it doesn't overlap a kept one.
    notes.sort_unstable_by(|a, b| note_score(b).total_cmp(&note_score(a)));
    let mut kept: Vec<Note> = Vec::with_capacity(notes.len());
    for n in notes.drain(..) {
        if !kept.iter().any(|k| spans_overlap(k, &n)) {
            kept.push(n);
        }
    }
    kept.sort_unstable_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));
    *notes = kept;
}

/// Rank for overlap resolution: confidence weighted by criticality level.
fn note_score(n: &Note) -> f32 {
    n.conf * f32::from(n.crit as u8)
}

/// Whether two notes' `[off, off+len)` byte spans overlap (a zero-length match
/// is treated as one byte so two at the same offset still collapse).
fn spans_overlap(a: &Note, b: &Note) -> bool {
    let a_end = a.off + u64::from(a.len.max(1));
    let b_end = b.off + u64::from(b.len.max(1));
    a.off < b_end && b.off < a_end
}

/// Sort windows by start, merge overlapping/adjacent ones into [`Segment`]s, and
/// render each via `render_segment`. Segments are emitted in file order; the
/// renderer (tiny/JSON) inserts gap markers where consecutive `loc` values jump.
fn merge(
    mut windows: Vec<Window>,
    render_segment: impl Fn(&Segment) -> Vec<ContextLine>,
) -> Vec<ContextLine> {
    if windows.is_empty() {
        return Vec::new();
    }
    windows.sort_unstable_by_key(|w| w.lo);

    let mut out = Vec::new();
    let mut seg: Option<Segment> = None;
    for w in windows {
        match &mut seg {
            // Merge when the next window overlaps or sits adjacent to the run.
            Some(s) if w.lo <= s.hi.saturating_add(1) => {
                s.hi = s.hi.max(w.hi);
                s.notes.push((w.at, w.note));
            }
            _ => {
                if let Some(done) = seg.take() {
                    out.extend(render_segment(&done));
                }
                seg = Some(Segment {
                    lo: w.lo,
                    hi: w.hi,
                    notes: vec![(w.at, w.note)],
                });
            }
        }
    }
    if let Some(done) = seg {
        out.extend(render_segment(&done));
    }
    out
}

// ========================================================================
// Helpers
// ========================================================================

/// True when the head of the file is mostly printable/whitespace — a cheap
/// "is this text?" check for types filefacts neither calls source nor binary.
fn looks_textual(data: &[u8]) -> bool {
    let head = &data[..data.len().min(4096)];
    if head.is_empty() {
        return false;
    }
    let printable = head
        .iter()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    printable * 100 / head.len() >= 90
}

/// True when the file looks minified (no usable line structure): no newline at
/// all, or an average line length beyond [`MINIFIED_AVG_LINE`].
fn is_minified(data: &[u8]) -> bool {
    let newlines = data.iter().filter(|b| **b == b'\n').count();
    newlines == 0 || data.len() / (newlines + 1) > MINIFIED_AVG_LINE
}

/// Clip `text` to `max` characters. When `col` is given and the text is longer
/// than `max`, the window is centered on that byte column; elided sides get `…`.
fn clip(text: &str, col: Option<usize>, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return text.trim_end().to_string();
    }
    // Translate the byte column to a char index (best effort).
    let center = col
        .map(|c| {
            text.get(..c.min(text.len()))
                .map_or(0, |s| s.chars().count())
        })
        .unwrap_or(0);
    let half = max / 2;
    let start = center
        .saturating_sub(half)
        .min(chars.len().saturating_sub(max));
    let end = (start + max).min(chars.len());
    let mut s = String::new();
    if start > 0 {
        s.push('…');
    }
    s.extend(&chars[start..end]);
    if end < chars.len() {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Evidence, FindingKind, TargetInfo};

    fn report(findings: Vec<Finding>) -> AnalysisReport {
        let mut r = crate::types::AnalysisReport::new(TargetInfo {
            path: "/t".to_string(),
            file_type: "python".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        r.findings = findings;
        r
    }

    fn finding(id: &str, crit: Criticality, offsets: &[u64]) -> Finding {
        let mut f = Finding::new(
            id.to_string(),
            FindingKind::Capability,
            format!("{id} desc"),
            0.9,
        );
        f.crit = crit;
        f.evidence = offsets
            .iter()
            .map(|o| Evidence::new("m", "s", "match").with_offset(*o))
            .collect();
        f
    }

    fn line(ctx: &[ContextLine], loc: u64) -> Option<&ContextLine> {
        ctx.iter().find(|c| c.loc == loc)
    }

    #[test]
    fn source_lines_merge_and_collide() {
        //                  0         1         2         3
        //                  0123456789012345 6789012345678901 2345
        let data = b"import os\nx = 1\ndata = decode(p)\nexec(data)\nend\n";
        // offset 16 = line 3 ("data = ..."), offset 33 = line 4 ("exec(data)")
        let mut r = report(vec![
            finding("a/eval", Criticality::Hostile, &[16]), // "data" on line 3
            finding("b/fs", Criticality::Suspicious, &[23]), // "decode" on line 3 — distinct span
            finding("c/exec", Criticality::Notable, &[33]), // line 4 — windows merge
        ]);
        capture(&mut r, data, FileType::Python);

        // Two findings at distinct spans on line 3: one line, two notes.
        assert!(matches!(line(&r.context, 3), Some(c) if c.notes.len() == 2));
        assert_eq!(r.context.iter().filter(|c| c.loc == 3).count(), 1);
        // Line 4 is its own hit; windows merged so there is no gap line missing.
        assert!(matches!(line(&r.context, 4), Some(c) if c.notes.len() == 1));
        // A context-only neighbour line carries no notes.
        assert!(matches!(line(&r.context, 2), Some(c) if c.notes.is_empty()));
    }

    #[test]
    fn composite_inherits_component_offset() {
        let data = b"a\nb\nopen(f)\nexec(p)\nc\n"; // "open" line 3 (off 4), "exec" line 4 (off 11)
        let mut comp = finding("comp/open", Criticality::Component, &[4]);
        comp.desc = "open".to_string();
        let mut composite = finding("obj/loader", Criticality::Suspicious, &[]);
        composite.trait_refs = vec!["comp/open".to_string()];
        let mut r = report(vec![comp, composite]);
        capture(&mut r, data, FileType::Python);

        // The composite (no evidence of its own) annotates the component's line
        // via the trait_refs fallback. Both share the same offset, so overlap
        // dedup keeps the stronger composite and drops the component.
        let l3 = line(&r.context, 3);
        assert!(matches!(l3, Some(c) if c.notes.iter().any(|n| n.id == "obj/loader")));
        assert!(matches!(l3, Some(c) if !c.notes.iter().any(|n| n.id == "comp/open")));
    }

    #[test]
    fn overlapping_traits_keep_highest_conf_times_level() {
        let data = b"exec(payload)\n"; // both match at offset 0
        let mut hi = finding("a/strong", Criticality::Hostile, &[0]);
        hi.conf = 0.9;
        let mut lo = finding("b/weak", Criticality::Notable, &[0]);
        lo.conf = 0.9;
        let mut r = report(vec![hi, lo]);
        capture(&mut r, data, FileType::Python);
        let l1 = line(&r.context, 1);
        assert!(matches!(l1, Some(c) if c.notes.len() == 1));
        assert!(matches!(l1, Some(c) if c.notes[0].id == "a/strong"));
    }

    #[test]
    fn no_anchor_finding_yields_no_context() {
        let data = b"hello world\n";
        let mut r = report(vec![finding("meta/x", Criticality::Notable, &[])]);
        capture(&mut r, data, FileType::Python);
        assert!(r.context.is_empty());
    }

    #[test]
    fn binary_emits_raw_byte_window() {
        let data: Vec<u8> = (0u8..64).collect();
        let mut r = report(vec![finding("bin/x", Criticality::Notable, &[16])]);
        capture(&mut r, &data, FileType::Elf);
        // Byte-offset mode: one hex-flagged window of raw bytes spanning the
        // match (the renderer wraps it into rows at display time).
        let hit = r.context.iter().find(|c| !c.notes.is_empty());
        assert!(matches!(hit, Some(c) if c.hex && c.data.contains(&16u8)));
    }
}
