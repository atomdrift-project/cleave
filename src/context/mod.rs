//! Context capture: turn a file's findings into a merged, render-ready
//! [`ContextLine`] list — the matched content shown once, in file order,
//! annotated with the findings that touch it.
//!
//! This is the output surface that replaces raw per-finding [`Evidence`]. Each
//! finding contributes up to [`ATOMIC_MAX_MATCHES`] byte-addressed windows sized
//! by its criticality ([`Criticality::hex_context`]); overlapping windows merge
//! into one chunk. Two traits matching the same span are redundant, so the
//! weaker (`conf × crit`) is dropped — only the strongest annotation shows. A
//! textual file additionally carries a `LineIndex`, which labels each chunk with
//! the 1-based source line/column of its first byte; binaries carry neither.
//! Rendering those bytes as numbered text lines or a hex dump is solely an
//! output concern.
//!
//! [`Evidence`]: crate::types::Evidence

use filefacts::FileType;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::types::{
    AnalysisReport, ContextLine, Criticality, Finding, Note, traits_findings::MAX_EV_LOCS,
};

/// Locations shown for an atomic trait that matches in several places.
const ATOMIC_MAX_MATCHES: usize = MAX_EV_LOCS;

/// Populate `report.context` from `report.findings`, slicing windows out of
/// `data`. Every file type uses the same byte-addressed window model.
pub(crate) fn capture(report: &mut AnalysisReport, data: &[u8], file_type: FileType) {
    if report.findings.is_empty() || data.is_empty() {
        return;
    }

    // Anchor symbol matches that arrived without a byte offset before any
    // anchoring runs, so both the matched finding and any composite that
    // references it pick up the recovered position.
    anchor_orphan_symbol_matches(&mut report.findings, data);

    // Capture context for every finding that can render: only Filtered noise is
    // skipped. Components are captured whether or not a composite references
    // them — the LLM/tiny view's low-tier fill (`TinyOpts::low_tier_fill`) shows
    // a top-scored file's best component/baseline traits even when nothing
    // notable fired, and a trait without captured context would render as
    // nothing there. Baselines were always captured; this aligns components.
    let by_id = index_by_id(&report.findings);
    let shown: Vec<&Finding> = report.findings.iter().filter(|f| should_show(f)).collect();
    if shown.is_empty() {
        return;
    }

    let textual = file_type.is_source_code() || (!file_type.is_binary() && looks_textual(data));
    let line_index = textual.then(|| LineIndex::new(data));
    report.context = capture_byte_slices(&shown, &by_id, data, line_index.as_ref());
}

/// Whether a finding contributes context: everything except Filtered noise.
/// Low-tier traits are captured too — whether the render shows them is the
/// output layer's call (`select_ids` / `low_tier_fill`), and it can only show
/// what was captured.
fn should_show(finding: &Finding) -> bool {
    finding.crit != Criticality::Filtered
}

/// One byte-addressed match window before merging.
struct Window {
    /// Inclusive start of the window.
    lo: u64,
    /// Inclusive end of the window.
    hi: u64,
    /// Byte position where the note attaches.
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
    let mut anchors = local_anchors(finding, by_id);
    anchors.truncate(if composite { 1 } else { ATOMIC_MAX_MATCHES });
    anchors
}

/// Collect a finding's local leg anchors `(offset, len, confidence)`
/// transitively: its own evidence plus, recursively, every component it
/// references and *their* components. A composite is often built from
/// "aggregator" components — an `any:` of other components, carrying no offset of
/// their own (cleave can't nest `any:` inside `all:`, so trait authors flatten
/// through these). A single level then resolves to no leg; the walk descends
/// until it reaches evidence with a real byte offset. Each anchor keeps the
/// confidence of the finding whose evidence produced it, so the placement pass
/// ranks legs by their true evidence strength. `seen` guards reference cycles.
fn collect_leg_anchors(
    finding: &Finding,
    by_id: &FxHashMap<&str, &Finding>,
    seen: &mut FxHashSet<String>,
    out: &mut Vec<(u64, u32, f32)>,
) {
    if !seen.insert(finding.id.clone().to_string()) {
        return;
    }
    for (off, len) in finding.evidence.iter().filter_map(local_anchor) {
        out.push((off, len, finding.conf));
    }
    for ref_id in &finding.trait_refs {
        if let Some(component) = by_id.get(ref_id.as_str()) {
            collect_leg_anchors(component, by_id, seen, out);
        }
    }
}

/// All of a finding's local byte anchors `(offset, len)`, file-ordered and
/// deduped by offset — its own evidence plus its components' (a composite's
/// "legs"), resolved transitively. Falls back to [`fallback_anchor`] when none
/// are local. Unlike [`finding_anchors`] this keeps every leg, so a composite can
/// be placed at the first one not already taken by a stronger match.
fn local_anchors(finding: &Finding, by_id: &FxHashMap<&str, &Finding>) -> Vec<(u64, u32)> {
    let mut legs = Vec::new();
    collect_leg_anchors(finding, by_id, &mut FxHashSet::default(), &mut legs);
    if legs.is_empty() {
        return fallback_anchor(finding, by_id);
    }
    let mut anchors: Vec<(u64, u32)> = legs.into_iter().map(|(off, len, _)| (off, len)).collect();
    anchors.sort_unstable_by_key(|(off, _)| *off);
    anchors.dedup_by_key(|(off, _)| *off);
    anchors
}

/// A composite's candidate legs `(offset, len, confidence)` — one per local
/// component match — ordered most-confident first (ties: earliest offset),
/// deduped by offset keeping the highest confidence, and capped. `confidence` is
/// the *component's* confidence, so the placement pass anchors the composite at
/// its strongest evidence point. Falls back to [`fallback_anchor`] (carrying the
/// composite's own confidence) when no leg is local — e.g. a cross-file composite
/// whose components live in other files, which then has no leg and is omitted
/// from the byte view (it renders as a located-elsewhere note instead).
fn composite_legs(finding: &Finding, by_id: &FxHashMap<&str, &Finding>) -> Vec<(u64, u32, f32)> {
    /// Bound on legs considered — composites reference at most a handful of
    /// distinguishing components; a few extra metric legs add nothing.
    const MAX_LEGS: usize = 8;

    let mut legs = Vec::new();
    collect_leg_anchors(finding, by_id, &mut FxHashSet::default(), &mut legs);
    if legs.is_empty() {
        return fallback_anchor(finding, by_id)
            .into_iter()
            .map(|(o, l)| (o, l, finding.conf))
            .collect();
    }
    // Keep the highest-confidence leg per offset…
    legs.sort_by(|a, b| a.0.cmp(&b.0).then(b.2.total_cmp(&a.2)));
    legs.dedup_by_key(|l| l.0);
    // …then order by confidence (desc), earliest offset breaking ties.
    legs.sort_by(|a, b| b.2.total_cmp(&a.2).then(a.0.cmp(&b.0)));
    legs.truncate(MAX_LEGS);
    legs
}

/// Anchor symbol matches that carry a name but no byte offset.
///
/// Most formats hand each import/export/function the file offset of its name —
/// but degraded extraction can't: rizin recovery with no PLT address, forwarded
/// PE exports, a future format gap. The matched value is still the symbol *name*,
/// literal bytes present in the file, so locate it directly. Symbol-table names
/// are NUL-terminated, so searching `name\0` lands on the real table entry
/// rather than a same-prefix substring (`read` inside `readdir`). Mutating the
/// evidence here (rather than only the local anchor) lets a composite that
/// references this finding pick up the recovered offset through its component.
///
/// A name genuinely absent from the file stays unanchored and is still surfaced
/// by [`fallback_anchor`] — that is the matcher bug the guard exists to catch.
fn anchor_orphan_symbol_matches(findings: &mut [Finding], data: &[u8]) {
    for finding in findings {
        for e in &mut finding.evidence {
            if !matches!(e.method.as_str(), "symbol" | "symbols") || e.byte_offset().is_some() {
                continue;
            }
            // An `archive:` location indexes an embedded member's bytes, not
            // this file's — its own member anchors it.
            if e.location
                .as_deref()
                .is_some_and(|l| l.starts_with("archive:"))
            {
                continue;
            }
            if let Some(off) = locate_nul_terminated(data, &e.value) {
                e.offsets.push(off);
            }
        }
    }
}

/// First file offset of `value` stored as a NUL-terminated string — the shape a
/// symbol/string table holds a name in. Values shorter than three bytes are
/// skipped: they match too liberally to anchor meaningfully.
fn locate_nul_terminated(data: &[u8], value: &str) -> Option<u64> {
    if value.len() < 3 {
        return None;
    }
    let mut needle = Vec::with_capacity(value.len() + 1);
    needle.extend_from_slice(value.as_bytes());
    needle.push(0);
    memchr::memmem::find(data, &needle).map(|pos| pos as u64)
}

/// A finding without a local byte offset has no honest context window. When
/// [`finding_anchors`] collects none, distinguish the two reasons:
///
/// - The finding's offsets index an embedded archive member (`archive:`
///   location, skipped by [`local_anchor`]). That member renders them in its own
///   context, so this finding stays description-only here — no fallback.
/// - The finding carries no byte offset anywhere. Two unrelated cases land here:
///   a *content* matcher
///   (string/symbol/raw/text/ast/…) that matched specific bytes but failed to
///   record where — a real bug worth an error — or a *file-global* fact (signing
///   trust, UUID, arch, metrics, a `value:` field match, an `exists: false`
///   absence) which belongs in the file-level annotation surface. Classify by
///   evidence method and log accordingly; neither case fabricates byte-zero
///   context.
fn fallback_anchor(finding: &Finding, by_id: &FxHashMap<&str, &Finding>) -> Vec<(u64, u32)> {
    // An `archive:` location carries a real offset in an embedded member's byte
    // space — `local_anchor` skips it (it doesn't index *this* file's bytes), and
    // the member renders it in its own context. `byte_offset()` can't parse that
    // form, so check the prefix explicitly; otherwise these member findings look
    // offset-less and get mis-reported as bugs.
    let has_offset = |e: &crate::types::Evidence| {
        e.byte_offset().is_some()
            || e.location
                .as_deref()
                .is_some_and(|l| l.starts_with("archive:"))
    };
    let has_remote_offset = finding.evidence.iter().any(&has_offset)
        || finding.trait_refs.iter().any(|id| {
            by_id
                .get(id.as_str())
                .is_some_and(|c| c.evidence.iter().any(&has_offset))
        });
    if has_remote_offset {
        // Offsets belong to an embedded member; that member owns their context.
        return Vec::new();
    }
    let is_content_match = finding.evidence.iter().any(|e| {
        matches!(
            e.method.as_str(),
            "string"
                | "symbol"
                | "symbols"
                | "raw"
                | "text"
                | "literal"
                | "string_literal"
                | "ast"
                | "ast_query"
                | "encoded_string"
                | "hex"
                | "xor"
        )
    });
    if is_content_match {
        tracing::error!(
            finding_id = %finding.id,
            kind = ?finding.kind,
            "content match has no file offset — the matcher should record where it matched"
        );
    } else {
        tracing::debug!(
            finding_id = %finding.id,
            "file-global finding has no byte context"
        );
    }
    Vec::new()
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

/// Render cap for an anchored window's match length. A *located* metric can
/// span a whole concealed region (hundreds of KiB); the rendered preview must
/// stay a few rows, so the anchor length is capped here. The true, uncapped
/// span still rides the compact span output (`match_len`) for prism/tooling.
const MAX_ANCHOR_LEN: u64 = 512;

/// Byte length of an evidence match for rendering/placement. Mirrors the
/// compact span source — `match_len` when set (decoded-layer or located
/// metrics, where `value` is not the source bytes), else `value.len()` — but
/// caps it so a large span yields a bounded preview rather than rendering the
/// entire region.
fn len_of(e: &crate::types::Evidence) -> u32 {
    let raw = match e.match_len {
        Some(l) => l.min(MAX_ANCHOR_LEN),
        None => e.value.len() as u64,
    };
    u32::try_from(raw).unwrap_or(u32::MAX)
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

/// Source position index used only to label byte-addressed text chunks. Window
/// sizing and merging remain identical to binary capture.
struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(data: &[u8]) -> Self {
        let mut starts = vec![0];
        starts.extend(
            data.iter()
                .enumerate()
                .filter_map(|(i, b)| (*b == b'\n').then_some(i + 1)),
        );
        Self { starts }
    }

    /// 1-based `(line, column)` of byte `off`.
    fn position(&self, off: u64) -> (u64, u64) {
        let off = usize::try_from(off).unwrap_or(usize::MAX);
        let idx = match self.starts.binary_search(&off) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let col = off.saturating_sub(self.starts.get(idx).copied().unwrap_or(0)) + 1;
        (idx as u64 + 1, col as u64)
    }
}

/// Strongest composite criticality referencing each leg id. An atomic trait a
/// stronger composite drew on is sized by that composite's severity rather than
/// its own lower one, so the evidence
/// behind a hostile conclusion renders with the conclusion's context.
fn referring_crit<'a>(shown: &[&'a Finding]) -> FxHashMap<&'a str, Criticality> {
    let mut m: FxHashMap<&'a str, Criticality> = FxHashMap::default();
    for f in shown.iter().filter(|f| !f.trait_refs.is_empty()) {
        for r in &f.trait_refs {
            m.entry(r.as_str())
                .and_modify(|c| *c = (*c).max(f.crit))
                .or_insert(f.crit);
        }
    }
    m
}

/// A finding's rank for overlap resolution: confidence weighted by criticality.
/// Matches [`note_score`] so the placement pass and the per-chunk dedup agree on
/// which match is "stronger."
fn finding_score(finding: &Finding) -> f32 {
    finding.conf * f32::from(finding.crit.rank())
}

// ========================================================================
// Byte-addressed context windows
// ========================================================================

fn capture_byte_slices(
    shown: &[&Finding],
    by_id: &FxHashMap<&str, &Finding>,
    data: &[u8],
    line_index: Option<&LineIndex>,
) -> Vec<ContextLine> {
    let total = data.len() as u64;

    // `[off, off+len)` widened to the criticality-sized context margin
    // (asymmetric — more trailing than leading, since a payload runs forward from
    // the match), plus the match anchor `at`. The strongest matches reserve the
    // widest window; overlapping windows merge into one segment, which
    // `render_byte_segment` emits as a single raw-byte chunk.
    let bounds = |crit: Criticality, off: u64, len: u32| {
        let (before, after) = crit.hex_context();
        let lo = off.saturating_sub(before);
        let hi = (off + u64::from(len) + after).min(total);
        (lo, hi, off)
    };

    // An atomic leg a stronger composite drew on reserves that composite's wider
    // window, so the evidence is sized for the conclusion it supports.
    let leg_crit = referring_crit(shown);

    let mut windows: Vec<Window> = Vec::new();
    // Match span `[start, end)` of every placed note, with its strength. A later
    // composite is placed only where no *stronger* match already sits.
    let mut placed: Vec<(u64, u64, f32)> = Vec::new();
    let span = |off: u64, len: u32| (off, off + u64::from(len.max(1)));

    // Atomic findings anchor at their own offsets (the fixed scaffolding). A leg a
    // stronger composite drew on is sized by that composite's severity.
    for finding in shown.iter().filter(|f| f.trait_refs.is_empty()) {
        let score = finding_score(finding);
        let crit = leg_crit
            .get(finding.id.as_str())
            .map_or(finding.crit, |&c| c.max(finding.crit));
        for (off, len) in finding_anchors(finding, by_id) {
            let (lo, hi, at) = bounds(crit, off, len);
            windows.push(Window {
                lo,
                hi,
                at,
                note: note_for(finding, off, len),
            });
            let (s, e) = span(off, len);
            placed.push((s, e, score));
        }
    }

    // Composites are conclusions that span several legs (their components). Place
    // each at its strongest-evidence leg — the highest-confidence component — that
    // no equal-or-stronger match already occupies, so it anchors at its best real
    // location instead of being silently dropped when a leg collides; the other
    // legs keep showing their component traits. A composite whose every leg is
    // dominated is omitted (no honest spot for it). Strongest-first so the
    // higher-severity conclusion claims the contested leg.
    let mut composites: Vec<&&Finding> =
        shown.iter().filter(|f| !f.trait_refs.is_empty()).collect();
    composites.sort_by(|a, b| {
        finding_score(b)
            .total_cmp(&finding_score(a))
            .then_with(|| a.id.cmp(&b.id))
    });
    for finding in composites {
        let score = finding_score(finding);
        let leg = composite_legs(finding, by_id)
            .into_iter()
            .find(|&(off, len, _)| {
                let (s, e) = span(off, len);
                !placed
                    .iter()
                    .any(|&(ps, pe, pscore)| pscore >= score && ps < e && s < pe)
            });
        if let Some((off, len, _)) = leg {
            let (lo, hi, at) = bounds(finding.crit, off, len);
            windows.push(Window {
                lo,
                hi,
                at,
                note: note_for(finding, off, len),
            });
            let (s, e) = span(off, len);
            placed.push((s, e, score));
        }
    }

    merge(windows, |seg| render_byte_segment(data, seg, line_index))
}

/// Emit a merged byte segment as one raw-byte unit: the contiguous slice
/// `[lo, hi)` with every match note attached at its absolute offset. The
/// renderer wraps it into hex|ascii rows at the terminal's width and inserts a
/// break before the next unit when their offsets aren't contiguous.
fn render_byte_segment(
    data: &[u8],
    seg: &Segment,
    line_index: Option<&LineIndex>,
) -> Vec<ContextLine> {
    let total = data.len() as u64;
    let lo = seg.lo.min(total);
    let hi = seg.hi.min(total);
    if lo >= hi {
        return Vec::new();
    }
    let (line, col) = match line_index {
        Some(index) => {
            let (l, c) = index.position(lo);
            (Some(l), Some(c))
        }
        None => (None, None),
    };
    vec![ContextLine {
        loc: lo,
        line,
        col,
        data: data[lo as usize..hi as usize].to_vec(),
        notes: seg.all_notes(),
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
    /// All notes in the segment, deduped + sorted.
    fn all_notes(&self) -> Vec<Note> {
        let mut notes: Vec<Note> = self.notes.iter().map(|(_, n)| n.clone()).collect();
        dedup_notes(&mut notes);
        notes
    }
}

/// Reduce a chunk's notes to the set worth showing:
/// 1. dedup by finding id (keep highest crit);
/// 2. dedup overlapping byte spans — two traits matching the same location are
///    redundant, so keep the strongest (`conf × crit`), greedily;
/// 3. order by severity desc, id asc — stable, deterministic output.
fn dedup_notes(notes: &mut Vec<Note>) {
    notes.sort_unstable_by(|a, b| a.id.cmp(&b.id).then_with(|| b.crit.cmp(&a.crit)));
    notes.dedup_by(|a, b| a.id == b.id);

    // Strongest-first, then keep a note only if it doesn't overlap a kept one.
    // The id tie-break makes the winner among equal-score overlapping notes
    // deterministic — without it, the displayed annotation flips with trait
    // evaluation order (which shifts across builds).
    notes.sort_unstable_by(|a, b| {
        note_score(b)
            .total_cmp(&note_score(a))
            .then_with(|| a.id.cmp(&b.id))
    });
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
    n.conf * f32::from(n.crit.rank())
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

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
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

    fn block_for<'a>(ctx: &'a [ContextLine], id: &str) -> Option<&'a ContextLine> {
        ctx.iter()
            .find(|c| c.notes.iter().any(|note| note.id == id))
    }

    #[test]
    fn textual_matches_share_the_same_byte_window() {
        let data = b"import os\nx = 1\ndata = decode(p)\nexec(data)\nend\n";
        let mut r = report(vec![
            finding("a/eval", Criticality::Hostile, &[16]),
            finding("b/fs", Criticality::Suspicious, &[23]),
            finding("c/exec", Criticality::Notable, &[33]),
        ]);
        capture(&mut r, data, FileType::Python);

        // The hostile window (±128/256) spans the whole 47-byte file, so all three
        // matches merge into one chunk anchored at byte 0 (line 1, column 1), with
        // three distinct non-overlapping notes.
        assert_eq!(r.context.len(), 1);
        assert_eq!(r.context[0].loc, 0);
        assert_eq!(r.context[0].line, Some(1));
        assert_eq!(r.context[0].col, Some(1));
        assert_eq!(r.context[0].notes.len(), 3);
    }

    #[test]
    fn distant_matches_on_one_long_line_each_have_context() {
        // The core fix: two matches 9 KB apart on a single newline-free line each
        // get their own byte-window chunk instead of collapsing to one clipped line.
        let mut data = vec![b'x'; 10_000];
        data[100] = b'A';
        data[9_000] = b'B';
        let mut r = report(vec![
            finding("text/first", Criticality::Notable, &[100]),
            finding("text/second", Criticality::Suspicious, &[9_000]),
        ]);
        capture(&mut r, &data, FileType::JavaScript);

        let first = block_for(&r.context, "text/first").expect("first chunk");
        let second = block_for(&r.context, "text/second").expect("second chunk");
        // `loc` is the byte offset of the window start; both sit on line 1, at the
        // column their offset lands on (there are no newlines to reset it).
        assert_eq!((first.loc, first.line, first.col), (36, Some(1), Some(37)));
        assert_eq!(
            (second.loc, second.line, second.col),
            (8_904, Some(1), Some(8_905))
        );
        assert_eq!(first.data[64], b'A');
        assert_eq!(second.data[96], b'B');
    }

    #[test]
    fn textual_chunk_keeps_multiline_start_position() {
        let mut data = vec![b'x'; 900];
        data[99] = b'\n';
        data[199] = b'\n';
        data[500] = b'M';
        let mut r = report(vec![finding("text/hit", Criticality::Notable, &[500])]);
        capture(&mut r, &data, FileType::JavaScript);

        // Window starts at byte 436, which is on line 3 (after the newlines at 99
        // and 199), at column 436 − 200 + 1 = 237.
        let chunk = block_for(&r.context, "text/hit").expect("text chunk");
        assert_eq!(chunk.loc, 436);
        assert_eq!(chunk.line, Some(3));
        assert_eq!(chunk.col, Some(237));
        assert_eq!(chunk.data[64], b'M');
    }

    #[test]
    fn locationless_finding_has_no_fabricated_context() {
        let data = b"import os\nx = 1\n";
        let mut r = report(vec![finding("struct/entropy", Criticality::Notable, &[])]);
        capture(&mut r, data, FileType::Python);
        assert!(r.context.is_empty());
    }

    #[test]
    fn archive_member_offset_is_not_pinned() {
        let data = b"import os\nx = 1\n";
        let mut f = finding("member/evil", Criticality::Hostile, &[]);
        // Offset indexes an embedded member (archive: location). The member renders
        // it in its own context, so it must stay description-only here — never
        // pinned to byte 0 of the carrier.
        f.evidence = vec![
            Evidence::new("m", "s", "match")
                .with_offset(5)
                .with_location("archive:member.bin"),
        ];
        let mut r = report(vec![f]);
        capture(&mut r, data, FileType::Python);
        assert!(
            r.context
                .iter()
                .all(|c| c.notes.iter().all(|n| n.id != "member/evil")),
            "archive-member finding must not be pinned into the carrier: {:?}",
            r.context
        );
    }

    #[test]
    fn archive_location_with_embedded_offset_is_not_pinned() {
        // The real shape: the member offset is encoded *in* the `archive:` location
        // string (`archive:<member>:0x<off>`), not the `offsets` vec — so
        // `byte_offset()` can't see it. The carrier must still recognise it as a
        // remote offset and leave the finding description-only, not pin it to byte 0.
        let data = b"import os\nx = 1\n";
        let mut f = finding("member/evil", Criticality::Hostile, &[]);
        f.evidence = vec![
            Evidence::new("text", "raw_content", "match")
                .with_location("archive:package/src/hooks/deps:0x3fa97"),
        ];
        let mut r = report(vec![f]);
        capture(&mut r, data, FileType::Python);
        assert!(
            r.context
                .iter()
                .all(|c| c.notes.iter().all(|n| n.id != "member/evil")),
            "archive-member finding with an embedded-offset location must not be \
             pinned into the carrier: {:?}",
            r.context
        );
    }

    #[test]
    fn composite_walks_to_first_undominated_leg() {
        // A 256-byte binary. A stronger atomic holds offset 10; the composite's
        // most-confident leg is also 10 (via comp/a), with a weaker leg at 100.
        let data = vec![0u8; 256];
        let strong = finding("atomic/strong", Criticality::Hostile, &[10]);
        let mut comp_a = finding("comp/a", Criticality::Component, &[10]);
        comp_a.conf = 0.9;
        let mut comp_b = finding("comp/b", Criticality::Component, &[100]);
        comp_b.conf = 0.8;
        let mut composite = finding("obj/composite", Criticality::Suspicious, &[]);
        composite.trait_refs = vec!["comp/a".to_string().into(), "comp/b".to_string().into()];

        let mut r = report(vec![strong, comp_a, comp_b, composite]);
        capture(&mut r, &data, FileType::Elf);

        let note_at = |off: u64| {
            r.context
                .iter()
                .flat_map(|c| &c.notes)
                .any(|n| n.id == "obj/composite" && n.off == off)
        };
        assert!(
            !note_at(10),
            "composite must skip the leg held by a stronger match: {:?}",
            r.context
        );
        assert!(
            note_at(100),
            "composite anchors at its next undominated leg: {:?}",
            r.context
        );
    }

    #[test]
    fn composite_omitted_when_every_leg_dominated() {
        // The composite's only leg (offset 10, via comp/only) is held by a
        // stronger atomic, so it has no honest spot and is omitted entirely.
        let data = vec![0u8; 64];
        let strong = finding("atomic/strong", Criticality::Hostile, &[10]);
        let mut comp = finding("comp/only", Criticality::Component, &[10]);
        comp.conf = 0.9;
        let mut composite = finding("obj/dominated", Criticality::Suspicious, &[]);
        composite.trait_refs = vec!["comp/only".to_string().into()];

        let mut r = report(vec![strong, comp, composite]);
        capture(&mut r, &data, FileType::Elf);

        assert!(
            r.context
                .iter()
                .flat_map(|c| &c.notes)
                .all(|n| n.id != "obj/dominated"),
            "a composite dominated on every leg is omitted: {:?}",
            r.context
        );
    }

    #[test]
    fn composite_inherits_component_offset() {
        let data = b"a\nb\nopen(f)\nexec(p)\nc\n"; // "open" line 3 (off 4), "exec" line 4 (off 11)
        let mut comp = finding("comp/open", Criticality::Component, &[4]);
        comp.desc = "open".to_string().into();
        let mut composite = finding("obj/loader", Criticality::Suspicious, &[]);
        composite.trait_refs = vec!["comp/open".to_string().into()];
        let mut r = report(vec![comp, composite]);
        capture(&mut r, data, FileType::Python);

        // The composite (no evidence of its own) anchors at its component's offset.
        // Both share that span, so overlap dedup keeps the stronger composite and
        // drops the component note.
        let chunk = block_for(&r.context, "obj/loader").expect("composite chunk");
        assert!(
            !chunk.notes.iter().any(|n| n.id == "comp/open"),
            "overlapping component dropped for the stronger composite: {:?}",
            r.context
        );
    }

    #[test]
    fn textual_atomic_leg_reserves_stronger_composites_window() {
        let data = vec![b'x'; 2_048];
        let near = finding("cap/near", Criticality::Notable, &[800]);
        let mut far = finding("cap/far", Criticality::Notable, &[100]);
        far.conf = 0.95; // the composite's most-confident leg — it anchors here
        let mut composite = finding("obj/implant", Criticality::Hostile, &[]);
        composite.trait_refs = vec!["cap/near".to_string().into(), "cap/far".to_string().into()];

        let mut r = report(vec![near, far, composite]);
        capture(&mut r, &data, FileType::Python);

        // The near leg inherits the hostile 128-byte lead-in (not notable's 64), so
        // its window starts at 800 − 128; the composite anchored far away at 100.
        let near = block_for(&r.context, "cap/near").expect("near chunk");
        assert_eq!(near.loc, 800 - 128);
        assert_eq!(near.line, Some(1));
        assert_eq!(near.col, Some(800 - 128 + 1));
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
        let ids: Vec<&str> = r
            .context
            .iter()
            .flat_map(|c| &c.notes)
            .map(|n| n.id.as_str())
            .collect();
        assert!(ids.contains(&"a/strong"), "strongest kept: {:?}", r.context);
        assert!(
            !ids.contains(&"b/weak"),
            "weaker overlapping trait dropped: {:?}",
            r.context
        );
    }

    #[test]
    fn locate_nul_terminated_finds_table_entry_not_substring() {
        let data = b"readdir\0read\0";
        // "read\0" matches the standalone table entry at offset 8, never the
        // "read" prefix inside "readdir" (which is followed by 'd', not NUL).
        assert_eq!(locate_nul_terminated(data, "read"), Some(8));
        // Too-short values match too liberally to anchor — skipped.
        assert_eq!(locate_nul_terminated(data, "rd"), None);
        // A value absent from the file gets no anchor.
        assert_eq!(locate_nul_terminated(data, "write"), None);
    }

    #[test]
    fn orphan_symbol_match_anchors_at_name_in_file() {
        // A symbol matched with a name but no offset — the shape degraded
        // extraction produces (rizin recovery with no PLT address, a forwarded
        // PE export). It must anchor at the name's bytes in the file, not float
        // at byte 0, and the recovered offset must land on the evidence so a
        // referencing composite inherits it.
        let data = b"....\0sleep\0....";
        let mut f = finding("micro/sleep", Criticality::Notable, &[]);
        f.evidence = vec![Evidence {
            method: "symbol".to_string(),
            value: "sleep".to_string(),
            location: Some("import".to_string()),
            ..Default::default()
        }];
        let mut r = report(vec![f]);
        capture(&mut r, data, FileType::Elf);
        assert_eq!(r.findings[0].evidence[0].byte_offset(), Some(5));
        assert!(
            r.context
                .iter()
                .any(|c| c.notes.iter().any(|n| n.id == "micro/sleep")),
            "recovered symbol finding should render anchored: {:?}",
            r.context
        );
    }

    #[test]
    fn binary_emits_raw_byte_window() {
        let data: Vec<u8> = (0u8..64).collect();
        let mut r = report(vec![finding("bin/x", Criticality::Notable, &[16])]);
        capture(&mut r, &data, FileType::Elf);
        // Byte-offset mode: one window of raw bytes spanning the match, carrying no
        // line/col labels (the renderer wraps it into hex rows at display time).
        let hit = r.context.iter().find(|c| !c.notes.is_empty());
        assert!(
            matches!(hit, Some(c) if c.line.is_none() && c.col.is_none() && c.data.contains(&16u8))
        );
    }

    #[test]
    fn binary_window_scales_with_criticality() {
        // A hostile binary match reserves a far wider byte window than a component
        // one — `Criticality::hex_context` (128/256 vs 32/64). The two matches sit
        // far apart so their windows stay separate.
        let data = vec![0u8; 1024];
        let hostile = finding("mal/exec", Criticality::Hostile, &[500]);
        let component = finding("cap/str", Criticality::Component, &[100]);
        let mut r = report(vec![hostile, component]);
        capture(&mut r, &data, FileType::Elf);

        let block = |id: &str| {
            r.context
                .iter()
                .find(|c| c.notes.iter().any(|n| n.id == id))
                .unwrap_or_else(|| panic!("no block for {id}: {:?}", r.context))
        };
        // Lead-in (`before`) scales with severity: hostile 128, component 32.
        assert_eq!(block("mal/exec").loc, 500 - 128);
        assert_eq!(block("cap/str").loc, 100 - 32);
        // Total window (before + after) scales too: (128+256) − (32+64) = 288 bytes,
        // independent of the match length (which is equal for both).
        let delta = block("mal/exec").data.len() as i64 - block("cap/str").data.len() as i64;
        assert_eq!(
            delta,
            (128 + 256) - (32 + 64),
            "window size scales with criticality: {:?}",
            r.context
        );
    }

    #[test]
    fn binary_overlapping_traits_keep_strongest() {
        // Two traits matching the same bytes collapse to the strongest
        // (`conf × crit`) — the same overlap dedup as the text path, in hex mode.
        let data = vec![0u8; 512];
        let strong = finding("mal/exec", Criticality::Hostile, &[100]);
        let weak = finding("cap/str", Criticality::Notable, &[100]);
        let mut r = report(vec![strong, weak]);
        capture(&mut r, &data, FileType::Elf);

        let ids: Vec<&str> = r
            .context
            .iter()
            .flat_map(|c| &c.notes)
            .map(|n| n.id.as_str())
            .collect();
        assert!(ids.contains(&"mal/exec"), "strongest kept: {:?}", r.context);
        assert!(
            !ids.contains(&"cap/str"),
            "weaker overlapping trait dropped: {:?}",
            r.context
        );
    }

    #[test]
    fn binary_atomic_leg_reserves_stronger_composites_window() {
        // The byte analogue of `atomic_leg_reserves_stronger_composites_window`: a
        // notable atomic leg a hostile composite drew on reserves the hostile byte
        // window (lead-in 128, not notable's 64). The composite anchors at its
        // stronger far leg (offset 100), so the widening at offset 800 is the leg's
        // own inherited severity.
        let data = vec![0u8; 2048];
        let near = finding("cap/near", Criticality::Notable, &[800]);
        let mut far = finding("cap/far", Criticality::Notable, &[100]);
        far.conf = 0.95; // the composite's most-confident leg — it anchors here
        let mut composite = finding("obj/implant", Criticality::Hostile, &[]);
        composite.trait_refs = vec!["cap/near".to_string().into(), "cap/far".to_string().into()];
        let mut r = report(vec![near, far, composite]);
        capture(&mut r, &data, FileType::Elf);

        let near_block = r
            .context
            .iter()
            .find(|c| c.notes.iter().any(|n| n.id == "cap/near"));
        assert_eq!(
            near_block.map(|c| c.loc),
            Some(800 - 128),
            "near leg inherits the hostile 128-byte lead-in: {:?}",
            r.context
        );
    }
}
