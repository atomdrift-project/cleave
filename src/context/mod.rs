//! Context: the bytes around a file's findings, and the notes that label them.
//!
//! `capture` runs while a file's bytes are in hand. Each shown finding claims
//! the bytes it matched — an atomic trait up to `ATOMIC_MAX_MATCHES` spans, a
//! composite its strongest leg no stronger match already holds — widened by a
//! criticality-sized margin ([`Criticality::hex_context`]); overlapping windows
//! merge into one [`ContextLine`]. A textual file labels each window with the
//! 1-based line and column of its first byte; binaries carry neither.
//!
//! Notes are neither captured nor stored. [`notes`] derives them from a file's
//! final findings whenever something renders, with the same placement capture
//! used, so a note can never name a finding removed after capture, and a stored
//! report renders exactly as a live one.

use filefacts::FileType;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::types::traits_findings::{MAX_EV_LOCS, finding_spans};
use crate::types::{AnalysisReport, ContextLine, Criticality, Finding, Istr, Note};

/// Locations shown for an atomic trait that matches in several places.
const ATOMIC_MAX_MATCHES: usize = MAX_EV_LOCS;

/// Legs a composite may be placed on. Composites reference a handful of
/// distinguishing components; more legs add nothing.
const MAX_LEGS: usize = 8;

/// Longest match a note highlights. A located metric can span a whole
/// concealed region; its preview must stay a few rows. The uncapped length
/// still rides the finding's spans.
const MAX_NOTE_LEN: u64 = 512;

/// Text files at or under this size are captured whole: a header comment or
/// docstring is often the one place that says what the code is for.
const SMALL_TEXT_WHOLE_BYTES: u64 = 2048;

/// Slice `report.context` out of `data`: one window per shown finding's
/// placement, sized by criticality, overlapping windows merged.
///
/// `doomed` names findings still in `report` that the end-of-analysis
/// low-value filter will delete (`CapabilityMapper::doomed_low_value_ids`);
/// they claim no bytes. Pass an empty set when the findings are already final.
pub(crate) fn capture(
    report: &mut AnalysisReport,
    data: &[u8],
    file_type: FileType,
    doomed: &FxHashSet<Istr>,
) {
    if report.findings.is_empty() || data.is_empty() {
        return;
    }
    // Recover symbol offsets first, so a composite drawing on the symbol
    // finds the position through its component.
    anchor_orphan_symbol_matches(&mut report.findings, data);

    let shown: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.crit != Criticality::Filtered && !doomed.contains(&f.id))
        .collect();
    if shown.is_empty() {
        return;
    }
    let by_id = index_by_id(&report.findings);
    for f in shown.iter().filter(|f| legs(f, &by_id).is_empty()) {
        report_unanchored(f, &by_id, &report.target.path);
    }

    let total = data.len() as u64;
    let textual =
        file_type.is_source_code() || (!file_type.is_executable_code() && looks_textual(data));
    let whole = textual && total <= SMALL_TEXT_WHOLE_BYTES;
    let windows = place(&shown, &by_id, &Ranker::new(&shown))
        .into_iter()
        .map(|(note, sizing)| {
            if whole {
                return (0, total);
            }
            let (before, after) = sizing.hex_context();
            let end = note.off + u64::from(note.len) + after;
            (note.off.saturating_sub(before), end.min(total))
        })
        .collect();

    let lines = textual.then(|| LineIndex::new(data));
    report.context = merge(windows)
        .into_iter()
        .filter(|&(lo, hi)| lo < hi)
        .filter_map(|(lo, hi)| {
            let data = data.get(usize::try_from(lo).ok()?..usize::try_from(hi).ok()?)?;
            let (line, col) = lines.as_ref().map(|l| l.position(lo)).unzip();
            Some(ContextLine {
                loc: lo,
                line,
                col,
                data: data.to_vec(),
            })
        })
        .collect();
}

/// The notes on each of a file's context windows, indexed like `context`.
///
/// Every shown finding is placed exactly as `capture` placed it, attached to
/// the window holding its offset, and each window's notes are reduced to the
/// ones worth showing (`dedup_notes`). A finding inherited from a member
/// (`src`) brings no spans of its own (inheritance strips them), but as a
/// composite it may still label this file's own matching legs. Provenance is
/// deliberately ignored: a stored report cannot always tell an inherited
/// composite from a native one, and live and replay must agree.
#[must_use]
pub fn notes(findings: &[Finding], context: &[ContextLine]) -> Vec<Vec<Note>> {
    let mut out = vec![Vec::new(); context.len()];
    let shown: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.crit != Criticality::Filtered)
        .collect();
    if shown.is_empty() || out.is_empty() {
        return out;
    }
    let ranker = Ranker::new(&shown);
    for (note, _) in place(&shown, &index_by_id(findings), &ranker) {
        let holder = context
            .iter()
            .position(|c| note.off >= c.loc && note.off - c.loc < c.data.len() as u64);
        if let Some(i) = holder {
            out[i].push(note);
        }
    }
    for window in &mut out {
        dedup_notes(window, &ranker);
    }
    out
}

/// Each shown finding's notes, with the criticality that sizes its window.
///
/// Atomic traits are the fixed scaffolding: one note per span, sized by the
/// strongest composite drawing on them. Composites are conclusions spanning
/// several legs; strongest first, each takes its most confident leg that no
/// equal-or-stronger match already holds, so the higher-severity conclusion
/// claims a contested leg. A composite whose every leg is held gets no note.
fn place(
    shown: &[&Finding],
    by_id: &FxHashMap<&str, &Finding>,
    ranker: &Ranker<'_>,
) -> Vec<(Note, Criticality)> {
    let mut placed: Vec<(Note, Criticality)> = Vec::new();
    // The byte ranges claimed so far, with the strength that claimed them.
    let mut held: Vec<(u64, u64, Strength)> = Vec::new();
    let claim = |f: &Finding, [off, len]: [u64; 2], held: &mut Vec<(u64, u64, Strength)>| {
        let note = note_for(f, off, len);
        held.push((
            note.off,
            note.off + u64::from(note.len.max(1)),
            ranker.of(f),
        ));
        note
    };

    for f in shown.iter().filter(|f| f.trait_refs.is_empty()) {
        for span in finding_spans(f).into_iter().take(ATOMIC_MAX_MATCHES) {
            placed.push((claim(f, span, &mut held), ranker.sizing(f)));
        }
    }

    let mut composites: Vec<&Finding> = shown
        .iter()
        .copied()
        .filter(|f| !f.trait_refs.is_empty())
        .collect();
    composites.sort_by(|a, b| {
        ranker
            .of(b)
            .total_cmp(&ranker.of(a))
            .then_with(|| a.id.cmp(&b.id))
    });
    for f in composites {
        let strength = ranker.of(f);
        let free = legs(f, by_id).into_iter().find(|&[off, len]| {
            let end = off + len.clamp(1, MAX_NOTE_LEN);
            !held
                .iter()
                .any(|&(lo, hi, s)| s.total_cmp(&strength).is_ge() && lo < end && off < hi)
        });
        if let Some(span) = free {
            placed.push((claim(f, span, &mut held), f.crit));
        }
    }
    placed
}

/// A finding's candidate locations: its own spans and those of every component
/// it draws on, transitively (aggregator components carry no offset of their
/// own). One per offset, keeping the most confident; ordered most confident
/// first, earliest offset breaking ties; capped at [`MAX_LEGS`]. Empty when
/// the finding matched no byte of this file.
fn legs(composite: &Finding, by_id: &FxHashMap<&str, &Finding>) -> Vec<[u64; 2]> {
    let mut found: Vec<([u64; 2], f32)> = Vec::new();
    let mut seen: FxHashSet<&str> = FxHashSet::default();
    let mut stack = vec![composite];
    while let Some(f) = stack.pop() {
        if !seen.insert(f.id.as_str()) {
            continue;
        }
        found.extend(finding_spans(f).into_iter().map(|span| (span, f.conf)));
        stack.extend(
            f.trait_refs
                .iter()
                .filter_map(|r| by_id.get(r.as_str()).copied()),
        );
    }
    found.sort_by(|a, b| a.0[0].cmp(&b.0[0]).then(b.1.total_cmp(&a.1)));
    found.dedup_by_key(|(span, _)| span[0]);
    found.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0[0].cmp(&b.0[0])));
    found.truncate(MAX_LEGS);
    found.into_iter().map(|(span, _)| span).collect()
}

/// A note for `finding`'s match at `off`, its length capped at [`MAX_NOTE_LEN`].
fn note_for(finding: &Finding, off: u64, len: u64) -> Note {
    Note {
        crit: finding.crit,
        id: finding.id.clone(),
        desc: finding.desc.clone(),
        off,
        len: u32::try_from(len.min(MAX_NOTE_LEN)).unwrap_or(u32::MAX),
        conf: finding.conf,
    }
}

/// Index findings by id, first occurrence winning, for component lookup.
fn index_by_id(findings: &[Finding]) -> FxHashMap<&str, &Finding> {
    let mut by_id = FxHashMap::default();
    for f in findings {
        by_id.entry(f.id.as_str()).or_insert(f);
    }
    by_id
}

/// Merge overlapping or adjacent `(lo, hi)` windows, in file order.
fn merge(mut windows: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    windows.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(windows.len());
    for (lo, hi) in windows {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// Log a shown finding that claims no bytes of this file. Its offsets either
/// index an embedded member (that member shows them — nothing to report), or
/// it has none: a file-global fact (signing trust, a metric) is expected, but a
/// content matcher that matched bytes without recording where is a bug.
fn report_unanchored(finding: &Finding, by_id: &FxHashMap<&str, &Finding>, file_path: &str) {
    let in_member = |f: &Finding| {
        f.evidence.iter().any(|e| {
            e.byte_offset().is_some()
                || e.location
                    .as_deref()
                    .is_some_and(|l| l.starts_with("archive:"))
        })
    };
    if in_member(finding)
        || finding
            .trait_refs
            .iter()
            .any(|r| by_id.get(r.as_str()).is_some_and(|c| in_member(c)))
    {
        return;
    }
    const CONTENT: [&str; 12] = [
        "string",
        "symbol",
        "symbols",
        "raw",
        "text",
        "literal",
        "string_literal",
        "ast",
        "ast_query",
        "encoded_string",
        "hex",
        "xor",
    ];
    if finding
        .evidence
        .iter()
        .any(|e| CONTENT.contains(&e.method.as_str()))
    {
        tracing::error!(
            finding_id = %finding.id,
            kind = ?finding.kind,
            "{file_path}: content match has no file offset — the matcher should record where it matched"
        );
    } else {
        tracing::debug!(finding_id = %finding.id, "file-global finding has no byte context");
    }
}

/// Anchor symbol matches that carry a name but no byte offset.
///
/// Most formats hand each import/export/function the file offset of its name —
/// but degraded extraction can't: recovery with no PLT address, forwarded
/// PE exports, a future format gap. The matched value is still the symbol *name*,
/// literal bytes present in the file, so locate it directly. Symbol-table names
/// are NUL-terminated, so searching `name\0` lands on the real table entry
/// rather than a same-prefix substring (`read` inside `readdir`). Mutating the
/// evidence here (rather than only the local anchor) lets a composite that
/// references this finding pick up the recovered offset through its component.
///
/// A name genuinely absent from the file stays unanchored and is still surfaced
/// by [`report_unanchored`] — that is the matcher bug the guard exists to catch.
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
            // Mach-O import facts normalize the leading underscore and may
            // strip an ABI suffix such as `$INODE64` from the on-disk name.
            let off = if e.location.as_deref() == Some("import") {
                locate_macho_import(data, &e.value)
                    .or_else(|| locate_nul_terminated(data, &e.value))
            } else {
                locate_nul_terminated(data, &e.value)
            };
            if let Some(off) = off {
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

/// Find a normalized Mach-O import at its on-disk spelling, allowing an ABI
/// suffix (for example `_opendir$INODE64`) before the NUL terminator.
fn locate_macho_import(data: &[u8], value: &str) -> Option<u64> {
    if value.len() < 3 {
        return None;
    }
    let mut needle = Vec::with_capacity(value.len() + 1);
    needle.push(b'_');
    needle.extend_from_slice(value.as_bytes());
    let mut search_from = 0usize;
    while let Some(relative) = memchr::memmem::find(data.get(search_from..)?, &needle) {
        let position = search_from.checked_add(relative)?;
        let suffix_at = position.checked_add(needle.len())?;
        if data
            .get(suffix_at)
            .is_some_and(|byte| *byte == 0 || *byte == b'$')
        {
            return Some(position as u64);
        }
        search_from = position.checked_add(1)?;
    }
    None
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

/// A match's rank for overlap resolution, in order:
/// 1. criticality — a trait's own, raised to that of the strongest composite
///    drawing on it (see [`referring_crit`]);
/// 2. the trait's own criticality, so a composite still outranks the legs it
///    lent its criticality to;
/// 3. an invocation over a reference (see [`is_invocation`]): of two equally
///    graded notes on one span, "Shell invokes the curl command" tells a
///    reader what the line does, "References curl file-output option" only
///    what it mentions;
/// 4. confidence.
///
/// Placement and the per-window dedup share it, so they agree on which match
/// is "stronger."
///
/// Composite support counts because the weaker note is dropped outright: a
/// notable leg behind a suspicious conclusion (a paste-site URL a tunnel
/// publishes its address to) used to lose its span to a more confident but
/// generic notable (a short-domain URL heuristic), and the evidence the
/// conclusion rests on never owned a line.
#[derive(Clone, Copy, Debug)]
struct Strength {
    rank: u8,
    own: u8,
    invocation: bool,
    conf: f32,
}

impl Strength {
    fn total_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank
            .cmp(&other.rank)
            .then(self.own.cmp(&other.own))
            .then(self.invocation.cmp(&other.invocation))
            .then(self.conf.total_cmp(&other.conf))
    }
}

/// What [`Strength`] needs to know about a file's findings beyond a note.
struct Ranker<'a> {
    /// Strongest composite criticality referencing each leg.
    leg_crit: FxHashMap<&'a str, Criticality>,
    /// Findings that describe an invocation.
    invocations: FxHashSet<&'a str>,
}

impl<'a> Ranker<'a> {
    fn new(shown: &[&'a Finding]) -> Self {
        Self {
            leg_crit: referring_crit(shown),
            invocations: shown
                .iter()
                .filter(|f| is_invocation(f))
                .map(|f| f.id.as_str())
                .collect(),
        }
    }

    fn of(&self, f: &Finding) -> Strength {
        self.strength(f.id.as_str(), f.crit, f.conf)
    }

    /// The criticality that sizes an atomic trait's window: its own, raised to
    /// that of the strongest composite drawing on it.
    fn sizing(&self, f: &Finding) -> Criticality {
        self.leg_crit
            .get(f.id.as_str())
            .map_or(f.crit, |&c| c.max(f.crit))
    }

    fn strength(&self, id: &str, crit: Criticality, conf: f32) -> Strength {
        Strength {
            rank: self.leg_crit.get(id).map_or(crit, |&c| c.max(crit)).rank(),
            own: crit.rank(),
            invocation: self.invocations.contains(id),
            conf,
        }
    }
}

/// Whether a finding describes an invocation rather than a reference: a leaf
/// id naming a call (`-call`, `-command`, `invoke`, `exec`) or a description
/// using an action verb ("Source invokes systemctl enable action"). Decided
/// from the finding alone, so a stored report ranks exactly as a live one.
fn is_invocation(finding: &Finding) -> bool {
    const ID_MARKERS: [&str; 4] = ["-call", "-command", "invoke", "exec"];
    const VERBS: [&str; 5] = ["invokes", "calls", "runs", "executes", "spawns"];
    let id = finding.id.as_str();
    let leaf = id.rsplit_once("::").map_or(id, |(_, leaf)| leaf);
    ID_MARKERS.iter().any(|m| leaf.contains(m))
        || finding
            .desc
            .as_str()
            .split_whitespace()
            .any(|w| VERBS.iter().any(|v| w.eq_ignore_ascii_case(v)))
}

/// Path depth below the namespace at which two notes count as the same kind
/// of evidence: `supply-chain/impersonation` and `malware/supply-chain` differ.
const NOTE_FAMILY_DEPTH: usize = 2;

/// Reduce a chunk's notes to the set worth showing:
/// 1. dedup by finding id (keep highest crit);
/// 2. dedup overlapping byte spans, strongest first ([`Strength`]), greedily.
///    Two traits of one family on the same bytes say the same thing, so the
///    weaker goes. An equally graded suspicious-or-worse trait from another
///    family says something different (a campaign attribution and an
///    impersonation finding on one `require` line), so one such second note
///    per span is kept. Notable lines stay single: there, a second note is
///    usually a generic restatement (a short domain beside a paste-site URL);
/// 3. order by severity desc, id asc — stable, deterministic output.
fn dedup_notes(notes: &mut Vec<Note>, ranker: &Ranker<'_>) {
    notes.sort_unstable_by(|a, b| a.id.cmp(&b.id).then_with(|| b.crit.cmp(&a.crit)));
    notes.dedup_by(|a, b| a.id == b.id);

    // Strongest-first, then keep a note only if it doesn't overlap a kept one.
    // The id tie-break makes the winner among equal-score overlapping notes
    // deterministic — without it, the displayed annotation flips with trait
    // evaluation order (which shifts across builds).
    let strength = |n: &Note| ranker.strength(n.id.as_str(), n.crit, n.conf);
    notes.sort_unstable_by(|a, b| {
        strength(b)
            .total_cmp(&strength(a))
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut kept: Vec<Note> = Vec::with_capacity(notes.len());
    for note in notes.drain(..) {
        let note_end = note.off + u64::from(note.len.max(1));
        let mut overlapping = kept.iter().filter(|kept| {
            let kept_end = kept.off + u64::from(kept.len.max(1));
            kept.off < note_end && note.off < kept_end
        });
        let keep = match (overlapping.next(), overlapping.next()) {
            (None, _) => true,
            (Some(only), None) => {
                note.crit >= Criticality::Suspicious
                    && note.crit == only.crit
                    && crate::output::trait_family(only.id.as_str(), NOTE_FAMILY_DEPTH)
                        != crate::output::trait_family(note.id.as_str(), NOTE_FAMILY_DEPTH)
            }
            (Some(_), Some(_)) => false,
        };
        if keep {
            kept.push(note);
        }
    }
    kept.sort_unstable_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));
    *notes = kept;
}

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
mod tests;
