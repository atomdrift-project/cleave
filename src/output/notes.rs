//! Notes for findings without a context window, and suppression lines.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// What the context pass draws for a file, which the location-less notes
/// must not repeat.
#[derive(Clone, Copy)]
pub(super) struct ContextCoverage<'a> {
    /// The notes derived for each of the file's context windows.
    pub(super) notes: &'a [Vec<Note>],
    /// Finding ids drawn as byte or source windows.
    pub(super) windowed: &'a HashSet<&'a str>,
    /// Findings holding a note whose every window the plan cut.
    pub(super) capped: &'a HashSet<&'a str>,
    /// Byte ranges of the source windows drawn.
    pub(super) drawn: &'a [(u64, u64)],
    /// Any context is drawn at all.
    pub(super) shown: bool,
}

/// Emit selected findings that have *no anchorable location of their own* — once
/// context is captured, that means a cross-file composite (its evidence lives in a
/// member, so it has no local window) and nothing else: any intra-file finding is
/// either shown at its offset by the context pass or was dominated there and
/// dropped, never resurrected here (see the filter below). When no context was
/// captured at all, every selected finding falls through here, since this is then
/// the only place they can surface. The terminal (Rich) view renders each as a
/// severity-tinted gutter glyph and description (no comment marker — there's no
/// code to comment on), and a cross-file composite trails its contributing
/// members; the LLM (Minimal) view uses the `{marker} SEV desc` annotation form.
pub(super) fn render_no_anchor(
    out: &mut String,
    file: &FileAnalysis,
    selected: &[&str],
    coverage: &ContextCoverage<'_>,
    owed: &HashSet<&str>,
    id_to_file: &HashMap<u32, &FileAnalysis>,
    opts: &TinyOpts,
    colorize: bool,
) {
    let ContextCoverage {
        notes,
        windowed,
        capped,
        drawn,
        shown: context_shown,
    } = *coverage;
    let sel: HashSet<&str> = selected.iter().copied().collect();

    let rich = matches!(opts.header, HeaderStyle::Rich);
    // Placement anchors every shown finding that matched a byte of this file
    // (`context::notes`). So once context exists, a finding missing from
    // `windowed` wasn't location-less; its window was *dominated* by a stronger
    // overlapping match and dropped by the placement pass. The dominating match
    // already represents that span, so showing the loser again — here, with no
    // location — is pure noise. Only the highest-scored finding per span is kept.
    // Once context exists, the no-anchor block therefore surfaces *only* cross-file
    // composites (located in a member, shown with a trail, with no local window to
    // be dominated). Everything else is shown at its offset by the context pass or
    // was dominated and dropped. When no context was captured at all, the block is
    // the only way to surface findings, so it keeps them. A finding in `capped`
    // holds a note the window plan (`TinyOpts::max_windows`,
    // `windows_per_finding`) declined to draw — capped, not dominated — so it
    // is listed here: the cap trades evidence, never findings. The LLM view
    // also lists a finding no selected note overlaps: what dominated it was a
    // composite this view withholds, so nothing on screen represents its span
    // (`relabel_composite_notes` hands a leg the composite's note only where
    // that note covers the leg's own evidence). A finding whose evidence sits
    // inside a `drawn` source window is already on screen, whatever note that
    // window carries, so it is not listed again.
    //
    // A file past the context cap (`context_shown` false) drew no windows even
    // though it captured context, so the dominance argument doesn't apply: this
    // block is the only place its findings can surface. Treat it as uncaptured,
    // and lower the floor to notable so no real detection is lost to the cap.
    let captured = context_shown && !file.context.is_empty();

    // A location-less finding has no honest byte chunk, so this is its only
    // output surface. Keep notable+ regardless of whether other findings in the
    // file captured context. Focused mode is stricter: a note with no location
    // to anchor it earns a line only at focus criticality or above — a
    // location-less notable (e.g. a container's archive-shape observation) is
    // exactly the noise the focused view exists to drop.
    let floor = match opts.focus_crit {
        Some(fc) => fc,
        None => opts.min_crit.max(Criticality::Notable),
    };
    let represented = |f: &Finding| {
        let spans = crate::types::traits_findings::finding_spans(f);
        let overlaps = |lo: u64, hi: u64| {
            spans
                .iter()
                .any(|&[off, len]| off < hi && lo < off + len.max(1))
        };
        drawn.iter().any(|&(lo, hi)| overlaps(lo, hi))
            || notes
                .iter()
                .flatten()
                .filter(|n| sel.contains(n.id.as_str()))
                .any(|n| overlaps(n.off, n.off + u64::from(n.len.max(1))))
    };
    let mut rest: Vec<&Finding> = file
        .findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            let id = f.id.as_str();
            (f.crit >= floor || owed.contains(id)) && sel.contains(id) && !windowed.contains(id)
        })
        .filter(|(index, f)| {
            // Owed evidence is never "represented" by another trait's note:
            // the reader must see it named, so it lists here unless drawn.
            owed.contains(f.id.as_str())
                || !captured
                || capped.contains(f.id.as_str())
                || (!rich && !represented(f))
                || file.composite_sources.contains_key(f.id.as_str())
                || !file.finding_has_local_offset(*index)
        })
        .map(|(_, f)| f)
        .collect();
    rest.sort_unstable_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));

    let mut seen = HashSet::new();
    for f in rest {
        if !seen.insert(f.id.as_str()) {
            continue;
        }
        let desc = terse_description(&f.desc);
        if !rich {
            // LLM/tiny view: a whole-file finding that anchored to no line renders
            // as a bare annotation — `{marker} SEV desc`, no location — matching
            // the form the located findings use (which insert a `LINE[:COL]`
            // between the severity and the description). Should be rare.
            let marker = comment_marker(&file.file_type);
            out.push_str(&format!(
                "{marker} {} {}\n",
                f.crit.letter(),
                annotate_desc(&desc, &f.id)
            ));
            continue;
        }
        // Terminal view: severity gutter glyph + description, no comment marker.
        let glyph = gutter_glyph(Some(f.crit), colorize);
        if colorize {
            out.push_str(&format!("{glyph} {}\n", desc.bright_white()));
        } else {
            out.push_str(&format!("{glyph} {desc}\n"));
        }
        // A cross-file composite names the members it drew from, aligned under
        // the description on a dim trailing line.
        let members = composite_source_trail(file, &f.id, id_to_file);
        if !members.is_empty() {
            const MAX_MEMBERS: usize = 5;
            let trail = if members.len() > MAX_MEMBERS {
                format!(
                    "↳ {}, +{} more",
                    members[..MAX_MEMBERS].join(", "),
                    members.len() - MAX_MEMBERS
                )
            } else {
                format!("↳ {}", members.join(", "))
            };
            if colorize {
                out.push_str(&format!("  {}\n", trail.bright_black()));
            } else {
                out.push_str(&format!("  {trail}\n"));
            }
        }
    }
}

/// Render the traits this file matched but withheld or demoted, with the legs
/// that did it and the bytes those legs fired on.
///
/// The point is an independent second opinion: a reader that only sees what the
/// engine chose to report cannot tell a clean file from a suppressed one, and
/// the suppressor is the interesting half — `netrc` withheld because the file
/// looks like a test fixture is a judgement worth checking, not a fact.
///
/// Legs carry byte spans rather than rendered bytes. Where the leg is itself a
/// reported finding its window is already drawn above; where it is a
/// `crit: exception` composite (the common benign-context suppressor, stripped
/// before output) the span is the only handle there is, and it is enough to
/// pull the bytes from the file.
///
/// Trait ids stand alone, without the descriptions reported findings carry: a
/// taxonomy path already says what the trait is
/// (`…/http/url/domain::js-remote-host-url`), and the reader these lines exist
/// for can take it from there. Prose would only crowd out the legs, which are
/// the part nothing else in the report states.
pub(super) fn render_suppressions(
    out: &mut String,
    file: &FileAnalysis,
    opts: &TinyOpts,
    colorize: bool,
) {
    /// Suppressions shown per file. Enough to see a pattern, few enough that a
    /// heavily-suppressed file does not crowd out its actual findings.
    const MAX_SHOWN: usize = 8;
    /// Legs shown per suppression.
    const MAX_LEGS: usize = 3;

    if !has_shown_suppressions(file, opts) {
        return;
    }
    let shown: Vec<&crate::types::Suppression> = file
        .suppressions
        .iter()
        .filter(|s| s.crit >= opts.min_crit)
        .take(MAX_SHOWN)
        .collect();

    let rich = matches!(opts.header, HeaderStyle::Rich);
    // Offsets in the same base the file's own rows carry, so a leg's bytes are
    // looked up the same way as a finding's. (A text file's windows are labelled
    // `LINE:COL`; a leg is a raw byte offset into the file either way, since the
    // trait it fired on drew no window to sit beside.)
    let hex = is_binary_file_type(&file.file_type);
    for suppression in shown {
        let verb = match suppression.kind {
            crate::types::SuppressionKind::Unless => "withheld",
            crate::types::SuppressionKind::Downgrade => "downgraded",
        };
        let legs: Vec<String> = suppression
            .by
            .iter()
            .take(MAX_LEGS)
            .map(|leg| {
                if leg.spans.is_empty() {
                    super::sample_text(&leg.id).into_owned()
                } else {
                    let spans: Vec<String> = leg
                        .spans
                        .iter()
                        .map(|[off, _]| {
                            if hex {
                                format!("{off:x}")
                            } else {
                                off.to_string()
                            }
                        })
                        .collect();
                    format!("{} @{}", super::sample_text(&leg.id), spans.join(","))
                }
            })
            .collect();
        let more = suppression.by.len().saturating_sub(MAX_LEGS);
        let by = match (legs.is_empty(), more) {
            (true, _) => String::new(),
            (false, 0) => format!(" by {}", legs.join("; ")),
            (false, n) => format!(" by {}, +{n} more", legs.join("; ")),
        };

        if rich {
            let line = format!(
                "⊘ {verb} {} {}{by}",
                suppression.crit.letter(),
                super::sample_text(&suppression.id)
            );
            if colorize {
                out.push_str(&format!("{}\n", line.bright_black()));
            } else {
                out.push_str(&format!("{line}\n"));
            }
        } else {
            // Machine/LLM view: same comment-marker form the located findings
            // use, with the verb standing where a location would.
            let marker = comment_marker(&file.file_type);
            out.push_str(&format!(
                "{marker} {} {verb} {}{by}\n",
                suppression.crit.letter(),
                super::sample_text(&suppression.id),
            ));
        }
    }
    let hidden = file
        .suppressions
        .iter()
        .filter(|s| s.crit >= opts.min_crit)
        .count()
        .saturating_sub(MAX_SHOWN);
    if hidden > 0 {
        let marker = if rich {
            "⊘"
        } else {
            comment_marker(&file.file_type)
        };
        out.push_str(&format!("{marker} +{hidden} more suppressed\n"));
    }
}
