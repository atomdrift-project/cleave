//! Which findings and context windows a view shows.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Per file id, the evidence the LLM/tiny view must render in that file: each
/// suspicious/hostile atom the file matched, and every atom a
/// suspicious/hostile composite anywhere in the report transitively rests on,
/// placed in the member where it matched.
///
/// The view withholds composites (see `select_ids`), so these atoms are all
/// that is left of a withheld conclusion; losing one to a criticality floor,
/// the one-note-per-row rule, dedup or a window cap silently weakened the
/// evidence a grader weighs. Resolution uses what analysis recorded — no rule
/// is re-evaluated, and a leg absent from the report (never matched, or
/// suppressed) resolves to nothing:
///   - a container's leg that also matched natively in members below it
///     belongs to the deepest such members, narrowed to the composite's
///     recorded `composite_sources` members when any of them carry it;
///   - a native composite leg expands into its own `trait_refs` in place;
///   - an inherited copy (`src` set) resolves in the member it came from.
pub(super) fn evidence_legs(files: &[FileAnalysis]) -> HashMap<u32, BTreeSet<&str>> {
    use crate::types::file_analysis::ARCHIVE_DELIMITER;
    let by_id: HashMap<u32, &FileAnalysis> = files.iter().map(|f| (f.id, f)).collect();
    // Per id, the files it matched natively in.
    let mut native: HashMap<&str, Vec<&FileAnalysis>> = HashMap::new();
    for file in files {
        for f in file.findings.iter().filter(|f| f.src.is_none()) {
            let homes = native.entry(f.id.as_str()).or_default();
            if homes.last().is_none_or(|h| h.id != file.id) {
                homes.push(file);
            }
        }
    }
    let below = |d: &FileAnalysis, f: &FileAnalysis| {
        d.path.len() > f.path.len() + ARCHIVE_DELIMITER.len()
            && d.path.starts_with(f.path.as_str())
            && d.path[f.path.len()..].starts_with(ARCHIVE_DELIMITER)
    };

    let mut out: HashMap<u32, BTreeSet<&str>> = HashMap::new();
    for file in files {
        for c in &file.findings {
            let owned = c.src.is_none() || file.composite_sources.contains_key(c.id.as_str());
            if c.crit < Criticality::Suspicious || !owned {
                continue;
            }
            let sources: HashSet<u32> = file
                .composite_sources
                .get(c.id.as_str())
                .into_iter()
                .flatten()
                .map(|s| s.file)
                .collect();
            // An elevated atom resolves like a leg: a container's copy of a
            // member's match belongs to that member.
            let mut stack: Vec<(&FileAnalysis, &str)> = if c.trait_refs.is_empty() {
                vec![(file, c.id.as_str())]
            } else {
                c.trait_refs.iter().map(|r| (file, r.as_str())).collect()
            };
            let mut seen: HashSet<(u32, &str)> = HashSet::new();
            while let Some((f, id)) = stack.pop() {
                if !seen.insert((f.id, id)) {
                    continue;
                }
                let homes = native.get(id).map_or(&[][..], Vec::as_slice);
                let inner: Vec<&FileAnalysis> =
                    homes.iter().copied().filter(|d| below(d, f)).collect();
                // Only the deepest: a nested container re-carries its members'.
                let mut deeper: Vec<&FileAnalysis> = inner
                    .iter()
                    .copied()
                    .filter(|d| !inner.iter().any(|e| below(e, d)))
                    .collect();
                if deeper.iter().any(|d| sources.contains(&d.id)) {
                    deeper.retain(|d| sources.contains(&d.id));
                }
                if !deeper.is_empty() {
                    stack.extend(deeper.into_iter().map(|d| (d, id)));
                } else if let Some(g) = f
                    .findings
                    .iter()
                    .find(|g| g.src.is_none() && g.id.as_str() == id)
                {
                    if g.trait_refs.is_empty() {
                        out.entry(f.id).or_default().insert(g.id.as_str());
                    } else {
                        stack.extend(g.trait_refs.iter().map(|r| (f, r.as_str())));
                    }
                } else if let Some(m) = f
                    .findings
                    .iter()
                    .find_map(|g| (g.id.as_str() == id).then_some(g.src).flatten())
                    .and_then(|m| by_id.get(&m))
                {
                    stack.push((m, id));
                }
            }
        }
    }
    out
}

/// Whether `text` names trait `id` as a whole token: not as the prefix of a
/// longer id (`a::b` inside `a::b-c`) nor the tail of another path.
pub(super) fn mentions_id(text: &str, id: &str) -> bool {
    let is_id_byte =
        |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'/' | b':' | b'-' | b'_' | b'.');
    let bytes = text.as_bytes();
    text.match_indices(id).any(|(i, _)| {
        !bytes[..i].last().is_some_and(is_id_byte)
            && !bytes.get(i + id.len()).is_some_and(is_id_byte)
    })
}

/// The plain LLM view ([`TinyOpts::tiny`]).
#[must_use]
pub fn format_tiny(report: &AnalysisReport) -> String {
    format_context(report, &TinyOpts::tiny())
}

/// Paths of files that are archive containers — i.e. some other file is an
/// archive member of theirs (`<container>!!<member>`). Synthetic embedded-binary
/// extractions (`…!!embedded:…`) are sub-views of a member, not members, so they
/// don't make their carrier a container.
pub(super) fn archive_container_paths<'a>(files: &[&'a FileAnalysis]) -> HashSet<&'a str> {
    use crate::types::file_analysis::ARCHIVE_DELIMITER;
    let mut paths = HashSet::new();
    for f in files {
        if let Some(idx) = f.path.rfind(ARCHIVE_DELIMITER) {
            let leaf = &f.path[idx + ARCHIVE_DELIMITER.len()..];
            if leaf.starts_with("embedded:") {
                continue;
            }
            paths.insert(&f.path[..idx]);
        }
    }
    paths
}

/// The deepest nesting level at which each finding id appears as a *native*
/// finding (one located in that file, `src` unset — not inherited from a child).
/// A container drops any finding also native deeper down, since that member is
/// where it was actually located.
pub(super) fn native_finding_depths<'a>(files: &[&'a FileAnalysis]) -> HashMap<&'a str, u32> {
    let mut depths: HashMap<&str, u32> = HashMap::new();
    for f in files {
        for finding in f.findings.iter().filter(|fd| fd.src.is_none()) {
            depths
                .entry(finding.id.as_str())
                .and_modify(|d| *d = (*d).max(f.depth))
                .or_insert(f.depth);
        }
    }
    depths
}

/// Render-ready member trail for a cross-file composite: the container-relative
/// path of each member it drew from, suffixed with a location (`:line` for
/// source, `@0x<off>` for binary) when one is known. Reads the provenance
/// resolved at finalize (`file.composite_sources`), resolving member file ids to
/// their analysis via `id_to_file`. A registry/provenance leg (not an archive
/// member) renders as `registry/<purl>` instead of a member path. Empty when the
/// finding isn't a cross-file composite.
pub(super) fn composite_source_trail(
    container: &FileAnalysis,
    finding_id: &str,
    id_to_file: &HashMap<u32, &FileAnalysis>,
) -> Vec<String> {
    use crate::types::file_analysis::ARCHIVE_DELIMITER;
    let Some(sources) = container.composite_sources.get(finding_id) else {
        return Vec::new();
    };
    let mut prefix = container.path.clone();
    prefix.push_str(ARCHIVE_DELIMITER);
    sources
        .iter()
        .map(|s| {
            let Some(&file) = id_to_file.get(&s.file) else {
                return "?".to_string();
            };
            // A registry node is a grafted provenance leg, not an archive member:
            // show it as `registry/<purl>` rebuilt from its registry.* facts, so
            // the trail reads as a package identity rather than the synthetic
            // `*.registry.json` filename.
            if let Some(purl) = registry_purl(file) {
                return super::sample_text(&format!("registry/{purl}")).into_owned();
            }
            let rel = file.path.strip_prefix(&prefix).unwrap_or(&file.path);
            let rel = super::sample_text(&rel.replace(ARCHIVE_DELIMITER, "/")).into_owned();
            match (s.line, s.offset) {
                (Some(line), _) => format!("{rel}:{line}"),
                (None, Some(off)) => format!("{rel}@0x{off:x}"),
                (None, None) => rel,
            }
        })
        .collect()
}

/// Reconstruct a package URL from a registry node's flattened `registry.*` facts
/// (`registry.ecosystem`/`name`/`version`, from filefacts). `None` for any
/// non-registry file. Used to render a package-scoped composite's provenance leg
/// as `registry/<purl>` in its source trail.
pub(super) fn registry_purl(file: &FileAnalysis) -> Option<String> {
    if file.file_type != "registry" {
        return None;
    }
    let fact = |k: &str| file.kv.get(k).and_then(|v| v.as_str());
    let ecosystem = fact("registry.ecosystem")?;
    let name = fact("registry.name")?;
    let mut purl = format!("pkg:{ecosystem}/{name}");
    if let Some(version) = fact("registry.version") {
        purl.push('@');
        purl.push_str(version);
    }
    Some(purl)
}

/// Append `block` to `out`, indenting every non-empty line by `depth` levels
/// (two spaces each) so archive members and other nested files nest visually
/// under their container. Blank lines stay blank.
pub(super) fn indent_block(out: &mut String, block: &str, depth: u32) {
    if depth == 0 {
        out.push_str(block);
        return;
    }
    let indent = "  ".repeat(depth as usize);
    for seg in block.split_inclusive('\n') {
        let (line, newline) = match seg.strip_suffix('\n') {
            Some(line) => (line, "\n"),
            None => (seg, ""),
        };
        if !line.is_empty() {
            out.push_str(&indent);
            out.push_str(line);
        }
        out.push_str(newline);
    }
}

/// Which context windows a file draws and which selected findings each one
/// annotates: `None` for a window not drawn, else the note ids it renders.
///
/// Applies [`TinyOpts::windows_per_finding`] in file order (a finding's first
/// windows claim it). When the file's windows then exceed
/// [`TinyOpts::max_windows`] or [`TinyOpts::window_bytes`], [`pick_windows`]
/// chooses which to keep. The plan is the single source of truth for the
/// windowed-vs-location-less split: a selected finding in no drawn window
/// renders as a bare note instead.
pub(super) fn window_plan<'a>(
    file: &FileAnalysis,
    notes: &'a [Vec<Note>],
    selected: &[&'a str],
    opts: &TinyOpts,
) -> Vec<Planned<'a>> {
    let sel: HashSet<&str> = selected.iter().copied().collect();
    let mut drawn: HashMap<&str, usize> = HashMap::new();
    let mut plan: Vec<Planned<'a>> = Vec::with_capacity(notes.len());
    for window_notes in notes {
        let mut ids: HashSet<&'a str> = HashSet::new();
        for n in window_notes {
            let id = n.id.as_str();
            if !sel.contains(id) || ids.contains(id) {
                continue;
            }
            let count = drawn.entry(id).or_insert(0);
            if opts.windows_per_finding > 0 && *count >= opts.windows_per_finding {
                continue;
            }
            *count += 1;
            ids.insert(id);
        }
        plan.push(Planned {
            notes: window_notes,
            ids: (!ids.is_empty()).then_some(ids),
        });
    }
    let windows = plan.iter().filter(|w| w.ids.is_some()).count();
    let bytes: usize = plan
        .iter()
        .zip(&file.context)
        .filter(|(w, _)| w.ids.is_some())
        .map(|(_, line)| line.data.len())
        .sum();
    let capped = opts.max_windows > 0 && windows > opts.max_windows;
    let budgeted = opts.window_bytes > 0 && bytes > opts.window_bytes;
    if capped || budgeted {
        let kept = pick_windows(file, &plan, &sel, opts);
        for (w, keep) in plan.iter_mut().zip(kept) {
            if !keep {
                w.ids = None;
            }
        }
    }
    plan
}

/// One context window in the render plan: the notes derived for it and, when
/// the plan draws it, the finding ids it annotates.
pub(super) struct Planned<'a> {
    pub(super) notes: &'a [Note],
    pub(super) ids: Option<HashSet<&'a str>>,
}

/// One annotated note's say in which windows a budgeted file draws.
pub(super) struct StoryNote<'a> {
    pub(super) conf: f32,
    /// The trait's family two and three path segments below its namespace
    /// (`objectives/command-and-control/infrastructure[/paste]`).
    pub(super) family2: &'a str,
    pub(super) family3: &'a str,
    /// `1 + 0.25` per withheld composite drawing on the note, up to four.
    pub(super) support: f32,
}

/// A window [`pick_windows`] may draw.
pub(super) struct Candidate<'a> {
    pub(super) line: usize,
    /// The window's effective criticality rank: the highest of its notes' own
    /// criticality and that of any withheld composite drawing on them.
    pub(super) tier: u8,
    pub(super) bytes: usize,
    pub(super) notes: Vec<StoryNote<'a>>,
}

impl Candidate<'_> {
    /// What drawing this window adds to the story told so far: each note's
    /// confidence, discounted for families already drawn and raised for
    /// composite support, over the square root of the window's size so a
    /// compact window showing several things beats a sprawling one.
    pub(super) fn gain(&self, drawn2: &HashMap<&str, f32>, drawn3: &HashMap<&str, f32>) -> f32 {
        let value: f32 = self
            .notes
            .iter()
            .map(|n| {
                let decay = drawn2.get(n.family2).copied().unwrap_or(1.0)
                    * drawn3.get(n.family3).copied().unwrap_or(1.0);
                n.conf * decay * n.support
            })
            .sum();
        value / (self.bytes.max(1) as f32).sqrt()
    }
}

/// Which of a file's planned windows fit its window budget, indexed like
/// `plan`, chosen to tell the most story in the fewest bytes.
///
/// Criticality wins: windows are drawn in descending [`Candidate::tier`], so a
/// suspicious-backed window beats any number of notable ones. Within a tier the
/// next window is the one with the best [`Candidate::gain`], recomputed after
/// every pick: each pick halves its notes' three-segment families and halves
/// their two-segment families again, so the budget spreads across what the
/// program does instead of repeating one behavior. Ties fall to file order.
/// A window that would overspend the byte budget is skipped, and smaller ones
/// may still fit.
///
/// A composite leg ranks by the withheld composite it supports, but its window
/// is still annotated with the leg's own grade and id: the composite's
/// conclusion never reaches the grader. A `metadata/` note that no withheld
/// composite draws on (an import, say) earns no window here — a file's import
/// block would otherwise outbid its behavior — and still lists as a
/// location-less note.
pub(super) fn pick_windows<'a>(
    file: &FileAnalysis,
    plan: &[Planned<'a>],
    selected: &HashSet<&str>,
    opts: &TinyOpts,
) -> Vec<bool> {
    let support = withheld_composite_support(file, selected);
    let mut candidates: Vec<Candidate<'a>> = Vec::new();
    for (i, w) in plan.iter().enumerate() {
        let Some(ids) = &w.ids else { continue };
        let mut seen: HashSet<&str> = HashSet::new();
        let mut tier = 0u8;
        let mut notes = Vec::new();
        for n in w.notes {
            let id = n.id.as_str();
            if !ids.contains(id) || !seen.insert(id) {
                continue;
            }
            let backing = support.get(id);
            if backing.is_none() && id.starts_with("metadata/") {
                continue;
            }
            let (rank, composites) = backing.map_or((0, 0), |b| (b.rank, b.composites));
            tier = tier.max(n.crit.rank()).max(rank);
            notes.push(StoryNote {
                conf: n.conf,
                family2: trait_family(id, 2),
                family3: trait_family(id, 3),
                support: 1.0 + 0.25 * composites.min(4) as f32,
            });
        }
        if !notes.is_empty() {
            candidates.push(Candidate {
                line: i,
                tier,
                bytes: file.context[i].data.len(),
                notes,
            });
        }
    }

    let mut kept = vec![false; plan.len()];
    let mut drawn2: HashMap<&str, f32> = HashMap::new();
    let mut drawn3: HashMap<&str, f32> = HashMap::new();
    let (mut windows, mut spent) = (0usize, 0usize);
    while opts.max_windows == 0 || windows < opts.max_windows {
        let best = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| opts.window_bytes == 0 || spent + c.bytes <= opts.window_bytes)
            .map(|(k, c)| (k, c.tier, c.gain(&drawn2, &drawn3)))
            .max_by(|a, b| a.1.cmp(&b.1).then(a.2.total_cmp(&b.2)).then(b.0.cmp(&a.0)));
        let Some((k, _, _)) = best else { break };
        let pick = candidates.remove(k);
        kept[pick.line] = true;
        windows += 1;
        spent += pick.bytes;
        let families2: HashSet<&str> = pick.notes.iter().map(|n| n.family2).collect();
        let families3: HashSet<&str> = pick.notes.iter().map(|n| n.family3).collect();
        for f in families2 {
            *drawn2.entry(f).or_insert(1.0) *= 0.5;
        }
        for f in families3 {
            *drawn3.entry(f).or_insert(1.0) *= 0.5;
        }
    }
    kept
}

/// A trait id's family: its namespace plus the next `depth` path segments,
/// e.g. `objectives/command-and-control/infrastructure` at depth 2. A shorter
/// path is its own family.
pub(crate) fn trait_family(id: &str, depth: usize) -> &str {
    let path = id.split_once("::").map_or(id, |(path, _)| path);
    path.match_indices('/')
        .nth(depth)
        .map_or(path, |(i, _)| &path[..i])
}

/// How the withheld composites in a file back one trait.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct CompositeSupport {
    /// Highest criticality rank among them.
    pub(super) rank: u8,
    /// How many distinct composites draw on the trait.
    pub(super) composites: usize,
}

/// Per id, the native composites in `file` that are not in `selected` and
/// reference it — directly, or through nested composites.
///
/// The tiny view withholds composites and shows their legs, but a leg's note
/// carries only the leg's own grade, so evidence behind a hostile conclusion
/// ranked like any notable atom and lost the window budget to a file's import
/// block. [`pick_windows`] ranks the leg by this backing instead, without
/// putting the composite's id or grade in front of the grader.
pub(super) fn withheld_composite_support<'a>(
    file: &'a FileAnalysis,
    selected: &HashSet<&str>,
) -> HashMap<&'a str, CompositeSupport> {
    let composites: HashMap<&str, &Finding> = file
        .findings
        .iter()
        .filter(|f| f.src.is_none() && !f.trait_refs.is_empty())
        .map(|f| (f.id.as_str(), f))
        .collect();
    let mut support: HashMap<&str, CompositeSupport> = HashMap::new();
    for f in composites
        .values()
        .filter(|f| !selected.contains(f.id.as_str()))
    {
        let rank = f.crit.rank();
        let mut seen: HashSet<&str> = HashSet::from([f.id.as_str()]);
        let mut stack: Vec<&str> = f
            .trait_refs
            .iter()
            .map(crate::types::Istr::as_str)
            .collect();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let s = support.entry(id).or_insert(CompositeSupport {
                rank,
                composites: 0,
            });
            s.rank = s.rank.max(rank);
            s.composites += 1;
            if let Some(g) = composites.get(id) {
                stack.extend(g.trait_refs.iter().map(crate::types::Istr::as_str));
            }
        }
    }
    support
}

/// A file's window notes with every note for a withheld composite reassigned
/// to the composite's own legs, or `None` when nothing changes.
///
/// The LLM/tiny view drops composites and shows their legs (`select_ids`), but
/// placement keeps only the strongest note on an overlapping span, and
/// a hostile composite anchored on its leg's evidence beats that notable leg
/// every time. The leg then owned no note at all: the window with the matched
/// line was drawn only if some other selected trait happened to sit on it, and
/// its annotation was never the leg's. A note whose id is a composite (native
/// or inherited: notes ignore provenance, see [`crate::context::notes`])
/// becomes one note per leg that is selected here, has no located note of its
/// own, and has a span of its own evidence overlapping the note's, at the
/// composite's span with the leg's identity. A composite's note covers only
/// the one leg it was anchored on, so the overlap test keeps its other legs
/// from being labeled onto a line that is not their evidence; they stay
/// location-less. A composite with no such leg keeps its (unselected,
/// unrendered) note, and a composite that is itself selected (a leg of a
/// wider one) keeps its own.
pub(super) fn relabel_composite_notes(
    file: &FileAnalysis,
    notes: &[Vec<Note>],
    selected: &[&str],
) -> Option<Vec<Vec<Note>>> {
    let sel: HashSet<&str> = selected.iter().copied().collect();
    let located: HashSet<&str> = notes.iter().flatten().map(|n| n.id.as_str()).collect();
    let mut legs: HashMap<&str, Vec<(&Finding, Vec<[u64; 2]>)>> = HashMap::new();
    for f in &file.findings {
        // A composite that is itself selected — a leg of a wider composite,
        // guaranteed by `select_ids` — keeps its own note: it is shown, so
        // its evidence stays with it.
        if f.trait_refs.is_empty() || sel.contains(f.id.as_str()) {
            continue;
        }
        let mine: Vec<(&Finding, Vec<[u64; 2]>)> = composite_atoms(file, [f])
            .into_iter()
            .filter(|r| sel.contains(r) && !located.contains(r))
            .filter_map(|r| {
                file.findings
                    .iter()
                    .find(|g| g.src.is_none() && g.id.as_str() == r)
            })
            .map(|g| (g, crate::types::traits_findings::finding_spans(g)))
            .collect();
        if !mine.is_empty() {
            legs.entry(f.id.as_str()).or_default().extend(mine);
        }
    }
    if legs.is_empty() {
        return None;
    }
    let mut changed = false;
    let relabeled = notes
        .iter()
        .map(|window| {
            let mut out: Vec<Note> = Vec::with_capacity(window.len());
            for n in window {
                let end = n.off + u64::from(n.len.max(1));
                let covered: Vec<&Finding> = legs
                    .get(n.id.as_str())
                    .into_iter()
                    .flatten()
                    .filter(|(_, spans)| {
                        spans
                            .iter()
                            .any(|&[off, len]| off < end && n.off < off + len.max(1))
                    })
                    .map(|&(leg, _)| leg)
                    .collect();
                if covered.is_empty() {
                    out.push(n.clone());
                    continue;
                }
                changed = true;
                for leg in covered {
                    if out.iter().any(|m| m.id == leg.id && m.off == n.off) {
                        continue;
                    }
                    out.push(Note {
                        crit: leg.crit,
                        id: leg.id.clone(),
                        desc: leg.desc.clone(),
                        off: n.off,
                        len: n.len,
                        conf: leg.conf,
                    });
                }
            }
            out
        })
        .collect();
    changed.then_some(relabeled)
}

/// Whether a file contributes anything to the context view.
pub(super) fn file_has_output(file: &FileAnalysis, opts: &TinyOpts) -> bool {
    // A file whose only output is what the analysis withheld still has
    // something to say — arguably the most important thing, since a reader
    // that never sees it reads the silence as a clean file.
    if has_shown_suppressions(file, opts) {
        return true;
    }
    // With a low-tier fill in play, any non-filtered trait can end up shown, so
    // a file carrying only unreferenced components must survive this gate for
    // the fill to reach it.
    if opts.low_tier_fill > 0 {
        return file
            .findings
            .iter()
            .any(|f| f.crit != Criticality::Filtered);
    }
    file.findings.iter().any(|f| tiny_should_show(f, file))
}

/// cleave's own terminal view: the rich header, without an embedding host's card layout.
/// The one view whose height is spent on a human reading a verdict at a
/// terminal, so the one that trims hardest.
pub(super) fn is_terminal_view(opts: &TinyOpts) -> bool {
    matches!(opts.header, HeaderStyle::Rich) && !opts.card
}

/// Whether this file has suppressions [`render_suppressions`] would draw.
///
/// The single gate every skip path consults, so a file can never be dropped
/// from the view for having nothing but withheld traits to report.
///
/// cleave's terminal view draws none: a human reading a verdict wants the
/// evidence, not the engine's internal second-guessing, and the trailing block
/// routinely ran longer than the findings above it. Every other view keeps
/// them — there the withheld half is signal a grader can weigh.
pub(super) fn has_shown_suppressions(file: &FileAnalysis, opts: &TinyOpts) -> bool {
    !is_terminal_view(opts) && file.suppressions.iter().any(|s| s.crit >= opts.min_crit)
}

/// The top-`n` finding ids to show, ranked by `crit × conf` (highest first) and
/// floored at `min_crit` (after the usual component/filtered gating).
///
/// `low_tier_fill` (nonzero for the LLM/tiny view's highest-scoring files) tops
/// the selection up with the best remaining low-tier traits — components and
/// baselines alike, ranked by the same `crit × conf` — until that many traits
/// show in total. The guaranteed set (notable+, and components a composite drew
/// on) is never truncated by the budget. This is what keeps an undetected file
/// legible to an LLM: with nothing notable to show, its strongest low-tier
/// traits still convey what the program *does* (matching a report viewer, whose
/// headline ranks traits verdict-agnostically).
pub(super) fn select_ids<'a>(
    file: &'a FileAnalysis,
    opts: &TinyOpts,
    low_tier_fill: usize,
) -> Vec<&'a str> {
    // Focused mode: when the file carries any native finding at or above
    // `focus_crit`, the candidate set narrows to those findings plus the
    // traits they reference (`trait_refs` — a composite's legs). Legs bypass
    // `min_crit` so a referenced component can appear beside its composite.
    let focus_legs: Option<HashSet<&str>> = opts.focus_crit.and_then(|fc| {
        let focused: Vec<&Finding> = file
            .findings
            .iter()
            .filter(|f| f.src.is_none() && f.crit >= fc)
            .collect();
        if focused.is_empty() {
            return None;
        }
        Some(
            focused
                .iter()
                .flat_map(|f| f.trait_refs.iter().map(crate::types::Istr::as_str))
                .collect(),
        )
    });

    // The LLM/tiny view shows evidence, not conclusions. A composite *is*
    // cleave's own verdict, and putting it in front of the grader invites the
    // model to agree with it instead of reasoning from what was observed; the
    // legs carry the same information without the conclusion attached. So the
    // tiny view drops composites and guarantees their legs in their place.
    //
    // Consumers must therefore read severity from the structured report, never
    // by scanning this render for `H`/`S` letters — most elevated findings are
    // composites and no longer appear here at all. Their evidence does: the
    // legs below, and `evidence_legs` across members.
    let minimal = matches!(opts.header, HeaderStyle::Minimal);
    // Legs resolve through nested composites to the atoms beneath: an
    // intermediate composite's name is as much a conclusion as the top one's.
    let composite_legs: BTreeSet<&str> = if minimal {
        composite_atoms(file, file.findings.iter())
    } else {
        BTreeSet::new()
    };

    // Per id, keep the best score and the highest criticality seen — the
    // latter decides whether the id bypasses the cap.
    let mut scored: HashMap<&str, (f32, Criticality)> = HashMap::new();
    for f in &file.findings {
        // An inherited copy (`src` set, native to a member below) is rendered by
        // its origin member, not here. A *cross-file composite* also carries
        // source provenance — `composite_sources` records the members it drew
        // from — but is native to no member at all: it exists only on this
        // container. Treating it as an inherited copy dropped it from every
        // rendered view while leaving it in the JSON, so a container-scope
        // finding was invisible in `cleave analyze` and in the LLM render alike
        // (measured on localstack-core's `aws-instance-launch-with-user-data`).
        // `compact.rs` draws the same distinction for the JSON path.
        let inherited_copy = f.src.is_some() && !file.composite_sources.contains_key(f.id.as_str());
        // Baseline (universal low-signal noise) is dropped from the primary
        // selection: it crowds the record list without helping the reader reach
        // a verdict. Referenced component traits stay — they're the
        // source-context counterweight. (Both tiers re-enter below as
        // `low_tier_fill` candidates.)
        if inherited_copy || !tiny_should_show(f, file) {
            continue;
        }
        if minimal && !f.trait_refs.is_empty() {
            continue;
        }
        if let (Some(legs), Some(fc)) = (&focus_legs, opts.focus_crit) {
            if f.crit < fc && !legs.contains(f.id.as_str()) {
                continue;
            }
        } else if f.crit < opts.min_crit || f.crit == Criticality::Baseline {
            continue;
        }
        let score = f.conf * f32::from(f.crit.rank());
        scored
            .entry(f.id.as_str())
            .and_modify(|(s, c)| {
                *s = s.max(score);
                *c = (*c).max(f.crit);
            })
            .or_insert((score, f.crit));
    }
    let mut ranked: Vec<(&str, f32, Criticality)> =
        scored.into_iter().map(|(id, (s, c))| (id, s, c)).collect();
    ranked.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(b.0)));

    // Findings at or above `always_crit` are shown regardless of `top_n`;
    // `top_n` then caps only the lower-criticality remainder. A suspicious or
    // hostile trait is never dropped to truncation.
    let mut out: Vec<&str> = Vec::new();
    let mut filler: Vec<&str> = Vec::new();
    for (id, _, crit) in ranked {
        if opts.always_crit.is_some_and(|threshold| crit >= threshold) {
            out.push(id);
        } else {
            filler.push(id);
        }
    }
    let remaining = opts.top_n.saturating_sub(out.len());
    out.extend(filler.into_iter().take(remaining));

    // Guarantee the legs of every omitted composite. They are usually
    // `component`, so the cap or the ranking could otherwise drop the only
    // evidence left for a finding whose conclusion was just withheld. Additive
    // and native-only: a leg carried by another member is rendered there.
    if minimal && !composite_legs.is_empty() {
        let mut have: HashSet<&str> = out.iter().copied().collect();
        for f in &file.findings {
            let id = f.id.as_str();
            if f.src.is_none() && composite_legs.contains(id) && have.insert(id) {
                out.push(id);
            }
        }
    }

    // Top up to `low_tier_fill` with the best low-tier traits the primary pass
    // excluded (unreferenced components, baselines) — additive only: it never
    // evicts anything selected above.
    if out.len() < low_tier_fill {
        let selected: HashSet<&str> = out.iter().copied().collect();
        let mut low: HashMap<&str, f32> = HashMap::new();
        for f in &file.findings {
            if f.src.is_some()
                || !matches!(f.crit, Criticality::Component | Criticality::Baseline)
                || selected.contains(f.id.as_str())
            {
                continue;
            }
            let score = f.conf * f32::from(f.crit.rank());
            low.entry(f.id.as_str())
                .and_modify(|s| *s = s.max(score))
                .or_insert(score);
        }
        let mut low_ranked: Vec<(&str, f32)> = low.into_iter().collect();
        low_ranked.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        out.extend(
            low_ranked
                .into_iter()
                .take(low_tier_fill - out.len())
                .map(|(id, _)| id),
        );
    }
    out
}

/// Display path for a header. An archive member is shown archive-relative — the
/// container's on-disk directory is noise and the internal `!!` delimiter reads
/// better as `/`: `/tmp/x.zip!!lib/a.so` → `x.zip/lib/a.so`. A standalone/root
/// path is reduced to its basename only when `basename_root` is set (the LLM
/// view, where the directory is noise and can leak a corpus label).
pub(super) fn tiny_path(path: &str, basename_root: bool) -> String {
    use crate::types::file_analysis::ARCHIVE_DELIMITER;
    fn basename(p: &str) -> &str {
        p.rsplit(['/', '\\']).next().unwrap_or(p)
    }
    let path = match path.split_once(ARCHIVE_DELIMITER) {
        Some((root, members)) => {
            format!(
                "{}/{}",
                basename(root),
                members.replace(ARCHIVE_DELIMITER, "/")
            )
        }
        None if basename_root => basename(path).to_string(),
        None => path.to_string(),
    };
    super::sample_text(&path).into_owned()
}
