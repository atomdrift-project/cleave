//! Which findings and context windows a view shows.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

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
/// The plan is the single source of truth for the windowed-vs-location-less
/// split: a selected finding in no drawn window renders as a bare note
/// instead.
pub(super) fn window_plan<'a>(
    file: &FileAnalysis,
    notes: &'a [Vec<Note>],
    selected: &[&'a str],
) -> Vec<Planned<'a>> {
    let sel: HashSet<&str> = selected.iter().copied().collect();
    let mut plan: Vec<Planned<'a>> = notes
        .iter()
        .map(|window_notes| {
            let ids: HashSet<&'a str> = window_notes
                .iter()
                .map(|n| n.id.as_str())
                .filter(|id| sel.contains(id))
                .collect();
            Planned {
                notes: window_notes,
                ids: (!ids.is_empty()).then_some(ids),
            }
        })
        .collect();
    // A text file's leading comment (`context::capture` takes it alongside
    // the finding windows) carries no note, but it is what the file says it
    // is for, so it is drawn.
    if let (Some(first), Some(line)) = (plan.first_mut(), file.context.first())
        && first.ids.is_none()
        && line.loc == 0
        && first.notes.is_empty()
        && line.line.is_some()
    {
        first.ids = Some(HashSet::new());
    }
    plan
}

/// One context window in the render plan: the notes derived for it and, when
/// the plan draws it, the finding ids it annotates.
pub(super) struct Planned<'a> {
    pub(super) notes: &'a [Note],
    pub(super) ids: Option<HashSet<&'a str>>,
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

/// cleave's own terminal view, as opposed to an embedding host's card layout.
/// The one view whose height is spent on a human reading a verdict at a
/// terminal, so the one that trims hardest.
pub(super) fn is_terminal_view(opts: &TinyOpts) -> bool {
    !opts.card
}

/// Whether this file has suppressions [`render_suppressions`] would draw.
///
/// The single gate every skip path consults, so a file can never be dropped
/// from the view for having nothing but withheld traits to report.
///
/// Only the card layout draws them. cleave's terminal view draws none: a human
/// reading a verdict wants the evidence, not the engine's internal
/// second-guessing, and the trailing block routinely ran longer than the
/// findings above it.
pub(super) fn has_shown_suppressions(file: &FileAnalysis, opts: &TinyOpts) -> bool {
    opts.card && file.suppressions.iter().any(|s| s.crit >= MIN_CRIT)
}

/// The top-`n` finding ids to show, ranked by `crit × conf` (highest first) and
/// floored at [`MIN_CRIT`] (after the usual component/filtered gating).
pub(super) fn select_ids<'a>(file: &'a FileAnalysis, opts: &TinyOpts) -> Vec<&'a str> {
    // Focused mode: when the file carries any native finding at or above
    // `focus_crit`, the candidate set narrows to those findings plus the
    // traits they reference (`trait_refs` — a composite's legs). Legs bypass
    // [`MIN_CRIT`] so a referenced component can appear beside its composite.
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
        // finding was invisible in `cleave analyze` (measured on
        // localstack-core's `aws-instance-launch-with-user-data`).
        // `compact.rs` draws the same distinction for the JSON path.
        let inherited_copy = f.src.is_some() && !file.composite_sources.contains_key(f.id.as_str());
        // Baseline (universal low-signal noise) is dropped from the
        // selection: it crowds the record list without helping the reader reach
        // a verdict. Referenced component traits stay — they're the
        // source-context counterweight.
        if inherited_copy || !tiny_should_show(f, file) {
            continue;
        }
        if let (Some(legs), Some(fc)) = (&focus_legs, opts.focus_crit) {
            if f.crit < fc && !legs.contains(f.id.as_str()) {
                continue;
            }
        } else if f.crit < MIN_CRIT {
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
    out
}

/// Display path for a header. An archive member is shown archive-relative — the
/// container's on-disk directory is noise and the internal `!!` delimiter reads
/// better as `/`: `/tmp/x.zip!!lib/a.so` → `x.zip/lib/a.so`. A standalone/root
/// path is reduced to its basename only when `basename_root` is set (the card
/// layout, whose caller has already named the artifact).
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
