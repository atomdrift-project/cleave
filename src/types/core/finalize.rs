//! Finalizing a report: stripping, child inheritance, composite sources and reference links.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl AnalysisReport {
    /// Strip Component- and Baseline-criticality findings that no fired composite
    /// references, then recompute summaries. Component traits are composite
    /// building blocks and baseline traits are universal noise; both are only
    /// worth keeping in the output once a composite that uses them has fired (its
    /// id appears in some finding's `trait_refs`). Dropping the rest is the bulk
    /// of what shrinks large archive reports.
    ///
    /// MUST run only after every up-the-chain composite recomputation (archive and
    /// encoding-layer inheritance, container re-evaluation): those parent
    /// composites consume the component/baseline findings as inputs, so stripping
    /// earlier would stop them firing. See `Self::attach_composite_sources`,
    /// which deliberately records each composite→member tie *before* this strip
    /// removes the low-tier traits.
    ///
    /// As an exception, a file that would otherwise be left with no
    /// notable-or-higher finding keeps its `RESCUE_LOW_TIER_KEEP` best
    /// low-tier traits. An empty findings list tells a downstream LLM consumer
    /// nothing about the file; a few weak traits at least give it a clue.
    ///
    /// Returns `(components_removed, baselines_removed)`.
    pub fn strip_unmatched_traits(&mut self) -> (usize, usize) {
        // `crit: exception` composites are assembly-only: they drive `unless:` /
        // `downgrade:` suppression while composites are evaluated, and by the time
        // we finalize a report that work is already baked into the surviving
        // findings' criticalities. They must never surface in output, so drop them
        // unconditionally here — before the component/baseline strip and its
        // low-tier rescue, so an exception can never be referenced-rescued or
        // low-tier-rescued back into the rendered findings.
        self.findings.retain(|f| f.crit != Criticality::Exception);
        for file in &mut self.files {
            file.findings.retain(|f| f.crit != Criticality::Exception);
        }

        // A trait is kept regardless of its own criticality when a fired
        // composite that had it in scope cites it — never one that fired in a
        // sibling member (see `Citations`). The scopes are the rules': the
        // report's own engine, or the global one `finalize` also falls back to.
        let fallback;
        let rules = match &self.engine {
            Some(engine) => engine.rules(),
            None => {
                fallback = crate::shared_resources::fallback_engine();
                fallback.rules()
            }
        };
        let citations = crate::capabilities::Citations::of(rules, self);

        // A component/baseline finding is strippable unless a fired composite
        // references it — or unless it *arrived* at that tier via its own
        // `downgrade:`. A rule that downgrades asked for less emphasis, not for
        // deletion; stripping those made a notable behavior vanish from the
        // report and from `--format=json` whenever nothing happened to
        // reference it, while an identical referenced trait survived at the
        // lower tier. Honour the tier the downgrade asked for.
        let low_tier = |f: &Finding| {
            matches!(f.crit, Criticality::Component | Criticality::Baseline)
                && !f.downgraded
                // Import identity remains useful to ML/diffs even at baseline.
                && !crate::capabilities::is_dynamic_import_ref(&f.id)
        };
        let top = citations.for_path(None);
        let strippable =
            |f: &Finding| low_tier(f) && !top.iter().any(|c| c.contains(f.id.as_str()));

        use rayon::prelude::*;
        let tally = |f: &Finding, c: &mut usize, b: &mut usize| match f.crit {
            Criticality::Component => *c += 1,
            Criticality::Baseline => *b += 1,
            _ => {}
        };

        // Top-level findings are cleared at finalize and never serve as the
        // per-file LLM clue, so they follow the base rule with no rescue.
        let mut components = 0usize;
        let mut baselines = 0usize;
        self.findings.retain(|f| {
            let keep = !strippable(f);
            if !keep {
                tally(f, &mut components, &mut baselines);
            }
            keep
        });

        // Per file: rescue the best low-tier traits when nothing else survives.
        // A file's strip reads only that file plus the citations in its scope,
        // so archives fan out and each worker tallies locally — the counts are
        // summed after, rather than funnelled through one shared closure. Same
        // split (and threshold) as `filter_findings`.
        let strip_file = |file: &mut FileAnalysis| -> (usize, usize) {
            let cited = citations.for_path(Some(file.path.as_str()));
            let strippable =
                |f: &Finding| low_tier(f) && !cited.iter().any(|c| c.contains(f.id.as_str()));
            let rescued = Self::rescue_low_tier(&file.findings, &strippable);
            let (mut c, mut b) = (0usize, 0usize);
            file.findings.retain(|f| {
                let keep = !strippable(f) || rescued.contains(f.id.as_str());
                if !keep {
                    tally(f, &mut c, &mut b);
                }
                keep
            });
            (c, b)
        };
        let parallel = self.files.len() >= 32 && crate::rayon_nest::inner_work_parallel();
        let (file_components, file_baselines) = if parallel {
            self.files
                .par_iter_mut()
                .map(strip_file)
                .reduce(|| (0, 0), |a, x| (a.0 + x.0, a.1 + x.1))
        } else {
            self.files
                .iter_mut()
                .map(strip_file)
                .fold((0, 0), |a, x| (a.0 + x.0, a.1 + x.1))
        };
        components += file_components;
        baselines += file_baselines;

        if components + baselines > 0 {
            if parallel {
                self.files.par_iter_mut().for_each(|file| {
                    Self::refresh_formula(file);
                    file.compute_summary();
                });
            } else {
                for file in &mut self.files {
                    Self::refresh_formula(file);
                    file.compute_summary();
                }
            }
            self.summary = Some(ReportSummary::from_files(&self.files));
            tracing::debug!(
                components_removed = components,
                baselines_removed = baselines,
                "stripped unmatched component and baseline traits before render",
            );
        }

        (components, baselines)
    }

    /// Pick the ids of the low-tier traits to keep for a file that carries no
    /// notable-or-higher signal, so its findings list is never empty. Returns an
    /// empty set when the file already has real signal (no rescue needed) or has
    /// no strippable traits to offer.
    ///
    /// Candidates rank best-first by score (criticality × confidence), with the
    /// trait id as a deterministic final tiebreak.
    pub(super) fn rescue_low_tier<F>(
        findings: &[Finding],
        strippable: &F,
    ) -> std::collections::HashSet<crate::types::Istr>
    where
        F: Fn(&Finding) -> bool,
    {
        if findings.iter().any(|f| f.crit >= Criticality::Notable) {
            return std::collections::HashSet::new();
        }

        let score = |f: &Finding| f32::from(f.crit.rank()) * f.conf;
        let mut candidates: Vec<&Finding> = findings.iter().filter(|f| strippable(f)).collect();
        candidates.sort_by(|a, b| score(b).total_cmp(&score(a)).then(a.id.cmp(&b.id)));
        candidates
            .into_iter()
            .take(RESCUE_LOW_TIER_KEEP)
            .map(|f| f.id.clone())
            .collect()
    }

    /// Add child-file findings to their containing wrapper while preserving the
    /// child entries. This keeps archive members, embedded binaries, and UPX
    /// layers attributable as separate files, but ensures filtering and root
    /// summaries still reflect behavior hidden behind the wrapper.
    pub fn inherit_child_findings_into_wrappers(&mut self) -> Vec<usize> {
        use rustc_hash::{FxHashMap, FxHashSet};

        if self.files.len() <= 1 {
            return Vec::new();
        }

        let path_to_index: FxHashMap<String, usize> = self
            .files
            .iter()
            .enumerate()
            .map(|(idx, file)| (file.path.clone(), idx))
            .collect();

        // Sort key: deepest wrappers first, so findings propagate level by
        // level — a child merges into its immediate wrapper before that
        // wrapper is itself merged (as a child) into the next level up.
        let level_of = |file: &FileAnalysis| (file.depth, wrapper_delimiter_count(&file.path));
        let mut child_indices: Vec<usize> = self
            .files
            .iter()
            .enumerate()
            .filter_map(|(idx, file)| immediate_wrapper_path(&file.path).map(|_| idx))
            .collect();
        child_indices.sort_by_key(|&idx| std::cmp::Reverse(level_of(&self.files[idx])));

        // Merge one level at a time, batching every child of the same parent
        // into a single extend + dedupe. The per-child variant re-deduplicated
        // the parent's entire findings list (evidence dedup included) once per
        // child — on a 63k-member archive whose members share one wrapper,
        // that is 63k full-list dedups of the same accumulating list, and it
        // made this pass dominate archive scans (2,865 s for a
        // corpus that scans in 337 s as loose files). Batching is safe because
        // a parent's own upward merge always happens at a strictly later
        // level than everything it receives (its (depth, delimiter) key is
        // strictly below its children's), so flushing at level boundaries
        // preserves the propagation order.
        let mut changed = FxHashSet::default();
        let mut pending: FxHashMap<usize, Vec<Finding>> = FxHashMap::default();
        let mut i = 0;
        while i < child_indices.len() {
            let level = level_of(&self.files[child_indices[i]]);
            while i < child_indices.len() {
                let child_idx = child_indices[i];
                if level_of(&self.files[child_idx]) != level {
                    break;
                }
                i += 1;
                let Some(parent_path) = immediate_wrapper_path(&self.files[child_idx].path) else {
                    continue;
                };
                let Some(&parent_idx) = path_to_index.get(parent_path) else {
                    continue;
                };
                if parent_idx == child_idx || self.files[child_idx].findings.is_empty() {
                    continue;
                }

                // Stamp the inherited copies with the child's file id so consumers
                // can tell a wrapper finding bubbled up from a member (and from which
                // one), and de-duplicate the view by attributing it to its origin.
                // Preserve any deeper `src` already set (a finding inherited through
                // several wrapper layers keeps pointing at where it was located).
                let child_id = self.files[child_idx].id;
                pending.entry(parent_idx).or_default().extend(
                    self.files[child_idx].findings.iter().cloned().map(|mut f| {
                        f.src.get_or_insert(child_id);
                        // Precomputed emission spans are member-local byte
                        // offsets; on the wrapper they are as meaningless as
                        // `archive:`-located evidence (which the span
                        // derivation filters out). Carrying them up unioned
                        // child offsets into the wrapper's spans and evicted
                        // its own under the span cap.
                        f.precomputed_spans = None;
                        // Same reasoning for raw evidence: stamp inherited
                        // locations `archive:`-prefixed (as the fold rollup
                        // does), so the wrapper's span derivation skips them
                        // instead of emitting child byte offsets as wrapper
                        // spans.
                        for ev in &mut f.evidence {
                            match &ev.location {
                                None => ev.location = Some("archive:member".to_string()),
                                Some(loc) if !loc.starts_with("archive:") => {
                                    ev.location = Some(format!("archive:member:{loc}"));
                                }
                                _ => {}
                            }
                        }
                        f
                    }),
                );
                changed.insert(parent_idx);
            }
            // Flush the level: one extend + one dedupe per parent, however many
            // children contributed.
            for (parent_idx, findings) in pending.drain() {
                let parent = &mut self.files[parent_idx];
                parent.findings.extend(findings);
                dedupe_finding_list(&mut parent.findings);
            }
        }

        let mut changed: Vec<usize> = changed.into_iter().collect();
        changed.sort_unstable();
        // Formula and summary are derived views — nothing in the upward
        // propagation reads them — so refresh each changed parent once at the
        // end rather than once per contributing child.
        for &idx in &changed {
            let parent = &mut self.files[idx];
            Self::refresh_formula(parent);
            parent.compute_summary();
        }
        changed
    }

    /// Resolve, for every cross-file composite finding, the archive members it
    /// drew components from — recording each as a [`CompositeSource`] (member
    /// file id plus the component's location when a context note pins it). The
    /// composite's `trait_refs` name its component traits; a member contributed
    /// if it carries a finding with one of those ids. Stored on the container
    /// file's `composite_sources`, keyed by composite finding id.
    ///
    /// Runs during `finalize`, before component findings are filtered from the
    /// output: the low-tier traits that link a composite to a member (e.g. an
    /// install-hook presence trait on a package.json) are gone by render/compact
    /// time, so this is the one point where the tie is recoverable.
    pub(super) fn attach_composite_sources(files: &mut [FileAnalysis]) {
        use super::super::file_analysis::{ARCHIVE_DELIMITER, CompositeSource};
        use rustc_hash::FxHashMap;
        use std::collections::BTreeMap;

        // A composite spanning more members than this is treated as a ubiquitous
        // pattern, not targeted provenance — its sources are dropped (see below).
        const MAX_COMPOSITE_SOURCES: usize = 8;

        // Component finding id → file indices carrying it (skip synthetic
        // embedded-binary extractions; their carrier member stands in for them).
        let mut id_to_files: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
        for (i, f) in files.iter().enumerate() {
            if f.path.contains("embedded:") {
                continue;
            }
            for finding in &f.findings {
                id_to_files.entry(finding.id.as_str()).or_default().push(i);
            }
        }

        // Invert containment ONCE: file index → member set, from every path
        // ancestor (each ARCHIVE_DELIMITER boundary) plus the parent_id link.
        // The membership test below is then a set probe instead of a
        // per-candidate path prefix compare, and files with no members skip
        // resolution outright. The old shape tested every carrier of a
        // component id against every composite-bearing file's path: leaf
        // members (which have no children, so the ubiquitous early-break never
        // fired) each scanned the full carrier list — on a 63k-member archive
        // with ~8k manifest composites, ~10^8 string compares that made this
        // pass the dominant single-thread finalize cost (the bulk
        // of a ~330 s tail on a 1,870 s scan; 8/14 tail stack samples).
        use rustc_hash::FxHashSet;
        let path_to_index: FxHashMap<&str, usize> = files
            .iter()
            .enumerate()
            .map(|(i, f)| (f.path.as_str(), i))
            .collect();
        let id_to_index: FxHashMap<u32, usize> =
            files.iter().enumerate().map(|(i, f)| (f.id, i)).collect();
        let mut members_of: FxHashMap<usize, FxHashSet<usize>> = FxHashMap::default();
        for (mi, member) in files.iter().enumerate() {
            let p = member.path.as_str();
            let mut pos = 0;
            while let Some(off) = p[pos..].find(ARCHIVE_DELIMITER) {
                let boundary = pos + off;
                if let Some(&ci) = path_to_index.get(&p[..boundary])
                    && ci != mi
                {
                    members_of.entry(ci).or_default().insert(mi);
                }
                pos = boundary + ARCHIVE_DELIMITER.len();
            }
            // A grafted direct child (linked by `parent_id`, not path) — e.g.
            // the `*.registry.json` provenance node the fetch pass hangs off
            // the artifact. A package-scoped composite's registry leg lives on
            // this link, so path ancestry alone would drop it.
            if let Some(pid) = member.parent_id
                && let Some(&ci) = id_to_index.get(&pid)
                && ci != mi
            {
                members_of.entry(ci).or_default().insert(mi);
            }
        }

        // Borrow `files` immutably to resolve, collect owned results, then write
        // back — the resolution reads every file while we build per-container maps.
        let mut resolved: Vec<(usize, BTreeMap<String, Vec<CompositeSource>>)> = Vec::new();
        for (ci, container) in files.iter().enumerate() {
            let Some(member_set) = members_of.get(&ci) else {
                continue; // no nested members or grafted children — nothing to resolve
            };
            let mut per_finding: BTreeMap<String, Vec<CompositeSource>> = BTreeMap::new();
            for finding in &container.findings {
                if finding.trait_refs.is_empty() {
                    continue;
                }
                // member file id → source (dedup per member, earliest source location wins).
                let mut by_member: BTreeMap<u32, CompositeSource> = BTreeMap::new();
                let mut ubiquitous = false;
                'refs: for trait_ref in &finding.trait_refs {
                    let Some(idxs) = id_to_files.get(trait_ref.as_str()) else {
                        continue;
                    };
                    for &mi in idxs {
                        if mi == ci || !member_set.contains(&mi) {
                            continue; // neither a nested member nor a direct child
                        }
                        let member = &files[mi];
                        let entry = by_member
                            .entry(member.id)
                            .or_insert_with(|| CompositeSource {
                                file: member.id,
                                ..Default::default()
                            });
                        if let Some((line, offset)) = evidence_location(member, trait_ref) {
                            let candidate = (line, offset);
                            let current = (entry.line, entry.offset);
                            if source_location_order(candidate) < source_location_order(current) {
                                entry.line = line;
                                entry.offset = offset;
                            }
                        }
                        // A composite that spans most of the archive isn't *based
                        // on* particular files — it's a ubiquitous pattern (a
                        // sourcemap reference, a language sigil). Recording every
                        // member as a "source" is noise and bloats the output, so
                        // drop the provenance once it stops being a targeted set.
                        if by_member.len() > MAX_COMPOSITE_SOURCES {
                            ubiquitous = true;
                            break 'refs;
                        }
                    }
                }
                if !ubiquitous && !by_member.is_empty() {
                    per_finding.insert(
                        finding.id.clone().to_string(),
                        by_member.into_values().collect(),
                    );
                }
            }
            if !per_finding.is_empty() {
                resolved.push((ci, per_finding));
            }
        }

        // Merge, don't replace: `link_flagged_references` also records
        // `composite_sources` (for flagged-reference findings, which carry no
        // `trait_refs` and are skipped above), and a re-run after the fetch graft
        // (`refresh_composite_sources`) must not clobber those. Keys are finding
        // ids, so extend refreshes each composite's own entry in place.
        for (ci, map) in resolved {
            files[ci].composite_sources.extend(map);
        }
    }

    /// Shrink all Vec fields to fit their contents, freeing excess capacity.
    /// Call this after analysis is complete to reduce memory footprint.
    pub fn shrink_to_fit(&mut self) {
        self.traits.shrink_to_fit();
        self.findings.shrink_to_fit();
        self.structure.shrink_to_fit();
        self.functions.shrink_to_fit();
        self.strings.shrink_to_fit();
        self.sections.shrink_to_fit();
        self.imports.shrink_to_fit();
        self.exports.shrink_to_fit();
        self.yara_matches.shrink_to_fit();
        self.syscalls.shrink_to_fit();
        self.archive_contents.shrink_to_fit();
        self.files.shrink_to_fit();
    }

    /// Drop the analysis fields that nothing downstream consumes, the moment a
    /// member's analysis (matching) is complete.
    ///
    /// `traits`, `structure`, `strings`, `yara_matches` and `syscalls` are
    /// produced by analyzers and matched against during trait evaluation, but the compact output
    /// (`compact::convert_file`) never serializes them and archive-scope
    /// evaluation consumes only the member's matched `findings`. On an archive
    /// with thousands of members, retaining them until the end accumulates
    /// multiple GB of live, unused memory. Clearing them here — right after the
    /// member's matching finishes, before the result is collected — keeps the
    /// compact output identical (render context and YARA findings have already
    /// been materialized into `context` / `findings`).
    pub(crate) fn clear_unserialized_member_fields(&mut self) {
        self.traits = Vec::new();
        self.structure = Vec::new();
        self.strings = Vec::new();
        self.yara_matches = Vec::new();
        self.syscalls = Vec::new();
        for file in &mut self.files {
            file.clear_unserialized_fields();
        }
    }

    /// Tie a file to the report's other files it references, and flag any
    /// reference to a file that was itself detected hostile/suspicious.
    ///
    /// Each [`filefacts`] reference is resolved against the report's files (see
    /// [`super::super::reference_graph`]): an external dependency (PURL) matches a
    /// file whose declared identity carries that package name, a relative path
    /// matches a sibling member by full path. When a resolved target's verdict
    /// is suspicious or hostile, the referrer gains a finding:
    /// - an **external** dependency raises one
    ///   `objectives/supply-chain/malicious-dependency` finding, one
    ///   criticality below the target (a hostile dep → a suspicious referrer);
    /// - an **internal** sibling raises one neutral `metadata/relationship`
    ///   fact — the bundle's hostility already lives on the bad member, so the
    ///   referrer is recorded, not re-scored.
    ///
    /// The general (benign-included) file→file edge is filled separately on the
    /// compact `refs` (`compact::link_reference_targets`); this pass adds only
    /// the flagged-target findings, whose `composite_sources` name the targets.
    pub(super) fn link_flagged_references(files: &mut [FileAnalysis]) {
        use super::super::file_analysis::CompositeSource;
        use super::super::reference_graph as rg;
        use super::super::traits_findings::FindingKind;
        use std::collections::HashMap;

        // Index the report once: declared identity name → file id (external),
        // full path → file id (internal), and each file's own verdict (its
        // strongest native finding). Owned keys so the mutable pass is free of
        // the index's borrow.
        let mut by_name: HashMap<String, u32> = HashMap::new();
        let mut by_path: HashMap<String, u32> = HashMap::new();
        let mut verdict: HashMap<u32, Criticality> = HashMap::new();
        for f in files.iter() {
            by_path.entry(f.path.clone()).or_insert(f.id);
            if let Some(identity) = &f.identity {
                for name in rg::identity_names(identity) {
                    by_name.entry(name.to_string()).or_insert(f.id);
                }
            }
            let v = f
                .findings
                .iter()
                .filter(|fd| fd.src.is_none())
                .map(|fd| fd.crit)
                .max()
                .unwrap_or(Criticality::Baseline);
            verdict.insert(f.id, v);
        }

        for f in files.iter_mut() {
            let own_id = f.id;
            let own_path = f.path.clone();
            // Snapshot the locators, dropping the immutable `filefacts` borrow
            // before mutating `findings`.
            let refs: Vec<(filefacts::RefLocator, Option<u64>)> = match &f.filefacts {
                Some(ff) => ff
                    .references
                    .iter()
                    .map(|r| (r.locator.clone(), r.offset))
                    .collect(),
                None => continue,
            };

            // Flagged targets, deduped, split by edge kind.
            let mut ext: Vec<(u32, Option<u64>, String, Criticality)> = Vec::new();
            let mut int: Vec<(u32, Option<u64>)> = Vec::new();
            for (locator, offset) in &refs {
                let (target, external, label) = match locator {
                    filefacts::RefLocator::Purl(p) => match rg::package_name_from_purl(p) {
                        Some(name) => (by_name.get(&name).copied(), true, name),
                        None => continue,
                    },
                    filefacts::RefLocator::Path(p) => {
                        let target = rg::resolve_local_target(&own_path, p, |path| {
                            by_path.get(path).copied()
                        });
                        (target, false, String::new())
                    }
                    // URLs, and locator kinds newer than this build.
                    _ => continue,
                };
                let Some(tid) = target else { continue };
                if tid == own_id {
                    continue;
                }
                let tv = verdict.get(&tid).copied().unwrap_or(Criticality::Baseline);
                if tv < Criticality::Suspicious {
                    continue;
                }
                if external {
                    if !ext.iter().any(|(id, ..)| *id == tid) {
                        ext.push((tid, *offset, label, tv));
                    }
                } else if !int.iter().any(|(id, _)| *id == tid) {
                    int.push((tid, *offset));
                }
            }

            // External: one supply-chain finding, crit one-below the worst target.
            if let Some(worst) = ext.iter().map(|(.., v)| *v).max()
                && let Some(crit) = rg::one_below(worst)
            {
                let names = ext
                    .iter()
                    .map(|(.., n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let sources = ext
                    .iter()
                    .map(|(tid, off, ..)| CompositeSource {
                        file: *tid,
                        line: None,
                        offset: *off,
                    })
                    .collect();
                Self::push_reference_finding(
                    f,
                    "objectives/supply-chain/malicious-dependency::references-malicious-component",
                    FindingKind::Indicator,
                    crit,
                    format!("References a flagged dependency: {names}"),
                    sources,
                );
            }
            // Internal: one neutral metadata fact naming the flagged sibling(s).
            if !int.is_empty() {
                let sources = int
                    .iter()
                    .map(|(tid, off)| CompositeSource {
                        file: *tid,
                        line: None,
                        offset: *off,
                    })
                    .collect();
                Self::push_reference_finding(
                    f,
                    "metadata/relationship::references-flagged-component",
                    FindingKind::Structural,
                    Criticality::Baseline,
                    "References a flagged file in this bundle".to_string(),
                    sources,
                );
            }
        }
    }

    /// Add a synthesized reference finding to `file` (idempotent on the id), with
    /// the flagged targets recorded as its `composite_sources` trail.
    pub(super) fn push_reference_finding(
        file: &mut FileAnalysis,
        id: &str,
        kind: super::super::traits_findings::FindingKind,
        crit: Criticality,
        desc: String,
        sources: Vec<super::super::file_analysis::CompositeSource>,
    ) {
        if file.findings.iter().any(|fd| fd.id == id) {
            return; // already linked (e.g. a re-finalize)
        }
        file.findings.push(Finding {
            precomputed_spans: None,
            id: id.to_string().into(),
            kind,
            desc: desc.into(),
            conf: 0.9,
            crit,
            trait_refs: Vec::new(),
            src: None,
            mbc: None,
            attack: None,
            evidence: Vec::new(),
            match_count: 0,
            source_file: None,
            downgraded: false,
        });
        file.composite_sources.insert(id.to_string(), sources);
    }

    /// Finalize the report for output: populate files[], clear top-level duplicates,
    /// merge metadata into summary, filter internal symbols findings.
    ///
    /// After this call, `files[]` is the single source of truth and `version` is "3".
    pub fn finalize(&mut self) {
        let engine = self
            .engine
            .clone()
            .unwrap_or_else(crate::shared_resources::fallback_engine);
        // Create the root file entry
        let mut root_file = self.to_file_analysis(0, &engine);
        root_file.path = self.target.path.clone();
        root_file.depth = 0;
        root_file.parent_id = None;
        root_file.compute_summary();

        if self.files.is_empty() {
            // Simple case: just the root file
            self.files.push(root_file);
        } else {
            // Files were pre-populated by archive/payload analyzers
            // Renumber IDs and insert root file at position 0
            let root_path = self.target.path.clone();
            for (idx, file) in self.files.iter_mut().enumerate() {
                file.id = (idx + 1) as u32; // Shift IDs to make room for root
                if file.depth == 1 && file.parent_id.is_none() {
                    file.parent_id = Some(0); // Point to root
                }
                // Ensure paths have proper archive prefix (!! for archives, ## for decoded)
                let needs_root_prefix = !file.path.strip_prefix(&root_path).is_some_and(|suffix| {
                    suffix.starts_with(super::super::file_analysis::ARCHIVE_DELIMITER)
                        || suffix.starts_with(super::super::file_analysis::ENCODING_DELIMITER)
                });
                if needs_root_prefix {
                    file.path =
                        super::super::file_analysis::encode_archive_path(&root_path, &file.path);
                }
            }
            self.files.insert(0, root_file);
        }

        // Nested analyzers often return local IDs (or no parent ID). After
        // flattening and renumbering, fill missing containment links from the
        // same logical-path relationship used by wrapper finding inheritance.
        // Explicit graft/reference links remain authoritative.
        // Resolve against a borrowed index, then apply: the index keys point
        // into the very paths the update walks, so the two passes cannot
        // overlap. An owning index would clone every member path to say so.
        let path_ids: rustc_hash::FxHashMap<&str, u32> = self
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.id))
            .collect();
        let parent_ids: Vec<Option<u32>> = self
            .files
            .iter()
            .map(|file| {
                file.parent_id.or_else(|| {
                    immediate_wrapper_path(&file.path)
                        .and_then(|parent| path_ids.get(parent).copied())
                        .filter(|id| *id != file.id)
                })
            })
            .collect();
        for (file, parent_id) in self.files.iter_mut().zip(parent_ids) {
            file.parent_id = parent_id;
        }

        self.inherit_child_findings_into_wrappers();

        // Attribute findings that arrived via the archive *aggregate* (their
        // evidence carries an `archive:<member>` location but no `src` yet — the
        // aggregate copy predates `inherit`'s id-stamping and wins de-dup). Map
        // the member name back to its file id so every inherited finding can be
        // traced to where it was located. Runs before evidence is stripped, since
        // the location lives on the (transient) evidence.
        {
            use rustc_hash::FxHashMap;
            let member_to_id: FxHashMap<String, u32> = self
                .files
                .iter()
                .filter(|f| {
                    f.path
                        .contains(super::super::file_analysis::ARCHIVE_DELIMITER)
                })
                .map(|f| (leaf_member(&f.path).to_string(), f.id))
                .collect();
            for file in &mut self.files {
                let own_id = file.id;
                for finding in &mut file.findings {
                    if finding.src.is_some() {
                        continue;
                    }
                    let src = finding.evidence.iter().find_map(|e| {
                        let member = located_member(e.location.as_deref()?)?;
                        member_to_id.get(member).copied()
                    });
                    // Only mark when it points at a *different* file — a member's
                    // own finding listed on the member itself stays native.
                    if let Some(id) = src
                        && id != own_id
                    {
                        finding.src = Some(id);
                    }
                }
            }
        }

        // Tie each cross-file composite to the members it fired on, while the
        // per-member component findings/notes are still present (the compact
        // output and the terminal component-filter drop the low-tier ones that
        // link a composite to a member, e.g. an install-hook trait on a
        // package.json). Must run before those drops.
        Self::attach_composite_sources(&mut self.files);

        // Flag references to a file that was itself detected hostile/suspicious,
        // before the score is recomputed so a referrer's verdict reflects it.
        Self::link_flagged_references(&mut self.files);

        // Context windows on sub-notable, un-cited members serve no reader:
        // the ML pipeline never reads `ctx`, and a report viewer renders member context only
        // for records with signal — a notable+ finding, or membership in a
        // fired composite's `from` legs (`composite_sources`, resolved just
        // above). On a member-heavy archive those windows were the largest
        // single JSON term (dt: 71 MB of 227 MB under `--show all`) read by
        // nothing. Sweep them here — AFTER attach/link so the cited set is
        // the exact fired-leg set, not a static reachability approximation
        // (measured: rule-reference reachability kept 43k of 54k members'
        // ctx; the fired set is ~16k).
        {
            {
                use rustc_hash::FxHashSet;
                let cited: FxHashSet<u32> = self
                    .files
                    .iter()
                    .flat_map(|f| f.composite_sources.values().flatten().map(|s| s.file))
                    .collect();
                for file in &mut self.files {
                    if file.depth == 0
                        || file.context.is_empty()
                        || cited.contains(&file.id)
                        || file.findings.iter().any(|f| f.crit >= Criticality::Notable)
                    {
                        continue;
                    }
                    file.context = Vec::new();
                }
            }
        }

        for file in &mut self.files {
            file.strip_source_fields();
            Self::refresh_formula(file);
            file.compute_summary();
            sort_for_output(file);
        }

        // Compute report summary and merge metadata into it
        let mut summary = ReportSummary::from_files(&self.files);
        summary.duration_ms = self.metadata.analysis_duration_ms;
        summary.tools = std::mem::take(&mut self.metadata.tools_used);
        summary.errors = std::mem::take(&mut self.metadata.errors);
        self.summary = Some(summary);

        // Clear top-level arrays — data now lives exclusively in files[]
        // Existing skip_serializing_if = "Vec::is_empty" prevents these from appearing in output
        let _ = std::mem::take(&mut self.traits);
        let _ = std::mem::take(&mut self.findings);
        let _ = std::mem::take(&mut self.suppressions);
        let _ = std::mem::take(&mut self.analysis_gaps);
        let _ = std::mem::take(&mut self.structure);
        let _ = std::mem::take(&mut self.functions);
        let _ = std::mem::take(&mut self.strings);
        let _ = std::mem::take(&mut self.sections);
        let _ = std::mem::take(&mut self.imports);
        let _ = std::mem::take(&mut self.exports);
        let _ = std::mem::take(&mut self.yara_matches);
        let _ = std::mem::take(&mut self.syscalls);
        let _ = std::mem::take(&mut self.archive_contents);

        // Clear fields that are redundant with files[0] / summary
        self.target = TargetInfo::default();
        self.analysis_timestamp = None;
        self.metadata = AnalysisMetadata::default();
        self.scanned_path = None;

        // Set version to v3
        self.version = "3".to_string();
    }
}
