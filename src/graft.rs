//! Grafting findings onto finished reports: reference outcomes and package composites.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Evaluate package-scoped composites over the union of a fetched artifact's
/// findings and its registry metadata's findings, grafting any newly-matched
/// composite onto the artifact node (the node whose `sha256` is `artifact_sha`).
/// Returns the number of composite findings grafted.
///
/// This is how `--fetch` / `pkg:` lets a `scope: package` (or `scope: outer`)
/// composite correlate a registry fact — deprecated, low downloads, a fresh
/// publish date — with a behavior in the artifact bytes, even though the two
/// were analyzed as separate reports and never share an archive. The caller
/// owns pairing (which registry record belongs to which artifact); this owns
/// evaluation and the report mutation. A no-op — returning `Ok(0)` — when
/// either side is empty or no package/outer composites match.
///
/// # Errors
/// Returns an error if the capability mapper cannot be initialized.
/// Evaluate traits against a file's post-fetch `references.*` facts and graft
/// what fires onto that file.
///
/// The follow phase runs *after* trait evaluation — it needs the references
/// the analysis found — so anything it learns arrives too late for the pass
/// that would have used it. For a reference that resolved this does not matter:
/// the payload is grafted into the tree as a child of the file that declared
/// it, and its own findings come with it. For one that did **not** resolve there
/// is no payload and no node, so the outcome existed only in the fetch log,
/// where no rule could reach it.
///
/// That outcome is worth a rule. A manifest naming a dependency the registry no
/// longer serves is pointing at something withdrawn, and packages are withdrawn
/// for reasons — the VS Code marketplace pulls extensions for malware, npm
/// unpublishes for the same. The declaring package usually remains installed and
/// still pointing at it.
///
/// Deliberately *not* a new composite scope. The facts land on the file that
/// made the claim (attributed by the fetch edge's declaring endpoint), so an
/// ordinary file-scoped trait reads them with the matchers that already exist;
/// only the timing needed fixing, not the scoping model. This re-runs atomic
/// evaluation for the one file whose facts changed, which is why it takes a sha
/// rather than walking the report.
pub fn graft_reference_outcome_traits(
    report: &mut AnalysisReport,
    file_sha: &str,
    options: &AnalysisOptions,
) -> Result<usize> {
    graft_located_reference_outcome_traits(report, file_sha, options, &Default::default())
}

/// Re-evaluate follow-phase facts with the source spans of their fetch edges.
/// The spans locate the declaring calls, not bytes from an unavailable payload.
pub fn graft_located_reference_outcome_traits(
    report: &mut AnalysisReport,
    file_sha: &str,
    options: &AnalysisOptions,
    spans: &std::collections::BTreeMap<String, Vec<filefacts::Span>>,
) -> Result<usize> {
    graft_reference_outcomes_batch(report, &[(file_sha, spans)], options)
}

/// Apply a follow phase's changed facts, then reevaluate each affected container
/// once. Rebuilding the archive-wide finding pool after every source makes a
/// package with N declaring members pay for the same N-member pool N times.
/// All member-local rules still run with their original source coordinates.
/// Inner containers precede outer containers so retained child findings remain
/// available to their parent; package correlation runs after all local facts.
pub fn graft_reference_outcomes_batch(
    report: &mut AnalysisReport,
    sources: &[(
        &str,
        &std::collections::BTreeMap<String, Vec<filefacts::Span>>,
    )],
    options: &AnalysisOptions,
) -> Result<usize> {
    if sources.is_empty() {
        return Ok(0);
    }
    let mapper = shared_resources::capability_mapper_with_options(options)?;
    // Source checks only read their member. Index each digest once, evaluate
    // those checks independently, then merge in source order before pooling.
    // Preserve the existing first-node behavior for duplicate member digests.
    let mut file_indices = rustc_hash::FxHashMap::default();
    for (index, file) in report.files.iter().enumerate() {
        file_indices.entry(file.sha256.as_str()).or_insert(index);
    }
    let evaluate = |(sha, spans): &(
        &str,
        &std::collections::BTreeMap<String, Vec<filefacts::Span>>,
    )| {
        let index = *file_indices.get(sha)?;
        reference_outcome_findings(&report.files[index], &mapper, spans)
            .map(|findings| (index, findings))
    };
    let additions: Vec<_> = if sources.len() >= 8 && crate::rayon_nest::inner_work_parallel() {
        use rayon::prelude::*;
        sources.par_iter().filter_map(evaluate).collect()
    } else {
        sources.iter().filter_map(evaluate).collect()
    };
    if additions.is_empty() {
        return Ok(0);
    }
    let mut grafted = 0;
    let mut parents = std::collections::BTreeSet::new();
    for (index, findings) in additions {
        grafted += report.graft_file_findings_deferred(index, findings);
        if let Some((parent, _)) = report.files[index].path.rsplit_once("!!") {
            parents.insert(parent.to_owned());
        }
    }
    // Reverse lexical order visits a nested path before its prefix.
    for parent in parents.iter().rev() {
        grafted += graft_reference_outcome_container(report, parent, &mapper);
    }
    let fallback_sha = sources[0].0;
    // The atomic facts landed on one member, but a rule that convicts on them
    // pairs them with facts from elsewhere in the artifact — the manifest that
    // declared the reference sits beside the archive root that carries the
    // package-shape metrics. Those composites were evaluated in the main pass,
    // before the follow existed, so re-run the pooling scopes over everything
    // the report now holds and graft what newly fires onto the root.
    // Archive-level atomic findings live on the report itself, not on any one
    // member, so pooling only the per-file lists misses exactly the facts an
    // archive-wide rule pairs the member's with.
    let pooled = report
        .findings
        .iter()
        .chain(report.files.iter().flat_map(|f| &f.findings));
    if !report.findings.is_empty() || report.files.iter().any(|f| !f.findings.is_empty()) {
        // Graft onto the outermost file node, not `target.sha256`: a merged
        // report assembled by a caller (scan's fetch phase grafts payload
        // subtrees into it) does not necessarily carry a target digest, and
        // grafting to an empty sha silently matches no file and drops the
        // finding. The shallowest node is the artifact the pooled rule is a
        // statement about; the declaring file is the fallback.
        let root_sha = report
            .files
            .iter()
            .min_by_key(|f| f.depth)
            .map_or_else(|| fallback_sha.to_string(), |f| f.sha256.clone());
        let fresh = mapper.evaluate_package_composites(pooled);
        if !fresh.is_empty() {
            grafted += report.graft_findings_deferred(&root_sha, fresh);
        }
    }
    if grafted > 0 {
        report.refresh_grafted_findings();
    }
    Ok(grafted)
}

pub(super) fn reference_outcome_findings(
    file: &crate::types::FileAnalysis,
    mapper: &capabilities::CapabilityMapper,
    spans: &std::collections::BTreeMap<String, Vec<filefacts::Span>>,
) -> Option<Vec<crate::types::Finding>> {
    // Nothing was attributed to this file, so nothing new can fire.
    if !file.filefacts_metrics.as_ref().is_some_and(|m| {
        m.contains_key("references.declared_count")
            || m.contains_key("references.undeclared_import_count")
    }) {
        return None;
    }

    // A synthetic one-file report carrying just this file's facts. The bytes are
    // long gone by the follow phase, and the `references.*` traits are metric and
    // value matchers that never wanted them.
    let mut scratch = AnalysisReport::new(crate::types::TargetInfo {
        path: file.path.clone(),
        file_type: file.file_type.clone(),
        size_bytes: file.size,
        sha256: file.sha256.clone(),
        architectures: None,
    });
    scratch.filefacts_metrics = file.filefacts_metrics.clone();
    scratch.filefacts_metric_spans = Some(spans.clone());
    scratch.findings = file.findings.clone();
    // Archive retention may release evidence text while preserving byte spans.
    // Rehydrate locations only, so post-fetch proximity checks retain the
    // original source coordinates without inventing unavailable source text.
    for finding in &mut scratch.findings {
        if finding.evidence.iter().all(|e| e.offsets.is_empty())
            && let Some(spans) = &finding.precomputed_spans
        {
            for &[offset, len] in spans {
                let mut evidence = crate::types::Evidence::new("retained-span", "cleave", "")
                    .with_offset(offset)
                    .with_location(format!("0x{offset:x}"));
                evidence.match_len = Some(len);
                finding.evidence.push(evidence);
            }
        }
    }
    scratch.files.push(file.clone());
    let no_bytes: &[u8] = &[];
    let mut found = mapper.evaluate_traits_with_ast(&scratch, no_bytes, None, None);
    if found.is_empty() {
        return None;
    }
    // File-local composites must see both the retained source observations and
    // the new follow facts. Archive pooling alone cannot evaluate these rules.
    scratch.findings.extend(found.iter().cloned());
    let local = mapper.evaluate_composite_rules(
        &scratch,
        no_bytes,
        None,
        None,
        &crate::composite_rules::SectionMap::default(),
        None,
        None,
        &[],
        &[],
    );
    found.extend(local);
    Some(found)
}

pub(super) fn graft_reference_outcome_container(
    report: &mut AnalysisReport,
    parent_path: &str,
    mapper: &capabilities::CapabilityMapper,
) -> usize {
    let Some(parent) = report.files.iter().find(|f| f.path == parent_path) else {
        return 0;
    };
    let mut container = AnalysisReport::new(crate::types::TargetInfo {
        path: parent.path.clone(),
        file_type: parent.file_type.clone(),
        size_bytes: parent.size,
        sha256: parent.sha256.clone(),
        architectures: None,
    });
    container.findings = parent.findings.clone();
    container.filefacts_metrics = parent.filefacts_metrics.clone();
    let mut nested = Vec::new();
    let mut members = Vec::new();
    let mut origins = rustc_hash::FxHashMap::default();
    let bit = crate::composite_rules::FileType::from_str(&parent.file_type).type_bit();
    for finding in &parent.findings {
        *origins.entry(finding.id.to_string()).or_default() |= bit;
    }
    for member in report.files.iter().filter(|f| {
        f.path
            .rsplit_once("!!")
            .is_some_and(|(p, _)| p == parent.path)
    }) {
        let bit = crate::composite_rules::FileType::from_str(&member.file_type).type_bit();
        for finding in &member.findings {
            *origins.entry(finding.id.to_string()).or_default() |= bit;
            nested.push(finding);
        }
        members.push(member);
    }
    // Grafting runs after analysis, when the member's bytes are gone; rules
    // that read container bytes see none here, as they would in a report.
    let fresh = mapper.evaluate_container_composites_with_members(
        &container,
        &[],
        nested,
        &parent.file_type,
        Some(&origins),
        Some(&members),
    );
    let parent_sha = parent.sha256.clone();
    report.graft_findings_deferred(&parent_sha, fresh)
}

/// Graft package-level composite findings onto a report by correlating an
/// artifact's findings with those of its registry metadata.
///
/// Composites that span both sides can only fire once the two sets are pooled,
/// so this evaluates them together and attaches anything new to `artifact_sha`.
/// Returns the number of findings grafted.
pub fn graft_package_composites(
    report: &mut AnalysisReport,
    artifact_sha: &str,
    artifact_findings: &[Finding],
    registry_findings: &[Finding],
    options: &AnalysisOptions,
) -> Result<usize> {
    // Nothing to correlate unless both sides contributed findings.
    if artifact_findings.is_empty() || registry_findings.is_empty() {
        return Ok(0);
    }
    let mapper = shared_resources::capability_mapper_with_options(options)?;
    let seed = artifact_findings.iter().chain(registry_findings);
    let new_findings = mapper.evaluate_package_composites(seed);
    if new_findings.is_empty() {
        return Ok(0);
    }
    Ok(report.graft_findings(artifact_sha, new_findings))
}
