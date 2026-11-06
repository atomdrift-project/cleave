//! Checks that hostile verdicts rest on content, not one fact.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// The fact a leg reads, as a comparable key.
///
/// Two legs sharing a key are asking about one thing, so a single value can
/// answer both and the question of the moment is whether one ever does. Only
/// the *name* facts are keyed: a path never reads the bytes, so two name legs
/// satisfied by one member are one observation. Content surfaces are a
/// different question -- two `text:` legs over one file can be independent
/// evidence even when their patterns overlap.
pub(super) fn leg_fact_key(cond: &Condition) -> Option<(&'static str, &str)> {
    match cond {
        Condition::Kv(q) => {
            // A cross-fact comparison, an existence assertion, a length bound
            // or a validator is not a value matcher, so there is no value set
            // to intersect.
            if q.eq.is_some()
                || q.ne.is_some()
                || q.exists.is_some()
                || q.length_min.is_some()
                || q.length_max.is_some()
                || q.is_check.is_some()
                || q.not.is_some()
            {
                return None;
            }
            Some(("value", q.path.as_str()))
        }
        Condition::Path(q) => {
            if q.is_check.is_some() {
                return None;
            }
            Some(("basename", ""))
        }
        _ => None,
    }
}

/// The set of values a leg accepts, written as one regex.
///
/// `exact` is pinned to the whole value, `substr` floats, and `regex` is taken
/// as authored; a case-insensitive leg gets the flag its engine would apply.
/// Reducing all three spellings to one language is the point -- an `exact:`
/// and a `regex:` naming the same file are the same evidence, however they are
/// written.
pub(super) fn leg_value_pattern(cond: &Condition) -> Option<String> {
    let (exact, substr, regex, case_insensitive) = match cond {
        Condition::Kv(q) => (
            q.exact.as_deref(),
            q.substr.as_deref(),
            q.regex.as_deref(),
            q.case_insensitive,
        ),
        Condition::Path(q) => (
            q.exact.as_deref(),
            q.substr.as_deref(),
            q.regex.as_deref(),
            q.case_insensitive,
        ),
        _ => return None,
    };
    let body = match (exact, substr, regex) {
        (Some(v), None, None) => format!(r"\A{}\z", regex::escape(v)),
        (None, Some(v), None) => regex::escape(v),
        (None, None, Some(v)) => format!("(?:{v})"),
        _ => return None,
    };
    Some(if case_insensitive {
        format!("(?i){body}")
    } else {
        body
    })
}

/// A value-set automaton: the byte strings a leg accepts, searched the way the
/// engine searches them (a pattern with no anchor matches anywhere).
pub(super) type ValueSetDfa = regex_automata::dfa::dense::DFA<Vec<u32>>;

/// Build the [`ValueSetDfa`] for `pattern`, or `None` when it exceeds the
/// determinization budget.
pub(super) fn value_set_dfa(pattern: &str) -> Option<ValueSetDfa> {
    use regex_automata::dfa::dense;

    // `MatchKind::All` keeps the automaton reporting every match rather than
    // stopping at the leftmost one, which is what "does any value satisfy
    // this" needs. The size limits keep a pathological pattern from turning a
    // validation run into a determinization.
    dense::Builder::new()
        .configure(
            dense::Config::new()
                .match_kind(regex_automata::MatchKind::All)
                .dfa_size_limit(Some(1 << 22))
                .determinize_size_limit(Some(1 << 22)),
        )
        .build(pattern)
        .ok()
}

/// A witness search over the two automata run in lockstep.
///
/// Every node is a pair of states; the walk is finite because the state pair
/// space is, and `None` means it hit its budget without deciding. Callers
/// supply what counts as a witness at the end of the value.
pub(super) fn product_walk(
    dfa_a: &ValueSetDfa,
    dfa_b: &ValueSetDfa,
    anchored: bool,
    witness: impl Fn(bool, bool) -> bool,
    prune_on_b_match: bool,
) -> Option<bool> {
    use regex_automata::Anchored;
    use regex_automata::dfa::Automaton;
    use regex_automata::util::start;

    let config = start::Config::new().anchored(if anchored {
        Anchored::Yes
    } else {
        Anchored::No
    });
    let (start_a, start_b) = (
        dfa_a.start_state(&config).ok()?,
        dfa_b.start_state(&config).ok()?,
    );

    // Byte classes collapse the 256 transitions into the handful each pattern
    // actually distinguishes. Two bytes are interchangeable here only when
    // *both* automata treat them alike, so the alphabet is one representative
    // per distinct pair of classes -- typically a dozen bytes, not 256.
    let (classes_a, classes_b) = (dfa_a.byte_classes(), dfa_b.byte_classes());
    let mut seen_classes = HashSet::new();
    let alphabet: Vec<u8> = (0..=255u8)
        .filter(|&byte| seen_classes.insert((classes_a.get(byte), classes_b.get(byte))))
        .collect();

    // A side that has already matched is frozen: its obligation is discharged,
    // and stepping it on could only walk it into a dead state and prune a
    // search that is still live for the other side. Under `anchored` there is
    // nothing to freeze -- the match has to end exactly at the value's end.
    let mut seen = HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((start_a, start_b, false, false));
    seen.insert((start_a, start_b, false, false));

    let mut budget = 250_000usize;
    while let Some((sa, sb, ma, mb)) = queue.pop_front() {
        budget = budget.checked_sub(1)?;

        let done_a = ma || dfa_a.is_match_state(dfa_a.next_eoi_state(sa));
        let done_b = mb || dfa_b.is_match_state(dfa_b.next_eoi_state(sb));
        if witness(done_a, done_b) {
            return Some(true);
        }

        for &byte in &alphabet {
            let (mut na, mut nb) = (sa, sb);
            let (mut nma, mut nmb) = (ma, mb);
            if !ma {
                na = dfa_a.next_state(sa, byte);
                if dfa_a.is_dead_state(na) || dfa_a.is_quit_state(na) {
                    continue;
                }
                nma = !anchored && dfa_a.is_match_state(na);
            }
            if !mb {
                nb = dfa_b.next_state(sb, byte);
                if dfa_b.is_quit_state(nb) {
                    continue;
                }
                // A dead `b` is fatal when the witness needs `b` to match and
                // is exactly what the witness wants when it needs `b` not to.
                if dfa_b.is_dead_state(nb) && prune_on_b_match {
                    continue;
                }
                nmb = !anchored && dfa_b.is_match_state(nb);
                if nmb && prune_on_b_match {
                    continue;
                }
            }
            if seen.insert((na, nb, nma, nmb)) {
                queue.push_back((na, nb, nma, nmb));
            }
        }
    }
    Some(false)
}

/// Whether both matchers can match the *same text*.
///
/// This is "the same evidence, spelled differently" stated precisely: run both
/// patterns anchored at both ends and ask whether one span satisfies both.
/// `\.(xlsx|xls)$` and `\.(xlsm|xlsx)$` meet on `.xlsx`, so an archive member
/// named that way answers both legs with one filename.
///
/// It is deliberately not "one value satisfies both". A preinstall script
/// holding `http://…` and an `xxd` call satisfies a URL leg and a hex-encode
/// leg at once, but those legs match different text and are two observations.
pub(super) fn same_span_satisfies_both(a: &ValueSetDfa, b: &ValueSetDfa) -> Option<bool> {
    product_walk(a, b, true, |done_a, done_b| done_a && done_b, true)
}

/// Whether every value `a` accepts, `b` accepts too.
///
/// The search is for a counter-example -- a value that `a` matches and `b`
/// does not -- so finding none proves containment. An `exact:` leg naming
/// `docs/Invoice-90233.xlsx` alongside a regex leg for `\.(xlsx|xls)$` matches
/// different *text*, but every member the first accepts the second accepts,
/// so the second is not telling the rule anything new.
pub(super) fn value_set_contains(a: &ValueSetDfa, b: &ValueSetDfa) -> Option<bool> {
    let witness = product_walk(a, b, false, |done_a, done_b| done_a && !done_b, false)?;
    Some(!witness)
}

/// Whether two legs carry the same surrounding constraints.
///
/// A leg with its own count floor, density, size window or suppression is
/// asserting something the other one is not -- "three spreadsheet members" is
/// a different claim from "an xlsx member" even though one member answers
/// both matchers. Only legs that differ solely in how their matcher is
/// spelled are the same evidence.
pub(super) fn same_leg_constraints(a: &TraitDefinition, b: &TraitDefinition) -> bool {
    a.count_min == b.count_min
        && a.count_max == b.count_max
        && a.per_kb_min == b.per_kb_min
        && a.per_kb_max == b.per_kb_max
        && a.size_min == b.size_min
        && a.size_max == b.size_max
        && a.entropy_min == b.entropy_min
        && a.entropy_max == b.entropy_max
        && a.not.is_none()
        && b.not.is_none()
        && a.unless.is_none()
        && b.unless.is_none()
}

/// Required legs that one value can satisfy at once.
///
/// A conviction is supposed to rest on two pieces of evidence. When two `all:`
/// legs read the same fact and some single value answers both, there is one
/// piece of evidence spelled two ways: `zip-xlsx-spreadsheet-stage` required
/// an archive member matching `\\.xlsx$` and one matching
/// `\\.(xlsx|xlsm|xlsb|xls)$`, which one `.xlsx` member satisfies. The rule
/// convicts at `hostile`/0.93 on a filename it counted twice.
///
/// Overlap is enough -- containment is not required. `\\.(xlsx|xls)$` and
/// `\\.(xlsm|xlsx)$` cover different extension sets, and neither implies the
/// other, but one `.xlsx` member still answers both.
///
/// Legs that no single value can satisfy stay silent, because requiring two
/// *different* members is a real layout fingerprint: `archive-sideload-bundle`
/// wants a `setup.exe` at the root and a binary under `Updates/`, and no one
/// path is both.
///
/// Returns `(composite id, first leg, second leg, the fact they share)`.
pub(crate) fn find_one_fact_convictions(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, String, String, String)> {
    let composite_by_id: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|c| (c.id.as_str(), c)).collect();
    let by_id: HashMap<&str, &TraitDefinition> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t))
        .collect();
    let mut all_ids: Vec<&str> = by_id.keys().copied().collect();
    all_ids.extend(composite_by_id.keys().copied());
    let index = ReferenceIndex::new(all_ids);

    let mut cache: HashMap<String, Vec<&str>> = HashMap::new();
    // Pairs that pass the cheap tests, in report order, each carrying the two
    // value patterns still to be compared.
    let mut pairs: Vec<((String, String, String, String), usize, usize)> = Vec::new();
    let mut pattern_slot: HashMap<String, usize> = HashMap::new();
    let mut patterns: Vec<String> = Vec::new();
    for rule in composite_rules {
        // Scoped to convictions. Two spellings of one fact in a notable rule
        // are untidy; in a suspicious or hostile one they are the difference
        // between evidence and the appearance of it.
        if rule.crit < crate::types::Criticality::Suspicious {
            continue;
        }
        let Some(required) = rule.all.as_ref() else {
            continue;
        };
        let legs: Vec<&str> = required
            .iter()
            .filter_map(|c| match c {
                Condition::Trait { id } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        if legs.len() < 2 {
            continue;
        }

        // A leg that resolves to a composite, a directory or an ambiguous
        // short name stands for several conditions, and no one value set
        // describes it.
        let resolved: Vec<Option<&TraitDefinition>> = legs
            .iter()
            .map(|leg| {
                let ids = resolve_cached(leg, &index, &mut cache);
                let [id] = ids[..] else { return None };
                by_id.get(id).copied()
            })
            .collect();

        for (i, a) in resolved.iter().enumerate() {
            let Some(a) = a else { continue };
            for (j, b) in resolved.iter().enumerate().skip(i + 1) {
                let Some(b) = b else { continue };
                if a.id == b.id {
                    continue;
                }
                let (Some(key_a), Some(key_b)) = (leg_fact_key(&a.r#if), leg_fact_key(&b.r#if))
                else {
                    continue;
                };
                if key_a != key_b {
                    continue;
                }
                if !same_leg_constraints(a, b) {
                    continue;
                }
                let (Some(pattern_a), Some(pattern_b)) =
                    (leg_value_pattern(&a.r#if), leg_value_pattern(&b.r#if))
                else {
                    continue;
                };
                let mut slot = |pattern: String| {
                    *pattern_slot.entry(pattern).or_insert_with_key(|pattern| {
                        patterns.push(pattern.clone());
                        patterns.len() - 1
                    })
                };
                let (slot_a, slot_b) = (slot(pattern_a), slot(pattern_b));
                let fact = if key_a.1.is_empty() {
                    "the file name".to_string()
                } else {
                    key_a.1.to_string()
                };
                pairs.push((
                    (
                        rule.id.clone(),
                        legs[i].to_string(),
                        legs[j].to_string(),
                        fact,
                    ),
                    slot_a,
                    slot_b,
                ));
            }
        }
    }

    // Determinizing is nearly all of this check's cost, and every pattern and
    // every pair is independent: each pattern is built once, then the pairs
    // are judged in parallel and kept in report order. A verdict depends only
    // on the two patterns, so an earlier run's stands and only the patterns of
    // pairs without one are determinized.
    let facts = super::super::facts_cache::active();
    let verdict_key = |slot_a: usize, slot_b: usize| {
        super::super::facts_cache::key(
            "one-fact",
            &[patterns[slot_a].as_bytes(), patterns[slot_b].as_bytes()],
        )
    };
    let known: Vec<Option<bool>> = pairs
        .iter()
        .map(|&(_, slot_a, slot_b)| {
            facts
                .as_ref()
                .and_then(|facts| facts.get::<bool>(&verdict_key(slot_a, slot_b)))
        })
        .collect();
    let mut needed = vec![false; patterns.len()];
    for (&(_, slot_a, slot_b), known) in pairs.iter().zip(&known) {
        if known.is_none() {
            needed[slot_a] = true;
            needed[slot_b] = true;
        }
    }
    let dfas: Vec<Option<ValueSetDfa>> = patterns
        .par_iter()
        .zip(needed)
        .map(|(pattern, needed)| if needed { value_set_dfa(pattern) } else { None })
        .collect();
    pairs
        .into_par_iter()
        .zip(known)
        .filter_map(|((finding, slot_a, slot_b), known)| {
            let same_evidence = known.unwrap_or_else(|| {
                // The same evidence, either because the two matchers can match
                // one span or because one leg's values are all already
                // accepted by the other.
                let same_evidence = match (&dfas[slot_a], &dfas[slot_b]) {
                    (Some(dfa_a), Some(dfa_b)) => {
                        same_span_satisfies_both(dfa_a, dfa_b) == Some(true)
                            || value_set_contains(dfa_a, dfa_b) == Some(true)
                            || value_set_contains(dfa_b, dfa_a) == Some(true)
                    }
                    _ => false,
                };
                if let Some(facts) = &facts {
                    facts.put(verdict_key(slot_a, slot_b), &same_evidence);
                }
                same_evidence
            });
            same_evidence.then_some(finding)
        })
        .collect()
}

/// Cache for [`ReferenceIndex::resolve`]. These checks resolve the same
/// handful of references across thousands of composites.
pub(super) fn resolve_cached<'a>(
    reference: &str,
    index: &ReferenceIndex<'a>,
    cache: &mut HashMap<String, Vec<&'a str>>,
) -> Vec<&'a str> {
    if let Some(hit) = cache.get(reference) {
        return hit.clone();
    }
    let resolved = index.resolve(reference);
    cache.insert(reference.to_string(), resolved.clone());
    resolved
}

/// Whether a condition describes what a file *is called* or pins it to an exact
/// measurement, rather than saying anything about its contents.
///
/// A path never reads the bytes. A metric usually does -- an overlay's entropy,
/// a section ratio, a zeroed PE checksum are all measurements of the file
/// itself, and rules built from them are doing real structural analysis. The
/// exception is a metric pinned to a single value (`min == max`), which
/// identifies one artifact the way a hash does: `digininja-postinstall` required
/// `strings.count` of exactly 13.
pub(super) fn is_name_or_shape_only(condition: &Condition) -> bool {
    match condition {
        Condition::Path(_) => true,
        Condition::Metrics(m) => matches!((m.min, m.max), (Some(lo), Some(hi)) if lo == hi),
        _ => false,
    }
}

/// Objective directories whose whole subject is the filename an attacker chose.
pub(super) const NAME_IS_THE_TECHNIQUE: &[&str] = &[
    "objectives/evasion/masquerade/",
    "objectives/supply-chain/impersonation/",
    "objectives/execution/lure/",
    "metadata/file/extension/",
];

/// What one leg of a conviction can reach, reduced to what the verdict needs.
#[derive(Clone, Copy)]
pub(super) struct LegEvidence {
    /// Something on the way reads the file's contents: an inline condition on
    /// a composite, or a terminal trait that is not a name or shape.
    pub(super) reads_content: bool,
    /// The leg reaches at least one terminal trait.
    pub(super) reaches_terminal: bool,
}

/// Walk one leg far enough to decide it: stop at the first thing that reads
/// content, since one is enough to clear the rule.
pub(super) fn leg_evidence<'a>(
    reference: &str,
    index: &ReferenceIndex<'a>,
    by_id: &HashMap<&str, &TraitDefinition>,
    composite_by_id: &HashMap<&str, &'a CompositeTrait>,
    cache: &mut HashMap<String, Vec<&'a str>>,
) -> LegEvidence {
    let mut evidence = LegEvidence {
        reads_content: false,
        reaches_terminal: false,
    };
    let mut stack = resolve_cached(reference, index, cache);
    let mut seen: HashSet<&str> = HashSet::new();
    while let Some(next) = stack.pop() {
        if !seen.insert(next) {
            continue;
        }
        let Some(sub) = composite_by_id.get(next) else {
            evidence.reaches_terminal = true;
            if !by_id
                .get(next)
                .is_some_and(|d| is_name_or_shape_only(&d.r#if))
            {
                evidence.reads_content = true;
                return evidence;
            }
            continue;
        };
        for c in sub.all.iter().flatten().chain(sub.any.iter().flatten()) {
            if c.is_trait_reference() {
                for child in c.trait_references() {
                    stack.extend(resolve_cached(child, index, cache));
                }
            } else if !is_name_or_shape_only(c) {
                evidence.reads_content = true;
                return evidence;
            }
        }
    }
    evidence
}

/// Every terminal trait a leg reaches, required or alternative.
pub(super) fn leg_terminals<'a>(
    reference: &str,
    index: &ReferenceIndex<'a>,
    composite_by_id: &HashMap<&str, &'a CompositeTrait>,
    cache: &mut HashMap<String, Vec<&'a str>>,
    terminals: &mut HashSet<&'a str>,
) {
    let mut stack = resolve_cached(reference, index, cache);
    let mut seen: HashSet<&str> = HashSet::new();
    while let Some(next) = stack.pop() {
        if !seen.insert(next) {
            continue;
        }
        match composite_by_id.get(next) {
            Some(sub) => {
                for c in sub.all.iter().flatten().chain(sub.any.iter().flatten()) {
                    for child in c.trait_references() {
                        stack.extend(resolve_cached(child, index, cache));
                    }
                }
            }
            None => {
                terminals.insert(next);
            }
        }
    }
}

/// Convictions assembled entirely from name, size and metric facts.
///
/// `digininja-postinstall` was the clearest: an exact `.tgz` basename, a file
/// size pinned to 1917 bytes, and `strings.count` of exactly 13 -- a file hash
/// wearing behavioural clothing, which matches one artifact and not the next
/// build of the same malware. Names and shapes corroborate; they do not convict.
///
/// A rule is reported when no positive leg reads content -- neither an inline
/// condition anywhere on the way nor a terminal trait -- and some leg reaches a
/// terminal. Deciding that needs only two facts per leg, and most legs settle
/// at their first content-reading trait, so the full terminal list is walked
/// only for the rules that are reported.
///
/// Returns `(composite id, the terminal ids it rests on)`.
pub(crate) fn find_convictions_without_content(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, Vec<String>)> {
    use crate::types::Criticality;

    let by_id: HashMap<&str, &TraitDefinition> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t))
        .collect();
    let composite_by_id: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut all_ids: Vec<&str> = by_id.keys().copied().collect();
    all_ids.extend(composite_by_id.keys().copied());
    let index = ReferenceIndex::new(all_ids);

    let mut cache: HashMap<String, Vec<&str>> = HashMap::new();
    // A leg's evidence depends only on its reference, and the same legs recur
    // across thousands of rules, so each is walked once.
    let mut legs: HashMap<&str, LegEvidence> = HashMap::new();
    let mut found = Vec::new();
    for rule in composite_rules {
        if rule.crit < Criticality::Suspicious {
            continue;
        }
        // Objectives where the name IS the finding. Masquerading, lures,
        // typosquats and architecture-suffixed bot drops are detected precisely
        // by what the attacker called the file -- `payment-receipt.pdf.exe` is
        // the attack, not a label on it -- so a name-only conviction is correct
        // there and nowhere else.
        if NAME_IS_THE_TECHNIQUE
            .iter()
            .any(|prefix| rule.id.starts_with(prefix))
        {
            continue;
        }
        // Every positive leg counts here, `any:` included: one content-derived
        // alternative is enough to say the rule rests on more than a filename.
        let positive = || rule.all.iter().flatten().chain(rule.any.iter().flatten());
        let mut reads_content = false;
        let mut reaches_terminal = false;
        for cond in positive() {
            if cond.is_trait_reference() {
                for id in cond.trait_references() {
                    // A reference into a runtime-synthesized namespace resolves
                    // to nothing statically, but it is not absent evidence: an
                    // import, a code signature or an entitlement is a fact about
                    // the file's contents, recovered per-scan. Counting those as
                    // "no content" reported rules like `setup-py-ctypes-imports`
                    // as resting on their filename alone.
                    if is_runtime_synthesized_namespace(id) {
                        reads_content = true;
                    } else {
                        let leg = *legs.entry(id.as_str()).or_insert_with(|| {
                            leg_evidence(id, &index, &by_id, &composite_by_id, &mut cache)
                        });
                        reads_content |= leg.reads_content;
                        reaches_terminal |= leg.reaches_terminal;
                    }
                }
            } else {
                reads_content |= !is_name_or_shape_only(cond);
            }
            // One content-reading leg clears the rule; the rest cannot change that.
            if reads_content {
                break;
            }
        }
        if reads_content || !reaches_terminal {
            continue;
        }
        let mut terminals: HashSet<&str> = HashSet::new();
        for cond in positive() {
            for id in cond.trait_references() {
                leg_terminals(id, &index, &composite_by_id, &mut cache, &mut terminals);
            }
        }
        let mut ids: Vec<String> = terminals.iter().map(|t| (*t).to_string()).collect();
        ids.sort();
        found.push((rule.id.clone(), ids));
    }
    found
}
