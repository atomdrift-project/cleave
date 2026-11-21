//! The duplicate-trait audit of `cleave validate --dupes`: pairs of atomic
//! traits whose every match, across the fixtures and any extra corpus, sits
//! at the same location as a match of the other.
//!
//! A pair is reported when both traits fire in exactly the same files, at
//! least [`MIN_SUPPORT`] of them, and in each of those files every located
//! match of either trait overlaps a located match of the other. One match
//! anywhere that the other trait does not share rules the pair out.
//!
//! Each analyzed file is folded into per-trait and per-pair file counts as it
//! finishes, so no report outlives its own analysis. A file is counted once
//! per distinct content: a corpus holding many versions of one package would
//! otherwise count a bundled file once per copy.

use crate::types::{AnalysisReport, Criticality, FileAnalysis, Istr};
use cleave::CapabilityMapper;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// A pair must be co-located in at least this many distinct files.
const MIN_SUPPORT: u32 = 3;
/// Evidence without a byte offset (symbols, imports) is located by value: each
/// distinct value gets a one-byte pseudo-span above any real offset.
const VALUE_BASE: u64 = 1 << 62;

#[derive(Default)]
struct PairCount {
    /// Files in which every match of each trait overlaps one of the other.
    files: u32,
    /// Of those, files where some shared match covers exactly the same bytes.
    identical: u32,
    /// The lexically first such file and a shared offset in it, for a
    /// deterministic example whatever order the lanes finish in.
    example: Option<(String, Option<u64>)>,
}

#[derive(Default)]
struct Counts {
    files: u64,
    /// Files skipped because their content was already counted.
    repeats: u64,
    /// The leading 128 bits of each counted file's SHA-256.
    seen: HashSet<u128>,
    /// Files in which each atomic trait fired.
    fires: HashMap<Istr, u32>,
    /// Keyed by the two ids in order.
    pairs: HashMap<(Istr, Istr), PairCount>,
}

impl Counts {
    fn merge(&mut self, folds: Vec<(&FileAnalysis, FileFold)>) {
        for (file, fold) in folds {
            let digest = file
                .sha256
                .get(..32)
                .and_then(|h| u128::from_str_radix(h, 16).ok());
            if digest.is_some_and(|d| !self.seen.insert(d)) {
                self.repeats += 1;
                continue;
            }
            self.files += 1;
            for id in &fold.ids {
                *self.fires.entry(id.clone()).or_default() += 1;
            }
            for (a, b, identical, offset) in fold.pairs {
                let (a, b) = (&fold.ids[a as usize], &fold.ids[b as usize]);
                let key = if a <= b {
                    (a.clone(), b.clone())
                } else {
                    (b.clone(), a.clone())
                };
                let pair = self.pairs.entry(key).or_default();
                pair.files += 1;
                pair.identical += u32::from(identical);
                if pair.example.as_ref().is_none_or(|(p, _)| file.path < *p) {
                    pair.example = Some((file.path.clone(), offset));
                }
            }
        }
    }
}

/// Co-location counts gathered across every analyzed file.
pub(super) struct Tally {
    /// Every atomic trait: its criticality and defining file.
    atomic: HashMap<String, (Criticality, String)>,
    /// The traits directory as resolved and as canonicalized (they differ
    /// through a symlink), stripped from displayed paths.
    roots: Vec<String>,
    counts: parking_lot::Mutex<Counts>,
}

#[derive(Clone, Copy)]
struct Span {
    start: u64,
    end: u64,
    t: u32,
}

/// A span still open in the sweep, and the traits already found covering it.
struct Open {
    span: Span,
    covered_by: Vec<u32>,
}

/// One file's view: the atomic traits that fired, and the pairs of them
/// whose every match here overlaps a match of the other.
struct FileFold {
    ids: Vec<Istr>,
    /// `ids` indices, whether some shared match is the exact same bytes, and
    /// the first shared offset (`None` for offset-less evidence).
    pairs: Vec<(u32, u32, bool, Option<u64>)>,
}

impl Tally {
    pub(super) fn new(mapper: &CapabilityMapper, traits_dir: &std::path::Path) -> Self {
        let atomic = mapper
            .rule_shapes()
            .into_iter()
            .filter(|(_, s)| s.atomic)
            .map(|(id, s)| (id, (s.crit, s.defined_in)))
            .collect();
        Self {
            atomic,
            roots: [
                Some(traits_dir.to_path_buf()),
                cleave::traits_repo::try_resolve().ok(),
            ]
            .into_iter()
            .flatten()
            .map(|dir| format!("{}/", dir.display()))
            .collect(),
            counts: parking_lot::Mutex::default(),
        }
    }

    /// Fold every file of `report` into the counts.
    pub(super) fn add(&self, report: &AnalysisReport) {
        self.add_files(&report.files);
    }

    fn add_files(&self, files: &[FileAnalysis]) {
        let folds: Vec<(&FileAnalysis, FileFold)> =
            files.iter().map(|file| (file, self.fold(file))).collect();
        self.counts.lock().merge(folds);
    }

    fn fold(&self, file: &FileAnalysis) -> FileFold {
        let mut ids: Vec<Istr> = Vec::new();
        let mut index: HashMap<&str, u32> = HashMap::new();
        let mut values: HashMap<&str, u64> = HashMap::new();
        let mut spans: Vec<Span> = Vec::new();
        for finding in &file.findings {
            // Inherited findings are counted in the child that located them.
            if finding.src.is_some() || !self.atomic.contains_key(finding.id.as_str()) {
                continue;
            }
            let t = *index.entry(finding.id.as_str()).or_insert_with(|| {
                ids.push(finding.id.clone());
                (ids.len() - 1) as u32
            });
            let mut push = |start: u64, len: u64| {
                spans.push(Span {
                    start,
                    end: start.saturating_add(len.max(1)),
                    t,
                });
            };
            for e in &finding.evidence {
                if e.location
                    .as_deref()
                    .is_some_and(|l| l.starts_with("archive:"))
                {
                    continue;
                }
                let len = e.match_len.unwrap_or(e.value.len() as u64);
                if !e.offsets.is_empty() {
                    e.offsets.iter().for_each(|&o| push(o, len));
                } else if let Some(o) = e.byte_offset() {
                    push(o, len);
                } else if !e.value.is_empty() {
                    let next = VALUE_BASE + 2 * values.len() as u64;
                    push(*values.entry(e.value.as_str()).or_insert(next), 1);
                }
            }
            for &[o, len] in finding.precomputed_spans.iter().flatten() {
                push(o, len);
            }
        }

        spans.sort_unstable_by_key(|s| (s.start, std::cmp::Reverse(s.end), s.t));
        spans.dedup_by_key(|s| (s.start, s.end, s.t));
        let mut located = vec![0u32; ids.len()];
        for s in &spans {
            located[s.t as usize] += 1;
        }
        // covered[(a, b)]: spans of `a` that overlap some span of `b`.
        let mut covered: HashMap<(u32, u32), u32> = HashMap::new();
        // Per pair (low, high): any identical span, and the first shared offset.
        let mut met: HashMap<(u32, u32), (bool, u64)> = HashMap::new();
        let mut open: Vec<Open> = Vec::new();
        for s in &spans {
            open.retain(|o| o.span.end > s.start);
            let mut covered_by = Vec::new();
            for o in &mut open {
                let other = o.span.t;
                if other == s.t {
                    continue;
                }
                if !covered_by.contains(&other) {
                    covered_by.push(other);
                    *covered.entry((s.t, other)).or_default() += 1;
                }
                if !o.covered_by.contains(&s.t) {
                    o.covered_by.push(s.t);
                    *covered.entry((other, s.t)).or_default() += 1;
                }
                let identical = o.span.start == s.start && o.span.end == s.end;
                let entry = met
                    .entry((other.min(s.t), other.max(s.t)))
                    .or_insert((identical, s.start));
                entry.0 |= identical;
            }
            open.push(Open {
                span: *s,
                covered_by,
            });
        }

        let all_covered =
            |a: u32, b: u32| covered.get(&(a, b)).copied().unwrap_or(0) == located[a as usize];
        let pairs = met
            .into_iter()
            .filter(|&((a, b), _)| all_covered(a, b) && all_covered(b, a))
            .map(|((a, b), (identical, offset))| {
                (a, b, identical, (offset < VALUE_BASE).then_some(offset))
            })
            .collect();
        FileFold { ids, pairs }
    }

    /// Every pair that is co-located in each file either trait fires in.
    pub(super) fn audit(self) -> Audit {
        let counts = self.counts.into_inner();
        let relative = |path: &str| {
            self.roots
                .iter()
                .find_map(|root| path.strip_prefix(root.as_str()))
                .unwrap_or(path)
                .to_owned()
        };
        let side = |id: &Istr| {
            let (crit, defined_in) = &self.atomic[id.as_str()];
            Side {
                id: id.to_string(),
                crit: format!("{crit:?}").to_lowercase(),
                defined_in: relative(defined_in),
            }
        };
        let fires = |id: &Istr| counts.fires.get(id).copied().unwrap_or(0);
        let mut pairs: Vec<Dupe> = counts
            .pairs
            .iter()
            .filter(|((a, b), p)| {
                p.files >= MIN_SUPPORT && p.files == fires(a) && p.files == fires(b)
            })
            .map(|((a, b), p)| {
                let (example, offset) = p.example.clone().unwrap_or_default();
                Dupe {
                    files: p.files,
                    identical: p.identical,
                    a: side(a),
                    b: side(b),
                    example: relative(&example),
                    offset,
                }
            })
            .collect();
        pairs.sort_by(|x, y| {
            (std::cmp::Reverse(x.files), &x.a.id, &x.b.id).cmp(&(
                std::cmp::Reverse(y.files),
                &y.a.id,
                &y.b.id,
            ))
        });
        Audit {
            files: counts.files,
            repeats: counts.repeats,
            atomic_traits: self.atomic.len(),
            fired_traits: counts.fires.len(),
            pairs,
        }
    }
}

#[derive(Serialize)]
pub(super) struct Audit {
    /// Distinct files (archive members included) folded into the counts.
    pub(super) files: u64,
    /// Files skipped as byte-identical to one already counted.
    pub(super) repeats: u64,
    /// Atomic traits loaded; only these are compared.
    pub(super) atomic_traits: usize,
    /// Atomic traits that fired in some file. The rest could not be checked:
    /// add samples that trigger them via `--dupes DIR`.
    pub(super) fired_traits: usize,
    pub(super) pairs: Vec<Dupe>,
}

#[derive(Serialize)]
pub(super) struct Dupe {
    /// Files in which both fire; neither fires anywhere else.
    pub(super) files: u32,
    /// Files in which some shared match is the exact same bytes.
    pub(super) identical: u32,
    pub(super) a: Side,
    pub(super) b: Side,
    pub(super) example: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) offset: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct Side {
    pub(super) id: String,
    pub(super) crit: String,
    pub(super) defined_in: String,
}

impl Audit {
    pub(super) fn table(&self) -> String {
        let esc = |s: &str| crate::output::escape_control_chars(s).into_owned();
        let mut out = format!(
            "\nDuplicate traits: {} pair(s) match at the same location wherever either \
             fires; {} distinct file(s), {} repeat(s) skipped; {} of {} atomic traits fired\n",
            self.pairs.len(),
            self.files,
            self.repeats,
            self.fired_traits,
            self.atomic_traits,
        );
        for p in &self.pairs {
            let width = p.a.id.len().max(p.b.id.len());
            out.push('\n');
            for s in [&p.a, &p.b] {
                let _ = writeln!(
                    out,
                    "  {:width$}  {:10} {}",
                    s.id,
                    s.crit,
                    esc(&s.defined_in)
                );
            }
            let at = p.offset.map(|o| format!(" @{o:#x}")).unwrap_or_default();
            let _ = writeln!(
                out,
                "    {} file(s), {} with identical bytes; e.g. {}{at}",
                p.files,
                p.identical,
                esc(&p.example)
            );
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::{Evidence, Finding, FindingKind};

    fn tally(ids: &[&str]) -> Tally {
        Tally {
            atomic: ids
                .iter()
                .map(|id| {
                    (
                        (*id).to_owned(),
                        (Criticality::Notable, format!("{id}.yaml")),
                    )
                })
                .collect(),
            roots: Vec::new(),
            counts: parking_lot::Mutex::default(),
        }
    }

    /// A finding for `id` matching `value` at each of `offsets`.
    fn hit(id: &str, value: &str, offsets: &[u64]) -> Finding {
        let mut finding = Finding::new(id, FindingKind::Capability, "", 1.0);
        finding.evidence.push(Evidence {
            value: value.to_owned(),
            offsets: offsets.to_vec(),
            ..Evidence::default()
        });
        finding
    }

    /// `n` files with distinct (empty) hashes, each holding `findings()`.
    fn files(n: usize, findings: impl Fn() -> Vec<Finding>) -> Vec<FileAnalysis> {
        (0..n)
            .map(|i| FileAnalysis {
                path: format!("f{i}"),
                findings: findings(),
                ..FileAnalysis::default()
            })
            .collect()
    }

    fn pairs(t: Tally) -> Vec<(String, String, u32, u32)> {
        t.audit()
            .pairs
            .into_iter()
            .map(|p| (p.a.id, p.b.id, p.files, p.identical))
            .collect()
    }

    #[test]
    fn identical_matches_are_duplicates() {
        let t = tally(&["a", "b"]);
        t.add_files(&files(3, || {
            vec![hit("a", "exec", &[10]), hit("b", "exec", &[10])]
        }));
        let audit = t.audit();
        assert_eq!(audit.pairs.len(), 1);
        let pair = &audit.pairs[0];
        assert_eq!((pair.files, pair.identical), (3, 3));
        assert_eq!((pair.example.as_str(), pair.offset), ("f0", Some(10)));
    }

    #[test]
    fn overlapping_matches_are_duplicates() {
        let t = tally(&["a", "b"]);
        // `a` covers 10..14, `b` covers 12..19.
        t.add_files(&files(3, || {
            vec![hit("a", "exec", &[10]), hit("b", "c(bash)", &[12])]
        }));
        assert_eq!(pairs(t), [("a".into(), "b".into(), 3, 0)]);
    }

    #[test]
    fn one_wide_match_may_cover_several() {
        let t = tally(&["a", "b"]);
        t.add_files(&files(3, || {
            vec![
                hit("a", "exec", &[10, 20]),
                hit("b", "0123456789abcdefghij", &[8]),
            ]
        }));
        assert_eq!(pairs(t).len(), 1);
    }

    #[test]
    fn adjacent_matches_do_not_meet() {
        let t = tally(&["a", "b"]);
        t.add_files(&files(3, || {
            vec![hit("a", "exec", &[10]), hit("b", "exec", &[14])]
        }));
        assert!(pairs(t).is_empty());
    }

    #[test]
    fn one_unshared_match_rules_a_pair_out() {
        let t = tally(&["a", "b"]);
        t.add_files(&files(3, || {
            vec![hit("a", "exec", &[10]), hit("b", "exec", &[10])]
        }));
        t.add_files(&files(1, || {
            vec![hit("a", "exec", &[10, 50]), hit("b", "exec", &[10])]
        }));
        assert!(pairs(t).is_empty());
    }

    #[test]
    fn firing_alone_in_one_file_rules_a_pair_out() {
        let t = tally(&["a", "b"]);
        t.add_files(&files(3, || {
            vec![hit("a", "exec", &[10]), hit("b", "exec", &[10])]
        }));
        t.add_files(&files(1, || vec![hit("b", "exec", &[10])]));
        assert!(pairs(t).is_empty());
    }

    #[test]
    fn pairs_below_support_are_dropped() {
        let t = tally(&["a", "b"]);
        t.add_files(&files(2, || {
            vec![hit("a", "exec", &[10]), hit("b", "exec", &[10])]
        }));
        assert!(pairs(t).is_empty());
    }

    #[test]
    fn repeated_content_is_counted_once() {
        let t = tally(&["a", "b"]);
        let mut copies = files(3, || vec![hit("a", "exec", &[10]), hit("b", "exec", &[10])]);
        for copy in &mut copies {
            copy.sha256 = "ab".repeat(32);
        }
        t.add_files(&copies);
        let audit = t.audit();
        assert_eq!((audit.files, audit.repeats), (1, 2));
        assert!(audit.pairs.is_empty());
    }

    #[test]
    fn offsetless_evidence_meets_by_value() {
        let t = tally(&["a", "b", "c"]);
        t.add_files(&files(3, || {
            vec![
                hit("a", "connect", &[]),
                hit("b", "connect", &[]),
                hit("c", "socket", &[]),
            ]
        }));
        let audit = t.audit();
        assert_eq!(audit.pairs.len(), 1);
        assert_eq!(audit.pairs[0].offset, None);
    }

    #[test]
    fn composites_and_inherited_findings_are_ignored() {
        let t = tally(&["a"]);
        t.add_files(&files(3, || {
            let mut inherited = hit("a", "exec", &[10]);
            inherited.src = Some(1);
            vec![
                hit("a", "exec", &[10]),
                hit("composite", "exec", &[10]),
                inherited,
            ]
        }));
        let audit = t.audit();
        assert!(audit.pairs.is_empty());
        assert_eq!(audit.fired_traits, 1);
    }

    #[test]
    fn report_paths_are_relative_to_the_traits_directory() {
        let mut t = tally(&["a", "b"]);
        t.roots = vec!["/traits/".to_owned()];
        t.atomic.insert(
            "a".to_owned(),
            (Criticality::Suspicious, "/traits/x/a.yaml".to_owned()),
        );
        let copies: Vec<FileAnalysis> = (0..3)
            .map(|i| FileAnalysis {
                path: format!("/traits/testdata/f{i}"),
                findings: vec![hit("a", "exec", &[10]), hit("b", "exec", &[10])],
                ..FileAnalysis::default()
            })
            .collect();
        t.add_files(&copies);
        let audit = t.audit();
        let pair = &audit.pairs[0];
        assert_eq!(pair.example, "testdata/f0");
        assert_eq!(
            (pair.a.crit.as_str(), pair.a.defined_in.as_str()),
            ("suspicious", "x/a.yaml")
        );
    }

    #[test]
    fn table_escapes_control_characters_in_paths() {
        let t = tally(&["a", "b"]);
        let copies: Vec<FileAnalysis> = (0..3)
            .map(|i| FileAnalysis {
                path: format!("evil\u{1b}[2J{i}"),
                findings: vec![hit("a", "exec", &[10]), hit("b", "exec", &[10])],
                ..FileAnalysis::default()
            })
            .collect();
        t.add_files(&copies);
        let table = t.audit().table();
        assert!(!table.contains('\u{1b}'));
        assert!(table.contains("1 pair(s)"));
        assert!(table.contains("@0xa"));
    }

    #[test]
    fn audit_serializes_its_counts_and_pairs() {
        let t = tally(&["a", "b"]);
        t.add_files(&files(3, || {
            vec![hit("a", "connect", &[]), hit("b", "connect", &[])]
        }));
        let json = serde_json::to_value(t.audit()).unwrap();
        assert_eq!(json["files"], 3);
        assert_eq!(json["repeats"], 0);
        assert_eq!(json["fired_traits"], 2);
        assert_eq!(json["pairs"][0]["files"], 3);
        assert_eq!(json["pairs"][0]["a"]["id"], "a");
        // Offset-less evidence has no offset to report.
        assert!(json["pairs"][0].get("offset").is_none());
    }

    #[test]
    fn decoded_matches_use_their_source_length() {
        let t = tally(&["a", "b"]);
        t.add_files(&files(3, || {
            let mut decoded = hit("a", "x", &[0]);
            decoded.evidence[0].match_len = Some(20);
            vec![decoded, hit("b", "y", &[15])]
        }));
        assert_eq!(pairs(t).len(), 1);
    }
}
