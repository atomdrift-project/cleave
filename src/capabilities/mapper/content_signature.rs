//! Short ASCII byte sequences used to reject impossible raw, text, path and literal matches.
//! Hash collisions only admit extra candidates for the full matcher. A pattern
//! that cannot match a newline is also turned away from text whose lines are
//! all shorter than its shortest match.
use crate::composite_rules::{Condition, TraitDefinition};
use regex_syntax::hir::{Hir, HirKind};

/// The grams of a text: its bytes, pairs and trigrams, ASCII letters
/// lowercased, each hashed to a bit.
#[derive(Debug)]
pub(super) struct Signature {
    bits: [u64; 1024],
    /// Whether the text is all ASCII. In other text, Unicode case folding
    /// can make an ASCII letter of a character whose bytes hold none.
    ascii: bool,
    /// The longest run of bytes without a newline, in any text added.
    longest_line: usize,
}

/// What a match must leave in the text it is found in: every clause holds,
/// and a clause holds when the text has any one of its grams.
#[derive(Clone, Copy, Default, Debug)]
pub(super) struct RequiredGrams {
    /// Gram ids, clause after clause.
    grams: [u16; MAX_GRAMS],
    /// Where each clause ends in `grams`.
    ends: [u8; MAX_CLAUSES],
    clauses: u8,
    /// The condition folds case as Unicode does, so only all-ASCII text can
    /// be turned away. A regex folds within ASCII alone and needs no such care.
    unicode_folding: bool,
    /// The shortest line a match fits in: its shortest length, for a pattern
    /// that cannot match a newline, else 0.
    line_min: u32,
}

/// The most text a signature is taken of.
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;

const MAX_GRAMS: usize = 16;
const MAX_CLAUSES: usize = 8;

/// The most strings, and the most bytes in them, that a sub-pattern's matches
/// are enumerated to. Past either, only grams are kept.
const MAX_EXACT: usize = 16;
const MAX_EXACT_BYTES: usize = 256;

/// The grams one long literal contributes, spread evenly along it.
const MAX_GRAMS_PER_LITERAL: usize = 6;

/// Lowercased strings of one to three bytes, any one of which a match holds.
type Clause = Vec<Vec<u8>>;

/// What is known of the text a sub-pattern matches.
enum Shape {
    /// Every match, lowercased, is one of these strings.
    Exact(Vec<Vec<u8>>),
    /// Every match satisfies each of these clauses. None says nothing.
    Loose(Vec<Clause>),
}

fn pair(a: u8, b: u8) -> u16 {
    (u16::from(a) * 251 + u16::from(b)) ^ 0xabcd
}

fn trigram(a: u8, b: u8, c: u8) -> u16 {
    u16::from(a)
        .wrapping_mul(251 * 251)
        .wrapping_add(u16::from(b) * 251)
        .wrapping_add(u16::from(c))
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Requirement {
    Content(RequiredGrams),
    Path(RequiredGrams),
    Literal(RequiredGrams),
    None,
}

impl Requirement {
    pub(super) fn of(rule: &TraitDefinition) -> Self {
        match &rule.r#if {
            Condition::Raw(q) => Self::Content(RequiredGrams::required(
                &q.exact,
                &q.substr,
                &q.word,
                &q.regex,
                q.case_insensitive,
            )),
            Condition::Text(q) if !q.exclude_html_comments && !q.exclude_comments => Self::Content(
                RequiredGrams::required(&q.exact, &q.substr, &q.word, &q.regex, q.case_insensitive),
            ),
            Condition::Literal(q)
                if matches!(q.kind.as_deref(), None | Some("string"))
                    && q.value.is_none()
                    && q.radix.is_none() =>
            {
                Self::Literal(RequiredGrams::required(
                    &q.exact,
                    &q.substr,
                    &q.word,
                    &q.regex,
                    q.case_insensitive,
                ))
            }
            // An AST condition reads the source its tree was parsed from.
            Condition::TreeSitter(q) => Self::Content(RequiredGrams::of_ast(q)),
            Condition::Path(q) => Self::Path(RequiredGrams::required(
                &q.exact,
                &q.substr,
                &None,
                &q.regex,
                q.case_insensitive,
            )),
            _ => Self::None,
        }
    }

    pub(super) fn accepts(
        &self,
        source: Option<&Signature>,
        path: Option<&Signature>,
        literals: Option<&Signature>,
    ) -> bool {
        match self {
            Self::Content(bits) => source.is_none_or(|s| s.accepts(bits)),
            Self::Literal(bits) => literals.is_none_or(|s| s.accepts(bits)),
            Self::Path(bits) => path.is_none_or(|s| s.accepts(bits)),
            Self::None => true,
        }
    }
}

impl Signature {
    fn add_text(&mut self, bytes: &[u8]) {
        let mark = |bits: &mut [u64], id: u16| {
            let i = usize::from(id);
            bits[i / 64] |= 1 << (i % 64);
        };
        self.longest_line = bytes
            .split(|&b| b == b'\n')
            .map(<[u8]>::len)
            .fold(self.longest_line, usize::max);
        let mut folded = bytes.iter().map(u8::to_ascii_lowercase);
        let Some(mut a) = folded.next() else { return };
        mark(&mut self.bits, u16::from(a));
        let Some(mut b) = folded.next() else { return };
        mark(&mut self.bits, u16::from(b));
        mark(&mut self.bits, pair(a, b));
        for c in folded {
            mark(&mut self.bits, u16::from(c));
            mark(&mut self.bits, pair(b, c));
            mark(&mut self.bits, trigram(a, b, c));
            (a, b) = (b, c);
        }
    }

    fn accepts(&self, required: &RequiredGrams) -> bool {
        if usize::try_from(required.line_min).is_ok_and(|min| min > self.longest_line) {
            return false;
        }
        if required.unicode_folding && !self.ascii {
            return true;
        }
        let contains = |&id: &u16| {
            let i = usize::from(id);
            self.bits[i / 64] & (1 << (i % 64)) != 0
        };
        let mut start = 0;
        required.ends[..usize::from(required.clauses)]
            .iter()
            .all(|&end| {
                let clause = &required.grams[start..usize::from(end)];
                start = usize::from(end);
                clause.iter().any(contains)
            })
    }

    /// The grams of a file's text and of the strings decoded from it, when
    /// the file is UTF-8: text conditions search that text byte for byte.
    /// Other bytes are searched through a view that replaces what is not
    /// UTF-8, which the file's own grams do not describe.
    pub(super) fn source(data: &[u8], report: &crate::types::AnalysisReport) -> Option<Self> {
        if data.len() > MAX_TEXT_BYTES || std::str::from_utf8(data).is_err() {
            return None;
        }
        let mut signature = Self {
            bits: [0; 1024],
            ascii: data.is_ascii(),
            longest_line: 0,
        };
        signature.add_text(data);
        for s in report
            .strings
            .iter()
            .filter(|s| !s.encoding_chain.is_empty())
        {
            if s.value.len() > 1024 * 1024 {
                return None;
            }
            signature.ascii &= s.value.is_ascii();
            signature.add_text(s.value.as_bytes());
        }
        Some(signature)
    }

    /// Use the same decoded values as the literal evaluator. Each value starts
    /// a fresh sequence so adjacent literals cannot contribute a shared gram.
    pub(super) fn literals(
        ctx: &crate::composite_rules::context::EvaluationContext<'_>,
    ) -> Option<Self> {
        let mut sig = Self {
            bits: [0; 1024],
            ascii: true,
            longest_line: 0,
        };
        let mut remaining: usize = MAX_TEXT_BYTES;
        for &index in ctx.literal_strings() {
            let bytes = ctx.report.strings[index as usize].value.as_bytes();
            remaining = remaining.checked_sub(bytes.len())?;
            if !bytes.is_ascii() {
                return None;
            }
            sig.add_text(bytes);
        }
        Some(sig)
    }

    pub(super) fn ascii(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_TEXT_BYTES || !bytes.is_ascii() {
            return None;
        }
        let mut signature = Self {
            bits: [0; 1024],
            ascii: true,
            longest_line: 0,
        };
        signature.add_text(bytes);
        Some(signature)
    }
}

/// The id a [`Signature`] files a lowercased string of one to three bytes under.
fn gram_id(gram: &[u8]) -> Option<u16> {
    match *gram {
        [a] => Some(u16::from(a)),
        [a, b] => Some(pair(a, b)),
        [a, b, c] => Some(trigram(a, b, c)),
        _ => None,
    }
}

/// Clauses that hold for any text containing one of `strings`. A set with the
/// empty string, or with no string at all, says nothing.
fn clauses_of(strings: &[Vec<u8>]) -> Vec<Clause> {
    if strings.is_empty() || strings.iter().any(Vec::is_empty) {
        return Vec::new();
    }
    if let [only] = strings {
        if only.len() <= 3 {
            return vec![vec![only.clone()]];
        }
        let stride = (only.len() - 2).div_ceil(MAX_GRAMS_PER_LITERAL);
        return only
            .windows(3)
            .step_by(stride)
            .map(|gram| vec![gram.to_vec()])
            .collect();
    }
    // Whichever string it is, the text has its first bytes and its last.
    let ends = |pick: fn(&[u8]) -> &[u8]| {
        let mut clause: Clause = strings.iter().map(|s| pick(s).to_vec()).collect();
        clause.sort_unstable();
        clause.dedup();
        clause
    };
    let heads = ends(|s| &s[..s.len().min(3)]);
    let tails = ends(|s| &s[s.len().saturating_sub(3)..]);
    if heads == tails {
        vec![heads]
    } else {
        vec![heads, tails]
    }
}

/// How readily a clause holds by chance: a lone byte is in most files, a
/// trigram in few, and every further gram is another way to hold.
fn chance(clause: &Clause) -> usize {
    clause
        .iter()
        .map(|gram| match gram.len() {
            1 => 16,
            2 => 4,
            _ => 1,
        })
        .sum()
}

/// Every string of `left` followed by every string of `right`, while that
/// stays within [`MAX_EXACT`] and [`MAX_EXACT_BYTES`].
fn joined(left: &[Vec<u8>], right: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    if left.len() * right.len() > MAX_EXACT {
        return None;
    }
    let mut all: Vec<Vec<u8>> = left
        .iter()
        .flat_map(|a| {
            right
                .iter()
                .map(move |b| [a.as_slice(), b.as_slice()].concat())
        })
        .collect();
    all.sort_unstable();
    all.dedup();
    (all.iter().map(Vec::len).sum::<usize>() <= MAX_EXACT_BYTES).then_some(all)
}

/// What holds whichever branch matched: the surest clause of each, joined
/// into one. A branch that promises nothing leaves nothing to promise.
fn any_branch(branches: impl Iterator<Item = Vec<Clause>>) -> Vec<Clause> {
    let mut either = Clause::new();
    for clauses in branches {
        let Some(surest) = clauses.into_iter().min_by_key(chance) else {
            return Vec::new();
        };
        either.extend(surest);
    }
    either.sort_unstable();
    either.dedup();
    if either.is_empty() {
        Vec::new()
    } else {
        vec![either]
    }
}

impl Shape {
    fn into_clauses(self) -> Vec<Clause> {
        match self {
            Shape::Exact(strings) => clauses_of(&strings),
            Shape::Loose(clauses) => clauses,
        }
    }

    fn of(hir: &Hir) -> Shape {
        match hir.kind() {
            HirKind::Empty | HirKind::Look(_) => Shape::Exact(vec![Vec::new()]),
            HirKind::Literal(lit) => Shape::Exact(vec![lit.0.to_ascii_lowercase()]),
            HirKind::Class(regex_syntax::hir::Class::Bytes(class)) => {
                let size: usize = class
                    .ranges()
                    .iter()
                    .map(regex_syntax::hir::ClassBytesRange::len)
                    .sum();
                if size > MAX_EXACT {
                    return Shape::Loose(Vec::new());
                }
                let mut bytes: Vec<Vec<u8>> = class
                    .ranges()
                    .iter()
                    .flat_map(|r| r.start()..=r.end())
                    .map(|b| vec![b.to_ascii_lowercase()])
                    .collect();
                bytes.sort_unstable();
                bytes.dedup();
                Shape::Exact(bytes)
            }
            HirKind::Class(regex_syntax::hir::Class::Unicode(_)) => Shape::Loose(Vec::new()),
            HirKind::Capture(cap) => Shape::of(&cap.sub),
            HirKind::Repetition(rep) => match (rep.min, rep.max, Shape::of(&rep.sub)) {
                (0, Some(1), Shape::Exact(mut strings)) => {
                    strings.push(Vec::new());
                    strings.sort_unstable();
                    strings.dedup();
                    Shape::Exact(strings)
                }
                (0, _, _) => Shape::Loose(Vec::new()),
                (_, _, Shape::Loose(clauses)) => Shape::Loose(clauses),
                (min, max, Shape::Exact(strings)) => {
                    // A match opens with `min` copies in a row; three of them
                    // already make a trigram of a single byte.
                    let mut run = strings.clone();
                    let mut copies = 1;
                    while copies < min.min(3)
                        && let Some(longer) = joined(&run, &strings)
                    {
                        run = longer;
                        copies += 1;
                    }
                    if max == Some(min) && copies == min {
                        Shape::Exact(run)
                    } else {
                        Shape::Loose(clauses_of(&run))
                    }
                }
            },
            HirKind::Concat(terms) => {
                // `run` is what the terms since the last gap can spell, end
                // to end; a gap, or a run grown too large, banks its clauses.
                let mut run = vec![Vec::new()];
                let mut clauses = Vec::new();
                let mut exact = true;
                for term in terms {
                    match Shape::of(term) {
                        Shape::Exact(strings) => match joined(&run, &strings) {
                            Some(longer) => run = longer,
                            None => {
                                clauses.extend(clauses_of(&run));
                                exact = false;
                                run = strings;
                            }
                        },
                        Shape::Loose(more) => {
                            clauses.extend(clauses_of(&run));
                            clauses.extend(more);
                            exact = false;
                            run = vec![Vec::new()];
                        }
                    }
                }
                if exact {
                    return Shape::Exact(run);
                }
                clauses.extend(clauses_of(&run));
                Shape::Loose(clauses)
            }
            HirKind::Alternation(terms) => {
                let shapes: Vec<Shape> = terms.iter().map(Shape::of).collect();
                let mut all = Vec::new();
                let mut exact = true;
                for shape in &shapes {
                    match shape {
                        Shape::Exact(strings) => all.extend(strings.iter().cloned()),
                        Shape::Loose(_) => exact = false,
                    }
                }
                all.sort_unstable();
                all.dedup();
                if exact
                    && all.len() <= MAX_EXACT
                    && all.iter().map(Vec::len).sum::<usize>() <= MAX_EXACT_BYTES
                {
                    return Shape::Exact(all);
                }
                Shape::Loose(any_branch(shapes.into_iter().map(Shape::into_clauses)))
            }
        }
    }
}

/// The shortest line a match of `hir` fits in: its shortest length when no
/// part of it can match a newline, else 0, which turns nothing away.
fn line_min(hir: &Hir) -> u32 {
    fn spans_lines(hir: &Hir) -> bool {
        match hir.kind() {
            HirKind::Empty | HirKind::Look(_) => false,
            HirKind::Literal(lit) => lit.0.contains(&b'\n'),
            HirKind::Class(regex_syntax::hir::Class::Bytes(class)) => class
                .ranges()
                .iter()
                .any(|r| (r.start()..=r.end()).contains(&b'\n')),
            HirKind::Class(regex_syntax::hir::Class::Unicode(class)) => class
                .ranges()
                .iter()
                .any(|r| (r.start()..=r.end()).contains(&'\n')),
            HirKind::Capture(cap) => spans_lines(&cap.sub),
            HirKind::Repetition(rep) => spans_lines(&rep.sub),
            HirKind::Concat(terms) | HirKind::Alternation(terms) => terms.iter().any(spans_lines),
        }
    }
    if spans_lines(hir) {
        return 0;
    }
    hir.properties()
        .minimum_len()
        .and_then(|len| u32::try_from(len).ok())
        .unwrap_or(0)
}

/// Whether `pattern` is searched by the engine that folds case as Unicode
/// does: the raw matcher sends a pattern with a `\u` or `\p` escape there.
fn unicode_engine(pattern: &str) -> bool {
    !crate::composite_rules::evaluators::can_use_byte_matching(pattern)
}

impl RequiredGrams {
    /// Keep the clauses least likely to hold by chance, as many as fit. A
    /// clause is kept whole or not at all: it promises one of its grams, so
    /// dropping a gram would reject text that has only that one.
    fn of(mut clauses: Vec<Clause>) -> Self {
        clauses.sort_by_key(chance);
        clauses.dedup();
        let mut kept = Self::default();
        let mut used = 0;
        for clause in &clauses {
            let Some(ids) = clause
                .iter()
                .map(|gram| gram_id(gram))
                .collect::<Option<Vec<u16>>>()
            else {
                continue;
            };
            let clause_count = usize::from(kept.clauses);
            if ids.is_empty() || clause_count == MAX_CLAUSES || used + ids.len() > MAX_GRAMS {
                continue;
            }
            kept.grams[used..used + ids.len()].copy_from_slice(&ids);
            used += ids.len();
            kept.ends[clause_count] = used as u8;
            kept.clauses += 1;
        }
        kept
    }

    /// What a match of an AST condition leaves in the source.
    ///
    /// A query's literals are those an earlier process recorded when it
    /// compiled the query; until one has, nothing is required. Simple mode
    /// tests a node's text, which may be cut short with `...`, or a callee
    /// name joined from the source's identifiers with `.`, so only what lies
    /// between dots is sure to be in the source as written.
    fn of_ast(q: &crate::composite_rules::condition::TreeSitterQuery) -> Self {
        if let Some(query) = &q.query {
            return crate::capabilities::derivation_memo::with_ast_literals(query, |patterns| {
                let mut patterns = patterns.iter().map(|requirements| {
                    requirements
                        .iter()
                        .flat_map(|any| {
                            let literals: Vec<Vec<u8>> =
                                any.iter().map(|(l, _)| l.to_ascii_lowercase()).collect();
                            clauses_of(&literals)
                        })
                        .collect::<Vec<Clause>>()
                });
                match (patterns.next(), patterns.len()) {
                    (Some(only), 0) => only,
                    (Some(first), _) => any_branch(std::iter::once(first).chain(patterns)),
                    (None, _) => Vec::new(),
                }
            })
            .map(Self::of)
            .unwrap_or_default();
        }
        let dotless = |clause: &Clause| clause.iter().all(|gram| !gram.contains(&b'.'));
        let clauses = match (&q.exact, &q.substr, &q.regex) {
            (Some(literal), _, _) | (None, Some(literal), _) if literal.is_ascii() => {
                return Self {
                    unicode_folding: q.case_insensitive,
                    ..Self::of(
                        literal
                            .split('.')
                            .flat_map(|piece| clauses_of(&[piece.as_bytes().to_ascii_lowercase()]))
                            .collect(),
                    )
                };
            }
            (None, None, Some(pattern)) if pattern.is_ascii() => {
                let mut clauses = regex_syntax::ParserBuilder::new()
                    .unicode(false)
                    .utf8(false)
                    .case_insensitive(q.case_insensitive)
                    .multi_line(true)
                    .build()
                    .parse(pattern)
                    .map(|hir| Shape::of(&hir).into_clauses())
                    .unwrap_or_default();
                clauses.retain(dotless);
                return Self {
                    unicode_folding: unicode_engine(pattern),
                    ..Self::of(clauses)
                };
            }
            _ => Vec::new(),
        };
        Self::of(clauses)
    }

    fn required(
        exact: &Option<String>,
        substr: &Option<String>,
        word: &Option<String>,
        regex: &Option<String>,
        ci: bool,
    ) -> Self {
        if [exact, substr, word, regex]
            .iter()
            .filter(|opt| opt.is_some())
            .count()
            != 1
        {
            return Self::default();
        }
        if let Some(pattern) = regex {
            if !pattern.is_ascii() {
                return Self::default();
            }
            let Ok(hir) = regex_syntax::ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .case_insensitive(ci)
                .build()
                .parse(pattern)
            else {
                return Self::default();
            };
            return Self {
                unicode_folding: unicode_engine(pattern),
                line_min: line_min(&hir),
                ..Self::of(Shape::of(&hir).into_clauses())
            };
        }
        match exact.as_ref().or(substr.as_ref()).or(word.as_ref()) {
            Some(lit) if lit.is_ascii() => Self {
                unicode_folding: ci,
                ..Self::of(clauses_of(&[lit.as_bytes().to_ascii_lowercase()]))
            },
            _ => Self::default(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "a probe given a bad file should say so")]
mod tests {
    use super::*;
    use crate::types::AnalysisReport;

    #[test]
    fn required_grams_preserve_optional_and_alternate_matches() {
        for (pattern, text, ci) in [
            ("foo(?:bar)?", "foo", false),
            ("(?:afternoon|afterward)", "afterward", false),
            ("(?:cat|dog)", "dog", false),
            ("prefix[a-z]*end", "prefixend", false),
            ("ab+c", "ABBC", true),
            ("x*?", "", false),
            ("(?i:prefix)(?:abc|abd)postfix", "PREFIXabdpostfix", false),
            ("ab(?:x)?cd", "abxcd", false),
        ] {
            let rule = RequiredGrams::required(&None, &None, &None, &Some(pattern.into()), ci);
            assert!(
                Signature::ascii(text.as_bytes()).is_some_and(|s| s.accepts(&rule)),
                "{pattern} on {text}"
            );
        }
        let rule = RequiredGrams::required(&None, &Some("powershell".into()), &None, &None, false);
        assert!(Signature::ascii(b"xyz").is_some_and(|s| !s.accepts(&rule)));
    }

    /// A pattern that cannot match a newline needs a line at least as long as
    /// its shortest match; one that can, or whose length is open, needs none.
    #[test]
    fn a_match_needs_a_line_as_long_as_it() {
        let rule = |pattern: &str| {
            RequiredGrams::required(&None, &None, &None, &Some(pattern.into()), false)
        };
        let run = "ab".repeat(150);
        let one_line = format!("x = 1\ny = \"{run}\"\n");
        let broken = run
            .as_bytes()
            .chunks(100)
            .map(|c| String::from_utf8_lossy(c))
            .collect::<Vec<_>>()
            .join("\n");
        for (pattern, line_min) in [
            ("^[a-z]{200,}$", 200),
            ("[A-Za-z0-9+/]{2048,}={0,2}", 2048),
            ("(?i)[0-9a-f]{8}-[0-9a-f]{4}", 13),
            (r"\s{200,}", 0),
            ("[^x]{200,}", 0),
            ("(?s)a.{200,}", 0),
            ("a\nb{200}", 0),
            ("ab*", 1),
        ] {
            assert_eq!(rule(pattern).line_min, line_min, "{pattern}");
        }
        let long = rule("[a-z]{250,}");
        assert!(Signature::ascii(one_line.as_bytes()).is_some_and(|s| s.accepts(&long)));
        assert!(Signature::ascii(broken.as_bytes()).is_some_and(|s| !s.accepts(&long)));
        // A newline-crossing pattern is never turned away for its length.
        let crossing = rule(r"[a-z\s]{250,}");
        assert!(Signature::ascii(broken.as_bytes()).is_some_and(|s| s.accepts(&crossing)));
        // Lines are measured in each text on its own: two texts do not join.
        let mut two = Signature::ascii(&run.as_bytes()[..200]).expect("ascii");
        two.add_text(&run.as_bytes()[..200]);
        assert!(!two.accepts(&long));
    }

    /// Offline screen of the gate against real patterns and files: how often
    /// it spares a search, and that it never rejects a file the pattern
    /// matches. Run with:
    /// `PROBE_PATTERNS=<file> PROBE_DIR=<dir> cargo test -p cleave --release --lib gram_gate_probe -- --ignored --nocapture`
    #[test]
    #[ignore = "offline probe: set PROBE_PATTERNS and PROBE_DIR"]
    fn gram_gate_probe() {
        let (Ok(patterns), Ok(dir)) = (
            std::env::var("PROBE_PATTERNS").map(std::fs::read_to_string),
            std::env::var("PROBE_DIR"),
        ) else {
            return;
        };
        let patterns = patterns.expect("PROBE_PATTERNS names a readable file");
        let files: Vec<(Vec<u8>, Signature)> = walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .filter_map(|entry| std::fs::read(entry.path()).ok())
            .filter_map(|bytes| {
                Signature::source(&bytes, &AnalysisReport::new(Default::default()))
                    .map(|signature| (bytes, signature))
            })
            .collect();
        let (mut pairs, mut spared, mut ungated) = (0usize, 0usize, 0usize);
        // Bytes searched and bytes spared, by file size: under 64 KiB, under
        // 1 MiB, and the rest.
        let mut bytes_by_size = [(0usize, 0usize); 3];
        let size_class = |len: usize| usize::from(len >= 64 << 10) + usize::from(len >= 1 << 20);
        for pattern in patterns.lines() {
            let rule = RequiredGrams::required(&None, &None, &None, &Some(pattern.into()), false);
            // The raw matcher's byte engine; the other one is not screened.
            if unicode_engine(pattern) {
                continue;
            }
            let Ok(regex) = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .multi_line(true)
                .build()
            else {
                continue;
            };
            let rejected = files
                .iter()
                .filter(|(bytes, signature)| {
                    let reject = !signature.accepts(&rule);
                    assert!(
                        !(reject && regex.is_match(bytes)),
                        "{pattern} matches a file its grams reject"
                    );
                    let (searched, skipped) = &mut bytes_by_size[size_class(bytes.len())];
                    *searched += bytes.len();
                    *skipped += if reject { bytes.len() } else { 0 };
                    reject
                })
                .count();
            pairs += files.len();
            spared += rejected;
            ungated += usize::from(rule.clauses == 0);
            println!("{rejected}\t{}\t{pattern}", rule.clauses);
        }
        println!(
            "SUMMARY files={} pairs={pairs} spared={spared} ungated_patterns={ungated}",
            files.len()
        );
        for (label, (searched, skipped)) in ["<64K", "<1M", ">=1M"].iter().zip(bytes_by_size) {
            println!(
                "BYTES {label} searched_mb={} spared_mb={}",
                searched >> 20,
                skipped >> 20
            );
        }
    }

    /// Text a pattern cannot match is turned away by what its branches,
    /// short literals, small classes and counted repetitions have in common;
    /// text it does match never is.
    #[test]
    fn short_literals_classes_and_branches_reject_text_that_cannot_match() {
        let possible = |pattern: &str, input: &str| {
            let rule = RequiredGrams::required(&None, &None, &None, &Some(pattern.into()), false);
            Signature::ascii(input.as_bytes()).is_none_or(|s| s.accepts(&rule))
        };
        for (pattern, matching, impossible) in [
            // Branches of different lengths share no gram, yet one must occur.
            (
                r"\b(nc|ncat|netcat)\b\s+\S+\s*\|\s*(ba)?sh\b",
                "nc host | bash",
                "import os\nprint(1)",
            ),
            // A two-byte literal and a lone byte are grams too.
            (r"(?i)\b7z[ar]?(\.exe)?\s+x\b", "7Z.EXE x", "tar xf archive"),
            (r"\w+\s*\^=\s*\w+", "key ^= pad", "key = pad"),
            // A counted repetition of one byte is a run of it.
            (r"_{10,50}=", "____________=1", "__init__ = 1"),
            // A small class spells out its members.
            (
                r"(?i)[\\/](Temp|Tmp)[\\/]",
                r"C:\TEMP\x",
                "attempt/template",
            ),
            (r"%0[3-8]d|:0>[3-8]\}", "{:0>5}", "x = 100 % 3"),
            // Optional parts are skipped, not required.
            (r"colou?r:\s*red", "color: red", "colder"),
            (r#"(?i)(%22|")\s*(%5D|\])"#, "%22%5d", "plain"),
        ] {
            assert!(
                possible(pattern, matching),
                "{pattern} must admit {matching:?}"
            );
            assert!(
                !possible(pattern, impossible),
                "{pattern} should reject {impossible:?}"
            );
        }
        // No gram is required of a pattern that can match with no fixed text:
        // any line long enough to hold a match is admitted.
        let line = " ".repeat(300);
        for pattern in [r"[A-Za-z0-9+/]{200,}={0,2}", r"\w+\W\w+", r"(a|\w)*", r"x?"] {
            assert!(possible(pattern, &line), "{pattern}");
        }
    }

    /// An AST condition is turned away by what its matches must leave in the
    /// source, and only by text that is in the source as written: a callee
    /// name is joined from identifiers the source may spread over lines.
    #[test]
    fn ast_conditions_require_only_what_the_source_spells() {
        use crate::composite_rules::condition::TreeSitterQuery;
        let possible = |q: &TreeSitterQuery, source: &str| {
            let rule = RequiredGrams::of_ast(q);
            Signature::ascii(source.as_bytes()).is_none_or(|s| s.accepts(&rule))
        };
        let simple =
            |exact: Option<&str>, substr: Option<&str>, regex: Option<&str>| TreeSitterQuery {
                kind: Some("call".into()),
                exact: exact.map(Into::into),
                substr: substr.map(Into::into),
                regex: regex.map(Into::into),
                ..Default::default()
            };
        let exact = simple(Some("os.system"), None, None);
        assert!(possible(&exact, "import os\nos.system('id')"));
        assert!(
            possible(&exact, "os \\n  .system('id')"),
            "a callee joined across lines"
        );
        assert!(!possible(&exact, "import os\nos.getcwd()"));

        let substr = simple(None, Some("urlretrieve"), None);
        assert!(possible(&substr, "urllib.request.urlretrieve(u, p)"));
        assert!(!possible(&substr, "urllib.request.urlopen(u)"));

        let regex = simple(None, None, Some(r"subprocess\.(run|call|Popen)\("));
        assert!(
            possible(&regex, "subprocess\n.Popen(cmd)"),
            "a callee joined across lines"
        );
        assert!(!possible(&regex, "os.system(cmd)"));
        // All this pattern spells crosses a dot, which the source need not.
        let dotted = simple(None, None, Some(r"^a\.b$"));
        assert!(possible(&dotted, "a\n.b()"));

        // A query requires nothing until a process that compiled it has
        // recorded its literals. The memo outlives the process in the test
        // cache, so the query that shows this is one nothing ever records.
        let query = |name: &str| TreeSitterQuery {
            query: Some(format!(r#"((identifier) @n (#eq? @n "{name}"))"#)),
            ..Default::default()
        };
        assert!(possible(&query("zzgramnever"), "print(1)"));
        // These are the literals this query derives.
        let query = query("zzgramprobe");
        crate::capabilities::derivation_memo::record_ast_literals(
            query.query.as_deref().unwrap_or_default(),
            vec![vec![vec![(b"zzgramprobe".to_vec(), false)]]],
        );
        assert!(possible(&query, "zzgramprobe = 1"));
        assert!(!possible(&query, "print(1)"));
    }

    /// A clause promises one of its grams, so it is kept whole or dropped:
    /// trimming it to fit would reject text that has only a trimmed gram.
    #[test]
    fn a_clause_too_large_to_keep_is_dropped_whole() {
        let words: Vec<String> = (b'a'..=b'z')
            .map(|c| format!("{0}{0}{0}", c as char))
            .collect();
        let pattern = format!(r"({})\s+end", words.join("|"));
        let rule = RequiredGrams::required(&None, &None, &None, &Some(pattern), false);
        for word in &words {
            let text = format!("{word} end");
            assert!(
                Signature::ascii(text.as_bytes()).is_some_and(|s| s.accepts(&rule)),
                "{word}"
            );
        }
        assert!(Signature::ascii(b"zzz stop").is_some_and(|s| !s.accepts(&rule)));
    }

    #[test]
    fn alternatives_require_one_prefix_and_never_drop_an_unrepresented_branch() {
        let possible = |pattern: &str, input: &str| {
            let rule = RequiredGrams::required(&None, &None, &None, &Some(pattern.into()), false);
            Signature::ascii(input.as_bytes()).is_none_or(|s| s.accepts(&rule))
        };
        assert!(!possible("cat|dog", "no pets"));
        assert!(possible("cat|dog", "bulldog"));
        assert!(possible("cat|x", "x"));
        assert!(possible("cat|", ""));
        // The fixed-size requirement cannot hold every distinct prefix here.
        let words = (0..16).map(|i| format!("{i:02}z")).collect::<Vec<_>>();
        let pattern = words.join("|");
        assert!(words.iter().all(|word| possible(&pattern, word)));
    }

    #[test]
    fn literal_signature_uses_extracted_values_and_defers_on_unicode() {
        use crate::composite_rules::{FileType, context::EvaluationContext};
        let mut report = AnalysisReport::new(Default::default());
        let required = RequiredGrams::required(&Some("ab".into()), &None, &None, &None, false);
        for value in ["a", "b"] {
            report.strings.push(crate::types::StringInfo {
                value: value.into(),
                offset: None,
                encoding: String::new(),
                string_type: None,
                section: Some("ast".into()),
                encoding_chain: Vec::new(),
                fragments: None,
            });
        }
        let signature = |report: &AnalysisReport| {
            let ctx = EvaluationContext::test_only_new(report, b"ab", FileType::Python);
            Signature::literals(&ctx)
        };
        assert!(signature(&report).is_some_and(|s| !s.accepts(&required)));
        report.strings[0].value = "AB".into();
        assert!(signature(&report).is_some_and(|s| s.accepts(&required)));
        report.strings[1].value = "K".into();
        assert!(signature(&report).is_none());
    }

    #[test]
    fn decoded_matches_and_unicode_folding_pass_the_gate() {
        let mut report = AnalysisReport::new(Default::default());
        report.strings.push(crate::types::StringInfo {
            value: "unique".into(),
            offset: None,
            encoding: String::new(),
            string_type: None,
            section: None,
            encoding_chain: vec!["base64".into()],
            fragments: None,
        });
        let rule = RequiredGrams::required(&Some("unique".into()), &None, &None, &None, false);
        assert!(Signature::source(b"dW5pcXVl", &report).is_some_and(|s| s.accepts(&rule)));
        let folded = RequiredGrams::required(&Some("K".into()), &None, &None, &None, true);
        assert!(Signature::ascii(b"k").is_some_and(|s| s.accepts(&folded)));
        // The Kelvin sign lowercases to `k`, which its bytes do not hold:
        // text that is not ASCII never turns away a condition that folds
        // case as Unicode does. A regex folds within ASCII alone.
        let kelvin = Signature::source("\u{212A}".as_bytes(), &report);
        assert!(kelvin.as_ref().is_some_and(|s| s.accepts(&folded)));
        let regex = RequiredGrams::required(&None, &None, &None, &Some("(?i)kelvin".into()), false);
        assert!(kelvin.is_some_and(|s| !s.accepts(&regex)));
        assert!(
            Signature::source("caf\u{e9} KELVIN".as_bytes(), &report)
                .is_some_and(|s| s.accepts(&regex))
        );
        // Bytes that are not UTF-8 are searched through a view with other bytes.
        assert!(Signature::source(b"kelvin \xff", &report).is_none());
    }
}
