//! Short ASCII byte sequences used to reject impossible raw, text, path and literal matches.
//! Hash collisions only admit extra candidates for the full matcher.
use crate::composite_rules::{Condition, TraitDefinition};
use regex_syntax::hir::{Hir, HirKind};

#[derive(Debug)]
pub(super) struct Signature([u64; 1024]);

#[derive(Clone, Copy, Default, Debug)]
pub(super) struct RequiredGrams {
    bits: [u16; 12],
    len: u8,
    /// Each bit represents a possible prefix when the branches have no common gram.
    alternatives: bool,
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
        let mut folded = bytes.iter().map(u8::to_ascii_lowercase);
        let Some(mut a) = folded.next() else { return };
        mark(&mut self.0, u16::from(a));
        let Some(mut b) = folded.next() else { return };
        mark(&mut self.0, u16::from(b));
        mark(&mut self.0, pair(a, b));
        for c in folded {
            mark(&mut self.0, u16::from(c));
            mark(&mut self.0, pair(b, c));
            mark(&mut self.0, trigram(a, b, c));
            (a, b) = (b, c);
        }
    }

    fn accepts(&self, required: &RequiredGrams) -> bool {
        let contains = |&id: &u16| {
            let i = usize::from(id);
            self.0[i / 64] & (1 << (i % 64)) != 0
        };
        if required.alternatives {
            required.slice().iter().any(contains)
        } else {
            required.slice().iter().all(contains)
        }
    }

    pub(super) fn source(data: &[u8], report: &crate::types::AnalysisReport) -> Option<Self> {
        let mut signature = Self::ascii(data)?;
        for s in report
            .strings
            .iter()
            .filter(|s| !s.encoding_chain.is_empty())
        {
            if !s.value.is_ascii() || s.value.len() > 1024 * 1024 {
                return None;
            }
            signature.add_text(s.value.as_bytes());
        }
        Some(signature)
    }

    /// Use the same decoded values as the literal evaluator. Each value starts
    /// a fresh sequence so adjacent literals cannot contribute a shared gram.
    pub(super) fn literals(
        ctx: &crate::composite_rules::context::EvaluationContext<'_>,
    ) -> Option<Self> {
        let mut sig = Self([0; 1024]);
        let mut remaining: usize = 4 * 1024 * 1024;
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
        if bytes.len() > 4 * 1024 * 1024 || !bytes.is_ascii() {
            return None;
        }
        let mut signature = Self([0; 1024]);
        signature.add_text(bytes);
        Some(signature)
    }
}

impl RequiredGrams {
    fn slice(&self) -> &[u16] {
        &self.bits[..usize::from(self.len)]
    }

    fn insert(&mut self, id: u16) {
        if usize::from(self.len) < self.bits.len() && !self.slice().contains(&id) {
            self.bits[usize::from(self.len)] = id;
            self.len += 1;
        }
    }

    fn add_text(&mut self, bytes: &[u8]) {
        match bytes {
            [a] => self.insert(u16::from(a.to_ascii_lowercase())),
            [a, b] => self.insert(pair(a.to_ascii_lowercase(), b.to_ascii_lowercase())),
            _ => {}
        }
        let count = bytes.len().saturating_sub(2);
        let stride = count.div_ceil(self.bits.len()).max(1);
        for bytes in bytes.windows(3).step_by(stride) {
            self.insert(trigram(
                bytes[0].to_ascii_lowercase(),
                bytes[1].to_ascii_lowercase(),
                bytes[2].to_ascii_lowercase(),
            ));
        }
    }

    fn folded_byte(hir: &Hir) -> Option<u8> {
        match hir.kind() {
            HirKind::Literal(lit) if lit.0.len() == 1 => Some(lit.0[0].to_ascii_lowercase()),
            HirKind::Class(regex_syntax::hir::Class::Bytes(class)) => {
                let first = class.ranges().first()?.start().to_ascii_lowercase();
                class
                    .ranges()
                    .iter()
                    .all(|r| r.start() == r.end() && r.start().to_ascii_lowercase() == first)
                    .then_some(first)
            }
            _ => None,
        }
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
            return regex_syntax::ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .case_insensitive(ci)
                .build()
                .parse(pattern)
                .map(|hir| Self::for_regex(&hir))
                .unwrap_or_default();
        }
        let mut signature = Self::default();
        if let Some(lit) = exact.as_ref().or(substr.as_ref()).or(word.as_ref())
            && lit.is_ascii()
        {
            signature.add_text(lit.as_bytes());
        }
        signature
    }

    fn for_regex(hir: &Hir) -> Self {
        let mut result = Self::hir(hir);
        if result.len != 0 {
            return result;
        }
        // If branches have no common gram, a complete set of possible
        // prefixes can still reject a source that contains none of them.
        let seq = regex_syntax::hir::literal::Extractor::new()
            .limit_total(32)
            .limit_literal_len(3)
            .extract(hir);
        let Some(literals) = seq.literals() else {
            return result;
        };
        for lit in literals {
            let [a, b, c, ..] = lit.as_bytes() else {
                return Self::default();
            };
            let id = trigram(
                a.to_ascii_lowercase(),
                b.to_ascii_lowercase(),
                c.to_ascii_lowercase(),
            );
            if usize::from(result.len) == result.bits.len() && !result.slice().contains(&id) {
                return Self::default();
            }
            result.insert(id);
        }
        result.alternatives = result.len != 0;
        result
    }

    fn hir(hir: &Hir) -> Self {
        let mut result = Self::default();
        match hir.kind() {
            HirKind::Literal(lit) => result.add_text(&lit.0),
            HirKind::Capture(cap) => return Self::hir(&cap.sub),
            HirKind::Repetition(rep) if rep.min > 0 => return Self::hir(&rep.sub),
            HirKind::Concat(terms) => {
                // Adjacent single-byte classes such as [aA][bB][cC] have one
                // spelling after folding. Optional or unknown terms break the run.
                let (mut first, mut second) = (None, None);
                for term in terms {
                    if let Some(byte) = Self::folded_byte(term) {
                        if let (Some(a), Some(b)) = (first, second) {
                            result.insert(trigram(a, b, byte));
                        }
                        (first, second) = (second, Some(byte));
                    } else {
                        (first, second) = (None, None);
                        for &id in Self::hir(term).slice() {
                            result.insert(id);
                        }
                    }
                }
            }
            HirKind::Alternation(terms) => {
                let mut children = terms.iter().map(Self::hir);
                if let Some(first) = children.next() {
                    result = first;
                    for child in children {
                        let previous = result;
                        result = Self::default();
                        for &id in previous.slice() {
                            if child.slice().contains(&id) {
                                result.insert(id);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        result
    }
}

#[cfg(test)]
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
        assert!(Signature::source("é".as_bytes(), &report).is_none());
    }
}
