//! Necessary bytes and adjacent byte pairs for short sources and target paths.
use crate::composite_rules::{Condition, TraitDefinition};
use regex_syntax::hir::{Hir, HirKind};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Signature([u64; 4]);

#[derive(Clone, Copy, Debug)]
pub(super) enum Requirement {
    Content(Signature),
    Path(Signature),
    None,
}

impl Requirement {
    pub(super) fn of(rule: &TraitDefinition) -> Self {
        match &rule.r#if {
            Condition::Raw(q) => Self::Content(Signature::required(
                &q.exact,
                &q.substr,
                &q.word,
                &q.regex,
                q.case_insensitive,
            )),
            Condition::Text(q) if !q.exclude_html_comments && !q.exclude_comments => Self::Content(
                Signature::required(&q.exact, &q.substr, &q.word, &q.regex, q.case_insensitive),
            ),
            Condition::Path(q) => Self::Path(Signature::required(
                &q.exact,
                &q.substr,
                &None,
                &q.regex,
                q.case_insensitive,
            )),
            _ => Self::None,
        }
    }

    pub(super) fn accepts(self, source: Option<&Signature>, path: Option<&Signature>) -> bool {
        match self {
            Self::Content(bits) => source.is_none_or(|s| s.accepts(bits)),
            Self::Path(bits) => path.is_none_or(|s| s.accepts(bits)),
            Self::None => true,
        }
    }
}

impl Signature {
    fn mark(&mut self, hash: usize) {
        let bit = hash & 255;
        self.0[bit / 64] |= 1 << (bit % 64);
    }

    fn add_text(&mut self, bytes: &[u8]) {
        let mut prev = None;
        for &byte in bytes {
            let byte = usize::from(byte.to_ascii_lowercase());
            self.mark(byte);
            if let Some(first) = prev {
                self.mark(first * 31 + byte);
            }
            prev = Some(byte);
        }
    }

    pub(super) fn accepts(self, required: Self) -> bool {
        self.0
            .iter()
            .zip(required.0)
            .all(|(have, need)| need & !have == 0)
    }

    pub(super) fn source(data: &[u8], report: &crate::types::AnalysisReport) -> Option<Self> {
        let mut signature = Self::ascii(data)?;
        for s in report
            .strings
            .iter()
            .filter(|s| !s.encoding_chain.is_empty())
        {
            if !s.value.is_ascii() || s.value.len() > 4096 {
                return None;
            }
            signature.add_text(s.value.as_bytes());
        }
        Some(signature)
    }

    pub(super) fn ascii(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 4096 || !bytes.is_ascii() {
            return None;
        }
        let mut signature = Self::default();
        signature.add_text(bytes);
        Some(signature)
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
                .map(|hir| Self::hir(&hir))
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

    fn hir(hir: &Hir) -> Self {
        let mut result = Self::default();
        match hir.kind() {
            HirKind::Literal(lit) => result.add_text(&lit.0),
            HirKind::Capture(cap) => return Self::hir(&cap.sub),
            HirKind::Repetition(rep) if rep.min > 0 => return Self::hir(&rep.sub),
            HirKind::Concat(terms) => {
                for term in terms {
                    let bits = Self::hir(term);
                    for (out, v) in result.0.iter_mut().zip(bits.0) {
                        *out |= v;
                    }
                }
            }
            HirKind::Alternation(terms) => {
                let mut terms = terms.iter().map(Self::hir);
                if let Some(first) = terms.next() {
                    result = first;
                    for bits in terms {
                        for (out, v) in result.0.iter_mut().zip(bits.0) {
                            *out &= v;
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
    fn required_bytes_preserve_optional_and_alternate_matches() {
        for (pattern, text, ci) in [
            ("foo(?:bar)?", "foo", false),
            ("(?:afternoon|afterward)", "afterward", false),
            ("(?:cat|dog)", "dog", false),
            ("prefix[a-z]*end", "prefixend", false),
            ("ab+c", "ABBC", true),
            ("x*?", "", false),
        ] {
            let rule = Signature::required(&None, &None, &None, &Some(pattern.into()), ci);
            assert!(
                Signature::ascii(text.as_bytes()).is_some_and(|s| s.accepts(rule)),
                "{pattern} on {text}"
            );
        }
        let rule = Signature::required(&None, &Some("powershell".into()), &None, &None, false);
        assert!(Signature::ascii(b"xyz").is_some_and(|s| !s.accepts(rule)));
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
        let rule = Signature::required(&Some("unique".into()), &None, &None, &None, false);
        assert!(Signature::source(b"dW5pcXVl", &report).is_some_and(|s| s.accepts(rule)));
        let folded = Signature::required(&Some("K".into()), &None, &None, &None, true);
        assert!(Signature::ascii(b"k").is_some_and(|s| s.accepts(folded)));
        assert!(Signature::source("é".as_bytes(), &report).is_none());
    }
}
