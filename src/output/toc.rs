//! `--format toc`: a table of contents for each file — one row per finding,
//! grouped under namespace pills, with a description and evidence column.

use std::collections::{BTreeMap, HashSet};

use colored::Colorize;

use super::{
    aggregate_findings_by_directory, display_file_type, display_path, file_rule, terminal_width,
    terse_description, truncate_with_ellipsis,
};
use crate::theme;
use crate::types::traits_findings::finding_spans;
use crate::types::{AnalysisReport, ContextLine, Criticality, Finding};

/// Namespace sections, declared in render order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Namespace {
    WellKnown,
    Objectives,
    MicroBehaviors,
    Metadata,
    ThirdParty,
}

impl Namespace {
    fn from_trait_id(id: &str) -> Option<Self> {
        match id.split('/').next()? {
            "well-known" => Some(Self::WellKnown),
            "objectives" => Some(Self::Objectives),
            "micro-behaviors" => Some(Self::MicroBehaviors),
            "metadata" => Some(Self::Metadata),
            "third_party" | "third-party" => Some(Self::ThirdParty),
            _ => None,
        }
    }

    /// Section label as a muted pill — bold white on a dark background whose
    /// hue encodes the namespace.
    fn pill(self) -> colored::ColoredString {
        let (name, r, g, b) = match self {
            Self::WellKnown => ("WELL-KNOWN", 95, 0, 0),
            Self::Objectives => ("OBJECTIVES", 95, 0, 95),
            Self::MicroBehaviors => ("MICRO-BEHAVIORS", 0, 0, 95),
            Self::Metadata => ("METADATA", 48, 48, 48),
            Self::ThirdParty => ("THIRD-PARTY", 120, 56, 0),
        };
        format!(" {name} ").bold().white().on_truecolor(r, g, b)
    }
}

/// The trait id without its namespace: `objectives/c2/http/beacon` → `c2/http/beacon`.
fn short_trait_id(id: &str) -> &str {
    match id.split_once('/') {
        Some((ns, rest)) if Namespace::from_trait_id(ns).is_some() => rest,
        _ => id,
    }
}

/// Bullet by criticality: `•` notable, `••` suspicious, `•••` hostile.
fn bullet(crit: Criticality) -> colored::ColoredString {
    match crit {
        Criticality::Hostile => theme::paint_hostile("•••"),
        Criticality::Suspicious => theme::paint_suspicious(" ••"),
        _ => theme::paint_baseline("  •"),
    }
}

fn paint(text: &str, crit: Criticality) -> colored::ColoredString {
    match crit {
        Criticality::Hostile => theme::paint_hostile(text),
        Criticality::Suspicious => theme::paint_suspicious(text),
        _ => theme::paint_baseline(text),
    }
}

/// What a finding matched: its evidence values, or — in a report read back from
/// JSON, which keeps byte spans rather than values — the context bytes its
/// spans cover, as text when they are text and as hex bytes otherwise.
fn evidence_values(finding: &Finding, context: &[ContextLine]) -> Vec<String> {
    if !finding.evidence.is_empty() {
        return finding.evidence.iter().map(|e| e.value.clone()).collect();
    }
    finding_spans(finding)
        .into_iter()
        .filter_map(|[offset, length]| {
            context.iter().find_map(|c| {
                let start = usize::try_from(offset.checked_sub(c.loc)?).ok()?;
                let end = start.checked_add(usize::try_from(length).ok()?)?;
                let bytes = c.data.get(start..end)?;
                Some(match std::str::from_utf8(bytes) {
                    Ok(text) if !text.chars().any(|c| c.is_control() && c != '\n') => {
                        text.to_owned()
                    }
                    _ => bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                })
            })
        })
        .collect()
}

/// Up to five distinct evidence values with blank lines dropped. Comma-joined,
/// unless a value spans lines: then one value per line.
fn format_evidence(finding: &Finding, context: &[ContextLine]) -> String {
    let mut seen = HashSet::new();
    let values: Vec<String> = evidence_values(finding, context)
        .iter()
        .map(|v| {
            v.lines()
                .filter(|l| !l.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .filter(|v| !v.is_empty() && seen.insert(v.clone()))
        .take(5)
        .collect();
    let sep = if values.iter().any(|v| v.contains('\n')) {
        "\n"
    } else {
        ", "
    };
    values.join(sep)
}

/// Render every file with notable-or-higher findings as a table of contents.
#[must_use]
pub fn format_toc(report: &AnalysisReport) -> String {
    // Columns beyond the trait id: bullet(3) + space + two 2-space gutters.
    const OVERHEAD: usize = 8;
    // Room kept for evidence: descriptions truncate first, since they are often
    // paraphrasable from the trait id.
    const MIN_EVIDENCE_WIDTH: usize = 24;
    // Beyond this, a multi-line value ends with a `…` line.
    const MAX_EVIDENCE_LINES: usize = 4;

    let mut output = String::new();
    let term_width = terminal_width();

    for file in &report.files {
        // Components show only when a notable-or-higher finding uses them.
        let referenced: HashSet<&str> = file
            .findings
            .iter()
            .filter(|f| f.crit >= Criticality::Notable && f.conf >= 0.5)
            .flat_map(|f| f.trait_refs.iter().map(crate::types::Istr::as_str))
            .collect();
        let shown: Vec<Finding> = file
            .findings
            .iter()
            .filter(|f| {
                f.conf >= 0.5
                    && (f.crit >= Criticality::Notable
                        || (f.crit == Criticality::Component && referenced.contains(f.id.as_str())))
            })
            .cloned()
            .collect();
        let aggregated = aggregate_findings_by_directory(&shown);

        let mut sections: BTreeMap<Namespace, Vec<&Finding>> = BTreeMap::new();
        for finding in &aggregated {
            if let Some(ns) = Namespace::from_trait_id(&finding.id) {
                sections.entry(ns).or_default().push(finding);
            }
        }
        if sections.is_empty() {
            continue;
        }
        for findings in sections.values_mut() {
            findings.sort_unstable_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));
        }

        // Column widths span every section so the file reads as one table.
        let rows = || sections.values().flatten();
        let trait_width = rows()
            .map(|f| short_trait_id(&f.id).len())
            .max()
            .unwrap_or(20);
        let desc_width = rows()
            .map(|f| terse_description(&f.desc).len())
            .max()
            .unwrap_or(30)
            .min(term_width.saturating_sub(OVERHEAD + trait_width + MIN_EVIDENCE_WIDTH));
        let evidence_width = term_width.saturating_sub(OVERHEAD + trait_width + desc_width);
        let evidence_indent = " ".repeat(OVERHEAD + trait_width + desc_width);

        let file_type = display_file_type(&file.file_type);
        let type_formula = match crate::formula::of(&file.findings) {
            Some(formula) if !formula.is_empty() => format!("{file_type} • {formula}"),
            _ => file_type,
        };
        let indent = "  ".repeat(file.depth as usize);
        output.push_str(&format!(
            "{indent}{}  {}\n",
            display_path(file).bright_white().bold(),
            type_formula.bright_black()
        ));
        output.push_str(&format!(
            "{indent}{}\n",
            file_rule(term_width.saturating_sub(indent.len()))
        ));

        for (i, (ns, findings)) in sections.iter().enumerate() {
            if i > 0 {
                output.push('\n');
            }
            output.push_str(&format!("{}\n", ns.pill()));

            for finding in findings {
                let bullet = bullet(finding.crit);
                let trait_id = short_trait_id(&finding.id);
                let evidence = format_evidence(finding, &file.context);
                let lines: Vec<&str> = evidence.lines().collect();
                if lines.is_empty() {
                    output.push_str(&format!("{bullet} {trait_id}\n"));
                    continue;
                }
                let desc = truncate_with_ellipsis(&terse_description(&finding.desc), desc_width);
                for (j, line) in lines.iter().take(MAX_EVIDENCE_LINES).enumerate() {
                    let value = paint(&truncate_with_ellipsis(line, evidence_width), finding.crit);
                    if j == 0 {
                        output.push_str(&format!(
                            "{bullet} {trait_id:trait_width$}  {desc:desc_width$}  {value}\n"
                        ));
                    } else {
                        output.push_str(&format!("{evidence_indent}{value}\n"));
                    }
                }
                if lines.len() > MAX_EVIDENCE_LINES {
                    output.push_str(&format!("{evidence_indent}{}\n", paint("…", finding.crit)));
                }
            }
        }
        // A blank line separates this file from the next.
        output.push('\n');
    }
    output
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::output::tests::strip_ansi;
    use crate::types::{Evidence, FileAnalysis, FindingKind, TargetInfo};

    fn finding(id: &str, crit: Criticality, values: &[&str]) -> Finding {
        let mut f = Finding::new(id, FindingKind::Indicator, "A description", 0.9);
        f.crit = crit;
        f.evidence = values
            .iter()
            .map(|v| Evidence {
                method: "yara".into(),
                source: "test".into(),
                value: (*v).into(),
                ..Default::default()
            })
            .collect();
        f
    }

    fn report(findings: Vec<Finding>) -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo::default());
        report.files.push(FileAnalysis {
            path: "/test/sample.bin".into(),
            file_type: "elf".into(),
            findings,
            ..FileAnalysis::default()
        });
        report
    }

    #[test]
    fn evidence_is_deduped_comma_joined_and_capped() {
        let f = finding(
            "objectives/x",
            Criticality::Notable,
            &["a", "b", "a", "", "c", "d", "e", "f"],
        );
        assert_eq!(format_evidence(&f, &[]), "a, b, c, d, e");
        let none = finding("objectives/x", Criticality::Notable, &[]);
        assert_eq!(format_evidence(&none, &[]), "");
    }

    #[test]
    fn multi_line_evidence_keeps_one_value_per_line() {
        let f = finding(
            "objectives/x",
            Criticality::Notable,
            &["one\n\n two", "three"],
        );
        assert_eq!(format_evidence(&f, &[]), "one\n two\nthree");
    }

    #[test]
    fn spans_resolve_against_context_when_values_are_absent() {
        // A report read back from JSON keeps spans, not values.
        let mut f = finding("objectives/x", Criticality::Notable, &[]);
        f.precomputed_spans = Some(vec![[14, 4], [500, 3], [40, 3]]);
        let context = [
            ContextLine {
                loc: 10,
                line: Some(1),
                col: Some(1),
                data: b"let eval = 1;\n".to_vec(),
            },
            ContextLine {
                loc: 40,
                line: None,
                col: None,
                data: vec![0x8B, 0x44, 0x00, 0xCD],
            },
        ];
        assert_eq!(format_evidence(&f, &context), "eval, 8B 44 00");
    }

    #[test]
    fn empty_report_renders_nothing() {
        assert!(format_toc(&report(vec![])).is_empty());
        let quiet = finding("objectives/x", Criticality::Baseline, &["v"]);
        assert!(format_toc(&report(vec![quiet])).is_empty());
    }

    #[test]
    fn sections_render_in_namespace_order_with_short_ids() {
        let output = strip_ansi(&format_toc(&report(vec![
            finding(
                "third_party/Sekoia/Backdoor/Bpfdoor",
                Criticality::Hostile,
                &["$op1"],
            ),
            finding("micro-behaviors/fs/chown", Criticality::Notable, &["chown"]),
            finding(
                "objectives/c2/http/beacon",
                Criticality::Suspicious,
                &["GET /x"],
            ),
        ])));
        let order: Vec<usize> = ["OBJECTIVES", "MICRO-BEHAVIORS", "THIRD-PARTY"]
            .iter()
            .map(|label| output.find(label).expect("section present"))
            .collect();
        assert!(order.is_sorted(), "{output}");
        assert!(output.contains("Sekoia/Backdoor/Bpfdoor"));
        assert!(!output.contains("third_party/Sekoia"));
        assert!(output.contains(" •• c2/http/beacon"));
        assert!(output.contains("GET /x"));
        assert!(output.starts_with("/test/sample.bin  ELF"));
    }

    #[test]
    fn long_multi_line_evidence_ends_with_an_ellipsis_row() {
        let output = strip_ansi(&format_toc(&report(vec![finding(
            "objectives/x/y",
            Criticality::Notable,
            &["1\n2\n3\n4\n5"],
        )])));
        assert!(output.contains("4\n"));
        assert!(!output.contains("5\n"));
        assert!(output.trim_end().ends_with('…'), "{output}");
    }
}
