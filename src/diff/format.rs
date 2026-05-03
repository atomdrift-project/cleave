//! Terminal renderer for diff reports.
//!
//! v1 keeps the layout deliberately small: a header, a per-scope summary
//! block, and a per-file detail section. Trait changes are grouped by
//! taxonomy top-level directory; KV changes by namespace. More elaborate
//! split views land after we have real data to design against.
use std::fmt::Write as _;

use colored::Colorize;

use crate::types::{AnalysisReport, Criticality};
use crate::types::{
    Changed, DiffReportV1, FileDiffEntry, FileStatus, KvChange, MetricChange, ScopeDiff,
    SectionChange, StringChange, SymbolChange, SymbolKind, TraitChange,
};

/// Render an `AnalysisReport` carrying a [`DiffReportV1`] as a colored
/// terminal-friendly string.
#[must_use]
pub fn format_terminal(report: &AnalysisReport) -> String {
    let Some(diff) = report.diff.as_ref() else {
        return "no diff present in report\n".to_string();
    };
    let mut out = String::new();
    write_header(&mut out, diff);
    write_scope_summary(&mut out, diff);
    write_file_details(&mut out, diff);
    out
}

fn write_header(out: &mut String, diff: &DiffReportV1) {
    let _ = writeln!(
        out,
        "{} {}  →  {}",
        "diff".bold().bright_cyan(),
        diff.old_root,
        diff.new_root
    );
    let s = &diff.summary;
    let _ = writeln!(
        out,
        "  files: {} changed, {} added, {} removed, {} unchanged",
        s.files_changed, s.files_added, s.files_removed, s.files_unchanged
    );
    let _ = writeln!(
        out,
        "  overall rate of change: {}",
        format_pct(s.overall_roc).bold()
    );
    out.push('\n');
}

fn write_scope_summary(out: &mut String, diff: &DiffReportV1) {
    let _ = writeln!(out, "{}", "scope rollup".bold().bright_white());
    let scopes = &diff.scopes;
    write_scope_line(out, "traits", scopes.traits.as_ref());
    write_scope_line(out, "metrics", scopes.metrics.as_ref());
    write_scope_line(out, "kv", scopes.kv.as_ref());
    write_scope_line(out, "symbols", scopes.symbols.as_ref());
    write_scope_line(out, "strings", scopes.strings.as_ref());
    write_scope_line(out, "sections", scopes.sections.as_ref());
    out.push('\n');
}

fn write_scope_line<T>(out: &mut String, name: &str, scope: Option<&ScopeDiff<T>>) {
    let Some(s) = scope else {
        return;
    };
    if s.is_empty() {
        return;
    }
    let trunc = if s.truncated { " (truncated)" } else { "" };
    let _ = writeln!(
        out,
        "  {:<9} {:>6} {:>6} {:>6}   {} of {}{}",
        name,
        format!("{}+", s.added.len()).bright_green(),
        format!("{}-", s.removed.len()).bright_red(),
        format!("{}~", s.changed.len()).bright_yellow(),
        format_pct(s.roc).bold(),
        s.old_count.max(s.new_count),
        trunc,
    );
}

fn write_file_details(out: &mut String, diff: &DiffReportV1) {
    if diff.files.is_empty() {
        return;
    }
    let _ = writeln!(out, "{}", "files".bold().bright_white());
    for file in &diff.files {
        write_file_block(out, file);
    }
}

fn write_file_block(out: &mut String, file: &FileDiffEntry) {
    let status = match file.status {
        FileStatus::Added => "ADDED".bright_green().bold(),
        FileStatus::Removed => "REMOVED".bright_red().bold(),
        FileStatus::Changed => "CHANGED".bright_yellow().bold(),
        FileStatus::Unchanged => "UNCHANGED".dimmed(),
    };
    let _ = writeln!(out, "\n  {} {}", status, file.path.bold());

    if let Some(t) = &file.scopes.traits {
        if t.has_changes() {
            write_traits(out, t);
        }
    }
    if let Some(m) = &file.scopes.metrics {
        if m.has_changes() {
            write_metrics(out, m);
        }
    }
    if let Some(kv) = &file.scopes.kv {
        if kv.has_changes() {
            write_kv(out, kv);
        }
    }
    if let Some(sy) = &file.scopes.symbols {
        if sy.has_changes() {
            write_symbols(out, sy);
        }
    }
    if let Some(st) = &file.scopes.strings {
        if st.has_changes() {
            write_strings(out, st);
        }
    }
    if let Some(se) = &file.scopes.sections {
        if se.has_changes() {
            write_sections(out, se);
        }
    }
}

// ----- per-scope renderers --------------------------------------------------

fn write_traits(out: &mut String, scope: &ScopeDiff<TraitChange>) {
    let _ = writeln!(out, "    {}  {}", "traits".bright_cyan(), roc_tag(scope));
    let groups = group_by_section(scope);
    for (section, items) in groups {
        let _ = writeln!(out, "      [{}]", section.bright_white());
        for (sign, t, _) in items {
            let _ = writeln!(
                out,
                "        {} {}  {}{}",
                sign,
                t.id,
                colorize_crit(crit_label(t.crit), t.crit),
                if t.desc.is_empty() {
                    String::new()
                } else {
                    format!("  {}", t.desc.dimmed())
                },
            );
        }
    }
}

/// Borrowed-rather-than-cloned `(sign_glyph, &TraitChange, originating_kind)`
/// triples grouped by taxonomy top-level (`well-known`, `objectives`, …).
type GroupedTraits<'a> = Vec<(
    String,
    Vec<(colored::ColoredString, &'a TraitChange, ChangeKind)>,
)>;

#[derive(Copy, Clone)]
enum ChangeKind {
    Added,
    Removed,
    Changed,
}

fn group_by_section(scope: &ScopeDiff<TraitChange>) -> GroupedTraits<'_> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<String, Vec<(colored::ColoredString, &TraitChange, ChangeKind)>> =
        BTreeMap::new();
    for t in &scope.added {
        groups.entry(t.trait_section.clone()).or_default().push((
            "+".bright_green(),
            t,
            ChangeKind::Added,
        ));
    }
    for t in &scope.removed {
        groups.entry(t.trait_section.clone()).or_default().push((
            "-".bright_red(),
            t,
            ChangeKind::Removed,
        ));
    }
    for c in &scope.changed {
        groups
            .entry(c.new.trait_section.clone())
            .or_default()
            .push(("~".bright_yellow(), &c.new, ChangeKind::Changed));
    }
    groups.into_iter().collect()
}

fn write_metrics(out: &mut String, scope: &ScopeDiff<MetricChange>) {
    let _ = writeln!(out, "    {}  {}", "metrics".bright_cyan(), roc_tag(scope));
    for c in &scope.added {
        let _ = writeln!(out, "      {} {} = {}", "+".bright_green(), c.path, c.value);
    }
    for c in &scope.removed {
        let _ = writeln!(out, "      {} {} = {}", "-".bright_red(), c.path, c.value);
    }
    for c in &scope.changed {
        let _ = writeln!(
            out,
            "      {} {} : {} → {}",
            "~".bright_yellow(),
            c.new.path,
            c.old.value.to_string().dimmed(),
            c.new.value.to_string().bright_white()
        );
    }
}

fn write_kv(out: &mut String, scope: &ScopeDiff<KvChange>) {
    let _ = writeln!(out, "    {}  {}", "kv".bright_cyan(), roc_tag(scope));
    use std::collections::BTreeMap;
    let mut by_ns: BTreeMap<String, Vec<(colored::ColoredString, &KvChange, Option<&KvChange>)>> =
        BTreeMap::new();
    for c in &scope.added {
        by_ns
            .entry(c.namespace.clone())
            .or_default()
            .push(("+".bright_green(), c, None));
    }
    for c in &scope.removed {
        by_ns
            .entry(c.namespace.clone())
            .or_default()
            .push(("-".bright_red(), c, None));
    }
    for Changed { old, new } in &scope.changed {
        by_ns
            .entry(new.namespace.clone())
            .or_default()
            .push(("~".bright_yellow(), new, Some(old)));
    }
    for (ns, items) in by_ns {
        let pretty = if ns.is_empty() {
            "(root)".to_string()
        } else {
            ns
        };
        let _ = writeln!(out, "      [{}]", pretty.bright_white());
        for (sign, new, old_opt) in items {
            match old_opt {
                None => {
                    let _ = writeln!(
                        out,
                        "        {} {} = {}",
                        sign,
                        new.path,
                        truncate(&new.value.to_string(), 200)
                    );
                }
                Some(old) => {
                    let _ = writeln!(
                        out,
                        "        {} {} : {} → {}",
                        sign,
                        new.path,
                        truncate(&old.value.to_string(), 100).dimmed(),
                        truncate(&new.value.to_string(), 100).bright_white()
                    );
                }
            }
        }
    }
}

fn write_symbols(out: &mut String, scope: &ScopeDiff<SymbolChange>) {
    let _ = writeln!(out, "    {}  {}", "symbols".bright_cyan(), roc_tag(scope));
    for c in &scope.added {
        let _ = writeln!(out, "      {} {}", "+".bright_green(), symbol_label(c));
    }
    for c in &scope.removed {
        let _ = writeln!(out, "      {} {}", "-".bright_red(), symbol_label(c));
    }
}

fn symbol_label(c: &SymbolChange) -> String {
    let kind = match c.kind {
        SymbolKind::Import => "import",
        SymbolKind::Export => "export",
    };
    match &c.library {
        Some(lib) => format!("[{kind}] {} @ {lib}", c.symbol),
        None => format!("[{kind}] {}", c.symbol),
    }
}

fn write_strings(out: &mut String, scope: &ScopeDiff<StringChange>) {
    let _ = writeln!(out, "    {}  {}", "strings".bright_cyan(), roc_tag(scope));
    for c in &scope.added {
        let _ = writeln!(
            out,
            "      {} {}",
            "+".bright_green(),
            truncate(&c.value, 200)
        );
    }
    for c in &scope.removed {
        let _ = writeln!(
            out,
            "      {} {}",
            "-".bright_red(),
            truncate(&c.value, 200)
        );
    }
}

fn write_sections(out: &mut String, scope: &ScopeDiff<SectionChange>) {
    let _ = writeln!(out, "    {}  {}", "sections".bright_cyan(), roc_tag(scope));
    for c in &scope.added {
        let _ = writeln!(out, "      {} {}", "+".bright_green(), section_label(c));
    }
    for c in &scope.removed {
        let _ = writeln!(out, "      {} {}", "-".bright_red(), section_label(c));
    }
    for Changed { old, new } in &scope.changed {
        let _ = writeln!(
            out,
            "      {} {} : size {} → {}, entropy {:.2} → {:.2}",
            "~".bright_yellow(),
            new.name,
            old.size,
            new.size,
            old.entropy,
            new.entropy
        );
    }
}

fn section_label(s: &SectionChange) -> String {
    let perms = s.permissions.as_deref().unwrap_or("???");
    format!(
        "{} (size {}, entropy {:.2}, perms {})",
        s.name, s.size, s.entropy, perms
    )
}

// ----- helpers --------------------------------------------------------------

fn roc_tag<T>(scope: &ScopeDiff<T>) -> colored::ColoredString {
    let n = format!(
        "{}+ {}- {}~  ({})",
        scope.added.len(),
        scope.removed.len(),
        scope.changed.len(),
        format_pct(scope.roc)
    );
    n.dimmed()
}

fn format_pct(roc: f32) -> String {
    format!("{:.1}%", roc * 100.0)
}

fn crit_label(c: Criticality) -> &'static str {
    match c {
        Criticality::Filtered => "filtered",
        Criticality::Component => "component",
        Criticality::Baseline => "baseline",
        Criticality::Notable => "notable",
        Criticality::Suspicious => "suspicious",
        Criticality::Hostile => "hostile",
    }
}

fn colorize_crit(text: &str, c: Criticality) -> colored::ColoredString {
    match c {
        Criticality::Hostile => text.bright_red().bold(),
        Criticality::Suspicious => text.bright_yellow(),
        Criticality::Notable => text.bright_blue(),
        Criticality::Baseline => text.bright_green(),
        Criticality::Component | Criticality::Filtered => text.dimmed(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::{
        DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, ScopeDiff, ScopeDiffs, ScopeRocs,
        StringChange, TargetInfo,
    };

    fn report_with_diff(diff: DiffReportV1) -> AnalysisReport {
        let mut r = AnalysisReport::new(TargetInfo::default());
        r.diff = Some(diff);
        r
    }

    #[test]
    fn empty_diff_renders_header() {
        let r = report_with_diff(DiffReportV1 {
            old_root: "old".into(),
            new_root: "new".into(),
            summary: DiffSummary::default(),
            scopes: ScopeDiffs::default(),
            files: vec![],
        });
        let out = format_terminal(&r);
        assert!(out.contains("diff"));
        assert!(out.contains("old"));
        assert!(out.contains("new"));
    }

    #[test]
    fn renders_added_string() {
        let r = report_with_diff(DiffReportV1 {
            old_root: "a".into(),
            new_root: "b".into(),
            summary: DiffSummary {
                files_changed: 1,
                overall_roc: 0.1,
                scope_roc: ScopeRocs {
                    strings: 0.1,
                    ..Default::default()
                },
                ..Default::default()
            },
            scopes: ScopeDiffs {
                strings: Some(ScopeDiff {
                    added: vec![StringChange {
                        value: "evil".into(),
                    }],
                    new_count: 10,
                    old_count: 9,
                    ..Default::default()
                }),
                ..Default::default()
            },
            files: vec![FileDiffEntry {
                path: "lib/foo.so".into(),
                status: FileStatus::Changed,
                scopes: ScopeDiffs {
                    strings: Some(ScopeDiff {
                        added: vec![StringChange {
                            value: "evil".into(),
                        }],
                        new_count: 10,
                        old_count: 9,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            }],
        });
        let out = format_terminal(&r);
        assert!(out.contains("lib/foo.so"));
        assert!(out.contains("evil"));
        assert!(out.contains("CHANGED"));
    }

    #[test]
    fn truncate_ellipsis() {
        assert_eq!(truncate("abc", 10), "abc");
        let t = truncate("abcdefghij", 5);
        assert!(t.ends_with('…'));
        assert_eq!(t.chars().count(), 5);
    }
}
