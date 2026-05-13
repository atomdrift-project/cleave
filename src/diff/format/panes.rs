//! Per-file detail panes — one per significant file. Each pane lists
//! only the scopes that actually changed, in the same order as the
//! ledger columns.

use std::fmt::Write as _;

use colored::Colorize;
use serde_json::Value;

use crate::types::{
    Changed, DiffReportV1, FileDiffEntry, FileStatus, KvChange, MetricChange, ScopeDiff,
    SectionChange, StringChange, SymbolChange, SymbolKind, TraitChange,
};

use super::ledger::sort_in_place;
use super::{
    count_badges, crit_dots, crit_rank, file_max_roc, format_value, is_significant_file,
    max_added_crit, paint_crit, paint_roc, paint_sign, short_id, truncate, WIDTH,
};
use crate::theme::{pill_scope, ScopePill};

pub(super) fn write(out: &mut String, diff: &DiffReportV1) {
    let mut files: Vec<&FileDiffEntry> = diff
        .files
        .iter()
        .filter(|f| f.status != FileStatus::Unchanged && is_significant_file(f))
        .collect();
    sort_in_place(&mut files);
    for file in files {
        write_pane(out, file);
        out.push('\n');
    }
}

/// Per-file detail pane. Multi-file mode prints a heading line with
/// the file-level criticality dot, max change-% across scopes, and
/// the file path, followed by a hairline rule. Single-file mode
/// (`<root>` placeholder) skips the heading entirely — the diff
/// header already names both versions and the per-scope lines carry
/// their own change-%, so the file-pane heading would just duplicate
/// what's right next to it.
fn write_pane(out: &mut String, file: &FileDiffEntry) {
    if file.path != "<root>" {
        let max_roc = file_max_roc(&file.scopes);
        let max_crit = max_added_crit(file);
        // Header layout: "{dots(3)}  {roc} changed  {path}". Compute the
        // visible-column offset of `path` so the formula line below can
        // hang under it without ANSI-stripping math at render time.
        let roc_str = format!("{:.1}%", max_roc * 100.0);
        let path_indent = 3 + 2 + roc_str.len() + 1 + "changed".len() + 2;
        let _ = writeln!(
            out,
            "{}  {} {}  {}",
            crit_dots(max_crit),
            paint_roc(max_roc).bold(),
            "changed".dimmed(),
            file.path.bold(),
        );
        write_formula_line(
            out,
            path_indent,
            file.old_formula.as_deref(),
            file.new_formula.as_deref(),
        );
        let _ = writeln!(
            out,
            "{}",
            crate::theme::paint_rule(crate::theme::RULE_CHAR.to_string().repeat(WIDTH))
        );
    }
    // Single-file mode (`<root>` placeholder) renders the formulas as part
    // of the header so they can align under the `old → new` filenames; see
    // `header::write`.

    if let Some(t) = file.scopes.traits.as_ref().filter(|s| s.has_changes()) {
        write_traits(out, t);
    }
    if let Some(m) = file.scopes.metrics.as_ref().filter(|s| s.has_changes()) {
        write_metrics(out, m);
    }
    if let Some(k) = file.scopes.kv.as_ref().filter(|s| s.has_changes()) {
        write_kv(out, k);
    }
    if let Some(y) = file.scopes.symbols.as_ref().filter(|s| s.has_changes()) {
        write_symbols(out, y);
    }
    if let Some(s) = file.scopes.strings.as_ref().filter(|s| s.has_changes()) {
        write_strings(out, s);
    }
    if let Some(e) = file.scopes.sections.as_ref().filter(|s| s.has_changes()) {
        write_sections(out, e);
    }
}

/// Hang the old/new behavioral fingerprints under the file path. Output is
/// suppressed when both sides are absent (added/removed pure-no-formula
/// case). Layout: `<indent>{old} → {new}` for changed files, or just one
/// side for added/removed.
fn write_formula_line(out: &mut String, indent: usize, old: Option<&str>, new: Option<&str>) {
    let pad = " ".repeat(indent);
    let arrow = "→".dimmed();
    let body = match (old, new) {
        (Some(o), Some(n)) => format!("{}  {}  {}", o.dimmed(), arrow, n.dimmed()),
        (Some(o), None) => format!("{}  {}", o.dimmed(), "(removed)".dimmed()),
        (None, Some(n)) => format!("{}  {}", "(added)".dimmed(), n.dimmed()),
        (None, None) => return,
    };
    let _ = writeln!(out, "{pad}{body}");
}

/// ` traits   98% changed  +10 -1` heading: scope name as a colored
/// pill (cool hue family, mirrors analyze's namespace pills), per-scope
/// change-% tinted by intensity with a dimmed `changed` label, then
/// add/remove/change badges. Caller has already gated on `has_changes`,
/// so at least one count will be present.
fn scope_heading<T>(scope_name: &str, scope_kind: ScopePill, scope: &ScopeDiff<T>) -> String {
    let view: crate::types::ScopeView<'_> = Some(scope).into();
    let bits = count_badges(view);
    let pill = pill_scope(scope_name, scope_kind);
    let roc_label = format!("{} {}", paint_roc(scope.roc), "changed".dimmed());
    if bits.is_empty() {
        format!("\n  {}  {}", pill, roc_label)
    } else {
        format!("\n  {}  {}  {}", pill, roc_label, bits.join(" "))
    }
}

// ---- traits -----------------------------------------------------------------

fn write_traits(out: &mut String, scope: &ScopeDiff<TraitChange>) {
    let _ = writeln!(out, "{}", scope_heading("traits", ScopePill::Traits, scope));

    // All trait changes, sorted by criticality desc then id. Baseline /
    // component still render — they're dimmed by `paint_crit` and the
    // dot column — so the reader sees the full picture instead of a
    // "N hidden" breadcrumb.
    let mut rows: Vec<(&'static str, &TraitChange)> = Vec::new();
    rows.extend(scope.added.iter().map(|t| ("+", t)));
    rows.extend(scope.removed.iter().map(|t| ("-", t)));
    rows.extend(scope.changed.iter().map(|c| ("~", &c.new)));
    rows.sort_by(|a, b| {
        crit_rank(b.1.crit)
            .cmp(&crit_rank(a.1.crit))
            // At equal criticality, prefer cleave-native traits over
            // `third_party/` (vendored YARA / external rules). Cleave's
            // own composites are typically more discriminating than
            // blanket third-party signatures, so they should anchor
            // the analyst's attention first.
            .then_with(|| {
                a.1.id
                    .starts_with("third_party/")
                    .cmp(&b.1.id.starts_with("third_party/"))
            })
            .then_with(|| a.1.id.cmp(&b.1.id))
    });

    for (sign, t) in &rows {
        let _ = writeln!(
            out,
            "    {} {} {}",
            crit_dots(t.crit),
            paint_sign(sign),
            paint_crit(short_id(&t.id), t.crit),
        );
    }
}

// ---- metrics ----------------------------------------------------------------

/// One row to render in the metrics pane, with the impact magnitude
/// pre-computed so we can sort by it and emit `+%` inline.
struct MetricRow<'a> {
    path: &'a str,
    /// `"+"` (added), `"-"` (removed), `"~"` (changed).
    sign: &'static str,
    /// Old value (only used when `sign == "~"`).
    old: Option<&'a Value>,
    /// New value (or, for `+`/`-`, the only value).
    new: &'a Value,
    /// Absolute relative change, used to rank within a group.  For
    /// adds/removes (one-sided) we use the magnitude of the value
    /// itself so big numbers lead.
    rank: f64,
}

fn write_metrics(out: &mut String, scope: &ScopeDiff<MetricChange>) {
    let _ = writeln!(
        out,
        "{}",
        scope_heading("metrics", ScopePill::Metrics, scope)
    );

    let mut rows: Vec<MetricRow<'_>> = Vec::new();
    for c in &scope.added {
        rows.push(MetricRow {
            path: &c.path,
            sign: "+",
            old: None,
            new: &c.value,
            rank: numeric_magnitude(&c.value),
        });
    }
    for c in &scope.removed {
        rows.push(MetricRow {
            path: &c.path,
            sign: "-",
            old: None,
            new: &c.value,
            rank: numeric_magnitude(&c.value),
        });
    }
    for Changed { old, new } in &scope.changed {
        rows.push(MetricRow {
            path: &new.path,
            sign: "~",
            old: Some(&old.value),
            new: &new.value,
            rank: relative_change_value(&old.value, &new.value).abs(),
        });
    }

    // Group by namespace prefix (`text.`, `binary.`, `identifiers.`,
    // `strings.`, `functions.`, `imports.`, `elf.`, …). Within each
    // group split into change-rows and add/remove-rows, ranking each
    // separately so a +N count addition doesn't wedge between two
    // huge percent changes that share the same numeric scale by
    // accident.
    let mut groups: std::collections::BTreeMap<&str, Vec<&MetricRow<'_>>> =
        std::collections::BTreeMap::new();
    for row in &rows {
        let ns = row.path.split_once('.').map_or(row.path, |(p, _)| p);
        groups.entry(ns).or_default().push(row);
    }
    // Group order: by max impact across all rows in the group, so
    // the namespace with the biggest mover leads.
    let mut ordered: Vec<(&str, Vec<&MetricRow<'_>>)> = groups.into_iter().collect();
    for (_, group) in &mut ordered {
        group.sort_by(|a, b| {
            b.rank
                .partial_cmp(&a.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    ordered.sort_by(|a, b| {
        let a_max = a.1.first().map_or(0.0, |r| r.rank);
        let b_max = b.1.first().map_or(0.0, |r| r.rank);
        b_max
            .partial_cmp(&a_max)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for (i, (ns, group)) in ordered.iter().enumerate() {
        if i > 0 {
            let _ = writeln!(out);
        }
        // Namespace sub-header — `strings:`, `text:`, … in dimmed
        // text. Anchors which group the rows below belong to without
        // forcing the reader to chase the metric prefix on every
        // line.
        let _ = writeln!(out, "    {}", format!("{ns}:").dimmed());

        // Within the group: percent-changes first (sorted by impact),
        // then `+` adds (sorted by absolute value), then `-` removes.
        // Each sub-block stays internally ranked; mixing scales
        // (relative-change vs raw-count) only confuses the eye.
        let (mut changes, mut adds, mut removes): (Vec<_>, Vec<_>, Vec<_>) =
            (Vec::new(), Vec::new(), Vec::new());
        for row in group {
            match row.sign {
                "~" => changes.push(*row),
                "+" => adds.push(*row),
                "-" => removes.push(*row),
                _ => {}
            }
        }
        for sub in [&mut changes, &mut adds, &mut removes] {
            sub.sort_by(|a, b| {
                b.rank
                    .partial_cmp(&a.rank)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        for row in changes.iter().chain(adds.iter()).chain(removes.iter()) {
            write_metric_row(out, row);
        }
    }
}

fn write_metric_row(out: &mut String, row: &MetricRow<'_>) {
    match row.sign {
        "+" | "-" => {
            let _ = writeln!(
                out,
                "    {} {:<40} = {}",
                paint_sign(row.sign),
                row.path,
                format_metric_value_with_units(row.path, row.new),
            );
        }
        "~" => {
            // `~` rows always carry an old value (set by the
            // construction loop). `unwrap_or` keeps clippy happy
            // and gives sensible output if the invariant is ever
            // violated upstream.
            let old = row.old.unwrap_or(row.new);
            let (up, down) = value_direction(old, row.new);
            let pct = relative_change_value(old, row.new) * 100.0;
            let pct_str = if pct.abs() < 0.01 {
                "      ".to_string() // pure float-rounding case
            } else {
                format!("{pct:>+4.0}%  ")
            };
            let _ = writeln!(
                out,
                "    {} {:<40} {} {} {} {}",
                numeric_direction(old, row.new),
                row.path,
                pct_str.dimmed(),
                format_metric_value_with_units(row.path, old).dimmed(),
                "→".dimmed(),
                paint_delta(format_metric_value_with_units(row.path, row.new), up, down,),
            );
        }
        _ => {}
    }
}

/// Magnitude of a JSON numeric value (`abs(f64)`), or 0 for non-numeric.
/// Used to rank added/removed entries so big counts and big sizes
/// surface above small ones.
fn numeric_magnitude(v: &Value) -> f64 {
    v.as_f64().map_or(0.0, f64::abs)
}

/// Relative change `(new - old) / |old|` for two JSON numeric values.
/// Falls back to the new-side magnitude when `old == 0` so a 0 → N
/// delta reads as 100% growth rather than infinity.  Returns 0 when
/// either side isn't numeric.
fn relative_change_value(old: &Value, new: &Value) -> f64 {
    let (Some(a), Some(b)) = (old.as_f64(), new.as_f64()) else {
        return 0.0;
    };
    if a == 0.0 && b == 0.0 {
        return 0.0;
    }
    let denom = if a.abs() > 0.0 { a.abs() } else { b.abs() };
    (b - a) / denom
}

/// Format a metric value with a human-readable unit annotation when
/// the field name suggests a byte-valued size.  Other numeric / string
/// values fall through to [`format_metric_value`].
fn format_metric_value_with_units(path: &str, v: &Value) -> String {
    if is_byte_metric(path) {
        if let Some(bytes) = v.as_u64() {
            return format!("{} ({})", humanize_bytes(bytes), bytes);
        }
    }
    format_metric_value(v)
}

/// `true` for metric paths whose value is byte-valued and benefits
/// from a human-readable suffix.  Conservative — we only match the
/// well-known byte fields rather than guess from substrings.
fn is_byte_metric(path: &str) -> bool {
    matches!(
        path,
        "file.size"
            | "binary.code_size"
            | "binary.overlay_size"
            | "binary.avg_section_size"
            | "binary.avg_func_size"
            | "binary.avg_function_size"
            | "binary.max_string_length"
            | "strings.total_bytes"
            | "elf.load_segment_max_p_filesz"
            | "elf.load_segment_max_p_memsz"
    )
}

/// Render a byte count in the most compact human-readable form.
fn humanize_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.1}GB", b / GB)
    } else if b >= MB {
        format!("{:.1}MB", b / MB)
    } else if b >= KB {
        format!("{:.1}KB", b / KB)
    } else {
        format!("{bytes}B")
    }
}

/// Like [`format_value`], but rounds JSON floats to 2 decimal places.
/// Integer values render as-is. Used by the metrics pane so noisy
/// trailing precision (`3.3148789405822754`) doesn't drown out the
/// meaningful digits.
fn format_metric_value(v: &Value) -> String {
    if let Value::Number(n) = v {
        let is_int = n.is_i64() || n.is_u64();
        if !is_int {
            if let Some(f) = n.as_f64() {
                return format!("{f:.2}");
            }
        }
    }
    format_value(v)
}

/// `↑` / `↓` for numeric increase / decrease, `~` otherwise.  Tinted
/// by relative-change magnitude using the same palette as ROC: red
/// ≥50%, yellow ≥9%, blue otherwise — so the eye gets direction AND
/// magnitude at a glance.
fn numeric_direction(old: &Value, new: &Value) -> colored::ColoredString {
    let (Some(a), Some(b)) = (old.as_f64(), new.as_f64()) else {
        return crate::theme::paint_arrow_unchanged();
    };
    let glyph = if b > a {
        "↑"
    } else if b < a {
        "↓"
    } else {
        "~"
    };
    let denom = a.abs().max(b.abs());
    let rel = if denom == 0.0 {
        0.0
    } else {
        (b - a).abs() / denom
    };
    crate::theme::paint_intensity_f64(rel, glyph)
}

// ---- kv ---------------------------------------------------------------------

/// Per-row data for the kv pane.  Mirrors the metric-pane layout so
/// the same group/sort/render flow can be reused.
struct KvRow<'a> {
    sign: &'static str,
    path: &'a str,
    old: Option<&'a Value>,
    new: &'a Value,
}

fn write_kv(out: &mut String, scope: &ScopeDiff<KvChange>) {
    let _ = writeln!(out, "{}", scope_heading("kv", ScopePill::Kv, scope));

    let mut rows: Vec<KvRow<'_>> = Vec::new();
    for c in &scope.added {
        rows.push(KvRow {
            sign: "+",
            path: &c.path,
            old: None,
            new: &c.value,
        });
    }
    for c in &scope.removed {
        rows.push(KvRow {
            sign: "-",
            path: &c.path,
            old: None,
            new: &c.value,
        });
    }
    for Changed { old, new } in &scope.changed {
        rows.push(KvRow {
            sign: "~",
            path: &new.path,
            old: Some(&old.value),
            new: &new.value,
        });
    }

    // Group by top-level namespace (`source.`, `elf.`, `binary.`,
    // `debug.`, …). Same chunking pattern as the metrics pane —
    // sub-headers anchor which group each row belongs to so the
    // reader doesn't chase the prefix on every line.
    let mut groups: std::collections::BTreeMap<&str, Vec<&KvRow<'_>>> =
        std::collections::BTreeMap::new();
    for row in &rows {
        let ns = kv_namespace(row.path);
        groups.entry(ns).or_default().push(row);
    }
    let ordered: Vec<(&str, Vec<&KvRow<'_>>)> = groups.into_iter().collect();

    for (i, (ns, group)) in ordered.iter().enumerate() {
        if i > 0 {
            let _ = writeln!(out);
        }
        let _ = writeln!(out, "    {}", format!("{ns}:").dimmed());

        // Within group: changes first, adds, removes — same order as
        // the metrics pane so panes feel consistent.
        let (mut changes, mut adds, mut removes): (Vec<_>, Vec<_>, Vec<_>) =
            (Vec::new(), Vec::new(), Vec::new());
        for row in group {
            match row.sign {
                "~" => changes.push(*row),
                "+" => adds.push(*row),
                "-" => removes.push(*row),
                _ => {}
            }
        }
        for row in changes.iter().chain(adds.iter()).chain(removes.iter()) {
            write_kv_row(out, row.sign, row.path, row.old, row.new);
        }
    }
}

/// Top-level namespace of a kv path (the prefix before the first
/// `.` or `[`). Falls back to the whole path when no separator is
/// present so flat namespaces don't collapse into an empty group.
fn kv_namespace(path: &str) -> &str {
    let dot = path.find('.').unwrap_or(path.len());
    let bracket = path.find('[').unwrap_or(path.len());
    let cut = dot.min(bracket);
    &path[..cut]
}

/// One kv row. Membership-encoded paths (`prefix[]=value`, produced by
/// the flattener for arrays of leaves) display as `prefix[]   value`
/// since the path already contains the value — printing
/// `path = value` would show the same string twice. Regular
/// path/value pairs use the `path = value` form.
fn write_kv_row(
    out: &mut String,
    sign: &str,
    path: &str,
    old_value: Option<&Value>,
    value: &Value,
) {
    let (display_path, is_membership) = match path.find("[]=") {
        Some(idx) => (format!("{}[]", &path[..idx]), true),
        None => (path.to_string(), false),
    };

    if is_membership {
        let _ = writeln!(
            out,
            "    {} {:<40}   {}",
            paint_sign(sign),
            truncate(&display_path, 40),
            format_value(value),
        );
    } else if let Some(old) = old_value {
        let _ = writeln!(
            out,
            "    {} {:<40} : {} {} {}",
            paint_sign(sign),
            truncate(&display_path, 40),
            format_value(old).dimmed(),
            "→".dimmed(),
            format_value(value),
        );
    } else {
        let _ = writeln!(
            out,
            "    {} {:<40} = {}",
            paint_sign(sign),
            truncate(&display_path, 40),
            format_value(value),
        );
    }
}

// ---- symbols ----------------------------------------------------------------

fn write_symbols(out: &mut String, scope: &ScopeDiff<SymbolChange>) {
    let _ = writeln!(
        out,
        "{}",
        scope_heading("symbols", ScopePill::Symbols, scope)
    );

    // Old/new totals + per-kind breakdown in a dimmed sub-line.
    // ScopeDiff carries the aggregate counts; we re-derive the
    // imports/exports split from the actual entries since the diff
    // engine doesn't preserve kind-level totals.
    if scope.old_count > 0 || scope.new_count > 0 {
        let added_imports = scope
            .added
            .iter()
            .filter(|s| s.kind == SymbolKind::Import)
            .count();
        let added_exports = scope
            .added
            .iter()
            .filter(|s| s.kind == SymbolKind::Export)
            .count();
        let removed_imports = scope
            .removed
            .iter()
            .filter(|s| s.kind == SymbolKind::Import)
            .count();
        let removed_exports = scope
            .removed
            .iter()
            .filter(|s| s.kind == SymbolKind::Export)
            .count();
        let mut parts = Vec::new();
        match (added_imports, removed_imports) {
            (0, 0) => {}
            (n, 0) => parts.push(format!("+{n} imports")),
            (0, n) => parts.push(format!("-{n} imports")),
            (a, r) => parts.push(format!("+{a}/-{r} imports")),
        }
        match (added_exports, removed_exports) {
            (0, 0) => {}
            (n, 0) => parts.push(format!("+{n} exports")),
            (0, n) => parts.push(format!("-{n} exports")),
            (a, r) => parts.push(format!("+{a}/-{r} exports")),
        }
        let breakdown = if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join(", "))
        };
        let _ = writeln!(
            out,
            "    {}",
            format!(
                "{} → {} symbols{}",
                scope.old_count, scope.new_count, breakdown
            )
            .dimmed()
        );
    }

    // Alphabetical sort makes obfuscator patterns cluster (e.g., the
    // run of single-letter / digit-suffixed names common in JS
    // packers stack together) so the reader's eye picks the
    // structure out without scanning the whole list.
    let kind_order = |k: SymbolKind| match k {
        SymbolKind::Import => 0u8,
        SymbolKind::Export => 1u8,
    };
    let mut added: Vec<&SymbolChange> = scope.added.iter().collect();
    added.sort_by(|a, b| {
        kind_order(a.kind)
            .cmp(&kind_order(b.kind))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });
    let mut removed: Vec<&SymbolChange> = scope.removed.iter().collect();
    removed.sort_by(|a, b| {
        kind_order(a.kind)
            .cmp(&kind_order(b.kind))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });

    for c in added {
        let _ = writeln!(out, "    {} {}", paint_sign("+"), symbol_label(c));
    }
    for c in removed {
        let _ = writeln!(out, "    {} {}", paint_sign("-"), symbol_label(c));
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

// ---- strings ----------------------------------------------------------------

/// Cap for "low-signal" string changes (random-looking obfuscator
/// payload, asm leakage that survived stng's filter, etc.). Strings
/// that classify to a known kind via `stng::classify_string`
/// (URL/Path/Hostname/Email/ShellCmd/…) bypass the cap and are
/// always shown — they're the diff-signal we're protecting.
const STRING_LOW_SIGNAL_CAP: usize = 10;

/// Strings shorter than this rarely carry diff signal — most are
/// 4-5 char asm/data fragments interpreted as ASCII. Real meaningful
/// strings (paths, identifiers, error messages, URLs) easily clear
/// the floor; magic-number tokens (`RIFF`, `BSJB`, `IDAT`) are below
/// it but rarely change between binary versions, so missing them in
/// diffs is acceptable.
const STRING_MIN_LEN: usize = 6;

fn long_enough(s: &StringChange) -> bool {
    s.value.chars().count() >= STRING_MIN_LEN
}

/// `true` when stng's classifier recognised the string as a specific
/// kind (URL, Path, Hostname, Email, ShellCmd, Registry, …) — the
/// strings an analyst usually cares about. Unrecognised strings are
/// either real-but-uncategorised text or noise; the cap applies.
fn is_high_signal(s: &str) -> bool {
    stng::classify_string(s).is_some_and(|k| k.is_classifier_output())
}

fn write_strings(out: &mut String, scope: &ScopeDiff<StringChange>) {
    let added: Vec<&StringChange> = scope.added.iter().filter(|s| long_enough(s)).collect();
    let removed: Vec<&StringChange> = scope.removed.iter().filter(|s| long_enough(s)).collect();
    let changed: Vec<&Changed<StringChange>> = scope
        .changed
        .iter()
        .filter(|c| long_enough(&c.new) || long_enough(&c.old))
        .collect();
    let short_dropped = (scope.added.len() - added.len())
        + (scope.removed.len() - removed.len())
        + (scope.changed.len() - changed.len());

    let _ = writeln!(
        out,
        "{}",
        scope_heading("strings", ScopePill::Strings, scope)
    );

    if short_dropped > 0 {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {short_dropped} strings under {STRING_MIN_LEN} chars hidden").dimmed()
        );
    }

    let (added_kept, added_hidden) = filter_signal(&added, |s| is_high_signal(&s.value));
    let (removed_kept, removed_hidden) = filter_signal(&removed, |s| is_high_signal(&s.value));
    let (changed_kept, changed_hidden) = filter_signal(&changed, |c| {
        is_high_signal(&c.new.value) || is_high_signal(&c.old.value)
    });

    if added_hidden > 0 {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {added_hidden} low-signal added strings hidden").dimmed()
        );
    }
    for s in added_kept {
        let _ = writeln!(out, "    {} {}", paint_sign("+"), truncate(&s.value, 200));
    }
    if removed_hidden > 0 {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {removed_hidden} low-signal removed strings hidden").dimmed()
        );
    }
    for s in removed_kept {
        let _ = writeln!(out, "    {} {}", paint_sign("-"), truncate(&s.value, 200));
    }
    if changed_hidden > 0 {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {changed_hidden} low-signal changed strings hidden").dimmed()
        );
    }
    for c in changed_kept {
        let _ = writeln!(
            out,
            "    {} {} {} {}",
            paint_sign("~"),
            truncate(&c.old.value, 80).dimmed(),
            "→".dimmed(),
            truncate(&c.new.value, 80),
        );
    }
}

/// Partition string changes into `(kept, hidden_count)`. Items where
/// `is_high_signal(item)` returns true always make the keep list;
/// the rest fall under `STRING_LOW_SIGNAL_CAP` (most-recent first,
/// matching the original "tail" behaviour for noisy diffs).
///
/// Returns the kept items in their original order so high-signal
/// strings stay interleaved with the visible low-signal tail rather
/// than being grouped at the front.
fn filter_signal<T, F>(items: &[T], is_signal: F) -> (Vec<T>, usize)
where
    T: Copy,
    F: Fn(T) -> bool,
{
    if items.len() <= STRING_LOW_SIGNAL_CAP {
        return (items.to_vec(), 0);
    }

    // Walk from the end, accepting up to `cap` low-signal items plus
    // every high-signal item. The boundary between visible and
    // hidden falls wherever the cap is reached.
    let mut keep_idx = std::collections::BTreeSet::new();
    let mut low_signal_kept = 0usize;
    for (i, item) in items.iter().enumerate().rev() {
        if is_signal(*item) {
            keep_idx.insert(i);
        } else if low_signal_kept < STRING_LOW_SIGNAL_CAP {
            keep_idx.insert(i);
            low_signal_kept += 1;
        }
    }

    let kept: Vec<T> = items
        .iter()
        .enumerate()
        .filter(|(i, _)| keep_idx.contains(i))
        .map(|(_, item)| *item)
        .collect();
    let hidden = items.len() - kept.len();
    (kept, hidden)
}

// ---- sections (binary) ------------------------------------------------------

fn write_sections(out: &mut String, scope: &ScopeDiff<SectionChange>) {
    let _ = writeln!(
        out,
        "{}",
        scope_heading("sections", ScopePill::Sections, scope)
    );

    for s in &scope.added {
        let _ = writeln!(out, "    {} {}", paint_sign("+"), section_label(s));
    }
    for s in &scope.removed {
        let _ = writeln!(out, "    {} {}", paint_sign("-"), section_label(s));
    }

    // Section deltas under 9% are below scan-relevance: padding shifts,
    // metadata bumps, dynstr realignment. Hide the row when both size
    // and entropy moved <9%; suppress the entropy column when only it
    // moved that little.
    const NOISE: f64 = 0.09;
    let mut hidden = 0u32;

    // Pre-rank visible changes by max(|size%|, |entropy%|) so the
    // biggest movers lead and the trailing 9-15% changes come last.
    let mut visible: Vec<(&Changed<SectionChange>, f64, f64)> = scope
        .changed
        .iter()
        .filter_map(|c| {
            let size_pct = relative_change(c.old.size as f64, c.new.size as f64);
            let ent_pct = relative_change(c.old.entropy, c.new.entropy);
            if size_pct.abs() <= NOISE && ent_pct.abs() <= NOISE {
                hidden += 1;
                return None;
            }
            Some((c, size_pct, ent_pct))
        })
        .collect();
    visible.sort_by(|a, b| {
        let ra = a.1.abs().max(a.2.abs());
        let rb = b.1.abs().max(b.2.abs());
        rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
    });

    for (Changed { old, new }, size_pct, ent_pct) in &visible {
        let (size_pct, ent_pct) = (*size_pct, *ent_pct);
        // Pad-then-color: ANSI escape bytes inflate the byte length so
        // `{:>8}` won't measure them as visible width.
        let size_col = format!(
            "size {} {:>+4.0}%   {} {} {}",
            section_arrow(size_pct),
            size_pct * 100.0,
            format!("{:>8}", old.size).dimmed(),
            "→".dimmed(),
            paint_delta(format!("{:>8}", new.size), size_pct > 0.0, size_pct < 0.0),
        );
        let ent_col = if ent_pct.abs() > NOISE {
            format!(
                "    entropy {} {:>+4.0}%   {} {} {}",
                section_arrow(ent_pct),
                ent_pct * 100.0,
                format!("{:>4.2}", old.entropy).dimmed(),
                "→".dimmed(),
                paint_delta(
                    format!("{:>4.2}", new.entropy),
                    ent_pct > 0.0,
                    ent_pct < 0.0,
                ),
            )
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "    {} {:<18}   {}{}",
            paint_sign("~"),
            new.name,
            size_col,
            ent_col,
        );
    }
    if hidden > 0 {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {hidden} sections with sub-9% size & entropy moves hidden").dimmed(),
        );
    }
}

/// Standard relative change `(new - old) / |old|`. Falls back to the
/// new-side magnitude when `old == 0` so a 0 → N delta reads as +100%
/// rather than `+inf`. Returns `0.0` when both sides are zero.
fn relative_change(old: f64, new: f64) -> f64 {
    if old == 0.0 && new == 0.0 {
        return 0.0;
    }
    let denom = if old.abs() > 0.0 {
        old.abs()
    } else {
        new.abs()
    };
    (new - old) / denom
}

/// `↑` / `↓` arrow tinted by relative-change magnitude (`~` when the
/// sign is exactly zero).  Routed through `theme::paint_intensity_f64`
/// so section-pane arrows share the same severity-tier palette as
/// metric-pane arrows and ROC% in headings.
fn section_arrow(pct: f64) -> colored::ColoredString {
    let glyph = if pct > 0.0 {
        "↑"
    } else if pct < 0.0 {
        "↓"
    } else {
        "~"
    };
    crate::theme::paint_intensity_f64(pct, glyph)
}

/// Tint a value string by direction: bright-white for an increase,
/// dimmed for a decrease, normal for "no movement". Used on the
/// "new" side of metric / section changed rows so the eye is drawn
/// to the values that actually grew, and de-emphasises the ones
/// that shrank — without forcing the reader to map an arrow back
/// to a number.
fn paint_delta<S: AsRef<str>>(text: S, increased: bool, decreased: bool) -> colored::ColoredString {
    let s = text.as_ref();
    if increased {
        s.bright_white()
    } else if decreased {
        s.dimmed()
    } else {
        s.normal()
    }
}

/// `(increased, decreased)` for two JSON values (typically a metric
/// pair). `(false, false)` for non-numeric or equal values.
fn value_direction(old: &Value, new: &Value) -> (bool, bool) {
    if let (Some(a), Some(b)) = (old.as_f64(), new.as_f64()) {
        return (b > a, b < a);
    }
    (false, false)
}

fn section_label(s: &SectionChange) -> String {
    let perms = s.permissions.as_deref().unwrap_or("???");
    format!(
        "{} (size {}, entropy {:.2}, perms {})",
        s.name, s.size, s.entropy, perms
    )
}

// =============================================================================
// Tests for pane-level rendering. Header + ledger have their own
// tests in submodule `tests`.
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::{Criticality, MetricChange, ScopeDiff};

    #[test]
    fn metric_direction_arrows() {
        let scope: ScopeDiff<MetricChange> = ScopeDiff {
            changed: vec![
                Changed {
                    old: MetricChange {
                        path: "x".into(),
                        value: Value::from(10),
                    },
                    new: MetricChange {
                        path: "x".into(),
                        value: Value::from(20),
                    },
                },
                Changed {
                    old: MetricChange {
                        path: "y".into(),
                        value: Value::from(20),
                    },
                    new: MetricChange {
                        path: "y".into(),
                        value: Value::from(10),
                    },
                },
            ],
            old_count: 2,
            new_count: 2,
            old_weight: 2.0,
            new_weight: 2.0,
            change_weight: 0.5,
            roc: 0.25,
            truncated: false,
            ..Default::default()
        };
        let _ = Criticality::Baseline; // silence unused import (tests/imports stay tidy)
        let mut out = String::new();
        write_metrics(&mut out, &scope);
        assert!(out.contains('↑'));
        assert!(out.contains('↓'));
        assert!(!out.contains(" ~ "));
    }
}
