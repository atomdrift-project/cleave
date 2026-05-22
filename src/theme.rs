//! Shared color and style theme for cleave's terminal output.
//!
//! Both the `analyze` (`output.rs`) and `diff` (`diff/format/*`)
//! surfaces consume the same semantic tokens here so the two views
//! read as one design language.  Changing a hue happens in this file;
//! both surfaces shift together.
//!
//! ## Severity palette
//!
//! Tiered between the original `bright_*` ANSI defaults (too saturated
//! for modern terminal themes — they read as "stadium scoreboard")
//! and a fully-muted slate palette (eye-friendly but quiet).  The
//! middle ground keeps the hue intent (red is red, blue is blue) but
//! drops the phosphor-tube saturation so the colors sit comfortably
//! against any terminal background.
//!
//! | tier        | analyze 8-color | slate (too muted) | **theme middle** |
//! |-------------|-----------------|-------------------|------------------|
//! | hostile     | `bright_red`    | rose 174          | **coral 167**    |
//! | suspicious  | `bright_yellow` | amber 215         | **gold 214**     |
//! | notable     | `bright_blue`   | slate-blue 110    | **azure 39**     |
//! | baseline    | `bright_green`  | sage 108          | **forest 71**    |
//! | component   | `dimmed`        | gray              | **gray 244**     |
//!
//! ## Adding new tokens
//!
//! Prefer a *semantic* name (`paint_hostile`, `paint_intensity`) over
//! a *concrete* name (`paint_coral`, `paint_167`).  Callers shouldn't
//! know which 256-color index a level maps to.

use colored::{ColoredString, Colorize};

// ─── severity color tuples ──────────────────────────────────────────
//
// Pinned RGB triples mapping to 256-color indices 167/214/39/71/244
// (xterm extended palette).  Truecolor used directly for portability
// — the `colored` crate doesn't filefacts a 256-color setter, and every
// modern terminal that runs cleave handles truecolor cleanly.
//
// Constants are `pub(crate)` so future themes can swap them without
// touching every consumer.

pub(crate) const HOSTILE_RGB: (u8, u8, u8) = (215, 95, 95); // coral red (256: 167)
pub(crate) const SUSPICIOUS_RGB: (u8, u8, u8) = (255, 175, 0); // gold amber (214)
pub(crate) const NOTABLE_RGB: (u8, u8, u8) = (0, 175, 255); // azure blue (39)
pub(crate) const BASELINE_RGB: (u8, u8, u8) = (95, 175, 95); // forest green (71)
pub(crate) const COMPONENT_RGB: (u8, u8, u8) = (128, 128, 128); // mid gray (244)

// ─── severity painters ──────────────────────────────────────────────
//
// One painter per criticality level.  Hostile and suspicious are
// bolded (high-attention findings); notable / baseline / component
// stay regular weight to leave reading bandwidth for the bold tier.

/// Paint `text` with the hostile severity (coral red, bold).
#[must_use]
pub fn paint_hostile<S: AsRef<str>>(text: S) -> ColoredString {
    let (r, g, b) = HOSTILE_RGB;
    text.as_ref().bold().truecolor(r, g, b)
}

/// Paint `text` with the suspicious severity (gold amber, bold).
#[must_use]
pub fn paint_suspicious<S: AsRef<str>>(text: S) -> ColoredString {
    let (r, g, b) = SUSPICIOUS_RGB;
    text.as_ref().bold().truecolor(r, g, b)
}

/// Paint `text` with the notable severity (azure blue, regular weight).
#[must_use]
pub fn paint_notable<S: AsRef<str>>(text: S) -> ColoredString {
    let (r, g, b) = NOTABLE_RGB;
    text.as_ref().truecolor(r, g, b)
}

/// Paint `text` with the baseline severity (forest green, regular weight).
#[must_use]
pub fn paint_baseline<S: AsRef<str>>(text: S) -> ColoredString {
    let (r, g, b) = BASELINE_RGB;
    text.as_ref().truecolor(r, g, b)
}

/// Paint `text` with the component severity (mid gray, regular weight).
#[must_use]
pub fn paint_component<S: AsRef<str>>(text: S) -> ColoredString {
    let (r, g, b) = COMPONENT_RGB;
    text.as_ref().truecolor(r, g, b)
}

// ─── intensity tier (ROC%, confidence%, relative-change magnitude) ──
//
// 0.0–1.0 scale (not 0–100).  Picks a severity color by tier so a
// "how strong is this signal?" number reads with the same palette as
// "how dangerous is this finding?".  Below 5% the value is dimmed —
// genuinely uninteresting content shouldn't compete for attention.

/// Pick a severity painter for `text` based on `pct` (0.0–1.0 scale).
/// Tiers: ≥50% hostile, ≥20% suspicious, ≥5% notable, >0% normal,
/// ≤0% dimmed. Used so a "how strong is this signal?" number reads
/// with the same palette as the criticality of a finding.
#[must_use]
pub fn paint_intensity<S: AsRef<str>>(pct: f32, text: S) -> ColoredString {
    let s = text.as_ref();
    match pct {
        p if p >= 0.50 => paint_hostile(s),
        p if p >= 0.20 => paint_suspicious(s),
        p if p >= 0.05 => paint_notable(s),
        p if p > 0.0 => s.normal(),
        _ => s.dimmed(),
    }
}

/// Float variant — same tiers, takes `f64` for callers that already
/// have a relative-change number in that scale (the diff metric and
/// section panes).
#[must_use]
pub fn paint_intensity_f64<S: AsRef<str>>(rel: f64, text: S) -> ColoredString {
    paint_intensity(rel.abs() as f32, text)
}

// ─── pills ──────────────────────────────────────────────────────────
//
// Truecolor backgrounds for top-level section labels.  Two families:
//
//   * **namespace pills** — analyze-side section headers
//     (`well-known`, `objectives`, `micro-behaviors`, `metadata`,
//     `third-party`).  Hot hue family (red / magenta / blue / gray /
//     orange).
//
//   * **scope pills** — diff-side scope headers (`traits`, `metrics`,
//     `kv`, `symbols`, `strings`, `sections`).  Cool hue family
//     (plum / teal / ochre / rose / ocean / slate) so the analyst
//     can tell at a glance which mode they're in.
//
// Both use `bold white` foreground; readability over a dark bg.

/// Analyze-side namespace pill kinds — one per top-level taxonomy
/// section (well-known, objectives, micro-behaviors, metadata,
/// third-party). Hot hue family; pairs with `pill_namespace`.
#[derive(Debug, Clone, Copy)]
pub enum NamespacePill {
    /// `well-known` — established malware families and signatures.
    WellKnown,
    /// `objectives` — high-level adversary goals.
    Objectives,
    /// `micro-behaviors` — low-level capability primitives.
    MicroBehaviors,
    /// `metadata` — structural / build-info findings.
    Metadata,
    /// `third-party` — vendored YARA / external rule matches.
    ThirdParty,
}

/// Render `label` as an analyze-side namespace pill (bold white on
/// the hot-family background for `ns`).
#[must_use]
pub fn pill_namespace(label: &str, ns: NamespacePill) -> ColoredString {
    let (r, g, b) = match ns {
        NamespacePill::WellKnown => (95, 0, 0),
        NamespacePill::Objectives => (95, 0, 95),
        NamespacePill::MicroBehaviors => (0, 0, 95),
        NamespacePill::Metadata => (48, 48, 48),
        NamespacePill::ThirdParty => (120, 56, 0),
    };
    format!(" {label} ").bold().white().on_truecolor(r, g, b)
}

/// Diff-side scope pill kinds — one per per-file scope heading
/// (`traits`, `metrics`, `kv`, `symbols`, `strings`, `sections`).
/// Cool hue family; pairs with `pill_scope`.
#[derive(Debug, Clone, Copy)]
pub enum ScopePill {
    /// `traits` — added/removed/changed trait findings.
    Traits,
    /// `metrics` — numeric metric deltas.
    Metrics,
    /// `kv` — key/value tree deltas.
    Kv,
    /// `symbols` — exported / imported / internal symbol deltas.
    Symbols,
    /// `strings` — extracted-string deltas.
    Strings,
    /// `sections` — binary section deltas (size / entropy).
    Sections,
}

/// Render `label` as a diff-side scope pill (bold white on the
/// cool-family background for `scope`).
#[must_use]
pub fn pill_scope(label: &str, scope: ScopePill) -> ColoredString {
    let (r, g, b) = match scope {
        ScopePill::Traits => (60, 30, 75),   // plum
        ScopePill::Metrics => (0, 60, 55),   // teal
        ScopePill::Kv => (75, 55, 0),        // ochre
        ScopePill::Symbols => (75, 0, 55),   // rose
        ScopePill::Strings => (0, 55, 75),   // ocean
        ScopePill::Sections => (55, 55, 55), // slate
    };
    format!(" {label} ").bold().white().on_truecolor(r, g, b)
}

// ─── rules and separators ───────────────────────────────────────────
//
// One character, one color, both surfaces.  Used between files in
// analyze and under per-file pane headings in diff.

/// Glyph for full-width section / file rules.
pub const RULE_CHAR: char = '─';

/// Color for rules — slate-blue, dim enough to recede but visible
/// against any terminal background.
#[must_use]
pub fn paint_rule<S: AsRef<str>>(text: S) -> ColoredString {
    text.as_ref().truecolor(80, 100, 120)
}

// ─── direction arrows ───────────────────────────────────────────────
//
// `↑` / `↓` (and `~` for unchanged) tinted by relative-change
// magnitude using the same tier as `paint_intensity`.  Diff-only:
// analyze has no direction concept.

/// `↑` glyph tinted by `rel_change` magnitude (intensity tier).
#[must_use]
pub fn paint_arrow_up(rel_change: f64) -> ColoredString {
    paint_intensity_f64(rel_change, "↑")
}

/// `↓` glyph tinted by `rel_change` magnitude (intensity tier).
#[must_use]
pub fn paint_arrow_down(rel_change: f64) -> ColoredString {
    paint_intensity_f64(rel_change, "↓")
}

/// Neutral `~` glyph (dimmed) for unchanged metric rows.
#[must_use]
pub fn paint_arrow_unchanged() -> ColoredString {
    "~".dimmed()
}

// ─── add / remove / change signs ────────────────────────────────────
//
// Diff-side `+`/`-`/`~` glyphs.  We keep these slightly brighter
// than the severity tiers so the signs read as *verbs* (this row
// added, this row removed) not as severity dimensions.  Same hue
// family as the severity palette, full saturation reserved for the
// glyphs alone.

/// Color a diff change-indicator: `+` baseline (green), `-` hostile
/// (red), `~` suspicious (gold). Anything else falls through to
/// `normal()`.
#[must_use]
pub fn paint_sign(sign: &str) -> ColoredString {
    let (r, g, b) = match sign {
        "+" => BASELINE_RGB,
        "-" => HOSTILE_RGB,
        "~" => SUSPICIOUS_RGB,
        _ => return sign.normal(),
    };
    sign.bold().truecolor(r, g, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intensity_tiers_pick_expected_severity() {
        // 0.6 → hostile, 0.3 → suspicious, 0.1 → notable, 0.02 → normal, 0.0 → dimmed.
        // We can't compare ColoredString contents directly, but we
        // can compare the ANSI escape sequences they render to.
        assert_eq!(
            paint_intensity(0.6, "x").to_string(),
            paint_hostile("x").to_string(),
        );
        assert_eq!(
            paint_intensity(0.3, "x").to_string(),
            paint_suspicious("x").to_string(),
        );
        assert_eq!(
            paint_intensity(0.1, "x").to_string(),
            paint_notable("x").to_string(),
        );
        assert_eq!(
            paint_intensity(0.02, "x").to_string(),
            "x".normal().to_string()
        );
        assert_eq!(
            paint_intensity(0.0, "x").to_string(),
            "x".dimmed().to_string()
        );
    }

    #[test]
    fn intensity_f64_takes_absolute_value() {
        // `-0.6` and `0.6` should land on the same severity tier — the
        // diff cares about magnitude of change, not direction.
        assert_eq!(
            paint_intensity_f64(-0.6, "x").to_string(),
            paint_intensity_f64(0.6, "x").to_string(),
        );
    }

    #[test]
    fn signs_use_severity_palette() {
        // `+` matches baseline RGB, `-` hostile, `~` suspicious — verify
        // by composing the same painter directly.
        let (r, g, b) = BASELINE_RGB;
        assert_eq!(
            paint_sign("+").to_string(),
            "+".bold().truecolor(r, g, b).to_string(),
        );
        let (r, g, b) = HOSTILE_RGB;
        assert_eq!(
            paint_sign("-").to_string(),
            "-".bold().truecolor(r, g, b).to_string(),
        );
        let (r, g, b) = SUSPICIOUS_RGB;
        assert_eq!(
            paint_sign("~").to_string(),
            "~".bold().truecolor(r, g, b).to_string(),
        );
    }

    #[test]
    fn pills_render_with_bold_white_on_truecolor() {
        // Smoke test — pills should produce non-empty colored output.
        let p = pill_namespace("OBJECTIVES", NamespacePill::Objectives);
        assert!(!p.to_string().is_empty());
        assert!(p.to_string().contains("OBJECTIVES"));

        let s = pill_scope("traits", ScopePill::Traits);
        assert!(!s.to_string().is_empty());
        assert!(s.to_string().contains("traits"));
    }
}
