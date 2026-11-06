//! Escaping sample-derived text for terminals and logs.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Spaces a tab expands to in the source view.
pub(super) const TAB_WIDTH: usize = 2;

pub(super) fn is_terminal_direction_control(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// Characters that render as nothing: zero-width spaces and joiners, the
/// word joiner and invisible operators, the byte-order mark, the soft hyphen,
/// the Mongolian vowel separator, and the tag characters. In a path or a
/// signer name they make two strings that read alike compare unequal, or hide
/// text inside one that reads innocently.
pub(super) fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200d}'
            | '\u{2060}'..='\u{2064}'
            | '\u{feff}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// Sample-derived text as it appears inside one rendered line: a path, a
/// signer or product name, a finding's description, an evidence value. Every
/// control character (escape, carriage return and line feed included), every
/// bidirectional control and every invisible character becomes visible
/// `\u{..}` text.
///
/// The final [`sanitize_terminal_output`] boundary must keep the renderer's
/// own colors and line breaks, so it cannot tell them from ones a sample
/// carries: a member name with `\x1b[30;40m` would hide the text after it,
/// and one with `\n` would forge a line of output. Text from the sample goes
/// through here before the renderer adds its own.
#[must_use]
pub fn sample_text(s: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    let escape = |c: char| c.is_control() || is_terminal_direction_control(c) || is_invisible(c);
    if !s.chars().any(escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if escape(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Replace terminal-significant control and directionality characters with
/// escaped text.
///
/// Sample-derived strings (file names, source lines) can carry CSI/OSC escape
/// sequences that rewrite what an operator sees in the terminal. Control
/// characters other than tab, newline, and carriage return, plus Unicode
/// bidirectional formatting controls, become `\u{XX}` text. Returns the input
/// unchanged (no allocation) when nothing needs escaping, which is the
/// overwhelmingly common case. For one-line log fields use
/// [`escape_log_field`], which escapes line breaks too.
#[must_use]
pub fn escape_control_chars(s: &str) -> std::borrow::Cow<'_, str> {
    escape_controls(s, |c| matches!(c, '\t' | '\n' | '\r'))
}

/// [`escape_control_chars`] for a value inside a single log record: line
/// breaks are escaped as well, so a file name containing `\n` cannot forge a
/// log line.
#[must_use]
pub fn escape_log_field(s: &str) -> std::borrow::Cow<'_, str> {
    escape_controls(s, |c| c == '\t')
}

pub(super) fn escape_controls(s: &str, keep: fn(char) -> bool) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;
    let escape = |c: char| (c.is_control() && !keep(c)) || is_terminal_direction_control(c);
    if !s.chars().any(escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if escape(c) {
            // Infallible on String; see expand_tabs.
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Remove terminal control sequences from a fully rendered human-facing view
/// while preserving SGR styling sequences used by the renderer.
///
/// Sample-derived paths, archive member names, identity claims, and evidence
/// all reach terminal output. Escaping those fields one by one is brittle: a
/// newly rendered field can silently reopen CSI/OSC injection. This final
/// boundary permits only newlines, tabs, and CSI Select Graphic Rendition
/// sequences (`ESC [ ... m`). Every other control character, every Unicode
/// bidirectional formatting control and every invisible character is rendered
/// as visible `\\u{...}` text. Colors and line breaks a sample carries look
/// like the renderer's own here; [`sample_text`] escapes those where sample
/// text enters a view.
/// SGR can alter presentation; it cannot move the cursor, clear the screen,
/// set the terminal title, or write clipboard contents. SGR 8 (conceal), which
/// the renderer never emits and which would hide the text after it, is
/// escaped too.
#[must_use]
pub fn sanitize_terminal_output(s: &str) -> std::borrow::Cow<'_, str> {
    use std::borrow::Cow;

    fn sgr_len(s: &str) -> Option<usize> {
        let bytes = s.as_bytes();
        if bytes.get(..2) != Some(b"\x1b[") {
            return None;
        }
        let mut i = 2;
        while let Some(&b) = bytes.get(i) {
            if b == b'm' {
                let conceals = s[2..i].split([';', ':']).any(|p| p == "8");
                return (!conceals).then_some(i + 1);
            }
            if !b.is_ascii_digit() && !matches!(b, b';' | b':') {
                return None;
            }
            i += 1;
        }
        None
    }

    let mut out = String::new();
    let mut copied = 0;
    let mut i = 0;
    while i < s.len() {
        let Some(ch) = s[i..].chars().next() else {
            break;
        };
        if ch == '\u{1b}'
            && let Some(len) = sgr_len(&s[i..])
        {
            i += len;
            continue;
        }
        if (ch.is_control() && !matches!(ch, '\n' | '\t'))
            || is_terminal_direction_control(ch)
            || is_invisible(ch)
        {
            if out.is_empty() {
                out.reserve(s.len());
            }
            out.push_str(&s[copied..i]);
            let _ = write!(out, "\\u{{{:x}}}", u32::from(ch));
            i += ch.len_utf8();
            copied = i;
        } else {
            i += ch.len_utf8();
        }
    }
    if out.is_empty() {
        Cow::Borrowed(s)
    } else {
        out.push_str(&s[copied..]);
        Cow::Owned(out)
    }
}

/// Expand tabs to a fixed display width and escape control characters,
/// returning the display form plus a map from every input byte offset to the
/// corresponding display byte offset.
///
/// Control characters (except the tab handled above) are escaped as
/// `\u{XX}` — sample-derived source lines can carry terminal escape
/// sequences, and this is the single funnel both the colorized and plain
/// renderers draw their text from. The map points every byte of an escaped
/// character at the start of its escape sequence, so a match highlight
/// whose offset lands on one covers the whole escape.
pub(super) fn expand_tabs(line: &str) -> (String, Vec<usize>) {
    let mut display = String::with_capacity(line.len());
    let mut map = vec![0usize; line.len() + 1];
    let mut opos = 0usize;
    for ch in line.chars() {
        let clen = ch.len_utf8();
        for slot in map.iter_mut().skip(opos).take(clen) {
            *slot = display.len();
        }
        opos += clen;
        if ch == '\t' {
            for _ in 0..TAB_WIDTH {
                display.push(' ');
            }
        } else if ch.is_control() {
            // Infallible on String; see escape_control_chars.
            let _ = write!(display, "\\u{{{:x}}}", u32::from(ch));
        } else {
            display.push(ch);
        }
    }
    map[line.len()] = display.len();
    (display, map)
}

/// Color a source slice: the matched `spans` (byte ranges within `text`) in the
/// severity hue (bold), the rest in the terminal's default color so the code
/// reads naturally. Empty `spans` leave the text untinted.
pub(super) fn paint_spans(text: &str, mut spans: Vec<(usize, usize, Criticality)>) -> String {
    if spans.is_empty() {
        return text.to_string();
    }
    spans.sort_unstable_by_key(|&(s, _, _)| s);
    let mut buf = String::new();
    let mut pos = 0;
    for (start, end, crit) in spans {
        if start < pos {
            continue;
        }
        if let Some(pre) = text.get(pos..start) {
            buf.push_str(pre); // default color
        }
        if let Some(ev) = text.get(start..end) {
            let (er, eg, eb) = crit_rgb(crit);
            buf.push_str(&ev.truecolor(er, eg, eb).bold().to_string());
        }
        pos = end;
    }
    buf.push_str(text.get(pos..).unwrap_or(""));
    buf
}
