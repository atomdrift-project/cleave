use super::{
    escape_control_chars, escape_log_field, expand_tabs, sample_text, sanitize_terminal_output,
};

#[test]
fn clean_text_passes_through_unescaped() {
    let s = "ordinary/path with spaces.tar.gz\n";
    assert_eq!(escape_control_chars(s).as_ref(), s);
}

#[test]
fn terminal_escapes_become_visible_text() {
    assert_eq!(
        escape_control_chars("evil\u{1b}[31mred\u{1b}[0m").as_ref(),
        "evil\\u{1b}[31mred\\u{1b}[0m"
    );
    // C1 8-bit controls are the alternative CSI door some terminals honor.
    assert_eq!(escape_control_chars("x\u{9b}9A").as_ref(), "x\\u{9b}9A");
}

#[test]
fn tab_newline_cr_are_preserved() {
    let s = "a\tb\nc\rd";
    assert_eq!(escape_control_chars(s).as_ref(), s);
}

#[test]
fn final_terminal_boundary_blocks_active_terminal_controls() {
    let hostile = concat!(
        "ok\x1b[31mred\x1b[0m",
        "\x1b[2Jclear",
        "\x1b]52;c;Y2xpcGJvYXJk\x07",
        "\rrewrite",
        "\u{9b}2J",
        "photo\u{202e}exe.jpg",
        "\x1b[0;8mhidden"
    );
    assert_eq!(
        sanitize_terminal_output(hostile).as_ref(),
        concat!(
            "ok\x1b[31mred\x1b[0m",
            "\\u{1b}[2Jclear",
            "\\u{1b}]52;c;Y2xpcGJvYXJk\\u{7}",
            "\\u{d}rewrite",
            "\\u{9b}2J",
            "photo\\u{202e}exe.jpg",
            "\\u{1b}[0;8mhidden"
        )
    );
}

#[test]
fn log_fields_cannot_forge_lines() {
    assert_eq!(
        escape_log_field("a.bin\n2026-01-01 INFO forged").as_ref(),
        "a.bin\\u{a}2026-01-01 INFO forged"
    );
    assert_eq!(escape_control_chars("two\nlines").as_ref(), "two\nlines");
}

/// The renderer's funnel must both escape and keep the byte-offset map
/// aligned, so a highlight landing on a control byte covers its escape.
#[test]
fn expand_tabs_escapes_and_maps_control_chars() {
    let (display, map) = expand_tabs("a\u{1b}b\tc");
    assert_eq!(display, "a\\u{1b}b  c");
    // Byte 1..2 of the input is the ESC; its map slot points at the
    // start of the escape text, and byte 2 ('b') points past it.
    let esc_start = map[1];
    assert_eq!(&display[esc_start..esc_start + 4], "\\u{1");
    assert_eq!(map[2], esc_start + 6);
    // The tab maps to the start of its two-space expansion.
    assert_eq!(&display[map[3]..map[3] + 2], "  ");
}

/// The final boundary keeps the renderer's colors and line breaks, so it
/// cannot strip ones a sample carries; `sample_text` is where sample text is
/// made inert before the renderer adds its own.
#[test]
fn sample_text_cannot_color_hide_or_break_a_line() {
    assert_eq!(sample_text("plain/path.js").as_ref(), "plain/path.js");
    assert!(matches!(
        sample_text("plain/path.js"),
        std::borrow::Cow::Borrowed(_)
    ));
    // Black on black would hide what follows; a line break forges a row.
    assert_eq!(
        sample_text("a.js\u{1b}[30;40mhidden\n\u{1b}[32m✓ clean").as_ref(),
        "a.js\\u{1b}[30;40mhidden\\u{a}\\u{1b}[32m✓ clean"
    );
    // Invisible and direction characters become visible.
    assert_eq!(
        sample_text("Mi\u{200b}crosoft\u{202e}cod.exe").as_ref(),
        "Mi\\u{200b}crosoft\\u{202e}cod.exe"
    );
    assert_eq!(sample_text("\u{e0041}tag").as_ref(), "\\u{e0041}tag");
}

#[test]
fn final_boundary_makes_invisible_characters_visible() {
    assert_eq!(
        sanitize_terminal_output("pay\u{200d}pal\u{feff}").as_ref(),
        "pay\\u{200d}pal\\u{feff}"
    );
    // The renderer's own SGR still passes.
    assert_eq!(
        sanitize_terminal_output("\u{1b}[1mbold\u{1b}[0m").as_ref(),
        "\u{1b}[1mbold\u{1b}[0m"
    );
}
