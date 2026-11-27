#![allow(clippy::unwrap_used)]

/// The masker with no cancellation flag, which therefore always finishes.
fn mask_markup_comments(source: &[u8]) -> Option<Vec<u8>> {
    super::mask_markup_comments(source, None).unwrap()
}

#[test]
fn leaves_sources_without_comments_unallocated() {
    assert_eq!(mask_markup_comments(b"<p>live</p>"), None);
}

#[test]
fn masks_html_and_aspnet_comments_without_shifting_offsets() {
    let source =
        b"<p>live</p>\n<!-- hidden\ncode -->\n<%-- server hidden --%>\n<textarea>tail</textarea>";
    let masked = mask_markup_comments(source).unwrap();
    assert_eq!(masked.len(), source.len());
    assert_eq!(masked.iter().filter(|b| **b == b'\n').count(), 4);
    assert!(masked.windows(4).any(|w| w == b"live"));
    assert!(!masked.windows(6).any(|w| w == b"hidden"));
    assert!(masked.windows(4).any(|w| w == b"tail"));
}

#[test]
fn does_not_treat_raw_text_element_contents_as_html_comments() {
    let source = b"<textarea><!-- submitted source --></textarea><script><!-- js source --></script><!-- page note -->";
    let masked = mask_markup_comments(source).unwrap();
    assert!(
        masked
            .windows(b"<!-- submitted source -->".len())
            .any(|w| w == b"<!-- submitted source -->")
    );
    assert!(
        masked
            .windows(b"<!-- js source -->".len())
            .any(|w| w == b"<!-- js source -->")
    );
    assert!(
        !masked
            .windows(b"page note".len())
            .any(|w| w == b"page note")
    );
}

#[test]
fn unterminated_comments_mask_to_eof_but_keep_line_breaks() {
    let source = b"live\n<!-- hidden\nmore";
    let masked = mask_markup_comments(source).unwrap();
    assert_eq!(masked.len(), source.len());
    assert_eq!(masked.iter().filter(|b| **b == b'\n').count(), 2);
    assert!(masked.starts_with(b"live\n"));
    assert!(!masked.windows(6).any(|w| w == b"hidden"));
}

/// Masking must stay linear: the old walk sought a closing `>` from every
/// `<`, so a large file with many `<` and no `>` cost O(n²).
fn assert_linear(source: &[u8]) -> Option<Vec<u8>> {
    let started = std::time::Instant::now();
    let masked = mask_markup_comments(source);
    let elapsed = started.elapsed();
    // Linear work on a few MB takes milliseconds even unoptimized; the
    // quadratic walk took minutes on this much input.
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "masking {} bytes took {elapsed:?}",
        source.len()
    );
    masked
}

#[test]
fn arrow_annotations_without_any_close_bracket_are_linear() {
    // The shape of a CASTEP `.md` output (Isurwars/Correlation's
    // examples/Cellulose/Cellulose.md, 70 MB): every line ends in a `<--`
    // annotation and the file has no `>` at all. It held a scan for hours.
    let line = b"   -1.4325306526941392E+003   -1.4322167161074769E+003  <-- E\n";
    let source = line.repeat(4 * 1024 * 1024 / line.len());
    assert_eq!(assert_linear(&source), None);
}

#[test]
fn unquoted_apostrophes_after_bare_angles_are_linear() {
    // Quotes flip the tag scanner's state; `<a it's` with no `>` used to scan
    // to EOF from every `<`.
    let source = b"x <a it's 1 <b don't\n".repeat(200_000);
    assert_eq!(assert_linear(&source), None);
}

#[test]
fn unterminated_raw_text_start_tags_end_the_walk() {
    // A start tag never closed swallows the rest of the input in the HTML
    // tokenizer: a later `<!--` is attribute text, not a comment. Repeated,
    // the old walk rescanned to EOF from each one.
    let mut source = b"<!-- lead -->\n".to_vec();
    source.extend(b"<script src='x\n".repeat(200_000));
    source.extend(b"<!-- tail -->");
    let masked = assert_linear(&source).unwrap();
    assert!(!masked.windows(4).any(|w| w == b"lead"));
    assert!(masked.ends_with(b"<!-- tail -->"));
}

#[test]
fn unclosed_raw_text_elements_are_linear() {
    let mut source = b"<script>".to_vec();
    source.extend(b"if (a </scrip b) { c('<!--') }\n".repeat(150_000));
    assert_eq!(assert_linear(&source), None);
}

#[test]
fn bare_angles_do_not_hide_later_comments() {
    let source = b"E <-- energy\n<1 and a<b\n<!-- hidden -->\n<p>live</p>";
    let masked = mask_markup_comments(source).unwrap();
    assert_eq!(masked.len(), source.len());
    assert!(masked.starts_with(b"E <-- energy\n<1 and a<b\n"));
    assert!(!masked.windows(6).any(|w| w == b"hidden"));
    assert!(masked.ends_with(b"<p>live</p>"));
}

#[test]
fn raw_text_names_match_whole_and_case_insensitively() {
    // `<scripts>` is not `<script>`, so its comment is still a comment;
    // `<SCRIPT>` is, so its contents are raw text until `</script >`.
    let source =
        b"<scripts><!-- a --></scripts><SCRIPT type=\"x>y\"><!-- b --></script ><!-- c -->";
    let masked = mask_markup_comments(source).unwrap();
    assert!(!masked.windows(6).any(|w| w == b"<!-- a"));
    assert!(masked.windows(10).any(|w| w == b"<!-- b -->"));
    assert!(!masked.windows(6).any(|w| w == b"<!-- c"));
}

#[test]
fn plaintext_ends_the_walk() {
    let source = b"<!-- a --><plaintext><!-- b -->";
    let masked = mask_markup_comments(source).unwrap();
    assert!(!masked.windows(6).any(|w| w == b"<!-- a"));
    assert!(masked.ends_with(b"<plaintext><!-- b -->"));
}
