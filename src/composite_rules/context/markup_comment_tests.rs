#![allow(clippy::unwrap_used)]
use super::mask_markup_comments;

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
