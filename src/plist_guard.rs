//! Bounded parsing of untrusted property lists.
//!
//! Two plist shapes take the process down, and neither is a panic that
//! `catch_unwind` could recover:
//!
//! - A binary plist may reference one collection from many places (a DAG; the
//!   reader rejects only cycles), and the reader expands every reference into
//!   its own copy. A 171-byte DAG expands to 124 GB.
//! - Deserializing recurses once per nesting level, so a deep nest (100k
//!   `<array>`s, about 700 KB) overflows the stack and aborts.
//!
//! [`to_json`] refuses both before they cost anything. It mirrors filefacts'
//! `plist_guard`, which is private to that crate.

/// Nesting cap. Real Apple artifacts stay far below it.
const MAX_DEPTH: usize = 128;

/// Values a binary plist may expand to beyond two per input byte. Every
/// object costs a marker byte and every reference at least one more, so only
/// a plist reusing one collection under many references can exceed this.
const EXTRA_VALUES: u64 = 4096;

/// Parse a plist (XML, binary or ASCII) into JSON, or `None` when it does not
/// parse, nests deeper than [`MAX_DEPTH`], or is a binary plist whose shared
/// references expand past what its size allows.
pub(crate) fn to_json(bytes: &[u8]) -> Option<serde_json::Value> {
    if bytes.starts_with(b"bplist00") {
        let cap = (bytes.len() as u64)
            .saturating_mul(2)
            .saturating_add(EXTRA_VALUES);
        if bplist_expanded_len(bytes, cap).is_some_and(|len| len > cap) {
            tracing::debug!(
                len = bytes.len(),
                cap,
                "binary plist expands past its cap; not parsed"
            );
            return None;
        }
    }
    // `Value::from_reader` builds the tree without recursing, so the depth is
    // checked on the tree before anything recursive (conversion, drop) runs.
    let tree = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    let too_deep = depth_exceeds(&tree, MAX_DEPTH);
    dismantle(tree);
    if too_deep {
        tracing::debug!(
            len = bytes.len(),
            "plist nests deeper than {MAX_DEPTH} levels; not parsed"
        );
        return None;
    }
    plist::from_bytes(bytes).ok()
}

/// Whether any collection in `value` sits deeper than `cap`, the root being
/// at depth 1. Iterative, so it is safe on the trees it rejects.
fn depth_exceeds(value: &plist::Value, cap: usize) -> bool {
    let mut stack = vec![(value, 1usize)];
    while let Some((value, depth)) = stack.pop() {
        match value {
            plist::Value::Array(items) if depth <= cap => {
                stack.extend(items.iter().map(|child| (child, depth + 1)));
            }
            plist::Value::Dictionary(entries) if depth <= cap => {
                stack.extend(entries.values().map(|child| (child, depth + 1)));
            }
            plist::Value::Array(_) | plist::Value::Dictionary(_) => return true,
            _ => {}
        }
    }
    false
}

/// Drop a plist tree without recursing: moving each collection's children out
/// first keeps the drop flat however deep the tree is.
fn dismantle(value: plist::Value) {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            plist::Value::Array(items) => stack.extend(items),
            plist::Value::Dictionary(entries) => stack.extend(entries.into_iter().map(|(_, v)| v)),
            _ => {}
        }
    }
}

/// A big-endian unsigned integer of `width` (1..=8) bytes at `at`.
fn be_uint(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
    let field = bytes.get(at..at.checked_add(width)?)?;
    (width <= 8).then(|| field.iter().fold(0, |n, &b| (n << 8) | u64::from(b)))
}

/// The number of values a binary plist expands to, counting a shared object
/// again at every reference, saturating just past `cap`. `None` when the
/// object table cannot be read, or has a cycle; the plist reader then
/// reports the malformation itself.
fn bplist_expanded_len(bytes: &[u8], cap: u64) -> Option<u64> {
    let trailer = bytes.len().checked_sub(32)?;
    let offset_width = usize::from(*bytes.get(trailer + 6)?);
    let ref_width = usize::from(*bytes.get(trailer + 7)?);
    let objects = usize::try_from(be_uint(bytes, trailer + 8, 8)?).ok()?;
    let top = usize::try_from(be_uint(bytes, trailer + 16, 8)?).ok()?;
    let table = usize::try_from(be_uint(bytes, trailer + 24, 8)?).ok()?;
    if !(1..=8).contains(&offset_width) || !(1..=8).contains(&ref_width) || objects > bytes.len() {
        return None;
    }
    // The objects a collection references; empty for a scalar.
    let children = |object: usize| -> Option<Vec<usize>> {
        let at = usize::try_from(be_uint(
            bytes,
            table.checked_add(object.checked_mul(offset_width)?)?,
            offset_width,
        )?)
        .ok()?;
        let marker = *bytes.get(at)?;
        let refs_per_entry = match marker >> 4 {
            0xA..=0xC => 1,
            0xD => 2,
            _ => return Some(Vec::new()),
        };
        let (count, refs_at) = match marker & 0x0F {
            0x0F => {
                // The count follows as an int object: 0x1n, then 2^n bytes.
                let int_marker = *bytes.get(at.checked_add(1)?)?;
                if int_marker >> 4 != 0x1 {
                    return None;
                }
                let width = 1usize.checked_shl(u32::from(int_marker & 0x0F))?;
                (be_uint(bytes, at.checked_add(2)?, width)?, at + 2 + width)
            }
            n => (u64::from(n), at + 1),
        };
        let refs = usize::try_from(count).ok()?.checked_mul(refs_per_entry)?;
        if refs.checked_mul(ref_width)? > bytes.len() {
            return None;
        }
        (0..refs)
            .map(|i| {
                let child = be_uint(bytes, refs_at.checked_add(i * ref_width)?, ref_width)?;
                usize::try_from(child).ok().filter(|&c| c < objects)
            })
            .collect()
    };

    // Post-order walk with memoized sizes: a collection is its start and end
    // plus everything its references expand to. Each reference read is an
    // edge the expansion repeats at least once, so reading more than `cap` of
    // them already shows the expansion passes it; that count also keeps the
    // walk itself linear when many objects share one large collection.
    const OPEN: u64 = u64::MAX;
    let mut size = vec![0u64; objects];
    let top_kids = children(top)?;
    let mut refs_read = top_kids.len() as u64;
    let mut stack = vec![(top, top_kids, 0usize)];
    *size.get_mut(top)? = OPEN;
    while let Some((object, kids, next)) = stack.last_mut() {
        if refs_read > cap {
            return Some(refs_read);
        }
        if let Some(&kid) = kids.get(*next) {
            *next += 1;
            match *size.get(kid)? {
                OPEN => return None,
                0 => {
                    let grandkids = children(kid)?;
                    refs_read = refs_read.saturating_add(grandkids.len() as u64);
                    if grandkids.is_empty() {
                        *size.get_mut(kid)? = 1;
                    } else {
                        *size.get_mut(kid)? = OPEN;
                        stack.push((kid, grandkids, 0));
                    }
                }
                _ => {}
            }
            continue;
        }
        let total = kids
            .iter()
            .try_fold(2u64, |total, &kid| {
                Some(total.saturating_add(*size.get(kid)?))
            })?
            .min(cap.saturating_add(1));
        let object = *object;
        *size.get_mut(object)? = total;
        stack.pop();
        if total > cap {
            return Some(total);
        }
    }
    size.get(top).copied()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// An XML plist of `levels` nested `<array>`s.
    fn nested_xml(levels: usize) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\">{}<string>x</string>{}</plist>",
            "<array>".repeat(levels),
            "</array>".repeat(levels)
        )
        .into_bytes()
    }

    /// A binary plist of `levels` arrays, each holding 14 references to the
    /// next: a few hundred bytes that expand to 14^`levels` values.
    fn reference_dag(levels: u8) -> Vec<u8> {
        let mut bytes = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for level in 0..levels {
            offsets.push(bytes.len() as u8);
            // An array marker with its count, 14, in the low nibble.
            bytes.push(0xA0 | 0x0E);
            bytes.extend(std::iter::repeat_n(level + 1, 14));
        }
        offsets.push(bytes.len() as u8);
        bytes.extend([0x10, 0x00]);
        let table = bytes.len() as u64;
        bytes.extend(&offsets);
        bytes.extend([0u8; 6]);
        bytes.extend([1, 1]);
        bytes.extend((offsets.len() as u64).to_be_bytes());
        bytes.extend(0u64.to_be_bytes());
        bytes.extend(table.to_be_bytes());
        bytes
    }

    /// Run `f` on a 2 MiB thread, the stack a rayon worker gets.
    fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap()
    }

    #[test]
    fn ordinary_plists_convert() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.example.agent</string><key>RunAtLoad</key><true/></dict></plist>"#;
        let json = to_json(xml).unwrap();
        assert_eq!(json["Label"], "com.example.agent");
        assert_eq!(json["RunAtLoad"], true);
        assert!(to_json(&nested_xml(MAX_DEPTH - 1)).is_some());
    }

    #[test]
    fn deep_nesting_is_refused_without_overflowing_the_stack() {
        assert!(on_small_stack(|| to_json(&nested_xml(100_000))).is_none());
    }

    #[test]
    fn shared_reference_expansion_is_refused() {
        // 14^12 values from about 200 bytes.
        let dag = reference_dag(12);
        assert!(dag.len() < 512);
        assert!(on_small_stack(move || to_json(&dag)).is_none());
        // A shallow DAG within the cap still parses.
        assert!(to_json(&reference_dag(2)).is_some());
    }
}
