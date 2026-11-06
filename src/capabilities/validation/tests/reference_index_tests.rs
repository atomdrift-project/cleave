use crate::capabilities::validation::constraints::ReferenceIndex;

/// The linear scan the index replaced, kept as the definition of the
/// matching rules it must reproduce exactly.
fn scan<'a>(reference: &str, ids: &[&'a str]) -> Vec<&'a str> {
    let id = reference.trim_end_matches('/');
    ids.iter()
        .copied()
        .filter(|f| {
            if id.contains("::") {
                *f == id
            } else if !id.contains('/') {
                f.ends_with(&format!("::{id}")) || f.ends_with(&format!("/{id}"))
            } else {
                *f == id || f.starts_with(&format!("{id}::")) || f.starts_with(&format!("{id}/"))
            }
        })
        .collect()
}

#[test]
fn resolve_matches_a_scan_of_every_id() {
    let ids = vec![
        "objectives/c2/irc::mirc-ping",
        "objectives/c2/irc::mirc-join",
        "objectives/c2/irc/client::mirc-ping",
        "objectives/c2/ircd::daemon",
        "micro-behaviors/net/socket::open",
        "micro-behaviors/net/socket/raw::open",
        "legacy/path/open",
        "objectives/c2/irc::mirc-join",
        "well-known/tool::a:b",
        "objectives/c2",
    ];
    let index = ReferenceIndex::new(ids.clone());
    for reference in [
        "objectives/c2/irc::mirc-ping",
        "objectives/c2/irc::mirc-join",
        "objectives/c2/irc::missing",
        "mirc-ping",
        "open",
        "a:b",
        "b",
        "objectives/c2/irc",
        "objectives/c2/irc/",
        "objectives/c2",
        "objectives",
        "micro-behaviors/net/socket",
        "legacy/path",
        "legacy/path/open",
        "",
        "/",
        "missing",
    ] {
        assert_eq!(
            index.resolve(reference),
            scan(reference, &ids),
            "reference {reference:?}"
        );
    }
}
