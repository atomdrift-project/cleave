//! Hostname shape: does a host read as generated rather than chosen?
//!
//! Campaign infrastructure is often registered by script: a fresh domain per
//! wave, named by a generator. This judges the one label the registrant
//! picked -- the registrable label, left of the public suffix -- so
//! `cdn.qzxkvbnmwrt.xyz` is judged on `qzxkvbnmwrt` and `registry.npmjs.org`
//! on `npmjs`, never on a subdomain or the TLD.
//!
//! A label reads as generated when any of these holds:
//!
//! - its letters fail the English bigram model ([`random_validator`]);
//! - it mixes in two or more digits with letters after them (`x7k2m9p4`),
//!   which leaves out a product name with a version suffix (`office365`);
//! - it has a run of six consonants, or six letters with no vowel at all
//!   (`y` counts as a vowel, so `rhythm` and `crypto` pass).
//!
//! Two named datasets sit beside the shape rules: a host under
//! `trusted-fetch-hosts` (or equal to one) is never suspicious, and a host
//! under an `abused-tlds` TLD always is. See [`crate::datasets`].
//!
//! [`random_validator`]: crate::random_validator

use std::net::IpAddr;

use crate::datasets::Dataset;

/// The datasets this validator reads, resolved once.
fn datasets() -> Option<(Dataset, Dataset)> {
    Some((
        Dataset::named("trusted-fetch-hosts")?,
        Dataset::named("abused-tlds")?,
    ))
}

/// Shortest registrable label worth judging: below this, a label is too
/// short to look generated either way.
const MIN_LABEL: usize = 6;

/// Whether `s` -- a hostname, or a URL whose host is judged -- reads as
/// generated. IP literals and single-label names are never hostnames here.
#[must_use]
pub(crate) fn is_sus_hostname(s: &str) -> bool {
    let Some(host) = host(s) else {
        return false;
    };
    let Some((trusted, abused_tlds)) = datasets() else {
        return false;
    };
    // Every suffix of the host at a label boundary: `a.b.github.com`,
    // `b.github.com`, `github.com`, `com`.
    let mut suffixes = std::iter::successors(Some(host.as_str()), |h| {
        h.split_once('.').map(|(_, rest)| rest)
    });
    if suffixes.any(|suffix| trusted.contents().entries.contains(suffix)) {
        return false;
    }
    let tld = host.rsplit('.').next().unwrap_or_default();
    abused_tlds.contents().entries.contains(tld)
        || registrable_label(&host).is_some_and(|label| label_is_generated(&label))
}

/// The lowercase host of `s`: the scheme, userinfo, port, path, query and
/// fragment removed. `None` for an IP literal or a name without a dot.
fn host(s: &str) -> Option<String> {
    let s = s.trim();
    let rest = s.split_once("://").map_or(s, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit('@').next()?;
    if hostport.starts_with('[') {
        return None; // bracketed IPv6 literal
    }
    let host = hostport.split(':').next()?.trim_end_matches('.');
    if host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// The label left of the public suffix. Without a suffix list, a two-letter
/// country TLD under a short second level (`co.uk`, `com.au`) counts as
/// the suffix.
fn registrable_label(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    let second = *labels.get(n.checked_sub(2)?)?;
    let label = match (
        labels.get(n - 1),
        n.checked_sub(3).and_then(|i| labels.get(i)),
    ) {
        (Some(tld), Some(third)) if tld.len() == 2 && second.len() <= 3 => *third,
        _ => second,
    };
    Some(label.to_string())
}

fn label_is_generated(label: &str) -> bool {
    let letters = label.bytes().filter(u8::is_ascii_alphabetic).count();
    if label.len() < MIN_LABEL || letters == 0 {
        return false;
    }
    if crate::random_validator::is_random_like(label) {
        return true;
    }
    let digits = label.bytes().filter(u8::is_ascii_digit).count();
    let letter_after_digit = label
        .bytes()
        .skip_while(|b| !b.is_ascii_digit())
        .any(|b| b.is_ascii_alphabetic());
    if digits >= 2 && letter_after_digit {
        return true;
    }
    let is_vowel = |b: u8| b"aeiouy".contains(&b);
    let mut run = 0usize;
    let mut longest = 0usize;
    for b in label.bytes() {
        if b.is_ascii_alphabetic() && !is_vowel(b) {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let vowels = label.bytes().filter(|&b| is_vowel(b)).count();
    longest >= 6 || (letters >= 6 && vowels == 0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn datasets_resolve() {
        assert!(datasets().is_some());
    }

    #[test]
    fn trusted_domains_and_abused_tlds() {
        // Trusted at a label boundary only.
        assert!(!is_sus_hostname("https://x7k2m9p4.github.com/a"));
        assert!(is_sus_hostname("x7k2m9p4github.com"));
        // An abused TLD convicts a readable label.
        assert!(is_sus_hostname("http://update.tk/x"));
    }

    #[test]
    fn generated_hosts() {
        for host in [
            "qzxkvbnmwrt.xyz",
            "https://cdn.qzxkvbnmwrt.xyz/p.sh",
            "x7k2m9p4.com",
            "http://user@kwtfnttv.net:8080/x",
            "a1b2c3d4e5.co.uk",
            "bcdfghjklm.top",
        ] {
            assert!(is_sus_hostname(host), "{host}");
        }
    }

    #[test]
    fn chosen_hosts() {
        for host in [
            "registry.npmjs.org",
            "https://raw.githubusercontent.com/o/r/main/x",
            "storage.googleapis.com",
            "office365.com",
            "example.co.uk",
            "rhythm-crypto.io",
            "cloudflare.com",
            "localhost",
            "127.0.0.1",
            "http://[::1]:3000/",
            "evil.com",
        ] {
            assert!(!is_sus_hostname(host), "{host}");
        }
    }

    #[test]
    fn judges_the_registrable_label() {
        assert_eq!(
            host("https://u@Cdn.Example.CO.uk:443/p?q#f")
                .as_deref()
                .and_then(registrable_label)
                .as_deref(),
            Some("example")
        );
        assert_eq!(
            host("a.b.npmjs.org")
                .as_deref()
                .and_then(registrable_label)
                .as_deref(),
            Some("npmjs")
        );
    }
}
