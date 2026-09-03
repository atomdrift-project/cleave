//! `regex-explosion`: find regexes whose lazy DFA explodes on bundle-shaped
//! text — the pathological shape — without timing anything.
//!
//! A regex is pathological when its automaton needs a new DFA state for
//! nearly every input position: typically a counted repetition over a wide
//! class that begins at a frequent byte (`[\\/][^\r\n]{1,120}`,
//! `>\s*[^\n]{0,120}`), so each occurrence of that byte opens another
//! overlapping counter and the state is the set of all live counters. On a
//! real bundle the production lazy DFA then fills and clears its cache
//! over and over, gives up, and falls back to the PikeVM at 20–100 ms per
//! MB — against ~0.05 ms for a well-formed rule (2026-09-02 npm corpus: 37
//! such patterns were 39% of a 10 MB bundle's trait time).
//!
//! Whether that happens depends on how often the opening byte occurs, so
//! the probe runs each pattern over a fixed, deterministic haystack with a
//! real bundle's byte mix — minified-JavaScript-like statements with paths,
//! URLs, regex literals, markup and shell lines — using the production
//! engine's lazy DFA and cache size, and reads the engine's own counters:
//! bytes of DFA state built, cache clears, give-up. A well-formed pattern
//! leaves a few KB of state (median 3 KB over the 25,000-pattern corpus,
//! 99th percentile 129 KB); a pathological one leaves hundreds of KB to the
//! full megabyte or gives up. No timers: the verdict is the same on every
//! machine and in every build profile. Cost ≈ 0.3 ms per pattern.
//!
//! It deliberately does not say whether a pattern is *expensive* in
//! practice — a pathological regex whose gate atom never occurs costs
//! nothing — only that it explodes whenever its atom does occur.

use super::helpers::find_line_number;
use crate::composite_rules::{Condition, RawQuery, TextQuery, TraitDefinition};
use rayon::prelude::*;
use regex_automata::hybrid::dfa::DFA;
use regex_automata::{Anchored, Input, MatchErrorKind};
use std::sync::OnceLock;
use std::time::Instant;

/// Haystack length. Explosions show within a few KB; 128 KB keeps the
/// whole corpus under half a second on a workstation.
pub(crate) const HAYSTACK_BYTES: usize = 3 * LEG_BYTES;

/// The haystack is scanned in three equal legs over one DFA cache: two to
/// warm the automaton up (a bounded one, however large, plateaus by then —
/// two 120-wide counters multiply to ~14,000 states and are all built
/// within 128 KB), the third to see whether it is still growing.
pub(crate) const LEG_BYTES: usize = 64 << 10;

/// State growth over the last leg at or above which a pattern is
/// pathological: half a byte of new DFA state per input byte after 128 KB
/// of warm-up means the automaton is still minting a state for most
/// positions — unbounded growth, which on a real bundle fills the cache,
/// clears it repeatedly and ends in the PikeVM. A bounded automaton
/// plateaus during warm-up and adds nothing. Swept over the trait corpus
/// (2026-09-02): last-leg growth median 0, p90 0, p99 22 KB; the patterns
/// that give up on real 10 MB bundles add 100 KB to a full megabyte.
pub(crate) const GROWTH_BYTES_LIMIT: usize = LEG_BYTES / 2;

// ---------------------------------------------------------------- haystack

/// xorshift64: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
}

const IDENTS: &[&str] = &[
    "a",
    "b",
    "c",
    "e",
    "t",
    "n",
    "r",
    "i",
    "o",
    "s",
    "u",
    "l",
    "p",
    "f",
    "d",
    "h",
    "m",
    "v",
    "x",
    "y",
    "w",
    "k",
    "g",
    "el",
    "fn",
    "cb",
    "ctx",
    "opts",
    "res",
    "req",
    "err",
    "data",
    "val",
    "key",
    "obj",
    "arr",
    "str",
    "num",
    "len",
    "self",
    "that",
    "node",
    "child",
    "parent",
    "root",
    "item",
    "list",
    "map",
    "set",
    "buf",
    "out",
    "tmp",
    "ret",
    "config",
    "module",
    "exports",
    "require",
    "define",
    "window",
    "document",
    "navigator",
    "location",
    "process",
    "global",
    "Buffer",
    "Promise",
    "Object",
    "Array",
    "String",
    "Number",
    "Math",
    "JSON",
    "Date",
    "console",
    "exec",
    "spawn",
    "child_process",
    "fs",
    "path",
    "http",
    "https",
    "url",
    "crypto",
    "zlib",
];
const METHODS: &[&str] = &[
    "get",
    "set",
    "push",
    "pop",
    "map",
    "filter",
    "reduce",
    "forEach",
    "then",
    "catch",
    "call",
    "apply",
    "bind",
    "test",
    "exec",
    "match",
    "replace",
    "split",
    "join",
    "slice",
    "indexOf",
    "charCodeAt",
    "fromCharCode",
    "toString",
    "parse",
    "stringify",
    "resolve",
    "reject",
    "on",
    "emit",
    "write",
    "read",
    "open",
    "close",
    "createElement",
    "appendChild",
    "addEventListener",
    "click",
    "focus",
    "getFullYear",
    "getTime",
];
const PATHS: &[&str] = &[
    "/usr/local/bin/",
    "/usr/bin/",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/etc/",
    "/home/",
    "./src/",
    "../lib/",
    "C:\\\\Users\\\\",
    "C:\\\\Windows\\\\System32\\\\",
    "%APPDATA%\\\\",
    "/run/",
    "/mnt/",
    "/opt/",
    "node_modules/",
];
const EXTS: &[&str] = &[
    "js", "json", "ts", "exe", "dll", "vmx", "sh", "py", "txt", "png", "css", "html", "wasm",
    "node", "bin", "zip", "gz",
];
const URLS: &[&str] = &["https://", "http://", "wss://", "ftp://"];
const HOSTS: &[&str] = &[
    "example.com",
    "cdn.jsdelivr.net",
    "api.github.com",
    "localhost:3000",
    "127.0.0.1:8080",
    "raw.githubusercontent.com",
];
const WORDS: &[&str] = &[
    "source code",
    "password",
    "token",
    "secret",
    "bot",
    "crawler",
    "spider",
    "hdmi",
    "proxy",
    "socks5",
    "install",
    "update",
    "download",
    "upload",
    "payload",
    "session",
    "admin",
    "user",
    "login",
    "cookie",
];
const HEX: &[&str] = &[
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
];

fn hex_run(r: &mut Rng, out: &mut String, n: usize) {
    for _ in 0..n {
        out.push_str(r.pick(HEX));
    }
}

fn string_lit(r: &mut Rng, out: &mut String) {
    let q = r.pick(&["\"", "'", "`"]);
    out.push_str(q);
    match r.below(10) {
        0..=2 => {
            out.push_str(r.pick(PATHS));
            out.push_str(r.pick(IDENTS));
            out.push('.');
            out.push_str(r.pick(EXTS));
        }
        3..=4 => {
            out.push_str(r.pick(URLS));
            out.push_str(r.pick(HOSTS));
            out.push('/');
            out.push_str(r.pick(IDENTS));
            out.push('/');
            out.push_str(r.pick(IDENTS));
            out.push('?');
            out.push_str(r.pick(IDENTS));
            out.push('=');
            out.push_str(&r.below(1000).to_string());
            out.push('&');
            out.push_str(r.pick(IDENTS));
            out.push('=');
            out.push_str(r.pick(IDENTS));
        }
        5 => out.push_str(r.pick(WORDS)),
        6 => {
            let tag = r.pick(IDENTS);
            out.push('<');
            out.push_str(tag);
            out.push(' ');
            out.push_str(r.pick(IDENTS));
            out.push_str("=\"");
            out.push_str(r.pick(IDENTS));
            out.push_str("\">");
            out.push_str(r.pick(IDENTS));
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        7 => {
            let n = 8 + r.below(40);
            hex_run(r, out, n);
        }
        _ => {
            let n = 1 + r.below(6);
            for i in 0..n {
                if i > 0 {
                    out.push(' ');
                }
                out.push_str(r.pick(IDENTS));
            }
        }
    }
    out.push_str(q);
}

fn expr(r: &mut Rng, out: &mut String, depth: usize) {
    match r.below(16) {
        0..=3 => {
            out.push_str(r.pick(IDENTS));
            out.push('.');
            out.push_str(r.pick(METHODS));
            out.push('(');
            if depth < 2 {
                expr(r, out, depth + 1);
            } else {
                out.push_str(r.pick(IDENTS));
            }
            out.push(')');
        }
        4..=5 => {
            out.push_str(r.pick(IDENTS));
            out.push('[');
            if r.below(2) == 0 {
                out.push_str(r.pick(IDENTS));
            } else {
                out.push_str(&r.below(100).to_string());
            }
            out.push(']');
        }
        6..=7 => string_lit(r, out),
        8 => {
            out.push('{');
            let n = 1 + r.below(4);
            for i in 0..n {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(r.pick(IDENTS));
                out.push(':');
                if r.below(2) == 0 {
                    out.push_str(r.pick(IDENTS));
                } else {
                    out.push_str(&r.below(50).to_string());
                }
            }
            out.push('}');
        }
        9 => {
            out.push('[');
            let n = r.below(5);
            for i in 0..n {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(r.pick(IDENTS));
            }
            out.push(']');
        }
        10 => {
            out.push('/');
            out.push_str(r.pick(IDENTS));
            out.push_str(r.pick(&["\\d+", "[a-z]+", ".*", "\\s*", ""]));
            out.push('/');
            out.push_str(r.pick(&["", "g", "i", "gi"]));
        }
        11 => {
            out.push_str(r.pick(IDENTS));
            out.push_str(r.pick(&[">>", "<<", ">>>", "&", "|", "^"]));
            out.push_str(&r.below(32).to_string());
        }
        12 => {
            out.push('(');
            out.push_str(r.pick(IDENTS));
            out.push_str(")=>");
            out.push_str(r.pick(IDENTS));
        }
        13 => {
            out.push_str("0x");
            let n = 1 + r.below(6);
            hex_run(r, out, n);
        }
        14 => {
            out.push_str(r.pick(IDENTS));
            out.push_str(r.pick(&["===", "!==", "==", "<", ">", "&&", "||", "+", "-", "*"]));
            out.push_str(r.pick(IDENTS));
        }
        _ => out.push_str(r.pick(IDENTS)),
    }
}

fn statement(r: &mut Rng, out: &mut String) {
    match r.below(12) {
        0..=3 => {
            out.push_str("var ");
            out.push_str(r.pick(IDENTS));
            out.push('=');
            expr(r, out, 0);
            out.push(';');
        }
        4..=5 => {
            out.push_str("if(");
            expr(r, out, 0);
            out.push_str("){");
            out.push_str(r.pick(IDENTS));
            out.push('=');
            expr(r, out, 0);
            out.push('}');
        }
        6 => {
            out.push_str("function ");
            out.push_str(r.pick(IDENTS));
            out.push('(');
            let n = r.below(4);
            for i in 0..n {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(r.pick(IDENTS));
            }
            out.push_str("){return ");
            expr(r, out, 0);
            out.push('}');
        }
        7 => {
            let v = r.pick(IDENTS);
            out.push_str("for(var ");
            out.push_str(v);
            out.push_str("=0;");
            out.push_str(v);
            out.push('<');
            out.push_str(r.pick(IDENTS));
            out.push_str(".length;");
            out.push_str(v);
            out.push_str("++){");
            expr(r, out, 0);
            out.push('}');
        }
        8 => {
            out.push_str(r.pick(IDENTS));
            out.push('.');
            out.push_str(r.pick(METHODS));
            out.push('=');
            expr(r, out, 0);
            out.push(';');
        }
        9 => {
            out.push_str("return ");
            expr(r, out, 0);
            out.push(',');
            expr(r, out, 0);
            out.push(';');
        }
        10 => {
            out.push_str(r.pick(IDENTS));
            out.push('(');
            expr(r, out, 0);
            out.push(',');
            expr(r, out, 0);
            out.push_str(");");
        }
        _ => {
            out.push_str("// ");
            let n = 3 + r.below(8);
            for i in 0..n {
                if i > 0 {
                    out.push(' ');
                }
                out.push_str(r.pick(IDENTS));
            }
        }
    }
}

fn shell_line(r: &mut Rng, out: &mut String) {
    match r.below(8) {
        0..=1 => {
            out.push_str("curl -o ");
            out.push_str(r.pick(PATHS));
            out.push_str(r.pick(IDENTS));
            out.push(' ');
            out.push_str(r.pick(URLS));
            out.push_str(r.pick(HOSTS));
            out.push('/');
            out.push_str(r.pick(IDENTS));
        }
        2..=3 => {
            out.push_str("echo ");
            out.push_str(r.pick(IDENTS));
            out.push_str(" > ");
            out.push_str(r.pick(PATHS));
            out.push_str(r.pick(IDENTS));
            out.push_str("; chmod +x ");
            out.push_str(r.pick(PATHS));
            out.push_str(r.pick(IDENTS));
        }
        4 => {
            out.push_str("cp ");
            out.push_str(r.pick(PATHS));
            out.push_str(r.pick(IDENTS));
            out.push(' ');
            out.push_str(r.pick(PATHS));
            out.push('.');
            out.push_str(r.pick(IDENTS));
        }
        5 => {
            out.push_str("export ");
            out.push_str(&r.pick(IDENTS).to_ascii_uppercase());
            out.push('=');
            out.push_str(r.pick(IDENTS));
            out.push(':');
            out.push_str(r.pick(PATHS));
        }
        6 => {
            out.push_str("if [ -f ");
            out.push_str(r.pick(PATHS));
            out.push_str(r.pick(IDENTS));
            out.push_str(" ]; then ");
            out.push_str(r.pick(IDENTS));
            out.push(' ');
            out.push_str(r.pick(IDENTS));
            out.push_str("; fi");
        }
        _ => {
            out.push_str("wget -O ");
            out.push_str(r.pick(PATHS));
            out.push_str(r.pick(IDENTS));
            out.push(' ');
            out.push_str(r.pick(URLS));
            out.push_str(r.pick(HOSTS));
        }
    }
}

/// The haystack: exactly `size` bytes, identical on every host. Three in
/// four lines are minified-length (200–6,200 bytes) JavaScript-like
/// statements; one block in ten is shell-style short lines.
pub(crate) fn synthetic_bundle(size: usize) -> Vec<u8> {
    let mut r = Rng(0x9E37_79B9_7F4A_7C15);
    let mut out = String::with_capacity(size + 8192);
    while out.len() < size {
        let target = if r.below(4) == 0 {
            20 + r.below(120)
        } else {
            200 + r.below(6000)
        };
        let start = out.len();
        if r.below(10) == 0 {
            while out.len() - start < target {
                shell_line(&mut r, &mut out);
                out.push('\n');
            }
        } else {
            while out.len() - start < target {
                statement(&mut r, &mut out);
            }
            out.push('\n');
        }
    }
    out.truncate(size);
    out.into_bytes()
}

fn haystack() -> &'static [u8] {
    static H: OnceLock<Vec<u8>> = OnceLock::new();
    H.get_or_init(|| synthetic_bundle(HAYSTACK_BYTES))
}

// ---------------------------------------------------------------- probe

/// What the production lazy DFA did on the haystack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Explosion {
    /// The engine hit its give-up thresholds (production falls back to the
    /// PikeVM for the rest of the search).
    pub(crate) gave_up: bool,
    /// Times the cache filled and was cleared before the search ended.
    pub(crate) cache_clears: usize,
    /// Bytes of DFA state in the cache when the search ended (states built
    /// since the last clear).
    pub(crate) state_bytes: usize,
    /// State bytes added while scanning the last leg of the haystack.
    pub(crate) growth_bytes: usize,
}

impl Explosion {
    pub(crate) fn is_pathological(self) -> bool {
        self.gave_up || self.cache_clears > 0 || self.growth_bytes >= GROWTH_BYTES_LIMIT
    }
}

/// Run the lazy DFA over `hay` as production does — same syntax flags,
/// same cache size, same give-up thresholds, unanchored, every match,
/// resuming after each — and read its counters. `None` when the pattern
/// does not compile (another validator reports that).
pub(crate) fn probe(pattern: &str, case_insensitive: bool, hay: &[u8]) -> Option<Explosion> {
    let dfa = DFA::builder()
        .configure(
            DFA::config()
                .cache_capacity(crate::composite_rules::evaluators::regex_dfa_cache_bytes())
                .minimum_cache_clear_count(Some(3))
                .minimum_bytes_per_state(Some(10)),
        )
        .syntax(
            regex_automata::util::syntax::Config::new()
                .case_insensitive(case_insensitive)
                .multi_line(true)
                .unicode(false)
                .utf8(false),
        )
        .build(pattern)
        .ok()?;
    let mut cache = dfa.create_cache();
    let mut gave_up = false;
    // Three legs over one cache; growth is measured on the last one.
    let leg = hay.len() / 3;
    let mut before_last = 0usize;
    'legs: for (lo, hi) in [(0, leg), (leg, 2 * leg), (2 * leg, hay.len())] {
        let mut start = lo;
        while start <= hi {
            let input = Input::new(hay).range(start..hi).anchored(Anchored::No);
            match dfa.try_search_fwd(&mut cache, &input) {
                Ok(Some(m)) => start = m.offset().max(start + 1),
                Ok(None) => break,
                Err(e) => {
                    gave_up = matches!(e.kind(), MatchErrorKind::GaveUp { .. });
                    break 'legs;
                }
            }
        }
        if hi == 2 * leg {
            before_last = cache.memory_usage();
        }
    }
    let state_bytes = cache.memory_usage();
    Some(Explosion {
        gave_up,
        cache_clears: cache.clear_count(),
        state_bytes,
        growth_bytes: state_bytes.saturating_sub(before_last),
    })
}

/// Probe a pattern on the standard haystack.
pub(crate) fn explosion(pattern: &str, case_insensitive: bool) -> Option<Explosion> {
    probe(pattern, case_insensitive, haystack())
}

// ---------------------------------------------------------------- validator

fn can_use_byte_matching(pattern: &str) -> bool {
    pattern.is_ascii()
        && !pattern.contains("\\u")
        && !pattern.contains("\\p")
        && !pattern.contains("\\P")
}

struct Candidate<'a> {
    trait_idx: usize,
    pattern: &'a str,
    case_insensitive: bool,
    kind: &'static str,
}

fn candidates(traits: &[TraitDefinition]) -> Vec<Candidate<'_>> {
    traits
        .iter()
        .enumerate()
        .filter_map(|(trait_idx, t)| match &t.r#if {
            Condition::Text(TextQuery {
                regex: Some(regex),
                case_insensitive,
                ..
            }) => Some(Candidate {
                trait_idx,
                pattern: regex,
                case_insensitive: *case_insensitive,
                kind: "text",
            }),
            Condition::Raw(RawQuery {
                regex: Some(regex),
                case_insensitive,
                ..
            }) => Some(Candidate {
                trait_idx,
                pattern: regex,
                case_insensitive: *case_insensitive,
                kind: "raw",
            }),
            _ => None,
        })
        .filter(|c| can_use_byte_matching(c.pattern))
        .collect()
}

/// Outcome of one run, for the summary line and tests.
#[derive(Debug, Default)]
pub(crate) struct ExplosionReport {
    pub(crate) candidates: usize,
    pub(crate) flagged: usize,
    pub(crate) elapsed_ms: u128,
}

/// Probe every text/raw regex; one warning per pathological pattern.
pub(crate) fn find_pathological_regex_patterns(
    traits: &[TraitDefinition],
    warnings: &mut Vec<String>,
) -> ExplosionReport {
    let started = Instant::now();
    let hay = haystack();
    let cands = candidates(traits);
    let mut hits: Vec<(usize, Explosion)> = cands
        .par_iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let e = probe(c.pattern, c.case_insensitive, hay)?;
            e.is_pathological().then_some((i, e))
        })
        .collect();
    hits.sort_by_key(|&(i, _)| i);
    for (i, e) in &hits {
        let c = &cands[*i];
        let t = &traits[c.trait_idx];
        let file = t.defined_in.to_str().unwrap_or("unknown").to_string();
        let location = match find_line_number(&file, &t.id) {
            Some(line) => format!("{file}:{line}"),
            None => file,
        };
        let how = if e.gave_up {
            "gave up (PikeVM fallback in production)".to_string()
        } else if e.cache_clears > 0 {
            format!(
                "filled and cleared its {} KB cache {} times",
                crate::composite_rules::evaluators::regex_dfa_cache_bytes() >> 10,
                e.cache_clears
            )
        } else {
            format!(
                "was still growing — {} KB of new states over the last {} KB (a typical trait regex adds none)",
                e.growth_bytes >> 10,
                LEG_BYTES >> 10
            )
        };
        warnings.push(format!(
            "Regex explosion: trait '{}' in {} — on {} KB of bundle-shaped text the lazy DFA of this `type: {}` regex {}. Pattern: {}",
            t.id,
            location,
            HAYSTACK_BYTES >> 10,
            c.kind,
            how,
            c.pattern
        ));
    }
    let report = ExplosionReport {
        candidates: cands.len(),
        flagged: hits.len(),
        elapsed_ms: started.elapsed().as_millis(),
    };
    tracing::info!(
        candidates = report.candidates,
        flagged = report.flagged,
        elapsed_ms = report.elapsed_ms,
        "regex-explosion: lazy-DFA explosion check"
    );
    report
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn haystack_is_deterministic_bundle_shaped_text() {
        let a = synthetic_bundle(64 << 10);
        let b = synthetic_bundle(64 << 10);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64 << 10);
        assert!(a.is_ascii());
        let slashes = a.iter().filter(|&&c| c == b'/').count();
        let newlines = a.iter().filter(|&&c| c == b'\n').count();
        assert!(slashes > 500, "slashes: {slashes}");
        assert!(newlines > 10 && newlines < 2000, "newlines: {newlines}");
        let longest = a.split(|&c| c == b'\n').map(<[u8]>::len).max().unwrap_or(0);
        assert!(longest > 2000, "longest line: {longest}");
    }

    /// The 2026-09-02 rewrites: each pathological original is flagged,
    /// each presence-equivalent rewrite is not.
    #[test]
    fn rewritten_patterns_stop_exploding() {
        let pairs = [
            (
                r#"(^|[\\/])[^\r\n]{1,120}\.vmx($|[\s"'`])"#,
                // One counter, not two: the line-start branch stops at the
                // first slash, where the slash branch takes over.
                r#"(^[^\r\n\\/]{1,120}|[\\/][^\r\n\\/]{0,120})\.vmx($|[\s"'`])"#,
            ),
            (
                r"(wget\s+-O|>\s*)[^\n]{0,120}(/dev/shm/|/tmp/)\.[a-zA-Z0-9][a-zA-Z0-9._-]{2,120}\b",
                r"(wget\s+-O[^\n]{0,120}|>\s*[^\n>]{0,120})(/dev/shm/|/tmp/)\.[a-zA-Z0-9][a-zA-Z0-9._-]{2,120}\b",
            ),
            (
                r#"(?i)[/\\~]([^"\r\n]{0,60}[/\\])?source\s+code"#,
                r#"(?i)[/\\~](source\s+code|[^"\r\n/\\]{0,60}[/\\]source\s+code)"#,
            ),
            (
                r"\{[^}\n]{0,120}\[[^\]]{1,80}\]\s*:[^}\n]{0,120}\}\s*=",
                r"\{[^{}\n]{0,120}\[[^\[\]]{1,80}\]\s*:[^}\n]{0,120}\}\s*=",
            ),
            (
                r"[a-zA-Z_$][\w$]{0,40}\.click\s*\(\s*\)",
                r"\b[a-zA-Z_$][\w$]*\.click\s*\(\s*\)",
            ),
            (
                r"\[[^\r\n]{1,900}\]\s*\([^;\r\n]{1,256},\s*0\s*,\s*(false|true)\s*\)",
                r"\[[^\r\n\]]{1,900}\]\s*\([^;\r\n]{1,256},\s*0\s*,\s*(false|true)\s*\)",
            ),
        ];
        for (bad, good) in pairs {
            let b = explosion(bad, false).unwrap();
            let g = explosion(good, false).unwrap();
            assert!(b.is_pathological(), "should explode: {bad} ({b:?})");
            assert!(!g.is_pathological(), "should not explode: {good} ({g:?})");
        }
    }

    #[test]
    fn well_formed_patterns_are_quiet() {
        for p in [
            r"\bchild_process\b",
            r"\bpassword\s*[:=]",
            r"https?://[A-Za-z0-9.-]{1,64}/[A-Za-z0-9._/-]{1,64}",
            r"\bexec(Sync)?\s*\(",
            r"/tmp/\.[A-Za-z0-9][A-Za-z0-9._-]{2,64}\b",
            r"(?i)\b(this\s+)?(document|pdf|file)\s+(is|appears to be)\s+corrupt(ed)?\b",
            r"\b\d{1,3}\.\d{1,3}\.0\.0\b",
            r"[^\n]{0,200}\bnet(\.exe)?\s+session\b",
            r"\bfunction\s+[A-Za-z_$][\w$]*\s*\(",
        ] {
            let e = explosion(p, false).unwrap();
            assert!(!e.is_pathological(), "should not explode: {p} ({e:?})");
        }
    }

    #[test]
    fn double_overlapping_run_gives_up() {
        let e = explosion(r"\w[^\n]{0,120}\w[^\n]{0,120}\.vmx\b", false).unwrap();
        assert!(e.is_pathological(), "{e:?}");
    }
}
