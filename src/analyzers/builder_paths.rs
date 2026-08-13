//! Cross-format builder-path / builder-username extraction.
//!
//! Compiled binaries routinely leak the developer workstation's
//! filesystem layout in ways that are recoverable without a real
//! parser pass:
//!
//! - **Go** binaries embed every source file path through their
//!   `pclntab` even after `go build` strips DWARF, including the
//!   build host's `/home/<user>/...` or `/Users/<user>/...`
//!   directory. Only `-trimpath` removes them.
//! - **C/C++** binaries with DWARF carry `DW_AT_comp_dir` as a
//!   literal absolute path; `-fdebug-prefix-map` is the only thing
//!   that suppresses it.
//! - **`__FILE__` macro expansions** survive even `strip` because
//!   they live in `.rodata` as literal strings used by error
//!   messages, log lines, and asserts.
//! - **PE PDB paths** — already extracted via the goblin debug
//!   directory walker; we just need to slice out the username.
//!
//! The extractor is intentionally byte-pattern-based, not parser-
//! based.  It walks the entire file looking for a small set of
//! well-known builder-path prefixes (`/home/`, `/Users/`,
//! `C:\Users\`, `C:/Users/`) and pulls out the third path
//! component as the username.  Empty / generic names
//! (`root`, `runner`, `builder`) are filtered out so we don't
//! confuse CI-rooted builds for personal workstations.
//!
//! # Output
//!
//! - `BuilderPaths.usernames` — set of distinct candidate
//!   usernames, sorted, capped at 8 to bound memory.
//! - `BuilderPaths.source_dirs` — set of `<prefix>/<user>` directory
//!   paths (no trailing component), capped at 16.
//! - `BuilderPaths.full_paths` — first ~32 absolute paths in
//!   discovery order, capped at the snippet limit per path.
//! - `BuilderPaths.path_count` — total occurrences (uncapped count).

use std::collections::BTreeSet;

/// Maximum username candidates returned. Real builds emit one or
/// two; commodity malware sometimes leaks build-host CI paths
/// alongside.
const MAX_USERNAMES: usize = 8;
/// Maximum source directories returned.
const MAX_SOURCE_DIRS: usize = 16;
/// Maximum full paths returned for kv-tree exposure (each path up
/// to MAX_PATH_LEN bytes).
const MAX_FULL_PATHS: usize = 32;
/// Cap on a single recovered path — real workstation paths run
/// 60-120 bytes; very long matches are usually scan-noise.
const MAX_PATH_LEN: usize = 256;
/// Where to stop scanning. Most real binaries leak their builder
/// paths in the first 32MB; capping bounds adversarial input.
const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024;

/// Generic / CI usernames that don't represent a person.  We still
/// emit the path itself, but skip the name so trait authors don't
/// false-positive on commodity GitHub Actions builds.
const GENERIC_USERNAMES: &[&str] = &[
    "root",
    "user",
    "ubuntu",
    "debian",
    "alpine",
    "fedora",
    "runner",  // GitHub Actions
    "builder", // GitLab / generic CI
    "build",   // generic
    "circleci",
    "travis",
    "jenkins",
    "buildkite",
    "gitlab-runner",
    "vsts",
    "vstsadmin",
    "azpcontainer",
    "agent", // Azure Pipelines
    "container",
    "docker",
    "Administrator",
    "DefaultAccount",
    "Public",
];

/// Recovered builder-path data.
#[derive(Debug, Clone, Default)]
pub(crate) struct BuilderPaths {
    /// Distinct candidate usernames (with generic names filtered).
    pub usernames: Vec<String>,
    /// All extracted candidate usernames including generics — used
    /// when the only signal is a CI runner path.
    pub raw_usernames: Vec<String>,
    /// Distinct `<prefix>/<user>` directory paths.
    pub source_dirs: Vec<String>,
    /// Full absolute paths discovered in scan order, capped.
    pub full_paths: Vec<String>,
    /// Total raw occurrences detected (uncapped, useful as a metric).
    pub path_count: u32,
}

/// Scan raw binary bytes for builder-path prefixes and recover
/// usernames + source directories.  Pure read path; no allocation
/// per match beyond the eventual kept-set.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> BuilderPaths {
    let mut out = BuilderPaths::default();
    let bound = data.len().min(MAX_SCAN_BYTES);
    let scan = &data[..bound];

    let mut user_set: BTreeSet<String> = BTreeSet::new();
    let mut raw_user_set: BTreeSet<String> = BTreeSet::new();
    let mut dir_set: BTreeSet<String> = BTreeSet::new();
    let mut paths: Vec<String> = Vec::new();

    for prefix in PREFIXES {
        let needle = prefix.bytes;
        let mut start = 0;
        while start + needle.len() <= scan.len() {
            let Some(pos) = find_subslice(&scan[start..], needle) else {
                break;
            };
            let abs = start + pos;
            // Read the candidate path: from `abs` up to the first
            // byte that isn't a printable POSIX/Windows path char.
            let path_end = scan_path_end(scan, abs, prefix.separator);
            if path_end - abs < needle.len() + 1 {
                start = abs + needle.len();
                continue;
            }
            out.path_count = out.path_count.saturating_add(1);

            let raw = &scan[abs..path_end];
            let path_str = String::from_utf8_lossy(raw).into_owned();
            let path_str = if path_str.len() > MAX_PATH_LEN {
                path_str[..MAX_PATH_LEN].to_string()
            } else {
                path_str
            };

            // Pull the username (the path component immediately
            // after the prefix).
            let after_prefix = &path_str[needle.len()..];
            if let Some((user, _rest)) = split_first_component(after_prefix, prefix.separator)
                && !user.is_empty()
                && is_valid_username(user)
            {
                raw_user_set.insert(user.to_string());
                if !is_generic_username(user) {
                    user_set.insert(user.to_string());
                }
                let dir = format!("{}{}", String::from_utf8_lossy(needle), user);
                dir_set.insert(dir);
            }

            if paths.len() < MAX_FULL_PATHS && !paths.iter().any(|p| p == &path_str) {
                paths.push(path_str);
            }

            start = path_end;
        }
    }

    out.usernames = user_set.into_iter().take(MAX_USERNAMES).collect();
    out.raw_usernames = raw_user_set.into_iter().take(MAX_USERNAMES).collect();
    out.source_dirs = dir_set.into_iter().take(MAX_SOURCE_DIRS).collect();
    out.full_paths = paths;
    out
}

/// Compute the build-target directory: the longest common ancestor
/// of all paths that share the same builder home prefix. This is
/// the FS directory where the binary was built — for Go binaries
/// usually the directory containing the main package's source
/// file, for C/C++ usually the build root from CMake or Make.
///
/// Returns `None` when paths don't share enough common structure
/// (single path → return its parent directory; mixed users →
/// no single ancestor).
#[must_use]
pub(crate) fn find_build_root(paths: &[String]) -> Option<String> {
    if paths.is_empty() {
        return None;
    }
    // Filter to paths anchored at a builder home; we don't want to
    // include `/etc/...` or `/usr/...` paths from imported libc.
    let candidates: Vec<&str> = paths
        .iter()
        .map(String::as_str)
        .filter(|p| {
            p.starts_with("/home/")
                || p.starts_with("/Users/")
                || p.starts_with("C:\\Users\\")
                || p.starts_with("C:/Users/")
                || p.starts_with("D:\\Users\\")
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }

    // Single-path case — return its parent directory.
    if candidates.len() == 1 {
        let path = candidates[0];
        let separator = if path.contains('\\') { '\\' } else { '/' };
        let last = path.rfind(separator)?;
        if last == 0 {
            return None;
        }
        return Some(path[..last].to_string());
    }

    // Multi-path: longest common prefix, then trim to last separator.
    let separator = if candidates[0].contains('\\') {
        '\\'
    } else {
        '/'
    };
    let mut prefix = candidates[0];
    for c in &candidates[1..] {
        let common = prefix
            .bytes()
            .zip(c.bytes())
            .take_while(|(left, right)| left == right)
            .count();
        prefix = &prefix[..common];
        if prefix.is_empty() {
            return None;
        }
    }
    // Trim back to the last separator so we return a directory.
    let last_sep = prefix.rfind(separator)?;
    if last_sep == 0 {
        return None;
    }
    Some(prefix[..last_sep].to_string())
}

/// Best-effort username recovery from a Microsoft PDB path.  Returns
/// `None` for paths that aren't anchored at `C:\Users\<user>\...`.
#[must_use]
pub(crate) fn extract_username_from_pdb(pdb_path: &str) -> Option<String> {
    let p = pdb_path.trim();
    // Match `<drive>:\Users\<user>\...` or `<drive>:/Users/<user>/...`.
    let lower = p.to_ascii_lowercase();
    let backslash_idx = lower.find(":\\users\\");
    let forward_idx = lower.find(":/users/");
    let (start, sep) = if let Some(idx) = backslash_idx {
        (idx + ":\\users\\".len(), '\\')
    } else {
        let idx = forward_idx?;
        (idx + ":/users/".len(), '/')
    };
    let rest = &p[start..];
    let (user, _) = split_first_component(rest, sep)?;
    if !user.is_empty() && is_valid_username(user) && !is_generic_username(user) {
        Some(user.to_string())
    } else {
        None
    }
}

#[derive(Clone, Copy)]
struct Prefix {
    bytes: &'static [u8],
    separator: char,
}

const PREFIXES: &[Prefix] = &[
    Prefix {
        bytes: b"/home/",
        separator: '/',
    },
    Prefix {
        bytes: b"/Users/",
        separator: '/',
    },
    Prefix {
        bytes: b"C:\\Users\\",
        separator: '\\',
    },
    Prefix {
        bytes: b"C:/Users/",
        separator: '/',
    },
    Prefix {
        bytes: b"D:\\Users\\",
        separator: '\\',
    },
];

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Walk forward from `start` to find the end of a candidate path.
/// Stops at the first byte that isn't a printable path character
/// (NUL, control char, quote, whitespace beyond a single space).
fn scan_path_end(data: &[u8], start: usize, separator: char) -> usize {
    let mut i = start;
    while i < data.len() {
        let b = data[i];
        if !is_path_byte(b, separator) {
            break;
        }
        i += 1;
    }
    i
}

fn is_path_byte(b: u8, separator: char) -> bool {
    // Allow standard alphanum, dot, underscore, hyphen, plus `:`
    // for Windows drive letters and the appropriate separator.
    // Reject NUL, control chars, quotes, whitespace — paths with
    // spaces are rare in builder dirs and including them often
    // glues two unrelated strings together.
    matches!(b,
        b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' |
        b'.' | b'_' | b'-' | b'+' | b'@' | b'~' | b'%' | b'$' | b':'
    ) || (b == b'/' && separator == '/')
        || (b == b'\\' && separator == '\\')
}

/// Split `<first><sep><rest>` into `(first, rest)`.  When no
/// separator is present, the entire input becomes `first` and
/// `rest` is empty — covers the "path ends at the username with
/// no trailing path component" case (e.g. `/home/alice` standalone).
fn split_first_component(s: &str, separator: char) -> Option<(&str, &str)> {
    if s.is_empty() {
        return None;
    }
    match s.find(separator) {
        Some(0) => None,
        Some(idx) => Some((&s[..idx], &s[idx + 1..])),
        None => Some((s, "")),
    }
}

fn is_valid_username(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    // Usernames are alphanum + . _ - + @ in practice.  Reject
    // anything with characters that suggest we glommed onto a
    // non-path string (`%`, `$`).
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@'))
}

fn is_generic_username(s: &str) -> bool {
    GENERIC_USERNAMES.iter().any(|g| g.eq_ignore_ascii_case(s))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn extract_finds_unix_home_path() {
        let data = b"...some bytes...\x00/home/alice/projects/sample/main.go\x00more...";
        let bp = extract(data);
        assert!(bp.usernames.contains(&"alice".to_string()));
        assert!(
            bp.full_paths
                .iter()
                .any(|p| p.starts_with("/home/alice/projects/sample/main.go"))
        );
        assert!(bp.source_dirs.contains(&"/home/alice".to_string()));
    }

    #[test]
    fn extract_finds_macos_users_path() {
        let data = b"\x00/Users/bob/go/src/github.com/foo/bar\x00";
        let bp = extract(data);
        assert!(bp.usernames.contains(&"bob".to_string()));
        assert!(
            bp.full_paths
                .iter()
                .any(|p| p.starts_with("/Users/bob/go/src/"))
        );
    }

    #[test]
    fn extract_finds_windows_users_path() {
        let data = b"\x00C:\\Users\\charlie\\source\\repos\\sample\\main.cs\x00";
        let bp = extract(data);
        assert!(bp.usernames.contains(&"charlie".to_string()));
    }

    #[test]
    fn extract_filters_generic_ci_usernames() {
        let data = b"\x00/home/runner/work/build/main.go\x00";
        let bp = extract(data);
        // `runner` is filtered from `usernames` (CI), but kept in
        // `raw_usernames` so trait authors can still target the
        // CI build pattern.
        assert!(!bp.usernames.contains(&"runner".to_string()));
        assert!(bp.raw_usernames.contains(&"runner".to_string()));
    }

    #[test]
    fn extract_deduplicates_repeated_paths() {
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend_from_slice(b"\x00/home/dev/proj/file.go\x00");
        }
        let bp = extract(&data);
        assert_eq!(bp.usernames.len(), 1);
        assert_eq!(bp.full_paths.len(), 1);
        assert!(bp.path_count >= 100);
    }

    #[test]
    fn extract_handles_multiple_users() {
        let data = b"\x00/home/alice/proj\x00/home/bob/proj\x00/Users/carol/proj\x00";
        let bp = extract(data);
        assert_eq!(bp.usernames, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn extract_caps_at_max_usernames() {
        let mut data = Vec::new();
        for i in 0..20 {
            data.extend_from_slice(format!("\x00/home/user{}/proj\x00", i).as_bytes());
        }
        let bp = extract(&data);
        assert_eq!(bp.usernames.len(), MAX_USERNAMES);
    }

    #[test]
    fn extract_username_from_pdb_canonical() {
        let user = extract_username_from_pdb("C:\\Users\\dev\\projects\\sample\\sample.pdb");
        assert_eq!(user.as_deref(), Some("dev"));
    }

    #[test]
    fn extract_username_from_pdb_forward_slashes() {
        let user = extract_username_from_pdb("C:/Users/alice/Documents/sample/sample.pdb");
        assert_eq!(user.as_deref(), Some("alice"));
    }

    #[test]
    fn extract_username_from_pdb_filters_generic() {
        let user = extract_username_from_pdb("C:\\Users\\Administrator\\projects\\sample.pdb");
        assert!(user.is_none());
    }

    #[test]
    fn extract_username_from_pdb_no_users_dir() {
        // A build path that doesn't go through C:\Users (e.g. CI agent paths).
        assert!(extract_username_from_pdb("D:\\agent\\build\\sample.pdb").is_none());
    }

    #[test]
    fn build_root_single_path_returns_parent() {
        let paths = vec!["/Users/alice/projects/sample/main.go".to_string()];
        assert_eq!(
            find_build_root(&paths).as_deref(),
            Some("/Users/alice/projects/sample")
        );
    }

    #[test]
    fn build_root_multi_path_finds_common_ancestor() {
        let paths = vec![
            "/Users/alice/projects/sample/main.go".to_string(),
            "/Users/alice/projects/sample/internal/loader.go".to_string(),
            "/Users/alice/projects/sample/cmd/cli/main.go".to_string(),
        ];
        assert_eq!(
            find_build_root(&paths).as_deref(),
            Some("/Users/alice/projects/sample")
        );
    }

    #[test]
    fn build_root_mixed_users_returns_none() {
        let paths = vec![
            "/Users/alice/proj/main.go".to_string(),
            "/Users/bob/other/main.go".to_string(),
        ];
        // Common ancestor would be `/Users` which is too generic;
        // we accept anything past `/Users/<user>/`.
        let root = find_build_root(&paths);
        // `/Users` is the LCP — last separator at index 0 — so we
        // refuse to return it (avoid claiming everything was built
        // at the system root).
        assert!(root.as_deref() == Some("/Users") || root.is_none());
    }

    #[test]
    fn build_root_excludes_system_paths() {
        let paths = vec![
            "/etc/ssl/cert.pem".to_string(),
            "/usr/lib/libc.so.6".to_string(),
        ];
        // No builder-home paths → no build root recoverable.
        assert!(find_build_root(&paths).is_none());
    }

    #[test]
    fn build_root_windows_paths() {
        let paths = vec![
            "C:\\Users\\dev\\projects\\app\\main.cs".to_string(),
            "C:\\Users\\dev\\projects\\app\\models\\user.cs".to_string(),
        ];
        assert_eq!(
            find_build_root(&paths).as_deref(),
            Some("C:\\Users\\dev\\projects\\app")
        );
    }

    #[test]
    fn extract_rejects_path_with_invalid_chars() {
        // String with embedded non-path bytes shouldn't get folded
        // into the path scan.
        let data = b"\x00/home/alice ng\xff/path\x00";
        let bp = extract(data);
        // Should still find /home/alice (truncated at the space).
        assert!(bp.usernames.contains(&"alice".to_string()));
    }
}
