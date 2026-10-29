//! Zero-telemetry update notifier and manifest-backed traits-ref resolution.
//!
//! In interactive runs, at most once every 24 hours, cleave fetches a small
//! static TOML manifest (`cleave.toml`) in the background and prints a one-line
//! notice when a newer release exists. The fetch is a plain GET of a static file — no version,
//! identity, or any other data is sent — so it leaks nothing even if the host
//! logs requests. A fresh result is cached locally so subsequent runs print the
//! notice without touching the network at all.
//!
//! The same manifest also tells `update-rules` which git ref each release line
//! should track for the traits repository: [`traits_ref`] reads `cleave.toml`,
//! keyed on this binary's version. Those fetches add a constant `?update=1`
//! query, so the server can tell an update from a notice check; nothing else
//! is sent.
//!
//! The opt-out is honored everywhere: pass `--no-update-check` or set
//! `CLEAVE_NO_UPDATE_CHECK` to disable the notice. The base URL is overridable
//! via `CLEAVE_UPDATE_URL` (primarily for testing against a local server).

use crate::update_manifest::{self, Manifest};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default location of the hosted manifests.
const DEFAULT_BASE_URL: &str = "https://atomdrift.org/updates/";
/// Minimum interval between network checks for the notice.
const CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;
/// Whole-request budget for a manifest fetch. Short on purpose: the check must
/// never noticeably delay a command, and an offline host should fail fast.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Build the URL for a named manifest. Apply-time fetches set the `?update=1`
/// marker — a constant flag (no data embedded) distinguishing a fetch tied to
/// an `update-rules` action from a passive notice check.
fn manifest_url(name: &str, marker: bool) -> String {
    let base = std::env::var("CLEAVE_UPDATE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
    manifest_url_from(&base, name, marker)
}

/// [`manifest_url`] over an explicit base, so the join can be tested without
/// writing `CLEAVE_UPDATE_URL` into the (process-wide, multi-threaded) test
/// environment.
fn manifest_url_from(base: &str, name: &str, marker: bool) -> String {
    let sep = if base.ends_with('/') { "" } else { "/" };
    let query = if marker { "?update=1" } else { "" };
    format!("{base}{sep}{name}{query}")
}

/// Fetch and parse a manifest over HTTPS.
fn fetch(name: &str, marker: bool) -> Result<Manifest> {
    let url = manifest_url(name, marker);
    let client = reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(FETCH_TIMEOUT)
        .user_agent(concat!("cleave/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building update-check HTTP client")?;
    let text = client
        .get(&url)
        .send()
        .with_context(|| format!("fetching {url}"))?
        .error_for_status()
        .with_context(|| format!("{url} returned an error status"))?
        .text()
        .context("reading manifest body")?;
    Manifest::parse(&text)
}

/// On-disk record of the last notice check (successful or failed).
#[derive(Debug, Default, Serialize, Deserialize)]
struct Cache {
    /// Unix time the manifest was last fetched.
    checked_unix: u64,
    /// `latest` field from that fetch.
    latest: String,
    /// `url` field from that fetch, if any.
    #[serde(default)]
    url: Option<String>,
}

/// Path to the notice cache (`<cache_dir>/atomdrift/cleave/update-check.toml`).
fn cache_path() -> Option<PathBuf> {
    Some(
        dirs::cache_dir()?
            .join("atomdrift")
            .join("cleave")
            .join("update-check.toml"),
    )
}

/// Current Unix time in seconds (0 if the clock predates the epoch).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Persist the notice cache (best-effort; failures are non-fatal).
fn write_cache(cache: &Cache) {
    let Some(path) = cache_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = toml::to_string(cache) {
        let _ = crate::cache::atomic_write(&path, text.as_bytes());
    }
}

/// Print the one-line notice, but only when `latest` is genuinely newer.
fn notify(latest: &str, url: Option<&str>, installed: &str) {
    if !update_manifest::is_newer(latest, installed) {
        return;
    }
    // `latest` is semver by now; `url` is free text bound for a terminal, where
    // an escape sequence could rewrite what the user sees.
    match url.filter(|u| !u.chars().any(char::is_control)) {
        Some(url) => {
            eprintln!("update available: cleave {latest} (you have {installed}) — {url}");
        }
        None => eprintln!("update available: cleave {latest} (you have {installed})"),
    }
}

/// Run the update notice for an interactive command.
///
/// Only runs when stderr is a terminal, so pipelines and sandboxes never touch
/// the network. The notice is printed from the local cache; when that is older
/// than a day, a background thread refreshes it (bounded by `FETCH_TIMEOUT`)
/// and the next run shows the result, so the check never delays a command. Any
/// network or parse failure is logged at debug level and otherwise ignored.
pub fn maybe_notify(disabled_by_flag: bool) {
    use std::io::IsTerminal;
    if disabled_by_flag
        || std::env::var_os("CLEAVE_NO_UPDATE_CHECK").is_some()
        || !std::io::stderr().is_terminal()
    {
        return;
    }
    let installed = env!("CARGO_PKG_VERSION");
    let cached: Cache = cache_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default();
    notify(&cached.latest, cached.url.as_deref(), installed);
    if now_unix().saturating_sub(cached.checked_unix) < CHECK_INTERVAL_SECS {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("update-check".into())
        .spawn(move || refresh_cache(cached));
    if let Err(e) = spawned {
        tracing::debug!(error = %e, "update check skipped");
    }
}

/// Fetch the manifest and record the result. A failed attempt is stamped too,
/// keeping the last known release, so an unreachable manifest is not retried
/// on every run.
fn refresh_cache(previous: Cache) {
    let fresh = match fetch("cleave.toml", false) {
        Ok(manifest) => Cache {
            checked_unix: now_unix(),
            latest: manifest.latest,
            url: manifest.url,
        },
        Err(e) => {
            tracing::debug!(error = %format!("{e:#}"), "update check skipped");
            Cache {
                checked_unix: now_unix(),
                ..previous
            }
        }
    };
    write_cache(&fresh);
}

/// Resolve the traits ref the installed cleave version should track, per
/// `cleave.toml`. `None` means no rule applied (or the fetch failed) — the
/// caller keeps its existing default. This is an apply-time fetch, so the
/// `?update=1` marker is set.
#[must_use]
pub fn traits_ref() -> Option<String> {
    let installed = env!("CARGO_PKG_VERSION");
    match fetch("cleave.toml", true) {
        Ok(m) => match m.resolve(installed) {
            Some(rule) if !rule.git_ref.is_empty() => {
                tracing::info!(version = installed, git_ref = %rule.git_ref, "traits ref resolved from cleave.toml");
                Some(rule.git_ref.clone())
            }
            _ => {
                tracing::debug!(
                    version = installed,
                    "no cleave.toml rule matched; using default traits ref"
                );
                None
            }
        },
        Err(e) => {
            tracing::debug!(error = %format!("{e:#}"), "cleave.toml fetch failed; using default traits ref");
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn manifest_url_joins_and_marks() {
        // Through the explicit-base helper: the old test set
        // `CLEAVE_UPDATE_URL` in a multi-threaded test binary, where other
        // threads read the environment (the traits fingerprint hashes this
        // very variable into cache keys).
        let base = "https://example.test/u/";
        assert_eq!(
            manifest_url_from(base, "cleave.toml", false),
            "https://example.test/u/cleave.toml"
        );
        assert_eq!(
            manifest_url_from(base, "cleave.toml", true),
            "https://example.test/u/cleave.toml?update=1"
        );

        // A base without a trailing slash still joins correctly.
        assert_eq!(
            manifest_url_from("https://example.test/u", "cleave.toml", false),
            "https://example.test/u/cleave.toml"
        );
    }
}
