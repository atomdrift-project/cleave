//! Zero-telemetry update notifier and manifest-backed traits-ref resolution.
//!
//! On first run and at most once every 24 hours, cleave fetches a small static
//! TOML manifest (`cleave.toml`) and prints a one-line notice when a newer
//! release exists. The fetch is a plain GET of a static file — no version,
//! identity, or any other data is sent — so it leaks nothing even if the host
//! logs requests. A fresh result is cached locally so subsequent runs print the
//! notice without touching the network at all.
//!
//! The same manifest also tells `update-rules` which git ref each release line
//! should track for the traits repository: [`traits_ref`] reads `cleave.toml`,
//! keyed on this binary's version.
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

/// Resolve the manifest base URL (overridable via `CLEAVE_UPDATE_URL`).
fn base_url() -> String {
    std::env::var("CLEAVE_UPDATE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned())
}

/// Build the URL for a named manifest. Apply-time fetches set the `?update=1`
/// marker — a constant flag (no data embedded) distinguishing a fetch tied to
/// an `update-rules` action from a passive notice check.
fn manifest_url(name: &str, marker: bool) -> String {
    let base = base_url();
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

/// Path to the notice cache (`<cache_dir>/cleave/update-check.toml`).
fn cache_path() -> Option<PathBuf> {
    Some(dirs::cache_dir()?.join("cleave").join("update-check.toml"))
}

/// Current Unix time in seconds (0 if the clock predates the epoch).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the notice cache, returning `None` on any error (treated as "no cache").
fn read_cache() -> Option<Cache> {
    let text = std::fs::read_to_string(cache_path()?).ok()?;
    toml::from_str(&text).ok()
}

/// Persist the notice cache (best-effort; failures are non-fatal).
fn write_cache(cache: &Cache) {
    let Some(path) = cache_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = toml::to_string(cache) {
        let _ = std::fs::write(&path, text);
    }
}

/// Print the one-line notice, but only when `latest` is genuinely newer.
fn notify(latest: &str, url: Option<&str>, installed: &str) {
    if !update_manifest::is_newer(latest, installed) {
        return;
    }
    match url {
        Some(url) => {
            eprintln!("update available: cleave {latest} (you have {installed}) — {url}");
        }
        None => eprintln!("update available: cleave {latest} (you have {installed})"),
    }
}

/// Run the update notice for an interactive command.
///
/// A fresh (<24h) cache is used without any network access. Otherwise the
/// manifest is fetched once (bounded by [`FETCH_TIMEOUT`]), the cache is
/// refreshed, and a notice is printed if a newer release exists. Any network or
/// parse failure is logged at debug level and otherwise ignored — the check is
/// strictly best-effort and never blocks or fails a command.
pub fn maybe_notify(disabled_by_flag: bool) {
    if disabled_by_flag || std::env::var_os("CLEAVE_NO_UPDATE_CHECK").is_some() {
        return;
    }
    let installed = env!("CARGO_PKG_VERSION");
    let cached = read_cache();

    // A fresh stamp (a recent success *or* a recent failed attempt) is used
    // without any network access.
    if let Some(cache) = &cached
        && now_unix().saturating_sub(cache.checked_unix) < CHECK_INTERVAL_SECS
    {
        notify(&cache.latest, cache.url.as_deref(), installed);
        return;
    }

    match fetch("cleave.toml", false) {
        Ok(manifest) => {
            write_cache(&Cache {
                checked_unix: now_unix(),
                latest: manifest.latest.clone(),
                url: manifest.url.clone(),
            });
            notify(&manifest.latest, manifest.url.as_deref(), installed);
        }
        Err(e) => {
            tracing::debug!(error = %format!("{e:#}"), "update check skipped");
            // Stamp the failed attempt so an unreachable manifest doesn't
            // trigger a network call on every run. Preserve any previously
            // known `latest` so a transient failure still shows the last notice.
            let prev = cached.unwrap_or_default();
            write_cache(&Cache {
                checked_unix: now_unix(),
                latest: prev.latest.clone(),
                url: prev.url.clone(),
            });
            notify(&prev.latest, prev.url.as_deref(), installed);
        }
    }
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
        // SAFETY: the test binary is single-threaded at this point.
        unsafe { std::env::set_var("CLEAVE_UPDATE_URL", "https://example.test/u/") };
        assert_eq!(
            manifest_url("cleave.toml", false),
            "https://example.test/u/cleave.toml"
        );
        assert_eq!(
            manifest_url("cleave.toml", true),
            "https://example.test/u/cleave.toml?update=1"
        );

        // A base without a trailing slash still joins correctly.
        unsafe { std::env::set_var("CLEAVE_UPDATE_URL", "https://example.test/u") };
        assert_eq!(
            manifest_url("cleave.toml", false),
            "https://example.test/u/cleave.toml"
        );
        unsafe { std::env::remove_var("CLEAVE_UPDATE_URL") };
    }
}
