//! R2-backed trait rule updates.
//!
//! `cleave update-rules` fetches a manifest from the update bucket, resolves the
//! trait bundle compatible with *this* cleave release, downloads it, verifies its
//! sha256, and installs it into the traits directory.
//!
//! Signature verification is deferred for v1: trust is HTTPS to our own bucket
//! plus the manifest's per-artifact sha256 (which catches corruption). The
//! manifest is already cosign-signed upstream, so authenticity checking can be
//! added later without changing the publish side.
//!
//! # Channels
//!
//! There are two, and they publish the same layout. The public bucket carries
//! the open-source release, rolled up every four hours. The enriched channel
//! carries each ruleset the hour it clears QA, and is reached through a small
//! service that checks a subscription key and serves the private bucket
//! behind it.
//!
//! A key in `ISOTOPE13_TOKEN` or `~/.tok/isotope13` selects the enriched
//! channel; without one, nothing changes and nothing is sent anywhere new. A
//! key Beamline refuses falls back to the public channel with a warning rather
//! than failing the update: an expired subscription should leave a CI gate
//! running on last week's rules, not stop it.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Base URL for the public update bucket (`<base>/versions.toml`, `<base>/traits/...`).
const BASE_URL: &str = "https://updates.atomdrift.org/cleave";

/// Base URL for the enriched channel, which serves the identical layout from
/// the private bucket once the key has been checked.
///
/// The counterpart of [`BASE_URL`] rather than a different shape: both are
/// `updates.<org>` and both resolve the manifest's relative `file` paths the
/// same way, so the only thing this constant changes is which bucket answers.
const ENRICHED_URL: &str = "https://updates.isotope13.ai/v1/rules/cleave";

/// Environment override for a subscription key, checked before the file.
const TOKEN_ENV: &str = "ISOTOPE13_TOKEN";
/// Where a subscription key lives otherwise — the same `~/.tok/<service>`
/// convention every other isotope13 service reads one from.
const TOKEN_FILE: &str = "isotope13";

/// Whole-request budget for manifest + bundle downloads.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Connect budget — fail fast when the bucket is unreachable so a default
/// auto-update can't stall on an offline host (the whole-request [`TIMEOUT`]
/// still covers a slow but reachable download).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Sidecar recording what the R2 backend installed. The installed tree is a
/// `git archive` extraction with no `.git`, so the commit/date live here instead.
const SIDECAR: &str = ".cleave-rules.toml";

/// This build's version, matched against the manifest's release keys (e.g. `2.0.0-rc.4`).
fn our_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    latest: String,
    #[serde(default)]
    artifacts: BTreeMap<String, Artifact>,
    #[serde(default)]
    stable: BTreeMap<String, String>,
    #[serde(default)]
    upgrade: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Artifact {
    file: String,
    sha256: String,
    commit: String,
    date: String,
}

/// Sidecar contents — what the R2 backend last installed.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Installed {
    /// Full commit hash of the installed traits bundle.
    pub commit: String,
    /// Committer date of that commit (`YYYY-MM-DD`).
    pub date: String,
    /// `stable:<version>`, `latest`, or `pin:<key>` — how the pointer was resolved.
    pub source: String,
    /// The cleave version that performed the install.
    pub version: String,
}

/// Read the install sidecar, if the traits dir was populated by the R2 backend.
#[must_use]
pub fn installed(dir: &Path) -> Option<Installed> {
    let text = std::fs::read_to_string(dir.join(SIDECAR)).ok()?;
    toml::from_str(&text).ok()
}

/// True if the dir is a git checkout (or symlinked to one) — a dev tree we must
/// never overwrite. `join(".git").exists()` follows the symlink, so it catches
/// both the symlinked-to-a-checkout and the direct-checkout cases.
fn is_git_managed(dir: &Path) -> bool {
    dir.join(".git").exists()
}

/// Install or refresh the traits compatible with this cleave release.
pub fn update(dir: &Path, force: bool, quiet: bool) -> Result<(), String> {
    if is_git_managed(dir) {
        if !quiet {
            eprintln!(
                "Traits at {} are git-managed (a checkout or symlink to one); leaving them untouched.\nUse 'git pull' there to update, or remove the directory to switch to bundle updates.",
                dir.display()
            );
        }
        return Ok(());
    }
    // A quiet refresh of an already-present install is the auto-update path: fail
    // fast if the bucket is unreachable. A first-ever download — or any explicit,
    // non-quiet update — stays patient so a slow first fetch still completes.
    let connect = (quiet && installed(dir).is_some()).then_some(CONNECT_TIMEOUT);
    let (manifest, channel) = fetch_manifest(connect)?;
    let (key, source) = resolve(&manifest)?;
    let artifact = artifact_for(&manifest, &key)?;

    if !force && installed(dir).is_some_and(|i| i.commit.starts_with(&key)) {
        if !quiet {
            eprintln!("Already up to date: {} ({})", key, artifact.date);
            warn_if_behind(&manifest);
        }
        return Ok(());
    }

    if !quiet {
        eprintln!(
            "Installing traits {} ({}) for cleave {} [{}]...",
            key,
            artifact.date,
            our_version(),
            source
        );
    }
    install(dir, artifact, &source, &channel)?;
    if !quiet {
        eprintln!(
            "Traits updated to {} ({}) at {}",
            key,
            artifact.date,
            dir.display()
        );
        warn_if_behind(&manifest);
    }
    Ok(())
}

/// Report what would be installed without changing anything.
pub fn check(dir: &Path) -> Result<(), String> {
    if is_git_managed(dir) {
        eprintln!(
            "Traits at {} are git-managed; use 'git pull' there to update.",
            dir.display()
        );
        return Ok(());
    }
    let (manifest, _) = fetch_manifest(None)?;
    let (key, source) = resolve(&manifest)?;
    let artifact = artifact_for(&manifest, &key)?;

    match installed(dir) {
        Some(i) if i.commit.starts_with(&key) => {
            eprintln!("Up to date: {} ({})", key, artifact.date);
        }
        Some(i) => {
            eprintln!(
                "Update available: {} ({}) — currently {} [{}]",
                key,
                artifact.date,
                i.commit.chars().take(9).collect::<String>(),
                source
            );
        }
        None => eprintln!(
            "Not installed; available: {} ({}) [{}]",
            key, artifact.date, source
        ),
    }
    warn_if_behind(&manifest);
    Ok(())
}

/// Pin to a specific commit, if a bundle for it was published.
pub fn pin(dir: &Path, commit: &str) -> Result<(), String> {
    let (manifest, channel) = fetch_manifest(None)?;
    let key = manifest
        .artifacts
        .keys()
        .find(|k| k.starts_with(commit) || commit.starts_with(k.as_str()))
        .cloned()
        .ok_or_else(|| {
            format!(
                "no published bundle for commit {commit} (only pointed-to commits have bundles)"
            )
        })?;
    let artifact = artifact_for(&manifest, &key)?;
    eprintln!("Pinning traits to {} ({})...", key, artifact.date);
    install(dir, artifact, &format!("pin:{key}"), &channel)?;
    eprintln!("Traits pinned to {} at {}", key, dir.display());
    Ok(())
}

// --- internals --------------------------------------------------------------

/// Resolve this build's trait pointer: its own `[stable]` entry, else `latest`.
fn resolve(m: &Manifest) -> Result<(String, String), String> {
    if let Some(key) = m.stable.get(our_version()) {
        return Ok((key.clone(), format!("stable:{}", our_version())));
    }
    if !m.latest.is_empty() {
        return Ok((m.latest.clone(), "latest".to_string()));
    }
    Err("manifest has no pointer for this version and no `latest`".to_string())
}

fn artifact_for<'a>(m: &'a Manifest, key: &str) -> Result<&'a Artifact, String> {
    m.artifacts
        .get(key)
        .ok_or_else(|| format!("manifest references {key} but has no [artifacts.{key}] entry"))
}

/// Warn (but don't fail) if a newer *release* supports rules this build can't.
/// The manifest's `[upgrade]` table already excludes HEAD-only-ahead cases, so a
/// dev/unlisted build is never warned.
fn warn_if_behind(m: &Manifest) {
    if let Some(target) = m.upgrade.get(our_version()) {
        eprintln!(
            "Note: cleave {} cannot use the newest rules. Upgrade to cleave {} for the latest detections.",
            our_version(),
            target
        );
    }
}

/// Which channel answered, carried from the manifest fetch to the bundle fetch.
///
/// Threaded rather than recomputed on purpose: a manifest from the enriched
/// channel names bundles that exist only there, so resolving the two against
/// different bases would 404 on a subscriber whose key expired between the two
/// requests. One decision, made once, used twice.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Channel {
    Public,
    Enriched(String),
}

impl Channel {
    fn base(&self) -> &'static str {
        match self {
            Channel::Public => BASE_URL,
            Channel::Enriched(_) => ENRICHED_URL,
        }
    }

    fn token(&self) -> Option<&str> {
        match self {
            Channel::Public => None,
            Channel::Enriched(token) => Some(token),
        }
    }
}

/// The subscription key, if this host has one. Trimmed, and an empty value is
/// the same as none — an unset variable and one set to "" mean the same thing
/// to whoever wrote the script.
fn subscription_key() -> Option<String> {
    if let Some(key) = std::env::var(TOKEN_ENV).ok().and_then(|k| key_from(&k)) {
        return Some(key);
    }
    let path = dirs::home_dir()?.join(".tok").join(TOKEN_FILE);
    key_from(&std::fs::read_to_string(path).ok()?)
}

/// The first non-empty line, trimmed, or `None`.
///
/// Both sources go through this so a key pasted into a file with a trailing
/// newline and one exported with a stray space behave identically — and so an
/// empty variable means "no key" rather than a key that is the empty string,
/// which would be sent as `Authorization: Bearer ` and rejected.
fn key_from(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn fetch_manifest(connect: Option<Duration>) -> Result<(Manifest, Channel), String> {
    let mut channel = subscription_key().map_or(Channel::Public, Channel::Enriched);
    let mut bytes = download(&channel, "versions.toml", connect);

    // A key the server will not accept is a subscription that lapsed, a token
    // that was revoked, or a typo. None of those should stop a scan: fall back
    // to what every non-subscriber gets, and say so once.
    if let (Channel::Enriched(_), Err(err)) = (&channel, &bytes)
        && err.unauthorized()
    {
        tracing::warn!(
            "isotope13 subscription key was not accepted ({}); using public rules. Check https://dash.isotope13.ai",
            err.status_text()
        );
        channel = Channel::Public;
        bytes = download(&channel, "versions.toml", connect);
    }

    let text = bytes.map_err(|e| e.message)?;
    let text = String::from_utf8(text).map_err(|e| format!("manifest is not valid UTF-8: {e}"))?;
    let manifest = toml::from_str(&text)
        .map_err(|e| format!("parsing manifest {}/versions.toml: {e}", channel.base()))?;
    Ok((manifest, channel))
}

/// Download a bundle, verify its sha256, and atomically swap it into `dir`.
fn install(dir: &Path, artifact: &Artifact, source: &str, channel: &Channel) -> Result<(), String> {
    // Patient: the manifest fetch already reached the bucket.
    let bytes = download(channel, &artifact.file, None).map_err(|e| e.message)?;

    let got = hex(Sha256::digest(&bytes).as_slice());
    if got != artifact.sha256 {
        return Err(format!(
            "sha256 mismatch for {}: got {got}, manifest says {}",
            artifact.file, artifact.sha256
        ));
    }

    let parent = dir.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;

    let staging = sibling(parent, ".cleave-traits-staging");
    let backup = sibling(parent, ".cleave-traits-backup");
    remove_any(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("create staging: {e}"))?;

    let decoder = zstd::stream::read::Decoder::new(Cursor::new(&bytes))
        .map_err(|e| format!("opening zstd stream: {e}"))?;
    tar::Archive::new(decoder)
        .unpack(&staging)
        .map_err(|e| format!("extracting {}: {e}", artifact.file))?;

    let meta = Installed {
        commit: artifact.commit.clone(),
        date: artifact.date.clone(),
        source: source.to_string(),
        version: our_version().to_string(),
    };
    let rendered = toml::to_string(&meta).map_err(|e| format!("rendering sidecar: {e}"))?;
    std::fs::write(staging.join(SIDECAR), rendered).map_err(|e| format!("writing sidecar: {e}"))?;

    swap_into_place(&staging, dir, &backup)
}

/// Replace `dir` with `staging`, keeping a rollback copy at `backup`.
///
/// Existence is probed with `symlink_metadata`, not `exists`: a *dangling*
/// symlink at `dir` — e.g. a hand-made pointer to a traits checkout that has
/// since moved — reports as absent to `exists()`, so the old path was left in
/// place and renaming the staging directory onto it failed with `ENOTDIR`,
/// wedging every install until the link was removed by hand.
fn swap_into_place(staging: &Path, dir: &Path, backup: &Path) -> Result<(), String> {
    remove_any(backup);
    if std::fs::symlink_metadata(dir).is_ok() {
        std::fs::rename(dir, backup).map_err(|e| format!("backing up old traits: {e}"))?;
    }
    if let Err(e) = std::fs::rename(staging, dir) {
        if std::fs::symlink_metadata(backup).is_ok() {
            let _ = std::fs::rename(backup, dir);
        }
        return Err(format!("installing traits: {e}"));
    }
    remove_any(backup);
    Ok(())
}

/// Best-effort removal of `path`, whatever it is.
///
/// `remove_dir_all` fails on a symlink, and a stale link left behind blocks the
/// swap, so dispatch on the link's own type rather than its target's.
fn remove_any(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => drop(std::fs::remove_dir_all(path)),
        Ok(_) => drop(std::fs::remove_file(path)),
        Err(_) => {}
    }
}

fn sibling(parent: &Path, name: &str) -> PathBuf {
    parent.join(name)
}

/// A failed download, with the HTTP status when there was one.
///
/// The status is what tells a lapsed subscription apart from a bucket that is
/// down. The first should quietly drop to the public channel; the second is an
/// error the operator needs to see, and swallowing it would leave a host
/// silently pinned to whatever it installed last.
struct FetchError {
    status: Option<u16>,
    message: String,
}

impl FetchError {
    fn unauthorized(&self) -> bool {
        matches!(self.status, Some(401 | 403))
    }

    /// Whether asking again could plausibly answer differently. A transport
    /// failure has no status at all and is the commonest thing worth retrying.
    fn retryable(&self) -> bool {
        match self.status {
            None => true,
            Some(status) => status == 408 || status == 429 || status >= 500,
        }
    }

    fn status_text(&self) -> String {
        self.status
            .map_or_else(|| "no response".to_string(), |s| format!("HTTP {s}"))
    }
}

/// How many times a download is attempted before it is called a failure.
const ATTEMPTS: u32 = 4;
/// First backoff step; each retry doubles it, and jitter is applied on top.
const RETRY_BASE: Duration = Duration::from_millis(250);
/// Ceiling for one backoff step, so a run of failures cannot stall a scan.
const RETRY_MAX: Duration = Duration::from_secs(8);

/// Fetch one artifact, retrying the failures that are worth retrying.
///
/// A rules update runs at startup on every scan, so a single dropped
/// connection to the bucket should not cost a host its update — it would go on
/// scanning with whatever it installed last, silently a week behind. Only
/// transport errors and 5xx are retried: a 404 means the manifest names a
/// bundle that is not published, and a 401 means the subscription key was
/// refused, which the caller handles by falling back to the public channel.
/// Asking either of those again just spends the user's time.
fn download(
    channel: &Channel,
    path: &str,
    connect: Option<Duration>,
) -> Result<Vec<u8>, FetchError> {
    let mut backoff = RETRY_BASE;
    let mut attempt = 1;
    loop {
        match download_once(channel, path, connect) {
            Ok(bytes) => {
                if attempt > 1 {
                    tracing::info!(attempt, path, "rules download succeeded after a retry");
                }
                return Ok(bytes);
            }
            Err(err) => {
                if attempt >= ATTEMPTS || !err.retryable() {
                    return Err(err);
                }
                let wait = jitter(backoff);
                tracing::warn!(
                    attempt,
                    path,
                    wait_ms = wait.as_millis(),
                    error = %err.message,
                    "rules download failed; retrying"
                );
                std::thread::sleep(wait);
                backoff = (backoff * 2).min(RETRY_MAX);
                attempt += 1;
            }
        }
    }
}

/// Full jitter: anywhere between nothing and the whole step.
///
/// Every host in a CI fleet starts its scans on the same schedule, so a fixed
/// backoff would send them all back at the bucket together — which is the
/// shape of load that keeps something down once it is.
fn jitter(step: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let span = u64::try_from(step.as_millis()).unwrap_or(u64::MAX).max(1);
    Duration::from_millis(u64::from(nanos) % span)
}

fn download_once(
    channel: &Channel,
    path: &str,
    connect: Option<Duration>,
) -> Result<Vec<u8>, FetchError> {
    let url = format!("{}/{path}", channel.base());
    tracing::debug!("fetching {url}");
    let mut builder = reqwest::blocking::Client::builder().timeout(TIMEOUT);
    if let Some(connect) = connect {
        builder = builder.connect_timeout(connect);
    }
    let client = builder.build().map_err(|e| FetchError {
        status: None,
        message: format!("http client: {e}"),
    })?;

    let mut request = client.get(&url);
    if let Some(key) = channel.token() {
        request = request.bearer_auth(key);
    }
    let resp = request.send().map_err(|e| FetchError {
        status: None,
        message: format!("GET {url}: {e}"),
    })?;

    let status = resp.status();
    if !status.is_success() {
        return Err(FetchError {
            status: Some(status.as_u16()),
            message: format!("GET {url}: {status}"),
        });
    }
    resp.bytes().map(|b| b.to_vec()).map_err(|e| FetchError {
        status: Some(status.as_u16()),
        message: format!("reading {url}: {e}"),
    })
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Stage a directory holding a single marker file.
    #[test]
    fn a_key_is_the_first_non_empty_line() {
        assert_eq!(
            key_from("i13_krypton85_abc\n"),
            Some("i13_krypton85_abc".into())
        );
        assert_eq!(key_from("  i13_x  "), Some("i13_x".into()));
        assert_eq!(key_from("\n\n  \ni13_y\nignored\n"), Some("i13_y".into()));
        // An empty value is no key, not an empty bearer token.
        assert_eq!(key_from(""), None);
        assert_eq!(key_from("   \n\t\n"), None);
    }

    #[test]
    fn only_the_enriched_channel_sends_a_key() {
        let public = Channel::Public;
        assert_eq!(public.base(), BASE_URL);
        assert_eq!(public.token(), None);

        let enriched = Channel::Enriched("i13_krypton85_abc".into());
        assert_eq!(enriched.base(), ENRICHED_URL);
        assert_eq!(enriched.token(), Some("i13_krypton85_abc"));
    }

    #[test]
    fn only_failures_that_could_answer_differently_are_retried() {
        let at = |status| FetchError {
            status: Some(status),
            message: String::new(),
        };
        // A dropped connection is the commonest thing worth asking again about.
        assert!(
            FetchError {
                status: None,
                message: String::new(),
            }
            .retryable()
        );
        assert!(at(500).retryable());
        assert!(at(503).retryable());
        assert!(at(429).retryable());
        assert!(at(408).retryable());
        // A bundle that is not published stays unpublished however many times
        // we ask, and a refused key is handled by falling back, not by asking.
        assert!(!at(404).retryable());
        assert!(!at(401).retryable());
        assert!(!at(400).retryable());
    }

    #[test]
    fn backoff_jitter_never_exceeds_its_step() {
        // Full jitter: the wait is somewhere in [0, step), so a fleet that
        // starts together does not come back together.
        for step in [RETRY_BASE, Duration::from_secs(1), RETRY_MAX] {
            let wait = jitter(step);
            assert!(wait < step, "{wait:?} must be under {step:?}");
        }
        // A zero step must not divide by zero.
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn a_refused_key_falls_back_but_an_outage_does_not() {
        let refused = |status| FetchError {
            status: Some(status),
            message: String::new(),
        };
        // A lapsed subscription drops to the public channel...
        assert!(refused(401).unauthorized());
        assert!(refused(403).unauthorized());
        // ...but a bucket that is down is an error the operator must see, not
        // a host silently pinned to whatever it installed last.
        assert!(!refused(404).unauthorized());
        assert!(!refused(500).unauthorized());
        assert!(
            !FetchError {
                status: None,
                message: String::new(),
            }
            .unauthorized()
        );
        assert_eq!(refused(401).status_text(), "HTTP 401");
    }

    fn staged(root: &Path) -> PathBuf {
        let staging = root.join(".cleave-traits-staging");
        std::fs::create_dir_all(staging.join("objectives")).unwrap();
        std::fs::write(staging.join("marker"), "new").unwrap();
        staging
    }

    #[test]
    fn swap_replaces_existing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("traits");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("stale"), "old").unwrap();

        let staging = staged(tmp.path());
        swap_into_place(&staging, &dir, &tmp.path().join(".cleave-traits-backup")).unwrap();

        assert!(dir.join("marker").is_file());
        assert!(!dir.join("stale").exists(), "old tree should be gone");
        assert!(!staging.exists(), "staging should have been moved");
    }

    #[cfg(unix)]
    #[test]
    fn swap_replaces_dangling_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("traits");
        std::os::unix::fs::symlink(tmp.path().join("gone"), &dir).unwrap();
        assert!(!dir.exists(), "precondition: the link resolves to nothing");

        let staging = staged(tmp.path());
        swap_into_place(&staging, &dir, &tmp.path().join(".cleave-traits-backup")).unwrap();

        assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
        assert!(dir.join("marker").is_file());
    }

    #[test]
    fn swap_leaves_no_backup_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("traits");
        let backup = tmp.path().join(".cleave-traits-backup");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(backup.join("leftover")).unwrap();

        swap_into_place(&staged(tmp.path()), &dir, &backup).unwrap();

        assert!(
            !backup.exists(),
            "backup should be dropped after a good swap"
        );
    }
}
