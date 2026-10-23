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
//! the open-source release, rolled up every four hours, and is fetched with no
//! token. The enriched channel carries each ruleset the hour it clears QA, and
//! is reached through the rules Worker, which checks a subscription token and
//! serves the private bucket behind it.
//!
//! [`crate::enriched::enabled`] chooses the channel; holding a token does not.
//! Asked for enriched, a token the Worker will not honour is an error, never a
//! quiet downgrade to public rules — see [`enriched_manifest`].

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
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

/// The manifest's name under either base.
const MANIFEST: &str = "versions.toml";
/// The rules Worker's answer to "which bucket did this token open".
const CHANNEL_HEADER: &str = "x-isotope13-channel";

/// Whole-request budget for manifest + bundle downloads.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Connect budget — fail fast when the bucket is unreachable so a default
/// auto-update can't stall on an offline host (the whole-request [`TIMEOUT`]
/// still covers a slow but reachable download).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Sidecar recording what the R2 backend installed. The installed tree is a
/// `git archive` extraction with no `.git`, so the commit/date live here instead.
const SIDECAR: &str = ".cleave-rules.toml";

/// Why rules were not updated.
///
/// Two kinds, because callers treat them oppositely. A host that cannot reach
/// the bucket keeps scanning with the rules it has; a host asked for enriched
/// rules that cannot have them must say so, not quietly scan with something
/// else.
#[derive(Debug)]
pub enum Error {
    /// `--enriched` cannot be honoured: no token, or one the rules Worker
    /// refused.
    Enriched(String),
    /// Anything else: the network, the bucket, the manifest, the disk.
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Enriched(message) | Error::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Error::Other(message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Error::Other(message.to_string())
    }
}

fn print_status(message: &str) {
    eprintln!("{}", crate::output::escape_control_chars(message));
}

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
pub fn update(dir: &Path, force: bool, quiet: bool) -> Result<(), Error> {
    if is_git_managed(dir) {
        if !quiet {
            print_status(&format!(
                "Traits at {} are git-managed (a checkout or symlink to one); leaving them untouched.\nUse 'git pull' there to update, or remove the directory to switch to bundle updates.",
                dir.display()
            ));
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
            print_status(&format!("Already up to date: {} ({})", key, artifact.date));
            warn_if_behind(&manifest);
        }
        return Ok(());
    }

    if !quiet {
        print_status(&format!(
            "Installing {} traits {} ({}) for cleave {} [{}]...",
            channel.name(),
            key,
            artifact.date,
            our_version(),
            source
        ));
    }
    install(dir, artifact, &source, &channel)?;
    tracing::info!(
        event = "enriched.rules",
        channel = channel.name(),
        commit = %artifact.commit,
        date = %artifact.date,
        outcome = "installed"
    );
    if !quiet {
        print_status(&format!(
            "Traits updated to {} ({}) at {}",
            key,
            artifact.date,
            dir.display()
        ));
        warn_if_behind(&manifest);
    }
    Ok(())
}

/// Report what would be installed without changing anything.
pub fn check(dir: &Path) -> Result<(), Error> {
    if is_git_managed(dir) {
        print_status(&format!(
            "Traits at {} are git-managed; use 'git pull' there to update.",
            dir.display()
        ));
        return Ok(());
    }
    let (manifest, _) = fetch_manifest(None)?;
    let (key, source) = resolve(&manifest)?;
    let artifact = artifact_for(&manifest, &key)?;

    match installed(dir) {
        Some(i) if i.commit.starts_with(&key) => {
            print_status(&format!("Up to date: {} ({})", key, artifact.date));
        }
        Some(i) => {
            print_status(&format!(
                "Update available: {} ({}) — currently {} [{}]",
                key,
                artifact.date,
                i.commit.chars().take(9).collect::<String>(),
                source
            ));
        }
        None => print_status(&format!(
            "Not installed; available: {} ({}) [{}]",
            key, artifact.date, source
        )),
    }
    warn_if_behind(&manifest);
    Ok(())
}

/// Pin to a specific commit, if a bundle for it was published.
pub fn pin(dir: &Path, commit: &str) -> Result<(), Error> {
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
    print_status(&format!("Pinning traits to {} ({})...", key, artifact.date));
    install(dir, artifact, &format!("pin:{key}"), &channel)?;
    print_status(&format!("Traits pinned to {} at {}", key, dir.display()));
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
        print_status(&format!(
            "Note: cleave {} cannot use the newest rules. Upgrade to cleave {} for the latest detections.",
            our_version(),
            target
        ));
    }
}

/// Which channel answered, carried from the manifest fetch to the bundle fetch.
///
/// Threaded rather than recomputed on purpose: a manifest from the enriched
/// channel names bundles that exist only there, so resolving the two against
/// different bases would 404 on a subscriber whose token was revoked between
/// the two requests. One decision, made once, used twice.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Channel {
    Public,
    Enriched(crate::enriched::Token),
}

impl Channel {
    fn base(&self) -> &'static str {
        match self {
            Channel::Public => BASE_URL,
            Channel::Enriched(_) => ENRICHED_URL,
        }
    }

    /// The channel's name, which is also its traits directory's suffix.
    fn name(&self) -> &'static str {
        match self {
            Channel::Public => "oss",
            Channel::Enriched(_) => "enriched",
        }
    }

    fn token(&self) -> Option<&crate::enriched::Token> {
        match self {
            Channel::Public => None,
            Channel::Enriched(token) => Some(token),
        }
    }
}

fn fetch_manifest(connect: Option<Duration>) -> Result<(Manifest, Channel), Error> {
    let (bytes, channel) = if crate::enriched::enabled() {
        let held = crate::enriched::token().map_err(Error::Enriched)?;
        enriched_manifest(held, connect)?
    } else {
        let fetched = download(&Channel::Public, MANIFEST, connect).map_err(|e| e.message)?;
        (fetched.bytes, Channel::Public)
    };
    let text = String::from_utf8(bytes).map_err(|e| format!("manifest is not valid UTF-8: {e}"))?;
    let manifest = toml::from_str(&text)
        .map_err(|e| format!("parsing manifest {}/{MANIFEST}: {e}", channel.base()))?;
    Ok((manifest, channel))
}

/// Ask for a token, check it against the enriched channel, and save it.
///
/// What `hood login` runs: the same check every enriched update makes, so a
/// token is saved only once the rules Worker has honoured it.
///
/// # Errors
///
/// No terminal to ask on, or a token the Worker will not honour.
pub fn login() -> Result<(), Error> {
    let token =
        crate::enriched::prompt("Sign in to isotope13 Enriched").map_err(Error::Enriched)?;
    enriched_manifest(Some((token, crate::enriched::Source::Prompt)), None).map(drop)
}

/// The enriched manifest, and the channel — with the token — that opened it.
///
/// The rules Worker answers a token it will not honour (revoked, Community
/// tier, a typo) with the *public* manifest and a 200, so that old clients keep
/// running. Asked for enriched, that is a refusal: the channel header must say
/// `fresh`. A refused saved token is replaced by asking, once, on a terminal;
/// a refused token from the environment or the prompt is an error. A prompted
/// token is saved only after it has been honoured.
fn enriched_manifest(
    mut held: Option<(crate::enriched::Token, crate::enriched::Source)>,
    connect: Option<Duration>,
) -> Result<(Vec<u8>, Channel), Error> {
    use crate::enriched::Source;
    loop {
        let (token, source) = match held.take() {
            Some(found) => found,
            None => (
                crate::enriched::prompt("isotope13 Enriched needs a token")
                    .map_err(Error::Enriched)?,
                Source::Prompt,
            ),
        };
        let tid = token.fingerprint();
        let channel = Channel::Enriched(token);
        let refused = match download(&channel, MANIFEST, connect) {
            Ok(got) if got.fresh => {
                // A token that opened the channel but could not be saved still
                // opens it for this run; the next one asks again.
                if let (Source::Prompt, Some(token)) = (source, channel.token()) {
                    match crate::enriched::save(token) {
                        Ok(path) => {
                            print_status(&format!("Saved isotope13 token to {}", path.display()));
                        }
                        Err(e) => tracing::warn!(%tid, error = %e, "isotope13 token not saved"),
                    }
                }
                tracing::info!(
                    event = "enriched.token",
                    source = source.as_str(),
                    outcome = "ok",
                    %tid
                );
                return Ok((got.bytes, channel));
            }
            Ok(_) => "answered with the public channel".to_string(),
            Err(err) if err.unauthorized() => err.status_text(),
            Err(err) => return Err(Error::Other(err.message)),
        };
        tracing::warn!(
            event = "enriched.token",
            source = source.as_str(),
            outcome = "refused",
            %tid,
            %refused
        );
        let why = format!(
            "isotope13 token {tid} is not entitled to enriched rules ({refused}: revoked, or Community tier)"
        );
        if source != Source::File {
            return Err(Error::Enriched(format!(
                "{why}; see {}",
                crate::enriched::DASH_URL
            )));
        }
        let token = crate::enriched::prompt(&why).map_err(Error::Enriched)?;
        held = Some((token, Source::Prompt));
    }
}

/// Download a bundle, verify its sha256, and atomically swap it into `dir`.
fn install(dir: &Path, artifact: &Artifact, source: &str, channel: &Channel) -> Result<(), String> {
    // Patient: the manifest fetch already reached the bucket.
    let bytes = download(channel, &artifact.file, None)
        .map_err(|e| e.message)?
        .bytes;

    let got = hex(Sha256::digest(&bytes).as_slice());
    if got != artifact.sha256 {
        return Err(format!(
            "sha256 mismatch for {}: got {got}, manifest says {}",
            artifact.file, artifact.sha256
        ));
    }

    let parent = dir.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;

    // Named for the directory they replace: `traits-oss` and `traits-enriched`
    // share a parent, and two installs must not share a staging tree.
    let name = dir
        .file_name()
        .map_or_else(|| "traits".into(), |n| n.to_string_lossy());
    let staging = sibling(parent, &format!(".{name}-staging"));
    let backup = sibling(parent, &format!(".{name}-backup"));
    remove_any(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("create staging: {e}"))?;

    let decoder = zstd::stream::read::Decoder::new(Cursor::new(&bytes))
        .map_err(|e| format!("opening zstd stream: {e}"))?;
    unpack_bundle(decoder, &staging).map_err(|e| format!("extracting {}: {e}", artifact.file))?;

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

/// Extract a rules bundle without giving archive entries filesystem semantics.
///
/// The bundle is remote input even after its digest matches the remote
/// manifest. In particular, a link named [`SIDECAR`] would make the metadata
/// write in [`install`] overwrite its target. Rules need only ordinary files
/// and directories, so links, devices, FIFOs, and other special entries are
/// rejected before anything at that entry is created. Git archives also contain
/// a PAX global metadata header (`pax_global_header`), which is not a file to
/// extract. Consume and skip that valid header so the archive is handled like
/// the one produced by `git archive --format=tar`.
fn unpack_bundle<R: Read>(reader: R, staging: &Path) -> Result<(), String> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|e| format!("reading tar entries: {e}"))?;

    for entry in entries {
        let mut entry = entry.map_err(|e| format!("reading tar entry: {e}"))?;
        let kind = entry.header().entry_type();
        if kind.is_pax_global_extensions() {
            io::copy(&mut entry, &mut io::sink())
                .map_err(|e| format!("reading PAX global header: {e}"))?;
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| format!("reading tar entry path: {e}"))?
            .into_owned();
        if !kind.is_file() && !kind.is_dir() {
            return Err(format!(
                "unsupported tar entry type {kind:?} at {}",
                path.display()
            ));
        }
        if !entry
            .unpack_in(staging)
            .map_err(|e| format!("unpacking {}: {e}", path.display()))?
        {
            return Err(format!(
                "tar entry escapes the staging directory: {}",
                path.display()
            ));
        }
    }
    Ok(())
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

/// A successful download, and whether the rules Worker said it came from the
/// fresh bucket.
struct Fetched {
    bytes: Vec<u8>,
    fresh: bool,
}

/// A failed download, with the HTTP status when there was one.
///
/// The status is what tells a refused token apart from a bucket that is down:
/// the first asks for another token, the second is an error the operator needs
/// to see, and neither is retried into the other.
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
/// bundle that is not published, and a 401 means the token was refused, which
/// [`enriched_manifest`] answers by asking for another. Asking either of those
/// again just spends the user's time.
fn download(
    channel: &Channel,
    path: &str,
    connect: Option<Duration>,
) -> Result<Fetched, FetchError> {
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
) -> Result<Fetched, FetchError> {
    let url = format!("{}/{path}", channel.base());
    tracing::debug!("fetching {url}");
    // The bucket answers over TLS only, and nothing it serves is a redirect:
    // following one could hand the token, or the manifest that vouches for
    // every bundle, to a host that is neither of ours.
    let mut builder = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT);
    if let Some(connect) = connect {
        builder = builder.connect_timeout(connect);
    }
    let client = builder.build().map_err(|e| FetchError {
        status: None,
        message: format!("http client: {e}"),
    })?;

    let mut request = client.get(&url);
    if let Some(token) = channel.token() {
        request = request.bearer_auth(token.secret());
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
    let fresh = resp
        .headers()
        .get(CHANNEL_HEADER)
        .is_some_and(|v| v.as_bytes() == b"fresh");
    let bytes = resp.bytes().map_err(|e| FetchError {
        status: Some(status.as_u16()),
        message: format!("reading {url}: {e}"),
    })?;
    Ok(Fetched {
        bytes: bytes.to_vec(),
        fresh,
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

    #[test]
    fn bundle_rejects_links_before_the_sidecar_write_can_follow_them() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = tmp.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, "unchanged").unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::symlink());
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name(&victim).unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, SIDECAR, std::io::empty())
            .unwrap();
        let archive = builder.into_inner().unwrap();

        let error = unpack_bundle(Cursor::new(archive), &staging).unwrap_err();
        assert!(error.contains("unsupported tar entry type Symlink"));
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "unchanged");
        assert!(std::fs::symlink_metadata(staging.join(SIDECAR)).is_err());
    }

    #[test]
    fn only_the_enriched_channel_sends_a_token() {
        let public = Channel::Public;
        assert_eq!(public.base(), BASE_URL);
        assert_eq!(public.token(), None);

        let token = crate::enriched::Token::parse("i13_krypton85_abc").unwrap();
        let enriched = Channel::Enriched(token.clone());
        assert_eq!(enriched.base(), ENRICHED_URL);
        assert_eq!(enriched.token(), Some(&token));
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
        // we ask, and a refused token is answered with another, not by asking.
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
    fn a_refused_token_is_told_apart_from_an_outage() {
        let refused = |status| FetchError {
            status: Some(status),
            message: String::new(),
        };
        // A refused token asks for another...
        assert!(refused(401).unauthorized());
        assert!(refused(403).unauthorized());
        // ...but a bucket that is down is an error the operator must see, not
        // a reason to prompt anyone for a token.
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
        let staging = root.join(".traits-staging");
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
        swap_into_place(&staging, &dir, &tmp.path().join(".traits-backup")).unwrap();

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
        swap_into_place(&staging, &dir, &tmp.path().join(".traits-backup")).unwrap();

        assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
        assert!(dir.join("marker").is_file());
    }

    #[test]
    fn swap_leaves_no_backup_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("traits");
        let backup = tmp.path().join(".traits-backup");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(backup.join("leftover")).unwrap();

        swap_into_place(&staged(tmp.path()), &dir, &backup).unwrap();

        assert!(
            !backup.exists(),
            "backup should be dropped after a good swap"
        );
    }
}
