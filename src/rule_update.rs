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

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Base URL for the public update bucket (`<base>/versions.toml`, `<base>/traits/...`).
const BASE_URL: &str = "https://updates.atomdrift.org/cleave";

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
    let manifest = fetch_manifest(connect)?;
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
    install(dir, artifact, &source)?;
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
    let manifest = fetch_manifest(None)?;
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
    let manifest = fetch_manifest(None)?;
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
    install(dir, artifact, &format!("pin:{key}"))?;
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

fn fetch_manifest(connect: Option<Duration>) -> Result<Manifest, String> {
    let url = format!("{BASE_URL}/versions.toml");
    let text = http_get(&url, connect)?;
    let text = String::from_utf8(text).map_err(|e| format!("manifest is not valid UTF-8: {e}"))?;
    toml::from_str(&text).map_err(|e| format!("parsing manifest {url}: {e}"))
}

/// Download a bundle, verify its sha256, and atomically swap it into `dir`.
fn install(dir: &Path, artifact: &Artifact, source: &str) -> Result<(), String> {
    let url = format!("{BASE_URL}/{}", artifact.file);
    // Patient: the manifest fetch already reached the bucket.
    let bytes = http_get(&url, None)?;

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

fn http_get(url: &str, connect: Option<Duration>) -> Result<Vec<u8>, String> {
    tracing::debug!("fetching {url}");
    let mut builder = reqwest::blocking::Client::builder().timeout(TIMEOUT);
    if let Some(connect) = connect {
        builder = builder.connect_timeout(connect);
    }
    let client = builder.build().map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| format!("GET {url}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GET {url}: {e}"))?;
    resp.bytes()
        .map(|b| b.to_vec())
        .map_err(|e| format!("reading {url}: {e}"))
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
