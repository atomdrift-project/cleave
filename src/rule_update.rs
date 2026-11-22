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
//! # Feeds
//!
//! Three feeds publish the same layout (see [`crate::feed`]). `oss-delayed` is
//! the public bucket, rolled up every eight days and fetched with no token.
//! `zero-day` and `supporter` are served by the rules Worker, which checks a
//! subscription token and answers from the private bucket, or refuses with
//! the feeds the token's plan does open.
//!
//! [`crate::feed::current`] chooses the feed; holding a token does not. A feed
//! the Worker refuses is an error carrying what the plan opens, never a quiet
//! downgrade — [`refresh`] decides whether to fall back.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Base URL for the public update bucket (`<base>/versions.toml`, `<base>/traits/...`).
const BASE_URL: &str = "https://updates.atomdrift.org/cleave";

/// Base URL for the paid feeds: `<FEED_URL>/<feed>/versions.toml` and the
/// bundles beside it, served from the private bucket once the token has been
/// checked.
///
/// The counterpart of [`BASE_URL`] rather than a different shape: both resolve
/// the manifest's relative `file` paths the same way, so the only thing a feed
/// changes is which base answers.
const FEED_URL: &str = "https://updates.isotope13.ai/v1/rules/cleave";

/// The manifest's name under either base.
const MANIFEST: &str = "versions.toml";
/// The feed the rules Worker served.
const FEED_HEADER: &str = "x-isotope13-feed";
/// The feeds the caller's token opens, best first.
const FEEDS_HEADER: &str = "x-isotope13-feeds";
/// The plan a recognised token is on; absent for one the Worker never minted.
const TIER_HEADER: &str = "x-isotope13-tier";

/// Whole-request budget for manifest + bundle downloads.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Connect budget — fail fast when the bucket is unreachable so a default
/// auto-update can't stall on an offline host (the whole-request [`TIMEOUT`]
/// still covers a slow but reachable download).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Sidecar recording what the R2 backend installed. The installed tree is a
/// `git archive` extraction with no `.git`, so the commit/date live here instead.
const SIDECAR: &str = ".cleave-rules.toml";

/// Largest download accepted from the update bucket. A rules bundle is tens of
/// megabytes compressed; the cap bounds what a misbehaving server can make us
/// buffer.
const MAX_DOWNLOAD_BYTES: u64 = 1 << 30;

/// Largest unpacked bundle, and most entries, accepted from one bundle. A full
/// rules tree is under 1 GiB in ~60k files.
const MAX_UNPACKED_BYTES: u64 = 8 << 30;
const MAX_BUNDLE_ENTRIES: usize = 500_000;

/// Why rules were not updated.
///
/// Two kinds, because callers treat them oppositely. A host that cannot reach
/// the bucket keeps scanning with the rules it has; a host whose feed cannot
/// be had must say so, or fall back, not quietly scan with something else.
#[derive(Debug)]
pub enum Error {
    /// The feed cannot be had: no token, or one the rules Worker refused.
    Refused(Refusal),
    /// Anything else: the network, the bucket, the manifest, the disk.
    Other(String),
}

/// A feed the rules service would not serve, and what it would.
#[derive(Debug)]
pub struct Refusal {
    /// What was wrong and what to do, in words.
    pub message: String,
    /// The feeds the token opens, best first; empty when it opened none.
    pub opened: Vec<crate::feed::Feed>,
    /// Whether the service recognised the token, so `opened` reflects a plan.
    pub recognised: bool,
}

impl Refusal {
    fn new(message: String) -> Self {
        Self {
            message,
            opened: Vec::new(),
            recognised: false,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Refused(refusal) => f.write_str(&refusal.message),
            Error::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

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
    /// Commit time of that commit, Unix seconds: the mtime `git archive`
    /// stamps on every entry. Absent from sidecars written before it was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed: Option<u64>,
    /// `stable:<version>`, `latest`, or `pin:<key>` — how the pointer was resolved.
    pub source: String,
    /// The cleave version that performed the install.
    pub version: String,
    /// Windows installs keep rule bytes compressed on disk.
    #[serde(default)]
    pub packed_rules: bool,
}

/// Read the install sidecar, if the traits dir was populated by the R2 backend.
#[must_use]
pub fn installed(dir: &Path) -> Option<Installed> {
    let text = std::fs::read_to_string(dir.join(SIDECAR)).ok()?;
    toml::from_str(&text).ok()
}

/// When the traits installed at `dir` were committed, Unix seconds. A sidecar
/// written before the commit time was kept answers with the last second of
/// its commit date, so a verdict from that day never counts as newer. `None`
/// without a sidecar: a git checkout, whose working tree may be newer than
/// any commit.
#[must_use]
pub fn committed_at(dir: &Path) -> Option<u64> {
    let installed = installed(dir)?;
    installed.committed.or_else(|| end_of_day(&installed.date))
}

/// The last second of the UTC day `date` (`YYYY-MM-DD`), Unix seconds.
fn end_of_day(date: &str) -> Option<u64> {
    let mut parts = date.splitn(3, '-').map(str::parse::<i64>);
    let (Some(Ok(y)), Some(Ok(m)), Some(Ok(d))) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Days from 1970-01-01 to y-m-d (Howard Hinnant's days_from_civil).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from((days + 1) * 86_400 - 1).ok()
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
    let (key, source) = resolve(&manifest).map_err(Error::Other)?;
    let artifact = artifact_for(&manifest, &key).map_err(Error::Other)?;

    if !force
        && installed(dir)
            .is_some_and(|i| i.commit.starts_with(&key) && (!cfg!(windows) || i.packed_rules))
    {
        if !quiet {
            print_status(&format!("Already up to date: {} ({})", key, artifact.date));
            warn_if_behind(&manifest);
        }
        return Ok(());
    }

    if !quiet {
        print_status(&format!(
            "Installing {} rules {} ({}) for cleave {} [{}]...",
            channel.feed(),
            key,
            artifact.date,
            our_version(),
            source
        ));
    }
    install(dir, artifact, &source, &channel).map_err(Error::Other)?;
    tracing::info!(
        event = "feed.rules",
        feed = channel.feed().slug(),
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
    }
    compile_installed(dir, quiet);
    if !quiet {
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
    let (key, source) = resolve(&manifest).map_err(Error::Other)?;
    let artifact = artifact_for(&manifest, &key).map_err(Error::Other)?;

    match installed(dir) {
        Some(i) if i.commit.starts_with(&key) && (!cfg!(windows) || i.packed_rules) => {
            print_status(&format!("Up to date: {} ({})", key, artifact.date));
        }
        Some(i) if i.commit.starts_with(&key) => {
            print_status(&format!(
                "Rule revision is current, but this Windows install needs packed storage; run `cleave update-rules` ({key})"
            ));
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
        })
        .map_err(Error::Other)?;
    let artifact = artifact_for(&manifest, &key).map_err(Error::Other)?;
    print_status(&format!("Pinning traits to {} ({})...", key, artifact.date));
    install(dir, artifact, &format!("pin:{key}"), &channel).map_err(Error::Other)?;
    print_status(&format!("Traits pinned to {} at {}", key, dir.display()));
    compile_installed(dir, false);
    Ok(())
}

/// Compile the YARA rules just installed into `dir` — now, as part of the
/// update, rather than in the first scan after it. Only the buckets whose
/// sources changed are compiled; a bundle never carries compiled rules (see
/// [`unpack_bundle`]), so this host's cache is the only place they come from.
///
/// Only for the tree scans actually read: an update of some other directory
/// has nothing here to warm.
fn compile_installed(dir: &Path, quiet: bool) {
    crate::cache::invalidate_traits_scan();
    let canonical = |p: &Path| std::fs::canonicalize(p).ok();
    if canonical(dir).is_none() || canonical(dir) != canonical(&crate::cache::traits_path()) {
        return;
    }
    let started = std::time::Instant::now();
    let (compiled, buckets) = crate::compile_yara_rules(true);
    if compiled == 0 {
        return;
    }
    let message = format!(
        "Compiled {compiled} of {buckets} YARA rule sets in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    if quiet {
        tracing::info!("{message}");
    } else {
        print_status(&message);
    }
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

/// Which feed answered, carried from the manifest fetch to the bundle fetch.
///
/// Threaded rather than recomputed on purpose: a manifest from a paid feed
/// names bundles that exist only there, so resolving the two against
/// different bases would 404 on a subscriber whose token was revoked between
/// the two requests. One decision, made once, used twice.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Channel {
    Public,
    Paid(crate::feed::Feed, crate::feed::Token),
}

impl Channel {
    fn base(&self) -> String {
        match self {
            Channel::Public => BASE_URL.to_string(),
            Channel::Paid(feed, _) => format!("{FEED_URL}/{}", feed.slug()),
        }
    }

    fn feed(&self) -> crate::feed::Feed {
        match self {
            Channel::Public => crate::feed::Feed::OssDelayed,
            Channel::Paid(feed, _) => *feed,
        }
    }

    fn token(&self) -> Option<&crate::feed::Token> {
        match self {
            Channel::Public => None,
            Channel::Paid(_, token) => Some(token),
        }
    }
}

fn fetch_manifest(connect: Option<Duration>) -> Result<(Manifest, Channel), Error> {
    let feed = crate::feed::current();
    let (bytes, channel) = if feed.needs_token() {
        let held =
            crate::feed::token().map_err(|e| Error::Refused(Refusal::new(format!("{e:#}"))))?;
        let (bytes, token) = paid_manifest(feed, held, connect)?;
        (bytes, Channel::Paid(feed, token))
    } else {
        let fetched =
            download(&Channel::Public, MANIFEST, connect).map_err(|e| Error::Other(e.message))?;
        (fetched.bytes, Channel::Public)
    };
    let text = String::from_utf8(bytes)
        .map_err(|e| Error::Other(format!("manifest is not valid UTF-8: {e}")))?;
    let manifest = toml::from_str(&text).map_err(|e| {
        Error::Other(format!(
            "parsing manifest {}/{MANIFEST}: {e}",
            channel.base()
        ))
    })?;
    Ok((manifest, channel))
}

/// Install or refresh the rules this run uses, in the tree it chose.
///
/// When the rules Worker refuses the feed and it was not named on the command
/// line, the run falls back to the best feed the plan opens — says so once,
/// through [`crate::feed::fall_back`] — and refreshes that instead. A named
/// feed's refusal is the error. A network failure is neither: it is returned,
/// and the rules on disk serve.
pub fn refresh(force: bool, quiet: bool) -> Result<(), Error> {
    match update(&crate::traits_repo::install_target(), force, quiet) {
        Err(Error::Refused(refusal)) if !crate::feed::explicit() => {
            crate::feed::fall_back(&refusal.opened, refusal.recognised, &refusal.message);
            // The target moved with the fall back: it is the new feed's tree now.
            update(&crate::traits_repo::install_target(), force, quiet)
        }
        done => done,
    }
}

/// Switch this host to `feed`: connect this computer if the feed needs a token
/// and none is held, install the feed's rules, and only then save the choice
/// for every later run. What `cleave feed <name>` runs.
///
/// # Errors
///
/// No token and no terminal to connect on, a plan that does not include the
/// feed, or a failed download. Nothing is saved on any of them.
pub fn switch(feed: crate::feed::Feed) -> Result<(), Error> {
    crate::feed::select(feed, true);
    sign_in()?;
    let dir = crate::traits_repo::installed_dir(feed);
    update(&dir, false, false)?;
    let saved = crate::feed::save_choice(feed).map_err(|e| Error::Other(format!("{e:#}")))?;
    let installed = installed(&dir).map_or_else(String::new, |i| {
        format!(
            " ({} {})",
            i.commit.chars().take(7).collect::<String>(),
            i.date
        )
    });
    print_status(&format!(
        "✓ Using the {feed}{installed}. Saved to {}.",
        crate::feed::tilde(&saved)
    ));
    // A pin to another feed's tree (scan pins the installed tree) follows the
    // switch; any other override is the operator's, and still wins.
    match crate::traits_repo::override_dir() {
        Some(dir)
            if crate::feed::Feed::ALL
                .into_iter()
                .any(|other| dir == crate::traits_repo::installed_dir(other)) =>
        {
            crate::traits_repo::set_override_dir(Some(crate::traits_repo::installed_dir(feed)));
        }
        Some(dir) => print_status(&format!(
            "Note: the traits directory is overridden ({}), and the override still wins.",
            dir.display()
        )),
        None => {}
    }
    Ok(())
}

/// The token a named paid feed needs, asked for now if this host holds none.
/// Does nothing for `oss-delayed`, or for a feed that was not named on the
/// command line (that one falls back instead of asking).
///
/// Called once, before anything fetches rules, so the asking happens at the
/// start of a run rather than inside whichever download happens first — and
/// happens once, rather than once per download that fails without it.
///
/// # Errors
///
/// No token and no terminal to ask on, or none accepted.
pub fn sign_in() -> Result<(), Error> {
    let feed = crate::feed::current();
    if !feed.needs_token() || !crate::feed::explicit() {
        return Ok(());
    }
    match crate::feed::token().map_err(|e| Error::Refused(Refusal::new(format!("{e:#}"))))? {
        Some(_) => Ok(()),
        None if crate::feed::interactive() => connect_device(Some(feed), None).map(drop),
        None => Err(needs_a_token()),
    }
}

/// Connect this computer to its isotope13 plan, check the token it is issued,
/// and save it. What `hood connect` runs, and what scan runs when
/// `--analyze=remote` finds no token.
///
/// # Errors
///
/// No terminal to show the code on, no approval, or a token the rules service
/// does not recognise.
pub fn connect() -> Result<(), Error> {
    if !crate::feed::interactive() {
        return Err(needs_a_token());
    }
    let feed = crate::feed::current();
    connect_device(feed.needs_token().then_some(feed), None).map(drop)
}

fn needs_a_token() -> Error {
    Error::Refused(Refusal::new(format!(
        "the {} needs an isotope13 token: {}",
        crate::feed::current(),
        crate::feed::how_to_get_one()
    )))
}

/// How long a newly issued token may take to reach the rules Worker. Dash
/// writes it to KV a moment before handing it over; KV takes up to a minute
/// to reach every edge, and the Worker caches a miss for another minute. A
/// check that lands first is not believed until both have run out.
const ISSUE_PROPAGATION: Duration = Duration::from_secs(150);
/// How often a newly issued token is checked again while it propagates.
const ISSUE_RECHECK: Duration = Duration::from_secs(5);

/// Connect, check, save: the one place a token is asked for.
///
/// The issued token is checked against `feed` — the paid feed this run needs —
/// or, when only connecting, against the zero-day feed: either way the answer
/// says whether the rules service knows the token and which feeds its plan
/// opens. Returns the feed's manifest when the token opened it.
///
/// A token dash has just issued is real, so it is saved whatever plan it is
/// on. What it is not, yet, is everywhere — so a check that does not
/// recognise it waits out KV's propagation before believing that.
fn connect_device(
    feed: Option<crate::feed::Feed>,
    connect: Option<Duration>,
) -> Result<Option<(Vec<u8>, crate::feed::Token)>, Error> {
    use crate::feed::{Connected, Feed, Source};
    // What dash records the device as: the tool and the OS, nothing that
    // names the person or the machine.
    let label = format!("{} on {}", crate::feed::tool(), std::env::consts::OS);
    let Connected { token, progress } =
        crate::feed::connect(&label).map_err(|e| Error::Refused(Refusal::new(format!("{e:#}"))))?;
    progress.set("Approved. Connecting…");

    let probe = feed.unwrap_or(Feed::ZeroDay);
    let started = std::time::Instant::now();
    let checked = loop {
        match check_token(&token, Source::Device, probe, connect)? {
            Err(Answer::Refused { tier: None, .. }) if started.elapsed() < ISSUE_PROPAGATION => {
                if crate::cancellation::is_cancelled() {
                    return Err(Error::Refused(Refusal::new("connection cancelled".into())));
                }
                let waited = started.elapsed().as_secs();
                tracing::debug!(
                    tid = %token.fingerprint(),
                    waited,
                    "issued token not at the edge yet; checking again"
                );
                // A second stage, so a wait that is KV catching up reads as
                // one — and a wait that never ends names which side to look at.
                progress.set(&format!(
                    "Approved. Waiting for the rules service to see the new token… {waited}s"
                ));
                std::thread::sleep(ISSUE_RECHECK);
            }
            other => break other,
        }
    };
    let tid = token.fingerprint();
    match checked {
        Ok(Opened { manifest, tier }) => {
            let plan = tier.as_deref().map(crate::feed::plan_name);
            progress.finish(&match plan {
                Some(plan) => format!("✓ Connected on the {plan} plan."),
                None => "✓ Connected.".to_string(),
            });
            save_issued(&token);
            Ok(Some((manifest, token)))
        }
        // Only connecting: a recognised token is a connection, whatever its
        // plan includes.
        Err(Answer::Refused {
            tier: Some(tier), ..
        }) if feed.is_none() => {
            progress.finish(&format!(
                "✓ Connected on the {} plan.",
                crate::feed::plan_name(&tier)
            ));
            save_issued(&token);
            Ok(None)
        }
        Err(answer @ Answer::Refused { tier: Some(_), .. }) => {
            drop(progress);
            let saved = save_issued(&token);
            let refused = refusal(&tid, Source::Device, probe, answer);
            Err(Error::Refused(Refusal {
                message: format!("connected, but {}.{saved}", refused.message),
                ..refused
            }))
        }
        Err(Answer::Refused { tier: None, .. }) => Err(Error::Refused(Refusal::new(format!(
            "isotope13 issued token {tid}, but the rules service had not seen it after {}s; run again in a minute",
            ISSUE_PROPAGATION.as_secs()
        )))),
        Err(answer) => Err(Error::Refused(refusal(&tid, Source::Device, probe, answer))),
    }
}

/// Save a token this computer was just issued, and say where, quietly. A
/// token that could not be saved still opens the feed for this run; the
/// next one connects again. Returns what was said, for an error to carry.
fn save_issued(token: &crate::feed::Token) -> String {
    use colored::Colorize;
    let said = match crate::feed::save(token) {
        Ok(path) => format!("Token saved to {}", crate::feed::tilde(&path)),
        Err(e) => format!("The token could not be saved ({e}); it is used for this run only"),
    };
    eprintln!("   {}\n", said.dimmed());
    format!(" {said}.")
}

/// A paid feed's manifest, and the token that opened it.
///
/// A feed named on the command line whose saved token the Worker no longer
/// recognises — revoked, or this computer disconnected — is reached by
/// connecting again, on a terminal; any other refusal is an error that says
/// what was wrong, where the token came from, and which feeds the plan does
/// open, and [`refresh`] turns it into a fall back when the feed was not
/// named. No token at all is the same error — the CLIs ask through
/// [`sign_in`] before they get here.
fn paid_manifest(
    feed: crate::feed::Feed,
    held: Option<(crate::feed::Token, crate::feed::Source)>,
    connect: Option<Duration>,
) -> Result<(Vec<u8>, crate::feed::Token), Error> {
    use crate::feed::Source;
    let Some((token, source)) = held else {
        return Err(needs_a_token());
    };
    let answer = match check_token(&token, source, feed, connect)? {
        Ok(Opened { manifest, .. }) => return Ok((manifest, token)),
        Err(answer) => answer,
    };
    let unknown = matches!(
        answer,
        Answer::Refused { tier: None, .. } | Answer::Status(_)
    );
    if source == Source::File && unknown && crate::feed::explicit() && crate::feed::interactive() {
        print_status(&format!(
            "✗ {}.\n",
            refusal(&token.fingerprint(), source, feed, answer).message
        ));
        return connect_device(Some(feed), connect)?
            .ok_or_else(|| Error::Other(format!("connected, but the {feed} did not answer")));
    }
    Err(Error::Refused(refusal(
        &token.fingerprint(),
        source,
        feed,
        answer,
    )))
}

/// A paid feed's manifest, and the plan the token that opened it is on.
struct Opened {
    manifest: Vec<u8>,
    tier: Option<String>,
}

/// Ask the rules Worker for `feed` with a token: what it opened, or what it
/// said instead. Only a transport or bucket failure is an `Error`; a refusal
/// is an answer.
fn check_token(
    token: &crate::feed::Token,
    source: crate::feed::Source,
    feed: crate::feed::Feed,
    connect: Option<Duration>,
) -> Result<Result<Opened, Answer>, Error> {
    let tid = token.fingerprint();
    let answer = match download(&Channel::Paid(feed, token.clone()), MANIFEST, connect) {
        Ok(got) if got.feed == Some(feed) => {
            tracing::info!(
                event = "feed.token",
                source = source.as_str(),
                feed = feed.slug(),
                outcome = "ok",
                tier = got.tier.as_deref().unwrap_or(""),
                %tid
            );
            return Ok(Ok(Opened {
                manifest: got.bytes,
                tier: got.tier,
            }));
        }
        // The Worker names the feed it served; anything else is not the feed
        // asked for, whatever the bytes are.
        Ok(got) => Answer::Status(format!(
            "an answer for {} instead",
            got.feed.map_or("no named feed", crate::feed::Feed::slug)
        )),
        Err(err) if err.status == Some(403) => Answer::Refused {
            opened: err.feeds,
            tier: err.tier,
        },
        Err(err) if err.unauthorized() => Answer::Status(err.status_text()),
        Err(err) => return Err(Error::Other(err.message)),
    };
    // Info, not warn: the caller turns a refusal into an error that says the
    // same thing in words, and a terminal should not read it twice.
    tracing::info!(
        event = "feed.token",
        source = source.as_str(),
        feed = feed.slug(),
        outcome = "refused",
        %tid,
        refused = %answer
    );
    Ok(Err(answer))
}

/// What the rules Worker said instead of serving a feed.
enum Answer {
    /// A 403: the feeds the token opens, and the plan it resolved to when the
    /// Worker recognised it.
    Refused {
        opened: Vec<crate::feed::Feed>,
        tier: Option<String>,
    },
    /// A 401, or an answer that was not the feed asked for.
    Status(String),
}

impl std::fmt::Display for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Answer::Refused {
                tier: Some(tier),
                opened,
            } => {
                let opened: Vec<_> = opened.iter().map(|feed| feed.slug()).collect();
                write!(f, "{tier} plan; opens {}", opened.join(","))
            }
            Answer::Refused { tier: None, .. } => f.write_str("token not recognised"),
            Answer::Status(status) => f.write_str(status),
        }
    }
}

/// A refusal in words someone can act on — what was wrong, where the token
/// came from, and what to do about it — with the feeds the plan does open.
fn refusal(
    tid: &str,
    source: crate::feed::Source,
    feed: crate::feed::Feed,
    answer: Answer,
) -> Refusal {
    use crate::feed::Source;
    let dash = crate::feed::DASH_URL;
    let env = crate::feed::TOKEN_ENV;
    let saved = || {
        crate::feed::token_path().map_or_else(
            || "the saved token".to_string(),
            |p| p.display().to_string(),
        )
    };
    let message = match (&answer, source) {
        (
            Answer::Refused {
                tier: Some(tier),
                opened,
            },
            _,
        ) => {
            let plan = crate::feed::plan_name(tier);
            match opened.iter().find(|open| open.needs_token()) {
                Some(best) => format!(
                    "isotope13 token {tid} is on the {plan} plan, which does not include the {feed}; it includes the {best}: run `{} feed {}`, or upgrade at {dash}plans",
                    crate::feed::tool(),
                    best.slug()
                ),
                None => format!(
                    "isotope13 token {tid} is on the {plan} plan, which includes only the {}; upgrade at {dash}plans for the supporter and zero-day feeds",
                    crate::feed::Feed::OssDelayed
                ),
            }
        }
        (Answer::Refused { tier: None, .. }, Source::Env) => format!(
            "isotope13 does not recognise the token in {env} ({tid}): check it holds the whole token, and that it has not been revoked at {dash}"
        ),
        (Answer::Refused { tier: None, .. }, Source::File) => format!(
            "isotope13 no longer recognises this computer's token ({tid}, saved at {}): it was revoked, or the computer was disconnected",
            saved()
        ),
        (Answer::Refused { tier: None, .. }, Source::Device) => {
            format!("isotope13 does not recognise the token it just issued ({tid})")
        }
        (Answer::Status(status), _) => {
            format!("isotope13 refused token {tid} for the {feed} ({status}); see {dash}")
        }
    };
    match answer {
        Answer::Refused { opened, tier } => Refusal {
            message,
            opened,
            recognised: tier.is_some(),
        },
        Answer::Status(_) => Refusal::new(message),
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

    // Named for the directory they replace: each feed's tree shares a parent, and two installs must not share a staging tree.
    let name = dir
        .file_name()
        .map_or_else(|| "traits".into(), |n| n.to_string_lossy());
    // Held until the swap is done: concurrent updaters (an auto-update, an
    // explicit `update-rules`, a server's reload) would otherwise share the
    // fixed staging path below, one deleting what another is extracting, and
    // install a partial tree whose sidecar claims the whole commit.
    let lock_path = sibling(parent, &format!(".{name}.lock"));
    let lock = std::fs::File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("opening {}: {e}", lock_path.display()))?;
    match lock.lock() {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
        Err(e) => return Err(format!("locking {}: {e}", lock_path.display())),
    }
    let staging = sibling(parent, &format!(".{name}-staging"));
    let backup = sibling(parent, &format!(".{name}-backup"));
    remove_any(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("create staging: {e}"))?;

    let decoder = zstd::stream::read::Decoder::new(Cursor::new(&bytes))
        .map_err(|e| format!("opening zstd stream: {e}"))?;
    let committed = unpack_bundle(decoder, &staging, cfg!(windows))
        .map_err(|e| format!("extracting {}: {e}", artifact.file))?;

    let meta = Installed {
        commit: artifact.commit.clone(),
        date: artifact.date.clone(),
        committed,
        source: source.to_string(),
        version: our_version().to_string(),
        packed_rules: cfg!(windows),
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
///
/// Returns the commit time: the newest mtime of any entry, which `git archive`
/// (and pulsar's deterministic re-pack) sets to the commit's own.
fn unpack_bundle<R: Read>(
    reader: R,
    staging: &Path,
    pack_rules: bool,
) -> Result<Option<u64>, String> {
    let mut archive = tar::Archive::new(reader);
    // `git archive` writes group-writable modes (its default `tar.umask` is
    // 0002), and tar applies them as given: on a host whose users share a
    // primary group, any of them could then edit the rules every scan runs.
    archive.set_mask(0o022);
    let mut written = std::collections::HashSet::new();
    let mut unpacked = 0u64;
    let mut committed: Option<u64> = None;
    let entries = archive
        .entries()
        .map_err(|e| format!("reading tar entries: {e}"))?;

    for (count, entry) in entries.enumerate() {
        let mut entry = entry.map_err(|e| format!("reading tar entry: {e}"))?;
        unpacked = unpacked.saturating_add(entry.size());
        if count >= MAX_BUNDLE_ENTRIES || unpacked > MAX_UNPACKED_BYTES {
            return Err(format!(
                "bundle exceeds {MAX_BUNDLE_ENTRIES} entries or {MAX_UNPACKED_BYTES} bytes"
            ));
        }
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
        // Compiled rules are native code (see `yara_engine`'s cache); a
        // bundle's are never installed, whatever an older publisher shipped.
        if path.starts_with("third-party/compiled") {
            continue;
        }
        if let Ok(mtime) = entry.header().mtime() {
            committed = committed.max(Some(mtime));
        }
        // A `.git` would mark the installed tree as a checkout, and every later
        // update — the one that would replace a bad bundle — leaves those alone.
        if path.starts_with(".git") {
            return Err(format!("reserved tar entry: {}", path.display()));
        }
        if !kind.is_file() && !kind.is_dir() {
            return Err(format!(
                "unsupported tar entry type {kind:?} at {}",
                path.display()
            ));
        }
        // Some bundle YAML (notably third-party/config.yaml and validation
        // fixtures) is read directly by other commands. Only source-tree rule
        // files are exposed through RuleSources' virtual paths.
        let in_rule_tree = [
            "metadata",
            "micro-behaviors",
            "objectives",
            "well-known",
            "third-party",
        ]
        .iter()
        .any(|directory| path.starts_with(directory));
        let pack = pack_rules
            && kind.is_file()
            && in_rule_tree
            && path != Path::new("third-party/config.yaml")
            && matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yaml" | "yml" | "yar" | "yara")
            );
        if pack {
            // tar::Entry::unpack_in validates paths for ordinary files. The
            // compressed path is written by us, so validate it explicitly.
            if !path
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                return Err(format!("unsafe tar entry path: {}", path.display()));
            }
            let mut packed_name = path.as_os_str().to_os_string();
            packed_name.push(".zst");
            let destination = staging.join(packed_name);
            if !written.insert(destination.clone()) || destination.exists() {
                return Err(format!("duplicate tar entry: {}", path.display()));
            }
            std::fs::create_dir_all(destination.parent().unwrap_or(staging))
                .map_err(|e| format!("creating parent of {}: {e}", destination.display()))?;
            let file = std::fs::File::create(&destination)
                .map_err(|e| format!("creating {}: {e}", destination.display()))?;
            let mut encoder = zstd::stream::write::Encoder::new(file, 3)
                .map_err(|e| format!("compressing {}: {e}", path.display()))?;
            io::copy(&mut entry, &mut encoder)
                .map_err(|e| format!("compressing {}: {e}", path.display()))?;
            encoder
                .finish()
                .map_err(|e| format!("finishing {}: {e}", destination.display()))?;
            continue;
        }
        if !written.insert(staging.join(&path)) {
            return Err(format!("duplicate tar entry: {}", path.display()));
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
    Ok(committed)
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
        if std::fs::symlink_metadata(backup).is_ok()
            && let Err(restore) = std::fs::rename(backup, dir)
        {
            return Err(format!(
                "installing traits: {e}; restoring the previous traits also failed \
                 ({restore}); they are at {}",
                backup.display()
            ));
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

/// A successful download, and the feed the rules Worker said it served.
struct Fetched {
    bytes: Vec<u8>,
    /// `x-isotope13-feed`; absent from the public bucket.
    feed: Option<crate::feed::Feed>,
    /// The plan the token resolved to, when the Worker recognised it.
    tier: Option<String>,
}

/// A failed download, with the HTTP status when there was one.
///
/// The status is what tells a refused token apart from a bucket that is down:
/// the first asks for another token, the second is an error the operator needs
/// to see, and neither is retried into the other.
#[derive(Default)]
struct FetchError {
    status: Option<u16>,
    message: String,
    /// `x-isotope13-feeds` on a refusal: what the token does open.
    feeds: Vec<crate::feed::Feed>,
    /// `x-isotope13-tier` on a refusal from a Worker that knew the token.
    tier: Option<String>,
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
/// [`paid_manifest`] answers by asking for another. Asking either of those
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
        message: format!("http client: {e}"),
        ..FetchError::default()
    })?;

    let mut request = client.get(&url);
    if let Some(token) = channel.token() {
        request = request.bearer_auth(token.secret());
    }
    let resp = request.send().map_err(|e| FetchError {
        message: format!("GET {url}: {e}"),
        ..FetchError::default()
    })?;

    let status = resp.status();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    // Echoed by the Worker; only a plain identifier is believed.
    let tier = header(TIER_HEADER)
        .filter(|t| !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_alphanumeric()));
    if !status.is_success() {
        return Err(FetchError {
            status: Some(status.as_u16()),
            message: format!("GET {url}: {status}"),
            feeds: header(FEEDS_HEADER).map_or_else(Vec::new, |feeds| {
                feeds
                    .split(',')
                    .filter_map(|slug| crate::feed::Feed::from_slug(slug.trim()))
                    .collect()
            }),
            tier,
        });
    }
    let feed = header(FEED_HEADER).and_then(|slug| crate::feed::Feed::from_slug(&slug));
    let mut bytes = Vec::new();
    resp.take(MAX_DOWNLOAD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| FetchError {
            status: Some(status.as_u16()),
            message: format!("reading {url}: {e}"),
            ..FetchError::default()
        })?;
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(FetchError {
            status: Some(status.as_u16()),
            message: format!("{url} is larger than {MAX_DOWNLOAD_BYTES} bytes"),
            ..FetchError::default()
        });
    }
    Ok(Fetched { bytes, feed, tier })
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
mod tests;
