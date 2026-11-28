//! Rule feeds: which published ruleset a host scans with.
//!
//! Three feeds carry the same rules and differ only in how long a ruleset
//! waits after it clears QA:
//!
//! | feed | delay | needs |
//! |---|---|---|
//! | `zero-day` | up to 15 minutes | a team plan: Basic, Enhanced, or Critical |
//! | `supporter` | up to 48 hours | a Supporter plan or better |
//! | `oss` | up to 8 days, the public roll-up | nothing |
//!
//! A run's feed is `--feed` (each tool also reads it from its own variable:
//! `CLEAVE_FEED`, `SCAN_FEED`, `HOOD_FEED`), and `auto` when neither is given: the best feed this computer's login opens, else `oss`. Nothing is
//! saved between runs but the login itself, so one host can run every feed at
//! once. A feed named on the command line is insisted on: with no login it
//! asks for one on a terminal, and a plan that does not include it is an
//! error. Under `auto`, a feed the rules service refuses falls back to the
//! best feed the plan does open.
//!
//! The paid feeds need a token — the tool's own variable (`CLEAVE_TOKEN`,
//! `SCAN_TOKEN`, `HOOD_TOKEN`; see [`set_token_env`]), else the one saved in
//! `<config>/atomdrift/isotope13-api.json` by `<tool> login`. The token is
//! opaque here: whether it is valid, and which feeds it opens, is the
//! server's to say. What it last said is kept in the cache (see [`Plan`]) so
//! that `auto` need not ask on every run; the token file holds nothing that
//! could go stale beside it. The token travels only to isotope13's own hosts,
//! in an `Authorization` header, and never into a log: logs carry its
//! [`Token::fingerprint`], the same one the service's dashboard shows. The
//! `oss` feed is fetched with no token, from atomdrift's own bucket.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The variable a token is read from when the running tool names none.
const DEFAULT_TOKEN_ENV: &str = "CLEAVE_TOKEN";
/// The variable the running tool reads a token from; see [`set_token_env`].
static TOKEN_ENV: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
/// What the rules service last said about a token, under the cache directory.
const PLAN_FILE: &str = "plan.json";
/// How long that answer stands in for asking again. Every paid download
/// refreshes it, so only a plan that opens no paid feed ever reaches it:
/// `auto` then asks once a day whether the plan has changed.
const PLAN_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
/// The Atomdrift console, where a computer is signed in and a plan chosen,
/// as commercial customers (the zero-day feed) are steered to it.
pub const CONSOLE_COM: &str = "https://console.atomdrift.com/";
/// The same console, as open-source users and supporters are steered to it.
pub const CONSOLE_ORG: &str = "https://console.atomdrift.org/";
/// The saved token, under `<config>/atomdrift/`. Shared by every atomdrift tool.
const TOKEN_FILE: &str = "isotope13-api.json";
/// Longer than any token the console mints, short enough that a stray paste of a
/// whole document is refused rather than sent.
const MAX_TOKEN_LEN: usize = 256;

/// A published ruleset stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Feed {
    /// Each ruleset as soon as it clears QA.
    ZeroDay,
    /// The newest zero-day ruleset, republished every 48 hours.
    Supporter,
    /// The open-source roll-up, published every eight days.
    Oss,
}

impl Feed {
    /// Every feed, best first.
    pub const ALL: [Feed; 3] = [Feed::ZeroDay, Feed::Supporter, Feed::Oss];

    /// The name on the command line, in headers, and in JSON.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Feed::ZeroDay => "zero-day",
            Feed::Supporter => "supporter",
            Feed::Oss => "oss",
        }
    }

    /// The feed a slug names.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|feed| feed.slug() == slug)
    }

    /// The feed a name from the rules service means. The service still calls
    /// the open feed by its old name, `oss-delayed`.
    pub(crate) fn from_service(name: &str) -> Option<Self> {
        match name {
            "oss-delayed" => Some(Feed::Oss),
            name => Self::from_slug(name),
        }
    }

    /// The longest a ruleset waits after QA before this feed carries it:
    /// pulsar checks for one every 15 minutes, republishes the supporter feed
    /// every 48 hours, and the public roll-up every eight days.
    #[must_use]
    pub fn delay(self) -> &'static str {
        match self {
            Feed::ZeroDay => "up to 15 minutes",
            Feed::Supporter => "up to 48 hours",
            Feed::Oss => "up to 8 days",
        }
    }

    /// Whether fetching this feed takes an isotope13 token.
    #[must_use]
    pub fn needs_token(self) -> bool {
        self != Feed::Oss
    }

    /// The console this feed's users are sent to: `.com` for the commercial
    /// zero-day feed, `.org` for everyone else. The two are one console.
    #[must_use]
    pub fn console(self) -> &'static str {
        match self {
            Feed::ZeroDay => CONSOLE_COM,
            Feed::Supporter | Feed::Oss => CONSOLE_ORG,
        }
    }

    /// Where to get a plan that opens this feed: the zero-day feed comes only
    /// with a team plan, so its link starts a team; the others' is the Plan
    /// tab of whoever opens it, at `/me/plan`.
    #[must_use]
    pub fn plans(self) -> String {
        match self {
            Feed::ZeroDay => format!("{CONSOLE_COM}teams#new"),
            Feed::Supporter | Feed::Oss => format!("{CONSOLE_ORG}me/plan"),
        }
    }

    /// The installed tree's directory name, under `<data>/atomdrift/cleave/`.
    #[must_use]
    pub fn dir_name(self) -> &'static str {
        match self {
            Feed::ZeroDay => "traits-zero-day",
            Feed::Supporter => "traits-supporter",
            Feed::Oss => "traits-oss",
        }
    }

    fn index(self) -> u8 {
        match self {
            Feed::ZeroDay => 0,
            Feed::Supporter => 1,
            Feed::Oss => 2,
        }
    }
}

impl fmt::Display for Feed {
    /// The name in a sentence or a banner: "zero-day feed".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Feed::ZeroDay => "zero-day feed",
            Feed::Supporter => "supporter feed",
            Feed::Oss => "oss feed",
        })
    }
}

/// What `--feed` asks for: a feed, or `auto`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Choice {
    /// The best feed this computer's plan opens; `oss` when not signed in.
    #[default]
    Auto,
    /// Each ruleset as soon as it clears QA.
    ZeroDay,
    /// The newest zero-day ruleset, republished every 48 hours.
    Supporter,
    /// The open-source roll-up, published every eight days.
    Oss,
}

impl Choice {
    /// The feed named, or `None` for `auto`.
    #[must_use]
    pub fn feed(self) -> Option<Feed> {
        match self {
            Choice::Auto => None,
            Choice::ZeroDay => Some(Feed::ZeroDay),
            Choice::Supporter => Some(Feed::Supporter),
            Choice::Oss => Some(Feed::Oss),
        }
    }
}

/// This run's feed, as a [`Feed::index`]. Open source until [`resolve`] runs.
static CURRENT: AtomicU8 = AtomicU8::new(2);
static EXPLICIT: AtomicBool = AtomicBool::new(false);

/// The feed this run uses.
#[must_use]
pub fn current() -> Feed {
    match CURRENT.load(Ordering::Relaxed) {
        0 => Feed::ZeroDay,
        1 => Feed::Supporter,
        _ => Feed::Oss,
    }
}

/// Whether this run's feed was named (by `--feed` or its environment
/// variable) rather than `auto`, so a refusal is an error rather than a fall back, and a missing
/// token is asked for.
#[must_use]
pub fn explicit() -> bool {
    EXPLICIT.load(Ordering::Relaxed)
}

/// Use `feed` for the rest of this run.
///
/// The default traits directory follows the feed, so the capability mapper and
/// traits fingerprint built from another one are dropped, exactly as
/// [`crate::traits_repo::set_override_dir`] does. Calling it before the first
/// analysis costs nothing.
pub fn select(feed: Feed, explicit: bool) {
    EXPLICIT.store(explicit, Ordering::Relaxed);
    if CURRENT.swap(feed.index(), Ordering::Relaxed) != feed.index() {
        crate::shared_resources::invalidate_capability_mapper();
        crate::cache::invalidate_traits_scan();
    }
}

/// Decide this run's feed from `--feed` (clap reads the tool's variable for it).
/// Called once, before anything resolves a traits directory.
///
/// `auto` is the best feed the held token's plan opens, as the rules service
/// last said ([`Plan`]); the zero-day feed when that is not known (a refusal
/// then falls back, and records what the plan opens); `oss` with no token.
///
/// # Errors
///
/// A saved token file that others can read, or that cannot be read or
/// parsed: a fault to fix rather than a token to quietly do without.
pub fn resolve(choice: Choice) -> anyhow::Result<()> {
    let feed = match choice.feed() {
        Some(feed) => feed,
        None => match token()? {
            None => Feed::Oss,
            Some((token, _)) => Plan::load()
                .filter(|plan| plan.is_for(&token))
                .and_then(|plan| plan.feeds.first().copied())
                .unwrap_or(Feed::ZeroDay),
        },
    };
    select(feed, choice != Choice::Auto);
    let from = if choice == Choice::Auto {
        "auto"
    } else {
        "flag"
    };
    tracing::info!(event = "feed.mode", feed = feed.slug(), from);
    Ok(())
}

/// Leave the current feed for the rest of this run, because the rules service
/// refused it (or could not be reached for a first install) and the feed is
/// `auto`'s choice rather than named: the best of `opened` — the feeds the
/// plan opens, best first — is used instead. When the service gave no answer,
/// the best tree already installed for a lesser feed serves, else `oss`.
///
/// Landing on the best feed a `recognised` token's plan opens is `auto` doing
/// its job, and is logged, not warned about; anything else is a warning.
///
/// A traits override pinned to the refused feed's tree (scan pins the
/// installed tree so a checkout in the working directory cannot supply the
/// rules) follows, or the new feed's rules would never be resolved.
pub fn fall_back(opened: &[Feed], recognised: bool, why: &str) {
    let from = current();
    let installed = || {
        Feed::ALL
            .into_iter()
            .skip_while(|&feed| feed != from)
            .skip(1)
            .find(|&feed| crate::traits_repo::has_traits(&crate::traits_repo::installed_dir(feed)))
    };
    let to = opened
        .iter()
        .copied()
        .find(|&feed| feed != from)
        .or_else(|| if opened.is_empty() { installed() } else { None })
        .unwrap_or(Feed::Oss);
    if recognised && opened.first() == Some(&to) {
        tracing::info!(
            event = "feed.fallback",
            from = from.slug(),
            to = to.slug(),
            reason = %why,
            "using the {to}, the best feed this plan opens"
        );
    } else {
        tracing::warn!(
            event = "feed.fallback",
            from = from.slug(),
            to = to.slug(),
            reason = %why,
            "the {from} is unavailable; using the {to}"
        );
    }
    select(to, false);
    if crate::traits_repo::override_dir()
        .is_some_and(|dir| dir == crate::traits_repo::installed_dir(from))
    {
        crate::traits_repo::set_override_dir(Some(crate::traits_repo::installed_dir(to)));
    }
}

/// What the rules service last said about a token: its plan, and the feeds
/// that plan opens, best first. A cache, not configuration — losing it costs
/// `auto` one question to the service — kept so that `auto` lands on the
/// right feed without asking on every run, and offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// [`Token::fingerprint`] of the token the answer was about.
    tid: String,
    /// The plan's tier as the service names it, when it recognised the token.
    pub tier: Option<String>,
    /// The feeds the plan opens, best first.
    #[serde(with = "feed_slugs")]
    pub feeds: Vec<Feed>,
    /// When the service said so, in seconds since the Unix epoch.
    at: u64,
}

impl Plan {
    /// The answer for the token this computer holds, if it is recent enough
    /// to act on. Reads only the disk.
    #[must_use]
    pub fn current() -> Option<Self> {
        let (token, _) = token().ok().flatten()?;
        Self::load().filter(|plan| plan.is_for(&token))
    }

    fn is_for(&self, token: &Token) -> bool {
        self.tid == token.fingerprint() && now().saturating_sub(self.at) < PLAN_TTL.as_secs()
    }

    fn path() -> Option<PathBuf> {
        crate::cache::cache_dir()
            .ok()
            .map(|dir| dir.join(PLAN_FILE))
    }

    /// The answer for `token`, if it is recent enough to act on.
    pub(crate) fn for_token(token: &Token) -> Option<Self> {
        Self::load().filter(|plan| plan.is_for(token))
    }

    fn load() -> Option<Self> {
        let path = Self::path()?;
        let text = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&text)
            .inspect_err(
                |e| tracing::debug!(path = %path.display(), error = %e, "ignoring the cached plan"),
            )
            .ok()
    }

    /// Record what the service said about `token`. A failure to write costs
    /// only a question next run, so it is logged and otherwise ignored.
    pub(crate) fn remember(token: &Token, tier: Option<&str>, feeds: &[Feed]) {
        if feeds.is_empty() {
            return;
        }
        let plan = Self {
            tid: token.fingerprint(),
            tier: tier.map(str::to_owned),
            feeds: feeds.to_vec(),
            at: now(),
        };
        let Some(path) = Self::path() else { return };
        let written = serde_json::to_vec(&plan)
            .map_err(|e| e.to_string())
            .and_then(|json| crate::cache::atomic_write(&path, &json).map_err(|e| e.to_string()));
        match written {
            Ok(()) => tracing::debug!(
                event = "feed.plan",
                tid = %plan.tid,
                tier = plan.tier.as_deref().unwrap_or(""),
                feeds = %plan.feeds.iter().map(|f| f.slug()).collect::<Vec<_>>().join(","),
                "remembered what the plan opens"
            ),
            Err(e) => tracing::debug!(path = %path.display(), error = %e, "plan not cached"),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Feeds as their slugs, so the cache file reads as the CLI spells them.
mod feed_slugs {
    use super::Feed;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(feeds: &[Feed], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(feeds.iter().map(|feed| feed.slug()))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Feed>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|slug| {
                Feed::from_slug(slug)
                    .ok_or_else(|| serde::de::Error::custom(format!("no feed named {slug:?}")))
            })
            .collect()
    }
}

/// How this run came to its feed, for a version report beside the feed's
/// name: `auto, Basic plan`, or `named, not signed in: …`. Reads only the
/// disk.
#[must_use]
pub fn describe() -> String {
    let how = if explicit() { "named" } else { "auto" };
    let plan = match token() {
        Ok(None) => format!("not signed in: `{} login`", tool()),
        Err(e) => format!("token unusable: {e}"),
        Ok(Some(_)) => Plan::current().and_then(|plan| plan.tier).map_or_else(
            || "signed in".to_string(),
            |tier| format!("{} plan", plan_name(&tier)),
        ),
    };
    format!("{how}, {plan}")
}

/// The running tool's name (its executable's file stem, `cleave` by
/// default), for a command to suggest.
pub(crate) fn tool() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "cleave".to_string())
}

/// A subscription token. Its `Debug` shows only the fingerprint, so a token
/// cannot reach a log through a stray `{:?}`.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Parse a token as pasted or exported: the first non-empty line, trimmed.
    ///
    /// An empty value is no token rather than an empty one, which would be sent
    /// as `Authorization: Bearer ` and refused. Anything with interior
    /// whitespace or control characters, or longer than any token the console mints,
    /// is a paste gone wrong and is refused before it is sent anywhere.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let line = text.lines().map(str::trim).find(|line| !line.is_empty())?;
        let plausible = line.len() <= MAX_TOKEN_LEN && line.bytes().all(|b| b.is_ascii_graphic());
        plausible.then(|| Self(line.to_string()))
    }

    /// The token itself, for an `Authorization` header and nothing else.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.0
    }

    /// The first 16 hex characters of the token's SHA-256: how the service
    /// names a token without holding it.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        hex::encode(&Sha256::digest(self.0.as_bytes())[..8])
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({})", self.fingerprint())
    }
}

/// Where a token came from, which decides what a refusal does: only a saved
/// token is replaced by asking for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The tool's token variable, [`token_env`].
    Env,
    /// The saved file.
    File,
    /// Issued to this computer by the device flow just now, and not saved
    /// until it is accepted.
    Device,
}

impl Source {
    /// The name structured logs use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Env => "env",
            Source::File => "file",
            Source::Device => "device",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TokenFile {
    token: String,
}

/// The saved token's path: `<config>/atomdrift/isotope13-api.json`.
#[must_use]
pub fn token_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("atomdrift").join(TOKEN_FILE))
}

/// Name the variable this tool reads a token from — `SCAN_TOKEN` for
/// atomscan, `HOOD_TOKEN` for hood — before anything reads a token. Each tool
/// keeps its own, as it keeps its own settings; `CLEAVE_TOKEN` otherwise.
/// The first call wins.
pub fn set_token_env(name: &'static str) {
    if TOKEN_ENV.set(name).is_err() {
        tracing::debug!(
            name,
            kept = token_env(),
            "the token variable was already named"
        );
    }
}

/// The variable a token is read from before the saved file: how CI supplies
/// one with no file and no prompt.
#[must_use]
pub fn token_env() -> &'static str {
    TOKEN_ENV.get().copied().unwrap_or(DEFAULT_TOKEN_ENV)
}

/// The token to use, if this host has one: [`token_env`], then the saved file.
///
/// # Errors
///
/// A saved file that others can read, or that cannot be read or parsed. Each is
/// a fault to fix rather than a token to quietly do without.
pub fn token() -> anyhow::Result<Option<(Token, Source)>> {
    if let Some(token) = std::env::var(token_env())
        .ok()
        .and_then(|v| Token::parse(&v))
    {
        return Ok(Some((token, Source::Env)));
    }
    let Some(path) = token_path() else {
        return Ok(None);
    };
    Ok(read_token_file(&path)?.map(|token| (token, Source::File)))
}

fn read_token_file(path: &Path) -> anyhow::Result<Option<Token>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    };
    check_private(path)?;
    let file: TokenFile = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
    Token::parse(&file.token)
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("{} holds no usable token", path.display()))
}

/// Refuse a token file anyone but its owner can read or write, as ssh refuses
/// a private key: a token another account can read is a token to revoke.
#[cfg(unix)]
fn check_private(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(anyhow::anyhow!(
            "{} is accessible to other users (mode {:o}); run: chmod 600 '{}'",
            path.display(),
            mode & 0o777,
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Save a token for every later run, readable by this user alone.
///
/// Written beside its final name and renamed into place, so a crash leaves the
/// old token or the new one, never half of either.
///
/// # Errors
///
/// When there is no config directory, or it cannot be written.
pub fn save(token: &Token) -> anyhow::Result<PathBuf> {
    let path =
        token_path().ok_or_else(|| anyhow::anyhow!("no config directory to save the token in"))?;
    write_token_file(&path, token)?;
    Ok(path)
}

fn write_token_file(path: &Path, token: &Token) -> anyhow::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("token path has no parent"))?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", dir.display()))?;

    let staging = path.with_extension("json.tmp");
    drop(std::fs::remove_file(&staging));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let body = serde_json::to_string(&TokenFile {
        token: token.secret().to_string(),
    })
    .map_err(|e| anyhow::anyhow!("rendering token file: {e}"))?;
    let written = options.open(&staging).and_then(|mut file| {
        file.write_all(body.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()
    });
    if let Err(e) = written.and_then(|()| std::fs::rename(&staging, path)) {
        drop(std::fs::remove_file(&staging));
        return Err(anyhow::anyhow!("writing {}: {e}", path.display()));
    }
    Ok(())
}

/// Whether a token can be asked for: stdin and stderr are both terminals.
#[must_use]
pub fn interactive() -> bool {
    use std::io::IsTerminal;
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// What to do when there is no token and no terminal to ask on: a CI job is
/// told what to set rather than left waiting on stdin.
#[must_use]
pub fn how_to_get_one() -> String {
    format!(
        "run `{} login` on a terminal, or set {}",
        tool(),
        token_env()
    )
}

/// Why this computer is being signed in, which heads the prompt and picks
/// the console it is sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    /// `<tool> login`: signing in for its own sake.
    Login,
    /// A named feed that needs a subscription, and no sign-in held.
    Needs(Feed),
    /// A named feed that needs a subscription, and a sign-in that no longer
    /// works.
    Expired(Feed),
}

impl Ask {
    /// The console to send this computer to: the feed's, or for a plain
    /// sign-in, the feed this run resolved to.
    fn console(self) -> &'static str {
        match self {
            Ask::Login => current().console(),
            Ask::Needs(feed) | Ask::Expired(feed) => feed.console(),
        }
    }

    /// The feed this sign-in is for, when it is for one.
    #[must_use]
    pub fn feed(self) -> Option<Feed> {
        match self {
            Ask::Login => None,
            Ask::Needs(feed) | Ask::Expired(feed) => Some(feed),
        }
    }

    /// The prompt's heading, and the line under it.
    fn heading(self) -> (String, Option<&'static str>) {
        match self {
            Ask::Login => ("Sign in to Atomdrift".to_string(), None),
            Ask::Needs(feed) => (format!("The {feed} requires a subscription."), None),
            Ask::Expired(feed) => (
                format!("The {feed} requires a subscription."),
                Some("This computer's sign-in has expired or was revoked."),
            ),
        }
    }
}

/// The prompt: why, and the link to approve this computer at.
fn welcome(ask: Ask, link: &str) {
    use colored::Colorize;
    let (heading, note) = ask.heading();
    eprintln!("\n \u{269b}\u{fe0f} {}", heading.bold());
    if let Some(note) = note {
        eprintln!("    {}", note.dimmed());
    }
    eprintln!(
        "\n    Open this link to approve this computer:\n    {}\n",
        link.bold()
    );
}

/// Whether `link` is a plain URL on the console, under either of its names:
/// it is printed to the terminal and handed to the platform's opener, so it
/// must carry no spaces or controls.
fn is_console_link(link: &str) -> bool {
    (link.starts_with(CONSOLE_COM) || link.starts_with(CONSOLE_ORG))
        && link.bytes().all(|b| b.is_ascii_graphic())
}

/// Open `url` in the browser this desktop uses, when there is one. Nothing
/// is reported either way: the link is on the screen regardless, and over
/// SSH it is the link that gets used.
///
/// Only an absolute path to the opener is run, never a name found on PATH.
fn open_browser(url: &str) {
    use std::process::{Command, Stdio};
    let (opener, args): (&str, &[&str]) = match std::env::consts::OS {
        "macos" => ("open", &[]),
        // Not `cmd /C start`: cmd would treat `&` in the query as a separator.
        "windows" => ("rundll32", &["url.dll,FileProtocolHandler"]),
        _ if std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some() =>
        {
            ("xdg-open", &[])
        }
        _ => return,
    };
    let Some(path) = crate::tool_resolution::resolve(opener) else {
        return;
    };
    let spawned = Command::new(path)
        .args(args)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match spawned {
        Ok(_) => tracing::debug!(opener, "opened the browser"),
        Err(e) => tracing::debug!(opener, error = %e, "could not open the browser"),
    }
}

/// A line of progress at the bottom of the terminal, redrawn in place.
///
/// Started while something is waited for, and finished with the line that
/// takes its place; dropped unfinished, it leaves nothing behind. Writes to
/// stderr, which [`interactive`] has established is a terminal.
#[derive(Debug)]
pub struct Progress {
    label: std::sync::Arc<std::sync::Mutex<String>>,
    stop: std::sync::Arc<AtomicBool>,
    spinner: Option<std::thread::JoinHandle<()>>,
}

impl Progress {
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

    /// Start showing `label`, animated.
    #[must_use]
    pub fn start(label: &str) -> Self {
        use std::io::Write;
        let label = std::sync::Arc::new(std::sync::Mutex::new(label.to_string()));
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let spinner = {
            let (label, stop) = (label.clone(), stop.clone());
            std::thread::spawn(move || {
                for frame in Self::FRAMES.iter().cycle() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let text = label.lock().map(|l| l.clone()).unwrap_or_default();
                    let mut err = io::stderr().lock();
                    let _ = write!(err, "\r\x1b[2K    {frame} {text}");
                    let _ = err.flush();
                    std::thread::sleep(std::time::Duration::from_millis(80));
                }
            })
        };
        Self {
            label,
            stop,
            spinner: Some(spinner),
        }
    }

    /// Change what is being waited for.
    pub fn set(&self, label: &str) {
        if let Ok(mut held) = self.label.lock() {
            *held = label.to_string();
        }
    }

    /// Stop, and leave `line` where the progress was.
    pub fn finish(mut self, line: &str) {
        self.clear();
        eprintln!("    {line}");
    }

    fn clear(&mut self) {
        use std::io::Write;
        self.stop.store(true, Ordering::Relaxed);
        if let Some(spinner) = self.spinner.take() {
            let _ = spinner.join();
        }
        let mut err = io::stderr().lock();
        let _ = write!(err, "\r\x1b[2K");
        let _ = err.flush();
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.spinner.is_some() {
            self.clear();
        }
    }
}

/// What the console answers when a flow starts.
#[derive(Deserialize)]
struct DeviceStart {
    device_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

/// What the console answers to a poll: the token once approved, or a reason.
#[derive(Deserialize, Default)]
struct DevicePoll {
    token: Option<String>,
    error: Option<String>,
}

/// A token the console has just issued to this computer, and the progress
/// line still showing, for the caller to finish once the token is checked.
#[derive(Debug)]
pub struct Connected {
    /// The issued token, not yet checked against the rules channel.
    pub token: Token,
    /// The line still animating on the terminal.
    pub progress: Progress,
}

/// Sign this computer in through the console's device flow: ask for a code,
/// show why and where to approve it, open the browser on it, and wait. The
/// token that comes back is a device's, not one of the org's listed API
/// tokens. Whether a subscription is needed, and getting one, is the
/// console's business once the link is opened.
///
/// `label` is what the console records the device as, and nothing more. The
/// feed asked for goes with it, so the approval page can say when the plan
/// being approved lacks it and where to get one that has it.
///
/// # Errors
///
/// No terminal to show the link on, the console unreachable, the code
/// expiring unapproved, or Ctrl-C.
pub fn connect(ask: Ask, label: &str) -> anyhow::Result<Connected> {
    use std::time::{Duration, Instant};
    if !interactive() {
        return Err(anyhow::anyhow!(
            "signing in needs a terminal: {}",
            how_to_get_one()
        ));
    }
    let console = Console::new(ask.console())?;
    let body =
        serde_json::json!({ "label": label, "feed": ask.feed().map(Feed::slug) }).to_string();
    let (status, text) = console.post("device/code", &body)?;
    if status != 200 {
        return Err(anyhow::anyhow!(
            "{} could not start a sign-in (HTTP {status})",
            console.base
        ));
    }
    let start: DeviceStart = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("{} answered oddly: {e}", console.base))?;
    let expires = Duration::from_secs(start.expires_in.clamp(60, 3600));
    let interval = Duration::from_secs(start.interval.clamp(1, 60));
    let link = start
        .verification_uri_complete
        .unwrap_or(start.verification_uri);
    if !console.local && !is_console_link(&link) {
        // The host only: a parsed one is plain text, the rest is the server's.
        let host = reqwest::Url::parse(&link)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default();
        return Err(anyhow::anyhow!(
            "{} sent an approval link on another site ({host:?}); not opening it",
            console.base
        ));
    }
    welcome(ask, &link);
    open_browser(&link);
    let progress = Progress::start("Waiting for approval…");

    let poll = serde_json::json!({ "device_code": start.device_code }).to_string();
    let started = Instant::now();
    let mut failures = 0u32;
    loop {
        // Slept in slices so Ctrl-C is noticed within the second.
        for _ in 0..interval.as_secs() {
            if crate::cancellation::is_cancelled() {
                return Err(anyhow::anyhow!("sign-in cancelled"));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if started.elapsed() > expires {
            return Err(anyhow::anyhow!(
                "the approval code expired; run again for a new one"
            ));
        }
        let (status, text) = match console.post("device/token", &poll) {
            Ok(answer) => answer,
            // One dropped poll is not a verdict; a run of them is the console gone.
            Err(e) if failures < 5 => {
                failures += 1;
                tracing::debug!(error = %e, failures, "device poll failed; trying again");
                continue;
            }
            Err(e) => return Err(e),
        };
        failures = 0;
        let answer: DevicePoll = serde_json::from_str(&text).unwrap_or_default();
        match (status, answer.token) {
            (200, Some(token)) => {
                let token = Token::parse(&token)
                    .ok_or_else(|| anyhow::anyhow!("the console issued a token that is not one"))?;
                tracing::info!(event = "feed.device", outcome = "connected", tid = %token.fingerprint());
                return Ok(Connected { token, progress });
            }
            (202, _) => {}
            (410, _) => {
                return Err(anyhow::anyhow!(
                    "the approval code expired or was already used; run again for a new one"
                ));
            }
            (status, _) => {
                let reason = answer.error.unwrap_or_default();
                return Err(anyhow::anyhow!(
                    "{} refused the sign-in (HTTP {status} {})",
                    console.base,
                    reason.escape_debug()
                ));
            }
        }
    }
}

/// A plan as the dashboard names it.
#[must_use]
pub fn plan_name(tier: &str) -> String {
    match tier {
        "free" => "Community".to_string(),
        "business" => "Basic".to_string(),
        "oem" => "Critical".to_string(),
        other => {
            let mut chars = other.chars();
            chars
                .next()
                .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        }
    }
}

/// A path with the home directory written as `~`, for a line on a terminal.
#[must_use]
pub fn tilde(path: &Path) -> String {
    match dirs::home_dir().and_then(|home| path.strip_prefix(home).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// How the console is reached: TLS only, no redirects, and a short deadline
/// per call, so a device code can go nowhere but the console.
///
/// A debug build honours `CLEAVE_CONSOLE_URL`, so the flow can be run against
/// a local console; a release build has no override.
struct Console {
    base: String,
    /// Whether `base` is the debug override, whose links are its own.
    local: bool,
    http: reqwest::blocking::Client,
}

impl Console {
    fn new(console: &str) -> anyhow::Result<Self> {
        #[cfg(debug_assertions)]
        let local = std::env::var("CLEAVE_CONSOLE_URL")
            .ok()
            .filter(|v| !v.is_empty());
        #[cfg(not(debug_assertions))]
        let local: Option<String> = None;
        let base = local.as_ref().map_or_else(
            || console.to_string(),
            |local| format!("{}/", local.trim_end_matches('/')),
        );
        let http = reqwest::blocking::Client::builder()
            .https_only(local.is_none())
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("cleave/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| anyhow::anyhow!("http client: {e}"))?;
        Ok(Self {
            base,
            local: local.is_some(),
            http,
        })
    }

    fn post(&self, path: &str, json: &str) -> anyhow::Result<(u16, String)> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .body(json.to_string())
            .send()
            .map_err(|e| anyhow::anyhow!("POST {url}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .map_err(|e| anyhow::anyhow!("reading {url}: {e}"))?;
        Ok((status, text))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_console_links_are_opened() {
        // The console answers under either name, whichever was asked.
        assert!(is_console_link(
            "https://console.atomdrift.com/device/AB-12?x=1"
        ));
        assert!(is_console_link(
            "https://console.atomdrift.org/device/AB-12"
        ));
        assert!(!is_console_link("https://evil.example/device"));
        assert!(!is_console_link(
            "https://console.atomdrift.org.evil.example/"
        ));
        assert!(!is_console_link(
            "http://console.atomdrift.org/device/AB-12"
        ));
        assert!(!is_console_link("https://console.atomdrift.org/x\x1b[2J"));
        assert!(!is_console_link("https://console.atomdrift.org/ calc.exe"));
    }

    #[test]
    fn commercial_users_are_steered_to_dot_com() {
        assert_eq!(Feed::ZeroDay.console(), CONSOLE_COM);
        assert_eq!(Feed::Supporter.console(), CONSOLE_ORG);
        assert_eq!(Feed::Oss.console(), CONSOLE_ORG);
        assert_eq!(Ask::Needs(Feed::ZeroDay).console(), CONSOLE_COM);
        assert_eq!(Ask::Expired(Feed::Supporter).console(), CONSOLE_ORG);
        assert_eq!(Feed::ZeroDay.plans(), format!("{CONSOLE_COM}teams#new"));
        assert_eq!(Feed::Supporter.plans(), format!("{CONSOLE_ORG}me/plan"));
        assert_eq!(Ask::Login.feed(), None);
        assert_eq!(Ask::Needs(Feed::ZeroDay).feed(), Some(Feed::ZeroDay));
        assert_eq!(Ask::Expired(Feed::Supporter).feed(), Some(Feed::Supporter));
    }

    #[test]
    fn the_prompt_says_why_in_one_sentence() {
        assert_eq!(
            Ask::Needs(Feed::ZeroDay).heading(),
            (
                "The zero-day feed requires a subscription.".to_string(),
                None
            )
        );
        let (heading, note) = Ask::Expired(Feed::Supporter).heading();
        assert_eq!(heading, "The supporter feed requires a subscription.");
        assert!(note.is_some_and(|n| n.contains("expired or was revoked")));
        assert_eq!(Ask::Login.heading().0, "Sign in to Atomdrift");
    }

    #[test]
    fn feeds_are_named_and_ordered_best_first() {
        let slugs: Vec<_> = Feed::ALL.iter().map(|f| f.slug()).collect();
        assert_eq!(slugs, ["zero-day", "supporter", "oss"]);
        for feed in Feed::ALL {
            assert_eq!(Feed::from_slug(feed.slug()), Some(feed));
            // The CLI spells a feed the way the rules service does.
            let value = clap::ValueEnum::to_possible_value(&feed).unwrap();
            assert_eq!(value.get_name(), feed.slug());
            assert!(feed.dir_name().starts_with("traits-"));
            assert!(feed.dir_name().ends_with(feed.slug()));
        }
        assert_eq!(Feed::from_slug("Zero-Day"), None);
        assert_eq!(Feed::from_slug("enriched"), None);
        // The old name is the rules service's, never the CLI's.
        assert_eq!(Feed::from_slug("oss-delayed"), None);
        assert_eq!(Feed::from_service("oss-delayed"), Some(Feed::Oss));
        assert_eq!(Feed::from_service("supporter"), Some(Feed::Supporter));
        assert_eq!(Feed::ZeroDay.to_string(), "zero-day feed");
        assert_eq!(Feed::Oss.to_string(), "oss feed");
        assert!(Feed::ZeroDay.needs_token() && Feed::Supporter.needs_token());
        assert!(!Feed::Oss.needs_token());
    }

    #[test]
    fn a_choice_is_auto_or_a_feed_spelled_alike() {
        assert_eq!(Choice::default(), Choice::Auto);
        assert_eq!(Choice::Auto.feed(), None);
        let names: Vec<_> = <Choice as clap::ValueEnum>::value_variants()
            .iter()
            .map(|c| {
                clap::ValueEnum::to_possible_value(c)
                    .unwrap()
                    .get_name()
                    .to_string()
            })
            .collect();
        assert_eq!(names, ["auto", "zero-day", "supporter", "oss"]);
        for choice in <Choice as clap::ValueEnum>::value_variants() {
            if let Some(feed) = choice.feed() {
                let name = clap::ValueEnum::to_possible_value(choice).unwrap();
                assert_eq!(name.get_name(), feed.slug());
            }
        }
    }

    #[test]
    fn a_plan_is_for_one_token_and_goes_stale() {
        let token = Token::parse("i13_krypton85_abc").unwrap();
        let other = Token::parse("i13_krypton85_def").unwrap();
        let plan = Plan {
            tid: token.fingerprint(),
            tier: Some("supporter".into()),
            feeds: vec![Feed::Supporter, Feed::Oss],
            at: now(),
        };
        assert!(plan.is_for(&token));
        assert!(!plan.is_for(&other), "another token's answer");
        let stale = Plan {
            at: now() - PLAN_TTL.as_secs(),
            ..plan.clone()
        };
        assert!(!stale.is_for(&token));

        // Written as the CLI spells the feeds, and read back the same.
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains(r#""feeds":["supporter","oss"]"#), "{json}");
        assert_eq!(serde_json::from_str::<Plan>(&json).unwrap(), plan);
        // A feed this build does not know makes the whole answer unusable.
        let unknown = json.replace(r#"["supporter""#, r#"["platinum""#);
        assert!(serde_json::from_str::<Plan>(&unknown).is_err());
    }

    #[test]
    fn the_hint_names_the_login_command() {
        let hint = how_to_get_one();
        assert!(hint.contains(" login`"), "{hint}");
        assert!(hint.contains(token_env()), "{hint}");
        assert!(!hint.to_lowercase().contains("uplink"), "{hint}");
    }

    #[test]
    fn a_plan_is_named_as_the_dashboard_names_it() {
        assert_eq!(plan_name("free"), "Community");
        assert_eq!(plan_name("supporter"), "Supporter");
        assert_eq!(plan_name("business"), "Basic");
        assert_eq!(plan_name("enhanced"), "Enhanced");
        assert_eq!(plan_name("oem"), "Critical");
        // A tier this build has never heard of is still shown, not hidden.
        assert_eq!(plan_name("platinum"), "Platinum");
        assert_eq!(plan_name(""), "");
    }

    #[test]
    fn a_path_under_home_is_written_with_a_tilde() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(tilde(&home.join("x").join("y")), "~/x/y");
        assert_eq!(tilde(Path::new("/etc/hosts")), "/etc/hosts");
    }

    #[test]
    fn a_token_is_the_first_non_empty_line() {
        let parsed = |s| Token::parse(s).map(|t| t.secret().to_string());
        assert_eq!(
            parsed("i13_krypton85_abc\n").as_deref(),
            Some("i13_krypton85_abc")
        );
        assert_eq!(parsed("  i13_x  ").as_deref(), Some("i13_x"));
        assert_eq!(parsed("\n\n  \ni13_y\nignored\n").as_deref(), Some("i13_y"));
        // An empty value is no token, not an empty bearer token.
        assert_eq!(parsed(""), None);
        assert_eq!(parsed("   \n\t\n"), None);
    }

    #[test]
    fn a_paste_gone_wrong_is_never_a_token() {
        assert!(Token::parse("i13 krypton85").is_none(), "interior space");
        assert!(Token::parse("i13_\u{7f}x").is_none(), "control character");
        assert!(Token::parse("i13_é").is_none(), "non-ASCII");
        assert!(Token::parse(&"a".repeat(MAX_TOKEN_LEN + 1)).is_none());
        assert!(Token::parse(&"a".repeat(MAX_TOKEN_LEN)).is_some());
    }

    #[test]
    fn debug_shows_the_fingerprint_never_the_token() {
        let token = Token::parse("i13_krypton85_h7q3mx2p9wkd4rz8bn5tvcyfd0").unwrap();
        let shown = format!("{token:?}");
        assert!(!shown.contains("h7q3mx2p9wkd4rz8bn5tvcyfd0"));
        assert_eq!(shown, format!("Token({})", token.fingerprint()));
        assert_eq!(token.fingerprint().len(), 16);
    }

    #[test]
    fn a_saved_token_reads_back_and_is_private() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("atomdrift").join(TOKEN_FILE);
        let token = Token::parse("i13_krypton85_abc").unwrap();
        write_token_file(&path, &token).unwrap();
        assert_eq!(read_token_file(&path).unwrap(), Some(token.clone()));
        assert!(
            !path.with_extension("json.tmp").exists(),
            "no staging left behind"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }

        // Replacing it is atomic and leaves only the new token.
        let next = Token::parse("i13_krypton85_def").unwrap();
        write_token_file(&path, &next).unwrap();
        assert_eq!(read_token_file(&path).unwrap(), Some(next));
    }

    #[test]
    fn no_file_is_no_token_but_a_broken_one_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOKEN_FILE);
        assert_eq!(read_token_file(&path).unwrap(), None);

        std::fs::write(&path, "not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(
            read_token_file(&path)
                .unwrap_err()
                .to_string()
                .contains("parsing")
        );

        std::fs::write(&path, r#"{"token":"  "}"#).unwrap();
        assert!(
            read_token_file(&path)
                .unwrap_err()
                .to_string()
                .contains("no usable token")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_token_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOKEN_FILE);
        std::fs::write(&path, r#"{"token":"i13_krypton85_abc"}"#).unwrap();
        for mode in [0o644, 0o640, 0o604, 0o660] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = read_token_file(&path).unwrap_err();
            assert!(
                err.to_string().contains("chmod 600"),
                "mode {mode:o}: {err}"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_token_file(&path).unwrap().is_some());
    }
}
