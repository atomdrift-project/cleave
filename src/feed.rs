//! Rule feeds: which published ruleset a host scans with.
//!
//! Three feeds carry the same rules and differ only in how long a ruleset
//! waits after it clears QA:
//!
//! | feed | delay | needs |
//! |---|---|---|
//! | `zero-day` | none | a Business, POC, or Critical plan |
//! | `supporter` | 72 hours | an Early Supporter plan or better |
//! | `oss-delayed` | the eight-day public roll-up | nothing |
//!
//! A run's feed is, in order: `--feed` (or `ATOMDRIFT_FEED`), the choice saved
//! by `cleave feed <name>` in `<config>/atomdrift/feed`, the zero-day feed when
//! an isotope13 token is held, else `oss-delayed`. A feed named on the command
//! line is insisted on: a refusal is an error. Any other choice that the rules
//! service refuses falls back to the best feed the plan still opens, saying so.
//!
//! The paid feeds need a token — `ISOTOPE13_TOKEN`, else the one saved in
//! `<config>/atomdrift/isotope13-api.json` when this computer was connected.
//! The token is opaque here: whether it is valid, and which feeds it opens, is
//! the server's to say, so the saved file holds the token and nothing that
//! could go stale beside it. It travels only to isotope13's own hosts, in an
//! `Authorization` header, and never into a log: logs carry its
//! [`Token::fingerprint`], the same one the service's dashboard shows. The
//! `oss-delayed` feed is fetched with no token, from atomdrift's own bucket.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Environment variable holding a token. Checked before the saved file; how CI
/// supplies one with no file and no prompt.
pub const TOKEN_ENV: &str = "ISOTOPE13_TOKEN";
/// Environment equivalent of `--feed`.
pub const FEED_ENV: &str = "ATOMDRIFT_FEED";
/// Where a customer mints a token.
pub const DASH_URL: &str = "https://dash.isotope13.io/";
/// The saved token, under `<config>/atomdrift/`. Shared by every atomdrift tool.
const TOKEN_FILE: &str = "isotope13-api.json";
/// The saved feed choice, under `<config>/atomdrift/`. Shared likewise.
const CHOICE_FILE: &str = "feed";
/// Longer than any token dash mints, short enough that a stray paste of a
/// whole document is refused rather than sent.
const MAX_TOKEN_LEN: usize = 256;

/// A published ruleset stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Feed {
    /// Each ruleset as soon as it clears QA.
    ZeroDay,
    /// The ruleset that cleared QA at least 72 hours ago.
    Supporter,
    /// The open-source roll-up, published every eight days.
    OssDelayed,
}

impl Feed {
    /// Every feed, best first.
    pub const ALL: [Feed; 3] = [Feed::ZeroDay, Feed::Supporter, Feed::OssDelayed];

    /// The name on the command line, in headers, and in JSON.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Feed::ZeroDay => "zero-day",
            Feed::Supporter => "supporter",
            Feed::OssDelayed => "oss-delayed",
        }
    }

    /// The feed for a slug the rules service sent.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|feed| feed.slug() == slug)
    }

    /// How long a ruleset waits after QA before this feed carries it.
    #[must_use]
    pub fn delay(self) -> &'static str {
        match self {
            Feed::ZeroDay => "none",
            Feed::Supporter => "72 hours",
            Feed::OssDelayed => "up to 8 days",
        }
    }

    /// Whether fetching this feed takes an isotope13 token.
    #[must_use]
    pub fn needs_token(self) -> bool {
        self != Feed::OssDelayed
    }

    /// The installed tree's directory name, under `<data>/atomdrift/cleave/`.
    #[must_use]
    pub fn dir_name(self) -> &'static str {
        match self {
            Feed::ZeroDay => "traits-zero-day",
            Feed::Supporter => "traits-supporter",
            Feed::OssDelayed => "traits-oss-delayed",
        }
    }

    fn index(self) -> u8 {
        match self {
            Feed::ZeroDay => 0,
            Feed::Supporter => 1,
            Feed::OssDelayed => 2,
        }
    }
}

impl fmt::Display for Feed {
    /// The name in a sentence or a banner: "zero-day feed".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Feed::ZeroDay => "zero-day feed",
            Feed::Supporter => "supporter feed",
            Feed::OssDelayed => "opensource feed",
        })
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
        _ => Feed::OssDelayed,
    }
}

/// Whether this run's feed was named on the command line (`--feed` or
/// [`FEED_ENV`]), so a refusal is an error rather than a fall back, and a
/// missing token is asked for.
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

/// Decide this run's feed from the flag and what the host holds. Called once,
/// before anything resolves a traits directory.
///
/// `flag` is `--feed`; without one, [`FEED_ENV`]. Without either: the saved
/// choice, else the zero-day feed when a token is held (refused, it falls back
/// to whatever the plan opens), else `oss-delayed`. A saved paid feed with no
/// token held any more is `oss-delayed`, with a warning.
///
/// # Errors
///
/// A saved token file that others can read, or that cannot be read or
/// parsed: a fault to fix rather than a token to quietly do without.
pub fn resolve(flag: Option<Feed>) -> anyhow::Result<()> {
    // The CLIs read the variable through clap; this covers callers that have
    // no flag to give (hood).
    let flag = flag.or_else(env_feed);
    let (feed, from) = match flag {
        Some(feed) => (feed, "flag"),
        None => match saved_choice() {
            Some(feed) if feed.needs_token() && token()?.is_none() => {
                tracing::warn!(
                    event = "feed.fallback",
                    saved = feed.slug(),
                    "the {feed} needs an isotope13 token and none is held; using the {}",
                    Feed::OssDelayed
                );
                (Feed::OssDelayed, "saved")
            }
            Some(feed) => (feed, "saved"),
            None if token()?.is_some() => (Feed::ZeroDay, "token"),
            None => (Feed::OssDelayed, "default"),
        },
    };
    select(feed, flag.is_some());
    tracing::info!(event = "feed.mode", feed = feed.slug(), from);
    Ok(())
}

/// The feed [`FEED_ENV`] names. Anything else there is ignored, with a warning:
/// a typo must not quietly decide which rules a host scans with.
fn env_feed() -> Option<Feed> {
    let value = std::env::var(FEED_ENV).ok()?;
    let feed = Feed::from_slug(value.trim());
    if feed.is_none() && !value.trim().is_empty() {
        tracing::warn!(
            value = %value.escape_debug(),
            "{FEED_ENV} names no feed (zero-day, supporter, oss-delayed); ignoring it"
        );
    }
    feed
}

/// Leave the current feed for the rest of this run, because the rules service
/// refused it (or could not be reached for a first install) and the feed was
/// not named on the command line: the best of `opened` — the feeds the plan
/// opens, best first — is used instead, else `oss-delayed`, and the one
/// warning says why.
///
/// When the host had saved no choice and the token was `recognised`, the feed
/// fallen back to is saved, so later runs start there instead of asking for a
/// feed the plan does not include every time.
///
/// A traits override pinned to the refused feed's tree (scan pins the
/// installed tree so a checkout in the working directory cannot supply the
/// rules) follows, or the new feed's rules would never be resolved.
pub fn fall_back(opened: &[Feed], recognised: bool, why: &str) {
    let from = current();
    let to = opened
        .iter()
        .copied()
        .find(|&feed| feed != from)
        .unwrap_or(Feed::OssDelayed);
    tracing::warn!(
        event = "feed.fallback",
        from = from.slug(),
        to = to.slug(),
        reason = %why,
        "the {from} is unavailable; using the {to}"
    );
    select(to, false);
    if recognised && saved_choice().is_none() {
        match save_choice(to) {
            Ok(path) => {
                tracing::info!(event = "feed.saved", feed = to.slug(), path = %path.display())
            }
            Err(e) => tracing::debug!(error = %e, "feed choice not saved"),
        }
    }
    if crate::traits_repo::override_dir()
        .is_some_and(|dir| dir == crate::traits_repo::installed_dir(from))
    {
        crate::traits_repo::set_override_dir(Some(crate::traits_repo::installed_dir(to)));
    }
}

/// The saved choice's path: `<config>/atomdrift/feed`.
#[must_use]
pub fn choice_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("atomdrift").join(CHOICE_FILE))
}

/// The feed `cleave feed <name>` saved, if any. A file holding anything else is
/// no choice, with a warning: it is only ever written by this module.
#[must_use]
pub fn saved_choice() -> Option<Feed> {
    let path = choice_path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "could not read the saved feed");
            return None;
        }
    };
    let feed = Feed::from_slug(text.trim());
    if feed.is_none() {
        tracing::warn!(path = %path.display(), "the saved feed is not one this build knows; ignoring it");
    }
    feed
}

/// Save `feed` as this host's choice for every later run, by every atomdrift
/// tool.
///
/// # Errors
///
/// When there is no config directory, or it cannot be written.
pub fn save_choice(feed: Feed) -> anyhow::Result<PathBuf> {
    let path =
        choice_path().ok_or_else(|| anyhow::anyhow!("no config directory to save the feed in"))?;
    write_choice(&path, feed)?;
    Ok(path)
}

fn write_choice(path: &Path, feed: Feed) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("creating {}: {e}", dir.display()))?;
    }
    crate::cache::atomic_write(path, format!("{}\n", feed.slug()).as_bytes())
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))
}

/// The feeds, one per line, for `cleave feed`: which this run uses, how
/// delayed each is, and what is installed for it. Reads only the disk.
#[must_use]
pub fn list() -> String {
    use std::fmt::Write;
    let mut out = format!("  {:<13} {:<14} INSTALLED\n", "FEED", "DELAY");
    for feed in Feed::ALL {
        let mark = if feed == current() { '*' } else { ' ' };
        let installed = crate::rule_update::installed(&crate::traits_repo::installed_dir(feed))
            .map_or_else(
                || "—".to_string(),
                |i| {
                    format!(
                        "{}  {}",
                        i.commit.chars().take(7).collect::<String>(),
                        i.date
                    )
                },
            );
        let _ = writeln!(
            out,
            "{mark} {:<13} {:<14} {installed}",
            feed.slug(),
            feed.delay()
        );
    }
    let tool = tool();
    let _ = write!(out, "\nSwitch with `{tool} feed <name>`.");
    if matches!(token(), Ok(None)) {
        let _ = write!(
            out,
            " The zero-day and supporter feeds need a plan: {DASH_URL}plans"
        );
    }
    out.push('\n');
    out
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
    /// whitespace or control characters, or longer than any token dash mints,
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
    /// [`TOKEN_ENV`].
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

/// The token to use, if this host has one: [`TOKEN_ENV`], then the saved file.
///
/// # Errors
///
/// A saved file that others can read, or that cannot be read or parsed. Each is
/// a fault to fix rather than a token to quietly do without.
pub fn token() -> anyhow::Result<Option<(Token, Source)>> {
    if let Some(token) = std::env::var(TOKEN_ENV).ok().and_then(|v| Token::parse(&v)) {
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
        "set {TOKEN_ENV}, or run `{} feed zero-day` (or `supporter`) on a terminal to connect this computer. Plans are at {DASH_URL}plans",
        tool()
    )
}

/// The welcome: what connecting is for, and the link to approve.
fn welcome(link: &str) {
    use colored::Colorize;
    eprintln!(
        "\n⚛️  Connect this computer to your {} plan.\n\n   \
         Approve it in your browser:  {}\n",
        "isotope¹³".bold(),
        link.bold(),
    );
}

/// Whether `link` is a plain URL on dash: it is printed to the terminal and
/// handed to the platform's opener, so it must carry no spaces or controls.
fn is_dash_link(link: &str) -> bool {
    link.starts_with(DASH_URL) && link.bytes().all(|b| b.is_ascii_graphic())
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
                    let _ = write!(err, "\r\x1b[2K   {frame} {text}");
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
        eprintln!("   {line}");
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

/// What dash answers when a flow starts.
#[derive(Deserialize)]
struct DeviceStart {
    device_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

/// What dash answers to a poll: the token once approved, or a reason.
#[derive(Deserialize, Default)]
struct DevicePoll {
    token: Option<String>,
    error: Option<String>,
}

/// A token dash has just issued to this computer, and the progress line
/// still showing, for the caller to finish once the token is checked.
#[derive(Debug)]
pub struct Connected {
    /// The issued token, not yet checked against the rules channel.
    pub token: Token,
    /// The line still animating on the terminal.
    pub progress: Progress,
}

/// Connect this computer through dash's device flow: ask for a code, open
/// the browser on it, and wait for the customer to approve. The token that
/// comes back is a device's, not one of the org's listed API tokens.
///
/// `label` is what dash records the device as, and nothing more.
///
/// # Errors
///
/// No terminal to show the link on, dash unreachable, the code expiring
/// unapproved, or Ctrl-C.
pub fn connect(label: &str) -> anyhow::Result<Connected> {
    use std::time::{Duration, Instant};
    if !interactive() {
        return Err(anyhow::anyhow!(
            "this computer has no isotope13 token: {}",
            how_to_get_one()
        ));
    }
    let dash = Dash::new()?;
    let body = serde_json::json!({ "label": label }).to_string();
    let (status, text) = dash.post("device/code", &body)?;
    if status != 200 {
        return Err(anyhow::anyhow!(
            "{DASH_URL} could not start a connection (HTTP {status})"
        ));
    }
    let start: DeviceStart = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("{DASH_URL} answered oddly: {e}"))?;
    let expires = Duration::from_secs(start.expires_in.clamp(60, 3600));
    let interval = Duration::from_secs(start.interval.clamp(1, 60));
    let link = start
        .verification_uri_complete
        .unwrap_or(start.verification_uri);
    if !is_dash_link(&link) {
        return Err(anyhow::anyhow!(
            "{DASH_URL} sent an approval link that is not its own"
        ));
    }
    welcome(&link);
    open_browser(&link);
    let progress = Progress::start("Waiting for approval…");

    let poll = serde_json::json!({ "device_code": start.device_code }).to_string();
    let started = Instant::now();
    let mut failures = 0u32;
    loop {
        // Slept in slices so Ctrl-C is noticed within the second.
        for _ in 0..interval.as_secs() {
            if crate::cancellation::is_cancelled() {
                return Err(anyhow::anyhow!("connection cancelled"));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if started.elapsed() > expires {
            return Err(anyhow::anyhow!(
                "the code expired before it was approved; run again for a new one"
            ));
        }
        let (status, text) = match dash.post("device/token", &poll) {
            Ok(answer) => answer,
            // One dropped poll is not a verdict; a run of them is dash gone.
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
                    .ok_or_else(|| anyhow::anyhow!("dash issued a token that is not one"))?;
                tracing::info!(event = "feed.device", outcome = "connected", tid = %token.fingerprint());
                return Ok(Connected { token, progress });
            }
            (202, _) => {}
            (410, _) => {
                return Err(anyhow::anyhow!(
                    "the code expired or was already used; run again for a new one"
                ));
            }
            (status, _) => {
                let reason = answer.error.unwrap_or_default();
                return Err(anyhow::anyhow!(
                    "{DASH_URL} refused the connection (HTTP {status} {reason})"
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
        "supporter" => "Early Supporter".to_string(),
        "business" => "Business".to_string(),
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

/// How dash is reached: TLS only, no redirects, and a short deadline per call,
/// so a device code can go nowhere but dash.
///
/// A debug build honours `ISOTOPE13_DASH_URL`, so the flow can be run against
/// `node local.js`; a release build has no override.
struct Dash {
    base: String,
    http: reqwest::blocking::Client,
}

impl Dash {
    fn new() -> anyhow::Result<Self> {
        #[cfg(debug_assertions)]
        let local = std::env::var("ISOTOPE13_DASH_URL")
            .ok()
            .filter(|v| !v.is_empty());
        #[cfg(not(debug_assertions))]
        let local: Option<String> = None;
        let base = local.map_or_else(
            || DASH_URL.to_string(),
            |local| format!("{}/", local.trim_end_matches('/')),
        );
        let http = reqwest::blocking::Client::builder()
            .https_only(base == DASH_URL)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("cleave/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| anyhow::anyhow!("http client: {e}"))?;
        Ok(Self { base, http })
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
    fn only_plain_dash_links_are_opened() {
        assert!(is_dash_link(
            "https://dash.isotope13.io/device?code=AB-12&x=1"
        ));
        assert!(!is_dash_link("https://evil.example/device"));
        assert!(!is_dash_link("https://dash.isotope13.io/x\x1b[2J"));
        assert!(!is_dash_link("https://dash.isotope13.io/ calc.exe"));
    }

    #[test]
    fn feeds_are_named_and_ordered_best_first() {
        let slugs: Vec<_> = Feed::ALL.iter().map(|f| f.slug()).collect();
        assert_eq!(slugs, ["zero-day", "supporter", "oss-delayed"]);
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
        assert_eq!(Feed::ZeroDay.to_string(), "zero-day feed");
        assert_eq!(Feed::OssDelayed.to_string(), "opensource feed");
        assert!(Feed::ZeroDay.needs_token() && Feed::Supporter.needs_token());
        assert!(!Feed::OssDelayed.needs_token());
    }

    #[test]
    fn the_hint_names_the_feed_command_and_the_plans() {
        let hint = how_to_get_one();
        assert!(hint.contains(" feed zero-day`"), "{hint}");
        assert!(hint.contains(TOKEN_ENV), "{hint}");
        assert!(hint.contains("plans"), "{hint}");
        assert!(!hint.to_lowercase().contains("uplink"), "{hint}");
    }

    #[test]
    fn a_saved_choice_is_one_slug_per_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("atomdrift").join(CHOICE_FILE);
        write_choice(&path, Feed::Supporter).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "supporter\n");
        write_choice(&path, Feed::ZeroDay).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "zero-day\n");
    }

    #[test]
    fn a_plan_is_named_as_the_dashboard_names_it() {
        assert_eq!(plan_name("free"), "Community");
        assert_eq!(plan_name("supporter"), "Early Supporter");
        assert_eq!(plan_name("business"), "Business");
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
