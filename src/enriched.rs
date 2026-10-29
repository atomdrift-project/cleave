//! isotope13 Enriched: the subscription token, and the switch it throws.
//!
//! A token — `ISOTOPE13_TOKEN`, else the one saved in
//! `<config>/atomdrift/isotope13-api.json` — selects the fresh ruleset in
//! `traits-enriched/`, and in scan, remote verdicts. Once a computer is
//! connected it stays connected: the token is used for every refresh until
//! the rules Worker refuses it, and only then does a run fall back to the
//! open-source rules, saying so. `--enriched` (or `ATOMDRIFT_ENRICHED=1`)
//! adds insistence: with no token it connects this computer — on a terminal,
//! through [`crate::rule_update::sign_in`], with a code approved at
//! <https://dash.isotope13.io/device> — and a refusal is an error rather than
//! a fall back. `ATOMDRIFT_ENRICHED=0` keeps the open-source rules whatever
//! the host holds.
//!
//! The token is opaque here. Whether it is valid, and what it is entitled to,
//! is the server's to say, so the saved file holds the token and nothing that
//! could go stale beside it. It travels only to isotope13's own hosts, in an
//! `Authorization` header, and never into a log: logs carry its
//! [`Token::fingerprint`], the same one Beamline and dash show.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Environment variable holding a token. Checked before the saved file; how CI
/// supplies one with no file and no prompt.
pub const TOKEN_ENV: &str = "ISOTOPE13_TOKEN";
/// Environment equivalent of `--enriched`.
pub const ENABLE_ENV: &str = "ATOMDRIFT_ENRICHED";
/// Where a customer mints a token.
pub const DASH_URL: &str = "https://dash.isotope13.io/";
/// The saved token, under `<config>/atomdrift/`. Shared by every atomdrift tool.
const TOKEN_FILE: &str = "isotope13-api.json";
/// Longer than any token dash mints, short enough that a stray paste of a
/// whole document is refused rather than sent.
const MAX_TOKEN_LEN: usize = 256;

static ENABLED: AtomicBool = AtomicBool::new(false);
static REQUIRED: AtomicBool = AtomicBool::new(false);

/// Turn enriched mode on or off for this process.
///
/// The default traits directory follows this switch, so the capability mapper
/// and traits fingerprint built from the other one are dropped, exactly as
/// [`crate::traits_repo::set_override_dir`] does. Calling it before the first
/// analysis costs nothing.
pub fn set_enabled(on: bool) {
    if ENABLED.swap(on, Ordering::Relaxed) != on {
        crate::shared_resources::invalidate_capability_mapper();
        crate::cache::invalidate_traits_scan();
    }
}

/// Whether this run uses the Enriched rules: decided by [`resolve`], and
/// withdrawn by [`fall_back`].
#[must_use]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Whether `--enriched` insisted: no token connects this computer, and a
/// refusal is an error rather than a fall back to the open-source rules.
#[must_use]
pub fn required() -> bool {
    REQUIRED.load(Ordering::Relaxed)
}

/// Decide this run's rules from what the host holds. Called once, before
/// anything resolves a traits directory.
///
/// A held token means Enriched. `required` — `--enriched`, or
/// [`ENABLE_ENV`] set to `1` — means Enriched too, with the token asked for
/// by [`crate::rule_update::sign_in`] when there is none. [`ENABLE_ENV`] set
/// to `0` means the open-source rules, whatever is held.
///
/// # Errors
///
/// A saved token file that others can read, or that cannot be read or
/// parsed: a fault to fix rather than a token to quietly do without.
pub fn resolve(required: bool) -> Result<(), String> {
    let switch = env_switch(std::env::var(ENABLE_ENV).ok().as_deref());
    let required = required || switch == Some(true);
    REQUIRED.store(required, Ordering::Relaxed);
    // Opted out, and the flag did not overrule it: whatever is held stays unused.
    let opted_out = switch == Some(false) && !required;
    let held = if opted_out { None } else { token()? };
    let on = held.is_some() || required;
    set_enabled(on);
    tracing::info!(
        event = "enriched.mode",
        enabled = on,
        required,
        token = held.map_or("none", |(_, source)| source.as_str())
    );
    Ok(())
}

/// Leave the Enriched channel for the rest of this run, because it could not
/// be had and `--enriched` did not insist: the open-source rules are used
/// from here on, and the one warning says why.
///
/// A traits override pinned to the Enriched tree (scan pins the installed
/// tree so a checkout in the working directory cannot supply the rules)
/// follows, or the open-source rules would never be resolved.
pub fn fall_back(why: &str) {
    tracing::warn!(
        event = "enriched.fallback",
        reason = %why,
        "isotope13 Enriched unavailable; using the open-source rules"
    );
    set_enabled(false);
    if crate::traits_repo::override_dir()
        .is_some_and(|dir| dir == crate::traits_repo::installed_dir(true))
    {
        crate::traits_repo::set_override_dir(Some(crate::traits_repo::installed_dir(false)));
    }
}

/// What [`ENABLE_ENV`] says: on, off, or nothing.
fn env_switch(value: Option<&str>) -> Option<bool> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
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

    /// The first 16 hex characters of the token's SHA-256: how Beamline, the
    /// rules Worker, and dash name a token without holding it.
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
pub fn token() -> Result<Option<(Token, Source)>, String> {
    if let Some(token) = std::env::var(TOKEN_ENV).ok().and_then(|v| Token::parse(&v)) {
        return Ok(Some((token, Source::Env)));
    }
    let Some(path) = token_path() else {
        return Ok(None);
    };
    Ok(read_token_file(&path)?.map(|token| (token, Source::File)))
}

fn read_token_file(path: &Path) -> Result<Option<Token>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    check_private(path)?;
    let file: TokenFile =
        serde_json::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    Token::parse(&file.token)
        .map(Some)
        .ok_or_else(|| format!("{} holds no usable token", path.display()))
}

/// Refuse a token file anyone but its owner can read or write, as ssh refuses
/// a private key: a token another account can read is a token to revoke.
#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} is accessible to other users (mode {:o}); run: chmod 600 '{}'",
            path.display(),
            mode & 0o777,
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), String> {
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
pub fn save(token: &Token) -> Result<PathBuf, String> {
    let path = token_path().ok_or("no config directory to save the token in")?;
    write_token_file(&path, token)?;
    Ok(path)
}

fn write_token_file(path: &Path, token: &Token) -> Result<(), String> {
    use std::io::Write;
    let dir = path.parent().ok_or("token path has no parent")?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;

    let staging = path.with_extension("json.tmp");
    drop(std::fs::remove_file(&staging));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let body = serde_json::to_string(&TokenFile {
        token: token.secret().to_string(),
    })
    .map_err(|e| format!("rendering token file: {e}"))?;
    let written = options.open(&staging).and_then(|mut file| {
        file.write_all(body.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()
    });
    if let Err(e) = written.and_then(|()| std::fs::rename(&staging, path)) {
        drop(std::fs::remove_file(&staging));
        return Err(format!("writing {}: {e}", path.display()));
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
        "set {TOKEN_ENV}, or run with --enriched on a terminal to connect this computer (hood: `hood enrich`). Plans are at {DASH_URL}"
    )
}

/// "isotope¹³ Enriched" in its colours: the one way the product is named on
/// a terminal, from the welcome to every tool's `version`.
#[must_use]
pub fn brand() -> String {
    use colored::Colorize;
    format!(
        "{} {}",
        "isotope¹³".truecolor(255, 0, 204).bold(),
        "Enriched".truecolor(0, 158, 142).bold()
    )
}

/// The welcome: one line on what Enriched is, and the link to approve.
fn welcome(link: &str) {
    use colored::Colorize;
    eprintln!(
        "\n⚛️  {} — the latest atomdrift rules, the moment they clear QA.\n\n   \
         Approve this computer in your browser:  {}\n",
        brand(),
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
    let Some(path) = filefacts::tools::resolve(opener) else {
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
pub fn connect(label: &str) -> Result<Connected, String> {
    use std::time::{Duration, Instant};
    if !interactive() {
        return Err(format!(
            "isotope13 Enriched needs a token: {}",
            how_to_get_one()
        ));
    }
    let dash = Dash::new()?;
    let body = serde_json::json!({ "label": label }).to_string();
    let (status, text) = dash.post("device/code", &body)?;
    if status != 200 {
        return Err(format!(
            "{DASH_URL} could not start a connection (HTTP {status})"
        ));
    }
    let start: DeviceStart =
        serde_json::from_str(&text).map_err(|e| format!("{DASH_URL} answered oddly: {e}"))?;
    let expires = Duration::from_secs(start.expires_in.clamp(60, 3600));
    let interval = Duration::from_secs(start.interval.clamp(1, 60));
    let link = start
        .verification_uri_complete
        .unwrap_or(start.verification_uri);
    if !is_dash_link(&link) {
        return Err(format!(
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
                return Err("connection cancelled".to_string());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if started.elapsed() > expires {
            return Err(
                "the code expired before it was approved; run again for a new one".to_string(),
            );
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
                let token = Token::parse(&token).ok_or("dash issued a token that is not one")?;
                tracing::info!(event = "enriched.device", outcome = "connected", tid = %token.fingerprint());
                return Ok(Connected { token, progress });
            }
            (202, _) => {}
            (410, _) => {
                return Err(
                    "the code expired or was already used; run again for a new one".to_string(),
                );
            }
            (status, _) => {
                let reason = answer.error.unwrap_or_default();
                return Err(format!(
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
    fn new() -> Result<Self, String> {
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
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self { base, http })
    }

    fn post(&self, path: &str, json: &str) -> Result<(u16, String), String> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .body(json.to_string())
            .send()
            .map_err(|e| format!("POST {url}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| format!("reading {url}: {e}"))?;
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
    fn the_env_switch_is_on_off_or_absent() {
        for on in ["1", "true", " YES ", "on"] {
            assert_eq!(env_switch(Some(on)), Some(true), "{on:?}");
        }
        for off in ["0", "false", "No", "off"] {
            assert_eq!(env_switch(Some(off)), Some(false), "{off:?}");
        }
        for unset in [None, Some(""), Some("maybe")] {
            assert_eq!(env_switch(unset), None, "{unset:?}");
        }
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
        assert!(read_token_file(&path).unwrap_err().contains("parsing"));

        std::fs::write(&path, r#"{"token":"  "}"#).unwrap();
        assert!(
            read_token_file(&path)
                .unwrap_err()
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
            assert!(err.contains("chmod 600"), "mode {mode:o}: {err}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_token_file(&path).unwrap().is_some());
    }
}
