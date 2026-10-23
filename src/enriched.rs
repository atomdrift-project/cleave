//! isotope13 Enriched: the subscription token, and the switch that requires it.
//!
//! `--enriched` (or `ATOMDRIFT_ENRICHED=1`) selects the fresh ruleset in
//! `traits-enriched/`, and in scan, remote verdicts. It requires a token:
//! `ISOTOPE13_TOKEN`, else the one saved in `<config>/atomdrift/isotope13-api.json`,
//! else — on a terminal — one pasted from <https://dash.isotope13.io/>. Holding a
//! token never turns enriched on by itself.
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

/// Turn enriched mode on or off for this process (`--enriched`).
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

/// Whether enriched mode was asked for, by [`set_enabled`] or [`ENABLE_ENV`].
#[must_use]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
        || std::env::var(ENABLE_ENV)
            .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
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
    /// Pasted at the prompt just now, and not saved until it is accepted.
    Prompt,
}

impl Source {
    /// The name structured logs use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Env => "env",
            Source::File => "file",
            Source::Prompt => "prompt",
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

/// Ask for a token on the terminal, without echoing it.
///
/// `why` opens the prompt, and is the whole error when there is no terminal to
/// ask on: a CI job is told what to set rather than left waiting on stdin.
///
/// # Errors
///
/// No terminal, a read failure, or nothing usable entered.
pub fn prompt(why: &str) -> Result<Token, String> {
    use std::io::IsTerminal;
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        return Err(format!(
            "{why}: set {TOKEN_ENV}, or run once in a terminal to paste one from {DASH_URL}"
        ));
    }
    eprint!("{why}. Create a token at {DASH_URL} and paste it here.\ntoken: ");
    let line = read_hidden_line().map_err(|e| format!("reading token: {e}"))?;
    Token::parse(&line).ok_or_else(|| "no token entered".to_string())
}

/// Read one line from the terminal with echo off, restoring it however the
/// read ends. `ECHONL` keeps the newline, so the cursor still moves on.
#[cfg(unix)]
fn read_hidden_line() -> io::Result<String> {
    use std::os::fd::AsRawFd;

    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: `self.1` is the state `tcgetattr` reported for this fd.
            unsafe { libc::tcsetattr(self.0, libc::TCSANOW, &self.1) };
        }
    }

    let fd = io::stdin().as_raw_fd();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: `fd` is stdin, checked to be a terminal; tcgetattr fills the
    // struct on success, and it is read only then.
    if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: initialized by the successful tcgetattr above.
    let original = unsafe { original.assume_init() };
    let mut quiet = original;
    quiet.c_lflag &= !libc::ECHO;
    quiet.c_lflag |= libc::ECHONL;
    // SAFETY: `quiet` is a valid termios derived from the terminal's own.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _restore = Restore(fd, original);
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line)
}

/// Windows consoles echo the paste; the one platform where that is accepted.
#[cfg(not(unix))]
fn read_hidden_line() -> io::Result<String> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
