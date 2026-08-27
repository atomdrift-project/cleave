//! Archive extraction guards for bomb protection.
//!
//! This module provides safety mechanisms to prevent archive bomb attacks,
//! including excessive file counts, decompression bombs (zip bombs), and
//! path traversal attacks (zip slip).

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// =============================================================================
// Archive Bomb Protection Constants
// =============================================================================

/// Maximum size of a single decompressed file (20 GB). Raised from 1 GB to admit
/// members of full OS images (ISO/UDF, DMG, install.wim/squashfs), which the
/// os-image feed acquires as good-baseline corpora.
pub(crate) const MAX_FILE_SIZE: u64 = 20 * 1024 * 1024 * 1024;

/// Maximum total extraction size (20 GB). Raised from 7 GB for the same reason;
/// a multi-GB install ISO expands to roughly its own size.
pub(crate) const MAX_TOTAL_SIZE: u64 = 20 * 1024 * 1024 * 1024;

/// Maximum number of files to extract. Large application container images can
/// legitimately exceed 100,000 entries (Kibana 9.4 contains about 137,000), so
/// retain the anti-abuse guard with enough headroom for normal distributions.
pub(crate) const MAX_FILE_COUNT: usize = 350_000;

/// Maximum ZIP central directory entries. The zip crate allocates per-entry
/// during `ZipArchive::new()`, so a crafted ZIP claiming billions of entries
/// can OOM-abort the process before any guard runs. This cap is checked
/// immediately after `ZipArchive::new()` at every call site.
pub(crate) const MAX_ZIP_ENTRIES: usize = 200_000;

/// Maximum compression ratio before considering it suspicious (100:1)
pub(crate) const MAX_COMPRESSION_RATIO: u64 = 100;
/// Minimum expanded size before a high compression ratio is treated as a bomb.
///
/// This keeps the ratio heuristic focused on materially dangerous expansion
/// rather than compact single-stream fixtures that compress well but remain
/// under the normal per-file extraction cap.
pub(crate) const MIN_ZIP_BOMB_UNCOMPRESSED_SIZE: u64 = 256 * 1024 * 1024;

/// Maximum non-fatal extraction notes retained per archive.
///
/// A single corrupt container can fail on every one of its members, so the
/// note list is capped and the overflow summarized rather than letting a
/// 200,000-entry ZIP push 200,000 strings into the report.
pub(crate) const MAX_EXTRACTION_NOTES: usize = 32;

/// Per-member forensic metadata captured during extraction.
///
/// Fields are populated from the archive container format (tar headers, ZIP
/// central directory, etc.) at the point the entry is read. After extraction
/// completes, [`ExtractionGuard::take_member_metadata`] is drained and merged
/// into the corresponding [`crate::types::core::ArchiveEntry`] items by path.
///
/// `archive_path` is the entry name as recorded *inside* the archive — kept
/// pre-sanitization so the merge can key by the same string the analyzer
/// computes from the extracted directory walk (after sanitization round-trip).
#[derive(Debug, Clone, Default)]
pub(crate) struct ExtractedMemberMetadata {
    pub archive_path: String,
    pub compressed_size: Option<u64>,
    pub compression_method: Option<String>,
    pub mtime_unix: Option<i64>,
    pub mode_octal: Option<u32>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub uname: Option<String>,
    pub gname: Option<String>,
    pub entry_type: Option<String>,
    pub linkname: Option<String>,
    pub host_os: Option<String>,
}

/// Reasons an archive may be considered hostile
#[derive(Debug, Clone)]
pub(crate) enum HostileArchiveReason {
    /// A file path contains ".." components that would escape the extraction directory
    PathTraversal(String),
    /// The compression ratio exceeds the zip-bomb threshold
    ZipBomb {
        /// Compressed size in bytes
        compressed: u64,
        /// Uncompressed size in bytes
        uncompressed: u64,
    },
    /// Total number of archive members exceeds the limit
    ExcessiveFileCount(usize),
    /// Total uncompressed size of all members exceeds the limit
    ExcessiveTotalSize(u64),
    /// A single file's uncompressed size exceeds the per-file limit
    ExcessiveFileSize {
        /// Name of the oversized file
        file: String,
        /// Uncompressed size in bytes
        size: u64,
    },
    /// A symlink target points outside the extraction directory
    SymlinkEscape(String),
    /// An archive entry has an excessively long name
    ExcessiveEntryName {
        /// Length of the entry name in bytes
        len: usize,
        /// Truncated preview of the name
        preview: String,
    },
}

/// Tracks extraction limits and detects hostile patterns
#[derive(Debug)]
pub(crate) struct ExtractionGuard {
    total_bytes: AtomicU64,
    file_count: AtomicUsize,
    hostile_reasons: Mutex<Vec<HostileArchiveReason>>,
    member_metadata: Mutex<Vec<ExtractedMemberMetadata>>,
    /// Non-fatal extraction notes: a stream that ended mid-decode, a member
    /// that could not be read. Recorded so a partial extraction is visible in
    /// the report instead of passing for a complete one. Unlike
    /// [`HostileArchiveReason`] these never become findings — truncation is a
    /// collection artifact as often as it is an evasion attempt, and scoring it
    /// would move every partially-downloaded archive off benign.
    extraction_notes: Mutex<Vec<String>>,
    /// Count of notes beyond [`MAX_EXTRACTION_NOTES`], summarized on drain.
    dropped_notes: AtomicUsize,
    /// Per-request cancellation flag from the server. When set, extraction
    /// stops at the next entry boundary via `check_file_count()`.
    cancellation: Option<Arc<AtomicBool>>,
    /// Case-folded extraction paths already claimed by a member, so two members
    /// whose names differ only in case do not collapse into one file on a
    /// case-insensitive filesystem. See [`ExtractionGuard::claim_output_path`].
    claimed_paths: Mutex<std::collections::HashSet<String>>,
}

impl ExtractionGuard {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_cancellation(None)
    }

    /// Create a guard with a cancellation flag from the server.
    pub(crate) fn with_cancellation(flag: Option<Arc<AtomicBool>>) -> Self {
        Self {
            total_bytes: AtomicU64::new(0),
            file_count: AtomicUsize::new(0),
            hostile_reasons: Mutex::new(Vec::new()),
            member_metadata: Mutex::new(Vec::new()),
            extraction_notes: Mutex::new(Vec::new()),
            dropped_notes: AtomicUsize::new(0),
            cancellation: flag,
            claimed_paths: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Returns true if the server has signalled cancellation.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Acquire))
    }

    /// Returns a clone of the cancellation flag, if one was provided.
    pub(crate) fn cancellation(&self) -> Option<Arc<AtomicBool>> {
        self.cancellation.clone()
    }

    pub(crate) fn add_hostile_reason(&self, reason: HostileArchiveReason) {
        if let Ok(mut reasons) = self.hostile_reasons.lock() {
            reasons.push(reason);
        }
    }

    pub(crate) fn take_reasons(&self) -> Vec<HostileArchiveReason> {
        self.hostile_reasons
            .lock()
            .map(|mut r| std::mem::take(&mut *r))
            .unwrap_or_default()
    }

    /// Record a non-fatal extraction problem — a member skipped, a stream that
    /// ended early. The caller has already recovered; this only makes the gap
    /// visible in `report.metadata.errors`.
    pub(crate) fn add_extraction_note(&self, note: String) {
        if let Ok(mut notes) = self.extraction_notes.lock() {
            if notes.len() >= MAX_EXTRACTION_NOTES {
                self.dropped_notes.fetch_add(1, Ordering::Relaxed);
                return;
            }
            notes.push(note);
        }
    }

    /// Drain the extraction notes, appending a summary line when the cap
    /// dropped any.
    pub(crate) fn take_extraction_notes(&self) -> Vec<String> {
        let mut notes = self
            .extraction_notes
            .lock()
            .map(|mut n| std::mem::take(&mut *n))
            .unwrap_or_default();
        let dropped = self.dropped_notes.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            notes.push(format!("archive extraction: {dropped} further problems"));
        }
        notes
    }

    /// Record forensic metadata for an archive entry. Called from per-format
    /// extractors (tar, zip, …) when the entry header is read.
    pub(crate) fn record_member_metadata(&self, metadata: ExtractedMemberMetadata) {
        if let Ok(mut entries) = self.member_metadata.lock() {
            entries.push(metadata);
        }
    }

    /// Drain accumulated per-member metadata for merging into the final report.
    /// Reserve an extraction path for one member, renaming it if a previously
    /// extracted member already claimed the same name **case-insensitively**.
    ///
    /// Unix filesystems distinguish `evil.exe` from `EVIL.exe`; NTFS does not.
    /// Without this, the second member silently overwrites the first, and the
    /// first is never analyzed — so an archive can hide a payload behind a
    /// case-variant twin, and the same archive yields a different member count
    /// depending on which worker picked it up.
    ///
    /// Only ever call this for a *file*. Directories must keep their sanitized
    /// name: renaming one would orphan every member extracted beneath it, since
    /// their own paths are derived from the un-renamed parent. Two directories
    /// differing only in case simply merge, which loses nothing — every member
    /// still lands somewhere and still gets analyzed.
    ///
    /// The disambiguator goes before the extension (`evil.tar.gz` becomes
    /// `evil~2.tar.gz`) so file-type detection, which reads the extension, is
    /// unaffected.
    pub(crate) fn claim_output_path(&self, path: PathBuf) -> PathBuf {
        fn fold(path: &Path) -> String {
            path.to_string_lossy().to_lowercase()
        }

        let Ok(mut claimed) = self.claimed_paths.lock() else {
            // A poisoned lock must not stop extraction; the worst case is the
            // pre-existing overwrite behaviour.
            return path;
        };
        if claimed.insert(fold(&path)) {
            return path;
        }

        let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Split at the first `.` so multi-part extensions stay intact.
        let (stem, ext) = match name.find('.') {
            Some(idx) => (&name[..idx], &name[idx..]),
            None => (name.as_str(), ""),
        };

        for n in 2..=MAX_NAME_COLLISION_RETRIES {
            let candidate = parent.join(format!("{stem}~{n}{ext}"));
            if claimed.insert(fold(&candidate)) {
                return candidate;
            }
        }
        // Pathological: thousands of case-variants of one name. Fall back to the
        // original and accept the overwrite rather than fail the extraction.
        path
    }

    pub(crate) fn take_member_metadata(&self) -> Vec<ExtractedMemberMetadata> {
        self.member_metadata
            .lock()
            .map(|mut m| std::mem::take(&mut *m))
            .unwrap_or_default()
    }

    /// Check if we can extract another file, returns false if limits exceeded
    /// or the request has been cancelled.
    pub(crate) fn check_file_count(&self) -> bool {
        if self.is_cancelled() {
            return false;
        }
        let count = self.file_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count > MAX_FILE_COUNT {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveFileCount(count));
            return false;
        }
        true
    }

    /// Check and track bytes, returns false if limits exceeded
    pub(crate) fn check_bytes(&self, bytes: u64, file_name: &str) -> bool {
        // Check single file size
        if bytes > MAX_FILE_SIZE {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: file_name.to_string(),
                size: bytes,
            });
            return false;
        }

        // Check total size
        let total = self.total_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if total > MAX_TOTAL_SIZE {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveTotalSize(total));
            return false;
        }
        true
    }

    /// Check compression ratio for zip bomb detection
    pub(crate) fn check_compression_ratio(&self, compressed: u64, uncompressed: u64) -> bool {
        if compressed > 0
            && uncompressed / compressed > MAX_COMPRESSION_RATIO
            && uncompressed >= MIN_ZIP_BOMB_UNCOMPRESSED_SIZE
        {
            self.add_hostile_reason(HostileArchiveReason::ZipBomb {
                compressed,
                uncompressed,
            });
            return false;
        }
        true
    }
}

/// How many `~N` suffixes to try before giving up on disambiguating a
/// case-insensitive name collision. Far above any real archive; a backstop
/// against a crafted one shipping thousands of case-variants of one name.
const MAX_NAME_COLLISION_RETRIES: u32 = 1000;

/// Maximum length of a single path component (Linux NAME_MAX).
pub(crate) const MAX_PATH_COMPONENT_LEN: usize = 255;

/// The Windows path separator. Spelled by codepoint because it appears in
/// character lists below, where an escaped literal reads worse than a name.
const BACKSLASH: char = 0x5C_u8 as char;

/// Characters that cannot appear in a Windows filename, plus both path
/// separators and `%` itself.
///
/// `%` is escaped so the mapping stays injective: without it `a%3Ab` and `a:b`
/// would both extract to `a%3Ab`, and a hostile archive could mask one member by
/// shipping another whose name collides with its escaped form.
///
/// Neither separator survives [`split_entry_segments`], which treats both as
/// separators; they are listed so the escape is total over the character set.
const WINDOWS_FORBIDDEN: &[char] = &['<', '>', ':', '"', '|', '?', '*', BACKSLASH, '/', '%'];

/// Device names Windows resolves ahead of any file of the same name, matched
/// case-insensitively against the segment's stem (the part before the first
/// `.`), so `nul`, `NUL.txt` and `com1.tar.gz` all match.
///
/// Writing to one of these silently succeeds and goes to the device, so an
/// unescaped member named `nul.exe` is discarded rather than analyzed — a
/// payload that never reaches a rule. Which names a given Windows build
/// intercepts varies (Windows 11 26200 was measured to take `nul` but create
/// real files for `con` and `com1`, while older builds take all of them), so the
/// whole documented set is escaped regardless of host.
const WINDOWS_RESERVED_STEMS: &[&str] = &[
    "con", "prn", "aux", "nul", "conin$", "conout$", "com0", "com1", "com2", "com3", "com4",
    "com5", "com6", "com7", "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6",
    "lpt7", "lpt8", "lpt9",
];

/// Percent-escape one character as `%XX` (uppercase hex), per UTF-8 byte.
fn push_escaped(out: &mut String, ch: char) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut buf = [0u8; 4];
    for byte in ch.encode_utf8(&mut buf).as_bytes() {
        out.push('%');
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0F)] as char);
    }
}

/// Split an archive entry name into segments, treating both path separators as
/// separators on every platform.
///
/// Deliberately not `Path::components()`: that parses by host convention, so a
/// tar member whose name literally contains a backslash is one segment on unix
/// and two on Windows. The same archive would then yield different member names
/// depending on which worker picked it up, and a fleet mixing both cannot key a
/// shared corpus.
fn split_entry_segments(entry_name: &str) -> Vec<&str> {
    entry_name
        .split(['/', BACKSLASH])
        .filter(|seg| !seg.is_empty() && *seg != ".")
        .collect()
}

/// True when `entry_name` is anchored outside the destination — a unix absolute
/// path, a drive-rooted Windows path, or a UNC share.
///
/// A drive is only treated as anchoring when a separator follows it (`C:/x`,
/// `C:` + backslash + `x`). Bare `C:x` is drive-*relative*, and so is any
/// single-letter name containing a colon — `a:b` is an ordinary filename in the
/// unix archives this reads, and Windows would resolve it against drive A:.
/// Rejecting those would skip the member outright, which is precisely the
/// evasion this module exists to close, so they fall through to
/// [`escape_segment`] and have the colon escaped instead. That is strictly
/// safer than rejecting: the escaped name is an ordinary relative one, and the
/// member still reaches a rule.
fn is_anchored(entry_name: &str) -> bool {
    if entry_name.starts_with('/') || entry_name.starts_with(BACKSLASH) {
        return true;
    }
    // Drive-rooted: one alphabetic character, a colon, then a separator.
    let mut chars = entry_name.chars();
    matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(c), Some(':'), Some(sep))
            if c.is_ascii_alphabetic() && (sep == '/' || sep == BACKSLASH)
    )
}

/// Make one path segment safe to create as a file on any host, injectively.
///
/// Escaping rather than rejecting is deliberate: this code exists to analyze
/// hostile archives, and a member skipped for its name is a member whose bytes
/// no rule ever sees. Renaming keeps the content in the pipeline.
///
/// Injective because every transformation is a percent-escape and `%` is itself
/// escaped, so distinct inputs stay distinct — two members cannot be made to
/// collide, and the original name is recoverable from the escaped one.
fn escape_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for ch in segment.chars() {
        // Control characters are rejected by Windows and awkward everywhere;
        // 0x7F (DEL) with them.
        if WINDOWS_FORBIDDEN.contains(&ch) || (ch as u32) < 0x20 || ch as u32 == 0x7F {
            push_escaped(&mut out, ch);
        } else {
            out.push(ch);
        }
    }

    // Windows silently strips trailing dots and spaces, so `report.` and
    // `report` become the same file. Escape the trailing run instead of letting
    // the filesystem drop it, which would lose the distinction and let one
    // member overwrite another.
    let trimmed_len = out.trim_end_matches(['.', ' ']).len();
    if trimmed_len < out.len() {
        let tail = out.split_off(trimmed_len);
        for ch in tail.chars() {
            push_escaped(&mut out, ch);
        }
    }

    // Reserved device names are matched on the stem, so escaping any one
    // character of it is enough to make the name ordinary. The first character
    // is escaped rather than a suffix appended: appending is not injective, as a
    // real member named `nul_` would collide with an escaped `nul`.
    let stem = out.split('.').next().unwrap_or("");
    if WINDOWS_RESERVED_STEMS
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
        && let Some(first) = out.chars().next()
    {
        let mut escaped = String::with_capacity(out.len() + 2);
        push_escaped(&mut escaped, first);
        escaped.push_str(&out[first.len_utf8()..]);
        out = escaped;
    }

    out
}

/// Truncate an escaped segment to [`MAX_PATH_COMPONENT_LEN`] bytes without
/// splitting a UTF-8 character or leaving a half-written `%XX` escape.
fn truncate_segment(segment: &str) -> &str {
    if segment.len() <= MAX_PATH_COMPONENT_LEN {
        return segment;
    }
    let mut end = truncate_to_char_boundary(segment, MAX_PATH_COMPONENT_LEN).len();
    // Back off a dangling `%` or `%X` so the result stays decodable.
    let bytes = segment.as_bytes();
    for back in 1..=2 {
        if end >= back && bytes[end - back] == b'%' {
            end -= back;
            break;
        }
    }
    &segment[..end]
}

/// Sanitize an archive entry path into a destination path, or `None` when the
/// entry cannot be represented safely at all.
///
/// Two different jobs, deliberately kept apart:
///
/// - **Traversal is rejected.** `..`, absolute paths, drive letters and UNC
///   roots return `None`; there is no safe interpretation of an entry trying to
///   leave the extraction directory, and the caller records it as hostile.
/// - **Unrepresentable names are escaped, not rejected.** A member Windows
///   cannot name — a colon (which would silently become an NTFS alternate data
///   stream), a reserved device name (which the device would swallow), a
///   trailing dot (which Windows strips) — is percent-escaped so it still lands
///   on disk and still gets analyzed. Skipping it would hand hostile archives a
///   trivial way to hide a payload from every rule.
///
/// The escaping applies on every platform, not only Windows, so the same archive
/// yields the same member names on every worker in a mixed fleet.
///
/// Segments longer than [`MAX_PATH_COMPONENT_LEN`] are truncated to avoid
/// `ENAMETOOLONG`. The caller should separately check `entry_name.len()` and
/// record a [`HostileArchiveReason::ExcessiveEntryName`] when appropriate.
pub(crate) fn sanitize_entry_path(entry_name: &str, dest_dir: &Path) -> Option<PathBuf> {
    let relative = escaped_relative_path(entry_name)?;
    let mut result = dest_dir.to_path_buf();
    for segment in relative.split('/') {
        result.push(segment);
    }
    // Belt and braces: nothing above can escape, but the check is cheap and this
    // is the last line before a write.
    if !result.starts_with(dest_dir) {
        return None;
    }
    Some(result)
}

/// The relative path [`sanitize_entry_path`] would produce for `entry_name`, as
/// a `/`-joined string, or `None` for an entry it would reject.
///
/// Shared with the member-metadata merge, which is keyed by the name recorded
/// *inside* the archive while the report's entries come from walking the
/// extracted tree — the two differ exactly when a name had to be escaped.
pub(crate) fn escaped_relative_path(entry_name: &str) -> Option<String> {
    if is_anchored(entry_name) {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for segment in split_entry_segments(entry_name) {
        if segment == ".." {
            return None;
        }
        let escaped = escape_segment(segment);
        // `escape_segment` only grows a non-empty segment, and empty segments
        // were filtered out by the split, so this is unreachable in practice.
        if escaped.is_empty() {
            return None;
        }
        parts.push(truncate_segment(&escaped).to_string());
    }
    // `.`, `""` and `./.` all reduce to nothing. Returning `dest_dir` from
    // `sanitize_entry_path` would hand the caller the extraction root to create
    // as a *file*, so refuse instead.
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("/"))
}

/// Truncate `s` to at most `max_bytes` without splitting a UTF-8 character.
fn truncate_to_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Check if a symlink target would escape the extraction directory
///
/// Returns true if the symlink target points outside dest_dir when resolved
/// from the symlink's location.
pub(crate) fn symlink_escapes(symlink_path: &Path, target: &str, dest_dir: &Path) -> bool {
    let target_path = Path::new(target);
    let symlink_str = symlink_path.to_string_lossy();
    let symlink_name = symlink_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();

    if target_path.is_absolute()
        && (target == "/usr/bin/python3" || target == "/usr/bin/python")
        && (symlink_str.contains("/node_gyp_bins/python")
            || symlink_name == "python3"
            || symlink_name == "python")
    {
        return false;
    }

    // Absolute targets always escape
    if target_path.is_absolute() {
        return true;
    }

    // Resolve target relative to symlink's parent directory
    let symlink_parent = symlink_path.parent().unwrap_or(dest_dir);
    let mut resolved = symlink_parent.to_path_buf();

    // Walk through target components, handling .. and .
    for component in target_path.components() {
        match component {
            Component::Normal(c) => resolved.push(c),
            Component::CurDir => {} // "." doesn't change path
            Component::ParentDir => {
                // ".." moves up one level
                resolved.pop();
            }
            Component::Prefix(_) | Component::RootDir => {
                // These make it absolute, which escapes
                return true;
            }
        }
    }

    // Check if resolved path is still under dest_dir
    // We need to canonicalize the comparison to handle . and .. properly
    !resolved.starts_with(dest_dir)
}

/// Size-limited reader that stops after a maximum number of bytes.
///
/// When the limit is reached, `read` returns `Ok(0)` (EOF) rather than an
/// error, which correctly satisfies the [`Read`] contract and lets callers
/// like `read_to_end` / `copy` terminate normally. Use [`is_limited`] after
/// the read to distinguish a genuine end-of-stream from a limit hit.
///
/// [`is_limited`]: LimitedReader::is_limited
pub(crate) struct LimitedReader<R> {
    inner: R,
    remaining: u64,
    limit_hit: bool,
}

impl<R: Read> LimitedReader<R> {
    pub(crate) fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
            limit_hit: false,
        }
    }

    /// Returns `true` if the byte limit was reached before the underlying
    /// stream was exhausted — i.e., the data was silently truncated.
    pub(crate) fn is_limited(&self) -> bool {
        self.limit_hit
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            self.limit_hit = true;
            return Ok(0);
        }
        let max_read = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..max_read])?;
        self.remaining = self.remaining.saturating_sub(n as u64);
        Ok(n)
    }
}

/// A `Read` adapter that checks a cancellation flag on every call.
///
/// Wrapping a decompressor or other streaming reader with `CancellableReader`
/// ensures that long-running I/O (e.g. decompressing a large archive entry)
/// is interrupted promptly when the per-request cancellation flag is set,
/// rather than running until the underlying stream is exhausted.
pub(crate) struct CancellableReader<R> {
    inner: R,
    cancelled: Arc<AtomicBool>,
}

impl<R> CancellableReader<R> {
    pub(crate) fn new(inner: R, cancelled: Arc<AtomicBool>) -> Self {
        Self { inner, cancelled }
    }
}

impl<R: Read> Read for CancellableReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        self.inner.read(buf)
    }
}

/// A `Write` adapter that checks a cancellation flag on every call.
///
/// Wrapping an output file with `CancellableWriter` lets extraction routines
/// that delegate all I/O to a C library (e.g. apple_xar) be interrupted
/// cooperatively: the C library calls `write()`, which fails with
/// `ErrorKind::Interrupted` when the flag is set, causing the library to
/// return an error that propagates back through the extractor.
pub(crate) struct CancellableWriter<W: Write> {
    inner: W,
    cancelled: Arc<AtomicBool>,
}

impl<W: Write> CancellableWriter<W> {
    pub(crate) fn new(inner: W, cancelled: Arc<AtomicBool>) -> Self {
        Self { inner, cancelled }
    }
}

impl<W: Write> Write for CancellableWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
