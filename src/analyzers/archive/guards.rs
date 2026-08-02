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

/// Maximum number of files to extract
pub(crate) const MAX_FILE_COUNT: usize = 100_000;

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

/// Maximum length of a single path component (Linux NAME_MAX).
pub(crate) const MAX_PATH_COMPONENT_LEN: usize = 255;

/// Sanitize archive entry path to prevent path traversal attacks (zip slip).
///
/// Individual path components longer than 255 bytes are truncated to avoid
/// ENAMETOOLONG errors on extraction. The caller should separately check
/// `entry_name.len()` and record a [`HostileArchiveReason::ExcessiveEntryName`]
/// when appropriate.
pub(crate) fn sanitize_entry_path(entry_name: &str, dest_dir: &Path) -> Option<PathBuf> {
    let path = Path::new(entry_name);

    // Reject absolute paths
    if path.is_absolute() {
        return None;
    }

    // Build path component by component, rejecting dangerous ones
    let mut result = dest_dir.to_path_buf();
    for component in path.components() {
        match component {
            Component::Normal(c) => {
                let s = c.to_string_lossy();
                if s.len() > MAX_PATH_COMPONENT_LEN {
                    // Truncate on a char boundary to avoid splitting a multi-byte sequence.
                    let truncated = truncate_to_char_boundary(&s, MAX_PATH_COMPONENT_LEN);
                    result.push(truncated);
                } else {
                    result.push(c);
                }
            }
            Component::CurDir => {} // Skip "."
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                // Reject "..", drive prefixes, and root
                return None;
            }
        }
    }

    // Final check: ensure result is still under dest_dir
    if !result.starts_with(dest_dir) {
        return None;
    }

    Some(result)
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
