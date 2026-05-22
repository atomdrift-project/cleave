//! Go buildinfo extractor (cross-format: PE / ELF / Mach-O / raw).
//!
//! Go binaries embed a self-describing structure at module-init time
//! containing the compiler version, main module path, dependency
//! list, and build settings (-ldflags, GOOS, GOARCH, vcs.revision,
//! …). cleave's analyzer reads this byte-pattern directly without
//! parsing the surrounding format, so the same code works whether
//! the binary is `.elf`, `.exe`, or `.dylib`.
//!
//! # Format reference
//!
//! `runtime/debug.ReadBuildInfo` (Go 1.18+) embeds a 32-byte aligned
//! header followed by varint-prefixed strings:
//!
//! ```text
//! Offset  Bytes  Contents
//! 0x00    14     "\xff Go buildinf:"
//! 0x0E    1      ptr_size (4 or 8)
//! 0x0F    1      flags  (bit 1 = varint format, present since 1.18)
//! 0x10    16     reserved (zero-padded)
//! 0x20    var    <varint length> <utf8 version>          e.g. "go1.21.0"
//! 0x20+N  var    <varint length> <modinfo blob>
//! ```
//!
//! The modinfo blob is wrapped in two 16-byte sentinels (the leading
//! `\x30\x77\xaf\x0c\x92\x74\x08\x02...` and trailing
//! `\xf9\x32\x43\x1c\x35\x9c\xb6\x07...`) and contains tab-separated
//! `key\tvalue` records, one per line:
//!
//! ```text
//! path<TAB>github.com/attacker/sample
//! mod<TAB>github.com/attacker/sample<TAB>(devel)<TAB>
//! dep<TAB>golang.org/x/sys<TAB>v0.0.0-20220715151400-c0bba94af5f8<TAB>h1:...
//! build<TAB>-buildmode=exe
//! build<TAB>-compiler=gc
//! build<TAB>CGO_ENABLED=0
//! build<TAB>GOOS=linux
//! build<TAB>GOARCH=amd64
//! build<TAB>vcs=git
//! build<TAB>vcs.revision=<sha>
//! build<TAB>vcs.time=2024-01-15T10:30:00Z
//! build<TAB>vcs.modified=true
//! ```
//!
//! We extract these into a `GoBuildInfo` struct that the analyzer
//! integration layer maps onto the `go.*` kv tree per the schema in
//! filefacts's `go.*` namespace.

use std::collections::BTreeMap;

/// Parsed Go buildinfo. Each field is empty/None when not recoverable.
#[derive(Debug, Clone, Default)]
pub(crate) struct GoBuildInfo {
    /// Go version string (e.g. `"go1.21.0"`).
    pub version: String,
    /// `path` line — main module / package path.
    pub main_path: String,
    /// `mod` line — main module's own version + sum.
    pub main_module: Option<GoModuleRef>,
    /// `dep` lines — every transitive module dependency the binary
    /// was linked against, in order.
    pub dependencies: Vec<GoModuleRef>,
    /// `build` lines — flags + environment values used at compile
    /// time.  Keys preserved verbatim from the buildinfo (e.g.
    /// `-buildmode`, `-compiler`, `GOOS`, `vcs.revision`, `-ldflags`).
    pub build_settings: BTreeMap<String, String>,
    /// Go's per-build content-derived ID hash from
    /// `.note.go.buildid` (or its Mach-O / PE equivalent). Distinct
    /// from `vcs.revision` (the git commit) and from GNU build-id
    /// (the linker's content hash). Format is the raw action-id /
    /// content-id pair the Go linker emits, e.g. `"abc.../def..."`.
    pub build_id: Option<String>,
    /// GoRoot at compile time — the Go installation path on the
    /// builder host. Strong attribution leak: distinguishes Homebrew
    /// (`/opt/homebrew/Cellar/go/...`, `/usr/local/Cellar/go/...`),
    /// stock install (`/usr/local/go`), distro packages
    /// (`/builddir/build/.../golang-...`, `/build/golang-...`), and
    /// custom dev installs.
    pub go_root: Option<String>,
    /// Developer's local source-tree root, recovered from non-GoRoot
    /// non-module-cache paths in the pclntab. Empty when the binary
    /// was built with `-trimpath` (which itself is a useful signal).
    /// Leaks the developer's working directory — strong attribution.
    pub main_root: Option<String>,
    /// Per-package count of standard-library dependencies (path has
    /// no dot in its first segment, e.g. `fmt`, `crypto/sha256`).
    pub deps_std: u32,
    /// Per-package count of replaced (`=>` form) dependencies.
    pub deps_replaced: u32,
    /// Per-package count of vendored dependencies (heuristic: path
    /// contains `/vendor/`).
    pub deps_vendored: u32,
    /// Per-package count of third-party module dependencies (any
    /// dep that isn't std/replaced/vendored).
    pub deps_thirdparty: u32,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GoModuleRef {
    pub path: String,
    pub version: String,
    pub sum: String,
    /// `=> replaced_path` form when the module was replaced via
    /// `replace` directive in go.mod.
    pub replaced_by: Option<Box<GoModuleRef>>,
}

/// Magic bytes that prefix the Go buildinfo header. 14 bytes.
const MAGIC: &[u8] = b"\xff Go buildinf:";

/// Maximum buildinfo blob bytes to consume after the header.  Real
/// binaries cluster well under 32KB; this caps adversarial inputs
/// that might claim huge varint lengths.
const MAX_BUILDINFO_BYTES: usize = 64 * 1024;

/// Extract Go buildinfo from raw binary bytes. Returns `None` for
/// non-Go binaries or when the header is missing/malformed.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<GoBuildInfo> {
    let (buf, pos) = find_magic(data)?;
    if pos + 0x20 > buf.len() {
        return None;
    }
    let ptr_size = buf[pos + 0x0E];
    let flags = buf[pos + 0x0F];

    // Modern (Go 1.18+) varint format: flags & 2 == 2.  We don't
    // bother with the old pointer-based format — Go 1.17 has been
    // unsupported for years and the old format requires resolving
    // pointers through the binary's load layout.
    if flags & 0x02 == 0 {
        return None;
    }
    if !matches!(ptr_size, 4 | 8) {
        return None;
    }

    let body_start = pos + 0x20;
    let body_end = (body_start + MAX_BUILDINFO_BYTES).min(buf.len());
    let body = &buf[body_start..body_end];

    let mut cursor = 0usize;
    // The version field is always UTF-8.
    let version = read_varint_string(body, &mut cursor)?;
    // The modinfo blob carries non-UTF-8 sentinel bytes around the
    // text payload — keep it raw through sentinel stripping so the
    // sentinels survive the comparison, then convert lossily for
    // the line walker.
    let modinfo_bytes = read_varint_bytes(body, &mut cursor)?;
    let trimmed = strip_sentinels(modinfo_bytes);
    let modinfo = String::from_utf8_lossy(trimmed);

    let mut info = GoBuildInfo {
        version,
        ..Default::default()
    };

    for line in modinfo.split('\n') {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, '\t');
        let key = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("");
        match key {
            "path" => info.main_path = rest.to_string(),
            "mod" => {
                if let Some(m) = parse_module_ref(rest) {
                    info.main_module = Some(m);
                }
            }
            "dep" => {
                if let Some(m) = parse_module_ref(rest) {
                    info.dependencies.push(m);
                }
            }
            "=>" => {
                // Replacement of the most-recently-seen dep.
                if let Some(replacement) = parse_module_ref(rest) {
                    if let Some(last) = info.dependencies.last_mut() {
                        last.replaced_by = Some(Box::new(replacement));
                    }
                }
            }
            "build" => {
                // `build` lines are `key=value` (split once); some
                // older Go versions emit just `flag value` without
                // an `=` sign — handle both.
                let (k, v) = match rest.split_once('=') {
                    Some((k, v)) => (k.to_string(), v.to_string()),
                    None => match rest.split_once(' ') {
                        Some((k, v)) => (k.to_string(), v.to_string()),
                        None => (rest.to_string(), String::new()),
                    },
                };
                if !k.is_empty() {
                    info.build_settings.insert(k, v);
                }
            }
            _ => {} // Future / unknown keys; tolerate silently.
        }
    }

    // Build ID + GoRoot are not in buildinfo — they live in
    // separate ELF notes / scattered string-pool patterns.
    info.build_id = extract_go_build_id(data);
    info.go_root = extract_go_root(data);
    info.main_root = extract_go_main_root(data, info.go_root.as_deref());
    classify_dependencies(&mut info);

    Some(info)
}

/// Tally dependency provenance from the parsed module list. Cheap —
/// runs over the already-parsed `dependencies` vec, no extra scanning.
fn classify_dependencies(info: &mut GoBuildInfo) {
    for dep in &info.dependencies {
        if dep.replaced_by.is_some() {
            info.deps_replaced += 1;
            continue;
        }
        if dep.path.contains("/vendor/") {
            info.deps_vendored += 1;
            continue;
        }
        if is_stdlib_path(&dep.path) {
            info.deps_std += 1;
            continue;
        }
        info.deps_thirdparty += 1;
    }
}

/// Heuristic: a Go stdlib package path has no dot in its first path
/// segment. Third-party module paths are domain-rooted (`github.com/…`,
/// `golang.org/x/…`, `k8s.io/…`) so the first segment always contains
/// a dot. False-positive risk is negligible — every public Go module
/// goes through a domain-rooted import path.
fn is_stdlib_path(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or("");
    !first.is_empty() && !first.contains('.')
}

/// Locate the Go build ID. Tries (in order):
///   1. ELF `.note.go.buildid` section — n_type = 4, name = "Go\0\0",
///      desc = ASCII string of form "actionID/contentID".
///   2. The format's read-only data section (`.rodata` ELF / `__rodata`
///      Mach-O / `.rdata` PE) — scanned for the printable
///      `Go build ID: "<id>"` marker the Go linker emits.
///   3. Bounded full-file fallback (first 4 MB) — only reached when
///      the binary lacks a recognizable rodata section.
#[must_use]
fn extract_go_build_id(data: &[u8]) -> Option<String> {
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        if let Some(id) = read_elf_go_buildid(data) {
            return Some(id);
        }
    }
    let needle = b"Go build ID: \"";
    let scan_in = |bytes: &[u8]| -> Option<String> {
        let pos = memchr::memmem::find(bytes, needle)?;
        let after = &bytes[pos + needle.len()..];
        let end = after.iter().take(256).position(|&b| b == b'"')?;
        let id = std::str::from_utf8(&after[..end]).ok()?;
        (!id.is_empty()).then(|| id.to_string())
    };
    if let Some(rodata) = read_rodata(data) {
        if let Some(id) = scan_in(rodata) {
            return Some(id);
        }
    }
    // Last-ditch fallback for unusual layouts. Capped tight (4 MB) —
    // when present, the marker sits in the linker-emitted runtime
    // strings near the start of the data segment.
    let horizon = data.len().min(4 * 1024 * 1024);
    scan_in(&data[..horizon])
}

/// Best-effort read of the format's read-only data section. Returns
/// `None` for unknown formats or stripped binaries; callers fall back
/// to a bounded raw scan.
fn read_rodata(data: &[u8]) -> Option<&[u8]> {
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return crate::analyzers::binary_extractors::read_elf_section(data, b".rodata");
    }
    if is_macho(data) {
        // Newer toolchains emit `__TEXT,__const`; older `__TEXT,__rodata`.
        return crate::analyzers::macho_extractors::find_section(data, "__TEXT", "__const")
            .or_else(|| {
                crate::analyzers::macho_extractors::find_section(data, "__TEXT", "__rodata")
            });
    }
    // PE: `.rdata` is the conventional read-only data section.
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return read_pe_section(data, b".rdata");
    }
    None
}

fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    matches!(
        u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])),
        0xFEED_FACE | 0xFEED_FACF | 0xCEFA_EDFE | 0xCFFA_EDFE | 0xCAFE_BABE | 0xBEBA_FECA
    )
}

/// Read `.note.go.buildid` (ELF). Note layout (LE):
///   u32 namesz | u32 descsz | u32 type | name (padded 4) | desc (padded 4)
/// For Go: namesz=4, name="Go\0\0", type=4, desc=ASCII id.
fn read_elf_go_buildid(data: &[u8]) -> Option<String> {
    let bytes = crate::analyzers::binary_extractors::read_elf_section(data, b".note.go.buildid")?;
    if bytes.len() < 16 {
        return None;
    }
    let namesz = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
    let descsz = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    let _ntype = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let name_off = 12usize;
    let desc_off = name_off + ((namesz + 3) & !3);
    let desc_end = desc_off.checked_add(descsz)?;
    if desc_end > bytes.len() {
        return None;
    }
    let desc = bytes[desc_off..desc_end].split(|&b| b == 0).next()?;
    let s = std::str::from_utf8(desc).ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Detect GoRoot at compile time by scanning the pclntab (where Go
/// stores source-file paths used in stack traces) for the canonical
/// `/src/runtime/` prefix and walking back to find the install root.
///
/// Section-targeted: pclntab can sit 60+ MB into a large Go service
/// binary (kube-apiserver, Kong), so a full-file scan is wasteful.
/// When the section can't be located (stripped binary, unknown
/// format) we skip silently — `go_root` is best-effort attribution,
/// not a load-bearing field.
#[must_use]
fn extract_go_root(data: &[u8]) -> Option<String> {
    let pclntab = read_pclntab(data)?;
    let needle = b"/src/runtime/";
    let pos = memchr::memmem::find(pclntab, needle)?;
    // Walk backwards to find the start of the path (a printable-ASCII
    // run terminated by a non-path byte). Cap at 256 chars upstream
    // to avoid pathological scans.
    let mut start = pos;
    let lo = pos.saturating_sub(256);
    while start > lo {
        let b = pclntab[start - 1];
        if !is_path_byte(b) {
            break;
        }
        start -= 1;
    }
    if start == pos {
        return None;
    }
    let s = std::str::from_utf8(&pclntab[start..pos]).ok()?;
    (!s.is_empty()).then(|| s.to_string())
}

/// Recover the developer's local source-tree root. Scans the pclntab
/// for source-file paths (`*.go`) that are neither under `go_root`
/// nor in the Go module cache (`/pkg/mod/`), then takes their longest
/// common directory prefix. Empty when the binary was built with
/// `-trimpath` (which strips developer paths) — that absence is itself
/// a signal worth recording differentially.
#[must_use]
fn extract_go_main_root(data: &[u8], go_root: Option<&str>) -> Option<String> {
    let pclntab = read_pclntab(data)?;
    // Cap candidate count to keep the longest-common-prefix walk
    // bounded on huge binaries — pclntab on Kong has ~12k file paths.
    const MAX_CANDIDATES: usize = 4096;
    let mut candidates: Vec<&str> = Vec::new();
    let finder = memchr::memmem::Finder::new(b".go\0");
    for rel in finder.find_iter(pclntab) {
        if candidates.len() >= MAX_CANDIDATES {
            break;
        }
        // Walk backwards from the `.go` match to the path start.
        let mut start = rel;
        let lo = rel.saturating_sub(512);
        while start > lo {
            let b = pclntab[start - 1];
            if !is_path_byte(b) && b != b'/' {
                break;
            }
            start -= 1;
        }
        if start == rel {
            continue;
        }
        // Need an absolute-ish path — relative module paths like
        // `github.com/foo/bar.go` (emitted under -trimpath) don't
        // identify a developer source tree.
        if pclntab[start] != b'/' {
            continue;
        }
        let path_bytes = &pclntab[start..rel + 3]; // include ".go"
        let Ok(s) = std::str::from_utf8(path_bytes) else {
            continue;
        };
        if let Some(root) = go_root {
            if s.starts_with(root) {
                continue;
            }
        }
        if s.contains("/pkg/mod/") || s.contains("/src/runtime/") {
            continue;
        }
        candidates.push(s);
    }
    if candidates.is_empty() {
        return None;
    }
    let prefix = longest_common_dir_prefix(&candidates)?;
    // Require at least one path component beyond `/` — otherwise the
    // "common prefix" is the filesystem root, which carries no signal.
    if prefix.is_empty() || prefix == "/" {
        return None;
    }
    Some(prefix)
}

/// Longest common directory prefix across `paths`, ending without a
/// trailing slash (or `/` for filesystem-root-only commonality).
fn longest_common_dir_prefix(paths: &[&str]) -> Option<String> {
    let first = paths.first()?;
    let mut max = first.len();
    for &p in &paths[1..] {
        let common = first
            .as_bytes()
            .iter()
            .zip(p.as_bytes())
            .take_while(|(a, b)| a == b)
            .count();
        if common < max {
            max = common;
        }
        if max == 0 {
            return None;
        }
    }
    let truncated = &first[..max];
    // Trim back to the last `/` so we end on a directory boundary.
    let cut = truncated.rfind('/')?;
    Some(if cut == 0 {
        "/".to_string()
    } else {
        truncated[..cut].to_string()
    })
}

/// Locate the Go pclntab section (line-number table — also stores
/// source file paths). Section names by format:
///   * ELF:    `.gopclntab`
///   * Mach-O: `__TEXT,__gopclntab`
///   * PE:     `.gopclntab`
fn read_pclntab(data: &[u8]) -> Option<&[u8]> {
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return crate::analyzers::binary_extractors::read_elf_section(data, b".gopclntab");
    }
    if is_macho(data) {
        return crate::analyzers::macho_extractors::find_section(data, "__TEXT", "__gopclntab");
    }
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return read_pe_section(data, b".gopclntab");
    }
    None
}

fn is_path_byte(b: u8) -> bool {
    matches!(b, b'/' | b'.' | b'-' | b'_' | b'+' | b':') || b.is_ascii_alphanumeric()
}

/// Locate the Go buildinfo magic. Returns the buffer that contains
/// it (either the format-specific section bytes or the original
/// data slice) along with the offset of the magic within that
/// buffer. Caller does all subsequent reads relative to the returned
/// buffer — the section path avoids any full-file scan, and the
/// fallback path makes the buffer == data so the offset is the file
/// offset.
fn find_magic(data: &[u8]) -> Option<(&[u8], usize)> {
    // Modern Go (1.18+) always emits a dedicated buildinfo section
    // for ELF / Mach-O / PE. Look there first; absence of the section
    // for a recognizable format means this isn't a Go binary, so we
    // skip the full-file fallback (which on a 78 MB non-Go binary
    // costs 1+ ms of pointless SIMD scanning).
    if let Some(format) = recognize_format(data) {
        let section = read_buildinfo_section_for(data, format)?;
        let rel = memchr::memmem::find(section, MAGIC)?;
        return Some((section, rel));
    }
    // Raw / unknown formats: SIMD memmem fallback.
    let pos = memchr::memmem::find(data, MAGIC)?;
    Some((data, pos))
}

#[derive(Copy, Clone)]
enum BinaryFormat {
    Elf,
    MachO,
    Pe,
}

fn recognize_format(data: &[u8]) -> Option<BinaryFormat> {
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return Some(BinaryFormat::Elf);
    }
    if is_macho(data) {
        return Some(BinaryFormat::MachO);
    }
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return Some(BinaryFormat::Pe);
    }
    None
}

fn read_buildinfo_section_for(data: &[u8], fmt: BinaryFormat) -> Option<&[u8]> {
    match fmt {
        BinaryFormat::Elf => {
            crate::analyzers::binary_extractors::read_elf_section(data, b".go.buildinfo")
        }
        BinaryFormat::MachO => {
            crate::analyzers::macho_extractors::find_section(data, "__DATA", "__go_buildinfo")
                .or_else(|| {
                    crate::analyzers::macho_extractors::find_section(
                        data,
                        "__DATA_CONST",
                        "__go_buildinfo",
                    )
                })
        }
        BinaryFormat::Pe => read_pe_section(data, b".go.buildinfo"),
    }
}

/// Minimal PE section reader — enough to fetch a named section's raw
/// bytes without pulling goblin into this module. Returns `None` when
/// the file isn't a recognizable PE or the named section is absent.
fn read_pe_section<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    // COFF header starts at e_lfanew + 4.
    let coff = e_lfanew + 4;
    let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().ok()?) as usize;
    let opt_header_size = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().ok()?) as usize;
    let section_table = coff + 20 + opt_header_size;
    let table_bytes = num_sections.checked_mul(40)?;
    if section_table + table_bytes > data.len() {
        return None;
    }
    for i in 0..num_sections {
        let entry = &data[section_table + i * 40..section_table + (i + 1) * 40];
        let name_field = &entry[..8];
        // Section names are null-padded ASCII; strip trailing NULs.
        let trimmed = name_field.split(|&b| b == 0).next().unwrap_or(&[]);
        if trimmed != name {
            continue;
        }
        let raw_size = u32::from_le_bytes(entry[16..20].try_into().ok()?) as usize;
        let raw_ptr = u32::from_le_bytes(entry[20..24].try_into().ok()?) as usize;
        let end = raw_ptr.checked_add(raw_size)?;
        if end > data.len() {
            return None;
        }
        return Some(&data[raw_ptr..end]);
    }
    None
}

fn read_varint_string(buf: &[u8], cursor: &mut usize) -> Option<String> {
    let bytes = read_varint_bytes(buf, cursor)?;
    Some(String::from_utf8_lossy(bytes).to_string())
}

/// Like [`read_varint_string`] but returns the raw byte slice — used
/// for blobs that carry non-UTF-8 framing bytes (e.g. modinfo
/// sentinels) which must survive intact through later processing.
fn read_varint_bytes<'a>(buf: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let len = read_varint(buf, cursor)?;
    if len > MAX_BUILDINFO_BYTES {
        return None;
    }
    let end = cursor.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let slice = &buf[*cursor..end];
    *cursor = end;
    Some(slice)
}

/// Decode a Go-style unsigned LEB128 varint.  Returns the value and
/// advances the cursor.  Caps at u32 to avoid pathological lengths.
fn read_varint(buf: &[u8], cursor: &mut usize) -> Option<usize> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *cursor >= buf.len() || shift > 56 {
            return None;
        }
        let b = buf[*cursor];
        *cursor += 1;
        result |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    usize::try_from(result).ok()
}

/// Strip the leading `\x30\x77\xaf\x0c\x92\x74\x08\x02...` sentinel
/// and trailing `\xf9\x32\x43\x1c...` sentinel that wrap modinfo
/// blobs in modern Go binaries.  Returns the inner bytes; on
/// mismatch returns the original slice unchanged.
fn strip_sentinels(blob: &[u8]) -> &[u8] {
    const LEAD: &[u8] = b"\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6";
    const TAIL: &[u8] = b"\xf9\x32\x43\x1c\x35\x9c\xb6\x07\x4e\x60\x90\xeb\x05\x14\x49\xfb";
    if blob.len() < LEAD.len() + TAIL.len() {
        return blob;
    }
    if !blob.starts_with(LEAD) {
        return blob;
    }
    let after_lead = &blob[LEAD.len()..];
    if !after_lead.ends_with(TAIL) {
        return blob;
    }
    &after_lead[..after_lead.len() - TAIL.len()]
}

/// Parse a `mod`/`dep` record body into a [`GoModuleRef`].  Records
/// are tab-separated: `<path>\t<version>\t<sum>` (sum optional).
fn parse_module_ref(rest: &str) -> Option<GoModuleRef> {
    let parts: Vec<&str> = rest.split('\t').collect();
    let path = parts.first()?.to_string();
    if path.is_empty() {
        return None;
    }
    let version = parts
        .get(1)
        .map(std::string::ToString::to_string)
        .unwrap_or_default();
    let sum = parts
        .get(2)
        .map(std::string::ToString::to_string)
        .unwrap_or_default();
    Some(GoModuleRef {
        path,
        version,
        sum,
        replaced_by: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Build a synthetic buildinfo blob that the extractor can chew
    /// on.  Mirrors the modern (Go 1.18+) varint-prefixed format.
    fn build_buildinfo(version: &str, modinfo: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.push(8); // ptr_size
        buf.push(0x02); // flags: varint format
        buf.extend_from_slice(&[0u8; 16]); // reserved padding to 0x20
        write_varint(&mut buf, version.len());
        buf.extend_from_slice(version.as_bytes());
        let mut wrapped = Vec::new();
        wrapped
            .extend_from_slice(b"\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6");
        wrapped.extend_from_slice(modinfo.as_bytes());
        wrapped
            .extend_from_slice(b"\xf9\x32\x43\x1c\x35\x9c\xb6\x07\x4e\x60\x90\xeb\x05\x14\x49\xfb");
        write_varint(&mut buf, wrapped.len());
        buf.extend_from_slice(&wrapped);
        buf
    }

    fn write_varint(buf: &mut Vec<u8>, mut v: usize) {
        while v >= 0x80 {
            buf.push(((v as u8) & 0x7F) | 0x80);
            v >>= 7;
        }
        buf.push(v as u8);
    }

    #[test]
    fn extract_simple_go_binary() {
        let modinfo = "path\tgithub.com/attacker/sample\n\
                       mod\tgithub.com/attacker/sample\t(devel)\t\n\
                       build\t-buildmode=exe\n\
                       build\tCGO_ENABLED=0\n\
                       build\tGOOS=linux\n\
                       build\tGOARCH=amd64\n\
                       build\tvcs=git\n\
                       build\tvcs.revision=abc123def\n\
                       build\tvcs.time=2024-01-15T10:30:00Z\n\
                       build\tvcs.modified=false\n";
        let bin = build_buildinfo("go1.21.0", modinfo);
        let info = extract(&bin).expect("buildinfo present");
        assert_eq!(info.version, "go1.21.0");
        assert_eq!(info.main_path, "github.com/attacker/sample");
        assert_eq!(
            info.build_settings.get("GOOS").map(String::as_str),
            Some("linux")
        );
        assert_eq!(
            info.build_settings.get("CGO_ENABLED").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            info.build_settings.get("vcs.revision").map(String::as_str),
            Some("abc123def")
        );
        let main = info.main_module.expect("main module recorded");
        assert_eq!(main.path, "github.com/attacker/sample");
    }

    #[test]
    fn extract_with_dependencies() {
        let modinfo = "path\tmain\n\
                       mod\tmain\tv0.0.0-00010101000000-000000000000\t\n\
                       dep\tgolang.org/x/sys\tv0.0.0-20220715151400-c0bba94af5f8\th1:abc\n\
                       dep\tgithub.com/foo/bar\tv1.2.3\th1:def\n";
        let bin = build_buildinfo("go1.22.0", modinfo);
        let info = extract(&bin).expect("buildinfo present");
        assert_eq!(info.dependencies.len(), 2);
        assert_eq!(info.dependencies[0].path, "golang.org/x/sys");
        assert_eq!(info.dependencies[0].sum, "h1:abc");
        assert_eq!(info.dependencies[1].path, "github.com/foo/bar");
        assert_eq!(info.dependencies[1].version, "v1.2.3");
    }

    #[test]
    fn extract_with_module_replacement() {
        let modinfo = "path\tmain\n\
                       mod\tmain\t(devel)\t\n\
                       dep\tgithub.com/foo/bar\tv1.2.3\th1:abc\n\
                       =>\tgithub.com/myfork/bar\tv0.0.1\th1:xyz\n";
        let bin = build_buildinfo("go1.21.0", modinfo);
        let info = extract(&bin).expect("buildinfo present");
        assert_eq!(info.dependencies.len(), 1);
        let dep = &info.dependencies[0];
        let replacement = dep.replaced_by.as_ref().expect("replaced");
        assert_eq!(replacement.path, "github.com/myfork/bar");
    }

    #[test]
    fn extract_returns_none_for_non_go() {
        assert!(extract(b"random bytes here").is_none());
    }

    #[test]
    fn extract_returns_none_for_old_pointer_format() {
        let mut bin = Vec::new();
        bin.extend_from_slice(MAGIC);
        bin.push(8); // ptr_size
        bin.push(0x00); // flags: pointer format (not varint)
        bin.extend_from_slice(&[0u8; 24]);
        assert!(extract(&bin).is_none());
    }

    #[test]
    fn extract_handles_modinfo_without_sentinels() {
        let modinfo = "path\tplain\n";
        // Build a buildinfo without the sentinel wrap.
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.push(8);
        buf.push(0x02);
        buf.extend_from_slice(&[0u8; 16]);
        write_varint(&mut buf, "go1.20.0".len());
        buf.extend_from_slice(b"go1.20.0");
        write_varint(&mut buf, modinfo.len());
        buf.extend_from_slice(modinfo.as_bytes());
        let info = extract(&buf).expect("parses without sentinels");
        assert_eq!(info.main_path, "plain");
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0usize, 1, 127, 128, 255, 16384, 1_000_000] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let mut cursor = 0;
            let read = read_varint(&buf, &mut cursor).unwrap();
            assert_eq!(read, v, "round-trip failed for {v}");
        }
    }
}
