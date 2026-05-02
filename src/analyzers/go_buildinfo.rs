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
//! `binary_kv`.

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
    let pos = find_magic(data)?;
    if pos + 0x20 > data.len() {
        return None;
    }
    let ptr_size = data[pos + 0x0E];
    let flags = data[pos + 0x0F];

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
    let body_end = (body_start + MAX_BUILDINFO_BYTES).min(data.len());
    let body = &data[body_start..body_end];

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

    Some(info)
}

fn find_magic(data: &[u8]) -> Option<usize> {
    // Magic is 16-byte aligned per Go runtime conventions, but
    // we don't depend on that — direct slice search keeps us
    // robust against header packing variations.
    data.windows(MAGIC.len()).position(|w| w == MAGIC)
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
    let version = parts.get(1).map(|s| s.to_string()).unwrap_or_default();
    let sum = parts.get(2).map(|s| s.to_string()).unwrap_or_default();
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
        wrapped.extend_from_slice(b"\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6");
        wrapped.extend_from_slice(modinfo.as_bytes());
        wrapped.extend_from_slice(b"\xf9\x32\x43\x1c\x35\x9c\xb6\x07\x4e\x60\x90\xeb\x05\x14\x49\xfb");
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
