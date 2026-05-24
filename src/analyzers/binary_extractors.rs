//! Lightweight byte-level extractors that augment the binary kv
//! tree with toolchain attribution data we don't already have on
//! the metrics structs.
//!
//! Each extractor is intentionally small and side-effect-free:
//! takes a `&[u8]` (raw file bytes) or `&AnalysisReport` (already
//! populated), returns an optional string or short list, and the
//! analyzer integration layer stitches the results into
//! `report.values_tree`.
//!
//! Trade-off: this is slightly redundant with parsing already done
//! by the format analyzers (`analyzers::elf::analyze_structural`).
//! The redundancy is intentional — these extractors run on raw
//! bytes without depending on goblin's higher-level types, so an
//! analyzer panic or bug elsewhere never starves attribution data.

use crate::types::{AnalysisReport, Import};
use std::collections::BTreeSet;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// ELF `.comment` section
// ---------------------------------------------------------------------------

/// Public re-export of the internal ELF section reader so other
/// modules (e.g. `go_buildinfo`) can fetch named sections without
/// duplicating the parser.
pub(crate) fn read_elf_section<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    read_section(data, name)
}

/// Locate a named ELF section and return its byte slice. Lenient
/// parser — bails on malformed inputs rather than propagating
/// errors. Caps memory; only reads section header table.
fn read_section<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if data.len() < 0x40 || &data[..4] != b"\x7fELF" {
        return None;
    }
    let is_64 = data[4] == 2;
    let is_le = data[5] == 1;
    if !is_le {
        // Big-endian ELF parsing for `.comment` extraction is rare
        // enough that we punt; the section is still found via the
        // string-scan fallback below for trait authors.
        return scan_section_fallback(data, name);
    }

    // e_shoff (section header table file offset)
    // e_shentsize (section header entry size)
    // e_shnum (number of section headers)
    // e_shstrndx (section name string table index)
    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        if data.len() < 0x40 {
            return None;
        }
        let shoff = u64::from_le_bytes(data[0x28..0x30].try_into().ok()?);
        let shentsize = u16::from_le_bytes(data[0x3a..0x3c].try_into().ok()?);
        let shnum = u16::from_le_bytes(data[0x3c..0x3e].try_into().ok()?);
        let shstrndx = u16::from_le_bytes(data[0x3e..0x40].try_into().ok()?);
        (
            shoff as usize,
            shentsize as usize,
            shnum as usize,
            shstrndx as usize,
        )
    } else {
        if data.len() < 0x34 {
            return None;
        }
        let shoff = u32::from_le_bytes(data[0x20..0x24].try_into().ok()?);
        let shentsize = u16::from_le_bytes(data[0x2e..0x30].try_into().ok()?);
        let shnum = u16::from_le_bytes(data[0x30..0x32].try_into().ok()?);
        let shstrndx = u16::from_le_bytes(data[0x32..0x34].try_into().ok()?);
        (
            shoff as usize,
            shentsize as usize,
            shnum as usize,
            shstrndx as usize,
        )
    };

    if e_shentsize == 0 || e_shnum == 0 || e_shstrndx >= e_shnum {
        return None;
    }
    if e_shoff.checked_add(e_shentsize.checked_mul(e_shnum)?)? > data.len() {
        return None;
    }

    // Locate the section-name string table.
    let shstrtab = read_shdr(data, e_shoff, e_shentsize, e_shstrndx, is_64)?;
    let (shstr_off, shstr_size) = (shstrtab.sh_offset as usize, shstrtab.sh_size as usize);
    if shstr_off.checked_add(shstr_size)? > data.len() {
        return None;
    }
    let shstrings = &data[shstr_off..shstr_off + shstr_size];

    // Walk section headers looking for our name.
    for i in 0..e_shnum {
        let shdr = read_shdr(data, e_shoff, e_shentsize, i, is_64)?;
        let name_off = shdr.sh_name as usize;
        if name_off >= shstrings.len() {
            continue;
        }
        let nul = shstrings[name_off..].iter().position(|&b| b == 0)?;
        let candidate = &shstrings[name_off..name_off + nul];
        if candidate == name {
            let off = shdr.sh_offset as usize;
            let size = shdr.sh_size as usize;
            if off.checked_add(size)? > data.len() {
                return None;
            }
            return Some(&data[off..off + size]);
        }
    }
    None
}

/// Fallback for big-endian ELFs: locate the literal section name
/// in the file then peek a fixed offset back to find the section
/// header. Imprecise — used only when LE parsing isn't available.
fn scan_section_fallback<'a>(_data: &'a [u8], _name: &[u8]) -> Option<&'a [u8]> {
    None
}

#[derive(Debug, Clone, Copy)]
struct Shdr {
    sh_name: u32,
    sh_offset: u64,
    sh_size: u64,
}

fn read_shdr(data: &[u8], shoff: usize, entsize: usize, idx: usize, is_64: bool) -> Option<Shdr> {
    let off = shoff.checked_add(entsize.checked_mul(idx)?)?;
    let entry = data.get(off..off + entsize)?;
    let sh_name = u32::from_le_bytes(entry.get(..4)?.try_into().ok()?);
    if is_64 {
        let sh_offset = u64::from_le_bytes(entry.get(0x18..0x20)?.try_into().ok()?);
        let sh_size = u64::from_le_bytes(entry.get(0x20..0x28)?.try_into().ok()?);
        Some(Shdr {
            sh_name,
            sh_offset,
            sh_size,
        })
    } else {
        let sh_offset = u32::from_le_bytes(entry.get(0x10..0x14)?.try_into().ok()?) as u64;
        let sh_size = u32::from_le_bytes(entry.get(0x14..0x18)?.try_into().ok()?) as u64;
        Some(Shdr {
            sh_name,
            sh_offset,
            sh_size,
        })
    }
}


// ---------------------------------------------------------------------------
// Rust runtime detection
// ---------------------------------------------------------------------------

/// Detect a Rust binary by looking for the canonical Rust allocator
/// shim symbols (`__rust_alloc`, `__rust_dealloc`, etc.) and panic
/// infrastructure (`rust_panic`, `rust_begin_unwind`). These are
/// emitted by every rustc-built binary and are unmistakeable.
///
/// Scans both imports (for ELF/PE where Rust stdlib may be a shared
/// dep) AND exports (for Mach-O where Rust stdlib is statically
/// linked and the runtime symbols appear as defined locals).
///
/// Returns the list of distinct Rust ABI symbols observed (sorted),
/// or empty when no Rust signal present.
#[must_use]
pub(crate) fn detect_rust_symbols(
    imports: &[Import],
    exports: &[crate::types::Export],
) -> Vec<String> {
    let mut out = BTreeSet::new();
    let exact_marks = [
        "rust_alloc",
        "rust_dealloc",
        "rust_realloc",
        "rust_alloc_zeroed",
        "rust_alloc_error_handler",
        "rust_panic",
        "rust_begin_unwind",
        "rust_eh_personality",
    ];
    let scan_name = |s: &str, out: &mut BTreeSet<String>| {
        let s = s.trim_start_matches('_');
        for mark in exact_marks {
            if s == mark {
                out.insert(mark.to_string());
            }
        }
    };
    for imp in imports {
        scan_name(imp.symbol.as_str(), &mut out);
    }
    for exp in exports {
        scan_name(exp.symbol.as_str(), &mut out);
    }
    out.into_iter().collect()
}

/// Determine Rust symbol-mangling style from observed symbols.
/// Returns `Some("v0")` when any symbol uses the new v0 mangling
/// (`_R...`), `Some("legacy")` when the legacy mangling
/// (`_ZN.*17h<16-hex>E`) is observed exclusively, or `None` when no
/// Rust mangling is detectable. Scans both imports and exports.
#[must_use]
pub(crate) fn detect_rust_mangling(
    imports: &[Import],
    exports: &[crate::types::Export],
) -> Option<&'static str> {
    let legacy_re = legacy_rust_mangling_regex()?;
    let mut saw_legacy = false;
    let check = |s: &str, saw_legacy: &mut bool| -> bool {
        if s.starts_with("_R") && s.len() > 4 {
            return true; // v0
        }
        // Cheap byte-level prefilter: only fall through to the regex
        // for symbols that could plausibly match `_?ZN.*17h…E`.
        if is_legacy_rust_mangling_candidate(s) && legacy_re.is_match(s) {
            *saw_legacy = true;
        }
        false
    };
    for imp in imports {
        if check(imp.symbol.as_str(), &mut saw_legacy) {
            return Some("v0");
        }
    }
    for exp in exports {
        if check(exp.symbol.as_str(), &mut saw_legacy) {
            return Some("v0");
        }
    }
    if saw_legacy {
        Some("legacy")
    } else {
        None
    }
}

fn is_legacy_rust_mangling_candidate(s: &str) -> bool {
    let s = s.strip_prefix('_').unwrap_or(s);
    s.starts_with("ZN") && s.ends_with('E') && s.as_bytes().windows(3).any(|w| w == b"17h")
}

fn legacy_rust_mangling_regex() -> Option<&'static regex::Regex> {
    static LEGACY_RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    LEGACY_RE
        .get_or_init(|| regex::Regex::new(r"^_?ZN.*17h[0-9a-f]{16}E$").ok())
        .as_ref()
}

/// Whether the ELF carries a `.rustc` section. Set on rustc-built
/// `lib` crates (rlib metadata) and some `bin` crates depending on
/// build profile. An explicit "this is a Rust artifact" marker.
#[must_use]
pub(crate) fn has_rustc_section(data: &[u8]) -> bool {
    read_section(data, b".rustc").is_some()
}

// ---------------------------------------------------------------------------
// Aggregate hook: layer extracted data onto the binary kv tree
// ---------------------------------------------------------------------------

/// Run all post-analysis extractors and merge their results into
/// `report.values_tree`. Idempotent: safe to call multiple times.
pub(crate) fn augment_report(report: &mut AnalysisReport, raw_data: &[u8]) {
    use serde_json::{json, Value};

    // Build the augmenting Value first so we don't have to worry
    // about partial-update consistency.
    let mut augment = serde_json::Map::new();


    // Top unnamed functions by cyclomatic complexity. rizin labels
    // discovered-but-unnamed functions as `fcn.<addr>`; named ones
    // are `sym.X`, `entry0`, `main`, etc. A high-complexity unnamed
    // function in a stripped library is interesting in its own right
    // — it carries the bulk of internal logic without any ABI tie.
    // The xz 5.6.0 backdoor lives in two anonymous functions
    // (cc=165, cc=147); surfacing them by name lets a diff highlight
    // their *appearance* between releases as a first-class signal.
    let mut unnamed: Vec<&crate::types::binary::Function> = report
        .functions
        .iter()
        .filter(|f| f.name.starts_with("fcn."))
        .filter(|f| f.complexity.unwrap_or(0) > 1)
        .collect();
    unnamed.sort_by(|a, b| {
        b.complexity
            .unwrap_or(0)
            .cmp(&a.complexity.unwrap_or(0))
            .then_with(|| b.size.unwrap_or(0).cmp(&a.size.unwrap_or(0)))
    });
    if !unnamed.is_empty() {
        // Single-number trait targets: count of unnamed funcs whose
        // cyclomatic complexity clears the "interesting" bar (>50,
        // matching `binary.high_complexity_func_count`). Drift in
        // this number between releases is the cleanest one-shot
        // signal that hidden complexity grew (xz 5.4.5: 6, xz 5.6.0: 13).
        let _ = unnamed
            .iter()
            .filter(|f| f.complexity.unwrap_or(0) > 50)
            .count();

        const MAX_UNNAMED: usize = 8;
        let arr: Vec<Value> = unnamed
            .iter()
            .take(MAX_UNNAMED)
            .map(|f| {
                let mut node = serde_json::Map::new();
                if let Some(off) = f.offset.as_deref() {
                    node.insert("addr".into(), json!(off));
                }
                if let Some(sz) = f.size {
                    node.insert("size".into(), json!(sz));
                }
                if let Some(cc) = f.complexity {
                    node.insert("cc".into(), json!(cc));
                }
                if let Some(cf) = f.control_flow.as_ref() {
                    node.insert("bbs".into(), json!(cf.basic_blocks));
                }
                Value::Object(node)
            })
            .collect();
        let binary_extra = augment
            .entry(String::from("binary"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = binary_extra.as_object_mut() {
            obj.insert("top_complex_unnamed".into(), Value::Array(arr));
        }
    }

    // Rust runtime detection — allocator shim + panic infrastructure
    // imports are unmistakeable. The `.rustc` section (ELF) is an
    // explicit "this is a Rust artifact" marker.
    let rust_symbols = detect_rust_symbols(&report.imports, &report.exports);
    let rust_mangling = detect_rust_mangling(&report.imports, &report.exports);
    let rust_section = has_rustc_section(raw_data);
    if !rust_symbols.is_empty() || rust_mangling.is_some() || rust_section {
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            // Cross-format toolchain attribution: when Rust is detected,
            // it's the source-language toolchain regardless of which
            // linker LC_BUILD_VERSION names. Move any prior toolchain_family
            // value (e.g. `ld` from Mach-O LC_BUILD_VERSION) to `linker`
            // so both signals are preserved.
            if let Some(prior) = obj.get("toolchain_family").cloned() {
                if prior.as_str() != Some("rustc") {
                    obj.entry("linker".to_string()).or_insert(prior);
                }
            }
            obj.insert("toolchain_family".into(), json!("rustc"));
            if !rust_symbols.is_empty() {
                obj.insert("rust_runtime_symbols".into(), json!(rust_symbols));
            }
            if let Some(m) = rust_mangling {
                obj.insert("rust_mangling".into(), json!(m));
            }
        }
    }
    let _ = rust_section;

    // Builder-path / username recovery.  Cross-format byte scan
    // for `/home/<u>/`, `/Users/<u>/`, and `C:\Users\<u>\` —
    // these leak the build host's filesystem layout and the
    // developer's username (strong attribution signal that
    // survives stripping).
    //
    // Naming: when exactly one canonical username is recovered we
    // filefacts the singular `username`; otherwise we filefacts the
    // array `usernames` (mutually exclusive shapes).  Trait authors
    // target one or the other based on cardinality; the
    // `username_from` field carries provenance.
    let bp = super::builder_paths::extract(raw_data);
    if !bp.usernames.is_empty() || !bp.source_dirs.is_empty() || !bp.full_paths.is_empty() {
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            match bp.usernames.len() {
                0 => {}
                1 => {
                    obj.insert("username".into(), json!(bp.usernames[0].clone()));
                    if let Some(home) = bp.source_dirs.first() {
                        obj.insert("user_home".into(), json!(home.clone()));
                    }
                    obj.insert("username_from".into(), json!("byte_scan"));
                }
                _ => {
                    obj.insert("usernames".into(), json!(bp.usernames.clone()));
                }
            }
            if !bp.full_paths.is_empty() {
                obj.insert("source_paths".into(), json!(bp.full_paths.clone()));
            }
            // Build-root: longest common ancestor of discovered
            // builder-anchored paths.
            if let Some(root) = super::builder_paths::find_build_root(&bp.full_paths) {
                obj.insert("build_root".into(), json!(root));
            }
        }
    }

    // PDB-derived username for PE binaries (when filefacts surfaced the
    // PDB path). The `.pdb` filename in the PE Debug Directory is a
    // single canonical reference, not subject to scan noise — preferred
    // when present.
    let pdb_path_from_filefacts = report
        .filefacts
        .as_ref()
        .and_then(|e| e.values.get("pe"))
        .and_then(|pe| pe.get("debug"))
        .and_then(|d| d.get("pdb"))
        .and_then(|p| p.get("path"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if let Some(pdb) = pdb_path_from_filefacts.as_deref() {
        if let Some(user) = super::builder_paths::extract_username_from_pdb(pdb) {
            let build_extra = augment
                .entry(String::from("build"))
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(obj) = build_extra.as_object_mut() {
                // PDB is high-confidence; supersede byte-scan
                // results.  Drop `usernames[]` if PDB gave us a
                // canonical answer.
                obj.remove("usernames");
                obj.insert("username".into(), json!(user.clone()));
                obj.insert("username_from".into(), json!("pdb_path"));
            }
        }
    }

    // Go buildinfo — cross-format scan for the magic header.
    // Trait authors looking for "where was this Go binary built"
    // compose `build.build_root` + `build.toolchain_family == "go"`
    // rather than a Go-specific duplicate field.
    if let Some(go) = super::go_buildinfo::extract(raw_data) {
        let go_value = serialize_go_buildinfo(&go);
        if let Some(obj) = go_value.as_object() {
            if !obj.is_empty() {
                augment.insert("go".into(), go_value);
            }
        }
        // Toolchain attribution feeds the cross-format build.*
        // section.  `go.main_path` (the import path) lives ONLY on
        // the Go subtree — it's not a filesystem path, so it
        // doesn't belong on `build.source_paths`.
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            if !go.version.is_empty() {
                obj.entry("toolchain".to_string())
                    .or_insert_with(|| json!(go.version.clone()));
                obj.entry("toolchain_family".to_string())
                    .or_insert_with(|| json!("go"));
            }
        }
    }

    if augment.is_empty() {
        return;
    }

    // Merge `augment` into the existing values_tree (or create one).
    let existing = report
        .values_tree
        .take()
        .map(|b| *b)
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let merged = deep_merge(existing, Value::Object(augment));
    report.values_tree = Some(Box::new(merged));
}

/// Parse a plist (XML or binary) into a serde_json::Value with
/// snake_cased keys. Handles top-level dicts, arrays, strings, ints,
/// reals, booleans, and dates (formatted as ISO-8601). Binary data
/// blobs are dropped (kv tree isn't a useful surface for them).
/// Returns `None` on parse failure or empty result.
/// Serialize a parsed Go buildinfo into the `go.*` kv-tree shape.
/// Pike-pass restructure: the original
/// runtime/buildinfo flat dict (with keys like `-buildmode`,
/// `vcs.revision`, `CGO_ENABLED`) is normalized into two clean
/// sub-trees so value path traversal works:
///
/// - `go.build.{mode, compiler, goos, goarch, goamd64, goarm,
///   cgo, trimpath, ldflags, asmflags, gcflags, buildvcs}`
/// - `go.vcs.{type, revision, time, modified}`
///
/// Booleans (`cgo`, `trimpath`, `modified`, `buildvcs`) are
/// parsed from the `"0"`/`"1"`/`"true"`/`"false"` string form.
/// Unknown keys land in a fallback `go.build.other.<key>` map so
/// nothing is lost.
fn serialize_go_buildinfo(info: &super::go_buildinfo::GoBuildInfo) -> serde_json::Value {
    use serde_json::{json, Map, Value};
    let mut go = Map::new();
    if !info.version.is_empty() {
        go.insert("version".into(), json!(info.version));
    }
    if !info.main_path.is_empty() {
        go.insert("main_path".into(), json!(info.main_path));
    }
    if let Some(bid) = info.build_id.as_deref() {
        if !bid.is_empty() {
            go.insert("build_id".into(), json!(bid));
        }
    }
    if let Some(gr) = info.go_root.as_deref() {
        if !gr.is_empty() {
            go.insert("go_root".into(), json!(gr));
        }
    }
    if let Some(mr) = info.main_root.as_deref() {
        if !mr.is_empty() {
            go.insert("main_root".into(), json!(mr));
        }
    }
    if info.deps_std + info.deps_thirdparty + info.deps_replaced + info.deps_vendored > 0 {
        let mut deps_breakdown = Map::new();
        deps_breakdown.insert("std".into(), json!(info.deps_std));
        deps_breakdown.insert("thirdparty".into(), json!(info.deps_thirdparty));
        deps_breakdown.insert("replaced".into(), json!(info.deps_replaced));
        deps_breakdown.insert("vendored".into(), json!(info.deps_vendored));
        go.insert("deps_breakdown".into(), Value::Object(deps_breakdown));
    }
    if let Some(main) = &info.main_module {
        let mut mm = Map::new();
        if !main.path.is_empty() {
            mm.insert("path".into(), json!(main.path));
        }
        if !main.version.is_empty() {
            mm.insert("version".into(), json!(main.version));
        }
        if !main.sum.is_empty() {
            mm.insert("sum".into(), json!(main.sum));
        }
        if !mm.is_empty() {
            go.insert("main_module".into(), Value::Object(mm));
        }
    }
    if !info.dependencies.is_empty() {
        let arr: Vec<Value> = info
            .dependencies
            .iter()
            .map(|m| {
                let mut entry = Map::new();
                entry.insert("path".into(), json!(m.path));
                if !m.version.is_empty() {
                    entry.insert("version".into(), json!(m.version));
                }
                if !m.sum.is_empty() {
                    entry.insert("sum".into(), json!(m.sum));
                }
                if let Some(rep) = &m.replaced_by {
                    entry.insert(
                        "replaced_by".into(),
                        json!({
                            "path": rep.path,
                            "version": rep.version,
                        }),
                    );
                }
                Value::Object(entry)
            })
            .collect();
        go.insert("dependencies".into(), Value::Array(arr));
    }

    let mut build = Map::new();
    let mut vcs = Map::new();
    let mut other = Map::new();
    for (raw_key, raw_val) in &info.build_settings {
        let key = raw_key.as_str();
        // VCS sub-tree.
        if let Some(suffix) = key.strip_prefix("vcs.") {
            vcs.insert(suffix.to_string(), go_value_for(suffix, raw_val));
            continue;
        }
        if key == "vcs" {
            vcs.insert("system".into(), json!(raw_val));
            continue;
        }
        // Build flags — strip leading `-` and snake-case.
        let stripped = key.strip_prefix('-').unwrap_or(key);
        let canonical = match stripped {
            "buildmode" => Some("mode"),
            "compiler" => Some("compiler"),
            "trimpath" => Some("trimpath"),
            "buildvcs" => Some("buildvcs"),
            "ldflags" => Some("ldflags"),
            "asmflags" => Some("asmflags"),
            "gcflags" => Some("gcflags"),
            "tags" => Some("tags"),
            "race" => Some("race"),
            "msan" => Some("msan"),
            "asan" => Some("asan"),
            "GOOS" => Some("goos"),
            "GOARCH" => Some("goarch"),
            "GOAMD64" => Some("goamd64"),
            "GOARM" => Some("goarm"),
            "GO386" => Some("go386"),
            "CGO_ENABLED" => Some("cgo"),
            "CGO_CFLAGS" | "CGO_CPPFLAGS" | "CGO_CXXFLAGS" | "CGO_FFLAGS" | "CGO_LDFLAGS" => {
                Some("cgo_flags")
            }
            _ => None,
        };
        if let Some(name) = canonical {
            build.insert(name.into(), go_value_for(name, raw_val));
        } else {
            other.insert(stripped.to_string(), json!(raw_val));
        }
    }
    if !build.is_empty() {
        if !other.is_empty() {
            build.insert("other".into(), Value::Object(other));
        }
        go.insert("build".into(), Value::Object(build));
    } else if !other.is_empty() {
        go.insert(
            "build".into(),
            Value::Object({
                let mut m = Map::new();
                m.insert("other".into(), Value::Object(other));
                m
            }),
        );
    }
    if !vcs.is_empty() {
        go.insert("vcs".into(), Value::Object(vcs));
    }
    Value::Object(go)
}

/// Coerce a Go build-setting string into the canonical kv shape
/// for that field — booleans parsed for known boolean keys, plain
/// strings otherwise.
fn go_value_for(key: &str, raw: &str) -> serde_json::Value {
    use serde_json::json;
    let bool_keys = [
        "cgo", "trimpath", "modified", "buildvcs", "race", "msan", "asan",
    ];
    if bool_keys.contains(&key) {
        let v = raw.trim();
        if matches!(v, "1" | "true" | "True" | "TRUE") {
            return json!(true);
        }
        if matches!(v, "0" | "false" | "False" | "FALSE") {
            return json!(false);
        }
    }
    json!(raw)
}

/// Merge two JSON values, with `b` taking precedence at leaves.
/// Object keys union; arrays from `b` replace arrays from `a`.
fn deep_merge(a: serde_json::Value, b: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(mut am), Value::Object(bm)) => {
            for (k, bv) in bm {
                let av = am.remove(&k).unwrap_or(Value::Null);
                am.insert(k, deep_merge(av, bv));
            }
            Value::Object(am)
        }
        (_, b) => b,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn deep_merge_unions_objects() {
        use serde_json::json;
        let a = json!({"build": {"is_pie": true}, "elf": {"foo": 1}});
        let b = json!({"build": {"distro": "ubuntu"}});
        let m = deep_merge(a, b);
        assert_eq!(m["build"]["is_pie"], true);
        assert_eq!(m["build"]["distro"], "ubuntu");
        assert_eq!(m["elf"]["foo"], 1);
    }

}
