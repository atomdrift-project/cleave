//! Finding scopes and the archive/package paths they resolve against.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Scope of evidence for a composite rule or downgrade condition.
///
/// A composite's conditions can match in different parts of the analysis
/// tree. Its scope controls how tightly evidence from distinct conditions
/// must share an analysis-tree ancestor before the composite is allowed to
/// fire. Downgrade conditions may also name the immediate parent relationship
/// to use root identity when interpreting an embedded child.
///
/// The default (omitted from YAML) is [`Scope::File`]: evidence must
/// share the same leaf-file (the deepest file-shaped unit, e.g. a PE
/// extracted from a zip). Decoded payload layers below the file are
/// pooled together at the file level.
///
/// Every scope below has one fixed, unconditional definition, computed the
/// same way regardless of where the consuming composite itself runs or how
/// deeply nested it is. None of them ever widen to "pool everything" as a
/// silent fallback -- only `Outer` does that, and only because that is its
/// entire, explicit job.
///
/// ```text
/// Outer    →  anywhere within the current top-level analysis
///             (one `analyze_file` call: one sample, however deeply nested)
/// Package  →  nearest enclosing package-ecosystem archive (npm/gem/whl/
///             nupkg/crate/conda/egg/python_sdist), always innermost
///             (falls back to File when no such ancestor exists)
/// Archive  →  nearest enclosing archive of any kind, always innermost
///             (falls back to File when no such ancestor exists)
/// Nest     →  a JVM class and its `$`-named inner, anonymous and
///             lambda classes (`Foo.class` + `Foo$Bar.class`); the JVM's
///             nest. Not archive nesting. Any other file: same as File
/// File     →  same leaf-file (the deepest file-shaped unit, e.g. a
///             PE inside a zip; ignores decoded payload layers below)
///             (default)
/// Leaf     →  same exact analyzed unit: a decoded payload layer is its
///             own unit, but a position inside a unit is not
/// Parent   →  immediate parent findings only (downgrade conditions only)
/// FileOrParent → matched file and immediate parent (downgrade only)
/// ```
///
/// For location scopes, two pieces of evidence share scope iff their keys are
/// equal, where the key is computed by [`Scope::key`] from each
/// `Evidence.location`. Parent scopes are evaluated from the report tree and
/// do not use location keys.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Scope {
    /// Anywhere within the current top-level analysis (one `analyze_file`
    /// call). This is the one scope that deliberately pools by presence
    /// (empty key) rather than by location -- the explicit, auditable
    /// choice for correlation that should reach beyond any single
    /// archive/package boundary, e.g. tying a fetched artifact's bytes to
    /// its separately-fetched registry metadata.
    Outer,
    /// Nearest enclosing package-ecosystem archive (npm/gem/whl/nupkg/
    /// crate/conda/egg/python_sdist) -- always the innermost one, computed
    /// the same way regardless of where the consuming composite runs. When
    /// no such ancestor exists (nested or as the top-level analyzed file
    /// itself), behaves exactly like [`Scope::File`] -- never widens to
    /// pool globally as a fallback.
    Package,
    /// Nearest enclosing archive of any kind -- always the innermost one.
    /// When no enclosing archive exists, behaves exactly like
    /// [`Scope::File`] -- never widens to pool globally as a fallback.
    Archive,
    /// A JVM class together with its nestmates: the inner, anonymous and
    /// lambda classes compiled beside it as `Outer$Inner.class`. Source that
    /// is one unit to its author -- a TLS client and the TrustManager it
    /// defines inline -- lands in several class files, and `file` sees only
    /// one of them while `archive` pools every class in the JAR. For a
    /// location that is not a `.class` member, behaves exactly like
    /// [`Scope::File`].
    ///
    /// "Nest" is the JVM's term (JEP 181 `NestHost`/`NestMembers`); it has
    /// nothing to do with archives nested inside archives.
    Nest,
    /// The immediate analyzed parent file. This scope is only meaningful for
    /// downgrade gates and is evaluated by the parent/child analysis pass.
    Parent,
    /// The matched file or its immediate analyzed parent. This is useful
    /// when an existing file-local downgrade also needs a parent identity gate.
    #[serde(rename = "file-or-parent")]
    FileOrParent,
    /// Same leaf-file. The deepest file-shaped unit (e.g. a PE
    /// extracted from a zip). Decoded payload layers below the
    /// file are pooled together at the file level. Default.
    #[default]
    File,
    /// Same exact analyzed unit: each decoded payload layer is a unit of
    /// its own. Positions within a unit (byte offsets, AST `row:col`) are
    /// not, so an AST leg and a text leg in one unit share the scope.
    Leaf,
}

impl Scope {
    /// Compute the scope key for a piece of evidence given its
    /// `Evidence.location`. Two evidence items share scope iff their
    /// scope keys are equal.
    ///
    /// `archive_contents` and `top_level_file_type` come from the current
    /// analysis's `AnalysisReport`. [`Scope::Package`] reads both;
    /// [`Scope::Archive`] reads `archive_contents` to tell which `!`
    /// ancestors are archives; every other scope ignores them.
    ///
    /// The key is a borrowed substring of `location` (or the empty
    /// string), so this is allocation-free.
    pub(super) fn key<'a>(
        self,
        location: Option<&'a str>,
        archive_contents: &[crate::types::ArchiveEntry],
        top_level_file_type: &str,
    ) -> &'a str {
        match (self, location) {
            // Outer scope or no location info — all evidence shares one key.
            // This is the only scope that pools by presence, deliberately.
            (Scope::Outer, _) | (_, None) => "",
            // Leaf: the exact analyzed unit, with any position inside it
            // dropped.
            (Scope::Leaf, Some(loc)) => strip_byte_offset_location(strip_ast_position(loc)),
            // File: strip any decoded-payload suffix; what remains is
            // the leaf-file identifier. Parent is meaningful only to the
            // explicit downgrade pass; a composite cannot pool a parent's
            // evidence through a location key, so it keys like File.
            (Scope::File | Scope::Parent | Scope::FileOrParent, Some(loc)) => {
                strip_byte_offset_location(strip_ast_position(strip_decode_suffix(loc)))
            }
            // Nest: the file key cut back to its nest host's name.
            (Scope::Nest, Some(loc)) => {
                nest_host(strip_byte_offset_location(strip_decode_suffix(loc)))
            }
            // Archive: nearest enclosing archive entry path, falling back to
            // file-scope (never a global pool) when nothing encloses it.
            (Scope::Archive, Some(loc)) => {
                let p = parent_archive(loc, archive_contents);
                if p.is_empty() {
                    strip_byte_offset_location(strip_decode_suffix(loc))
                } else {
                    p
                }
            }
            // Package: nearest enclosing package-ecosystem archive, same
            // fall-back-to-file rule as Archive.
            (Scope::Package, Some(loc)) => {
                let p = parent_package(loc, archive_contents, top_level_file_type);
                if p.is_empty() {
                    strip_byte_offset_location(strip_decode_suffix(loc))
                } else {
                    p
                }
            }
        }
    }
}

impl Scope {
    /// Whether this scope can join evidence from different files, which is
    /// what makes a composite run in the container pass and what obliges it
    /// to name a container type in `for:`.
    pub(crate) fn pools_members(self) -> bool {
        matches!(
            self,
            Scope::Outer | Scope::Package | Scope::Archive | Scope::Nest
        )
    }
}

/// The nest-host key for a file-scope key: `…/Foo$Bar$1.class` and
/// `…/Foo.class` both become `…/Foo`. A key that is not a `.class` member is
/// returned unchanged, so [`Scope::Nest`] degrades to [`Scope::File`].
///
/// The `.class` may be followed by a `:`-joined inner location that
/// `strip_byte_offset_location` kept (`…/Foo.class:12:5`); the class name
/// ends at that `.class`. A `$` in the first character of the simple name
/// (`$Proxy1`) is part of the name, not a nest separator.
pub(crate) fn nest_host(key: &str) -> &str {
    let Some(end) = key
        .rmatch_indices(".class")
        .map(|(i, _)| i)
        .find(|&i| matches!(key.as_bytes().get(i + ".class".len()), None | Some(b':')))
    else {
        return key;
    };
    let class = &key[..end];
    let name = class.rfind(['/', '!', ':']).map_or(0, |i| i + 1);
    match class[name..]
        .char_indices()
        .skip(1)
        .find(|&(_, c)| c == '$')
    {
        Some((i, _)) => &class[..name + i],
        None => class,
    }
}

/// Strip cleave's decoded-payload suffix from a location, returning
/// the leaf-file portion. Decoded payload locations carry the
/// `encoding_chain:` prefix; for those the file-level key collapses
/// to the empty string (same input). Pure positional locations of
/// the form `row:col` (or `row:col:tail`) — produced by the AST
/// evaluator, which has no file path to prefix — also collapse to
/// the empty string so AST evidence pools with non-AST evidence in
/// the same analyzed unit under `scope: file`. Otherwise composites
/// that mix AST conditions with text/symbol/encoded conditions can
/// never satisfy `min_distinct_conditions` because every AST match
/// buckets to its own `row:col` key while sibling evidence buckets to
/// the empty key.
///
/// For archive entry locations like `archive:foo.zip!bar.so`, no
/// decode suffix is present and the input is returned unchanged.
pub(super) fn strip_decode_suffix(location: &str) -> &str {
    if location.starts_with("encoding_chain:") {
        // Decoded layer with no associated file path. Collapse to
        // input-wide key so file-scoped composites still pool input
        // evidence with decoded evidence from the same input.
        ""
    } else if location.starts_with("value:") {
        // KV evidence carries the kv-path in `location` for display;
        // it identifies a field within a single file, not a leaf-file
        // boundary. Collapse to the input-wide key so file-scoped
        // composites pool kv evidence with non-kv evidence in the
        // same file.
        ""
    } else if location.starts_with("embedded@") || location.starts_with("embedded:") {
        // Embedded-code findings (e.g. shell extracted from a
        // Dockerfile RUN block, or a YAML `run:` step) carry a
        // `embedded@<offset>:<inner>` prefix to record where in the
        // parent file they came from. The parent is still one
        // analyzed unit, so pool sibling embedded-code findings — and
        // host-file findings — under the same file-scope key.
        ""
    } else if is_positional_only(location) {
        ""
    } else {
        location
    }
}

/// Strip byte-offset-only evidence detail from a scope location.
///
/// Byte offsets (`0x1234`, `offset:1234`) identify where evidence was
/// found inside an analyzed unit; they do not identify a different
/// analysis-tree leaf. Scope filtering should use the containing unit
/// as the bucket and leave byte distance to `near_bytes`.
///
/// Archive aggregation prefixes nested evidence as
/// `archive:path/to/member:<inner-location>`, so preserve the archive
/// member key while dropping a trailing byte offset.
pub(super) fn strip_byte_offset_location(location: &str) -> &str {
    // Structured-value paths identify facts on this leaf, not separate files.
    // Keep archive/decoded ownership while discarding field detail.
    if location.starts_with("value:") {
        return "";
    }
    if let Some((prefix, _)) = location.rsplit_once(":value:") {
        return prefix;
    }
    if parse_location_as_byte_offset(location).is_some() {
        return "";
    }

    if let Some((prefix, suffix)) = location.rsplit_once(":offset:")
        && parse_hex_or_dec_offset(suffix).is_some()
    {
        return prefix;
    }

    if let Some((prefix, suffix)) = location.rsplit_once(':')
        && (suffix.starts_with("0x")
            || suffix.starts_with("0X")
            || suffix.bytes().all(|b| b.is_ascii_digit()))
        && parse_location_as_byte_offset(suffix).is_some()
    {
        return prefix;
    }

    location
}

/// Drop the AST `row:col` position from a location, keeping the unit it
/// names. AST evidence is located by position (`12:5`), and a member or
/// decoded layer prefixes its unit (`archive:pkg/a.py:12:5`,
/// `encoding_chain:base64:12:5`), where text evidence in the same unit
/// carries a byte offset that [`strip_byte_offset_location`] removes.
/// Without this, an AST leg keys to its own line and never shares a scope
/// with the text legs beside it.
pub(super) fn strip_ast_position(location: &str) -> &str {
    if is_positional_only(location) {
        return "";
    }
    let is_number = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    match location.rsplit_once(':') {
        Some((head, column)) if is_number(column) => match head.rsplit_once(':') {
            Some((unit, row)) if is_number(row) && !unit.is_empty() => unit,
            _ => location,
        },
        _ => location,
    }
}

/// True if `location` is a pure `row:col` (or `row:col:...`) string
/// with no leading file path, archive prefix, or scheme. Such
/// locations carry no file-identity information so they should
/// collapse to the input-wide key under `scope: file`.
pub(super) fn is_positional_only(location: &str) -> bool {
    let mut parts = location.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    // Both leading components must be all-digit, non-empty. Any
    // remaining trailing components are tolerated (some evaluators
    // may extend the position with a third coordinate).
    !first.is_empty()
        && first.bytes().all(|b| b.is_ascii_digit())
        && !second.is_empty()
        && second.bytes().all(|b| b.is_ascii_digit())
}

/// For an archive entry location, return the path of its nearest
/// enclosing archive (the path cut at the innermost `!` whose ancestor is
/// an archive). For non-archive locations, return the empty string — the
/// caller falls back to file scope in that case.
///
/// Archive paths have the shape `archive:<path>` where `<path>` may
/// contain `!` separators for nested archives:
///   archive:foo.so                    → "archive:"          (single-level)
///   archive:foo.zip!bar.so            → "archive:foo.zip"   (parent zip)
///   archive:outer.zip!inner.zip!x.so  → "archive:outer.zip!inner.zip"
pub(super) fn parent_archive<'a>(
    location: &'a str,
    archive_contents: &[crate::types::ArchiveEntry],
) -> &'a str {
    let Some(after_prefix) = location.strip_prefix("archive:") else {
        return "";
    };
    // Drop any encoded-payload suffix that may follow the entry path.
    let entry_path = match after_prefix.find("::") {
        Some(idx) => &after_prefix[..idx],
        None => after_prefix,
    };
    // Walk the `!`-delimited ancestors from innermost to outermost. Not every
    // `!` opens an archive: a script lifted out of a file's structure (a
    // GitHub Actions `run:` step, `action.yml!/runs/steps/0/run`) is a child
    // of that file, which encloses nothing. Such an ancestor is skipped, so
    // the step keys to the archive that holds the file, as the file's own
    // findings do. An ancestor the entry list does not name stays a boundary.
    let mut end = entry_path.len();
    while let Some(bang_idx) = entry_path[..end].rfind('!') {
        let ancestor_path = &entry_path[..bang_idx];
        let encloses = archive_contents
            .iter()
            .find(|m| m.path == ancestor_path)
            .is_none_or(|m| {
                let kind = FileType::from_str(&m.file_type);
                kind.is_archive() || kind.is_package()
            });
        if encloses {
            // Nested entry: keep `archive:<path-up-to-that-!>`.
            return &location[.."archive:".len() + bang_idx];
        }
        end = bang_idx;
    }
    // Single-level entry: all peers in this archive share the bare prefix as
    // their key.
    "archive:"
}

/// Is this filefacts `label()` string an ecosystem package -- a unit of
/// distribution (npm, deb, rpm, whl, vsix, ...) rather than a generic
/// container (zip, tar, iso)?
///
/// Derived from the `#[package]` enum markers rather than a second hand-written
/// list: this is the same question [`FileType::is_package`] answers, asked of a
/// string instead of a variant. The two used to be separate `matches!` arms and
/// drifted, which is exactly how the `ARCHIVES` / `is_archive()` split went
/// wrong. `label` comes from `report_file_type()` (filefacts' label, not the
/// `Debug` enum name), matching `AnalysisReport.archive_contents[].file_type`
/// and `AnalysisReport.target.file_type`.
pub(super) fn is_package_label(label: &str) -> bool {
    // `from_str` maps every alias and spelling filefacts emits onto the
    // routing enum, so the marker set is consulted once, in one place.
    FileType::from_str(label).is_package()
}

/// For an archive entry location, return the path of its nearest enclosing
/// *package-ecosystem* archive (npm/gem/whl/nupkg/crate/conda/egg/
/// python_sdist) -- a stricter version of [`parent_archive`] that skips past
/// plain zip/tar wrappers to find the actual package boundary. For example,
/// a member two levels inside `outer.zip!pkg.tgz!lib/x.js` keys to
/// `archive:outer.zip!pkg.tgz` if `pkg.tgz` is npm-typed, even though
/// `outer.zip` is the nearer archive in the generic sense.
///
/// Returns the empty string when no ancestor -- nested, or the top-level
/// analyzed file itself -- is a package-ecosystem type; the caller falls
/// back to file-scope in that case, matching `parent_archive`'s contract.
///
/// `archive_contents` entries are looked up by their `path`, which uses the
/// same `!`-separated convention as `Evidence.location`
/// (`AnalysisReport.archive_contents`'s own doc comment).
pub(super) fn parent_package<'a>(
    location: &'a str,
    archive_contents: &[crate::types::ArchiveEntry],
    top_level_file_type: &str,
) -> &'a str {
    let Some(after_prefix) = location.strip_prefix("archive:") else {
        return "";
    };
    let entry_path = match after_prefix.find("::") {
        Some(idx) => &after_prefix[..idx],
        None => after_prefix,
    };
    // Walk the `!`-delimited ancestors from innermost to outermost.
    let mut end = entry_path.len();
    while let Some(bang_idx) = entry_path[..end].rfind('!') {
        let ancestor_path = &entry_path[..bang_idx];
        let is_package = archive_contents
            .iter()
            .find(|m| m.path == ancestor_path)
            .is_some_and(|m| is_package_label(&m.file_type));
        if is_package {
            return &location[.."archive:".len() + bang_idx];
        }
        end = bang_idx;
    }
    // No nested package-ecosystem ancestor found; a single-level entry
    // (e.g. scanning a bare .whl directly) keys off the analyzed file's own
    // type instead, since it never appears in `archive_contents` itself.
    if is_package_label(top_level_file_type) {
        return "archive:";
    }
    ""
}
