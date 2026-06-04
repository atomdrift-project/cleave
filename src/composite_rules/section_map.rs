//! Section mapping for binary files.
//!
//! Provides utilities for resolving section names and byte ranges
//! in ELF, Mach-O, and PE binaries. The section table is always
//! sourced from `filefacts::open`'s typed `Sections` view — cleave
//! never re-parses the file format.

use rustc_hash::FxHashMap;
use std::sync::{Arc, RwLock};

/// Information about a binary section.
#[derive(Debug, Clone)]
pub(crate) struct SectionInfo {
    /// Section name (e.g., ".text", "__TEXT,__text")
    pub name: String,
    /// Absolute start offset in file
    pub start: u64,
    /// Absolute end offset in file (exclusive)
    pub end: u64,
}

/// Section mapping for a binary file.
///
/// Used to resolve section constraints in trait conditions.
#[derive(Debug, Clone, Default)]
pub(crate) struct SectionMap {
    sections: Vec<SectionInfo>,
    file_size: u64,
    /// Cache for section bounds lookups (shared across clones)
    bounds_cache: Arc<RwLock<FxHashMap<String, Option<(u64, u64)>>>>,
}

impl SectionMap {
    /// Create an empty section map for non-binary files.
    #[must_use]
    pub(crate) fn empty(file_size: u64) -> Self {
        Self {
            sections: Vec::new(),
            file_size,
            bounds_cache: Arc::new(RwLock::new(FxHashMap::default())),
        }
    }

    /// Create a section map from cleave's report-side section list.
    #[must_use]
    pub(crate) fn from_report_sections(sections: &[crate::types::Section], file_size: u64) -> Self {
        let sections: Vec<SectionInfo> = sections
            .iter()
            .filter_map(|s| {
                let start = s.offset?;
                Some(SectionInfo {
                    name: s.name.clone(),
                    start,
                    end: start.saturating_add(s.size),
                })
            })
            .collect();
        Self {
            sections,
            file_size,
            bounds_cache: Arc::new(RwLock::new(FxHashMap::default())),
        }
    }

    /// Create a section map from a borrowed filefacts parse.
    #[must_use]
    pub(crate) fn from_filefacts(parsed: &filefacts::ParsedFile<'_>, file_size: u64) -> Self {
        let sections: Vec<SectionInfo> = parsed
            .sections()
            .iter()
            .map(|s| SectionInfo {
                name: s.name.clone(),
                start: s.file_offset,
                end: s.file_offset.saturating_add(s.file_size),
            })
            .collect();
        Self {
            sections,
            file_size,
            bounds_cache: Arc::new(RwLock::new(FxHashMap::default())),
        }
    }

    /// Create a section map by sourcing the section table from
    /// `filefacts::open`.
    ///
    /// Every binary format filefacts recognises (ELF, PE, Mach-O thin,
    /// Mach-O fat) surfaces its sections through `parsed.sections()`
    /// with `name`/`file_offset`/`file_size` fields already normalised.
    /// Files filefacts can't parse (unknown format, malformed magic)
    /// produce an empty section list, which becomes an empty
    /// `SectionMap` — the same behaviour the old goblin-fallback path
    /// produced.
    pub(crate) fn from_binary(binary_data: &[u8]) -> Self {
        let file_size = binary_data.len() as u64;
        let Ok(parsed) = filefacts::open(binary_data) else {
            return Self::empty(file_size);
        };
        let sections: Vec<SectionInfo> = parsed
            .sections()
            .iter()
            .map(|s| SectionInfo {
                name: s.name.clone(),
                start: s.file_offset,
                end: s.file_offset.saturating_add(s.file_size),
            })
            .collect();
        Self {
            sections,
            file_size,
            bounds_cache: Arc::new(RwLock::new(FxHashMap::default())),
        }
    }

    /// Returns true if this map contains any section information.
    #[must_use]
    pub(crate) fn has_sections(&self) -> bool {
        !self.sections.is_empty()
    }

    /// Returns a list of all section names in this map.
    #[must_use]
    pub(crate) fn section_names(&self) -> Vec<&str> {
        self.sections.iter().map(|s| s.name.as_str()).collect()
    }

    /// Checks if a section name matches a required section name (exact or fuzzy).
    #[must_use]
    pub(crate) fn section_matches(actual: &str, required: &str) -> bool {
        if actual == required {
            return true;
        }

        // Bare PE/ELF name → dotted form: `rsrc` matches `.rsrc`, `idata` matches
        // `.idata`, etc. The enumerated table below only covers text/data/rdata
        // (plus their Mach-O segment,section forms); this general rule lets any
        // section be referenced without its leading dot.
        if bare_matches_dotted(actual, required) {
            return true;
        }

        if macho_section_component_matches(actual, required) {
            return true;
        }

        if is_fuzzy_name(required) {
            for pattern in fuzzy_section_patterns(required) {
                if actual == *pattern {
                    return true;
                }
            }
        }

        false
    }

    /// Get bounds for a section by name (exact or fuzzy match).
    ///
    /// Fuzzy matching allows rule authors to write `.text` and it will match
    /// `__TEXT,__text` on Mach-O or `.text` on ELF/PE.
    #[must_use]
    pub(crate) fn bounds(&self, name: &str) -> Option<(u64, u64)> {
        // Check cache first (read lock)
        if let Ok(cache) = self.bounds_cache.read()
            && let Some(cached) = cache.get(name)
        {
            return *cached;
        }

        // SLOW PATH: Iterate through sections
        let result = self.compute_bounds(name);

        // Update cache (write lock)
        if let Ok(mut cache) = self.bounds_cache.write() {
            cache.insert(name.to_string(), result);
        }

        result
    }

    /// Internal logic for computing section bounds without caching
    fn compute_bounds(&self, name: &str) -> Option<(u64, u64)> {
        // Try exact match first
        for section in &self.sections {
            if section.name == name {
                return Some((section.start, section.end));
            }
        }

        // Bare PE/ELF name → dotted form (e.g. `rsrc` -> `.rsrc`).
        for section in &self.sections {
            if bare_matches_dotted(&section.name, name) {
                return Some((section.start, section.end));
            }
        }

        // Bare Mach-O section component (e.g. `__const`/`const` -> `__TEXT,__const`).
        for section in &self.sections {
            if macho_section_component_matches(&section.name, name) {
                return Some((section.start, section.end));
            }
        }

        // Try fuzzy match if name doesn't look exact
        if is_fuzzy_name(name) {
            let patterns = fuzzy_section_patterns(name);
            for pattern in patterns {
                for section in &self.sections {
                    if section.name == *pattern {
                        return Some((section.start, section.end));
                    }
                }
            }
        }

        None
    }

    /// Resolve a trait location constraint into a byte range.
    ///
    /// Returns None if the constraints cannot be resolved or are invalid.
    #[must_use]
    pub(crate) fn resolve_range(
        &self,
        section: Option<&str>,
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> Option<(u64, u64)> {
        if section.is_none() && (section_offset.is_some() || section_offset_range.is_some()) {
            return None;
        }

        let (base_start, base_end) = if let Some(sec_name) = section {
            self.bounds(sec_name)?
        } else {
            (0, self.file_size)
        };

        if let Some(off) = offset {
            let start = resolve_offset_start(off, base_start, base_end)?;
            return Some((start, start + 1));
        }

        if let Some(sec_off) = section_offset {
            let start = resolve_offset_start(sec_off, base_start, base_end)?;
            return Some((start, start + 1));
        }

        let (rel_start, rel_end) = if let Some(range) = offset_range {
            range
        } else if let Some(sec_range) = section_offset_range {
            sec_range
        } else if section.is_some() {
            // Section only: return full section range
            return Some((base_start, base_end));
        } else {
            // No constraints: return full file range
            return Some((0, self.file_size));
        };

        let start = resolve_offset_start(rel_start, base_start, base_end)?;
        let end = match rel_end {
            Some(e) => resolve_offset_end(e, base_start, base_end)?,
            None => base_end,
        };

        if start >= end {
            return None;
        }

        Some((start, end))
    }

    /// Internal helper for tests to build a map from tuples
    #[cfg(test)]
    pub(crate) fn from_sections_and_size(sections: Vec<(&str, u64, u64)>, file_size: u64) -> Self {
        Self {
            sections: sections
                .into_iter()
                .map(|(name, start, end)| SectionInfo {
                    name: name.to_string(),
                    start,
                    end,
                })
                .collect(),
            file_size,
            bounds_cache: Arc::new(RwLock::new(FxHashMap::default())),
        }
    }
}

/// Resolve a potentially negative offset to an absolute position.
fn resolve_offset_start(offset: i64, base_start: u64, base_end: u64) -> Option<u64> {
    let base_size = base_end.saturating_sub(base_start);

    let abs_rel_offset = if offset >= 0 {
        offset as u64
    } else {
        base_size.checked_sub(offset.unsigned_abs())?
    };

    if abs_rel_offset >= base_size {
        return None;
    }

    Some(base_start + abs_rel_offset)
}

/// Resolve an inclusive start/exclusive end bound for a range.
fn resolve_offset_end(offset: i64, base_start: u64, base_end: u64) -> Option<u64> {
    let base_size = base_end.saturating_sub(base_start);

    let abs_rel_offset = if offset >= 0 {
        offset as u64
    } else {
        base_size.checked_sub(offset.unsigned_abs())?
    };

    if abs_rel_offset > base_size {
        return None;
    }

    Some(base_start + abs_rel_offset)
}

/// Returns true if the section name looks like a generic name that should be fuzzy matched.
/// Accepts both dotted (`.text`) and un-dotted (`text`) forms — the un-dotted form is
/// common in hand-authored rules and maps to the same set of platform-specific sections.
/// True when `required` is a bare section name (no leading `.`/`_`, no `,`) and
/// `actual` is exactly its dotted PE/ELF form — e.g. `bare_matches_dotted(".rsrc",
/// "rsrc")`. Lets authors write `section: rsrc` and match `.rsrc` without having
/// to enumerate every section in the fuzzy table.
fn bare_matches_dotted(actual: &str, required: &str) -> bool {
    !required.is_empty()
        && !required.starts_with('.')
        && !required.starts_with('_')
        && !required.contains(',')
        && actual.strip_prefix('.') == Some(required)
}

/// Mach-O sections are reported as `SEGMENT,SECTION` (e.g. `__TEXT,__const`,
/// `__TEXT,__cstring`). Let authors reference one by its bare section component
/// — with or without the leading `__` — so `section: __const`, `section: const`,
/// `section: __cstring`, and `section: cstring` all match `__TEXT,__const` /
/// `__TEXT,__cstring`. The segment prefix rarely distinguishes intent, so a bare
/// reference matches that section in any segment. This mirrors how a user reads
/// the name out of `cleave sections` and drops the `SEGMENT,` qualifier.
fn macho_section_component_matches(actual: &str, required: &str) -> bool {
    if required.is_empty() || required.contains(',') {
        return false;
    }
    match actual.split_once(',') {
        Some((_segment, section)) => {
            section == required || section.strip_prefix("__") == Some(required)
        }
        None => false,
    }
}

fn is_fuzzy_name(name: &str) -> bool {
    matches!(
        name,
        ".text" | ".data" | ".rdata" | ".rodata" | "text" | "data" | "rdata" | "rodata"
    )
}

/// Returns a list of platform-specific section names for a generic name.
fn fuzzy_section_patterns(name: &str) -> &'static [&'static str] {
    match name {
        ".text" | "text" => &[".text", "__TEXT,__text"],
        ".data" | "data" => &[".data", "__DATA,__data"],
        ".rdata" | "rdata" | ".rodata" | "rodata" => {
            &[".rdata", ".rodata", "__TEXT,__const", "__DATA,__const"]
        }
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_map() -> SectionMap {
        SectionMap::from_sections_and_size(
            vec![(".text", 0x1000, 0x2000), (".data", 0x2000, 0x3000)],
            0x4000,
        )
    }

    #[test]
    fn test_bounds_exact() {
        let map = make_test_map();
        assert_eq!(map.bounds(".text"), Some((0x1000, 0x2000)));
        assert_eq!(map.bounds(".data"), Some((0x2000, 0x3000)));
    }

    #[test]
    fn test_bounds_fuzzy_macho() {
        let map = SectionMap::from_sections_and_size(vec![("__TEXT,__text", 0x100, 0x200)], 0x1000);
        assert_eq!(map.bounds(".text"), Some((0x100, 0x200)));
    }

    #[test]
    fn test_bare_macho_section_component_matches() {
        // Mach-O sections are `SEGMENT,SECTION`; a bare section component should
        // resolve, with or without the leading `__`.
        let map = SectionMap::from_sections_and_size(
            vec![
                ("__TEXT,__text", 0x1000, 0x2000),
                ("__TEXT,__const", 0x2000, 0x2800),
                ("__TEXT,__cstring", 0x2800, 0x3000),
            ],
            0x4000,
        );
        assert_eq!(map.bounds("__const"), Some((0x2000, 0x2800)));
        assert_eq!(map.bounds("const"), Some((0x2000, 0x2800)));
        assert_eq!(map.bounds("__cstring"), Some((0x2800, 0x3000)));
        assert_eq!(map.bounds("cstring"), Some((0x2800, 0x3000)));
        // Full `SEGMENT,SECTION` and the fuzzy `rdata` alias still work.
        assert_eq!(map.bounds("__TEXT,__const"), Some((0x2000, 0x2800)));
        assert_eq!(map.bounds("rdata"), Some((0x2000, 0x2800)));
        assert!(SectionMap::section_matches("__TEXT,__const", "__const"));
        assert!(SectionMap::section_matches("__TEXT,__const", "const"));
        // A non-matching component must not resolve.
        assert_eq!(map.bounds("__data"), None);
        assert!(!SectionMap::section_matches("__TEXT,__const", "text"));
    }

    #[test]
    fn test_bare_name_matches_dotted_pe_section() {
        // A bare PE/ELF section name (no leading dot) must match its dotted form
        // for any section, not just the enumerated text/data/rdata set.
        let map = SectionMap::from_sections_and_size(
            vec![(".rsrc", 0x5000, 0x6000), (".idata", 0x6000, 0x6100)],
            0x8000,
        );
        assert_eq!(map.bounds("rsrc"), Some((0x5000, 0x6000)));
        assert_eq!(map.bounds("idata"), Some((0x6000, 0x6100)));
        assert!(SectionMap::section_matches(".rsrc", "rsrc"));
        assert!(SectionMap::section_matches(".idata", "idata"));
        // Negative: must be the exact dotted form, not a prefix or unrelated name.
        assert!(!SectionMap::section_matches(".rsrc2", "rsrc"));
        assert!(!SectionMap::section_matches(".text", "rsrc"));
        assert_eq!(map.bounds("nope"), None);
    }

    #[test]
    fn test_resolve_full_file() {
        let map = make_test_map();
        assert_eq!(
            map.resolve_range(None, None, None, None, None),
            Some((0, 0x4000))
        );
    }

    #[test]
    fn test_resolve_section_only() {
        let map = make_test_map();
        assert_eq!(
            map.resolve_range(Some(".text"), None, None, None, None),
            Some((0x1000, 0x2000))
        );
    }

    #[test]
    fn test_resolve_absolute_offset() {
        let map = make_test_map();
        assert_eq!(
            map.resolve_range(None, Some(0x100), None, None, None),
            Some((0x100, 0x101))
        );
    }

    #[test]
    fn test_resolve_negative_offset() {
        let map = make_test_map();
        // last byte of file
        assert_eq!(
            map.resolve_range(None, Some(-1), None, None, None),
            Some((0x3fff, 0x4000))
        );
    }

    #[test]
    fn test_resolve_section_offset() {
        let map = make_test_map();
        assert_eq!(
            map.resolve_range(Some(".text"), None, None, Some(0x10), None),
            Some((0x1010, 0x1011))
        );
    }

    #[test]
    fn test_resolve_section_negative_offset() {
        let map = make_test_map();
        // last byte of .text
        assert_eq!(
            map.resolve_range(Some(".text"), None, None, Some(-1), None),
            Some((0x1fff, 0x2000))
        );
    }

    #[test]
    fn test_section_offset_without_section_fails() {
        let map = make_test_map();
        // section_offset without section should fail
        assert_eq!(map.resolve_range(None, None, None, Some(0x100), None), None);
    }
}
