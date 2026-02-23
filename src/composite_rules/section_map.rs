//! Section mapping for binary files.
//!
//! Provides utilities for resolving section names and byte ranges
//! in ELF, Mach-O, and PE binaries.

use goblin::elf::Elf;
use goblin::mach::MachO;
use goblin::pe::PE;

/// Information about a binary section.
#[derive(Debug, Clone)]
pub(crate) struct SectionInfo {
    /// Section name (e.g., ".text", "__TEXT,__text")
    pub name: String,
    /// File offset where section starts
    pub start: u64,
    /// File offset where section ends (start + size)
    pub end: u64,
}

/// Map of sections in a binary file.
///
/// Used to resolve section constraints in trait conditions.
#[derive(Debug, Clone, Default)]
pub(crate) struct SectionMap {
    sections: Vec<SectionInfo>,
    file_size: u64,
}

impl SectionMap {
    /// Create an empty section map for non-binary files.
    #[must_use]
    pub(crate) fn empty(file_size: u64) -> Self {
        Self {
            sections: Vec::new(),
            file_size,
        }
    }

    /// Create a section map from an ELF binary.
    #[must_use]
    pub(crate) fn from_elf<'a>(elf: &Elf<'a>, file_size: u64) -> Self {
        let mut sections = Vec::new();

        for sh in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                if !name.is_empty() && sh.sh_size > 0 {
                    sections.push(SectionInfo {
                        name: name.to_string(),
                        start: sh.sh_offset,
                        end: sh.sh_offset.saturating_add(sh.sh_size),
                    });
                }
            }
        }

        Self {
            sections,
            file_size,
        }
    }

    /// Create a section map from a Mach-O binary.
    #[must_use]
    pub(crate) fn from_macho<'a>(macho: &MachO<'a>, file_size: u64) -> Self {
        let mut sections = Vec::new();

        for segment in &macho.segments {
            for (section, _data) in segment.into_iter().flatten() {
                let section_start = u64::from(section.offset);
                let section_size = section.size;
                if section_size > 0 {
                    // Store both short name and segment,section format
                    let short_name = section.name().unwrap_or("(unknown)").to_string();
                    let seg_name = segment.name().unwrap_or("(unknown)");
                    let full_name = format!("{},{}", seg_name, short_name);

                    sections.push(SectionInfo {
                        name: short_name,
                        start: section_start,
                        end: section_start.saturating_add(section_size),
                    });

                    // Also add the full segment,section name for exact matching
                    sections.push(SectionInfo {
                        name: full_name,
                        start: section_start,
                        end: section_start.saturating_add(section_size),
                    });
                }
            }
        }

        Self {
            sections,
            file_size,
        }
    }

    /// Create a section map from a PE binary.
    #[must_use]
    pub(crate) fn from_pe<'a>(pe: &PE<'a>, file_size: u64) -> Self {
        let mut sections = Vec::new();

        for section in &pe.sections {
            let section_start = u64::from(section.pointer_to_raw_data);
            let section_size = u64::from(section.size_of_raw_data);
            if section_size > 0 {
                let name = String::from_utf8_lossy(&section.name)
                    .trim_end_matches('\0')
                    .to_string();
                if !name.is_empty() {
                    sections.push(SectionInfo {
                        name,
                        start: section_start,
                        end: section_start.saturating_add(section_size),
                    });
                }
            }
        }

        Self {
            sections,
            file_size,
        }
    }

    /// Create a section map by auto-detecting binary format.
    ///
    /// Tries to parse as ELF, Mach-O, or PE. Returns an empty map for
    /// unrecognized formats (source files, etc.)
    #[must_use]
    pub(crate) fn from_binary(data: &[u8]) -> Self {
        let file_size = data.len() as u64;

        // Try ELF first (most common for analysis)
        if let Ok(elf) = Elf::parse(data) {
            return Self::from_elf(&elf, file_size);
        }

        // Try Mach-O
        if let Ok(macho) = MachO::parse(data, 0) {
            return Self::from_macho(&macho, file_size);
        }

        // Try PE
        if let Ok(pe) = PE::parse(data) {
            return Self::from_pe(&pe, file_size);
        }

        // Not a recognized binary format
        Self::empty(file_size)
    }

    /// Get the section containing a given file offset.
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn section_for_offset(&self, offset: u64) -> Option<&str> {
        for section in &self.sections {
            if offset >= section.start && offset < section.end {
                return Some(&section.name);
            }
        }
        None
    }

    /// Get bounds for a section by name (exact or fuzzy match).
    ///
    /// Fuzzy names like "text" match platform-specific variants.
    /// Exact names (starting with "." or "__") match exactly.
    #[must_use]
    pub(crate) fn bounds(&self, name: &str) -> Option<(u64, u64)> {
        // Try exact match first
        for section in &self.sections {
            if section.name == name {
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

    /// Check if a section name matches a pattern (exact or fuzzy).
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn section_matches(actual: &str, pattern: &str) -> bool {
        // Exact match
        if actual == pattern {
            return true;
        }

        // Fuzzy match
        if is_fuzzy_name(pattern) {
            let patterns = fuzzy_section_patterns(pattern);
            for p in patterns {
                if actual == *p {
                    return true;
                }
            }
        }

        false
    }

    /// Resolve effective byte range for filtering.
    ///
    /// # Arguments
    /// * `section` - Section name constraint (exact or fuzzy)
    /// * `offset` - Absolute file position
    /// * `offset_range` - Absolute byte range
    /// * `section_offset` - Offset relative to section start
    /// * `section_offset_range` - Range relative to section start
    ///
    /// # Returns
    /// `(start, end)` as absolute file offsets, or `None` if:
    /// - Section specified but not found
    /// - Resulting range is empty or invalid
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) fn resolve_range(
        &self,
        section: Option<&str>,
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> Option<(u64, u64)> {
        // Start with full file range or section bounds
        let (mut base_start, mut base_end) = if let Some(sec_name) = section {
            self.bounds(sec_name)?
        } else {
            (0, self.file_size)
        };

        // Apply absolute offset (takes precedence)
        if let Some(off) = offset {
            let abs_off = resolve_offset(off, self.file_size);
            // For absolute offset with section, must be within section
            if section.is_some() && (abs_off < base_start || abs_off >= base_end) {
                return None;
            }
            return Some((abs_off, abs_off.saturating_add(1)));
        }

        // Apply absolute offset range
        if let Some((start, end)) = offset_range {
            let abs_start = resolve_offset(start, self.file_size);
            let abs_end = end
                .map(|e| resolve_offset(e, self.file_size))
                .unwrap_or(self.file_size);

            // Intersect with section bounds if section specified
            base_start = base_start.max(abs_start);
            base_end = base_end.min(abs_end);
        }

        // Apply section-relative offset
        if let Some(sec_off) = section_offset {
            section?; // section_offset requires section
            let section_size = base_end - base_start;
            let abs_off = base_start + resolve_offset(sec_off, section_size);
            if abs_off < base_start || abs_off >= base_end {
                return None;
            }
            return Some((abs_off, abs_off.saturating_add(1)));
        }

        // Apply section-relative offset range
        if let Some((start, end)) = section_offset_range {
            section?; // section_offset_range requires section
            let section_size = base_end - base_start;
            let rel_start = resolve_offset(start, section_size);
            let rel_end = end
                .map(|e| resolve_offset(e, section_size))
                .unwrap_or(section_size);

            base_start += rel_start;
            base_end = base_start + rel_end.saturating_sub(rel_start);
        }

        // Validate range
        if base_start >= base_end {
            return None;
        }

        Some((base_start, base_end.min(self.file_size)))
    }

    /// Get all unique section names.
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn section_names(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        let mut names = Vec::new();
        for section in &self.sections {
            if seen.insert(&section.name) {
                names.push(section.name.as_str());
            }
        }
        names
    }

    /// Check if this map has any sections (i.e., is a binary file).
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn has_sections(&self) -> bool {
        !self.sections.is_empty()
    }
}

/// Resolve a potentially negative offset to an absolute position.
///
/// Negative offsets are relative to the end of the range.
fn resolve_offset(offset: i64, range_size: u64) -> u64 {
    if offset >= 0 {
        offset as u64
    } else {
        // Negative: from end
        range_size.saturating_sub((-offset) as u64)
    }
}

/// Check if name is a fuzzy pattern (no leading . or __).
fn is_fuzzy_name(name: &str) -> bool {
    !name.starts_with('.') && !name.starts_with("__")
}

/// Map fuzzy section names to platform-specific patterns.
fn fuzzy_section_patterns(name: &str) -> &'static [&'static str] {
    match name {
        "text" => &[".text", "__text", "__TEXT,__text"],
        "data" => &[".data", "__data", "__DATA,__data"],
        "rodata" => &[
            ".rodata",
            ".rdata",
            "__const",
            "__DATA,__const",
            "__TEXT,__const",
        ],
        "bss" => &[".bss", "__bss", "__DATA,__bss"],
        _ => &[], // not a fuzzy name, use exact match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_map() -> SectionMap {
        SectionMap {
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    start: 0x1000,
                    end: 0x2000,
                },
                SectionInfo {
                    name: ".data".to_string(),
                    start: 0x2000,
                    end: 0x3000,
                },
                SectionInfo {
                    name: ".rodata".to_string(),
                    start: 0x3000,
                    end: 0x4000,
                },
            ],
            file_size: 0x5000,
        }
    }

    #[test]
    fn test_bounds_exact() {
        let map = make_test_map();
        assert_eq!(map.bounds(".text"), Some((0x1000, 0x2000)));
        assert_eq!(map.bounds(".data"), Some((0x2000, 0x3000)));
        assert_eq!(map.bounds(".nonexistent"), None);
    }

    #[test]
    fn test_bounds_fuzzy() {
        let map = make_test_map();
        assert_eq!(map.bounds("text"), Some((0x1000, 0x2000)));
        assert_eq!(map.bounds("data"), Some((0x2000, 0x3000)));
        assert_eq!(map.bounds("rodata"), Some((0x3000, 0x4000)));
    }

    #[test]
    fn test_section_matches() {
        assert!(SectionMap::section_matches(".text", ".text"));
        assert!(SectionMap::section_matches(".text", "text"));
        assert!(SectionMap::section_matches("__text", "text"));
        assert!(!SectionMap::section_matches(".data", "text"));
    }

    #[test]
    fn test_resolve_range_no_constraints() {
        let map = make_test_map();
        assert_eq!(
            map.resolve_range(None, None, None, None, None),
            Some((0, 0x5000))
        );
    }

    #[test]
    fn test_resolve_range_section_only() {
        let map = make_test_map();
        assert_eq!(
            map.resolve_range(Some(".text"), None, None, None, None),
            Some((0x1000, 0x2000))
        );
        assert_eq!(
            map.resolve_range(Some("text"), None, None, None, None),
            Some((0x1000, 0x2000))
        );
    }

    #[test]
    fn test_resolve_range_absolute_offset() {
        let map = make_test_map();
        // Absolute offset without section
        assert_eq!(
            map.resolve_range(None, Some(0x100), None, None, None),
            Some((0x100, 0x101))
        );
        // Negative offset (from end)
        assert_eq!(
            map.resolve_range(None, Some(-0x100), None, None, None),
            Some((0x4f00, 0x4f01))
        );
    }

    #[test]
    fn test_resolve_range_absolute_range() {
        let map = make_test_map();
        assert_eq!(
            map.resolve_range(None, None, Some((0, Some(0x1000))), None, None),
            Some((0, 0x1000))
        );
        // Negative end (last 1024 bytes)
        assert_eq!(
            map.resolve_range(None, None, Some((-0x400, None)), None, None),
            Some((0x4c00, 0x5000))
        );
    }

    #[test]
    fn test_resolve_range_section_with_relative_offset() {
        let map = make_test_map();
        // Section-relative offset
        assert_eq!(
            map.resolve_range(Some(".text"), None, None, Some(0x100), None),
            Some((0x1100, 0x1101))
        );
        // Section-relative negative offset
        assert_eq!(
            map.resolve_range(Some(".text"), None, None, Some(-0x100), None),
            Some((0x1f00, 0x1f01))
        );
    }

    #[test]
    fn test_resolve_range_section_with_relative_range() {
        let map = make_test_map();
        // First 0x100 bytes of .text
        assert_eq!(
            map.resolve_range(Some(".text"), None, None, None, Some((0, Some(0x100)))),
            Some((0x1000, 0x1100))
        );
        // Last 0x100 bytes of .text
        assert_eq!(
            map.resolve_range(Some(".text"), None, None, None, Some((-0x100, None))),
            Some((0x1f00, 0x2000))
        );
    }

    #[test]
    fn test_resolve_range_section_not_found() {
        let map = make_test_map();
        assert_eq!(
            map.resolve_range(Some(".nonexistent"), None, None, None, None),
            None
        );
    }

    #[test]
    fn test_section_offset_without_section_fails() {
        let map = make_test_map();
        // section_offset without section should fail
        assert_eq!(map.resolve_range(None, None, None, Some(0x100), None), None);
    }
}
