//! Post-analysis check: detect when multiple traits match the same offset in testdata files.
//!
//! Runs cleave analysis on files in testdata/ and groups findings by (file, offset).
//! Flags when multiple traits fire on identical byte ranges — a semantic overlap the
//! static validator can't detect (e.g., `\bfoo\b` and `foo` both matching "foo").

use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Result of a testdata overlap check
#[derive(Debug, Clone)]
pub struct OverlapFinding {
    /// File path (relative to testdata root)
    pub file_path: String,
    /// Byte range of the overlap (start..end)
    pub range: (u64, u64),
    /// Trait IDs whose ranges overlap here
    pub trait_ids: Vec<String>,
    /// Number of distinct traits with overlapping ranges
    pub overlap_count: usize,
}

/// Check testdata files for overlapping trait matches
pub fn check_testdata_overlaps(
    testdata_dir: &Path,
    options: &cleave::AnalysisOptions,
) -> Result<Vec<OverlapFinding>> {
    let mut overlaps = Vec::new();

    // Find all files in testdata/ (recursively)
    let testdata_files = find_testdata_files(testdata_dir)?;
    if testdata_files.is_empty() {
        eprintln!("No testdata files found in {:?}", testdata_dir);
        return Ok(overlaps);
    }

    eprintln!(
        "Checking {} testdata file(s) for overlapping traits...",
        testdata_files.len()
    );

    for file_path in testdata_files {
        let relative_path = file_path
            .strip_prefix(testdata_dir)
            .unwrap_or(&file_path)
            .to_string_lossy()
            .to_string();

        match analyze_file_for_overlaps(&file_path, options) {
            Ok(file_overlaps) => {
                overlaps.extend(file_overlaps.into_iter().map(|(range, trait_ids)| {
                    OverlapFinding {
                        file_path: relative_path.clone(),
                        range,
                        overlap_count: trait_ids.len(),
                        trait_ids,
                    }
                }));
            }
            Err(e) => {
                eprintln!("  Warning: failed to analyze {}: {}", relative_path, e);
            }
        }
    }

    // Sort by file, then by range start for consistent output
    overlaps.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.range.0.cmp(&b.range.0))
    });

    Ok(overlaps)
}

/// Range with associated trait ID
#[derive(Debug, Clone)]
struct TraitRange {
    offset: u64,
    length: u64,
    trait_id: String,
}

/// Analyze a single file and return overlapping byte ranges
fn analyze_file_for_overlaps(
    file_path: &Path,
    options: &cleave::AnalysisOptions,
) -> Result<BTreeMap<(u64, u64), Vec<String>>> {
    let data = std::fs::read(file_path)?;
    let filename = file_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let report = cleave::analyze_bytes(&data, &filename, options)?;

    // Collect all trait ranges (offset, length, trait_id)
    let mut trait_ranges: Vec<TraitRange> = Vec::new();

    for file_analysis in &report.files {
        for finding in &file_analysis.findings {
            // Skip composite rules — we want atomic trait overlaps
            if finding.id.contains("::") {
                let (dir, _) = finding.id.rsplit_once("::").unwrap_or(("", &finding.id));
                // Skip if it's a composite (more than 2-3 levels deep typically)
                if dir.matches("::").count() > 2 {
                    continue;
                }
            }

            // Collect all ranges where this trait fired
            for evidence in &finding.evidence {
                // Estimate range length: for now, use evidence value length as a proxy
                // (in reality, evidence might be a substring of the match)
                let length = evidence.value.len() as u64;
                for &offset in &evidence.offsets {
                    trait_ranges.push(TraitRange {
                        offset,
                        length,
                        trait_id: finding.id.clone(),
                    });
                }
            }
        }
    }

    // Find overlapping ranges
    let mut overlaps: BTreeMap<(u64, u64), BTreeSet<String>> = BTreeMap::new();

    for i in 0..trait_ranges.len() {
        for j in (i + 1)..trait_ranges.len() {
            let a = &trait_ranges[i];
            let b = &trait_ranges[j];

            // Check if ranges overlap: [a.start, a.end) and [b.start, b.end)
            let a_end = a.offset + a.length;
            let b_end = b.offset + b.length;

            let overlap_start = a.offset.max(b.offset);
            let overlap_end = a_end.min(b_end);

            if overlap_start < overlap_end {
                // Ranges overlap
                overlaps
                    .entry((overlap_start, overlap_end))
                    .or_default()
                    .insert(a.trait_id.clone());
                overlaps
                    .entry((overlap_start, overlap_end))
                    .or_default()
                    .insert(b.trait_id.clone());
            }
        }
    }

    // Convert to final format
    let result = overlaps
        .into_iter()
        .map(|(range, traits)| (range, traits.into_iter().collect::<Vec<_>>()))
        .collect();

    Ok(result)
}

/// Find all files in testdata/ recursively
fn find_testdata_files(testdata_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if !testdata_dir.exists() {
        // Testdata dir doesn't exist — that's OK, just return empty
        return Ok(files);
    }

    walkdir::WalkDir::new(testdata_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_file())
        .for_each(|entry| {
            files.push(entry.path().to_path_buf());
        });

    Ok(files)
}

/// Format overlap findings for display
pub fn format_overlaps(overlaps: &[OverlapFinding]) -> String {
    if overlaps.is_empty() {
        return "✓ No overlapping trait ranges found in testdata".to_string();
    }

    let mut output = format!(
        "⚠ Found {} byte range(s) with overlapping traits:\n",
        overlaps.len()
    );

    for overlap in overlaps {
        output.push_str(&format!(
            "  {}: bytes [{}, {}) → {} traits: {}\n",
            overlap.file_path,
            overlap.range.0,
            overlap.range.1,
            overlap.overlap_count,
            overlap.trait_ids.join(", ")
        ));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlap_finding_sorting() {
        let mut overlaps = [
            OverlapFinding {
                file_path: "b.txt".to_string(),
                range: (100, 110),
                trait_ids: vec!["a".to_string(), "b".to_string()],
                overlap_count: 2,
            },
            OverlapFinding {
                file_path: "a.txt".to_string(),
                range: (200, 210),
                trait_ids: vec!["x".to_string(), "y".to_string()],
                overlap_count: 2,
            },
            OverlapFinding {
                file_path: "a.txt".to_string(),
                range: (100, 110),
                trait_ids: vec!["x".to_string(), "y".to_string()],
                overlap_count: 2,
            },
        ]
        .to_vec();

        overlaps.sort_by(|a, b| {
            a.file_path
                .cmp(&b.file_path)
                .then(a.range.0.cmp(&b.range.0))
        });

        assert_eq!(overlaps[0].file_path, "a.txt");
        assert_eq!(overlaps[0].range, (100, 110));
        assert_eq!(overlaps[1].file_path, "a.txt");
        assert_eq!(overlaps[1].range, (200, 210));
    }

    #[test]
    fn test_format_overlaps_empty() {
        let overlaps = vec![];
        assert!(format_overlaps(&overlaps).contains("No overlapping trait ranges"));
    }

    #[test]
    fn test_format_overlaps_with_findings() {
        let overlaps = vec![OverlapFinding {
            file_path: "test.zip".to_string(),
            range: (512, 520),
            trait_ids: vec!["trait_a".to_string(), "trait_b".to_string()],
            overlap_count: 2,
        }];

        let output = format_overlaps(&overlaps);
        assert!(output.contains("test.zip"));
        assert!(output.contains("512"));
        assert!(output.contains("520"));
        assert!(output.contains("trait_a"));
        assert!(output.contains("trait_b"));
    }
}
