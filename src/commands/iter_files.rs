//! `cleave iter-files` — enumerate recognized files for downstream pipelines.
//!
//! Walks the given targets and emits one JSONL record per file that cleave
//! considers a recognized program file. The output is intentionally minimal
//! (`{path, type, sz}`): callers like hopper own their own hashing and
//! caching, so they only need to know *which* files exist and what cleave
//! would classify them as.
//!
//! No archive descent in v1. Top-level archives are reported (so the caller
//! can submit them for analysis), but their contents are not enumerated here
//! — that work happens during full analysis and is split out by the caller
//! (see hopper's ExplodeArchiveMembers).

use crate::analyzers::{detect_file_type_from_data, is_analyzable, FileTypeExt};
use crate::file_io;
use anyhow::Result;
use serde::Serialize;
use std::io::{BufWriter, Write};
use std::path::Path;
use walkdir::WalkDir;

/// One JSONL record emitted by `cleave iter-files`.
#[derive(Serialize)]
struct IterFilesEntry<'a> {
    path: &'a str,
    #[serde(rename = "type")]
    file_type: &'a str,
    sz: u64,
}

/// Configuration for `cleave iter-files`.
#[derive(Debug)]
pub struct IterFilesConfig<'a> {
    /// File or directory targets to enumerate.
    pub targets: &'a [String],
    /// Maximum file size in bytes to consider; 0 means no limit.
    pub max_file_size: u64,
}

/// Run `cleave iter-files` against the configured targets.
///
/// Walks each target (skipping `.git` directories), classifies files via the
/// same magic-byte recognizer used during analysis, and writes a JSONL line
/// for every file whose detected type is a recognized program type. Files
/// larger than `max_file_size` (when nonzero) are skipped. Per-file errors
/// are logged at debug level and otherwise ignored.
pub fn run(config: &IterFilesConfig<'_>) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for target in config.targets {
        let path = Path::new(target.as_str());
        if !path.exists() {
            anyhow::bail!("Path does not exist: {}", target);
        }
        if path.is_dir() {
            walk_directory(path, config, &mut out);
        } else if path.is_file() {
            if let Err(e) = list_file(path, config, &mut out) {
                tracing::debug!(path = %path.display(), error = %e, "list_file failed");
            }
        }
    }
    out.flush()?;
    Ok(())
}

fn walk_directory<W: Write>(root: &Path, config: &IterFilesConfig<'_>, out: &mut W) {
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !e.file_name().to_string_lossy().starts_with(".git"))
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if let Err(e) = list_file(path, config, out) {
            tracing::debug!(path = %path.display(), error = %e, "list_file failed");
        }
    }
}

fn list_file<W: Write>(path: &Path, config: &IterFilesConfig<'_>, out: &mut W) -> Result<()> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    if config.max_file_size > 0 && size > config.max_file_size {
        return Ok(());
    }

    let file_data = file_io::read_file_smart(path)?;
    let file_type = detect_file_type_from_data(path, file_data.as_slice());
    if !is_analyzable(path, &file_type) {
        return Ok(());
    }

    let path_str = path.display().to_string();
    let type_str = file_type.report_file_type();
    let entry = IterFilesEntry {
        path: &path_str,
        file_type: &type_str,
        sz: size,
    };
    serde_json::to_writer(&mut *out, &entry)?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn lists_recognized_files_skips_unknown() {
        let dir = tempfile::tempdir().unwrap();

        // Recognized: shell script (magic bytes via shebang).
        let sh_path = dir.path().join("hello.sh");
        let mut f = std::fs::File::create(&sh_path).unwrap();
        f.write_all(b"#!/bin/sh\necho hello\n").unwrap();

        // Unknown: a plain README that cleave should not classify as a program.
        let readme = dir.path().join("README");
        std::fs::write(&readme, b"hi\n").unwrap();

        let mut buf: Vec<u8> = Vec::new();
        let targets = vec![dir.path().display().to_string()];
        {
            let config = IterFilesConfig {
                targets: &targets,
                max_file_size: 0,
            };
            // Run the inner walker directly so the test doesn't need stdout.
            walk_directory(dir.path(), &config, &mut buf);
        }

        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("hello.sh"),
            "expected hello.sh in output, got: {out}"
        );
        assert!(
            !out.contains("README"),
            "README should not appear in output: {out}"
        );

        // Each line should parse as JSON with the expected fields.
        for line in out.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.get("path").is_some());
            assert!(v.get("type").is_some());
            assert!(v.get("sz").is_some());
        }
    }

    #[test]
    fn respects_max_file_size() {
        let dir = tempfile::tempdir().unwrap();
        let sh_path = dir.path().join("big.sh");
        let mut f = std::fs::File::create(&sh_path).unwrap();
        f.write_all(b"#!/bin/sh\n").unwrap();
        f.write_all(&vec![b'x'; 1024]).unwrap();

        let mut buf: Vec<u8> = Vec::new();
        let targets = vec![dir.path().display().to_string()];
        let config = IterFilesConfig {
            targets: &targets,
            max_file_size: 100, // smaller than the file
        };
        walk_directory(dir.path(), &config, &mut buf);
        assert!(
            buf.is_empty(),
            "expected no output, got: {:?}",
            String::from_utf8_lossy(&buf)
        );
    }
}
