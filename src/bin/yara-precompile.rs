//! Offline YARA pre-compiler — peer to `yara-update`, run after it.
//!
//! Reads the trait rule sources (respecting `CLEAVE_TRAITS_DIR`, the same way
//! cleave does), classifies them per filetype, compiles each tier with the
//! exact `yara_x` version cleave links, and writes portable `<tier>.yrc` files
//! plus a `manifest.json` into the output directory (default
//! `third-party/compiled`, relative to the working directory).
//!
//! The `.yrc` hold WASM bytecode, not native code, so a single build is
//! loadable on every client architecture and OS — cleave loads them at runtime
//! with no in-process compilation. Because this binary is built from cleave's
//! own crate, the serialized format is guaranteed to match the cleave that will
//! load it (the only `.yrc` compatibility axis is the yara-x version).
//!
//! `--check` verifies an existing directory instead of writing one: it fails
//! unless the compiled rules are complete and built from the rule sources
//! currently on disk. That is the state the engine silently falls back from, so
//! checking it is what keeps a stale artifact from reaching clients.
//!
//! Usage: `yara-precompile [--check] [DIR]`  (default `third-party/compiled`)

#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut check = false;
    let mut dir = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--check" => check = true,
            "-h" | "--help" => {
                eprintln!("usage: yara-precompile [--check] [DIR]  (default third-party/compiled)");
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => {
                eprintln!("yara-precompile: unknown flag {other}");
                return ExitCode::FAILURE;
            }
            other => dir = Some(PathBuf::from(other)),
        }
    }
    let dir = dir.unwrap_or_else(|| PathBuf::from("third-party/compiled"));

    if check {
        return match cleave::check_precompiled_yara(&dir) {
            Ok(()) => {
                eprintln!("yara-precompile: {} is complete and current", dir.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("yara-precompile: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

    let started = std::time::Instant::now();
    match cleave::precompile_yara(&dir, true) {
        Ok((builtin, third_party)) => {
            eprintln!(
                "yara-precompile: compiled {builtin} built-in + {third_party} third-party rules -> {} ({} ms)",
                dir.display(),
                started.elapsed().as_millis(),
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("yara-precompile: {e:#}");
            ExitCode::FAILURE
        }
    }
}
