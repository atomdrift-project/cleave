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
//! Usage: `yara-precompile [OUT_DIR]`  (default `third-party/compiled`)

#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let out_dir = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("third-party/compiled"), PathBuf::from);

    let started = std::time::Instant::now();
    match cleave::precompile_yara(&out_dir, true) {
        Ok((builtin, third_party)) => {
            eprintln!(
                "yara-precompile: compiled {builtin} built-in + {third_party} third-party rules -> {} ({} ms)",
                out_dir.display(),
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
