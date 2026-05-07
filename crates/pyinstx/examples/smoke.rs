//! Smoke-test driver: extract a PyInstaller exe to a directory.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let mut args = std::env::args().skip(1);
    let (Some(input), Some(out_arg)) = (args.next(), args.next()) else {
        eprintln!("usage: smoke <exe> <out_dir>");
        return ExitCode::from(2);
    };
    let out_dir: PathBuf = out_arg.into();
    let data = match std::fs::read(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read {input}: {e}");
            return ExitCode::from(1);
        }
    };
    println!("input: {} bytes", data.len());
    println!("is_pyinstaller: {}", pyinstx::is_pyinstaller(&data));
    let stats = match pyinstx::extract(&data, &out_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("extract: {e}");
            return ExitCode::from(1);
        }
    };
    println!("files_written = {}", stats.files_written);
    println!("py_version    = {:?}", stats.py_version);
    println!("entry_points  = {:?}", stats.entry_points);
    ExitCode::SUCCESS
}
