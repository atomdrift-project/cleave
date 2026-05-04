//! Smoke-test driver: extract a PyInstaller exe to a directory.

use std::path::PathBuf;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let mut args = std::env::args().skip(1);
    let input = args.next().expect("usage: smoke <exe> <out_dir>");
    let out_dir: PathBuf = args.next().expect("usage: smoke <exe> <out_dir>").into();
    let data = std::fs::read(&input).expect("read input");
    println!("input: {} bytes", data.len());
    println!("is_pyinstaller: {}", pyinstx::is_pyinstaller(&data));
    let stats = pyinstx::extract(&data, &out_dir).expect("extract");
    println!("files_written = {}", stats.files_written);
    println!("py_version    = {:?}", stats.py_version);
    println!("entry_points  = {:?}", stats.entry_points);
}
