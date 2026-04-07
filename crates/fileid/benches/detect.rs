//! Benchmarks for fileid detection.
//!
//! Run with: cargo bench -p fileid

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::path::Path;

fn load(name: &str) -> Vec<u8> {
    let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

fn bench_magic_bytes(c: &mut Criterion) {
    let elf = load("linux_ls");
    let macho = load("macho_expr");
    let so = load("libpam.so.0");

    let mut g = c.benchmark_group("magic");
    g.bench_function("elf_no_ext", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("linux_ls")), black_box(&elf)))
    });
    g.bench_function("macho_fat_no_ext", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("expr")), black_box(&macho)))
    });
    g.bench_function("elf_so_ext", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("libpam.so.0")), black_box(&so)))
    });
    g.finish();
}

fn bench_shebang(c: &mut Criterion) {
    let sh = load("test.sh");
    let py = load("sample.py");
    let pl = load("test.pl");
    let shell_no_ext = load("shell_no_ext");

    let mut g = c.benchmark_group("shebang");
    g.bench_function("shell_with_ext", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("test.sh")), black_box(&sh)))
    });
    g.bench_function("shell_no_ext", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("mystery")), black_box(&shell_no_ext)))
    });
    g.bench_function("python_with_ext", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("sample.py")), black_box(&py)))
    });
    g.bench_function("perl_with_ext", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("test.pl")), black_box(&pl)))
    });
    g.finish();
}

fn bench_extension_only(c: &mut Criterion) {
    // Minimal data that doesn't trigger magic/shebang — falls through to extension
    let data = b"x = 1\n";

    let mut g = c.benchmark_group("extension");
    g.bench_function("python", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("app.py")), black_box(data.as_slice())))
    });
    g.bench_function("javascript", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("app.js")), black_box(data.as_slice())))
    });
    g.bench_function("typescript", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("app.ts")), black_box(data.as_slice())))
    });
    g.bench_function("rust", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("lib.rs")), black_box(data.as_slice())))
    });
    g.finish();
}

fn bench_heuristic(c: &mut Criterion) {
    let bash_profile = load("bash_profile"); // 53 bytes, no shebang, no ext
    let js = load("sample.js"); // 182 bytes, no shebang

    let mut g = c.benchmark_group("heuristic");
    g.bench_function("shell_53b", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("bash_profile")), black_box(&bash_profile)))
    });
    g.bench_function("js_182b", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("bundle")), black_box(&js)))
    });
    g.finish();
}

fn bench_skip(c: &mut Criterion) {
    let yaml = load("config.yaml");
    let random: Vec<u8> = (0..=255).collect(); // 256 bytes

    let mut g = c.benchmark_group("skip");
    g.bench_function("yaml_config", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("config.yaml")), black_box(&yaml)))
    });
    g.bench_function("unknown_256b", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("data.bin")), black_box(&random)))
    });
    g.bench_function("unknown_no_ext_256b", |b| {
        b.iter(|| fileid::detect(black_box(Path::new("mystery")), black_box(&random)))
    });
    g.finish();
}

fn bench_mismatch(c: &mut Criterion) {
    let elf = load("linux_ls");

    let mut g = c.benchmark_group("mismatch");
    g.bench_function("elf_disguised_as_jpg", |b| {
        b.iter(|| {
            let det = fileid::detect(black_box(Path::new("image.jpg")), black_box(&elf));
            black_box(det.map(|d| d.extension_mismatch()));
        })
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_magic_bytes,
    bench_shebang,
    bench_extension_only,
    bench_heuristic,
    bench_skip,
    bench_mismatch,
);
criterion_main!(benches);
