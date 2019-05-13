#[macro_use]
extern crate criterion;
extern crate mft;

use criterion::Criterion;
use mft::MftParser;
use std::path::{Path, PathBuf};

fn process_90_mft_records(sample: impl AsRef<Path>) {
    let parser = MftParser::from_path(sample).unwrap();

    let _: Vec<_> = parser.iter_entries().take(90).collect();
}

fn criterion_benchmark(c: &mut Criterion) {
    let sample = PathBuf::from(file!())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("samples")
        .join("MFT");

    c.bench_function("read 90 records", move |b| {
        b.iter(|| process_90_mft_records(&sample))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
