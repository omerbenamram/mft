#[macro_use]
extern crate criterion;
extern crate mft;

use criterion::Criterion;
use mft::MftParser;
use std::path::{Path, PathBuf};

fn process_90_mft_records(sample: &[u8]) {
    let mut parser = MftParser::from_buffer(sample.to_vec()).unwrap();

    let _: Vec<_> = parser.iter_entries().take(90).collect();
}

fn criterion_benchmark(c: &mut Criterion) {
    let sample = include_bytes!("../../samples/MFT");

    c.bench_function("read 90 records", move |b| {
        b.iter(|| process_90_mft_records(sample))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
