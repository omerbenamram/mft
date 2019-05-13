#[macro_use]
extern crate criterion;
extern crate mft;

use criterion::Criterion;
use mft::MftParser;

fn process_1000_mft_records(sample: &[u8]) {
    let mut parser = MftParser::from_buffer(sample.to_vec()).unwrap();

    let mut count = 0;
    for entry in parser.iter_entries().take(1000).filter_map(|a| a.ok()) {
        for attr in entry.iter_attributes() {
            count += 1;
        }
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let sample = include_bytes!("../../samples/MFT");

    // baseline ~4.14 ms.
    c.bench_function("read 1000 records", move |b| {
        b.iter(|| process_1000_mft_records(sample))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
