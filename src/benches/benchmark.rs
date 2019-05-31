#[macro_use]
extern crate criterion;
extern crate mft;

use criterion::Criterion;
use mft::{MftEntry, MftParser, ReadSeek};

fn process_1000_mft_records(sample: &[u8]) {
    let mut parser = MftParser::from_buffer(sample.to_vec()).unwrap();

    let mut count = 0;
    for entry in parser.iter_entries().take(1000).filter_map(|a| a.ok()) {
        for _attr in entry.iter_attributes() {
            count += 1;
        }
    }
}

fn get_full_path(parser: &mut MftParser<impl ReadSeek>, entries: &[MftEntry]) {
    let mut paths = Vec::with_capacity(10000);

    for entry in entries {
        paths.push(parser.get_full_path_for_entry(&entry));
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let sample = include_bytes!("../../samples/MFT");

    // baseline ~4.14 ms.
    c.bench_function("read 1000 records", move |b| {
        b.iter(|| process_1000_mft_records(sample))
    });

    c.bench_function("get_full_path", move |b| {
        let mut parser = MftParser::from_buffer(sample.to_vec()).unwrap();

        let entries: Vec<MftEntry> = parser
            .iter_entries()
            .take(10000)
            .filter_map(Result::ok)
            .collect();

        b.iter(|| get_full_path(&mut parser, &entries))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
