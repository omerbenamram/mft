use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use mft::csv::FlatMftEntryWithName;
use mft::{MftEntry, MftParser};
use std::hint::black_box;
use std::io::Cursor;

const SAMPLE: &[u8] = include_bytes!("../../samples/MFT");

/// A parser over the in-memory sample, without copying it.
fn parser() -> MftParser<Cursor<&'static [u8]>> {
    MftParser::from_read_seek(Cursor::new(SAMPLE), Some(SAMPLE.len() as u64)).unwrap()
}

fn all_entries() -> Vec<MftEntry> {
    parser().iter_entries().filter_map(Result::ok).collect()
}

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse");
    group.throughput(Throughput::Bytes(SAMPLE.len() as u64));

    group.bench_function("entries", |b| {
        b.iter(|| {
            let mut parser = parser();
            for entry in parser.iter_entries() {
                let _ = black_box(entry);
            }
        })
    });

    group.bench_function("entries_and_attributes", |b| {
        b.iter(|| {
            let mut parser = parser();
            let mut count = 0usize;
            for entry in parser.iter_entries().filter_map(Result::ok) {
                for attr in entry.iter_attributes() {
                    count += black_box(attr).is_ok() as usize;
                }
            }
            count
        })
    });

    group.finish();
}

fn bench_serialize(c: &mut Criterion) {
    let entries = all_entries();

    let mut group = c.benchmark_group("serialize");
    group.throughput(Throughput::Elements(entries.len() as u64));

    group.bench_function("json", |b| {
        let mut buf = Vec::with_capacity(64 * 1024 * 1024);
        b.iter(|| {
            buf.clear();
            for entry in &entries {
                serde_json::to_writer(&mut buf, entry).unwrap();
                buf.push(b'\n');
            }
            buf.len()
        })
    });

    group.bench_function("csv", |b| {
        let mut parser = parser();
        b.iter(|| {
            let mut writer = csv::Writer::from_writer(Vec::with_capacity(8 * 1024 * 1024));
            for entry in &entries {
                writer
                    .serialize(FlatMftEntryWithName::from_entry(entry, &mut parser))
                    .unwrap();
            }
            writer.into_inner().unwrap().len()
        })
    });

    group.finish();
}

fn bench_full_path(c: &mut Criterion) {
    let entries = all_entries();

    let mut group = c.benchmark_group("full_path");
    group.throughput(Throughput::Elements(entries.len() as u64));

    // Fresh parser per iteration: measures resolution including cache misses.
    group.bench_function("cold_cache", |b| {
        b.iter(|| {
            let mut parser = parser();
            for entry in &entries {
                black_box(parser.get_full_path_for_entry(entry).unwrap());
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_parse, bench_serialize, bench_full_path);
criterion_main!(benches);
