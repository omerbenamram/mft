//! Stream sizes come from on-disk fields. These tests check that the readers measure them against
//! what the mapping pairs and the image really hold.

use md5::{Digest as _, Md5};

mod common;

use common::synth::{
    CLUSTER_SIZE, FLAG_COMPRESSED, NonResident, Record, Run, SynthVolume, lznt1_compress,
};

const ENTRY: u64 = 20;

fn text(len: usize, tag: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut line = 0usize;
    while out.len() < len {
        out.extend_from_slice(
            format!("{tag} line {line:06} at byte {:08}\r\n", out.len()).as_bytes(),
        );
        line += 1;
    }
    out.truncate(len);
    out
}

fn pad_to_cluster(mut bytes: Vec<u8>) -> Vec<u8> {
    let padded = bytes.len().div_ceil(CLUSTER_SIZE) * CLUSTER_SIZE;
    bytes.resize(padded, 0);
    bytes
}

/// A `$DATA` attribute whose size field says almost 8 EiB while its runs map 4 clusters. What the
/// runs don't map is a hole. Nothing may do work in proportion to the claimed size: a positioned
/// read answers at once, and hashing, whose cost can't be anything but proportional, refuses a
/// size no file on the volume can have.
#[test]
fn test_absurd_stream_size_costs_nothing() {
    const HUGE: u64 = 0x7fff_ffff_ffff_0000;

    for compressed in [false, true] {
        let mut vol = SynthVolume::new(256, 32);
        let lcn = vol.first_free_lcn();
        let stored = text(4 * CLUSTER_SIZE, "small");
        vol.write_clusters(lcn, &stored);

        let runs = [Run::Data {
            lcn: lcn as i64,
            len: 4,
        }];
        vol.set_record(
            ENTRY,
            Record::file().attr(
                NonResident {
                    flags: if compressed { FLAG_COMPRESSED } else { 0 },
                    compression_unit: if compressed { 2 } else { 0 },
                    allocated_size: HUGE,
                    valid_data_length: HUGE,
                    ..NonResident::data(1, HUGE, &runs)
                }
                .build(),
            ),
        );
        let fs = vol.into_fs();

        let message = fs.md5_file_stream(ENTRY, "").unwrap_err().to_string();
        assert!(
            message.contains("is larger than the 2199023255552 bytes a file on this volume"),
            "md5 (compressed={compressed}): unexpected error: {message}"
        );

        let stream = fs.open_file_default_stream_read_at(ENTRY).unwrap();
        assert_eq!(stream.len(), HUGE);
        let mut buf = vec![0xAAu8; 4 * CLUSTER_SIZE + 100];
        stream.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..stored.len()], &stored[..], "compressed={compressed}");
        assert!(buf[stored.len()..].iter().all(|&b| b == 0));
        let mut buf = vec![0xAAu8; 4096];
        stream.read_exact_at(HUGE - 4096, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
    }
}

/// The recovery case: a record whose mapping pairs were cut short while its size survived (a
/// deleted or partly overwritten file). The clusters that are still mapped must stay readable on
/// every path; the rest of the stream is a hole.
#[test]
fn test_stream_longer_than_its_data_runs_reads_the_tail_as_zeros() {
    const MAPPED_CLUSTERS: usize = 16;
    const FILE_SIZE: usize = 40 * CLUSTER_SIZE + 123;

    for compressed in [false, true] {
        let mut vol = SynthVolume::new(256, 32);
        let lcn = vol.first_free_lcn();
        let head = text(MAPPED_CLUSTERS * CLUSTER_SIZE, "head");
        vol.write_clusters(lcn, &head);

        let mut expected = head.clone();
        expected.resize(FILE_SIZE, 0);

        // 16 clusters is one full compression unit, stored as it is.
        let runs = [Run::Data {
            lcn: lcn as i64,
            len: MAPPED_CLUSTERS as u64,
        }];
        vol.set_record(
            ENTRY,
            Record::file().attr(
                NonResident {
                    flags: if compressed { FLAG_COMPRESSED } else { 0 },
                    compression_unit: if compressed { 4 } else { 0 },
                    ..NonResident::data(1, FILE_SIZE as u64, &runs)
                }
                .build(),
            ),
        );
        let fs = vol.into_fs();

        assert!(
            fs.read_file_default_stream(ENTRY).unwrap() == expected,
            "read differs (compressed={compressed})"
        );
        assert_eq!(
            fs.md5_file_stream(ENTRY, "").unwrap(),
            hex::encode(Md5::digest(&expected)),
            "md5 (compressed={compressed})"
        );

        let stream = fs.open_file_default_stream_read_at(ENTRY).unwrap();
        assert_eq!(stream.len(), FILE_SIZE as u64);
        let from = MAPPED_CLUSTERS * CLUSTER_SIZE - 10;
        let mut buf = vec![0xAAu8; FILE_SIZE - from];
        stream.read_exact_at(from as u64, &mut buf).unwrap();
        assert_eq!(buf, expected[from..], "read_at (compressed={compressed})");

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.bin");
        fs.export_file_default_stream_to_path(ENTRY, &out).unwrap();
        assert!(
            std::fs::read(&out).unwrap() == expected,
            "export differs (compressed={compressed})"
        );
    }
}

/// A sparse file: the hole is not stored, hashes as zeros and comes out of an export as zeros.
#[test]
fn test_sparse_stream_hashes_and_exports_holes_as_zeros() {
    const HOLE_CLUSTERS: u64 = 16 * 1024; // 8 MiB

    let mut vol = SynthVolume::new(256, 32);
    let lcn_head = vol.first_free_lcn() + 7;
    let lcn_tail = vol.first_free_lcn() + 2;
    let head = text(2 * CLUSTER_SIZE, "head");
    let tail = text(2 * CLUSTER_SIZE - 100, "tail");
    vol.write_clusters(lcn_head, &head);
    vol.write_clusters(lcn_tail, &tail);

    let mut expected = head.clone();
    expected.resize(expected.len() + HOLE_CLUSTERS as usize * CLUSTER_SIZE, 0);
    expected.extend_from_slice(&tail);

    vol.set_record(
        ENTRY,
        Record::file().attr(
            NonResident::data(
                1,
                expected.len() as u64,
                &[
                    Run::Data {
                        lcn: lcn_head as i64,
                        len: 2,
                    },
                    Run::Sparse { len: HOLE_CLUSTERS },
                    Run::Data {
                        lcn: lcn_tail as i64,
                        len: 2,
                    },
                ],
            )
            .build(),
        ),
    );
    let fs = vol.into_fs();

    assert_eq!(
        fs.md5_file_stream(ENTRY, "").unwrap(),
        hex::encode(Md5::digest(&expected))
    );

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    fs.export_file_default_stream_to_path(ENTRY, &out).unwrap();
    assert!(std::fs::read(&out).unwrap() == expected, "export differs");
}

/// The same for a compressed stream: whole compression units that are not stored.
#[test]
fn test_compressed_stream_hashes_and_exports_sparse_units_as_zeros() {
    const UNIT_CLUSTERS: u64 = 16;
    const UNIT: usize = UNIT_CLUSTERS as usize * CLUSTER_SIZE;
    const HOLE_UNITS: u64 = 512; // 4 MiB

    let mut vol = SynthVolume::new(256, 32);
    let first = text(UNIT, "first");
    let last = text(UNIT / 2 + 5, "last");
    let first_stored = pad_to_cluster(lznt1_compress(&first));
    let last_stored = pad_to_cluster(lznt1_compress(&last));
    let n_first = (first_stored.len() / CLUSTER_SIZE) as u64;
    let n_last = (last_stored.len() / CLUSTER_SIZE) as u64;
    assert!(n_first < UNIT_CLUSTERS && n_last < UNIT_CLUSTERS);

    let lcn_first = vol.first_free_lcn();
    let lcn_last = lcn_first + 40;
    vol.write_clusters(lcn_first, &first_stored);
    vol.write_clusters(lcn_last, &last_stored);

    let mut expected = first.clone();
    expected.resize(expected.len() + HOLE_UNITS as usize * UNIT, 0);
    expected.extend_from_slice(&last);

    let runs = [
        Run::Data {
            lcn: lcn_first as i64,
            len: n_first,
        },
        Run::Sparse {
            len: UNIT_CLUSTERS - n_first + HOLE_UNITS * UNIT_CLUSTERS,
        },
        Run::Data {
            lcn: lcn_last as i64,
            len: n_last,
        },
        Run::Sparse {
            len: UNIT_CLUSTERS - n_last,
        },
    ];
    vol.set_record(
        ENTRY,
        Record::file().attr(
            NonResident {
                flags: FLAG_COMPRESSED,
                compression_unit: 4,
                ..NonResident::data(1, expected.len() as u64, &runs)
            }
            .build(),
        ),
    );
    let fs = vol.into_fs();

    assert_eq!(
        fs.md5_file_stream(ENTRY, "").unwrap(),
        hex::encode(Md5::digest(&expected))
    );

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    fs.export_file_default_stream_to_path(ENTRY, &out).unwrap();
    assert!(std::fs::read(&out).unwrap() == expected, "export differs");
}
