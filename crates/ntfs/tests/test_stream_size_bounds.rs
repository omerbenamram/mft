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

/// A `$DATA` attribute whose size field says almost 8 EiB while its runs map 4 clusters. Every
/// reader has to refuse it; before, hashing and exporting treated the missing part as a hole and
/// went on for 2^63 bytes.
#[test]
fn test_stream_size_beyond_data_runs_is_an_error() {
    const HUGE: u64 = 0x7fff_ffff_ffff_0000;

    for compressed in [false, true] {
        let mut vol = SynthVolume::new(256, 32);
        let lcn = vol.first_free_lcn();
        vol.write_clusters(lcn, &text(4 * CLUSTER_SIZE, "small"));

        let runs = [Run::Data {
            lcn: lcn as i64,
            len: 4,
        }];
        vol.set_record(
            ENTRY,
            Record::file().attr(
                NonResident {
                    flags: if compressed { FLAG_COMPRESSED } else { 0 },
                    compression_unit: if compressed { 4 } else { 0 },
                    allocated_size: HUGE,
                    valid_data_length: HUGE,
                    ..NonResident::data(1, HUGE, &runs)
                }
                .build(),
            ),
        );
        let fs = vol.into_fs();

        let expect_size_error = |what: &str, err: ntfs::ntfs::Error| {
            let message = err.to_string();
            assert!(
                message.contains("is larger than the 2048 bytes its data runs map"),
                "{what} (compressed={compressed}): unexpected error: {message}"
            );
        };

        expect_size_error("md5", fs.md5_file_stream(ENTRY, "").unwrap_err());
        expect_size_error("read", fs.read_file_default_stream(ENTRY).unwrap_err());
        expect_size_error(
            "open",
            fs.open_file_default_stream_read_at(ENTRY)
                .map(|_| ())
                .unwrap_err(),
        );

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.bin");
        expect_size_error(
            "export",
            fs.export_file_default_stream_to_path(ENTRY, &out)
                .unwrap_err(),
        );
        assert_eq!(std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0), 0);
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
