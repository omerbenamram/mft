//! A non-resident stream can be longer than its valid data length: the file was extended without
//! being written. The clusters past that mark hold whatever was on the disk before, and NTFS
//! returns zeros for them. So must every reader here.

mod common;

use common::synth::{
    ATTR_DATA, CLUSTER_SIZE, FLAG_COMPRESSED, NonResident, Record, Run, SynthVolume,
    assert_all_readers_return, lznt1_compress, text,
};

const ENTRY: u64 = 20;

#[test]
fn test_uncompressed_stream_reads_zeros_past_valid_data_length() {
    const CLUSTERS: usize = 8;
    const FILE_SIZE: usize = CLUSTERS * CLUSTER_SIZE - 96;

    // The valid data length may fall anywhere: at 0, inside a cluster, on a cluster boundary,
    // at the file size, or (corrupt) beyond it.
    for valid_len in [
        0usize,
        1,
        1000,
        2 * CLUSTER_SIZE,
        FILE_SIZE - 1,
        FILE_SIZE,
        FILE_SIZE + 5000,
    ] {
        let mut vol = SynthVolume::new(256, 32);
        let lcn = vol.first_free_lcn() + 3;

        // What the clusters hold: the file's bytes, and stale bytes of an older file after them.
        let written = text(FILE_SIZE, "written");
        let mut on_disk = vec![0xEEu8; CLUSTERS * CLUSTER_SIZE];
        let kept = valid_len.min(FILE_SIZE);
        on_disk[..kept].copy_from_slice(&written[..kept]);
        vol.write_clusters(lcn, &on_disk);

        vol.set_record(
            ENTRY,
            Record::file().attr(
                NonResident {
                    valid_data_length: valid_len as u64,
                    ..NonResident::data(
                        1,
                        FILE_SIZE as u64,
                        &[Run::Data {
                            lcn: lcn as i64,
                            len: CLUSTERS as u64,
                        }],
                    )
                }
                .build(),
            ),
        );
        let fs = vol.into_fs();

        let mut expected = written[..kept].to_vec();
        expected.resize(FILE_SIZE, 0);
        assert_all_readers_return(&fs, ENTRY, &expected, &format!("valid_len={valid_len}"));
    }
}

/// The same with the stream in two extents (a multi-extent reader is a different code path).
#[test]
fn test_multi_extent_stream_reads_zeros_past_valid_data_length() {
    use common::synth::{ATTR_ATTRIBUTE_LIST, attribute_list_entry, resident_attr};

    const EXT: u64 = 21;
    const FILE_SIZE: usize = 8 * CLUSTER_SIZE - 96;
    // Inside the second extent.
    const VALID_LEN: usize = 5 * CLUSTER_SIZE + 17;

    let mut vol = SynthVolume::new(256, 32);
    let lcn_a = vol.first_free_lcn() + 30;
    let lcn_b = vol.first_free_lcn() + 3;

    let written = text(FILE_SIZE, "written");
    let mut on_disk = vec![0xEEu8; 8 * CLUSTER_SIZE];
    on_disk[..VALID_LEN].copy_from_slice(&written[..VALID_LEN]);
    vol.write_clusters(lcn_a, &on_disk[..4 * CLUSTER_SIZE]);
    vol.write_clusters(lcn_b, &on_disk[4 * CLUSTER_SIZE..]);

    let mut list = Vec::new();
    list.extend(attribute_list_entry(ATTR_DATA, "", 0, ENTRY, 2));
    list.extend(attribute_list_entry(ATTR_DATA, "", 4, EXT, 1));
    vol.set_record(
        ENTRY,
        Record::file()
            .attr(resident_attr(ATTR_ATTRIBUTE_LIST, "", 1, &list))
            .attr(
                NonResident {
                    vcn_last: 3,
                    allocated_size: 8 * CLUSTER_SIZE as u64,
                    valid_data_length: VALID_LEN as u64,
                    ..NonResident::data(
                        2,
                        FILE_SIZE as u64,
                        &[Run::Data {
                            lcn: lcn_a as i64,
                            len: 4,
                        }],
                    )
                }
                .build(),
            ),
    );
    vol.set_record(
        EXT,
        Record::extension_of(ENTRY).attr(
            NonResident {
                vcn_first: 4,
                vcn_last: 7,
                allocated_size: 0,
                valid_data_length: 0,
                ..NonResident::data(
                    1,
                    0,
                    &[Run::Data {
                        lcn: lcn_b as i64,
                        len: 4,
                    }],
                )
            }
            .build(),
        ),
    );
    let fs = vol.into_fs();

    let mut expected = written[..VALID_LEN].to_vec();
    expected.resize(FILE_SIZE, 0);
    assert_all_readers_return(&fs, ENTRY, &expected, "two extents");
}

#[test]
fn test_compressed_stream_reads_zeros_past_valid_data_length() {
    const UNIT_CLUSTERS: u64 = 16;
    const UNIT: usize = UNIT_CLUSTERS as usize * CLUSTER_SIZE;
    const FILE_SIZE: usize = 2 * UNIT - 200;

    for valid_len in [0usize, 700, UNIT, UNIT + 4500] {
        let mut vol = SynthVolume::new(256, 32);
        let content = text(FILE_SIZE, "compressed");

        // Both units are stored in full, so there are decodable bytes past the valid data length
        // that must not show up.
        let mut runs = Vec::new();
        let mut lcn = vol.first_free_lcn();
        for unit in content.chunks(UNIT) {
            let mut stored = lznt1_compress(unit);
            stored.resize(stored.len().div_ceil(CLUSTER_SIZE) * CLUSTER_SIZE, 0);
            let clusters = (stored.len() / CLUSTER_SIZE) as u64;
            assert!(clusters < UNIT_CLUSTERS);
            vol.write_clusters(lcn, &stored);
            runs.push(Run::Data {
                lcn: lcn as i64,
                len: clusters,
            });
            runs.push(Run::Sparse {
                len: UNIT_CLUSTERS - clusters,
            });
            lcn += clusters + 2;
        }

        vol.set_record(
            ENTRY,
            Record::file().attr(
                NonResident {
                    flags: FLAG_COMPRESSED,
                    compression_unit: 4,
                    valid_data_length: valid_len as u64,
                    ..NonResident::data(1, FILE_SIZE as u64, &runs)
                }
                .build(),
            ),
        );
        let fs = vol.into_fs();

        let mut expected = content[..valid_len].to_vec();
        expected.resize(FILE_SIZE, 0);
        assert_all_readers_return(
            &fs,
            ENTRY,
            &expected,
            &format!("compressed valid_len={valid_len}"),
        );
    }
}
