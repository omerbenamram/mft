//! `$DATA` streams whose extents are spread over several MFT records by an `$ATTRIBUTE_LIST`.

use md5::{Digest as _, Md5};

mod common;

use common::synth::{
    ATTR_ATTRIBUTE_LIST, ATTR_DATA, CLUSTER_SIZE, FLAG_COMPRESSED, NonResident, Record, Run,
    SynthVolume, attribute_list_entry, encode_runs, lznt1_compress, pad_to_cluster, resident_attr,
    text,
};

fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// The layout of entry 48 of `ntfs1-gen2.E01`: the base record holds nothing but a non-resident
/// `$ATTRIBUTE_LIST`, and every `$DATA` extent lives in an extension record.
#[test]
fn test_non_resident_attribute_list_finds_data_extents() {
    const BASE: u64 = 20;
    const EXT_A: u64 = 21;
    const EXT_B: u64 = 22;

    let mut vol = SynthVolume::new(256, 32);
    let free = vol.first_free_lcn();

    let content = text(8 * CLUSTER_SIZE - 100, "nonres-list");
    let stored = pad_to_cluster(content.clone());
    // The two halves are stored out of order on disk.
    let lcn_a = free + 20;
    let lcn_b = free + 4;
    vol.write_clusters(lcn_a, &stored[..4 * CLUSTER_SIZE]);
    vol.write_clusters(lcn_b, &stored[4 * CLUSTER_SIZE..]);

    let mut list = Vec::new();
    list.extend(attribute_list_entry(ATTR_DATA, "", 0, EXT_A, 1));
    list.extend(attribute_list_entry(ATTR_DATA, "", 4, EXT_B, 1));
    let list_lcn = free;
    vol.write_clusters(list_lcn, &list);

    vol.set_record(
        BASE,
        Record::file().attr(
            NonResident {
                type_code: ATTR_ATTRIBUTE_LIST,
                ..NonResident::data(
                    1,
                    list.len() as u64,
                    &[Run::Data {
                        lcn: list_lcn as i64,
                        len: 1,
                    }],
                )
            }
            .build(),
        ),
    );
    vol.set_record(
        EXT_A,
        Record::extension_of(BASE).attr(
            NonResident {
                vcn_last: 3,
                allocated_size: stored.len() as u64,
                ..NonResident::data(
                    1,
                    content.len() as u64,
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
        EXT_B,
        Record::extension_of(BASE).attr(
            NonResident {
                vcn_first: 4,
                vcn_last: 7,
                allocated_size: 0,
                file_size: 0,
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

    assert_eq!(fs.read_file_default_stream(BASE).unwrap(), content);
    assert_eq!(
        fs.md5_file_stream(BASE, "").unwrap(),
        hex::encode(Md5::digest(&content))
    );

    let stream = fs.open_file_default_stream_read_at(BASE).unwrap();
    assert_eq!(stream.len(), content.len() as u64);
    // A read that crosses from the first extent into the second.
    let mut buf = vec![0u8; 1000];
    let at = 4 * CLUSTER_SIZE - 500;
    stream.read_exact_at(at as u64, &mut buf).unwrap();
    assert_eq!(buf, &content[at..at + 1000]);
}

/// A compressed stream in two extents, with a compression unit that starts in the first extent
/// and ends in the second (as in entry 48 of `ntfs1-gen2.E01`).
#[test]
fn test_compressed_stream_with_multiple_extents_reads_across_extents() {
    const BASE: u64 = 20;
    const EXT: u64 = 21;
    const UNIT_CLUSTERS: u64 = 16;
    const UNIT: usize = UNIT_CLUSTERS as usize * CLUSTER_SIZE;

    let mut vol = SynthVolume::new(512, 32);
    let free = vol.first_free_lcn();

    // Unit 0 and 1 compress; unit 2 is noise and is stored as is; unit 3 is a short tail.
    let mut content = text(2 * UNIT, "compressed");
    content.extend(noise(UNIT));
    content.extend(text(UNIT / 2 + 77, "tail"));

    let unit0 = pad_to_cluster(lznt1_compress(&content[..UNIT]));
    let unit1 = pad_to_cluster(lznt1_compress(&content[UNIT..2 * UNIT]));
    let unit2 = content[2 * UNIT..3 * UNIT].to_vec();
    let unit3 = pad_to_cluster(lznt1_compress(&content[3 * UNIT..]));
    let clusters = |bytes: &[u8]| (bytes.len() / CLUSTER_SIZE) as u64;
    let (n0, n1, n3) = (clusters(&unit0), clusters(&unit1), clusters(&unit3));
    assert!(n0 < UNIT_CLUSTERS && n3 < UNIT_CLUSTERS);
    assert!(
        (2..UNIT_CLUSTERS).contains(&n1),
        "unit 1 must be splittable"
    );

    // Unit 1's stored clusters are split between the extents.
    let n1_head = n1 / 2;
    let n1_tail = n1 - n1_head;
    let split = n1_head as usize * CLUSTER_SIZE;

    let lcn_unit0 = free + 100;
    let lcn_unit1_head = free + 40;
    let lcn_unit1_tail = free + 200;
    let lcn_unit2 = free + 60;
    let lcn_unit3 = free + 10;
    vol.write_clusters(lcn_unit0, &unit0);
    vol.write_clusters(lcn_unit1_head, &unit1[..split]);
    vol.write_clusters(lcn_unit1_tail, &unit1[split..]);
    vol.write_clusters(lcn_unit2, &unit2);
    vol.write_clusters(lcn_unit3, &unit3);

    let first_extent_clusters = UNIT_CLUSTERS + n1_head;
    let runs_a = [
        Run::Data {
            lcn: lcn_unit0 as i64,
            len: n0,
        },
        Run::Sparse {
            len: UNIT_CLUSTERS - n0,
        },
        Run::Data {
            lcn: lcn_unit1_head as i64,
            len: n1_head,
        },
    ];
    let runs_b = [
        Run::Data {
            lcn: lcn_unit1_tail as i64,
            len: n1_tail,
        },
        Run::Sparse {
            len: UNIT_CLUSTERS - n1,
        },
        Run::Data {
            lcn: lcn_unit2 as i64,
            len: UNIT_CLUSTERS,
        },
        Run::Data {
            lcn: lcn_unit3 as i64,
            len: n3,
        },
        Run::Sparse {
            len: UNIT_CLUSTERS - n3,
        },
    ];

    // The attribute list is resident here and also names the extent held in the base record.
    let mut list = Vec::new();
    list.extend(attribute_list_entry(ATTR_DATA, "", 0, BASE, 2));
    list.extend(attribute_list_entry(
        ATTR_DATA,
        "",
        first_extent_clusters,
        EXT,
        1,
    ));

    vol.set_record(
        BASE,
        Record::file()
            .attr(resident_attr(ATTR_ATTRIBUTE_LIST, "", 1, &list))
            .attr(
                NonResident {
                    type_code: ATTR_DATA,
                    name: "",
                    instance: 2,
                    flags: FLAG_COMPRESSED,
                    compression_unit: 4,
                    vcn_first: 0,
                    vcn_last: first_extent_clusters - 1,
                    allocated_size: 4 * UNIT as u64,
                    file_size: content.len() as u64,
                    valid_data_length: content.len() as u64,
                    mapping_pairs: encode_runs(&runs_a),
                }
                .build(),
            ),
    );
    // As on real volumes, only the first extent carries the sizes and the compression unit.
    vol.set_record(
        EXT,
        Record::extension_of(BASE).attr(
            NonResident {
                type_code: ATTR_DATA,
                name: "",
                instance: 1,
                flags: FLAG_COMPRESSED,
                compression_unit: 0,
                vcn_first: first_extent_clusters,
                vcn_last: 4 * UNIT_CLUSTERS - 1,
                allocated_size: 0,
                file_size: 0,
                valid_data_length: 0,
                mapping_pairs: encode_runs(&runs_b),
            }
            .build(),
        ),
    );

    let fs = vol.into_fs();

    assert_eq!(fs.read_file_default_stream(BASE).unwrap(), content);
    assert_eq!(
        fs.md5_file_stream(BASE, "").unwrap(),
        hex::encode(Md5::digest(&content))
    );

    let stream = fs.open_file_default_stream_read_at(BASE).unwrap();
    assert_eq!(stream.len(), content.len() as u64);
    // From the middle of unit 1 (split between the extents) into the stored unit 2.
    let at = UNIT + UNIT / 2;
    let mut buf = vec![0u8; UNIT];
    stream.read_exact_at(at as u64, &mut buf).unwrap();
    assert_eq!(buf, &content[at..at + UNIT]);

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    fs.export_file_default_stream_to_path(BASE, &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), content);
}
