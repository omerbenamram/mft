//! `read_dir` falls back to a scan of the MFT for records that name the directory as their
//! parent. That scan is for a directory whose index is damaged. An intact, empty index is an
//! empty directory and must not cost a walk over the whole MFT, and the scan must not go past
//! the records the `$MFT` really has.

mod common;

use common::synth::{
    ATTR_FILE_NAME, ATTR_INDEX_ROOT, MFT_RECORD_SIZE, NonResident, Record, Run, SynthVolume,
    file_name_value, resident_attr,
};

const MFT_RECORDS: u64 = 32;
const EMPTY_DIR: u64 = 20;
const DAMAGED_DIR: u64 = 22;

/// An `$I30` index root whose only entry is the end marker: an empty directory.
fn empty_index_root() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x30u32.to_le_bytes()); // indexed attribute: $FILE_NAME
    v.extend_from_slice(&1u32.to_le_bytes()); // collation: file name
    v.extend_from_slice(&4096u32.to_le_bytes()); // index record size
    v.extend_from_slice(&[8, 0, 0, 0]); // clusters per index record
    v.extend_from_slice(&16u32.to_le_bytes()); // offset of the first entry
    v.extend_from_slice(&32u32.to_le_bytes()); // node size
    v.extend_from_slice(&32u32.to_le_bytes()); // allocated size
    v.extend_from_slice(&0u32.to_le_bytes()); // flags: no $INDEX_ALLOCATION
    v.extend_from_slice(&0u64.to_le_bytes()); // file reference
    v.extend_from_slice(&16u16.to_le_bytes()); // entry length
    v.extend_from_slice(&0u16.to_le_bytes()); // key length
    v.extend_from_slice(&2u32.to_le_bytes()); // flags: last entry
    v
}

fn volume() -> SynthVolume {
    let mut vol = SynthVolume::new(256, MFT_RECORDS);

    vol.set_record(
        EMPTY_DIR,
        Record::directory()
            .attr(resident_attr(
                ATTR_FILE_NAME,
                "",
                1,
                &file_name_value(5, "empty"),
            ))
            .attr(resident_attr(
                ATTR_INDEX_ROOT,
                "$I30",
                2,
                &empty_index_root(),
            )),
    );
    // A deleted file that still names the empty directory as its parent.
    let mut deleted = Record::file().attr(resident_attr(
        ATTR_FILE_NAME,
        "",
        1,
        &file_name_value(EMPTY_DIR, "gone.txt"),
    ));
    deleted.flags = 0;
    vol.set_record(EMPTY_DIR + 1, deleted);

    // A directory whose index root was wiped, and a live file in it.
    vol.set_record(
        DAMAGED_DIR,
        Record::directory()
            .attr(resident_attr(
                ATTR_FILE_NAME,
                "",
                1,
                &file_name_value(5, "damaged"),
            ))
            .attr(resident_attr(ATTR_INDEX_ROOT, "$I30", 2, &[0u8; 32])),
    );
    vol.set_record(
        DAMAGED_DIR + 1,
        Record::file().attr(resident_attr(
            ATTR_FILE_NAME,
            "",
            1,
            &file_name_value(DAMAGED_DIR, "kept.txt"),
        )),
    );
    vol
}

fn names(entries: Vec<ntfs::ntfs::filesystem::DirectoryEntry>) -> Vec<(String, u64)> {
    entries.into_iter().map(|e| (e.name, e.entry_id)).collect()
}

#[test]
fn intact_empty_index_is_an_empty_directory() {
    let fs = volume().into_fs();

    assert_eq!(names(fs.read_dir(EMPTY_DIR).unwrap()), vec![]);
    assert_eq!(names(fs.read_dir_strict(EMPTY_DIR).unwrap()), vec![]);

    // The name that is no longer indexed is still there for whoever asks for it.
    assert_eq!(
        names(fs.read_dir_including_deleted(EMPTY_DIR).unwrap()),
        vec![("gone.txt".to_string(), EMPTY_DIR + 1)]
    );
}

#[test]
fn damaged_index_falls_back_to_the_parent_scan() {
    let fs = volume().into_fs();
    assert_eq!(
        names(fs.read_dir(DAMAGED_DIR).unwrap()),
        vec![("kept.txt".to_string(), DAMAGED_DIR + 1)]
    );
}

#[test]
fn parent_scan_is_bounded_by_the_records_the_mft_maps() {
    let mut vol = volume();
    // `$MFT` claims a size far beyond its runs (and beyond the image).
    let mft_clusters = MFT_RECORDS * (MFT_RECORD_SIZE as u64 / common::synth::CLUSTER_SIZE as u64);
    vol.set_record(
        0,
        Record::file().attr(
            NonResident::data(
                1,
                1 << 40,
                &[Run::Data {
                    lcn: common::synth::MFT_LCN as i64,
                    len: mft_clusters,
                }],
            )
            .build(),
        ),
    );
    let fs = vol.into_fs();

    assert_eq!(fs.volume().mft_record_capacity(), MFT_RECORDS);
    assert_eq!(
        names(fs.read_dir(DAMAGED_DIR).unwrap()),
        vec![("kept.txt".to_string(), DAMAGED_DIR + 1)]
    );
}
