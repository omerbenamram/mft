//! Reads images written by libewf's `ewfacquire` (see `tests/fixtures/README.md`).

use ewf::{EwfReader, VerifyOptions};
use md5::{Digest as _, Md5};

const SECTOR_SIZE: usize = 512;
const MEDIA_SECTORS: usize = 20;
const CHUNK_SIZE: usize = 16 * SECTOR_SIZE;
/// MD5 of the media, as stored in the images and reported by `ewfverify`.
const MEDIA_MD5: [u8; 16] = [
    0xcd, 0x88, 0xc8, 0xf3, 0xf4, 0x21, 0x05, 0x27, 0x86, 0xeb, 0x40, 0xf5, 0x01, 0x17, 0x47, 0x4c,
];

/// Rebuilds the media the fixtures were acquired from.
fn fixture_media() -> Vec<u8> {
    let media_size = MEDIA_SECTORS * SECTOR_SIZE;
    let mut media = Vec::with_capacity(media_size + 64);
    let mut line = 0usize;
    while media.len() < media_size {
        let sector = media.len() / SECTOR_SIZE;
        media.extend_from_slice(
            format!("sector {sector:05} line {line:07} of the partial-last-chunk fixture\n")
                .as_bytes(),
        );
        line += 1;
    }
    media.truncate(media_size);
    media
}

/// Copies a fixture to a temporary directory under `name` and checks every read path against the
/// media it was acquired from.
fn assert_reads_fixture_media(fixture: &[u8], name: &str) {
    let media = fixture_media();
    assert_eq!(<[u8; 16]>::from(Md5::digest(&media)), MEDIA_MD5);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, fixture).unwrap();

    let img = EwfReader::open(&path).unwrap();
    assert_eq!(img.len(), media.len() as u64);
    assert_eq!(img.chunk_size(), CHUNK_SIZE);
    assert_eq!(img.chunk_count(), 2);
    assert_eq!(img.image_metadata().unwrap().digests.md5, Some(MEDIA_MD5));

    // The whole media in one read.
    let mut all = vec![0u8; media.len()];
    img.read_exact_at(0, &mut all).unwrap();
    assert_eq!(<[u8; 16]>::from(Md5::digest(&all)), MEDIA_MD5);
    assert_eq!(all, media);

    // A read that starts in the full chunk and ends at the last byte of the short one.
    let start = CHUNK_SIZE - 100;
    let mut tail = vec![0u8; media.len() - start];
    img.read_exact_at(start as u64, &mut tail).unwrap();
    assert_eq!(tail, &media[start..]);

    // A read inside the short chunk only.
    let mut inside = [0u8; SECTOR_SIZE];
    img.read_exact_at((CHUNK_SIZE + SECTOR_SIZE) as u64, &mut inside)
        .unwrap();
    assert_eq!(inside, &media[CHUNK_SIZE + SECTOR_SIZE..][..SECTOR_SIZE]);

    // Reads past the end of the media still fail.
    let mut past = [0u8; 2];
    assert!(
        img.read_exact_at(media.len() as u64 - 1, &mut past)
            .is_err()
    );

    img.verify(VerifyOptions::default()).unwrap();
}

#[test]
fn test_libewf_encase6_compressed_short_last_chunk_reads_media() {
    assert_reads_fixture_media(
        include_bytes!("fixtures/libewf_encase6_fast.E01.bin"),
        "image.E01",
    );
}

#[test]
fn test_libewf_encase6_uncompressed_short_last_chunk_reads_media() {
    assert_reads_fixture_media(
        include_bytes!("fixtures/libewf_encase6_none.E01.bin"),
        "image.E01",
    );
}

#[test]
fn test_libewf_smart_compressed_table_without_entries_checksum_reads_media() {
    assert_reads_fixture_media(
        include_bytes!("fixtures/libewf_smart_fast.s01.bin"),
        "image.s01",
    );
}

#[test]
fn test_libewf_smart_uncompressed_table_without_entries_checksum_reads_media() {
    assert_reads_fixture_media(
        include_bytes!("fixtures/libewf_smart_none.s01.bin"),
        "image.s01",
    );
}

#[test]
fn test_libewf_original_ewf_table_without_entries_checksum_reads_media() {
    assert_reads_fixture_media(
        include_bytes!("fixtures/libewf_ewf_fast.e01.bin"),
        "image.e01",
    );
}

/// The entries checksum of an EnCase-style table is still checked: flipping a bit in it, or in the
/// entries it covers, must fail the open. (The reader takes the chunk offsets from `table2` when
/// an image has one, so that is the table to damage.)
#[test]
fn test_encase_table_entries_checksum_is_still_checked() {
    let good: &[u8] = include_bytes!("fixtures/libewf_encase6_fast.E01.bin");

    // Walk the section descriptors (type[16], next[8], size[8], padding[40], checksum[4]) to the
    // `table2` section.
    let mut tables = Vec::new();
    let mut offset = 13usize;
    loop {
        let section_type = &good[offset..offset + 16];
        let next = u64::from_le_bytes(good[offset + 16..offset + 24].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(good[offset + 24..offset + 32].try_into().unwrap()) as usize;
        if section_type.starts_with(b"table2\0") {
            tables.push((offset, size));
        }
        if next == offset || next == 0 {
            break;
        }
        offset = next;
    }
    assert_eq!(tables.len(), 1, "expected one `table2`");

    for (start, size) in tables {
        // The footer is the last 4 bytes of the section; the last entry sits just before it.
        for corrupt_at in [start + size - 1, start + size - 5] {
            let mut bad = good.to_vec();
            bad[corrupt_at] ^= 0x01;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("image.E01");
            std::fs::write(&path, &bad).unwrap();
            let err = EwfReader::open(&path).unwrap_err();
            assert!(
                err.to_string().contains("table entries checksum mismatch"),
                "unexpected error: {err}"
            );
        }
    }
}
