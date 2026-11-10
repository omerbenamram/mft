//! The `pagesize` segment is an on-disk number of up to 4 GiB. Reading through the public
//! [`AffImage`] must cost what the container really stores, not what that number says.

use aff::AffImage;
use aff::format::{AF_PAGE_COMP_ALG_ZERO, AF_PAGE_COMP_ALG_ZLIB, AF_PAGE_COMPRESSED};
use forensic_image::ReadAt;
use std::io::Write as _;

fn aff_segment(name: &str, data: &[u8], arg: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"AFF\0");
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&arg.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"ATT\0");
    let seg_len = (16 + name.len() + data.len() + 8) as u32;
    out.extend_from_slice(&seg_len.to_be_bytes());
    out
}

fn aff_quad(v: u64) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&((v & 0xffff_ffff) as u32).to_be_bytes());
    out[4..8].copy_from_slice(&((v >> 32) as u32).to_be_bytes());
    out
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn write_aff(dir: &std::path::Path, segments: &[Vec<u8>]) -> std::path::PathBuf {
    let mut bytes = b"AFF10\r\n\0".to_vec();
    for seg in segments {
        bytes.extend_from_slice(seg);
    }
    let path = dir.join("image.aff");
    std::fs::write(&path, bytes).unwrap();
    path
}

/// An 81-byte file that claims pages of 4 GiB and an image of 1 TiB, with no pages at all.
/// It is a valid, entirely sparse image: every read returns zeros. Each read used to allocate
/// (and copy) a 4 GiB page.
#[test]
fn test_tiny_file_with_4gib_pages_reads_zeros() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_aff(
        dir.path(),
        &[
            aff_segment("pagesize", &[], u32::MAX),
            aff_segment("imagesize", &aff_quad(1 << 40), 2),
        ],
    );
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 81);

    let img = AffImage::open(&path).unwrap();
    assert_eq!(img.len(), 1 << 40);
    assert_eq!(img.page_size(), u32::MAX as usize);

    for i in 0..2000u64 {
        let mut buf = [0xAAu8; 512];
        img.read_exact_at(i * 536_870_909, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 512]);
    }
    let mut buf = [0xAAu8; 512];
    img.read_exact_at((1 << 40) - 512, &mut buf).unwrap();
    assert_eq!(buf, [0u8; 512]);
    assert!(img.read_exact_at((1 << 40) - 511, &mut buf).is_err());
}

/// Stored, compressed, zero and missing pages under a 4 GiB page size, read many times.
#[test]
fn test_4gib_pages_read_stored_bytes_and_zeros() {
    let page_size = u32::MAX;
    let page = |n: u64| n * u64::from(page_size);
    let text = b"0123456789".repeat(100);

    let dir = tempfile::tempdir().unwrap();
    let path = write_aff(
        dir.path(),
        &[
            aff_segment("pagesize", &[], page_size),
            aff_segment("imagesize", &aff_quad(page(6)), 2),
            aff_segment("page0", b"ABCDEFGH", 0),
            aff_segment(
                "page3",
                &zlib(&text),
                AF_PAGE_COMPRESSED | AF_PAGE_COMP_ALG_ZLIB,
            ),
            aff_segment(
                "page5",
                &page_size.to_be_bytes(),
                AF_PAGE_COMPRESSED | AF_PAGE_COMP_ALG_ZERO,
            ),
        ],
    );
    let img = AffImage::open(&path).unwrap();
    assert_eq!(img.len(), page(6));

    for round in 0..2000u64 {
        let mut buf = [0xAAu8; 16];
        img.read_exact_at(4, &mut buf).unwrap();
        assert_eq!(&buf, b"EFGH\0\0\0\0\0\0\0\0\0\0\0\0");

        img.read_exact_at(page(1) + round, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 16]);

        img.read_exact_at(page(3) + 990, &mut buf).unwrap();
        assert_eq!(&buf, b"0123456789\0\0\0\0\0\0");

        img.read_exact_at(page(5) + round, &mut buf).unwrap();
        assert_eq!(buf, [0u8; 16]);
    }

    // Across a page boundary: the last byte of page 2 (not stored) and the start of page 3.
    let mut buf = [0xAAu8; 5];
    img.read_exact_at(page(3) - 1, &mut buf).unwrap();
    assert_eq!(&buf, b"\x000123");

    // The whole stored text in one read.
    let mut all = vec![0u8; text.len()];
    img.read_exact_at(page(3), &mut all).unwrap();
    assert_eq!(all, text);
}
