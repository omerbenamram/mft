use ntfs::image::{AffImage, ReadAt};
use std::io::Write;

fn aff_quad_u64(v: u64) -> [u8; 8] {
    // AFFLIB stores 64-bit values as an `aff_quad`:
    // - low 32 bits, then high 32 bits
    // - each 32-bit word is in network byte order (big-endian)
    let low = (v & 0xffff_ffff) as u32;
    let high = (v >> 32) as u32;
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&low.to_be_bytes());
    out[4..8].copy_from_slice(&high.to_be_bytes());
    out
}

fn zlib_compress(bytes: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

fn aff_segment(name: &str, data: &[u8], arg: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"AFF\0");
    out.extend_from_slice(&(name.len() as u32).to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&arg.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"ATT\0");
    out
}

fn build_aff1_file(segments: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    // File signature: "AFF10\r\n\0" (8 bytes)
    out.extend_from_slice(b"AFF10\r\n\0");

    for (i, seg) in segments.into_iter().enumerate() {
        if i != 0 {
            // Prefix/back-pointer field (AFFLIB uses this for reverse traversal).
            // The current Rust parser ignores it but expects 4 bytes between segments.
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        out.extend_from_slice(&seg);
    }

    out
}

#[test]
fn test_sparse_and_missing_pages_are_zero_filled_and_len_uses_imagesize() {
    // Per AFFLIB: missing pages represent zero-filled regions. Also, logical length is derived
    // from the `imagesize` segment rather than `(max_page+1)*pagesize`.
    let page_size = 8usize;
    let image_size = 32u64; // 4 pages

    // Page flags (from AFFLIB `afflib.h`)
    const AF_PAGE_COMPRESSED: u32 = 0x0001;
    const AF_PAGE_COMP_ALG_ZLIB: u32 = 0x0000;

    let page0 = b"AAAAAAAA";
    let page2 = b"CCCCCCCC";
    let page0_z = zlib_compress(page0);
    let page2_z = zlib_compress(page2);

    let segments = vec![
        aff_segment("pagesize", &[], page_size as u32),
        aff_segment("imagesize", &aff_quad_u64(image_size), 2),
        aff_segment(
            "page0",
            &page0_z,
            AF_PAGE_COMPRESSED | AF_PAGE_COMP_ALG_ZLIB,
        ),
        aff_segment(
            "page2",
            &page2_z,
            AF_PAGE_COMPRESSED | AF_PAGE_COMP_ALG_ZLIB,
        ),
    ];

    let bytes = build_aff1_file(segments);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), bytes).unwrap();

    let img = AffImage::open(tmp.path()).unwrap();
    assert_eq!(img.len(), image_size);

    let mut buf = vec![0u8; image_size as usize];
    img.read_exact_at(0, &mut buf).unwrap();

    assert_eq!(&buf[0..8], page0);
    assert_eq!(&buf[8..16], [0u8; 8].as_slice()); // missing page1 => zeros
    assert_eq!(&buf[16..24], page2);
    assert_eq!(&buf[24..32], [0u8; 8].as_slice()); // missing page3 (out of range) => zeros
}

#[test]
fn test_zero_compressed_page_returns_zeros() {
    let page_size = 8usize;
    let image_size = 24u64; // 3 pages

    // Page flags (from AFFLIB `afflib.h`)
    const AF_PAGE_COMPRESSED: u32 = 0x0001;
    const AF_PAGE_COMP_ALG_ZLIB: u32 = 0x0000;
    const AF_PAGE_COMP_ALG_ZERO: u32 = 0x0030;

    let page0 = b"AAAAAAAA";
    let page2 = b"RRRRRRRR";
    let page0_z = zlib_compress(page0);

    // ZERO compressor encodes a 4-byte count of NUL bytes, in network order (ntohl()).
    let zero_len = (page_size as u32).to_be_bytes();

    let segments = vec![
        aff_segment("pagesize", &[], page_size as u32),
        aff_segment("imagesize", &aff_quad_u64(image_size), 2),
        aff_segment(
            "page0",
            &page0_z,
            AF_PAGE_COMPRESSED | AF_PAGE_COMP_ALG_ZLIB,
        ),
        aff_segment(
            "page1",
            &zero_len,
            AF_PAGE_COMPRESSED | AF_PAGE_COMP_ALG_ZERO,
        ),
        aff_segment("page2", page2, 0),
    ];

    let bytes = build_aff1_file(segments);
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), bytes).unwrap();

    let img = AffImage::open(tmp.path()).unwrap();
    assert_eq!(img.len(), image_size);

    let mut buf = vec![0u8; image_size as usize];
    img.read_exact_at(0, &mut buf).unwrap();

    assert_eq!(&buf[0..8], page0);
    assert_eq!(&buf[8..16], [0u8; 8].as_slice()); // ZERO compressor => zeros
    assert_eq!(&buf[16..24], page2); // uncompressed => raw bytes
}
