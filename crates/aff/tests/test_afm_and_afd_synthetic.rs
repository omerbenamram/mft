use aff::{AffImage, ContainerKind};
use forensic_image::ReadAt;

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

fn build_aff1_file(segments: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"AFF10\r\n\0");
    for seg in segments {
        out.extend_from_slice(&seg);
    }
    out
}

#[test]
fn test_afm_reads_split_raw_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let afm_path = tmp.path().join("sample.afm");
    let raw_path = tmp.path().join("sample.000");

    let page_size = 8usize;
    let payload = b"abcdefgh0123"; // 12 bytes
    std::fs::write(&raw_path, payload).unwrap();

    let segments = vec![
        aff_segment("pagesize", &[], page_size as u32),
        aff_segment(aff::format::AF_RAW_IMAGE_FILE_EXTENSION, b"000", 0),
    ];
    let bytes = build_aff1_file(segments);
    std::fs::write(&afm_path, bytes).unwrap();

    let img = AffImage::open(&afm_path).unwrap();
    assert_eq!(img.kind(), ContainerKind::Afm);
    assert_eq!(img.page_size(), page_size);
    assert_eq!(img.len(), payload.len() as u64);

    let mut buf = vec![0u8; payload.len()];
    img.read_exact_at(0, &mut buf).unwrap();
    assert_eq!(&buf, payload);

    // AFM page segments are served from the split-raw payload.
    let page0 = img.read_segment("page0").unwrap().unwrap();
    assert_eq!(page0.data, payload[..page_size].to_vec());
}

#[test]
fn test_afd_unions_files_and_zero_fills_missing_pages() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("container.afd");
    std::fs::create_dir_all(&dir).unwrap();

    let page_size = 8usize;
    let image_size = 24u64; // 3 pages

    let file0 = build_aff1_file(vec![
        aff_segment("pagesize", &[], page_size as u32),
        aff_segment("imagesize", &{
            let low = (image_size & 0xffff_ffff) as u32;
            let high = (image_size >> 32) as u32;
            let mut q = [0u8; 8];
            q[0..4].copy_from_slice(&low.to_be_bytes());
            q[4..8].copy_from_slice(&high.to_be_bytes());
            q
        }, 2),
        aff_segment("foo", b"from0", 0),
        aff_segment("page0", b"AAAAAAAA", 0),
    ]);
    let file1 = build_aff1_file(vec![
        aff_segment("pagesize", &[], page_size as u32),
        aff_segment("imagesize", &{
            let low = (image_size & 0xffff_ffff) as u32;
            let high = (image_size >> 32) as u32;
            let mut q = [0u8; 8];
            q[0..4].copy_from_slice(&low.to_be_bytes());
            q[4..8].copy_from_slice(&high.to_be_bytes());
            q
        }, 2),
        aff_segment("foo", b"from1", 0),
        aff_segment("page1", b"BBBBBBBB", 0),
    ]);

    std::fs::write(dir.join("file_000.aff"), file0).unwrap();
    std::fs::write(dir.join("file_001.aff"), file1).unwrap();

    let img = AffImage::open(&dir).unwrap();
    assert_eq!(img.kind(), ContainerKind::Afd);
    assert_eq!(img.page_size(), page_size);
    assert_eq!(img.len(), image_size);

    // Segment resolution: first subfile wins.
    let foo = img.read_segment("foo").unwrap().unwrap();
    assert_eq!(foo.data, b"from0".to_vec());

    let mut buf = vec![0u8; image_size as usize];
    img.read_exact_at(0, &mut buf).unwrap();
    assert_eq!(&buf[0..8], b"AAAAAAAA");
    assert_eq!(&buf[8..16], b"BBBBBBBB");
    assert_eq!(&buf[16..24], [0u8; 8].as_slice());
}


