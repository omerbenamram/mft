use std::process::Command;

use ewf::writer::{Ewf1CompressionLevel, Ewf1Format, EwfHeaderValues, EwfWriter, EwfWriterOptions};
use md5::{Digest as _, Md5};

const GOLDEN_IMAGE_TEXT: &str = include_str!("golden/ewfinfo_image_text.txt");
const GOLDEN_IMAGE_DFXML: &str = include_str!("golden/ewfinfo_image_dfxml.xml");
const GOLDEN_LOGICAL_HIERARCHY: &str = include_str!("golden/ewfinfo_logical_hierarchy.txt");
const GOLDEN_LOGICAL_FILE_ENTRY: &str = include_str!("golden/ewfinfo_logical_file_entry.txt");
const GOLDEN_LOGICAL_BODYFILE: &str = include_str!("golden/ewfinfo_logical_bodyfile.txt");

const EWF1_LVF_SIGNATURE: [u8; 8] = [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]; // "LVF\t\r\n\xff\0"
const EWF1_FILE_HEADER_SIZE: usize = 13;
const EWF1_SECTION_DESCRIPTOR_SIZE: usize = 76;
const EWF1_TABLE_HEADER_SIZE: usize = 24;

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

fn ensure_trailing_newline(mut s: String) -> String {
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn strip_text_header(s: &str) -> &str {
    // libewf (and our CLI) emits a text header:
    //   ewfinfo <version>\n\n
    if s.starts_with("ewfinfo ")
        && let Some(idx) = s.find("\n\n")
    {
        return &s[idx + 2..];
    }
    s
}

fn normalize_text_output(stdout: &str) -> String {
    let s = normalize_newlines(stdout);
    ensure_trailing_newline(strip_text_header(&s).to_string())
}

fn replace_all_tag_text(s: &str, tag: &str, replacement: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");

    let mut out = String::with_capacity(s.len());
    let mut rest = s;

    while let Some(open_idx) = rest.find(&open) {
        out.push_str(&rest[..open_idx]);
        out.push_str(&open);

        let after_open = &rest[open_idx + open.len()..];
        let Some(close_idx) = after_open.find(&close) else {
            // Malformed input; keep the remainder unchanged.
            out.push_str(after_open);
            return out;
        };

        out.push_str(replacement);
        out.push_str(&close);
        rest = &after_open[close_idx + close.len()..];
    }

    out.push_str(rest);
    out
}

fn normalize_dfxml(stdout: &str) -> String {
    let s = normalize_newlines(stdout);
    let s = replace_all_tag_text(&s, "os_sysname", "__OS__");
    let s = replace_all_tag_text(&s, "arch", "__ARCH__");
    replace_all_tag_text(&s, "image_filename", "__IMAGE_FILENAME__")
}

fn run_ewfinfo(args: &[&str]) -> std::process::Output {
    let exe = env!("CARGO_BIN_EXE_ewfinfo");
    Command::new(exe).args(args).output().expect("run ewfinfo")
}

fn build_synthetic_e01(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let path = dir.path().join("ewfinfo.E01");

    let mut opts = EwfWriterOptions::new(Ewf1Format::E01, 1_474_560);
    opts.bytes_per_sector = 512;
    opts.sectors_per_chunk = 64;
    // Make error granularity intentionally differ from sectors_per_chunk to catch copy/paste bugs
    // in `ewfinfo` rendering.
    opts.error_granularity = Some(1);
    opts.compression_level = Ewf1CompressionLevel::None;
    opts.set_identifier = Some([
        0x86, 0x99, 0x10, 0xfc, 0xe1, 0x43, 0x49, 0x08, 0x93, 0x28, 0xaf, 0xed, 0xf4, 0xa7, 0xbe,
        0x1e,
    ]);
    opts.header_values = EwfHeaderValues {
        case_number: "1".to_string(),
        evidence_number: "1.1".to_string(),
        description: "Floppy".to_string(),
        examiner_name: "John D.".to_string(),
        notes: "Just a floppy in my system".to_string(),
        acquisition_datetime: "2006-12-09 10:00:12".to_string(),
        system_datetime: "2006-12-09 10:00:12".to_string(),
        acquisition_software: "ewfacquire".to_string(),
        acquisition_software_version: "20061209".to_string(),
        acquisition_os: "Linux".to_string(),
    };

    let mut w = EwfWriter::create(&path, opts).expect("create E01");
    w.write(&vec![0u8; 1_474_560]).expect("write");
    w.finish().expect("finish");
    path
}

fn adler32_rfc1950(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;

    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    (b << 16) | a
}

fn make_section_descriptor(
    type_string: &str,
    start_offset: u64,
    size: u64,
) -> [u8; EWF1_SECTION_DESCRIPTOR_SIZE] {
    let mut raw = [0u8; EWF1_SECTION_DESCRIPTOR_SIZE];

    // type string (ASCII, NUL-terminated)
    let mut type_bytes = [0u8; 16];
    let src = type_string.as_bytes();
    let copy_len = src.len().min(type_bytes.len().saturating_sub(1));
    type_bytes[..copy_len].copy_from_slice(&src[..copy_len]);
    raw[..16].copy_from_slice(&type_bytes);

    // next_offset (informational)
    let next_offset = start_offset.saturating_add(size);
    raw[16..24].copy_from_slice(&next_offset.to_le_bytes());

    // size
    raw[24..32].copy_from_slice(&size.to_le_bytes());

    let checksum = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
    raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    raw
}

fn make_table_header(number_of_entries: u32, base_offset: u64) -> [u8; EWF1_TABLE_HEADER_SIZE] {
    let mut hdr = [0u8; EWF1_TABLE_HEADER_SIZE];
    hdr[0..4].copy_from_slice(&number_of_entries.to_le_bytes());
    hdr[8..16].copy_from_slice(&base_offset.to_le_bytes());
    let checksum = adler32_rfc1950(&hdr[..EWF1_TABLE_HEADER_SIZE - 4]);
    hdr[EWF1_TABLE_HEADER_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    hdr
}

fn write_lvf_header(file: &mut Vec<u8>, segment_number: u16) {
    file.extend_from_slice(&EWF1_LVF_SIGNATURE);
    file.push(0x01); // start of fields
    file.extend_from_slice(&segment_number.to_le_bytes());
    file.extend_from_slice(&0u16.to_le_bytes()); // end of fields
    assert_eq!(file.len(), EWF1_FILE_HEADER_SIZE);
}

fn encode_utf16le_no_bom(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn hello_chunk_512() -> [u8; 512] {
    let mut out = [0u8; 512];
    out[..5].copy_from_slice(b"hello");
    out
}

fn build_synthetic_l01(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let chunk = hello_chunk_512();

    let mut file: Vec<u8> = Vec::new();
    write_lvf_header(&mut file, 1);

    let mut append_section = |typ: &str, body: &[u8]| -> u64 {
        let start_offset = file.len() as u64;
        let size = (EWF1_SECTION_DESCRIPTOR_SIZE + body.len()) as u64;
        let desc = make_section_descriptor(typ, start_offset, size);
        file.extend_from_slice(&desc);
        file.extend_from_slice(body);
        start_offset
    };

    // data section: number_of_chunks is 0 for L01, but chunk geometry is still present.
    let mut data_body = vec![0u8; 24];
    data_body[0..4].copy_from_slice(&1u32.to_le_bytes()); // version/unknown
    data_body[4..8].copy_from_slice(&0u32.to_le_bytes()); // number_of_chunks (often 0)
    data_body[8..12].copy_from_slice(&1u32.to_le_bytes()); // sectors_per_chunk
    data_body[12..16].copy_from_slice(&512u32.to_le_bytes()); // bytes_per_sector
    data_body[16..24].copy_from_slice(&1u64.to_le_bytes()); // number_of_sectors
    append_section("data", &data_body);

    // sectors: uncompressed chunk + Adler32 of chunk bytes
    let mut sectors_body = Vec::new();
    sectors_body.extend_from_slice(&chunk);
    let checksum = adler32_rfc1950(&chunk);
    sectors_body.extend_from_slice(&checksum.to_le_bytes());
    let sectors_start = append_section("sectors", &sectors_body);
    let chunk_file_off = (sectors_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64) as u32;

    // table2: one entry, base_offset=0, no compression flag.
    let mut table2_body: Vec<u8> = Vec::new();
    table2_body.extend_from_slice(&make_table_header(1, 0));
    table2_body.extend_from_slice(&chunk_file_off.to_le_bytes());
    append_section("table2", &table2_body);

    // ltree: EnCase 7 style serialized tree (UTF-16LE without BOM).
    let ltree_text = concat!(
        "2\n",
        "rec\n",
        "tb\n",
        "5\n",
        "\n",
        "entry\n",
        "1\t1\n",
        "p\tn\tid\tac\twr\tmo\tcr\tls\tbe\n",
        "0\t1\n",
        "1\n",
        "0\t1\n",
        "1\tdir\t1\t10\t20\t30\t40\t0\t\n",
        "0\t0\n",
        "\tfile.txt\t42\t100\t200\t300\t400\t5\t1 0 5\n",
        "\n",
    );
    let ltree_data = encode_utf16le_no_bom(ltree_text);

    let mut ltree_hdr = [0u8; 48];
    let md5 = {
        let mut h = Md5::new();
        h.update(&ltree_data);
        let d = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&d[..]);
        out
    };
    ltree_hdr[0..16].copy_from_slice(&md5);
    ltree_hdr[16..24].copy_from_slice(&(ltree_data.len() as u64).to_le_bytes());
    // checksum at 24..28 filled later
    let mut hdr_for_checksum = ltree_hdr;
    hdr_for_checksum[24..28].fill(0);
    let hdr_checksum = adler32_rfc1950(&hdr_for_checksum);
    ltree_hdr[24..28].copy_from_slice(&hdr_checksum.to_le_bytes());

    let mut ltree_body = Vec::new();
    ltree_body.extend_from_slice(&ltree_hdr);
    ltree_body.extend_from_slice(&ltree_data);
    append_section("ltree", &ltree_body);

    append_section("done", &[]);

    let path = dir.path().join("case.L01");
    std::fs::write(&path, &file).expect("write L01");
    path
}

#[test]
fn test_ewfinfo_real_fixture_nps_formats_epoch_dates_and_reports_encase6() {
    // Regression test for real-world EWF1 images where header dates are stored as Unix epoch
    // seconds. libewf formats these according to `-d` (default: `ctime`) and reports `.E01` as
    // "EnCase 6".
    //
    // We run the binary with a fixed TZ to keep output deterministic across CI environments.
    let exe = env!("CARGO_BIN_EXE_ewfinfo");
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/ewf/nps-2010-emails.E01");
    assert!(fixture.exists(), "missing fixture: {}", fixture.display());

    let out = Command::new(exe)
        .env("TZ", "UTC")
        .arg(&fixture)
        .output()
        .expect("run ewfinfo");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let actual = normalize_text_output(&String::from_utf8_lossy(&out.stdout));

    // Ensure we did not print the raw epoch value.
    assert!(!actual.contains("1296677487"));
    // Ensure the formatted ctime string is present (TZ=UTC).
    assert!(actual.contains("Acquisition date:      Wed Feb  2 20:11:27 2011"));
    assert!(actual.contains("System date:           Wed Feb  2 20:11:27 2011"));
    // Ensure file format matches libewf.
    assert!(actual.contains("File format:        EnCase 6"));
}

#[test]
fn test_ewfinfo_image_text_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    let e01 = build_synthetic_e01(&dir);

    let out = run_ewfinfo(&[e01.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let actual = normalize_text_output(&String::from_utf8_lossy(&out.stdout));
    let expected = ensure_trailing_newline(normalize_newlines(GOLDEN_IMAGE_TEXT));
    assert_eq!(actual, expected);
}

#[test]
fn test_ewfinfo_image_dfxml_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    let e01 = build_synthetic_e01(&dir);

    let out = run_ewfinfo(&["-f", "dfxml", e01.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let actual = normalize_dfxml(&String::from_utf8_lossy(&out.stdout));
    let expected = normalize_newlines(GOLDEN_IMAGE_DFXML);
    assert_eq!(actual, expected);
}

#[test]
fn test_ewfinfo_logical_hierarchy_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    let l01 = build_synthetic_l01(&dir);

    let out = run_ewfinfo(&["-H", l01.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let actual = normalize_text_output(&String::from_utf8_lossy(&out.stdout));
    let expected = ensure_trailing_newline(normalize_newlines(GOLDEN_LOGICAL_HIERARCHY));
    assert_eq!(actual, expected);
}

#[test]
fn test_ewfinfo_logical_file_entry_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    let l01 = build_synthetic_l01(&dir);

    let out = run_ewfinfo(&["-F", "dir/file.txt", l01.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let actual = normalize_text_output(&String::from_utf8_lossy(&out.stdout));
    let expected = ensure_trailing_newline(normalize_newlines(GOLDEN_LOGICAL_FILE_ENTRY));
    assert_eq!(actual, expected);
}

#[test]
fn test_ewfinfo_logical_bodyfile_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    let l01 = build_synthetic_l01(&dir);

    let bodyfile_path = dir.path().join("bodyfile");
    let out = run_ewfinfo(&[
        "-B",
        bodyfile_path.to_str().unwrap(),
        "-H",
        l01.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let bodyfile = std::fs::read_to_string(&bodyfile_path).expect("read bodyfile");
    let actual = ensure_trailing_newline(normalize_newlines(&bodyfile));
    let expected = ensure_trailing_newline(normalize_newlines(GOLDEN_LOGICAL_BODYFILE));
    assert_eq!(actual, expected);
}

#[test]
fn test_ewfinfo_logical_dfxml_is_not_implemented_yet() {
    let dir = tempfile::tempdir().unwrap();
    let l01 = build_synthetic_l01(&dir);

    let out = run_ewfinfo(&["-f", "dfxml", "-H", l01.to_str().unwrap()]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dfxml output is not yet implemented"));
}
