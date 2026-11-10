//! A tiny in-memory NTFS volume builder for tests.
//!
//! Real images only hold the layouts their authors happened to produce. This builder writes the
//! handful of on-disk structures the reader needs (boot sector, `$MFT` records with fixups,
//! resident and non-resident attributes, mapping pairs, attribute lists, LZNT1 data) so a test can
//! describe one exact layout, valid or hostile, in a few lines.
//!
//! Geometry: 512-byte sectors, one sector per cluster, 1024-byte MFT records, 4096-byte index
//! records. The `$MFT` starts at cluster [`MFT_LCN`] and is described by record 0.

use md5::{Digest as _, Md5};
use ntfs::image::ReadAt;
use ntfs::ntfs::{FileSystem, Volume};
use std::io;
use std::sync::Arc;

pub const CLUSTER_SIZE: usize = 512;
pub const MFT_RECORD_SIZE: usize = 1024;
pub const MFT_LCN: u64 = 4;

pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_INDEX_ROOT: u32 = 0x90;

pub const FLAG_COMPRESSED: u16 = 0x0001;

pub const RECORD_IN_USE: u16 = 0x0001;
pub const RECORD_IS_DIRECTORY: u16 = 0x0002;

/// An in-memory image.
#[derive(Debug)]
pub struct MemImage(pub Vec<u8>);

impl ReadAt for MemImage {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        let src = self
            .0
            .get(start..end)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

/// One mapping pair.
#[derive(Debug, Clone, Copy)]
pub enum Run {
    /// `len` clusters stored at cluster `lcn`.
    Data { lcn: i64, len: u64 },
    /// `len` clusters that are not stored.
    Sparse { len: u64 },
}

fn min_signed_bytes(value: i64) -> usize {
    (1..8)
        .find(|n| {
            let shift = 64 - 8 * *n as u32;
            (value << shift) >> shift == value
        })
        .unwrap_or(8)
}

fn min_unsigned_bytes(value: u64) -> usize {
    (1..8).find(|n| value >> (8 * *n as u32) == 0).unwrap_or(8)
}

/// Encodes mapping pairs. Each LCN is stored as a signed delta from the previous stored run.
pub fn encode_runs(runs: &[Run]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev_lcn = 0i64;
    for run in runs {
        match *run {
            Run::Data { lcn, len } => {
                let delta = lcn - prev_lcn;
                prev_lcn = lcn;
                let len_bytes = min_unsigned_bytes(len);
                let off_bytes = min_signed_bytes(delta);
                out.push(((off_bytes as u8) << 4) | len_bytes as u8);
                out.extend_from_slice(&len.to_le_bytes()[..len_bytes]);
                out.extend_from_slice(&delta.to_le_bytes()[..off_bytes]);
            }
            Run::Sparse { len } => {
                let len_bytes = min_unsigned_bytes(len);
                out.push(len_bytes as u8);
                out.extend_from_slice(&len.to_le_bytes()[..len_bytes]);
            }
        }
    }
    out.push(0);
    out
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn pad8(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }
}

/// Builds a resident attribute record.
pub fn resident_attr(type_code: u32, name: &str, instance: u16, value: &[u8]) -> Vec<u8> {
    let name_bytes = utf16le(name);
    let mut out = vec![0u8; 24];
    out.extend_from_slice(&name_bytes);
    pad8(&mut out);
    let value_offset = out.len();
    out.extend_from_slice(value);
    pad8(&mut out);

    let total = out.len() as u32;
    out[0..4].copy_from_slice(&type_code.to_le_bytes());
    out[4..8].copy_from_slice(&total.to_le_bytes());
    out[8] = 0; // resident
    out[9] = (name_bytes.len() / 2) as u8;
    out[10..12].copy_from_slice(&24u16.to_le_bytes());
    out[14..16].copy_from_slice(&instance.to_le_bytes());
    out[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    out[20..22].copy_from_slice(&(value_offset as u16).to_le_bytes());
    out
}

/// A non-resident attribute record. Every header field is taken as given, so a test can write
/// sizes and flags a real volume would never hold.
#[derive(Debug, Clone)]
pub struct NonResident<'a> {
    pub type_code: u32,
    pub name: &'a str,
    pub instance: u16,
    pub flags: u16,
    /// The raw compression unit field (log2 of the unit size in clusters; 0 = not compressed).
    pub compression_unit: u16,
    pub vcn_first: u64,
    pub vcn_last: u64,
    pub allocated_size: u64,
    pub file_size: u64,
    pub valid_data_length: u64,
    /// Encoded mapping pairs, see [`encode_runs`].
    pub mapping_pairs: Vec<u8>,
}

impl NonResident<'_> {
    /// An uncompressed unnamed `$DATA` attribute of `file_size` bytes over `runs`.
    pub fn data(instance: u16, file_size: u64, runs: &[Run]) -> Self {
        let clusters: u64 = runs
            .iter()
            .map(|r| match r {
                Run::Data { len, .. } | Run::Sparse { len } => *len,
            })
            .sum();
        Self {
            type_code: ATTR_DATA,
            name: "",
            instance,
            flags: 0,
            compression_unit: 0,
            vcn_first: 0,
            vcn_last: clusters.saturating_sub(1),
            allocated_size: clusters * CLUSTER_SIZE as u64,
            file_size,
            valid_data_length: file_size,
            mapping_pairs: encode_runs(runs),
        }
    }

    pub fn build(&self) -> Vec<u8> {
        let name_bytes = utf16le(self.name);
        // The header grows by the 8-byte "total allocated" field when a compression unit is set.
        let header_len = if self.compression_unit != 0 {
            0x48
        } else {
            0x40
        };
        let mut out = vec![0u8; header_len];
        out.extend_from_slice(&name_bytes);
        pad8(&mut out);
        let runs_offset = out.len();
        out.extend_from_slice(&self.mapping_pairs);
        pad8(&mut out);

        let total = out.len() as u32;
        out[0..4].copy_from_slice(&self.type_code.to_le_bytes());
        out[4..8].copy_from_slice(&total.to_le_bytes());
        out[8] = 1; // non-resident
        out[9] = (name_bytes.len() / 2) as u8;
        out[10..12].copy_from_slice(&(header_len as u16).to_le_bytes());
        out[12..14].copy_from_slice(&self.flags.to_le_bytes());
        out[14..16].copy_from_slice(&self.instance.to_le_bytes());
        out[16..24].copy_from_slice(&self.vcn_first.to_le_bytes());
        out[24..32].copy_from_slice(&self.vcn_last.to_le_bytes());
        out[32..34].copy_from_slice(&(runs_offset as u16).to_le_bytes());
        out[34..36].copy_from_slice(&self.compression_unit.to_le_bytes());
        out[40..48].copy_from_slice(&self.allocated_size.to_le_bytes());
        out[48..56].copy_from_slice(&self.file_size.to_le_bytes());
        out[56..64].copy_from_slice(&self.valid_data_length.to_le_bytes());
        if self.compression_unit != 0 {
            out[64..72].copy_from_slice(&self.allocated_size.to_le_bytes());
        }
        out
    }
}

/// Builds one `$ATTRIBUTE_LIST` entry.
pub fn attribute_list_entry(
    type_code: u32,
    name: &str,
    lowest_vcn: u64,
    segment_entry: u64,
    instance: u16,
) -> Vec<u8> {
    let name_bytes = utf16le(name);
    let mut out = vec![0u8; 26];
    out.extend_from_slice(&name_bytes);
    pad8(&mut out);

    let total = out.len() as u16;
    out[0..4].copy_from_slice(&type_code.to_le_bytes());
    out[4..6].copy_from_slice(&total.to_le_bytes());
    out[6] = (name_bytes.len() / 2) as u8;
    out[7] = 26;
    out[8..16].copy_from_slice(&lowest_vcn.to_le_bytes());
    // Segment reference: 48-bit entry number, 16-bit sequence number (1, as `Record` writes).
    out[16..24].copy_from_slice(&(segment_entry | (1 << 48)).to_le_bytes());
    out[24..26].copy_from_slice(&instance.to_le_bytes());
    out
}

/// A `$FILE_NAME` value for `name` under directory `parent_entry`.
pub fn file_name_value(parent_entry: u64, name: &str) -> Vec<u8> {
    let name_units: Vec<u16> = name.encode_utf16().collect();
    let mut out = vec![0u8; 66];
    out[0..8].copy_from_slice(&(parent_entry | (1 << 48)).to_le_bytes());
    out[64] = name_units.len() as u8;
    out[65] = 3; // Win32 + DOS namespace
    out.extend(name_units.iter().flat_map(|u| u.to_le_bytes()));
    out
}

/// An MFT record under construction.
#[derive(Debug, Clone)]
pub struct Record {
    pub flags: u16,
    /// Entry number of the base record, for an extension record.
    pub base_entry: Option<u64>,
    pub attributes: Vec<Vec<u8>>,
}

impl Record {
    pub fn file() -> Self {
        Self {
            flags: RECORD_IN_USE,
            base_entry: None,
            attributes: Vec::new(),
        }
    }

    pub fn directory() -> Self {
        Self {
            flags: RECORD_IN_USE | RECORD_IS_DIRECTORY,
            ..Self::file()
        }
    }

    pub fn extension_of(base_entry: u64) -> Self {
        Self {
            base_entry: Some(base_entry),
            ..Self::file()
        }
    }

    pub fn attr(mut self, attribute: Vec<u8>) -> Self {
        self.attributes.push(attribute);
        self
    }

    fn build(&self, entry: u64) -> Vec<u8> {
        const USA_OFFSET: usize = 0x30;
        const FIRST_ATTRIBUTE: usize = 0x38;
        const USN: [u8; 2] = [0x01, 0x00];

        let mut rec = vec![0u8; MFT_RECORD_SIZE];
        rec[0..4].copy_from_slice(b"FILE");
        rec[4..6].copy_from_slice(&(USA_OFFSET as u16).to_le_bytes());
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        rec[0x10..0x12].copy_from_slice(&1u16.to_le_bytes()); // sequence
        rec[0x12..0x14].copy_from_slice(&1u16.to_le_bytes()); // hard links
        rec[0x14..0x16].copy_from_slice(&(FIRST_ATTRIBUTE as u16).to_le_bytes());
        rec[0x16..0x18].copy_from_slice(&self.flags.to_le_bytes());
        rec[0x1c..0x20].copy_from_slice(&(MFT_RECORD_SIZE as u32).to_le_bytes());
        if let Some(base) = self.base_entry {
            rec[0x20..0x28].copy_from_slice(&(base | (1 << 48)).to_le_bytes());
        }
        rec[0x28..0x2a].copy_from_slice(&(self.attributes.len() as u16 + 1).to_le_bytes());
        rec[0x2c..0x30].copy_from_slice(&(entry as u32).to_le_bytes());

        let mut pos = FIRST_ATTRIBUTE;
        for attribute in &self.attributes {
            let end = pos + attribute.len();
            // Leave room for the end marker, and keep clear of the fixup slots (the last two
            // bytes of each sector) only as far as real records do: attributes may span them.
            assert!(
                end + 8 <= MFT_RECORD_SIZE,
                "attributes do not fit in a record"
            );
            rec[pos..end].copy_from_slice(attribute);
            pos = end;
        }
        rec[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        rec[0x18..0x1c].copy_from_slice(&((pos + 8) as u32).to_le_bytes());

        // Fixups: move the last two bytes of each sector into the update sequence array and put
        // the update sequence number in their place.
        rec[USA_OFFSET..USA_OFFSET + 2].copy_from_slice(&USN);
        for sector in 0..MFT_RECORD_SIZE / 512 {
            let tail = (sector + 1) * 512 - 2;
            let slot = USA_OFFSET + 2 + sector * 2;
            let saved = [rec[tail], rec[tail + 1]];
            rec[slot..slot + 2].copy_from_slice(&saved);
            rec[tail..tail + 2].copy_from_slice(&USN);
        }
        rec
    }
}

/// A synthetic NTFS volume.
#[derive(Debug)]
pub struct SynthVolume {
    data: Vec<u8>,
    mft_records: u64,
}

impl SynthVolume {
    /// Creates a zero-filled volume of `total_clusters` clusters whose `$MFT` holds `mft_records`
    /// records. Record 0 (`$MFT`) is written; every other record is empty until set.
    pub fn new(total_clusters: usize, mft_records: u64) -> Self {
        let mut data = vec![0u8; total_clusters * CLUSTER_SIZE];

        data[3..11].copy_from_slice(b"NTFS    ");
        data[0x0b..0x0d].copy_from_slice(&512u16.to_le_bytes());
        data[0x0d] = 1; // sectors per cluster
        data[0x28..0x30].copy_from_slice(&(total_clusters as u64).to_le_bytes());
        data[0x30..0x38].copy_from_slice(&MFT_LCN.to_le_bytes());
        data[0x38..0x40].copy_from_slice(&MFT_LCN.to_le_bytes());
        data[0x40] = 0xf6; // 2^10 bytes per MFT record
        data[0x44] = 0xf4; // 2^12 bytes per index record
        data[0x48..0x50].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        data[510] = 0x55;
        data[511] = 0xaa;

        let mut volume = Self { data, mft_records };
        let mft_clusters = volume.mft_clusters();
        assert!(MFT_LCN + mft_clusters <= total_clusters as u64);
        volume.set_record(
            0,
            Record::file().attr(
                NonResident::data(
                    1,
                    mft_records * MFT_RECORD_SIZE as u64,
                    &[Run::Data {
                        lcn: MFT_LCN as i64,
                        len: mft_clusters,
                    }],
                )
                .build(),
            ),
        );
        volume
    }

    fn mft_clusters(&self) -> u64 {
        self.mft_records * (MFT_RECORD_SIZE / CLUSTER_SIZE) as u64
    }

    /// The first cluster after the `$MFT`.
    pub fn first_free_lcn(&self) -> u64 {
        MFT_LCN + self.mft_clusters()
    }

    pub fn total_clusters(&self) -> u64 {
        (self.data.len() / CLUSTER_SIZE) as u64
    }

    pub fn set_record(&mut self, entry: u64, record: Record) {
        assert!(entry < self.mft_records);
        let offset = MFT_LCN as usize * CLUSTER_SIZE + entry as usize * MFT_RECORD_SIZE;
        self.data[offset..offset + MFT_RECORD_SIZE].copy_from_slice(&record.build(entry));
    }

    /// Writes `bytes` starting at cluster `lcn`.
    pub fn write_clusters(&mut self, lcn: u64, bytes: &[u8]) {
        let offset = lcn as usize * CLUSTER_SIZE;
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    pub fn into_image(self) -> Vec<u8> {
        self.data
    }

    pub fn into_volume(self) -> Volume {
        Volume::open(Arc::new(MemImage(self.data)), 0).expect("synthetic volume opens")
    }

    pub fn into_fs(self) -> FileSystem {
        FileSystem::new(self.into_volume())
    }
}

/// Compresses `data` as an LZNT1 stream, the way NTFS stores a compression unit: 4096-byte
/// chunks, each compressed on its own, and stored raw when compression does not shrink it.
///
/// This is an independent, greedy encoder written from the MS-XCA description; it shares no code
/// with the decoder under test.
pub fn lznt1_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(4096) {
        let body = lznt1_compress_chunk(chunk);
        if body.len() < chunk.len() {
            let header = 0xb000u16 | (body.len() as u16 - 1);
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&body);
        } else {
            let header = 0x3000u16 | (chunk.len() as u16 - 1);
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }
    out
}

fn lznt1_compress_chunk(chunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;

    while pos < chunk.len() {
        let flag_index = out.len();
        out.push(0u8);

        for bit in 0..8 {
            if pos >= chunk.len() {
                break;
            }

            // The split between displacement and length bits depends on how much of the chunk
            // has been produced: 12 length bits at the start, 4 near the end.
            let mut length_bits = 12u32;
            let mut produced = pos.saturating_sub(1);
            while produced >= 0x10 {
                length_bits -= 1;
                produced >>= 1;
            }
            let max_len = (1usize << length_bits) - 1 + 3;

            let mut best_len = 0usize;
            let mut best_disp = 0usize;
            for start in 0..pos {
                let mut len = 0usize;
                while len < max_len
                    && pos + len < chunk.len()
                    && chunk[start + len] == chunk[pos + len]
                {
                    len += 1;
                }
                if len > best_len {
                    best_len = len;
                    best_disp = pos - start;
                }
            }

            if best_len >= 3 {
                let token = (((best_disp - 1) as u16) << length_bits) | (best_len - 3) as u16;
                out[flag_index] |= 1 << bit;
                out.extend_from_slice(&token.to_le_bytes());
                pos += best_len;
            } else {
                out.push(chunk[pos]);
                pos += 1;
            }
        }
    }

    out
}

/// Readable, position-dependent test content of `len` bytes.
pub fn text(len: usize, tag: &str) -> Vec<u8> {
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

/// Zero-pads `bytes` to a whole number of clusters, the way it sits on the volume.
pub fn pad_to_cluster(mut bytes: Vec<u8>) -> Vec<u8> {
    let padded = bytes.len().div_ceil(CLUSTER_SIZE) * CLUSTER_SIZE;
    bytes.resize(padded, 0);
    bytes
}

/// Checks every way of reading the unnamed stream of `entry` against `expected`.
pub fn assert_all_readers_return(fs: &FileSystem, entry: u64, expected: &[u8], what: &str) {
    let bytes = fs.read_file_default_stream(entry).unwrap();
    assert!(
        bytes == expected,
        "{what}: read_file_default_stream differs"
    );

    assert_eq!(
        fs.md5_file_stream(entry, "").unwrap(),
        hex::encode(Md5::digest(expected)),
        "{what}: md5_file_stream"
    );

    let stream = fs.open_file_default_stream_read_at(entry).unwrap();
    assert_eq!(stream.len(), expected.len() as u64, "{what}: stream length");
    let mut all = vec![0xAAu8; expected.len()];
    stream.read_exact_at(0, &mut all).unwrap();
    assert!(all == expected, "{what}: read_at (whole stream) differs");
    // Small reads at odd offsets, including ones that straddle the valid data length.
    let mut offset = 0usize;
    while offset < expected.len() {
        let n = 333.min(expected.len() - offset);
        let mut buf = vec![0xAAu8; n];
        stream.read_exact_at(offset as u64, &mut buf).unwrap();
        assert!(
            buf == expected[offset..offset + n],
            "{what}: read_at at {offset} differs"
        );
        offset += n;
    }
    let mut past = [0u8; 2];
    assert!(
        stream
            .read_exact_at(expected.len() as u64 - 1, &mut past)
            .is_err(),
        "{what}: a read past the end must fail"
    );

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    fs.export_file_default_stream_to_path(entry, &out).unwrap();
    assert!(
        std::fs::read(&out).unwrap() == expected,
        "{what}: export differs"
    );
}
