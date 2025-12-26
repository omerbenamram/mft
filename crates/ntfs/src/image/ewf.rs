//! EWF/E01 (Expert Witness Format) random-access reader.
//!
//! This module provides `EwfImage`, an implementation of `ReadAt` over EWF v1 (classic `.E01`)
//! images. The focus is **correctness** and faithful behavior compared to `external/libewf`
//! (notably: descriptor and table checksums, and the v1 2 GiB wraparound offset encoding).
//!
//! Current limitations:
//! - Only **single-segment** EWF v1 files are supported (a lone `.E01` without `.E02`, …).
//! - EWF v2 and encrypted EWF are not supported yet.

use crate::image::ReadAt;
use flate2::read::ZlibDecoder;
use lru::LruCache;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};

const EWF1_EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const EWF1_LVF_SIGNATURE: [u8; 8] = [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
const EWF2_EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];
const EWF2_LEF_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

const EWF1_FILE_HEADER_SIZE: usize = 8 + 1 + 2 + 2;
const EWF1_SECTION_DESCRIPTOR_SIZE: usize = 16 + 8 + 8 + 40 + 4;
const EWF1_TABLE_HEADER_SIZE: usize = 4 + 4 + 8 + 4 + 4;

/// Random-access view over a single-segment EWF v1 (`.E01`) image.
#[derive(Debug)]
pub struct EwfImage {
    /// Entire segment file contents.
    ///
    /// For now this reader maps an EWF image by loading the `.E01` segment into memory.
    /// (This keeps the implementation simple while we harden correctness; we can switch to
    /// file-backed reading later without changing the public `ReadAt` interface.)
    data: Arc<[u8]>,

    /// Logical media size in bytes (the size of the emulated disk), as declared in the `volume`
    /// (or `disk`) section.
    media_size: u64,

    /// Size in bytes of one EWF "chunk" of media data.
    ///
    /// This is derived from `sectors_per_chunk * bytes_per_sector` in the `volume` section.
    chunk_size: usize,

    /// Chunk tables in this segment.
    ///
    /// Some writers emit multiple `sectors` + `table`/`table2` groups within the same `.E01`.
    /// Each group provides offsets for a contiguous range of chunk indices.
    chunk_groups: Vec<EwfChunkGroup>,

    /// Total number of chunks across all groups.
    chunk_count: u64,

    /// In-memory LRU cache of decoded chunks (keyed by chunk index).
    cache: Mutex<LruCache<u64, Vec<u8>>>,
}

#[derive(Debug)]
struct EwfChunkGroup {
    /// Global chunk index of the first entry in this group.
    first_chunk_index: u64,

    /// Base file offset for this group's entries.
    chunk_base: u64,

    /// Table entries for this group (v1 `table` / `table2`) storing per-chunk offsets and the
    /// compression bit.
    chunk_entries: Vec<u32>,

    /// Absolute file offset where the chunk data region for this group ends.
    ///
    /// This is typically the end of the corresponding `sectors` section.
    chunk_data_end: u64,
}

impl EwfImage {
    /// Opens a single-segment EWF v1 image from `path`.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let data: Arc<[u8]> = std::fs::read(path)?.into();

        let header = Ewf1FileHeader::parse(&data)?;
        if header.segment_number != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "only single-segment EWF v1 images are supported (expected segment_number=1)",
            ));
        }
        let sections = parse_ewf1_section_descriptors(&data, header.sections_start_offset())?;

        // Some writers store volume parameters in a `disk` section (not `volume`).
        let volume_desc = sections
            .iter()
            .find(|s| s.type_string == "volume" || s.type_string == "disk")
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing required section `volume` (or `disk`)",
                )
            })?;
        let volume = parse_volume_section_v1(&data, volume_desc)?;

        // Prefer `table2` if present. Some images contain *multiple* tables that must be
        // concatenated (each associated with a `sectors` section).
        let use_table2 = sections.iter().any(|s| s.type_string == "table2");
        let table_type = if use_table2 { "table2" } else { "table" };

        let mut chunk_groups: Vec<EwfChunkGroup> = Vec::new();
        let mut chunk_count: u64 = 0;
        let mut pending_sectors_end: Option<u64> = None;

        for desc in &sections {
            match desc.type_string.as_str() {
                // Chunk data section. The table that follows describes offsets into this region.
                "sectors" | "sector" => {
                    let end = desc.start_offset.saturating_add(desc.size);
                    pending_sectors_end = Some(end);
                }
                x if x == table_type => {
                    let table = parse_table_section_v1(&data, desc)?;
                    if table.entries.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "table has no entries",
                        ));
                    }

                    if table.base_offset > data.len() as u64 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "table base_offset out of bounds",
                        ));
                    }

                    let last_entry = *table.entries.last().expect("non-empty");
                    let chunk_data_end = match pending_sectors_end.take() {
                        Some(end) => end,
                        None => {
                            compute_chunk_data_end_offset_v1(desc, table.base_offset, last_entry)?
                        }
                    };

                    if chunk_data_end > data.len() as u64 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "chunk data end out of bounds",
                        ));
                    }

                    let entries_len_u64 = u64::try_from(table.entries.len()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "table entry count overflow")
                    })?;

                    chunk_groups.push(EwfChunkGroup {
                        first_chunk_index: chunk_count,
                        chunk_base: table.base_offset,
                        chunk_entries: table.entries,
                        chunk_data_end,
                    });

                    chunk_count = chunk_count.saturating_add(entries_len_u64);
                }
                _ => {}
            }
        }

        if chunk_groups.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("no `{table_type}` sections found"),
            ));
        }

        if volume.number_of_chunks as u64 != chunk_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "volume/table chunk count mismatch: volume={} table={}",
                    volume.number_of_chunks, chunk_count
                ),
            ));
        }

        let expected_chunks_from_media = div_ceil_u64(volume.media_size, volume.chunk_size as u64);
        if expected_chunks_from_media != chunk_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "media size/chunk size mismatch: media_size={} chunk_size={} expected_chunks={} table_chunks={}",
                    volume.media_size, volume.chunk_size, expected_chunks_from_media, chunk_count
                ),
            ));
        }

        Ok(Self {
            data,
            media_size: volume.media_size,
            chunk_size: volume.chunk_size,
            chunk_groups,
            chunk_count,
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(256).expect("256 > 0"))),
        })
    }

    /// Returns the logical EWF chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Returns the number of chunks in the logical media.
    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    fn read_chunk(&self, chunk_index: u64) -> io::Result<Vec<u8>> {
        if let Some(hit) = self.cache.lock().expect("poisoned").get(&chunk_index) {
            return Ok(hit.clone());
        }

        if chunk_index >= self.chunk_count() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let (start, end, is_compressed) = self.chunk_range(chunk_index)?;

        let start_usize = usize::try_from(start)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk start overflow"))?;
        let end_usize = usize::try_from(end)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk end overflow"))?;

        if end_usize > self.data.len() || start_usize >= end_usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk offsets out of bounds",
            ));
        }

        let slice = &self.data[start_usize..end_usize];

        let mut out = vec![0u8; self.chunk_size];

        if is_compressed {
            let cursor = io::Cursor::new(slice);
            let mut decoder = ZlibDecoder::new(cursor);
            decoder.read_exact(&mut out)?;
        } else {
            // Uncompressed chunks are stored as: [chunk bytes][u32 adler32 checksum]
            let required = self
                .chunk_size
                .checked_add(4)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?;
            if slice.len() < required {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short uncompressed chunk",
                ));
            }

            let data_part = &slice[..self.chunk_size];
            let checksum_part = &slice[self.chunk_size..self.chunk_size + 4];
            let stored = u32::from_le_bytes(checksum_part.try_into().expect("len=4"));
            let calculated = adler32_rfc1950(data_part);

            if stored != calculated {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "uncompressed chunk checksum mismatch",
                ));
            }

            out.copy_from_slice(data_part);
        }

        self.cache
            .lock()
            .expect("poisoned")
            .put(chunk_index, out.clone());

        Ok(out)
    }

    /// Computes the file-backed byte range for a given chunk index.
    ///
    /// Mirrors `libewf` v1 logic, including the 2 GiB wraparound encoding used by some writers.
    fn chunk_range(&self, chunk_index: u64) -> io::Result<(u64, u64, bool)> {
        let (group, idx) = self.group_for_chunk(chunk_index)?;

        let current = group.chunk_entries[idx];
        let next = group.chunk_entries.get(idx + 1).copied();

        let is_compressed = (current >> 31) != 0;
        let current_off = current & 0x7fff_ffff;

        let start = group.chunk_base.saturating_add(current_off as u64);

        let end = if let Some(next) = next {
            let next_off = next & 0x7fff_ffff;

            // libewf: if next_off < current_off, compute size from the *stored* (unmasked) next entry.
            let size = if next_off < current_off {
                if next < current_off {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "table offsets out of order",
                    ));
                }
                (next - current_off) as u64
            } else {
                (next_off - current_off) as u64
            };

            start
                .checked_add(size)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk end overflow"))?
        } else {
            // There is no indication how large the last chunk is. It is derived from the offset of
            // the next section, following libewf v1 behavior.
            group.chunk_data_end
        };

        if end <= start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk range",
            ));
        }

        Ok((start, end, is_compressed))
    }

    fn group_for_chunk(&self, chunk_index: u64) -> io::Result<(&EwfChunkGroup, usize)> {
        // Find the last group whose `first_chunk_index` is <= chunk_index.
        let pos = self
            .chunk_groups
            .partition_point(|g| g.first_chunk_index <= chunk_index);
        let group_idx = pos.checked_sub(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "chunk index out of range")
        })?;
        let group = &self.chunk_groups[group_idx];

        let local_u64 = chunk_index.saturating_sub(group.first_chunk_index);
        let local = usize::try_from(local_u64)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "chunk index overflow"))?;
        if local >= group.chunk_entries.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok((group, local))
    }
}

impl ReadAt for EwfImage {
    fn len(&self) -> u64 {
        self.media_size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let mut remaining = buf.len();
        let mut out_pos = 0usize;
        let mut cur = offset;

        while remaining > 0 {
            let chunk_index = cur / self.chunk_size as u64;
            let within = (cur % self.chunk_size as u64) as usize;

            let chunk = self.read_chunk(chunk_index)?;
            let take = remaining.min(self.chunk_size - within);
            buf[out_pos..out_pos + take].copy_from_slice(&chunk[within..within + take]);

            out_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Ewf1FileHeader {
    segment_number: u16,
}

impl Ewf1FileHeader {
    fn parse(data: &[u8]) -> io::Result<Self> {
        if data.len() < EWF1_FILE_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short ewf header",
            ));
        }

        let sig: [u8; 8] = data[0..8].try_into().expect("len=8");
        if sig == EWF1_EVF_SIGNATURE || sig == EWF1_LVF_SIGNATURE {
            let segment_number = u16::from_le_bytes(data[9..11].try_into().expect("len=2"));
            return Ok(Self { segment_number });
        }

        if sig == EWF2_EVF_SIGNATURE || sig == EWF2_LEF_SIGNATURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "EWF v2 not supported yet",
            ));
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported EWF signature",
        ))
    }

    fn sections_start_offset(&self) -> u64 {
        // EWF v1 sections start immediately after the fixed-size v1 file header.
        EWF1_FILE_HEADER_SIZE as u64
    }
}

#[derive(Debug, Clone)]
struct Ewf1SectionDescriptor {
    start_offset: u64,
    type_string: String,
    size: u64,
}

impl Ewf1SectionDescriptor {
    fn parse_at(data: &[u8], start_offset: u64) -> io::Result<Self> {
        let start = usize::try_from(start_offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "section offset overflow"))?;

        let raw = data
            .get(start..start + EWF1_SECTION_DESCRIPTOR_SIZE)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "truncated section descriptor")
            })?;

        let stored_checksum = u32::from_le_bytes(
            raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..]
                .try_into()
                .expect("len=4"),
        );
        let calculated_checksum = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
        if stored_checksum != calculated_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "section descriptor checksum mismatch",
            ));
        }

        let type_string = parse_ascii_nul_terminated(&raw[0..16]);
        let next_offset = u64::from_le_bytes(raw[16..24].try_into().expect("len=8"));
        let mut size = u64::from_le_bytes(raw[24..32].try_into().expect("len=8"));

        // libewf behavior: some writers leave size = 0, but set next_offset; infer size from that.
        if size == 0 && next_offset != start_offset && next_offset >= start_offset {
            size = next_offset - start_offset;
        }

        Ok(Self {
            start_offset,
            type_string,
            size,
        })
    }

    fn data_range<'a>(&self, file: &'a [u8]) -> io::Result<&'a [u8]> {
        let start = self
            .start_offset
            .checked_add(EWF1_SECTION_DESCRIPTOR_SIZE as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
        let end = self
            .start_offset
            .checked_add(self.size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;

        let start = usize::try_from(start)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "range overflow"))?;
        let end = usize::try_from(end)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "range overflow"))?;

        file.get(start..end).ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "section data out of bounds")
        })
    }
}

fn parse_ewf1_section_descriptors(
    data: &[u8],
    first_section_offset: u64,
) -> io::Result<Vec<Ewf1SectionDescriptor>> {
    let mut sections = Vec::new();
    let mut offset = first_section_offset;

    // Hard safety cap: avoid pathological scans on corrupted inputs.
    for _ in 0..100_000 {
        if offset == 0 || offset >= data.len() as u64 {
            break;
        }

        let desc = Ewf1SectionDescriptor::parse_at(data, offset)?;
        let is_last = desc.type_string == "next" || desc.type_string == "done";

        let advance = if desc.size != 0 {
            desc.size
        } else {
            // libewf: for last sections (`next`/`done`) some writers set size=0; advance by descriptor size.
            EWF1_SECTION_DESCRIPTOR_SIZE as u64
        };

        if advance == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero advance while scanning sections",
            ));
        }

        sections.push(desc);
        if is_last {
            break;
        }

        offset = offset.saturating_add(advance);
    }

    if sections.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no EWF sections found",
        ));
    }

    Ok(sections)
}

#[derive(Debug, Clone, Copy)]
struct VolumeV1 {
    number_of_chunks: u32,
    chunk_size: usize,
    media_size: u64,
}

fn parse_volume_section_v1(
    data: &[u8],
    volume_desc: &Ewf1SectionDescriptor,
) -> io::Result<VolumeV1> {
    let volume_data = volume_desc.data_range(data)?;

    if volume_data.len() < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "volume section data too small",
        ));
    }

    let number_of_chunks = u32::from_le_bytes(volume_data[4..8].try_into().expect("len=4"));
    let sectors_per_chunk = u32::from_le_bytes(volume_data[8..12].try_into().expect("len=4"));
    let bytes_per_sector = u32::from_le_bytes(volume_data[12..16].try_into().expect("len=4"));
    let number_of_sectors = u64::from_le_bytes(volume_data[16..24].try_into().expect("len=8"));

    if number_of_chunks == 0 || sectors_per_chunk == 0 || bytes_per_sector == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid volume parameters",
        ));
    }

    let chunk_size = sectors_per_chunk
        .checked_mul(bytes_per_sector)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size overflow"))?
        as usize;

    let media_size = number_of_sectors
        .checked_mul(bytes_per_sector as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "media size overflow"))?;

    Ok(VolumeV1 {
        number_of_chunks,
        chunk_size,
        media_size,
    })
}

#[derive(Debug, Clone)]
struct TableV1 {
    base_offset: u64,
    entries: Vec<u32>,
}

fn parse_table_section_v1(data: &[u8], table_desc: &Ewf1SectionDescriptor) -> io::Result<TableV1> {
    let section_data = table_desc.data_range(data)?;

    let header = section_data
        .get(..EWF1_TABLE_HEADER_SIZE)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "table header too small"))?;

    let stored_header_checksum = u32::from_le_bytes(
        header[EWF1_TABLE_HEADER_SIZE - 4..]
            .try_into()
            .expect("len=4"),
    );
    let calculated_header_checksum = adler32_rfc1950(&header[..EWF1_TABLE_HEADER_SIZE - 4]);
    if stored_header_checksum != calculated_header_checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "table header checksum mismatch",
        ));
    }

    let number_of_entries = u32::from_le_bytes(header[0..4].try_into().expect("len=4"));
    let base_offset = u64::from_le_bytes(header[8..16].try_into().expect("len=8"));

    if number_of_entries == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "table number_of_entries is 0",
        ));
    }

    let entries_len = usize::try_from(number_of_entries)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "table entry count overflow"))?;
    let entries_bytes = entries_len
        .checked_mul(4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entries size overflow"))?;

    let entries_start = EWF1_TABLE_HEADER_SIZE;
    let entries_end = entries_start
        .checked_add(entries_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entries end overflow"))?;

    let entries_data = section_data
        .get(entries_start..entries_end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated table entries"))?;

    // Optional entries checksum (footer): immediately follows entries.
    if let Some(footer) = section_data.get(entries_end..entries_end + 4) {
        let stored_entries_checksum = u32::from_le_bytes(footer.try_into().expect("len=4"));
        let calculated_entries_checksum = adler32_rfc1950(entries_data);
        if stored_entries_checksum != calculated_entries_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "table entries checksum mismatch",
            ));
        }
    }

    let mut out = Vec::with_capacity(entries_len);
    for chunk in entries_data.chunks_exact(4) {
        out.push(u32::from_le_bytes(chunk.try_into().expect("len=4")));
    }

    Ok(TableV1 {
        base_offset,
        entries: out,
    })
}

fn parse_ascii_nul_terminated(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let slice = &bytes[..len];
    // EWF section type strings are ASCII; non-ASCII bytes are mapped lossily to keep parsing robust.
    String::from_utf8_lossy(slice).to_string()
}

fn div_ceil_u64(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    a / b + u64::from(!a.is_multiple_of(b))
}

fn compute_chunk_data_end_offset_v1(
    table_desc: &Ewf1SectionDescriptor,
    base_offset: u64,
    last_entry: u32,
) -> io::Result<u64> {
    let last_chunk_data_offset = base_offset.saturating_add((last_entry & 0x7fff_ffff) as u64);

    let end = if table_desc.type_string == "table2" {
        // libewf: For table2 the chunk data is stored 2 sections before the table2 section.
        table_desc.start_offset.saturating_sub(table_desc.size)
    } else if last_chunk_data_offset < table_desc.start_offset {
        // Chunk data stored before the table section.
        table_desc.start_offset
    } else {
        // Chunk data stored inside the table section.
        table_desc.start_offset.saturating_add(table_desc.size)
    };

    if end <= last_chunk_data_offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "last chunk end offset out of bounds",
        ));
    }

    Ok(end)
}

fn adler32_rfc1950(data: &[u8]) -> u32 {
    // RFC1950 adler32; same as zlib's adler32.
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;

    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

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

        // next_offset (best-effort; not used by our scanner if size != 0)
        let next_offset = start_offset.saturating_add(size);
        raw[16..24].copy_from_slice(&next_offset.to_le_bytes());

        // size
        raw[24..32].copy_from_slice(&size.to_le_bytes());

        // reserved bytes (40) left as zeros

        let checksum = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
        raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
        raw
    }

    fn make_table_header(number_of_entries: u32, base_offset: u64) -> [u8; EWF1_TABLE_HEADER_SIZE] {
        let mut hdr = [0u8; EWF1_TABLE_HEADER_SIZE];
        hdr[0..4].copy_from_slice(&number_of_entries.to_le_bytes());
        // hdr[4..8] reserved/unknown = 0
        hdr[8..16].copy_from_slice(&base_offset.to_le_bytes());
        // hdr[16..20] reserved/unknown = 0
        let checksum = adler32_rfc1950(&hdr[..EWF1_TABLE_HEADER_SIZE - 4]);
        hdr[EWF1_TABLE_HEADER_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
        hdr
    }

    #[test]
    fn test_open_disk_section_and_multi_table2_groups() -> io::Result<()> {
        // Build a minimal EWF v1 EVF file with:
        // - `disk` section (instead of `volume`)
        // - two `sectors` + `table2` groups (each group contains one chunk)
        // - `done` terminator
        //
        // Each chunk is zlib-compressed and should decompress to 512 bytes.

        let chunk_size = 512usize;
        let chunk0 = vec![b'A'; chunk_size];
        let chunk1 = vec![b'B'; chunk_size];
        let chunk0_z = {
            use flate2::{Compression, write::ZlibEncoder};
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&chunk0).unwrap();
            enc.finish().unwrap()
        };
        let chunk1_z = {
            use flate2::{Compression, write::ZlibEncoder};
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&chunk1).unwrap();
            enc.finish().unwrap()
        };

        // --- File header ---
        let mut file: Vec<u8> = Vec::new();
        file.extend_from_slice(&EWF1_EVF_SIGNATURE);
        file.push(0); // unknown byte
        file.extend_from_slice(&1u16.to_le_bytes()); // segment_number
        file.extend_from_slice(&0u16.to_le_bytes()); // unknown
        assert_eq!(file.len(), EWF1_FILE_HEADER_SIZE);

        // Helper to append a section: descriptor + body, returning its start_offset.
        let mut sections: Vec<(String, u64, u64)> = Vec::new();
        let mut append_section = |typ: &str, body: &[u8]| {
            let start_offset = file.len() as u64;
            let size = (EWF1_SECTION_DESCRIPTOR_SIZE + body.len()) as u64;
            let desc = make_section_descriptor(typ, start_offset, size);
            file.extend_from_slice(&desc);
            file.extend_from_slice(body);
            sections.push((typ.to_string(), start_offset, size));
            start_offset
        };

        // disk section body: layout matches parse_volume_section_v1 (we only use fields starting at offset 4).
        let mut disk_body = vec![0u8; 24];
        disk_body[0..4].copy_from_slice(&1u32.to_le_bytes()); // version/unknown
        disk_body[4..8].copy_from_slice(&2u32.to_le_bytes()); // number_of_chunks
        disk_body[8..12].copy_from_slice(&1u32.to_le_bytes()); // sectors_per_chunk
        disk_body[12..16].copy_from_slice(&512u32.to_le_bytes()); // bytes_per_sector
        disk_body[16..24].copy_from_slice(&2u64.to_le_bytes()); // number_of_sectors
        append_section("disk", &disk_body);

        // group 0: sectors (chunk0_z) + table2 (1 entry)
        let sectors0_start = append_section("sectors", &chunk0_z);
        let chunk0_file_off = (sectors0_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64) as u32;

        let mut table2_0_body: Vec<u8> = Vec::new();
        table2_0_body.extend_from_slice(&make_table_header(1, 0));
        table2_0_body.extend_from_slice(&(chunk0_file_off | 0x8000_0000).to_le_bytes());
        append_section("table2", &table2_0_body);

        // group 1: sectors (chunk1_z) + table2 (1 entry)
        let sectors1_start = append_section("sectors", &chunk1_z);
        let chunk1_file_off = (sectors1_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64) as u32;

        let mut table2_1_body: Vec<u8> = Vec::new();
        table2_1_body.extend_from_slice(&make_table_header(1, 0));
        table2_1_body.extend_from_slice(&(chunk1_file_off | 0x8000_0000).to_le_bytes());
        append_section("table2", &table2_1_body);

        append_section("done", &[]);

        // Write to a temp file so we exercise the real open path.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.E01");
        std::fs::write(&path, &file)?;

        let img = EwfImage::open(&path)?;
        assert_eq!(img.len(), 1024);
        assert_eq!(img.chunk_size(), 512);
        assert_eq!(img.chunk_count(), 2);

        let mut buf = vec![0u8; 1024];
        img.read_exact_at(0, &mut buf)?;
        assert_eq!(&buf[..512], &chunk0[..]);
        assert_eq!(&buf[512..], &chunk1[..]);

        // Cross-chunk read.
        let mut mid = vec![0u8; 40];
        img.read_exact_at(500, &mut mid)?;
        assert_eq!(&mid[..12], &vec![b'A'; 12]);
        assert_eq!(&mid[12..], &vec![b'B'; 28]);

        Ok(())
    }
}
