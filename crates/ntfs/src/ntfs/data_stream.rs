//! NTFS non-resident `$DATA` stream readers.
//!
//! This module provides random-access [`crate::image::ReadAt`] implementations for non-resident
//! NTFS attributes backed by *data runs* (mapping pairs).
//!
//! Two stream flavors are supported:
//! - [`DataRunsStream`]: uncompressed non-resident streams (standard + sparse runs).
//! - [`CompressedDataRunsStream`]: NTFS-compressed streams (LZNT1), implementing random access by
//!   caching decompressed *compression units*.
//!
//! The focus is **correctness** and robust behavior on real-world images:
//! - Sparse runs are surfaced as zero-filled ranges.
//! - Overflows are checked and reported as structured errors.
//! - Reads that extend beyond the described runs fail (rather than silently truncating).
//!
//! Current limitations:
//! - `CompressedDataRunsStream` treats “mixed sparse + standard within a single compression unit”
//!   as unsupported (best-effort error), because reconstructing interleaved holes inside a unit is
//!   subtle and currently not implemented.
//! - Compression is assumed to be NTFS LZNT1 (as used by NTFS compressed attributes).

use crate::image::ReadAt;
use crate::ntfs::compression::lznt1::decompress_lznt1_to_len;
use crate::ntfs::{Error, Result, Volume};
use lru::LruCache;
use mft::attribute::data_run::{DataRun, RunType};
use std::num::NonZeroUsize;
use std::sync::Mutex;

#[derive(Debug, Clone)]
struct RunMapping {
    /// Starting VCN for this run (in clusters).
    vcn_start: u64,
    /// The data run covering `[vcn_start, vcn_start + run.lcn_length)`.
    run: DataRun,
}

fn build_run_mappings(data_runs: &[DataRun]) -> Vec<RunMapping> {
    let mut out = Vec::with_capacity(data_runs.len());
    let mut vcn = 0u64;
    for run in data_runs {
        out.push(RunMapping {
            vcn_start: vcn,
            run: *run,
        });
        vcn = vcn.saturating_add(run.lcn_length);
    }
    out
}

/// A non-resident stream backed by NTFS data runs (uncompressed).
///
/// This is the simplest view over a non-resident attribute: runs are interpreted as either:
/// - [`RunType::Standard`]: allocated clusters mapped to on-disk LCNs, or
/// - [`RunType::Sparse`]: holes that read as zeros.
#[derive(Debug, Clone)]
pub struct DataRunsStream {
    /// Underlying volume for physical reads.
    volume: Volume,
    /// Mapping pairs describing the stream layout.
    data_runs: Vec<DataRun>,
    /// Logical stream length in bytes (may be smaller than the total run coverage).
    len: u64,
}

impl DataRunsStream {
    /// Creates a new stream over `data_runs` with a logical `len` in bytes.
    pub fn new(volume: Volume, data_runs: Vec<DataRun>, len: u64) -> Self {
        Self {
            volume,
            data_runs,
            len,
        }
    }

    /// Returns the logical stream length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` if the logical stream length is 0.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a reference to the underlying [`Volume`].
    pub fn volume(&self) -> &Volume {
        &self.volume
    }
}

impl ReadAt for DataRunsStream {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        // Delegate to volume mapping; convert our Result to io::Result.
        match read_from_data_runs(&self.volume, &self.data_runs, offset, buf) {
            Ok(()) => Ok(()),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            )),
        }
    }
}

/// A compressed non-resident stream backed by NTFS data runs.
///
/// This implements random-access by caching decompressed compression units.
///
/// NTFS compressed attributes are stored in *compression units*: fixed-size groups of clusters.
/// Each unit is either:
/// - Stored uncompressed (all clusters allocated), or
/// - Stored compressed (fewer clusters allocated) and decompressed with LZNT1 into the full unit,
/// - Entirely sparse (no clusters allocated), reading back as zeros.
///
/// This reader builds a run-to-VCN mapping once, then serves reads by:
/// 1. Locating the unit for the requested offset.
/// 2. Reading the unit’s allocated clusters from disk.
/// 3. Decompressing (when needed) into a fixed-size buffer.
/// 4. Caching the decompressed unit in an LRU keyed by unit index.
#[derive(Debug)]
pub struct CompressedDataRunsStream {
    /// Underlying volume for physical reads.
    volume: Volume,
    /// Data runs annotated with their starting VCN (in clusters).
    run_mappings: Vec<RunMapping>,
    /// Logical stream length in bytes.
    len: u64,
    /// Cluster size in bytes.
    cluster_size: u64,
    /// Compression unit size in clusters.
    unit_clusters: u64,
    /// Compression unit size in bytes (`unit_clusters * cluster_size`).
    unit_bytes: u64,
    /// LRU cache of decompressed units keyed by `unit_index`.
    cache: Mutex<LruCache<u64, Vec<u8>>>,
}

impl CompressedDataRunsStream {
    /// Creates a compressed stream backed by `data_runs`.
    ///
    /// - `len` is the logical stream length in bytes.
    /// - `unit_clusters` is the compression-unit size in clusters (as declared in the attribute).
    pub fn new(
        volume: Volume,
        data_runs: Vec<DataRun>,
        len: u64,
        unit_clusters: u64,
    ) -> Result<Self> {
        let cluster_size = volume.header.cluster_size as u64;
        if cluster_size == 0 {
            return Err(Error::InvalidData {
                message: "cluster size is 0".to_string(),
            });
        }
        if unit_clusters == 0 {
            return Err(Error::InvalidData {
                message: "compression unit clusters is 0".to_string(),
            });
        }
        let unit_bytes =
            unit_clusters
                .checked_mul(cluster_size)
                .ok_or_else(|| Error::InvalidData {
                    message: "unit size overflow".to_string(),
                })?;

        Ok(Self {
            volume,
            run_mappings: build_run_mappings(&data_runs),
            len,
            cluster_size,
            unit_clusters,
            unit_bytes,
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(32).expect("32 > 0"))),
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns `true` if the logical stream length is 0.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn read_unit(&self, unit_index: u64) -> Result<Vec<u8>> {
        if let Some(hit) = self.cache.lock().expect("poisoned").get(&unit_index) {
            return Ok(hit.clone());
        }

        let unit_vcn_start = unit_index.saturating_mul(self.unit_clusters);
        let unit_vcn_end = unit_vcn_start.saturating_add(self.unit_clusters);

        // Collect physical segments for this unit.
        let mut segments: Vec<(u64, u64)> = Vec::new(); // (lcn, len_clusters)
        let mut has_sparse = false;
        let mut saw_sparse = false;

        for mapping in &self.run_mappings {
            let run_vcn_start = mapping.vcn_start;
            let run_vcn_end = run_vcn_start.saturating_add(mapping.run.lcn_length);

            if run_vcn_end <= unit_vcn_start {
                continue;
            }
            if run_vcn_start >= unit_vcn_end {
                break;
            }

            let overlap_start = run_vcn_start.max(unit_vcn_start);
            let overlap_end = run_vcn_end.min(unit_vcn_end);
            let overlap_len = overlap_end.saturating_sub(overlap_start);
            if overlap_len == 0 {
                continue;
            }

            match mapping.run.run_type {
                RunType::Sparse => {
                    has_sparse = true;
                    saw_sparse = true;
                }
                RunType::Standard => {
                    if saw_sparse {
                        // Best effort: mixed sparse/standard inside a compression unit is tricky.
                        // We'll treat this as unsupported for now.
                        return Err(Error::InvalidData {
                            message: "unsupported: standard clusters after sparse within compression unit".to_string(),
                        });
                    }
                    let lcn = mapping
                        .run
                        .lcn_offset
                        .saturating_add(overlap_start - run_vcn_start);
                    segments.push((lcn, overlap_len));
                }
            }
        }

        let allocated_clusters: u64 = segments.iter().map(|(_, len)| *len).sum();
        let mut unit_out = vec![0u8; self.unit_bytes as usize];

        if allocated_clusters == 0 && has_sparse {
            // Entire unit is sparse => zeros.
        } else if !has_sparse && allocated_clusters == self.unit_clusters {
            // Stored uncompressed: read the full unit.
            let mut dst_off = 0usize;
            for (lcn, len_clusters) in segments {
                let bytes = len_clusters.saturating_mul(self.cluster_size);
                let mut tmp = vec![0u8; bytes as usize];
                let off = lcn.saturating_mul(self.cluster_size);
                self.volume.read_exact_at(off, &mut tmp)?;
                unit_out[dst_off..dst_off + tmp.len()].copy_from_slice(&tmp);
                dst_off += tmp.len();
            }
        } else {
            // Stored compressed: read allocated clusters and decompress.
            let comp_bytes = allocated_clusters.saturating_mul(self.cluster_size) as usize;
            let mut comp = Vec::with_capacity(comp_bytes);
            for (lcn, len_clusters) in segments {
                let bytes = len_clusters.saturating_mul(self.cluster_size) as usize;
                let mut tmp = vec![0u8; bytes];
                let off = lcn.saturating_mul(self.cluster_size);
                self.volume.read_exact_at(off, &mut tmp)?;
                comp.extend_from_slice(&tmp);
            }

            let decompressed = decompress_lznt1_to_len(&comp, self.unit_bytes as usize)?;
            unit_out.copy_from_slice(&decompressed);
        }

        self.cache
            .lock()
            .expect("poisoned")
            .put(unit_index, unit_out.clone());

        Ok(unit_out)
    }
}

impl ReadAt for CompressedDataRunsStream {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }

        let mut remaining = buf.len();
        let mut out_pos = 0usize;
        let mut cur = offset;

        while remaining > 0 {
            let unit_index = cur / self.unit_bytes;
            let within = (cur % self.unit_bytes) as usize;
            let unit = self
                .read_unit(unit_index)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

            let take = remaining.min((self.unit_bytes as usize).saturating_sub(within));
            buf[out_pos..out_pos + take].copy_from_slice(&unit[within..within + take]);

            out_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }
}

/// Reads bytes from a runlist into `buf`, starting at `offset` within the logical stream.
///
/// This is the shared “runlist reader” used by [`DataRunsStream`] and various filesystem readers.
///
/// Behavior:
/// - [`RunType::Standard`]: data is read from the volume at
///   `lcn_offset * cluster_size + within_run`.
/// - [`RunType::Sparse`]: the corresponding range is filled with zeros.
/// - If `offset + buf.len()` extends beyond the covered runs, this returns an error.
pub fn read_from_data_runs(
    volume: &Volume,
    data_runs: &[DataRun],
    offset: u64,
    buf: &mut [u8],
) -> Result<()> {
    let cluster_size = volume.header.cluster_size as u64;
    if cluster_size == 0 {
        return Err(Error::InvalidData {
            message: "cluster_size is 0".to_string(),
        });
    }

    let mut remaining = buf.len();
    let mut out_pos = 0usize;
    let mut cur_off = offset;

    // Stream offset at the start of the current run (in bytes).
    let mut stream_pos = 0u64;

    for run in data_runs {
        let run_len_bytes =
            run.lcn_length
                .checked_mul(cluster_size)
                .ok_or_else(|| Error::InvalidData {
                    message: "data run length overflow".to_string(),
                })?;

        if cur_off >= stream_pos.saturating_add(run_len_bytes) {
            stream_pos = stream_pos.saturating_add(run_len_bytes);
            continue;
        }

        while remaining > 0 && cur_off < stream_pos.saturating_add(run_len_bytes) {
            let within = (cur_off - stream_pos) as usize;
            let available = (run_len_bytes as usize).saturating_sub(within);
            let take = remaining.min(available);

            match run.run_type {
                RunType::Sparse => buf[out_pos..out_pos + take].fill(0),
                RunType::Standard => {
                    let vol_off = run.lcn_offset.saturating_mul(cluster_size) + within as u64;
                    volume.read_exact_at(vol_off, &mut buf[out_pos..out_pos + take])?;
                }
            }

            out_pos += take;
            remaining -= take;
            cur_off = cur_off.saturating_add(take as u64);
        }

        if remaining == 0 {
            break;
        }

        stream_pos = stream_pos.saturating_add(run_len_bytes);
    }

    if remaining != 0 {
        return Err(Error::InvalidData {
            message: "read beyond end of data runs".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs::VolumeHeader;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone)]
    struct MemImage {
        data: Arc<[u8]>,
        reads: Arc<AtomicUsize>,
    }

    impl MemImage {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: data.into(),
                reads: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl ReadAt for MemImage {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
            if end > self.len() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }

            let start = usize::try_from(offset)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
            let end = usize::try_from(end)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "end overflow"))?;

            self.reads.fetch_add(1, Ordering::Relaxed);
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }
    }

    fn test_volume(image: Arc<dyn ReadAt>, cluster_size: u32) -> Volume {
        let header = VolumeHeader {
            bytes_per_sector: 0,
            sectors_per_cluster: 0,
            cluster_size,
            total_sectors: 0,
            mft_lcn: 0,
            mirror_mft_lcn: 0,
            mft_entry_size: 0,
            index_entry_size: 0,
            volume_serial_number: 0,
        };
        Volume::new_for_tests(image, 0, header)
    }

    #[test]
    fn read_from_data_runs_reads_standard_and_fills_sparse_across_runs() {
        let cluster_size = 4u32;

        // Physical clusters:
        // cluster 0: 1..=4
        // cluster 1: 5..=8
        // cluster 2: 9..=12
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[1, 2, 3, 4]);
        data[4..8].copy_from_slice(&[5, 6, 7, 8]);
        data[8..12].copy_from_slice(&[9, 10, 11, 12]);

        let img = MemImage::new(data);
        let volume = test_volume(Arc::new(img), cluster_size);

        let runs = vec![
            DataRun {
                lcn_offset: 0,
                lcn_length: 2,
                run_type: RunType::Standard,
            },
            DataRun {
                lcn_offset: 0,
                lcn_length: 1,
                run_type: RunType::Sparse,
            },
            DataRun {
                lcn_offset: 2,
                lcn_length: 1,
                run_type: RunType::Standard,
            },
        ];

        let mut buf = vec![0u8; 16];
        read_from_data_runs(&volume, &runs, 0, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 9, 10, 11, 12]);

        let mut buf2 = vec![0u8; 10];
        read_from_data_runs(&volume, &runs, 6, &mut buf2).unwrap();
        assert_eq!(buf2, [7, 8, 0, 0, 0, 0, 9, 10, 11, 12]);
    }

    #[test]
    fn read_from_data_runs_errors_on_overread() {
        let cluster_size = 4u32;
        let img = MemImage::new(vec![0u8; 64]);
        let volume = test_volume(Arc::new(img), cluster_size);

        let runs = vec![DataRun {
            lcn_offset: 0,
            lcn_length: 1, // 4 bytes total
            run_type: RunType::Standard,
        }];

        let mut buf = vec![0u8; 2];
        let err = read_from_data_runs(&volume, &runs, 3, &mut buf).unwrap_err();
        match err {
            Error::InvalidData { message } => assert_eq!(message, "read beyond end of data runs"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn data_runs_stream_converts_errors_to_io() {
        let cluster_size = 4u32;
        let img = MemImage::new(vec![0u8; 64]);
        let volume = test_volume(Arc::new(img), cluster_size);

        let runs = vec![DataRun {
            lcn_offset: 0,
            lcn_length: 1,
            run_type: RunType::Standard,
        }];

        let stream = DataRunsStream::new(volume, runs, 4);

        let mut buf = vec![0u8; 2];
        let err = stream.read_exact_at(3, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn compressed_data_runs_stream_reads_uncompressed_unit_and_caches() {
        let cluster_size = 4u32;

        let mut data = vec![0u8; 64];
        data[0..16].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        let img = MemImage::new(data);
        let reads = img.reads.clone();
        let volume = test_volume(Arc::new(img), cluster_size);

        let runs = vec![DataRun {
            lcn_offset: 0,
            lcn_length: 4,
            run_type: RunType::Standard,
        }];

        let stream = CompressedDataRunsStream::new(volume, runs, 16, 4).unwrap();

        let mut buf = vec![0u8; 16];
        stream.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(reads.load(Ordering::Relaxed), 1);

        // Same unit should be served from cache (no additional reads).
        let mut buf2 = vec![0u8; 16];
        stream.read_exact_at(0, &mut buf2).unwrap();
        assert_eq!(buf2, buf);
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn compressed_data_runs_stream_errors_on_standard_after_sparse_within_unit() {
        let cluster_size = 4u32;
        let img = MemImage::new(vec![0u8; 64]);
        let volume = test_volume(Arc::new(img), cluster_size);

        // One unit is 4 clusters. Make it sparse for first half, then standard => unsupported.
        let runs = vec![
            DataRun {
                lcn_offset: 0,
                lcn_length: 2,
                run_type: RunType::Sparse,
            },
            DataRun {
                lcn_offset: 0,
                lcn_length: 2,
                run_type: RunType::Standard,
            },
        ];

        let stream = CompressedDataRunsStream::new(volume, runs, 16, 4).unwrap();
        let mut buf = vec![0u8; 16];
        let err = stream.read_exact_at(0, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("standard clusters after sparse within compression unit")
        );
    }
}
