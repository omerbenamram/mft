use crate::image::ReadAt;
use crate::ntfs::data_stream::read_from_data_runs;
use crate::ntfs::volume_header::VolumeHeader;
use crate::ntfs::{Error, Result};
use mft::attribute::MftAttributeType;
use std::fmt;
use std::sync::Arc;

/// A view over an NTFS volume inside an image.
///
/// MFT entry reading uses the `$MFT` file's data runs (extracted from entry 0) so it works even
/// when `$MFT` is fragmented.
#[derive(Clone)]
pub struct Volume {
    image: Arc<dyn ReadAt>,
    volume_offset: u64,
    pub header: VolumeHeader,
    mft_data_runs: Vec<mft::attribute::data_run::DataRun>,
}

impl fmt::Debug for Volume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Volume")
            .field("volume_offset", &self.volume_offset)
            .field("header", &self.header)
            .field("image_len", &self.image.len())
            .field("mft_data_runs", &self.mft_data_runs.len())
            .finish()
    }
}

impl Volume {
    pub fn open(image: Arc<dyn ReadAt>, volume_offset: u64) -> Result<Self> {
        let header = VolumeHeader::read_from_image(image.as_ref(), volume_offset)?;

        // The cluster and record sizes size the buffers of every later read. They come from the
        // boot sector, so measure them against the image before trusting them.
        let image_len = image.len().saturating_sub(volume_offset);
        if u64::from(header.cluster_size) > image_len
            || u64::from(header.mft_entry_size) > image_len
            || u64::from(header.index_entry_size) > image_len
        {
            return Err(Error::InvalidBootSector {
                message: "cluster or record size is larger than the image",
            });
        }

        let mut volume = Self {
            image,
            volume_offset,
            header,
            mft_data_runs: Vec::new(),
        };

        // Bootstrap: read MFT entry 0 using the boot-sector-provided MFT location, and use its
        // `$DATA` mapping pairs to read arbitrary entries.
        let entry0_buf = volume.read_mft_entry_raw_contiguous(0)?;
        let entry0 = mft::MftEntry::from_buffer(entry0_buf, 0)?;

        for attr in entry0
            .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name.is_empty())
        {
            if let Some(dr) = attr.data.as_data_runs().cloned() {
                volume.mft_data_runs = dr.data_runs;
                break;
            }
        }

        Ok(volume)
    }

    pub fn volume_offset(&self) -> u64 {
        self.volume_offset
    }

    /// Returns the number of bytes the image holds from the start of this volume on.
    ///
    /// This is the real upper bound for anything stored on the volume, whatever the sizes in
    /// the boot sector or in an attribute say.
    pub fn image_len(&self) -> u64 {
        self.image.len().saturating_sub(self.volume_offset)
    }

    /// Returns how many MFT records can really be read from this volume: what the `$MFT` runs
    /// map, and no more than fits in the image. The size stored in `$MFT`'s record may claim
    /// more.
    pub fn mft_record_capacity(&self) -> u64 {
        let record_size = u64::from(self.header.mft_entry_size).max(1);
        let image_len = self.image_len();
        let mft_bytes = if self.mft_data_runs.is_empty() {
            // No mapping: records are read contiguously from the boot sector's `$MFT` offset.
            image_len.saturating_sub(self.header.mft_offset_bytes())
        } else {
            self.mft_data_runs
                .iter()
                .fold(0u64, |clusters, run| {
                    clusters.saturating_add(run.lcn_length)
                })
                .saturating_mul(u64::from(self.header.cluster_size))
                .min(image_len)
        };
        mft_bytes / record_size
    }

    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let image_offset = self.volume_offset.checked_add(offset).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "volume offset out of range",
            )
        })?;
        self.image.read_exact_at(image_offset, buf)
    }

    /// Reads raw bytes of the MFT entry with `entry_number`.
    pub fn read_mft_entry_raw(&self, entry_number: u64) -> Result<Vec<u8>> {
        let entry_size = self.header.mft_entry_size as usize;

        let mut buf = vec![0u8; entry_size];
        if self.mft_data_runs.is_empty() {
            // Fallback for unusual/corrupt volumes where we couldn't obtain the $MFT mapping.
            let entry_offset = self
                .header
                .mft_offset_bytes()
                .saturating_add(entry_number.saturating_mul(self.header.mft_entry_size as u64));
            self.read_exact_at(entry_offset, &mut buf)?;
            return Ok(buf);
        }

        let mft_offset = entry_number.saturating_mul(self.header.mft_entry_size as u64);
        read_from_data_runs(self, &self.mft_data_runs, mft_offset, &mut buf)?;
        Ok(buf)
    }

    pub fn read_mft_entry(&self, entry_number: u64) -> Result<mft::MftEntry> {
        let buf = self.read_mft_entry_raw(entry_number)?;
        Ok(mft::MftEntry::from_buffer(buf, entry_number)?)
    }

    fn read_mft_entry_raw_contiguous(&self, entry_number: u64) -> Result<Vec<u8>> {
        let entry_size = self.header.mft_entry_size as usize;
        let entry_offset = self
            .header
            .mft_offset_bytes()
            .saturating_add(entry_number.saturating_mul(self.header.mft_entry_size as u64));

        let mut buf = vec![0u8; entry_size];
        self.read_exact_at(entry_offset, &mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
impl Volume {
    /// Test helper: constructs a volume from an arbitrary [`ReadAt`] and a pre-parsed header.
    ///
    /// This bypasses NTFS bootstrapping (reading `$MFT` entry 0 to obtain mapping pairs) and is
    /// intended for unit tests that exercise lower-level helpers such as data-run readers.
    pub(crate) fn new_for_tests(
        image: Arc<dyn ReadAt>,
        volume_offset: u64,
        header: VolumeHeader,
    ) -> Self {
        Self {
            image,
            volume_offset,
            header,
            mft_data_runs: Vec::new(),
        }
    }
}
