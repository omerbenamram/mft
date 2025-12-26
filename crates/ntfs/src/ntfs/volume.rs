use crate::image::ReadAt;
use crate::ntfs::Result;
use crate::ntfs::data_stream::read_from_data_runs;
use crate::ntfs::volume_header::VolumeHeader;
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
            if let Some(dr) = attr.data.into_data_runs() {
                volume.mft_data_runs = dr.data_runs;
                break;
            }
        }

        Ok(volume)
    }

    pub fn volume_offset(&self) -> u64 {
        self.volume_offset
    }

    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.image
            .read_exact_at(self.volume_offset.saturating_add(offset), buf)
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
