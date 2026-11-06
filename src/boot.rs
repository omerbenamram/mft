//! The NTFS boot sector, the first sector of the volume and of the `$Boot` file.
//!
//! [`BootSector::from_slice`] reads the BIOS parameter block: the sector and cluster sizes, the
//! size of the volume, where `$MFT` and `$MFTMirr` start, the size of a file record and of an
//! index record, and the volume serial number.
//!
//! <https://flatcap.github.io/linux-ntfs/ntfs/files/boot.html>

use serde::Serialize;

use crate::err::{Error, Result};
use crate::utils::{read_u16, read_u32, read_u64};

/// The size of the boot sector.
pub const BOOT_SECTOR_SIZE: usize = 512;

/// The BIOS parameter block of an NTFS boot sector, with the sizes and offsets it implies.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct BootSector {
    /// The OEM ID, `NTFS    `.
    pub oem_id: String,
    pub bytes_per_sector: u16,
    /// Decoded: a byte of 0xF4 (-12) means 2^12 sectors, which Windows 10 1709 and later use for
    /// clusters larger than 64 KiB.
    pub sectors_per_cluster: u32,
    /// `bytes_per_sector * sectors_per_cluster`.
    pub cluster_size: u64,
    pub media_descriptor: u8,
    pub sectors_per_track: u16,
    pub number_of_heads: u16,
    /// The sectors before the volume on its disk.
    pub hidden_sectors: u32,
    /// The sectors in the volume, less the backup boot sector at its end.
    pub total_sectors: u64,
    /// `total_sectors * bytes_per_sector`.
    pub volume_size: u64,
    /// The cluster `$MFT` starts at.
    pub mft_lcn: u64,
    /// The byte offset in the volume `$MFT` starts at.
    pub mft_offset: u64,
    pub mft_mirror_lcn: u64,
    pub mft_mirror_offset: u64,
    /// The size of a file record (`FILE`) in bytes.
    pub mft_entry_size: u32,
    /// The size of an index record (`INDX`) in bytes.
    pub index_entry_size: u32,
    pub volume_serial_number: u64,
    /// The low 32 bits of the serial number as `vol` and `dir` show them (`1234-ABCD`), the value
    /// shortcuts and prefetch files record for the volume.
    pub volume_serial: String,
    pub checksum: u32,
}

impl BootSector {
    /// Parses the first 512 bytes of `buf`, which must have the `NTFS    ` OEM ID and the
    /// `0x55AA` signature.
    ///
    /// # Example
    ///
    /// ```
    /// use mft::boot::BootSector;
    ///
    /// let mut sector = [0u8; 512];
    /// sector[3..11].copy_from_slice(b"NTFS    ");
    /// sector[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    /// sector[0x0D] = 8; // 4 KiB clusters
    /// sector[0x28..0x30].copy_from_slice(&2_097_151u64.to_le_bytes());
    /// sector[0x30..0x38].copy_from_slice(&786_432u64.to_le_bytes());
    /// sector[0x40] = 0xF6; // 2^10 bytes per file record
    /// sector[0x44] = 1; // one cluster per index record
    /// sector[0x48..0x50].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    /// sector[510] = 0x55;
    /// sector[511] = 0xAA;
    ///
    /// let boot = BootSector::from_slice(&sector).unwrap();
    /// assert_eq!(boot.cluster_size, 4096);
    /// assert_eq!(boot.mft_offset, 786_432 * 4096);
    /// assert_eq!(boot.mft_entry_size, 1024);
    /// assert_eq!(boot.index_entry_size, 4096);
    /// assert_eq!(boot.volume_serial, "9ABC-DEF0");
    /// ```
    pub fn from_slice(buf: &[u8]) -> Result<Self> {
        let invalid = |detail: &str| Error::InvalidBootSector {
            detail: detail.to_string(),
        };
        let sector = buf
            .get(..BOOT_SECTOR_SIZE)
            .ok_or_else(|| invalid("shorter than 512 bytes"))?;
        if &sector[3..11] != b"NTFS    " {
            return Err(invalid("no `NTFS    ` OEM ID at offset 3"));
        }
        if sector[510..512] != [0x55, 0xAA] {
            return Err(invalid("no 0x55AA signature at offset 510"));
        }

        // Every read is in bounds of the 512 bytes.
        let u16_at = |offset| read_u16(sector, offset).unwrap_or_default();
        let u32_at = |offset| read_u32(sector, offset).unwrap_or_default();
        let u64_at = |offset| read_u64(sector, offset).unwrap_or_default();

        let bytes_per_sector = u16_at(0x0B);
        let sectors_per_cluster = match sector[0x0D] {
            raw @ 0..=0x80 => u32::from(raw),
            raw => 1u32
                .checked_shl(256 - u32::from(raw))
                .ok_or_else(|| invalid("sectors per cluster out of range"))?,
        };
        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return Err(invalid("bytes per sector or sectors per cluster is zero"));
        }
        let cluster_size = u64::from(bytes_per_sector) * u64::from(sectors_per_cluster);

        let record_size = |offset: usize, name: &str| -> Result<u32> {
            // Positive: a count of clusters. Negative: the log2 of a size in bytes.
            let size = match sector[offset] as i8 {
                clusters @ 1.. => cluster_size.checked_mul(clusters as u64),
                shift @ -31..=-1 => Some(1 << -shift),
                _ => None,
            };
            size.and_then(|size| u32::try_from(size).ok())
                .ok_or_else(|| invalid(&format!("{name} out of range")))
        };

        let total_sectors = u64_at(0x28);
        let mft_lcn = u64_at(0x30);
        let mft_mirror_lcn = u64_at(0x38);
        let volume_serial_number = u64_at(0x48);
        let low = volume_serial_number as u32;

        Ok(BootSector {
            oem_id: String::from_utf8_lossy(&sector[3..11]).into_owned(),
            bytes_per_sector,
            sectors_per_cluster,
            cluster_size,
            media_descriptor: sector[0x15],
            sectors_per_track: u16_at(0x18),
            number_of_heads: u16_at(0x1A),
            hidden_sectors: u32_at(0x1C),
            total_sectors,
            volume_size: total_sectors.saturating_mul(u64::from(bytes_per_sector)),
            mft_lcn,
            mft_offset: mft_lcn.saturating_mul(cluster_size),
            mft_mirror_lcn,
            mft_mirror_offset: mft_mirror_lcn.saturating_mul(cluster_size),
            mft_entry_size: record_size(0x40, "file record size")?,
            index_entry_size: record_size(0x44, "index record size")?,
            volume_serial_number,
            volume_serial: format!("{:04X}-{:04X}", low >> 16, low & 0xFFFF),
            checksum: u32_at(0x50),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sector() -> [u8; 512] {
        let mut sector = [0u8; 512];
        sector[3..11].copy_from_slice(b"NTFS    ");
        sector[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        sector[0x0D] = 8;
        sector[0x40] = 0xF6;
        sector[0x44] = 1;
        sector[510] = 0x55;
        sector[511] = 0xAA;
        sector
    }

    #[test]
    fn large_clusters_are_a_power_of_two() {
        let mut sector = sector();
        // 2^12 sectors of 512 bytes: 2 MiB clusters.
        sector[0x0D] = 0xF4;
        let boot = BootSector::from_slice(&sector).unwrap();
        assert_eq!(boot.sectors_per_cluster, 4096);
        assert_eq!(boot.cluster_size, 2 << 20);
        // One cluster per index record.
        assert_eq!(boot.index_entry_size, 2 << 20);
    }

    #[test]
    fn rejects_other_file_systems_and_bad_sizes() {
        let mut fat = sector();
        fat[3..11].copy_from_slice(b"MSDOS5.0");
        assert!(BootSector::from_slice(&fat).is_err());

        let mut unsigned = sector();
        unsigned[511] = 0;
        assert!(BootSector::from_slice(&unsigned).is_err());

        let mut zero = sector();
        zero[0x0D] = 0;
        assert!(BootSector::from_slice(&zero).is_err());

        let mut huge = sector();
        huge[0x40] = 0x80;
        assert!(BootSector::from_slice(&huge).is_err());

        assert!(BootSector::from_slice(&sector()[..511]).is_err());
    }
}
