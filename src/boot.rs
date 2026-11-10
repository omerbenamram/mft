//! The NTFS boot sector, the first sector of the volume and of the `$Boot` file.
//!
//! [`BootSector::from_slice`] reads the BIOS parameter block: the sector and cluster sizes, the
//! size of the volume, where `$MFT` and `$MFTMirr` start, the size of a file record and of an
//! index record, and the volume serial number.
//!
//! <https://flatcap.github.io/linux-ntfs/ntfs/files/boot.html>

use serde::{Serialize, Serializer};

use crate::err::{Error, Result};

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
    /// Serialized as a hex string (`0xE49CB2C49CB2C4F8`), since JSON numbers above 2^53 lose
    /// precision in many readers.
    #[serde(serialize_with = "serialize_serial_number")]
    pub volume_serial_number: u64,
    /// The low 32 bits of the serial number as `vol` and `dir` show them (`1234-ABCD`), the value
    /// shortcuts and prefetch files record for the volume.
    pub volume_serial: String,
    pub checksum: u32,
}

fn serialize_serial_number<S: Serializer>(
    serial: &u64,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("0x{serial:016X}"))
}

/// The largest cluster NTFS supports.
const MAX_CLUSTER_SIZE: u64 = 2 << 20;

impl BootSector {
    /// Parses the first 512 bytes of `buf`, which must have the `NTFS    ` OEM ID and the
    /// `0x55AA` signature, a power-of-two sector size from 256 to 4096 bytes, a power-of-two
    /// count of sectors per cluster for clusters of at most 2 MiB, and offsets and sizes that fit
    /// in 64 bits.
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
        let sector: &[u8; BOOT_SECTOR_SIZE] = buf
            .first_chunk()
            .ok_or_else(|| invalid("shorter than 512 bytes"))?;
        if &sector[3..11] != b"NTFS    " {
            return Err(invalid("no `NTFS    ` OEM ID at offset 3"));
        }
        if sector[510..512] != [0x55, 0xAA] {
            return Err(invalid("no 0x55AA signature at offset 510"));
        }

        let u16_at = |offset| u16::from_le_bytes(le_bytes(sector, offset));
        let u32_at = |offset| u32::from_le_bytes(le_bytes(sector, offset));
        let u64_at = |offset| u64::from_le_bytes(le_bytes(sector, offset));

        let bytes_per_sector = u16_at(0x0B);
        if !bytes_per_sector.is_power_of_two() || !(256..=4096).contains(&bytes_per_sector) {
            return Err(invalid(&format!(
                "bytes per sector {bytes_per_sector} is not a power of two from 256 to 4096"
            )));
        }
        // Up to 0x80, the count itself. Above, the negative log2 of the count.
        let sectors_per_cluster = match sector[0x0D] {
            raw @ 0..=0x80 => u32::from(raw),
            raw => 1u32.checked_shl(256 - u32::from(raw)).unwrap_or(0),
        };
        let cluster_size = u64::from(bytes_per_sector) * u64::from(sectors_per_cluster);
        if !sectors_per_cluster.is_power_of_two() || cluster_size > MAX_CLUSTER_SIZE {
            return Err(invalid(&format!(
                "sectors per cluster byte 0x{:02X} is not a power of two for a cluster of at \
                 most 2 MiB",
                sector[0x0D]
            )));
        }

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
        let bytes = |count: u64, unit: u64, name: &str| {
            count
                .checked_mul(unit)
                .ok_or_else(|| invalid(&format!("{name} overflows")))
        };

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
            volume_size: bytes(total_sectors, u64::from(bytes_per_sector), "volume size")?,
            mft_lcn,
            mft_offset: bytes(mft_lcn, cluster_size, "$MFT offset")?,
            mft_mirror_lcn,
            mft_mirror_offset: bytes(mft_mirror_lcn, cluster_size, "$MFTMirr offset")?,
            mft_entry_size: record_size(0x40, "file record size")?,
            index_entry_size: record_size(0x44, "index record size")?,
            volume_serial_number,
            volume_serial: format!("{:04X}-{:04X}", low >> 16, low & 0xFFFF),
            checksum: u32_at(0x50),
        })
    }
}

/// A [`BootSector`] as one CSV row, with the column names of the other CSVs.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FlatBootSector {
    pub oem_id: String,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u32,
    pub cluster_size: u64,
    pub media_descriptor: u8,
    pub sectors_per_track: u16,
    pub number_of_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors: u64,
    pub volume_size: u64,
    pub mft_lcn: u64,
    pub mft_offset: u64,
    pub mft_mirror_lcn: u64,
    pub mft_mirror_offset: u64,
    pub mft_entry_size: u32,
    pub index_entry_size: u32,
    /// As in JSON, a hex string.
    #[serde(serialize_with = "serialize_serial_number")]
    pub volume_serial_number: u64,
    pub volume_serial: String,
    pub checksum: u32,
}

impl From<&BootSector> for FlatBootSector {
    fn from(boot: &BootSector) -> Self {
        let boot = boot.clone();
        FlatBootSector {
            oem_id: boot.oem_id,
            bytes_per_sector: boot.bytes_per_sector,
            sectors_per_cluster: boot.sectors_per_cluster,
            cluster_size: boot.cluster_size,
            media_descriptor: boot.media_descriptor,
            sectors_per_track: boot.sectors_per_track,
            number_of_heads: boot.number_of_heads,
            hidden_sectors: boot.hidden_sectors,
            total_sectors: boot.total_sectors,
            volume_size: boot.volume_size,
            mft_lcn: boot.mft_lcn,
            mft_offset: boot.mft_offset,
            mft_mirror_lcn: boot.mft_mirror_lcn,
            mft_mirror_offset: boot.mft_mirror_offset,
            mft_entry_size: boot.mft_entry_size,
            index_entry_size: boot.index_entry_size,
            volume_serial_number: boot.volume_serial_number,
            volume_serial: boot.volume_serial,
            checksum: boot.checksum,
        }
    }
}

/// The `N` bytes at `offset` of the sector.
fn le_bytes<const N: usize>(sector: &[u8; BOOT_SECTOR_SIZE], offset: usize) -> [u8; N] {
    std::array::from_fn(|i| sector[offset + i])
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

        for bytes_per_sector in [0u16, 128, 513, 8192] {
            let mut odd = sector();
            odd[0x0B..0x0D].copy_from_slice(&bytes_per_sector.to_le_bytes());
            assert!(BootSector::from_slice(&odd).is_err(), "{bytes_per_sector}");
        }
        // 3 sectors, 2^32 sectors, and 2^13 sectors of 512 bytes (4 MiB clusters).
        for raw in [3u8, 0xE0, 0xF3] {
            let mut odd = sector();
            odd[0x0D] = raw;
            assert!(BootSector::from_slice(&odd).is_err(), "{raw:#x}");
        }

        let mut huge = sector();
        huge[0x40] = 0x80;
        assert!(BootSector::from_slice(&huge).is_err());

        assert!(BootSector::from_slice(&sector()[..511]).is_err());
    }

    #[test]
    fn rejects_offsets_that_overflow() {
        let mut far = sector();
        far[0x30..0x38].copy_from_slice(&(u64::MAX / 1024).to_le_bytes());
        let err = BootSector::from_slice(&far).unwrap_err();
        assert!(err.to_string().contains("$MFT offset overflows"), "{err}");

        let mut big = sector();
        big[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(BootSector::from_slice(&big).is_err());
    }

    #[test]
    fn serial_number_is_a_hex_string() {
        let mut sector = sector();
        sector[0x48..0x50].copy_from_slice(&0xE49C_B2C4_9CB2_C4F8u64.to_le_bytes());
        let boot = BootSector::from_slice(&sector).unwrap();
        let json = serde_json::to_value(&boot).unwrap();
        assert_eq!(json["volume_serial_number"], "0xE49CB2C49CB2C4F8");

        let mut csv = csv::Writer::from_writer(vec![]);
        csv.serialize(FlatBootSector::from(&boot)).unwrap();
        let csv = String::from_utf8(csv.into_inner().unwrap()).unwrap();
        assert!(csv.starts_with("OemId,BytesPerSector,"), "{csv}");
        assert!(csv.contains(",0xE49CB2C49CB2C4F8,9CB2-C4F8,"), "{csv}");
    }
}
