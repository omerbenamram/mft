//! NTFS volume boot record (VBR) parser.
//!
//! This module provides [`VolumeHeader`], a compact parser for the NTFS boot sector fields that
//! the rest of this crate needs to interpret on-disk structures (cluster sizing, `$MFT` location,
//! record sizing, and the volume serial number).
//!
//! The focus is **correctness** and actionable diagnostics on corrupted inputs. Parsing uses
//! [`crate::parse::Reader`], so offset-aware parse errors can be reported relative to the source
//! image by threading a `base_offset` through the reader.
//!
//! Current limitations:
//! - Only the canonical OEM ID `NTFS    ` is accepted.
//! - Only the first 512 bytes of the boot sector are parsed; the backup VBR is not consulted.
//! - Only a small subset of BPB fields are validated (enough to derive layout parameters).

use crate::image::ReadAt;
use crate::ntfs::{Error, Result};
use crate::parse::Reader;
use std::fmt;

/// NTFS Volume Boot Record (VBR) derived parameters.
///
#[derive(Debug, Clone)]
pub struct VolumeHeader {
    /// Bytes per sector.
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Cluster size in bytes (`bytes_per_sector * sectors_per_cluster`).
    pub cluster_size: u32,

    /// Total sectors in the volume.
    pub total_sectors: u64,
    /// Logical cluster number (LCN) of `$MFT`.
    pub mft_lcn: u64,
    /// Logical cluster number (LCN) of `$MFTMirr`.
    pub mirror_mft_lcn: u64,

    /// MFT file record size in bytes.
    pub mft_entry_size: u32,
    /// Index record size in bytes.
    pub index_entry_size: u32,

    /// Volume serial number.
    pub volume_serial_number: u64,
}

impl fmt::Display for VolumeHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "bytes_per_sector: {}", self.bytes_per_sector)?;
        writeln!(f, "sectors_per_cluster: {}", self.sectors_per_cluster)?;
        writeln!(f, "cluster_size: {}", self.cluster_size)?;
        writeln!(f, "total_sectors: {}", self.total_sectors)?;
        writeln!(f, "volume_size_bytes: {}", self.volume_size_bytes())?;
        writeln!(f, "mft_lcn: {}", self.mft_lcn)?;
        writeln!(f, "mirror_mft_lcn: {}", self.mirror_mft_lcn)?;
        writeln!(f, "mft_entry_size: {}", self.mft_entry_size)?;
        writeln!(f, "index_entry_size: {}", self.index_entry_size)?;
        writeln!(
            f,
            "volume_serial_number: 0x{:016x}",
            self.volume_serial_number
        )?;
        Ok(())
    }
}

impl VolumeHeader {
    /// Reads and parses the NTFS boot sector at `volume_offset`.
    ///
    /// `volume_offset` should point at the start of the NTFS volume within `image`
    /// (for example: the partition start for a partitioned disk image).
    pub fn read_from_image(image: &dyn ReadAt, volume_offset: u64) -> Result<Self> {
        let mut boot = [0u8; 512];
        image.read_exact_at(volume_offset, &mut boot)?;
        Self::from_boot_sector(&boot, volume_offset)
    }

    /// Parses an NTFS boot sector buffer.
    ///
    /// `base_offset` is used only for error reporting: it tells the underlying [`Reader`] what
    /// offset to report in parse errors (useful when `boot` is a slice taken from a larger image).
    pub fn from_boot_sector(boot: &[u8; 512], base_offset: u64) -> Result<Self> {
        // Validate OEM ID.
        if &boot[3..11] != b"NTFS    " {
            return Err(Error::InvalidBootSector {
                message: "missing OEM ID (expected `NTFS    ` at offset 0x03)",
            });
        }

        // Validate signature.
        if boot[510] != 0x55 || boot[511] != 0xAA {
            return Err(Error::InvalidBootSector {
                message: "missing boot sector signature (expected 0x55AA at offset 0x1FE)",
            });
        }

        let mut r = Reader::with_base_offset(boot, base_offset);

        // Skip jump (3) + OEM ID (8)
        r.skip("jump+oem_id", 11)?;

        let bytes_per_sector = r.u16_le("bytes_per_sector")?;
        let sectors_per_cluster = r.u8("sectors_per_cluster")?;

        // Skip: reserved sectors (2), zeros (3), unused (2), media (1), zeros (2),
        // sectors/track (2), heads (2), hidden sectors (4), unused (4), unused (4).
        r.skip("bpb_skip", 2 + 3 + 2 + 1 + 2 + 2 + 2 + 4 + 4 + 4)?;

        let total_sectors = r.u64_le("total_sectors")?;
        let mft_lcn = r.u64_le("mft_lcn")?;
        let mirror_mft_lcn = r.u64_le("mirror_mft_lcn")?;

        let clusters_per_mft_record_raw = r.u8("clusters_per_mft_record_raw")? as i8;
        r.skip("clusters_per_mft_record_padding", 3)?;

        let clusters_per_index_record_raw = r.u8("clusters_per_index_record_raw")? as i8;
        r.skip("clusters_per_index_record_padding", 3)?;

        let volume_serial_number = r.u64_le("volume_serial_number")?;

        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return Err(Error::InvalidBootSector {
                message: "bytes_per_sector or sectors_per_cluster is zero",
            });
        }

        let cluster_size = u32::from(bytes_per_sector) * u32::from(sectors_per_cluster);

        let mft_entry_size =
            compute_record_size("mft_entry_size", clusters_per_mft_record_raw, cluster_size)?;
        let index_entry_size = compute_record_size(
            "index_entry_size",
            clusters_per_index_record_raw,
            cluster_size,
        )?;

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            cluster_size,
            total_sectors,
            mft_lcn,
            mirror_mft_lcn,
            mft_entry_size,
            index_entry_size,
            volume_serial_number,
        })
    }

    pub fn volume_size_bytes(&self) -> u64 {
        self.total_sectors
            .saturating_mul(self.bytes_per_sector as u64)
    }

    /// Returns the byte offset of `$MFT` relative to the start of the volume.
    ///
    /// Note this does **not** include any partition/volume base offset; callers reading from a
    /// larger disk image should add the volume base offset separately.
    pub fn mft_offset_bytes(&self) -> u64 {
        self.mft_lcn.saturating_mul(self.cluster_size as u64)
    }
}

/// Decodes an NTFS record size field from the boot sector.
///
/// NTFS encodes these record sizes as a signed 8-bit integer:
/// - If the value is positive, it is a count of clusters.
/// - If the value is negative, the size is \(2^{|v|}\) bytes.
/// - A value of 0 is invalid.
fn compute_record_size(
    _field: &'static str,
    clusters_per_record: i8,
    cluster_size: u32,
) -> Result<u32> {
    if clusters_per_record > 0 {
        Ok(cluster_size.saturating_mul(clusters_per_record as u32))
    } else if clusters_per_record < 0 {
        // Avoid overflow on `i8::MIN` (negating -128 is undefined in `i8`).
        let shift = u32::from(clusters_per_record.unsigned_abs());
        if shift >= 31 {
            return Err(Error::InvalidBootSector {
                message: "record size exponent out of range",
            });
        }
        Ok(1u32 << shift)
    } else {
        Err(Error::InvalidBootSector {
            message: "record size value cannot be 0",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_sector_template() -> [u8; 512] {
        let mut boot = [0u8; 512];
        // OEM ID.
        boot[3..11].copy_from_slice(b"NTFS    ");
        // Signature.
        boot[510] = 0x55;
        boot[511] = 0xAA;
        boot
    }

    fn write_u16_le(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn write_u64_le(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn parses_valid_boot_sector() {
        let mut boot = boot_sector_template();
        write_u16_le(&mut boot, 0x0b, 512);
        boot[0x0d] = 8; // sectors per cluster => cluster_size=4096

        write_u64_le(&mut boot, 0x28, 0x1122_3344_5566_7788);
        write_u64_le(&mut boot, 0x30, 4);
        write_u64_le(&mut boot, 0x38, 8);

        boot[0x40] = 0xF6; // -10 => 1024 bytes
        boot[0x44] = 0x01; // 1 cluster => 4096 bytes

        write_u64_le(&mut boot, 0x48, 0xAABB_CCDD_1122_3344);

        let h = VolumeHeader::from_boot_sector(&boot, 0).unwrap();
        assert_eq!(h.bytes_per_sector, 512);
        assert_eq!(h.sectors_per_cluster, 8);
        assert_eq!(h.cluster_size, 4096);
        assert_eq!(h.total_sectors, 0x1122_3344_5566_7788);
        assert_eq!(h.mft_lcn, 4);
        assert_eq!(h.mirror_mft_lcn, 8);
        assert_eq!(h.mft_entry_size, 1024);
        assert_eq!(h.index_entry_size, 4096);
        assert_eq!(h.volume_serial_number, 0xAABB_CCDD_1122_3344);
    }

    #[test]
    fn rejects_bad_oem_id() {
        let mut boot = boot_sector_template();
        boot[3..11].copy_from_slice(b"NOTNTFS!");
        let err = VolumeHeader::from_boot_sector(&boot, 0).unwrap_err();
        match err {
            Error::InvalidBootSector { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_signature() {
        let mut boot = boot_sector_template();
        boot[510] = 0;
        boot[511] = 0;
        let err = VolumeHeader::from_boot_sector(&boot, 0).unwrap_err();
        match err {
            Error::InvalidBootSector { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_bytes_per_sector_or_sectors_per_cluster() {
        let mut boot = boot_sector_template();
        write_u16_le(&mut boot, 0x0b, 0);
        boot[0x0d] = 8;
        assert!(matches!(
            VolumeHeader::from_boot_sector(&boot, 0),
            Err(Error::InvalidBootSector { .. })
        ));

        let mut boot = boot_sector_template();
        write_u16_le(&mut boot, 0x0b, 512);
        boot[0x0d] = 0;
        assert!(matches!(
            VolumeHeader::from_boot_sector(&boot, 0),
            Err(Error::InvalidBootSector { .. })
        ));
    }

    #[test]
    fn record_size_exponent_out_of_range_is_error_not_panic() {
        let mut boot = boot_sector_template();
        write_u16_le(&mut boot, 0x0b, 512);
        boot[0x0d] = 8;

        // i8::MIN => abs=128, out of supported range; should error (and not overflow/panic).
        boot[0x40] = 0x80; // -128
        boot[0x44] = 0x01;

        let err = VolumeHeader::from_boot_sector(&boot, 0).unwrap_err();
        match err {
            Error::InvalidBootSector { message } => {
                assert_eq!(message, "record size exponent out of range");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn record_size_zero_is_error() {
        let mut boot = boot_sector_template();
        write_u16_le(&mut boot, 0x0b, 512);
        boot[0x0d] = 8;

        boot[0x40] = 0; // invalid
        boot[0x44] = 1;
        let err = VolumeHeader::from_boot_sector(&boot, 0).unwrap_err();
        match err {
            Error::InvalidBootSector { message } => {
                assert_eq!(message, "record size value cannot be 0");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
