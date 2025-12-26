use crate::ntfs::{Error, Result};

/// Number of UTF-16 code units in the NTFS `$UpCase` mapping table (BMP only).
pub const UPCASE_CHARACTER_COUNT: usize = 65_536;

/// Size of the `$UpCase` table in bytes (65536 * 2).
pub const UPCASE_TABLE_SIZE_BYTES: usize = UPCASE_CHARACTER_COUNT * 2;

/// A deterministic uppercasing table used by NTFS for case-insensitive name comparisons.
///
/// NTFS stores this mapping in the `$UpCase` system file (MFT entry 10).
/// The table is defined over **UTF-16 code units** (`u16`) and therefore supports unpaired
/// surrogates (they will typically map to themselves).
#[derive(Debug, Clone)]
pub struct UpcaseTable {
    map: Vec<u16>,
}

impl UpcaseTable {
    /// Parses a `$UpCase` table from its on-disk bytes.
    ///
    /// Strict validation:
    /// - input must be exactly 131072 bytes (65536 u16 values)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != UPCASE_TABLE_SIZE_BYTES {
            return Err(Error::InvalidData {
                message: format!(
                    "invalid $UpCase size: expected {UPCASE_TABLE_SIZE_BYTES} bytes, got {}",
                    bytes.len()
                ),
            });
        }

        let map = bytes
            .chunks_exact(2)
            .map(|two| u16::from_le_bytes([two[0], two[1]]))
            .collect::<Vec<_>>();

        debug_assert_eq!(map.len(), UPCASE_CHARACTER_COUNT);

        Ok(Self { map })
    }

    /// Maps a UTF-16 code unit to its uppercase equivalent per the `$UpCase` table.
    #[inline]
    pub fn map_u16(&self, u: u16) -> u16 {
        self.map[u as usize]
    }

    #[cfg(test)]
    pub(crate) fn identity_for_tests() -> Self {
        let map = (0u32..UPCASE_CHARACTER_COUNT as u32)
            .map(|v| v as u16)
            .collect();
        Self { map }
    }

    #[cfg(test)]
    pub(crate) fn from_mapping_for_tests(map: Vec<u16>) -> Self {
        assert_eq!(map.len(), UPCASE_CHARACTER_COUNT);
        Self { map }
    }
}
