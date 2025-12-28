//! EWF2 chunk-table primitives.
//!
//! EWF2 stores per-chunk metadata in the *sector table* section. Each table entry contains a flags
//! bitmask describing how the corresponding chunk is stored (compressed, checksumed, pattern fill,
//! etc.).

use bitflags::bitflags;

bitflags! {
    /// EWF2 sector-table entry flags.
    ///
    /// Unknown bits are preserved (see [`Ewf2ChunkDataFlags::from_raw`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Ewf2ChunkDataFlags: u32 {
        const COMPRESSED  = 0x0000_0001;
        const CHECKSUMED  = 0x0000_0002;
        const PATTERNFILL = 0x0000_0004;
    }
}

impl Ewf2ChunkDataFlags {
    pub(crate) fn from_raw(raw: u32) -> Self {
        Self::from_bits_retain(raw)
    }

    pub(crate) fn raw(self) -> u32 {
        self.bits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_data_flags_preserves_unknown_bits() {
        let raw = 0x4000_0000u32 | Ewf2ChunkDataFlags::CHECKSUMED.bits();
        let flags = Ewf2ChunkDataFlags::from_raw(raw);
        assert_eq!(flags.raw(), raw);
        assert!(flags.contains(Ewf2ChunkDataFlags::CHECKSUMED));
        assert!(!flags.contains(Ewf2ChunkDataFlags::COMPRESSED));
    }
}
