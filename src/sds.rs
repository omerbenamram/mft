//! The security descriptor stream of `$Secure`, `$Secure:$SDS`.
//!
//! Since NTFS 3.0 a file's `$STANDARD_INFORMATION` holds a security ID, and the descriptor it
//! stands for is kept once per volume in `$SDS`. Each entry is a 20-byte header (the hash of the
//! descriptor, the security ID, the entry's own offset in the stream and its length) followed by
//! a self-relative security descriptor, and entries start on 16-byte boundaries. The stream is
//! written in 256 KiB blocks, each followed by a 256 KiB copy of itself.
//!
//! [`SdsEntries`] walks the blocks that aren't copies and yields each entry whose header gives
//! its own offset.
//!
//! <https://flatcap.github.io/linux-ntfs/ntfs/files/secure.html>

use std::collections::HashMap;

use serde::Serialize;

use crate::attribute::x50::SecurityDescriptorAttr;
use crate::utils::{read_u32, read_u64};

/// `$SDS` is written in blocks of this size, each followed by a copy of itself.
pub const SDS_BLOCK_SIZE: usize = 0x40000;

/// The size of an entry's header.
const HEADER_SIZE: usize = 20;

/// One entry of `$SDS`.
#[derive(Serialize, Debug, Clone)]
pub struct SdsEntry<'a> {
    /// The entry's offset in the stream.
    pub offset: u64,
    /// The ID `$STANDARD_INFORMATION` refers to the descriptor by.
    pub security_id: u32,
    /// The hash of the descriptor, which `$Secure:$SDH` indexes the entries by.
    pub hash: u32,
    /// Whether `hash` is the hash of the descriptor that follows it.
    pub valid_hash: bool,
    /// The header and the descriptor.
    pub length: u32,
    /// `None` when a SID or ACL of the descriptor runs past the entry.
    pub descriptor: Option<SecurityDescriptorAttr<'a>>,
}

impl<'a> SdsEntry<'a> {
    /// Parses the entry at `offset` of `sds`, the whole stream. Returns `None` unless its header
    /// gives `offset` as its offset and the entry fits in the rest of its block.
    pub fn from_slice(sds: &'a [u8], offset: usize) -> Option<Self> {
        let hash = read_u32(sds, offset)?;
        let security_id = read_u32(sds, offset + 4)?;
        let own_offset = read_u64(sds, offset + 8)?;
        let length = read_u32(sds, offset + 16)?;

        let block_end = (offset / SDS_BLOCK_SIZE + 1) * SDS_BLOCK_SIZE;
        let end = offset.checked_add(length as usize)?;
        if own_offset != offset as u64 || (length as usize) < HEADER_SIZE || end > block_end {
            return None;
        }
        let value = sds.get(offset + HEADER_SIZE..end)?;

        Some(SdsEntry {
            offset: own_offset,
            security_id,
            hash,
            valid_hash: descriptor_hash(value) == hash,
            length,
            descriptor: SecurityDescriptorAttr::from_slice(value),
        })
    }
}

/// The hash NTFS keeps of a descriptor: each 32-bit word is added to the hash rotated left by 3.
pub fn descriptor_hash(value: &[u8]) -> u32 {
    let (words, _) = value.as_chunks::<4>();
    words.iter().fold(0u32, |hash, word| {
        hash.rotate_left(3).wrapping_add(u32::from_le_bytes(*word))
    })
}

/// The entries of an `$SDS` stream, in the order they are stored.
///
/// # Example
///
/// ```
/// use mft::sds::SdsEntries;
///
/// // One entry: security ID 0x100, owner SYSTEM (S-1-5-18), no group and no ACLs.
/// let mut sds = vec![0u8; 64];
/// let descriptor: &[u8] = &[
///     0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00,
///     0x00, 0x00,
/// ];
/// sds[4..8].copy_from_slice(&0x100u32.to_le_bytes());
/// sds[16..20].copy_from_slice(&(20 + descriptor.len() as u32).to_le_bytes());
/// sds[20..20 + descriptor.len()].copy_from_slice(descriptor);
///
/// let entries: Vec<_> = SdsEntries::new(&sds).collect();
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].security_id, 0x100);
/// assert_eq!(entries[0].descriptor.as_ref().unwrap().to_sddl(), "O:S-1-5-18");
/// ```
pub struct SdsEntries<'a> {
    sds: &'a [u8],
    offset: usize,
}

impl<'a> SdsEntries<'a> {
    pub fn new(sds: &'a [u8]) -> Self {
        SdsEntries { sds, offset: 0 }
    }
}

impl<'a> Iterator for SdsEntries<'a> {
    type Item = SdsEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset + HEADER_SIZE <= self.sds.len() {
            // Odd blocks are copies of the block before them.
            if (self.offset / SDS_BLOCK_SIZE) % 2 == 1 {
                self.offset = (self.offset / SDS_BLOCK_SIZE + 1) * SDS_BLOCK_SIZE;
                continue;
            }
            match SdsEntry::from_slice(self.sds, self.offset) {
                Some(entry) => {
                    // A hash that doesn't match may mean a damaged length, which would skip the
                    // entries after it, so only a matching one is trusted to step over the entry.
                    self.offset += if entry.valid_hash {
                        (entry.length as usize).next_multiple_of(16)
                    } else {
                        16
                    };
                    return Some(entry);
                }
                // The zeros after a block's last entry, or a damaged entry.
                None => self.offset += 16,
            }
        }
        None
    }
}

/// The owner and the SDDL of each security ID in `$SDS`, to resolve the security ID of a file's
/// `$STANDARD_INFORMATION`. Where an ID has more than one entry, the last one wins, except that
/// an entry whose hash doesn't match never replaces one whose hash does.
#[derive(Debug, Clone, Default)]
pub struct SecurityIds(HashMap<u32, ResolvedSecurityId>);

/// What [`SecurityIds`] keeps of a descriptor.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSecurityId {
    pub owner: Option<String>,
    pub sddl: String,
}

impl SecurityIds {
    pub fn from_sds(sds: &[u8]) -> Self {
        // Whether the kept entry of each ID had a matching hash: a damaged entry doesn't replace
        // an intact one.
        let mut ids: HashMap<u32, (bool, ResolvedSecurityId)> = HashMap::new();
        for entry in SdsEntries::new(sds) {
            let Some(descriptor) = entry.descriptor else {
                continue;
            };
            if !entry.valid_hash && ids.get(&entry.security_id).is_some_and(|(valid, _)| *valid) {
                continue;
            }
            let resolved = ResolvedSecurityId {
                sddl: descriptor.to_sddl(),
                owner: descriptor.owner,
            };
            ids.insert(entry.security_id, (entry.valid_hash, resolved));
        }
        SecurityIds(
            ids.into_iter()
                .map(|(id, (_, resolved))| (id, resolved))
                .collect(),
        )
    }

    pub fn get(&self, security_id: u32) -> Option<&ResolvedSecurityId> {
        self.0.get(&security_id)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// An [`SdsEntry`] flattened to one CSV row.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FlatSdsEntry {
    pub offset: u64,
    pub security_id: u32,
    pub hash: String,
    pub valid_hash: bool,
    pub length: u32,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub control: Option<String>,
    pub sddl: Option<String>,
}

impl FlatSdsEntry {
    pub fn from_entry(entry: &SdsEntry<'_>) -> Self {
        let descriptor = entry.descriptor.as_ref();
        FlatSdsEntry {
            offset: entry.offset,
            security_id: entry.security_id,
            hash: format!("0x{:08x}", entry.hash),
            valid_hash: entry.valid_hash,
            length: entry.length,
            owner: descriptor.and_then(|d| d.owner.clone()),
            group: descriptor.and_then(|d| d.group.clone()),
            control: descriptor.map(|d| format!("0x{:04x}", d.control.bits())),
            sddl: descriptor.map(SecurityDescriptorAttr::to_sddl),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry at `offset` with an owner-only descriptor.
    fn put_entry(sds: &mut [u8], offset: usize, security_id: u32) {
        let descriptor: &[u8] = &[
            0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            0x12, 0x00, 0x00, 0x00,
        ];
        let entry = &mut sds[offset..offset + 20 + descriptor.len()];
        entry[..4].copy_from_slice(&descriptor_hash(descriptor).to_le_bytes());
        entry[4..8].copy_from_slice(&security_id.to_le_bytes());
        entry[8..16].copy_from_slice(&(offset as u64).to_le_bytes());
        entry[16..20].copy_from_slice(&(20 + descriptor.len() as u32).to_le_bytes());
        entry[20..].copy_from_slice(descriptor);
    }

    #[test]
    fn skips_mirror_blocks_and_damaged_entries() {
        let mut sds = vec![0u8; 3 * SDS_BLOCK_SIZE];
        put_entry(&mut sds, 0, 0x100);
        // The 52-byte entry is padded to 64.
        put_entry(&mut sds, 64, 0x101);
        // A copy: its header gives the offset of the original.
        sds.copy_within(..128, SDS_BLOCK_SIZE);
        put_entry(&mut sds, 2 * SDS_BLOCK_SIZE, 0x102);
        // A header whose offset isn't its own.
        put_entry(&mut sds, 2 * SDS_BLOCK_SIZE + 64, 0x103);
        sds[2 * SDS_BLOCK_SIZE + 64 + 8] ^= 1;

        let entries: Vec<_> = SdsEntries::new(&sds).collect();
        let ids: Vec<_> = entries.iter().map(|e| e.security_id).collect();
        assert_eq!(ids, [0x100, 0x101, 0x102]);
        assert!(entries.iter().all(|e| e.valid_hash));

        let ids = SecurityIds::from_sds(&sds);
        assert_eq!(ids.len(), 3);
        assert_eq!(ids.get(0x101).unwrap().owner.as_deref(), Some("S-1-5-18"));
    }

    #[test]
    fn a_damaged_length_does_not_hide_the_next_entries() {
        let mut sds = vec![0u8; 256];
        put_entry(&mut sds, 0, 0x100);
        put_entry(&mut sds, 64, 0x101);
        // The first entry claims to run over the second.
        sds[16..20].copy_from_slice(&200u32.to_le_bytes());

        let entries: Vec<_> = SdsEntries::new(&sds).collect();
        let ids: Vec<_> = entries.iter().map(|e| e.security_id).collect();
        assert_eq!(ids, [0x100, 0x101]);
        assert!(!entries[0].valid_hash);
        assert!(entries[1].valid_hash);
    }

    #[test]
    fn a_damaged_entry_does_not_replace_an_intact_one() {
        let mut sds = vec![0u8; 128];
        put_entry(&mut sds, 0, 0x100);
        put_entry(&mut sds, 64, 0x100);
        // Make the second entry's owner S-1-5-19, which no longer matches its hash.
        sds[64 + 20 + 28] = 0x13;
        let ids = SecurityIds::from_sds(&sds);
        assert_eq!(ids.get(0x100).unwrap().owner.as_deref(), Some("S-1-5-18"));
    }

    #[test]
    fn entries_may_not_cross_a_block() {
        let mut sds = vec![0u8; SDS_BLOCK_SIZE + 64];
        put_entry(&mut sds, SDS_BLOCK_SIZE - 32, 0x100);
        assert_eq!(SdsEntries::new(&sds).count(), 0);
    }
}
