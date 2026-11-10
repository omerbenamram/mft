//! The security descriptor stream of `$Secure`, `$Secure:$SDS`.
//!
//! Since NTFS 3.0 a file's `$STANDARD_INFORMATION` holds a security ID, and the descriptor it
//! stands for is kept once per volume in `$SDS`. Each entry is a 20-byte header (the hash of the
//! descriptor, the security ID, the entry's own offset in the stream and its length) followed by
//! a self-relative security descriptor, and entries start on 16-byte boundaries. The stream is
//! written in 256 KiB blocks, each followed by a 256 KiB copy of itself.
//!
//! [`SdsEntries`] walks each block and its copy, and yields each entry whose header gives its own
//! offset. An entry of a block is taken from the copy when it is damaged in the block.
//!
//! <https://flatcap.github.io/linux-ntfs/ntfs/files/secure.html>

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Serialize, Serializer};

use crate::attribute::x50::{SecurityDescriptorAttr, SecurityDescriptorControl};
use crate::utils::{read_u32, read_u64};

/// `$SDS` is written in blocks of this size, each followed by a copy of itself.
pub const SDS_BLOCK_SIZE: usize = 0x40000;

/// The size of an entry's header.
const HEADER_SIZE: usize = 20;

/// The size of the fixed part of a self-relative security descriptor.
const DESCRIPTOR_HEADER_SIZE: usize = 20;

/// The end of the 256 KiB block `offset` is in.
fn block_end(offset: usize) -> usize {
    (offset / SDS_BLOCK_SIZE + 1) * SDS_BLOCK_SIZE
}

/// One entry of `$SDS`.
#[derive(Serialize, Debug, Clone)]
pub struct SdsEntry<'a> {
    /// The entry's offset in the stream, as its header gives it. For an entry read from a
    /// block's copy, this is the offset of the original, 256 KiB before it.
    pub offset: u64,
    /// Whether the entry was read from a block's copy because it is damaged or missing in the
    /// block itself.
    pub from_mirror: bool,
    /// The ID `$STANDARD_INFORMATION` refers to the descriptor by.
    pub security_id: u32,
    /// The hash of the descriptor, which `$Secure:$SDH` indexes the entries by. Serialized as a
    /// hex string (`0x32fec6cb`).
    #[serde(serialize_with = "serialize_hash")]
    pub hash: u32,
    /// Whether `hash` is the hash of the descriptor that follows it, and the descriptor starts
    /// like a self-relative one (revision 1, `SE_SELF_RELATIVE`). An empty or zeroed descriptor
    /// never has a valid hash, even though its hash is 0.
    pub valid_hash: bool,
    /// The header and the descriptor.
    pub length: u32,
    /// `None` when a SID or ACL of the descriptor runs past the entry.
    pub descriptor: Option<SecurityDescriptorAttr<'a>>,
}

fn serialize_hash<S: Serializer>(hash: &u32, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("0x{hash:08x}"))
}

impl<'a> SdsEntry<'a> {
    /// Parses the entry at `offset` of `sds`, the whole stream. Returns `None` unless its header
    /// gives `offset` as its offset and the entry fits in the rest of its block.
    pub fn from_slice(sds: &'a [u8], offset: usize) -> Option<Self> {
        Self::parse(sds, offset, false)
    }

    /// Parses the entry at `offset`, which is in a block's copy when `from_mirror` is set: its
    /// header then gives the offset of the original, a block before it.
    fn parse(sds: &'a [u8], offset: usize, from_mirror: bool) -> Option<Self> {
        let hash = read_u32(sds, offset)?;
        let security_id = read_u32(sds, offset + 4)?;
        let own_offset = read_u64(sds, offset + 8)?;
        let length = read_u32(sds, offset + 16)?;

        let expected_offset = if from_mirror {
            offset.checked_sub(SDS_BLOCK_SIZE)?
        } else {
            offset
        };
        let end = offset.checked_add(length as usize)?;
        if own_offset != expected_offset as u64
            || (length as usize) < HEADER_SIZE
            || end > block_end(offset)
        {
            return None;
        }
        let value = sds.get(offset + HEADER_SIZE..end)?;

        Some(SdsEntry {
            offset: own_offset,
            from_mirror,
            security_id,
            hash,
            valid_hash: is_descriptor_like(value) && descriptor_hash(value) == hash,
            length,
            descriptor: SecurityDescriptorAttr::from_slice(value),
        })
    }

    /// The descriptor in SDDL, as [`SecurityDescriptorAttr::to_sddl`] formats it.
    pub fn sddl(&self) -> Option<String> {
        self.descriptor
            .as_ref()
            .map(SecurityDescriptorAttr::to_sddl)
    }
}

/// Whether `value` starts like a self-relative security descriptor: revision 1 and the
/// `SE_SELF_RELATIVE` control flag, in a value at least as long as the descriptor's header.
fn is_descriptor_like(value: &[u8]) -> bool {
    value.len() >= DESCRIPTOR_HEADER_SIZE
        && value[0] == 1
        && u16::from_le_bytes([value[2], value[3]])
            & SecurityDescriptorControl::SE_SELF_RELATIVE.bits()
            != 0
}

/// The hash NTFS keeps of a descriptor: each 32-bit word is added to the hash rotated left by 3.
pub fn descriptor_hash(value: &[u8]) -> u32 {
    let (words, _) = value.as_chunks::<4>();
    words.iter().fold(0u32, |hash, word| {
        hash.rotate_left(3).wrapping_add(u32::from_le_bytes(*word))
    })
}

/// Whether `start`, the first bytes of a stream, looks like an `$SDS`: whether it has an entry
/// with a valid hash at a 16-byte boundary of the first block whose header gives its own offset.
pub fn looks_like_sds(start: &[u8]) -> bool {
    BlockEntries::new(start, 0, false).any(|entry| entry.valid_hash)
}

/// The entries of one 256 KiB block (or of its copy), in the order they are stored.
struct BlockEntries<'a> {
    sds: &'a [u8],
    offset: usize,
    end: usize,
    from_mirror: bool,
}

impl<'a> BlockEntries<'a> {
    fn new(sds: &'a [u8], start: usize, from_mirror: bool) -> Self {
        BlockEntries {
            sds,
            offset: start,
            end: block_end(start).min(sds.len()),
            from_mirror,
        }
    }
}

impl<'a> Iterator for BlockEntries<'a> {
    type Item = SdsEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset + HEADER_SIZE <= self.end {
            match SdsEntry::parse(self.sds, self.offset, self.from_mirror) {
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
                // The zeros after the block's last entry, or a damaged entry: go on from the
                // 16 bytes with the next byte that isn't zero, or to the end of the block.
                None => {
                    let rest = &self.sds[self.offset..self.end];
                    self.offset = match rest.iter().position(|&b| b != 0) {
                        Some(nonzero) => self.offset + (nonzero / 16 * 16).max(16),
                        None => self.end,
                    };
                }
            }
        }
        None
    }
}

/// The entries of an `$SDS` stream, in the order they are stored.
///
/// Each 256 KiB block is followed by a copy of itself. The entries are read from the block, and
/// an entry that is missing there or whose hash doesn't match is taken from the copy when the
/// copy's has a matching hash (with `from_mirror` set). An intact entry of the block is never
/// replaced, and no entry is yielded twice.
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
/// assert_eq!(entries[0].sddl().as_deref(), Some("O:S-1-5-18"));
/// ```
pub struct SdsEntries<'a> {
    sds: &'a [u8],
    /// The start of the next block to read.
    block: usize,
    /// The entries of the block last read.
    pending: std::collections::btree_map::IntoValues<u64, SdsEntry<'a>>,
}

impl<'a> SdsEntries<'a> {
    pub fn new(sds: &'a [u8]) -> Self {
        SdsEntries {
            sds,
            block: 0,
            pending: BTreeMap::new().into_values(),
        }
    }

    /// The entries of the block at `self.block`, with the damaged ones taken from its copy.
    fn read_block(&self) -> BTreeMap<u64, SdsEntry<'a>> {
        let mut entries: BTreeMap<u64, SdsEntry<'a>> =
            BlockEntries::new(self.sds, self.block, false)
                .map(|entry| (entry.offset, entry))
                .collect();
        let mirror = self.block + SDS_BLOCK_SIZE;
        if mirror < self.sds.len() {
            for entry in BlockEntries::new(self.sds, mirror, true).filter(|e| e.valid_hash) {
                if !entries.get(&entry.offset).is_some_and(|e| e.valid_hash) {
                    entries.insert(entry.offset, entry);
                }
            }
        }
        entries
    }
}

impl<'a> Iterator for SdsEntries<'a> {
    type Item = SdsEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(entry) = self.pending.next() {
                return Some(entry);
            }
            if self.block >= self.sds.len() {
                return None;
            }
            self.pending = self.read_block().into_values();
            self.block += 2 * SDS_BLOCK_SIZE;
        }
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
        let mut ids = HashMap::new();
        // The IDs whose kept entry has a matching hash: a damaged entry doesn't replace those.
        let mut intact = HashSet::new();
        for entry in SdsEntries::new(sds) {
            let Some(descriptor) = entry.descriptor else {
                continue;
            };
            if entry.valid_hash {
                intact.insert(entry.security_id);
            } else if intact.contains(&entry.security_id) {
                continue;
            }
            let resolved = ResolvedSecurityId {
                sddl: descriptor.to_sddl(),
                owner: descriptor.owner,
            };
            ids.insert(entry.security_id, resolved);
        }
        SecurityIds(ids)
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

/// An [`SdsEntry`] flattened to one CSV row, with the hash and the control flags formatted as
/// in JSON.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FlatSdsEntry {
    pub offset: u64,
    pub from_mirror: bool,
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
            from_mirror: entry.from_mirror,
            security_id: entry.security_id,
            hash: format!("0x{:08x}", entry.hash),
            valid_hash: entry.valid_hash,
            length: entry.length,
            owner: descriptor.and_then(|d| d.owner.clone()),
            group: descriptor.and_then(|d| d.group.clone()),
            control: descriptor.map(|d| d.control.to_string()),
            sddl: entry.sddl(),
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
    fn an_empty_or_zeroed_descriptor_has_no_valid_hash() {
        let mut sds = vec![0u8; 128];
        // An entry with no descriptor: its hash, 0, is the hash of nothing.
        sds[16..20].copy_from_slice(&20u32.to_le_bytes());
        // An entry with a zeroed descriptor, whose hash is 0 as well.
        sds[64 + 8..64 + 16].copy_from_slice(&64u64.to_le_bytes());
        sds[64 + 16..64 + 20].copy_from_slice(&52u32.to_le_bytes());

        let entries: Vec<_> = SdsEntries::new(&sds).collect();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.hash == 0 && !e.valid_hash));
        assert!(!looks_like_sds(&sds));
    }

    #[test]
    fn damaged_entries_are_recovered_from_the_mirror() {
        let mut sds = vec![0u8; 2 * SDS_BLOCK_SIZE];
        put_entry(&mut sds, 0, 0x100);
        put_entry(&mut sds, 64, 0x101);
        put_entry(&mut sds, 128, 0x102);
        sds.copy_within(..192, SDS_BLOCK_SIZE);
        // In the block, the second entry's owner no longer matches its hash, and the third
        // entry's header is wiped.
        sds[64 + 20 + 28] = 0x13;
        sds[128..148].fill(0);
        // The copy of the first entry is damaged, but the block's is intact.
        sds[SDS_BLOCK_SIZE + 20 + 28] = 0x13;

        let entries: Vec<_> = SdsEntries::new(&sds).collect();
        let found: Vec<_> = entries
            .iter()
            .map(|e| (e.offset, e.security_id, e.from_mirror, e.valid_hash))
            .collect();
        assert_eq!(
            found,
            [
                (0, 0x100, false, true),
                (64, 0x101, true, true),
                (128, 0x102, true, true),
            ]
        );
        let ids = SecurityIds::from_sds(&sds);
        assert_eq!(ids.get(0x101).unwrap().owner.as_deref(), Some("S-1-5-18"));
        assert_eq!(ids.get(0x102).unwrap().owner.as_deref(), Some("S-1-5-18"));
    }

    #[test]
    fn entries_after_zeros_are_found() {
        let mut sds = vec![0u8; SDS_BLOCK_SIZE];
        put_entry(&mut sds, 0x1000, 0x100);
        put_entry(&mut sds, SDS_BLOCK_SIZE - 64, 0x101);
        let ids: Vec<_> = SdsEntries::new(&sds).map(|e| e.security_id).collect();
        assert_eq!(ids, [0x100, 0x101]);
    }

    #[test]
    fn detects_an_sds_whose_first_entry_is_not_at_its_start() {
        let mut sds = vec![0u8; 0x10000];
        assert!(!looks_like_sds(&sds));
        // A wiped first entry, then an intact one.
        sds[..48].fill(0xFF);
        put_entry(&mut sds, 0x80, 0x101);
        assert!(looks_like_sds(&sds));
    }

    #[test]
    fn entries_may_not_cross_a_block() {
        let mut sds = vec![0u8; SDS_BLOCK_SIZE + 64];
        put_entry(&mut sds, SDS_BLOCK_SIZE - 32, 0x100);
        assert_eq!(SdsEntries::new(&sds).count(), 0);
    }
}
