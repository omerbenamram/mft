use crate::image::ReadAt;
use crate::ntfs::data_stream::{
    CompressedDataRunsStream, DataRunsStream, StreamPiece, for_each_stream_piece,
    read_from_data_runs,
};
use crate::ntfs::efs::{EfsFekDecryptor, EfsMetadataV1, EfsRsaKeyBag};
use crate::ntfs::index::{IndexRoot, IndexValueFlags, apply_index_record_fixups};
use crate::ntfs::name::{FileNameKey, UpcaseTable, eq_case_insensitive_ntfs, eq_case_sensitive};
use crate::ntfs::{Error, Result, Volume};
use md5::{Digest as _, Md5};
use mft::attribute::AttributeDataFlags;
use mft::attribute::MftAttributeType;
use mft::attribute::data_run::{DataRun, RunType};
use mft::attribute::header::ResidentialHeader;
use mft::attribute::non_resident_attr::NonResidentAttr;
use mft::attribute::x20::{AttributeListAttr, AttributeListEntry};
use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirectoryEntry {
    pub name: String,
    pub name_utf16: Vec<u16>,
    pub entry_id: u64,
}

#[derive(Debug, Clone)]
pub struct FileSystem {
    volume: Volume,
    upcase_table: Arc<OnceLock<Arc<UpcaseTable>>>,
}

impl FileSystem {
    pub fn new(volume: Volume) -> Self {
        Self {
            volume,
            upcase_table: Arc::new(OnceLock::new()),
        }
    }

    pub fn volume(&self) -> &Volume {
        &self.volume
    }

    fn upcase_table(&self) -> Result<Arc<UpcaseTable>> {
        if let Some(t) = self.upcase_table.get() {
            return Ok(Arc::clone(t));
        }

        // `$UpCase` is MFT entry 10 (unnamed `$DATA` stream).
        let raw = self.read_file_default_stream(10)?;
        let table = Arc::new(UpcaseTable::from_bytes(&raw)?);

        // Handle races: if another thread sets it first, we just use the stored one.
        let _ = self.upcase_table.set(Arc::clone(&table));
        Ok(Arc::clone(
            self.upcase_table
                .get()
                .expect("upcase table should be initialized"),
        ))
    }

    /// Reads the directory entries for the directory at `dir_entry_id`.
    ///
    /// This uses `$INDEX_ROOT` and, when present, `$INDEX_ALLOCATION` for `$I30`.
    pub fn read_dir(&self, dir_entry_id: u64) -> Result<Vec<DirectoryEntry>> {
        let entry = self.volume.read_mft_entry(dir_entry_id)?;
        if !entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {dir_entry_id} is not a directory"),
            });
        }

        let (index_root, has_allocation) = match self.read_i30_index_root(&entry) {
            Ok(x) => x,
            Err(_) => {
                // Some volumes might have damaged/missing index structures; fall back to scanning
                // the MFT based on parent references.
                return self.read_dir_parent_scan(dir_entry_id);
            }
        };

        // Collect values from root.
        let mut out: Vec<DirectoryEntry> = Vec::new();
        let mut seen: HashSet<(u64, Vec<u16>)> = HashSet::new();
        let mut sub_nodes: VecDeque<u64> = VecDeque::new();

        for v in &index_root.node.values {
            if let Some(fname) = &v.file_name
                && !v.flags.contains(IndexValueFlags::IS_LAST)
            {
                let entry_id = v.file_reference_raw & 0x0000_FFFF_FFFF_FFFF;
                let name_utf16 = fname.name_utf16().to_vec();
                let name = String::from_utf16_lossy(&name_utf16);
                if seen.insert((entry_id, name_utf16.clone())) {
                    out.push(DirectoryEntry {
                        name,
                        name_utf16,
                        entry_id,
                    });
                }
            }

            if v.flags.contains(IndexValueFlags::IS_BRANCH_NODE)
                && let Some(vcn) = v.sub_node_vcn
            {
                sub_nodes.push_back(vcn);
            }
        }

        if has_allocation {
            let data_runs = self.read_i30_index_allocation_runs(&entry)?;
            let mut visited_vcns: HashSet<u64> = HashSet::new();

            while let Some(vcn) = sub_nodes.pop_front() {
                if !visited_vcns.insert(vcn) {
                    continue;
                }

                let mut record = vec![0u8; self.volume.header.index_entry_size as usize];
                let offset = vcn.saturating_mul(self.volume.header.cluster_size as u64);
                read_from_data_runs(&self.volume, &data_runs, offset, &mut record)?;

                // Validate signature.
                if record.len() < 4 || &record[0..4] != b"INDX" {
                    continue;
                }

                if let Err(_e) = apply_index_record_fixups(&mut record) {
                    // Best-effort: skip corrupted/non-conforming index records.
                    continue;
                }

                // The index node header begins after the index record header (24 bytes).
                let node_start = 24;
                let node = crate::ntfs::index::IndexNode::parse_from_node_start(
                    &record,
                    self.volume.volume_offset() + offset,
                    node_start,
                )?;

                for v in &node.values {
                    if let Some(fname) = &v.file_name
                        && !v.flags.contains(IndexValueFlags::IS_LAST)
                    {
                        let entry_id = v.file_reference_raw & 0x0000_FFFF_FFFF_FFFF;
                        let name_utf16 = fname.name_utf16().to_vec();
                        let name = String::from_utf16_lossy(&name_utf16);
                        if seen.insert((entry_id, name_utf16.clone())) {
                            out.push(DirectoryEntry {
                                name,
                                name_utf16,
                                entry_id,
                            });
                        }
                    }

                    if v.flags.contains(IndexValueFlags::IS_BRANCH_NODE)
                        && let Some(child) = v.sub_node_vcn
                    {
                        sub_nodes.push_back(child);
                    }
                }
            }
        }

        if out.is_empty() {
            // Fallback: some volumes have missing/corrupt $I30 nodes even though FILE_NAME parent
            // references are intact.
            return self.read_dir_parent_scan(dir_entry_id);
        }

        Ok(out)
    }

    /// Reads the directory entries for the directory at `dir_entry_id` **strictly**.
    ///
    /// Unlike [`read_dir`], this method does **not** fall back to scanning the MFT based on parent
    /// references. This is intended for tooling that prefers a hard failure over a partial or
    /// potentially misleading directory listing.
    pub fn read_dir_strict(&self, dir_entry_id: u64) -> Result<Vec<DirectoryEntry>> {
        let entry = self.volume.read_mft_entry(dir_entry_id)?;
        if !entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {dir_entry_id} is not a directory"),
            });
        }

        let (index_root, has_allocation) = self.read_i30_index_root(&entry)?;

        // Collect values from root.
        let mut out: Vec<DirectoryEntry> = Vec::new();
        let mut seen: HashSet<(u64, Vec<u16>)> = HashSet::new();
        let mut sub_nodes: VecDeque<u64> = VecDeque::new();

        for v in &index_root.node.values {
            if let Some(fname) = &v.file_name
                && !v.flags.contains(IndexValueFlags::IS_LAST)
            {
                let entry_id = v.file_reference_raw & 0x0000_FFFF_FFFF_FFFF;
                let name_utf16 = fname.name_utf16().to_vec();
                let name = String::from_utf16_lossy(&name_utf16);
                if seen.insert((entry_id, name_utf16.clone())) {
                    out.push(DirectoryEntry {
                        name,
                        name_utf16,
                        entry_id,
                    });
                }
            }

            if v.flags.contains(IndexValueFlags::IS_BRANCH_NODE)
                && let Some(vcn) = v.sub_node_vcn
            {
                sub_nodes.push_back(vcn);
            }
        }

        if has_allocation {
            let data_runs = self.read_i30_index_allocation_runs(&entry)?;
            let mut visited_vcns: HashSet<u64> = HashSet::new();

            while let Some(vcn) = sub_nodes.pop_front() {
                if !visited_vcns.insert(vcn) {
                    continue;
                }

                let mut record = vec![0u8; self.volume.header.index_entry_size as usize];
                let offset = vcn.saturating_mul(self.volume.header.cluster_size as u64);
                read_from_data_runs(&self.volume, &data_runs, offset, &mut record)?;

                // Referenced nodes should be valid index records.
                if record.len() < 4 || &record[0..4] != b"INDX" {
                    return Err(Error::InvalidData {
                        message: format!(
                            "index record signature mismatch at vcn={vcn} offset=0x{:x}",
                            self.volume.volume_offset() + offset
                        ),
                    });
                }

                apply_index_record_fixups(&mut record).map_err(|e| Error::InvalidData {
                    message: format!(
                        "index record fixup failed at vcn={vcn} offset=0x{:x}: {e}",
                        self.volume.volume_offset() + offset
                    ),
                })?;

                // The index node header begins after the index record header (24 bytes).
                let node_start = 24;
                let node = crate::ntfs::index::IndexNode::parse_from_node_start(
                    &record,
                    self.volume.volume_offset() + offset,
                    node_start,
                )?;

                for v in &node.values {
                    if let Some(fname) = &v.file_name
                        && !v.flags.contains(IndexValueFlags::IS_LAST)
                    {
                        let entry_id = v.file_reference_raw & 0x0000_FFFF_FFFF_FFFF;
                        let name_utf16 = fname.name_utf16().to_vec();
                        let name = String::from_utf16_lossy(&name_utf16);
                        if seen.insert((entry_id, name_utf16.clone())) {
                            out.push(DirectoryEntry {
                                name,
                                name_utf16,
                                entry_id,
                            });
                        }
                    }

                    if v.flags.contains(IndexValueFlags::IS_BRANCH_NODE)
                        && let Some(child) = v.sub_node_vcn
                    {
                        sub_nodes.push_back(child);
                    }
                }
            }
        }

        Ok(out)
    }

    /// Reads directory entries and includes entries that are **not present** in `$I30`.
    ///
    /// This is useful for "undelete" style workflows: deleted files/directories are typically
    /// removed from the parent directory index, but their `FILE_NAME` attributes may still exist
    /// in their MFT records. This method returns a union of:
    /// - `$I30` traversal results (fast, allocated view)
    /// - a parent-reference scan of the MFT (slower, includes deleted/unlinked names)
    pub fn read_dir_including_deleted(&self, dir_entry_id: u64) -> Result<Vec<DirectoryEntry>> {
        let mut out = self.read_dir(dir_entry_id)?;
        let scan = self.read_dir_parent_scan(dir_entry_id)?;

        let mut seen: HashSet<(u64, Vec<u16>)> = out
            .iter()
            .map(|e| (e.entry_id, e.name_utf16.clone()))
            .collect();
        for e in scan {
            if seen.insert((e.entry_id, e.name_utf16.clone())) {
                out.push(e);
            }
        }
        Ok(out)
    }

    /// Reads the default `$DATA` stream (unnamed) of a file entry into memory.
    pub fn read_file_default_stream(&self, entry_id: u64) -> Result<Vec<u8>> {
        self.read_file_stream(entry_id, "")
    }

    /// Opens the USN change journal (`$Extend\\$UsnJrnl:$J`) as a stateful record reader.
    ///
    /// Returns:
    /// - `Ok(None)` if the journal is not present (`$UsnJrnl` entry or `$J` stream absent)
    /// - `Ok(Some(_))` if present
    /// - `Err(_)` for invalid/unsupported layouts (strict)
    pub fn open_usn_change_journal(&self) -> Result<Option<crate::ntfs::usn::UsnChangeJournal>> {
        use crate::ntfs::usn::journal::DEFAULT_USN_JOURNAL_BLOCK_SIZE;

        let usn_entry_id = match self.resolve_path_strict("\\$Extend\\$UsnJrnl") {
            Ok(id) => id,
            Err(Error::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };

        let entry = self.volume.read_mft_entry(usn_entry_id)?;

        // Prefer the canonical ADS name "$J", but allow "J" (some tools/images omit `$`).
        let mut data_extents = self.collect_data_extents(&entry, "$J")?;
        if data_extents.is_empty() {
            data_extents = self.collect_data_extents(&entry, "J")?;
        }
        if data_extents.is_empty() {
            // `$UsnJrnl` exists but `$J` stream is absent => treat as N/A (matches upstream).
            return Ok(None);
        }

        if data_extents.iter().any(|e| e.is_compressed) {
            return Err(Error::Unsupported {
                what: "compressed $UsnJrnl:$J".to_string(),
            });
        }

        let sizes = stream_sizes(&data_extents)?;
        let stream = zero_past_valid_data(
            Arc::new(self.open_uncompressed_stream(&data_extents, sizes.file)?),
            sizes.valid,
        );

        Ok(Some(crate::ntfs::usn::UsnChangeJournal::new(
            stream,
            DEFAULT_USN_JOURNAL_BLOCK_SIZE,
        )?))
    }

    /// Returns `true` if the MFT entry is marked allocated/in-use.
    ///
    /// This is useful for “show deleted” UX: entries that are not allocated are typically deleted,
    /// even if their metadata/streams may still be recoverable.
    pub fn is_entry_allocated(&self, entry_id: u64) -> Result<bool> {
        let entry = self.volume.read_mft_entry(entry_id)?;
        Ok(entry
            .header
            .flags
            .contains(mft::entry::EntryFlags::ALLOCATED))
    }

    /// Returns `true` if the entry has the `FILE_ATTRIBUTE_ENCRYPTED` flag (EFS).
    pub fn is_entry_efs_encrypted(&self, entry_id: u64) -> Result<bool> {
        let entry = self.volume.read_mft_entry(entry_id)?;
        Ok(is_entry_efs_encrypted(&entry))
    }

    /// Exports the default unnamed `$DATA` stream to `out`, streaming in chunks.
    ///
    /// This avoids allocating the entire file into memory and supports:
    /// - resident and non-resident data
    /// - sparse regions (left as holes in the output file, which read back as zeros)
    /// - NTFS-compressed `$DATA`
    pub fn export_file_default_stream_to_path(&self, entry_id: u64, out: &Path) -> Result<()> {
        let entry = self.volume.read_mft_entry(entry_id)?;
        if entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {entry_id} is a directory"),
            });
        }

        let mut f = File::create(out)?;

        // If this is an extension record, follow to the base record first (mirrors `collect_data_extents`).
        let base_entry_id = if entry.header.base_reference.entry != 0 {
            entry.header.base_reference.entry
        } else {
            entry.header.record_number
        };
        let base_entry = if base_entry_id == entry.header.record_number {
            entry.clone()
        } else {
            self.volume.read_mft_entry(base_entry_id)?
        };

        // Resident fast-path.
        for attr in base_entry
            .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name.is_empty())
        {
            if let ResidentialHeader::Resident(rh) = &attr.header.residential_header {
                let start = attr.header.start_offset as usize + rh.data_offset as usize;
                let end = start + rh.data_size as usize;
                let data = base_entry
                    .data
                    .get(start..end)
                    .ok_or_else(|| Error::InvalidData {
                        message: "resident data out of bounds".to_string(),
                    })?;
                f.write_all(data)?;
                return Ok(());
            }
        }

        // Non-resident: gather extents (including attribute list) and stream in chunks.
        let data_extents = self.collect_data_extents(&entry, "")?;
        if data_extents.is_empty() {
            return Err(Error::NotFound {
                what: "missing $DATA stream ``".to_string(),
            });
        }

        let sizes = stream_sizes(&data_extents)?;

        // Holes (sparse runs, compression units that are not stored, anything past the valid
        // data length or the end of the mapping pairs) are skipped in the output file instead
        // of being written out as zeros, so the work is bounded by the clusters the image
        // really stores, not by the sizes the attribute claims.
        self.for_each_piece(&data_extents, sizes, |piece| {
            match piece {
                StreamPiece::Data(bytes) => f.write_all(bytes)?,
                StreamPiece::Hole(len) => seek_forward(&mut f, len)?,
            }
            Ok(())
        })?;
        f.set_len(sizes.file)?;

        Ok(())
    }

    /// Reads a `$DATA` stream of a file entry into memory.
    ///
    /// - Use `stream_name = ""` for the default unnamed stream.
    /// - Use a non-empty stream name to read an Alternate Data Stream (ADS), e.g. `stream_name =
    ///   "Zone.Identifier"`.
    pub fn read_file_stream(&self, entry_id: u64, stream_name: &str) -> Result<Vec<u8>> {
        let entry = self.volume.read_mft_entry(entry_id)?;
        if entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {entry_id} is a directory"),
            });
        }

        self.read_data_stream_from_entry(&entry, stream_name)
    }

    /// Opens a `$DATA` stream of a file entry as a random-access reader.
    ///
    /// This is intended for mount-style consumers (FUSE/Dokan) that need to satisfy reads by
    /// `(offset, length)` without loading entire files into memory.
    ///
    /// Notes:
    /// - The returned reader is **read-only**.
    /// - Compressed streams are supported (LZNT1).
    /// - Alternate Data Streams (ADS) are supported via `stream_name`.
    pub fn open_file_stream_read_at(
        &self,
        entry_id: u64,
        stream_name: &str,
    ) -> Result<Arc<dyn ReadAt>> {
        let entry = self.volume.read_mft_entry(entry_id)?;
        if entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {entry_id} is a directory"),
            });
        }
        self.open_data_stream_from_entry_read_at(&entry, stream_name)
    }

    /// Opens the default unnamed `$DATA` stream as a random-access reader.
    pub fn open_file_default_stream_read_at(&self, entry_id: u64) -> Result<Arc<dyn ReadAt>> {
        self.open_file_stream_read_at(entry_id, "")
    }

    /// Opens the default unnamed `$DATA` stream as a random-access reader, returning plaintext if
    /// the file is EFS-encrypted.
    ///
    /// This supports **sector-aligned** EFS decryption (512-byte units), allowing random reads
    /// without reading the full file into memory.
    ///
    /// Current limitation: EFS + NTFS compression is not supported.
    pub fn open_file_default_stream_read_at_decrypted(
        &self,
        entry_id: u64,
        efs_keys: &EfsRsaKeyBag,
    ) -> Result<Arc<dyn ReadAt>> {
        let entry = self.volume.read_mft_entry(entry_id)?;
        if entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {entry_id} is a directory"),
            });
        }

        if !is_entry_efs_encrypted(&entry) {
            return self.open_data_stream_from_entry_read_at(&entry, "");
        }

        // Detect resident $DATA early: EFS decryption is sector-based and requires reading full
        // 512-byte sectors from disk. Resident attributes do not preserve the padded ciphertext
        // bytes (if any), so this layout is treated as unsupported (and is extremely uncommon in
        // practice).
        for attr in entry
            .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name.is_empty())
        {
            if let ResidentialHeader::Resident(rh) = &attr.header.residential_header {
                if rh.data_size == 0 {
                    return Ok(Arc::new(ResidentReadAt::new(Vec::new())));
                }
                return Err(Error::Unsupported {
                    what: "EFS-encrypted resident $DATA".to_string(),
                });
            }
        }

        // Parse `$EFS` metadata and unwrap the FEK.
        let efs_blob = read_efs_attribute_blob(&self.volume, &entry)?;
        let meta = EfsMetadataV1::parse(&efs_blob, 0)?;
        let fek = EfsFekDecryptor::from_metadata_v1(&meta, efs_keys)?;

        // Open ciphertext stream, but allow reads up to whole sectors.
        let data_extents = self.collect_data_extents(&entry, "")?;
        if data_extents.is_empty() {
            // No non-resident extents and no resident $DATA above => treat as absent.
            return Err(Error::NotFound {
                what: "missing $DATA stream ``".to_string(),
            });
        }
        if data_extents.iter().any(|e| e.is_compressed) {
            return Err(Error::Unsupported {
                what: "EFS-encrypted + compressed $DATA".to_string(),
            });
        }

        let sizes = stream_sizes(&data_extents)?;
        if sizes.file == 0 {
            return Ok(Arc::new(ResidentReadAt::new(Vec::new())));
        }

        // The ciphertext is read in whole sectors and as the clusters hold it; the valid data
        // length applies to the plaintext.
        let cipher_len = sizes.file.div_ceil(512).saturating_mul(512);
        let cipher: Arc<dyn ReadAt> =
            Arc::new(self.open_uncompressed_stream(&data_extents, cipher_len)?);

        Ok(zero_past_valid_data(
            Arc::new(EfsDecryptingReadAt::new(cipher, fek, sizes.file)),
            sizes.valid,
        ))
    }

    /// Computes an MD5 over a `$DATA` stream of a file entry, without loading the entire stream
    /// into memory.
    ///
    /// This is intended for tooling (e.g. bodyfile generation) where streams can be very large
    /// (`$BadClus:$Bad`), and allocating `Vec<u8>` would be impractical.
    ///
    /// The returned string is lowercase hex, matching SleuthKit bodyfile convention.
    pub fn md5_file_stream(&self, entry_id: u64, stream_name: &str) -> Result<String> {
        let entry = self.volume.read_mft_entry(entry_id)?;
        if entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {entry_id} is a directory"),
            });
        }

        // Resident fast-path.
        for attr in entry.iter_attributes_matching(Some(vec![MftAttributeType::DATA])) {
            let attr = attr?;
            if attr.header.name != stream_name {
                continue;
            }
            if let ResidentialHeader::Resident(rh) = &attr.header.residential_header {
                let start = attr.header.start_offset as usize + rh.data_offset as usize;
                let end = start + rh.data_size as usize;
                let data = entry
                    .data
                    .get(start..end)
                    .ok_or_else(|| Error::InvalidData {
                        message: "resident data out of bounds".to_string(),
                    })?;
                return Ok(md5_of_bytes_hex_lower(data));
            }
        }

        // Non-resident: gather extents (including attribute list) and stream in chunks.
        let data_extents = self.collect_data_extents(&entry, stream_name)?;
        if data_extents.is_empty() {
            return Err(Error::NotFound {
                what: format!("missing $DATA stream `{stream_name}`"),
            });
        }

        let sizes = stream_sizes(&data_extents)?;
        let file_size = sizes.file;

        // Hashing takes time in proportion to the size, holes included, and the size is an
        // on-disk field. Refuse one that no file on this volume can have.
        let max_size = MAX_FILE_CLUSTERS.saturating_mul(self.volume.header.cluster_size as u64);
        if file_size > max_size {
            return Err(Error::InvalidData {
                message: format!(
                    "stream size {file_size} is larger than the {max_size} bytes a file on this volume can have; not hashing it"
                ),
            });
        }

        let mut h = Md5::new();
        self.for_each_piece(&data_extents, sizes, |piece| {
            match piece {
                StreamPiece::Data(bytes) => h.update(bytes),
                StreamPiece::Hole(len) => md5_update_zeros(&mut h, len),
            }
            Ok(())
        })?;

        Ok(hex::encode(h.finalize()))
    }

    /// Reads the default `$DATA` stream and returns **plaintext** if the file is EFS-encrypted.
    ///
    /// - If the file is **not** EFS-encrypted, this behaves like [`read_file_default_stream`].
    /// - If the file **is** EFS-encrypted, this method requires an RSA private key (usually from a
    ///   `.pfx`) to unwrap the FEK from `$EFS` metadata and decrypt the `$DATA` content.
    pub fn read_file_default_stream_decrypted(
        &self,
        entry_id: u64,
        efs_keys: &EfsRsaKeyBag,
    ) -> Result<Vec<u8>> {
        let entry = self.volume.read_mft_entry(entry_id)?;
        if entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {entry_id} is a directory"),
            });
        }

        if !is_entry_efs_encrypted(&entry) {
            return self.read_data_stream_from_entry(&entry, "");
        }

        // Parse `$EFS` metadata and unwrap the FEK.
        let efs_blob = read_efs_attribute_blob(&self.volume, &entry)?;
        let meta = EfsMetadataV1::parse(&efs_blob, 0)?;

        let fek = EfsFekDecryptor::from_metadata_v1(&meta, efs_keys)?;

        // Read ciphertext up to a whole number of sectors (512 bytes).
        let data_extents = self.collect_data_extents(&entry, "")?;
        if data_extents.is_empty() {
            return Err(Error::NotFound {
                what: "missing $DATA stream ``".to_string(),
            });
        }
        if data_extents.iter().any(|e| e.is_compressed) {
            return Err(Error::Unsupported {
                what: "EFS-encrypted + compressed $DATA".to_string(),
            });
        }

        let sizes = stream_sizes(&data_extents)?;
        // The ciphertext is read in whole sectors and as the clusters hold it; the valid data
        // length is applied to the plaintext below, not to this read.
        let cipher_len = sizes.file.div_ceil(512).saturating_mul(512);
        let mut bytes = alloc_stream_buffer(cipher_len, "$DATA stream")?;
        self.open_uncompressed_stream(&data_extents, cipher_len)?
            .read_exact_at(0, &mut bytes)
            .map_err(Error::Io)?;

        fek.decrypt_in_place(&mut bytes, 0)?;
        bytes.truncate(sizes.file as usize);
        bytes[sizes.valid as usize..].fill(0);
        Ok(bytes)
    }

    fn read_data_stream_from_entry(
        &self,
        entry: &mft::MftEntry,
        stream_name: &str,
    ) -> Result<Vec<u8>> {
        // Fast-path: resident data stream in the base record.
        for attr in entry
            .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name == stream_name)
        {
            if let ResidentialHeader::Resident(rh) = &attr.header.residential_header {
                let start = attr.header.start_offset as usize + rh.data_offset as usize;
                let end = start + rh.data_size as usize;
                let data = entry
                    .data
                    .get(start..end)
                    .ok_or_else(|| Error::InvalidData {
                        message: "resident data out of bounds".to_string(),
                    })?;
                return Ok(data.to_vec());
            }
        }

        // Gather DATA attributes (including via attribute list) and read.
        let data_extents = self.collect_data_extents(entry, stream_name)?;
        if data_extents.is_empty() {
            return Err(Error::NotFound {
                what: format!("missing $DATA stream `{stream_name}`"),
            });
        }

        let sizes = stream_sizes(&data_extents)?;
        let mut out = alloc_stream_buffer(sizes.file, "$DATA stream")?;
        // Bytes past the valid data length stay zero: they are not read from the volume.
        self.open_stream(&data_extents, sizes.file)?
            .read_exact_at(0, &mut out[..sizes.valid as usize])
            .map_err(Error::Io)?;
        Ok(out)
    }

    fn open_data_stream_from_entry_read_at(
        &self,
        entry: &mft::MftEntry,
        stream_name: &str,
    ) -> Result<Arc<dyn ReadAt>> {
        // Resident fast-path: the stream content lives inside the MFT record.
        for attr in entry
            .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name == stream_name)
        {
            if let ResidentialHeader::Resident(rh) = &attr.header.residential_header {
                let start = attr.header.start_offset as usize + rh.data_offset as usize;
                let end = start + rh.data_size as usize;
                let data = entry
                    .data
                    .get(start..end)
                    .ok_or_else(|| Error::InvalidData {
                        message: "resident data out of bounds".to_string(),
                    })?;

                return Ok(Arc::new(ResidentReadAt::new(data.to_vec())));
            }
        }

        // Gather extents (including attribute list) and open.
        let data_extents = self.collect_data_extents(entry, stream_name)?;
        if data_extents.is_empty() {
            return Err(Error::NotFound {
                what: format!("missing $DATA stream `{stream_name}`"),
            });
        }

        let sizes = stream_sizes(&data_extents)?;
        Ok(zero_past_valid_data(
            self.open_stream(&data_extents, sizes.file)?,
            sizes.valid,
        ))
    }

    /// Opens the stream described by `extents` (sorted by VCN), compressed or not, as the
    /// clusters hold it: the valid data length is not applied.
    fn open_stream(&self, extents: &[DataExtent], len: u64) -> Result<Arc<dyn ReadAt>> {
        if extents.iter().any(|e| e.is_compressed) {
            return Ok(Arc::new(self.open_compressed_stream(extents)?));
        }
        Ok(Arc::new(self.open_uncompressed_stream(extents, len)?))
    }

    /// Opens the uncompressed stream described by `extents` (sorted by VCN) with a logical
    /// length of `len` bytes, as the clusters hold it: the valid data length is not applied.
    ///
    /// Every uncompressed read goes through this one view, so that reading, hashing and
    /// exporting a file agree on its content whatever state its mapping pairs are in.
    fn open_uncompressed_stream(&self, extents: &[DataExtent], len: u64) -> Result<DataRunsStream> {
        Ok(DataRunsStream::new(
            self.volume.clone(),
            join_extent_runs(extents)?,
            len,
        ))
    }

    /// Walks the stream described by `extents` (sorted by VCN) in order, handing stored bytes
    /// and holes to `sink`. Works for compressed and uncompressed streams alike. Everything
    /// past the valid data length is one last hole.
    fn for_each_piece(
        &self,
        extents: &[DataExtent],
        sizes: StreamSizes,
        mut sink: impl FnMut(StreamPiece<'_>) -> Result<()>,
    ) -> Result<()> {
        let len = sizes.valid;
        if extents.iter().any(|e| e.is_compressed) {
            let stream = self.open_compressed_stream(extents)?;
            let mut buf = vec![0u8; 1024 * 1024];
            let mut off = 0u64;
            while off < len {
                // Compression units that are not stored at all are one hole, however many.
                let hole = stream.sparse_len_at(off).min(len - off);
                if hole > 0 {
                    sink(StreamPiece::Hole(hole))?;
                    off += hole;
                    continue;
                }

                let n = (len - off).min(buf.len() as u64) as usize;
                stream
                    .read_exact_at(off, &mut buf[..n])
                    .map_err(Error::Io)?;
                sink(StreamPiece::Data(&buf[..n]))?;
                off += n as u64;
            }
        } else {
            let runs = join_extent_runs(extents)?;
            for_each_stream_piece(&self.volume, &runs, len, &mut sink)?;
        }

        if sizes.file > sizes.valid {
            sink(StreamPiece::Hole(sizes.file - sizes.valid))?;
        }
        Ok(())
    }

    /// Resolves a path (e.g. `\\Raw\\file.txt`) into an MFT entry id.
    pub fn resolve_path(&self, path: &str) -> Result<u64> {
        let mut cur = 5_u64; // root directory
        for component in split_path(path) {
            let entries = self.read_dir(cur)?;
            cur = self.resolve_component_in_dir(cur, &entries, component)?;
        }
        Ok(cur)
    }

    /// Resolves a path (e.g. `\\Raw\\file.txt`) into an MFT entry id **strictly**.
    ///
    /// This uses [`read_dir_strict`] for each component and does not attempt to recover from
    /// missing/corrupted `$I30` structures by scanning the MFT.
    pub fn resolve_path_strict(&self, path: &str) -> Result<u64> {
        let mut cur = 5_u64; // root directory
        for component in split_path(path) {
            let entries = self.read_dir_strict(cur)?;
            cur = self.resolve_component_in_dir(cur, &entries, component)?;
        }
        Ok(cur)
    }

    /// Resolves a single path component under a directory entry (best-effort).
    ///
    /// This uses [`read_dir`], which may fall back to an MFT parent-reference scan when `$I30`
    /// structures are missing/corrupt.
    pub fn lookup_in_dir(&self, dir_entry_id: u64, component: &str) -> Result<u64> {
        let entries = self.read_dir(dir_entry_id)?;
        self.resolve_component_in_dir(dir_entry_id, &entries, component)
    }

    /// Resolves a single path component under a directory entry (strict).
    ///
    /// This uses [`read_dir_strict`] and does not fall back to MFT scans.
    pub fn lookup_in_dir_strict(&self, dir_entry_id: u64, component: &str) -> Result<u64> {
        let entries = self.read_dir_strict(dir_entry_id)?;
        self.resolve_component_in_dir(dir_entry_id, &entries, component)
    }

    /// Resolves a path **including deleted/unlinked directory entries**, into an MFT entry id.
    ///
    /// This is similar to [`resolve_path`], but it uses [`read_dir_including_deleted`] at each
    /// path component. This allows resolving paths that no longer exist in directory indexes (e.g.
    /// deleted directories).
    pub fn resolve_path_including_deleted(&self, path: &str) -> Result<u64> {
        let mut cur = 5_u64; // root directory
        for component in split_path(path) {
            let entries = self.read_dir_including_deleted(cur)?;
            cur = self.resolve_component_in_dir(cur, &entries, component)?;
        }
        Ok(cur)
    }

    fn resolve_component_in_dir(
        &self,
        dir_entry_id: u64,
        entries: &[DirectoryEntry],
        component: &str,
    ) -> Result<u64> {
        let case_sensitive = self.is_directory_case_sensitive(dir_entry_id)?;
        let upcase = if case_sensitive {
            None
        } else {
            Some(self.upcase_table()?)
        };

        resolve_component_in_entries(
            dir_entry_id,
            entries,
            component,
            case_sensitive,
            upcase.as_deref(),
        )
    }

    /// Fallback directory listing based on scanning FILE_NAME parent references in the MFT.
    ///
    /// This is slower than index traversal but works even when `$I30` structures are missing or
    /// zeroed.
    fn read_dir_parent_scan(&self, dir_entry_id: u64) -> Result<Vec<DirectoryEntry>> {
        let entry_count = self
            .estimate_mft_entry_count()
            .unwrap_or(10_000)
            .min(200_000);

        let mut out = Vec::new();
        let mut seen: HashSet<(u64, Vec<u16>)> = HashSet::new();

        for i in 0..entry_count {
            let entry = match self.volume.read_mft_entry(i) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let child_id = entry.header.record_number;
            for attr in entry
                .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
                .filter_map(std::result::Result::ok)
            {
                let (start, end) = match &attr.header.residential_header {
                    ResidentialHeader::Resident(rh) => {
                        let start = attr.header.start_offset as usize + rh.data_offset as usize;
                        let end = start + rh.data_size as usize;
                        (start, end)
                    }
                    ResidentialHeader::NonResident(_) => {
                        return Err(Error::Unsupported {
                            what: "non-resident $FILE_NAME attribute".to_string(),
                        });
                    }
                };

                let raw = entry
                    .data
                    .get(start..end)
                    .ok_or_else(|| Error::InvalidData {
                        message: "FILE_NAME resident content out of bounds".to_string(),
                    })?;

                // Fast parent check using the first 8 bytes. Only fully parse names for this directory.
                if raw.len() < 8 {
                    return Err(Error::InvalidData {
                        message: "FILE_NAME attribute too small for parent reference".to_string(),
                    });
                }
                let parent_raw = u64::from_le_bytes(raw[0..8].try_into().expect("len=8"));
                let parent_entry_id = parent_raw & 0x0000_FFFF_FFFF_FFFF;
                if parent_entry_id != dir_entry_id {
                    continue;
                }

                let key = FileNameKey::parse(raw, 0)?;
                let name_utf16 = key.name_utf16().to_vec();
                let name = String::from_utf16_lossy(&name_utf16);

                if seen.insert((child_id, name_utf16.clone())) {
                    out.push(DirectoryEntry {
                        name,
                        name_utf16,
                        entry_id: child_id,
                    });
                }
            }
        }

        Ok(out)
    }

    fn is_directory_case_sensitive(&self, dir_entry_id: u64) -> Result<bool> {
        let entry = self.volume.read_mft_entry(dir_entry_id)?;
        if !entry.is_dir() {
            return Err(Error::InvalidData {
                message: format!("entry {dir_entry_id} is not a directory"),
            });
        }

        let attr = entry
            .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
            .next()
            .ok_or_else(|| Error::NotFound {
                what: format!("missing $STANDARD_INFORMATION in entry {dir_entry_id}"),
            })??;

        let Some(si) = attr.data.as_standard_info().cloned() else {
            return Err(Error::InvalidData {
                message: format!(
                    "$STANDARD_INFORMATION attribute had unexpected content in entry {dir_entry_id}"
                ),
            });
        };

        // Mirror upstream behavior:
        // case-sensitive iff (maximum_number_of_versions == 0 && version_number == 1)
        Ok(standard_info_indicates_case_sensitive(&si))
    }

    fn estimate_mft_entry_count(&self) -> Option<u64> {
        let entry0 = self.volume.read_mft_entry(0).ok()?;
        for attr in entry0
            .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name.is_empty())
        {
            if let ResidentialHeader::NonResident(nr) = &attr.header.residential_header {
                let bytes = nr.file_size;
                if self.volume.header.mft_entry_size == 0 {
                    return None;
                }
                return Some(bytes / self.volume.header.mft_entry_size as u64);
            }
        }
        None
    }

    fn read_i30_index_root(&self, entry: &mft::MftEntry) -> Result<(IndexRoot, bool)> {
        let mut attrs = entry
            .iter_attributes_matching(Some(vec![MftAttributeType::IndexRoot]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name == "$I30")
            .collect::<Vec<_>>();

        let attr = attrs.pop().ok_or_else(|| Error::NotFound {
            what: "missing $I30 $INDEX_ROOT".to_string(),
        })?;

        let (data_offset, data_size) = match &attr.header.residential_header {
            ResidentialHeader::Resident(h) => (h.data_offset as usize, h.data_size as usize),
            ResidentialHeader::NonResident(_) => {
                return Err(Error::InvalidData {
                    message: "$INDEX_ROOT cannot be non-resident".to_string(),
                });
            }
        };

        let start = attr.header.start_offset as usize + data_offset;
        let end = start + data_size;
        let buf = entry
            .data
            .get(start..end)
            .ok_or_else(|| Error::InvalidData {
                message: "index root content out of bounds".to_string(),
            })?;

        let root = IndexRoot::parse(buf, self.volume.volume_offset() + start as u64)?;
        let has_alloc = root
            .node
            .header
            .flags
            .contains(crate::ntfs::index::IndexNodeFlags::HAS_ALLOCATION_ATTRIBUTE);
        Ok((root, has_alloc))
    }

    fn read_i30_index_allocation_runs(
        &self,
        entry: &mft::MftEntry,
    ) -> Result<Vec<mft::attribute::data_run::DataRun>> {
        let mut attrs = entry
            .iter_attributes_matching(Some(vec![MftAttributeType::IndexAllocation]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name == "$I30")
            .collect::<Vec<_>>();

        let attr = attrs.pop().ok_or_else(|| Error::NotFound {
            what: "missing $I30 $INDEX_ALLOCATION".to_string(),
        })?;

        let NonResidentAttr { data_runs } = match attr.data.as_data_runs().cloned() {
            Some(dr) => dr,
            None => {
                return Err(Error::InvalidData {
                    message: "expected non-resident data runs for $INDEX_ALLOCATION".to_string(),
                });
            }
        };

        Ok(data_runs)
    }

    fn collect_data_extents(
        &self,
        entry: &mft::MftEntry,
        stream_name: &str,
    ) -> Result<Vec<DataExtent>> {
        // If this is an extension record, follow to the base record first.
        let base_entry_id = if entry.header.base_reference.entry != 0 {
            entry.header.base_reference.entry
        } else {
            entry.header.record_number
        };

        let base_entry = if base_entry_id == entry.header.record_number {
            entry.clone()
        } else {
            self.volume.read_mft_entry(base_entry_id)?
        };

        let mut extents = Vec::new();

        // Direct DATA attributes in base record.
        for attr in base_entry
            .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
            .filter_map(std::result::Result::ok)
            .filter(|a| a.header.name == stream_name)
        {
            if let ResidentialHeader::NonResident(nr) = &attr.header.residential_header {
                let runs = attr
                    .data
                    .as_data_runs()
                    .cloned()
                    .ok_or_else(|| Error::InvalidData {
                        message: "expected data runs".to_string(),
                    })?
                    .data_runs;

                extents.push(DataExtent::from_non_resident_attr(&attr, nr, runs)?);
            }
        }

        // Attribute list extents.
        for al in
            self.read_attribute_list(&base_entry, MftAttributeType::DATA as u32, stream_name)?
        {
            // The list also names the attributes held in the base record; those are collected
            // above.
            if al.segment_entry == base_entry_id {
                continue;
            }

            let seg_id = al.segment_entry;
            let seg = self.volume.read_mft_entry(seg_id)?;

            // Match by instance id.
            let attr = seg
                .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
                .filter_map(std::result::Result::ok)
                .filter(|a| a.header.name == stream_name)
                .find(|a| a.header.instance == al.instance)
                .ok_or_else(|| Error::NotFound {
                    what: format!(
                        "attribute list references missing DATA extent in entry {seg_id}"
                    ),
                })?;

            let nr = match &attr.header.residential_header {
                ResidentialHeader::NonResident(nr) => nr,
                _ => {
                    return Err(Error::InvalidData {
                        message: "attribute list referenced non non-resident extent".to_string(),
                    });
                }
            };
            let runs = attr
                .data
                .as_data_runs()
                .cloned()
                .ok_or_else(|| Error::InvalidData {
                    message: "expected data runs".to_string(),
                })?
                .data_runs;

            let mut extent = DataExtent::from_non_resident_attr(&attr, nr, runs)?;
            extent.vcn_first = al.lowest_vcn;
            extents.push(extent);
        }

        // Sort by VCN.
        extents.sort_by_key(|e| e.vcn_first);
        Ok(extents)
    }

    /// Returns the entries of the `$ATTRIBUTE_LIST` of `base_entry` that describe the attribute
    /// of type `attribute_type` named `name`, or nothing when the record has no attribute list.
    ///
    /// The list is resident in most records. When a file has so many extents that the list no
    /// longer fits in the record, NTFS makes the list itself non-resident; it is then read from
    /// its data runs (which always live in the base record).
    fn read_attribute_list(
        &self,
        base_entry: &mft::MftEntry,
        attribute_type: u32,
        name: &str,
    ) -> Result<Vec<AttributeListItem>> {
        let matching = |list: &AttributeListAttr<'_>| -> Vec<AttributeListItem> {
            list.entries
                .iter()
                .filter(|e| e.attribute_type == attribute_type && e.name == name)
                .map(AttributeListItem::from)
                .collect()
        };

        for attr in base_entry
            .iter_attributes_matching(Some(vec![MftAttributeType::AttributeList]))
            .filter_map(std::result::Result::ok)
        {
            if let Some(list) = attr.data.as_attribute_list() {
                return Ok(matching(list));
            }

            let ResidentialHeader::NonResident(nr) = &attr.header.residential_header else {
                continue;
            };
            let runs = &attr
                .data
                .as_data_runs()
                .ok_or_else(|| Error::InvalidData {
                    message: "expected data runs for non-resident $ATTRIBUTE_LIST".to_string(),
                })?
                .data_runs;

            if nr.file_size > MAX_ATTRIBUTE_LIST_SIZE {
                return Err(Error::InvalidData {
                    message: format!(
                        "non-resident $ATTRIBUTE_LIST is too large: {} bytes (limit {MAX_ATTRIBUTE_LIST_SIZE})",
                        nr.file_size
                    ),
                });
            }
            // Bytes past the valid data length are not part of the list.
            let valid = nr.valid_data_length.min(nr.file_size) as usize;
            let mut raw = vec![0u8; valid];
            read_from_data_runs(&self.volume, runs, 0, &mut raw)?;

            let list = AttributeListAttr::from_slice(&raw)?;
            return Ok(matching(&list));
        }
        Ok(Vec::new())
    }

    /// Opens a compressed `$DATA` stream described by `extents` (sorted by VCN).
    ///
    /// A fragmented compressed file keeps its mapping pairs in several extents (one attribute
    /// per MFT record, tied together by the attribute list). The runs of all extents are joined
    /// into one run list, because a compression unit may start in one extent and end in the next.
    fn open_compressed_stream(&self, extents: &[DataExtent]) -> Result<CompressedDataRunsStream> {
        let first = extents.first().ok_or_else(|| Error::InvalidData {
            message: "compressed stream has no extents".to_string(),
        })?;
        let unit_clusters = first
            .compression_unit_clusters
            .ok_or_else(|| Error::InvalidData {
                message: "missing compression unit size".to_string(),
            })?;

        CompressedDataRunsStream::new(
            self.volume.clone(),
            join_extent_runs(extents)?,
            first.file_size,
            unit_clusters,
        )
    }
}

/// Largest number of clusters a file can span: NTFS addresses at most 2^32 clusters per volume,
/// and documents the same limit for one file.
const MAX_FILE_CLUSTERS: u64 = 1 << 32;

/// The two sizes of a non-resident stream, as its first extent states them.
#[derive(Debug, Clone, Copy)]
struct StreamSizes {
    /// Logical size of the stream.
    ///
    /// It is an on-disk field and is not required to fit the mapping pairs. On an intact volume
    /// the runs cover it. When they don't (a deleted or partly overwritten record whose mapping
    /// pairs were cut short while the size survived), the part of the stream past the runs is
    /// treated as a hole: it reads as zeros, so the clusters that are still mapped stay
    /// readable.
    file: u64,
    /// Valid data length, capped at `file`.
    ///
    /// NTFS keeps a high-water mark of the bytes that were really written to a non-resident
    /// stream. A file can be longer than that (it was extended without writing, for example
    /// with `SetEndOfFile`), and the clusters past the mark then still hold whatever was on the
    /// disk before. NTFS returns zeros for that range, and so do the readers here.
    valid: u64,
}

/// Returns the sizes of the stream described by `extents` (sorted by VCN).
fn stream_sizes(extents: &[DataExtent]) -> Result<StreamSizes> {
    let first = extents.first().ok_or_else(|| Error::InvalidData {
        message: "stream has no extents".to_string(),
    })?;
    Ok(StreamSizes {
        file: first.file_size,
        valid: first.valid_data_length.min(first.file_size),
    })
}

fn is_entry_efs_encrypted(entry: &mft::MftEntry) -> bool {
    for attr in entry
        .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
        .filter_map(std::result::Result::ok)
    {
        if let Some(si) = attr.data.as_standard_info().cloned()
            && si
                .file_flags
                .contains(mft::attribute::FileAttributeFlags::FILE_ATTRIBUTE_ENCRYPTED)
        {
            return true;
        }
    }
    false
}

fn read_efs_attribute_blob(volume: &Volume, entry: &mft::MftEntry) -> Result<Vec<u8>> {
    let attr = entry
        .iter_attributes_matching(Some(vec![MftAttributeType::LoggedUtilityStream]))
        .filter_map(std::result::Result::ok)
        .find(|a| a.header.name == "$EFS")
        .ok_or_else(|| Error::NotFound {
            what: "missing $EFS logged utility stream".to_string(),
        })?;

    match &attr.header.residential_header {
        ResidentialHeader::Resident(rh) => {
            let start = attr.header.start_offset as usize + rh.data_offset as usize;
            let end = start + rh.data_size as usize;
            let data = entry
                .data
                .get(start..end)
                .ok_or_else(|| Error::InvalidData {
                    message: "$EFS resident data out of bounds".to_string(),
                })?;
            Ok(data.to_vec())
        }
        ResidentialHeader::NonResident(nr) => {
            let runs = attr
                .data
                .as_data_runs()
                .cloned()
                .ok_or_else(|| Error::InvalidData {
                    message: "expected data runs for $EFS".to_string(),
                })?
                .data_runs;
            let mut buf = alloc_stream_buffer(nr.file_size, "$EFS attribute")?;
            read_from_data_runs(volume, &runs, 0, &mut buf)?;
            Ok(buf)
        }
    }
}

/// Largest stream the in-memory readers ([`FileSystem::read_file_stream`] and its relatives)
/// load: 1 GiB.
///
/// A stream's size is an on-disk field, and nothing on the volume bounds it: a sparse or
/// compressed file can be far larger than the image it sits in, and so can a corrupt size. The
/// in-memory readers therefore stop at this fixed size, whatever the image. A larger stream is
/// read piece by piece through [`FileSystem::open_file_stream_read_at`], hashed with
/// [`FileSystem::md5_file_stream`] or exported with
/// [`FileSystem::export_file_default_stream_to_path`].
pub const MAX_IN_MEMORY_STREAM_BYTES: u64 = 1024 * 1024 * 1024;

/// Allocates a zeroed buffer to read `len` bytes of a stream into memory.
///
/// `len` comes from an on-disk size field, so it is held to [`MAX_IN_MEMORY_STREAM_BYTES`]. An
/// allocation the system refuses is an error, not an abort.
fn alloc_stream_buffer(len: u64, what: &str) -> Result<Vec<u8>> {
    if len > MAX_IN_MEMORY_STREAM_BYTES {
        return Err(Error::Unsupported {
            what: format!(
                "reading a {what} of {len} bytes into memory: the limit is {MAX_IN_MEMORY_STREAM_BYTES} bytes"
            ),
        });
    }

    let too_large = || Error::Unsupported {
        what: format!("reading a {what} of {len} bytes into memory: allocation failed"),
    };
    let len = usize::try_from(len).map_err(|_| too_large())?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(len).map_err(|_| too_large())?;
    buf.resize(len, 0);
    Ok(buf)
}

fn md5_of_bytes_hex_lower(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Feeds `len` zero bytes to `hasher`.
fn md5_update_zeros(hasher: &mut Md5, len: u64) {
    static ZEROS: [u8; 64 * 1024] = [0u8; 64 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(ZEROS.len() as u64) as usize;
        hasher.update(&ZEROS[..n]);
        remaining -= n as u64;
    }
}

/// Moves the write position of `file` forward by `len` bytes, leaving a hole.
fn seek_forward(file: &mut File, len: u64) -> Result<()> {
    let len = i64::try_from(len).map_err(|_| Error::InvalidData {
        message: format!("hole of {len} bytes is too large to export"),
    })?;
    file.seek(SeekFrom::Current(len))?;
    Ok(())
}

fn standard_info_indicates_case_sensitive(si: &mft::attribute::x10::StandardInfoAttr) -> bool {
    si.max_version == 0 && si.version == 1
}

fn resolve_component_in_entries(
    dir_entry_id: u64,
    entries: &[DirectoryEntry],
    component: &str,
    case_sensitive: bool,
    upcase: Option<&UpcaseTable>,
) -> Result<u64> {
    let needle_utf16 = component.encode_utf16().collect::<Vec<_>>();

    let mut matches = Vec::new();
    if case_sensitive {
        for e in entries {
            if eq_case_sensitive(&e.name_utf16, &needle_utf16) {
                matches.push(e);
            }
        }
    } else {
        let upcase = upcase.ok_or_else(|| Error::InvalidData {
            message: "missing $UpCase table for case-insensitive comparison".to_string(),
        })?;
        for e in entries {
            if eq_case_insensitive_ntfs(upcase, &e.name_utf16, &needle_utf16) {
                matches.push(e);
            }
        }
    }

    if matches.is_empty() {
        return Err(Error::NotFound {
            what: format!("path component `{component}` under entry {dir_entry_id}"),
        });
    }

    let mut entry_ids: HashSet<u64> = matches.iter().map(|e| e.entry_id).collect();
    if entry_ids.len() == 1 {
        return Ok(entry_ids.drain().next().expect("len=1"));
    }

    // Ambiguous: multiple different entry IDs match. Provide candidates deterministically.
    let mut candidates = matches
        .iter()
        .map(|e| (e.entry_id, e.name.clone()))
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    candidates.dedup();

    let listed = candidates
        .into_iter()
        .map(|(id, name)| format!("{name} (entry {id})"))
        .collect::<Vec<_>>()
        .join(", ");

    Err(Error::InvalidData {
        message: format!(
            "ambiguous path component `{component}` under entry {dir_entry_id}: {listed}"
        ),
    })
}

fn split_path(path: &str) -> impl Iterator<Item = &str> {
    path.split(['\\', '/'])
        .filter(|s| !s.is_empty() && *s != ".")
}

#[cfg(test)]
mod case_sensitivity_tests {
    use super::standard_info_indicates_case_sensitive;
    use jiff::Timestamp;
    use mft::attribute::FileAttributeFlags;
    use mft::attribute::x10::StandardInfoAttr;

    #[test]
    fn test_standard_information_case_sensitive_flag() {
        let ts = Timestamp::new(0, 0).unwrap();
        let mk = |max_version: u32, version: u32| StandardInfoAttr {
            created: ts,
            modified: ts,
            mft_modified: ts,
            accessed: ts,
            file_flags: FileAttributeFlags::from_bits_truncate(0),
            max_version,
            version,
            class_id: 0,
            owner_id: 0,
            security_id: 0,
            quota: 0,
            usn: 0,
        };

        assert!(standard_info_indicates_case_sensitive(&mk(0, 1)));
        assert!(!standard_info_indicates_case_sensitive(&mk(0, 0)));
        assert!(!standard_info_indicates_case_sensitive(&mk(1, 1)));
    }
}

#[cfg(test)]
mod path_resolution_tests {
    use super::resolve_component_in_entries;
    use crate::ntfs::Error;
    use crate::ntfs::filesystem::DirectoryEntry;
    use crate::ntfs::name::UpcaseTable;
    use crate::ntfs::name::upcase::UPCASE_CHARACTER_COUNT;

    fn ascii_upcase_for_tests() -> UpcaseTable {
        let mut map = (0u32..UPCASE_CHARACTER_COUNT as u32)
            .map(|v| v as u16)
            .collect::<Vec<_>>();
        for (lower, upper) in (b'a'..=b'z').zip(b'A'..=b'Z') {
            map[lower as usize] = upper as u16;
        }
        UpcaseTable::from_mapping_for_tests(map)
    }

    fn dirent(name: &str, entry_id: u64) -> DirectoryEntry {
        DirectoryEntry {
            name: name.to_string(),
            name_utf16: name.encode_utf16().collect(),
            entry_id,
        }
    }

    #[test]
    fn case_insensitive_match_errors_on_ambiguous_different_entry_ids() {
        let up = ascii_upcase_for_tests();
        let entries = vec![dirent("foo", 1), dirent("FOO", 2)];
        let err = resolve_component_in_entries(5, &entries, "foo", false, Some(&up)).unwrap_err();
        assert!(matches!(err, Error::InvalidData { .. }));
        assert!(err.to_string().contains("ambiguous path component `foo`"));
    }

    #[test]
    fn case_insensitive_match_allows_multiple_names_for_same_entry_id() {
        let up = ascii_upcase_for_tests();
        let entries = vec![dirent("foo", 1), dirent("FOO", 1)];
        let id = resolve_component_in_entries(5, &entries, "foo", false, Some(&up)).unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn case_sensitive_match_requires_exact_utf16() {
        let entries = vec![dirent("foo", 1), dirent("FOO", 2)];
        let id = resolve_component_in_entries(5, &entries, "foo", true, None).unwrap();
        assert_eq!(id, 1);
        assert!(resolve_component_in_entries(5, &entries, "Foo", true, None).is_err());
    }
}

#[derive(Debug, Clone)]
struct DataExtent {
    vcn_first: u64,
    file_size: u64,
    /// The valid data length. Like the file size, it only means something in the extent that
    /// starts at VCN 0.
    valid_data_length: u64,
    is_compressed: bool,
    compression_unit_clusters: Option<u64>,
    data_runs: Vec<mft::attribute::data_run::DataRun>,
}

/// Wraps `inner` so that bytes from `valid_len` on read as zeros without touching `inner`.
fn zero_past_valid_data(inner: Arc<dyn ReadAt>, valid_len: u64) -> Arc<dyn ReadAt> {
    if valid_len >= inner.len() {
        return inner;
    }
    Arc::new(ValidDataReadAt { inner, valid_len })
}

/// A [`ReadAt`] view that applies a stream's valid data length, see [`StreamSizes::valid`].
struct ValidDataReadAt {
    inner: Arc<dyn ReadAt>,
    valid_len: u64,
}

impl ReadAt for ValidDataReadAt {
    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        use std::io;

        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        if end > self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let valid = usize::try_from(self.valid_len.saturating_sub(offset))
            .map_or(buf.len(), |v| v.min(buf.len()));
        if valid > 0 {
            self.inner.read_exact_at(offset, &mut buf[..valid])?;
        }
        buf[valid..].fill(0);
        Ok(())
    }
}

/// A simple in-memory [`ReadAt`] implementation.
#[derive(Debug, Clone)]
struct ResidentReadAt {
    data: Arc<[u8]>,
}

impl ResidentReadAt {
    fn new(bytes: Vec<u8>) -> Self {
        Self { data: bytes.into() }
    }
}

impl ReadAt for ResidentReadAt {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        use std::io;

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

        buf.copy_from_slice(&self.data[start..end]);
        Ok(())
    }
}

/// A [`ReadAt`] wrapper that decrypts EFS ciphertext on-the-fly.
///
/// Decryption is performed in 512-byte sectors, matching Windows NTFS EFS behavior.
struct EfsDecryptingReadAt {
    cipher: Arc<dyn ReadAt>,
    decryptor: EfsFekDecryptor,
    plain_len: u64,
}

impl EfsDecryptingReadAt {
    fn new(cipher: Arc<dyn ReadAt>, decryptor: EfsFekDecryptor, plain_len: u64) -> Self {
        Self {
            cipher,
            decryptor,
            plain_len,
        }
    }
}

impl ReadAt for EfsDecryptingReadAt {
    fn len(&self) -> u64 {
        self.plain_len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        use std::io;

        if buf.is_empty() {
            return Ok(());
        }

        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        if end > self.plain_len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let aligned_start = (offset / 512).saturating_mul(512);
        let aligned_end = end.div_ceil(512).saturating_mul(512);
        let aligned_len = aligned_end
            .checked_sub(aligned_start)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range underflow"))?;

        // `aligned_len` is always a multiple of 512 bytes.
        let mut tmp = vec![0u8; aligned_len as usize];
        self.cipher.read_exact_at(aligned_start, &mut tmp)?;
        self.decryptor
            .decrypt_in_place(&mut tmp, aligned_start)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let start_in_tmp = usize::try_from(offset - aligned_start)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        buf.copy_from_slice(&tmp[start_in_tmp..start_in_tmp + buf.len()]);
        Ok(())
    }
}

impl DataExtent {
    fn from_non_resident_attr(
        attr: &mft::attribute::MftAttribute,
        nr: &mft::attribute::header::NonResidentHeader,
        data_runs: Vec<mft::attribute::data_run::DataRun>,
    ) -> Result<Self> {
        let file_size = nr.file_size;
        let vcn_first = nr.vnc_first;

        let is_compressed = attr
            .header
            .data_flags
            .contains(AttributeDataFlags::IS_COMPRESSED)
            || nr.unit_compression_size > 0;

        let compression_unit_clusters = if is_compressed {
            // Interpret as a shift count (common NTFS behavior): unit_clusters = 1 << shift.
            let shift = (nr.unit_compression_size & 0x00ff) as u32;
            let unit_clusters = 1u64.checked_shl(shift).ok_or_else(|| Error::InvalidData {
                message: format!("compression unit shift {shift} is out of range"),
            })?;
            Some(unit_clusters)
        } else {
            None
        };

        Ok(Self {
            vcn_first,
            file_size,
            valid_data_length: nr.valid_data_length,
            is_compressed,
            compression_unit_clusters,
            data_runs,
        })
    }
}

/// Upper bound for a non-resident `$ATTRIBUTE_LIST`. NTFS itself limits the list to 256 KiB.
const MAX_ATTRIBUTE_LIST_SIZE: u64 = 1024 * 1024;

/// Where one `$ATTRIBUTE_LIST` entry points, detached from the buffer it was parsed from.
#[derive(Debug, Clone)]
struct AttributeListItem {
    lowest_vcn: u64,
    /// MFT entry number of the record that holds the attribute.
    segment_entry: u64,
    /// Attribute instance id inside that record.
    instance: u16,
}

impl From<&AttributeListEntry<'_>> for AttributeListItem {
    fn from(entry: &AttributeListEntry<'_>) -> Self {
        Self {
            lowest_vcn: entry.lowest_vcn,
            segment_entry: entry.segment_reference.entry,
            instance: entry.reserved,
        }
    }
}

/// Joins the data runs of `extents` (sorted by VCN) into one run list that starts at VCN 0.
///
/// A hole between two extents becomes a sparse run. Extents that overlap are rejected.
fn join_extent_runs(extents: &[DataExtent]) -> Result<Vec<DataRun>> {
    let mut runs: Vec<DataRun> = Vec::new();
    let mut next_vcn = 0u64;

    for extent in extents {
        if extent.vcn_first < next_vcn {
            return Err(Error::InvalidData {
                message: format!(
                    "overlapping $DATA extents: extent starts at VCN {} but VCN {next_vcn} is already mapped",
                    extent.vcn_first
                ),
            });
        }
        if extent.vcn_first > next_vcn {
            runs.push(DataRun {
                lcn_offset: 0,
                lcn_length: extent.vcn_first - next_vcn,
                run_type: RunType::Sparse,
            });
            next_vcn = extent.vcn_first;
        }

        for run in &extent.data_runs {
            next_vcn = next_vcn
                .checked_add(run.lcn_length)
                .ok_or_else(|| Error::InvalidData {
                    message: "data run length overflow".to_string(),
                })?;
            runs.push(*run);
        }
    }

    Ok(runs)
}
