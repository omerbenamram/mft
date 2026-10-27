use crate::entry::MftEntry;
use crate::err::{Error, Result};

use crate::EntryHeader;
use log::{debug, trace};

use lru::LruCache;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

pub struct MftParser<T: Read + Seek> {
    data: T,
    /// Entry size is present in the volume header, but this is not available to us.
    /// Instead this will be guessed from the entry headers, see `guess_entry_size`.
    entry_size: u32,
    size: u64,
    entries_cache: LruCache<u64, PathBuf>,
    // Parent entries whose paths are currently being resolved. Used to break cycles in
    // corrupt (or maliciously crafted) parent references.
    resolving_parents: HashSet<u64>,
    // Next expected read offset in the underlying stream. Used to avoid a seek syscall when
    // reading entries sequentially.
    next_read_offset: u64,
}

impl MftParser<BufReader<File>> {
    /// Instantiates an instance of the parser from a file path.
    /// Does not mutate the file contents in any way.
    pub fn from_path(filename: impl AsRef<Path>) -> Result<Self> {
        let f = filename.as_ref();

        let mft_fh = File::open(f).map_err(|e| Error::failed_to_open_file(f, e))?;
        let size = fs::metadata(f)?.len();

        Self::from_read_seek(BufReader::with_capacity(4096, mft_fh), Some(size))
    }
}

impl MftParser<Cursor<Vec<u8>>> {
    /// Instantiates an instance of the parser from a buffer containing a full MFT file.
    /// Useful for testing.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self> {
        let size = buffer.len() as u64;
        let cursor = Cursor::new(buffer);

        Self::from_read_seek(cursor, Some(size))
    }
}

impl<T: Read + Seek> MftParser<T> {
    pub fn from_read_seek(mut data: T, size: Option<u64>) -> Result<Self> {
        let size = match size {
            Some(sz) => sz,
            None => data.seek(SeekFrom::End(0))?,
        };

        let entry_size = Self::guess_entry_size(&mut data, size)?;

        data.rewind()?;

        Ok(Self {
            data,
            entry_size,
            size,
            entries_cache: LruCache::new(NonZeroUsize::new(1000).expect("1000 > 0")),
            resolving_parents: HashSet::new(),
            next_read_offset: 0,
        })
    }

    /// Entry size is present in the volume header, but this is not available to us.
    /// We use the first entry to guess the entry size for all the other records.
    /// If the first entry is zeroed or corrupt, we look for the next entry with a plausible size.
    fn guess_entry_size(data: &mut T, size: u64) -> Result<u32> {
        // Entry sizes are 1024 or 4096 in practice, both multiples of the probe stride.
        const PROBE_STRIDE: u64 = 1024;
        const MAX_PROBES: u64 = 64;

        fn is_plausible(entry_size: u32) -> bool {
            entry_size.is_power_of_two() && (512..=65536).contains(&entry_size)
        }

        data.rewind()?;
        let first_entry = EntryHeader::from_reader(data, 0);
        if let Ok(header) = &first_entry
            && is_plausible(header.total_entry_size)
        {
            return Ok(header.total_entry_size);
        }

        for probe in 1..MAX_PROBES {
            let offset = probe * PROBE_STRIDE;
            if offset >= size {
                break;
            }
            data.seek(SeekFrom::Start(offset))?;
            if let Ok(header) = EntryHeader::from_reader(data, probe)
                && header.is_valid()
                && is_plausible(header.total_entry_size)
            {
                debug!(
                    "First entry has no usable size, using entry size {} from offset {offset}",
                    header.total_entry_size
                );
                return Ok(header.total_entry_size);
            }
        }

        match first_entry {
            Err(e) => Err(e),
            Ok(header) => Err(Error::Any {
                detail: format!(
                    "could not determine MFT entry size (first entry declares {} bytes)",
                    header.total_entry_size
                ),
            }),
        }
    }

    pub fn get_entry_count(&self) -> u64 {
        self.size / u64::from(self.entry_size)
    }

    /// Reads an entry from the MFT by entry number.
    pub fn get_entry(&mut self, entry_number: u64) -> Result<MftEntry> {
        debug!("Reading entry {entry_number}");

        let entry_size = u64::from(self.entry_size);
        let desired_offset = entry_number * entry_size;

        // Avoid seeking when reading sequential entries; this keeps the BufReader hot and
        // removes a large number of __lseek syscalls in tight loops.
        if self.next_read_offset != desired_offset {
            self.data.seek(SeekFrom::Start(desired_offset))?;
            self.next_read_offset = desired_offset;
        }

        let mut entry_buffer = vec![0; self.entry_size as usize];

        self.data.read_exact(&mut entry_buffer)?;
        self.next_read_offset = self.next_read_offset.saturating_add(entry_size);

        MftEntry::from_buffer(entry_buffer, entry_number)
    }

    /// Iterates over all the entries in the MFT.
    pub fn iter_entries(&mut self) -> impl Iterator<Item = Result<MftEntry>> + '_ {
        let total_entries = self.get_entry_count();

        (0..total_entries).map(move |i| self.get_entry(i))
    }

    fn inner_get_entry(&mut self, parent_entry_id: u64, entry_name: Option<&str>) -> PathBuf {
        let cached_entry = self.entries_cache.get(&parent_entry_id);

        // If my parent path is known, then my path is parent's full path + my name.
        // Else, retrieve and cache my parent's path.
        if let Some(cached_parent_path) = cached_entry {
            match entry_name {
                Some(name) => cached_parent_path.clone().join(name),
                None => cached_parent_path.clone(),
            }
        } else {
            if !self.resolving_parents.insert(parent_entry_id) {
                trace!("Found a cycle in parent references at entry ID {parent_entry_id}");
                let orphan = PathBuf::from("[Orphaned]");
                return match entry_name {
                    Some(name) => orphan.join(name),
                    None => orphan,
                };
            }

            let path = match self.get_entry(parent_entry_id).ok() {
                Some(parent) => match self.get_full_path_for_entry(&parent) {
                    Ok(Some(path)) if parent.is_dir() => path,
                    Ok(Some(_)) => PathBuf::from("[Unknown]"),
                    // I have a parent, which doesn't have a filename attribute.
                    // Default to root.
                    _ => PathBuf::new(),
                },
                // Parent is maybe corrupted or incomplete, use a sentinel instead.
                None => PathBuf::from("[Unknown]"),
            };

            self.resolving_parents.remove(&parent_entry_id);
            self.entries_cache.put(parent_entry_id, path.clone());
            match entry_name {
                Some(name) => path.join(name),
                None => path,
            }
        }
    }

    /// Gets the full path for an entry.
    /// Caches computations.
    pub fn get_full_path_for_entry(&mut self, entry: &MftEntry) -> Result<Option<PathBuf>> {
        let entry_id = entry.header.record_number;
        match entry.find_best_name_attribute() {
            Some(filename_header) => {
                let parent_entry_id = filename_header.parent.entry;
                let name = filename_header.name.to_utf8_string();

                // MFT entry 5 is the root path.
                if parent_entry_id == 5 {
                    return Ok(Some(PathBuf::from(name)));
                }

                if parent_entry_id == entry_id {
                    trace!("Found self-referential file path, for entry ID {entry_id}");
                    return Ok(Some(PathBuf::from("[Orphaned]").join(&name)));
                }

                if parent_entry_id > 0 {
                    Ok(Some(self.inner_get_entry(parent_entry_id, Some(&name))))
                } else {
                    trace!("Found orphaned entry ID {entry_id}");

                    let orphan = PathBuf::from("[Orphaned]").join(&name);

                    self.entries_cache
                        .put(entry.header.record_number, orphan.clone());

                    Ok(Some(orphan))
                }
            }
            None => match entry.header.base_reference.entry {
                // I don't have a parent reference, and no X30 attribute. Though luck.
                0 => Ok(None),
                parent_entry_id => Ok(Some(self.inner_get_entry(parent_entry_id, None))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::fixtures::mft_sample;
    use crate::{MftEntry, MftParser};
    use std::path::PathBuf;

    const ENTRY_SIZE: usize = 1024;

    /// Builds a minimal 1024-byte `FILE` record, optionally with a Win32 `$FILE_NAME`.
    fn synthetic_entry(is_dir: bool, name: Option<(&str, u64)>) -> Vec<u8> {
        let mut e = vec![0u8; ENTRY_SIZE];
        e[0..4].copy_from_slice(b"FILE");
        e[4..6].copy_from_slice(&0x30u16.to_le_bytes()); // usa offset
        e[6..8].copy_from_slice(&3u16.to_le_bytes()); // usa size
        e[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence
        e[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard link count
        e[20..22].copy_from_slice(&0x38u16.to_le_bytes()); // first attribute
        let flags: u16 = if is_dir { 0x3 } else { 0x1 };
        e[22..24].copy_from_slice(&flags.to_le_bytes());
        e[28..32].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
        // Update sequence number 1, stamped at the end of both sectors.
        e[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
        e[510..512].copy_from_slice(&1u16.to_le_bytes());
        e[1022..1024].copy_from_slice(&1u16.to_le_bytes());

        let mut offset = 0x38;
        if let Some((name, parent)) = name {
            let mut value = Vec::new();
            let mut parent_ref = parent.to_le_bytes();
            parent_ref[6..8].copy_from_slice(&1u16.to_le_bytes());
            value.extend_from_slice(&parent_ref);
            const FT: [u8; 8] = [0xD5, 0x2D, 0x48, 0x58, 0x43, 0x5F, 0xCE, 0x01];
            for _ in 0..4 {
                value.extend_from_slice(&FT);
            }
            value.extend_from_slice(&[0; 16]); // sizes
            value.extend_from_slice(&[0; 8]); // flags + reparse value
            value.push(name.len() as u8);
            value.push(1); // Win32 namespace
            for b in name.as_bytes() {
                value.extend_from_slice(&[*b, 0]);
            }

            let record_length = (24 + value.len() + 7) & !7;
            let attr = &mut e[offset..offset + record_length];
            attr[0..4].copy_from_slice(&0x30u32.to_le_bytes());
            attr[4..8].copy_from_slice(&(record_length as u32).to_le_bytes());
            attr[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
            attr[20..22].copy_from_slice(&24u16.to_le_bytes());
            attr[24..24 + value.len()].copy_from_slice(&value);
            offset += record_length;
        }
        e[offset..offset + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        e[24..28].copy_from_slice(&((offset + 8) as u32).to_le_bytes()); // used size
        e
    }

    #[test]
    fn test_get_full_path_breaks_parent_cycles() {
        // Entries 0-4 are placeholders, 5 is the root, 6 and 7 are directories that claim
        // each other as parents, and 8 is a file inside 6.
        let mut mft = Vec::new();
        for _ in 0..5 {
            mft.extend(synthetic_entry(false, None));
        }
        mft.extend(synthetic_entry(true, Some((".", 5))));
        mft.extend(synthetic_entry(true, Some(("A", 7))));
        mft.extend(synthetic_entry(true, Some(("B", 6))));
        mft.extend(synthetic_entry(false, Some(("f.txt", 6))));

        let mut parser = MftParser::from_buffer(mft).unwrap();
        let entry = parser.get_entry(8).unwrap();
        let path = parser.get_full_path_for_entry(&entry).unwrap().unwrap();

        assert_eq!(
            path,
            PathBuf::from("[Orphaned]")
                .join("B")
                .join("A")
                .join("f.txt")
        );
    }

    #[test]
    fn test_zeroed_first_entry_uses_next_entry_size() {
        let mut mft = vec![0u8; ENTRY_SIZE];
        mft.extend(synthetic_entry(false, Some(("f.txt", 5))));

        let parser = MftParser::from_buffer(mft).unwrap();
        assert_eq!(parser.get_entry_count(), 2);
    }

    #[test]
    fn test_all_zero_mft_is_error_not_panic() {
        assert!(MftParser::from_buffer(vec![0u8; ENTRY_SIZE * 4]).is_err());
    }

    // entrypoint for clion profiler.
    #[test]
    fn test_process_90_mft_entries() {
        let sample = mft_sample();

        let mut parser = MftParser::from_path(sample).unwrap();

        let mut count = 0;
        for record in parser.iter_entries().take(10000).filter_map(|a| a.ok()) {
            for _attribute in record.iter_attributes() {
                count += 1;
            }
        }

        assert!(count > 0)
    }

    #[test]
    fn test_get_full_path() {
        let sample = mft_sample();
        let mut parser = MftParser::from_path(sample).unwrap();

        let mut paths = Vec::with_capacity(1000);
        let entries: Vec<MftEntry> = parser
            .iter_entries()
            .take(1000)
            .filter_map(Result::ok)
            .collect();

        for entry in entries {
            if let Some(path) = parser.get_full_path_for_entry(&entry).unwrap() {
                paths.push(path)
            }
        }

        assert_eq!(paths.len(), 988);
    }

    #[test]
    fn test_get_full_name() {
        let sample = mft_sample();
        let mut parser = MftParser::from_path(sample).unwrap();

        let e = parser.get_entry(5).unwrap();
        parser.get_full_path_for_entry(&e).unwrap();
    }
}
