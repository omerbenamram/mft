use crate::FileNameAttr;
use crate::attribute::{MftAttributeContent, MftAttributeType};
use crate::entry::{MftEntry, find_best_name_attribute_in, is_long_name};
use crate::err::{Error, Result};

use crate::EntryHeader;
use log::{debug, trace, warn};

use lru::LruCache;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

/// How an entry contributes to the paths of its children.
enum PathStep {
    /// The entry's full path is known without looking further.
    Final(PathBuf),
    /// The entry has no name, and takes the path of its base entry.
    Alias(u64),
    /// The entry's path is its parent's path joined with `name`.
    Named { name: String, parent: PathParent },
}

enum PathParent {
    Root,
    Orphan,
    Entry(u64),
}

pub struct MftParser<T: Read + Seek> {
    data: T,
    /// Entry size is present in the volume header, but this is not available to us.
    /// Instead this will be guessed from the entry headers, see `guess_entry_size`.
    entry_size: u32,
    size: u64,
    entries_cache: LruCache<u64, PathBuf>,
    /// Extension record IDs by base record ID, built on first use by scanning the whole MFT.
    /// Only needed for entries whose `$ATTRIBUTE_LIST` is non-resident, since the clusters
    /// holding it aren't in the MFT.
    extensions_index: Option<HashMap<u64, Vec<u64>>>,
    // Where the underlying stream is positioned, if known. Used to avoid a seek syscall when
    // reading entries sequentially.
    next_read_offset: Option<u64>,
}

impl MftParser<BufReader<File>> {
    /// Instantiates an instance of the parser from a file path.
    /// Does not mutate the file contents in any way.
    pub fn from_path(filename: impl AsRef<Path>) -> Result<Self> {
        let f = filename.as_ref();

        let mft_fh = File::open(f).map_err(|e| Error::failed_to_open_file(f, e))?;
        let size = fs::metadata(f)?.len();

        Self::from_read_seek(BufReader::with_capacity(32 * 1024, mft_fh), Some(size))
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
            extensions_index: None,
            next_read_offset: Some(0),
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

        let mut entry_buffer = vec![0; self.entry_size as usize];
        self.read_entry_bytes(entry_number, &mut entry_buffer)?;

        MftEntry::from_buffer(entry_buffer, entry_number)
    }

    /// Reads the raw bytes of an entry into `buffer`, which is one entry long.
    fn read_entry_bytes(&mut self, entry_number: u64, buffer: &mut [u8]) -> Result<()> {
        let entry_size = u64::from(self.entry_size);
        let desired_offset = entry_number * entry_size;

        // Avoid seeking when reading sequential entries; this keeps the BufReader hot and
        // removes a large number of __lseek syscalls in tight loops.
        // A failed seek or read leaves the stream somewhere unknown, so the position is only
        // set again once the whole entry has been read.
        if self.next_read_offset.take() != Some(desired_offset) {
            self.data.seek(SeekFrom::Start(desired_offset))?;
        }
        self.data.read_exact(buffer)?;
        self.next_read_offset = Some(desired_offset + entry_size);
        Ok(())
    }

    /// Iterates over all the entries in the MFT.
    pub fn iter_entries(&mut self) -> impl Iterator<Item = Result<MftEntry>> + '_ {
        let total_entries = self.get_entry_count();

        (0..total_entries).map(move |i| self.get_entry(i))
    }

    /// Reads the extension records of a base entry: the records that hold the attributes its
    /// `$ATTRIBUTE_LIST` moved out of it. Returns no records for an entry without one.
    ///
    /// A resident `$ATTRIBUTE_LIST` names the records directly. A non-resident one lives outside
    /// the MFT (and one that fails to parse can't be trusted), so the first such entry triggers a
    /// scan of the whole MFT for records whose base reference points back at it. Either way, only records whose base reference matches the
    /// entry (number and sequence) are returned, so reused records of a deleted file are left
    /// out. Records that can't be read are skipped.
    pub fn get_extension_entries(&mut self, entry: &MftEntry) -> Vec<MftEntry> {
        let record_number = entry.header.record_number;
        // Only the header is needed to know that there is a list: content that fails to parse
        // still leaves the scan to find the extensions.
        let mut attribute_lists = entry
            .iter_attribute_records_matching(Some(vec![MftAttributeType::AttributeList]))
            .filter_map(Result::ok)
            .peekable();
        if attribute_lists.peek().is_none() {
            return Vec::new();
        }

        let mut ids: Vec<u64> = Vec::new();
        let mut needs_scan = false;
        for (header, record) in attribute_lists {
            let content = MftAttributeContent::from_record(record, &header).ok();
            match content
                .as_ref()
                .and_then(MftAttributeContent::as_attribute_list)
            {
                Some(list) => ids.extend(
                    list.entries
                        .iter()
                        .map(|e| e.segment_reference.entry)
                        .filter(|&id| id != record_number),
                ),
                None => needs_scan = true,
            }
        }
        if needs_scan {
            let index = self.extensions_index();
            ids.extend(index.get(&record_number).into_iter().flatten());
        }
        ids.sort_unstable();
        ids.dedup();

        ids.into_iter()
            .filter_map(|id| match self.get_entry(id) {
                Ok(record) if Self::is_extension_of(&record, entry) => Some(record),
                Ok(_) => {
                    trace!("Entry {id} is not an extension of entry {record_number}");
                    None
                }
                Err(e) => {
                    warn!("Failed to read extension record {id} of entry {record_number}: {e}");
                    None
                }
            })
            .collect()
    }

    /// Whether `record` is a current extension record of `base`. A record freed with a deleted
    /// file keeps pointing at the sequence number the file had before Windows bumped it on
    /// deletion. A freed record pointing at a live file was dropped from its attribute list.
    fn is_extension_of(record: &MftEntry, base: &MftEntry) -> bool {
        let reference = &record.header.base_reference;
        let sequence = base.header.sequence;
        let sequence_matches = reference.sequence == sequence
            || (!base.is_allocated() && reference.sequence == sequence.wrapping_sub(1));
        reference.entry == base.header.record_number
            && record.is_allocated() == base.is_allocated()
            && sequence_matches
    }

    fn extensions_index(&mut self) -> &HashMap<u64, Vec<u64>> {
        if self.extensions_index.is_none() {
            let mut index: HashMap<u64, Vec<u64>> = HashMap::new();
            let mut buffer = vec![0; self.entry_size as usize];
            for id in 0..self.get_entry_count() {
                // Only the header is needed, which the update sequence array doesn't touch.
                if self.read_entry_bytes(id, &mut buffer).is_ok()
                    && let Ok(header) = EntryHeader::from_reader(&mut buffer.as_slice(), id)
                    && !header.is_base_record()
                {
                    index
                        .entry(header.base_reference.entry)
                        .or_default()
                        .push(id);
                }
            }
            return self.extensions_index.insert(index);
        }
        self.extensions_index.get_or_insert_default()
    }

    /// The name and parent ID of an entry for path resolution, from
    /// [`find_best_name_attribute_in`]. Extension records are only read when the base record has
    /// no long name.
    fn best_name(&mut self, entry: &MftEntry) -> Option<(String, u64)> {
        let to_owned = |fname: FileNameAttr<'_>| (fname.name.to_utf8_string(), fname.parent.entry);

        let base_name = entry.find_best_name_attribute();
        if base_name.as_ref().is_some_and(is_long_name) {
            return base_name.map(to_owned);
        }

        // Without an `$ATTRIBUTE_LIST`, there are no extension records and nothing is read.
        let extensions = self.get_extension_entries(entry);
        find_best_name_attribute_in(entry, &extensions).map(to_owned)
    }

    /// Classifies an entry for path resolution, as the parent of another entry.
    fn path_step(&mut self, entry: &MftEntry) -> PathStep {
        let name = self.best_name(entry);
        Self::path_step_named(entry, name)
    }

    /// [`MftParser::path_step`], given the entry's [`MftParser::best_name`].
    fn path_step_named(entry: &MftEntry, name: Option<(String, u64)>) -> PathStep {
        match name {
            // A parent that isn't a directory can't be trusted.
            Some(_) if !entry.is_dir() => PathStep::Final(PathBuf::from("[Unknown]")),
            Some((name, parent)) => {
                let parent = match parent {
                    // MFT entry 5 is the root path.
                    5 => PathParent::Root,
                    0 => PathParent::Orphan,
                    id if id == entry.header.record_number => {
                        trace!("Found self-referential file path, for entry ID {id}");
                        PathParent::Orphan
                    }
                    id => PathParent::Entry(id),
                };
                PathStep::Named { name, parent }
            }
            // I have a parent, which doesn't have a filename attribute.
            None => match entry.header.base_reference.entry {
                0 => PathStep::Final(PathBuf::new()),
                _ if !entry.is_dir() => PathStep::Final(PathBuf::from("[Unknown]")),
                base => PathStep::Alias(base),
            },
        }
    }

    /// Resolves the path of a directory, given its own step, by walking up its ancestors.
    /// Caches the path of every directory on the way.
    ///
    /// The walk is iterative, so deep or cyclic parent chains can't overflow the stack.
    /// A cycle is cut at its lowest entry ID, which becomes `[Orphaned]/<name>`. This keeps
    /// paths independent of the order in which entries are resolved.
    fn resolve_directory_path(&mut self, entry_id: u64, first_step: PathStep) -> PathBuf {
        // Directories from `entry_id` upwards, each with its name.
        let mut chain: Vec<(u64, String)> = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut current_id = entry_id;
        let mut step = first_step;

        let mut prefix = loop {
            visited.insert(current_id);
            let next_id = match step {
                PathStep::Final(path) => {
                    self.entries_cache.put(current_id, path.clone());
                    break path;
                }
                PathStep::Alias(base) => base,
                PathStep::Named { name, parent } => {
                    chain.push((current_id, name));
                    match parent {
                        PathParent::Root => break PathBuf::new(),
                        PathParent::Orphan => break PathBuf::from("[Orphaned]"),
                        PathParent::Entry(id) => id,
                    }
                }
            };

            if let Some(cached) = self.entries_cache.get(&next_id) {
                break cached.clone();
            }

            if visited.contains(&next_id) {
                match chain.iter().position(|(id, _)| *id == next_id) {
                    Some(cycle_start) => {
                        trace!("Found a cycle in parent references at entry ID {next_id}");
                        let path = self.cut_cycle(&chain[cycle_start..]);
                        chain.truncate(cycle_start);
                        break path;
                    }
                    // A cycle made only of entries without names.
                    None => break PathBuf::from("[Orphaned]"),
                }
            }

            current_id = next_id;
            step = match self.get_entry(current_id) {
                Ok(parent) => self.path_step(&parent),
                // Parent is maybe corrupted or incomplete, use a sentinel instead.
                Err(_) => PathStep::Final(PathBuf::from("[Unknown]")),
            };
        };

        for (id, name) in chain.iter().rev() {
            prefix = prefix.join(name);
            self.entries_cache.put(*id, prefix.clone());
        }
        prefix
    }

    /// Assigns paths to the members of a parent cycle (child first, each one's parent is the
    /// next, and the last one's parent is the first), cutting it at the lowest entry ID.
    /// Caches them, and returns the path of the first member.
    fn cut_cycle(&mut self, cycle: &[(u64, String)]) -> PathBuf {
        let cut = cycle
            .iter()
            .enumerate()
            .min_by_key(|(_, (id, _))| *id)
            .map_or(0, |(i, _)| i);

        // Walk from the cut member down to its children, wrapping around the cycle.
        let mut path = PathBuf::from("[Orphaned]");
        let mut first_member_path = PathBuf::new();
        for offset in 0..cycle.len() {
            let i = (cut + cycle.len() - offset) % cycle.len();
            let (id, name) = &cycle[i];
            path = path.join(name);
            self.entries_cache.put(*id, path.clone());
            if i == 0 {
                first_member_path = path.clone();
            }
        }
        first_member_path
    }

    /// Gets the full path of the directory with the given entry ID.
    fn get_directory_path(&mut self, entry_id: u64) -> PathBuf {
        if let Some(cached) = self.entries_cache.get(&entry_id) {
            return cached.clone();
        }

        let step = match self.get_entry(entry_id) {
            Ok(entry) => self.path_step(&entry),
            // Parent is maybe corrupted or incomplete, use a sentinel instead.
            Err(_) => PathStep::Final(PathBuf::from("[Unknown]")),
        };
        self.resolve_directory_path(entry_id, step)
    }

    /// Gets the full path for an entry.
    /// Caches computations.
    pub fn get_full_path_for_entry(&mut self, entry: &MftEntry) -> Result<Option<PathBuf>> {
        let entry_id = entry.header.record_number;
        let filename_header = self.best_name(entry);

        // Directories go through the same walk as parents, so a directory's path always
        // matches the prefix of its children's paths.
        if entry.is_dir() && filename_header.is_some() {
            if let Some(cached) = self.entries_cache.get(&entry_id) {
                return Ok(Some(cached.clone()));
            }
            let step = Self::path_step_named(entry, filename_header);
            return Ok(Some(self.resolve_directory_path(entry_id, step)));
        }

        match filename_header {
            Some((name, parent_entry_id)) => {
                match parent_entry_id {
                    // MFT entry 5 is the root path.
                    5 => Ok(Some(PathBuf::from(name))),
                    0 => {
                        trace!("Found orphaned entry ID {entry_id}");
                        Ok(Some(PathBuf::from("[Orphaned]").join(name)))
                    }
                    id if id == entry_id => {
                        trace!("Found self-referential file path, for entry ID {entry_id}");
                        Ok(Some(PathBuf::from("[Orphaned]").join(name)))
                    }
                    id => Ok(Some(self.get_directory_path(id).join(name))),
                }
            }
            None => match entry.header.base_reference.entry {
                // I don't have a parent reference, and no X30 attribute. Though luck.
                0 => Ok(None),
                base_entry_id => Ok(Some(self.get_directory_path(base_entry_id))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::fixtures::mft_sample;
    use crate::{MftEntry, MftParser};
    use std::io::{self, Cursor, Read, Seek, SeekFrom};
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

    fn cyclic_mft() -> Vec<u8> {
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
        mft
    }

    fn resolve_in_order(order: &[u64]) -> Vec<(u64, PathBuf)> {
        let mut parser = MftParser::from_buffer(cyclic_mft()).unwrap();
        let mut paths: Vec<(u64, PathBuf)> = order
            .iter()
            .map(|&id| {
                let entry = parser.get_entry(id).unwrap();
                (id, parser.get_full_path_for_entry(&entry).unwrap().unwrap())
            })
            .collect();
        paths.sort();
        paths
    }

    /// Reads at most half an entry per call, and fails once mid-entry when `fail` is set.
    struct FlakyReader {
        inner: Cursor<Vec<u8>>,
        fail: bool,
    }

    impl Read for FlakyReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.fail && self.inner.position() % ENTRY_SIZE as u64 == ENTRY_SIZE as u64 / 2 {
                self.fail = false;
                return Err(io::Error::other("flaky read"));
            }
            let len = buf.len().min(ENTRY_SIZE / 2);
            self.inner.read(&mut buf[..len])
        }
    }

    impl Seek for FlakyReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn test_read_after_a_failed_read_seeks_back_to_the_entry() {
        let reader = FlakyReader {
            inner: Cursor::new(cyclic_mft()),
            fail: false,
        };
        let mut parser = MftParser::from_read_seek(reader, None).unwrap();

        parser.data.fail = true;
        assert!(parser.get_entry(5).is_err());

        // The failed read stopped halfway through entry 5, so reading it again has to seek.
        let entry = parser.get_entry(5).unwrap();
        assert_eq!(entry.find_best_name_attribute().unwrap().name, ".");
    }

    #[test]
    fn test_get_full_path_breaks_parent_cycles() {
        // The cycle is cut at its lowest entry ID (6).
        let expected = vec![
            (6, PathBuf::from("[Orphaned]").join("A")),
            (7, PathBuf::from("[Orphaned]").join("A").join("B")),
            (8, PathBuf::from("[Orphaned]").join("A").join("f.txt")),
        ];

        // Paths don't depend on the order entries are resolved in.
        assert_eq!(resolve_in_order(&[6, 7, 8]), expected);
        assert_eq!(resolve_in_order(&[7, 6, 8]), expected);
        assert_eq!(resolve_in_order(&[8, 7, 6]), expected);
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
    fn test_get_full_path_independent_of_resolution_order() {
        // Directory paths are cached as they are resolved, so make sure the cache never changes
        // the result: resolving in MFT order and in reverse order must agree.
        let sample = mft_sample();
        let mut forward_parser = MftParser::from_path(&sample).unwrap();
        let mut reverse_parser = MftParser::from_path(&sample).unwrap();

        let entries: Vec<MftEntry> = forward_parser
            .iter_entries()
            .filter_map(Result::ok)
            .collect();

        let forward: Vec<_> = entries
            .iter()
            .map(|e| forward_parser.get_full_path_for_entry(e).unwrap())
            .collect();
        let mut reverse: Vec<_> = entries
            .iter()
            .rev()
            .map(|e| reverse_parser.get_full_path_for_entry(e).unwrap())
            .collect();
        reverse.reverse();

        assert_eq!(forward.len(), entries.len());
        assert_eq!(forward, reverse);
    }

    #[test]
    fn test_get_full_name() {
        let sample = mft_sample();
        let mut parser = MftParser::from_path(sample).unwrap();

        let e = parser.get_entry(5).unwrap();
        parser.get_full_path_for_entry(&e).unwrap();
    }

    /// Records 76746 and 77871 of the CFReDS 2015 Data Leakage Case `$MFT` (NIST, public
    /// domain): a deleted file (sequence 4) and its freed extension record, which still points
    /// at sequence 3.
    #[test]
    fn test_deleted_file_keeps_its_extension_record() {
        let base = MftEntry::from_buffer(
            include_bytes!("../samples/entry_76746_deleted_base").to_vec(),
            76746,
        )
        .unwrap();
        let extension = MftEntry::from_buffer(
            include_bytes!("../samples/entry_77871_deleted_extension").to_vec(),
            77871,
        )
        .unwrap();
        assert!(!base.is_allocated() && !extension.is_allocated());
        assert_eq!(base.header.sequence, 4);
        assert_eq!(extension.header.base_reference.sequence, 3);
        assert!(MftParser::<std::io::Cursor<Vec<u8>>>::is_extension_of(
            &extension, &base
        ));

        // Once the file is live again (the record was reused), an old extension is stale.
        let mut reused = base.clone();
        reused.header.flags |= crate::entry::EntryFlags::ALLOCATED;
        assert!(!MftParser::<std::io::Cursor<Vec<u8>>>::is_extension_of(
            &extension, &reused
        ));
    }
}
