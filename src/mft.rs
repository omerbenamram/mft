use crate::FileNameAttr;
use crate::attribute::{MftAttributeContent, MftAttributeType};
use crate::entry::{MftEntry, find_best_name_attribute_in};
use crate::err::{Error, Result};

use crate::EntryHeader;
use log::{debug, trace, warn};

use lru::LruCache;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use winstructs::ntfs::mft_reference::MftReference;

/// How an entry contributes to the paths of its children.
enum PathStep {
    /// The entry's full path is known without looking further.
    Final(PathBuf),
    /// The entry has no name, and takes the path of its base entry.
    Alias(MftReference),
    /// The entry's path is its parent's path joined with `name`.
    Named { name: String, parent: PathParent },
}

enum PathParent {
    Root,
    Orphan,
    Entry(MftReference),
}

/// The sequence number and allocation of a record, which tell whether a reference points at the
/// file the record holds now.
#[derive(Clone, Copy)]
struct Generation {
    sequence: u16,
    allocated: bool,
}

impl Generation {
    fn of(entry: &MftEntry) -> Self {
        Generation {
            sequence: entry.header.sequence,
            allocated: entry.is_allocated(),
        }
    }

    /// Whether a reference with sequence number `sequence` points at this record, rather than at
    /// an earlier file the record held before it was reused. Windows bumps a record's sequence
    /// number when it frees it (skipping 0), so references to a deleted file are one behind its
    /// freed record. Sequence number 0 in a reference means it isn't checked.
    fn is_referenced_by(self, sequence: u16) -> bool {
        let after_free = match sequence.wrapping_add(1) {
            0 => 1,
            next => next,
        };
        sequence == 0
            || sequence == self.sequence
            || (!self.allocated && after_free == self.sequence)
    }
}

/// A directory on the way up from a directory to the root, in
/// [`MftParser::resolve_directory_path`].
struct Link {
    id: u64,
    generation: Option<Generation>,
    /// `None` if the directory takes its base entry's path.
    name: Option<String>,
}

/// A directory's path, as cached by the parser.
struct CachedPath {
    path: PathBuf,
    /// The directory's record, which references to it are checked against. `None` for a record
    /// that couldn't be read, whose path is `[Unknown]` whichever reference reaches it.
    generation: Option<Generation>,
}

/// The path of a file whose parent reference is stale: the parent's record now holds another
/// file.
fn stale_parent_path(reference: MftReference) -> PathBuf {
    trace!(
        "Found stale parent reference to entry ID {} (sequence {})",
        reference.entry, reference.sequence
    );
    PathBuf::from("[Orphaned]")
}

/// A copy of `path` with room for `extra` more bytes, so pushing them doesn't copy it again.
fn path_with_room(path: &Path, extra: usize) -> PathBuf {
    let mut copy = PathBuf::with_capacity(path.as_os_str().len() + extra);
    copy.push(path);
    copy
}

/// The most directory paths a parser caches. A directory that fell out of the cache is read again
/// for its next file, which past this size is rare: see H11 in `PERF.md`.
const MAX_CACHED_DIRECTORIES: usize = 65_536;

pub struct MftParser<T: Read + Seek> {
    data: T,
    /// Entry size is present in the volume header, but this is not available to us.
    /// Instead this will be guessed from the entry headers, see `guess_entry_size`.
    entry_size: u32,
    size: u64,
    entries_cache: LruCache<u64, CachedPath>,
    /// The directories that parent loops were cut at, which resolve as orphans. Kept outside
    /// `entries_cache`, so a loop stays cut after its paths leave it.
    cycle_cuts: BTreeSet<u64>,
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

        // `LruCache::new` allocates the whole table up front, so a small MFT gets a smaller cache,
        // though not below 1,000 paths: a corrupt MFT's parent references past its end are cached
        // too.
        let entry_count = usize::try_from(size / u64::from(entry_size)).unwrap_or(usize::MAX);
        let cache_size = entry_count.clamp(1_000, MAX_CACHED_DIRECTORIES);

        Ok(Self {
            data,
            entry_size,
            size,
            entries_cache: LruCache::new(
                NonZeroUsize::new(cache_size).expect("clamped to at least 1,000"),
            ),
            cycle_cuts: BTreeSet::new(),
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
        reference.entry == base.header.record_number
            && record.is_allocated() == base.is_allocated()
            && Generation::of(base).is_referenced_by(reference.sequence)
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

    /// The name and parent of an entry for path resolution, from
    /// [`find_best_name_attribute_in`]. Extension records are only read when the base record has
    /// no long name.
    fn best_name(&mut self, entry: &MftEntry) -> Option<(String, MftReference)> {
        if let Some(name) = entry.find_best_name_in_parent()
            && name.namespace.is_long()
        {
            return Some((name.name.to_utf8_string(), name.parent));
        }

        // Without an `$ATTRIBUTE_LIST`, there are no extension records and nothing is read.
        let extensions = self.get_extension_entries(entry);
        find_best_name_attribute_in(entry, &extensions)
            .map(|fname| (fname.name.to_utf8_string(), fname.parent))
    }

    /// Classifies an entry for path resolution, as the parent of another entry.
    fn path_step(&mut self, entry: &MftEntry) -> PathStep {
        let name = self.best_name(entry);
        self.path_step_named(entry, name)
    }

    /// [`MftParser::path_step`], given the entry's [`MftParser::best_name`].
    fn path_step_named(&self, entry: &MftEntry, name: Option<(String, MftReference)>) -> PathStep {
        match name {
            // A parent that isn't a directory can't be trusted.
            Some(_) if !entry.is_dir() => PathStep::Final(PathBuf::from("[Unknown]")),
            Some((name, parent)) => {
                let parent = match parent.entry {
                    // MFT entry 5 is the root path.
                    5 => PathParent::Root,
                    0 => PathParent::Orphan,
                    id if id == entry.header.record_number => {
                        trace!("Found self-referential file path, for entry ID {id}");
                        PathParent::Orphan
                    }
                    _ if self.cycle_cuts.contains(&entry.header.record_number) => {
                        PathParent::Orphan
                    }
                    _ => PathParent::Entry(parent),
                };
                PathStep::Named { name, parent }
            }
            // I have a parent, which doesn't have a filename attribute.
            None => match entry.header.base_reference.entry {
                0 => PathStep::Final(PathBuf::new()),
                _ if !entry.is_dir() => PathStep::Final(PathBuf::from("[Unknown]")),
                _ => PathStep::Alias(entry.header.base_reference),
            },
        }
    }

    /// Resolves the path of a directory, given its own step, by walking up its ancestors.
    /// Caches the path of every directory its path goes through.
    ///
    /// The walk is iterative, so deep or cyclic parent chains can't overflow the stack.
    /// A cycle is cut at its named entry with the lowest ID, which becomes `[Orphaned]/<name>`
    /// (in a cycle without names, every entry is `[Orphaned]`). This keeps paths independent of
    /// the order in which entries are resolved.
    ///
    /// A directory whose parent reference is stale (the parent's record was reused for another
    /// file) becomes `[Orphaned]/<name>` too.
    fn resolve_directory_path(
        &mut self,
        entry_id: u64,
        generation: Option<Generation>,
        first_step: PathStep,
    ) -> PathBuf {
        // Most directories' parents are cached.
        if let PathStep::Named {
            name,
            parent: PathParent::Entry(parent),
        } = &first_step
            && let Some(mut path) = self.cached_directory_path(*parent, 1 + name.len())
        {
            path.push(name);
            self.cache_path(entry_id, generation, path.clone());
            return path;
        }

        // Directories from `entry_id` upwards.
        let mut chain: Vec<Link> = Vec::new();
        // The length of their names, joined into a path.
        let mut names_len = 0;
        // Where each directory is in `chain`.
        let mut positions: HashMap<u64, usize> = HashMap::new();
        let (mut current_id, mut current_generation) = (entry_id, generation);
        let mut step = first_step;

        let mut prefix = loop {
            let (name, parent) = match step {
                PathStep::Final(path) => {
                    self.cache_path(current_id, current_generation, path.clone());
                    break path;
                }
                PathStep::Alias(base) => (None, PathParent::Entry(base)),
                PathStep::Named { name, parent } => {
                    names_len += 1 + name.len();
                    (Some(name), parent)
                }
            };
            chain.push(Link {
                id: current_id,
                generation: current_generation,
                name,
            });
            let next = match parent {
                PathParent::Root => break PathBuf::with_capacity(names_len),
                PathParent::Orphan => break PathBuf::from("[Orphaned]"),
                PathParent::Entry(reference) => reference,
            };

            if let Some(path) = self.cached_directory_path(next, names_len) {
                break path;
            }

            let Some((generation, next_step)) = self.referenced_step(next) else {
                break stale_parent_path(next);
            };

            // Most directories' parents are cached, so this is only built past a miss.
            positions.insert(current_id, chain.len() - 1);
            if let Some(&cycle_start) = positions.get(&next.entry) {
                trace!(
                    "Found a cycle in parent references at entry ID {}",
                    next.entry
                );
                // Cut at the named directory with the lowest ID, which becomes an orphan. The ones
                // past it resolve through it when they are asked for.
                if let Some(cut) = (cycle_start..chain.len())
                    .filter(|&i| chain[i].name.is_some())
                    .min_by_key(|&i| chain[i].id)
                {
                    self.cycle_cuts.insert(chain[cut].id);
                    chain.truncate(cut + 1);
                }
                break PathBuf::from("[Orphaned]");
            }

            (current_id, current_generation) = (next.entry, generation);
            step = next_step;
        };

        for link in chain.into_iter().rev() {
            prefix.extend(link.name);
            self.cache_path(link.id, link.generation, prefix.clone());
        }
        prefix
    }

    fn cache_path(&mut self, entry_id: u64, generation: Option<Generation>, path: PathBuf) {
        self.entries_cache
            .put(entry_id, CachedPath { path, generation });
    }

    /// The cached path of the directory `reference` points at, with room for `extra` more bytes,
    /// or `None` if it isn't cached. A stale reference gets `[Orphaned]`.
    fn cached_directory_path(&mut self, reference: MftReference, extra: usize) -> Option<PathBuf> {
        let cached = self.entries_cache.get(&reference.entry)?;
        if cached
            .generation
            .is_some_and(|g| !g.is_referenced_by(reference.sequence))
        {
            return Some(stale_parent_path(reference));
        }
        Some(path_with_room(&cached.path, extra))
    }

    /// Reads the directory `reference` points at, for path resolution: its record and its step,
    /// or `None` if the reference is stale.
    fn referenced_step(
        &mut self,
        reference: MftReference,
    ) -> Option<(Option<Generation>, PathStep)> {
        match self.get_entry(reference.entry) {
            Ok(entry) => {
                let generation = Generation::of(&entry);
                let step = self.path_step(&entry);
                if generation.is_referenced_by(reference.sequence) {
                    return Some((Some(generation), step));
                }
                // A record reused for a file is never cached as a directory on the way, so cache
                // it here, or every stale reference to it reads it again.
                if let PathStep::Final(path) = step {
                    self.cache_path(reference.entry, Some(generation), path);
                }
                None
            }
            // Parent is maybe corrupted or incomplete, use a sentinel instead.
            Err(_) => Some((None, PathStep::Final(PathBuf::from("[Unknown]")))),
        }
    }

    /// Gets the full path of the directory `reference` points at, or `[Orphaned]` if the
    /// reference is stale. A cached path gets room for `extra` more bytes.
    fn get_directory_path(&mut self, reference: MftReference, extra: usize) -> PathBuf {
        if let Some(path) = self.cached_directory_path(reference, extra) {
            return path;
        }
        match self.referenced_step(reference) {
            Some((generation, step)) => {
                self.resolve_directory_path(reference.entry, generation, step)
            }
            None => stale_parent_path(reference),
        }
    }

    /// Gets the full path of a file under one of its names, such as one of its hard links, which
    /// [`MftParser::get_full_path_for_entry`] doesn't pick.
    pub fn get_full_path_for_name(&mut self, entry: &MftEntry, name: &FileNameAttr<'_>) -> PathBuf {
        self.path_in_parent(
            entry.header.record_number,
            name.name.to_utf8_string(),
            name.parent,
        )
    }

    /// The path of the file `entry_id` named `name` in the directory `parent` points at.
    /// A stale `parent` (its record now holds another file) gives `[Orphaned]/<name>`.
    fn path_in_parent(&mut self, entry_id: u64, name: String, parent: MftReference) -> PathBuf {
        match parent.entry {
            // MFT entry 5 is the root path.
            5 => PathBuf::from(name),
            0 => {
                trace!("Found orphaned entry ID {entry_id}");
                PathBuf::from("[Orphaned]").join(name)
            }
            id if id == entry_id => {
                trace!("Found self-referential file path, for entry ID {entry_id}");
                PathBuf::from("[Orphaned]").join(name)
            }
            _ => {
                let mut path = self.get_directory_path(parent, 1 + name.len());
                path.push(name);
                path
            }
        }
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
                return Ok(Some(cached.path.clone()));
            }
            let step = self.path_step_named(entry, filename_header);
            return Ok(Some(self.resolve_directory_path(
                entry_id,
                Some(Generation::of(entry)),
                step,
            )));
        }

        match filename_header {
            Some((name, parent)) => Ok(Some(self.path_in_parent(entry_id, name, parent))),
            None => match entry.header.base_reference.entry {
                // I don't have a parent reference, and no X30 attribute. Though luck.
                0 => Ok(None),
                _ => Ok(Some(
                    self.get_directory_path(entry.header.base_reference, 0),
                )),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::tests::mft_reference_bytes;
    use crate::tests::fixtures::mft_sample;
    use crate::{MftEntry, MftParser};
    use itertools::Itertools;
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
            value.extend_from_slice(&mft_reference_bytes(parent, 1));
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

    /// An MFT whose entries 0-4 are placeholders, 5 is the root, and 6 on are `entries`.
    fn mft_of(entries: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
        let mut mft = Vec::new();
        for _ in 0..5 {
            mft.extend(synthetic_entry(false, None));
        }
        mft.extend(synthetic_entry(true, Some((".", 5))));
        mft.extend(entries.into_iter().flatten());
        mft
    }

    fn cyclic_mft() -> Vec<u8> {
        // 6 and 7 are directories that claim each other as parents, and 8 is a file inside 6.
        mft_of([
            synthetic_entry(true, Some(("A", 7))),
            synthetic_entry(true, Some(("B", 6))),
            synthetic_entry(false, Some(("f.txt", 6))),
        ])
    }

    /// A directory without a name, which takes the path of its base entry.
    fn nameless_directory(base: u64) -> Vec<u8> {
        let mut e = synthetic_entry(true, None);
        e[0x20..0x28].copy_from_slice(&mft_reference_bytes(base, 1)); // base record
        e
    }

    /// `entry` with its record's sequence number set to `sequence`. Parent references in
    /// [`synthetic_entry`]s point at sequence 1.
    fn with_sequence(mut entry: Vec<u8>, sequence: u16) -> Vec<u8> {
        entry[16..18].copy_from_slice(&sequence.to_le_bytes());
        entry
    }

    /// `entry` with its record freed, as when its file is deleted.
    fn freed(mut entry: Vec<u8>) -> Vec<u8> {
        entry[22] &= !0x1;
        entry
    }

    /// An MFT where 6 is a directory "A" with sequence number `sequence` and allocation
    /// `allocated`, holding a file (7) and a directory "B" (8) with a file of its own (9), all of
    /// which point at sequence 1 of 6.
    fn mft_with_parent_generation(sequence: u16, allocated: bool) -> Vec<u8> {
        let a = with_sequence(synthetic_entry(true, Some(("A", 5))), sequence);
        mft_of([
            if allocated { a } else { freed(a) },
            synthetic_entry(false, Some(("f.txt", 6))),
            synthetic_entry(true, Some(("B", 6))),
            synthetic_entry(false, Some(("g.txt", 8))),
        ])
    }

    fn full_path(parser: &mut MftParser<Cursor<Vec<u8>>>, id: u64) -> PathBuf {
        let entry = parser.get_entry(id).unwrap();
        parser.get_full_path_for_entry(&entry).unwrap().unwrap()
    }

    fn resolve_in_order(mft: &[u8], order: &[u64]) -> Vec<(u64, PathBuf)> {
        let mut parser = MftParser::from_buffer(mft.to_vec()).unwrap();
        let mut paths: Vec<(u64, PathBuf)> = order
            .iter()
            .map(|&id| (id, full_path(&mut parser, id)))
            .collect();
        paths.sort();
        paths
    }

    /// Checks that each of `expected`'s entries gets its `/`-separated path, in every order.
    fn assert_paths_in_any_order(mft: &[u8], expected: &[(u64, &str)]) {
        let expected: Vec<(u64, PathBuf)> = expected
            .iter()
            .map(|&(id, path)| (id, path.split('/').collect()))
            .collect();
        let ids = expected.iter().map(|&(id, _)| id);
        for order in ids.permutations(expected.len()) {
            assert_eq!(resolve_in_order(mft, &order), expected, "order {order:?}");
        }
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
        assert_paths_in_any_order(
            &cyclic_mft(),
            &[
                (6, "[Orphaned]/A"),
                (7, "[Orphaned]/A/B"),
                (8, "[Orphaned]/A/f.txt"),
            ],
        );
    }

    #[test]
    fn test_get_full_path_keeps_parent_cycles_cut_after_eviction() {
        let mut parser = MftParser::from_buffer(cyclic_mft()).unwrap();
        let a = PathBuf::from("[Orphaned]").join("A");
        assert_eq!(full_path(&mut parser, 7), a.join("B"));

        // The cycle was cut at 6, which stays cut once it leaves the cache instead of taking a
        // path through 7.
        parser.entries_cache.pop(&6);
        assert_eq!(full_path(&mut parser, 8), a.join("f.txt"));
    }

    #[test]
    fn test_get_full_path_through_a_nameless_directory() {
        // 7 is a directory without a name, which takes the path of 6 ("A", in the root).
        let mft = mft_of([
            synthetic_entry(true, Some(("A", 5))),
            nameless_directory(6),
            synthetic_entry(false, Some(("f.txt", 7))),
        ]);
        assert_paths_in_any_order(&mft, &[(6, "A"), (7, "A"), (8, "A/f.txt")]);
    }

    #[test]
    fn test_get_full_path_breaks_parent_cycles_through_nameless_directories() {
        // 6 ("A") is in 8 ("B"), which is in 7, a directory without a name that takes the path of
        // 6. The cycle is cut at its lowest named entry (6), wherever resolving starts.
        let mft = mft_of([
            synthetic_entry(true, Some(("A", 8))),
            nameless_directory(6),
            synthetic_entry(true, Some(("B", 7))),
            synthetic_entry(false, Some(("f.txt", 7))),
        ]);
        assert_paths_in_any_order(
            &mft,
            &[
                (6, "[Orphaned]/A"),
                (7, "[Orphaned]/A"),
                (8, "[Orphaned]/A/B"),
                (9, "[Orphaned]/A/f.txt"),
            ],
        );

        // With the nameless directory first (6, taking the path of 8), the cut is at 7 ("A").
        let mft = mft_of([
            nameless_directory(8),
            synthetic_entry(true, Some(("A", 6))),
            synthetic_entry(true, Some(("B", 7))),
            synthetic_entry(false, Some(("f.txt", 6))),
        ]);
        assert_paths_in_any_order(
            &mft,
            &[
                (6, "[Orphaned]/A/B"),
                (7, "[Orphaned]/A"),
                (8, "[Orphaned]/A/B"),
                (9, "[Orphaned]/A/B/f.txt"),
            ],
        );
    }

    #[test]
    fn test_get_full_path_breaks_parent_cycles_without_names() {
        // 6 and 7 are directories without names, each taking the path of the other.
        let mft = mft_of([
            nameless_directory(7),
            nameless_directory(6),
            synthetic_entry(false, Some(("f.txt", 6))),
        ]);
        assert_paths_in_any_order(
            &mft,
            &[
                (6, "[Orphaned]"),
                (7, "[Orphaned]"),
                (8, "[Orphaned]/f.txt"),
            ],
        );
    }

    #[test]
    fn test_get_full_path_orphans_stale_parent_references() {
        // 6 was reused for another directory, so 7 and 8 were in a directory that is gone.
        assert_paths_in_any_order(
            &mft_with_parent_generation(2, true),
            &[
                (6, "A"),
                (7, "[Orphaned]/f.txt"),
                (8, "[Orphaned]/B"),
                (9, "[Orphaned]/B/g.txt"),
            ],
        );
    }

    #[test]
    fn test_get_full_path_through_a_deleted_parent() {
        // Freeing 6 bumped its sequence number, but it still holds the directory 7 and 8 were in.
        assert_paths_in_any_order(
            &mft_with_parent_generation(2, false),
            &[(6, "A"), (7, "A/f.txt"), (8, "A/B"), (9, "A/B/g.txt")],
        );
        // Freeing it once more means it held another file in between.
        assert_paths_in_any_order(
            &mft_with_parent_generation(3, false),
            &[
                (6, "A"),
                (7, "[Orphaned]/f.txt"),
                (8, "[Orphaned]/B"),
                (9, "[Orphaned]/B/g.txt"),
            ],
        );
    }

    #[test]
    fn test_get_full_path_doesnt_cut_stale_parent_cycles() {
        // 6 and 7 claim each other as parents, but 7 points at an earlier file in 6's record, so
        // they don't make a cycle.
        let mft = mft_of([
            with_sequence(synthetic_entry(true, Some(("A", 7))), 2),
            synthetic_entry(true, Some(("B", 6))),
            synthetic_entry(false, Some(("f.txt", 7))),
        ]);
        assert_paths_in_any_order(
            &mft,
            &[
                (6, "[Orphaned]/B/A"),
                (7, "[Orphaned]/B"),
                (8, "[Orphaned]/B/f.txt"),
            ],
        );
        let mut parser = MftParser::from_buffer(mft).unwrap();
        for id in 6..=8 {
            full_path(&mut parser, id);
        }
        assert!(parser.cycle_cuts.is_empty());
    }

    #[test]
    fn test_generation_is_referenced_by() {
        let freed = |sequence| super::Generation {
            sequence,
            allocated: false,
        };
        assert!(freed(2).is_referenced_by(1));
        assert!(!freed(3).is_referenced_by(1));
        // Sequence numbers skip 0 when they wrap.
        assert!(freed(1).is_referenced_by(0xFFFF));
        assert!(!freed(0).is_referenced_by(0xFFFF));
        // A reference with sequence number 0 isn't checked.
        assert!(freed(7).is_referenced_by(0));
        let live = super::Generation {
            sequence: 2,
            allocated: true,
        };
        assert!(live.is_referenced_by(2) && !live.is_referenced_by(1));
    }

    #[test]
    fn test_get_full_path_orphans_stale_base_references() {
        // 7 takes the path of its base entry 6, which was reused.
        let mft = mft_of([
            with_sequence(synthetic_entry(true, Some(("A", 5))), 2),
            nameless_directory(6),
            synthetic_entry(false, Some(("f.txt", 7))),
        ]);
        assert_paths_in_any_order(
            &mft,
            &[(6, "A"), (7, "[Orphaned]"), (8, "[Orphaned]/f.txt")],
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
