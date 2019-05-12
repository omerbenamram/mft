use crate::entry::MftEntry;
use crate::enumerator::{PathEnumerator, PathMapping};
use crate::err::{self, Result};

use log::debug;
use snafu::ResultExt;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use winstructs::ntfs::mft_reference::MftReference;

pub struct MftParser {
    file: BufReader<File>,
    path_enumerator: PathEnumerator,
    entry_size: u32,
    offset: u64,
    size: u64,
}

impl MftParser {
    pub fn from_path(filename: impl AsRef<Path>) -> Result<MftParser> {
        let f = filename.as_ref();

        let mft_fh = File::open(f).context(err::FailedToOpenFile { path: f.to_owned() })?;
        let size = fs::metadata(f)?.len();

        let file = BufReader::with_capacity(4096, mft_fh);

        Ok(MftParser {
            file,
            path_enumerator: PathEnumerator::new(),
            entry_size: 1024,
            offset: 0,
            size,
        })
    }

    pub fn set_entry_size(&mut self, entry_size: u32) {
        self.entry_size = entry_size
    }

    pub fn get_entry_count(&self) -> u64 {
        self.size / u64::from(self.entry_size)
    }

    pub fn entry(&mut self, entry: u64) -> Result<MftEntry> {
        debug!("Reading entry {}", entry);
        self.file
            .seek(SeekFrom::Start(entry * u64::from(self.entry_size)))?;

        let mut entry_buffer = vec![0; self.entry_size as usize];
        self.file.read_exact(&mut entry_buffer)?;

        let mft_entry = self.entry_from_buffer(entry_buffer, entry)?;

        // We need to set the path if dir
        if let Some(mapping) = mft_entry.get_pathmap() {
            if mft_entry.is_dir() {
                self.path_enumerator
                    .set_mapping(mft_entry.header.entry_reference, mapping.clone());
            }
        }

        // TODO: don't do this mutably from here.
        //        mft_entry.set_full_names(self);

        Ok(mft_entry)
    }

    pub fn print_mapping(&self) {
        self.path_enumerator.print_mapping();
    }

    pub fn entry_from_buffer(&mut self, buffer: Vec<u8>, entry: u64) -> Result<MftEntry> {
        let mft_entry = MftEntry::new(buffer, entry)?;

        Ok(mft_entry)
    }

    pub fn get_fullpath(&mut self, reference: MftReference) -> String {
        let mut path_stack = Vec::new();
        self.enumerate_path_stack(&mut path_stack, reference);
        path_stack.join("/")
    }

    fn enumerate_path_stack(&mut self, name_stack: &mut Vec<String>, reference: MftReference) {
        // 1407374883553285 (5-5)
        if reference.entry == 1_407_374_883_553_285 {

        } else {
            match self.path_enumerator.get_mapping(reference) {
                Some(mapping) => {
                    self.enumerate_path_stack(name_stack, mapping.parent);
                    name_stack.push(mapping.name.clone());
                }
                None => {
                    // Mapping not exists
                    // Get entry number for this reference that does not exist
                    let entry = reference.entry;
                    // Gat mapping for it
                    match self.get_mapping_from_entry(entry) {
                        Ok(mapping) => match mapping {
                            Some(map) => {
                                self.path_enumerator.set_mapping(reference, map.clone());
                                self.enumerate_path_stack(name_stack, reference);
                            }
                            None => {
                                name_stack.push(String::from("[UNKNOWN]"));
                            }
                        },
                        Err(_error) => {
                            name_stack.push(String::from("[UNKNOWN]"));
                        }
                    }
                }
            }
        }
    }

    fn get_mapping_from_entry(&mut self, entry: u64) -> Result<Option<PathMapping>> {
        self.file
            .seek(SeekFrom::Start(entry * u64::from(self.entry_size)))?;

        let mut entry_buffer = vec![0; self.entry_size as usize];
        self.file.read_exact(&mut entry_buffer)?;

        let mft_entry = self.entry_from_buffer(entry_buffer, entry)?;

        Ok(mft_entry.get_pathmap())
    }
}
