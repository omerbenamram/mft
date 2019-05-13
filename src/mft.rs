use crate::entry::MftEntry;
use crate::enumerator::{PathEnumerator, PathMapping};
use crate::err::{self, Result};

use crate::ReadSeek;
use log::debug;
use snafu::ResultExt;

use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::Path;

pub struct MftParser<T: ReadSeek> {
    data: T,
    /// Entry size is present in the volume header, but this is not available to us.
    /// Instead this will be guessed by the entry size of the first entry.
    entry_size: u32,
    size: u64,
}

impl MftParser<BufReader<File>> {
    /// Instantiates an instance of the parser from a file path.
    /// Does not mutate the file contents in any way.
    pub fn from_path(filename: impl AsRef<Path>) -> Result<Self> {
        let f = filename.as_ref();

        let mft_fh = File::open(f).context(err::FailedToOpenFile { path: f.to_owned() })?;
        let size = fs::metadata(f)?.len();

        Ok(MftParser {
            data: BufReader::with_capacity(4096, mft_fh),
            entry_size: 1024,
            size,
        })
    }
}

impl MftParser<Cursor<Vec<u8>>> {
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self> {
        let size = buffer.len() as u64;
        let cursor = Cursor::new(buffer);

        Ok(MftParser {
            data: cursor,
            entry_size: 1024,
            size,
        })
    }
}

impl<T: Read + Seek> MftParser<T> {
    pub fn get_entry_count(&self) -> u64 {
        self.size / u64::from(self.entry_size)
    }

    pub fn iter_entries(&mut self) -> impl Iterator<Item = Result<MftEntry>> + '_ {
        let total_entries = self.get_entry_count();
        let mut count = 0;

        std::iter::from_fn(move || {
            if count == total_entries {
                None
            } else {
                // TODO: is this off by one?
                count += 1;
                debug!("Reading entry {}", count);

                if let Err(e) = self
                    .data
                    .seek(SeekFrom::Start(count * u64::from(self.entry_size)))
                    .eager_context(err::IoError)
                {
                    return Some(Err(e));
                };

                let mut entry_buffer = vec![0; self.entry_size as usize];

                if let Err(e) = self
                    .data
                    .read_exact(&mut entry_buffer)
                    .eager_context(err::IoError)
                {
                    return Some(Err(e));
                }

                Some(MftEntry::from_buffer(entry_buffer))
            }
        })
    }

    //    pub fn print_mapping(&self) {
    //        self.path_enumerator.print_mapping();
    //    }
    //
    //    pub fn get_fullpath(&mut self, reference: MftReference) -> String {
    //        let mut path_stack = Vec::new();
    //        self.enumerate_path_stack(&mut path_stack, reference);
    //        path_stack.join("/")
    //    }
    //
    //    fn enumerate_path_stack(&mut self, name_stack: &mut Vec<String>, reference: MftReference) {
    //        // 1407374883553285 (5-5)
    //        if reference.entry == 1_407_374_883_553_285 {
    //
    //        } else {
    //            match self.path_enumerator.get_mapping(reference) {
    //                Some(mapping) => {
    //                    self.enumerate_path_stack(name_stack, mapping.parent);
    //                    name_stack.push(mapping.name.clone());
    //                }
    //                None => {
    //                    // Mapping not exists
    //                    // Get entry number for this reference that does not exist
    //                    let entry = reference.entry;
    //                    // Gat mapping for it
    //                    match self.get_mapping_from_entry(entry) {
    //                        Ok(mapping) => match mapping {
    //                            Some(map) => {
    //                                self.path_enumerator.set_mapping(reference, map.clone());
    //                                self.enumerate_path_stack(name_stack, reference);
    //                            }
    //                            None => {
    //                                name_stack.push(String::from("[UNKNOWN]"));
    //                            }
    //                        },
    //                        Err(_error) => {
    //                            name_stack.push(String::from("[UNKNOWN]"));
    //                        }
    //                    }
    //                }
    //            }
    //        }
    //    }

    //    fn get_mapping_from_entry(&mut self, entry: u64) -> Result<Option<PathMapping>> {
    //        self.data
    //            .seek(SeekFrom::Start(entry * u64::from(self.entry_size)))?;
    //
    //        let mut entry_buffer = vec![0; self.entry_size as usize];
    //        self.data.read_exact(&mut entry_buffer)?;
    //
    //        let mft_entry = MftEntry::from_buffer(entry_buffer)?;
    //
    //        Ok(mft_entry.get_pathmap())
    //    }
}

#[cfg(test)]
mod tests {
    use crate::MftParser;
    use std::path::PathBuf;

    // entrypoint for clion profiler.
    #[test]
    fn test_process_90_mft_entries() {
        let sample = PathBuf::from(file!())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("samples")
            .join("MFT");

        let mut parser = MftParser::from_path(sample).unwrap();

        let _: Vec<_> = parser.iter_entries().take(90).collect();
    }
}
