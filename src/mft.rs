use seek_bufread::BufReader;
use enumerator::{PathEnumerator,PathMapping};
use rwinstructs::reference::{MftReference};
use errors::{MftError};
use entry::{MftEntry};
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem;

pub struct MftHandler {
    filehandle: BufReader<File>,
    path_enumerator: PathEnumerator,
    _entry_size: u32,
    _offset: u64,
    _size: u64
}
impl MftHandler{
    pub fn new(filename: &str) -> Result<MftHandler,MftError> {
        let mut mft_handler: MftHandler = unsafe {
            mem::zeroed()
        };

        let mut mft_fh = match File::open(filename) {
            Ok(usn_fh) => usn_fh,
            // Handle error here
            Err(error) => panic!("Error: {}",error)
        };

        // get file size
        mft_handler._size = match mft_fh.seek(SeekFrom::End(0)){
            Err(e) => panic!("Error: {}",e),
            Ok(size) => size
        };

        mft_handler.filehandle = BufReader::with_capacity(
            4096,
            mft_fh
        );

        mft_handler.set_entry_size(1024);

        Ok(mft_handler)
    }

    pub fn set_entry_size(&mut self, entry_size: u32){
        self._entry_size = entry_size
    }

    pub fn get_entry_count(&self)->u64 {
        self._size / self._entry_size as u64
    }

    pub fn entry(&mut self, entry: u64) -> Result<MftEntry,MftError> {
        self.filehandle.seek(
            SeekFrom::Start(entry * self._entry_size as u64)
        ).unwrap();

        let mut entry_buffer = vec![0; self._entry_size as usize];
        self.filehandle.read_exact(
            &mut entry_buffer
        )?;

        let mut mft_entry = self.entry_from_buffer(
            entry_buffer,
            entry
        )?;

        // We need to set the path if dir
        match mft_entry.get_pathmap() {
            Some(mapping) => {
                if mft_entry.is_dir() {
                    &self.path_enumerator.set_mapping(
                        mft_entry.header.entry_reference.clone().unwrap(),
                        mapping.clone()
                    );
                }
            },
            None    => {},
        }

        mft_entry.set_fullnames(
            self
        );

        Ok(mft_entry)
    }

    pub fn print_mapping(&self){
        self.path_enumerator.print_mapping();
    }

    pub fn entry_from_buffer(&mut self, buffer: Vec<u8>, entry: u64) -> Result<MftEntry,MftError> {
        let mft_entry = MftEntry::new(
            buffer,
            Some(entry)
        )?;

        Ok(mft_entry)
    }

    pub fn get_fullpath(&mut self, reference: MftReference) -> String {
        let mut path_stack = Vec::new();
        self.enumerate_path_stack(
            &mut path_stack,
            reference
        );
        path_stack.join("/")
    }

    fn enumerate_path_stack(&mut self, name_stack: &mut Vec<String>, reference: MftReference) {
        // 1407374883553285 (5-5)
        if reference.0 == 1407374883553285 {

        }
        else {
            match self.path_enumerator.get_mapping(reference){
                Some(mapping) => {
                    self.enumerate_path_stack(
                        name_stack,
                        mapping.parent.clone()
                    );
                    name_stack.push(
                        mapping.name.clone()
                    );
                },
                None => {
                    // Mapping not exists
                    // Get entry number for this reference that does not exist
                    let entry = reference.get_entry_number();
                    // Gat mapping for it
                    match self.get_mapping_from_entry(entry) {
                        Some(mapping) => {
                            self.path_enumerator.set_mapping(
                                reference,
                                mapping.clone()
                            );
                            self.enumerate_path_stack(
                                name_stack,
                                reference
                            );
                        },
                        None => {}
                    }
                }
            }
        }
    }

    fn get_mapping_from_entry(&mut self, entry: u64) -> Option<PathMapping>{
        self.filehandle.seek(
            SeekFrom::Start(entry * self._entry_size as u64)
        ).unwrap();

        let mut entry_buffer = vec![0; self._entry_size as usize];
        self.filehandle.read_exact(
            &mut entry_buffer
        ).unwrap();

        let mft_entry = self.entry_from_buffer(
            entry_buffer,
            entry
        );

        mft_entry.unwrap().get_pathmap()
    }
}
