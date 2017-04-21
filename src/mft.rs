use seek_bufread::BufReader;
use errors::{MftError};
use entry::{MftEntry};
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem;

pub struct MftHandler {
    filehandle: BufReader<File>,
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
        self.filehandle.read_exact(&mut entry_buffer)?;

        let mft_entry = self.entry_from_buffer(
            entry_buffer,
            entry
        )?;

        Ok(mft_entry)
    }

    pub fn entry_from_buffer(&mut self, mut buffer: Vec<u8>, entry: u64) -> Result<MftEntry,MftError> {
        let mft_entry = MftEntry::new(
            buffer,
            Some(entry)
        )?;

        Ok(mft_entry)
    }
}
