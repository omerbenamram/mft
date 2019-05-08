use std::io::{self, Read, Seek, SeekFrom};

pub mod err;
pub mod attr_x10;
pub mod attr_x30;
pub mod attribute;
pub mod entry;
pub mod enumerator;
pub mod mft;

pub(crate) mod utils;

pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek> ReadSeek for T {}
