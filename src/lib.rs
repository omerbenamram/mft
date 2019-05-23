#[macro_use]
extern crate num_derive;

pub use attribute::x10::StandardInfoAttr;
pub use attribute::x30::FileNameAttr;
pub use attribute::MftAttribute;

pub use crate::mft::MftParser;
pub use entry::{EntryHeader, MftEntry};

use std::io::{self, Read, Seek, SeekFrom};

pub mod attribute;
pub mod csv;
pub mod entry;
pub mod err;
pub mod mft;

pub(crate) mod macros;
pub(crate) mod utils;

#[cfg(test)]
pub(crate) mod tests;

pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek> ReadSeek for T {}
