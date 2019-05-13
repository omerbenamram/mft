#[macro_use]
extern crate num_derive;

pub use attribute::x10::StandardInfoAttr;
pub use attribute::x30::FileNameAttr;
pub use attribute::Attribute;

pub use entry::{EntryHeader, MftEntry};
pub use mft::MftParser;

use std::io::{self, Read, Seek, SeekFrom};

pub mod attribute;
pub mod entry;
pub mod enumerator;
pub mod err;
pub mod mft;

pub(crate) mod macros;
pub(crate) mod utils;

pub trait ReadSeek: Read + Seek {
    fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<T: Read + Seek> ReadSeek for T {}
