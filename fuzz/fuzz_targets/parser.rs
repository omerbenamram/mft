//! Treats the input as a whole $MFT: reads every record and builds its CSV row, which resolves
//! the full path by following parent references between records.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mft::MftParser;
use mft::csv::FlatMftEntryWithName;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let Ok(mut parser) = MftParser::from_read_seek(Cursor::new(data), Some(data.len() as u64))
    else {
        return;
    };

    for i in 0..parser.get_entry_count() {
        if let Ok(entry) = parser.get_entry(i) {
            let _ = FlatMftEntryWithName::from_entry(&entry, &mut parser);
        }
    }
});
