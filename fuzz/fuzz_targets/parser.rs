//! Treats the input as a whole $MFT: iterates records and resolves full paths, which follows
//! parent references between records.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mft::MftParser;

/// Caps the work per input so tiny record sizes don't turn one input into millions of records.
const MAX_ENTRIES: u64 = 256;

fuzz_target!(|data: &[u8]| {
    let Ok(mut parser) = MftParser::from_buffer(data.to_vec()) else {
        return;
    };

    let entries: Vec<_> = parser
        .iter_entries()
        .take(MAX_ENTRIES as usize)
        .filter_map(Result::ok)
        .collect();

    for entry in &entries {
        let _ = parser.get_full_path_for_entry(entry);
    }
});
