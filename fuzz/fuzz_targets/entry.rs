//! Parses one MFT record and walks everything a consumer would touch.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mft::MftEntry;

fuzz_target!(|data: &[u8]| {
    for entry in [
        MftEntry::from_buffer(data.to_vec(), 0),
        MftEntry::from_buffer_skip_fixup(data.to_vec(), 0),
    ]
    .into_iter()
    .flatten()
    {
        let _ = entry.find_best_name_attribute();
        // Serializing walks `iter_attributes` and every attribute's content.
        let _ = serde_json::to_writer(std::io::sink(), &entry);
    }
});
