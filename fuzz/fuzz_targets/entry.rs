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
        for attribute in entry.iter_attributes() {
            let _ = attribute;
        }
        let _ = entry.find_best_name_attribute();
        let _ = serde_json::to_vec(&entry);
    }
});
