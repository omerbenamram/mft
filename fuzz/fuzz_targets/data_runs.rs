//! Decodes a non-resident attribute's mapping pairs array.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mft::attribute::data_run::decode_data_runs;

fuzz_target!(|data: &[u8]| {
    let _ = decode_data_runs(data);
});
