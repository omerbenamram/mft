#![allow(dead_code)]
use std::path::PathBuf;

use std::sync::Once;

static LOGGER_INIT: Once = Once::new();

// Rust runs the tests concurrently, so unless we synchronize logging access
// it will crash when attempting to run `cargo test` with some logging facilities.
pub fn ensure_env_logger_initialized() {
    LOGGER_INIT.call_once(env_logger::init);
}

pub fn samples_dir() -> PathBuf {
    PathBuf::from(file!())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("samples")
        .canonicalize()
        .unwrap()
}

/// Test data that isn't published with the crate (unlike `samples/`).
pub fn testdata_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata")
}

/// The Windows 11 records under `testdata/win11` (CC-BY-4.0, see its `NOTICE.md`).
pub fn win11_sample(filename: &str) -> PathBuf {
    testdata_dir().join("win11").join(filename)
}

/// The single record `testdata/win11/entry_{entry_id}_{name}`.
pub fn win11_entry(entry_id: u64, name: &str) -> mft::MftEntry {
    let path = win11_sample(&format!("entry_{entry_id}_{name}"));
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // The record number stored at 0x2C catches a fixture cut from the wrong offset.
    let stored = u32::from_le_bytes(data[0x2C..0x30].try_into().unwrap());
    assert_eq!(u64::from(stored), entry_id, "{}", path.display());
    mft::MftEntry::from_buffer(data, entry_id).unwrap()
}

pub fn mft_sample() -> PathBuf {
    mft_sample_name("MFT")
}

pub fn mft_sample_name(filename: &str) -> PathBuf {
    samples_dir().join(filename)
}
