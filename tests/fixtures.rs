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

/// The Windows 11 records under `testdata/win11` (see its `NOTICE.md`). They are CC-BY-4.0, so they
/// stay out of `samples/`, which is published with the crate.
pub fn win11_sample(filename: &str) -> PathBuf {
    samples_dir()
        .parent()
        .unwrap()
        .join("testdata")
        .join("win11")
        .join(filename)
}

pub fn mft_sample() -> PathBuf {
    mft_sample_name("MFT")
}

pub fn mft_sample_name(filename: &str) -> PathBuf {
    samples_dir().join(filename)
}
