use std::path::PathBuf;

pub fn mft_sample() -> PathBuf {
    PathBuf::from(file!())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("samples")
        .join("MFT")
}
