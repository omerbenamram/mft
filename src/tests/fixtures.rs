use std::path::PathBuf;

pub fn mft_sample_name(filename: &str) -> PathBuf {
    PathBuf::from(file!())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("samples")
        .join(filename)

}

pub fn mft_sample() -> PathBuf {
    mft_sample_name("MFT")
}
