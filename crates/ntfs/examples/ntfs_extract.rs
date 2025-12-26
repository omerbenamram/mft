//! Dev helper: extract an NTFS file's default stream to a local path.
//!
//! Usage:
//! - `cargo run -p ntfs --example ntfs_extract -- <image.E01> <ntfs-path> <out-path>`
//!
//! Example:
//! - `cargo run -p ntfs --example ntfs_extract -- testdata/ntfs/ntfs1-gen2.E01 \\Raw\\NIST_logo.jpg /tmp/NIST_logo.jpg`

#![forbid(unsafe_code)]

use ntfs::image::EwfImage;
use ntfs::ntfs::{FileSystem, Volume};
use std::path::PathBuf;
use std::sync::Arc;

fn main() {
    let img_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("missing <image.E01>");
    let ntfs_path = std::env::args().nth(2).expect("missing <ntfs-path>");
    let out_path = std::env::args_os()
        .nth(3)
        .map(PathBuf::from)
        .expect("missing <out-path>");

    let img = EwfImage::open(img_path).expect("failed to open EWF image");
    let volume = Volume::open(Arc::new(img), 0).expect("failed to open NTFS volume");
    let fs = FileSystem::new(volume);

    let entry_id = fs.resolve_path(&ntfs_path).expect("failed to resolve path");
    let bytes = fs
        .read_file_default_stream(entry_id)
        .expect("failed to read default stream");

    std::fs::write(&out_path, bytes).expect("failed to write output");
    eprintln!("wrote {}", out_path.display());
}
