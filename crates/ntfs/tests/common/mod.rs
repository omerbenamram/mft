#![allow(dead_code)]

use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn ntfs_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/ntfs")
}

pub fn ntfs_fixture_path(name: &str) -> PathBuf {
    ntfs_fixture_root().join(name)
}

pub fn undelete7_fixture_path(name: &str) -> PathBuf {
    ntfs_fixture_root().join("7-undel-ntfs").join(name)
}

fn is_git_lfs_pointer(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };

    let mut buf = [0u8; 200];
    let Ok(n) = f.read(&mut buf) else {
        return false;
    };

    let Ok(s) = std::str::from_utf8(&buf[..n]) else {
        return false;
    };

    s.starts_with("version https://git-lfs.github.com/spec/v1")
}

fn fixture_missing_behavior(msg: &str) -> bool {
    if env::var_os("NTFS_TESTDATA_REQUIRED").is_some() {
        panic!("{msg}");
    }

    eprintln!("{msg}");
    false
}

/// Returns `true` iff `path` exists and is not a Git LFS pointer file.
///
/// If `NTFS_TESTDATA_REQUIRED=1` is set, missing/placeholder fixtures will **panic** (useful for CI).
/// Otherwise, the caller should `return` early from the test to skip it.
pub fn ensure_fixture(path: &Path) -> bool {
    if !path.exists() {
        return fixture_missing_behavior(&format!(
            "skipping: missing test fixture `{}` (did you forget to fetch testdata?)",
            path.display()
        ));
    }

    if is_git_lfs_pointer(path) {
        return fixture_missing_behavior(&format!(
            "skipping: `{}` looks like a Git LFS pointer file; run `git lfs install && git lfs pull`",
            path.display()
        ));
    }

    true
}


