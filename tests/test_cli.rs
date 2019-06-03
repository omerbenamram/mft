mod fixtures;

use fixtures::*;

use assert_cmd::prelude::*;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn it_respects_directory_output() {
    let d = tempdir().unwrap();
    let f = d.as_ref().join("test.out");

    let sample = mft_sample();

    let mut cmd = Command::cargo_bin("mft_dump").expect("failed to find binary");
    cmd.args(&["-f", &f.to_string_lossy(), sample.to_str().unwrap()]);

    assert!(
        cmd.output().unwrap().stdout.is_empty(),
        "Expected output to be printed to file, but was printed to stdout"
    );

    let mut expected = vec![];

    File::open(&f).unwrap().read_to_end(&mut expected).unwrap();
    assert!(
        !expected.is_empty(),
        "Expected output to be printed to file"
    )
}

#[test]
fn test_it_refuses_to_overwrite_directory() {
    let d = tempdir().unwrap();

    let sample = mft_sample();
    let mut cmd = Command::cargo_bin("mft_dump").expect("failed to find binary");
    cmd.args(&["-f", &d.path().to_string_lossy(), sample.to_str().unwrap()]);

    cmd.assert().failure().code(1);
}

#[test]
fn test_it_exports_resident_streams() {
    let d = tempdir().unwrap();

    let sample = mft_sample();
    let mut cmd = Command::cargo_bin("mft_dump").expect("failed to find binary");
    cmd.args(&[
        "-e",
        &d.path().to_string_lossy().to_string(),
        &sample.to_string_lossy().to_string(),
    ]);

    cmd.assert().success();

    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 2142)
}
