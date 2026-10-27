mod fixtures;

use fixtures::*;

use assert_cmd::cargo::cargo_bin_cmd;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use tempfile::tempdir;

#[test]
fn it_respects_directory_output() {
    let d = tempdir().unwrap();
    let f = d.as_ref().join("test.out");

    let sample = mft_sample();

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg("-f").arg(f.as_os_str()).arg(sample.as_os_str());

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
    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg("-f").arg(d.path()).arg(sample.as_os_str());

    cmd.assert().failure().code(1);
}

#[test]
fn test_non_mft_file_is_error() {
    let d = tempdir().unwrap();

    let f = d.as_ref().join("test.out");

    let mut file = File::create(&f).unwrap();
    file.write_all(b"I'm a file!").unwrap();

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg(f.as_os_str());

    cmd.assert().failure().code(1);
}

#[test]
fn test_it_exports_resident_streams() {
    let d = tempdir().unwrap();

    let sample = mft_sample();
    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg("-e").arg(d.path()).arg(sample.as_os_str());

    cmd.assert().success();

    // 2142 resident streams, 92 of which are empty and are not exported.
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 2050);
    for f in fs::read_dir(d.path()).unwrap() {
        assert!(f.unwrap().metadata().unwrap().len() > 0);
    }
}

#[test]
fn test_json_output_includes_full_path() {
    for format in ["json", "jsonl"] {
        let mut cmd = cargo_bin_cmd!("mft_dump");
        cmd.arg("-o")
            .arg(format)
            .arg("-r")
            .arg("0,8671")
            .arg(mft_sample());
        let output = cmd.output().unwrap();
        assert!(output.status.success());

        let stdout = String::from_utf8(output.stdout).unwrap();
        let paths: Vec<String> = serde_json::Deserializer::from_str(&stdout)
            .into_iter::<serde_json::Value>()
            .map(|entry| {
                entry.unwrap()["full_path"]
                    .as_str()
                    .unwrap()
                    .replace('\\', "/")
            })
            .collect();

        assert_eq!(
            paths,
            [
                "$MFT",
                "Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Thumbs.db"
            ],
            "unexpected paths for -o {format}"
        );
    }
}
