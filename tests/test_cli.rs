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
fn test_bodyfile_output() {
    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg("-o")
        .arg("bodyfile")
        .arg("-r")
        .arg("0,8671,11600")
        .arg(mft_sample());
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let thumbs =
        "/Documents and Settings/All Users/Documents/My Pictures/Sample Pictures/Thumbs.db";
    let gif = "/Documents and Settings/Donald Blake/Local Settings/Temporary Internet Files/Content.IE5/B70NJDCZ/online[1].gif";
    // Same layout as `fls -m /`: a `$FILE_NAME` line, then one line per `$DATA` stream.
    let expected = [
        "0|/$MFT ($FILE_NAME)|0-48-3|r/rr-xr-xr-x|0|0|74|1183207852|1183207852|1183207852|1183207852".to_string(),
        "0|/$MFT|0-128-1|r/rr-xr-xr-x|0|0|13402112|1183207852|1183207852|1183207852|1183207852".to_string(),
        format!("0|{thumbs} ($FILE_NAME)|8671-48-2|r/rr-xr-xr-x|0|0|84|1183244062|1183244062|1183244062|1183244062"),
        format!("0|{thumbs}|8671-128-3|r/rr-xr-xr-x|0|0|7680|1183244062|1183244062|1183244062|1183244062"),
        format!("0|{thumbs}:encryptable|8671-128-4|r/rr-xr-xr-x|0|0|0|1183244062|1183244062|1183244062|1183244062"),
        format!("0|{gif} ($FILE_NAME) (deleted)|11600-48-2|-/rrwxrwxrwx|0|0|92|1232382084|1232382084|1232382084|1232382084"),
        format!("0|{gif} (deleted)|11600-128-1|-/rrwxrwxrwx|0|0|84|1232382084|1232382084|1232382084|1232382084"),
    ];

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().collect::<Vec<_>>(), expected);
}

#[test]
fn test_bodyfile_lines_have_eleven_fields() {
    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg("-o").arg("bodyfile").arg(mft_sample());
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.lines().count() > 10_000);
    for line in stdout.lines() {
        assert_eq!(
            line.split('|').count(),
            11,
            "malformed bodyfile line: {line}"
        );
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
