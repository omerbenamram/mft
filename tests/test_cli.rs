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
            .map(|entry| entry.unwrap()["full_path"].as_str().unwrap().to_owned())
            .collect();

        assert_eq!(
            paths,
            [
                "$MFT",
                r"Documents and Settings\All Users\Documents\My Pictures\Sample Pictures\Thumbs.db"
            ],
            "unexpected paths for -o {format}"
        );
    }
}

#[test]
fn test_bodyfile_follows_extension_records() {
    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg("-o")
        .arg("bodyfile")
        .arg("-r")
        .arg("47,48")
        .arg(mft_sample_name("ntfs1-gen2.MFT"));
    let output = cmd.output().unwrap();
    assert!(output.status.success());

    // `$DATA` of both files lives in extension records (48's `$ATTRIBUTE_LIST` is non-resident).
    // Sizes match `fls -m` on `testdata/ntfs/ntfs1-gen2.E01`. `fls` renumbers the attribute ids
    // of merged attributes; these are the ids on disk.
    let stdout = String::from_utf8(output.stdout).unwrap();
    let data_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("-128-"))
        .map(|l| l.rsplitn(5, '|').last().unwrap())
        .collect();
    assert_eq!(
        data_lines,
        [
            "0|/RAW/logfile1.txt|47-128-0|r/rrwxrwxrwx|0|0|21888890",
            "0|/Compressed/logfile1.txt|48-128-0|r/rrwxrwxrwx|0|0|21888890",
        ]
    );
}

#[test]
fn it_dumps_a_usn_journal() {
    let sample = testdata_dir().join("usn").join("narcos-head.J");

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg("-o").arg("jsonl").arg(sample.as_os_str());
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");

    let records: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 248);
    for record in &records {
        // The zeros in front of the sample stand in for the first 67108864 - 8192 bytes of `$J`.
        assert_eq!(
            record["usn"].as_i64().unwrap() - 67_108_864 + 8192,
            record["offset"].as_i64().unwrap()
        );
    }
    insta::assert_snapshot!(serde_json::to_string_pretty(&records[0]).unwrap());
}

#[test]
fn it_dumps_a_usn_journal_as_csv() {
    let sample = testdata_dir().join("usn").join("narcos-head.J");

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.args(["-o", "csv", "--input-type", "usn"])
        .arg(sample.as_os_str());
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let csv = String::from_utf8(output.stdout).unwrap();
    insta::assert_snapshot!(csv.lines().take(3).collect::<Vec<_>>().join("\n"));
}

#[test]
fn it_dumps_i30_entries_with_slack() {
    let sample = testdata_dir().join("i30").join("narcos-windows.I30");

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.args(["-o", "csv"]).arg(sample.as_os_str());
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");

    let csv = String::from_utf8(output.stdout).unwrap();
    let mut reader = csv::Reader::from_reader(csv.as_bytes());
    let headers = reader.headers().unwrap().clone();
    let column = |name: &str| headers.iter().position(|h| h == name).unwrap();
    let (from_slack, name) = (column("FromSlack"), column("Name"));
    let rows: Vec<csv::StringRecord> = reader.records().map(Result::unwrap).collect();
    let (slack, live): (Vec<_>, Vec<_>) = rows.iter().partition(|row| &row[from_slack] == "true");
    assert_eq!(live.len(), 99);
    // The deleted names: in slack, but no longer in the index.
    let live_names: std::collections::BTreeSet<_> = live.iter().map(|row| &row[name]).collect();
    let deleted: std::collections::BTreeSet<_> = slack
        .iter()
        .map(|row| &row[name])
        .filter(|name| !live_names.contains(name))
        .collect();
    insta::assert_debug_snapshot!(deleted);
}

#[test]
fn it_dumps_a_boot_sector() {
    let sample = testdata_dir().join("boot").join("narcos.Boot");

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.args(["-o", "jsonl"]).arg(sample.as_os_str());
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    insta::assert_snapshot!(String::from_utf8(output.stdout).unwrap());
}

#[test]
fn it_dumps_security_descriptors() {
    let sample = testdata_dir().join("secure").join("narcos-head.SDS");

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.args(["-o", "csv"]).arg(sample.as_os_str());
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    insta::assert_snapshot!(String::from_utf8(output.stdout).unwrap());
}

#[test]
fn it_detects_security_descriptors_whose_first_entry_is_damaged() {
    // The sample is the start of the first block: fill the block up and add its copy.
    let mut sds = fs::read(testdata_dir().join("secure").join("narcos-head.SDS")).unwrap();
    sds.resize(0x40000, 0);
    sds.extend_from_within(..);
    sds[..64].fill(0);
    let d = tempdir().unwrap();
    let path = d.as_ref().join("$SDS");
    fs::write(&path, &sds).unwrap();

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.args(["-o", "csv"]).arg(path.as_os_str());
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let csv = String::from_utf8(output.stdout).unwrap();
    let rows: Vec<&str> = csv.lines().collect();
    assert!(rows.len() > 16, "{csv}");
    // The first entry is read from the copy, the others where they are.
    assert!(rows[1].starts_with("0,256,0x32fec6cb,true,true,"), "{csv}");
    assert!(
        rows[2].starts_with("128,257,0x3414c8f7,true,false,"),
        "{csv}"
    );
}

#[test]
fn it_rejects_mft_for_inputs_without_paths() {
    let sample = testdata_dir().join("boot").join("narcos.Boot");

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.arg("--mft").arg(mft_sample()).arg(sample.as_os_str());
    let output = cmd.output().unwrap();
    assert!(!output.status.success(), "{output:?}");
}

#[test]
fn it_dumps_log_records() {
    let sample = testdata_dir()
        .join("logfile")
        .join("narcos-sysreserved-head.LogFile");

    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.args(["-o", "csv"]).arg(sample.as_os_str());
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");

    let csv = String::from_utf8(output.stdout).unwrap();
    let mut lines = csv.lines();
    let header = lines.next().unwrap();
    // The records that add or remove a directory entry, with the names they log.
    let named: Vec<&str> = lines.filter(|line| !line.ends_with(',')).collect();
    insta::assert_snapshot!(format!("{header}\n{}", named.join("\n")));
}

#[test]
fn it_detects_a_log_whose_first_restart_page_is_damaged() {
    let sample = testdata_dir()
        .join("logfile")
        .join("narcos-sysreserved-head.LogFile");
    let dump = |path: &std::path::Path| {
        let mut cmd = cargo_bin_cmd!("mft_dump");
        cmd.args(["-o", "csv"]).arg(path.as_os_str());
        let output = cmd.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    let intact = dump(&sample);
    assert!(intact.starts_with("Offset,Lsn,"));

    let d = tempdir().unwrap();
    let path = d.as_ref().join("$LogFile");
    let log = fs::read(&sample).unwrap();
    // Zeros, and bytes that are no page at all. The second restart page is a copy of the first.
    for fill in [0u8, 0xA5] {
        let mut damaged = log.clone();
        damaged[..0x1000].fill(fill);
        fs::write(&path, &damaged).unwrap();
        assert!(dump(&path) == intact, "filled with {fill:#x}");
    }

    // With both restart pages gone, the record pages still say what the file is.
    let mut damaged = log.clone();
    damaged[..0x2000].fill(0);
    fs::write(&path, &damaged).unwrap();
    let mut cmd = cargo_bin_cmd!("mft_dump");
    cmd.args(["-o", "csv"]).arg(path.as_os_str());
    let output = cmd.output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("$LogFile"), "{stderr}");
}
