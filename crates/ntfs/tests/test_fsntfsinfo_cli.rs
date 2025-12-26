use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;
mod common;

#[test]
fn ntfsinfo_volume_subcommand_works() {
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let mut cmd = cargo_bin_cmd!("ntfs-info");
    cmd.arg(&img_path).arg("volume");
    cmd.assert()
        .success()
        .stdout(contains("bytes_per_sector: 512"))
        .stdout(contains("cluster_size: 1024"));
}

#[test]
fn ntfsinfo_c_style_e_single_entry_works() {
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let mut cmd = cargo_bin_cmd!("ntfs-info");
    cmd.arg("-E").arg("32").arg(&img_path);
    cmd.assert()
        .success()
        .stdout(contains("record_number: 32"))
        .stdout(contains("best_name: mult1.dat"));
}

#[test]
fn ntfsinfo_c_style_hierarchy_prints_and_does_not_panic() {
    let img_path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let mut cmd = cargo_bin_cmd!("ntfs-info");
    cmd.arg("-H").arg(&img_path);
    cmd.assert()
        .success()
        .stdout(contains("File system hierarchy:"))
        .stdout(contains("\\$MFT"));
}

#[test]
fn ntfsinfo_c_style_bodyfile_writes_file() {
    let img_path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let out_path = tmp.path().join("bodyfile.txt");

    let mut cmd = cargo_bin_cmd!("ntfs-info");
    cmd.arg("-B").arg(&out_path).arg(&img_path);
    cmd.assert().success();

    let body = std::fs::read_to_string(out_path).unwrap();
    assert!(body.contains("|\\|"), "expected root path in bodyfile");
}

#[test]
fn ntfsinfo_c_style_f_strict_fails_for_deleted_paths() {
    // On the undelete fixture, these files are deleted and typically not present in directory indexes,
    // so strict -F should fail.
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let mut cmd = cargo_bin_cmd!("ntfs-info");
    cmd.arg("-F").arg("\\mult1.dat").arg(&img_path);
    cmd.assert().failure().stderr(contains("Not found"));
}

#[test]
fn ntfsinfo_c_style_f_strict_is_case_insensitive_for_ascii_names() {
    // `$MFT` exists on all NTFS volumes. Root is typically case-insensitive, so `$mft` should
    // resolve to the same entry.
    let img_path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let mut cmd = cargo_bin_cmd!("ntfs-info");
    cmd.arg("-F").arg("\\$mft").arg(&img_path);
    cmd.assert().success().stdout(contains("mft_entry: 0"));
}

#[test]
fn ntfsinfo_usn_n_a_is_success() {
    // Most small fixtures do not contain a USN journal; tool should report N/A and exit 0.
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let mut cmd = cargo_bin_cmd!("ntfs-info");
    cmd.arg("-U").arg(&img_path);
    cmd.assert()
        .success()
        .stdout(contains("USN change journal: N/A"));
}
