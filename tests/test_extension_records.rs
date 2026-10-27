mod fixtures;

use fixtures::*;
use mft::attribute::x30::FileNamespace;
use mft::entry::{MftEntry, find_best_name_attribute_in};
use mft::mft::MftParser;

fn record_numbers(entries: &[MftEntry]) -> Vec<u64> {
    entries.iter().map(|e| e.header.record_number).collect()
}

#[test]
fn test_resident_attribute_list_extension_records() {
    let mut parser = MftParser::from_path(mft_sample_name("ntfs1-gen2.MFT")).unwrap();
    let entry = parser.get_entry(47).unwrap();

    // `$DATA` is split over six extension records, one per run of VCNs.
    let extensions = parser.get_extension_entries(&entry);
    assert_eq!(record_numbers(&extensions), [52, 55, 59, 67, 73, 81]);
}

#[test]
fn test_non_resident_attribute_list_extension_records() {
    let mut parser = MftParser::from_path(mft_sample_name("ntfs1-gen2.MFT")).unwrap();
    let entry = parser.get_entry(48).unwrap();
    assert!(entry.has_attribute_list());

    // The list's clusters aren't in the MFT, so the extensions are found by their base reference.
    let extensions = parser.get_extension_entries(&entry);
    assert!(!extensions.is_empty());
    assert!(
        extensions
            .iter()
            .all(|e| e.header.base_reference.entry == 48)
    );
}

#[test]
fn test_entry_without_attribute_list_has_no_extension_records() {
    let mut parser = MftParser::from_path(mft_sample()).unwrap();
    let entry = parser.get_entry(0).unwrap();
    assert!(!entry.has_attribute_list());
    assert!(parser.get_extension_entries(&entry).is_empty());

    // Record 3498 (`system.LOG`) keeps its `$DATA` in record 4711.
    let entry = parser.get_entry(3498).unwrap();
    assert_eq!(
        record_numbers(&parser.get_extension_entries(&entry)),
        [4711]
    );
}

/// Records 6645 and 62525 of the CFReDS 2015 Data Leakage Case `$MFT` (NIST, public domain).
/// The base record only has room for the 8.3 name of a WinSxS directory, and the long name moved
/// to the extension record (#148).
#[test]
fn test_long_name_in_extension_record_is_preferred_over_dos_name() {
    let base = MftEntry::from_buffer(
        include_bytes!("../samples/entry_6645_dos_name_base").to_vec(),
        6645,
    )
    .unwrap();
    let extension = MftEntry::from_buffer(
        include_bytes!("../samples/entry_62525_dos_name_extension").to_vec(),
        62525,
    )
    .unwrap();

    let short_name = base.find_best_name_attribute().unwrap();
    assert_eq!(short_name.namespace, FileNamespace::DOS);
    assert_eq!(short_name.name.to_utf8_string(), "AMC671~1.163");

    let best = find_best_name_attribute_in(&base, std::slice::from_ref(&extension)).unwrap();
    assert_eq!(best.namespace, FileNamespace::Win32);
    assert_eq!(
        best.name.to_utf8_string(),
        "amd64_microsoft-windows-minkernelapinamespace_31bf3856ad364e35_6.1.7600.16385_none_66a6e19d9580f9e3"
    );

    // Without extension records, the base record's name is all there is.
    assert_eq!(find_best_name_attribute_in(&base, &[]), Some(short_name));
}
