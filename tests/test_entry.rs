use mft::entry::MftEntry;
use serde_json;

#[test]
fn test_entry_invalid_fixup_value() {
    let mft_entry_buffer = include_bytes!("../samples/entry_102130_fixup_issue");

    let entry = MftEntry::from_buffer(
        mft_entry_buffer.to_vec(), 
        102130
    ).expect("Failed to parse entry");

    assert_eq!(entry.valid_fixup, Some(false));

    let mft_json_value = serde_json::to_value(&entry).expect("Error serializing MftEntry");
    assert_eq!(mft_json_value["valid_fixup"], serde_json::value::Value::from(false));
}