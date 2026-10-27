use mft::MftEntry;
use mft::attribute::MftAttributeType;
use mft::attribute::xe0::EaValue;

/// Record 87354 (`Windows/System32/vm3dum64.dll`) of the 2019 Narcos scenario `$MFT` (Digital
/// Corpora, CC0). Its `$EA` names the driver's security catalog and holds a kernel cache entry.
fn entry() -> MftEntry {
    MftEntry::from_buffer(
        include_bytes!("../samples/entry_87354_extended_attributes").to_vec(),
        87354,
    )
    .unwrap()
}

#[test]
fn test_parses_extended_attributes() {
    let entry = entry();

    let info = entry
        .iter_attributes_matching(Some(vec![MftAttributeType::EaInformation]))
        .next()
        .unwrap()
        .unwrap();
    let info = info.data.as_ea_information().unwrap();

    let ea = entry
        .iter_attributes_matching(Some(vec![MftAttributeType::EA]))
        .next()
        .unwrap()
        .unwrap();
    let value_size = ea.header.value_size();
    let ea = ea.data.as_ea().unwrap();

    assert_eq!(u64::from(info.unpacked_ea_size), value_size);
    assert_eq!(info.need_ea_count, 0);

    let names: Vec<_> = ea.entries.iter().map(|e| e.name.as_ref()).collect();
    assert_eq!(names, ["$CI.CATALOGHINT", "$KERNEL.PURGE.ESBCACHE"]);
    assert_eq!(
        ea.entries[0].value,
        EaValue::CatalogHint {
            catalog: "oem10.cat".into()
        }
    );
    assert!(matches!(ea.entries[1].value, EaValue::Other { data } if data.len() == 108));
}

#[test]
fn test_extended_attributes_json() {
    let entry = entry();
    let json = serde_json::to_value(&entry).unwrap();
    let ea = json["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["header"]["type_code"] == "EA")
        .unwrap();

    assert_eq!(
        ea["data"]["entries"][0],
        serde_json::json!({
            "flags": "(empty)",
            "name": "$CI.CATALOGHINT",
            "value": { "type": "CatalogHint", "catalog": "oem10.cat" }
        })
    );
    assert_eq!(ea["data"]["entries"][1]["value"]["type"], "Other");
}
