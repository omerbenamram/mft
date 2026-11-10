//! USN change journal (`$Extend\\$UsnJrnl:$J`) support.
//!
//! Records are parsed by [`mft::usn`]: `USN_RECORD_V2`, `V3` and `V4`. This module reads the
//! journal off a volume ([`UsnChangeJournal`]) and names flags the way `fsntfsinfo` does.

pub mod journal;

use mft::attribute::FileAttributeFlags;

pub use journal::{
    DEFAULT_USN_JOURNAL_BLOCK_SIZE, MIN_USN_RECORD_SIZE, UsnChangeJournal, UsnRawRecord,
};
pub use mft::usn::{UsnExtent, UsnReasonFlags, UsnRecord, UsnRecordDetails, UsnSourceFlags};

/// Returns the names of set `USN_REASON_*` flags, matching upstream spelling.
pub fn reason_flag_names(flags: UsnReasonFlags) -> impl Iterator<Item = &'static str> {
    flags.iter_names().map(|(name, _)| match name {
        // `fsntfsinfo` spells this one out.
        "USN_REASON_OBJECT_ID_CHANGE" => "USN_REASON_OBJECT_IDENTIFIER_CHANGE",
        name => name,
    })
}

/// Returns the names of set `USN_SOURCE_*` flags, matching upstream spelling.
pub fn source_flag_names(flags: UsnSourceFlags) -> impl Iterator<Item = &'static str> {
    flags.iter_names().map(|(name, _)| name)
}

/// Returns the names of set `FILE_ATTRIBUTE_*` flags, matching upstream spelling.
pub fn file_attribute_flag_names(flags: FileAttributeFlags) -> impl Iterator<Item = &'static str> {
    // Keep these aligned with `mft::attribute::FileAttributeFlags` / Windows constants.
    const MAP: &[(u32, &str)] = &[
        (0x0000_0001, "FILE_ATTRIBUTE_READ_ONLY"),
        (0x0000_0002, "FILE_ATTRIBUTE_HIDDEN"),
        (0x0000_0004, "FILE_ATTRIBUTE_SYSTEM"),
        (0x0000_0010, "FILE_ATTRIBUTE_DIRECTORY"),
        (0x0000_0020, "FILE_ATTRIBUTE_ARCHIVE"),
        (0x0000_0040, "FILE_ATTRIBUTE_DEVICE"),
        (0x0000_0080, "FILE_ATTRIBUTE_NORMAL"),
        (0x0000_0100, "FILE_ATTRIBUTE_TEMPORARY"),
        (0x0000_0200, "FILE_ATTRIBUTE_SPARSE_FILE"),
        (0x0000_0400, "FILE_ATTRIBUTE_REPARSE_POINT"),
        (0x0000_0800, "FILE_ATTRIBUTE_COMPRESSED"),
        (0x0000_1000, "FILE_ATTRIBUTE_OFFLINE"),
        (0x0000_2000, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"),
        (0x0000_4000, "FILE_ATTRIBUTE_ENCRYPTED"),
        (0x0001_0000, "FILE_ATTRIBUTE_VIRTUAL"),
    ];
    let bits = flags.bits();
    MAP.iter().filter_map(move |(mask, name)| {
        if (bits & mask) != 0 {
            Some(*name)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A `USN_RECORD_V2` named `test.txt`, `record_len` bytes long by its header.
    fn v2_record(record_len: u32) -> Vec<u8> {
        let name = utf16le("test.txt");
        let reason =
            (UsnReasonFlags::USN_REASON_FILE_CREATE | UsnReasonFlags::USN_REASON_CLOSE).bits();
        let source = UsnSourceFlags::USN_SOURCE_DATA_MANAGEMENT.bits();

        let mut buf = vec![0u8; 60 + name.len()];
        buf[0..4].copy_from_slice(&record_len.to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes()); // major
        buf[8..16].copy_from_slice(&0x0002_0000_0000_0040u64.to_le_bytes()); // file ref
        buf[16..24].copy_from_slice(&0x0005_0000_0000_0005u64.to_le_bytes()); // parent ref
        buf[24..32].copy_from_slice(&123u64.to_le_bytes()); // usn
        buf[32..40].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes()); // timestamp
        buf[40..44].copy_from_slice(&reason.to_le_bytes());
        buf[44..48].copy_from_slice(&source.to_le_bytes());
        buf[48..52].copy_from_slice(&0x99u32.to_le_bytes()); // security id
        buf[52..56].copy_from_slice(&0x20u32.to_le_bytes()); // file attrs
        buf[56..58].copy_from_slice(&(name.len() as u16).to_le_bytes());
        buf[58..60].copy_from_slice(&60u16.to_le_bytes());
        buf[60..].copy_from_slice(&name);
        buf
    }

    #[test]
    fn parse_usn_record_v2_roundtrip_minimal() {
        let buf = v2_record(76);
        let rec = UsnRecord::from_slice(&buf, 0).unwrap();
        assert_eq!(rec.major_version, 2);
        assert_eq!(rec.minor_version, 0);
        assert_eq!(rec.file_reference, mft::MftReference::new(0x40, 2));
        assert_eq!(rec.parent_reference, mft::MftReference::new(5, 5));
        assert_eq!(rec.usn, 123);
        assert_eq!(rec.timestamp().unwrap().to_string(), "2019-04-17T18:40:00Z");
        assert_eq!(
            reason_flag_names(rec.reason).collect::<Vec<_>>(),
            ["USN_REASON_FILE_CREATE", "USN_REASON_CLOSE"]
        );
        assert_eq!(
            source_flag_names(rec.source_info).collect::<Vec<_>>(),
            ["USN_SOURCE_DATA_MANAGEMENT"]
        );
        let UsnRecordDetails::Change {
            security_id,
            file_attributes,
            name,
            ..
        } = rec.details
        else {
            panic!("a v2 record is a change record");
        };
        assert_eq!(security_id, 0x99);
        assert_eq!(file_attributes, FileAttributeFlags::FILE_ATTRIBUTE_ARCHIVE);
        assert_eq!(name, "test.txt");
    }

    #[test]
    fn parse_usn_record_v2_rejects_length_mismatch() {
        // The header claims one byte more than the buffer holds.
        let buf = v2_record(77);
        assert!(matches!(
            UsnRecord::from_slice(&buf, 0),
            Err(mft::err::Error::InvalidUsnRecord { offset: 0, .. })
        ));
    }

    #[test]
    fn flag_names_keep_the_upstream_spelling() {
        let reason = UsnReasonFlags::USN_REASON_OBJECT_ID_CHANGE
            | UsnReasonFlags::USN_REASON_EA_CHANGE
            | UsnReasonFlags::from_bits_retain(0x0000_0008);
        assert_eq!(
            reason_flag_names(reason).collect::<Vec<_>>(),
            [
                "USN_REASON_EA_CHANGE",
                "USN_REASON_OBJECT_IDENTIFIER_CHANGE"
            ]
        );
    }
}
