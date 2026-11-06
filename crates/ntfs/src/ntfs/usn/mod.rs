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
    const MAP: &[(UsnReasonFlags, &str)] = &[
        (
            UsnReasonFlags::USN_REASON_DATA_OVERWRITE,
            "USN_REASON_DATA_OVERWRITE",
        ),
        (
            UsnReasonFlags::USN_REASON_DATA_EXTEND,
            "USN_REASON_DATA_EXTEND",
        ),
        (
            UsnReasonFlags::USN_REASON_DATA_TRUNCATION,
            "USN_REASON_DATA_TRUNCATION",
        ),
        (
            UsnReasonFlags::USN_REASON_NAMED_DATA_OVERWRITE,
            "USN_REASON_NAMED_DATA_OVERWRITE",
        ),
        (
            UsnReasonFlags::USN_REASON_NAMED_DATA_EXTEND,
            "USN_REASON_NAMED_DATA_EXTEND",
        ),
        (
            UsnReasonFlags::USN_REASON_NAMED_DATA_TRUNCATION,
            "USN_REASON_NAMED_DATA_TRUNCATION",
        ),
        (
            UsnReasonFlags::USN_REASON_FILE_CREATE,
            "USN_REASON_FILE_CREATE",
        ),
        (
            UsnReasonFlags::USN_REASON_FILE_DELETE,
            "USN_REASON_FILE_DELETE",
        ),
        (UsnReasonFlags::USN_REASON_EA_CHANGE, "USN_REASON_EA_CHANGE"),
        (
            UsnReasonFlags::USN_REASON_SECURITY_CHANGE,
            "USN_REASON_SECURITY_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_RENAME_OLD_NAME,
            "USN_REASON_RENAME_OLD_NAME",
        ),
        (
            UsnReasonFlags::USN_REASON_RENAME_NEW_NAME,
            "USN_REASON_RENAME_NEW_NAME",
        ),
        (
            UsnReasonFlags::USN_REASON_INDEXABLE_CHANGE,
            "USN_REASON_INDEXABLE_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_BASIC_INFO_CHANGE,
            "USN_REASON_BASIC_INFO_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_HARD_LINK_CHANGE,
            "USN_REASON_HARD_LINK_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_COMPRESSION_CHANGE,
            "USN_REASON_COMPRESSION_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_ENCRYPTION_CHANGE,
            "USN_REASON_ENCRYPTION_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_OBJECT_ID_CHANGE,
            "USN_REASON_OBJECT_IDENTIFIER_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_REPARSE_POINT_CHANGE,
            "USN_REASON_REPARSE_POINT_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_STREAM_CHANGE,
            "USN_REASON_STREAM_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_TRANSACTED_CHANGE,
            "USN_REASON_TRANSACTED_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_INTEGRITY_CHANGE,
            "USN_REASON_INTEGRITY_CHANGE",
        ),
        (
            UsnReasonFlags::USN_REASON_DESIRED_STORAGE_CLASS_CHANGE,
            "USN_REASON_DESIRED_STORAGE_CLASS_CHANGE",
        ),
        (UsnReasonFlags::USN_REASON_CLOSE, "USN_REASON_CLOSE"),
    ];

    MAP.iter().filter_map(move |(flag, name)| {
        if flags.contains(*flag) {
            Some(*name)
        } else {
            None
        }
    })
}

/// Returns the names of set `USN_SOURCE_*` flags, matching upstream spelling.
pub fn source_flag_names(flags: UsnSourceFlags) -> impl Iterator<Item = &'static str> {
    const MAP: &[(UsnSourceFlags, &str)] = &[
        (
            UsnSourceFlags::USN_SOURCE_DATA_MANAGEMENT,
            "USN_SOURCE_DATA_MANAGEMENT",
        ),
        (
            UsnSourceFlags::USN_SOURCE_AUXILIARY_DATA,
            "USN_SOURCE_AUXILIARY_DATA",
        ),
        (
            UsnSourceFlags::USN_SOURCE_REPLICATION_MANAGEMENT,
            "USN_SOURCE_REPLICATION_MANAGEMENT",
        ),
        (
            UsnSourceFlags::USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT,
            "USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT",
        ),
    ];
    MAP.iter().filter_map(move |(flag, name)| {
        if flags.contains(*flag) {
            Some(*name)
        } else {
            None
        }
    })
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
