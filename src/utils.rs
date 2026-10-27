use jiff::Timestamp;
use jiff::fmt::StdFmtWrite;
use jiff::fmt::temporal::DateTimePrinter;
use serde::Serializer;
use std::fmt;

/// NTFS timestamps have 100ns resolution, so always print all 7 fractional digits.
const TIMESTAMP_PRINTER: DateTimePrinter = DateTimePrinter::new().precision(Some(7));

struct Rfc3339<'a>(&'a Timestamp);

impl fmt::Display for Rfc3339<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        TIMESTAMP_PRINTER
            .print_timestamp(self.0, StdFmtWrite(f))
            .map_err(|_| fmt::Error)
    }
}

/// Serializes a timestamp as RFC 3339 in UTC with 100ns precision, e.g.
/// `2007-06-30T12:50:52.2523952Z`.
pub fn serialize_timestamp<S>(ts: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_str(&Rfc3339(ts))
}

pub fn serialize_option_timestamp<S>(
    ts: &Option<Timestamp>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match ts {
        Some(ts) => serialize_timestamp(ts, serializer),
        None => serializer.serialize_none(),
    }
}

/// Converts a Windows FILETIME (100ns intervals since 1601-01-01 UTC) to a timestamp, keeping the
/// full 100ns resolution.
///
/// Returns an error instead of panicking when the resulting timestamp is outside `jiff::Timestamp`'s
/// supported range (roughly years -9999 to 9999).
pub fn windows_filetime_to_timestamp(filetime_100ns: u64) -> crate::err::Result<Timestamp> {
    const WINDOWS_TO_UNIX_SECS: i64 = 11_644_473_600;

    let seconds = (filetime_100ns / 10_000_000) as i64 - WINDOWS_TO_UNIX_SECS;
    let subsec_nanos = ((filetime_100ns % 10_000_000) * 100) as i32;

    Timestamp::new(seconds, subsec_nanos)
        .map_err(|_| crate::err::Error::FiletimeTimestampOutOfRange { filetime_100ns })
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789ABCDEF";

    // Use `String` directly to avoid a second pass for UTF-8 validation.
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0x0F) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_filetime_to_timestamp_out_of_range_is_error() {
        let err = windows_filetime_to_timestamp(u64::MAX).unwrap_err();
        match err {
            crate::err::Error::FiletimeTimestampOutOfRange { filetime_100ns } => {
                assert_eq!(filetime_100ns, u64::MAX);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn timestamps_keep_100ns_precision() {
        let print = |filetime| {
            let ts = windows_filetime_to_timestamp(filetime).unwrap();
            serialize_timestamp(&ts, serde_json::value::Serializer)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            print(128_276_814_522_523_952),
            "2007-06-30T12:50:52.2523952Z"
        );
        assert_eq!(print(0), "1601-01-01T00:00:00.0000000Z");
    }

    #[test]
    fn test_to_hex_string_uppercase_no_separators() {
        assert_eq!(to_hex_string(&[]), "");
        assert_eq!(to_hex_string(&[0x00]), "00");
        assert_eq!(to_hex_string(&[0x0F, 0x10, 0xAB, 0xFF]), "0F10ABFF");
        assert_eq!(to_hex_string(b"Hi"), "4869");
    }
}
