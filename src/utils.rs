use jiff::Timestamp;
use jiff::fmt::StdFmtWrite;
use jiff::fmt::temporal::DateTimePrinter;
use serde::Serializer;
use std::fmt;

const TIMESTAMP_PRINTER_P0: DateTimePrinter = DateTimePrinter::new().precision(Some(0));
const TIMESTAMP_PRINTER_P3: DateTimePrinter = DateTimePrinter::new().precision(Some(3));
const TIMESTAMP_PRINTER_P6: DateTimePrinter = DateTimePrinter::new().precision(Some(6));
const TIMESTAMP_PRINTER_P9: DateTimePrinter = DateTimePrinter::new().precision(Some(9));

struct ChronoRfc3339Compat<'a>(&'a Timestamp);

impl fmt::Display for ChronoRfc3339Compat<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Match chrono's `SecondsFormat::AutoSi` behavior.
        let nanos = self.0.subsec_nanosecond();
        let printer = if nanos == 0 {
            &TIMESTAMP_PRINTER_P0
        } else if nanos % 1_000_000 == 0 {
            &TIMESTAMP_PRINTER_P3
        } else if nanos % 1_000 == 0 {
            &TIMESTAMP_PRINTER_P6
        } else {
            &TIMESTAMP_PRINTER_P9
        };

        printer
            .print_timestamp(self.0, StdFmtWrite(f))
            .map_err(|_| fmt::Error)
    }
}

pub fn serialize_timestamp_chrono_compat<S>(
    ts: &Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_str(&ChronoRfc3339Compat(ts))
}

pub fn serialize_option_timestamp_chrono_compat<S>(
    ts: &Option<Timestamp>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match ts {
        Some(ts) => serialize_timestamp_chrono_compat(ts, serializer),
        None => serializer.serialize_none(),
    }
}

/// Converts a Windows FILETIME (100ns intervals since 1601-01-01 UTC) to a Unix-epoch timestamp.
///
/// This is a hot path: we avoid chrono entirely and only allocate on error.
///
/// Returns an error instead of panicking when the resulting timestamp is outside `jiff::Timestamp`'s
/// supported range (roughly years -9999 to 9999).
pub fn windows_filetime_to_timestamp(filetime_100ns: u64) -> crate::err::Result<Timestamp> {
    // Match historical behavior (`winstructs::timestamp::WinTimestamp::to_datetime`):
    // FILETIME is 100ns resolution, but the conversion truncates to microseconds.
    const WINDOWS_TO_UNIX_EPOCH_MICROS: i64 = 11_644_473_600_000_000;

    let micros_since_windows_epoch = (filetime_100ns / 10) as i64;
    let micros_since_unix_epoch = micros_since_windows_epoch - WINDOWS_TO_UNIX_EPOCH_MICROS;

    let seconds = micros_since_unix_epoch.div_euclid(1_000_000);
    let subsec_micros = micros_since_unix_epoch.rem_euclid(1_000_000);
    let subsec_nanos = (subsec_micros * 1_000) as i32;

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
    fn test_to_hex_string_uppercase_no_separators() {
        assert_eq!(to_hex_string(&[]), "");
        assert_eq!(to_hex_string(&[0x00]), "00");
        assert_eq!(to_hex_string(&[0x0F, 0x10, 0xAB, 0xFF]), "0F10ABFF");
        assert_eq!(to_hex_string(b"Hi"), "4869");
    }
}
