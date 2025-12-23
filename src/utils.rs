use byteorder::ReadBytesExt;
use jiff::Timestamp;
use jiff::fmt::StdFmtWrite;
use jiff::fmt::temporal::DateTimePrinter;
use serde::Serializer;
use std::char::decode_utf16;
use std::fmt;
use std::fmt::Write;
use std::io::{self, Read, Seek};

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

pub(crate) fn serialize_timestamp_chrono_compat<S>(
    ts: &Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_str(&ChronoRfc3339Compat(ts))
}

pub(crate) fn serialize_option_timestamp_chrono_compat<S>(
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
pub(crate) fn windows_filetime_to_timestamp(filetime_100ns: u64) -> crate::err::Result<Timestamp> {
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
    let len = bytes.len();
    // Each byte is represented by 2 ascii bytes.
    let mut s = String::with_capacity(len * 2);

    for byte in bytes {
        write!(s, "{byte:02X}").expect("Writing to an allocated string cannot fail");
    }

    s
}

/// Reads a utf16 string from the given stream.
/// If `len` is given, exactly `len` u16 values are read from the stream.
/// If `len` is None, the string is assumed to be null terminated and the stream will be read to the first null (0).
pub fn read_utf16_string<T: Read + Seek>(stream: &mut T, len: Option<usize>) -> io::Result<String> {
    let mut buffer = match len {
        Some(len) => Vec::with_capacity(len),
        None => Vec::new(),
    };

    match len {
        Some(len) => {
            for _ in 0..len {
                let next_char = stream.read_u16::<byteorder::LittleEndian>()?;
                buffer.push(next_char);
            }
        }
        None => loop {
            let next_char = stream.read_u16::<byteorder::LittleEndian>()?;

            if next_char == 0 {
                break;
            }

            buffer.push(next_char);
        },
    }

    // We need to stop if we see a NUL byte, even if asked for more bytes.
    decode_utf16(buffer.into_iter().take_while(|&byte| byte != 0x00))
        .map(|r| r.map_err(|_e| io::Error::from(io::ErrorKind::InvalidData)))
        .collect()
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
}
