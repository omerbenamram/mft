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

/// Longest string produced by [`format_timestamp_chrono_compat`]:
/// `YYYY-MM-DDTHH:MM:SS.fffffffffZ`.
const TIMESTAMP_FAST_MAX_LEN: usize = 30;

/// Formats `ts` exactly like [`ChronoRfc3339Compat`] does, without going through `core::fmt`.
///
/// This is a hot path for both JSON and CSV output (every entry has 4-8 timestamps), and the
/// generic `fmt` machinery (plus serializers' `collect_str` adapters) dominated its cost.
///
/// Only years `0..=9999` are handled here (jiff prints other years with a sign and 6 digits);
/// returns `None` for those so the caller can fall back to jiff's printer.
fn format_timestamp_chrono_compat(
    ts: &Timestamp,
    out: &mut [u8; TIMESTAMP_FAST_MAX_LEN],
) -> Option<usize> {
    fn put2(out: &mut [u8], v: u32) {
        out[0] = b'0' + (v / 10) as u8;
        out[1] = b'0' + (v % 10) as u8;
    }

    let secs = ts.as_second();
    let nanos = ts.subsec_nanosecond();
    // jiff normalizes negative timestamps so that the second and nanosecond components share a
    // sign; convert to a floored second + non-negative nanosecond pair.
    let (secs, nanos) = if nanos < 0 {
        (secs - 1, (nanos + 1_000_000_000) as u32)
    } else {
        (secs, nanos as u32)
    };

    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    // Shift to days since -0400-03-01 so that every year we format (0..=9999) is covered by
    // non-negative `u32` arithmetic, which is noticeably cheaper than the `i64` equivalent.
    let shifted = days + 719_468 + i64::from(DAYS_PER_ERA);
    if !(0..i64::from(DAYS_PER_ERA) * 26).contains(&shifted) {
        return None;
    }
    let (year, month, day) = civil_from_shifted_days(shifted as u32);
    let year = year.checked_sub(400).filter(|y| *y <= 9999)?;

    put2(&mut out[0..2], year / 100);
    put2(&mut out[2..4], year % 100);
    out[4] = b'-';
    put2(&mut out[5..7], month);
    out[7] = b'-';
    put2(&mut out[8..10], day);
    out[10] = b'T';
    put2(&mut out[11..13], sod / 3600);
    out[13] = b':';
    put2(&mut out[14..16], (sod / 60) % 60);
    out[16] = b':';
    put2(&mut out[17..19], sod % 60);

    // Match chrono's `SecondsFormat::AutoSi` (see `ChronoRfc3339Compat`).
    let (frac, digits) = if nanos == 0 {
        (0, 0)
    } else if nanos % 1_000_000 == 0 {
        (nanos / 1_000_000, 3)
    } else if nanos % 1_000 == 0 {
        (nanos / 1_000, 6)
    } else {
        (nanos, 9)
    };

    let mut len = 19;
    if digits > 0 {
        out[len] = b'.';
        let mut v = frac;
        for i in (0..digits).rev() {
            out[len + 1 + i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        len += 1 + digits;
    }
    out[len] = b'Z';
    Some(len + 1)
}

const DAYS_PER_ERA: u32 = 146_097;

/// Converts days since 0000-03-01 to a proleptic Gregorian `(year, month, day)`.
///
/// <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
fn civil_from_shifted_days(z: u32) -> (u32, u32, u32) {
    let era = z / DAYS_PER_ERA;
    let doe = z % DAYS_PER_ERA; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = yoe + era * 400 + u32::from(month <= 2);
    (year, month, day)
}

pub fn serialize_timestamp_chrono_compat<S>(
    ts: &Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut buf = [0u8; TIMESTAMP_FAST_MAX_LEN];
    match format_timestamp_chrono_compat(ts, &mut buf) {
        Some(len) => serializer.serialize_str(
            std::str::from_utf8(&buf[..len]).expect("timestamp formatting emits ASCII only"),
        ),
        None => serializer.collect_str(&ChronoRfc3339Compat(ts)),
    }
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

/// A fixed-capacity, stack-allocated string buffer.
///
/// Writes that would overflow the buffer fail with `fmt::Error` (callers fall back to a slower,
/// allocating path), so this never truncates silently.
pub(crate) struct StackStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackStr<N> {
    pub(crate) fn new() -> Self {
        StackStr {
            buf: [0; N],
            len: 0,
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).expect("only `&str` data is ever written")
    }
}

impl<const N: usize> fmt::Write for StackStr<N> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        if end > N {
            return Err(fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Writes the same text as the `Debug` impl generated by `bitflags!` (`Name(A | B | 0x40)`, or
/// `Name(0x0)` when empty), using the flag names directly instead of `core::fmt` plumbing.
pub(crate) fn write_bitflags_debug<B>(
    type_name: &str,
    flags: &B,
    w: &mut impl fmt::Write,
) -> fmt::Result
where
    B: bitflags::Flags,
    B::Bits: fmt::LowerHex,
{
    w.write_str(type_name)?;
    w.write_char('(')?;
    if flags.is_empty() {
        w.write_str("0x0")?;
    } else {
        let mut first = true;
        let mut iter = flags.iter_names();
        for (name, _) in &mut iter {
            if !first {
                w.write_str(" | ")?;
            }
            first = false;
            w.write_str(name)?;
        }

        let remaining = iter.remaining().bits();
        if remaining != <B::Bits as bitflags::Bits>::EMPTY {
            if !first {
                w.write_str(" | ")?;
            }
            write!(w, "0x{remaining:x}")?;
        }
    }
    w.write_char(')')
}

/// Serializes a `bitflags!` type as its `Debug` string (the historical output format).
pub(crate) fn serialize_bitflags_debug<B, S>(
    type_name: &str,
    flags: &B,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    B: bitflags::Flags + fmt::Debug,
    B::Bits: fmt::LowerHex,
    S: Serializer,
{
    let mut buf = StackStr::<256>::new();
    match write_bitflags_debug(type_name, flags, &mut buf) {
        Ok(()) => serializer.serialize_str(buf.as_str()),
        // Only reachable for pathological flag combinations that overflow the buffer.
        Err(_) => serializer.collect_str(&format_args!("{flags:?}")),
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

    fn fast_timestamp(ts: &Timestamp) -> Option<String> {
        let mut buf = [0u8; TIMESTAMP_FAST_MAX_LEN];
        format_timestamp_chrono_compat(ts, &mut buf)
            .map(|len| std::str::from_utf8(&buf[..len]).unwrap().to_owned())
    }

    #[test]
    fn fast_timestamp_formatting_matches_jiff_printer() {
        let mut cases: Vec<(i64, i32)> = vec![
            (0, 0),
            (-1, 0),
            (-1, -1),
            (0, 1),
            (0, 999_999_999),
            (951_782_400, 0), // 2000-02-29
            (1_234_567_890, 123_000_000),
            (1_234_567_890, 123_456_000),
            (1_234_567_890, 123_456_789),
            (-11_644_473_600, 0),           // 1601-01-01, the FILETIME epoch
            (-62_167_219_200, 0),           // 0000-01-01
            (-62_167_219_201, 0),           // -0001-12-31 (falls back)
            (253_402_300_799, 999_000_000), // 9999-12-31T23:59:59.999
        ];

        // Deterministic pseudo-random sweep over the whole supported range.
        let (min, max) = (Timestamp::MIN.as_second(), Timestamp::MAX.as_second());
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..200_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let secs = min + (state >> 11) as i64 % (max - min);
            let nanos = match state % 4 {
                0 => 0,
                1 => ((state >> 7) % 1_000) as i32 * 1_000_000,
                2 => ((state >> 7) % 1_000_000) as i32 * 1_000,
                _ => ((state >> 7) % 1_000_000_000) as i32,
            };
            cases.push((secs, if secs < 0 { -nanos } else { nanos }));
        }

        for (secs, nanos) in cases {
            let Ok(ts) = Timestamp::new(secs, nanos) else {
                continue;
            };
            let expected = ChronoRfc3339Compat(&ts).to_string();
            match fast_timestamp(&ts) {
                Some(actual) => assert_eq!(actual, expected, "secs={secs} nanos={nanos}"),
                // Only years outside 0..=9999 may take the fallback path.
                None => assert!(
                    expected.starts_with('-') || expected.starts_with('+'),
                    "unexpected fallback for {expected}"
                ),
            }
        }
    }

    #[test]
    fn serialize_timestamp_uses_chrono_compat_format() {
        let ts = windows_filetime_to_timestamp(0x01CE_5F43_5848_2DD5).unwrap();
        let json = serde_json::to_string(&SerializeTs(ts)).unwrap();
        assert_eq!(json, format!("\"{}\"", ChronoRfc3339Compat(&ts)));
        assert_eq!(json, "\"2013-06-02T03:43:28.889595Z\"");
    }

    struct SerializeTs(Timestamp);

    impl serde::Serialize for SerializeTs {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serialize_timestamp_chrono_compat(&self.0, s)
        }
    }

    #[test]
    fn bitflags_formatting_matches_debug() {
        use crate::attribute::x90::{IndexEntryFlags, IndexRootFlags};
        use crate::attribute::{AttributeDataFlags, FileAttributeFlags};
        use crate::entry::EntryFlags;

        fn check<B>(name: &str, flags: B)
        where
            B: bitflags::Flags + fmt::Debug,
            B::Bits: fmt::LowerHex,
        {
            let mut buf = StackStr::<1024>::new();
            write_bitflags_debug(name, &flags, &mut buf).unwrap();
            assert_eq!(buf.as_str(), format!("{flags:?}"));
        }

        let mut state: u32 = 0x1234_5678;
        for i in 0..20_000u32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            // Mix sparse, dense and single-bit patterns.
            let bits = match i % 3 {
                0 => state,
                1 => state & (state >> 7) & (state >> 13),
                _ => 1u32.wrapping_shl(i % 32),
            };
            check(
                "FileAttributeFlags",
                FileAttributeFlags::from_bits_retain(bits),
            );
            check("EntryFlags", EntryFlags::from_bits_retain(bits as u16));
            check(
                "AttributeDataFlags",
                AttributeDataFlags::from_bits_retain(bits as u16),
            );
            check("IndexRootFlags", IndexRootFlags::from_bits_retain(bits));
            check("IndexEntryFlags", IndexEntryFlags::from_bits_retain(bits));
        }
        check("FileAttributeFlags", FileAttributeFlags::empty());
        check("FileAttributeFlags", FileAttributeFlags::all());

        // Longer than the serializer's stack buffer: must fall back, not truncate.
        let all = FileAttributeFlags::all();
        assert!(format!("{all:?}").len() > 256);
        assert_eq!(
            serde_json::to_string(&all).unwrap(),
            serde_json::to_string(&format!("{all:?}")).unwrap()
        );
    }

    #[test]
    fn stack_str_rejects_overflow() {
        use std::fmt::Write;
        let mut buf = StackStr::<4>::new();
        assert!(buf.write_str("abcd").is_ok());
        assert!(buf.write_str("e").is_err());
        assert_eq!(buf.as_str(), "abcd");
    }

    #[test]
    fn test_to_hex_string_uppercase_no_separators() {
        assert_eq!(to_hex_string(&[]), "");
        assert_eq!(to_hex_string(&[0x00]), "00");
        assert_eq!(to_hex_string(&[0x0F, 0x10, 0xAB, 0xFF]), "0F10ABFF");
        assert_eq!(to_hex_string(b"Hi"), "4869");
    }
}
