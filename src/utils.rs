use byteorder::{ByteOrder, LittleEndian};
use jiff::Timestamp;
use serde::Serializer;
use std::fmt;
use std::path::{Path, PathBuf};

/// Length of the string produced by [`format_timestamp`]: `YYYY-MM-DDTHH:MM:SS.fffffffZ`.
const TIMESTAMP_LEN: usize = 28;

/// Formats `ts` exactly like `format!("{ts:.7}")`, without going through `core::fmt`.
///
/// This is a hot path for both JSON and CSV output (every entry has 4-8 timestamps), and the
/// generic `fmt` machinery (plus serializers' `collect_str` adapters) dominated its cost.
///
/// Only years `0..=9999` are handled here (jiff prints other years with a sign and 6 digits);
/// returns `None` for those so the caller can fall back to jiff's `Display`.
fn format_timestamp(ts: &Timestamp, out: &mut [u8; TIMESTAMP_LEN]) -> Option<()> {
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
    out[19] = b'.';
    // 7 fractional digits (100ns), truncated like jiff's precision formatting.
    let mut frac = nanos / 100;
    for i in (20..27).rev() {
        out[i] = b'0' + (frac % 10) as u8;
        frac /= 10;
    }
    out[27] = b'Z';
    Some(())
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

/// Serializes a timestamp as RFC 3339 in UTC with 100ns precision, e.g.
/// `2007-06-30T12:50:52.2523952Z`.
pub fn serialize_timestamp<S>(ts: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut buf = [0u8; TIMESTAMP_LEN];
    match format_timestamp(ts, &mut buf) {
        Some(()) => serializer.serialize_str(
            std::str::from_utf8(&buf).expect("timestamp formatting emits ASCII only"),
        ),
        // NTFS timestamps have 100ns resolution, so always print all 7 fractional digits.
        // jiff's `Display` uses the formatter precision as the fractional-second precision.
        None => serializer.collect_str(&format_args!("{ts:.7}")),
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

/// Writes flags as `A | B | 0x40`, or as the name of a zero-valued flag (else `(empty)`) when no
/// bits are set: the format `mft` used with bitflags 1.x. Shared by the `Display` impl and
/// serialization generated by `impl_serialize_for_bitflags!`.
pub(crate) fn write_bitflags<B>(flags: &B, w: &mut impl fmt::Write) -> fmt::Result
where
    B: bitflags::Flags,
    B::Bits: bitflags::parser::WriteHex,
{
    if flags.is_empty() {
        let zero_flag = B::FLAGS.iter().find(|flag| flag.value().is_empty());
        return match zero_flag {
            Some(flag) => w.write_str(flag.name()),
            None => w.write_str("(empty)"),
        };
    }

    bitflags::parser::to_writer(flags, w)
}

/// Serializes flags in the [`write_bitflags`] format, built in a stack buffer so the serializer
/// gets one `serialize_str` call instead of `core::fmt` plumbing.
pub(crate) fn serialize_bitflags<B, S>(flags: &B, serializer: S) -> Result<S::Ok, S::Error>
where
    B: bitflags::Flags + fmt::Display,
    B::Bits: bitflags::parser::WriteHex,
    S: Serializer,
{
    let mut buf = StackStr::<256>::new();
    match write_bitflags(flags, &mut buf) {
        Ok(()) => serializer.serialize_str(buf.as_str()),
        // Only reachable for flag combinations whose text overflows the buffer.
        Err(_) => serializer.collect_str(flags),
    }
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

/// Formats a path resolved by [`crate::MftParser::get_full_path_for_entry`] with `\`
/// separators, the way Windows writes NTFS paths, whatever the host platform.
pub fn windows_path(path: &Path) -> String {
    WindowsPath(path).to_string()
}

struct WindowsPath<'a>(&'a Path);

impl fmt::Display for WindowsPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, component) in self.0.components().enumerate() {
            if i > 0 {
                f.write_str("\\")?;
            }
            f.write_str(&component.as_os_str().to_string_lossy())?;
        }
        Ok(())
    }
}

/// Serializes a path with `\` separators, see [`windows_path`].
pub fn serialize_windows_path<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_str(&WindowsPath(path))
}

/// Same as [`serialize_windows_path`], for an optional path.
pub fn serialize_option_windows_path<S>(
    path: &Option<PathBuf>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match path {
        Some(path) => serialize_windows_path(path, serializer),
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

/// Reads a little-endian `u16` at `offset`, or `None` past the end of `buf`.
pub(crate) fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset.checked_add(2)?)
        .map(LittleEndian::read_u16)
}

/// Reads a little-endian `u32` at `offset`, or `None` past the end of `buf`.
pub(crate) fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset.checked_add(4)?)
        .map(LittleEndian::read_u32)
}

/// Reads a little-endian `u64` at `offset`, or `None` past the end of `buf`.
pub(crate) fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    buf.get(offset..offset.checked_add(8)?)
        .map(LittleEndian::read_u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_path_uses_backslashes() {
        let path = PathBuf::from("[Orphaned]")
            .join("WINDOWS")
            .join("notepad.exe");
        assert_eq!(windows_path(&path), r"[Orphaned]\WINDOWS\notepad.exe");
        assert_eq!(windows_path(Path::new("$MFT")), "$MFT");
        assert_eq!(windows_path(Path::new(".")), ".");
        assert_eq!(windows_path(Path::new("")), "");
    }

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
        // Pre-1970 values have negative seconds with a nonnegative subsecond part.
        assert_eq!(print(1), "1601-01-01T00:00:00.0000001Z");
        assert_eq!(
            print(116_444_735_999_999_999),
            "1969-12-31T23:59:59.9999999Z"
        );
        assert_eq!(
            print(116_444_736_000_000_001),
            "1970-01-01T00:00:00.0000001Z"
        );
    }

    #[test]
    fn fast_timestamp_formatting_matches_jiff_display() {
        let mut cases: Vec<(i64, i32)> = vec![
            (0, 0),
            (-1, 0),
            (-1, -1),
            (-1, -100),
            (0, 1),
            (0, 99),
            (0, 100),
            (0, 999_999_999),
            (951_782_400, 0), // 2000-02-29
            (1_234_567_890, 123_456_700),
            (-11_644_473_600, 0),           // 1601-01-01, the FILETIME epoch
            (-62_167_219_200, 0),           // 0000-01-01
            (-62_167_219_201, 0),           // -0001-12-31 (falls back)
            (253_402_300_799, 999_999_900), // 9999-12-31T23:59:59.9999999
        ];

        // Deterministic pseudo-random sweep over the whole supported range.
        let (min, max) = (Timestamp::MIN.as_second(), Timestamp::MAX.as_second());
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..200_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let secs = min + (state >> 11) as i64 % (max - min);
            let nanos = match state % 3 {
                0 => 0,
                1 => ((state >> 7) % 10_000_000) as i32 * 100,
                _ => ((state >> 7) % 1_000_000_000) as i32,
            };
            cases.push((secs, if secs < 0 { -nanos } else { nanos }));
        }

        for (secs, nanos) in cases {
            let Ok(ts) = Timestamp::new(secs, nanos) else {
                continue;
            };
            let expected = format!("{ts:.7}");
            let mut buf = [0u8; TIMESTAMP_LEN];
            match format_timestamp(&ts, &mut buf) {
                Some(()) => assert_eq!(
                    std::str::from_utf8(&buf).unwrap(),
                    expected,
                    "secs={secs} nanos={nanos}"
                ),
                // Only years outside 0..=9999 may take the fallback path.
                None => assert!(
                    expected.starts_with('-') || expected.starts_with('+'),
                    "unexpected fallback for {expected}"
                ),
            }
        }
    }

    #[test]
    fn bitflags_formatting_matches_display() {
        use crate::attribute::x90::{IndexEntryFlags, IndexRootFlags};
        use crate::attribute::{AttributeDataFlags, FileAttributeFlags};
        use crate::entry::EntryFlags;

        /// The `Display` logic `impl_serialize_for_bitflags!` used before `write_bitflags`.
        fn reference<B>(flags: &B) -> String
        where
            B: bitflags::Flags,
            B::Bits: bitflags::parser::WriteHex,
        {
            if flags.is_empty() {
                return match B::FLAGS.iter().find(|flag| flag.value().is_empty()) {
                    Some(flag) => flag.name().to_string(),
                    None => "(empty)".to_string(),
                };
            }
            let mut s = String::new();
            bitflags::parser::to_writer(flags, &mut s).unwrap();
            s
        }

        fn check<B>(flags: B)
        where
            B: bitflags::Flags + fmt::Display,
            B::Bits: bitflags::parser::WriteHex,
        {
            let mut buf = StackStr::<1024>::new();
            write_bitflags(&flags, &mut buf).unwrap();
            assert_eq!(buf.as_str(), reference(&flags));
            assert_eq!(flags.to_string(), reference(&flags));
            assert_eq!(
                serde_json::to_string(&SerializeFlags(&flags)).unwrap(),
                serde_json::to_string(&flags.to_string()).unwrap()
            );
        }

        struct SerializeFlags<'a, B>(&'a B);

        impl<B> serde::Serialize for SerializeFlags<'_, B>
        where
            B: bitflags::Flags + fmt::Display,
            B::Bits: bitflags::parser::WriteHex,
        {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                serialize_bitflags(self.0, s)
            }
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
            check(FileAttributeFlags::from_bits_retain(bits));
            check(EntryFlags::from_bits_retain(bits as u16));
            check(AttributeDataFlags::from_bits_retain(bits as u16));
            check(IndexRootFlags::from_bits_retain(bits));
            check(IndexEntryFlags::from_bits_retain(bits));
        }
        check(FileAttributeFlags::empty());
        check(EntryFlags::empty());
        // Longer than the serializer's stack buffer: must fall back, not truncate.
        assert!(FileAttributeFlags::all().to_string().len() > 256);
        check(FileAttributeFlags::all());
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
