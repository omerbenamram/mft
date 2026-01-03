use serde::Serialize;
use serde::ser::{Error as _, Serializer};
use std::cell::RefCell;
use std::fmt;
use utf16_simd::Scratch;

thread_local! {
    static UTF16_SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::new());
}

/// Borrowed UTF-16LE string data.
///
/// This is a zero-copy view into an underlying byte buffer (typically an MFT entry buffer).
/// The bytes are interpreted as UTF-16LE code units.
///
/// Notes:
/// - The view is **not** required to be valid UTF-16. Lone surrogates are dropped when converting
///   to UTF-8 (WTF-16 style), matching `utf16-simd`'s semantics.
/// - This type is intentionally optimized for “decode only at output time” use-cases.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Utf16LeStr<'a> {
    utf16le: &'a [u8],
}

impl<'a> Utf16LeStr<'a> {
    /// Construct a borrowed UTF-16LE string from bytes.
    ///
    /// The slice length should be a multiple of 2. If it's not, the trailing odd byte is ignored.
    pub fn from_utf16le_bytes(utf16le: &'a [u8]) -> Self {
        let len = utf16le.len() & !1;
        Self {
            utf16le: &utf16le[..len],
        }
    }

    /// Construct a borrowed UTF-16LE string from bytes, truncating at the first UTF-16 NUL
    /// (`0x0000`) code unit, if present.
    pub fn from_utf16le_bytes_until_nul(utf16le: &'a [u8]) -> Self {
        let len = utf16le.len() & !1;
        let utf16le = &utf16le[..len];

        for i in (0..len).step_by(2) {
            if utf16le[i] == 0 && utf16le[i + 1] == 0 {
                return Self {
                    utf16le: &utf16le[..i],
                };
            }
        }

        Self { utf16le }
    }

    pub fn empty() -> Self {
        Self { utf16le: &[] }
    }

    pub fn is_empty(&self) -> bool {
        self.utf16le.is_empty()
    }

    pub fn as_utf16le_bytes(&self) -> &'a [u8] {
        self.utf16le
    }

    pub fn len_units(&self) -> usize {
        self.utf16le.len() / 2
    }

    /// Execute `f` with a temporary UTF-8 view of this string.
    ///
    /// This does not allocate per call (it reuses a thread-local scratch buffer), but callers
    /// must not try to re-enter `Utf16LeStr` conversion APIs from inside `f`.
    pub fn with_utf8<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        if self.is_empty() {
            return f("");
        }

        UTF16_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let out = scratch.escape_utf16le_raw(self.utf16le, self.len_units());
            let s = std::str::from_utf8(out).expect("utf16-simd outputs valid UTF-8");
            f(s)
        })
    }

    /// Allocate a UTF-8 `String` for this UTF-16LE data.
    pub fn to_utf8_string(&self) -> String {
        self.with_utf8(|s| s.to_owned())
    }

    /// Compare this UTF-16LE string to a UTF-8 `&str` without allocating.
    ///
    /// Fast path: if `other` is ASCII, compare directly against UTF-16LE bytes by requiring
    /// `hi == 0` for each code unit.
    pub fn eq_utf8(&self, other: &str) -> bool {
        if other.is_ascii() {
            let other = other.as_bytes();
            if self.utf16le.len() != other.len() * 2 {
                return false;
            }
            for (i, &b) in other.iter().enumerate() {
                if self.utf16le[i * 2] != b || self.utf16le[i * 2 + 1] != 0 {
                    return false;
                }
            }
            true
        } else {
            self.with_utf8(|s| s == other)
        }
    }

    /// ASCII-only case-insensitive equality against a UTF-8 `&str`, without allocating.
    ///
    /// Fast path: if `other` is ASCII, compare directly against UTF-16LE bytes by requiring
    /// `hi == 0` for each code unit and using `to_ascii_lowercase()` on the low byte.
    pub fn eq_ignore_ascii_case(&self, other: &str) -> bool {
        if other.is_ascii() {
            let other = other.as_bytes();
            if self.utf16le.len() != other.len() * 2 {
                return false;
            }
            for (i, &b) in other.iter().enumerate() {
                let lo = self.utf16le[i * 2];
                let hi = self.utf16le[i * 2 + 1];
                if hi != 0 {
                    return false;
                }
                if !lo.eq_ignore_ascii_case(&b) {
                    return false;
                }
            }
            true
        } else {
            self.with_utf8(|s| s.eq_ignore_ascii_case(other))
        }
    }
}

impl PartialEq<&str> for Utf16LeStr<'_> {
    fn eq(&self, other: &&str) -> bool {
        self.eq_utf8(other)
    }
}

impl Serialize for Utf16LeStr<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.is_empty() {
            return serializer.serialize_str("");
        }

        UTF16_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let out = scratch.escape_utf16le_raw(self.utf16le, self.len_units());
            let s = std::str::from_utf8(out).map_err(S::Error::custom)?;
            serializer.serialize_str(s)
        })
    }
}

impl fmt::Debug for Utf16LeStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Utf16LeStr")
            .field(&self.with_utf8(|s| s.to_owned()))
            .finish()
    }
}

impl fmt::Display for Utf16LeStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.with_utf8(|s| f.write_str(s))
    }
}
