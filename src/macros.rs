#[macro_export]
macro_rules! impl_serialize_for_bitflags {
    ($flags: ident) => {
        impl ::std::fmt::Display for $flags {
            /// Formats the flags as `A | B`, the same way `mft` did with bitflags 1.x.
            /// Empty flags are formatted as the name of a zero-valued flag if there is one,
            /// otherwise as `(empty)`.
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                $crate::utils::write_bitflags(self, f)
            }
        }

        impl serde::ser::Serialize for $flags {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                // Same text as `Display`, but built in a stack buffer without going through
                // `core::fmt` (which dominated serialization time).
                $crate::utils::serialize_bitflags(self, serializer)
            }
        }
    };
}
