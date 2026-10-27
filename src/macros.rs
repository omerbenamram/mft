#[macro_export]
macro_rules! impl_serialize_for_bitflags {
    ($flags: ident) => {
        impl ::std::fmt::Display for $flags {
            /// Formats the flags as `A | B`, the same way `mft` did with bitflags 1.x.
            /// Empty flags are formatted as the name of a zero-valued flag if there is one,
            /// otherwise as `(empty)`.
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                use bitflags::Flags;

                if self.is_empty() {
                    let zero_flag = <Self as Flags>::FLAGS
                        .iter()
                        .find(|flag| flag.value().is_empty());
                    return match zero_flag {
                        Some(flag) => f.write_str(flag.name()),
                        None => f.write_str("(empty)"),
                    };
                }

                bitflags::parser::to_writer(self, f)
            }
        }

        impl serde::ser::Serialize for $flags {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                // Stream the Display output directly to the serializer without allocating
                // an intermediate String. This is faster than `serialize_str(&format!(...))`.
                serializer.collect_str(self)
            }
        }
    };
}
