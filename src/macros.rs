#[macro_export]
macro_rules! impl_serialize_for_bitflags {
    ($flags: ident) => {
        impl serde::ser::Serialize for $flags {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                // Same text as `format!("{:?}", self)`, but built in a stack buffer without
                // going through `core::fmt` (which dominated serialization time).
                $crate::utils::serialize_bitflags_debug(stringify!($flags), self, serializer)
            }
        }
    };
}
