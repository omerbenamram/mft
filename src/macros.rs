#[macro_export]
macro_rules! impl_serialize_for_bitflags {
    ($flags: ident) => {
        impl serde::ser::Serialize for $flags {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                // Stream the Debug output directly to the serializer without allocating
                // an intermediate String. This is faster than `serialize_str(&format!(...))`.
                serializer.collect_str(&format_args!("{:?}", &self))
            }
        }
    };
}
