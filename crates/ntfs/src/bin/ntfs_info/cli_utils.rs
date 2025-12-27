pub(crate) fn parse_u64(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let (radix, digits) = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map(|d| (16, d))
        .unwrap_or((10, s));
    u64::from_str_radix(digits, radix).map_err(|e| e.to_string())
}
