pub fn to_hex_string(bytes: &Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    strs.join("")
}

pub fn print_buffer_as_hex(buffer: &[u8]) {
    println!("{}",to_hex_string(&buffer.to_vec()));
}
