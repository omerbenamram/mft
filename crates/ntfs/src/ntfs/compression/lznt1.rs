use crate::ntfs::{Error, Result};

/// Decompresses an MS-XCA LZNT1 stream into exactly `expected_len` bytes.
///
/// NTFS uses LZNT1 for compressed attributes. The stream is chunked into 4KiB blocks, each
/// preceded by a 2-byte header.
pub fn decompress_lznt1_to_len(input: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(expected_len);
    let mut pos = 0usize;

    while out.len() < expected_len {
        if pos + 2 > input.len() {
            // Truncated: pad with zeros (best effort).
            out.resize(expected_len, 0);
            return Ok(out);
        }

        let header = u16::from_le_bytes([input[pos], input[pos + 1]]);
        pos += 2;

        let chunk_len = ((header & 0x0FFF) as usize).saturating_add(1);
        let is_compressed = (header & 0x8000) != 0;

        if pos + chunk_len > input.len() {
            // Truncated chunk: pad.
            out.resize(expected_len, 0);
            return Ok(out);
        }

        let chunk = &input[pos..pos + chunk_len];
        pos += chunk_len;

        if !is_compressed {
            // Uncompressed chunk: copy as-is.
            let remaining = expected_len - out.len();
            let take = remaining.min(chunk.len());
            out.extend_from_slice(&chunk[..take]);
        } else {
            // Compressed chunk: decompress to up to 4KiB.
            let remaining = expected_len - out.len();
            let max_out = remaining.min(4096);
            decompress_lznt1_chunk(chunk, &mut out, max_out)?;
        }
    }

    Ok(out)
}

fn decompress_lznt1_chunk(input: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<()> {
    let base_len = out.len();
    let mut in_pos = 0usize;

    while out.len() - base_len < max_out {
        if in_pos >= input.len() {
            break;
        }

        let flags = input[in_pos];
        in_pos += 1;

        for bit in 0..8 {
            if out.len() - base_len >= max_out {
                break;
            }
            if in_pos >= input.len() {
                break;
            }

            if (flags & (1 << bit)) == 0 {
                // literal
                out.push(input[in_pos]);
                in_pos += 1;
                continue;
            }

            // copy token
            if in_pos + 2 > input.len() {
                return Err(Error::InvalidData {
                    message: "truncated lznt1 copy token".to_string(),
                });
            }
            let token = u16::from_le_bytes([input[in_pos], input[in_pos + 1]]);
            in_pos += 2;

            let cur = out.len() - base_len;
            if cur == 0 {
                return Err(Error::InvalidData {
                    message: "lznt1 copy token at start of chunk".to_string(),
                });
            }

            let (offset, length) = decode_lznt1_copy_token(token, cur)?;
            if offset == 0 || offset > cur {
                return Err(Error::InvalidData {
                    message: format!("lznt1 invalid offset {offset} at pos {cur}"),
                });
            }

            let src_start = out.len().saturating_sub(offset);
            for i in 0..length {
                if out.len() - base_len >= max_out {
                    break;
                }
                let b = out
                    .get(src_start + i)
                    .copied()
                    .ok_or_else(|| Error::InvalidData {
                        message: "lznt1 copy source out of bounds".to_string(),
                    })?;
                out.push(b);
            }
        }
    }

    Ok(())
}

fn decode_lznt1_copy_token(token: u16, cur_out_len: usize) -> Result<(usize, usize)> {
    // Dynamic split: number of offset bits grows with output position.
    //
    // A good mental model is:
    // - offset_bits = ceil(log2(cur_out_len))
    // - clamp to [4, 12]
    // - offset is stored in the high bits, length in the low bits.
    let mut offset_bits = if cur_out_len <= 1 {
        0
    } else {
        // ceil(log2(cur_out_len)) == floor(log2(cur_out_len - 1)) + 1
        let mut x = cur_out_len - 1;
        let mut bits = 0u16;
        while x > 0 {
            bits += 1;
            x >>= 1;
        }
        bits
    };

    offset_bits = offset_bits.clamp(4, 12);

    let offset_shift = 16u16.saturating_sub(offset_bits);
    let length_mask = (1u16 << offset_shift).saturating_sub(1);

    let length = (token & length_mask) as usize + 3;
    let offset = (token >> offset_shift) as usize + 1;

    Ok((offset, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompress_uncompressed_chunk_roundtrip() {
        // Build an "uncompressed" chunk header for 4 bytes.
        // header: bit15=0, len=(4-1)=3.
        let header = 0x0003u16;
        let mut input = Vec::new();
        input.extend_from_slice(&header.to_le_bytes());
        input.extend_from_slice(b"test");

        let out = decompress_lznt1_to_len(&input, 4).unwrap();
        assert_eq!(&out, b"test");
    }
}
