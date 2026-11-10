use crate::ntfs::{Error, Result};

/// Uncompressed size of one LZNT1 chunk.
const LZNT1_BLOCK_SIZE: usize = 4096;

/// Decompresses an MS-XCA LZNT1 stream into exactly `expected_len` bytes.
///
/// NTFS uses LZNT1 for compressed attributes. The stream is chunked into 4KiB blocks, each
/// preceded by a 2-byte header.
///
/// Every chunk describes one 4KiB block of output: a chunk that decodes to fewer bytes is
/// zero-filled up to the block boundary before the next chunk starts. A zero header ends the
/// stream; whatever follows it in the compression unit is slack, and the rest of the output is
/// zeros.
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

        if header == 0 {
            // End-of-stream marker: the bytes after it are not part of the stream.
            out.resize(expected_len, 0);
            return Ok(out);
        }

        let block_end = out.len().saturating_add(LZNT1_BLOCK_SIZE).min(expected_len);

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
            let take = remaining.min(chunk.len()).min(LZNT1_BLOCK_SIZE);
            out.extend_from_slice(&chunk[..take]);
        } else {
            // Compressed chunk: decompress to up to 4KiB.
            let remaining = expected_len - out.len();
            let max_out = remaining.min(LZNT1_BLOCK_SIZE);
            decompress_lznt1_chunk(chunk, &mut out, max_out)?;
        }

        // A short chunk still stands for a whole block.
        if out.len() < block_end {
            out.resize(block_end, 0);
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

    /// The worked example from MS-XCA ("LZNT1 example"), an independent reference vector.
    #[test]
    fn decompress_ms_xca_example() {
        let input: [u8; 59] = [
            0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xa2,
            0x47, 0x01, 0xa0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xc0,
            0x45, 0x20, 0x05, 0x24, 0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a, 0x44, 0xef, 0x03, 0x58,
            0x02, 0x8c, 0x09, 0x16, 0x01, 0x48, 0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01,
            0x18, 0x90, 0x00,
        ];
        let expected = "F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D \
                        E E F# D E F# G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D\0";
        let out = decompress_lznt1_to_len(&input, expected.len()).unwrap();
        assert_eq!(out, expected.as_bytes());
    }

    #[test]
    fn zero_header_ends_the_stream() {
        // One full uncompressed block, the end marker, then stale bytes that happen to follow
        // it in the compression unit.
        let mut input = vec![0xFF, 0x3F];
        input.extend_from_slice(&[b'A'; 4096]);
        input.extend_from_slice(&[0x00, 0x00]);
        input.extend_from_slice(&[0xEE; 64]);

        let out = decompress_lznt1_to_len(&input, 8192).unwrap();
        assert_eq!(out.len(), 8192);
        assert!(out[..4096].iter().all(|&b| b == b'A'));
        assert!(out[4096..].iter().all(|&b| b == 0));

        // A stream that is nothing but the marker is all zeros.
        let out = decompress_lznt1_to_len(&[0x00, 0x00, 0xEE, 0xEE, 0xEE], 4096).unwrap();
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn short_chunk_is_padded_to_a_full_block() {
        // Two compressed chunks of three literals each: flag byte 0, then the literals.
        let input = [
            0x03, 0xB0, 0x00, b'a', b'b', b'c', //
            0x03, 0xB0, 0x00, b'x', b'y', b'z',
        ];
        let out = decompress_lznt1_to_len(&input, 8192).unwrap();
        assert_eq!(&out[..3], b"abc");
        assert!(out[3..4096].iter().all(|&b| b == 0));
        assert_eq!(&out[4096..4099], b"xyz");
        assert!(out[4099..].iter().all(|&b| b == 0));

        // Same for a short uncompressed chunk followed by a compressed one whose copy token
        // must only see its own block.
        let input = [
            0x02, 0x30, b'a', b'b', b'c', //
            0x04, 0xB0, 0x02, b'q', 0x01, 0x00, 0x00,
        ];
        let out = decompress_lznt1_to_len(&input, 4096 + 8).unwrap();
        assert_eq!(&out[..3], b"abc");
        assert!(out[3..4096].iter().all(|&b| b == 0));
        // Literal 'q', then copy offset 1 length 4 (token 0x0001: offset 0, length 1).
        assert_eq!(&out[4096..], b"qqqqq\0\0\0");
    }

    #[test]
    fn output_never_exceeds_expected_len() {
        let input = [0x03, 0xB0, 0x00, b'a', b'b', b'c'];
        assert_eq!(decompress_lznt1_to_len(&input, 2).unwrap(), b"ab");
        assert_eq!(decompress_lznt1_to_len(&input, 5).unwrap(), b"abc\0\0");
    }
}
