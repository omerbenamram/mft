use crate::err::{Error, Result};

/// NTFS Update Sequence Array (USA) fixups are applied at **512-byte** strides regardless of the
/// volume bytes-per-sector setting.
pub const UPDATE_SEQUENCE_STRIDE_BYTES: usize = 512;

/// Applies NTFS Update Sequence Array (USA) fixups in-place.
///
/// This is the "multi-sector transfer" protection used by structures like `FILE` (MFT record) and
/// `INDX` (index record): the last 2 bytes of each 512-byte sector are temporarily replaced with an
/// update-sequence number, and the original bytes are stored in the USA array. This function
/// restores those original bytes.
///
/// Returns:
/// - `Ok(true)` if all processed sectors matched the update-sequence number.
/// - `Ok(false)` if any sector mismatch was detected **or** if the record ended before all
///   fixups could be applied (best-effort behavior).
///
/// Notes:
/// - `usa_count` is the number of 2-byte values in the array, including the initial update-sequence
///   number, so the number of fixups to apply is `usa_count - 1`.
/// - This function does not fail on mismatch; it still applies fixups to enable best-effort parsing.
pub fn apply_update_sequence_array_fixups_in_place(
    buffer: &mut [u8],
    usa_offset: u16,
    usa_count: u16,
) -> Result<bool> {
    apply_update_sequence_array_fixups_in_place_with(buffer, usa_offset, usa_count, |_ctx| {})
}

/// Context provided to the mismatch callback in
/// [`apply_update_sequence_array_fixups_in_place_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsaMismatch {
    /// 0-based sector index.
    pub sector_idx: usize,
    pub end_of_sector_bytes: [u8; 2],
    pub update_sequence: [u8; 2],
    pub replacement_bytes: [u8; 2],
}

/// Same as [`apply_update_sequence_array_fixups_in_place`], but allows observing mismatches.
///
/// The callback is invoked only when a sector mismatch is detected.
pub fn apply_update_sequence_array_fixups_in_place_with<F>(
    buffer: &mut [u8],
    usa_offset: u16,
    usa_count: u16,
    mut on_mismatch: F,
) -> Result<bool>
where
    F: FnMut(UsaMismatch),
{
    if usa_count < 2 {
        return Err(Error::Any {
            detail: "invalid number_of_fixup_values".to_string(),
        });
    }

    let usa_offset = usa_offset as usize;
    let usa_size_bytes = (usa_count as usize)
        .checked_mul(2)
        .ok_or_else(|| Error::Any {
            detail: "fixup array size overflow".to_string(),
        })?;
    let usa_end = usa_offset
        .checked_add(usa_size_bytes)
        .ok_or_else(|| Error::Any {
            detail: "fixup array end offset overflow".to_string(),
        })?;

    if usa_end > buffer.len() || usa_offset >= buffer.len() {
        return Err(Error::Any {
            detail: "fixup array out of bounds".to_string(),
        });
    }

    // Copy out the update-sequence bytes (avoid borrowing the buffer while mutating it).
    let update_sequence = [buffer[usa_offset], buffer[usa_offset + 1]];

    let sector_count = (usa_count as usize).saturating_sub(1);
    let mut valid_fixup = true;

    for sector_idx in 0..sector_count {
        let sector_end = (sector_idx + 1) * UPDATE_SEQUENCE_STRIDE_BYTES;
        if sector_end < 2 || sector_end > buffer.len() {
            // Best-effort: the record is shorter than expected for the declared number of sectors.
            // We treat it as invalid fixup but still keep any fixups applied so far.
            valid_fixup = false;
            break;
        }

        let replacement_offset = usa_offset + (sector_idx + 1) * 2;
        if replacement_offset + 2 > usa_end {
            return Err(Error::Any {
                detail: "fixup array out of bounds".to_string(),
            });
        }
        let replacement_bytes = [buffer[replacement_offset], buffer[replacement_offset + 1]];

        let end_of_sector = &mut buffer[sector_end - 2..sector_end];
        let end_of_sector_bytes = [end_of_sector[0], end_of_sector[1]];

        if end_of_sector_bytes != update_sequence {
            valid_fixup = false;
            on_mismatch(UsaMismatch {
                sector_idx,
                end_of_sector_bytes,
                update_sequence,
                replacement_bytes,
            });
        }

        end_of_sector.copy_from_slice(&replacement_bytes);
    }

    Ok(valid_fixup)
}
