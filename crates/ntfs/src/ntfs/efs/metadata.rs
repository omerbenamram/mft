//! `$EFS` metadata parsing (EFSRPC Metadata v1 on disk).
//!
//! NTFS stores EFS information in an attribute of type `LoggedUtilityStream` (`0x100`) named
//! `"$EFS"` (ref: `external/refs/repos/ntfsprogs-plus__ntfsprogs-plus@*/include/layout.h`,
//! “`$EFS Data Structure`” notes + `EFS_ATTR_HEADER`).
//!
//! The on-disk payload format we parse here is **EFSRPC Metadata Version 1** (ref:
//! `external/refs/specs/MS-EFSR.md` §2.2.2.1).
//!
//! ## What we parse (and why)
//!
//! - **DDF/DRF key list entries** (ref: MS‑EFSR §2.2.2.1.1 + §2.2.2.1.2): needed to locate both the
//!   per-file **Encrypted FEK** and the **Public Key Information** block describing which X.509
//!   certificate was used to encrypt it.
//! - **Encrypted FEK bytes** (ref: MS‑EFSR §2.2.2.1.5): passed to the crypto layer for RSA unwrap.
//! - **PublicKeyInfo / CertificateData thumbprint** (ref: MS‑EFSR §2.2.2.1.3 + §2.2.2.1.4): used
//!   by higher-level code to deterministically pick the correct private key from a `.pfx`
//!   (thumbprint-first, not trial-and-error). This is parsed in a dedicated step of the EFS work.
//!
//! ## Invariants we enforce (anti-“guessing”)
//!
//! - **All offsets are relative to the start of their containing structure**
//!   (ref: MS‑EFSR §2.2.2.1.2–§2.2.2.1.4).
//! - Referenced sub-fields must be **in-bounds** and **non-overlapping**
//!   (ref: MS‑EFSR §2.2.2.1.2 “Data Fields” constraints).
//! - Where MS‑EFSR specifies it, we also validate the “no unused areas > 8 contiguous bytes”
//!   property inside “Data Fields” (ref: MS‑EFSR §2.2.2.1.2 and §2.2.2.1.3).
//!
//! ## Current limitations
//!
//! - This module targets **Metadata Version 1** (EFS header `EFS Version` 1–3) and does not yet
//!   implement Metadata Version 2 (ref: MS‑EFSR §2.2.2.2).

use crate::parse::{ParseError, Reader, Result};
use std::io;

/// Parsed form of the on-disk `$EFS` stream (EFSRPC Metadata Version 1).
///
/// In MS-EFSR terms, this corresponds to "EFSRPC Metadata Version 1" (section 2.2.2.1), which
/// contains a header, followed by the DDF and (optionally) DRF key lists.
#[derive(Debug, Clone)]
pub struct EfsMetadataV1 {
    /// Total length in bytes of this metadata, as stored in the header.
    ///
    /// For well-formed `$EFS` attributes this should match the attribute's byte length.
    pub length: u32,

    /// Highest EFS version supported by the implementation that created this metadata.
    ///
    /// MS-EFSR defines:
    /// - `1`: DESX FEK, RSA-only wrapping
    /// - `2`: DESX/3DES/AES-256 FEK, RSA-only wrapping
    /// - `3`: DESX/3DES/AES-256 FEK, RSA or AES-256 wrapping (smartcard optimization)
    pub efs_version: u32,

    /// Per-machine GUID of the computer that created this metadata (16 bytes).
    pub efs_id: [u8; 16],

    /// Implementation-defined hash field (often zero on modern Windows).
    pub efs_hash: [u8; 16],

    /// Data Decryption Field (DDF) key list.
    pub ddf: Vec<KeyListEntry>,

    /// Data Recovery Field (DRF) key list, if present.
    pub drf: Vec<KeyListEntry>,
}

/// A single DDF/DRF key list entry (MS-EFSR 2.2.2.1.2).
#[derive(Debug, Clone)]
pub struct KeyListEntry {
    /// Total length in bytes of this entry.
    pub length: u32,

    /// Offset from the start of this entry to the Public Key Information field.
    pub public_key_info_offset: u32,

    /// Length in bytes of the encrypted FEK blob.
    pub encrypted_fek_length: u32,

    /// Offset from the start of this entry to the encrypted FEK blob.
    pub encrypted_fek_offset: u32,

    /// Flags describing how the FEK blob is wrapped.
    ///
    /// MS-EFSR defines:
    /// - `0`: RSA-wrapped FEK (most common)
    /// - `1`: AES-256-wrapped FEK using a key derived from an RSA smartcard signature
    pub flags: u32,

    /// The encrypted FEK blob bytes.
    pub encrypted_fek: Vec<u8>,

    /// Certificate thumbprint identifying the X.509 certificate used to encrypt this entry's FEK.
    ///
    /// This is the SHA-1 hash of the DER-encoded certificate (ref:
    /// `external/refs/specs/MS-EFSR.md` §2.2.2.1.4 “Certificate Thumbprint”).
    ///
    /// Note: this is extracted from the entry's PublicKeyInfo / CertificateData fields (ref:
    /// MS‑EFSR §2.2.2.1.3 + §2.2.2.1.4).
    pub cert_thumbprint_sha1: Option<[u8; 20]>,

    /// Optional SID hint identifying the key owner (ref: MS‑EFSR §2.2.2.1.3 “Owner Hint”).
    pub owner_hint_sid: Option<Vec<u8>>,

    /// Optional certificate container name hint (UTF-16, ref: MS‑EFSR §2.2.2.1.4).
    pub cert_container_name: Option<String>,

    /// Optional certificate provider name hint (UTF-16, ref: MS‑EFSR §2.2.2.1.4).
    pub cert_provider_name: Option<String>,

    /// Optional display name hint (UTF-16, ref: MS‑EFSR §2.2.2.1.4).
    pub cert_display_name: Option<String>,
}

impl EfsMetadataV1 {
    /// Parse an on-disk `$EFS` attribute buffer.
    ///
    /// `base_offset` is used only for better error messages (it labels offsets in [`ParseError`]).
    pub fn parse(buf: &[u8], base_offset: u64) -> Result<Self> {
        let mut r = Reader::with_base_offset(buf, base_offset);

        let length = r.u32_le("efs.length")?;
        let _reserved1 = r.u32_le("efs.reserved1")?;
        let efs_version = r.u32_le("efs.efs_version")?;
        let _reserved2 = r.u32_le("efs.reserved2")?;

        let efs_id = take_array::<16>(&mut r, "efs.efs_id")?;
        let efs_hash = take_array::<16>(&mut r, "efs.efs_hash")?;
        let _reserved3 = take_array::<16>(&mut r, "efs.reserved3")?;

        let ddf_offset = r.u32_le("efs.ddf_offset")? as usize;
        let drf_offset = r.u32_le("efs.drf_offset")? as usize;
        let _reserved4 = r.take("efs.reserved4", 12)?;

        // Validate reported length.
        if length as usize != buf.len() {
            // Keep this as a hard error: downstream parsing becomes ambiguous.
            return Err(crate::parse::ParseError::new(
                r.base_offset(),
                "efs.length",
                format!(
                    "metadata length mismatch: header={length} actual={}",
                    buf.len()
                ),
                "<hexdump unavailable for synthetic error>",
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "length mismatch",
                )),
            ));
        }

        let ddf = parse_key_list(buf, base_offset, ddf_offset, "efs.ddf")?;
        let drf = if drf_offset == 0 {
            Vec::new()
        } else {
            parse_key_list(buf, base_offset, drf_offset, "efs.drf")?
        };

        Ok(Self {
            length,
            efs_version,
            efs_id,
            efs_hash,
            ddf,
            drf,
        })
    }
}

fn parse_key_list(
    buf: &[u8],
    base_offset: u64,
    list_offset: usize,
    label: &'static str,
) -> Result<Vec<KeyListEntry>> {
    let mut top = Reader::with_base_offset(buf, base_offset);
    top.seek(label, list_offset)?;

    let count = top.u32_le("efs.key_list.count")? as usize;
    let mut entries = Vec::with_capacity(count);

    let mut pos = top.position();
    for _ in 0..count {
        top.seek("efs.key_list.entry", pos)?;

        // Peek the entry length (do not advance), then take the entire entry as a slice so that
        // intra-entry offsets are bounds-checked relative to the entry.
        let len_bytes = top.peek("efs.key_list.entry.length", 4)?;
        let entry_len = u32::from_le_bytes(len_bytes.try_into().expect("len=4")) as usize;

        let entry = top.take("efs.key_list.entry.bytes", entry_len)?;
        let mut r = Reader::with_base_offset(entry, base_offset.saturating_add(pos as u64));

        let length = r.u32_le("efs.key_list.entry.length")?;
        let public_key_info_offset = r.u32_le("efs.key_list.entry.public_key_info_offset")?;
        let encrypted_fek_length = r.u32_le("efs.key_list.entry.encrypted_fek_length")?;
        let encrypted_fek_offset = r.u32_le("efs.key_list.entry.encrypted_fek_offset")?;
        let flags = r.u32_le("efs.key_list.entry.flags")?;

        // Validate the KeyListEntry “Data Fields” constraints: PublicKeyInfo and EncryptedFEK must
        // be non-overlapping, contained in the data fields region, and the region must not have
        // gaps > 8 bytes (ref: `external/refs/specs/MS-EFSR.md` §2.2.2.1.2).
        {
            const DATA_FIELDS_START: usize = 20;
            let entry_base_offset = base_offset.saturating_add(pos as u64);

            let pk_off = usize::try_from(public_key_info_offset).map_err(|_| {
                ParseError::capture_from_slice(
                    entry,
                    entry_base_offset,
                    4,
                    "efs.key_list.entry.public_key_info_offset",
                    "public_key_info_offset overflow",
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "overflow")),
                )
            })?;
            if pk_off + 4 > entry.len() {
                return Err(ParseError::capture_from_slice(
                    entry,
                    entry_base_offset,
                    pk_off,
                    "efs.public_key_info.length",
                    "PublicKeyInfo length field out of bounds",
                    Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
                ));
            }
            let pk_len =
                u32::from_le_bytes(entry[pk_off..pk_off + 4].try_into().expect("len=4")) as usize;
            let pk_end = pk_off.checked_add(pk_len).ok_or_else(|| {
                ParseError::capture_from_slice(
                    entry,
                    entry_base_offset,
                    pk_off,
                    "efs.public_key_info.length",
                    "PublicKeyInfo length overflow",
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "overflow")),
                )
            })?;

            let fek_off = usize::try_from(encrypted_fek_offset).map_err(|_| {
                ParseError::capture_from_slice(
                    entry,
                    entry_base_offset,
                    12,
                    "efs.key_list.entry.encrypted_fek_offset",
                    "encrypted_fek_offset overflow",
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "overflow")),
                )
            })?;
            let fek_len = usize::try_from(encrypted_fek_length).map_err(|_| {
                ParseError::capture_from_slice(
                    entry,
                    entry_base_offset,
                    8,
                    "efs.key_list.entry.encrypted_fek_length",
                    "encrypted_fek_length overflow",
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "overflow")),
                )
            })?;
            let fek_end = fek_off.checked_add(fek_len).ok_or_else(|| {
                ParseError::capture_from_slice(
                    entry,
                    entry_base_offset,
                    fek_off,
                    "efs.key_list.entry.encrypted_fek",
                    "encrypted_fek length overflow",
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "overflow")),
                )
            })?;

            let mut ranges = vec![(pk_off, pk_end), (fek_off, fek_end)];
            validate_dense_data_fields(
                entry,
                entry_base_offset,
                "efs.key_list.entry.data_fields",
                DATA_FIELDS_START,
                entry.len(),
                &mut ranges,
            )?;
        }

        // Extract encrypted FEK bytes.
        r.seek(
            "efs.key_list.entry.encrypted_fek",
            encrypted_fek_offset as usize,
        )?;
        let encrypted_fek = r
            .take(
                "efs.key_list.entry.encrypted_fek",
                encrypted_fek_length as usize,
            )?
            .to_vec();

        // Parse Public Key Information (thumbprint + hints) for deterministic key selection.
        let pk_info = parse_entry_public_key_info(
            entry,
            base_offset.saturating_add(pos as u64),
            public_key_info_offset,
        )?;

        entries.push(KeyListEntry {
            length,
            public_key_info_offset,
            encrypted_fek_length,
            encrypted_fek_offset,
            flags,
            encrypted_fek,
            cert_thumbprint_sha1: Some(pk_info.certificate_data.thumbprint_sha1),
            owner_hint_sid: pk_info.owner_hint.map(|s| s.bytes),
            cert_container_name: pk_info.certificate_data.container_name,
            cert_provider_name: pk_info.certificate_data.provider_name,
            cert_display_name: pk_info.certificate_data.display_name,
        });

        pos = top.position();
    }

    Ok(entries)
}

fn take_array<const N: usize>(r: &mut Reader<'_>, field: &'static str) -> Result<[u8; N]> {
    let bytes = r.take(field, N)?;
    Ok(bytes.try_into().expect("slice length checked"))
}

/// Parse the PublicKeyInfo block for a key list entry.
///
/// MS-EFSR requires this to be present and well-formed for v1 metadata entries (ref:
/// `external/refs/specs/MS-EFSR.md` §2.2.2.1.2–§2.2.2.1.4).
fn parse_entry_public_key_info(
    entry: &[u8],
    entry_base_offset: u64,
    public_key_info_offset: u32,
) -> Result<PublicKeyInfo> {
    let pk_off = public_key_info_offset as usize;
    if pk_off == 0 {
        return Err(ParseError::capture_from_slice(
            entry,
            entry_base_offset,
            0,
            "efs.key_list.entry.public_key_info_offset",
            "public_key_info_offset is 0 (Public Key Information missing)",
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing public key info",
            )),
        ));
    }
    if pk_off + 4 > entry.len() {
        return Err(ParseError::capture_from_slice(
            entry,
            entry_base_offset,
            pk_off,
            "efs.public_key_info.length",
            "PublicKeyInfo length field out of bounds",
            Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
        ));
    }
    let pk_len = u32::from_le_bytes(entry[pk_off..pk_off + 4].try_into().expect("len=4")) as usize;
    if pk_len == 0 || pk_off + pk_len > entry.len() {
        return Err(ParseError::capture_from_slice(
            entry,
            entry_base_offset,
            pk_off,
            "efs.public_key_info.length",
            format!(
                "PublicKeyInfo length out of bounds: pk_len={pk_len} entry_len={}",
                entry.len()
            ),
            Box::new(io::Error::new(io::ErrorKind::InvalidData, "invalid length")),
        ));
    }
    let pk = &entry[pk_off..pk_off + pk_len];
    let info = PublicKeyInfo::parse(pk, entry_base_offset.saturating_add(pk_off as u64))?;
    Ok(info)
}

#[derive(Debug, Clone)]
struct PublicKeyInfo {
    owner_hint: Option<RpcSid>,
    certificate_data: CertificateData,
}

impl PublicKeyInfo {
    fn parse(buf: &[u8], base_offset: u64) -> Result<Self> {
        const HEADER_LEN: usize = 28;
        if buf.len() < HEADER_LEN {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                0,
                "efs.public_key_info",
                format!(
                    "PublicKeyInfo too small: len={} (< {HEADER_LEN})",
                    buf.len()
                ),
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }

        let mut r = Reader::with_base_offset(buf, base_offset);
        let length = r.u32_le("efs.public_key_info.length")? as usize;
        let owner_hint_offset = r.u32_le("efs.public_key_info.owner_hint_offset")? as usize;
        let info_type = r.u32_le("efs.public_key_info.type")?;
        let certificate_data_length =
            r.u32_le("efs.public_key_info.certificate_data_length")? as usize;
        let certificate_data_offset =
            r.u32_le("efs.public_key_info.certificate_data_offset")? as usize;
        let reserved = r.take("efs.public_key_info.reserved", 8)?;

        if length != buf.len() {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                0,
                "efs.public_key_info.length",
                format!("length mismatch: header={length} actual={}", buf.len()),
                Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "length mismatch",
                )),
            ));
        }

        // MS-EFSR shows this field as the constant 0x00000003 for the on-disk certificate form
        // (ref: `external/refs/specs/MS-EFSR.md` §2.2.2.1.3).
        if info_type != 3 {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                8,
                "efs.public_key_info.type",
                format!("unexpected PublicKeyInfo type: {info_type} (expected 3)"),
                Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected type",
                )),
            ));
        }

        if reserved != [0u8; 8] {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                20,
                "efs.public_key_info.reserved",
                "reserved field is not zero",
                Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reserved not zero",
                )),
            ));
        }

        // Validate CertificateData location.
        if certificate_data_offset < HEADER_LEN {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                16,
                "efs.public_key_info.certificate_data_offset",
                format!(
                    "certificate_data_offset points into header: {certificate_data_offset} (< {HEADER_LEN})"
                ),
                Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad offset")),
            ));
        }
        let cert_end = certificate_data_offset
            .checked_add(certificate_data_length)
            .ok_or_else(|| {
                ParseError::capture_from_slice(
                    buf,
                    base_offset,
                    12,
                    "efs.public_key_info.certificate_data_length",
                    "certificate_data length overflow",
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "overflow")),
                )
            })?;
        if cert_end > buf.len() {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                16,
                "efs.public_key_info.certificate_data_offset",
                "certificate_data out of bounds",
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }

        // Parse Owner Hint (SID) if present.
        let mut ranges: Vec<(usize, usize)> = vec![(
            certificate_data_offset,
            certificate_data_offset + certificate_data_length,
        )];
        let owner_hint = if owner_hint_offset == 0 {
            None
        } else {
            if owner_hint_offset < HEADER_LEN {
                return Err(ParseError::capture_from_slice(
                    buf,
                    base_offset,
                    4,
                    "efs.public_key_info.owner_hint_offset",
                    format!(
                        "owner_hint_offset points into header: {owner_hint_offset} (< {HEADER_LEN})"
                    ),
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad offset")),
                ));
            }
            let sid = RpcSid::parse(buf, base_offset, owner_hint_offset)?;
            let end = owner_hint_offset
                .checked_add(sid.bytes.len())
                .ok_or_else(|| {
                    ParseError::capture_from_slice(
                        buf,
                        base_offset,
                        owner_hint_offset,
                        "efs.public_key_info.owner_hint",
                        "owner hint length overflow",
                        Box::new(io::Error::new(io::ErrorKind::InvalidData, "overflow")),
                    )
                })?;
            ranges.push((owner_hint_offset, end));
            Some(sid)
        };

        // MS-EFSR requires that the “Data Fields” area is densely packed (no unused area > 8 bytes).
        // (ref: `external/refs/specs/MS-EFSR.md` §2.2.2.1.3 “Data Fields” constraints).
        validate_dense_data_fields(
            buf,
            base_offset,
            "efs.public_key_info.data_fields",
            HEADER_LEN,
            buf.len(),
            &mut ranges,
        )?;

        // Parse CertificateData as its own bounded slice.
        let cert_slice = &buf[certificate_data_offset..cert_end];
        let certificate_data = CertificateData::parse(
            cert_slice,
            base_offset.saturating_add(certificate_data_offset as u64),
        )?;

        Ok(Self {
            owner_hint,
            certificate_data,
        })
    }
}

#[derive(Debug, Clone)]
struct RpcSid {
    bytes: Vec<u8>,
}

impl RpcSid {
    fn parse(buf: &[u8], base_offset: u64, offset: usize) -> Result<Self> {
        // Minimal SID structure: revision (u8), sub_authority_count (u8),
        // identifier_authority (6 bytes), sub_authorities (4 * count bytes).
        // MS-EFSR calls this “RPC SID” / “SID in RPC marshaling format” (ref: MS‑EFSR §2.2.2.1.3).
        const MIN_LEN: usize = 8;
        if offset + MIN_LEN > buf.len() {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                offset,
                "efs.public_key_info.owner_hint",
                "owner hint SID out of bounds",
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }
        let count = buf[offset + 1] as usize;
        let len = MIN_LEN + count.saturating_mul(4);
        if offset + len > buf.len() {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                offset,
                "efs.public_key_info.owner_hint",
                "owner hint SID truncated",
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }
        Ok(Self {
            bytes: buf[offset..offset + len].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
struct CertificateData {
    thumbprint_sha1: [u8; 20],
    container_name: Option<String>,
    provider_name: Option<String>,
    display_name: Option<String>,
}

impl CertificateData {
    fn parse(buf: &[u8], base_offset: u64) -> Result<Self> {
        const HEADER_LEN: usize = 20;
        if buf.len() < HEADER_LEN {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                0,
                "efs.certificate_data",
                format!(
                    "CertificateData too small: len={} (< {HEADER_LEN})",
                    buf.len()
                ),
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }

        let mut r = Reader::with_base_offset(buf, base_offset);
        let thumbprint_offset = r.u32_le("efs.certificate_data.thumbprint_offset")? as usize;
        let thumbprint_length = r.u32_le("efs.certificate_data.thumbprint_length")? as usize;
        let container_name_offset =
            r.u32_le("efs.certificate_data.container_name_offset")? as usize;
        let provider_name_offset = r.u32_le("efs.certificate_data.provider_name_offset")? as usize;
        let display_name_offset = r.u32_le("efs.certificate_data.display_name_offset")? as usize;

        if thumbprint_offset < HEADER_LEN {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                0,
                "efs.certificate_data.thumbprint_offset",
                format!(
                    "thumbprint_offset points into header: {thumbprint_offset} (< {HEADER_LEN})"
                ),
                Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad offset")),
            ));
        }
        if thumbprint_length != 20 {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                4,
                "efs.certificate_data.thumbprint_length",
                format!("unexpected thumbprint length: {thumbprint_length} (expected 20)"),
                Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad length")),
            ));
        }
        if thumbprint_offset + 20 > buf.len() {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                thumbprint_offset,
                "efs.certificate_data.thumbprint",
                "thumbprint out of bounds",
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }

        // MS-EFSR requires ProviderName iff ContainerName.
        // (ref: `external/refs/specs/MS-EFSR.md` §2.2.2.1.4).
        if (container_name_offset == 0) != (provider_name_offset == 0) {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                8,
                "efs.certificate_data.container_name_offset",
                "container/provider presence mismatch (must either both be present or both absent)",
                Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad offsets")),
            ));
        }

        let thumbprint_sha1: [u8; 20] = buf[thumbprint_offset..thumbprint_offset + 20]
            .try_into()
            .expect("len=20");

        let mut ranges: Vec<(usize, usize)> = vec![(thumbprint_offset, thumbprint_offset + 20)];

        let container_name = if container_name_offset == 0 {
            None
        } else {
            if container_name_offset < HEADER_LEN {
                return Err(ParseError::capture_from_slice(
                    buf,
                    base_offset,
                    8,
                    "efs.certificate_data.container_name_offset",
                    format!(
                        "container_name_offset points into header: {container_name_offset} (< {HEADER_LEN})"
                    ),
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad offset")),
                ));
            }
            let (s, len) = parse_utf16_nul_terminated(
                buf,
                base_offset,
                container_name_offset,
                "efs.certificate_data.container_name",
            )?;
            ranges.push((container_name_offset, container_name_offset + len));
            Some(s)
        };

        let provider_name = if provider_name_offset == 0 {
            None
        } else {
            if provider_name_offset < HEADER_LEN {
                return Err(ParseError::capture_from_slice(
                    buf,
                    base_offset,
                    12,
                    "efs.certificate_data.provider_name_offset",
                    format!(
                        "provider_name_offset points into header: {provider_name_offset} (< {HEADER_LEN})"
                    ),
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad offset")),
                ));
            }
            let (s, len) = parse_utf16_nul_terminated(
                buf,
                base_offset,
                provider_name_offset,
                "efs.certificate_data.provider_name",
            )?;
            ranges.push((provider_name_offset, provider_name_offset + len));
            Some(s)
        };

        let display_name = if display_name_offset == 0 {
            None
        } else {
            if display_name_offset < HEADER_LEN {
                return Err(ParseError::capture_from_slice(
                    buf,
                    base_offset,
                    16,
                    "efs.certificate_data.display_name_offset",
                    format!(
                        "display_name_offset points into header: {display_name_offset} (< {HEADER_LEN})"
                    ),
                    Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad offset")),
                ));
            }
            let (s, len) = parse_utf16_nul_terminated(
                buf,
                base_offset,
                display_name_offset,
                "efs.certificate_data.display_name",
            )?;
            ranges.push((display_name_offset, display_name_offset + len));
            Some(s)
        };

        validate_dense_data_fields(
            buf,
            base_offset,
            "efs.certificate_data.data_fields",
            HEADER_LEN,
            buf.len(),
            &mut ranges,
        )?;

        Ok(Self {
            thumbprint_sha1,
            container_name,
            provider_name,
            display_name,
        })
    }
}

fn parse_utf16_nul_terminated(
    buf: &[u8],
    base_offset: u64,
    offset: usize,
    field: &'static str,
) -> Result<(String, usize)> {
    if offset >= buf.len() {
        return Err(ParseError::capture_from_slice(
            buf,
            base_offset,
            offset,
            field,
            "string offset out of bounds",
            Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
        ));
    }
    if !offset.is_multiple_of(2) {
        return Err(ParseError::capture_from_slice(
            buf,
            base_offset,
            offset,
            field,
            "UTF-16LE string offset is not 2-byte aligned",
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "unaligned utf16",
            )),
        ));
    }

    let mut u16s: Vec<u16> = Vec::new();
    let mut pos = offset;
    loop {
        if pos + 2 > buf.len() {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                pos,
                field,
                "unterminated UTF-16LE string",
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }
        let w = u16::from_le_bytes(buf[pos..pos + 2].try_into().expect("len=2"));
        pos += 2;
        if w == 0 {
            break;
        }
        u16s.push(w);
    }

    let s: String = std::char::decode_utf16(u16s)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();

    Ok((s, pos - offset))
}

fn validate_dense_data_fields(
    buf: &[u8],
    base_offset: u64,
    field: &'static str,
    data_fields_start: usize,
    data_fields_end: usize,
    ranges: &mut [(usize, usize)],
) -> Result<()> {
    if data_fields_start > data_fields_end || data_fields_end > buf.len() {
        return Err(ParseError::capture_from_slice(
            buf,
            base_offset,
            data_fields_start,
            field,
            "invalid data fields bounds",
            Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad bounds")),
        ));
    }

    // Normalize + sort.
    for (s, e) in ranges.iter_mut() {
        if *e < *s {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                *s,
                field,
                "range end before start",
                Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad range")),
            ));
        }
    }
    ranges.sort_by_key(|(s, _)| *s);

    // Bounds + containment.
    for (s, e) in ranges.iter() {
        if *s < data_fields_start {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                *s,
                field,
                format!(
                    "sub-field starts before Data Fields: start={s} data_fields_start={data_fields_start}"
                ),
                Box::new(io::Error::new(io::ErrorKind::InvalidData, "bad offset")),
            ));
        }
        if *e > data_fields_end {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                *s,
                field,
                "sub-field extends past Data Fields end",
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }
    }

    // Non-overlap + “no unused area > 8 bytes” (MS-EFSR invariant for Data Fields).
    let mut prev_end = data_fields_start;
    for (s, e) in ranges.iter() {
        if *s < prev_end {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                *s,
                field,
                "sub-fields overlap",
                Box::new(io::Error::new(io::ErrorKind::InvalidData, "overlap")),
            ));
        }
        let gap = s.saturating_sub(prev_end);
        if gap > 8 {
            return Err(ParseError::capture_from_slice(
                buf,
                base_offset,
                prev_end,
                field,
                format!("unused gap too large: gap={gap} (max=8)"),
                Box::new(io::Error::new(io::ErrorKind::InvalidData, "gap too large")),
            ));
        }
        prev_end = *e;
    }

    let tail_gap = data_fields_end.saturating_sub(prev_end);
    if tail_gap > 8 {
        return Err(ParseError::capture_from_slice(
            buf,
            base_offset,
            prev_end,
            field,
            format!("trailing unused gap too large: gap={tail_gap} (max=8)"),
            Box::new(io::Error::new(io::ErrorKind::InvalidData, "gap too large")),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le32(x: u32) -> [u8; 4] {
        x.to_le_bytes()
    }

    fn utf16le_nul(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn build_certificate_data(
        thumbprint: [u8; 20],
        container: Option<&str>,
        provider: Option<&str>,
        display: Option<&str>,
    ) -> Vec<u8> {
        // CertificateData header is 5 * u32.
        let header_len = 20usize;
        let mut buf = vec![0u8; header_len];

        // Place thumbprint immediately after the header (no gaps).
        let mut cursor = header_len;
        let thumb_off = cursor;
        let thumb_len = 20usize;
        buf.extend_from_slice(&thumbprint);
        cursor += thumb_len;

        let (container_off, container_bytes) = if let Some(s) = container {
            let bytes = utf16le_nul(s);
            let off = cursor;
            buf.extend_from_slice(&bytes);
            cursor += bytes.len();
            (off, Some(bytes))
        } else {
            (0usize, None)
        };

        let (provider_off, _provider_bytes) = if let Some(s) = provider {
            let bytes = utf16le_nul(s);
            let off = cursor;
            buf.extend_from_slice(&bytes);
            cursor += bytes.len();
            (off, Some(bytes))
        } else {
            (0usize, None)
        };

        let (display_off, _display_bytes) = if let Some(s) = display {
            let bytes = utf16le_nul(s);
            let off = cursor;
            buf.extend_from_slice(&bytes);
            (off, Some(bytes))
        } else {
            (0usize, None)
        };

        // Write header fields.
        buf[0..4].copy_from_slice(&le32(thumb_off as u32));
        buf[4..8].copy_from_slice(&le32(thumb_len as u32));
        buf[8..12].copy_from_slice(&le32(container_off as u32));
        buf[12..16].copy_from_slice(&le32(provider_off as u32));
        buf[16..20].copy_from_slice(&le32(display_off as u32));

        // Enforce the MS-EFSR constraint in the builder: if one of container/provider is present,
        // the other must be present too (ref: MS-EFSR §2.2.2.1.4).
        if (container_bytes.is_some() as u8) != (provider.is_some() as u8) {
            panic!("invalid test builder usage: container/provider presence must match");
        }

        buf
    }

    fn build_public_key_info(cert_data: &[u8], owner_hint: Option<&[u8]>) -> Vec<u8> {
        // PublicKeyInfo header is:
        // - length (u32)
        // - owner_hint_offset (u32)
        // - type (u32) = 3
        // - cert_data_len (u32)
        // - cert_data_offset (u32)
        // - reserved (8 bytes)
        let header_len = 28usize;
        let mut buf = vec![0u8; header_len];

        let mut cursor = header_len;
        let owner_off = if let Some(bytes) = owner_hint {
            let off = cursor;
            buf.extend_from_slice(bytes);
            cursor += bytes.len();
            off
        } else {
            0usize
        };

        let cert_off = cursor;
        buf.extend_from_slice(cert_data);
        cursor += cert_data.len();

        let total_len = cursor;
        buf[0..4].copy_from_slice(&le32(total_len as u32));
        buf[4..8].copy_from_slice(&le32(owner_off as u32));
        buf[8..12].copy_from_slice(&le32(3));
        buf[12..16].copy_from_slice(&le32(cert_data.len() as u32));
        buf[16..20].copy_from_slice(&le32(cert_off as u32));
        // reserved is already zero
        buf
    }

    #[test]
    fn certificate_data_parses_thumbprint() {
        let tp = [0x11u8; 20];
        let buf = build_certificate_data(tp, None, None, None);
        let parsed = CertificateData::parse(&buf, 0).unwrap();
        assert_eq!(parsed.thumbprint_sha1, tp);
        assert!(parsed.container_name.is_none());
        assert!(parsed.provider_name.is_none());
    }

    #[test]
    fn certificate_data_parses_utf16_strings() {
        let tp = [0x22u8; 20];
        let buf = build_certificate_data(tp, Some("cont"), Some("prov"), Some("disp"));
        let parsed = CertificateData::parse(&buf, 0).unwrap();
        assert_eq!(parsed.thumbprint_sha1, tp);
        assert_eq!(parsed.container_name.as_deref(), Some("cont"));
        assert_eq!(parsed.provider_name.as_deref(), Some("prov"));
        assert_eq!(parsed.display_name.as_deref(), Some("disp"));
    }

    #[test]
    fn certificate_data_rejects_provider_without_container() {
        let tp = [0x33u8; 20];

        // Build a buffer that violates MS-EFSR: provider present but container absent.
        let mut buf = build_certificate_data(tp, None, None, None);
        // Force provider offset to a non-zero value (points to thumbprint, but that's fine for a
        // negative test).
        buf[12..16].copy_from_slice(&le32(20));
        assert!(CertificateData::parse(&buf, 0).is_err());
    }

    #[test]
    fn certificate_data_rejects_thumbprint_length_not_20() {
        let tp = [0x66u8; 20];
        let mut buf = build_certificate_data(tp, None, None, None);
        buf[4..8].copy_from_slice(&le32(19));
        assert!(CertificateData::parse(&buf, 0).is_err());
    }

    #[test]
    fn certificate_data_rejects_large_unused_gap_in_data_fields() {
        // Header (20) + padding gap (16) + thumbprint (20).
        let mut buf = vec![0u8; 20 + 16 + 20];
        let thumb_off = 36u32;
        buf[0..4].copy_from_slice(&le32(thumb_off));
        buf[4..8].copy_from_slice(&le32(20));
        // container/provider/display offsets are 0
        // Fill thumbprint bytes.
        for b in &mut buf[thumb_off as usize..thumb_off as usize + 20] {
            *b = 0x77;
        }
        assert!(CertificateData::parse(&buf, 0).is_err());
    }

    #[test]
    fn public_key_info_parses_certificate_data() {
        let tp = [0x44u8; 20];
        let cd = build_certificate_data(tp, None, None, None);
        let pk = build_public_key_info(&cd, None);
        let parsed = PublicKeyInfo::parse(&pk, 0).unwrap();
        assert_eq!(parsed.certificate_data.thumbprint_sha1, tp);
        assert!(parsed.owner_hint.is_none());
    }

    #[test]
    fn public_key_info_rejects_large_unused_gap_in_data_fields() {
        let tp = [0x88u8; 20];
        let cd = build_certificate_data(tp, None, None, None);

        // PublicKeyInfo header (28) + padding gap (12) + cert data.
        let header_len = 28usize;
        let gap = 12usize;
        let cert_off = header_len + gap;
        let total_len = cert_off + cd.len();

        let mut buf = vec![0u8; total_len];
        buf[0..4].copy_from_slice(&le32(total_len as u32));
        buf[4..8].copy_from_slice(&le32(0)); // no owner hint
        buf[8..12].copy_from_slice(&le32(3));
        buf[12..16].copy_from_slice(&le32(cd.len() as u32));
        buf[16..20].copy_from_slice(&le32(cert_off as u32));
        // reserved is 0
        buf[cert_off..cert_off + cd.len()].copy_from_slice(&cd);

        assert!(PublicKeyInfo::parse(&buf, 0).is_err());
    }

    #[test]
    fn metadata_key_list_entry_extracts_thumbprint() {
        let tp = [0x55u8; 20];
        let cd = build_certificate_data(tp, None, None, None);
        let pk = build_public_key_info(&cd, None);
        let encrypted_fek = vec![0xAAu8; 128];

        let entry_header_len = 20usize;
        let pk_off = entry_header_len;
        let fek_off = pk_off + pk.len();
        let entry_len = fek_off + encrypted_fek.len();

        let mut entry = Vec::with_capacity(entry_len);
        entry.extend_from_slice(&le32(entry_len as u32));
        entry.extend_from_slice(&le32(pk_off as u32));
        entry.extend_from_slice(&le32(encrypted_fek.len() as u32));
        entry.extend_from_slice(&le32(fek_off as u32));
        entry.extend_from_slice(&le32(0)); // flags=0 (RSA)
        entry.extend_from_slice(&pk);
        entry.extend_from_slice(&encrypted_fek);

        // Build full EFS metadata with a single DDF entry.
        let header_len = 84usize;
        let ddf_offset = header_len;

        let mut meta = vec![0u8; header_len];
        // Write DDF offset and DRF offset in the header.
        meta[64..68].copy_from_slice(&le32(ddf_offset as u32));
        meta[68..72].copy_from_slice(&le32(0)); // no DRF

        // DDF key list structure: count + entries.
        meta.extend_from_slice(&le32(1));
        meta.extend_from_slice(&entry);

        // Write length field.
        let total_len = meta.len() as u32;
        meta[0..4].copy_from_slice(&le32(total_len));
        // Set efs_version=2.
        meta[8..12].copy_from_slice(&le32(2));

        let parsed = EfsMetadataV1::parse(&meta, 0).unwrap();
        assert_eq!(parsed.ddf.len(), 1);
        assert_eq!(parsed.ddf[0].encrypted_fek.len(), 128);
        assert_eq!(parsed.ddf[0].cert_thumbprint_sha1, Some(tp));
    }

    #[test]
    fn metadata_key_list_entry_rejects_large_unused_gap_between_fields() {
        let tp = [0x99u8; 20];
        let cd = build_certificate_data(tp, None, None, None);
        let pk = build_public_key_info(&cd, None);
        let encrypted_fek = vec![0xBBu8; 128];

        let entry_header_len = 20usize;
        let pk_off = entry_header_len;
        let gap = 16usize; // > 8, should be rejected
        let fek_off = pk_off + pk.len() + gap;
        let entry_len = fek_off + encrypted_fek.len();

        let mut entry = Vec::with_capacity(entry_len);
        entry.extend_from_slice(&le32(entry_len as u32));
        entry.extend_from_slice(&le32(pk_off as u32));
        entry.extend_from_slice(&le32(encrypted_fek.len() as u32));
        entry.extend_from_slice(&le32(fek_off as u32));
        entry.extend_from_slice(&le32(0)); // flags=0 (RSA)
        entry.extend_from_slice(&pk);
        entry.extend_from_slice(&vec![0u8; gap]);
        entry.extend_from_slice(&encrypted_fek);

        let header_len = 84usize;
        let ddf_offset = header_len;

        let mut meta = vec![0u8; header_len];
        meta[64..68].copy_from_slice(&le32(ddf_offset as u32));
        meta[68..72].copy_from_slice(&le32(0)); // no DRF
        meta.extend_from_slice(&le32(1));
        meta.extend_from_slice(&entry);
        let total_len = meta.len() as u32;
        meta[0..4].copy_from_slice(&le32(total_len));
        meta[8..12].copy_from_slice(&le32(2));

        assert!(EfsMetadataV1::parse(&meta, 0).is_err());
    }
}
