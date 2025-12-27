# AFFLIBv3 parity checklist

Human-maintained checklist tracking feature parity between this crate and the `AFFLIBv3` reference
implementation.

Reference commit pinned in this repository:

- `external/refs/repos/sshock__AFFLIBv3.commit`

## Scope / notes

- This crate is **read-only** and exposes a Rust-native API (`forensic_image::ReadAt` +
  `read_segment()`), not the full `AFFILE*` stream/DB API from AFFLIB.
- `[x]` means supported in this crate today; `[ ]` means not supported (or only partially
  supported; noted inline).
- Implementation note: the current AFF1 backend reads the entire `.aff` file into memory; AFFLIB
  is streaming + page-cache based.

## Container identification & open semantics (AFFLIB vnodes)

- AFFLIB’s vnode probe order matters (from `lib/afflib.cpp`): `s3://` (if enabled) → AFD → AFM → AFF →
  (VMDK/DMG/SPARSEIMAGE if enabled) → split-raw → raw.

- [x] AFF1 (`.aff`)
  - AFFLIB identify: file header `AFF10\r\n\0`, or (for non-existent/empty files) extension `.aff`
  - This crate: sniff header when possible; otherwise uses extension (`.aff`)
- [x] AFM (`.afm`)
  - AFFLIB identify: extension `.afm`
  - This crate: extension `.afm` (or header sniff + extension disambiguation)
- [x] AFD directory container
  - AFFLIB identify: a directory whose name ends in `.afd`
  - This crate: any directory containing `file_###.aff` entries (more permissive than AFFLIB)
- [ ] RAW passthrough (`.raw`, `.iso`, block devices)
- [ ] RAW passthrough details: AFFLIB fakes `pagesize`/`imagesize`/`sectorsize`/`devicesectors` segments
      even though raw has no segment store
- [ ] Split-raw standalone (`.000` / `.001` / `.A00`… without `.afm`)
- [ ] Split-raw identify in AFFLIB: `.000` / `.001` / `.aaa` / `.AAA` (first file of a set)
- [ ] `s3://` vnode (S3 object store)
- [ ] QEMU vnodes: VMDK (`.vmdk`), DMG (`.dmg`), SPARSEIMAGE (`.sparseimage`)
- [ ] URL handling (`file://...`)

## Segment database API (AFFLIB name/value store)

- [x] List segment names (`segment_names()`)
  - [ ] Virtualize encrypted names (hide `*/aes256` and expose the base name; AFFLIB `af_get_next_seg()` strips the suffix when auto-decrypt is enabled) — not implemented
  - [ ] AFM: include virtual `page<N>` entries in the listing (AFFLIB enumerates them via split-raw) — not implemented (we intentionally list metadata only)
  - [ ] Hide 0-length segment names (AFFLIB uses `AF_IGNORE == ""` to mark holes) — not implemented
- [x] Read a segment by name (`read_segment(name)`)
  - [x] Auto-decrypt `name/aes256` into `name` when a key is available (AFFLIB checks encrypted first)
- [ ] Cursor-based iteration (`af_get_next_seg` / `af_rewind_seg`)
- [ ] Write/update/delete segments (`af_update_seg`, `af_update_segf`, `af_del_seg`)
- [ ] Quadword helpers (`af_get_segq`, `af_update_segq`) — callers can parse 8-byte `aff_quad` manually

## Byte access API

- [x] Random-access reads via `forensic_image::ReadAt`
- [ ] Stream-style reads/seeks (`af_read`, `af_seek`, `af_tell`, `af_eof`)
- [ ] Stream-style writes (`af_write`) (crate is read-only)

## Error model / diagnostics

- [x] Missing segment → `Ok(None)` (vs AFFLIB `AF_ERROR_EOF`/`ENOENT`-style conventions)
- [ ] Distinguish “segment exists but buffer too small” (`AF_ERROR_DATASMALL`) — not applicable (Rust allocates `Vec`)
- [ ] Repair tooling (`affix`, `affrecover`) — not implemented

## Options & environment-variable behavior

- [x] Auto-decrypt toggle (AFFLIB `AF_OPTION_AUTO_DECRYPT`) via `AffOpenOptions.auto_decrypt`
- [ ] Auto-encrypt toggle (AFFLIB `AF_OPTION_AUTO_ENCRYPT`) — not implemented (read-only)
- [x] Page cache sizing (AFFLIB `af_set_cachesize` / `AFFLIB_CACHE_PAGES`) via `AffOpenOptions.page_cache_pages`
- [ ] AFFLIB open flags (`AF_OPEN_PRIMITIVE`, `AF_HALF_OPEN`, `AF_NO_CRYPTO`, `AF_BADBLOCK_FILL`)
- [ ] AFFLIB tracing/debug env vars (`AFFLIB_TRACEFILE`, `AFFLIB_CACHE_DEBUG`, `AFFLIB_CACHE_STATS`)
- [ ] AFFLIB passphrase env vars (`AFFLIB_PASSPHRASE`, `AFFLIB_PASSPHRASE_FILE`, `AFFLIB_PASSPHRASE_FD`)
- [ ] AFFLIB signing/sealing env vars (e.g. `AFFLIB_PEM_SIGNING_PASSPHRASE`, `AFFLIB_DECRYPTING_PRIVATE_KEYFILE`)

## Container metadata / stats

- [x] Basic info: container kind + `len()` + `page_size()` (subset of AFFLIB `af_vstat`)
- [ ] Full vnode stats (`af_vstat` fields like `segment_count_total`, `page_count_total`,
      `segment_count_signed`, `segment_count_encrypted`, etc.)
- [ ] `af_stats()` performance counters (cache hit/miss, bytes copied, pages compressed, …)

## Well-known segment names (AFFLIB constants)

The crate exposes most metadata as **raw segment bytes** via `read_segment()` (when present in the
container). Only a small subset currently affects behavior (`len()`, page size, crypto, page
decompression).

### Structural / housekeeping

- [ ] Ignore segments (`AF_IGNORE == ""`, 0-length name) — AFFLIB uses these as “holes”; this crate currently surfaces them as a real segment name `""`
- [ ] Segment name length limit (`AF_MAX_NAME_LEN == 64`) — not enforced in this crate

### Container type / provenance

- [x] `aff_file_type` (`"AFF"|"AFM"|"AFD"`) — exposed only (this crate does not use it for detection)
- [x] `afflib_version` — exposed only
- [x] `creator` — exposed only
- [x] `dir` (directory segment) — exposed only
- [x] `batch_name`, `batch_item_name` — exposed only

### Image geometry / device

- [x] `pagesize` (value stored in `arg`, `data_len == 0`) — parsed
- [x] `segsize` (deprecated alias for `pagesize`) — parsed
- [x] `imagesize` (8 bytes `aff_quad`) — parsed
- [ ] `AF_SEG_QUADWORD` flag (`0x0002`) for 8-byte segments — not used (we parse by segment name + length)
- [x] `sectorsize` (value stored in `arg`) — exposed only (not interpreted)
- [x] `devicesectors` (8 bytes `aff_quad`) — exposed only (not interpreted)
- [x] `badsectors` — exposed only
- [x] `badflag` — exposed only
- [x] `blanksectors` (8 bytes; count of all-NUL sectors) — exposed only

### Data pages

- [x] `page<N>` segments (logical disk bytes by page index)
- [x] Deprecated `seg<N>` page naming
- [x] Page compression flags in `arg` (`AF_PAGE_COMPRESSED`, `AF_PAGE_COMP_ALG_*`)
  - [x] ZLIB (`AF_PAGE_COMP_ALG_ZLIB`)
  - [x] LZMA (`AF_PAGE_COMP_ALG_LZMA`, feature `lzma`)
  - [x] ZERO (`AF_PAGE_COMP_ALG_ZERO`)

### Hashes & parity (as segments)

- [x] Image hashes: `md5`, `sha1`, `sha256` — exposed only (not verified)
- [x] Piecewise hashes: `page<N>_md5`, `page<N>_sha1`, `page<N>_sha256` — exposed only (not verified)
- [ ] Auto-generate piecewise hashes (`AF_OPTION_PIECEWISE_*`) — not implemented (read-only)
- [ ] Verify piecewise hashes (AFFLIB tools: `affinfo -v`) — not implemented
- [x] `parity0` (parity page) — exposed only
- [x] `parity0/sha256` — verified when present (treated like any other `*/sha256` signature segment)
- [ ] Recover broken pages using parity (`affrecover`) — not implemented

### AFM / split-raw metadata

- [x] `raw_image_file_extension` (3 bytes, e.g. `"000"`) — required for AFM open
- [x] `pages_per_raw_image_file` (8-byte quad) — exposed only (not used to drive splitting)

### Encryption & signatures

- [x] Encrypted segments suffix: `*/aes256` — auto-decrypted on read when key is available
- [x] Passphrase key segment: `affkey_aes256` — used for key derivation
- [x] Public-key sealed key segments: `affkey_evp%d` — used for unsealing (rev-1 only)
- [x] Signature suffix: `*/sha256` — verified (MODE0 + MODE1)
- [x] Signing certificate: `cert-sha256` (PEM X.509) — used for signature verification
- [ ] Chain-of-custody BOM segments: `affbom%d` — not parsed/verified
- [ ] BOM XML schema elements (`affbom`, `date`, `signingcert`, `segmenthash`) — not parsed/verified

### Acquisition metadata (common AFFLIB segment names)

- [x] Exposed (no typed parsing): `case_num`, `image_gid`, `acquisition_iso_country`,
  `acquisition_commandline`, `acquisition_date`, `acquisition_notes`, `acquisition_device`,
  `acquisition_seconds` (stored in `arg`), `acquisition_tecnician`, `acquisition_macaddr`,
  `acquisition_dmesg`

### Device metadata (common AFFLIB segment names)

- [x] Exposed (no typed parsing): `device_manufacturer`, `device_model`, `device_sn`, `device_firmware`,
  `device_source`, `cylinders`, `heads`, `sectors_per_track`, `lbasize`, `hpa_present`, `dco_present`,
  `location_in_computer`, `device_capabilities`

## Readers

### AFF1 — `.aff`

- [x] AFF1 header detection (`AFF10\r\n\0`)
- [x] Segment framing (`AFF\0` + headers + name + data + `ATT\0` + segment length)
- [x] Segment TOC scan (last-write-wins semantics for duplicate segment names)
- [x] `pagesize` / deprecated `segsize` (value in `arg`, `data_len == 0`)
- [x] `imagesize` parsing (AFFLIB `aff_quad` encoding)
- [x] `imagesize` inference when missing (mirrors AFFLIB `af_read_sizes`)
  - [ ] Prefer encrypted `imagesize/aes256` when a key is available — not implemented (open happens before the crypto wrapper is applied)
- [x] Page naming: `page<N>` and deprecated `seg<N>`
- [x] Sparse/missing pages read as zero-filled bytes
- [ ] Badblock fill for missing/sparse pages (`AF_BADBLOCK_FILL` / `badflag`) — not implemented
- [x] Page compression: none (plain page segment)
- [x] Page compression: zlib (`AF_PAGE_COMP_ALG_ZLIB`)
- [x] Page compression: ZERO (`AF_PAGE_COMP_ALG_ZERO`)
- [x] Page compression: LZMA (`AF_PAGE_COMP_ALG_LZMA`) — behind feature `lzma`
- [ ] Page compression: BZIP (`AF_PAGE_COMP_ALG_BZIP`) — not implemented in AFFLIB either

### AFD — directory container

- [x] Discover `file_###.aff` entries
- [x] Page map across directory (first file containing a page wins)
- [x] Global `imagesize` = max across subfiles (AFFLIB `afd_vstat` semantics)
- [x] Read pages by index even if a subfile `imagesize` is smaller (AFD quirk)
- [x] Missing pages read as zero-filled bytes
- [x] Segment lookup: first subfile containing the segment wins

### AFM — `.afm` metadata + split-raw payload

- [x] Metadata stored as AFF1 segments in `.afm`
- [x] Split-raw payload discovery by incrementing 3-char extension (`.000`..`.999`, `.A00`..)
- [x] Read disk bytes from raw payload via `ReadAt`
- [x] Synthetic `page<N>` segments backed by raw payload
- [ ] Use/validate `pages_per_raw_image_file` to drive split sizing and sanity checks — partial (we infer
      split boundaries from file sizes)
  - AFFLIB behavior: if `pages_per_raw_image_file` is missing/0-length, assume “not split”; otherwise
    split size is `pagesize * pages_per_raw_image_file` and additional consistency checks apply.

### Other AFFLIB container kinds

- [ ] RAW images (non-AFF)
- [ ] Standalone split-raw (without an `.afm` metadata file)
- [ ] AFFLIB optional backends (S3/VMDK/DMG/SPARSEIMAGE, etc.)

## Crypto / signatures

### AES-256 encryption (`*/aes256`)

- [x] Auto-decrypt `*/aes256` segments on read (feature `crypto`, default)
- [x] Derive AES-256 key from `affkey_aes256` using passphrase (`SHA256(passphrase)`)
  - [x] Accept legacy AFFLIB packing bug sizes (52/56 bytes)
- [x] Unseal `affkey_evp%d` using an RSA PEM private key (rev-1 only)
- [x] AES-256-CBC decrypt semantics incl. AFFLIB “extra bytes” + padding trimming
- [ ] Auto-encrypt on write (`AF_OPTION_AUTO_ENCRYPT` / `af_update_segf`) — not implemented (read-only)
- [ ] Passphrase establish/change APIs (`af_establish_aes_passphrase`, `af_change_aes_passphrase`, …)

### SHA-256 signatures (`*/sha256`, `cert-sha256`)

- [x] Verify `*/sha256` signature segments (feature `crypto`, default)
  - [x] MODE0: `(segname + NUL + arg_be + segment_data)`
  - [x] MODE1: `(segname + NUL + 0 + uncompressed page bytes)` (no implicit zero-padding)
- [ ] Write signatures (`af_set_sign_files`, `af_sign_seg*`, `af_sign_all_unsigned_segments`)
- [ ] Chain-of-custody / BOM segments (`affbom%d`) generation/verification

## Integrity metadata & hashes

- [ ] Piecewise page hash segments (`page<N>_md5`, `_sha1`, `_sha256`) generation
- [ ] Piecewise page hash verification / key validation via page hashes
- [ ] Image-level hash segments (`md5`, `sha1`, `sha256`) generation/verification
- [ ] `parity0` generation/verification
- [ ] Bad-sector related metadata (`badflag`, `badsectors`, `blanksectors`)

## Writers

- [ ] AFF1 writer (`.aff`)
- [ ] AFD writer
- [ ] AFM writer (metadata + split-raw)
- [ ] Compression on write (zlib/lzma/zero)
  - [ ] ZERO compression for all-zero pages (AFFLIB tries ZERO first)
  - [ ] ZLIB compression level control
  - [ ] LZMA compression (AFFLIB uses a fixed level in code; tool UX exposes `-L`)
- [ ] Image-level hashes (`md5`, `sha1`, `sha256`)
- [ ] Default page size behavior (`AFF_DEFAULT_PAGESIZE` ≈ 16MiB if not set before first write)
- [ ] Split sizing / maxsize (`af_set_maxsize`) for split-raw and/or multi-file workflows
- [ ] Segment signing / sealing

## CLI parity (AFFLIB tools)

- [x] `affcat` (partial): `aff-cat`
  - [x] Stream logical image bytes to stdout
  - [x] Offset/length selection
  - [x] Decrypt with passphrase / unseal keyfile (via `AffOpenOptions`)
  - [ ] Segment output mode (`-s <name>`)
  - [ ] Page/sector addressing modes (`-p`, `-S`)
  - [ ] Missing-page reporting / skipping semantics (`-n` / `-q`)
  - [ ] Output badflag for bad blocks (`-b`)
  - [ ] Range syntax (`-r offset:count`), long listing (`-L`)
- [x] `affinfo` (very partial): `aff-info`
  - [x] Print kind/len/pagesize and segment count
  - [x] List segment names
  - [ ] Segment previews / formatting heuristics (hex vs ascii)
  - [ ] Filter segments (`-s`), suppress data pages by default, wide output
  - [ ] Validate image hashes (`-m`/`-S`) and page hashes (`-v`)
  - [ ] Identify-only mode (`-i`)
- [x] `affverify` (subset): `aff-verify`
  - [x] Verify `*/sha256` signature segments (MODE0 + MODE1)
  - [ ] Verbose / “print all segments” modes matching AFFLIB
- [ ] `affsign` (sign existing image + write BOM segments)
- [ ] `affcrypto` (encrypt/decrypt, change passphrase, sealing/unsealing, password cracking helpers)
- [ ] `affsegment` (create/update/delete segments; quad/hex output)
- [ ] `affconvert` (raw↔aff conversions, recompress, AFD splitting, gzip/bzip2 probing)
- [ ] `affcopy` (copy/reorder/preen + (re)compress + optional signing + S3 copy)
- [ ] `affcompare` (compare images/dirs, show differing sectors, S3 existence checks)
- [ ] `affxml` (metadata/stats as XML)
- [ ] `affdiskprint` (diskprint structure generation/verification)
- [ ] `affstats` (stats derived from metadata or by scanning)
- [ ] `affix` (repair corruption / ensure GID)
- [ ] `affrecover` (recover pages using parity)
- [ ] `affuse` (FUSE mount)

