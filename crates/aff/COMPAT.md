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

## Container identification & open semantics (AFFLIB vnodes)

- [x] AFF1 (`.aff`)
- [x] AFM (`.afm`)
- [x] AFD directory container (`file_###.aff` entries)
  - Note: AFFLIB’s vnode identification expects directories ending in `.afd`; this crate is more
    permissive and treats any directory with `file_###.aff` entries as an AFD container.
- [ ] RAW passthrough (`.raw`, `.iso`, block devices)
- [ ] Split-raw standalone (`.000` / `.001` / `.A00`… without `.afm`)
- [ ] `s3://` vnode (S3 object store)
- [ ] QEMU vnodes: VMDK (`.vmdk`), DMG (`.dmg`), SPARSEIMAGE (`.sparseimage`)
- [ ] URL handling (`file://...`)

## Segment database API (AFFLIB name/value store)

- [x] List segment names (`segment_names()`)
  - [ ] Virtualize encrypted names (hide `*/aes256` and expose the base name; AFFLIB `af_get_next_seg()` strips the suffix when auto-decrypt is enabled) — not implemented
- [x] Read a segment by name (`read_segment(name)`)
  - [x] Auto-decrypt `name/aes256` into `name` when a key is available (AFFLIB checks encrypted first)
- [ ] Cursor-based iteration (`af_get_next_seg` / `af_rewind_seg`)
- [ ] Write/update/delete segments (`af_update_seg`, `af_update_segf`, `af_del_seg`)
- [ ] Quadword helpers (`af_get_segq`, `af_update_segq`) — callers can parse 8-byte `aff_quad` manually

## Byte access API

- [x] Random-access reads via `forensic_image::ReadAt`
- [ ] Stream-style reads/seeks (`af_read`, `af_seek`, `af_tell`, `af_eof`)
- [ ] Stream-style writes (`af_write`) (crate is read-only)

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
- [ ] Image-level hashes (`md5`, `sha1`, `sha256`)
- [ ] Segment signing / sealing

## CLI parity (AFFLIB tools)

- [x] `affcat` equivalent (`aff-cat`)
- [x] `affinfo` equivalent (`aff-info`)
- [x] `affverify` equivalent subset (`aff-verify` for `/sha256`)
- [ ] Other AFFLIB tools (`affcopy`, `affconvert`, `affcompare`, `affdiskprint`, `affxml`, `affsegment`,
      `affcrypto`, `affsign`, `affstats`, `affrecover`, `aff_bom`, …)

