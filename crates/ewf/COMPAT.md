# libewf parity checklist

Human-maintained checklist tracking feature parity between this crate and the `libewf` reference
implementation.

Reference commit pinned in this repository:

- `external/refs/repos/libyal__libewf.commit`

## Readers

### EWF1 (EVF) — `.E01` / `.S01`

- [x] Segment discovery (`.E01`..`.E99`, `.EAA`..; same for `.S01`)
- [x] `table` and `table2`
- [x] Multiple `sectors` + `table*` groups within a segment
- [x] v1 wraparound offset decoding (2 GiB wrap encoding)
- [x] Chunk decompression (zlib/deflate)
- [x] Uncompressed chunks
- [x] Chunk Adler32 verification
- [ ] EnCase 5/6 metadata edge-cases (header/header2 variants) — partial
- [x] EWF1 “sessions” section (optical media) — run parsing (used for `ewfinfo` output)

### EWF2 (EVF2) — `.Ex01`

- [x] Segment discovery (`.Ex01`..`.Ex99`, `.ExAA`..)
- [x] Reverse section descriptor chain parsing
- [x] Device information / case data (compressed UTF-16 object strings)
- [x] Sector data + sector tables
- [x] Zlib chunk decompression
- [x] Pattern fill / empty-block optimization
- [ ] bzip2 compression
- [ ] encryption
- [ ] Section MD5 integrity hash verification (descriptor flag) — partial

### Logical Evidence Files (LEF) — `.L01` / `.Lx01`

- [x] L01: parse `ltree` and map file extents → media-data offsets (basic `rec` + `entry`)
- [x] Lx01: parse “single files data” section (0x20) (basic `rec` + `entry`)
- [x] Read file contents by extents
- [ ] Full LEF metadata (map section, extended attributes, etc.)
- [ ] Duplicate-data-offset handling and “single byte repetition” semantics — partial
- [ ] Multiple extents per file (beyond basic parsing) — partial

## Writers

### EWF1 (EVF) — `.E01` / `.S01`

- [x] Segmented output
- [x] `table` / `table2` generation
- [x] Chunk compression (zlib/deflate)
- [x] Empty-block compression
- [x] Media hashing (MD5/SHA1)
- [x] Write resume (conservative)
- [ ] Encryption
- [ ] Multi-session / incremental acquisition

### EWF2 (EVF2) — `.Ex01`

- [x] Segmented output
- [x] Device info + case data sections
- [x] Sector data + sector table sections
- [x] MD5 + SHA1 hash sections
- [x] Pattern fill
- [ ] bzip2 compression
- [ ] encryption
- [ ] write resume

### LEF writers — `.L01` / `.Lx01`

- [ ] Not implemented (read-only in libewf; long-term goal here)

## Delta / shadow files

- [x] Copy-on-write overlay via `EwfDelta` (crate-specific delta format)
- [x] Persistence/resume by scanning an append-only log
- [ ] Interoperability with libewf delta/shadow format (not documented)

## Encrypted containers (non-EWF)

- [x] AccessData “ADCRYPT” container (FTK/AD encryption) — explicitly rejected with a clear error

## `ewfinfo` CLI parity (this repository)

This section tracks parity with libewf’s `ewfinfo` tool behavior (`external/libewf/ewftools/ewfinfo.c`,
`external/libewf/ewftools/info_handle.c`, `external/libewf/manuals/ewfinfo.1`).

Notes:
- **Library support**: spec-oriented metadata extraction lives in `crates/ewf/src/metadata.rs` and
  `EwfReader::image_metadata()`.
- **Image-mode reporting/rendering** is binary-owned: `crates/ewf/src/bin/ewfinfo/ewfinfo/`.
- **Logical evidence outputs** (`-F`/`-H`/`-B`) are implemented in the `ewfinfo` binary target only:
  `crates/ewf/src/bin/ewfinfo/`.

### Image mode (`.E01` / `.S01` / `.Ex01`) — metadata report

- [x] Text output (default / `-f text`)
- [x] DFXML output (`-f dfxml`) — **schema-aligned `<dfxml>`** (DFXML 2.0.0-beta.0) via `crates/dfxml`
- [x] Section filtering: `-i` (acquiry only), `-m` (media+hashes+sessions+tracks), `-e` (errors only)
- [x] Date formatting `-d ctime|dm|md|iso8601` for acquisition/system date header values
- [x] `-A ascii` (EWF1 header decoding)
- [ ] `-A windows-*` codepages for EWF1 header decoding (explicit `Unsupported` for now)
- [ ] `-v` verbose output parity (flag is accepted, but we don’t emit libewf-style verbose traces yet)
- [ ] libewf “DFXML” (`ewfobjects` root + `ewfinfo` sections) output compatibility — we intentionally emit schema-aligned DFXML instead

### Logical evidence mode (`.L01` / `.Lx01`) — tree + bodyfile

- [x] `-H` logical files hierarchy (text)
- [x] `-F <path>` file entry info (text) — **subset** of libewf fields
- [x] `-B <path>` bodyfile output (Sleuthkit 3.x+ columns) — **subset** of libewf behavior
- [x] `-s /|\\` path separator for text/hierarchy/bodyfile name fields
- [ ] `-f dfxml` for logical modes (`-H`/`-F`/`-B`) — not implemented (test asserts this)
- [ ] Full file-entry metadata parity (ACLs, owners/groups, short name, etc.)

