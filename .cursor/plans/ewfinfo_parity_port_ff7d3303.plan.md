---
name: ewfinfo parity port
overview: Implement a Rust `ewfinfo` CLI (clap) + supporting library report/printer APIs in `crates/ewf` that match libewf’s `ewfinfo` image-metadata behavior/output (text + DFXML), with explicit TODO/`unimplemented` for any unsupported surface area (no silent fallbacks). Keep logical file outputs (`-F`/`-H`/`-B`) in the `ewfinfo` binary target (not the library); use `miette` for application-facing diagnostics while keeping library errors in `thiserror`.
todos:
  - id: ewfinfo-api
    content: Add documented `crates/ewf::ewfinfo` library module for image-metadata reports + printers (no LEF/-F/-H/-B).
    status: completed
  - id: docs-and-unit-tests
    content: Add module docs + rustdoc examples + unit tests for every new public API (include “References” with upstream source file paths).
    status: completed
  - id: ewf1-metadata
    content: Implement EWF1 metadata extraction for header values, media/ewf info, digest hashes, sessions/tracks, and acquisition errors.
    status: completed
  - id: ewf2-metadata
    content: Implement EWF2 metadata extraction (device/case tags, set-id, compression, md5/sha1 sections, etc.).
    status: completed
  - id: ewfinfo-logical-cli
    content: Implement `ewfinfo` CLI-only logical evidence outputs (`-F`/`-H`/`-B`) in the `ewfinfo` binary target (may extend `LefReader` public API minimally, but keep formatting + bodyfile semantics out of the library).
    status: completed
  - id: printers
    content: Implement text + DFXML printers for the image-metadata report that match libewf `ewfinfo` formatting.
    status: completed
  - id: cli-ewfinfo
    content: Add `ewfinfo` binary target using clap for libewf-compatible flags/conflicts and miette for user-facing errors (binary can be multi-file).
    status: completed
  - id: golden-tests
    content: Add golden-output tests for text/dfxml/file-entry/hierarchy/bodyfile, plus TODO/unimplemented tests for unsupported paths.
    status: completed
---

# Port libewf `ewfinfo` to `crates/ewf`

## Goal

- Add a **new `ewfinfo` Rust binary** (in `crates/ewf`) and the supporting **public library APIs** so we can reproduce libewf `ewfinfo` feature-for-feature:
- Options: `-A -B -d -e -f -F -H -i -m -s -v -V -h` (per `external/libewf/manuals/ewfinfo.1` + `external/libewf/ewftools/ewfinfo.c`).
- Output: **text** and **DFXML** with the same section structure + formatting.
- **No best-effort fallbacks**: if something isn’t implemented in Rust, we leave an explicit `TODO:` and return `unimplemented!()` / `Error::Unsupported("TODO: ...")` rather than silently degrading.

## Approach (map C ewfinfo → Rust)

### 1) Create a reusable ewfinfo library module (image metadata only)

- Add a new **library** module under `crates/ewf/src/ewfinfo/` that provides a Rust-native “report + printer” API for **image metadata only**.
- **Do not** 1:1 port or “mirror” libewf’s `info_handle_t`. The `ewfinfo` **binary target** should own the clap-facing types and translate them into a small, strongly-typed library API.
- Keep the boundary sharp:
- **Library (`crates/ewf`)**: build a structured report for EWF *image* metadata + print it (text/DFXML).
- **Binary target (`ewfinfo`)**: owns **logical evidence** modes and outputs (`-F`/`-H`/`-B`), path separator handling, and any bodyfile semantics.
- Proposed (public) library surface (names TBD; document every `pub` item):
- `EwfInfoReport`: data model for the sections libewf prints for images:
- Acquisition/header values (libewf title: “Acquiry information”)
- EWF information
- Media information
- Digest hash information
- Sessions / Tracks
- Acquisition read errors
- `EwfInfoPrinter` (trait) + concrete printers (e.g. `TextPrinter`, `DfxmlPrinter`) with `EwfInfoPrintOptions` (date formatting, verbosity, etc.)
- `EwfInfoBuildOptions` for report construction knobs that actually affect parsing/normalization (e.g. header decoding/codepage), **not** CLI-only options like `-s`/`-B`.
- `EwfInfoError` (library) implemented with `thiserror`.
- **Module documentation requirements** (non-negotiable):
- Each new module gets `//!` docs with a short compatibility statement and a “References” section that attributes upstream reference material by file path (at minimum):
- `external/libewf/ewftools/info_handle.h`
- `external/libewf/ewftools/ewfinfo.c`
- `external/libewf/manuals/ewfinfo.1`
- Include rustdoc examples (doctests) that exercise the public API surface (using existing small fixtures/builders).

### 2) Extend readers to expose the metadata ewfinfo prints

Keep the existing small summary API (`EwfInfo` in [`crates/ewf/src/info.rs`](crates/ewf/src/info.rs)) stable; add *new* APIs instead.

#### Disk images (`EwfReader`)

- Add `EwfReader::ewfinfo_report(&self, opts: &EwfInfoBuildOptions) -> Result<EwfInfoReport, EwfInfoError>`.
- Implement format-specific extraction:
- **EWF1 (E01/S01)**: parse required sections from the already-discovered section descriptors (header/header2/volume/disk/data/hash/digest/error/session/track).
- Header values: parse both `header` (ASCII/codepage) and `header2` (UTF-16LE) and construct the same identifier→description mapping used by `info_handle_header_values_fprint`.
- EWF + media info fields: derive from parsed volume/disk/data structures (`sectors_per_chunk`, `bytes_per_sector`, `number_of_sectors`, `error_granularity`, `set_identifier`, compression level/method).
- Hash values: read stored global hashes from digest/hash sections (no recomputation unless ewfinfo does so).
- Sessions/tracks: parse ranges as start_sector/sector_count.
- Acquisition errors: parse ranges as start_sector/sector_count.
- **EWF2 (Ex01)**: reuse existing parsing in [`crates/ewf/src/reader.rs`](crates/ewf/src/reader.rs) (case data/device information tags) to populate the same report fields:
- `set_id`, `compression_method`, `chunk_count`, `sectors_per_chunk`, `bytes_per_sector`, `number_of_sectors`
- global MD5/SHA1 sections (parse from section types) to populate digest hash info
- sessions/tracks/errors: if format doesn’t carry them, report 0 entries (matching libewf behavior for “none present”).

### 3) Implement printers for exact text + DFXML output

- Add printer modules under `crates/ewf/src/ewfinfo/`:
- Text printer replicating:
- section headers/footers and indentation
- field label padding (the C code aligns to 24 columns)
- exact section titles: “Acquiry information”, “EWF information”, “Media information”, “Digest hash information”, etc.
- DFXML printer replicating the XML emitted by `info_handle_dfxml_*_fprint` (header/footer + element names).
- **No fallback behavior**: invalid inputs/options should be rejected early. For the **CLI**, clap should enforce as much as possible (enums, conflicts, defaults). For the **library**, return explicit `EwfInfoError::Unsupported("TODO: …")` where needed rather than silently defaulting.

### 4) Add the `ewfinfo` binary target (clap + miette) and keep logical outputs there

- Implement `ewfinfo` as a **binary target** that can be split across multiple Rust modules (prefer directory-style bin: `crates/ewf/src/bin/ewfinfo/main.rs` + submodules).
- Use **clap** to translate libewf flags/idioms into a typed CLI surface (instead of manually porting structs):
- `#[derive(Parser)] `root + `Args`/`Subcommand` as needed.
- `ValueEnum` / typed enums for `-f` (text/dfxml), `-d` (date format), etc.
- conflict groups for `-e`/`-i`/`-m` (mutually exclusive), and for logical modes (`-F` vs `-H` etc.) as required.
- rely on clap’s generated `--help`/`--version` UX while keeping short flags compatible.
- Use **miette** for user-facing diagnostics:
- Map library `thiserror` errors into `miette::Diagnostic` at the application boundary with helpful context (`wrap_err`, filenames, option values).
- Keep **logical evidence outputs** out of the library:
- `-F` (file entry detail), `-H` (hierarchy), `-B` (bodyfile) live in the `ewfinfo` binary target.
- If the binary needs additional LEF accessors, add small, generic `pub` APIs to `LefReader` (document + unit test them), but keep formatting and bodyfile semantics in the binary.

### 5) Tests + documentation (unit tests first, then golden outputs)

- Add **unit tests** for every new library type/module under `crates/ewf/src/ewfinfo/` (and any new public reader accessors):
- parsing/normalization invariants
- section ordering and required fields presence
- printer formatting invariants (labels, indentation, titles)
- Add **CLI unit tests** (clap `try_parse_from`) for flag conflicts/defaults and for mapping from CLI types → library options.
- Add deterministic **golden-output integration tests** in `crates/ewf/tests/` that:
- generate small synthetic E01/Ex01/L01/Lx01 fixtures using existing writer/test helpers
- run the Rust `ewfinfo` binary (via `std::process::Command`) and compare stdout to committed golden files for:
- default text
- `-f dfxml`
- `-F` and `-H`
- `-B` bodyfile output
- For any feature we haven’t implemented yet (e.g., extended attributes/access control entries if present in real-world files), add a test that asserts we fail with an **explicit TODO/unimplemented** marker.

## Files most likely to change

- [`crates/ewf/src/lib.rs`](crates/ewf/src/lib.rs) (export new ewfinfo APIs)
- [`crates/ewf/src/info.rs`](crates/ewf/src/info.rs) (keep as-is; add new full-metadata types elsewhere)
- [`crates/ewf/src/reader.rs`](crates/ewf/src/reader.rs) (expose/retain parsed metadata needed for ewfinfo)
- New: [`crates/ewf/src/ewfinfo/mod.rs`](crates/ewf/src/ewfinfo/mod.rs)
- New: [`crates/ewf/src/ewfinfo/print_text.rs`](crates/ewf/src/ewfinfo/print_text.rs)
- New: [`crates/ewf/src/ewfinfo/print_dfxml.rs`](crates/ewf/src/ewfinfo/print_dfxml.rs)
- New (preferred): `crates/ewf/src/bin/ewfinfo/` (binary crate modules, e.g. `main.rs`, `cli.rs`, `image.rs`, `logical.rs`, `bodyfile.rs`)

## Notes / constraints

- We’ll use libewf’s behavior/spec as reference but implement logic natively in Rust; no “silent compatibility” shims.
- Any missing surface area is left as `TODO:` + explicit `unimplemented`/`Unsupported` error (per your requirement).
- Error policy: `thiserror` in the library; `miette` at the application boundary for pretty CLI diagnostics.
