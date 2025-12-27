# `aff` — Advanced Forensic Format (AFF) reader

This crate provides **read-only** access to AFF containers with behavior closely aligned to
**AFFLIBv3**.

## Supported containers

- **AFF1** single-file (`.aff`)
- **AFM** (`.afm`) metadata + split-raw payload (`.000`, `.001`, …)
- **AFD** directory container (`file_000.aff`, `file_001.aff`, …)

## Quick start

```rust
use aff::AffOpenOptions;
use forensic_image::ReadAt;

let img = AffOpenOptions::new().open("image.aff")?;
let mut buf = [0u8; 512];
img.read_exact_at(0, &mut buf)?;
# Ok::<(), aff::Error>(())
```

## Features

- **`crypto`** (default): decrypt `/aes256` segments (read-side) + verify `/sha256` signatures (read-side)
- **`lzma`** (default): LZMA page decompression (`AF_PAGE_COMP_ALG_LZMA`)

For a human-maintained parity checklist against AFFLIBv3, see [`COMPAT.md`](./COMPAT.md).

## Reference materials

This repo vendors reference materials under `external/refs/` (AFFLIBv3 snapshot + public specs).
These are used for **correctness** and **parity testing**; the `aff` crate itself does not link to
AFFLIB.


