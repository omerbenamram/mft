# ewf

Rust implementation of the **Expert Witness Compression Format** (EWF) family of forensic image
formats.

This crate is **spec-driven** and aims to be **compatible with libewf** (the reference
implementation used for behavior parity and test vectors).

## Status

- **Experimental**: APIs are still moving while format coverage expands.
- **Focus**: correctness, random-access reads, and deterministic writers (no “load the whole image”).

## Supported formats & features

### Readers

- **EWF1 (EVF)**: `.E01` (EnCase) and `.S01` (SMART)
  - **Multi-segment discovery**: `.E01` → `.E02` … and `.EAA` … (same for `.S01`)
  - **Chunk compression**: zlib/deflate (including empty-block compression)
  - **Chunk tables**: `table` and `table2`
- **EWF2 (EVF2)**: `.Ex01`
  - **Chunk compression**: zlib/deflate
  - **Pattern fill** (“empty block” / zero block optimization)
- **Logical evidence (LEF)**: `.L01` and `.Lx01`
  - Exposed via `LefReader` (parses EnCase-style serialized file trees and reads file extents)
- **Delta/shadow overlay**
  - `EwfDelta` provides **copy-on-write** semantics on top of a base image set using a separate
    delta file (**crate-specific** delta format; see notes below).

### Writers

- **EWF1 (EVF)**: `.E01` and `.S01`
  - **Segmented output**
  - **Chunk compression** (format-dependent behavior)
  - **Checksums** and media hashes
  - **Write resume** (conservative)
- **EWF2 (EVF2)**: `.Ex01`
  - **Segmented output**
  - **Chunk compression**: zlib/deflate
  - **Pattern fill** (optional)

### Not (yet) supported

- **EWF2**:
  - bzip2 compression
  - encryption
  - delta/shadow interoperability with libewf
- **AccessData “AD encryption” (ADCRYPT)** containers (they use EWF extensions but are not EWF)
- **LEF writers**: `.L01` / `.Lx01` writing

For a human-maintained parity checklist against libewf, see [`COMPAT.md`](./COMPAT.md).

## Usage

### Read bytes from an image set

```rust,no_run
use ewf::EwfReader;

fn main() -> ewf::Result<()> {
    let img = EwfReader::open("disk.E01")?;

    let mut boot_sector = [0u8; 512];
    img.read_exact_at(0, &mut boot_sector)?;

    Ok(())
}
```

### Write an E01 image set

```rust,no_run
use ewf::writer::{Ewf1Format, EwfWriterOptions};
use ewf::EwfWriter;
use std::io::Write as _;

fn main() -> ewf::Result<()> {
    let media = vec![0u8; 1024];

    let mut opts = EwfWriterOptions::new(Ewf1Format::E01, media.len() as u64);
    opts.bytes_per_sector = 512;
    opts.sectors_per_chunk = 1;

    let mut w = EwfWriter::create("out.E01", opts)?;
    w.write_all(&media)?;
    w.finish()?;

    Ok(())
}
```

### Read logical evidence files (L01 / Lx01)

```rust,no_run
use ewf::LefReader;

fn main() -> ewf::Result<()> {
    let lef = LefReader::open("case.L01")?;
    let bytes = lef.read_file("hello.txt")?;
    println!("read {} bytes", bytes.len());
    Ok(())
}
```

### Use a delta/shadow file (copy-on-write overlay)

```rust,no_run
use ewf::EwfDelta;

fn main() -> ewf::Result<()> {
    let mut img = EwfDelta::open("base.E01", "shadow.ewfdelta")?;
    img.write_exact_at(0, b"NTFS")?;
    img.flush()?;
    Ok(())
}
```

## Reference implementation & specifications

This repository pins the libewf reference commit hash in:

- `external/refs/repos/libyal__libewf.commit`

We do **not** vendor the full upstream repository here. If you want to inspect the reference
implementation or the AsciiDoc “living spec” documents, clone `libyal/libewf` and check out the
pinned commit.

## Sources

- `libyal/libewf` repository: `https://github.com/libyal/libewf`
- `Expert Witness Compression Format (EWF).asciidoc` (EWF1 / E01 / S01 / L01): upstream `libewf` `documentation/`
- `Expert Witness Compression Format 2 (EWF2).asciidoc` (EWF2 / Ex01 / Lx01): upstream `libewf` `documentation/`

