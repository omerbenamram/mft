# Reference material

This folder holds **reference-only** pointers used for parity work. Nothing under `external/refs/`
is compiled or linked into the Rust crates.

## Pinned upstream commits

### `libyal/libewf`

- **Pinned commit**: `external/refs/repos/libyal__libewf.commit`
- **Upstream**: `https://github.com/libyal/libewf`

This crate does **not** vendor the full upstream repository snapshot; the pinned commit file is
enough to reproduce the reference checkout locally when needed.

### `dfxml-working-group/dfxml_schema`

- **Pinned commit**: `external/refs/repos/dfxml-working-group__dfxml_schema.commit`
- **Upstream**: `https://github.com/dfxml-working-group/dfxml_schema`

This repository is used as the reference for DFXML schema compliance. The workspace vendors a
minimal set of schema files under `crates/dfxml/schema/` for offline validation in tests.


