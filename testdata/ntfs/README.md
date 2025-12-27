# NTFS test fixtures (Git LFS)

This directory contains **binary NTFS test images** used by the `ntfs` crate integration tests under `crates/ntfs/tests/`.

These files are stored in **Git LFS** (see the repo root `.gitattributes`). If tests fail with parse errors or if you see tiny “pointer” files, run:

```bash
git lfs install
git lfs pull
```

## What’s here

### `NPS 2009 NTFS1` (Digital Corpora)

Files:

- `ntfs1-gen0.{aff,E01}`
- `ntfs1-gen1.{aff,E01}`
- `ntfs1-gen2.E01`
- `ntfs1-gen2.xml` (DFXML / `fiwalk` output; used as ground truth for per-file hashes)
- `narrative.txt` (dataset description)

Used by tests:

- Image backend parity / smoke: `crates/ntfs/tests/test_image_backends.rs`
- Volume/MFT open: `crates/ntfs/tests/test_volume_mft.rs`
- Directory traversal + compression + attribute list reads: `crates/ntfs/tests/test_dir_traversal.rs`, `crates/ntfs/tests/test_file_reads.rs`
- EFS metadata + decrypt regressions: `crates/ntfs/tests/test_efs_*.rs`, `crates/ntfs/tests/test_ewf_regressions.rs`

Provenance:

- CFReDS dataset page: `https://cfreds.nist.gov/all/DigitalCorpora/NPS2009NTFS1`
  - The CFReDS page links to a Digital Corpora download location for the dataset.

### `DFTT image #7` — NTFS Undelete Test #1 (GPL)

Files:

- `7-undel-ntfs/7-ntfs-undel.dd` (raw NTFS partition image, ~6MB)
- `7-undel-ntfs/index.html`, `results.txt` (reference values used by tests)
- `7-undel-ntfs/README.txt`, `COPYING-GNU.txt` (upstream provenance + license)

Used by tests:

- Deleted file recovery + ADS + parent-scan path resolution: `crates/ntfs/tests/test_ntfs_undelete_7.rs`
- Misc filesystem helpers: `crates/ntfs/tests/test_fsntfsinfo_cli.rs`, `crates/ntfs/tests/test_filesystem_helpers.rs`

Provenance / reference:

- Upstream project: `http://dftt.sourceforge.net/` (see `7-undel-ntfs/README.txt`)
- Upstream MD5 (from `7-undel-ntfs/index.html`): `e7dbb96759d9cd62b729463ebfe61dab`

License note:

- The `7-undel-ntfs` fixture is **GPL-2.0-only**, per the upstream `README.txt` and `COPYING-GNU.txt`.
- This repo also contains MIT/Apache-2.0 code; the GPL license here applies to the **fixture files in `7-undel-ntfs/`**, not automatically to the rest of the repository. (If your org has strict “no GPL artifacts anywhere” policies, don’t pull these LFS objects and/or remove this directory.)

## Integrity

See `SHA256SUMS` for SHA-256 checksums of all files in this directory (including `7-undel-ntfs/*`).


