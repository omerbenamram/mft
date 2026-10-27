# Fuzzing

Fuzz targets for the record parser, built with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (requires a nightly toolchain).

| Target | Input | What it exercises |
|--------|-------|-------------------|
| `entry` | one MFT record | `MftEntry::from_buffer` (with and without fixups), attribute iteration, `find_best_name_attribute`, JSON serialization |
| `data_runs` | a mapping pairs array | `decode_data_runs` |
| `parser` | a whole `$MFT` | `MftParser::from_buffer`, entry iteration and full path resolution across parent references |

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run entry -- -max_len=4096
```

Seeding the corpus with real records finds deeper bugs faster, for example by splitting `samples/MFT` into 1024-byte files under `fuzz/corpus/entry/`.

Crashes are written to `fuzz/artifacts/<target>/`. Reproduce one with `cargo +nightly fuzz run <target> <artifact>`.
