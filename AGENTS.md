# Repository Guidelines

## Project Structure & Module Organization
The crate root lives in `src/lib.rs` with supporting modules in `src/attribute`, `src/mft.rs`, and `src/utils.rs`. CLI code for the `mft_dump` binary sits in `src/bin/mft_dump.rs`. Reusable fixtures used by unit tests live in `src/tests`, while integration tests belong under `tests/`. Sample MFT images and large fixtures live in `samples/` and `testdata/`; keep new assets small and explain their origin in PR descriptions. README snippets are kept in sync via `tests/readme.rs` and the `doc-comment` harness.

## Build, Test, and Development Commands
Run `cargo build --all-targets` for a full local compile, and `cargo test --all-features` before pushing to mirror CI. Use `cargo bench --bench benchmark` when touching performance-critical code paths. `cargo fmt` and `cargo clippy --all-targets --all-features` should produce a clean workspace; address new lints or explain why they cannot be resolved.

## Coding Style & Naming Conventions
Follow Rust 2024 idioms and let `rustfmt` enforce four-space indentation and line wrapping. Favour descriptive snake_case for modules, functions, and test names, and PascalCase for types and enums. Prefer early returns with `?`, explicit error types via `thiserror`, and structured logging through the `log` macros. Keep public API additions documented with concise doc comments.

## Testing Guidelines
Add focused unit tests beside the code they cover inside `#[cfg(test)]` modules, and author end-to-end scenarios under `tests/` using the CLI or parser APIs. Use fixture builders in `src/tests/fixtures.rs` and shared disk images under `testdata/` to avoid duplication. Name tests after the behaviour under test (for example `test_parse_index_root_handles_resident_entries`). Verify benchmarks when modifying parsing hot paths.

## Commit & Pull Request Guidelines
Craft short, imperative commit subjects that describe the observable change (e.g., `Add resident index entry parser`). Commits should compile and pass tests independently. Pull requests need a summary of the change, a checklist of local commands run, and links to related issues. Include screenshots or sample output when altering CLI behaviour, and flag any changes to binary compatibility or minimum supported Rust version.
