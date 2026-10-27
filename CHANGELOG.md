# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Parse `$VOLUME_NAME` (0x60) and `$VOLUME_INFORMATION` (0x70) into `VolumeNameAttr` and `VolumeInformationAttr` (label, NTFS version, volume flags) instead of raw hex.
- Parse `$REPARSE_POINT` (0xC0) into `ReparsePointAttr`: the tag, its documented name, the GUID for third-party tags, and decoded symlink, junction/mount point, AppExecLink and WSL symlink targets. Other tags keep their data as hex.
- `mft_dump` JSON and JSONL output include each entry's `full_path` (previously only CSV had it).
- `FlatMftEntryWithName::from_entry_with_path` builds a CSV row from an already-resolved path.
- JSON output lists attributes that failed to parse in a per-entry `errors` array (only present when non-empty). Previously they were dropped silently.
- Expand `FileAttributeFlags` with the latest Windows-defined bits for NTFS parsing.
- Add `MftAttributeType::PropertySet` (`0xF0`, NT4-era `$PROPERTY_SET`).

### Changed
- JSON output of `$VOLUME_NAME` and `$VOLUME_INFORMATION` attributes changes from `{attribute_type, data}` raw hex to the parsed fields; `MftAttributeContent` gains the `AttrX60` and `AttrX70` variants, which breaks exhaustive matches.
- `MftAttributeContent` has a new `AttrXC0` variant, and `$REPARSE_POINT` JSON output changes from raw hex to the parsed structure.
- Timestamps keep NTFS's full 100ns resolution and are always written with 7 fractional digits (`2007-06-30T12:50:52.2523952Z`). They were truncated to microseconds and printed with 0, 3, 6 or 9 digits, chrono style. This changes every timestamp in JSON and CSV output. `serialize_timestamp_chrono_compat` and `serialize_option_timestamp_chrono_compat` are renamed to `serialize_timestamp` and `serialize_option_timestamp`.
- `FileNameAttr::logical_size` now holds the real size and `physical_size` the allocated size (see Fixed). Code that worked around the old swap needs to drop the workaround.
- Upgrade the crate to the Rust 2024 edition and require Rust 1.90 for builds.
- Forbid usage of `unsafe` code across the workspace and satisfy new Clippy lints.
- Keep formatting and lint configuration aligned with Rust 2024 expectations.

### Fixed
- `$FILE_NAME` `logical_size` and `physical_size` were swapped: the allocated size (offset 0x28) was reported as the logical size and the real size (0x30) as the physical size. JSON output and index entries change accordingly.
- `iter_attributes` keeps returning later attributes after one with an unknown type code, and
  `iter_attributes_matching` skips unrequested attributes without parsing their headers.
- Correct decoding of sparse non-resident data runs when reading MFT entries.
- Resolve the LCN of a data run that follows a sparse run relative to the last allocated run (#152).
- Serialize flags as `A | B` again instead of bitflags 2's `TypeName(A | B)` debug format.
- Break cycles in parent references instead of overflowing the stack while resolving paths.
- Recover the entry size from later records when the first entry is zeroed, instead of dividing by zero.
- `mft_dump -e` no longer writes empty files for zero-length resident streams (#23).

### Added
- JSON output includes `data_size` for resident attributes (#125).
- Address the `clippy::collapsible_if` warning emitted for the `mft_dump` CLI.

### CI
- Refresh CI workflows, add Apple Silicon release artifacts, and scope push triggers to `main` and `release/**`.

## [0.6.1] - 2023-02-18

### Changed
- Dependency updates

## [0.6.0] - 2022-01-05

### Changed
- Happy new year! lots of dependencies have been updated.
- update to rust edition 2021

## [0.5.2] - 2020-03-10

### Fixed
- Attribute list parsing

### Changed
- Warn on fixup mismatch instead of fail

### Added
- Additional File Attribute flags
- `valid_fixup` field to MftEntry

## [0.5.1] - 2020-02-06

### Fixed
- Added support for additional MFT attributes (parsed as raw streams)

## [0.5.0] - 2020-01-06

### Changed
- Bumped dependencies.
- `mft_dump` is now an optional features so consumers of the library can enjoy faster compilation time.
- Changed error handling to `anyhow` + `thiserror` from `snafu`.

## [0.4.4] - 2019-06-19

### Fixed
- Fixed a bug where `HasAlternateDataStreams` will miss entries with only a single named stream.

## [0.4.3] - 2019-06-06

### Added
- `mft_dump` can now dump only a specific range of entries with `-r`.
- CSV output now shows `FileSize`, `IsDeleted` as separate columns.

### Fixed
- Fixed an issue with debug-logs

## [0.4.2] - 2019-06-04

### Fixed
- Ignore zeroed entries in `mft_dump`

## [0.4.1] - 2019-06-04

### Fixed
- Files which are not an MFT now cause the program to terminate with a nice message.
- Nicely ignore zeroed files in `mft_dump`

## [0.4.0] - 2019-06-04

### Added
- `mft_dump` can now export resident streams to a directory.

## [0.3.0] - 2019-06-02

Fixed parsing of entries which are spread over multiple sectors.

## [0.2.0] - 2019-05-23

Initial release which I consider a usable beta.
