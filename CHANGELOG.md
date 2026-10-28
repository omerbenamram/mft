# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Parse resident `$SECURITY_DESCRIPTOR` (0x50) attributes into `SecurityDescriptorAttr`: the control flags, owner and group SIDs, and the SACL and DACL with each ACE's type, flags, access mask, object types and SID. Non-resident ones keep their data runs.
- Parse `$EA_INFORMATION` (0xD0) and `$EA` (0xE0) into `EaInformationAttr` and `EaAttr`: each extended attribute's flags, name and value. WSL's `$LXUID`, `$LXGID`, `$LXMOD` and `$LXDEV` and code integrity's `$CI.CATALOGHINT` are decoded, and other values keep their data as hex.

### Changed
- `MftAttributeContent` has a new `AttrX50` variant, and resident `$SECURITY_DESCRIPTOR` JSON output changes from raw hex to the parsed descriptor.
- `MftAttributeContent` has new `AttrXD0` and `AttrXE0` variants, and `$EA_INFORMATION` and `$EA` JSON output changes from raw hex to the parsed structures.
- `EntryFlags`, `AttributeDataFlags` and `FileAttributeFlags` values can hold bits without a name, so comparing one with `==` against named flags can now be false where it used to be true. JSON and CSV flag strings can end with a hex part, such as `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | 0x80000000`.

### Fixed
- Flag fields keep bits that have no name (entry flags, attribute data flags, and `$STANDARD_INFORMATION` and `$FILE_NAME` file attributes) instead of dropping them, such as the `0x80000000` set on `$Extend\$RmMetadata\$Txf`.
- A read error partway through an entry no longer makes the next `get_entry` read from the wrong offset.

## [0.8.0] - 2026-10-27

### Added
- CSV output has `StandardInfoLastMftModified` and `FileNameLastMftModified` columns (the "MFT entry changed" times), appended after `FullPath` so existing column positions don't move (#123).
- `windows_path`, `serialize_windows_path` and `serialize_option_windows_path` format a resolved path with `\` separators.
- `MftEntry::iter_attribute_records_matching` yields each attribute's header and raw record without parsing its content, and `ResidentHeader::value` slices a resident attribute's value out of its record.
- Parse `$VOLUME_NAME` (0x60) and `$VOLUME_INFORMATION` (0x70) into `VolumeNameAttr` and `VolumeInformationAttr` (label, NTFS version, volume flags) instead of raw hex.
- `mft_dump -o bodyfile` writes Sleuth Kit bodyfile lines in the `fls -m` layout, for timelining with `mactime`: one line per `$DATA` stream and `$INDEX_ROOT` with the `$STANDARD_INFORMATION` times, and a `($FILE_NAME)` line with the `$FILE_NAME` times.
- Parse `$REPARSE_POINT` (0xC0) into `ReparsePointAttr`: the tag, its documented name, the GUID for third-party tags, and decoded symlink, junction/mount point, AppExecLink and WSL symlink targets. Other tags keep their data as hex.
- `mft_dump` JSON and JSONL output include each entry's `full_path` (previously only CSV had it).
- `FlatMftEntryWithName::from_entry_with_path` builds a CSV row from an already-resolved path and the entry's extension records.
- `MftParser::get_extension_entries` reads the extension records that hold attributes an `$ATTRIBUTE_LIST` moved out of a base record, and `entry::find_best_name_attribute_in` picks a file's name across its base and extension records (#148).
- JSON output lists attributes that failed to parse in a per-entry `errors` array (only present when non-empty). Previously they were dropped silently.
- Add `MftAttributeType::PropertySet` (`0xF0`, NT4-era `$PROPERTY_SET`).
- JSON output includes `data_size` for resident attributes (#125).

### Changed
- **Breaking:** attributes borrow from the entry's record buffer instead of copying it. `MftAttribute`, `MftAttributeContent` and the name-carrying attribute types (`FileNameAttr`, `DataAttr`, `AttributeListAttr`, `IndexRootAttr`, ...) take a lifetime, names are borrowed UTF-16LE that decode on demand, and the `into_*` accessors are replaced by borrowing `as_*` ones (`as_file_name`, `as_data_runs`, ...). This makes parsing much faster but needs callers to keep the `MftEntry` alive while they use its attributes.
- Faster `mft_dump`: release builds use thin LTO with one codegen unit and native release binaries are profile-guided (PGO), timestamps and flags are formatted without `core::fmt`, directory paths are cached, and I/O buffers are larger (see PERF.md).
- CSV and JSON output write `full_path` with `\` separators on every platform, the way Windows shows NTFS paths. Linux and macOS builds used `/`. `get_full_path_for_entry` still returns a `PathBuf`, and bodyfile output keeps `fls`'s `/`.
- JSON output of `$VOLUME_NAME` and `$VOLUME_INFORMATION` attributes changes from `{attribute_type, data}` raw hex to the parsed fields (a `$VOLUME_INFORMATION` value too short to parse stays raw hex); `MftAttributeContent` gains the `AttrX60` and `AttrX70` variants, which breaks exhaustive matches.
- `MftAttributeContent` has a new `AttrXC0` variant, and `$REPARSE_POINT` JSON output changes from raw hex to the parsed structure.
- Timestamps keep NTFS's full 100ns resolution and are always written with 7 fractional digits (`2007-06-30T12:50:52.2523952Z`). They were truncated to microseconds and printed with 0, 3, 6 or 9 digits, chrono style. This changes every timestamp in JSON and CSV output. `serialize_timestamp_chrono_compat` and `serialize_option_timestamp_chrono_compat` are renamed to `serialize_timestamp` and `serialize_option_timestamp`.
- `FileNameAttr::logical_size` now holds the real size and `physical_size` the allocated size (see Fixed). Code that worked around the old swap needs to drop the workaround.
- Update all workspace dependencies to their latest releases, including `rand` 0.10, `lru` 0.19,
  `itertools` 0.15, `num-derive` 0.5, `criterion` 0.8, `quick-xml` 0.42, RustCrypto `md-5`/`sha1` 0.11
  and `aes`/`des` 0.9, and `fuser` 0.18 (the FUSE frontend now uses fuser's `&self` callbacks).

### Fixed
- Full paths use the long name of a file or directory whose base record only has room for its 8.3 short name, by looking in its extension records (#148). Paths like `Windows/servicing/LCU/PACKAG~1.7/...` become `Windows/servicing/LCU/Package_for_RollupFix~.../...`; on a Windows 11 sample, about a third of all paths change this way.
- CSV `FileSize`, `HasAlternateDataStreams` and the bodyfile's stream lines include `$DATA` attributes stored in extension records, instead of reporting such files as empty.
- `$FILE_NAME` `logical_size` and `physical_size` were swapped: the allocated size (offset 0x28) was reported as the logical size and the real size (0x30) as the physical size. JSON output and index entries change accordingly.
- `iter_attributes` keeps returning later attributes after one with an unknown type code, and
  `iter_attributes_matching` skips unrequested attributes without parsing their headers.
- Resolve the LCN of a data run that follows a sparse run relative to the last allocated run (#152).
- Serialize flags as `A | B` again instead of bitflags 2's `TypeName(A | B)` debug format.
- Break cycles in parent references instead of overflowing the stack while resolving paths.
- Recover the entry size from later records when the first entry is zeroed, instead of dividing by zero.
- `mft_dump -e` no longer writes empty files for zero-length resident streams (#23).
- The `ntfs` crate, its tools and the NTFS explorer GUI build again against the borrowed attribute API.

### CI
- Push triggers name `master` (they said `main`, so pushes to master didn't run CI).
- Lint and test every workspace crate (previously only the root `mft` crate), build the GUI, and check
  the 1.90 MSRV.

## [0.7.0] - 2025-12-23

### Added
- Expand `FileAttributeFlags` with the latest Windows-defined bits for NTFS parsing.

### Changed
- Upgrade the crate to the Rust 2024 edition and require Rust 1.90 for builds.
- Forbid usage of `unsafe` code across the workspace and satisfy new Clippy lints.
- Keep formatting and lint configuration aligned with Rust 2024 expectations.

### Fixed
- Correct decoding of sparse non-resident data runs when reading MFT entries.
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
