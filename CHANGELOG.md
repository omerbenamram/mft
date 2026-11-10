# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Parse the USN change journal (`$Extend\$UsnJrnl:$J`) in the new `mft::usn` module: `UsnJournal` reads an extracted `$J` and yields `UsnRecord`s (`USN_RECORD_V2`, `V3` and the range-tracking `V4`), skipping the zeros of the sparse start and page padding. A run of bytes that don't parse gives one `Error::InvalidUsnRecord` and reading carries on after it. All 305,198 records of the Narcos (Windows 10) `$J` parse, each with its USN equal to its offset in the stream.
- Parse `INDX` index records, the nodes of a large index in `$INDEX_ALLOCATION`, in the new `mft::indx` module. `IndxRecord::entries` gives a record's `$FILE_NAME` entries, and `IndxRecord::slack_entries` recovers the old entries left in its slack space, including ones whose entry header was overwritten (they have no `mft_reference`). When a current entry is damaged, the entries after it are recovered as slack entries. An entry with the end flag ends the entries only when it has no key, as a real end entry, and the next entry starts on the 8-byte boundary after the one before, whatever that one's length says. `IndxFile` reads an extracted `$INDEX_ALLOCATION:$I30` stream. In the Narcos `C:\Windows` index, the slack holds every deleted name that The Sleuth Kit's `fls -d` lists, plus two it doesn't (a directory and a DOS name).
- `mft_dump` dumps an `$I30` (detected by its `INDX` signature, or `--input-type i30`) as JSON, JSONL or CSV, with a `FromSlack` column and, with `--mft`, each entry's full path.
- Parse the NTFS boot sector (`$Boot`) in the new `mft::boot` module: `BootSector::from_slice` gives the sector and cluster sizes (including the power-of-two encoding for clusters over 64 KiB), the volume size, where `$MFT` and `$MFTMirr` start, the file and index record sizes, and the volume serial number (serialized as a hex string, since it exceeds 2^53), also as `vol` shows it. It rejects sector sizes other than a power of two from 256 to 4096, cluster sizes that aren't a power of two up to 2 MiB, and offsets that overflow.
- Parse `$Secure:$SDS` in the new `mft::sds` module: `SdsEntries` yields each security descriptor with its security ID, hash (and whether it matches the descriptor; an empty or zeroed one never does) and offset. An entry that is damaged or missing in a 256 KiB block is recovered from the copy that follows it (`from_mirror`). `SecurityIds` maps the security IDs of `$STANDARD_INFORMATION` to their owner and SDDL. All 1,624 security IDs used in the Narcos `$MFT` resolve in its `$SDS`, and all 2,296 entries' hashes match.
- Read `$LogFile` in the new `mft::logfile` module: `LogFile` parses both restart pages (the restart area with the checkpoint LSN, file size, sequence number bits and the log's clients) and picks the one in use (intact fixups first, then the newer LSN; a page with an implausible restart area is treated as damaged), follows the chain of clients in use (`client_chain_intact` flags a loop or a client cut off), reads the `RCRD` record page headers with their fixups, and maps an LSN to where its record is in the file (`LogFile::lsn_offset`, `None` for LSN 0 or an offset outside the record pages; whatever its pass, since pages the log hasn't reached again keep records of old passes, so the record found there must be checked against the LSN; the tail-copy pages aren't consulted).
- `LogFile::records` reads the log records of `$LogFile`: each record's LSNs, transaction and type, and for NTFS records the redo and undo operations (named, like `InitializeFileRecordSegment`), their target (attribute, VCN, LCNs, offsets) and data. A record that adds or removes a directory entry also gives the file reference, parent and name it logs, so the log shows files that were created, renamed or deleted. Records are found by an LSN that gives their own offset, so damaged records don't hide the ones after them. A copy of the log's tail that is newer than the page it belongs at, as after a crash, is read as that page, so the newest records are found when only the copy has them (tested on simulated crashes, not yet on a log from a volume that crashed). A record that continues into the next page is kept only when that page is an intact record page from the same pass of the log, and `truncated` flags LCNs or redo/undo data that run past where they can end (keeping what fits). On the Narcos main volume's log, 342,322 records parse, all but one follow the one before them in the file, and all but 2 of 192,763 previous-LSN links point to a record found.
- `mft_dump` dumps a `$LogFile` (detected by its `RSTR` page, or by its second restart page when the first page is damaged, or `--input-type logfile`) as JSON, JSONL or CSV, the CSV with every field of the JSON record but the redo and undo data (their lengths instead), among them the record flags, client sequence number, client index, client data length and `Truncated`, and `FileReference`, `ParentReference` and `FileName` columns for directory entry records.
- `SecurityDescriptorAttr::to_sddl` formats a descriptor in SDDL, with SIDs and access masks written out.
- `mft_dump` dumps a `$Boot` (detected by its `NTFS    ` OEM ID, or `--input-type boot`) and an `$SDS` (detected by an entry in its first 64 KiB whose hash matches, or `--input-type sds`) as JSON, JSONL or CSV, the CSV with an `Sddl` column.
- `mft_dump` dumps a `$J` as JSON, JSONL or CSV. It tells a `$J` from an `$MFT` by its first bytes (`--input-type mft|usn` overrides that), and `--mft <$MFT>` adds each file's full path (none for a 128-bit ReFS file id) and implies a `$J` input when `INPUT` would otherwise be read as an `$MFT`. `MftParser::get_full_path_in_directory` resolves such a path from a parent reference and a name.
- `MftEntry::stored_record_number` returns the record number NTFS wrote inside the record (the 32-bit field at offset 0x2C, NTFS 3.1 and later). `header.record_number` is the position the record was read from, so comparing the two finds records that were moved, carved or never numbered.

### Changed
- **Breaking:** `Error` has new `InvalidUsnRecord`, `InvalidIndexRecord`, `InvalidBootSector` and `InvalidLogFile` variants, which break exhaustive matches.
- The workspace's `ntfs` crate parses USN records with `mft::usn`, so `ntfs-info usn` now also reads v3 and v4 records, keeps flag bits without a name instead of failing on them, and prints the update time as a date. Its USN API changed with it: `UsnRecord` is `mft::usn::UsnRecord` (`UsnRecord::parse`, `UsnRecordV2` and the `V2` variant are gone), the flag constants carry their `USN_REASON_`/`USN_SOURCE_` prefixes, and invalid UTF-16 in a name is replaced rather than an error.

### Fixed
- A name the host would read as an absolute path no longer replaces the directories above it in a resolved path: `/etc` on Unix, or `C:x` and `\x` on Windows, which volumes written by other NTFS drivers and crafted MFTs can hold. `A\/etc\passwd` used to come out as `/etc/passwd`. Such a name in the root directory is written after `.`, so the path stays relative.
- A zeroed (never used) record's `header.record_number` is the number it was read as, instead of always 0.
- `Utf16LeStr::with_utf8` can be nested: converting or comparing another string inside the closure (`eq_utf8` with a non-ASCII string, `to_utf8_string`, `Display`) no longer panics with `RefCell already borrowed`.
- `MftParser::get_entry` returns an error for an entry number whose byte offset overflows (such as `1 << 54` with 1 KiB records), instead of returning entry 0 labelled with that number in release builds and panicking in debug builds.
- `mft_dump -e` no longer stops the whole dump when one stream can't be written. A file under a long path of non-ASCII names (80 Japanese characters are enough) gave a file name over 255 bytes, and a stream name holding a `/` gave a path into a missing directory: either one ended the run with an error and without the rest of the output. Exported file names are now cut to 255 bytes, and separators, the other characters Windows reserves and control characters become `_` in the stream's name as well as the path. A stream that still can't be written is reported on stderr and skipped, and the run then exits with an error once everything else is written. An existing file is never overwritten. The path part of the name is no longer shortened by the length of the output directory.
- A file with a timestamp past the year 9999 keeps its name, path and other timestamps. Windows accepts file times up to the year 30828, but one such value in a `$FILE_NAME` or `$STANDARD_INFORMATION` made the whole attribute fail to parse: the file then had no name and no path in every output, and the files inside such a directory were listed as if they were in the root. These timestamps now read as `Timestamp::MAX` (`9999-12-30T22:00:00.9999999Z`), and the raw value is logged as a warning (`mft_dump -v`). The same goes for the times in `$Quota` index entries. The public `windows_filetime_to_timestamp` still returns an error.
- A directory's `$INDEX_ROOT` entries no longer stop at the first one that references MFT entry 0. That entry is `$MFT`, which the root directory indexes, so on a volume whose root directory fits in its `$INDEX_ROOT` (4 KiB file records and few files in the root) every name sorting after `$MFT` was missing from `index_entries`: 10 of the 16 in our sample, among them the user's files. The entries now end at the one flagged as the last, as NTFS marks it.

## [0.10.0] - 2026-11-06

### Changed
- **Breaking:** mft no longer depends on `winstructs`, which took `chrono` along with it, so `chrono` is out of the dependency tree. `Guid` and `MftReference` are now mft's own types, at `mft::Guid` and `mft::MftReference` (also `mft::guid` and `mft::mft_reference`), with the same fields, constructors, `Display` and JSON output. Code that names `winstructs::guid::Guid` or `winstructs::ntfs::mft_reference::MftReference` should use the mft paths. `Guid` is now also `Copy`, `Eq`, `Ord` and `Hash`. `Error::FailedToReadMftReference` and `Error::FailedToReadGuid` carry a `std::io::Error` source instead of a `winstructs::err::Error`, and the never-used `Error::FailedToReadWindowsTime` is gone.

## [0.9.2] - 2026-11-03

### Fixed
- A file whose parent directory's record was reused for another file is now `[Orphaned]\<name>`, instead of getting a path through the record's new file (or `[Unknown]\<name>` when that file isn't a directory). Path resolution now checks the sequence number in each `$FILE_NAME` parent reference and base record reference. A deleted directory still holds the paths of the deleted files in it: Windows bumps a record's sequence number by one when it frees the record, so a freed parent one ahead of the reference still matches. In three of our sample images, this changes the paths of 43–99% of the deleted files, almost all of them from `[Unknown]\<name>`, and of no allocated files. Thanks @mcardonaes (#150).

## [0.9.1] - 2026-10-29

### Changed
- Resolving full paths takes 56–66% less work on large MFTs, with the same paths: it skips the sizes and flags of each `$FILE_NAME` and stops at the first `Win32` name, copies a directory's path once to build its children's, and caches up to 65,536 directory paths instead of 1,000. `mft_dump`'s CSV and bodyfile output take 11–12% fewer instructions there, and JSONL about 7%.

### Fixed
- Paths no longer depend on the order entries are resolved in when a corrupt MFT's parent references loop. A loop through a directory record without a `$FILE_NAME` is now cut at its named directory with the lowest entry number, as other loops are, and a directory a loop was cut at stays cut once it leaves the path cache.

## [0.9.0] - 2026-10-29

### Added
- Parse resident `$SECURITY_DESCRIPTOR` (0x50) attributes into `SecurityDescriptorAttr`: the control flags, owner and group SIDs, and the SACL and DACL with each ACE's type, flags, access mask, object types and SID. Non-resident ones keep their data runs.
- Parse `$EA_INFORMATION` (0xD0) and `$EA` (0xE0) into `EaInformationAttr` and `EaAttr`: each extended attribute's flags, name and value. WSL's `$LXUID`, `$LXGID`, `$LXMOD` and `$LXDEV` and code integrity's `$CI.CATALOGHINT` are decoded, and other values keep their data as hex.
- Parse the entries of view index roots, which index something other than file names, into `IndexEntries::view_entries`: `$Secure:$SDH` and `$SII` (each security descriptor's hash, id and place in `$SDS`), `$Extend\$Quota:$O` and `$Q` (quota owners and their usage and limits), `$Extend\$ObjId:$O` (object ids and their birth ids) and `$Extend\$Reparse:$R` (reparse tags by file). Entries of other view indexes keep their key and data as hex. As for `$I30`, only the entries in the root are read: a large index keeps the rest in `$INDEX_ALLOCATION`. The JSON adds a `view_entries` list only to these index roots.
- CSV output has `FileName`, `Lsn`, `Usn`, `SecurityId`, `ObjectId` and `AlternateDataStreams` columns (the file's name, its `$LogFile` sequence number, update sequence number, `$Secure` id, object id and the names of its named streams, `|`-separated), appended after `FileNameLastMftModified` so existing column positions don't move.
- `mft_dump -o csv --hard-link-rows` also writes a row for each other hard link of a file, with that link's path and `$FILE_NAME` columns, and `--stream-rows` a row for each named `$DATA` stream, with `FullPath` and `FileName` ending in `:<stream>` and the stream's size as `FileSize`. In the library, `FlatMftEntryWithName::rows_with_path` builds these rows and `MftParser::get_full_path_for_name` gives the path of a file under one of its names.

### Changed
- **Breaking:** `FlatMftEntryWithName` has new public fields for the new CSV columns, which breaks struct literals outside the crate.
- The CSV `FileName*` columns come from the file's best name (the one `FullPath` ends with: `Win32` over `POSIX` over `Dos`, including names in extension records) instead of its first `$FILE_NAME` attribute. Their times differ where Windows wrote the short name and the long name at different times, which is about 4% of the rows in our sample images.
- **Breaking:** `IndexEntries` has a new `view_entries` field, which breaks struct literals outside the crate.
- **Breaking:** `MftAttributeContent` has a new `AttrX50` variant, which breaks exhaustive matches, and resident `$SECURITY_DESCRIPTOR` JSON output changes from raw hex to the parsed descriptor.
- **Breaking:** `MftAttributeContent` has new `AttrXD0` and `AttrXE0` variants, and `$EA_INFORMATION` and `$EA` JSON output changes from raw hex to the parsed structures.
- **Breaking:** `EntryFlags`, `AttributeDataFlags`, `FileAttributeFlags`, `IndexRootFlags` and `IndexEntryFlags` values can hold bits without a name, so comparing one with `==` against named flags can now be false where it used to be true. JSON and CSV flag strings can end with a hex part, such as `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | 0x80000000`.

### Fixed
- View index roots, such as `$Secure:$SDH`, no longer show up with no entries.
- Flag fields keep bits that have no name (entry flags, attribute data flags, `$STANDARD_INFORMATION` and `$FILE_NAME` file attributes, and index flags) instead of dropping them, such as the `0x80000000` set on `$Extend\$RmMetadata\$Txf`.
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
