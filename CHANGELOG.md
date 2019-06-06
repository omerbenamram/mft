# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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