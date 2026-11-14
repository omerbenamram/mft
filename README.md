# MFT

[![Build status](https://github.com/omerbenamram/mft/actions/workflows/test.yml/badge.svg)](https://github.com/omerbenamram/mft/actions/workflows/test.yml)
[![crates.io](https://img.shields.io/crates/v/mft.svg)](https://crates.io/crates/mft)
[![docs.rs](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.rs/mft)

`mft` reads the NTFS Master File Table (`$MFT`) and the other NTFS metadata files, without Windows. It comes as a command-line tool, `mft_dump`, and as a Rust library. Python bindings are in [pymft-rs](https://github.com/omerbenamram/pymft-rs) (`pip install mft`).

```console
$ mft_dump -o csv --stream-rows samples/MFT | grep ':Zone.Identifier' | cut -d, -f2,12,17,22
12938,true,2009-01-14T21:09:23.0913008Z,[Orphaned]\winzip120[1].exe:Zone.Identifier
```

That is entry number, deleted, created and path: a deleted download, found by its `Zone.Identifier` stream.

What it reads:

| File | What you get |
| --- | --- |
| `$MFT` | Every file and folder with its full path, sizes, flags, and the timestamps of both `$STANDARD_INFORMATION` and `$FILE_NAME`. Deleted files too, until their record is reused. |
| `$Extend\$UsnJrnl:$J` | The change journal: each create, write, rename and delete, with its time |
| `$I30` | A folder's index records, with the entries of deleted files recovered from slack space |
| `$LogFile` | The transaction log: the redo and undo operation of each record |
| `$Secure:$SDS` | Security descriptors, each with its security ID, owner and SDDL |
| `$Boot` | The boot sector: cluster size, `$MFT` location, record sizes, volume serial |

The crate has no `unsafe` code and runs wherever Rust's standard library does. The minimum supported Rust version is 1.90.

## Install

- Download `mft_dump` for Windows, macOS or Linux (64-bit) from the [releases page](https://github.com/omerbenamram/mft/releases).
- Or build it: `cargo install mft`.

## `mft_dump`

```bash
mft_dump '$MFT'                                  # JSON, every attribute of every record
mft_dump -o jsonl '$MFT'                         # the same, one record per line
mft_dump -o csv '$MFT'                           # one row per file, for Timeline Explorer or a spreadsheet
mft_dump -o csv --hard-link-rows --stream-rows '$MFT'   # plus a row for each hard link and each alternate data stream
mft_dump -o bodyfile '$MFT'                      # Sleuth Kit bodyfile lines, for mactime
mft_dump -r 0-15,30 '$MFT'                       # only these record numbers
mft_dump -e streams/ -o json -f /dev/null --no-confirm-overwrite '$MFT'   # write resident data streams to streams/
```

Quote `'$MFT'` in a Unix shell, or it expands to nothing. `mft_dump --help` lists every option.

A resident stream is one small enough to be stored inside the MFT record, up to about 700 bytes. `-e` gets those back without the disk image: `Zone.Identifier` streams, small scripts, `desktop.ini` files. Each is written with a `.dontrun` extension.

The other NTFS files go through the same command. `mft_dump` tells them apart by their first bytes, and `--input-type` overrides that:

```bash
mft_dump -o csv --mft '$MFT' '$J'      # the change journal, with each file's full path from the $MFT
mft_dump -o csv --mft '$MFT' '$I30'    # a folder's index, with a FromSlack column for recovered entries
mft_dump -o csv '$LogFile'             # the transaction log, with the file names that index operations add or remove
mft_dump -o csv '$SDS'                 # security descriptors
mft_dump '$Boot'                       # the boot sector
```

## As a library

```rust,no_run
use mft::MftParser;
use mft::attribute::MftAttributeContent;
use std::path::PathBuf;

fn main() {
    // Change this to a path of your MFT sample.
    let fp = PathBuf::from(format!("{}/samples/MFT", std::env::var("CARGO_MANIFEST_DIR").unwrap()));

    let mut parser = MftParser::from_path(fp).unwrap();
    for entry in parser.iter_entries() {
        match entry {
            Ok(e) => {
                for attribute in e.iter_attributes().filter_map(|attr| attr.ok()) {
                    match attribute.data {
                        // $STANDARD_INFORMATION
                        MftAttributeContent::AttrX10(standard_info) => {
                            println!("\tX10 attribute: {:#?}", standard_info)
                        }
                        // $FILE_NAME
                        MftAttributeContent::AttrX30(filename_attribute) => {
                            println!("\tX30 attribute: {:#?}", filename_attribute)
                        }
                        _ => {
                            println!("\tSome other attribute: {:#?}", attribute)
                        }
                    }
                }
            }
            // A damaged record is an error for that record only.
            Err(err) => eprintln!("{}", err),
        }
    }
}
```

`MftParser::get_full_path_for_entry` gives an entry's path. The modules `mft::usn`, `mft::indx`, `mft::logfile`, `mft::sds` and `mft::boot` read the other files. The API reference is on [docs.rs](https://docs.rs/mft).

## Performance

`mft_dump -o csv` reads the 13 MB sample in this repository (`samples/MFT`, 13,068 records) in about 45 ms on a 4-core machine, and a 124 MB `$MFT` with 127,480 records in about half a second.

If you work on the parser, measure before and after on that sample:

```bash
cargo build --release --bin mft_dump

# Whole-program time, with the output sent to /dev/null.
hyperfine --warmup 3 --runs 20 \
  './target/release/mft_dump samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite' \
  './target/release/mft_dump samples/MFT -o csv -f /dev/null --no-confirm-overwrite'

# A CPU profile of the same run, to open in the Firefox Profiler.
mkdir -p target/samply
samply record --save-only --unstable-presymbolicate \
  -o target/samply/mft_dump_jsonl.profile.json.gz \
  --iteration-count 200 -- \
  ./target/release/mft_dump samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite
samply load target/samply/mft_dump_jsonl.profile.json.gz
```

In the profiler, the **Call Tree** tab with **Invert call stack** on shows the functions where time is spent, and with it off shows inclusive time from the top down. **Filter stack** narrows the view to `mft::` or `mft_dump::` frames. [`PERF.md`](PERF.md) has the full protocol and the log of what was tried.

## Resources
 - https://docs.microsoft.com/en-us/windows/desktop/DevNotes/master-file-table
 - https://github.com/libyal/libfsntfs/blob/master/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc
 - https://github.com/forensicmatt/RustyMft

## Test data

Some test data under `testdata/` comes from third parties and has its own licence, listed next to it: `testdata/ntfs/README.md` for the NTFS images, and `testdata/win11/NOTICE.md`
for the Windows 11 records (CC-BY-4.0). `testdata/` isn't part of the published crate.
