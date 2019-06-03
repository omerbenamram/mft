[![Build Status](https://dev.azure.com/benamram/DFIR/_apis/build/status/omerbenamram.mft?branchName=master)](https://dev.azure.com/benamram/DFIR/_build/latest?definitionId=5&branchName=master)
![crates.io](https://img.shields.io/crates/v/mft.svg)

# MFT
 
This is a parser for the MFT (master file table) format.

Supported rust version is latest stable rust (minimum 1.34) or nightly.

[Documentation](https://docs.rs/mft)

Python bindings are available as well at https://github.com/omerbenamram/pymft-rs (and at PyPi https://pypi.org/project/mft/)

## Features
 - Implemented using 100% safe rust - and works on all platforms supported by rust (that have stdlib).
 - Supports JSON and CSV outputs.
 - Supports extracting resident data streams.

## Installation (associated binary utility):
  - Download latest executable release from https://github.com/omerbenamram/mft/releases
    - Releases are automatically built for for Windows, macOS, and Linux. (64-bit executables only)
  - Build from sources using  `cargo install mft`
  
# `mft_dump` (Binary utility):
The main binary utility provided with this crate is `mft_dump`, and it provides a quick way to convert mft snapshots to different output formats.

Some examples
  - `mft_dump <evtx_file>` will dump contents of mft entries as JSON.
  - `mft_dump -o csv <evtx_file>` will dump contents of mft entries as CSV. 
  - `mft_dump -e <output_directory> -o json <input_file>` will extract all resident streams in MFT to files.

# Library usage:
```rust,no_run
use mft::MftParser;
use mft::attribute::MftAttributeContent;
use std::path::PathBuf;

fn main() {
    // Change this to a path of your .evtx sample. 
    let fp = PathBuf::from(format!("{}/samples/MFT", std::env::var("CARGO_MANIFEST_DIR").unwrap())); 
    
    let mut parser = MftParser::from_path(fp).unwrap();
    for entry in parser.iter_entries() {
        match entry {
            Ok(e) =>  {
                for attribute in e.iter_attributes().filter_map(|attr| attr.ok()) {
                    match attribute.data {
                        MftAttributeContent::AttrX10(standard_info) => {
                            println!("\tX10 attribute: {:#?}", standard_info)         
                        },
                        MftAttributeContent::AttrX30(filename_attribute) => {
                            println!("\tX30 attribute: {:#?}", filename_attribute)         
                        },
                        _ => {
                            println!("\tSome other attribute: {:#?}", attribute)
                        }
                    }
                   
                }
            }
            Err(err) => eprintln!("{}", err),
        }
    }
}
```

## Thanks/Resources:
 - https://docs.microsoft.com/en-us/windows/desktop/DevNotes/master-file-table
 - https://github.com/libyal/libfsntfs/blob/master/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc
 - https://github.com/forensicmatt/RustyMft
