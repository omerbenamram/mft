//! `ewfinfo` – show meta data stored in EWF files.
//!
//! This binary is the CLI front-end for the `ewf` crate.
//!
//! - Image metadata reporting (`-f text|dfxml`, `-i`/`-m`/`-e`, `-A`, `-d`) is implemented here
//!   (binary-owned reporting/rendering), backed by spec-oriented metadata from `ewf::EwfReader`.
//! - Logical evidence outputs (`-F`, `-H`, `-B`) are **CLI-only** and intentionally live here (not
//!   in the library), mirroring libewf’s separation between `info_handle` printing routines and the
//!   core readers.
//!
//! References:
//! - `external/libewf/ewftools/ewfinfo.c`
//! - `external/libewf/ewftools/info_handle.c`
//! - `external/libewf/ewftools/bodyfile.c`
//! - `external/libewf/manuals/ewfinfo.1`

mod bodyfile;
mod cli;
mod ewfinfo;
mod logical;

use clap::Parser;

fn main() -> miette::Result<()> {
    cli::Cli::parse().run()
}
