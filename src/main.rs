#[macro_use] extern crate log;
extern crate rustymft;
extern crate rwinstructs;
extern crate serde_json;
extern crate serde;
extern crate clap;
use log::LogLevel::Debug;
use clap::{App, Arg};
use rustymft::mft::{MftHandler};
use rwinstructs::reference;
use rwinstructs::serialize;
use serde::Serializer;
use serde::ser::SerializeSeq;
use std::fs;
use std::io;

fn process_directory<S>(directory: &str, serializer: S) where S: serde::Serializer {
    let mut seq = serializer.serialize_seq(None).unwrap();
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            let path_string = path.into_os_string().into_string().unwrap();
            if path_string.ends_with("mft"){
                process_file(&path_string,&mut seq);
            }
        }
    }
    seq.end().unwrap();
}

fn process_file<S: serde::ser::SerializeSeq>(filename: &str, serializer: &mut S) -> bool {
    // Check if file is a prefetch file
    let mut mft_handler = match MftHandler::new(filename) {
        Ok(mft_handler) => mft_handler,
        Err(error) => {
            warn!("Could not parse file: {} [error: {}]", filename, error);
            return false;
        }
    };

    for i in 0 .. mft_handler.get_entry_count() {
        let mft_entry = mft_handler.entry(i).unwrap();
        serializer.serialize_element(&mft_entry).unwrap();
    }

    return true;
}

fn is_directory(source: &str)->bool{
    fs::metadata(source).unwrap().file_type().is_dir()
}

fn main() {
    let source_arg = Arg::with_name("source")
        .short("s")
        .long("source")
        .value_name("FILE")
        .help("The source path. Can be a file or a directory.")
        .required(true)
        .takes_value(true);

    let options = App::new("RustyMft")
        .version("0.0.0")
        .author("Matthew Seyer <https://github.com/forensicmatt/RustyMft>")
        .about("Parse $MFT.")
        .arg(source_arg)
        .get_matches();

    // Set Reference Display Options
    unsafe{reference::NESTED_REFERENCE = true;}
    unsafe{serialize::U64_SERIALIZATION = serialize::U64Serialization::AsString;}

    let source = options.value_of("source").unwrap();

    let mut serializer = serde_json::Serializer::pretty(
        io::stdout()
    );

    if is_directory(source) {
        panic!("Directory source is not implemented yet.");
    } else {
        let mut seq = serializer.serialize_seq(None).unwrap();
        process_file(source,&mut seq);
        seq.end().unwrap();
    }
}
