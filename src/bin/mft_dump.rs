use clap::{App, Arg, ArgMatches};
use log::{error, warn};
use rustymft::mft::MftHandler;

use std::fs;

fn process_file(filename: &str, options: ArgMatches) -> bool {
    let mut mft_handler = match MftHandler::new(filename) {
        Ok(mft_handler) => mft_handler,
        Err(error) => {
            warn!("Could not parse file: {} [error: {}]", filename, error);
            return false;
        }
    };

    for i in 0..mft_handler.get_entry_count() {
        match mft_handler.entry(i) {
            Ok(mft_entry) => {
                let json_str = serde_json::to_string(&mft_entry).unwrap();
                println!("{}", json_str);
            }
            Err(error) => {
                error!("Could not mft_entry: {} [error: {}]", i, error);
                continue;
            }
        };
    }

    true
}

fn is_directory(source: &str) -> bool {
    fs::metadata(source).unwrap().file_type().is_dir()
}

fn main() {
    let matches = App::new("MFT Parser")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Omer B. <omerbenamram@gmail.com>")
        .about("Utility for parsing MFT snapshots")
        .arg(Arg::with_name("INPUT").required(true))
        .get_matches();

    process_file(matches.value_of("INPUT").expect("Required argument"));
}
