use clap::{App, Arg};
use log::{error, warn};
use mft::mft::MftHandler;



fn process_file(filename: &str) -> bool {
    let mut mft_handler = match MftHandler::from_path(filename) {
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

fn main() {
    let matches = App::new("MFT Parser")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Omer B. <omerbenamram@gmail.com>")
        .about("Utility for parsing MFT snapshots")
        .arg(Arg::with_name("INPUT").required(true))
        .get_matches();

    process_file(matches.value_of("INPUT").expect("Required argument"));
}
