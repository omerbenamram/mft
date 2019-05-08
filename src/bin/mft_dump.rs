use clap::{App, Arg};
use env_logger;
use log::{debug, error, info, warn};
use mft::mft::MftHandler;

fn process_file(filename: &str, indent: bool) -> bool {
    info!("Opening file {}", filename);
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
                let json_str = if indent {
                    serde_json::to_string_pretty(&mft_entry).unwrap()
                } else {
                    serde_json::to_string(&mft_entry).unwrap()
                };

                println!("{}", json_str);
            }
            Err(error) => {
                println!("Could not mft_entry: {} [error: {}]", i, error);
                continue;
            }
        };
    }

    true
}

fn main() {
    env_logger::init();

    let matches = App::new("MFT Parser")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Omer B. <omerbenamram@gmail.com>")
        .about("Utility for parsing MFT snapshots")
        .arg(Arg::with_name("INPUT").required(true))
        .arg(
            Arg::with_name("no-indent")
                .long("--no-indent")
                .takes_value(false)
                .help("When set, output will not be indented."),
        )
        .get_matches();

    let indent = !matches.is_present("no-indent");
    process_file(
        matches.value_of("INPUT").expect("Required argument"),
        indent,
    );
}
