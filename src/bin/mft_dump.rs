use clap::{App, Arg, ArgMatches};
use env_logger;
use log::{info};

use mft::mft::MftParser;
use std::path::PathBuf;

struct MftDump {
    filepath: PathBuf,
    indent: bool,
}

impl MftDump {
    pub fn from_cli_matches(matches: &ArgMatches) -> Self {
        MftDump {
            filepath: PathBuf::from(matches.value_of("INPUT").expect("Required argument")),
            indent: !matches.is_present("no-indent"),
        }
    }

    pub fn parse_file(&self) {
        info!("Opening file {:?}", &self.filepath);
        let mut mft_handler = match MftParser::from_path(&self.filepath) {
            Ok(mft_handler) => mft_handler,
            Err(error) => {
                eprintln!(
                    "Failed to parse {:?}, failed with: [{}]",
                    &self.filepath, error
                );
                std::process::exit(-1);
            }
        };

        for (i, entry) in mft_handler.iter_entries().enumerate() {
            match entry {
                Ok(mft_entry) => {
                    let json_str = if self.indent {
                        serde_json::to_string_pretty(&mft_entry).unwrap()
                    } else {
                        serde_json::to_string(&mft_entry).unwrap()
                    };

                    println!("{}", json_str);
                }
                Err(error) => {
                    eprintln!("Failed to parse MFT entry {}, failed with: [{}]", i, error);
                    continue;
                }
            }
        }
    }
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

    let app = MftDump::from_cli_matches(&matches);
    app.parse_file();
}
