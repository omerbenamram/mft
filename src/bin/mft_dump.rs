use clap::{App, Arg, ArgMatches};
use env_logger;
use log::info;
use mft::err::Result;

use mft::attribute::MftAttributeContent;
use mft::attribute::{FileAttributeFlags, MftAttributeType};
use mft::entry::EntryFlags;
use mft::mft::MftParser;
use mft::{MftAttribute, MftEntry, ReadSeek};
use serde::Serialize;

use chrono::{DateTime, Utc};
use mft::attribute::x30::FileNamespace;
use mft::attribute::MftAttributeType::FileName;
use mft::csv::FlatMftEntryWithName;
use std::cmp::max;
use std::io;
use std::io::Write;
use std::path::PathBuf;

enum OutputFormat {
    JSON,
    CSV,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "json" => Some(OutputFormat::JSON),
            "csv" => Some(OutputFormat::CSV),
            _ => None,
        }
    }
}

struct MftDump {
    filepath: PathBuf,
    indent: bool,
    output_format: OutputFormat,
}

impl MftDump {
    pub fn from_cli_matches(matches: &ArgMatches) -> Self {
        MftDump {
            filepath: PathBuf::from(matches.value_of("INPUT").expect("Required argument")),
            indent: !matches.is_present("no-indent"),
            output_format: OutputFormat::from_str(
                matches.value_of("output-format").unwrap_or_default(),
            )
            .expect("Validated with clap default values"),
        }
    }

    pub fn print_json_entry(&self, entry: &MftEntry) {
        let json_str = if self.indent {
            serde_json::to_string_pretty(&entry).expect("It should be valid UTF-8")
        } else {
            serde_json::to_string(&entry).expect("It should be valid UTF-8")
        };

        println!("{}", json_str);
    }

    pub fn print_csv_entry<W: Write>(
        &self,
        entry: &MftEntry,
        parser: &mut MftParser<impl ReadSeek>,
        writer: &mut csv::Writer<W>,
    ) {
        let flat_entry = FlatMftEntryWithName::from_entry(&entry, parser);

        writer.serialize(flat_entry).expect("Writing to CSV failed");
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

        let mut csv_writer = match self.output_format {
            OutputFormat::CSV => Some(csv::Writer::from_writer(io::stdout())),
            _ => None,
        };

        let number_of_entries = mft_handler.get_entry_count();

        let chunk_size = 1000;
        let mut chunk_count = 0;
        let mut entry_count = 0;

        while entry_count <= number_of_entries {
            let mut chunk = vec![];

            let start = chunk_count * chunk_size;
            let end = max(start + chunk_size, number_of_entries);

            for i in start..end {
                let entry = mft_handler.get_entry(i);

                match entry {
                    Ok(entry) => chunk.push(entry),
                    Err(error) => {
                        eprintln!("Failed to parse MFT entry {}, failed with: [{}]", i, error);
                    }
                }
                entry_count += 1;
            }

            for entry in chunk.iter() {
                match self.output_format {
                    OutputFormat::JSON => self.print_json_entry(entry),
                    OutputFormat::CSV => self.print_csv_entry(
                        entry,
                        &mut mft_handler,
                        csv_writer
                            .as_mut()
                            .expect("CSV Writer is for OutputFormat::CSV"),
                    ),
                }
            }

            chunk_count += 1;
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
                .help("When set, output will not be indented (works only with JSON output)."),
        )
        .arg(
            Arg::with_name("output-format")
                .short("-o")
                .long("--output-format")
                .takes_value(true)
                .possible_values(&["csv", "json"])
                .default_value("json")
                .help("Output format."),
        )
        .get_matches();

    let app = MftDump::from_cli_matches(&matches);
    app.parse_file();
}
