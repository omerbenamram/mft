use clap::{App, Arg, ArgMatches};
use env_logger;
use log::info;
use mft::err::Result;

use mft::attribute::FileAttributeFlags;
use mft::attribute::MftAttributeContent;
use mft::entry::EntryFlags;
use mft::mft::MftParser;
use mft::{MftAttribute, MftEntry, ReadSeek};
use serde::Serialize;

use chrono::{DateTime, Utc};
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

/// Used for CSV output
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FlatMftEntryWithName {
    pub signature: String,
    pub logfile_sequence_number: u64,
    pub sequence: u16,
    pub hard_link_count: u16,
    pub flags: EntryFlags,

    /// The size of the file, in bytes.
    pub used_entry_size: u32,
    pub total_entry_size: u32,

    pub parent_reference_entry: u64,
    pub parent_reference_sequence: u16,

    pub record_number: u64,
    pub entry_reference_entry: u64,

    /// Indicates whether the record is free or not.
    // TODO: implement
    pub in_use: bool,
    /// Indicates whether the record is a directory.
    pub is_a_directory: bool,
    /// The file extension (only for non-directories entries)
    pub entry_reference_sequence: u16,
    /// All of these fields are present for entries that have an 0x10 attribute.
    pub standard_info_flags: Option<FileAttributeFlags>,
    pub standard_info_last_modified: Option<DateTime<Utc>>,
    pub standard_info_last_access: Option<DateTime<Utc>>,
    pub standard_info_created: Option<DateTime<Utc>>,
    /// All of these fields are present for entries that have an 0x30 attribute.
    pub file_name_flags: Option<FileAttributeFlags>,
    pub file_name_last_modified: Option<DateTime<Utc>>,
    pub file_name_last_access: Option<DateTime<Utc>>,
    pub file_name_created: Option<DateTime<Utc>>,

    pub full_path: PathBuf,
}

impl FlatMftEntryWithName {
    pub fn from_entry(
        entry: &MftEntry,
        parser: &mut MftParser<impl ReadSeek>,
    ) -> FlatMftEntryWithName {
        let entry_attributes: Vec<MftAttribute> =
            entry.iter_attributes().filter_map(Result::ok).collect();

        let mut file_name = None;
        let mut standard_info = None;

        for attr in entry_attributes.iter() {
            if let MftAttributeContent::AttrX30(data) = &attr.data {
                file_name = Some(data.clone());
                break;
            }
        }
        for attr in entry_attributes.iter() {
            if let MftAttributeContent::AttrX10(data) = &attr.data {
                standard_info = Some(data.clone());
                break;
            }
        }

        FlatMftEntryWithName {
            record_number: entry.header.record_number,
            signature: String::from_utf8(entry.header.signature.to_ascii_uppercase()).unwrap(),
            logfile_sequence_number: entry.header.logfile_sequence_number,
            sequence: entry.header.sequence,
            hard_link_count: entry.header.hard_link_count,
            flags: entry.header.flags,
            used_entry_size: entry.header.used_entry_size,
            total_entry_size: entry.header.total_entry_size,
            parent_reference_entry: entry.header.base_reference.entry,
            parent_reference_sequence: entry.header.base_reference.sequence,
            entry_reference_entry: entry.header.entry_reference.entry,
            in_use: false,
            is_a_directory: entry.is_dir(),
            entry_reference_sequence: entry.header.entry_reference.sequence,
            standard_info_flags: standard_info.as_ref().and_then(|i| Some(i.file_flags)),
            standard_info_last_modified: standard_info.as_ref().and_then(|i| Some(i.modified)),
            standard_info_last_access: standard_info.as_ref().and_then(|i| Some(i.accessed)),
            standard_info_created: standard_info.as_ref().and_then(|i| Some(i.created)),
            file_name_flags: file_name.as_ref().and_then(|i| Some(i.flags)),
            file_name_last_modified: file_name.as_ref().and_then(|i| Some(i.modified)),
            file_name_last_access: file_name.as_ref().and_then(|i| Some(i.accessed)),
            file_name_created: file_name.as_ref().and_then(|i| Some(i.created)),
            full_path: parser
                .get_full_path_for_entry(entry)
                .expect("I/O Err")
                .unwrap_or_default(),
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
        // TODO: find a way to read entries in chunks without screwing double mutable references.
        let entires: Vec<Result<MftEntry>> = mft_handler.iter_entries().collect();

        let mut csv_writer = match self.output_format {
            OutputFormat::CSV => Some(csv::Writer::from_writer(io::stdout())),
            _ => None,
        };

        for (count, entry) in entires.iter().enumerate() {
            match entry {
                Ok(mft_entry) => match self.output_format {
                    OutputFormat::JSON => self.print_json_entry(&mft_entry),
                    OutputFormat::CSV => self.print_csv_entry(
                        &mft_entry,
                        &mut mft_handler,
                        csv_writer.as_mut().unwrap(),
                    ),
                },
                Err(error) => {
                    eprintln!(
                        "Failed to parse MFT entry {}, failed with: [{}]",
                        count, error
                    );
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
