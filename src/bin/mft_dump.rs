use clap::{App, Arg, ArgMatches};
use env_logger;
use indoc::indoc;
use log::Level;

use mft::attribute::MftAttributeType;
use mft::mft::MftParser;
use mft::{MftEntry, ReadSeek};

use dialoguer::Confirmation;
use mft::csv::FlatMftEntryWithName;

use snafu::ErrorCompat;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;

use std::fmt::Write as FmtWrite;
use std::{fs, io, path};

/// Simple error macro for use inside of internal errors in `MftDump`
macro_rules! err {
    ($($tt:tt)*) => { Err(Box::<dyn std::error::Error>::from(format!($($tt)*))) }
}

type StdErr = Box<dyn std::error::Error>;

#[derive(Debug, PartialOrd, PartialEq)]
enum OutputFormat {
    JSON,
    JSONL,
    CSV,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "json" => Some(OutputFormat::JSON),
            "jsonl" => Some(OutputFormat::JSONL),
            "csv" => Some(OutputFormat::CSV),
            _ => None,
        }
    }
}

struct MftDump {
    filepath: PathBuf,
    // We use an option here to be able to move the output out of mftdump from a mutable reference.
    output: Option<Box<dyn Write>>,
    data_streams_output: Option<PathBuf>,
    verbosity_level: Option<Level>,
    output_format: OutputFormat,
    backtraces: bool,
}

impl MftDump {
    pub fn from_cli_matches(matches: &ArgMatches) -> Result<Self, StdErr> {
        let output_format =
            OutputFormat::from_str(matches.value_of("output-format").unwrap_or_default())
                .expect("Validated with clap default values");

        let backtraces = matches.is_present("backtraces");

        let output: Option<Box<dyn Write>> = if let Some(path) = matches.value_of("output-target") {
            match Self::create_output_file(path, !matches.is_present("no-confirm-overwrite")) {
                Ok(f) => Some(Box::new(f)),
                Err(e) => {
                    return err!(
                        "An error occurred while creating output file at `{}` - `{}`",
                        path,
                        e
                    );
                }
            }
        } else {
            Some(Box::new(io::stdout()))
        };

        let data_streams_output = if let Some(path) = matches.value_of("data-streams-target") {
            let path = PathBuf::from(path);
            Self::create_output_dir(&path)?;
            Some(path)
        } else {
            None
        };

        let verbosity_level = match matches.occurrences_of("verbose") {
            0 => None,
            1 => Some(Level::Info),
            2 => Some(Level::Debug),
            3 => Some(Level::Trace),
            _ => {
                eprintln!("using more than  -vvv does not affect verbosity level");
                Some(Level::Trace)
            }
        };

        Ok(MftDump {
            filepath: PathBuf::from(matches.value_of("INPUT").expect("Required argument")),
            output,
            data_streams_output,
            verbosity_level,
            output_format,
            backtraces,
        })
    }

    fn create_output_dir(path: impl AsRef<Path>) -> Result<(), StdErr> {
        let p = path.as_ref();

        if p.exists() {
            if !p.is_dir() {
                return err!("There is a file at {}, refusing to overwrite", p.display());
            }
        // p exists and is a directory, it's ok to add files.
        } else {
            fs::create_dir_all(path)?
        }

        Ok(())
    }

    /// If `prompt` is passed, will display a confirmation prompt before overwriting files.
    fn create_output_file(
        path: impl AsRef<Path>,
        prompt: bool,
    ) -> Result<File, Box<dyn std::error::Error>> {
        let p = path.as_ref();

        if p.is_dir() {
            return err!(
                "There is a directory at {}, refusing to overwrite",
                p.display()
            );
        }

        if p.exists() {
            if prompt {
                match Confirmation::new()
                    .with_text(&format!(
                        "Are you sure you want to override output file at {}",
                        p.display()
                    ))
                    .default(false)
                    .interact()
                {
                    Ok(true) => Ok(File::create(p)?),
                    Ok(false) => err!("Cancelled"),
                    Err(e) => err!(
                        "Failed to write confirmation prompt to term caused by\n{}",
                        e
                    ),
                }
            } else {
                Ok(File::create(p)?)
            }
        } else {
            // Ok to assume p is not an existing directory
            match p.parent() {
                Some(parent) =>
                // Parent exist
                {
                    if parent.exists() {
                        Ok(File::create(p)?)
                    } else {
                        fs::create_dir_all(parent)?;
                        Ok(File::create(p)?)
                    }
                }
                None => err!("Output file cannot be root."),
            }
        }
    }

    /// Main entry point for `EvtxDump`
    pub fn run(&mut self) -> Result<(), StdErr> {
        self.try_to_initialize_logging();

        let mut parser = match MftParser::from_path(&self.filepath) {
            Ok(parser) => parser,
            Err(e) => {
                return err!(
                    "Failed to open file {}.\n\tcaused by: {}",
                    self.filepath.display(),
                    &e
                )
            }
        };

        // Since the JSON parser can do away with a &mut Write, but the csv parser needs ownership
        // of `Write`, we eagerly create the csv writer here, moving the Box<Write> out from
        // `Mftdump` and replacing it with None placeholder.
        let mut csv_writer = match self.output_format {
            OutputFormat::CSV => {
                Some(csv::Writer::from_writer(self.output.take().expect(
                    "There can only be one flow accessing the output at a time",
                )))
            }
            _ => None,
        };

        let number_of_entries = parser.get_entry_count();
        for i in 0..number_of_entries {
            let entry = parser.get_entry(i);

            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    eprintln!("{}", error);

                    if self.backtraces {
                        if let Some(bt) = error.backtrace() {
                            eprintln!("{}", bt);
                        }
                    }
                    continue;
                }
            };

            if let Some(data_streams_dir) = &self.data_streams_output {
                if let Ok(Some(path)) = parser.get_full_path_for_entry(&entry) {
                    let sanitized_path = sanitized(&path.to_string_lossy().to_string());

                    for (i, (name, stream)) in entry
                        .iter_attributes()
                        .filter_map(|a| a.ok())
                        .filter_map(|a| {
                            if a.header.type_code == MftAttributeType::DATA {
                                // resident
                                let name = a.header.name.clone();
                                if let Some(data) = a.data.into_data() {
                                    Some((name, data))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .enumerate()
                    {
                        let orig_path_component: String = data_streams_dir
                            .join(&sanitized_path)
                            .to_string_lossy()
                            .to_string();

                        // Add some random bits to prevent collisions
                        let random: [u8; 6] = rand::random();
                        let rando_string: String = to_hex_string(&random);

                        let truncated: String = orig_path_component.chars().take(150).collect();
                        let data_stream_path = format!(
                            "{path}__{random}_{stream_number}_{stream_name}.dontrun",
                            path = truncated,
                            random = rando_string,
                            stream_number = i,
                            stream_name = name
                        );

                        if PathBuf::from(&data_stream_path).exists() {
                            return err!(
                                "Tried to override an existing stream {} already exists!\
                                 This is a bug, please report to github!",
                                data_stream_path
                            );
                        }

                        let mut f = File::create(&data_stream_path)?;
                        f.write_all(stream.data())?;
                    }
                }
            }

            match self.output_format {
                OutputFormat::JSON | OutputFormat::JSONL => self.print_json_entry(&entry)?,
                OutputFormat::CSV => self.print_csv_entry(
                    &entry,
                    &mut parser,
                    csv_writer
                        .as_mut()
                        .expect("CSV Writer is for OutputFormat::CSV"),
                )?,
            }
        }

        Ok(())
    }

    fn try_to_initialize_logging(&self) {
        if let Some(level) = self.verbosity_level {
            match simplelog::WriteLogger::init(
                level.to_level_filter(),
                simplelog::Config::default(),
                io::stderr(),
            ) {
                Ok(_) => {}
                Err(e) => eprintln!("Failed to initialize logging: {:?}", e),
            };
        }
    }

    pub fn print_json_entry(&mut self, entry: &MftEntry) -> Result<(), Box<dyn std::error::Error>> {
        let out = self
            .output
            .as_mut()
            .expect("CSV Flow cannot occur, so `Mftdump` should still Own `output`");

        let json_str = if self.output_format == OutputFormat::JSON {
            serde_json::to_vec_pretty(&entry).expect("It should be valid UTF-8")
        } else {
            serde_json::to_vec(&entry).expect("It should be valid UTF-8")
        };

        out.write_all(&json_str)?;
        out.write_all(b"\n")?;

        Ok(())
    }

    pub fn print_csv_entry<W: Write>(
        &self,
        entry: &MftEntry,
        parser: &mut MftParser<impl ReadSeek>,
        writer: &mut csv::Writer<W>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let flat_entry = FlatMftEntryWithName::from_entry(&entry, parser);

        writer.serialize(flat_entry)?;

        Ok(())
    }
}

fn to_hex_string(bytes: &[u8]) -> String {
    let len = bytes.len();
    // Each byte is represented by 2 ascii bytes.
    let mut s = String::with_capacity(len * 2);

    for byte in bytes {
        write!(s, "{:02X}", byte).expect("Writing to an allocated string cannot fail");
    }

    s
}

// adapter from python version
// https://github.com/pallets/werkzeug/blob/9394af646038abf8b59d6f866a1ea5189f6d46b8/src/werkzeug/utils.py#L414
pub fn sanitized(component: &str) -> String {
    let mut buf = String::with_capacity(component.len());
    for c in component.chars() {
        match c {
            _sep if path::is_separator(c) => buf.push('_'),
            _ => buf.push(c),
        }
    }

    buf
}

fn main() {
    env_logger::init();

    let matches = App::new("MFT Parser")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Omer B. <omerbenamram@gmail.com>")
        .about("Utility for parsing MFT snapshots")
        .arg(Arg::with_name("INPUT").required(true))
        .arg(
            Arg::with_name("output-format")
                .short("-o")
                .long("--output-format")
                .takes_value(true)
                .possible_values(&["csv", "json", "jsonl"])
                .default_value("json")
                .help("Output format."),
        )
        .arg(
            Arg::with_name("output-target")
                .long("--output")
                .short("-f")
                .takes_value(true)
                .help(indoc!("Writes output to the file specified instead of stdout, errors will still be printed to stderr.
                       Will ask for confirmation before overwriting files, to allow overwriting, pass `--no-confirm-overwrite`
                       Will create parent directories if needed.")),
        )
        .arg(
            Arg::with_name("data-streams-target")
                .long("--extract-resident-streams")
                .short("-e")
                .takes_value(true)
                .help(indoc!("Writes resident data streams to the given directory.
                             Resident streams will be named like - `{path}__<random_bytes>_{stream_number}_{stream_name}.dontrun`
                             random is added to prevent collisions.")),
        )
        .arg(
            Arg::with_name("no-confirm-overwrite")
                .long("--no-confirm-overwrite")
                .takes_value(false)
                .help(indoc!("When set, will not ask for confirmation before overwriting files, useful for automation")),
        )
        .arg(Arg::with_name("verbose")
            .short("-v")
            .multiple(true)
            .takes_value(false)
            .help(indoc!(r#"
            Sets debug prints level for the application:
                -v   - info
                -vv  - debug
                -vvv - trace
            NOTE: trace output is only available in debug builds, as it is extremely verbose."#))
        )
        .arg(
            Arg::with_name("backtraces")
                .long("--backtraces")
                .takes_value(false)
                .help("If set, a backtrace will be printed with some errors if available"))
        .get_matches();

    let mut app = match MftDump::from_cli_matches(&matches) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("An error occurred while setting up the app: {}", &e);
            exit(1);
        }
    };

    match app.run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("A runtime error has occurred {}", &e);
            exit(1);
        }
    };
}
