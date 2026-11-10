#![forbid(unsafe_code)]
use clap::{Arg, ArgAction, ArgMatches};
use indoc::indoc;
use log::Level;
use serde::Serialize;

use mft::MftEntry;
use mft::attribute::MftAttributeType;
use mft::boot::{BOOT_SECTOR_SIZE, BootSector};
use mft::indx::{FlatIndxEntry, IndxEntry, IndxFile};
use mft::logfile::{FlatLogRecord, LogFile};
use mft::mft::MftParser;
use mft::sds::{FlatSdsEntry, SdsEntries, SdsEntry};
use mft::usn::{FlatUsnRecord, UsnJournal, UsnRecord};

use dialoguer::Confirm;
use mft::csv::{CsvRows, FlatMftEntryWithName};

use anyhow::anyhow;
use anyhow::{Context, Error, Result};
use sonic_rs as sonic_json;
use std::backtrace::Backtrace;
use std::fmt::{self, Write as FmtWrite};
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use mft::entry::ZERO_HEADER;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::{fs, io, path};

#[derive(Debug, Clone, Copy, PartialOrd, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
enum OutputFormat {
    JSON,
    JSONL,
    CSV,
    Bodyfile,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "json" => Some(OutputFormat::JSON),
            "jsonl" => Some(OutputFormat::JSONL),
            "csv" => Some(OutputFormat::CSV),
            "bodyfile" => Some(OutputFormat::Bodyfile),
            _ => None,
        }
    }
}

/// What kind of file `INPUT` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputType {
    Mft,
    /// The `$UsnJrnl:$J` change journal.
    Usn,
    /// A directory's `$INDEX_ALLOCATION:$I30` stream of `INDX` records.
    I30,
    /// The `$Boot` file, or the first sector of a volume.
    Boot,
    /// The `$Secure:$SDS` stream of security descriptors.
    Sds,
    /// The `$LogFile` transaction log.
    LogFile,
}

impl InputType {
    /// Tells an `$MFT` (which starts with a `FILE` or `BAAD` record), an `$I30` (an `INDX`
    /// record), a `$LogFile` (an `RSTR` or `CHKD` restart page, or with that page damaged, the
    /// second restart page or the first record page after them), a `$Boot` (`NTFS    ` at offset
    /// 3) and an `$SDS` (an entry at offset 0 whose hash matches its descriptor, there or in the
    /// copy of the first block) from a `$J`
    /// (whose first bytes that aren't zero are a USN record).
    /// The sparse start of a `$J` can run to gigabytes of zeros, so all of it is skipped. Anything
    /// else is read as an `$MFT`, as before `$J` support, such as an `$MFT` whose first record
    /// was wiped.
    fn detect(path: &Path) -> Result<Self> {
        let mut f = File::open(path)?;
        let mut start = Vec::new();
        // Enough for the signatures of a `$LogFile`'s second restart page and first record page
        // when its pages are 64 KiB, the largest there is.
        (&mut f).take((2 << 16) + 4).read_to_end(&mut start)?;
        match start.get(..4) {
            Some(b"FILE" | b"BAAD") => return Ok(InputType::Mft),
            Some(b"INDX") => return Ok(InputType::I30),
            // `chkdsk` marks the restart pages it has worked on `CHKD`.
            Some(b"RSTR" | b"CHKD") => return Ok(InputType::LogFile),
            _ => {}
        }
        if start.get(3..11) == Some(b"NTFS    ") {
            return Ok(InputType::Boot);
        }
        // An `$SDS` whose first entry is damaged has it again in the copy of its first block.
        let mut sds_mirror_start = Vec::new();
        f.seek(SeekFrom::Start(mft::sds::SDS_BLOCK_SIZE as u64))?;
        (&mut f).take(1 << 16).read_to_end(&mut sds_mirror_start)?;
        if mft::sds::looks_like(&start, &sds_mirror_start) {
            return Ok(InputType::Sds);
        }
        // A `$LogFile` whose first restart page is damaged still has the second one, a page
        // on, and its record pages after the two.
        let signature_at = |at: usize| start.get(at..at + 4);
        if (9..=16).map(|bits| 1usize << bits).any(|page_size| {
            matches!(signature_at(page_size), Some(b"RSTR" | b"CHKD"))
                || signature_at(2 * page_size) == Some(b"RCRD")
        }) {
            return Ok(InputType::LogFile);
        }
        f.rewind()?;
        match UsnJournal::new(f).next() {
            Some(Ok(_)) => Ok(InputType::Usn),
            // An `$I30` can start with records that were allocated but never used, all zeros.
            Some(Err(mft::err::Error::InvalidUsnRecord { offset, .. })) if offset % 512 == 0 => {
                let mut f = File::open(path)?;
                f.seek(SeekFrom::Start(offset))?;
                let mut signature = [0u8; 4];
                let read = f.read(&mut signature)?;
                if read == 4 && &signature == b"INDX" {
                    Ok(InputType::I30)
                } else {
                    Ok(InputType::Mft)
                }
            }
            Some(Err(mft::err::Error::InvalidUsnRecord { .. })) | None => Ok(InputType::Mft),
            Some(Err(error)) => Err(error.into()),
        }
    }
}

struct Ranges(Vec<RangeInclusive<usize>>);

impl Ranges {
    pub fn chain(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().cloned().flatten()
    }
}

impl FromStr for Ranges {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut ranges = vec![];
        for x in s.split(',') {
            // range
            if x.contains('-') {
                let range: Vec<&str> = x.split('-').collect();
                if range.len() != 2 {
                    return Err(anyhow!(
                        "Failed to parse ranges: Range should contain exactly one `-`, found {x}"
                    ));
                }

                ranges.push(range[0].parse()?..=range[1].parse()?);
            } else {
                let n = x.parse()?;
                ranges.push(n..=n);
            }
        }

        Ok(Ranges(ranges))
    }
}

/// A JSON output record: the entry plus its full path, which only the parser can resolve.
#[derive(Serialize)]
struct JsonEntry<'a> {
    #[serde(serialize_with = "mft::serialize_option_windows_path")]
    full_path: Option<PathBuf>,
    #[serde(flatten)]
    entry: &'a MftEntry,
}

/// A JSON output record for a `$J` or `$I30` input: the record plus the file's full path, when
/// an `$MFT` was given to resolve it.
#[derive(Serialize)]
struct JsonWithPath<'a, T> {
    #[serde(
        serialize_with = "mft::serialize_option_windows_path",
        skip_serializing_if = "Option::is_none"
    )]
    full_path: Option<PathBuf>,
    #[serde(flatten)]
    value: &'a T,
}

/// An `$I30` index entry with the index record it is in.
#[derive(Serialize)]
struct JsonIndxEntry<'a> {
    record_vcn: u64,
    record_lsn: u64,
    record_valid_fixup: bool,
    #[serde(flatten)]
    entry: &'a IndxEntry<'a>,
}

/// An `$SDS` entry, with its descriptor as SDDL too.
#[derive(Serialize)]
struct JsonSdsEntry<'a> {
    sddl: Option<String>,
    #[serde(flatten)]
    entry: &'a SdsEntry<'a>,
}

struct MftDump {
    filepath: PathBuf,
    // We use an option here to be able to move the output out of mftdump from a mutable reference.
    output: Option<Box<dyn Write>>,
    data_streams_output: Option<PathBuf>,
    verbosity_level: Option<Level>,
    output_format: OutputFormat,
    ranges: Option<Ranges>,
    json_buf: Vec<u8>,
    backtraces_enabled: bool,
    csv_rows: CsvRows,
    input_type: Option<InputType>,
    /// The `$MFT` to resolve the paths of the files in a `$J` with.
    paths_mft: Option<PathBuf>,
}

impl MftDump {
    pub fn from_cli_matches(matches: &ArgMatches) -> Result<Self> {
        let output_format: &String = matches.get_one("output-format").expect("has default");
        let output_target: Option<&String> = matches.get_one("output-target");
        let data_streams_target: Option<&String> = matches.get_one("data-streams-target");
        let input: &String = matches.get_one("INPUT").expect("required");

        let output_format =
            OutputFormat::from_str(output_format).expect("Validated with clap default values");
        let backtraces_enabled = matches.get_flag("backtraces");

        // Checked before the output file is created, which would truncate it.
        let csv_rows = CsvRows {
            hard_links: matches.get_flag("hard-link-rows"),
            streams: matches.get_flag("stream-rows"),
        };
        if csv_rows.any() && output_format != OutputFormat::CSV {
            return Err(anyhow!(
                "`--hard-link-rows` and `--stream-rows` only apply to `-o csv`"
            ));
        }

        let output: Option<Box<dyn Write>> = if let Some(path) = output_target {
            match Self::create_output_file(path, !matches.get_flag("no-confirm-overwrite")) {
                Ok(f) => Some(Box::new(BufWriter::with_capacity(1 << 16, f))),
                Err(e) => {
                    return Err(anyhow!(
                        "An error occurred while creating output file at `{path}` - `{e}`"
                    ));
                }
            }
        } else {
            Some(Box::new(BufWriter::with_capacity(1 << 16, io::stdout())))
        };

        let data_streams_output = if let Some(path) = data_streams_target {
            let path = PathBuf::from(path);
            Self::create_output_dir(&path)?;
            Some(path)
        } else {
            None
        };

        let verbosity_level = match matches.get_count("verbose") {
            0 => None,
            1 => Some(Level::Info),
            2 => Some(Level::Debug),
            3 => Some(Level::Trace),
            _ => {
                eprintln!("using more than  -vvv does not affect verbosity level");
                Some(Level::Trace)
            }
        };

        let input_type = match matches.get_one::<String>("input-type").map(String::as_str) {
            Some("mft") => Some(InputType::Mft),
            Some("usn") => Some(InputType::Usn),
            Some("i30") => Some(InputType::I30),
            Some("boot") => Some(InputType::Boot),
            Some("sds") => Some(InputType::Sds),
            Some("logfile") => Some(InputType::LogFile),
            _ => None,
        };
        let paths_mft = matches.get_one::<String>("mft").map(PathBuf::from);

        let ranges = match matches.get_one::<String>("entry-range") {
            Some(range) => Some(Ranges::from_str(range)?),
            None => None,
        };

        Ok(MftDump {
            filepath: PathBuf::from(input),
            output,
            data_streams_output,
            verbosity_level,
            output_format,
            ranges,
            json_buf: Vec::with_capacity(64 * 1024),
            backtraces_enabled,
            csv_rows,
            input_type,
            paths_mft,
        })
    }

    fn create_output_dir(path: impl AsRef<Path>) -> Result<()> {
        let p = path.as_ref();

        if p.exists() {
            if !p.is_dir() {
                return Err(anyhow!(
                    "There is a file at {}, refusing to overwrite",
                    p.display()
                ));
            }
        // p exists and is a directory, it's ok to add files.
        } else {
            fs::create_dir_all(path)?
        }

        Ok(())
    }

    /// If `prompt` is passed, will display a confirmation prompt before overwriting files.
    fn create_output_file(path: impl AsRef<Path>, prompt: bool) -> Result<File> {
        let p = path.as_ref();

        if p.is_dir() {
            return Err(anyhow!(
                "There is a directory at {}, refusing to overwrite",
                p.display()
            ));
        }

        if p.exists() {
            if prompt {
                match Confirm::new()
                    .with_prompt(format!(
                        "Are you sure you want to override output file at {}",
                        p.display()
                    ))
                    .default(false)
                    .interact()
                {
                    Ok(true) => Ok(File::create(p)?),
                    Ok(false) => Err(anyhow!("Cancelled")),
                    Err(e) => Err(anyhow!(
                        "Failed to write confirmation prompt to term caused by\n{e}"
                    )),
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
                None => Err(anyhow!("Output file cannot be root.")),
            }
        }
    }

    /// Main entry point for `EvtxDump`
    pub fn run(&mut self) -> Result<()> {
        self.try_to_initialize_logging();

        let input_type = match self.input_type {
            Some(input_type) => input_type,
            None => InputType::detect(&self.filepath)?,
        };
        match input_type {
            InputType::Usn => return self.run_usn(),
            InputType::I30 => return self.run_i30(),
            InputType::Boot => return self.run_boot(),
            InputType::Sds => return self.run_sds(),
            InputType::LogFile => return self.run_logfile(),
            InputType::Mft => {}
        }
        if self.paths_mft.is_some() {
            return Err(anyhow!("`--mft` only applies to a `$J` or `$I30` input"));
        }

        let mut parser = MftParser::from_path(&self.filepath)?;

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

        // Move ranges out of self here to avoid immutably locking self during
        // the `for i in entries` loop.
        let take_ranges = self.ranges.take();

        let entries = match take_ranges {
            Some(ref ranges) => Box::new(ranges.chain()),
            None => Box::new(0..number_of_entries as usize) as Box<dyn Iterator<Item = usize>>,
        };

        for i in entries {
            let entry = parser.get_entry(i as u64);

            let entry = match entry {
                Ok(entry) => match &entry.header.signature {
                    ZERO_HEADER => continue,
                    _ => entry,
                },
                Err(error) => {
                    eprintln!("{error}");
                    continue;
                }
            };

            let full_path = parser.get_full_path_for_entry(&entry).ok().flatten();
            // Exported streams, CSV and bodyfile describe a file rather than one record, so they
            // include the attributes stored in its extension records.
            let extensions = if self.data_streams_output.is_some()
                || matches!(
                    self.output_format,
                    OutputFormat::CSV | OutputFormat::Bodyfile
                ) {
                parser.get_extension_entries(&entry)
            } else {
                Vec::new()
            };

            if let Some(data_streams_dir) = &self.data_streams_output
                // An extension record's streams are exported with its base entry, under the
                // file's path. Only an extension that its base entry doesn't list exports its own.
                && (entry.header.is_base_record() || !is_listed_by_its_base(&mut parser, &entry))
                && let Some(path) = &full_path
            {
                let sanitized_path = sanitized(&path.to_string_lossy());

                for (i, (name, stream)) in std::iter::once(&entry)
                    .chain(&extensions)
                    .flat_map(|record| record.iter_attributes())
                    .filter_map(|a| a.ok())
                    .filter_map(|a| {
                        if a.header.type_code == MftAttributeType::DATA {
                            // resident
                            let name = a.header.name;
                            a.data
                                .as_data()
                                .copied()
                                // Empty streams carry no content, don't litter the output with them.
                                .filter(|data| !data.data().is_empty())
                                .map(|data| (name, data))
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
                    let data_stream_path =
                        format!("{truncated}__{rando_string}_{i}_{name}.dontrun");

                    if PathBuf::from(&data_stream_path).exists() {
                        return Err(anyhow!(
                            "Tried to override an existing stream {data_stream_path} already exists!\
                                 This is a bug, please report to github!"
                        ));
                    }

                    let mut f = File::create(&data_stream_path)?;
                    f.write_all(stream.data())?;
                }
            }

            match self.output_format {
                OutputFormat::JSON | OutputFormat::JSONL => {
                    self.print_json_entry(&entry, full_path)?
                }
                OutputFormat::Bodyfile => {
                    self.print_bodyfile_entry(&entry, &extensions, full_path)?
                }
                OutputFormat::CSV => self.print_csv_entry(
                    &mut parser,
                    &entry,
                    &extensions,
                    full_path,
                    csv_writer
                        .as_mut()
                        .expect("CSV Writer is for OutputFormat::CSV"),
                )?,
            }
        }

        Ok(())
    }

    /// Dumps the records of a `$J` change journal.
    fn run_usn(&mut self) -> Result<()> {
        let mut parser = self.open_for_other_input("$J")?;
        let records =
            UsnJournal::new(File::open(&self.filepath)?).filter_map(|record| match record {
                Ok(record) => Some(Ok(record)),
                Err(error @ mft::err::Error::InvalidUsnRecord { .. }) => {
                    eprintln!("{error}");
                    None
                }
                Err(error) => Some(Err(error)),
            });
        let mut full_path = |record: &UsnRecord| {
            let (parser, name) = (parser.as_mut()?, record.name()?);
            Some(parser.get_full_path_in_directory(
                record.file_reference.entry,
                name,
                record.parent_reference,
            ))
        };
        let mut sink = self.take_sink();
        for record in records {
            let record = record?;
            let full_path = full_path(&record);
            match &mut sink {
                Sink::Csv(writer) => {
                    writer.serialize(FlatUsnRecord::from_record(&record, full_path))?
                }
                Sink::Json(out) => {
                    let json_record = JsonWithPath {
                        full_path,
                        value: &record,
                    };
                    write_json_line(&mut self.json_buf, self.output_format, out, &json_record)?;
                }
            }
        }
        sink.flush()
    }

    /// Dumps the entries of a directory's `$I30` index records, live ones and the ones recovered
    /// from slack space.
    fn run_i30(&mut self) -> Result<()> {
        let mut parser = self.open_for_other_input("$I30")?;
        let mut sink = self.take_sink();

        for record in IndxFile::new(File::open(&self.filepath)?) {
            let record = match record {
                Ok(record) => record,
                Err(error @ mft::err::Error::InvalidIndexRecord { .. }) => {
                    eprintln!("{error}");
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let (live, errors) = record.entries_and_errors();
            for error in errors {
                eprintln!("{error}");
            }
            for entry in live.iter().chain(&record.slack_entries()) {
                let full_path = parser.as_mut().map(|parser| {
                    parser.get_full_path_in_directory(
                        entry.mft_reference.map_or(0, |r| r.entry),
                        &entry.file_name.name.to_utf8_string(),
                        entry.file_name.parent,
                    )
                });
                match &mut sink {
                    Sink::Csv(writer) => {
                        writer.serialize(FlatIndxEntry::from_entry(&record, entry, full_path))?
                    }
                    Sink::Json(out) => {
                        let json_entry = JsonWithPath {
                            full_path,
                            value: &JsonIndxEntry {
                                record_vcn: record.vcn,
                                record_lsn: record.lsn,
                                record_valid_fixup: record.valid_fixup,
                                entry,
                            },
                        };
                        write_json_line(&mut self.json_buf, self.output_format, out, &json_entry)?;
                    }
                }
            }
        }
        sink.flush()
    }

    /// Dumps the boot sector of a `$Boot`.
    fn run_boot(&mut self) -> Result<()> {
        self.check_no_mft("$Boot")?;
        let mut sector = Vec::new();
        File::open(&self.filepath)?
            .take(BOOT_SECTOR_SIZE as u64)
            .read_to_end(&mut sector)?;
        let boot = BootSector::from_slice(&sector)?;
        let mut sink = self.take_sink();
        match &mut sink {
            Sink::Csv(writer) => writer.serialize(&boot)?,
            Sink::Json(out) => write_json_line(&mut self.json_buf, self.output_format, out, &boot)?,
        }
        sink.flush()
    }

    /// Dumps the security descriptors of a `$Secure:$SDS`, skipping the copy of each block.
    fn run_sds(&mut self) -> Result<()> {
        self.check_no_mft("$SDS")?;
        let sds = fs::read(&self.filepath)?;
        let mut sink = self.take_sink();
        for entry in SdsEntries::new(&sds) {
            match &mut sink {
                Sink::Csv(writer) => writer.serialize(FlatSdsEntry::from_entry(&entry))?,
                Sink::Json(out) => {
                    let json_entry = JsonSdsEntry {
                        sddl: entry.descriptor.as_ref().map(|d| d.to_sddl()),
                        entry: &entry,
                    };
                    write_json_line(&mut self.json_buf, self.output_format, out, &json_entry)?
                }
            }
        }
        sink.flush()
    }

    /// Dumps the log records of a `$LogFile`, in file order.
    fn run_logfile(&mut self) -> Result<()> {
        self.check_no_mft("$LogFile")?;
        let log = LogFile::from_buffer(fs::read(&self.filepath)?)?;
        for page in log
            .record_pages()
            .iter()
            .filter_map(|page| page.as_ref().err())
        {
            eprintln!("{page}");
        }
        let mut sink = self.take_sink();
        for record in log.records() {
            match &mut sink {
                Sink::Csv(writer) => writer.serialize(FlatLogRecord::from_record(&record))?,
                Sink::Json(out) => {
                    write_json_line(&mut self.json_buf, self.output_format, out, &record)?
                }
            }
        }
        sink.flush()
    }

    /// Checks the flags of an input that has no paths to resolve.
    fn check_no_mft(&self, kind: &str) -> Result<()> {
        if self.paths_mft.is_some() {
            return Err(anyhow!("`--mft` doesn't apply to a `{kind}` input"));
        }
        self.open_for_other_input(kind).map(drop)
    }

    /// Checks that only the flags that apply to a `kind` input are set, and opens the `--mft`
    /// that resolves its paths.
    fn open_for_other_input(&self, kind: &str) -> Result<Option<MftParser<io::BufReader<File>>>> {
        if self.output_format == OutputFormat::Bodyfile {
            return Err(anyhow!("`-o bodyfile` doesn't apply to a `{kind}` input"));
        }
        if self.ranges.is_some() || self.data_streams_output.is_some() || self.csv_rows.any() {
            return Err(anyhow!(
                "`--ranges`, `--extract-resident-streams`, `--hard-link-rows` and `--stream-rows` \
                 only apply to an `$MFT` input"
            ));
        }
        Ok(match &self.paths_mft {
            Some(path) => Some(MftParser::from_path(path)?),
            None => None,
        })
    }

    /// Takes the output, as a CSV writer for `-o csv`.
    fn take_sink(&mut self) -> Sink {
        let out = self
            .output
            .take()
            .expect("There can only be one flow accessing the output at a time");
        match self.output_format {
            OutputFormat::CSV => Sink::Csv(Box::new(csv::Writer::from_writer(out))),
            _ => Sink::Json(out),
        }
    }

    fn try_to_initialize_logging(&self) {
        if let Some(level) = self.verbosity_level {
            match simplelog::WriteLogger::init(
                level.to_level_filter(),
                simplelog::Config::default(),
                io::stderr(),
            ) {
                Ok(_) => {}
                Err(e) => eprintln!("Failed to initialize logging: {e}"),
            };
        }
    }

    pub fn print_json_entry(&mut self, entry: &MftEntry, full_path: Option<PathBuf>) -> Result<()> {
        self.print_json(&JsonEntry { full_path, entry })
    }

    /// Writes `value` as one JSON (`-o json`) or JSONL (`-o jsonl`) output record.
    fn print_json(&mut self, value: &impl Serialize) -> Result<()> {
        let out = self
            .output
            .as_mut()
            .expect("CSV Flow cannot occur, so `Mftdump` should still Own `output`");
        write_json_line(&mut self.json_buf, self.output_format, out, value)
    }

    pub fn print_bodyfile_entry(
        &mut self,
        entry: &MftEntry,
        extensions: &[MftEntry],
        full_path: Option<PathBuf>,
    ) -> Result<()> {
        let out = self
            .output
            .as_mut()
            .expect("Bodyfile flow keeps `output`, it is only taken by the CSV writer");

        mft::bodyfile::write_entry(out, entry, extensions, &full_path.unwrap_or_default())?;

        Ok(())
    }

    pub fn print_csv_entry<T: Read + Seek, W: Write>(
        &self,
        parser: &mut MftParser<T>,
        entry: &MftEntry,
        extensions: &[MftEntry],
        full_path: Option<PathBuf>,
        writer: &mut csv::Writer<W>,
    ) -> Result<()> {
        let full_path = full_path.unwrap_or_default();
        if !self.csv_rows.any() {
            writer.serialize(FlatMftEntryWithName::from_entry_with_path(
                entry, extensions, full_path,
            ))?;
            return Ok(());
        }
        for row in FlatMftEntryWithName::rows_with_path(
            entry,
            extensions,
            full_path,
            self.csv_rows,
            |name| parser.get_full_path_for_name(entry, name),
        ) {
            writer.serialize(row)?;
        }

        Ok(())
    }

    fn annotate_error(&self, err: Error) -> Error {
        annotate_with_backtrace(err, self.backtraces_enabled)
    }
}

/// Whether `entry` is one of the extension records that its base entry's `$ATTRIBUTE_LIST`
/// leads to.
fn is_listed_by_its_base<T: Read + Seek>(parser: &mut MftParser<T>, entry: &MftEntry) -> bool {
    let record_number = entry.header.record_number;
    parser
        .get_entry(entry.header.base_reference.entry)
        .is_ok_and(|base| {
            parser
                .get_extension_entries(&base)
                .iter()
                .any(|e| e.header.record_number == record_number)
        })
}

/// Where the rows of a `$J` or `$I30` input go.
enum Sink {
    Csv(Box<csv::Writer<Box<dyn Write>>>),
    Json(Box<dyn Write>),
}

impl Sink {
    fn flush(&mut self) -> Result<()> {
        match self {
            Sink::Csv(writer) => writer.flush()?,
            Sink::Json(out) => out.flush()?,
        }
        Ok(())
    }
}

/// Writes `value` as one JSON (pretty) or JSONL line, through `buf`.
fn write_json_line(
    buf: &mut Vec<u8>,
    format: OutputFormat,
    out: &mut impl Write,
    value: &impl Serialize,
) -> Result<()> {
    buf.clear();
    if format == OutputFormat::JSON {
        sonic_json::to_writer_pretty(&mut *buf, value)?;
    } else {
        // JSONL is the performance-critical mode; use a faster serializer.
        sonic_json::to_writer(&mut *buf, value)?;
    }
    buf.push(b'\n');
    out.write_all(buf)?;
    Ok(())
}

fn to_hex_string(bytes: &[u8]) -> String {
    let len = bytes.len();
    // Each byte is represented by 2 ascii bytes.
    let mut s = String::with_capacity(len * 2);

    for byte in bytes {
        write!(s, "{byte:02X}").expect("Writing to an allocated string cannot fail");
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

fn main() -> Result<()> {
    let matches = clap::Command::new("MFT Parser")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Omer B. <omerbenamram@gmail.com>")
        .about("Utility for parsing MFT snapshots and USN change journals ($UsnJrnl:$J)")
        .arg(Arg::new("INPUT").required(true))
        .arg(
            Arg::new("input-type")
                .long("input-type")
                .action(ArgAction::Set)
                .value_parser(clap::builder::PossibleValuesParser::new(["auto", "mft", "usn", "i30", "boot", "sds", "logfile"]))
                .default_value("auto")
                .help(indoc!("What INPUT is: an `$MFT`, a `usn` change journal (`$Extend\\$UsnJrnl:$J`), or a directory's
                             `i30` index records (`$INDEX_ALLOCATION:$I30`, live entries and ones recovered from slack),
                             a `boot` sector (`$Boot`), the `sds` security descriptors (`$Secure:$SDS`), or the `logfile`
                             transaction log (`$LogFile`).
                             `auto` tells them apart by their first bytes.")),
        )
        .arg(
            Arg::new("mft")
                .long("mft")
                .short('m')
                .action(ArgAction::Set)
                .help(indoc!("With a `$J` or `$I30` input, the volume's `$MFT`, to add each file's full path.
                             A path through a directory whose record was reused since starts with `[Orphaned]`.")),
        )
        .arg(
            Arg::new("output-format")
                .short('o')
                .long("output-format")
                .action(ArgAction::Set)
                .value_parser(clap::builder::PossibleValuesParser::new(["csv", "json", "jsonl", "bodyfile"]))
                .default_value("json")
                .help("Output format. `bodyfile` writes Sleuth Kit bodyfile lines (like `fls -m`) for mactime."),
        )
        .arg(
            Arg::new("entry-range")
                .long("ranges")
                .short('r')
                .action(ArgAction::Set)
                .help(indoc!("Dumps only the given entry range(s), for example, `1-15,30` will dump entries 1-15, and 30")),
        )
        .arg(
            Arg::new("output-target")
                .long("output")
                .short('f')
                .action(ArgAction::Set)
                .help(indoc!("Writes output to the file specified instead of stdout, errors will still be printed to stderr.
                       Will ask for confirmation before overwriting files, to allow overwriting, pass `--no-confirm-overwrite`
                       Will create parent directories if needed.")),
        )
        .arg(
            Arg::new("data-streams-target")
                .long("extract-resident-streams")
                .short('e')
                .action(ArgAction::Set)
                .help(indoc!("Writes resident data streams to the given directory.
                             Resident streams will be named like - `{path}__<random_bytes>_{stream_number}_{stream_name}.dontrun`
                             random is added to prevent collisions.")),
        )
        .arg(
            Arg::new("hard-link-rows")
                .long("hard-link-rows")
                .action(ArgAction::SetTrue)
                .help(indoc!("With `-o csv`, also writes a row for each other hard link of a file, with that link's
                             path and `$FILE_NAME` columns. A file's `Dos` short name isn't a link.")),
        )
        .arg(
            Arg::new("stream-rows")
                .long("stream-rows")
                .action(ArgAction::SetTrue)
                .help(indoc!("With `-o csv`, also writes a row for each named data stream (ADS) of a file, with
                             `:<stream>` appended to `FullPath` and `FileName`, and the stream's size as `FileSize`.
                             Stream rows use the file's main path, not the paths of its other hard links.")),
        )
        .arg(
            Arg::new("no-confirm-overwrite")
                .long("no-confirm-overwrite")
                .action(ArgAction::SetTrue)
                .help(indoc!("When set, will not ask for confirmation before overwriting files, useful for automation")),
        )
        .arg(Arg::new("verbose")
            .short('v')
            .action(ArgAction::Count)
            .help(indoc!(r#"
            Sets debug prints level for the application:
                -v   - info
                -vv  - debug
                -vvv - trace
            NOTE: trace output is only available in debug builds, as it is extremely verbose."#))
        )
        .arg(
            Arg::new("backtraces")
                .long("backtraces")
                .action(ArgAction::SetTrue)
                .help("If set, a backtrace will be printed with some errors if available"))
        .get_matches();

    let backtraces_enabled = matches.get_flag("backtraces");

    let mut app = MftDump::from_cli_matches(&matches)
        .map_err(|err| annotate_with_backtrace(err, backtraces_enabled))
        .context("Failed setting up the app")?;
    app.run()
        .map_err(|err| app.annotate_error(err))
        .context("A runtime error has occurred")?;

    Ok(())
}

fn annotate_with_backtrace(err: Error, enabled: bool) -> Error {
    if !enabled {
        return err;
    }

    let backtrace = Backtrace::force_capture();
    err.context(ForcedBacktrace(backtrace))
}

struct ForcedBacktrace(Backtrace);

impl fmt::Display for ForcedBacktrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Backtrace (captured via --backtraces):")?;
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for ForcedBacktrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ForcedBacktrace").field(&self.0).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{MftParser, Path, Ranges, is_listed_by_its_base};
    use std::str::FromStr;

    #[test]
    fn it_works_with_single_number() {
        let ranges = Ranges::from_str("1").unwrap();
        assert_eq!(ranges.0, vec![1..=1]);
    }

    #[test]
    fn it_works_with_a_range() {
        let ranges = Ranges::from_str("1-5").unwrap();
        assert_eq!(ranges.0, vec![1..=5]);
    }

    #[test]
    fn it_works_with_a_range_and_a_number() {
        let ranges = Ranges::from_str("1-5,8").unwrap();
        assert_eq!(ranges.0, vec![1..=5, 8..=8]);
    }

    #[test]
    fn it_works_with_a_number_and_a_range() {
        let ranges = Ranges::from_str("1-5,8").unwrap();
        assert_eq!(ranges.0, vec![1..=5, 8..=8]);
    }

    #[test]
    fn it_works_with_more_than_2_number_and_a_range() {
        let ranges = Ranges::from_str("1-5,8,10-19").unwrap();
        assert_eq!(ranges.0, vec![1..=5, 8..=8, 10..=19]);
    }

    #[test]
    fn it_works_with_two_ranges() {
        let ranges = Ranges::from_str("1-10,20-25").unwrap();
        assert_eq!(ranges.0, vec![1..=10, 20..=25]);
    }

    #[test]
    fn it_errors_on_a_random_string() {
        let ranges = Ranges::from_str("hello");
        assert!(ranges.is_err())
    }

    #[test]
    fn it_errors_on_a_range_with_too_many_dashes() {
        let ranges = Ranges::from_str("1-5-8");
        assert!(ranges.is_err())
    }

    #[test]
    fn extension_records_are_exported_with_their_base_entry() {
        let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/ntfs1-gen2.MFT");
        let mut parser = MftParser::from_path(sample).unwrap();

        // Record 52 is one of the extension records listed by record 47.
        let extension = parser.get_entry(52).unwrap();
        assert!(is_listed_by_its_base(&mut parser, &extension));

        // Record 47 is a base record, and isn't one of `$MFT`'s extensions.
        let base = parser.get_entry(47).unwrap();
        assert!(!is_listed_by_its_base(&mut parser, &base));
    }
}
