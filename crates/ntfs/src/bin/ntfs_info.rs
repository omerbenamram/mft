//! Port of `external/libfsntfs/fsntfsinfo`.
#![forbid(unsafe_code)]

#[path = "ntfs_info/cli_utils.rs"]
mod cli_utils;

use clap::{Parser, Subcommand};
use md5::{Digest as _, Md5};
use mft::attribute::MftAttributeType;
use mft::attribute::header::ResidentialHeader;
use ntfs::image::Image;
use ntfs::ntfs::efs::EfsRsaKeyBag;
use ntfs::ntfs::{Error, FileSystem, Result, Volume};
use std::fs;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(
    about = "ntfs-info (Rust): inspect NTFS volumes and MFT entries",
    version
)]
struct Cli {
    /// Source image path (raw, E01, AFF).
    #[arg(value_name = "SOURCE")]
    image: PathBuf,

    /// Byte offset of the NTFS volume inside the image.
    #[arg(short = 'o', long, default_value_t = 0, value_parser = cli_utils::parse_u64)]
    offset: u64,

    /// Output file system hierarchy as a bodyfile.
    #[arg(
        short = 'B',
        conflicts_with_all = ["mft_entry_index", "file_entry_path", "show_usn"]
    )]
    bodyfile: Option<PathBuf>,

    /// Calculate an MD5 hash of a file entry to include in the bodyfile.
    #[arg(short = 'd', requires = "bodyfile")]
    calculate_md5: bool,

    /// Show information about a specific MFT entry index, or "all".
    #[arg(
        short = 'E',
        conflicts_with_all = ["bodyfile", "file_entry_path", "show_hierarchy", "show_usn"]
    )]
    mft_entry_index: Option<String>,

    /// Show information about a specific file entry path.
    #[arg(
        short = 'F',
        conflicts_with_all = ["bodyfile", "mft_entry_index", "show_hierarchy", "show_usn"]
    )]
    file_entry_path: Option<String>,

    /// Show the file system hierarchy.
    #[arg(short = 'H', conflicts_with_all = ["mft_entry_index", "file_entry_path", "show_usn"])]
    show_hierarchy: bool,

    /// Show information from the USN change journal ($UsnJrnl).
    #[arg(
        short = 'U',
        conflicts_with_all = ["bodyfile", "mft_entry_index", "file_entry_path", "show_hierarchy"]
    )]
    show_usn: bool,

    /// Verbose output (diagnostics).
    #[arg(short = 'v')]
    verbose: bool,

    /// New-style subcommands (kept for convenience). If provided, legacy flags are ignored.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print basic NTFS boot/volume header information.
    Volume,

    /// Inspect an MFT entry.
    Mft {
        /// MFT entry index (record number) or "all".
        #[arg(value_name = "ENTRY")]
        entry: String,
    },

    /// Inspect a file entry by path (e.g. "\\Windows\\System32").
    File {
        /// File entry path.
        #[arg(value_name = "PATH")]
        path: String,
    },

    /// Print file system hierarchy (optionally as a bodyfile).
    Hierarchy {
        /// Output a SleuthKit bodyfile to this path.
        #[arg(long)]
        bodyfile: Option<PathBuf>,

        /// Include MD5 hashes in bodyfile output.
        #[arg(long)]
        md5: bool,
    },

    /// Print USN change journal ($UsnJrnl) records.
    Usn,

    /// Read a $DATA stream from an MFT entry (supports ADS via --stream).
    Read {
        /// MFT entry number (record number).
        #[arg(value_parser = cli_utils::parse_u64)]
        entry: u64,

        /// Stream name (empty for default unnamed stream). For `file:ADS` use `--stream ADS`.
        #[arg(long, default_value = "")]
        stream: String,

        /// Write output to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,

        /// Print MD5 of the stream (and still write bytes if --out is set).
        #[arg(long)]
        md5: bool,

        /// Decrypt EFS-encrypted $DATA using an RSA key from a PKCS#12/PFX file.
        #[arg(long)]
        pfx: Option<PathBuf>,

        /// PFX password (omit for empty password).
        #[arg(long)]
        pfx_password: Option<String>,
    },
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
            // Common when piping to `head`, etc. Treat as success.
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let img = Image::open(&cli.image)?;
    let volume = Volume::open(Arc::new(img), cli.offset)?;
    let fs = FileSystem::new(volume);

    if cli.verbose {
        eprintln!("ntfs-info: verbose enabled");
    }

    if let Some(command) = cli.command {
        return match command {
            Command::Volume => cmd_volume(&fs),
            Command::Mft { entry } => cmd_mft_selector(&fs, &entry),
            Command::File { path } => cmd_file_entry_by_path(&fs, &path),
            Command::Hierarchy { bodyfile, md5 } => cmd_hierarchy(&fs, bodyfile, md5),
            Command::Usn => cmd_usn(&fs),
            Command::Read {
                entry,
                stream,
                out,
                md5,
                pfx,
                pfx_password,
            } => cmd_read(&fs, entry, &stream, out, md5, pfx, pfx_password),
        };
    }

    // Legacy / C-compatible mode selection (matches external/libfsntfs/fsntfstools/fsntfsinfo.c).
    if let Some(sel) = cli.mft_entry_index.as_deref() {
        return cmd_mft_selector(&fs, sel);
    }
    if let Some(path) = cli.file_entry_path.as_deref() {
        return cmd_file_entry_by_path(&fs, path);
    }
    if cli.bodyfile.is_some() || cli.show_hierarchy {
        return cmd_hierarchy(&fs, cli.bodyfile, cli.calculate_md5);
    }
    if cli.show_usn {
        return cmd_usn(&fs);
    }

    cmd_volume(&fs)
}

fn cmd_volume(fs: &FileSystem) -> Result<()> {
    let mut out = io::stdout().lock();
    write!(out, "{}", fs.volume().header)?;
    Ok(())
}

fn cmd_mft_selector(fs: &FileSystem, selector: &str) -> Result<()> {
    let selector = selector.trim();
    if selector.eq_ignore_ascii_case("all") {
        return cmd_mft_all(fs);
    }
    let entry_id = cli_utils::parse_u64(selector).map_err(|e| Error::InvalidData { message: e })?;
    cmd_mft(fs, entry_id)
}

fn cmd_mft_all(fs: &FileSystem) -> Result<()> {
    // Strict: if we cannot determine the MFT entry count, fail instead of guessing.
    let count = estimate_mft_entry_count(fs.volume())?.min(200_000);
    let mut out = io::stdout().lock();
    for i in 0..count {
        let entry = fs.volume().read_mft_entry(i)?;
        let allocated = entry
            .header
            .flags
            .contains(mft::entry::EntryFlags::ALLOCATED);
        let is_dir = entry.is_dir();
        let name = entry.find_best_name_attribute().map(|n| n.name);
        if let Some(name) = name {
            writeln!(out, "{i}\tallocated={allocated}\tdir={is_dir}\tname={name}")?;
        } else {
            writeln!(out, "{i}\tallocated={allocated}\tdir={is_dir}\tname=<none>")?;
        }
    }
    Ok(())
}

fn cmd_mft(fs: &FileSystem, entry_id: u64) -> Result<()> {
    let entry = fs.volume().read_mft_entry(entry_id)?;
    let allocated = entry
        .header
        .flags
        .contains(mft::entry::EntryFlags::ALLOCATED);

    let name = entry.find_best_name_attribute().map(|n| n.name);

    let mut out = io::stdout().lock();

    writeln!(out, "record_number: {}", entry.header.record_number)?;
    let sig = std::str::from_utf8(&entry.header.signature).unwrap_or("????");
    writeln!(out, "signature: {:?}", sig)?;
    writeln!(out, "allocated: {}", allocated)?;
    writeln!(out, "is_dir: {}", entry.is_dir())?;
    writeln!(
        out,
        "base_reference: {}-{}",
        entry.header.base_reference.entry, entry.header.base_reference.sequence
    )?;
    if let Some(name) = name {
        writeln!(out, "best_name: {}", name)?;
    }

    // Summarize all attributes (high level). Strict: do not ignore attribute parse errors.
    for attr in entry.iter_attributes() {
        let attr = attr?;
        let name = if attr.header.name.is_empty() {
            "<none>".to_string()
        } else {
            attr.header.name.clone()
        };
        match &attr.header.residential_header {
            ResidentialHeader::Resident(r) => {
                writeln!(
                    out,
                    "attr: type={:?} name={} resident size={} instance={}",
                    attr.header.type_code, name, r.data_size, attr.header.instance
                )?;
            }
            ResidentialHeader::NonResident(nr) => {
                writeln!(
                    out,
                    "attr: type={:?} name={} nonresident size={} vcn_first={} vcn_last={} instance={}",
                    attr.header.type_code,
                    name,
                    nr.file_size,
                    nr.vnc_first,
                    nr.vnc_last,
                    attr.header.instance
                )?;
            }
        }
    }

    Ok(())
}

fn cmd_file_entry_by_path(fs: &FileSystem, path: &str) -> Result<()> {
    // Strict: do not resolve via MFT parent-scan fallbacks.
    let entry_id = fs.resolve_path_strict(path)?;

    let mut out = io::stdout().lock();
    writeln!(out, "path: {path}")?;
    writeln!(out, "mft_entry: {entry_id}")?;
    cmd_mft(fs, entry_id)
}

fn cmd_hierarchy(fs: &FileSystem, bodyfile: Option<PathBuf>, calculate_md5: bool) -> Result<()> {
    use ntfs::ntfs::filesystem::{is_dot_dir_entry, join_ntfs_child_path};
    use std::collections::{HashSet, VecDeque};
    use std::io::BufWriter;

    enum Sink<'a> {
        Stdout(io::StdoutLock<'a>),
        Bodyfile {
            out: BufWriter<fs::File>,
            calculate_md5: bool,
        },
    }

    impl Sink<'_> {
        fn emit(&mut self, fs: &FileSystem, entry_id: u64, path: &str) -> Result<()> {
            match self {
                Sink::Stdout(out) => {
                    writeln!(out, "{path}\t(entry {entry_id})")?;
                    Ok(())
                }
                Sink::Bodyfile { out, calculate_md5 } => {
                    write_bodyfile_for_entry(fs, entry_id, path, *calculate_md5, out)
                }
            }
        }
    }

    let mut sink = match bodyfile {
        Some(p) => Sink::Bodyfile {
            out: BufWriter::new(fs::File::create(p)?),
            calculate_md5,
        },
        None => Sink::Stdout(io::stdout().lock()),
    };

    if let Sink::Stdout(out) = &mut sink {
        writeln!(out, "File system hierarchy:")?;
    }

    // Match upstream behavior: include the root directory itself.
    sink.emit(fs, 5, "\\")?;

    let mut queue: VecDeque<(u64, String)> = VecDeque::new();
    queue.push_back((5, "\\".to_string()));

    let mut visited_dirs: HashSet<u64> = HashSet::new();

    while let Some((dir_id, dir_path)) = queue.pop_front() {
        if !visited_dirs.insert(dir_id) {
            continue;
        }

        let entries = fs.read_dir_strict(dir_id)?;

        for e in entries {
            if is_dot_dir_entry(e.name.as_str()) {
                continue;
            }

            let child_path = join_ntfs_child_path(&dir_path, e.name.as_str());
            sink.emit(fs, e.entry_id, &child_path)?;

            let child_entry = fs.volume().read_mft_entry(e.entry_id)?;
            if child_entry.is_dir() {
                queue.push_back((e.entry_id, child_path));
            }
        }
    }

    Ok(())
}

fn cmd_usn(fs: &FileSystem) -> Result<()> {
    let mut out = io::stdout().lock();

    let Some(mut journal) = fs.open_usn_change_journal()? else {
        writeln!(out, "USN change journal: N/A")?;
        return Ok(());
    };

    writeln!(out, "USN change journal: \\$Extend\\$UsnJrnl")?;
    writeln!(out)?;

    for raw in journal.iter_record_bytes() {
        let raw = raw?;

        let rec = ntfs::ntfs::usn::UsnRecord::parse(&raw.bytes, raw.offset)?;
        match rec {
            ntfs::ntfs::usn::UsnRecord::V2(rec) => {
                writeln!(out, "USN record:")?;
                writeln!(out, "\tOffset\t\t\t\t: 0x{:x}", raw.offset)?;
                writeln!(
                    out,
                    "\tUpdate time\t\t\t: 0x{:016x}",
                    rec.timestamp_filetime
                )?;
                writeln!(out, "\tUpdate sequence number\t\t: {}", rec.usn)?;

                writeln!(
                    out,
                    "\tUpdate reason flags\t\t: 0x{:08x}",
                    rec.reason.bits()
                )?;
                for name in ntfs::ntfs::usn::reason_flag_names(rec.reason) {
                    writeln!(out, "\t\t({name})")?;
                }
                writeln!(out)?;

                writeln!(
                    out,
                    "\tUpdate source flags\t\t: 0x{:08x}",
                    rec.source_info.bits()
                )?;
                for name in ntfs::ntfs::usn::source_flag_names(rec.source_info) {
                    writeln!(out, "\t\t({name})")?;
                }
                writeln!(out)?;

                writeln!(out, "\tName\t\t\t\t: {}", rec.name)?;

                writeln!(
                    out,
                    "\tFile reference\t\t\t: {}",
                    format_file_reference(rec.file_reference)
                )?;
                writeln!(
                    out,
                    "\tParent file reference\t\t: {}",
                    format_file_reference(rec.parent_file_reference)
                )?;

                writeln!(
                    out,
                    "\tFile attribute flags\t\t: 0x{:08x}",
                    rec.file_attributes.bits()
                )?;
                for name in ntfs::ntfs::usn::file_attribute_flag_names(rec.file_attributes) {
                    writeln!(out, "\t\t({name})")?;
                }

                writeln!(out)?;
            }
        }
    }

    Ok(())
}

fn cmd_read(
    fs: &FileSystem,
    entry_id: u64,
    stream_name: &str,
    out: Option<PathBuf>,
    md5: bool,
    pfx: Option<PathBuf>,
    pfx_password: Option<String>,
) -> Result<()> {
    let bytes = if let Some(pfx_path) = pfx {
        if !stream_name.is_empty() {
            return Err(ntfs::ntfs::Error::Unsupported {
                what: "EFS decryption is only supported for the default unnamed $DATA stream"
                    .to_string(),
            });
        }
        let pfx_bytes = fs::read(pfx_path)?;
        let bag = EfsRsaKeyBag::from_pkcs12_der(&pfx_bytes, pfx_password.as_deref())?;
        fs.read_file_default_stream_decrypted(entry_id, &bag)?
    } else {
        fs.read_file_stream(entry_id, stream_name)?
    };

    if md5 {
        let mut h = Md5::new();
        h.update(&bytes);
        let digest = h.finalize();
        let mut out = io::stdout().lock();
        writeln!(out, "{}", hex::encode(digest))?;
    }

    match out {
        Some(path) => fs::write(path, &bytes)?,
        None if !md5 => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(&bytes)?;
        }
        None => {}
    }

    Ok(())
}

fn estimate_mft_entry_count(volume: &Volume) -> Result<u64> {
    let entry0 = volume.read_mft_entry(0)?;
    for attr in entry0.iter_attributes_matching(Some(vec![MftAttributeType::DATA])) {
        let attr = attr?;
        if !attr.header.name.is_empty() {
            continue;
        }
        if let ResidentialHeader::NonResident(nr) = &attr.header.residential_header {
            if volume.header.mft_entry_size == 0 {
                return Err(Error::InvalidData {
                    message: "mft_entry_size is 0".to_string(),
                });
            }
            return Ok(nr.file_size / volume.header.mft_entry_size as u64);
        }
    }
    Err(Error::NotFound {
        what: "missing $MFT $DATA mapping in entry 0".to_string(),
    })
}

fn format_file_reference(file_ref: u64) -> String {
    if file_ref == 0 {
        return "0".to_string();
    }
    let entry = file_ref & 0x0000_FFFF_FFFF_FFFF;
    let seq = file_ref >> 48;
    format!("{entry}-{seq}")
}

fn write_bodyfile_for_entry(
    fs: &FileSystem,
    entry_id: u64,
    path: &str,
    calculate_md5: bool,
    out: &mut impl io::Write,
) -> Result<()> {
    let entry = fs.volume().read_mft_entry(entry_id)?;

    // Strict: require $STANDARD_INFORMATION for timestamps and flags.
    let mut si_iter =
        entry.iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]));
    let si_attr = si_iter.next().ok_or_else(|| Error::NotFound {
        what: format!("missing $STANDARD_INFORMATION for entry {entry_id}"),
    })??;
    let si = si_attr
        .data
        .into_standard_info()
        .ok_or_else(|| Error::InvalidData {
            message: format!("failed to parse $STANDARD_INFORMATION for entry {entry_id}"),
        })?;

    let crtime = ts_to_bodyfile_time(&si.created);
    let mtime = ts_to_bodyfile_time(&si.modified);
    let ctime = ts_to_bodyfile_time(&si.mft_modified);
    let atime = ts_to_bodyfile_time(&si.accessed);
    let readonly = si
        .file_flags
        .contains(mft::attribute::FileAttributeFlags::FILE_ATTRIBUTE_READONLY);

    let mut mode_bytes: [u8; 10] = if entry.is_dir() {
        *b"drwxrwxrwx"
    } else {
        *b"-rwxrwxrwx"
    };
    if readonly {
        for idx in [2_usize, 5, 8] {
            mode_bytes[idx] = b'-';
        }
    }
    let mode = String::from_utf8_lossy(&mode_bytes).to_string();

    // Directory: emit a single line (size=0).
    if entry.is_dir() {
        let md5 = "00000000000000000000000000000000";
        let inode = format!("{}-{}", entry.header.record_number, entry.header.sequence);
        writeln!(
            out,
            "{}|{}|{}|{}|0|0|0|{}|{}|{}|{}",
            md5,
            escape_bodyfile_name(path),
            inode,
            mode,
            atime,
            mtime,
            ctime,
            crtime
        )
        .map_err(Error::Io)?;
        return Ok(());
    }

    // Files: emit one line per DATA stream (default + ADS).
    let mut any = false;
    for attr in entry.iter_attributes_matching(Some(vec![MftAttributeType::DATA])) {
        let attr = attr?;
        let stream_name = attr.header.name.clone();
        let size = match &attr.header.residential_header {
            ResidentialHeader::Resident(r) => r.data_size as u64,
            ResidentialHeader::NonResident(nr) => nr.file_size,
        };

        let md5 = if calculate_md5 {
            fs.md5_file_stream(entry_id, &stream_name)?
        } else {
            "00000000000000000000000000000000".to_string()
        };

        let inode = format!("{}-{}", entry.header.record_number, entry.header.sequence);
        let mut name = escape_bodyfile_name(path);
        if !stream_name.is_empty() {
            name.push(':');
            name.push_str(&escape_bodyfile_name(&stream_name));
        }

        writeln!(
            out,
            "{}|{}|{}|{}|0|0|{}|{}|{}|{}|{}",
            md5, name, inode, mode, size, atime, mtime, ctime, crtime
        )
        .map_err(Error::Io)?;
        any = true;
    }

    if !any {
        // No $DATA; emit a placeholder.
        let md5 = "00000000000000000000000000000000";
        let inode = format!("{}-{}", entry.header.record_number, entry.header.sequence);
        writeln!(
            out,
            "{}|{}|{}|{}|0|0|0|{}|{}|{}|{}",
            md5,
            escape_bodyfile_name(path),
            inode,
            mode,
            atime,
            mtime,
            ctime,
            crtime
        )
        .map_err(Error::Io)?;
    }

    Ok(())
}

fn ts_to_bodyfile_time(ts: &jiff::Timestamp) -> String {
    let sec = ts.as_second();
    let nanos = ts.subsec_nanosecond() as i64;
    // Bodyfile uses 100ns ticks (7 digits).
    let frac_100ns = (nanos / 100).clamp(0, 9_999_999);
    format!("{sec}.{frac_100ns:07}")
}

fn escape_bodyfile_name(s: &str) -> String {
    // Escape characters that would break bodyfile parsing.
    //
    // - Column separator: `|`
    // - Control chars: U+0000–U+001F and U+007F–U+009F
    //
    // We keep all other Unicode scalar values as UTF-8.
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let cp = ch as u32;
        let is_ctrl = (cp <= 0x1f) || ((0x7f..=0x9f).contains(&cp));
        if ch == '|' || is_ctrl {
            // Matches upstream style: \xNN for control characters.
            out.push('\\');
            out.push('x');
            let b = (cp & 0xff) as u8;
            out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        } else {
            out.push(ch);
        }
    }
    out
}
