#![forbid(unsafe_code)]

use clap::Parser;
use ntfs::image::Image;
use ntfs::ntfs::efs::EfsRsaKeyBag;
use ntfs::ntfs::{Error, FileSystem, Result, Volume};
use ntfs::tools::mount::vfs::Vfs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(
    about = "ntfs-mount (Rust): mount an NTFS volume (read-only) via FUSE (unix) or Dokan (windows)",
    version
)]
struct Cli {
    /// Source image path (raw, E01, AFF).
    #[arg(value_name = "SOURCE")]
    image: PathBuf,

    /// Where to mount the filesystem.
    ///
    /// - Unix (FUSE): a directory path
    /// - Windows (Dokan): a drive letter (e.g. \"M:\\\") or an empty directory
    #[arg(value_name = "MOUNTPOINT")]
    mountpoint: PathBuf,

    /// Byte offset of the NTFS volume inside the image.
    #[arg(short = 'o', long, default_value_t = 0, value_parser = parse_u64)]
    offset: u64,

    /// Strict traversal (do not fall back to scanning MFT parent references when indexes are missing).
    #[arg(long)]
    strict: bool,

    /// Decrypt EFS-encrypted files using an RSA key from a PKCS#12/PFX file.
    #[arg(long)]
    pfx: Option<PathBuf>,

    /// PFX password (omit for empty password).
    #[arg(long)]
    pfx_password: Option<String>,

    /// Enable debug output (backend-dependent).
    #[arg(long)]
    debug: bool,

    /// Number of worker threads (Dokan only; 0 lets Dokan pick a default).
    #[arg(long, default_value_t = 0)]
    threads: u16,
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let img = Image::open(&cli.image).map_err(Error::Io)?;
    let volume = Volume::open(Arc::new(img), cli.offset)?;
    let fs = FileSystem::new(volume);

    let keys = if let Some(pfx_path) = cli.pfx.as_ref() {
        let pfx = std::fs::read(pfx_path)?;
        Some(EfsRsaKeyBag::from_pkcs12_der(
            &pfx,
            cli.pfx_password.as_deref(),
        )?)
    } else {
        None
    };

    let vfs = Vfs::new(fs).with_strict(cli.strict).with_efs_keys(keys);

    // --- Unix / FUSE ---
    #[cfg(all(feature = "fuse", target_os = "linux"))]
    {
        return ntfs::tools::mount::fuse::mount(vfs, &cli.mountpoint).map_err(Error::Io);
    }

    // --- Windows / Dokan ---
    #[cfg(all(feature = "dokan", windows))]
    {
        let mp = cli.mountpoint.to_string_lossy().to_string();
        return ntfs::tools::mount::dokan::mount(vfs, &mp, cli.threads, cli.debug).map_err(|e| {
            Error::InvalidData {
                message: format!("dokan mount failed: {e}"),
            }
        });
    }

    // --- No backend available ---
    #[cfg(not(any(
        all(feature = "fuse", target_os = "linux"),
        all(feature = "dokan", windows)
    )))]
    {
        let _ = vfs; // keep variable used
        Err(Error::Unsupported {
            what: "ntfs-mount was built without a mount backend. Rebuild with `--features fuse` (unix) or `--features dokan` (windows)."
                .to_string(),
        })
    }
}

fn parse_u64(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let (radix, digits) = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map(|d| (16, d))
        .unwrap_or((10, s));
    u64::from_str_radix(digits, radix).map_err(|e| e.to_string())
}
