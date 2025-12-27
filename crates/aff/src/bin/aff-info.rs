use aff::AffOpenOptions;
use clap::Parser;
use forensic_image::ReadAt;
use std::path::PathBuf;

/// Print basic information about an AFF container.
#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    /// Path to an AFF1 file, an AFM file, or an AFD directory.
    path: PathBuf,

    /// Passphrase for decrypting `/aes256` segments (AFFLIB `affkey_aes256`).
    #[arg(long)]
    passphrase: Option<String>,

    /// PEM private key used to unseal `affkey_evp%d` segments.
    #[arg(long)]
    unseal_keyfile: Option<PathBuf>,

    /// Print all segment names.
    #[arg(long)]
    segments: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut opts = AffOpenOptions::new();
    opts.passphrase = cli.passphrase;
    opts.unseal_keyfile = cli.unseal_keyfile;

    let img = opts.open(&cli.path)?;

    println!("kind: {:?}", img.kind());
    println!("len: {}", img.len());
    println!("page_size: {}", img.page_size());

    let names = img.segment_names();
    println!("segments: {}", names.len());
    if cli.segments {
        for n in names {
            println!("{n}");
        }
    }

    Ok(())
}
