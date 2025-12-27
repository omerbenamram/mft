use aff::AffOpenOptions;
use clap::Parser;
use forensic_image::ReadAt;
use std::io::Write;
use std::path::PathBuf;

/// Stream bytes from an AFF container to stdout.
///
/// This is a read-only tool intended for piping into other utilities.
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

    /// Starting offset (bytes).
    #[arg(long, default_value_t = 0)]
    offset: u64,

    /// Number of bytes to read (defaults to the remainder of the image).
    #[arg(long)]
    length: Option<u64>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut opts = AffOpenOptions::new();
    opts.passphrase = cli.passphrase;
    opts.unseal_keyfile = cli.unseal_keyfile;

    let img = opts.open(&cli.path)?;

    let len = img.len();
    if cli.offset > len {
        anyhow::bail!("offset {} is past end-of-image {}", cli.offset, len);
    }
    let to_read = cli.length.unwrap_or_else(|| len - cli.offset);

    let mut stdout = std::io::stdout().lock();
    let mut buf = vec![0u8; 1024 * 1024];

    let mut remaining = to_read;
    let mut cur = cli.offset;
    while remaining > 0 {
        let take = (remaining as usize).min(buf.len());
        img.read_exact_at(cur, &mut buf[..take])?;
        stdout.write_all(&buf[..take])?;
        cur = cur.saturating_add(take as u64);
        remaining -= take as u64;
    }
    stdout.flush()?;
    Ok(())
}


