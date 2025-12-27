use aff::{AffOpenOptions, SignatureStatus, Verifier};
use clap::Parser;
use std::path::PathBuf;

/// Verify `/sha256` signature segments in an AFF container.
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut opts = AffOpenOptions::new();
    opts.passphrase = cli.passphrase;
    opts.unseal_keyfile = cli.unseal_keyfile;

    let img = opts.open(&cli.path)?;
    let verifier = Verifier::new(&img);
    let results = verifier.verify_all()?;

    if results.is_empty() {
        println!("no signature segments found");
        return Ok(());
    }

    let mut bad = false;
    for (name, status) in results {
        println!("{status:?}\t{name}");
        if status != SignatureStatus::Good {
            bad = true;
        }
    }

    if bad {
        std::process::exit(1);
    }
    Ok(())
}


