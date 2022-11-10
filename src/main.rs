use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(about = "Safe is a digital safe box")]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypting a file by master key
    Enc {
        /// Path of file to encrypt
        path: PathBuf,
    },
    /// Decrypting a file by master key
    Dec {
        /// Path of file to decrypt
        path: PathBuf,
    },
}

fn main() {
    let args = Args::parse();
    println!("{:#?}", args);
}
