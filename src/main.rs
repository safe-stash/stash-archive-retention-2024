use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::{Parser, Subcommand};
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "Safe is a digital safe box")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Encrypting a file by master key
    Enc {
        /// Path of input file to encrypt
        input: PathBuf,

        /// Path of output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Decrypting a file by master key
    Dec {
        /// Path of input file to decrypt
        input: PathBuf,

        /// Path of output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let key = [0x42; 32];
    let iv = [0x24; 16];

    match &cli.command {
        Commands::Enc { input, output } => {
            let buf = read_file(input)?;
            let res =
                Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&buf);

            match output {
                Some(o) => write_file(o, &buf)?,
                None => write_stdout(&res)?,
            }
        }
        Commands::Dec { input, output } => {
            let buf = read_file(input)?;
            let res = Aes256CbcDec::new(&key.into(), &iv.into())
                .decrypt_padded_vec_mut::<Pkcs7>(&buf)
                .unwrap();

            match output {
                Some(o) => write_file(o, &buf)?,
                None => write_stdout(&res)?,
            }
        }
    }
    Ok(())
}

/// Read the input file and return the data.
///
/// # Errors
///
/// This function will return an error if cannot open or read the input file.
fn read_file(input: &PathBuf) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(input)?;
    let mut buf = Vec::<u8>::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Write data in the buf to output file.
///
/// # Errors
///
/// This function will return an error if cannot create or write to output file.
fn write_file(output: &PathBuf, buf: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(output)?;
    file.write(buf)?;
    Ok(())
}

/// Write the buf to stdout.
///
/// # Errors
///
/// This function will return an error if cannot write in stdout.
fn write_stdout(buf: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    let mut stdout = io::stdout();
    stdout.write_all(buf)?;
    stdout.flush()?;
    Ok(())
}
