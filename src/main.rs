use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::{Parser, Subcommand};
use scrypt::{password_hash::SaltString, Params};
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

    let pass = rpassword::prompt_password("Enter the master password: ").unwrap();
    let pass = pass.as_bytes();

    let salt = SaltString::new("qYhaxiWJY63Try2WycoOtg")?; // ::generate(&mut scrypt::password_hash::rand_core::OsRng);
    let salt = salt.as_bytes();
    
    let params = Params::new(13, 8, 1)?; // log_n=13 for fast calculation; OWASP recommended log_n=16
    let mut key = [0; 32];
    let iv = [0x24; 16];
    
    scrypt::scrypt(pass, salt, &params, &mut key)?;

    match &cli.command {
        Commands::Enc { input, output } => {
            let buf = read_file(input)?;
            let res =
                Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&buf);

            match output {
                Some(o) => write_file(o, &res)?,
                None => write_stdout(&res)?,
            }
        }
        Commands::Dec { input, output } => {
            let buf = read_file(input)?;
            match Aes256CbcDec::new(&key.into(), &iv.into()).decrypt_padded_vec_mut::<Pkcs7>(&buf) {
                Ok(res) => match output {
                    Some(o) => write_file(o, &res)?,
                    None => write_stdout(&res)?,
                },
                Err(e) => println!("Decryption failed: {:?}", e)
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
