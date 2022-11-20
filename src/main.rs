use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::{Parser, Subcommand};
use rusqlite::{Connection, Result};
use scrypt::{password_hash::SaltString, Params};
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

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
    /// Insert an item into vault
    Add {
        /// Item name
        name: String,

        /// Value of item to be encrypted
        value: String,

        /// Update value if exists
        #[arg(short, long, required(false), default_value_t = false)]
        force: bool,
    },
    /// Get an item from vault
    Get {
        /// Item name to be searched
        name: String,
    },
    /// List saved items
    List {},
    /// Remove an item from vault
    Remove {
        /// Item name to be removed
        name: String,
    },
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug)]
struct VaultItem {
    _id: i32,
    item_name: String,
    item_value: Vec<u8>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let conn = sqlite_open("safe.db").expect("Failed to create or open sqlite db");

    let key = kdf().unwrap();
    let iv = [0x24; 16];

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
                Err(e) => println!("Decryption failed: {:?}", e),
            }
        }

        Commands::Add { name, value, force } => {
            let res = Aes256CbcEnc::new(&key.into(), &iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(&value.as_bytes());

            let item = VaultItem {
                _id: 0,
                item_name: name.to_string(),
                item_value: res,
            };

            sqlite_add(&conn, &item, force);
        }

        Commands::Get { name } => match sqlite_get(&conn, &name) {
            Ok(item) => {
                match Aes256CbcDec::new(&key.into(), &iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(&item.item_value)
                {
                    Ok(res) => println!(
                        "{:}={:}",
                        item.item_name,
                        String::from_utf8(res).expect("Failed to convert bytes")
                    ),
                    Err(e) => println!("Decryption failed during finding an item: {:?}", e),
                }
            }
            Err(e) => println!("{:}", e),
        },

        Commands::List {} => match sqlite_list(&conn) {
            Ok(items) => {
                for item in items {
                    match Aes256CbcDec::new(&key.into(), &iv.into())
                        .decrypt_padded_vec_mut::<Pkcs7>(&item.item_value)
                    {
                        Ok(res) => println!(
                            "{:}={:}",
                            item.item_name,
                            String::from_utf8(res).expect("Failed to convert fetched data")
                        ),
                        Err(_) => {
                            println!("Failed to list items");
                            exit(1)
                        }
                    }
                }
            }
            Err(e) => println!("{:}", e),
        },

        Commands::Remove { name } => sqlite_remove(&conn, &name),
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

/// Produces the derived key as output
///
/// # Errors
///
/// This function will return an error if cannot derive key from a password
fn kdf() -> Result<[u8; 32], Box<dyn Error>> {
    let pass = rpassword::prompt_password("Password: ").unwrap();
    let pass = pass.as_bytes();
    let salt = SaltString::new("qYhaxiWJY63Try2WycoOtg")?; // ::generate(&mut scrypt::password_hash::rand_core::OsRng);
    let salt = salt.as_bytes();
    let params = Params::new(13, 8, 1)?; // log_n=13 for fast calculation; OWASP recommended log_n=16
    let mut key = [0; 32];

    scrypt::scrypt(pass, salt, &params, &mut key)?;

    Ok(key)
}

/// Connects to sqlite database.
///
/// # Errors
///
/// This function will return an error if cannot create sqlite db.
fn sqlite_open<P: AsRef<Path>>(path: P) -> Result<Connection, Box<dyn Error>> {
    let conn = Connection::open(path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vault (
             id INTEGER PRIMARY KEY,
             item_name TEXT NOT NULL UNIQUE,
             item_value BLOB
         )",
        [],
    )?;
    Ok(conn)
}

/// Inserts an item to vault.
///
/// # Errors
///
/// This function will return an error if cannot insert into sqlite db.
fn sqlite_add(conn: &Connection, item: &VaultItem, update: &bool) {
    match conn.execute(
        "INSERT INTO vault (item_name, item_value) values (?1, ?2)",
        (&item.item_name, &item.item_value),
    ) {
        Ok(_) => println!("{:} saved.", &item.item_name),
        Err(e) => {
            if let rusqlite::Error::SqliteFailure(rc, _) = e {
                if rc.code == rusqlite::ErrorCode::ConstraintViolation {
                    if *update {
                        let mut stmt = conn
                            .prepare("UPDATE vault SET item_value = ?1 WHERE item_name = ?2")
                            .expect("Preparing update item failed");

                        stmt.execute(rusqlite::params![item.item_value, item.item_name])
                            .expect("Updating item failed");

                        println!("{:} updated", &item.item_name)
                    } else {
                        println!(
                            "{:} already exists! (error={:}), please try with -f to force update",
                            &item.item_name, rc.extended_code
                        )
                    }
                }
            } else {
                println!("{:}", e);
            }
        }
    }
}

/// Find an item in vault.
///
/// # Errors
///
/// This function will return an error if cannot execute query on sqlite db.
fn sqlite_get(conn: &Connection, item_name: &String) -> Result<VaultItem, rusqlite::Error> {
    let mut stmt = conn
        .prepare("SELECT * FROM vault WHERE item_name=?")
        .expect("Failed to query db");

    stmt.query_row([&item_name], |row| {
        Ok(VaultItem {
            _id: row.get(0)?,
            item_name: row.get(1)?,
            item_value: row.get(2)?,
        })
    })
}

/// Find all items in vault.
///
/// # Errors
///
/// This function will return an error if cannot execute query on sqlite db.
fn sqlite_list(conn: &Connection) -> Result<Vec<VaultItem>, Box<dyn Error>> {
    let mut stmt = conn
        .prepare("SELECT * FROM vault")
        .expect("Failed to query db");

    let item_iter = stmt.query_map([], |row| {
        Ok(VaultItem {
            _id: row.get(0)?,
            item_name: row.get(1)?,
            item_value: row.get(2)?,
        })
    })?;

    let mut list: Vec<VaultItem> = Vec::new();
    for item in item_iter {
        list.push(item.unwrap());
    }

    Ok(list)
}

/// Remove and item from vault.
///
/// # Errors
///
/// This function will return an error if cannot execute query on sqlite db.
fn sqlite_remove(conn: &Connection, name: &String) {
    let mut stmt = conn
        .prepare("DELETE FROM vault WHERE item_name=?")
        .expect("Failed to prepare delete query");

    match stmt.execute([name]) {
        Ok(v) => {
            if v == 1 {
                println!("{:} deleted.", name)
            }
        }
        Err(e) => println!("{:}", e),
    }
}
