use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use arboard::Clipboard;
use clap::{Parser, Subcommand};
use passworder::password;
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
    /// Generate password
    Gen {
        /// Show password
        #[arg(short, long)]
        show: bool,
    },
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug)]
struct VaultItem {
    _id: i32,
    name: String,
    category: i32,
    value: Vec<u8>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let conn = sqlite_open("safe.db").expect("Failed to create or open sqlite db");

    let iv = [0x24; 16];

    match &cli.command {
        Commands::Enc { input, output } => {
            let key = kdf().unwrap();
            let buf = read_file(input)?;
            let res =
                Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&buf);
            match output {
                Some(o) => write_file(o, &res)?,
                None => write_stdout(&res)?,
            }
        }

        Commands::Dec { input, output } => {
            let key = kdf().unwrap();
            let buf = read_file(input)?;
            match Aes256CbcDec::new(&key.into(), &iv.into()).decrypt_padded_vec_mut::<Pkcs7>(&buf) {
                Ok(res) => match output {
                    Some(o) => write_file(o, &res)?,
                    None => write_stdout(&res)?,
                },
                Err(e) => eprintln!("Decryption failed: {:?}", e),
            }
        }

        Commands::Add { name, value, force } => {
            let key = kdf().unwrap();
            let res = Aes256CbcEnc::new(&key.into(), &iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(&value.as_bytes());

            let item = VaultItem {
                _id: 0,
                name: name.to_string(),
                // TODO: do not hardcode
                category: 1,
                value: res,
            };

            sqlite_add(&conn, &item, force);
        }

        Commands::Get { name } => match sqlite_get(&conn, &name) {
            Ok(item) => {
                let key = kdf().unwrap();
                match Aes256CbcDec::new(&key.into(), &iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(&item.value)
                {
                    Ok(res) => println!(
                        "{:}={:}",
                        item.name,
                        String::from_utf8(res).expect("Failed to convert bytes")
                    ),
                    Err(_) => {
                        eprintln!("Failed to find an item");
                        exit(1)
                    }
                }
            }
            Err(e) => eprintln!("{:}", e),
        },

        Commands::List {} => match sqlite_list(&conn) {
            Ok(items) => {
                // TODO: no need to get key, if we list only unencrypted data
                let key = kdf().unwrap();
                println!("{:<20} {:<20}", "NAME", "VALUE");
                for item in items {
                    match Aes256CbcDec::new(&key.into(), &iv.into())
                        .decrypt_padded_vec_mut::<Pkcs7>(&item.value)
                    {
                        Ok(res) => println!(
                            "{:<20} {:<20}",
                            item.name,
                            String::from_utf8(res).expect("Failed to convert fetched data")
                        ),
                        Err(_) => {
                            eprintln!("Failed to list items");
                            exit(1)
                        }
                    }
                }
            }
            Err(e) => eprintln!("{:}", e),
        },

        Commands::Remove { name } => match sqlite_get(&conn, &name) {
            Ok(item) => {
                let key = kdf().unwrap();
                match Aes256CbcDec::new(&key.into(), &iv.into())
                    .decrypt_padded_vec_mut::<Pkcs7>(&item.value)
                {
                    Ok(_) => sqlite_remove(&conn, &name),
                    Err(_) => {
                        eprintln!("Failed to remove an item");
                        exit(1)
                    }
                }
            }
            Err(e) => eprintln!("{:}", e),
        },

        Commands::Gen { show } => {
            let pass = password::generate();
            if *show {
                println!("Generated password is: {}", pass);
            }
            let mut clipboard = Clipboard::new().unwrap();
            clipboard.set_text(pass).unwrap();
            println!("It's copied in the clipboard!");
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

/// Produces the derived key as output
///
/// # Errors
///
/// This function will return an error if cannot derive key from a password
fn kdf() -> Result<[u8; 32], Box<dyn Error>> {
    // TODO: remove password hint
    let pass = rpassword::prompt_password("Enter Master Password (1234 in DEV mode): ").unwrap();
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
    // TODO: normalize vault table
    // TODO: no need to init if DB exists
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS vault (
            id              INTEGER     PRIMARY KEY,
            name            TEXT        NOT NULL UNIQUE,
            category        INTEGER     NOT NULL,
            comment         TEXT,

            -- GENERAL category
            value           BLOB,

            -- PASSWORD category
            url             TEXT,
            user            TEXT,
            password        BLOB,

            FOREIGN KEY(category) REFERENCES item_category(id)
        );

        CREATE TABLE IF NOT EXISTS item_category (
            id          INTEGER PRIMARY KEY,
            category    TEXT    NOT NULL UNIQUE
        );

        INSERT OR IGNORE INTO item_category (category)
        VALUES
            ('GENERAL'),
            ('PASSWORD');
        "
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
        "INSERT INTO vault (name, category, value) VALUES (?1, ?2, ?3)",
        (&item.name, &item.category, &item.value),
    ) {
        Ok(_) => println!("{:} saved.", &item.name),
        Err(e) => {
            if let rusqlite::Error::SqliteFailure(rc, _) = e {
                match rc.code {
                    rusqlite::ErrorCode::ConstraintViolation => {
                        eprintln!("SQLite error: {:}", e);
                        if *update {
                            let mut stmt = conn
                                .prepare("UPDATE vault SET value = ?1 WHERE name = ?2")
                                .expect("Preparing update item failed");

                            stmt.execute(rusqlite::params![item.value, item.name])
                                .expect("Updating item failed");

                            println!("{:} updated", &item.name)
                        } else {
                            println!(
                                "{:} already exists! (error={:}), please try with -f to force update",
                                &item.name, rc.extended_code
                            )
                        }
                    }
                    _ => eprintln!("SQLite error: {:}", e)
                }
            } else {
                eprintln!("{:}", e);
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
        .prepare("SELECT * FROM vault WHERE name=?")
        .expect("Failed to query db");

    stmt.query_row([&item_name], |row| {
        Ok(VaultItem {
            _id: row.get(0)?,
            name: row.get(1)?,
            category: row.get(2)?,
            value: row.get(4)?,
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
        .prepare("SELECT * FROM vault ORDER BY name")
        .expect("Failed to query db");

    let item_iter = stmt.query_map([], |row| {
        Ok(VaultItem {
            _id: row.get(0)?,
            name: row.get(1)?,
            category: row.get(2)?,
            value: row.get(4)?,
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
        .prepare("DELETE FROM vault WHERE name=?")
        .expect("Failed to prepare delete query");

    match stmt.execute([name]) {
        Ok(v) => {
            if v == 1 {
                println!("{:} deleted.", name)
            }
        }
        Err(e) => eprintln!("{:}", e),
    }
}
