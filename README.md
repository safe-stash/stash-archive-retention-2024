# safe
A digital safe box.

# Roadmap

## General
- [X] basic command line
- [X] enc/dec a simple file by a key (AES-256)
- [X] derive encryption key from master key (Scrypt)
- [X] support SQLite as DB
  - [ ] check DB integrity
  - [ ] keep DB in .config folder
- [ ] master password has to meet a couple of strict rules
  - 12 chars and more
  - at least one lower, upper, digit and symbol
- [ ] pick a better IV

## Password Manager
- [X] password generator
  - [ ] wipe out clipboard after tiemout
  - [ ] parametrize (length, upper, lower, number, symbol, readable)
- [ ] server
  - [ ] PostgreSQL (app/service, user/email, password)
  - [ ] API
- [ ] login with "user/email" as user and "encrypted user/email" as password (we don't keep master password in the server, even encrypted)
- [ ] salt based on user/email instead of hard-coded one
- [ ] pre-defined types (password, note, bank account, id/passport, wifi password, key, etc)
  - [ ] do not support or limit the file storage (few MB for the first phase)
- [ ] custom type (key-value)
- [ ] define categories
- [ ] (time limited) recycle bin for secrets
- [ ] share secrets
- [ ] family sharing (with access management)
- [ ] audit log
- [ ] 2FA (OTP, Authenticator app, Yubikey)
- [ ] SSO integration
- [ ] monitor dark web for leaked passwords
- [ ] use `secstr` crate for zeroing in-mem passwords

## Clients
- [ ] Command line (extend current `safe` command with API calls)
- [ ] Web GUI
- [ ] desktop app for Mac, Windows and Linux
- [ ] mobile app for iOS and Android
- [ ] Browser extensions (generate, autosave, autofill, etc)
- [ ] keep master password locally (limited time, keyring, secured device, etc)