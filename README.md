# safe
A digital safe box.

# Roadmap

## General
- [X] basic command line
- [X] enc/dec a simple file by a key (AES-256)
- [X] derive encryption key from master key (Scrypt)
- [X] support SQLite as DB
- [ ] add editor to modify the file
- [ ] master password has to meet a couple of strict rules
  - 12 chars and more
  - at least one lower, upper, digit and symbol
- [ ] pick a better IV

## Password Manager
- [X] password generator
  - [ ] parametrize (length, upper, lower, number, symbol, readable)
- [ ] server
  - [ ] PostgreSQL (app/service, user/email, password)
  - [ ] pre-defined types (password, note, bank account, id/passport, wifi password, key, etc)
  - [ ] custom type (key-value)
  - [ ] API
- [ ] salt based on user/email instead of hard-coded one

## Clients
- [ ] Command line
- [ ] Web GUI
- [ ] iOS
- [ ] Android
- [ ] Browser extensions (autocomplete, etc)
- [ ] keep master password locally (limited time, keyring, secured device, etc)