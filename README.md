# safe
A digital safe box.

# Roadmap

## General
- [X] basic command line
- [X] enc/dec a simple file by a key (AES-256)
- [X] derive encryption key from master key (Scrypt)
- [X] support SQLite as DB
- [ ] master password has to meet a couple of strict rules
  - 12 chars and more
  - at least one lower, upper, digit and symbol
- [ ] pick a better IV

## Password Manager
- [X] password generator
  - [ ] parametrize (length, upper, lower, number, symbol, readable)
- [ ] server
  - [ ] PostgreSQL (app/service, user/email, password)
  - [ ] API
- [ ] login with user/email and encrypted user/email (we don't keep master password in the server, even encrypted)
- [ ] pre-defined types (password, note, bank account, id/passport, wifi password, key, etc)
- [ ] custom type (key-value)
- [ ] do not support or limit the file storage (few MB for the first phase)
- [ ] share secrets
- [ ] 2FA (OTP, Authenticator app, Yubikey)
- [ ] (time limited) recycle bin for secrets
- [ ] family sharing (with access management)
- [ ] salt based on user/email instead of hard-coded one
- [ ] audit log
- [ ] monitor dark web for leaked passwords
- [ ] SSO integration

## Clients
- [ ] Command line (extend current `safe` command with API calls)
- [ ] Web GUI
- [ ] desktop app for Mac, Windows and Linux
- [ ] mobile app for iOS and Android
- [ ] Browser extensions (generate, autosave, autofill, etc)
- [ ] keep master password locally (limited time, keyring, secured device, etc)