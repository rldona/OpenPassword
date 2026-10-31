# Security

OpenPassword stores my passwords, so a security bug is handled before anything else.

> **Personal project, no external audit.** There are no users to support, no bug bounty program and
> no agreed disclosure deadlines. The risks I know about and have decided to accept are in the
> [threat model](docs/threat-model.md).

## If you find a bug

Open an issue in the repository with:

- which component fails (`op-core`, `op-ffi`, the Android app, the CLI or the `.opvault` format) and
  in which commit or version;
- the steps or the file to reproduce it;
- what an attacker can achieve and under which assumptions (see the [threat model](docs/threat-model.md)).

There is nothing to protect with private disclosure: the repository has no external users.

## In scope

- The cryptography and its implementation: [specification](docs/crypto-spec.md), key derivation,
  per-item encryption and backup format.
- Reading untrusted data: `.opvault` backups, importers (KeePass, 1Password, Bitwarden, CSV),
  `otpauth://` links and QR codes.
- The Android app: autofill (domains, public suffixes and packages), automatic lock, biometrics,
  clipboard, permissions and backups.

## Out of scope

What the [threat model](docs/threat-model.md) leaves out: a rooted phone or malware with privileges,
a *keylogger*, or someone who knows the master password and has the secret key.

## Known and accepted bugs

They are in the [threat model](docs/threat-model.md) and in the archived internal review
([`docs/archive/audit/internal-review.md`](docs/archive/audit/internal-review.md)). The most relevant
one for daily use: on Android, the password copied to the clipboard is not erased after 30 s if the
app is in the background; it is erased when you return to the app or when the screen turns off.
