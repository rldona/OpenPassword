# Importer test files

All the data is made up. The passwords in this directory protect nothing real.

## `keepassxc-3.1.kdbx`

A real database created by **KeePassXC 2.8.0** from `fixture.xml`:

```sh
keepassxc-cli import -p -t 100 fixture.xml keepassxc-3.1.kdbx   # password: prueba-kdbx
```

KDBX 3.1, AES-256, AES-KDF (~5.8 million rounds) and values protected with Salsa20. It includes an
entry with history (only the current password must be imported), another one in the recycle bin (it must
not be imported), a custom protected field, a KeePassXC TOTP, a note, XML entities in
unprotected values and a password with leading and trailing spaces.

If `fixture.xml` changes, regenerate the `.kdbx` with the command above and review the tests in `kdbx.rs`.

## `keepassxc-keyfile.kdbx`, `keepassxc-keyfile-only.kdbx` and `sample.keyx`

The same `fixture.xml`, protected with a password and a key file, and with a key file only.
`sample.keyx` is the XML v2.0 key file that KeePassXC generated:

```sh
keepassxc-cli import -p --set-key-file sample.keyx -t 100 fixture.xml keepassxc-keyfile.kdbx
keepassxc-cli import --set-key-file sample.keyx -t 100 fixture.xml keepassxc-keyfile-only.kdbx
```

## Pending

`keepassxc-cli` only creates KDBX 3.1. A real KDBX 4 (ChaCha20 + Argon2id) created from the
KeePassXC interface (*Database → Database Settings → Security*) is missing to cover that path with a
reference file. Until then, the KDBX 4 code is written according to the specification
but has not been tested against a real file.
