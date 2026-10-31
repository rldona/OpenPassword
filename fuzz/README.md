# Fuzzing

Eleven [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) targets for everything that reads untrusted data. They need nightly:

| Target | What it receives |
|---|---|
| `import` | Any file that is imported: CSV, Bitwarden JSON, 1Password `.1pux` and KDBX. For KDBX it walks `kdbx::parse` without key derivation (fixed key, `kdbx_fuzzing::file`): header, HMAC or leading-bytes check |
| `kdbx_container` | KDBX 3.1/4 sealed with the fixed key: block splitting, outer encryption, gunzip, inner header and XML. The first byte selects the shape |
| `kdbx_xml` | The already decrypted KeePass XML, with protected values; includes seeds for deep nesting and for many entries |
| `key_file` | KeePass key files |
| `backup_header` | The plaintext part of an `.opvault` backup, which is read before asking for the password |
| `totp` | `otpauth://` links and bare secrets |
| `vault_json` | `VaultHeader` and `EncryptedItem` as JSON (the `serde` of `encoding::hex_bytes`) |
| `item_open` | An arbitrary `EncryptedItem` decrypted with the fixed test vault: key unwrapping, lengths and AAD |
| `item_plaintext` | Bytes that are sealed with a fixed key as `overview` and `details` and then decrypted: `padding::unpad` and the item JSON |
| `backup_body` | Bytes that are sealed with STREAM as the body of a backup and opened without KDF: chunking and JSON of the `Body` |
| `ffi_records` | `op-ffi`: arbitrary header and arbitrary `EncryptedItemRecord` (or sealed with the fixed key) |

## `cfg(fuzzing)` hooks

With random inputs the AEAD lets nothing through, so the last four targets (and `kdbx_container`, with `import::kdbx_fuzzing`) use the `op_core::fuzzing` module (`core/src/lib.rs`, plus `vault::fuzzing` and `backup::fuzzing`), which seals the input with a **fixed, public, test-only key** (`TEST_VAULT_KEY`). It only exists with `--cfg fuzzing`, which `cargo fuzz` sets and nothing else in this repository does: it does not enter any normal or release build. In addition, `core/src/lib.rs` rejects with `compile_error!` a `release` build with `--cfg fuzzing` (`cargo fuzz build` keeps them; with `-O` you have to add `-a`, and that is why every command here and in CI uses `-O -a`).

### Checking that they are not in what is distributed

`scripts/check-no-fuzzing-hooks.sh <libop_ffi.so>...` looks in the final native library, not in the `.rlib`: with `lto = true` the `.rlib` keeps *bitcode* and `strings` finds nothing even with the hooks inside (a `! strings … | grep seal_backup` on it always “passes”). Searching for the hook names (`seal_backup`, `seal_item_part`, `TEST_VAULT_KEY`) in the `.so` does not work either: the linking removes what nobody uses, so **they do not appear in a build with the hooks either**. That is why `op_core::fuzzing::HOOKS_MARKER` is a `#[used]` string (`OPENPASSWORD_FUZZING_HOOKS`) that only exists with `--cfg fuzzing` and survives linking. The script fails if it finds it and also if it does not find a control string that is always there (`cost above the accepted maximum`): that way an unreadable or empty file does not pass as “clean”.

```sh
# Negative control: the release library does not have them (exit 0).
cargo build -p op-ffi --release --locked
scripts/check-no-fuzzing-hooks.sh target/release/libop_ffi.so      # (.dylib on macOS)

# Positive control: a build with the hooks MUST fail the check.
scripts/check-no-fuzzing-hooks.sh --self-test
# Done by hand: the normal `release` rejects --cfg fuzzing, so the assertions are enabled.
RUSTFLAGS="--cfg fuzzing" CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_TARGET_DIR=/tmp/fz \
  cargo build -p op-ffi --release --locked
strings -a /tmp/fz/release/libop_ffi.so | grep -c OPENPASSWORD_FUZZING_HOOKS   # 1
```

CI runs the negative control on the Linux `libop_ffi.so`, the `--self-test` and the check on the libraries of the release APK (`lib/*/libop_ffi.so`).

Key derivations are not fuzzed: their cost is fixed by the file and is bounded (in KDBX, Argon2 ≤ 512 MiB, 1000 passes and 64 lanes with `memory × passes ≤ 3 GiB·pass`, and AES-KDF ≤ 200 million rounds; in `.opvault`, `KdfParams::MAXIMUM`).

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/import && cp seeds/import/* corpus/import/
cargo +nightly fuzz run -O -a import corpus/import -- -max_len=65536 -rss_limit_mb=2048 -timeout=10
```

`seeds/` are the initial inputs of each target. `corpus/` and `artifacts/` (the failures found) are not uploaded. CI runs each target for 30 s on every push (`-max_total_time=30`). `.github/workflows/fuzz-nightly.yml` runs them for 10 min every night (and manually with `workflow_dispatch`), with the corpus in `actions/cache` and minimized with `cargo fuzz cmin` on Sundays; if a target fails, it uploads its artifacts.

The seeds of the new targets are hand-written (with a temporary generator that uses the hooks), not minimized.
