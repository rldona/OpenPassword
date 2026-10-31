# Fuzzing

What is fuzzed, how, with which hooks, what is missing and why it is postponed. The usage guide is in
[`fuzz/README.md`](../../../fuzz/README.md)); the decision, in [`decisions.md`](decisions.md)) (ADR-AUD-05).

Status verified on 2026-10-30 over `HEAD` `a3daf4e`. The six new targets (`vault_json`,
`item_open`, `item_plaintext`, `backup_body`, `ffi_records` and `kdbx_container`), the `cfg(fuzzing)` hooks,
the nightly workflow and the CI reduction to 30 s are confirmed in that commit; the first five
targets are in `4e7fef0`. The local corpus figures are from the development machine.

## 1. Current coverage: eleven targets

All of them are `cargo-fuzz` (libFuzzer with AddressSanitizer by default), registered in `fuzz/Cargo.toml`
(separate workspace, requires nightly). Common CI parameters:
`-O --target x86_64-unknown-linux-gnu … -max_len=65536 -rss_limit_mb=2048 -timeout=10`.

| Target | Origin | What it receives | What it traverses | Seeds (`fuzz/seeds/<target>/`) | Local corpus (files, not versioned) |
|---|---|---|---|---|---|
| `import` | `4e7fef0` | File | `import::needs_password` and `import::parse(data, now)`: CSV, Bitwarden JSON and `.1pux`; and, since `a3daf4e`, `kdbx_fuzzing::file`: KDBX header and the checks before the KDF with a fixed key ([ID-INT-25](internal-review.md#id-int-25)), fixed) | 6 (9 521 B) | 27 888 |
| `kdbx_xml` | `4e7fef0` | UTF-8 XML | `kdbx_fuzzing::xml`: `read_entries` (groups, recycle bin, history, protected values with a fixed ChaCha20 stream, depth and entry limits) and `entry_to_item` | 3 (64 944 B; the two new ones are for deep nesting and the limit) | 5 334 |
| `key_file` | `4e7fef0` | Bytes | `kdbx_fuzzing::key_file` (`key_file_key`) | 2 (342 B) | 4 918 |
| `backup_header` | `4e7fef0` | Bytes | `backup::read_header` and `kdf.check_bounds()`. It does **not** call `check_within(MOBILE_MAXIMUM)` (ADR-AUD-07 asked for it; `fuzz/fuzz_targets/backup_header.rs:7-9`) | 1 (3 953 B) | 2 861 |
| `totp` | `4e7fef0` | UTF-8 | `Totp::parse`, `code_at(u64::MAX)`, `seconds_remaining` | 2 (157 B) | 1 868 |
| `vault_json` | new | Bytes | `serde_json` of `VaultHeader` and of `EncryptedItem` (`hex_bytes`), with round trip | 2 (1 142 B) | 4 513 |
| `item_open` | new | `EncryptedItem` in JSON | `vault.decrypt_overview`, `decrypt_details`, `decrypt_item` with the test vault | 1 (919 B) | 3 276 |
| `item_plaintext` | new | Bytes | `seal_item_part` (padding + sealing with a fixed key) → `decrypt_details` and `decrypt_overview`: `padding::unpad` and the item JSON | 3 (178 B) | 2 228 |
| `backup_body` | new | Bytes | `seal_backup` (STREAM with a fixed key) → `open_with_vault`: chunking and JSON `Body`, **without KDF**; also the raw bytes | 3 (2 391 B) | 936 |
| `kdbx_container` | `a3daf4e` | Bytes (the first one chooses the shape) | `kdbx_fuzzing::container`: KDBX 3.1/4 sealed with a fixed transformed key; `read_header`, `open_payload`: blocks with HMAC or hash, outer cipher (AES or ChaCha20), gunzip, inner header and XML | 5 (9 415 B) | 0 (no local corpus) |
| `ffi_records` | new | Bytes (`Unstructured`) | `op_ffi::Vault::unlock_with_vault_key` with an arbitrary and fixed header, and `decrypt_overview`/`decrypt_details` with an arbitrary or sealed `EncryptedItemRecord` | 1 (98 B) | 1 755 |

- **Total**: 29 seeds, about 93 000 B (`for t in seeds/*; do ls $t | wc -l; done`); the local corpus is files from the development machine and does not
  enter the repository (`fuzz/.gitignore`: `corpus/`, `artifacts/`).
- **Results**: `fuzz/artifacts/<target>/` is **empty** for the eleven targets on this machine
  (`ls fuzz/artifacts/*`): no saved failure. The commit message `4e7fef0` gives «about 48 million
  executions locally without failures» **for the first five targets**. **There is no execution figure
  recorded for the six new ones**: the local corpus size of five of them shows that they were
  run, not for how long; `kdbx_container` has no local corpus. Any execution figure per new target would be an estimate.
- **Findings it has produced so far**: none. The two `op-core` defects that fuzzing
  **did not** find —and that the internal review did— are in `internal-review.md` and are already fixed in `a3daf4e`:
  [ID-INT-01](internal-review.md#id-int-01)) (quadratic XML memory, which `kdbx_xml` did not find
  because it requires deep nesting **and** many entries; there are now limits and seeds) and
  [ID-INT-25](internal-review.md#id-int-25)) (the KDBX header coverage gap; it is now
  covered by `import` and `kdbx_container`).

## 2. `cfg(fuzzing)` hooks

`cargo fuzz` compiles with `--cfg fuzzing`; nothing else in the repository enables it. It is declared by
`[workspace.lints.rust] unexpected_cfgs … check-cfg = ["cfg(fuzzing)"]` (`Cargo.toml:15`).

| Module | File and line | What it exposes |
|---|---|---|
| `op_core::fuzzing` | `core/src/lib.rs:26` | `TEST_VAULT_KEY` (`[7; 32]`), `header()` (well-formed header, empty wrapped key), `vault()` (open vault with `unlock_with_vault_key`); it re-exports the next two |
| `vault::fuzzing` | `core/src/vault/mod.rs:273` | `seal_item_part(vault, plaintext)`: item key `[9; 32]`, nonce `[5; …]`, id `[2; 16]`, padding and sealing, to reach `unpad` and the JSON |
| `backup::fuzzing` | `core/src/backup/mod.rs:144` | `seal_backup(vault, body)` (file key `[4; 32]`, nonce `[6; …]`) and `open_with_vault(bytes, vault)` (`decrypt_body` without KDF) |
| `import::kdbx_fuzzing` | `core/src/import/mod.rs:11` → `core/src/import/kdbx.rs:661` | `xml(&str)`, `key_file(&[u8])`, `file(&[u8])` (header and checks before the KDF with a fixed, non-secret transformed key) and `container(&[u8])` (seals a KDBX with that key and reaches the XML) |

**Constant and public keys and nonces.** That is why the module cannot enter a production
binary. This is checked like this:

- **Valid check**: `strings -a android/app/build/rust/jniLibs/arm64-v8a/libop_ffi.so | grep -cE
  'seal_backup|seal_item_part|TEST_VAULT_KEY'` → **0**, with a positive control
  (`… | grep -c "cost above the accepted maximum"` → 1, a string that does exist). The `.so` was
  compiled at 10:14 on 30/10 with the tree that includes `check_within`.
- **README check: it does not work** ([ID-INT-21](internal-review.md#id-int-21))): over
  `target/release/libop_core.rlib` the same positive control gives 0, because with LTO the `.rlib` is
  *bitcode*. The auditor should not rely on it.
- `cargo build --release` does not define `fuzzing`, so the modules are not compiled: the absence in
  `libop_ffi.so` confirms it.

The risk that remains ([`decisions.md`](decisions.md)), «Risks that remain open»): code that only
exists in fuzzing and that the auditor has to read; it is asked to review it and a CI step with the
valid check is proposed.

## 3. Corpus and seeds

- **Seeds**: `fuzz/seeds/<target>/`, made by hand or with a temporary generator that uses the
  hooks and the vectors of `core/tests/vectors/op-v1.json` (those of the new targets, per
  `fuzz/README.md`). They are not minimised.
- **PR and *push*** (`ci.yml`, `fuzz` job): empty corpus plus the seeds, **30 s per target**
  (`-max_total_time=30`), eleven targets in series, no cache. If it fails, it uploads `fuzz/artifacts`.
- **Nightly** (`.github/workflows/fuzz-nightly.yml`): `cron: '17 3 * * *'` (UTC) and
  `workflow_dispatch`. Matrix of eleven jobs in parallel, one per target, `timeout-minutes: 150`,
  `-max_total_time=600` (**10 min**), `concurrency` of a single group without cancellation.
  - **Cached corpus**: `actions/cache` with key `fuzz-corpus-<target>-<run_id>` and
    `restore-keys: fuzz-corpus-<target>-`: each night it restores the most recent one and saves a new one.
  - **Minimisation**: `cargo fuzz cmin` only on Sunday (`date -u +%u = 7`).
  - **If a target fails**: it uploads `fuzz/artifacts/<target>` and the job turns red. `fail-fast:
    false`, so the other ten finish.
- **Never run**: the file was committed in `a3daf4e` and there is no record of any GitHub Actions
  run (neither manual nor scheduled) in this repository. Step 12 of the plan asks for a green
  `workflow_dispatch` run.
- **Expiry**: the Actions cache expires after 7 days without use (ADR-AUD-05). With `actions/cache`, the
  save happens on successful completion: if a target fails that night, **the corpus is not saved that day**
  (default behaviour of the action; unverified in this repository).

### Timings (estimates, not measured)

| What | Estimate | Basis |
|---|---|---|
| PR `fuzz` job | ≈ 5.5 min of fuzzing (11 × 30 s) plus compilation of 11 binaries | Arithmetic from `ci.yml`; ADR-AUD-05 says «about 5 min». **There is no real run duration recorded** |
| Nightly | ≈ 110 min of CPU (11 × 10 min), ≈ 10–20 min of wall clock in parallel plus compilation | Arithmetic from the workflow; not measured |
| Executions per target per minute | **Not measured** | There is no `exec/s` in the repository |

## 4. What is missing and why it is postponed

| Gap | Status | Reason |
|---|---|---|
| **`backup_header` without `check_within(MOBILE_MAXIMUM)`** | Requested by ADR-AUD-07, not done | The ceiling lives in `op-ffi`; `fuzz` already depends on `op-ffi` (`ffi_records`) |
| **Complete `open_backup` and `parse_import`** (with `check_mobile_kdf` and KDF) | No coverage | The cost of the KDF and the password; `ffi_records` only covers header and records |
| **KDBX KDF** | No coverage (deliberate) | Its cost is set by the file; the header, the blocks, the gunzip and the XML are covered with a fixed key (`import`, `kdbx_container`) |
| **XML memory under `-rss_limit_mb=2048`** | Open | There are limits and nesting seeds (ID-INT-01 fixed), but 2048 MB is still more than a phone can take |
| **Dictionaries and structure** (`-dict`, `Arbitrary` for JSON and XML) | None | The JSON targets start from raw bytes; dictionaries would speed up reaching valid fields |
| **Coverage measurement** (`cargo fuzz coverage`) | No report | There is no `exec/s`, no coverage per target, no data on which branches none of them reaches |
| **Jazzer for the autofill Kotlin** (`StructureParser`, `FieldClassifier`, `LoginMatcher`, `PublicSuffix`) | **Postponed** (decision no. 9) | `StructureParser` depends on `AssistStructure` and Jazzer does not reach it without Robolectric; `LoginMatcher` and `FieldClassifier` are pure functions with deterministic invariant tests (`LoginMatcherTest`: 29 tests, generators `Random(20260630)` and `Random(7)`, lines 75 and 87); Jazzer would require moving to JUnit 5 and adding dependencies to the Gradle verification |
| **`StructureParser`** | No fuzzing | Refactor it into a node abstraction without Android; it is the criterion for reconsidering Jazzer. A real candidate: [ID-INT-18](internal-review.md#id-int-18)) (recursion with no cap) |
| **ClusterFuzzLite** | **Postponed** | Persisting the corpus needs a repository or branch and a token (another secret) and a Dockerfile; the nightly gives the essentials with the same tools. Criterion for reconsidering: that the cache is lost often |
| **OSS-Fuzz** | **Discarded** | It requires a user base and its disclosure schedule does not fit before the audit |
| **Images and QR** (system image decoders and ZXing) | No fuzzing | System native code out of scope; ZXing without UI could be fuzzed with Jazzer later |
| **Differential tests** against another implementation (KeePassXC, `openssl`) | None | The golden vectors (`core/tests/vectors/op-v1.json`) cover the project's own format |

## 5. How to reproduce a local run

```sh
rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz
cd fuzz
mkdir -p corpus/kdbx_xml && cp seeds/kdbx_xml/* corpus/kdbx_xml/
cargo +nightly fuzz run -O -a kdbx_xml corpus/kdbx_xml -- -max_total_time=60 -max_len=65536 -rss_limit_mb=2048 -timeout=10
```

The XML of [ID-INT-01](internal-review.md#id-int-01)) no longer reproduces: it is covered by the test
`deep_group_nesting_is_refused_before_it_costs_memory` (`cargo test -p op-core deep_group`) and the seeds
of `fuzz/seeds/kdbx_xml/`.

## 6. What could not be checked

- Any `cargo fuzz` run in this review (only the symbol check and, before
  `a3daf4e`, the ID-INT-01 and ID-INT-25 test programs).
- The execution figures, `exec/s`, coverage and duration of the CI jobs.
- That the nightly workflow works on GitHub (corpus restored and saved, artifacts on a
  failure).
