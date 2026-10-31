# Prior internal review

Review of the code by the project itself, before handing it to the external auditor. One section per
area. Each finding can be **checked with `grep`, `sed -n` or a command** that is given; the ones that
have been reproduced carry the procedure. If an area is clean, that is stated and it is shown why.

The findings were written on 2026-10-30 against the working tree (`HEAD` `700f1a7` plus uncommitted
changes). Those changes and the fixes for findings ID-INT-01, 05, 07, 16 and 25 were committed
in `a3daf4e` ("Phase 3: hardening, supply chain and audit package"); the
state of each finding has been checked again against the code of that commit. **The line numbers
in the "Evidence" sections describe the code before the fix** and no longer match in the
fixed findings. A second block of fixes, **not committed yet** (on top of `a3daf4e`), closes ID-INT-26 (new) and
completes ID-INT-16 (its first fix was bypassable), besides adjusting ID-INT-02, ID-INT-05 and ID-INT-21; it is described in each finding. A third block, also **uncommitted** and
**without a hash yet** ("in the uncommitted block"), fixes or mitigates ID-INT-02, 03, 06, 08, 09, 10, 11, 12, 14, 17, 18, 21 and 23 and extends the instrumented test of ID-INT-13; each finding states
what is still **unverified on a device**. The lines may change if the code changes: the auditor will work on the frozen SHA
([`decisions.md`](decisions.md)), ADR-AUD-01). **Note (2026-10-30)**: what appears here as "uncommitted" is already in `183598d` and `3868f4f`; the text keeps the original wording.

**Scope of this review**: reading `core/src`, `ffi/src`, `android/app/src/main`, the workflows and
the build configuration, plus a run of `cargo test --workspace --locked` on the tree with the
third block (**102 pass, 0 fail, 1 ignored**: 50 unit tests of `op-core`, 9 + 3 + 19 + 5 integration
tests and 16 of `op-ffi`; in the original write-up, on `a3daf4e`, they were 95), and `cargo deny --locked check` (`advisories ok, bans ok, licenses ok, sources ok`) plus
`cargo deny --manifest-path fuzz/Cargo.toml --locked --config fuzz/deny.toml check` (same result, see ID-INT-23). The Kotlin
tests have **not** been run (in the original review there was no JDK in the `PATH`; they were later run on 2026-10-30 on macOS with JDK 17: **186 pass, 0 fail**), nor the instrumented ones in the original review. **Update of 2026-10-30**: the instrumented tests (17 tests) were later run on an SM-S948B (API 37) and passed; in a second part of the session DT-05 and DT-07 were run (`pass`) and DT-04 (**`fail`**: confirms ID-INT-14, later accepted as residual risk); the rest of the device tests have still not been run (see [`device-tests.md`](device-tests.md)), sections 3.3 and 3.4). **This is not a cryptographic
review**: derivation and vectors have not been checked beyond what the tests cover.

## Severity scale

The project's one ([`findings-process.md`](findings-process.md)) §1): **Critical**, **High**, **Medium**,
**Low**, **Info**. The ones assigned here are proposals of the project; the auditor reviews them. Where the
criterion of the scale and the real exploitability point to different levels, it is explained.

## Summary

| Severity | Findings | Fixed | Partial | Confirmed on device | Accepted | Open |
|---|---|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 | 0 | 0 |
| High | 2 | 2 | 0 | 0 | 0 | 0 |
| Medium | 3 | 2 | 0 | 0 | 1 | 0 |
| Low | 11 | 11 | 0 | 0 | 0 | 0 |
| Info | 10 | 4 | 1 | 0 | 3 | 2 |
| **Total** | **26** | **19** | **1** | **0** | **4** | **2** |

"Fixed" means that the code handles it and there are tests (JVM or Rust) written; it does **not** mean verified on a device except where stated (ID-INT-05, 08, 09 and 13, 2026-10-30, SM-S948B API 37; and, in part, ID-INT-16, see below). The fixes of the uncommitted block
were later run on the Kotlin JVM (186 pass, 0 fail, 2026-10-30). **"Confirmed on device"** means that the described failure was reproduced on a device: it is **not** "fixed" and the finding stays open until there is a fix and the test is repeated. What is still pending on a device or on human approval:

- **Device**: ID-INT-14 (confirmed on API 37 and **accepted as residual risk**; API 29, 33 and 36 were not tested, nor DT-04c or "on returning to the app"; [DT-04](device-tests.md#dt-04))), ID-INT-26 (autofill) and ID-INT-16 (the `webDomain` of a non-browser app is ignored: **verified on device** with DT-07 on API 37; DT-06 with Chrome, DT-08 and the `iframe` hypothesis are still missing), ID-INT-20 (loading of the suffix list **verified on device** in the debug build with DT-05; the R8 variant and the automatic update are still missing). ID-INT-13 was verified on 2026-10-30 on an SM-S948B (API 37) with the instrumented tests and DT-01; the instrumented tests of ID-INT-05, 08 and 09 also passed there. DT-02/DT-03 (API 28-30 and dialogs), DT-12 (Android 9) and everything that depends on a real vault are still pending.
- **Human approval**: the KDBX policy of ID-INT-02 (decision no. 4 of [`decisions.md`](decisions.md))) is still pending. **Decided on 2026-10-30**: the NCSA licence of `libfuzzer-sys` in `fuzz/deny.toml` (ID-INT-23, **approved**) and ID-INT-14 (**accepted as residual risk**).

| ID | Sev. | Area | Title | Status |
|---|---|---|---|---|
| [ID-INT-01](#id-int-01) | Medium | Rust | KDBX: the XML consumes quadratic memory (DoS reproduced) | **Fixed** (`a3daf4e`) |
| [ID-INT-02](#id-int-02) | Low | Rust | KDBX: the KeePass KDF does not go through the moving ceiling of `.opvault` | **Fixed** (KDBX policy approved on 2026-10-30; `KdfMemoryTest` green) |
| [ID-INT-03](#id-int-03) | Low | Rust | Importers: secrets in buffers that are not wiped | **Fixed** (in the uncommitted block; residues documented) |
| [ID-INT-04](#id-int-04) | Info | FFI | UniFFI output residues accepted | Accepted |
| [ID-INT-05](#id-int-05) | Medium | Android | Unlock does not close the `Vault` if it fails after `Vault.unlock` (known) | **Fixed** (`a3daf4e`; instrumented test green on device, 2026-10-30) |
| [ID-INT-06](#id-int-06) | Low | Android | A single unreadable item prevents unlocking the vault | **Fixed** (in the uncommitted block; Kotlin not run) |
| [ID-INT-07](#id-int-07) | Low | Android | Four FFI calls without catching `InternalException` | **Fixed** (`a3daf4e`) |
| [ID-INT-08](#id-int-08) | Low | Android | `lock()` does not take the `mutex`: race with an operation in progress | **Fixed** (in the uncommitted block; instrumented test green on device, 2026-10-30; JVM not run) |
| [ID-INT-09](#id-int-09) | Low | Android | `verifyPassword` does not count or wait for attempts | **Fixed** (in the uncommitted block; instrumented test green on device, 2026-10-30; JVM not run) |
| [ID-INT-10](#id-int-10) | Info | Android | `atomicWrite` does not force the flush to disk | **Fixed** (in the uncommitted block; residue: directory fsync; Kotlin not run) |
| [ID-INT-11](#id-int-11) | Info | Android | `AutoBackup` swallows `CancellationException` | **Fixed** (in the uncommitted block; Kotlin not run) |
| [ID-INT-12](#id-int-12) | Low | Android | `readBackupFile` leaves a plaintext copy without wiping it | **Fixed** (in the uncommitted block; Kotlin not run) |
| [ID-INT-13](#id-int-13) | Info | Android | A7: the implementation and its tests do not reach what the ADR describes | **Fixed and verified on device** (2026-10-30; DT-01 only `MainActivity`; banner in autofill not done) |
| [ID-INT-14](#id-int-14) | Medium | Clipboard | The 30 s wipe does not act if the app lost focus | **Accepted as residual risk** (decision of the owner, 2026-10-30; failure confirmed on device, DT-04, SM-S948B API 37: the wipe does not happen in the background) |
| [ID-INT-15](#id-int-15) | Info | Clipboard | No "sensitive" flag on API 28-32 | Accepted |
| [ID-INT-16](#id-int-16) | High | Autofill | Any app declares a page's domain: a browser is not required | **Fixed** (`a3daf4e`, completed in the uncommitted block; **verified on device** only that a non-browser app does not receive web datasets, DT-07 on API 37; not tested with Chrome or the `iframe`) |
| [ID-INT-17](#id-int-17) | Low | Autofill | `PendingSaves`: lazy expiry and no flush on lock | **Fixed** (in the uncommitted block; Kotlin not run) |
| [ID-INT-18](#id-int-18) | Low | Autofill | `StructureParser` walks the tree recursively and without a limit | **Fixed** (in the uncommitted block; Kotlin not run, not tested on device) |
| [ID-INT-19](#id-int-19) | Info | Autofill | Up to 5 logins in plaintext travel to `system_server` without dataset authentication | Accepted |
| [ID-INT-20](#id-int-20) | Info | Autofill | The public suffix list: no test with R8 and no update | Open (loading and application **verified on device** in the debug build, DT-05; no R8 and no automatic update) |
| [ID-INT-21](#id-int-21) | Low | Tooling | The check that `cfg(fuzzing)` does not get into release detects nothing | **Fixed** (in the uncommitted block; CI not run) |
| [ID-INT-22](#id-int-22) | Info | Tooling | `cargoBuild` does not declare `rust-toolchain.toml` or `.cargo/config.toml` as inputs | Open |
| [ID-INT-23](#id-int-23) | Info | Tooling | Generated files and *lockfiles* outside coverage | Partial (`.gitignore`; `fuzz/deny.toml` and the CI step done in the uncommitted block; NCSA licence **approved** on 2026-10-30) |
| [ID-INT-24](#id-int-24) | Info | Tooling | `fuzz/README.md` is out of date with respect to CI and the limits | **Fixed** (documentation) |
| [ID-INT-25](#id-int-25) | Low | Tooling | The `import` target does not reach the KDBX header parser | **Fixed** (`a3daf4e`) |
| [ID-INT-26](#id-int-26) | High | Autofill | An autofilled app can inject the domain into the mutable `PendingIntent` and receive credentials from any site | **Fixed** (uncommitted; not tested on device) |

### Defects already known before this review

| Defect | Where it was recorded | Finding | Status |
|---|---|---|---|
| Unlock does not close the `Vault` if `decryptOverview` fails after `Vault.unlock` | Previous review (this document) | ID-INT-05 | **Fixed** (`a3daf4e`) |
| FFI calls without catching `InternalException` | [`decisions.md`](decisions.md)) ADR-AUD-03 (8 sites) | ID-INT-07 | The 8 in the list, covered in `700f1a7`; the 4 that were left out of the list, in `a3daf4e` (**fixed**) |
| Out-of-memory in Argon2 aborts the process | [`decisions.md`](decisions.md)), "Risks that remain open" | ID-INT-02 | **Mitigated** (in the uncommitted block): KDBX has the same ceiling as mobile (512 MiB, 3 GiB·pass) and a RAM check before asking for the password; the ceiling reduces it, it does not remove it (it is still not a fallible allocation), and the policy is pending human approval |
| KDF that cannot be cancelled | Ibid. | — | Open, out of scope |
| Secrets in a JVM and Compose `String`; output `RustBuffer` without wiping | ADR-AUD-02 §6 | ID-INT-04 | Accepted and documented |
| `StructureParser` without fuzzing | ADR-AUD-05 | ID-INT-18 | The traversal is already iterative and bounded (in the uncommitted block); fuzzing is still postponed ([`fuzzing.md`](fuzzing.md))) |

---

## 1. Rust: `op-core`

### 1.1 Method

- `unsafe` is **forbidden** in the whole workspace: `[workspace.lints.rust] unsafe_code =
  "forbid"` (`Cargo.toml:13`) and the three crates inherit `[lints] workspace = true`.
  `grep -rn "unsafe" core/src ffi/src cli/src` returns nothing.
- Every production `unwrap`, `expect`, index and `as` has been reviewed (before `#[cfg(test)]`).
  Command: `for f in core/src/*.rs core/src/*/*.rs; do awk '/#\[cfg\(test\)\]/{exit} /\.unwrap\(\)|\.expect\(|panic!/{print FILENAME":"NR": "$0}' $f; done`.
  Result in `op-core`: **19 production `expect`** (plus 2 in the `cfg(fuzzing)` module,
  `backup/mod.rs:168,173`), **0 `unwrap`, 0 `panic!`**. All of them are protected by a previous check:

| Place | Why it cannot fail with hostile input |
|---|---|
| `backup/mod.rs:67` `u32::try_from(header_json.len())` | Header that the app itself has just serialised (`write`), not input |
| `backup/mod.rs:92` `try_into` of 4 bytes | After `bytes.len() < fixed` (`:84-86`) |
| `crypto/stream.rs:52` `chunks.pop()` | After `ciphertext.len() < TAG_LEN` (`:47-49`): there is at least one chunk |
| `vault/padding.rs:26` `prefix.try_into()` | `unpad` requires a length that is a multiple of 64 and non-empty (`:22-24`): there are ≥ 64 bytes |
| `import/kdbx.rs:90,95,100` `take(n)?.try_into()` | `take` returns exactly `n` bytes or an error (`:75-83`, with `checked_add`) |
| `import/kdbx.rs:195,200,206,357` | Guards `data.len() >= 4`, `== 8`, `== 4`, `== 4` right before |
| `crypto/aead.rs:41`, `stream.rs:31,36` | Encryption in memory; it only fails if the size exceeds the AEAD limit |
| `crypto/mod.rs:29` AAD parts > 4 GiB | The parts are short constants and ids |
| `totp.rs:180`, `kdbx.rs:471` HMAC | HMAC accepts keys of any length |
| `secret_key.rs:44,57` | 4-byte HKDF output and ASCII base32 |

- Tests (`cargo test --workspace --locked`, all green): 50 unit tests of `op-core` (36 s in the last run: Argon2
  with 64 MiB in the test profile), 9 of `tests/backup.rs`, 3 of `known_answers.rs`, 19 of
  `tests/vault.rs` and 5 of `tests/vectors.rs` (1 ignored).

### 1.2 Clean areas and why

- **`.opvault` format and AEAD** (`backup/mod.rs`, `crypto/stream.rs`, `crypto/aead.rs`,
  `vault/mod.rs`): lengths checked before splitting; AAD with domain, ids and revision
  (`vault/mod.rs:63-76`); header authenticated by the AAD of the body (`backup/mod.rs:46-48`); the
  version is checked after the magic (`:86-92`) and `check_bounds` runs **before** any KDF (`:101`).
  The `secret_key_id` is compared before deriving (`vault/mod.rs:105-107`).
- **TOTP** (`totp.rs`): input ≤ 4096 bytes (`:76`), `period` between 1 and 3600 (`:60`) —a division by
  zero is impossible—, digits between 6 and 8 (`:57`), `10u32.pow(8)` without overflow, `get(..10)` on a
  character boundary (`:81`).
- **Padding** (`vault/padding.rs`): `len > rest.len()` prevents any out-of-range read (`:27`).

<a id="id-int-01"></a>
### ID-INT-01 · KDBX: the XML consumes quadratic memory (DoS reproduced)

| Field | Value |
|---|---|
| Severity | **Medium** (repeatable DoS with a hostile file, criterion of the scale) |
| Component | `op-core`, KDBX importer |
| Evidence | `core/src/import/kdbx.rs:648` (`group_uuids: Vec<String>`), `:660` (one element is added per `<Group>`), `:710` (`entries.push((entry, group_uuids.clone()))`) |
| Status | **Fixed** in `a3daf4e`. |

**What happens.** Each `<Entry>` keeps a **full copy** of the stack of open groups
(`group_uuids.clone()`), and all the copies are retained until the end to decide whether the item
is in the recycle bin (`:722-729`). There is no limit on nesting depth or on the number of
entries beyond the 32 MiB of input (`import/mod.rs:34`). The consumption is `24 B × depth ×
entries` (the size of a `String`).

**Reproduction** (no file in the repository has been touched): a test crate outside the
repository, with `op-core = { path = … }` and `RUSTFLAGS="--cfg fuzzing"`, which calls
`op_core::import::kdbx_fuzzing::xml` with `<KeePassFile><Root>` + D × `<Group>` + E × `<Entry></Entry>` +
D × `</Group>`:

| Depth D | Entries E | XML size | Time | Peak RSS |
|---|---|---|---|---|
| 1000 | 1000 | 30,040 B | 8 ms | 11 MB |
| 4000 | 4000 | 120,040 B | 158 ms | 388,128 KB |
| 8000 | 4000 | 180,040 B | 527 ms | 757,504 KB |

Measured on macOS arm64 with `ps` every 20 ms; it matches the calculation (8000 × 4000 × 24 B = 768 MB). With the
32 MiB cap the required memory **has no practical ceiling**: it is a linear extrapolation, without
running it.

**Who can exploit it.** The author of the `.kdbx`, who also chooses the password that is typed in: a
database "from a friend, the password is X". The process dies from lack of memory (it aborts even if the
profile is `unwind`, ADR-AUD-03). The fuzzing target `kdbx_xml` (`-rss_limit_mb=2048`) has not
found it because it requires deep nesting **and** many entries.

**Recommendation.** Store in each entry only the index or the id chain of its group, or decide
"it is in the recycle bin" when closing the `<Entry>` with the current stack; and set a depth cap (for
example 64) returning `Malformed`. Add a test with that XML and a seed to `fuzz/seeds/kdbx_xml/`.

**Fix (`a3daf4e`).** `read_entries` no longer clones the group stack per entry (`core/src/import/kdbx.rs:808`) and the
decrypted XML has limits: `MAX_GROUP_DEPTH` 100 open groups, `MAX_XML_DEPTH` 256 open elements and `MAX_ENTRIES` 100,000
(`kdbx.rs:45-49`, checked at `:829`, `:836` and `:896`); when they are exceeded the import fails with
`InvalidInput` ("cannot be imported"). With them the memory is linear. Tests:
`deep_group_nesting_is_refused_before_it_costs_memory` (`kdbx.rs:1226`; the 180 KB XML that used to ask for ~900 MB is rejected),
`nesting_and_entry_limits_accept_their_edge` (`:1248`). New seeds: `fuzz/seeds/kdbx_xml/deep-groups-many-entries.xml` and
`depth-limit-edge.xml`. The commit message gives 926 MB of RSS → 3.4 MB for that XML (figure from the commit; **it has not been measured again** in this review).

<a id="id-int-02"></a>
### ID-INT-02 · KDBX: the KeePass KDF does not go through the moving ceiling of `.opvault`

| Field | Value |
|---|---|
| Severity | **Low** (risk already recorded in [`decisions.md`](decisions.md)); a vector that requires a hostile database) |
| Component | `op-core` / `op-ffi` |
| Evidence | `core/src/import/kdbx.rs:36-42,544-555` (today 512 MiB, 1000 passes, 64 lanes and `memory × passes ≤ 3 GiB·pass`; before, 1 GiB and 16 GiB·pass); `ffi/src/lib.rs:542-574` (`parse_import` does not call `check_mobile_kdf`); `VaultSession.kt:126-129,139,168` (the RAM check only exists for `.opvault`); `ExternalImport.kt:54,62` (import without that check) |
| Status | **Fixed** in the uncommitted block (no hash yet). The **policy** of rejecting KDBX databases that do not fit is still pending human approval (decision no. 4 of [`decisions.md`](decisions.md))). |

**Fix (in the uncommitted block).** Two parts, both verified **only by reading and by the Rust tests** (the Kotlin ones have not been run):
(1) the KDBX ceiling is aligned with mobile (512 MiB / 3 GiB·pass, `kdbx.rs:36-42`);
(2) `op_core::import::kdbx_argon2_cost` (`core/src/import/mod.rs:59`, exposed as `import_kdf` in `ffi/src/lib.rs:509`, `importKdf` in Kotlin) reads the header **without deriving** and returns the Argon2 cost (`None` for AES-KDF, KDBX 3.1 or files that are not KDBX);
`checkImportKdfFits` (`session/KdfMemory.kt:28`) throws `OpException.KdfTooExpensive` if the requested memory exceeds half of the device's RAM, and it is called in `readExternalExport` (`ui/settings/ExternalImport.kt:57`) **before** asking for the password, with its own error message.
Tests: `argon2_budget_accepts_the_edge_and_refuses_above_it`, `argon2_cost_is_none_without_argon2_and_errors_on_damaged_headers` (`kdbx.rs`), `import_kdf_reports_the_kdbx_argon2_cost_before_the_kdf` (`ffi/src/lib.rs:916`; run, green) and `KdfMemoryTest` (6 `@Test`, not run).
**Residues**: `argon2` 0.5 still reserves the memory without the possibility of a recoverable failure (a device with little *free* RAM may abort even if it passes the *total* RAM check); the check has not been tested on a device.

**Contrast in `a3daf4e`.** Still open: `parse_import` does not call `check_mobile_kdf`, and the RAM check (`checkKdfFits`, `VaultSession.kt:126`, rule of `KdfMemory.kt`: KDF memory ≤ half of the RAM)
only applies to `.opvault` copies (`restore` and `importBackup`). What there is, is the joint KDBX budget (`MAX_ARGON2_BYTES` 512 MiB and `MAX_ARGON2_WORK` 3 GiB·pass, `kdbx.rs:36-42`), pending human approval (no. 4).
**Update (uncommitted):** the KDBX ceiling was lowered from 1 GiB / 16 GiB·pass to 512 MiB / 3 GiB·pass, the same as the mobile ceiling of `.opvault` (512 MiB × 6 passes; `ffi/src/lib.rs:33`); the comment in `kdbx.rs:34-37` justifies it that way. Without a prior RAM check at that moment; **that part was fixed later** (see "Fix" below).

**What happens.** An `.opvault` copy is limited to 512 MiB / 6 / 8 on Android (`ffi/src/lib.rs:33`),
but (in `a3daf4e`) a KeePass database could ask for **1 GiB × 16 passes** and the import accepted it. Not any more: the test
`argon2_budget_accepts_the_edge_and_refuses_above_it` now sets 512 MiB × 6 as the edge and rejects 512 MiB × 7 and 1 GiB × 1 (`kdbx.rs:1191-1212`). `argon2` 0.5 reserves the
memory without the possibility of a recoverable failure: in a 32-bit process or with little free memory
it **aborts**. There is no prior RAM check for this path.

**Recommendation.** Decide the policy: apply the same mobile ceiling to KDBX (rejecting with a
clear message), or at least a RAM check before `parse_import`. It is a human decision
because it rejects legitimate databases.

<a id="id-int-03"></a>
### ID-INT-03 · Importers: secrets in buffers that are not wiped

| Field | Value |
|---|---|
| Severity | **Low** (undocumented residue; requires reading process memory, A10) |
| Component | `op-core`, importers |
| Evidence | `core/src/import/mod.rs:333` (`serde_json::Value` with all the passwords), `:517` (`data.fill(0)` only wipes the `Vec<u8>` of the `.1pux`, and not on the error path of the `?` at `:513-515`), `:227-250` (`Vec<Vec<String>>` of the CSV); `core/src/import/kdbx.rs:399-400` (`hex: String` and `decode_hex` with the material of the key file); `core/src/totp.rs` (`percent_decode` creates a `String` with the secret) |
| Status | **Fixed** in the uncommitted block (no hash yet), with documented residues. |

**Fix (in the uncommitted block).** The buffers with secrets in the importers become `Zeroizing` or are wiped when leaving scope, **also on the error paths**:
`core/src/import/mod.rs` (copy of the `.1pux`, CSV fields, JSON tree; module header), `kdbx.rs` (composite key, derived keys, `protected_stream_key`, key file and its `hex`, `decode_hex`,
decrypted text) and `totp.rs` (`otpauth://` parameters). The residues that cannot be wiped from Rust are in `docs/threat-model.md` (bullet "Importers"):
reallocations when a `String`/`Vec` grows, internal buffers of `serde_json`, field names of the JSON objects, `sha2` stack temporaries and what happens after crossing the FFI.
Verified with the Rust suite (green); there is no test that measures the wiping.

**What happens (before the fix).** `docs/threat-model.md` (A15) says "the bytes read are wiped from memory when they are parsed".
That is true for the input buffer (`Zeroizing` in `op-ffi`, `fill(0)` in Kotlin), but the **parsed**
structure (the JSON tree, the CSV fields, the KeePass strings after
`reveal`, `kdbx.rs:578`) contains the same passwords and is freed without wiping. In the `.1pux` the
`fill(0)` is not even run if the JSON is invalid (`?` at `:513-515`).

**Recommendation.** A `serde_json::Value` cannot be wiped without rewriting it. Document it as a
residue in the threat model, and when it is cheap, wrap the final strings in `Zeroizing`
(`Field` already derives `ZeroizeOnDrop`).

---

## 2. FFI: `op-ffi`

### 2.1 Method

`ffi/src/lib.rs` (903 lines) and `ffi/src/secret.rs` (69) have been read in full and their
14 tests have been run (`cargo test -p op-ffi`, 14 pass).

### 2.2 Clean area and why

There are no new findings in the Rust code of the boundary. Evidence, point by point:

- **No secret in a type without wiping**: `password` and `secret_key` are `SecretString` in
  `create` (`:334-336`), `unlock` (`:349-351`), `open_backup` (`:459-460`), `normalize_secret_key`
  (`:511`); `generate_secret_key` returns `SecretString` (`:505`); `FieldRecord.value`,
  `ItemDetailsRecord.notes` and `PasswordChangeRecord.value` are too (`:145,151,160`); `totp_code(input)`
  as well (`:588`). The `Vec<u8>` with secrets are wrapped in `Zeroizing` on entry: `vault_key`
  (`:366`, and the intermediate `[u8; 32]`, `:367`), the `.opvault` (`:461`), the imported files
  (`:535,548`) and the key file (`:549`). Outside the list, by design: `ItemOverviewRecord`
  (metadata), `header_json` (no user data) and `TotpCode.code` (6 to 8 digits with a short life).
  `Debug` of `SecretString` prints `<redacted>` (`secret.rs:38-42`, test `debug_hides_the_value`).
- **`Mutex` resistant to poisoning**: `guard()` recovers the guard (`:302-304`); `with` wipes the
  key, clears the poisoning and returns `OpError::Internal` (`:309-322`); `lock` and `is_locked`
  use `guard()` (`:437-443`). Tests: `lock_wipes_key_after_poisoned_mutex` (`:705`) and
  `with_after_poison_returns_internal_and_locks` (`:713`).
- **KDF ceiling before any derivation**: `unlock` (`:355`) and `open_backup` (`:463`) call
  `check_mobile_kdf` (`:472-481`) before `UnlockedVault::unlock`/`backup::open`;
  `Vault::create` only accepts `KdfProfile` (`:333-337`), without free parameters; `unlock_with_vault_key`
  does not run a KDF. Tests: `backup_above_the_mobile_ceiling_fails_fast` (`:801`),
  `mobile_ceiling_is_inclusive` (`:828`), `local_header_above_the_mobile_ceiling_is_refused_before_the_kdf`
  (`:867`), `backup_kdf_reports_the_header_cost` (`:844`).
- **Errors do not leak data**: `OpError::from` only forwards static strings (`:59-75`);
  `E::KdfParams` is translated to `InvalidInput`, not to `Internal`.
- **Single `expect`**: `:382` (`serde_json::to_string(v.header())`) serialises a structure of strings and
  numbers, impossible for it to fail.
- **No `unsafe`** (see 1.1).

<a id="id-int-04"></a>
### ID-INT-04 · UniFFI output residues accepted

| Field | Value |
|---|---|
| Severity | **Info** |
| Component | `op-ffi` / UniFFI |
| Evidence | `ffi/src/lib.rs:13-14` and `:385-387`; `ffi/src/secret.rs:8-11`, `:44-47` (`lower: \|secret\| secret.expose().to_owned()`) |
| Status | **Accepted** (ADR-AUD-02 §6) |

The `String` copy that `lower` hands to UniFFI and the output `RustBuffer` are freed without wiping;
`vault_key_bytes` returns a `Vec<u8>` that Kotlin must wipe (`VaultSession.kt:236-243` does it).
There is no wiping hook in UniFFI 0.32. It is recorded so that the auditor sees it as a decision and not
as an oversight. `docs/crypto-spec.md` §10 **still does not** mention `SecretString` (ADR-AUD-02,
migration 4, pending).

---

## 3. Android: session, storage and windows

### 3.1 Method

Full reading of `VaultSession.kt`, `VaultStorage.kt`, `ItemDatabase.kt`, `DeviceKeyStore.kt`,
`BiometricKeyStore.kt`, `AutoBackup.kt`, `OverlayProtection.kt`, `RootSignals.kt`, `MainActivity.kt`,
`OpenPasswordApp.kt` and the manifest; `grep` of all the `catch` blocks and calls to `session.*`.

### 3.2 Clean areas and why

- **Manifest**: no `INTERNET`; `allowBackup="false"`; `dataExtractionRules` excludes the five
  cloud and transfer domains (`xml/data_extraction_rules.xml`); only `MainActivity` exported and
  without reading the intent; the service requires `BIND_AUTOFILL_SERVICE`. `VerifyManifest`
  (`build.gradle.kts:163-180`) enforces it on every `assemble`.
- **Keystore keys**: AES-256-GCM, `setRandomizedEncryptionRequired(true)`,
  `setUnlockedDeviceRequired(true)`; the biometric one requires strong authentication on **every** use
  (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`, API 30+; on API 28-29 the system uses
  the default behaviour of `setUserAuthenticationRequired(true)`, **without verifying** that it is
  per use) and is invalidated when a biometric is enrolled (`BiometricKeyStore.kt:40-56`).
- **Anti-tapjacking** (A7): window and dialog protection in the three activities;
  `AlertDialog(` appears only once in `ui/Components.kt:195`
  (`grep -rn "AlertDialog(" android/app/src/main`).
- **Session after an internal failure**: `withVault` locks the session on `InternalException` or an
  unexpected `Locked` (`VaultSession.kt:434-443`, `:468-469`), with 4 tests (`FfiFailureHandlingTest`).
- **Restart**: the password is required after a restart and every 14 days (`:219-228`).

<a id="id-int-05"></a>
### ID-INT-05 · Unlock does not close the `Vault` if it fails after `Vault.unlock` (known)

| Field | Value |
|---|---|
| Severity | **Medium**. The criterion of the scale (§1: "key in memory after locking with the process alive") points to **High**; exploitation requires reading process memory (A10, out of scope, "Info" according to the same scale). Medium is proposed; **the auditor decides** |
| Component | Android, `VaultSession` |
| Evidence | `VaultSession.kt:107-108` (`unlock`), `:140-141` (`restore`), `:279-280` (`unlockWithBiometric`) |
| Status | **Fixed** in `a3daf4e`. Instrumented test `failedRestoreLeavesNoVaultBehind` run and green on SM-S948B (API 37, 2026-10-30). |

**What happens.** In the three paths, `Vault.unlock`, `openBackup` or `Vault.unlockWithVaultKey` return a
`Vault` with the key in memory, and then `storage.items().map { … decryptOverview(it) }` (or
`contents.items.map {…}`) can throw `OpException.Corrupted` (a damaged row) or `InternalException`
(a *panic*). The local variable is not locked (`lock()`) or closed (`close()`) on any branch:
in `unlock` and `unlockWithBiometric` the `catch` branches only return an `UnlockResult.Failed`; in
`restore` the exception leaves without touching `contents.vault`. The key stays in native memory until
UniFFI's `Cleaner` frees the object after a collection (`op_ffi.kt`, `UniffiCleaner`,
`build/generated/…:725`), a non-deterministic moment. The interface shows «bloqueado».

**Contrast**: `importBackup` does it right (`:193-196`, `finally { source.lock(); source.close() }`)
and `verifyPassword` too (`use { it.lock() }`, `:203`).

**Recommendation.** In the three places: `try { … } catch (t: Throwable) { unlocked.lock(); unlocked.close(); throw t }`
or a `use` block. Unit test with a fake `Vault` whose `decryptOverview` throws.

**Fix (`a3daf4e`).** The three paths (`unlock`, `restore`, `unlockWithBiometric`) wrap the `map { decryptOverview }`
in `VaultSession.discardOnFailure` (`VaultSession.kt`, `companion object`), which on any `Throwable` calls `lock()` and `close()` on the `Vault`
(`Vault.discard()`, best effort) and rethrows the original error. `restore` also uses `discard()` in its `catch`. Tests
(JVM, not run in this review): `FfiFailureHandlingTest`, "a failure after opening the vault releases it and rethrows",
"a failing release does not hide the original error" and "success does not release the vault". There is **no** test that exercises the three paths with a fake `Vault`, only the
helper function.

**Extension (uncommitted).** `VaultSession.create()` also releases the newly created `Vault` if persistence fails (`clearItems`, `saveSecretKey`, `writeHeader`, `recordPasswordUnlock`) with `discardOnFailure(created::discard)` (`VaultSession.kt:94-101`).

<a id="id-int-06"></a>
### ID-INT-06 · A single unreadable item prevents unlocking the vault

| Field | Value |
|---|---|
| Severity | **Low** (availability; requires a damaged row) |
| Component | Android, `VaultSession` |
| Evidence | `VaultSession.kt:108`, `:141`, `:280`: the `map { decryptOverview }` has no per-item tolerance; `:136` (`restore` requires that there is no vault) |
| Status | **Fixed** in the uncommitted block (no hash yet; Kotlin not run). |

**Fix (in the uncommitted block).** Policy chosen: isolate the damaged row and warn. `session/EntryLoading.kt` skips the rows whose summary throws `OpException.Corrupted` and returns their ids in `LoadedEntries.unreadable`;
`SessionState.Unlocked.unreadable` carries it to the interface, which shows a warning above the list (`UnreadableBanner` in `ui/vault/VaultListScreen.kt`, fed from `ui/AppRoot.kt`). Tests: `EntryLoadingTest` (4 `@Test`, not run).
**Pending**: the policy (skipping instead of failing) is a product decision that is not formally approved; the user still cannot repair or delete the unreadable row from the app.

**What happens (before the fix).** A row with a flipped bit (storage failure) makes `decryptOverview`
throw `Corrupted` and **the whole unlock fails** with «Los datos están dañados». The app does not offer to
delete the vault or restore over an existing one (`restore` requires `!storage.hasVault()`,
`VaultSession.kt:136`): the user must delete the app's data from Android Settings and
restore a backup. **Not reproduced.**

**Recommendation.** Decide the policy: isolate the damaged item and warn, or keep the total failure
and document the recovery route.

<a id="id-int-07"></a>
### ID-INT-07 · Four FFI calls without catching `InternalException`

| Field | Value |
|---|---|
| Severity | **Low** (no reachable *panic* is known; the criterion of ADR-AUD-03 is not met) |
| Component | Android, UI |
| Evidence | `ui/vault/ItemDetailScreen.kt:77` (`produceState { value = session.details(entry) }`) and `:217` (`session.delete(entry)`); `ui/vault/ItemEditorScreen.kt:93` (`LaunchedEffect`, `session.details(existing)`); `autofill/AutofillAuthActivity.kt:172-176` (`pick`: `session.details`, `session.save`) |
| Status | **Fixed** in `a3daf4e`. |

**What happens.** ADR-AUD-03 requires that **every** FFI call from a UI coroutine catch
`InternalException` or `Exception`. These four sites have no `try` at all, so a *panic*
reaches the coroutine as an uncaught exception and **closes the app**. `withVault` already locks the
session before rethrowing (`VaultSession.kt:439-442`), so there is no key leak: the effect is
the app closing.

**Why the test does not catch it.** `FfiFailureHandlingTest` (`:37-52`) looks for `catch (e: OpException)`
without a broad catch next to it; a site **without any `catch`** does not show up, and that is the case of these four.

**Recommendation.** Wrap them in a `try/catch` of `InternalException` (and `Exception`), and extend the
test to all calls to `session.*` inside `launch`/`LaunchedEffect`/`produceState`.

**Fix (`a3daf4e`).** The four sites now catch `OpException` and `InternalException` and show a message
(`ItemDetailScreen.kt`: `produceState` and delete; `ItemEditorScreen.kt`: load, which also leaves the form closed so as not to save an empty item on top;
`AutofillAuthActivity.kt`: `pick`). **Limit that remains**: `FfiFailureHandlingTest` still looks only for `catch (e: OpException)` without a broad catch, so a
new site **without any `catch`** would still go undetected; the recommendation to extend the test has not been applied.

<a id="id-int-08"></a>
### ID-INT-08 · `lock()` does not take the `mutex`: race with an operation in progress

| Field | Value |
|---|---|
| Severity | **Low** (narrow race; **not reproduced**) |
| Component | Android, `VaultSession` |
| Evidence | `VaultSession.kt:300-307` (`lock()`: `it.lock(); it.close(); vault = null`, without `mutex`); `:419-420` (`backgroundLock` runs `lock()` on the main thread); `:434-443` (`withVault` holds `mutex` and calls the `Vault` from `Dispatchers.Default`); `build/generated/uniffi/…/op_ffi.kt:1451-1453` (after `close()`, a call throws `IllegalStateException("… object has already been destroyed")`) |
| Status | **Fixed** in the uncommitted block (no hash yet). Instrumented test `locksInTheBackgroundWithoutComingBack` run and green on SM-S948B (API 37, 2026-10-30); `KeyHolderTest` (JVM) has still not been run. |

**Fix (in the uncommitted block).** `session/KeyHolder.kt` keeps the `Vault` in an `AtomicReference`: `lock()` swaps it for `null` and closes it without waiting for the `mutex` (no read/write race on the field), and `KeyHolder.use` turns the `IllegalStateException` of a `Vault` closed in the middle of an operation into `OpException.Locked`, which the callers already handle. Tests: `KeyHolderTest` (7 `@Test`, not run).
`lock()` still does not wait for the operation in progress: it ends with `Locked`, not with the app closing.

**What happens (before the fix).** The auto-lock (30 s in the background, `ACTION_SCREEN_OFF`) calls `lock()` from the
main thread without waiting for an operation that is inside `withVault`. If that operation makes
several FFI calls in a row (`importExternal` iterates over all the items, `:339-347`), the ones after `close()` throw `IllegalStateException`, which **is not** `OpException` or
`InternalException`. `withVault` rethrows it (`:441`) and the callers only catch those two (for
example `ExternalImport.kt:140-145`, `AutoBackup.kt:98-107` inside a `MainScope` without a handler):
the coroutine fails and the app closes. The native key is wiped (`lock()` goes first), there is no leak.

**Recommendation.** Either make `lock()` wait for the `mutex` (with a `tryLock` and defer), or make `withVault`
catch `IllegalStateException` as `OpException.Locked`.

<a id="id-int-09"></a>
### ID-INT-09 · `verifyPassword` does not count or wait for attempts

| Field | Value |
|---|---|
| Severity | **Low** (requires the vault already open and in the attacker's hands) |
| Component | Android, `VaultSession` |
| Evidence | `VaultSession.kt:201-210` (without `remainingWait()` or a counter) versus `:103-117` (`unlock` does have them); use in `SettingsScreen.kt:333` («ver la clave secreta») |
| Status | **Fixed** in the uncommitted block (no hash yet). Instrumented test `wrongPasswordsTriggerTheWait` run and green on SM-S948B (API 37, 2026-10-30); `AttemptLimiterTest` (JVM) has still not been run. |

**Fix (in the uncommitted block).** `session/AttemptLimiter.kt` is a counter shared by `unlock` and `verifyPassword` (`VaultSession.kt:80`): `verifyPassword` checks `remainingWait()` before running Argon2, records failures and successes, and returns `UnlockResult` (`Success`, `WrongPassword`, `MustWait`, `Failed`) instead of a boolean. Tests: `AttemptLimiterTest` (5 `@Test`, not run).

**What happens (before the fix).** The password check in Settings runs full Argon2 every time, with no limit
or wait. Anyone who has the phone with the vault open (A2, not A1) can try passwords without the
exponential wait. Each attempt runs full Argon2 (cost not measured in this review), which slows it down but does not limit it.

**Recommendation.** Reuse the failure counter of `unlock`; or document that A2 with the vault
open already sees everything.

<a id="id-int-10"></a>
### ID-INT-10 · `atomicWrite` does not force the flush to disk

| Field | Value |
|---|---|
| Severity | **Info** (not reproduced; the header is only written when creating or restoring) |
| Component | Android, `VaultStorage` |
| Evidence | `VaultStorage.kt:72-76`: `tmp.writeBytes(bytes)` and `renameTo` without `FileDescriptor.sync()`; uses: `:39` (header), `:41` (secret key), `:57` (biometric key) |
| Status | **Fixed** in the uncommitted block (no hash yet; Kotlin not run), with a documented residue. |

**Fix (in the uncommitted block).** `data/AtomicWrite.kt` calls `fd.sync()` on the temporary file **before** the `rename`. Tests: `AtomicWriteTest` (3 `@Test`, not run).
**Residue**: the `rename` itself is not flushed (Java cannot `fsync` a directory), so a power cut right after it may lose the rename, but it no longer leaves an empty header; it is documented in the file's comment.

**What happens (before the fix).** After a power cut right after creating the vault, the `rename` may persist
before the data and leave an empty header. The header does not change afterwards, so the risk is
limited to a newly created or restored vault.

<a id="id-int-11"></a>
### ID-INT-11 · `AutoBackup` swallows `CancellationException`

| Field | Value |
|---|---|
| Severity | **Info** |
| Component | Android, `AutoBackup` |
| Evidence | `AutoBackup.kt:108-121` (`catch (_: Exception)` around `withContext(Dispatchers.IO)`); `:62-67` (`disable()` clears the error and cancels the job) |
| Status | **Fixed** in the uncommitted block (no hash yet; Kotlin not run). |

**Fix (in the uncommitted block).** `AutoBackup` catches `CancellationException` before `catch (_: Exception)` and rethrows it (`AutoBackup.kt:120`), so cancelling the job no longer saves an error in `KEY_ERROR`. There is no specific test.

**What happens (before the fix).** Cancelling the job (`schedule`, `disable`, `backupNow`) during the write throws
`CancellationException`, which `catch (_: Exception)` turns into «No se pudo escribir…» and saves in
`KEY_ERROR` (`fail`, `:148-152`) even after `disable()`. It only affects the message in the interface.

<a id="id-int-12"></a>
### ID-INT-12 · `readBackupFile` leaves a plaintext copy without wiping it

| Field | Value |
|---|---|
| Severity | **Low** (residue; partly contradicts A15) |
| Component | Android, UI |
| Evidence | `ui/Components.kt:159` (`ByteArrayOutputStream`), `:167` (`out.toByteArray()` copy); `ExternalImport.kt:54-56,61-63` only wipe the returned `ByteArray` |
| Status | **Fixed** in the uncommitted block (no hash yet; Kotlin not run). |

**Fix (in the uncommitted block).** `ui/WipingRead.kt` (`readWiping`) reads into a single `ByteArray` with a cap, and wipes every intermediate buffer that is replaced or no longer used, also if the read fails or the limit is exceeded; the caller wipes the result. Tests: `WipingReadTest` (5 `@Test`, not run).
**Residue**: what the system, the content provider and the kernel keep while serving the file, and the `String`s that the parsers then build.

**What happens (before the fix).** For plaintext exports (CSV, JSON, `.1pux`) the `ByteArrayOutputStream` keeps its
own internal buffer (up to 2× the size because of the growth) and `toByteArray()` another copy. Only the
last one is wiped. The text with all the passwords stays on the heap until the next GC.

**Recommendation.** Read directly into a `ByteArray` of the known size (`available`/`length`) and
wipe it; or accept it and document it in A15.

<a id="id-int-13"></a>
### ID-INT-13 · A7: the implementation and its tests do not reach what the ADR describes

| Field | Value |
|---|---|
| Severity | **Info** |
| Component | Android, `OverlayProtection` |
| Evidence | `androidTest/.../OverlayProtectionTest.kt` (only `MainActivity`; the comment itself says «Pending: AutofillAuthActivity / SaveLoginActivity … and the dialogs»); `ui/AppRoot.kt:47` (`OverlayWarningBanner` only in `MainActivity`); `security/OverlayProtection.kt:39,57-62` (a `Toast` and only the first time per process) |
| Status | **Fixed and verified on device** (2026-10-30; see the limits below) |

**Update (in the uncommitted block).** `OverlayProtectionTest` (instrumented) now has 4 `@Test`: `mainActivityWindowIsProtected`, `autofillAuthActivityWindowIsProtected`, `saveLoginActivityWindowIsProtected` and `protectedAlertDialogWindowIsProtected`, that is, the three activities and a dialog.

**Verification on device (2026-10-30, SM-S948B, Android 17 / API 37, commit `183598d` with an uncommitted `fuzz/deny.toml`).** `./gradlew :app:connectedDebugAndroidTest`: 17 tests, 0 failures; the 4 of `OverlayProtectionTest` pass. In addition, [DT-01](device-tests.md#dt-01)) `passes`: with OpenPassword in the foreground the overlay of `test.overlay` is hidden (`shown=false`; SurfaceFlinger "hidden") and it reappears in the launcher. **Limits**: DT-01 only tested `MainActivity` and one tap, not the partial overlay; DT-02 (API 28-30, warning about a covered tap, partial tap) and DT-03 (dialogs in the real system) **have still not been run** and the warning could not be observed on API 37. The rest of the finding is still not done: the banner is only in `MainActivity` (`ui/AppRoot.kt:47`) and the two autofill activities only show a `Toast` the first time per process (`OverlayProtection.kt:60`).

The defense is in the three activities and in the dialogs (code), but ADR-AUD-06 asked for a banner
in the two autofill activities and an instrumented test for each activity and dialog. Today
there are (see above) four instrumented tests and a single `Toast` in the autofill activities. The 6 unit tests of `obscuredTouch` do
exist.

---

## 4. Clipboard

Code: `security/SensitiveClipboard.kt` (45 lines), used from the UI and cleared from
`OpenPasswordApp.kt:79` (screen off).

<a id="id-int-14"></a>
### ID-INT-14 · The 30 s wipe does not act if the app lost focus

| Field | Value |
|---|---|
| Severity | **Medium** (the scale would say **High**: "a defense described in the threat model … is bypassed"; Medium is kept: the project's proposal before confirming it, which the auditor decides) |
| Component | Android, clipboard |
| Evidence | `SensitiveClipboard.kt:34-39`: `if (clipboard.primaryClipDescription?.label == LABEL) clipboard.clearPrimaryClip()`, with the comment «Android 10+ may deny clipboard access in the background: then the description is null»; `OpenPasswordApp.kt:78-79`; **DT-04 on device** (see below) |
| Status | **Accepted as residual risk** (decision of the project owner, 2026-10-30). The failure is **confirmed on device** (SM-S948B, Android 17 / API 37): the wipe does **not** happen with the app in the background; it was not fixed. It was observed with the build installed from the working tree (commit and fingerprint not recorded). Not tested on API 29, 33 and 36. |

**Confirmation on device (2026-10-30, [DT-04](device-tests.md#dt-04)), second part of the session).** The clipboard was read with a reader of our own (in `onWindowFocusChanged`):

| Sequence | Result |
|---|---|
| Copy the password and open the reader after 5 s | `CLIPBOARD_HAS_TEXT` (positive control: copying works and the reader reads correctly) |
| Copy and wait 35 s with the app in the foreground | `CLIPBOARD_EMPTY` (control: the wipe **does** work with the app focused) |
| Copy, press Home, wait 36 s, open the reader | **`CLIPBOARD_HAS_TEXT` after 45 s**: the wipe **does not** happen in the background |

Conclusion (of the session): it is a **platform limitation** on API 37: `clearPrimaryClip()` from the background has no effect, and the current mechanism only clears with the app in the foreground. It was not isolated which of the three unknowns below causes it. **What was not tested**: that it is wiped on returning to OpenPassword (`onForeground`, the design of the mitigation), DT-04c (screen off), DT-04d (sensitive flag) and the API 29, 33 and 36 that this finding asked for. Evidence: session notes, with no archived files.

**Note on the message (uncommitted).** The app promised «Se borrará del portapapeles en 30 s» also in the background. The message now says «Se borrará en 30 s, o al volver a la app si sales.» (`ui/vault/ItemDetailScreen.kt:99,142,184`). This fixes what is promised to the user, **not** the wipe; and «o al volver a la app» is the design of the mitigation, **not verified on device**.

**Decision of the owner (2026-10-30): it is accepted as residual risk.** It is an Android limitation (`clearPrimaryClip()` has no effect in the background) and no route to a fix has been identified. **Current mitigations**: "sensitive" flag (API 33+); wipe after 30 s with the app in the foreground (verified, DT-04a); wipe on returning to the app and on screen off (design of the mitigation, **not verified on device**); and an honest message in the interface. **The copy button is not removed.** Reference: [DT-04](device-tests.md#dt-04)) (04b `fails`). The finding reopens if the auditor or a later test finds a route to a fix.

**Mitigation in code (in the uncommitted block), not verified.** `security/ClipboardClearPolicy.kt` is the pure decision (what to do depending on the deadline, the label and whether the clipboard can be read) and `SensitiveClipboard` applies it with the deadline **persisted** in `SharedPreferences` and a `Handler` of the process's main thread that attempts the wipe when it expires;
if the clipboard cannot be read at that moment nothing is touched and the wipe stays **pending** until the app returns to the foreground (`onForeground`, called from `OpenPasswordApp.kt:63,79`) or the screen is turned off (`clearIfOurs`). Tests: `ClipboardClearPolicyTest` (7 `@Test`, not run).
**What is still unknown** (the comment in `SensitiveClipboard.kt` itself says so): (1) whether `primaryClipDescription` is really `null` in the background; (2) whether `clearPrimaryClip()` is denied from the background; (3) whether the `Handler` runs with the process cached. DT-04 confirms the symptom on API 37 without distinguishing them.
As the risk is accepted, a copied password pasted into another app may stay in the clipboard until the user returns to OpenPassword, the screen is turned off or something else is copied; "with wipe" must **not** be claimed in A7 (already fixed in [`threat-model.md`](../../threat-model.md))).

**What happens.** The typical use is copying a password and **switching to the other app** to paste it: at that
moment OpenPassword no longer has focus. Since Android 10 only the app with focus and the default
keyboard read the clipboard; the code itself acknowledges it and, without access, `primaryClipDescription` is
`null`, the comparison fails and **nothing is wiped**. The 30 s timer and the `ACTION_SCREEN_OFF` receiver do the same. Conclusion from the code and the comment; **confirmed on a device on
2026-10-30** (API 37, see above) as to the symptom.

**Recommendation.** Test it also on API 29, 33 and 36. To fix it: also wipe on returning to the foreground,
or without checking the label (`clearPrimaryClip()` unconditionally if something was copied less than
30 s ago), and do not claim "with wipe" in A7. Note: according to DT-04, `clearPrimaryClip()` from the background does not act
on API 37, so the "without checking the label" route alone does not solve it in the background; neither of the two is verified.

<a id="id-int-15"></a>
### ID-INT-15 · No "sensitive" flag on API 28-32

| Field | Value |
|---|---|
| Severity | **Info** |
| Component | Android, clipboard |
| Evidence | `SensitiveClipboard.kt:23-27` (`EXTRA_IS_SENSITIVE` only with `SDK_INT >= TIRAMISU`); `minSdk = 28` (`build.gradle.kts:27`) |
| Status | **Accepted** (platform limitation, with no public alternative) |

---

## 5. Autofill

### 5.1 Method

Reading of `OpAutofillService`, `StructureParser`, `FieldClassifier` (above), `LoginMatcher`,
`PublicSuffix`, `Datasets`, `PendingSaves`, `SavePlanner`, `AutofillAuthActivity` and
`SaveLoginActivity`; `LoginMatcherTest` (29 tests, with the deterministic generators `Random(20260630)` and
`Random(7)`).

### 5.2 Clean area and why: `LoginMatcher` and `PublicSuffix`

- `hostMatches` (`LoginMatcher.kt:43-48`): exact host, or a real subdomain of a domain that is **not**
  public; without a list, exact only (fail closed). IP addresses and literals with `:` never match by
  suffix (`:45,52`).
- `hostOf` uses `java.net.URI`, so `https://google.com@evil.com` gives `evil.com`; a name with `_`
  gives `null` and does not match (`:55-65`).
- A web login is never valid for an app and vice versa (`:24-35`); a bare label such as `localhost`
  is not compared (`:70`).
- The list (`PublicSuffix.kt`) is loaded once, rejects a list with fewer than 100 rules (`:40`) and
  handles wildcard rules, exceptions and punycode forms (`:34-36`, `:44-47`).
- **It does not cover** (see ID-INT-16 and 20): the origin of the `webDomain` and the update of the list.

<a id="id-int-16"></a>
### ID-INT-16 · Any app declares a page's domain: a browser is not required

| Field | Value |
|---|---|
| Severity | **High** (criterion of the scale: "autofill hands credentials to the wrong site or app") |
| Component | Android, autofill |
| Evidence | `autofill/StructureParser.kt:35` (`node.webDomain` of the first node that has one) and `:53` (`webDomain?.let { FillTarget.Web(it) } ?: FillTarget.App(packageName)`); there is no browser list: `grep -rniE "chrome|browser|trusted|allowlist" android/app/src/main/kotlin/io/github/rldona/openpassword/autofill` only returns three comments (`OpAutofillService.kt:22`, `LoginMatcher.kt:6`, `FieldClassifier.kt:14`) and no check; `OpAutofillService.kt:38,41-42` and `Datasets.kt:37-43` deliver the data |
| Status | **Fixed**: the first fix (`a3daf4e`) was bypassable and was closed in the same block of work (see [ID-INT-26](#id-int-26) and the note at the end of this finding); uncommitted. **Verified on device** (DT-07, API 37) that a non-browser app does not receive web datasets; the rest (real Chrome, DT-08, `iframe`) not tested. |

**What happens.** `ViewNode.webDomain` is a value that **the originating app fills in** with
`ViewStructure.setWebDomain`; it is not data that the system verifies. `StructureParser` uses it as
soon as it appears (`:35`) and, if it exists, discards the package (`:53`). A malicious app that the user opens
can declare `webDomain = "banco.example"` on its login screen; `LoginMatcher` will offer the
logins of `banco.example` and, with the vault open, will deliver them in direct `Dataset`s
(`OpAutofillService.kt:36-44`) when the user taps the suggestion. Defense A12 ("exact package name,
verified by Android") does not apply because the web branch is chosen.

**Conditions**: the user must install and open the app and tap the suggestion (it appears with the title
of the legitimate login). Android's guide for autofill services asks to trust the domain
only from known browsers (allowlist of applications or *Digital Asset Links*). **Not
reproduced**: without a device or a test app. Related hypothesis, also untested: in a
browser, the `webDomain` of a node inside an `iframe` may differ from that of the first node, and the
fields of that `iframe` would be filled with the domain of another origin.

**Recommendation.** Accept `webDomain` only if `structure.activityComponent.packageName` belongs to
a list of supported browsers (as other password managers do), and in any other
case use `FillTarget.App`; contrast the `webDomain` per node with that of the fields that are filled; invariant
test in `LoginMatcherTest` (a non-browser app with a `webDomain` never matches a
web login).

**Fix (`a3daf4e`).** `StructureParser.targetFor` only returns `FillTarget.Web` if `webDomain != null` **and** `browsers.isBrowser(packageName)`;
otherwise, `FillTarget.App` (`autofill/StructureParser.kt:27-28`). `CachedBrowserCheck` (`autofill/BrowserCheck.kt`) considers a browser to be the package that
handles both `https://` and `http://` links (query with `queryIntentActivities`, `<queries>` in the manifest, without `QUERY_ALL_PACKAGES`), with a 5 min cache.
`LoginMatcher` matches subdomains only with a registrable domain according to `PublicSuffix` and requires an exact match if there is no list or it is an IP.
Tests: `BrowserCheckTest` (8) and the invariant ones of `LoginMatcherTest` (29; e.g. `appsPretendingToBeBrowsersGetNothingFromWebLogins`), not run here.
**Limits of that first fix**: an app that declared itself a browser (handled those links) was still believed; the `iframe` hypothesis (the `webDomain` is taken from the first node that has one, `StructureParser.kt:39`)
**has not been addressed**; not tested on device.

**Second fix (uncommitted).** The browser check **is no longer based only on the `intent-filter`**: declaring a `VIEW`/`BROWSABLE` filter for `http` and `https` requires no permission, so any app met it.
`CachedBrowserCheck.isBrowser` (`autofill/BrowserCheck.kt:68-73`) accepts a package if it is in `KnownBrowsers.PACKAGES` (`:26-39`) **or** if it is the default browser (`resolveActivity` of `ACTION_VIEW` `https` with `MATCH_DEFAULT_ONLY`, `:83-87`; `android`, the system chooser, is discarded) **and** it handles `https` and `http` (`:61-65`).
`LoginMatcher` also validates the host as an ASCII name (`[a-z0-9.-]+`, without scheme, port, path or Unicode; `LoginMatcher.kt:67-76`) and `PublicSuffix` catches `IOException` when reading the list and fails closed (exact host match; `PublicSuffix.kt:21-25`).
Tests (JVM, not run here): `BrowserCheckTest` (13 `@Test`) and `LoginMatcherTest` (30 `@Test`).
**Residual risks**: a browser that the user chooses as default and that is malicious is believed; the browser list becomes out of date (a new, non-default browser is treated as an app); the `iframe` hypothesis is still not addressed.

**Verification on device (2026-10-30, SM-S948B, Android 17 / API 37, debug build; [DT-07](device-tests.md#dt-07)), [DT-05](device-tests.md#dt-05))).** With Chrome as the default browser, a test app of our own (`test.fakebrowser`) that declares `webDomain = bank.example` through a virtual autofill structure produces «Para: test.fakebrowser»: the `webDomain` **is ignored** and there are no web matches. This verifies on device the core of the fix (a non-browser app does not receive web datasets). **Still unverified on device**: [DT-06](device-tests.md#dt-06)) (`webDomain` of real Chrome and token up to the correct activity), [DT-08](device-tests.md#dt-08)) (malicious default browser; it was only observed in passing that, with the test app as default in DT-05, its `webDomain` was taken into account, consistent with the residual risk) and the `iframe` hypothesis. In DT-07 the «Recordar…» checkbox was not noted and it was not repeated with the vault locked or after 5 min.

<a id="id-int-17"></a>
### ID-INT-17 · `PendingSaves`: lazy expiry and no flush on lock

| Field | Value |
|---|---|
| Severity | **Low** |
| Component | Android, autofill |
| Evidence | `autofill/PendingSaves.kt:20-40` (`expire()` is only called from `put` and `peek`; there is no timer); `SaveLoginActivity.kt:122` (the only call to `remove`, only `if (isFinishing)`); `VaultSession.kt:300-307` (`lock()` does not touch `PendingSaves`); `grep -rn PendingSaves android/app/src/main` confirms it |
| Status | **Fixed** in the uncommitted block (no hash yet; Kotlin not run). |

**Fix (in the uncommitted block).** `PendingSaves` delegates to `PendingStore` (`autofill/PendingSaves.kt`), which expires the entries after 5 min (`TTL_MS`) with a periodic sweep by a `Handler` (every 30 s while entries remain) in addition to the purge in `put`/`peek`, and `session.onLocked = PendingSaves::clear` (`OpenPasswordApp.kt:75`) clears them on lock. Tests: `PendingStoreTest` (6 `@Test`, not run).
**Residue**: the password is still a heap `String` until the GC collects it.

**What happens (before the fix).** The password typed in another app stays in a heap `String` for up to 5 min **only
if** another call to `put`/`peek` runs `expire()`; if none comes, it stays until the
process dies. If `SaveLoginActivity` is destroyed without `isFinishing` (e.g. for lack of memory), the
item is not removed. Locking the vault does not clear it. The Android README says "The password typed
stays in the app's memory"; it does not say for how long.

**Recommendation.** Clear `PendingSaves` in `VaultSession.lock()` and expire with a real timer.

<a id="id-int-18"></a>
### ID-INT-18 · `StructureParser` walks the tree recursively and without a limit

| Field | Value |
|---|---|
| Severity | **Low** (theoretical: **not reproduced**) |
| Component | Android, autofill |
| Evidence | `autofill/StructureParser.kt:15-18` (`find`) and `:34-48` (`visit`): recursion through `getChildAt` without a maximum depth; the call from `onFillRequest` is not protected (`OpAutofillService.kt:30`) |
| Status | **Fixed** in the uncommitted block (no hash yet; Kotlin not run). **No device test**; fuzzing of `StructureParser` is still postponed. |

**Fix (in the uncommitted block).** `autofill/TreeWalker.kt` (`walkTree`) is an **iterative** traversal with `MAX_DEPTH` = 100 and `MAX_NODES` = 20,000; `StructureParser` uses it in its two traversals (`StructureParser.kt:21,43`). When a limit is exceeded it stops visiting, it does not throw. Tests: `TreeWalkerTest` (6 `@Test`, not run).
It is still not checked what depth the system lets through when transmitting the `AssistStructure`.

**What happens (before the fix).** The structure is built by the originating app. A tree with very deep nesting
could exhaust the stack and throw `StackOverflowError` (an `Error`, not an `Exception`) inside the
OpenPassword process, which is the same as the app's. It has not been checked what depth the
system allows when transmitting the `AssistStructure` or whether Android bounds it beforehand.

**Recommendation.** Iterative traversal with a depth cap (e.g. 100) and a node cap. It is the
candidate that would justify fuzzing `StructureParser` if it is refactored into a node abstraction
([`fuzzing.md`](fuzzing.md))).

<a id="id-int-19"></a>
### ID-INT-19 · Up to 5 plaintext logins travel to `system_server` without dataset authentication

| Field | Value |
|---|---|
| Severity | **Info** (design behaviour; it must be documented) |
| Component | Android, autofill |
| Evidence | `OpAutofillService.kt:36-44` (with the vault open: `MAX_DIRECT = 5`, `:89`) and `Datasets.kt:37-43` (`builder.setValue(id, AutofillValue.forText(…))` with user and password); `setAuthentication` is only used with the vault locked (`Datasets.kt:56`) |
| Status | **Accepted** |

With the vault open, each fill response delivers to `system_server` (and from there to the suggestions
service and to the target app when the user chooses) the data of up to 5 matching logins,
not only the chosen one. It is the standard way Android works without dataset authentication, and it is
mitigated because the match is strict and because the vault locks. It is worth the threat model
saying so explicitly. It matters more the weaker the match is (ID-INT-16).

<a id="id-int-20"></a>
### ID-INT-20 · The public suffix list: no test with R8 and no update

| Field | Value |
|---|---|
| Severity | **Info** |
| Component | Android, autofill |
| Evidence | `PublicSuffix.kt:18` (loaded with `classLoader.getResourceAsStream`), `:20` (`isAvailable`); `unzip -l android/app/build/outputs/apk/release/app-release.apk` includes `public_suffix_list.dat` (338,012 B); version `2026-10-28_13-15-55_UTC` (header of the file); `ls android/app/src/androidTest/kotlin/…` (3 classes, none of autofill); **DT-05 on device** (see below) |
| Status | **Open**. Loading and application of the list **verified on device** in the debug build (2026-10-30, API 37); **not verified with R8** and without an update process. |

**Verification on device (2026-10-30, SM-S948B, API 37, debug build, [DT-05](device-tests.md#dt-05)) `passes`).** With the two positive controls: `x.alice.github.io` offers `alice.github.io` and `en.wikipedia.org` offers `wikipedia` (it only happens if the list loaded). The negatives: `evil.github.io` does not offer any login (with «Ningún login tiene guardado evil.github.io») and `alice.github.io` only matches `alice.github.io`, with `github.io` left in «OTROS LOGINS»; `github.io` matches exactly the suffix login. This shows that **the list loaded and was applied**, not that the app fails closed if it did not load (that is only covered by JVM tests, not run). The debug build does **not** go through R8 (`isMinifyEnabled = true` only in `release`), so the part of the finding about R8 **is still unverified** (variant 5.R8 of DT-05, not run). Updating the list **is still pending**: there is no process.

The resource is in the APK, but loading with R8 active (`isMinifyEnabled = true`, `build.gradle.kts:55`) has not been verified on device; if it failed, the
degradation would be to exact host, silently. The list counts as versioned data without an update
process: an old list lets a new public suffix through as a "registrable domain".

<a id="id-int-26"></a>
### ID-INT-26 · An autofilled app can inject the domain into the mutable `PendingIntent` and receive credentials from any site

| Field | Value |
|---|---|
| Severity | **High** (criterion of the scale: "autofill hands credentials to the wrong site or app") |
| Component | Android, autofill |
| Evidence | Before: the activity read the target from the `Intent` extras (`op.autofill.domain`, `op.autofill.package`, `op.autofill.username`, `op.autofill.password`; see `Datasets.LEGACY_EXTRAS`, `Datasets.kt:76`) and the `PendingIntent` is mutable (`Datasets.kt:50-55`, `FLAG_MUTABLE`). Now: `autofill/AutofillRequestTokens.kt:16-54`, `Datasets.kt:47-59,70-76`, `AutofillAuthActivity.kt:87-98` |
| Status | **Fixed** (uncommitted; not tested on device). Detected in the review of the first fix of [ID-INT-16](#id-int-16). |

**What happens.** `Dataset.setAuthentication` hands the `IntentSender` to the **app being filled**. Since the
`PendingIntent` has to be mutable (the system adds the structure to it), that app can fire it with
`Intent.fillIn` and add or replace extras. If the target domain travelled in an extra, a malicious
app could set `op.autofill.domain = "banco.example"`, make the user unlock and
choose a login, and receive on its screen the credentials of **any** domain. That bypassed everything
that ID-INT-16 had closed (the origin of the `webDomain` and the strict match), because the
domain no longer came from `StructureParser`.

**Conditions**: the user must open the malicious app, tap the OpenPassword suggestion and choose a
login (the activity shows the target: «Para: …»). **Not reproduced**: without a device or a test app;
the vector is deduced from the documentation of `PendingIntent` and `Intent.fillIn`.

**Fix (uncommitted).** The `Intent` carries only a token: 16 bytes of `SecureRandom` in hexadecimal
(`AutofillRequestTokens.put`, `:25-30`). The target (`FillTarget`) and the field ids are stored in a
`ConcurrentHashMap` of the process (`:23`), with a 5 min TTL (`TTL_MS`, `:50`) and single use
(`take` removes the entry, `:33-37`). `AutofillAuthActivity` removes the old extras
(`Datasets.LEGACY_EXTRAS.forEach(intent::removeExtra)`) before reading anything, retrieves the request with the
token and **fails closed**: token missing, unknown, used or expired, or without fields, calls
`finish()` without a result (`AutofillAuthActivity.kt:89-98`). The resolved request is kept in a
`ViewModel` for rotation (`RequestHolder`, `:160-162`) and is wiped on finish (`:136-140`).
In the same activity, «recordar el login para esta app» is not offered or applied if the package is a
browser (`canRemember = target is FillTarget.App && !isBrowserApp`, `:102,124`; `PickLogin`, `:195`).
Tests (JVM, not run here): `AutofillRequestTokensTest` (7 `@Test`).

**Residual risks**: the `PendingIntent` is still mutable (the system requires it), so nothing that
arrives in it is treated as data; the store is in process memory, so it is read by whoever already
runs code in OpenPassword (A10, out of scope); not tested on device.

---

## 6. Tooling, CI and build

### 6.1 Method

Reading of `.github/workflows/ci.yml` and `fuzz-nightly.yml`, `deny.toml`, `.github/dependabot.yml`,
`android/app/build.gradle.kts`, `android/gradle/verification-metadata.xml`, `scripts/sign-release.sh`
and `fuzz/`. Run of `cargo audit` (0 vulnerabilities, 139 *crates*) and `cargo deny --locked check`
(`advisories ok, bans ok, licenses ok, sources ok`).

### 6.2 Clean areas and why

- **CI with least privilege**: `permissions: contents: read` at *workflow* level; the `release` job
  adds `id-token: write` and `attestations: write` only to itself (`ci.yml`).
- **Actions pinned by SHA** with the version in the comment, and `cargo-deny`, `cargo-fuzz`,
  `cargo-ndk` and `cargo-cyclonedx` with a version (`ci.yml`; `grep -n "uses:" .github/workflows/*.yml` does not
  show any without a SHA). The detail and the limits are in [`dependencies.md`](dependencies.md)).
- **Gradle**: `verification-metadata.xml` with SHA-256 (no PGP signatures).
- **`rust-toolchain.toml`** pins `1.99.1` and the three Android targets; the APK is built with
  `--locked` (`build.gradle.kts:135`).

<a id="id-int-21"></a>
### ID-INT-21 · The check that `cfg(fuzzing)` does not get into release detects nothing

| Field | Value |
|---|---|
| Severity | **Low** (false security in a documented control) |
| Component | Tooling, fuzzing |
| Evidence | `fuzz/README.md` («cargo build -p op-core --release && ! strings target/release/libop_core.rlib \| grep -E 'seal_backup\|seal_item_part\|TEST_VAULT_KEY'»); negative control: `strings -a target/release/libop_core.rlib \| grep -c "cost above the accepted maximum"` gives **0** even though that string exists in the code, whereas in `libop_ffi.so` it gives **1** |
| Status | **Fixed** in the uncommitted block (no hash yet). The script and its self-test **have not been run in CI**. |

**Fix (in the uncommitted block).** `op_core::fuzzing::HOOKS_MARKER` (`core/src/lib.rs:42`, `#[used]`, only with `--cfg fuzzing`) is the marker that is looked for, because after LTO the final binary does not keep the hook names.
`scripts/check-no-fuzzing-hooks.sh <libop_ffi.so>…` fails if it finds the marker **or** if it does not find the control string (`cost above the accepted maximum`), so an unreadable binary does not pass as clean (negative control);
`--self-test` builds `op-ffi` with `--cfg fuzzing` and checks that the marker appears and that the check **fails** (positive control). CI runs it on `libop_ffi.so` (`ci.yml:30-31`) and on the libraries of the APK (`ci.yml:98`).
The fuzzing commands in `fuzz/README.md` and in [`fuzzing.md`](fuzzing.md)) were also fixed: with `-O` you have to add `-a` (`cargo +nightly fuzz run -O -a …`), because the `compile_error!` guard rejects `--cfg fuzzing` without `debug_assertions`.
In this review the script could not be run (there was no compiled `libop_ffi.so` in `target/release`; it returned "no such file").

**What happens (before the fix).** With `lto = true` the `.rlib` contains LLVM *bitcode* and `strings` does not even read it
properly (`warning: … Not an int attribute`); the command always "passes". The real check, and the one that does
work, is on the final binary: `strings -a …/libop_ffi.so | grep -cE
'seal_backup|seal_item_part|TEST_VAULT_KEY'` gives **0** (arm64, built at 10:14 on 30/10) and the control
string gives 1.

**Recommendation.** Replace it in the README and in a CI step with the check on
`libop_ffi.so`, **with** the positive control.

**Partial mitigation (uncommitted).** `core/src/lib.rs:20-22` adds `#[cfg(all(fuzzing, not(debug_assertions)))] compile_error!(…)`: a `release` build with `--cfg fuzzing` fails instead of including the hooks (`cargo fuzz build` keeps `debug_assertions`). This does not replace the check on the `.so`; that check is now `scripts/check-no-fuzzing-hooks.sh` (see "Fix" above), and the finding is **fixed**.

<a id="id-int-22"></a>
### ID-INT-22 · `cargoBuild` does not declare `rust-toolchain.toml` or `.cargo/config.toml` as inputs

| Field | Value |
|---|---|
| Severity | **Info** |
| Component | Build |
| Evidence | `android/app/build.gradle.kts:183-187` (`include("Cargo.toml", "Cargo.lock", "core/Cargo.toml", "core/src/**", "ffi/Cargo.toml", "ffi/uniffi.toml", "ffi/src/**")`) |
| Status | **Open** |

A change of toolchain or of `rustflags` does not invalidate the task and Gradle may reuse an old
`.so` locally. It does not affect CI (clean run). Relevant for whoever reproduces the build.

<a id="id-int-23"></a>
### ID-INT-23 · Generated files and *lockfiles* outside coverage

| Field | Value |
|---|---|
| Severity | **Info** |
| Component | Tooling |
| Evidence | `git status --short` shows `core/op-core.cdx.json` (78,084 B) and `cli/opvault-cli.cdx.json` (95,577 B) untracked and not ignored (`git check-ignore` returns nothing); `fuzz/Cargo.lock` (132 packages) has its own workspace and `cargo deny` does not walk it (it runs at the root) |
| Status | **Partial**: `*.cdx.json` is in `.gitignore` (`a3daf4e`) and the two files no longer exist; `fuzz/deny.toml` and the CI step for `fuzz/Cargo.lock` are done in the uncommitted block; the NCSA licence was **approved by the owner on 2026-10-30** |

**Fix (in the uncommitted block).** `fuzz/deny.toml` applies the same rules as the root `deny.toml` plus **one** exception: `libfuzzer-sys` is "(MIT OR Apache-2.0) AND NCSA", a permissive licence from the University of Illinois for the LLVM code it includes; it is only in the development harness and does not get into any distributed binary.
The `audit` job runs `cargo deny --manifest-path fuzz/Cargo.toml --locked --config fuzz/deny.toml check` (`ci.yml:44-45`). Run in this review: `advisories ok, bans ok, licenses ok, sources ok`.
The NCSA licence (ADR-AUD-04) was **approved by the owner on 2026-10-30**; the finding is still "partial" (see the status).

Risk of accidentally committing two SBOMs that are not published, and of the *fuzzing* environment having no
advisory review. The second one is development and does not get into the binary.

<a id="id-int-24"></a>
### ID-INT-24 · `fuzz/README.md` is out of date with respect to CI and the limits

| Field | Value |
|---|---|
| Severity | **Info** |
| Component | Documentation |
| Evidence | `fuzz/README.md`: "CI runs each target for 60 s on every push" versus `ci.yml` (`-max_total_time=30`); "Argon2 ≤ 1 GiB and 1000 passes in KDBX" versus `kdbx.rs:36-42` (`memory × passes ≤ 3 GiB·pass` and 512 MiB) |
| Status | **Fixed** (documentation). |

It has not been modified (out of the scope of this task).

**Fix.** `fuzz/README.md` now says 30 s per target in CI (`ci.yml`, `-max_total_time=30`), 11 targets and the joint KDBX budget instead of "1 GiB and 1000 passes" (figures later updated to 512 MiB and 3 GiB·pass).

<a id="id-int-25"></a>
### ID-INT-25 · The `import` target does not reach the KDBX header parser

| Field | Value |
|---|---|
| Severity | **Low** (coverage gap and documentation that claims more than it does) |
| Component | Fuzzing, KDBX importer |
| Evidence | `fuzz/fuzz_targets/import.rs:6-9` (`needs_password` and `parse(data, now)` without credentials); `core/src/import/mod.rs:62-75` (a `.kdbx` without a password or key file returns «this KeePass database needs its password» **before** calling `kdbx::parse`); `fuzz/README.md` ("… and the KDBX header") |
| Status | **Fixed** in `a3daf4e`. |

**What happens.** The README and the target's comment say that `import` walks "the KDBX
header". That is not true: without credentials, `parse_with_credentials` rejects the file at the door
(`mod.rs:70-75`) and never runs `kdbx::parse`, where the `Cursor`, the header fields and
`variant_dictionary` are (`kdbx.rs:75-215`). Checked with the two KeePass *seeds* of the target
itself (`fuzz/seeds/import/keepassxc-3.1.kdbx` and `keepassxc-keyfile.kdbx`) and a test program
outside the repository: `needs_password` gives `true` and `parse` gives "this KeePass database needs its
password" in both. Result: **no target exercises** the external header parser,
`variant_dictionary`, the HMAC block stream (KDBX 4), the hash block stream (KDBX 3.1),
the gunzip or the internal header of KDBX 4 (`kdbx.rs:343-362`); `kdbx_xml` starts after all of that.

**Recommendation.** A `cfg(fuzzing)` hook that calls `kdbx::parse` with a fixed password and a
minimal KDF (or that skips the derivation with a fixed composite key), just as
`seal_item_part` does with the AEAD. In the meantime, fix the README. See [`fuzzing.md`](fuzzing.md)).

**Fix (`a3daf4e`).** The `import` target now also calls `kdbx_fuzzing::file` (`fuzz/fuzz_targets/import.rs`), which runs `read_header` and `open_payload`
with a fixed transformed key, without the KDF. There is also a new target, `kdbx_container`, which seals a KDBX 3.1/4 with that key and reaches the HMAC or hash blocks, the external encryption, the gunzip,
the internal header and the XML; seeds in `fuzz/seeds/kdbx_container/` (5). The hooks are `kdbx_fuzzing::{file, container}` (`kdbx.rs`, `fuzzing` module). `cargo fuzz` has **not been run** in this review
(see [`fuzzing.md`](fuzzing.md))).

---

## 7. What has not been reviewed

- The **cryptography** (derivation, lengths, vectors): only what the tests exercise.
- The **dependencies** internally (`argon2`, `chacha20poly1305`, `quick-xml`, `zip`, `uniffi`):
  inventory and advisories in [`dependencies.md`](dependencies.md)), without reviewing their code.
- The **Compose interface** in general (states, navigation); only the calls to `session.*`.
- `FieldClassifier` and `SavePlanner`: read over, with tests.
- The **whole release process** (F-Droid, signing) beyond what is cited.
- Any **device test** except the ones run on 2026-10-30 (ID-INT-14 is confirmed as a failure on API 37 and accepted as residual risk; ID-INT-16 and 20 only in part; ID-INT-18 and 26 still need one).
