# Technical decisions prior to the external audit

Status: **implemented**, except ADR-AUD-01 (`release/0.2` branch and signed tag: they do not exist). The
commits `700f1a7`, `a3daf4e` and `3868f4f` implement ADR-AUD-02 to 07; the step-by-step status is in
[`hardening.md`](hardening.md)). The text of each ADR describes the decision as it was written, on top of
`9eb9c7f`, and has **not** been rewritten: where the code ended up different (for example, the KDBX
budget, which ended at 512 MiB and 3 GiB·pass instead of 16 GiB·pass), the code prevails.

Base inspected when the decisions were written: `main` at `9eb9c7f` («CI: fuzz with the runner's gnu target»).
Current status: `main` at `3868f4f`. Workspace version `0.1.0`
(`Cargo.toml`, `android/app/build.gradle.kts:28-29`); `0.2.0` is the next step, at freeze time.

Audit scope: `op-core`, `op-ffi`, the Android app and the `.opvault` v1 format. The `opvault` CLI
(`cli/`) **is out of scope**. The decisions that touch the shared Cargo profile mention it only for its
impact.

## Summary

| ID | Decision | Recommendation | Cost | Reversible |
|---|---|---|---|---|
| ADR-AUD-01 | Freezing `v0.2.0` | `release/0.2` branch, signed tag, changes only for fixes; first in `main` and then *cherry-pick* (except embargo) | Low | Yes |
| ADR-AUD-02 | Secrets across UniFFI | Its own `SecretString` type (in Kotlin it is still `String`) that is wiped when freed in Rust; bytes with explicit ownership; document the JVM and `RustBuffer` residue | Medium | Yes |
| ADR-AUD-03 | Panics in FFI | `panic = "unwind"` in `[profile.release]`; UniFFI already turns the panic into `InternalException`; fix the `Mutex` poisoning; every FFI call from a UI coroutine catches `InternalException` and the session moves to `Locked` on an internal failure | Low-medium | Yes |
| ADR-AUD-04 | Supply chain | `cargo-deny` (replaces `cargo-audit`), `verification-metadata.xml` with SHA-256, Actions pinned by SHA + Dependabot, CycloneDX SBOM and provenance attestation only in the release. No `cargo-vet` | Medium | Yes |
| ADR-AUD-05 | Fuzzing | `cargo-fuzz` only: 5 new targets with `cfg(fuzzing)` hooks and a nightly run with a cached corpus. Neither Jazzer nor ClusterFuzzLite nor OSS-Fuzz for now | Medium | Yes |
| ADR-AUD-06 | A7 and A10 defenses | A7: `filterTouchesWhenObscured` on the window + `setHideOverlayWindows` (API 31+) in the 3 activities **and in their dialogs**, plus a warning. A10: local heuristics behind an injectable interface; it **only warns** | Medium | Yes |
| ADR-AUD-07 | KDF and DoS | v1 **does** bound them (2 GiB / 16 / 16), but that ceiling leaves a DoS on mobile. It is kept in the format and a platform ceiling (512 MiB / 6 / 8) is added in `op-ffi` before any KDF, with a new error and a RAM check in Kotlin. The abort due to lack of memory is reduced, not eliminated | Low-medium | Yes |

---

## ADR-AUD-01 · Freeze strategy

### Context

- At `9eb9c7f`, CI (`.github/workflows/ci.yml`) only runs on `push` to `main` and on
  `pull_request`, but `docs/fdroid/README.md` asks to look for the run of the tag
  (`gh run list --branch v0.1.0`). The `tags: ['v*']` trigger is added in the commit that closes
  `v0.1.0`; before it, it did not exist. `release/**` is still missing.
- The unsigned APK that is published is the one from CI (Linux), it is reproducible and its artifact
  **expires after 14 days** (`retention-days: 14`). An audit lasts longer than that.
- `SECURITY.md` only supports «the latest published version and `main`».

### Options

1. Audit a tag of `main` with no branch.
2. `release/0.2` branch with fixes only in that branch.
3. `release/0.2` branch: fixes first in `main` and then *cherry-pick*, with an exception
   for vulnerabilities under embargo.

### Decision

Option 3.

- **Branch** `release/0.2`, created from the `main` commit that closes hardening (all the
  ADRs in this document implemented and green).
- **Tag** `v0.2.0` annotated and **signed** (`git tag -s`) on the tip of `release/0.2`. What is
  audited is the 40-character SHA, not the tag name.
- **Package for the auditor**, attached to a GitHub *pre-release* `v0.2.0` (not to a CI
  artifact, which expires):
  - the commit SHA and the signed tag;
  - `git archive --format=tar.gz v0.2.0` with its SHA-256;
  - the unsigned APK that CI builds for that tag, its SHA-256 and the link to the run;
  - the SBOMs and the provenance attestation (ADR-AUD-04);
  - the instructions to reproduce the build: `rust-toolchain.toml` (1.99.1), NDK
    `30.0.16248370`, Gradle 9.8.2 with `distributionSha256Sum`, and `docs/fdroid/README.md`;
  - optional: `cargo vendor` of the workspace, so the auditor can review the exact code of
    the dependencies offline.
- **Policy in `release/0.2` during the audit**:

  | Allowed | Not allowed |
  |---|---|
  | Fixes for auditor findings | New features |
  | Fixes for advisories received through `SECURITY.md` | Refactors |
  | Bumping a dependency **only** because of a RUSTSEC or GHSA advisory affecting it | Bumping dependencies routinely, Dependabot included |
  | CI changes that do not change the APK bytes (pinning SHAs, triggers) | Changing the *toolchain*, the NDK, AGP or Gradle |

  Each change ships as `v0.2.N` (signed tag) and is delivered to the auditor as `git diff v0.2.(N-1)..v0.2.N`.
- **Fix flow**: PR to `main`, review and merge; then `git cherry-pick -x` into
  `release/0.2`. The `-x` leaves traceability in the message.
  - Embargo exception: an unpublished vulnerability is fixed in the **temporary private
    fork** of the GitHub Security Advisory. It is merged into `main` and into `release/0.2` the same day
    `v0.2.N` is published.
  - Divergence exception: if `main` has already changed the affected file, it is fixed in
    `release/0.2` and then carried to `main` (*forward-port*), noting it in the PR.
- In `main` there is a **soft freeze** of `core/src/crypto`, `core/src/vault`, `core/src/backup`
  and `ffi/src` until the audit finishes: changes are accepted, but each PR must justify why
  it cannot wait. That keeps the *cherry-picks* trivial.

### Rationale

Fixing first in `main` prevents the branches from diverging and fixes from being lost, which is the typical
failure of projects maintained by a single person. The branch gives the auditor a stable base and
small, reviewable diffs. Signing the tag and attaching the artifacts to the release avoids
depending on the 14-day retention.

### Consequences and cost

- Two live branches during the audit, plus extra *cherry-pick* work.
- `SECURITY.md` must add «`release/0.2` until the audit closes» to the supported versions.
- A GPG or SSH tag-signing key is needed.

### Migration

1. Bump the version to `0.2.0` in `Cargo.toml` (`[workspace.package]`) and in
   `android/app/build.gradle.kts` (`versionCode = 2`, `versionName = "0.2.0"`), with the *changelog* in
   `fastlane/metadata/android/*/changelogs/2.txt`.
2. In `ci.yml`, keep `push.tags: ['v*']` (added in the commit that closes `v0.1.0`) and add
   `push.branches: [main, 'release/**']`.
3. Extend `retention-days` or, better, attach the APK to the release (step of ADR-AUD-04).
4. Create the branch and the signed tag, set up the *pre-release* and update `SECURITY.md`.

---

## ADR-AUD-02 · Secrets crossing UniFFI

### Context

Current state (`ffi/src/lib.rs`):

| Data | FFI type | Direction | Wiped today |
|---|---|---|---|
| Master password | `String` (`Vault::create`, `Vault::unlock`, `open_backup`, `parse_import`) | Kotlin→Rust | No: the Rust `String` is freed without wiping. Only the NFKD copy is wiped (`core/src/crypto/kdf.rs`, `Zeroizing`) |
| Secret key (SK) | `String` in both directions (`generate_secret_key`, `normalize_secret_key`) | ↔ | Not in FFI. `SecretKey` is wiped in the core |
| Vault key | `Vec<u8>` (`vault_key_bytes`, `unlock_with_vault_key`) | ↔ | Kotlin does `fill(0)` (`VaultSession.kt:220-224`, `262-269`). In Rust, the intermediate `[u8; 32]` from `try_into` is not wiped |
| Field values, notes, history | `FieldRecord.value`, `ItemDetailsRecord.notes` and `PasswordChangeRecord.value`, all `String` | ↔ | In the core, `Field` and the details derive `ZeroizeOnDrop` (`core/src/vault/item.rs`). Their `String` copies in the `Record`s are not wiped |
| TOTP seed | `totp_code(input: String)` | Kotlin→Rust | No |
| KeePass key file | `Option<Vec<u8>>` | Kotlin→Rust | Kotlin does `fill(0)` (`ExternalImport.kt:188, 198`). Rust does not wipe it |
| Imported or backup files | `Vec<u8>` | Kotlin→Rust | Kotlin does `fill(0)` on import (`ExternalImport.kt:54, 61`) |

Limits that cannot be avoided:

- Compose and the JVM work with immutable `String`, and Compose `TextField`s already create `String`.
- UniFFI copies the output data to a `RustBuffer`, which it later frees without wiping.

### Options

- **A. Document only.** It costs nothing and improves nothing.
- **B. Move the secrets to `ByteArray` in the API** (`Vec<u8>`). Kotlin could wipe its copy, but the
  password is already a Compose `String` before reaching that point. It breaks a lot of interface and gains little.
- **C. A UniFFI type of its own, `SecretString`** (in Rust, `Zeroizing<String>` with a hidden `Debug`; in
  Kotlin, `String`). Rust wipes all its input copies without depending on each function, and the Kotlin
  API does not change.
- **D. Opaque session**: the plaintext does not leave Rust and Kotlin asks for a specific field to
  show or copy it. It is the best reduction, but it forces a redesign of the UI and autofill.

### Decision

**C**, plus an explicit ownership contract. **D** is left for after the audit, for
example with the arrival of iOS.

Contract (it goes as a module comment in `ffi/src/lib.rs` and in `docs/crypto-spec.md` §10):

1. **Type.** In `ffi/src/lib.rs` (or in a new `ffi/src/secret.rs`) the following is defined:
   `pub struct SecretString(Zeroizing<String>)`, registered with `uniffi::custom_type!(SecretString, String, { lower, try_lift })`,
   with a `Debug` that prints `<redacted>`, plus `From<String>`, `From<&str>` and `fn expose(&self) -> &str`.
2. **Where it is used**: `password` in `Vault::create`, `Vault::unlock` and `open_backup`; `password` in
   `parse_import` (`Option<SecretString>`); `secret_key` in all functions, input and output;
   `FieldRecord.value`, `ItemDetailsRecord.notes`, `PasswordChangeRecord.value`, and the input of
   `totp_code`. It is **not** used in `ItemOverviewRecord`: title, URLs and tags are metadata that
   the list always keeps in memory. The threat model already classifies them separately (sensitivity
   «High», not «Critical»).
3. **Bytes.** `vault_key`, `key_file` and the files are still `Vec<u8>`. In Rust, the received `Vec`
   is wrapped in `Zeroizing` as soon as it comes in; in `unlock_with_vault_key`, the 32-byte
   array is created inside a `Zeroizing<[u8; 32]>`.
4. **Ownership.** Whoever creates the buffer wipes it.
   - A `ByteArray` that Kotlin passes to Rust still belongs to Kotlin, and Kotlin wipes it with `fill(0)` in
     a `finally`.
   - What Rust receives is its own and it wipes it on drop (`SecretString` or `Zeroizing`).
   - A `ByteArray` that Rust returns (`vault_key_bytes`) becomes Kotlin's, which must wipe it.
5. **Lifetime.** The life of plaintext secrets in Kotlin is limited to the unlocked session:
   - when moving to `SessionState.Locked`, `VaultSession` drops the references to the
     decrypted `ItemDetailsRecord`s;
   - the SK is only read from `VaultStorage` at the moment it is used.

   It is a *best effort* goal that is reviewed, not a guarantee.
6. **Accepted residue**, documented in `docs/threat-model.md` («Residual risks»):
   - the JVM and Compose `String`s;
   - the output `RustBuffer`, which UniFFI frees without wiping;
   - on output, the Rust `String` copy that is handed to UniFFI.

   What comes in **is** wiped: in the Kotlin→Rust direction, UniFFI builds the `String` from the
   buffer itself, without copying it, and `SecretString` wipes it.

### Rationale

C closes the only thing we truly control, the Rust-side copies. It does so structurally,
because a new function cannot forget the wipe if the type does it for it, and without touching the Kotlin
API. B has a lot of cost for very little gain, because Compose already produces `String`. D is
correct but does not fit in a frozen version.

### Consequences and cost

- The Kotlin interface does not change: the generated bindings still expose `String`.
- The Rust tests in `ffi/src/lib.rs` must be changed. Constructions such as `value: "2958".into()`
  still compile, but assertions such as `assert_eq!(…value, "2958")` must use `.expose()` or
  `PartialEq<&str>`.
- New tests: `Debug` hides the value; an explicit `zeroize()` leaves the text empty (without `unsafe`, the
  content is checked after `Zeroize::zeroize`).
- **Technical risk** (to verify in the first step): that `uniffi::custom_type!` from 0.32 works
  inside a `Record` with `#[uniffi(default = …)]` and in `Option<…>`. If it does not work, the alternative
  is `Zeroizing::new(arg)` as the first line of each exported function, plus a review check
  (`grep`) in CI.

### Migration

1. Isolated test (*spike*): `SecretString` with `custom_type!`; regenerate bindings and check that
   the generated `op_ffi.kt` (in `build/`, not versioned) does not change types.
2. Replace the types in `ffi/src/lib.rs` and adjust the tests.
3. In Kotlin, review the wiping of `vaultKeyBytes()` and `keyFile`, and that the details are released on lock.
4. Update `docs/crypto-spec.md` §10 and `docs/threat-model.md` (residual risks).

---

## ADR-AUD-03 · Panics at the FFI boundary

### Context

- `[profile.release] panic = "abort"` in `Cargo.toml`, and the app always builds `op-ffi` in release
  (`CargoNdkBuild`, `android/app/build.gradle.kts`).
- The bindings UniFFI generates (they are generated in `build/` and are not versioned) already expect panics:
  the Kotlin code translates the panic state into `InternalException`, which extends `kotlin.Exception`.
  With `abort`, that path never runs: a panic kills the process, autofill included
  (`OpAutofillService` lives in the same process).
- Surface with untrusted data and `expect`/indexing in production code:
  `core/src/backup/mod.rs:92`, `core/src/vault/padding.rs:26`, `core/src/crypto/stream.rs:52`
  (these three are protected by prior length checks), and the importers
  (`core/src/import/*`).
- **There are no panic tests** (`#[should_panic]` or `catch_unwind`: zero occurrences in `core`, `ffi` and `cli`).
- An **out of memory** (`handle_alloc_error`) aborts **whatever** the panic strategy is.
  Switching to `unwind` does not protect against the KDF (see ADR-AUD-07).
- `Vault::lock` does `if let Ok(mut guard) = self.inner.lock()` (`ffi/src/lib.rs:380-384`). With
  `unwind`, a panic inside `Vault::with` **poisons** the `Mutex`, and then **`lock()` does not wipe the
  key**. Today that does not happen because `abort` lets nobody survive.

### Options

1. Keep `abort`: a malicious file that triggers a panic leaves the app out of service (DoS).
2. `panic = "unwind"` in `[profile.release]`, without our own `catch_unwind`: UniFFI's is enough.
3. Mixed: a `release-ffi` profile with `inherits = "release"` and `panic = "unwind"` only for the app.

### Decision

Option 2.

- Set `panic = "unwind"` in `[profile.release]`. The CLI inherits the change, but it is out of scope
  and unwinding the stack in a CLI is harmless.
- No hand-written `catch_unwind`: UniFFI already wraps each call in its `rust_call`.
- `Vault::lock` and `Vault::is_locked` recover the poisoned guard with
  `unwrap_or_else(PoisonError::into_inner)`. Locking **always** wipes the key.
- `Vault::with` also handles poisoning: it returns `OpError::Internal` and **wipes** the key
  (empties the `Option`), so as not to keep using a half-broken state.
- **Verifiable criterion in Kotlin**: every FFI call from a UI coroutine (or from a service)
  must catch `InternalException`, or `Exception`/`Throwable` deliberately. No ad hoc list of
  «flows with untrusted data» is kept: any call can suffer a panic, and a bare
  `catch (e: OpException)` lets `InternalException` through as an uncaught exception in the
  coroutine, which closes the app. It is checked with a `grep` of `catch (e: OpException)` in
  `android/app/src/main`: each result must have next to it a `catch` of `InternalException` or
  `Exception`.
- **Sites that already cover it** (because they catch `Exception` or use `runCatching`; they do not need changing):
  - `RestoreScreen.kt:78` (`catch (_: Exception)`);
  - `ExternalImport.kt:48` and `:59` (`runCatching` around `parseImport`, with
    `importErrorMessage(Throwable)`);
  - `ItemEditorScreen.kt:325` and `ItemDetailScreen.kt:236` (`runCatching` over `totpCode`);
  - `OpAutofillService.kt:41` (`runCatching` around `session.details(...)`);
  - `SettingsScreen.kt:148-150` (export backup, `catch (_: Exception)`).
- **Sites that must be fixed** (they only catch `OpException`):
  - `SettingsScreen.kt:405-412`: importing a backup from Settings. It is the only restore/import flow
    that is really uncovered;
  - `VaultSession.kt:108-112`: unlock with password (and `:266`, unlock with the vault key
    from `BiometricFlows`);
  - `SaveLoginActivity.kt:191`: saving a login from autofill;
  - `ItemEditorScreen.kt:133`: saving in the item editor;
  - `BiometricFlows.kt:31`: enabling biometric unlock;
  - `OnboardingScreen.kt:246`: creating the vault;
  - `ExternalImport.kt:138`: importing external items into the vault;
  - `AutoBackup.kt:102`: automatic backup (the `catch (e: OpException)` after `exportBackup`).
- **Session state after an internal failure.** After a `Mutex` poisoning, `Vault::with`
  wipes the key in Rust, but Kotlin would still believe `SessionState` is `Unlocked`: all
  later calls would return `OpException.Locked` with the UI open and no vault. That is why
  `VaultSession` must move to `Locked` and empty `entries` when it receives `InternalException` or an
  unexpected `Locked` (that is, one that arrives with `_state` at `Unlocked`). It is done in a single place, the
  `withVault` wrapper (`VaultSession.kt:412`), and not in each screen.
- **Messages.** «Fichero no válido» is only used in the file flows (restore, import). In the
  rest (unlock, editor, autofill, biometrics, creating the vault) a generic error is shown
  («Ha ocurrido un error interno. Vuelve a desbloquear el baúl»). The panic message is **not**
  shown or logged.

### Rationale

Option 3 gives the same result for the app with more pieces: a new profile, `cargo ndk --profile` and a
different output path, with risk for the reproducible build. Option 1 leaves an obvious DoS that the
auditor will flag. The cost of `unwind` is small, because the Android targets already emit unwind
tables by default.

### Consequences and cost

- Size: it must be **measured**. Today `libop_ffi.so` takes up 1.40 MB on arm64 and 1.09 MB on armv7. An
  increase of a single-digit percentage is expected because of the *landing pads*. If it goes over 15%, option 3
  is reconsidered.
- The APK SHA-256 changes. It does not matter, because it is a new version.
- New tests in `ffi/src/lib.rs`:
  - `lock_wipes_key_after_poisoned_mutex`: poisons the `Mutex` with `std::panic::catch_unwind` on a
    thread that panics with the guard held. Tests always use `unwind`.
  - `with_after_poison_returns_internal_and_locks`.
- Leave a `// panic = "unwind": see docs/audit/decisions.md ADR-AUD-03` in `Cargo.toml`.

### Migration

1. Fix `lock`, `is_locked` and `with`, with their tests. It goes **before** the profile change.
2. Change the profile and measure the size of the three ABIs.
3. `InternalException` catches at the sites in the previous list, and moving `VaultSession` to
   `Locked` (with empty `entries`) when receiving `InternalException` or an unexpected `Locked`. A unit
   test of `VaultSession` with a fake `Vault` that throws `InternalException`.
4. Manual check in the emulator with a debug `.so` that includes a test panic function,
   behind a *feature* that never reaches release. It is optional.

---

## ADR-AUD-04 · Supply chain

### Context

- Rust: `cargo audit --deny warnings`, with ignores in `.cargo/audit.toml` (`RUSTSEC-2026-0374`,
  `basic-toml`, only in *bindgen*). `Cargo.lock` versioned; `zip` pinned (`=9.0.3`).
- Gradle: the *wrapper* already carries `distributionSha256Sum`, but there is **no** `verification-metadata.xml`.
  The repositories (`google()` and `mavenCentral()`) are content-filtered in `pluginManagement`.
- Actions pinned **by tag** (`actions/checkout@v7`, `taiki-e/install-action@v2`,
  `dtolnay/rust-toolchain@stable`…). At `9eb9c7f`, `cargo install cargo-ndk --locked` installs without a
  pinned version; the commit that closes `v0.1.0` pins it to `--version 4.1.2`.

### Options and assessment

| Tool | What it adds to the audit | Maintenance | Decision |
|---|---|---|---|
| `cargo-deny` | Advisories (the same as `cargo-audit`), **licenses** compatible with GPL-3.0 (an F-Droid requirement), **sources** (crates.io only) and duplicates | Low: one `deny.toml` | **Yes**, it replaces `cargo-audit` |
| `cargo-vet` | Proof of human review of each version of each crate | High: audit or import on every version bump; too much for one person | **No** for now; reconsider after the audit |
| `verification-metadata.xml` (SHA-256) | Integrity of **all** Maven artifacts, plugins included. It is the largest dependency surface of the project | Medium: regenerate on version bumps; there are per-platform artifacts (`aapt2` for Linux and for macOS) | **Yes**, checksums only; no PGP signatures, which require keeping a keyring |
| Actions by SHA | Prevents a moved tag from running foreign code in the CI that produces the published APK | Low, with Dependabot (`github-actions`) | **Yes** |
| CycloneDX SBOM | Exact inventory of what is distributed: Rust from `op-ffi` and Gradle `releaseRuntimeClasspath` | Low if it is only generated in the release | **Yes**, attached to the release |
| Provenance attestation (`actions/attest-build-provenance`) | Ties APK, commit and workflow together (SLSA); complements the reproducible build | Low: one step and two permissions in a single job | **Yes**, only with tags |

### Decision

The minimal sufficient set is the five rows marked «Yes»:

1. **`deny.toml`** at the root:
   - `[advisories]`: the ignored advisory is carried with its reason;
   - `[licenses]`: explicit list of allowed licenses, generated with `cargo deny list` and reviewed;
     any new license requires approval;
   - `[sources]`: `unknown-registry = "deny"` and `unknown-git = "deny"`;
   - `[bans]`: `multiple-versions = "warn"`.

   In `ci.yml`, the `audit` job becomes `cargo deny --locked check`. `.cargo/audit.toml` is deleted.
2. **`android/gradle/verification-metadata.xml`** generated with
   `./gradlew --write-verification-metadata sha256 :app:assembleDebug :app:assembleRelease :app:testDebugUnitTest :app:lint`
   **on Linux and on macOS**, merging both files.
3. **SHAs in `ci.yml`**, with the version in a comment (`uses: actions/checkout@<sha> # v7.x.y`).
   In addition:
   - a `.github/dependabot.yml` for `github-actions`, weekly;
   - `cargo install cargo-ndk --locked --version 4.1.2` (already pinned in the commit that closes `v0.1.0`);
   - pinned versions in `taiki-e/install-action` (`tool: cargo-deny@x.y.z`, `cargo-fuzz@x.y.z`).
4. **`release` job** in `ci.yml`, only with `tags: v*`. It needs `id-token: write` and
   `attestations: write` **only in that job**. It does this:
   - builds the APK;
   - generates `cargo cyclonedx` for `op-ffi` and the Gradle SBOM (plugin `org.cyclonedx.bom`, with a
     pinned version and covered by dependency verification);
   - publishes the attestation of the unsigned APK and of the SBOMs;
   - attaches everything to the release.

### Consequences and cost

- Every Gradle dependency bump forces the metadata to be regenerated. It is documented in
  `android/README.md`.
- The CycloneDX plugin adds a build dependency, build-only and verified.
- The attestation uses public Sigstore. It is acceptable in an open-source project.

### Migration

In this order, and each step green before the next: `deny.toml` and the job; the SHAs and
Dependabot; the Gradle metadata; the `release` job.

---

## ADR-AUD-05 · Fuzzing infrastructure

### Context

- There are 5 targets in `fuzz/fuzz_targets/`: `import`, `kdbx_xml`, `key_file`, `backup_header` and `totp`.
  CI runs a 60 s pass per target (`ci.yml`, `fuzz` job) and the corpus does not persist.
- What is not fuzzed today:
  - what comes **after** the AEAD: `padding::unpad`, the JSON of `ItemDetails` and `ItemOverview`, and
    the `Body` of the backup;
  - the `serde` of `VaultHeader` and `EncryptedItem` (`encoding::hex_bytes`);
  - the `op-ffi` layer: `parse_header` and `EncryptedItemRecord::try_from`.

  With random inputs the AEAD almost never lets anything through, so those parsers are only
  reached by encrypting the fuzzer input with a fixed key.
- `Cargo.toml` already declares `check-cfg = ["cfg(fuzzing)"]`.
- There are no servers of our own. Actions minutes for public repositories are free.

### Options

1. Only extend `cargo-fuzz` and add a nightly run.
2. In addition, Jazzer for the Kotlin of autofill.
3. In addition, ClusterFuzzLite.
4. OSS-Fuzz.

### Decision

Option 1.

New targets, in `fuzz/fuzz_targets/` and registered in `fuzz/Cargo.toml`:

| Target | Input | Path |
|---|---|---|
| `vault_json` | Bytes | `serde_json::from_slice::<VaultHeader>` and `::<EncryptedItem>` (covers `hex_bytes`) |
| `item_open` | Arbitrary `EncryptedItem` (JSON) | `UnlockedVault::unlock_with_vault_key(fixed header, fixed key)` → `decrypt_overview` and `decrypt_details`. Covers `unwrap_key`, lengths and AAD |
| `item_plaintext` | Bytes as plaintext JSON | Hook `fuzzing::seal_item_part` (fixed key) → `decrypt_details` and `decrypt_overview`. Covers `padding::unpad` and the `serde` of the items |
| `backup_body` | Bytes as plaintext body | Hook `fuzzing::seal_backup` (STREAM with a fixed key) → `backup::fuzzing::open_with_vault`. Covers `stream::decrypt` and the `Body` JSON, **without KDF** |
| `ffi_records` | Bytes split into header and record | `op_ffi::Vault::unlock_with_vault_key(header_json, [7;32])` → `decrypt_*` with an arbitrary `EncryptedItemRecord`. `fuzz/Cargo.toml` starts depending on `op-ffi` |

Hooks:

- A `#[cfg(fuzzing)] pub mod fuzzing` module in `core/src/lib.rs`, which re-exports thin wrappers
  of `crypto::seal`, `stream::encrypt` and of a `backup::decrypt_body` that receives an `&UnlockedVault`.
- It is never compiled outside `cargo fuzz`. The auditor will see it, and it is documented in `fuzz/README.md`.

CI:

- The `fuzz` job for PRs and *push* drops to 30 s per target (10 targets, about 5 min).
- A new workflow `.github/workflows/fuzz-nightly.yml` (`schedule`, daily) runs 10 min per
  target:
  - corpus in `actions/cache` per target, minimized with `cargo fuzz cmin` every week;
  - if it fails, it uploads the artifacts and the job goes red.

**Jazzer: not for now.**

- `StructureParser` depends on `AssistStructure`, so Jazzer does not reach it without Robolectric.
- `LoginMatcher` (A12) and `FieldClassifier` are pure functions with JUnit 4 tests. For them
  **invariant tests with a deterministic generator** are enough, with no new dependencies, in
  `LoginMatcherTest.kt`. Examples of invariants:
  - a host with a different registrable domain never matches;
  - `hostOf` never throws exceptions;
  - an `androidapp://` URL never matches a web one.
- Jazzer would force moving to JUnit 5 and adding more dependencies to the Gradle metadata.

**ClusterFuzzLite: postponed.** To persist the corpus it needs a repository or branch with a token
(one more secret) and a Dockerfile. The nightly job offers the essentials with the same tools
used locally.

**OSS-Fuzz: discarded.** It requires a user base and acceptance, and its disclosure schedule does not
fit a project that has not yet passed the audit.

### Consequences and cost

Five target files, a `cfg(fuzzing)` module, new *seeds* in `fuzz/seeds/<target>/`
(generated from the vectors in `core/tests/vectors/op-v1.json`) and a workflow.

Criteria to reconsider:

- Jazzer, if `StructureParser` is refactored to a node abstraction without Android.
- ClusterFuzzLite, if the cached corpus is lost often (the cache expires after 7 days without use).

---

## ADR-AUD-06 · A7 and A10 defenses

### Context

- `docs/threat-model.md` claims `filterTouchesWhenObscured` (A7) and «aviso si se detecta root» (A10).
  Neither of the two exists: a `grep` of `filterTouches|HideOverlay|Build.TAGS` in `android/app/src`
  returns nothing.
- There are **three** activities that show secrets or ask for the master password. All three already set
  `FLAG_SECURE`:
  - `MainActivity.kt:23`;
  - `autofill/AutofillAuthActivity.kt:72`;
  - `autofill/SaveLoginActivity.kt:69`.
- Existing pattern to imitate: `security/AutofillExclusion.kt` (`excludeFromAutofill(activity)`,
  which is called after `setContent`).
- `minSdk = 28`, `targetSdk = 36`. The unit tests are JUnit 4 without Robolectric.
- `VerifyManifest` (`android/app/build.gradle.kts:163-175`) already fails the build on forbidden permissions.

### A7 · Anti-tapjacking

Decision: protect **per window**, in the three activities, instead of screen by screen. All
the screens of those activities ask for the password, reveal or copy secrets, or confirm a
save or a fill. Protecting per screen would leave gaps and add complexity.

Limit that must be covered explicitly: Compose `AlertDialog`s (there are some in
`SettingsScreen.kt`, `ExternalImport.kt` and `VaultListScreen.kt`) are **separate windows**, with their
own *decor view*. Neither `decorView.filterTouchesWhenObscured` nor the activity window's `setHideOverlayWindows`
covers them, and several of them ask for the master password or confirm deletions and imports.
Therefore, «all screens» is only true if the dialogs are protected too (see below).

- **New file** `android/app/src/main/kotlin/io/github/rldona/openpassword/security/OverlayProtection.kt`:
  - `fun protectFromOverlays(activity: Activity)`:
    - sets `activity.window.decorView.filterTouchesWhenObscured = true`. Compose receives the taps
      through the root `View`, so the *decor view* is enough;
    - if `SDK_INT >= 31`, it calls `activity.window.setHideOverlayWindows(true)`.
  - `@Composable fun ProtectDialogWindow()`: it is placed inside the content of each dialog, gets
    its window with `(LocalView.current.parent as? DialogWindowProvider)?.window` and applies the same thing
    (`decorView.filterTouchesWhenObscured = true` and, with `SDK_INT >= 31`, `setHideOverlayWindows(true)`).
    Equivalent alternative: a `ProtectedAlertDialog` container of our own in `ui/Components.kt` that
    does it once and replaces all the `AlertDialog`s of the app; that way a new dialog cannot be
    forgotten. This one is preferred, with a `grep` check in CI that no
    `AlertDialog(` remains outside `Components.kt`.
  - Pure function `fun obscuredTouch(flags: Int): Obscured` with the values `NONE`, `FULL`
    (`MotionEvent.FLAG_WINDOW_IS_OBSCURED`) and `PARTIAL` (`FLAG_WINDOW_IS_PARTIALLY_OBSCURED`, API 29+).
    It receives the constants as a parameter, so it can be tested on the JVM.
  - `object OverlayWarning { val detected: StateFlow<Boolean> }`, which is set to `true` as soon as a
    `FULL` or `PARTIAL` tap arrives.
- **Activities**: each one calls `protectFromOverlays(this)` next to `excludeFromAutofill(this)`, and
  overrides `dispatchTouchEvent` to notify `OverlayWarning` before calling `super`.
  - A `FULL` tap is already discarded by the system through the filter, so the flow is not changed.
  - A `PARTIAL` tap is **not** discarded: a chat bubble elsewhere on the screen is normal.
- **Response**: a non-blocking warning in `ui/Components.kt` (`OverlayWarningBanner`) that is shown
  at the top in `AppRoot` and in the two autofill activities: «Otra app está mostrando algo encima
  de OpenPassword. Por seguridad se ignoran los toques tapados». The vault is not locked.
- **Manifest**: `<uses-permission android:name="android.permission.HIDE_OVERLAY_WINDOWS" />`.
  It is a normal permission (granted at install) and the API requires it. Today `android/README.md` (line 39)
  claims that the only permissions in the manifest are `USE_BIOMETRIC` and `CAMERA`: that sentence **must be
  updated** in the migration. `VerifyManifest` starts
  **requiring it** and checking that `FLAG_SECURE` is still met, although the latter cannot be seen
  in the manifest and is covered by an instrumented test.
- **Accepted false positives**: with API 28-30, apps that obscure the screen (blue-light
  filters) leave the app unresponsive in the areas they cover. The warning explains why. Accessibility
  *overlays* are not affected.

### A10 · Offline root detection

Decision: it **only warns, it never blocks.** The F-Droid audience often uses alternative ROMs
(LineageOS: `userdebug`, `test-keys` builds) without root. Blocking would push out legitimate
users and, besides, it is useless against a root that hides itself (Magisk). The threat model already leaves A10
out of scope, so the warning is informational.

- **New file** `security/RootSignals.kt`, in pure Kotlin and without Android:
  - `interface DeviceProbe { fun fileExists(path: String): Boolean; fun packageInstalled(name: String): Boolean; val buildTags: String?; val buildType: String }`;
  - `enum class RootSignal { SU_BINARY, ROOT_MANAGER_APP, TEST_KEYS, DEBUG_BUILD }`;
  - `object RootDetector { fun evaluate(probe: DeviceProbe): Set<RootSignal> }`;
  - the path and package lists as constants of the object, so the test can iterate over them.
- **Heuristics**:
  - `su` paths: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su`,
    `/data/local/xbin/su`, `/data/local/bin/su`, `/system/sd/xbin/su`, `/vendor/bin/su`, and also
    `/data/adb/magisk` and `/data/adb/ksu`;
  - packages: `com.topjohnwu.magisk`, `me.weishu.kernelsu`, `eu.chainfire.supersu`,
    `com.koushikdutta.superuser`, `com.noshufou.android.su`, `com.kingroot.kinguser`;
  - `Build.TAGS` containing `test-keys`;
  - `Build.TYPE` equal to `userdebug` or `eng`.
- **What is deliberately not used**:
  - `android.os.SystemProperties` through reflection (interfaces outside the SDK, restricted since API 28);
  - `Runtime.exec("su")` or `getprop` (spawning processes is a suspicious signal for the auditor);
  - Play Integrity or SafetyNet (network and Google);
  - key attestation (`RootOfTrust.verifiedBootState`), which can be done offline but requires
    parsing ASN.1 and is left for the future.
- **Package visibility (API 30+)**: a `<queries>` block with the specific packages in
  `AndroidManifest.xml`. `QUERY_ALL_PACKAGES` is **not** used.
- **Android implementation** `security/AndroidDeviceProbe.kt`: it uses `File.exists`,
  `PackageManager.getPackageInfo` and `Build`.
- **When it is evaluated**: once in `OpenPasswordApp.onCreate`, on `Dispatchers.IO`, and exposed as
  `val rootSignals: StateFlow<Set<RootSignal>>`.
- **Warning in the UI**:
  - a dismissible card in `ui/unlock/UnlockScreen.kt` and a «Seguridad del dispositivo» section
    in `ui/settings/SettingsScreen.kt`;
  - the dismissal is saved in `SharedPreferences` together with the set of signals: if a new
    signal appears, the warning shows up again.
  - Text: «Este dispositivo parece tener root o una compilación de depuración. Con root, otras apps
    pueden leer tus secretos de la memoria. OpenPassword no puede protegerte en ese caso».
- **Accepted false positives**: custom ROMs without root (`test-keys`, `userdebug`), emulators and
  root management packages that are installed but unused.
- **Accepted false negatives**: hidden Magisk (package under another name, DenyList) and KernelSU with
  hidden paths.

### Tests

| Test | Type | Covers |
|---|---|---|
| `app/src/test/.../RootDetectorTest.kt` | JUnit 4 with a fake `DeviceProbe` | Each signal separately; no signal on a "clean" profile; `test-keys` inside other tags; the paths and packages in the lists |
| `app/src/test/.../OverlayProtectionTest.kt` | JUnit 4 | `obscuredTouch` with combinations of flags |
| `app/src/androidTest/.../OverlayProtectionTest.kt` | Instrumented (local CI emulator) | The three activities have `decorView.filterTouchesWhenObscured == true` and `FLAG_SECURE` in `window.attributes.flags`; **in addition**, each dialog they show (master password, import, deletion) has `filterTouchesWhenObscured == true` on the dialog's own window, and a tap with the `FLAG_WINDOW_IS_OBSCURED` flag on its confirm button is not delivered |
| `VerifyManifest` | Build | That `HIDE_OVERLAY_WINDOWS` exists |
| Manual (checklist in `docs/audit/`) | Device | A test *overlay* app over `UnlockScreen` (API 30 and 34) and a `userdebug` emulator (it must show the warning) |

A rooted device is not needed: `DeviceProbe` is the test boundary.

### Migration

1. First `OverlayProtection.kt` (including dialog protection) with its tests, the manifest and
   the three activities; then the warning.
2. Then `RootSignals.kt` and `AndroidDeviceProbe.kt` with their tests, `<queries>` and the warning in the UI.
3. Update `docs/threat-model.md`:
   - in A7, the real text (it includes `setHideOverlayWindows` on API 31+, dialog protection and
     the limitations on API 28-30);
   - in A10: «aviso heurístico, sin red, que se puede eludir».
4. Update `android/README.md` (line 39): the sentence «los únicos permisos del manifiesto son
   `USE_BIOMETRIC` y `CAMERA`» now includes `HIDE_OVERLAY_WINDOWS`. Also `docs/fdroid/README.md`
   if it lists permissions (to be verified).

---

## ADR-AUD-07 · KDF limits and denial of service

### Context: the v1 format does bound the parameters, and the code shows it

- `core/src/crypto/kdf.rs` defines
  `KdfParams::MAXIMUM = argon2id(2_097_152, 16, 16)` (2 GiB, 16 passes, 16 lanes).
  `check_bounds()` rejects any parameter above that maximum and anything `argon2::Params::new`
  does not accept.
- `check_bounds` is applied in two places:
  1. in `backup::parse` (`core/src/backup/mod.rs`, `header.vault.kdf.check_bounds()?`), **before**
     asking for the password;
  2. in `derive_kek` (`params.check_bounds()?` as the first statement). **All** the paths to Argon2
     go through it: `UnlockedVault::unlock`, `rekey`, `backup::open` and the FFI `Vault::unlock`.
- It is specified in `docs/crypto-spec.md` §5 (row «Máximo aceptado al leer») and in
  `docs/opvault-format.md:58`. The tests are in `kdf.rs` (`bounds_reject_costly_or_invalid_params`)
  and the `backup_header` target exercises it.
- There is a filter before the KDF: `UnlockedVault::unlock` compares `header.secret_key_id` with the one of
  the user's SK and returns `WrongSecretKey` **before** deriving.

### But the ceiling leaves a DoS on mobile

- 2 GiB is more than an armv7 process can reserve and more than many phones have.
  `argon2` 0.5 reserves the block memory with an infallible allocation, so an out-of-memory
  **aborts the process** even if ADR-AUD-03 is adopted. If the system overcommits memory, the
  *low-memory killer* kills the app during the fill.
- In compute time: 2 GiB × 16 passes is about 43 times the cost of the recommended profile
  (256 MiB × 3). On a phone, that is minutes of CPU that cannot be cancelled from Kotlin.
- **How it is reached**:
  - `VaultSession.importBackup` with a **foreign** backup: the attacker supplies the file **and** its
    SK, so the `secret_key_id` filter is useless;
  - `VaultSession.restore`;
  - one's own backup replaced in the cloud (A4): the `secret_key_id` is visible in any header
    of a legitimate backup of the victim.

  The effect is a crash or a hang that can be repeated. There is no data loss, because
  restore only writes after opening.
- The local header (`VaultStorage.readHeader`) can only be manipulated by whoever writes to the app's private
  storage, that is, an attacker with root (out of scope).
- **KDBX**, related: `core/src/import/kdbx.rs:35-37` accepts Argon2 up to 1 GiB with
  **1000 iterations** and AES-KDF with 200 million rounds. 1 GiB × 1000 is hours. The user chooses
  the file, but it is still a DoS.
- The app only creates vaults with `RECOMMENDED` (256 MiB, 3, 4) or `MINIMUM` (64 MiB, 2, 1), depending on
  RAM (`OpenPasswordApp.kt`, `kdfProfileFor`). The CLI uses `RECOMMENDED` (`cli/src/main.rs:168`) and the
  vectors use 256 KiB or 64 MiB. **No file created by OpenPassword exceeds 256 MiB, 3 passes
  and 4 lanes.**

### Options

1. Do nothing: the format already bounds it.
2. Lower `KdfParams::MAXIMUM` in the core. It changes what the v1 format considers valid, and with that
   the specification and the CLI.
3. Keep the format maximum and add a lower **platform ceiling** in `op-ffi`, checked
   before any KDF, plus a RAM check in Kotlin before calling.

### Decision

Option 3.

- **The v1 format does not change**: `MAXIMUM`, the specification and the vectors stay the same. The validity
  of the format and the policy of a platform are different things, and the policy lives in the
  platform layer (`op-ffi`), which keeps the dependency direction.
- **In the core**, a new pure method in `core/src/crypto/kdf.rs`:
  `pub fn check_within(&self, limit: &KdfParams) -> Result<()>`. It is `check_bounds` generalized, and
  `check_bounds` becomes `self.check_within(&Self::MAXIMUM)`, without changing its behavior.
- **In `op-ffi`** (`ffi/src/lib.rs`):
  - `const MOBILE_MAXIMUM: KdfParams = KdfParams::argon2id(524_288, 6, 8)` (512 MiB, 6 passes, 8
    lanes). Reasoning with numbers:
    - it is double the memory and the passes of the recommended profile (256 MiB / 3 / 4), so **4 times**
      the cost (512 × 6 = 3072 versus 256 × 3 = 768 MiB·pass): room to raise the profile in the
      future without touching the ceiling;
    - no vault created by the app exceeds it (`OpenPasswordApp.kt:61` only uses `MINIMUM` or
      `RECOMMENDED`), so it does not invalidate anything that came out of OpenPassword;
    - the ceiling that was discarded, 1 GiB / 8 / 8, costs 8192 MiB·pass, about 10.7 times the recommended one,
      and 1 GiB in a row in a 32-bit process risks failing due to address space
      fragmentation. 512 MiB reduces it a lot, although it does not disappear completely on armv7;
    - alternative submitted for approval: a ceiling **per ABI** (32-bit: 256 MiB / 3 / 4, which is
      exactly what the app creates; 64-bit: 512 MiB / 6 / 8). It complicates behavior across
      devices (a backup opens on one phone and not on another) in exchange for more security on
      armv7;
    - it is a **platform** ceiling (`op-ffi`). `KdfParams::MAXIMUM` (2 GiB / 16 / 16), the
      specification of the v1 format and the vectors **do not change**;
  - it is checked in `Vault::unlock` (after `parse_header`) and in `open_backup`, before calling
    `backup::open`. For that the header is read with `backup::read_header(&bytes)`; parsing it twice
    costs very little;
  - a new variant `OpError::KdfTooExpensive { m_kib: u32, t: u32, p: u32 }`. Today
    `E::KdfParams(_)` is translated to `Internal`; when the limit is exceeded, the translation becomes
    `InvalidInput`.
- **Prior check in Kotlin**: a new FFI function, `backup_kdf(bytes: Vec<u8>) -> KdfInfo { m_kib, t, p }`,
  which carries no secret.
  - In `VaultSession.restore` and `importBackup`: if `m_kib × 1024 > totalMem / 2`, it is rejected with a
    clear message before calling `openBackup`. The `ActivityManager.MemoryInfo` query of
    `kdfProfileFor` is reused. This check is **complementary**: with 4 GB
    of RAM the threshold is 2 GiB and it lets through any value below the `op-ffi` ceiling, which is
    the real barrier. It is only useful for devices with little RAM (for example, 1 GB leaves the threshold at
    512 MiB; with a 512 MiB ceiling, it only changes anything below 1 GB of RAM).
  - The case is added to `OpException.toUserMessage()` (`VaultSession.kt:462`).
- **KDBX**: a joint budget `memory × iterations ≤ 16 GiB·pass` in `argon2_kdf` (for
  example, 64 MiB × 256 or 1 GiB × 16). It needs approval (see the final list), because it may reject
  legitimate KeePass databases with very high parameters.

### Consequences and cost

- A backup with a cost between the mobile ceiling and the format maximum is valid according to v1 but is not
  opened on Android. It is reported with a clear error, and the CLI could open it. No vault created by the
  app is affected (the app never exceeds 256 MiB / 3 / 4).
- Tests:
  - in `kdf.rs`, `check_within` at the boundaries;
  - in `ffi/src/lib.rs`, a backup with `m_kib = 524_289` fails with `KdfTooExpensive` without taking long
    (the test must finish in milliseconds). The header is built by hand from a real backup,
    because `create` does not allow vaults like that to be created;
  - the `backup_header` target also checks `check_within(MOBILE_MAXIMUM)`.
- There is no need to change the format or migrate data.

### Migration

1. `check_within` in the core and its tests.
2. The ceiling and the error in `op-ffi`, with their tests.
3. `backup_kdf` and the prior check in Kotlin.
4. The KDBX budget, if approved.
5. A note in `docs/crypto-spec.md` §5: «las plataformas PUEDEN aplicar un techo más bajo; Android:
   512 MiB / 6 / 8».

---

## Implementation plan (order and verification)

Each step can be verified separately.

| # | Step | Files | Depends on | Verification |
|---|---|---|---|---|
| 1 | `lock`, `is_locked` and `with` resistant to poisoning | `ffi/src/lib.rs` | — | `cargo test -p op-ffi` with the two new tests |
| 2 | `panic = "unwind"` and size measurement | `Cargo.toml` | 1 | `cargo build --release`; size of `libop_ffi.so` per ABI noted in the PR |
| 3 | Catch `InternalException` in every FFI call from UI coroutines and move the session to `Locked` on an internal failure | `session/VaultSession.kt` (`:108-112`, `:266`, `withVault`), `ui/settings/SettingsScreen.kt` (`:405-412`), `ui/settings/ExternalImport.kt` (`:138`), `ui/vault/ItemEditorScreen.kt` (`:133`), `ui/unlock/BiometricFlows.kt` (`:31`), `ui/onboarding/OnboardingScreen.kt` (`:246`), `autofill/SaveLoginActivity.kt` (`:191`), `backup/AutoBackup.kt` (`:102`) | 2 | `./gradlew :app:testDebugUnitTest`; `grep` of `catch (e: OpException)` with no `InternalException`/`Exception` catch next to it: zero results |
| 4 | Isolated test of `SecretString` (`custom_type!`) | `ffi/src/lib.rs` (or `ffi/src/secret.rs`) | — | Regenerated bindings without type changes in `op_ffi.kt` |
| 5 | Apply `SecretString` and `Zeroizing` across the whole API | `ffi/src/lib.rs` | 4 | `cargo test -p op-ffi`; app built |
| 6 | `check_within`, `MOBILE_MAXIMUM`, `KdfTooExpensive` and `backup_kdf` | `core/src/crypto/kdf.rs`, `ffi/src/lib.rs` | 5 (same surface) | Boundary tests; a DoS test that finishes in < 100 ms |
| 7 | Prior RAM check and user message | `session/VaultSession.kt` | 6 | Unit test of the decision function |
| 8 | KDBX budget (if approved) | `core/src/import/kdbx.rs` | — | Tests with parameters at the boundary |
| 9 | Protection against *overlays* (A7), dialogs included | `security/OverlayProtection.kt`, the 3 activities, `ui/Components.kt` (`ProtectedAlertDialog`) and the `AlertDialog`s of `SettingsScreen.kt`, `ExternalImport.kt` and `VaultListScreen.kt`, `AndroidManifest.xml`, `build.gradle.kts` (`VerifyManifest`), `android/README.md` (permissions) | — | Unit and instrumented tests (activities and dialogs); `assembleRelease` fails if the permission is removed |
| 10 | Root detection (A10) | `security/RootSignals.kt`, `security/AndroidDeviceProbe.kt`, `OpenPasswordApp.kt`, `ui/unlock/UnlockScreen.kt`, `ui/settings/SettingsScreen.kt`, `AndroidManifest.xml` (`<queries>`) | — | `RootDetectorTest`; `userdebug` emulator with the warning |
| 11 | `cfg(fuzzing)` hooks and 5 new targets with *seeds* | `core/src/lib.rs`, `core/src/backup/mod.rs`, `fuzz/` | 6 | `cargo +nightly fuzz build`; 60 s without failures per target; `cargo build --release` does not expose `fuzzing` |
| 12 | Nightly fuzzing | `.github/workflows/fuzz-nightly.yml`, `ci.yml` | 11 | One manual run (`workflow_dispatch`) green |
| 13 | Invariant tests for `LoginMatcher` | `app/src/test/.../LoginMatcherTest.kt` | — | `testDebugUnitTest` |
| 14 | `cargo-deny` | `deny.toml`, `ci.yml`, delete `.cargo/audit.toml` | — | `cargo deny --locked check` green |
| 15 | Actions by SHA, Dependabot and pinned tool versions | `ci.yml`, `.github/dependabot.yml` | 14 | CI green; no `uses:` without a SHA (`grep`) |
| 16 | Gradle dependency verification | `android/gradle/verification-metadata.xml`, `android/README.md` | 15 | Build on Linux (CI) and on macOS green; it fails if a checksum is altered |
| 17 | `release` job: SBOM and attestation | `ci.yml`, `android/app/build.gradle.kts` (CycloneDX plugin) | 15, 16 | Run with a test tag (`v0.2.0-rc1`); `gh attestation verify` passes |
| 18 | Documentation: threat model (A7, A10, residue), specification §5 and §10, `fuzz/README.md`, `SECURITY.md` | `docs/` | 1-17 | Review; no described defense without code that implements it |
| 19 | Version 0.2.0, `release/0.2` branch, signed tag and package for the auditor | `Cargo.toml`, `build.gradle.kts`, `fastlane/` | All | The APK SHA-256 from CI matches an independent Linux build |

Steps 1-8, 9-10, 11-13 and 14-17 form independent blocks and can move forward in parallel.

## Risks that remain open

| Risk | Why it remains open | Mitigation or next step |
|---|---|---|
| Secrets in JVM and Compose `String` | They cannot be wiped on the JVM | ADR-AUD-02, option D (opaque session) after the audit; documented as residue |
| Output `RustBuffer` and output `String` copy not wiped | UniFFI offers no wipe hook | Documented; reconsider if UniFFI adds one |
| Out of memory in Argon2 = abort | Infallible allocation in `argon2` 0.5; `panic = "unwind"` does not avoid it | The 512 MiB / 6 / 8 ceiling and the RAM check **reduce** the probability, but **do not** mitigate it: a device with little free memory or a fragmented 32-bit process can abort anyway, and the Kotlin RAM check (`totalMem / 2`) is lax. It remains open; only a fallible allocation in `argon2` or a KDF in another process would close it |
| KDF that cannot be cancelled | Blocking FFI call | «puede tardar» warning in the UI; out of scope |
| Hidden root (Magisk or KernelSU with concealment) | Local heuristics can be bypassed by design | Warning only; A10 remains out of scope |
| Partial tapjacking on API 28-30 | `filterTouchesWhenObscured` does not filter `PARTIALLY_OBSCURED` | Warning; API 31+ hides the *overlays* |
| `StructureParser` without fuzzing | It depends on `AssistStructure` | Refactor to a node abstraction later, and then Jazzer |
| Rust dependencies without human review | `cargo-vet` is not adopted | `cargo-deny`, few dependencies, pinned versions; reconsider after the audit |
| Rollback to an earlier version (A6) | Without synchronization it is not detected | Accepted in v1 |
| CI triggers for tags and `release/**` | `tags: ['v*']` is added with the closing of `v0.1.0` and has not yet been tested with a tag; `release/**` does not exist yet | ADR-AUD-01, migration 2; verify it with an `-rc` tag |
| `cfg(fuzzing)` hooks in the core code | Code that only exists in fuzzing | Auditor review; test that the release build does not export the module |

## Decisions that require human approval

All were approved on **2026-10-30**, except no. 1, which depends on the moment of publication.

| # | ADR | Decision | Status |
|---|---|---|---|
| 1 | ADR-AUD-01 | Which key signs the tags, soft freeze of `core/` and `ffi/` in `main`, and `release/0.2` in `SECURITY.md` | **Pending**: the branch and the tag are created when `0.2.0` is frozen |
| 2 | ADR-AUD-03 | `panic = "unwind"` and size threshold (+15%) | Approved and implemented (it grew 9.3%) |
| 3 | ADR-AUD-07 | Mobile ceiling of 512 MiB / 6 / 8, accepting that some backup valid according to v1 does not open on Android | Approved and implemented |
| 4 | ADR-AUD-07 | KDBX budget | Approved and implemented at 512 MiB / 3 GiB·pass |
| 5 | ADR-AUD-06 | Warning without blocking on root and publishing the `<queries>` with the root packages | Approved and implemented |
| 6 | ADR-AUD-06 | `HIDE_OVERLAY_WINDOWS` in the manifest and update of `android/README.md` | Approved and implemented; verified on device (DT-01) |
| 7 | ADR-AUD-04 | License list of `deny.toml`, CycloneDX plugin and NCSA exception for `libfuzzer-sys` | Approved and implemented |
| 8 | ADR-AUD-04 | Sigstore attestations and `id-token: write` in the release job | Approved and implemented; the job has not been run |
| 9 | ADR-AUD-05 | Not adopting Jazzer or ClusterFuzzLite before the audit | Approved |
| 10 | ADR-AUD-02 | Postponing the opaque session and accepting the documented residue | Approved |

Other decisions of the owner, outside the ADRs:

- **ID-INT-06**: an unreadable item is skipped with a warning; it neither blocks the unlock nor touches the row.
- **ID-INT-14**: wiping the clipboard in the background is accepted as residual risk of Android.
- **F-Droid**: publication paused since 2026-10-30 (see [`docs/fdroid/README.md`](../fdroid/README.md))).
