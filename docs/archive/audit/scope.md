# Audit scope (scope of work)

Document for the auditor. Describes what is audited, with which version, how to reproduce the code and the
build, which specific questions matter to us and what we expect to receive.

Status: **pending** completion of the fields marked `PENDING` (frozen SHA, deadlines, contacts).
See [`README.md`](README.md)).

## 1. Summary

OpenPassword is an **offline** password manager (the app does not declare the network permission),
**Android first**, licensed GPL-3.0-or-later. All cryptography lives in a Rust library
(`op-core`) that the Android app loads through UniFFI (`op-ffi`). A single maintainer; no
servers or accounts.

## 2. Objectives and assets to protect

Objective: that an independent third party assesses whether the implementation delivers what the
[cryptographic specification](../../crypto-spec.md)) and the [threat model](../../threat-model.md)) promise, and
finds flaws that would let an attacker within that model read or alter secrets.

| Asset | Examples | Sensitivity (per the threat model) |
|---|---|---|
| Secrets | passwords, CVV, PINs, seed phrases, API keys | Critical |
| Access credentials | master password, secret key (SK) | Critical |
| Backups | `.opvault` files | same as the secrets |
| Metadata | titles, URLs, which services the user uses | High |

Relevant attackers (A1–A16 of the threat model): thief with the phone, whoever obtains or manipulates a
`.opvault`, cloud provider, malicious app without privileges, phishing web or app
against autofill, supply chain, imported files or malicious QR codes. They are **out**
(threat model): malicious root or tampered firmware, *keylogger* and coercion.

Important: two defenses have limited effectiveness **by design**. Root detection (A10) only
warns and can be bypassed. Secret wiping in the JVM has accepted residue (ADR-AUD-02).
We care about knowing whether the documented limitations are the real ones, not only that they exist.

## 3. Version, code and build

| Data point | Value |
|---|---|
| Repository | <https://github.com/rldona/OpenPassword> |
| Version | `v0.2.0` (branch `release/0.2`, signed tag) |
| Frozen commit | **PENDING** (40-character SHA; that is what is audited, not the tag name) |
| Later changes | signed `v0.2.N`; `git diff v0.2.(N-1)..v0.2.N` is delivered (see [ADR-AUD-01](decisions.md#adr-aud-01--freeze-strategy))) |
| License | GPL-3.0-or-later |

### Getting the code

```sh
git clone https://github.com/rldona/OpenPassword.git
cd OpenPassword
git checkout <frozen-SHA>         # PENDING
git tag -v v0.2.0                 # once the signed tag exists
```

The GitHub `v0.2.0` pre-release will attach: `git archive` with its SHA-256, the unsigned APK from CI
and its SHA-256, the SBOMs and the provenance attestation (ADR-AUD-04, **to be implemented**; until they
exist, they are not promised).

### Build environment

The exact versions are those in these files; they are not repeated here so as not to de-synchronise them:

- Rust: [`rust-toolchain.toml`](../../../rust-toolchain.toml)) (it includes the three Android *targets*).
- JDK 17, Android SDK (platform 37), NDK `30.0.16248370`, `cargo-ndk 4.1.2`:
  [`android/README.md`](../../../android/README.md)) and [`ci.yml`](../../../.github/workflows/ci.yml)).
- Gradle: repository *wrapper* (`android/gradlew`), with `distributionSha256Sum`.

### Reproducible build

The unsigned APK is reproducible **on Linux** (CI uses `ubuntu-24.04`). On macOS it does not match the Linux one
byte for byte, and the reason is documented in [`docs/fdroid/README.md`](../fdroid/README.md)).
Therefore:

```sh
cd android
./gradlew :app:assembleRelease --console=plain
sha256sum app/build/outputs/apk/release/app-release-unsigned.apk
```

It must match the SHA-256 printed by CI for the same commit. Confirming that the APK that is
distributed (signed with the project key) is the CI one without the signature is part of the scope
(section 4).

## 4. In scope

| Component | Where | What is asked to review |
|---|---|---|
| `op-core` | `core/` (`src/crypto`, `src/vault`, `src/backup`, `src/import`, `src/totp.rs`) | Cryptography, format, importers, TOTP |
| `op-ffi` | `ffi/` | UniFFI boundary: secret types (`SecretString`), panics, KDF bounds, session `Mutex` |
| Android app | `android/app/src/main` | Session, autofill, Keystore and biometrics, clipboard, anti-tapjacking, root warning, storage, manifest |
| `.opvault` format v1 | [`docs/opvault-format.md`](../../opvault-format.md)), [`docs/crypto-spec.md`](../../crypto-spec.md)) | Design: key derivation, AAD, STREAM, versioning |
| Reproducible builds and signing | `android/`, `.github/workflows/ci.yml`, `scripts/sign-release.sh`, `rust-toolchain.toml` | That the published APK corresponds to the code, and that the signing chain is sound |

Any third-party dependency is evaluated **in its use** (how OpenPassword calls it), its code is not
audited; the inventory is in [`dependencies.md`](dependencies.md)) (in preparation).

## 5. Out of scope

- The `opvault` CLI (`cli/`). It shares `op-core`, so the core code is reviewed.
- Phase 4 of the proposal (future features).
- iOS and desktop (they do not exist yet).
- Compromised Android or hardware (malicious root, firmware), *keyloggers* and coercion
  ([threat model](../../threat-model.md))).
- Dependency code, the operating system and the Keystore (their use is audited).
- Third-party infrastructure (GitHub, F-Droid).
- Social engineering attacks against the maintainer.

## 6. Specific questions for the auditor

Each one links to the source that should be read. We want an explicit answer («correct», «finding
F-nn» or «I could not evaluate it»).

### Cryptography and format

1. **AEAD context and AAD.** Do the domains and the AAD parts (`op/wrap/v1`, `op/item/v1`, …;
   [`crypto-spec.md` §6.2](../../crypto-spec.md)), `core/src/crypto/aead.rs`) prevent swapping,
   reordering or reusing blocks between contexts (items, vault key, backups, versions)?
   Is there any field that should be authenticated and is not? Is *nonce* handling correct?
2. **STREAM.** Do chunking, the end marker and header authentication
   (`core/src/crypto/stream.rs`, `core/src/backup`) detect truncation, reordering and extension? Are there
   risks in the edge cases (zero blocks, exact block)?
3. **KDF and its bounding.** Argon2id with `KdfParams::MAXIMUM` in the format and a lower ceiling in
   `op-ffi` ([ADR-AUD-07](decisions.md#adr-aud-07--kdf-limits-and-denial-of-service)),
   `core/src/crypto/kdf.rs`). Is the composition master password + SK + NFKD correct? Are the
   `MINIMUM` and `RECOMMENDED` profiles adequate? Is there a path to Argon2 that bypasses `check_bounds`?
   Is a memory or time DoS reachable with a foreign file left open?
4. **KDBX import.** `core/src/import/kdbx.rs` (KDBX 3.1 and 4.x, Argon2, AES-KDF, XML). Are there
   parsing errors, DoS through parameters or through XML (expansion, depth) or leakage of protected
   values? Warning: KDBX 4 reading has not yet been tested with a real file
   (`android/README.md`).

### Android

5. **Autofill: matching and public suffixes.** `autofill/LoginMatcher.kt`,
   `PublicSuffix.kt`, `StructureParser.kt`, `SavePlanner.kt`. Can a phishing web page or app
   obtain credentials from another site (A12)? Is the handling of the public
   suffix list and of anomalous *hosts* (IDN, ports, schemes, `androidapp://`) correct and sufficient?
6. **Keystore and biometrics.** `security/DeviceKeyStore.kt`, `BiometricKeyStore.kt`, `Biometrics.kt`;
   [`crypto-spec.md` §9](../../crypto-spec.md)). Are the key parameters used correctly (AES-GCM,
   per-use authentication, invalidation when biometrics change, StrongBox)? Can authentication be bypassed
   or downgraded to device credential?
7. **Secret wiping.** When crossing UniFFI (`ffi/src/lib.rs`, `ffi/src/secret.rs`) and in the JVM
   (`session/VaultSession.kt`); [ADR-AUD-02](decisions.md#adr-aud-02--secrets-crossing-uniffi)) and
   [`crypto-spec.md` §10](../../crypto-spec.md)). Are the accepted residues the only ones? Are there copies in
   Rust or Kotlin that the ownership contract does not cover?
8. **Panics and session state.** Can a hostile file kill the process, leave the session in an
   inconsistent state or leave the key in memory after `lock()`?
   ([ADR-AUD-03](decisions.md#adr-aud-03--panics-at-the-ffi-boundary))).
9. **Clipboard.** `security/SensitiveClipboard.kt`: sensitive flag, clearing after 30 s,
   leaks to history or sync services.
10. **Root detection and anti-tapjacking.** `security/RootSignals.kt`, `AndroidDeviceProbe.kt`,
    `OverlayProtection.kt` ([ADR-AUD-06](decisions.md#adr-aud-06--a7-and-a10-defenses))). Is the protection
    of windows and dialogs complete? Is root detection merely informative and does it not open
    surface (for example, the `<queries>` block)?
11. **Storage and manifest.** SQLite with `secure_delete`, `allowBackup=false`, permissions,
    exported components, `FLAG_SECURE`, exclusion from the autofill of other services.
12. **Supply chain and signing.** Is the distributed APK equivalent to the CI one? Are `ci.yml`,
    `scripts/sign-release.sh` and the signing key management sound?

### Open questions

13. Which part of what the [threat model](../../threat-model.md)) claims does not hold up against the
    code?
14. What would be needed before recommending that real users store real data?

## 7. How to build and test

Real repository commands (CI: [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml))):

```sh
# Core and FFI (Rust)
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# Golden vectors of the v1 format (they also run with the previous command)
cargo test -p op-core --test vectors

# Android
cd android
./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease --console=plain
./gradlew :app:connectedDebugAndroidTest    # requires a phone or emulator
```

**Test vectors.** [`core/tests/vectors/op-v1.json`](../../../core/tests/vectors/op-v1.json)) pins
every byte of the v1 format (AAD, derivation, sealed blocks, backups). They are test data: their
keys protect nothing. Any other implementation must pass the same file. They are not
regenerated except with a new version of the format (`core/tests/vectors.rs`).

**Fuzzing.** Targets in `fuzz/fuzz_targets/`; instructions and description in
[`fuzz/README.md`](../../../fuzz/README.md)) (requires nightly and `cargo-fuzz`). The `cfg(fuzzing)` module
uses a fixed key **for tests only** and does not enter any normal build.

Environment note: the reference APK is compared on Linux. On macOS it can be built and tested,
but the SHA-256 will not match.

## 8. Expected deliverables

| Deliverable | Content |
|---|---|
| Preliminary report | Findings with severity, description, impact, location (file and line on the frozen SHA) and recommendation |
| PoC | Minimal reproduction of each finding of Medium severity or above (`.opvault` file, test, APK or script) |
| Re-test | Verification by the auditor of each fix, on a `v0.2.N` tag, with a per-finding status (fixed, partial, not fixed, accepted) |
| Publishable final report | Public version of the report after the re-test, including scope, methodology, findings and their final status |
| Summary for users | One page without technical jargon (optional) |

Format of the findings and severity scale: [`findings-process.md`](findings-process.md)). A
stable identifier per finding is preferred (`<VENDOR>-01`, …).

## 9. Confidentiality, communication and deadlines

- **Code:** public; there is no secret to protect in the code.
- **Findings:** confidential until a fix is published or until the agreed
  publication date. Channel: private GitHub Security Advisories of the repository
  (`https://github.com/rldona/OpenPassword/security/advisories`, the same channel as
  [`SECURITY.md`](../../../SECURITY.md))). Critical findings: immediate notice to the technical contact, without
  waiting for the report.
- **Publication:** the project wants to publish the final report. The contract must acknowledge that
  permission in writing (see [`vendors.md`](vendors.md))).
- **Non-disclosure agreement (NDA):** only if the vendor requires it and only for non-public
  information (release signing key, accesses). **PENDING** decision.

| Milestone | Date |
|---|---|
| Freeze (`v0.2.0` signed) | **PENDING** |
| Start | **PENDING** |
| Preliminary report | **PENDING** |
| Re-test | **PENDING** |
| Final report | **PENDING** |

Full calendar and exit conditions: [`budget-timeline.md`](budget-timeline.md)).

### Contacts

| Role | Contact |
|---|---|
| Maintainer and technical contact | `@rldona` on GitHub; email **PENDING** |
| Security / findings contact | Private GitHub advisories of the repository (see above) |
| Contractual contact | **PENDING** (person or entity that signs) |
| PGP key for encrypted email | **PENDING** (none is published in the repository) |
