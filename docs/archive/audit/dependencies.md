# Dependencies

Inventory of what goes into the product and into its build chain, with the real numbers from the
tree, what is linked into `libop_ffi.so`, duplicates, advisories, licenses versus GPL-3.0, pins and
proposals. Complements ADR-AUD-04 in [`decisions.md`](decisions.md)).

Status verified on 2026-10-30 over `HEAD` `a3daf4e`. `deny.toml`, `.github/dependabot.yml`,
`android/gradle/verification-metadata.xml`, the Actions pinned by SHA and the `release` job are
confirmed in that commit ([`hardening.md`](hardening.md))); **none of them has been run yet on
GitHub** (the `release` job) **nor with Gradle verification active**.
Every figure carries the command that produces it (section 8).

## 1. Figures

| Measure | Value | How it is obtained |
|---|---|---|
| Packages in `Cargo.lock` (root) | **139** (136 from crates.io + 3 of our own: `op-core`, `op-ffi`, `opvault-cli`) | `grep -c '^\[\[package\]\]' Cargo.lock`; `cargo metadata` |
| Packages in `fuzz/Cargo.lock` | 132 | Same. Separate workspace (`fuzz/Cargo.toml`) |
| Origins other than crates.io | **0** | `cargo metadata`: no package with a foreign `source`; `deny.toml` `[sources]` denies unknown registries and `git` |
| Library units compiled for `aarch64-linux-android` (`op-ffi`, release) | **73** (71 third-party + `op-core` + `op-ffi`) | `cargo +nightly build -p op-ffi --lib --release --target aarch64-linux-android --locked -Z unstable-options --unit-graph`, units with platform and `build` mode, without `proc-macro` or `custom-build` |
| *Crates* with a visible path in `libop_ffi.so` (arm64) | **23** | `strings -a …/libop_ffi.so \| grep -oE 'registry/src/[^/]+/[A-Za-z0-9_.+-]+'` (see 2.3) |
| Components in the Gradle SBOM (`releaseRuntimeClasspath`) | **144** | `android/app/build/reports/cyclonedx-direct/bom.json` (CycloneDX 3.5.1, 2026-10-30T09:34:26Z) |
| Components with a SHA-256 sum in `verification-metadata.xml` | **478** components, **918** sums | `grep -c "<component " …`, `grep -c "<sha256" …` |
| Duplicate versions (Rust) | **2** pairs | `cargo metadata`: `getrandom` 0.2.17 and 0.3.4; `syn` 2.0.119 and 3.0.9 |
| Known vulnerabilities (Rust) | **0** | `cargo audit --deny warnings`: 1386 advisories loaded, 139 packages, exit 0 |
| `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok` | `cargo deny --locked check` (0.20.2, locally) |
| Rust tests | **102 pass, 1 ignored** | `cargo test --workspace --locked` (50 unit tests from `op-core`, 9 + 3 + 19 + 5 integration, 16 from `op-ffi`) |

## 2. Rust

### 2.1 Direct dependencies

| Crate | Requested version | Resolved | For what | Crate |
|---|---|---|---|---|
| `argon2` | `0.5` (no default features: `alloc`, `zeroize`) | 0.5.3 | Argon2id (KEK) and KeePass | `op-core` |
| `chacha20poly1305` | `0.10` (`stream`) | 0.10.1 | XChaCha20-Poly1305 AEAD and STREAM | `op-core` |
| `hkdf`, `hmac`, `sha2`, `sha1` | `0.12`, `0.12`, `0.10`, `0.10` | 0.12.4, 0.12.1, 0.10.9, 0.10.7 | HKDF, HMAC, SHA-2, TOTP SHA-1 | `op-core` |
| `aes`, `cbc`, `chacha20`, `salsa20` | `0.8`, `0.1`, `0.9`, `0.10` | 0.8.4, 0.1.2, 0.9.1, 0.10.2 | KeePass ciphers (KDBX) | `op-core` |
| `flate2` | `1` (`zlib-rs`) | 1.1.10 | KDBX gunzip | `op-core` |
| `zip` | `=9.0.3` (no default features, `deflate-flate2-zlib-rs`) | 9.0.3 | `.1pux` | `op-core` |
| `quick-xml` | `0.42` | 0.42.0 | KDBX XML and key files | `op-core` |
| `serde`, `serde_json` | `1` | 1.0.229, 1.0.154 | `.opvault` format, importers | `op-core`, `op-ffi` |
| `base64`, `hex`, `unicode-normalization` | `0.22`, `0.4`, `0.1` | 0.22.1, 0.4.3, 0.1.26 | Encodings and NFKD | `op-core` (`hex` also `op-ffi`) |
| `getrandom` | `0.3` | 0.3.4 | System CSPRNG | `op-core` |
| `zeroize` | `1` (`derive`) | 1.9.1 | Key wiping | `op-core`, `op-ffi` |
| `thiserror` | `2` | 2.0.21 | Errors | `op-core`, `op-ffi` |
| `uniffi` | `0.32` (default features: `cargo-metadata`, …) | 0.32.2 | Kotlin bindings | `op-ffi` |
| `anyhow`, `clap`, `rpassword` | `1`, `4`, `7` | 1.0.104, 4.6.7, 7.5.4 | CLI (**out of scope**) | `opvault-cli` |

Core `Cargo.toml`: 21 dependencies; `op-ffi`: 5 plus `op-core`; the CLI: 8. The development
dependencies of `op-core` are only `op-core` with `insecure-test-params` (`core/Cargo.toml`).

### 2.2 What is linked into `libop_ffi.so`

- It is a `cdylib` (`ffi/Cargo.toml`, `crate-type = ["cdylib", "lib"]`) compiled with `--release --locked
  -p op-ffi` and hardcoded RUSTFLAGS (`--remap-path-prefix`, `--cfg aes_armv8`,
  `android/app/build.gradle.kts:128-131`), LTO and `panic = "unwind"` (`Cargo.toml:21-25`).
- The `cdylib` **does not include** `libop_core.rlib` as a separate library: `op-core` is inside.
- **Compiled for the target: 73 units.** They include crates that only exist because of the
  `cargo-metadata` feature of `uniffi` (`cargo_metadata`, `camino`, `cargo-platform`, `semver`, `tempfile`,
  `fastrand`, `rustix`, `errno`, `linux-raw-sys`, `typed-path`): `cargo tree -i tempfile --target
  aarch64-linux-android` shows them hanging off `uniffi` (`uniffi_pipeline` → `uniffi_meta` →
  `uniffi_macros`). **None of them leaves a trace in the binary**: `strings -a libop_ffi.so | grep -c
  'cargo_metadata\|camino\|tempfile'` gives **0**. They are removed by LTO; the evidence is the absence of
  strings, not a symbol analysis.
- **Visible in the binary (arm64): 23 crates**: `aes`, `anyhow`, `argon2`, `base64`, `blake2`, `bytes`,
  `cipher`, `crc32fast`, `flate2`, `hashbrown`, `hex`, `hkdf`, `indexmap`, `itoa`, `memchr`,
  `quick-xml`, `serde_core`, `serde_json`, `tinyvec`, `unicode-normalization`, `uniffi_core`, `zip`,
  `zlib-rs`. It is a **minimum**: a dependency without *panic* paths (for example `sha2`,
  `chacha20poly1305`) does not appear even if it is linked.
- **Not linked** (compiler only or build-machine tool): `uniffi_bindgen`,
  `askama`, `basic-toml`, `clap` (from `uniffi` with `cli`), `syn`, `proc-macro2`, `quote`. The bindgen
  runs with `cargo run --features bindgen` (`build.gradle.kts:155`).
- **Size** (`unzip -l android/app/build/outputs/apk/release/app-release.apk`): `libop_ffi.so`
  1 153 984 B (arm64-v8a), 882 924 B (armeabi-v7a) and 1 313 032 B (x86_64). Unstripped, in
  `build/rust/jniLibs`: 1 565 832, 1 197 124 and 1 610 976 B. The commit message `700f1a7` gives 9.3%
  on aarch64 due to `unwind`; it has not been measured again.

### 2.3 Duplicates and advisories

| Package | Versions | Path | Effect |
|---|---|---|---|
| `getrandom` | 0.2.17 and 0.3.4 | 0.3.4: direct from `op-core`. 0.2.17: via `rand_core` 0.6 → `crypto-common` 0.1.7 → the whole RustCrypto 0.1x family (`aead`, `cipher`, `digest`, `universal-hash`) | Two copies of the CSPRNG access in the binary (the 0.2 one only with the `getrandom` feature of `rand_core`, without verifying whether it is linked) |
| `syn` | 2.0.119 and 3.0.9 | Both only in build tools (`proc-macro`) | None in the binary |

`cargo deny` flags them as `warn` (`deny.toml`: `multiple-versions = "warn"`). `wildcards = "warn"` and not
`deny` because `op-ffi` and the CLI declare `op-core = { path = … }` without `publish = false` (comment in
`deny.toml`).

**Ignored advisory**: `RUSTSEC-2026-0374` (`basic-toml` 0.1.10, unmaintained) in
`deny.toml`. Only `uniffi_bindgen` → `askama` pulls it in, which is not in the Android target graph
(`cargo tree -p op-ffi --target aarch64-linux-android` does not contain it; it is in `Cargo.lock:167`).
`cargo audit` (without `.cargo/audit.toml`, deleted in `a3daf4e`) returns 0 vulnerabilities.

### 2.4 Licenses versus GPL-3.0-or-later

From `cargo metadata` over the 136 crates.io packages:

| License (SPDX) | Packages |
|---|---|
| `MIT OR Apache-2.0` | 82 |
| `MIT` | 17 |
| `Apache-2.0 OR MIT` | 12 |
| **`MPL-2.0`** | **8** (`uniffi`, `uniffi_bindgen`, `uniffi_core`, `uniffi_internal_macros`, `uniffi_macros`, `uniffi_meta`, `uniffi_pipeline`, `uniffi_udl`) |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 5 |
| `MIT/Apache-2.0` | 3 |
| `Apache-2.0` | 2 |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 2 (`unicode-ident`, `unicode-normalization`) |
| `Unlicense OR MIT` | 1 (`memchr`) |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 1 (`r-efi`, UEFI only) |
| `BSD-3-Clause` | 1 (`subtle`) |
| `Zlib OR Apache-2.0 OR MIT` | 1 (`tinyvec`) |
| `Zlib` | 1 (`zlib-rs`) |

- **Compatibility**: MIT, BSD-3-Clause, Zlib, Unicode-3.0 and Apache-2.0 are compatible with GPL-3.0; MPL-2.0
  allows distribution under GPL (its "secondary license" clause). `cargo deny list` groups
  6 MPL-2.0 packages (without `uniffi_bindgen` or `uniffi_udl`, which are only in tools). **This is not
  legal advice**: it is a reading of the SPDX metadata.
- **No incompatible license** in `cargo deny` (`licenses ok`) with the 10 allowed licenses of
  `deny.toml`.
- **The allowed-license list is wider than needed**: removing `Unlicense`,
  `Apache-2.0 WITH LLVM-exception` and `LGPL-2.1-or-later` the result is still `licenses ok`
  (tested with a copy of `deny.toml` in a temporary path, `cargo deny --locked --config … check
  licenses`). The three only appear as an alternative in an `OR` disjunction that is already satisfied with MIT or Apache. This
  matters because of `LGPL-2.1-or-later`: it opens a door that `deny` does not need. It is a **decision on
  the final list** (no. 7, [`decisions.md`](decisions.md))).

### 2.5 Rust pins and tools

| Item | Pin | Where |
|---|---|---|
| Compiler | `1.99.1` exact, with `rustfmt`, `clippy` and the three Android targets | `rust-toolchain.toml` |
| `zip` | `=9.0.3` (comment: «newer 9.1.x releases are under two weeks old») | `core/Cargo.toml` |
| Resolution | versioned `Cargo.lock`; `--locked` in `cargo test`, `clippy`, `build`, `deny` and in the Gradle task (`build.gradle.kts:135`) | `ci.yml` |
| `cargo-ndk` | `--locked --version 4.1.2` | `ci.yml` |
| `cargo-cyclonedx` | `--locked --version 0.5.9` | `ci.yml`, `release` job |
| `cargo-deny`, `cargo-fuzz` | `0.20.2`, `0.13.2` via `taiki-e/install-action` | `ci.yml`, `fuzz-nightly.yml` |
| NDK | `30.0.16248370` | `build.gradle.kts:23`, `ci.yml` |
| Actions | 40-character SHA with the version in a comment (7 distinct actions) | `ci.yml`, `fuzz-nightly.yml` |

The rest of the dependencies are *caret* ranges: the `Cargo.lock` is what pins them.
**Limitation**: `cargo install` compiles from crates.io without its own checksum, and
`taiki-e/install-action` downloads binaries; there is no independent verification of what is downloaded
(see 7).

## 3. Gradle

### 3.1 Direct dependencies (`android/app/build.gradle.kts:75-97`, `libs.versions.toml`)

| Dependency | Version | Scope |
|---|---|---|
| Compose BOM + `activity-compose`, `material3`, `material-icons-core`, `ui`, `ui-tooling-preview` | `2026.09.00`; 1.13.0; 1.4.0 (resolved); 1.7.8; 1.12.1 | Release |
| `lifecycle-process`, `lifecycle-runtime-compose` | 2.11.0 | Release |
| `kotlinx-coroutines-android` | 1.11.0 | Release |
| **`jna` `@aar`** | 5.17.0 | Release (Kotlin UniFFI uses it to load the native library) |
| `camera-camera2`, `camera-lifecycle`, `camera-view` | 1.6.2 | Release (QR scanner) |
| `zxing-core` | 3.5.4 | Release (decodes QR; no UI or Google services) |
| `ui-tooling` | (BOM) | `debug` only |
| `junit`, `androidx.test:runner`, `androidx.test.ext:junit` | 4.13.2, 1.7.0, 1.3.0 | Tests |

Build plugins: AGP `9.4.1`, Kotlin Compose `2.4.21`, `org.cyclonedx.bom` `3.5.1`. Gradle `9.8.2` with
`distributionSha256Sum` (`gradle-wrapper.properties`).

### 3.2 What ends up in the APK (SBOM of `releaseRuntimeClasspath`, 144 components)

| Group | Components |
|---|---|
| `androidx.*` | 117 (of which `androidx.compose.*` 37, `androidx.lifecycle` 18, `androidx.camera` 8) |
| `org.*` (Kotlin, `kotlinx`, `checker-qual`, `jspecify`, `annotations`) | 15 |
| `com.*` (`google.guava` 3, `google.zxing`, `google.dagger`, `google.errorprone`, `google.j2objc`, …) | 9 |
| `net.java.dev.jna`, `jakarta.inject`, `javax.inject` | 3 |

- **Native code in the APK**: `libop_ffi.so` and **`libjnidispatch.so` from JNA** (165 992 B arm64, 116 344 B
  armv7, 116 904 B x86_64), three ABIs (`unzip -l app-release.apk`). `abiFilters` drops the others.
- **Bundled data** (release APK): `public_suffix_list.dat` (338 012 B, MPL-2.0, `README.md:58`) and
  `assets/eff_large_wordlist.txt` (62 144 B, EFF Large Wordlist, **CC BY 3.0 US** per `README.md:57`).
- **Unused surface**: `androidx.media3:media3-common`, `-container` and `-muxer` and
  `androidx.camera:camera-video` arrive through CameraX for video, which the app does not use (the manifest removes
  `ACCESS_NETWORK_STATE`, which media3 pulls in). **Unverified** whether they can be excluded without breaking the
  scanner.
- **Gradle with no vulnerability analysis**: neither in CI nor locally. `cargo audit` and `cargo deny`
  cover Rust only. `guava 33.3.1-android`, `dagger 2.59` and `jna 5.17.0` have not been compared with any advisory
  database in this review.

### 3.3 Dependency verification

`android/gradle/verification-metadata.xml` (`a3daf4e`): `verify-metadata` active, **without signatures**
(`verify-signatures` set to `false`), **478** components and **918** SHA-256 sums, **133** groups, and
`aapt2` for **Linux and macOS** (`com.android.tools.build:aapt2:9.4.1-15978811`, `linux` and `osx` jars).
It covers the build plugins in addition to the libraries. **No build has been run with
verification active in this review** (there is no JDK in the `PATH`): whether the file
is complete is unverified. CI will check it when building on Linux.

### 3.4 Gradle licenses (from the SBOM)

All components are `Apache-2.0`, except: `androidx.camera:camera-core` (`Apache-2.0`,
`BSD-3-Clause`), `org.checkerframework:checker-qual` (`MIT`) and **`net.java.dev.jna:jna`
(`LGPL-2.1-or-later` and `Apache-2.0`, dual license)**. Apache-2.0 can be chosen, compatible with
GPL-3.0; if LGPL is chosen, it is also compatible. The `README.md` («Third-party components» section, lines 57-58) **does not mention JNA**: only the EFF
list and the suffix list. It must say which one applies. Also, **unverified** whether CC BY 3.0 US (EFF list)
is compatible with GPL-3.0: the FSF only recognises CC BY 4.0 as compatible, to my knowledge. It is
a data point, not code, but it is worth deciding with the license in front of you.

## 4. Build chain

| Link | Pinning | Weakness |
|---|---|---|
| Source code | Commit and, after ADR-AUD-01, signed tag | — |
| `Cargo.lock` | Versioned, `--locked` | Resolves against crates.io; no local copy (`cargo vendor` is optional) |
| Gradle | exact `libs.versions.toml` + `verification-metadata.xml` + wrapper with checksum | No PGP signatures; JNA and CameraX ship binaries |
| Compiler and NDK | `rust-toolchain.toml` and `ndkVersion` | The NDK download in CI is not checked with a checksum (`sdkmanager`) |
| CI actions | Commit SHA | `dtolnay/rust-toolchain`: SHA of the `stable` branch, not of a version |
| Tool binaries | Version | `taiki-e/install-action` downloads; `cargo install` compiles from crates.io without a checksum |
| Release APK | Provenance attestation (Sigstore) of the **unsigned** APK and of the SBOMs | The signature is added on the maintainer's computer afterwards; **the signed APK is not attested** (see 6) |

## 5. SBOM and attestations: status

- **`release` job** (`ci.yml`, only with `v*` tags; confirmed in `a3daf4e`, **never
  run**): builds the APK, generates `op-ffi.cdx.json` (`cargo cyclonedx --manifest-path
  ffi/Cargo.toml --format json --spec-version 1.5`) and the Gradle SBOM (`cyclonedxDirectBom`,
  `includeConfigs = releaseRuntimeClasspath`), computes `SHA256SUMS` and attests the unsigned APK and the
  two SBOMs with `actions/attest-build-provenance`. Permissions `id-token: write` and `attestations: write`
  only in that job. It uploads the artifact with 90 days retention (`retention-days: 90`, `ci.yml:143`). **It does not create the GitHub
  *release***: attaching the files is a manual step.
- **What the Rust SBOM contains**: the output of `cargo cyclonedx` over `ffi/Cargo.toml`, which
  includes the full `op-ffi` graph and not only what is linked. The files
  `core/op-core.cdx.json` and `cli/opvault-cli.cdx.json` from earlier tests are no longer in the tree and
  `*.cdx.json` is in `.gitignore` (ID-INT-23).
- **What it does not contain**: `libjnidispatch.so` as its own native component, the data lists (public
  suffixes and EFF) or the build tools.

## 6. Proposals

Priority: **P1** before freezing `v0.2.0`; **P2** during the audit; **P3** after.

| Prio. | Proposal | Why | Status |
|---|---|---|---|
| P1 | **Confirm and run once** the `release` job with a test tag (`v0.2.0-rc1`) and `gh attestation verify` | It is the only way to know that the attestation and the SBOMs work; the decision itself requires it (step 17) | pending |
| P1 | Remove `Unlicense`, `Apache-2.0 WITH LLVM-exception` and `LGPL-2.1-or-later` from `deny.toml` | Reduce the list to what is needed (section 2.4, tested) | pending (decision no. 7) |
| P1 | **Human decision**: confirm the license applied to JNA and the compatibility of CC BY 3.0 US (EFF list) with GPL-3.0, and reflect it in the `README.md` | Avoid a license breach | pending |
| P1 | Delete or ignore the `*.cdx.json` of `core/` and `cli/` | Avoid committing SBOMs that are not published | **done** in `a3daf4e` (`.gitignore:5`) |
| P1 | Check the build with `verification-metadata.xml` on Linux and macOS and see that it fails if a sum is altered | It is the proof of step 16 | pending (no JDK on this machine) |
| P2 | Also attest the **signed APK**, or publish the `SHA256SUMS` of the unsigned one and the comparison rule | Today the signature breaks the provenance chain | proposed |
| P2 | Gradle advisory analysis (for example `osv-scanner` over `verification-metadata.xml` or over the SBOM) in CI | Today there is none | proposed |
| P2 | Consider `uniffi = { default-features = false }` with the minimal feature and exclude `media3` from CameraX | Reduce what is compiled and distributed (73 library units; 3 `media3` artifacts) | **unverified** that it compiles and works |
| P2 | Add to the SBOM `libjnidispatch.so`, the public suffix list, the EFF list and the NDK | Complete SBOM of what is shipped | proposed |
| P2 | `cargo vendor` of the workspace at the frozen version, attached to the auditor's package | Offline review of the exact dependency code | Optional in ADR-AUD-01 |
| P2 | `publish = false` in `ffi/Cargo.toml` and `cli/Cargo.toml` and `allow-wildcard-paths = true`; then `wildcards = "deny"` | Close the pending item of `deny.toml` | Comment in `deny.toml` |
| P2 | That Dependabot does not open PRs against `release/0.2` (it only watches the default branch: `.github/dependabot.yml` does not define `target-branch`) | The ADR-AUD-01 policy forbids routine upgrades in the frozen branch | True by default; document it |
| P3 | `cargo vet` for the cryptography dependencies | Human review per version; discarded before the audit | Discarded in ADR-AUD-04 |
| P3 | PGP in `verification-metadata.xml` | Maintaining a keyring; high cost | Discarded |

## 7. What could not be verified

- That Gradle verification is complete and that it fails with an altered sum.
- That the Gradle SBOM covers everything that enters the APK (it is the runtime classpath one, not an
  analysis of the final APK).
- Whether `getrandom` 0.2.17 ends up linked.
- That `taiki-e/install-action` checks the sums of what it downloads.
- That there are no Gradle advisories (it has not been scanned).
- The license that applies to JNA and the compatibility of CC BY 3.0 US with GPL-3.0.

## 8. Commands to reproduce it

```sh
grep -c '^\[\[package\]\]' Cargo.lock fuzz/Cargo.lock           # 139 and 132
cargo metadata --locked --format-version 1 > meta.json          # licenses, duplicates, origins
cargo audit --deny warnings                                     # 0 vulnerabilities
cargo deny --locked check                                       # advisories, bans, licenses, sources
cargo deny --locked list                                        # licenses per package
cargo tree -p op-ffi --locked --target aarch64-linux-android -d # target duplicates
unzip -l android/app/build/outputs/apk/release/app-release.apk | grep -E 'lib/|public_suffix'
strings -a android/app/build/rust/jniLibs/arm64-v8a/libop_ffi.so | grep -oE 'registry/src/[^/]+/[A-Za-z0-9_.+-]+'
python3 -c "import json;print(len(json.load(open('android/app/build/reports/cyclonedx-direct/bom.json'))['components']))"
```
