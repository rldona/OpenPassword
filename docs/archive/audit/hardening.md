# Hardening: done and pending

List of the project's hardening measures with their priority, their status and what verifies them
(commit, test or command). It distinguishes what is **done** (confirmed in `git`), what is **only partly done**,
what is **pending** and what is **postponed or discarded**.

**State at the close of Phase 3 preparation (2026-10-30): hardening applied, 19 steps handled (16 done; 3 pending or partial: 9, 18 and 19) and external audit pending contracting.** What appears here as «without commit» is already in `183598d` and `3868f4f`; the text keeps the original wording.

State verified on 2026-10-30 against `HEAD` `a3daf4e` ("Phase 3: hardening, supply chain and
audit package") **plus uncommitted work** (autofill fixes, KDBX ceiling, `cfg(fuzzing)` guard, and a third block of fixes for ID-INT-02, 03, 06, 08, 09, 10, 11, 12, 14, 17, 18, 21 and 23; documentation; `git status` lists it): what previously appeared as «done, un
confirmed» is already in that commit (or in `700f1a7`, where indicated); what is marked «without commit» is not. The line numbers cited in
`ffi/src/lib.rs` and `VaultSession.kt` were written before the latest fixes and may have
shifted; the name of the test or of the symbol is the stable reference.

**Priority** (of what is left to do, with respect to the `v0.2.0` freeze): **P1** blocks the
freeze or is a defect the auditor will find in the first hour; **P2** is fixed during the
audit; **P3** afterwards.

**Status**: **Done**, **Partial**, **Pending**, **Postponed**, **Discarded**.

The Rust tests have been run in this review (`cargo test --workspace --locked`: 102 pass,
1 ignored: 50 unit tests in `op-core`, 9 + 3 + 19 + 5 integration tests and 16 in `op-ffi`; `cargo deny --locked check` and `cargo deny` over `fuzz/` with `fuzz/deny.toml`: `advisories ok, bans ok, licenses ok, sources ok`). **The Kotlin tests (186 `@Test` in `android/app/src/test`) were run on 2026-10-30 on macOS with JDK 17: 186 pass, 0 fail; the instrumented ones (17 tests) were too, on 2026-10-30 on an SM-S948B (API 37), and they passed; of the manual ones (DT) DT-01, DT-04, DT-05 and DT-07 were run on that device (DT-04 `falla`: ID-INT-14 confirmed; the rest of DT, not run or blocked)** (there is no
JDK on this machine): the rows that depend on them say so.

## 1. ADR-AUD plan: the 19 steps

Reproduces the "Implementation plan" table from [`decisions.md`](decisions.md)) with the real status.

| # | Step | Status | Commit or change | What verifies it |
|---|---|---|---|---|
| 1 | `lock`, `is_locked` and `with` resistant to poisoning | **Done** | `700f1a7` (`ffi/src/lib.rs:302-322`, `437-443`) | `lock_wipes_key_after_poisoned_mutex` (`:705`), `with_after_poison_returns_internal_and_locks` (`:713`) |
| 2 | `panic = "unwind"` and size measurement | **Done** | `700f1a7` (`Cargo.toml:25`) | `cargo build --release`; the commit message gives 9.3% on aarch64 (threshold 15%). **There is no measurement of the other two ABIs** in the commit; in the APK: arm64 1 153 984 B, armv7 882 924 B, x86_64 1 313 032 B |
| 3 | Catch `InternalException` and move the session to `Locked` | **Done** | `700f1a7` (`VaultSession.kt`, `withVault`) and `a3daf4e` (the 4 remaining sites: `ItemDetailScreen.kt`, `ItemEditorScreen.kt`, `AutofillAuthActivity.kt`; [ID-INT-07](internal-review.md#id-int-07))) | `FfiFailureHandlingTest` (7 tests, not run). **Limit**: the test only looks for `catch (e: OpException)` without a broad catch; a site with no `catch` at all would not be seen |
| 4 | Isolated test of `SecretString` | **Done** | `a3daf4e` (`ffi/src/secret.rs`) | Bindings regenerated: `uniffi::custom_type!` with `String`; `debug_hides_the_value`, `zeroize_empties_the_text` |
| 5 | `SecretString` and `Zeroizing` across the whole API | **Done** | `a3daf4e` (`ffi/src/lib.rs`, `ffi/Cargo.toml` +`zeroize`) | `cargo test -p op-ffi` (16 today; 14 when the step was done), `debug_hides_the_value`, `zeroize_empties_the_text`, `secret_strings_cross_records_and_options` (`lib.rs:880`) |
| 6 | `check_within`, `MOBILE_MAXIMUM`, `KdfTooExpensive`, `backup_kdf` | **Done** in `a3daf4e` | `core/src/crypto/kdf.rs:48-66`, `ffi/src/lib.rs:33,472-501` | `check_within_applies_each_axis_of_a_lower_ceiling` (`kdf.rs`), `backup_above_the_mobile_ceiling_fails_fast` (`lib.rs:801`), `mobile_ceiling_is_inclusive` (`:828`), `local_header_above_the_mobile_ceiling_is_refused_before_the_kdf` (`:867`), `backup_kdf_reports_the_header_cost` (`:844`) |
| 7 | Upfront RAM check and message | **Done** in `a3daf4e` for `.opvault`; **extended without commit** to KDBX import (`checkImportKdfFits`, [ID-INT-02](internal-review.md#id-int-02))) | `session/KdfMemory.kt`, `VaultSession.kt:126-129,502-504`, `ui/settings/ExternalImport.kt:57` | `KdfMemoryTest` (6 tests, not run); `import_kdf_reports_the_kdbx_argon2_cost_before_the_kdf` (`ffi/src/lib.rs`, run) |
| 8 | KDBX budget and XML limits | **Done** in `a3daf4e` (its approval, decision no. 4, **still pending human approval**) | `core/src/import/kdbx.rs:36-51` (`MAX_ARGON2_BYTES` 512 MiB and `MAX_ARGON2_WORK` 3 GiB·pass, aligned with the moving ceiling: change **without commit**; `MAX_GROUP_DEPTH` 100, `MAX_XML_DEPTH` 256, `MAX_ENTRIES` 100 000) and `check_argon2_cost` (`:544`) | `argon2_budget_accepts_the_edge_and_refuses_above_it`, `deep_group_nesting_is_refused_before_it_costs_memory`, `nesting_and_entry_limits_accept_their_edge` (memory goes from quadratic to linear; see [ID-INT-01](internal-review.md#id-int-01))) |
| 9 | Protection against *overlays* (A7) | **Partial** | `700f1a7` (`OverlayProtection.kt`, `ProtectedAlertDialog` in `Components.kt:187-205`, manifest, `VerifyManifest` in `build.gradle.kts:174-176`) | `OverlayProtectionTest` unit (6) and instrumented (4 `@Test` after the uncommitted block: `MainActivity`, `AutofillAuthActivity`, `SaveLoginActivity` and one `ProtectedAlertDialog`; **run and green** on SM-S948B, API 37, 2026-10-30; DT-01 `pasa` only in `MainActivity`); **missing** the banner in the two autofill activities (there is only a `Toast`) and DT-02/DT-03 on API 28-30 and dialogs ([ID-INT-13](internal-review.md#id-int-13)), fixed and verified on device in what the test covers) |
| 10 | Root detection (A10) | **Done** | `700f1a7` (`RootSignals.kt`, `AndroidDeviceProbe.kt`, `<queries>`, `RootWarning` in `Components.kt:226`) | `RootDetectorTest` (10 tests, not run) |
| 11 | `cfg(fuzzing)` hooks and targets with *seeds* | **Done** | `a3daf4e`: `core/src/lib.rs`, `vault/mod.rs`, `backup/mod.rs`, `import/kdbx.rs` (`fuzzing` module), `fuzz/`: 6 new targets (`vault_json`, `item_open`, `item_plaintext`, `backup_body`, `ffi_records`, `kdbx_container`) on top of the 5 in `4e7fef0`: **11 in total** | `cargo +nightly fuzz build` (not run here); `strings` on `libop_ffi.so`: 0 hook symbols ([`fuzzing.md`](fuzzing.md)) §2). **Without commit**: `compile_error!` guard in `core/src/lib.rs:20-22` for `cfg(fuzzing)` without `debug_assertions` (`release` build), which did not replace the check on the `.so` (now `scripts/check-no-fuzzing-hooks.sh` with `HOOKS_MARKER` and positive and negative controls, integrated into CI, not run there: [ID-INT-21](internal-review.md#id-int-21)), fixed) |
| 12 | Nightly fuzzing | **Done** | `a3daf4e`: `.github/workflows/fuzz-nightly.yml` (11 targets, 10 min each) | **No run** on GitHub; the green `workflow_dispatch` is missing |
| 13 | `LoginMatcher` invariant tests | **Done** in `a3daf4e` | `LoginMatcherTest.kt` (+232 lines; 29 tests; `Random(20260630)`, `Random(7)`) | Not run here |
| 14 | `cargo-deny` | **Done** in `a3daf4e` | `deny.toml`, `.github/workflows/ci.yml` (`audit` job), `.cargo/audit.toml` deleted | `cargo deny --locked check` → `advisories ok, bans ok, licenses ok, sources ok` (run) |
| 15 | Actions by SHA, Dependabot, pinned versions | **Done** in `a3daf4e` | `ci.yml`, `fuzz-nightly.yml`, `.github/dependabot.yml` | `grep -n "uses:" .github/workflows/*.yml`: all with a 40-character SHA and the version in a comment; `tool: cargo-deny@0.20.2`, `cargo-fuzz@0.13.2`; `cargo-ndk` 4.1.2, `cargo-cyclonedx` 0.5.9 |
| 16 | Gradle dependency verification | **Done** in `a3daf4e` | `android/gradle/verification-metadata.xml` (478 components, 918 sums, `aapt2` for Linux and macOS) | **No build has been run** with verification active; proving that it fails with an altered sum is still missing |
| 17 | `release` job: SBOM and attestation | **Done** in `a3daf4e` | `ci.yml` (`release` job), `build.gradle.kts` (CycloneDX plugin 3.5.1) | **Never run.** Missing `v0.2.0-rc1` and `gh attestation verify` |
| 18 | Documentation | **Partial** | `docs/crypto-spec.md` §5 (platform ceiling, `a3daf4e`); `android/README.md` (permissions and anti-tapjacking, `700f1a7`; `a3daf4e`); `docs/threat-model.md` (A7 and A10 implemented, new rows A17 and A18 and secret residues), `SECURITY.md` (`release/0.2`) and `fuzz/README.md` (30 s, 11 targets, KDBX budget): updated with this documentation package (not committed yet) | **Pending**: `docs/crypto-spec.md` §10 (`SecretString`, residues) |
| 19 | Version 0.2.0, branch `release/0.2`, signed tag and package | **Pending** (it does not depend on the F-Droid release, which is paused: the audit uses a GitHub pre-release) | `Cargo.toml` is still at `0.1.0` (`version.workspace`), `build.gradle.kts:29-30` at `versionCode = 1`, `versionName = "0.1.0"` | `git branch --list 'release/*'` empty |

## 2. Measures already in place inherited from previous work

They existed before this phase and are still in the tree. The commit is the first one that adds the code, according to
`git log -S`.

| Measure | Status | Commit | What verifies it |
|---|---|---|---|
| `unsafe_code = "forbid"` across the whole workspace | Done | `7d27845` | `Cargo.toml:13`; `grep -rn unsafe core/src ffi/src cli/src` returns nothing |
| Input limits (`MAX_INPUT` 32 MiB, bounded `.1pux`, bounded gunzip) | Done | `25731fc` (importers) | `core/src/import/mod.rs:34,504-512`, `kdbx.rs:331-337` |
| `check_bounds` before the KDF | Done | `7d27845` | `kdf.rs:48`; test `bounds_reject_costly_or_invalid_params` |
| No network and no system backup; permissions required at build time | Done | `e62bc09` | `VerifyManifest` (`build.gradle.kts:163-180`) on every `assemble` |
| `FLAG_SECURE` in the three activities | Done | `e62bc09` (main) | `grep -rn FLAG_SECURE android/app/src/main` (3 matches) |
| `secure_delete` in SQLite | Done | `e62bc09` | `ItemDatabase.kt:15-19` |
| Keystore keys (device and biometric) with invalidation on new biometric enrolment | Done | `28fcc5e` (biometrics) | `BiometricKeyStore.kt:40-56` |
| Exponential wait after failures | Done | `c69f81e` | `VaultSession.kt:477-481`; `UnlockBackoffTest` |
| Exclusion of the system autofill from our own windows | Done | `bb4b543` | `AutofillExclusion.kt:11-13` |
| «sensible» mark (API 33+) and clipboard wipe | Done the mark; **the wipe: failure confirmed on device and accepted as residual risk** (2026-10-30, API 37: it does not wipe with the app in the background; mitigation in uncommitted code with a persisted deadline and a `Handler`, **not verified**) | `e62bc09`; mitigation without commit (`ClipboardClearPolicy.kt`) | `SensitiveClipboard.kt`, [ID-INT-14](internal-review.md#id-int-14)) (accepted as residual risk) |
| Automatic lock for the whole process | Done | `ccef635` | `VaultSession.kt:386-425`, `OpenPasswordApp.kt:69-83` |
| Random token for saving logins | Done | `4038ae2` | `PendingSaves.kt` (expiry with sweep and wipe on lock, without commit: [ID-INT-17](internal-review.md#id-int-17)), fixed) |
| Fuzzing of 5 targets and `SECURITY.md` | Done | `4e7fef0` | `fuzz/`, `SECURITY.md` |

## 3. Other measures of this phase not listed as steps

| Measure | Status | Where | What verifies it |
|---|---|---|---|
| Public suffix list in autofill (`LoginMatcher` with `PublicSuffix`) | **Done** in `a3daf4e` | `autofill/PublicSuffix.kt`, `LoginMatcher.kt:43-48`, `resources/public_suffix_list.dat` (338 012 B, version `2026-10-28_13-15-55_UTC`) | `LoginMatcherTest` (29); resource present in `app-release.apk`; loading and application **verified on device** in the debug build (DT-05 `pasa`, 2026-10-30, API 37); **not verified** with R8 and with no update process ([ID-INT-20](internal-review.md#id-int-20)), open) |
| `HIDE_OVERLAY_WINDOWS` required by `VerifyManifest`; `<queries>` with 6 packages; `QUERY_ALL_PACKAGES` forbidden | **Done** | `build.gradle.kts:174-177`, `AndroidManifest.xml:11-24` | The build fails if one is missing or extra |
| `Vault::unlock` no longer passes `E::KdfParams` to `Internal` | **Done** in `a3daf4e` | `ffi/src/lib.rs:69` | Ceiling test (`:801`) |
| `README.md` with "Third-party components" (EFF, public suffixes) | **Done** in `a3daf4e` | `README.md:57-58` | No mention of JNA (see [`dependencies.md`](dependencies.md)) §3.4) |

## 4. Pending

### 4.1 Defects found in this review ([`internal-review.md`](internal-review.md)))

| Prio. | ID | Measure | Status |
|---|---|---|---|
| ~~P1~~ | ID-INT-16 | Accept `webDomain` only from browsers | **Done** in `a3daf4e` (`autofill/BrowserCheck.kt`, `StructureParser.targetFor`) and **completed without commit**: the first version accepted any app with an `https`/`http` `intent-filter`; now only `KnownBrowsers.PACKAGES` or the default browser that handles both schemes (`BrowserCheck.kt:68-73`); ASCII host in `LoginMatcher.kt:67-76`; `PublicSuffix` fails closed on `IOException`. `BrowserCheckTest` (13 `@Test`) and `LoginMatcherTest` (30), not run. The `iframe` hypothesis and part of the device test remain: **verified on device** that a non-browser app with a `webDomain` is ignored ([DT-07](device-tests.md#dt-07)) `pasa`, 2026-10-30, API 37) and that the suffix list loads and is applied ([DT-05](device-tests.md#dt-05)) `pasa`); **not run** [DT-06](device-tests.md#dt-06)) and [DT-08](device-tests.md#dt-08)) |
| ~~P1~~ | ID-INT-26 | So that the autofill destination does not travel in the extras of the mutable `PendingIntent` | **Done, without commit**: random 16-byte token, single-use, 5 min TTL (`AutofillRequestTokens.kt`); `AutofillAuthActivity.kt:87-98` wipes the old extras and fails closed; "remember" is not offered in browsers (`:102,124`). `AutofillRequestTokensTest` (7 `@Test`), not run. No device test |
| ~~P1~~ | ID-INT-05 | Close the `Vault` on the three unlock paths that fail after opening it | **Done** in `a3daf4e` (`VaultSession.discardOnFailure`); `FfiFailureHandlingTest` tests the helper function, not the three paths; `failedRestoreLeavesNoVaultBehind` (instrumented) green on SM-S948B, API 37, 2026-10-30. **Without commit**: `create()` also releases the `Vault` if persistence fails (`VaultSession.kt:94-101`) |
| ~~P1~~ | ID-INT-01 | Remove the quadratic memory from `read_entries` and put a depth cap; seed and test | **Done** in `a3daf4e` (`MAX_GROUP_DEPTH` 100, `MAX_XML_DEPTH` 256, `MAX_ENTRIES` 100 000); tests `deep_group_nesting_is_refused_before_it_costs_memory`, `nesting_and_entry_limits_accept_their_edge`; seeds in `fuzz/seeds/kdbx_xml/` |
| ~~P1~~ | ID-INT-14 | Test the clipboard wipe on API 29, 33 and 36 and fix it | **Accepted as residual risk** (owner's decision, 2026-10-30). Failure **confirmed on device** on API 37 ([DT-04](device-tests.md#dt-04)): it is not wiped with the app in the background; it is in the foreground): Android limitation, `clearPrimaryClip()` has no effect in the background. Mitigations: sensitive mark, wipe after 30 s in the foreground, wipe when returning to the app and when the screen turns off (`ClipboardClearPolicy.kt`, `ClipboardClearPolicyTest` 7, not run; the last two **not verified on device**), honest message in the app; the copy button is not removed. It was not tested on API 29, 33 and 36 or DT-04c/d |
| ~~P1~~ | ID-INT-25 | `cfg(fuzzing)` hook for `kdbx::parse` (fixed password and KDF) and fix the README | **Done** in `a3daf4e` (`kdbx_fuzzing::{file, container}`, target `kdbx_container`); README fixed (not committed yet) |
| ~~P2~~ | ID-INT-07 | Catch `InternalException` at the 4 sites and extend the test | **Done** in `a3daf4e` the 4 sites; **pending** extending the test to detect a site with no `catch` at all |
| ~~P2~~ | ID-INT-02 | Decide the KeePass KDF policy against the mobile ceiling (human decision no. 3-4) | **Done, without commit**: KDBX ceiling equal to the mobile one (512 MiB / 3 GiB·pass), `importKdf`/`kdbx_argon2_cost` and `checkImportKdfFits` before asking for the password. **Approved on 2026-10-30** (decision no. 4); `KdfMemoryTest` run and green |
| ~~P2~~ | ID-INT-08 | `lock()` coordinated with `mutex`, or `IllegalStateException` as `Locked` | **Done, without commit** (`KeyHolder.kt`, `AtomicReference`; `KeyHolderTest` 7, not run; instrumented test `locksInTheBackgroundWithoutComingBack` green on SM-S948B, API 37, 2026-10-30) |
| ~~P2~~ | ID-INT-17 | Empty `PendingSaves` on lock and real expiry | **Done, without commit** (`PendingStore`, sweep, `session.onLocked`; `PendingStoreTest` 6, not run) |
| ~~P2~~ | ID-INT-21 | Replace the README symbol check with the `.so` one with a positive control | **Done, without commit** (`HOOKS_MARKER`, `scripts/check-no-fuzzing-hooks.sh`, CI; **not run in CI**) |
| ~~P2~~ | ID-INT-06 | Decide what to do with an unreadable item | **Done, without commit** (skip and warn: `EntryLoading.kt`, `Unlocked.unreadable`; `EntryLoadingTest` 4, not run) |
| ~~P2~~ | ID-INT-09 | Count attempts in `verifyPassword` | **Done, without commit** (`AttemptLimiter`; `AttemptLimiterTest` 5, not run; instrumented test `wrongPasswordsTriggerTheWait` green on SM-S948B, API 37, 2026-10-30) |
| ~~P2~~ | ID-INT-12 | Read the file without intermediate plaintext copies | **Done, without commit** (`ui/WipingRead.kt`; `WipingReadTest` 5, not run) |
| **P2** | ID-INT-13 | Banner in the autofill activities and instrumented tests of activities and dialogs | **Fixed and verified on device** (2026-10-30): 4 instrumented `@Test` green and DT-01 `pasa` in `MainActivity`; the banner in the autofill activities is still **pending**, and DT-02/DT-03 blocked or not run |
| ~~P3~~ | ID-INT-03 | Document the importer residues | **Done, without commit** (`Zeroizing` and wipe in `import/mod.rs`, `kdbx.rs`, `totp.rs`; residues in `docs/threat-model.md`) |
| ~~P3~~ | ID-INT-18 | Iterative traversal with a cap in `StructureParser` | **Done, without commit** (`TreeWalker.kt`, depth 100 and 20 000 nodes; `TreeWalkerTest` 6, not run) |
| **P3** | ID-INT-10, 11, 22, 23 | Minor robustness and cleanup | **Done, without commit**: ID-INT-10 (`AtomicWrite.kt`, `fd.sync()`; residue: directory fsync) and 11 (`AutoBackup` rethrows `CancellationException`). **Partial**: 23 (`fuzz/deny.toml` and the CI step done; the NCSA licence was **approved by the owner on 2026-10-30**). **Pending**: 22 (open) |
| P3 | ID-INT-24 | Fix `fuzz/README.md` (30 s and KDBX limits) | **Done** (documentation, not committed yet) |

### 4.2 Pending from the plan and from the freeze

| Prio. | Measure | Status |
|---|---|---|
| ~~P1~~ | Confirm what was "unconfirmed" | **Done** in `a3daf4e` (this documentation update remains to be confirmed) |
| **P1** | Run the `release` job once with `v0.2.0-rc1` and `gh attestation verify` | **Pending** |
| **P1** | Run `fuzz-nightly.yml` once with `workflow_dispatch` | **Pending** |
| **P1** | Build with Gradle verification active on Linux and macOS; alter a sum and see the failure | **Pending** |
| **P1** | Run `./gradlew :app:testDebugUnitTest` and the instrumented `OverlayProtectionTest` and `VaultSessionTest` on an emulator | **Done** (`:app:testDebugUnitTest` run on 2026-10-30: 186 pass, 0 fail; the instrumented `OverlayProtectionTest` and `VaultSessionTest` were run on 2026-10-30 on an SM-S948B, API 37, and passed; not on an emulator) |
| **P1** | Update `docs/threat-model.md` according to [`threat-model-review.md`](threat-model-review.md)) §5 | **Partly done**: A7 and A10 implemented, row A17 and secret residues; the rest of [`threat-model-review.md`](threat-model-review.md)) §5 has not been reviewed here |
| **P1** | `docs/crypto-spec.md` §10 (`SecretString`, residues) | **Pending** (`SECURITY.md` already mentions `release/0.2`) |
| **P1** | Version `0.2.0`, branch `release/0.2`, signed tag, `retention-days` or attach to the release | **Pending** (steps 19 and ADR-AUD-01 migration) |
| **P1** | Human decisions from the final list in [`decisions.md`](decisions.md)): no. 1-10 (no. 3 is already marked "still pending human approval") | **Pending**, except those taken on 2026-10-30 outside that list (NCSA licence, ID-INT-14 accepted, F-Droid paused; see [`README.md`](README.md))) |
| **P1** | Decision on JNA and CC BY 3.0 US versus GPL-3.0 | **Pending** ([`dependencies.md`](dependencies.md)) §3.4) |
| **P2** | Remove `Unlicense`, `Apache-2.0 WITH LLVM-exception` and `LGPL-2.1-or-later` from `deny.toml`; `publish = false` and `wildcards = "deny"` | **Pending** |
| ~~P2~~ | Delete or ignore `core/op-core.cdx.json` and `cli/opvault-cli.cdx.json` | **Done** in `a3daf4e` (`.gitignore:5`) |
| **P2** | Attest or hash the **signed** APK; write the procedure for rotating and backing up the signing key | **Pending** |
| **P2** | Real timing measurement and fuzzing runs; `backup_header` with `check_within(MOBILE_MAXIMUM)` | **Pending** (the nested-group seeds already exist) |
| **P2** | Gradle warning analysis in CI | **Pending** |

## 5. Postponed or discarded (recorded decisions)

| Measure | Status | Where | Reason |
|---|---|---|---|
| Opaque session (ADR-AUD-02, option D): the plaintext does not leave Rust | **Postponed** | [`decisions.md`](decisions.md)) | It forces a redesign of the UI and of autofill; it does not fit in a frozen release |
| Jazzer for the autofill Kotlin | **Postponed** | ADR-AUD-05 | `AssistStructure` and JUnit 5 ([`fuzzing.md`](fuzzing.md)) §4) |
| ClusterFuzzLite | **Postponed** | ADR-AUD-05 | One more secret and a Dockerfile |
| OSS-Fuzz | **Discarded** | ADR-AUD-05 | Disclosure schedule and user base |
| `cargo-vet` | **Discarded for now** | ADR-AUD-04 | Maintenance cost for a single person |
| PGP signatures in Gradle verification | **Discarded** | ADR-AUD-04 | Maintaining a keyring |
| KDF ceiling per ABI (32-bit 256 MiB / 3 / 4) | **Alternative not decided** | ADR-AUD-07, decision no. 3 | Different behaviour between devices |
| Lock when root is detected | **Discarded** | ADR-AUD-06 | False positives (ROM without root) and evasion (hidden Magisk) |
| KDF in another process or `argon2` with fallible allocation | **Not planned** | Open risks in [`decisions.md`](decisions.md)) | The only way to fully close the out-of-memory abort |
| Cryptographic erasure of items | **Not planned** | [`threat-model-review.md`](threat-model-review.md)) §3.4 | It requires rotating the item key and rewriting the vault |

## 6. How to check what is "done"

What **cannot** be checked in the JVM or in CI (anti-tapjacking, clipboard in the background, suffix
list and browsers on a device, biometrics on API 28, real KDBX 4, automatic lock…) has its plan in
[`device-tests.md`](device-tests.md)). It is **partly run** (session closed on 2026-10-30, a single device, API 37): DT-01, DT-04 (`falla` in the background: ID-INT-14, accepted as residual risk), DT-05 (debug only) and DT-07 have a result; DT-02 and DT-12 are blocked and the rest, pending. What is pending requires an emulator or an API 28 device and does not block contracting the audit.

```sh
cargo test --workspace --locked                      # 102 pass, 1 ignored
cargo deny --locked check                            # advisories, bans, licenses, sources ok
cargo deny --manifest-path fuzz/Cargo.toml --locked --config fuzz/deny.toml check   # same (fuzz/)
scripts/check-no-fuzzing-hooks.sh --self-test        # positive and negative controls (builds op-ffi; not run here)
cargo audit --deny warnings                          # no vulnerabilities
git status --short                                   # what is uncommitted
grep -n "uses:" .github/workflows/*.yml              # all with SHA
grep -rn "catch (e: OpException)" android/app/src/main   # each one with InternalException next to it
scripts/check-no-fuzzing-hooks.sh android/app/build/rust/jniLibs/arm64-v8a/libop_ffi.so   # "ok … no fuzzing hooks (control string present)"
unzip -l android/app/build/outputs/apk/release/app-release.apk | grep -E 'lib/|public_suffix'
```
