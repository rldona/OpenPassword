# Critical review of the threat model

Review of [`../threat-model.md`](../../threat-model.md)) (v1, 48 lines) against the repository code.
It does not modify `threat-model.md`: section 5 lists the changes that would have to be applied.

> **Update after `a3daf4e`.** Changes 1 (A7), 3 (A10), 4 (with a new row A17 instead of extending A12; ID-INT-16 is fixed) and 13 (secret and importer residues) have been applied in `threat-model.md`. The others are still unapplied. The sections that describe ID-INT-01 and ID-INT-16 (and row A12 of section 2) reflect the state **before** `a3daf4e`, where both were fixed. The numbering of the new rows in section 5 (point 10) is no longer valid: A17 is now "App that declares a website's domain". A18 ("Filled app that triggers the authentication `PendingIntent`", ID-INT-26) was also added, also uncommitted.

State verified on 2026-10-30 against the working tree (`HEAD` `700f1a7` plus uncommitted changes,
which have since been in `a3daf4e`; see [`hardening.md`](hardening.md))). The `ID-INT-nn` findings are in
[`internal-review.md`](internal-review.md)). Claims that cannot be checked without a
device are marked **unverified**.

## 1. Summary

- The document **is no longer faithful to the code** in two rows: A7 and A10 still say "Planned, not yet
  implemented" and both defenses have existed since `700f1a7` (`OverlayProtection.kt`, `RootSignals.kt`).
- One row claims something the code **does not honour**: A12 says "exact package name (verified
  by Android) in apps" and treats it as a general guarantee, but autofill trusts the
  `webDomain` that any app declares (ID-INT-16).
- A defense the document takes for granted **may not work in the main use case**: the
  clipboard wipe (A7) does nothing if the app no longer has focus (ID-INT-14, unverified on
  device).
- At least 16 attacks or risks are missing (section 3). The nine that were expressly requested
  are all there; each one states what exists in the code today and what remains to be decided.
- There are implicit assumptions that change the outcome of the analysis (section 4), the most important: that
  the attacker never controls a **document provider**, an **installed app** that the user
  opens, or the **maintainer's computer**.

## 2. What it claims versus what exists

Verdict: **True** (the code backs it), **Partial**, **Outdated** (the text is older than the
code), **Incorrect** (the code contradicts it) or **Unverified**.

### 2.1 Assets and assumptions

| Text in `threat-model.md` | Verdict | Evidence and nuance |
|---|---|---|
| Assets: secrets, metadata, access credentials, backups | Partial | Missing **the APK signing key** and **the emergency kit** (it contains the SK in plaintext, `EmergencyKit.kt:31-39`). See 3.7 and 3.5 |
| Assumption: OS and hardware not compromised | True, but incomplete | It does not cover other apps (they are indeed untrusted in autofill), the keyboard or document providers |
| Assumption: the CSPRNG works | True | `getrandom::fill` (`core/src/crypto/rng.rs:4-6`); a failure returns `Error::Rng` and it does not continue |
| Assumption: the user keeps the master password or the kit | True | No recovery. In addition, **there is no password change in the app**: `rekey` exists in `op-core` (`vault/mod.rs:144`) and is not in `op-ffi` or in the UI (`grep -rn rekey ffi android` returns nothing). The "residual risk" of "backups with old credentials" describes a feature that cannot be used. The specification (§8) says the app MUST warn; there is no feature to warn with |

### 2.2 Attackers and defenses

| # | Declared status | Verdict | Evidence and nuance |
|---|---|---|---|
| A1 | Protected | True | Header with no user data (`vault/mod.rs:21-33`); encrypted items (`ItemDatabase.kt:9-12`); SK sealed with Keystore (`DeviceKeyStore.kt`). **Nuance**: the `id` and the `revision` of each item are in plaintext, and the existence and number of items are visible. Not mentioned |
| A2 | Protected | Partial | Exponential wait: 4 free attempts, then 30 s doubling up to 1 h (`VaultSession.kt:477-481`, test `UnlockBackoffTest`). It only covers `unlock`; `verifyPassword` neither counts nor waits (`:201-210`, ID-INT-09). Biometrics fall back on the system limit |
| A3 | Protected | True with a condition | "Without the SK, trying passwords is useless" only holds as long as the SK does not leak. It leaks through **the emergency kit in plaintext** (3.5) and it is **on the phone** sealed with Keystore. Minimum Argon2id allowed for new vaults: 64 MiB / 2 / 1 (`kdf.rs:33`) |
| A4 | Protected | Partial | "It only sees an authenticated blob": true for reading. It does not consider that the provider **writes, replaces or deletes** (3.2) or that `AutoBackup` **deletes** old copies by name pattern (`AutoBackup.kt:143-145`) |
| A5 | Protected | True | `body_aad` = SHA-256 of the header region (`backup/mod.rs:46-48`); STREAM with the last chunk marked; AAD per item, revision and part (`vault/mod.rs:63-76`). Tests: `core/tests/backup.rs` (9) |
| A6 | Accepted | Partial | Accepted, but **importing** an old copy of the same vault **resurrects deleted items** (3.2). It is not only "an item to a previous version" |
| A7 | Partial ("Planned, not yet implemented" `filterTouchesWhenObscured`) | **Outdated** | Implemented in `700f1a7`: `filterTouchesWhenObscured`, `setHideOverlayWindows` (API 31+), protected dialogs (`ProtectedAlertDialog`, `Components.kt:187-205`), and the permission required in `VerifyManifest` (`build.gradle.kts:174-176`). Real limits remain: a partially covered touch (`PARTIAL`) is delivered and on API 28-30 `setHideOverlayWindows` does not exist; the warning is a `Toast` once per process in the autofill activities (`OverlayProtection.kt:39,57-62`). **"Sensitive clipboard with wipe": unverified and probably ineffective in the background** (ID-INT-14) |
| A8 | Mitigated | True | `PasswordVisualTransformation` and per-field reveal (`Components.kt:79`) |
| A9 | Mitigated | **Partial** | "`cargo audit`": it has already been replaced by `cargo deny` in the working tree (`ci.yml`, `audit` job). "Reproducible builds": `docs/fdroid/README.md:59-61` says it is **only confirmed when F-Droid builds it**; there is no independent check today. "Few dependencies": 136 third-party crates in `Cargo.lock` and 144 Gradle components in the `releaseRuntimeClasspath` SBOM ([`dependencies.md`](dependencies.md))). It covers dependencies, **not** CI or the signing key (3.8 and 3.7) |
| A10 | Out of scope ("Planned, not yet implemented" the warning) | **Outdated** | Heuristic warning implemented (`RootSignals.kt`, `RootWarning` in `Components.kt:226-237`, `<queries>` in the manifest). The text should say "heuristic warning, no network, that can be bypassed", as ADR-AUD-06 asks |
| A11 | Out of scope | True | There is no decoy or duress password |
| A12 | Mitigated | **Partly incorrect** | Host matching is strict and uses the public suffix list (`LoginMatcher.kt:43-48`, `PublicSuffix.kt`). But a `webDomain` is declared by **any app** and it is not checked that it is a browser (`StructureParser.kt:35,53`, ID-INT-16). "Verified by Android" holds for the **package**, not for the domain |
| A13 | Protected | Partial | 30 s in the background, 3 min if there is a file picker, screen off and 5 min of inactivity (`VaultSession.kt:471-474`). `PendingSaves` is not emptied on lock (ID-INT-17) and a failed unlock leaves the native `Vault` alive (ID-INT-05) |
| A14 | Protected | True | `IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS` in the three activities (`AutofillExclusion.kt:11-13`; calls in `MainActivity.kt:45`, `AutofillAuthActivity.kt`, `SaveLoginActivity.kt`) |
| A15 | Mitigated | Partial | "The bytes read are wiped": `bytes.fill(0)` wipes the final copy (`ExternalImport.kt:50-58,61-63`), but `readBackupFile` leaves another one in the `ByteArrayOutputStream` (`Components.kt:159`) and in Rust the `serde_json::Value` tree, the CSV `String`s and the key file `hex` are not wiped (ID-INT-03, ID-INT-12) |
| A16 | Mitigated | True, with a nuance | Only `otpauth://totp/` (`QrDecoder.kt:49-52`), no network, no frames saved. **Nuance**: the image goes through the system image decoder before ZXing (`QrScanner.kt:163-177`), which is native code not audited here |

### 2.3 Residual risks

| Text | Verdict | Nuance |
|---|---|---|
| Total loss | True | — |
| JVM memory | Partial | Missing: the UniFFI output `RustBuffer` and the Rust `String` copy are freed without wiping (`ffi/src/lib.rs:13-14`, `secret.rs:8-11`, ADR-AUD-02 §6). Also missing the memory of Compose, `PendingSaves` and the `String`s of other managers' exports |
| Size metadata | True | The *padding* is 64 bytes (`padding.rs:7`): it hides the exact length, not the order of magnitude |
| Backups with old credentials | No effect today | There is no password change (see 2.1) |

## 3. Attacks and risks that are missing

Each entry: **what it is**, **what exists today** (with evidence), **gap** and **proposal for
`threat-model.md`**. The first nine (3.1 to 3.9) are the ones that were expressly requested.

### 3.1 Denial of service through parsers

- **What it is**: a hostile file that blocks, hangs or kills the app: `.opvault` copy, KDBX database, CSV,
  JSON, `.1pux`, QR, image or `AssistStructure`. A Rust *panic* and an out-of-memory are not the same thing.
- **Today**: `panic = "unwind"` (`Cargo.toml:25`) plus catching `InternalException` turn the
  *panic* into an error (`VaultSession.kt:434-443`); the mobile KDF ceiling 512 MiB / 6 / 8
  (`ffi/src/lib.rs:33`) and the KDBX budget (today 512 MiB and 3 GiB·pass, `kdbx.rs:36-42`; before 16 GiB·pass) bound the cost; the
  input limit is 32 MiB (`import/mod.rs:34`) and 64 MiB in Kotlin (`Components.kt:171`).
- **Gap**: an **out-of-memory aborts the process** with any *panic* strategy
  (ADR-AUD-03; open risk in [`decisions.md`](decisions.md))). And there is a real DoS, reproduced:
  **quadratic memory in the KeePass XML** (ID-INT-01: 180 KB of XML → 757 MB of RSS). The KeePass KDF
  does not go through the mobile ceiling (ID-INT-02). The body of an `.opvault` copy has no cap in Rust.
- **Proposal**: new row **A17 "Hostile file"**, status "Partial", with the list of limits and the
  caveat of the memory abort.

### 3.2 Rollback and replacement with old copies

- **What it is**: A6 covers replacing an item with a previous version. It does not cover: (a) restoring or
  importing an **old** copy of the same vault, (b) a provider that replaces or deletes files in the
  automatic backup folder, (c) the deletion of items that does not propagate.
- **Today**: `importBackup` merges by revision: if the item does not exist locally it adds it
  (`VaultSession.kt:184`: `mine == null -> upsert; added++`), so **a deleted item comes back** when
  an earlier copy is imported; if the copy's revision is higher, it overwrites (`:185`). There are no
  *tombstones*. `restore` only works with no vault (`:136`).
- **Gap**: the only thing an old copy cannot do is lower the revision of an
  existing item. But **a password the user deleted because it leaked reappears**. In addition
  `AutoBackup` deletes by name (`BackupNames.toDelete`, `AutoBackup.kt:143-145`): a provider that
  writes files with later names pushes the legitimate copies out of the 10 kept
  (hypothesis deduced from the code, **not reproduced**).
- **Proposal**: extend A6: "old copies resurrect deleted items; there are no *tombstones*"; in
  A4 add "a provider with write access can push out or delete copies".

### 3.3 Keyboards that learn and clipboard history

- **What it is**: a third-party IME learns or stores what is typed or copied.
- **Today**: password fields use `KeyboardType.Password` and `autoCorrectEnabled = false`
  (`Components.kt:51-80`, `ItemEditorScreen.kt:261-262`); PINs and card numbers use
  `NumberPassword`. In the rest (title, username, **notes**, URL) the keyboard is a normal text one
  (`ItemEditorScreen.kt:288-294`) and `privateImeOptions` and the custom learning flag are
  **not used** (`grep -rn "privateImeOptions\|NO_PERSONALIZED" android/app/src/main` returns
  nothing). The clipboard carries `EXTRA_IS_SENSITIVE` only from API 33 (`SensitiveClipboard.kt:23-27`).
- **Gap**: **secure notes** (seed phrases, API keys) are typed into a text field that the
  keyboard can learn; and on API 28-32 a clipboard manager or the keyboard sees the copied value without the
  mark (ID-INT-15). Android 10+ only gives the clipboard to the app with focus and to the default IME, which is
  precisely the keyboard.
- **Proposal**: new row **A18 "Third-party keyboard or clipboard manager"**, "Partial", with the
  protected fields and the ones that are not.

### 3.4 WAL and SQLite residues

- **What it is**: data remnants after deleting or editing an item: free pages, rollback journal,
  WAL.
- **Today**: `PRAGMA secure_delete = ON` (`ItemDatabase.kt:15-19`); there is no `enableWriteAheadLogging` or
  `setJournalMode` (`grep -rn "WriteAheadLogging\|journal" android/app/src` returns nothing), so
  the mode is decided by the Android default (**unverified** which one and whether it leaves a persistent
  `-journal` on each version). What is written is encrypted.
- **Gap**: deleting an item **is not a cryptographic erasure**: the item key is wrapped
  with the vault key, which does not change (`update_item` keeps the item key,
  `vault/mod.rs:174-193`). Anyone who keeps an old page, a journal or a disk backup and
  later obtains the vault key decrypts **items that were already deleted**. The
  previous revisions of an edited item are encrypted with the same item key. The exclusion of
  `database` in `data_extraction_rules.xml` prevents them from leaving through the system backup.
- **Proposal**: in "Residual risks": "deleting is not cryptographic erasure; the encryption of
  Android storage is the defense"; check on device the journal mode and the presence
  of `items.db-journal` or `items.db-wal` after deleting.

### 3.5 Emergency kit PDF (the SK in plaintext)

- **What it is**: the kit contains the SK. The model's text does not treat it as an asset or as a risk.
- **Today**: it is generated in memory (`EmergencyKit.pdf` returns a `ByteArray`, `EmergencyKit.kt:31-39`) and
  it is written wherever the user chooses with `CreateDocument` (`SettingsScreen.kt:116-128`,
  `OnboardingScreen.kt:192-203`). The app **does not write to the cache** (`grep -rn
  "cacheDir\|FileProvider\|createTempFile" android/app/src/main` returns nothing). The message says
  "Print it and then delete the PDF from the phone".
- **Gap**: the destination is an arbitrary provider: synced folder, cloud, document indexer; the app
  cannot delete it or know where it ended up. With the SK out, A3 depends only on the
  password. The PDF's `ByteArray` is not wiped from memory (residue, not a separate finding).
- **Proposal**: add the kit as an **asset** (Critical sensitivity, "same as the SK") and a row
  **A19 "Leaked emergency kit"**: "the user is responsible; without the SK, A3 degrades to the
  strength of the password".

### 3.6 Forged intents

- **What it is**: another app that sends an `Intent` to `MainActivity`, `AutofillAuthActivity` or
  `SaveLoginActivity`, or that forges a `PendingIntent`.
- **Today**: only `MainActivity` is exported and it does not read the intent; the other two are not (`AndroidManifest.xml:39-64`);
  the save token is 16 random bytes with a 5 min lifetime (`PendingSaves.kt:15-24`); the
  autofill `PendingIntent` is mutable but uses an explicit `Intent` (`Datasets.kt:50-55`). Details
  in [`attack-surface.md`](attack-surface.md)) §2.9.
- **Gap** (fixed after this review): this analysis took the mutable autofill `PendingIntent` as fine, but the filled-in app receives the `IntentSender` and can add extras to it: see [ID-INT-26](internal-review.md#id-int-26)), fixed without commit with a single-use token, and row A18 of `threat-model.md`. **Nuance**: the token expiry is lazy and
  there is no wipe on lock (ID-INT-17).
- **Proposal**: row **A20 "App that sends intents"**, "Mitigated": non-exported activities, random
  token, no data in the intent.

### 3.7 Rotation or loss of the signing key

- **What it is**: losing the key leaves users without updates; leaking it allows a
  malicious update with the legitimate signature.
- **Today**: the release key is in `~/.openpassword/release-signing.properties` and its `.p12`, on the
  maintainer's computer (`build.gradle.kts:13-18`, `scripts/sign-release.sh:13`); v2 and v3 signatures
  "so that it can be rotated" (`build.gradle.kts:43-45`). The APK is signed **after** downloading the artifact from
  CI (`sign-release.sh:21`). `docs/fdroid/README.md:29-31` asks for a copy outside the computer and
  admits that, if it is lost, "you will not be able to publish updates with the same signature".
- **Gap**: there is no written rotation procedure (v3 allows it, but it requires the old
  certificate) or revocation procedure; an app that cannot be updated with the same signature forces
  **uninstalling**, and uninstalling **wipes the local vault**, so the only way is to restore a backup.
  Single human and equipment point of failure.
- **Proposal**: asset "signing key" (Critical) and row **A21 "Compromise or loss of the signing
  key"**, "Accepted with procedure", linking to a runbook still to be written (v3 rotation, offline copy,
  security notice). **It is a human decision.**

### 3.8 Compromised CI and GitHub Actions

- **What it is**: that the APK the maintainer signs is not the one from the source code.
- **Today** (commit `a3daf4e`): Actions pinned by SHA, `cargo-deny@0.20.2` and
  `cargo-fuzz@0.13.2` with a version, `dependabot.yml`, Gradle's `verification-metadata.xml` and a `release`
  job with provenance attestation (`ci.yml`, `.github/dependabot.yml`,
  `android/gradle/verification-metadata.xml`). CI permissions: `contents: read`, and
  `id-token`/`attestations: write` only in the `release` job.
- **Gap**: the maintainer signs the CI artifact **without rebuilding it first** (macOS does not
  reproduce the Linux APK, `sign-release.sh:4-5`); the only independent check will be done by
  F-Droid later. `dtolnay/rust-toolchain` is pinned by the SHA of its **branch** `stable` (`# stable branch`), not of a
  tagged version, which makes it hard to review what changes on each update. `cargo install cargo-ndk` and
  `cargo install cargo-cyclonedx` go with a version and `--locked`, but **without a checksum**. The `release` job does not create the release: attaching the files is manual.
- **Proposal**: row **A22 "Compromised CI or build dependency"**, "Partial"; extend A9 and cite
  attestation, SBOM and Gradle verification as defenses, with the limit that a person signs an
  artifact they have not rebuilt.

### 3.9 Public suffixes in autofill

- **What it is**: that a login for `github.io` or `co.uk` is offered to any subdomain of that suffix.
- **Today**: `LoginMatcher.hostMatches` only allows subdomains of a stored host if it is **not** a
  public suffix (`LoginMatcher.kt:43-48`); the list (`public_suffix_list.dat`, version
  `2026-10-28_13-15-55_UTC`, 338 012 bytes) goes in `src/main/resources`; without the list, **only the exact
  host matches** (`PublicSuffix.kt:10-12, 20`). Tests: `LoginMatcherTest` (29).
- **Gap**: there is no mechanism to update the list. The resource **is in the release APK**
  (`unzip -l android/app/build/outputs/apk/release/app-release.apk | grep public_suffix` →
  `public_suffix_list.dat`, 338 012 bytes), but it is **unverified** that it loads on a device (the
  tests run on the JVM and there is no instrumented test). If it did not load, the degradation is silent
  and safe (exact host), but subdomain matching would be lost.
- **Proposal**: note in A12 with the behaviour ("subdomains only of registrable domains according to the
  public suffix list of 2026-10-28; without the list, exact matching").

### 3.10 More attacks that are missing

| # | What it is | Today | Proposal |
|---|---|---|---|
| 3.10.1 | **`webDomain` declared by an app** (variant of A12) | `StructureParser.kt:35,53`: the first one that appears is used without checking that whoever declares it is a browser | Fix A12 and open finding ID-INT-16 |
| 3.10.2 | **Plaintext credentials to `system_server` and the keyboard** on every fill response | `OpAutofillService.kt:36-44` and `Datasets.kt:37-43`: with the vault open, up to 5 `Dataset`s are handed over with username and password, with no dataset authentication (`setAuthentication` only with the vault locked) | Document as Android's design; row in A12/A13 |
| 3.10.3 | **Hostile document provider** (SAF) | See [`attack-surface.md`](attack-surface.md)) §2.10; only encrypted copies and the kit are written | New row A23 next to A4 |
| 3.10.4 | **System image decoders** when reading a QR from an image | `QrScanner.kt:163-177` | Note in A16 |
| 3.10.5 | **A single unreadable record prevents unlocking** | `VaultSession.kt:108,141,280` (ID-INT-06) | Residual availability risk; restoring requires having no vault (`:136`) |
| 3.10.6 | **Kotlin and Rust in the same process** | No privilege boundary | Explicit assumption (section 4) |
| 3.10.7 | **Clipboard wipe in the background** | `SensitiveClipboard.kt:38` (ID-INT-14) | Fix A7 |

## 4. Implicit assumptions

1. **The attacker never has the phone unlocked at the same time as knowing the password.** With the
   vault open nothing prevents seeing everything (A8 only covers the onlooker). The exponential wait
   acts **after** 4 failures.
2. **Document providers are passive.** The model does not distinguish a local folder from a
   cloud or from a malicious provider; `AutoBackup` deletes and creates files there.
3. **Everything an app declares in `AssistStructure` is true except the package.** That is false for the
   `webDomain` (ID-INT-16).
4. **Private storage is not read after being deleted.** It relies on Android's encryption; there is no
   cryptographic erasure (3.4).
5. **The keyboard is not hostile.** A `Password` field is recommended where possible; notes go in
   plain text.
6. **A single maintainer signs and guards the key**, and is trustworthy (3.7).
7. **GitHub CI, Sigstore and the crates.io index are trustworthy** except for what the SHAs and the
   sums pin (3.8).
8. **UniFFI's `Vec<u8>` and `String` come out unwiped**; it is accepted because the attacker who read the
   process memory already has root (A10, out of scope). If A10 moved into scope, the
   analysis would change completely.
9. **The phone's clock is trustworthy** for the automatic lock and for computing the 14 days of the mandatory
   password (`System.currentTimeMillis`, `VaultSession.kt:224`; the automatic lock uses
   `elapsedRealtime`, which is indeed monotonic).
10. **Android resets the boot counter only on reboot** (`BOOT_COUNT`); the model uses it
    as proof that "the phone rebooted" (`VaultSession.kt:223`).
11. **A read-only app for the vault does not exist**: whoever can open the app can edit and delete everything.

## 5. Concrete changes that must be applied to `threat-model.md`

None has been applied. Recommended order of application, from what fixes falsehoods to what adds.

1. **A7**: replace "Planned, not yet implemented: `filterTouchesWhenObscured`" with the real text:
   `FLAG_SECURE` in the three activities; `filterTouchesWhenObscured` in every window and in the dialogs
   (`ProtectedAlertDialog`); `setHideOverlayWindows` from API 31 with the normal permission
   `HIDE_OVERLAY_WINDOWS`; warning (banner in the main activity, single `Toast` in the autofill
   ones); limit on API 28-30 (a partially covered touch is delivered). Status "Mitigated"
   only when the instrumented tests of the other two activities and of the dialogs exist
   (today only `MainActivity`, `androidTest/.../OverlayProtectionTest.kt`).
2. **A7, clipboard**: "sensitive clipboard (API 33+) with a wipe after 30 s **if the app still has
   access**; in the background the wipe may not act (unverified on device)". Do not say
   "with wipe" without qualifying until it is confirmed.
3. **A10**: "heuristic warning, no network, that can be bypassed; it does not block".
4. **A12**: add "the `webDomain` is declared by the originating app; today it is trusted without requiring a
   browser (ID-INT-16)" or, once fixed, "only the `webDomain` of browsers in a list is trusted". Cite the public suffix
   list and its date.
5. **A2**: specify "exponential wait on password unlock (`unlock`); the password verification in
   Settings does not count attempts" until ID-INT-09 is fixed.
6. **A4 and A6**: add a provider with write access (replace, delete, push out copies) and the
   resurrection of deleted items when importing an old copy.
7. **A9**: split into three rows. Dependencies (cargo-deny, Gradle verification, SBOM); CI (SHAs,
   attestation); and signing key. Remove "reproducible builds" or qualify it with "pending
   confirmation by F-Droid".
8. **A13**: add `PendingSaves` (emptying) and the behaviour after an internal failure
   (the session moves to `Locked`, `VaultSession.kt:434-443`).
9. **A15**: "the final `ByteArray` is wiped; transient copies remain (`ByteArrayOutputStream`, `serde_json`
   trees, CSV strings)".
10. **New rows**: A17 hostile file; A18 third-party keyboard and clipboard; A19 leaked emergency
    kit; A20 intents; A21 signing key; A22 CI and build chain; A23
    hostile document provider.
11. **Assets**: add "Signing key (Critical)" and "Emergency kit (Critical, contains the SK)".
12. **Assumptions**: add those from section 4 that the team decides to keep (1, 2, 5, 6, 7 and 8 as a
    minimum).
13. **Residual risks**: add the non-cryptographic erasure (3.4), the output `RustBuffer`
    (`secret.rs:8-11`), the out-of-memory abort (ADR-AUD-03/07), and remove "Backups with old
    credentials" until the password change exists.
14. **Heading**: the document says "it is reviewed before every major release and before the audit".
    Add the date and the SHA against which it was reviewed.

## 6. What could not be checked

- Everything marked **unverified**: SQLite journal mode, clipboard wipe in the background,
  loading of the public suffix list on a device, and the reliability of any
  device test (no instrumented or manual test was run in this review).
- The execution of the CI `release` job and of `cargo deny` on GitHub: `cargo deny --locked check` was
  run locally and exited with "advisories ok, bans ok, licenses ok, sources ok".
