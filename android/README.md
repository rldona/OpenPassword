# Android app

Kotlin, Jetpack Compose and Material 3. All cryptography is done by `op-core` (Rust), which the app loads as `libop_ffi.so` through the UniFFI bindings.

## What it does already

- Signup: master password with a strength meter and a secret key to write down on paper.
- Unlock with master password; growing delay after 4 failed attempts.
- Unlock with fingerprint (strong biometrics). The master password is requested every 14 days and after every reboot.
- Vault: list, accent-insensitive search, filters by type and favorites.
- Cards: the number is validated with Luhn and the network is shown (Visa, Mastercard, American Express…).
- Password history on logins, Wi-Fi and secrets: the previous 10, with the change date, to view or copy them.
- Logins, cards, bank accounts, PINs, documents, Wi-Fi networks, secrets and secure notes: create, view, edit and delete.
- Bank accounts: the IBAN is validated (country length and check digits) and stored grouped in fours; the list only shows the bank and the last four digits.
- Documents (ID card, passport, driving license…): dates are stored as DD/MM/YYYY even if they are typed without slashes.
- Wi-Fi: the detail shows a standard QR (`WIFI:T:WPA;…`) so another phone can connect with its camera. Without a password it is treated as an open network.
- Reveal field by field and copy to the clipboard marked as sensitive, which is erased after 30 s.
- Generator of passwords, PINs and passphrases (EFF long list, 7776 words). At signup it can suggest a 6-word phrase as the master password.
- Emergency kit in PDF for printing, with the secret key and how to restore. It is offered at signup and in Settings, after confirming the password.
- Export an encrypted `.opvault` backup wherever the user chooses. It opens with `opvault decrypt`. From format v2 it includes the images.
- Encrypted images: attached to any item (ID card, card, policy) with the app's camera or from the gallery. They are rescaled to 2048 px, re-encoded without EXIF and sealed with the item's key. They are only visible inside the app, with zoom; they are not shared or saved to the gallery. There is a cap of 10 per item and 24 MiB per vault.
- Automatic backup to a folder chosen by the user (from their cloud, Syncthing or SD card): a few seconds after every change and on unlock if the last one is more than a day old. It keeps the last 10 and only deletes its own backups (`openpassword-auto-…opvault`). Since encrypting requires the vault to be open, with the vault locked no backups are made: pending ones are made on unlock.
- Vault health, offline: weak passwords, passwords repeated across logins, logins not changed for more than a year, expired cards or cards expiring in the next 2 months, and expired documents or documents expiring in the next 3. A warning appears above the list only when there is something to fix.
- Import from another manager: KeePass (`.kdbx` 3.1 and 4.x with a password, a key file or both; without recycle bin or history), 1Password `.1pux` (logins with TOTP and extra fields, standalone passwords, cards and notes), unencrypted Bitwarden JSON and CSV from Chrome / Google, Firefox, Bitwarden and 1Password (the columns are recognized by their name). Reading KDBX 4 has not been tested yet with a real file. It does not duplicate what already exists and, since the export has the passwords in the clear, it offers to delete the file when done.
- Restore a backup on a new phone from the welcome screen, with the secret key from the kit and the master password.
- Import a backup into the current vault: if it is from the same vault it is merged by revision; if it is from another one, its items are re-encrypted with this vault's keys.
- View the secret key again, after asking for the master password again.
- Automatic lock: 5 min without use, 30 s after leaving the app (even if you do not come back) or when the screen turns off. While a file or folder picker requested by the user is open (export, import, kit, backups folder), the margin is 3 minutes, only for that time.
- TOTP codes (two-step verification): the QR is scanned with the camera, read from a screenshot or image, or the `otpauth://` link or the secret is pasted; the detail shows the current code with its countdown. The code is copied, never the secret. The QR is decoded on the phone with ZXing; frames are not saved and the luminance copy is erased after it is analyzed.
- Save new logins from autofill: when submitting a form with a password, Android offers «Guardar en OpenPassword» ("Save in OpenPassword"). If a login for that site with the same user already exists, it offers to update its password. The typed password stays in the app's memory; the confirmation window only receives a token, and nothing is saved without confirmation.
- Autofill in other apps and in the browser (Chrome: *Settings → Autofill services → Autofill with another service* (*Ajustes → Servicios de autocompletar → Autocompletar con otro servicio*)).

**Publishing to stores: archived.** The project is for personal use; the F-Droid recipe, the metadata and the signing flow remain in [`docs/archive/fdroid/`](../docs/archive/fdroid) in case it is ever planned as a public product again. There is no tag or published release.

## Security enforced by the build

- `verify<Variant>Manifest` fails the build if the final manifest declares `INTERNET` or `ACCESS_NETWORK_STATE`, if `HIDE_OVERLAY_WINDOWS` is missing, if `QUERY_ALL_PACKAGES` is declared, or if `allowBackup` is not `false`.
- Anti-tapjacking: `filterTouchesWhenObscured` and `setHideOverlayWindows` in all three activities and in all dialogs (`ProtectedAlertDialog`); if a covered touch arrives, a warning is shown.
- Warning (never a block) if the device appears to be rooted or running a debug build: local heuristics without network; the manifest declares in `<queries>` only the root manager package names.
- `FLAG_SECURE` on the activity: no screenshots, recording or thumbnail in recents.
- The secret key is stored sealed with an AES-256-GCM key from the Android Keystore (StrongBox if present).
- Fingerprint: the vault key is sealed with another Keystore key that requires strong biometric authentication on every use, only works with the phone unlocked, and Android destroys it if a new fingerprint or face is added. The only manifest permissions are `USE_BIOMETRIC`, `CAMERA` and `HIDE_OVERLAY_WINDOWS` (normal Android 12+ permission that hides the overlay windows of other apps; anti-tapjacking); the camera is requested only when pressing «Escanear QR» ("Scan QR") or «Hacer foto» ("Take photo") and it is optional (`required="false"`): reading the QR from an image needs no permission. CameraX pulls in `ACCESS_NETWORK_STATE` from media3 and the manifest removes it.
- Items are stored in SQLite as opaque blobs with `secure_delete`. Plain SQLite is used instead of Room to avoid depending on annotation processors.
- Nothing sensitive is stored in Compose instance state (`rememberSaveable`).
- The app's windows are excluded from all autofill services, so neither Google's nor any other can read or offer to save what is typed into the vault.

## Autofill

- Android shows the suggestions and only fills the one the user taps.
- **Strict matching**:
  - On websites, only the saved host or its subdomains: `google.com` works for `accounts.google.com`, but never for `google.com.phishing.net` or for `evilgoogle.com`.
  - In apps, only the exact package name, which Android verifies, stored as `androidapp://package`.
  - A login for a website never works for an app, nor the other way round.
- With the vault locked only «Desbloquear OpenPassword» ("Unlock OpenPassword") is offered, which opens a window with password or fingerprint.
- If there is no match, the user can pick a login by hand. In apps it can be remembered for that app; on websites the user is warned to check the site.
- Fields are detected in `autofill/FieldClassifier.kt` (autofill hints, input type, HTML attributes and names in Spanish and English). The detection and matching logic has unit tests.

## Dependency verification

`gradle/verification-metadata.xml` keeps the SHA-256 of every Maven artifact (dependencies, plugins and build tools). Gradle checks it on every resolution and the build fails if a checksum does not match or is missing.

**A new dependency, or a version bump, requires updating that file.** With JDK 17, from `android/`:

    ./gradlew --write-verification-metadata sha256 :app:lintDebug :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease :app:cyclonedxDirectBom

Review the diff of the XML (only the new artifacts should appear) and upload it in the same commit. It is the same task list that the CI runs.

Limitation: some artifacts depend on the platform. On macOS, Gradle only resolves `aapt2-<version>-osx.jar`; the CI (Linux) also needs `aapt2-<version>-linux.jar`, which is added by hand with the SHA-256 of the file downloaded from `https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/<version>/`. If the CI fails with «Dependency verification failed» after an AGP bump, start there; if not, regenerate the file on Linux (`--write-verification-metadata` merges with what is already there).

## Building

Requirements: JDK 17, Android SDK with platform 37, NDK `30.0.16248370`, Rust with the Android targets and `cargo-ndk`.

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk --locked --version 4.1.2
sdkmanager "ndk;30.0.16248370"
cd android
./gradlew :app:assembleDebug
```

The `cargoBuild` task compiles `op-ffi` with `cargo ndk` (always in release, because Argon2id is too slow without optimization) and `uniffiBindings` generates the Kotlin code from the library. To build only one ABI and save time: `./gradlew :app:assembleDebug -PrustAbis=arm64-v8a`.

Native libraries are 16 KB aligned, as Android 15+ requires on devices with 16 KB pages.

## Tests

```sh
./gradlew :app:testDebugUnitTest            # JVM: generators, EFF list, strength, fields, delay after failures
./gradlew :app:connectedDebugAndroidTest    # on a phone or emulator: full session with real op-core, Keystore and SQLite
```

The instrumented tests use their own namespace per test (files, database and Keystore key) and delete it when done: they never touch the app's data. Gradle uninstalls the debug app at the end.

## Release signing

The key is not in the repository. Gradle only uses it if `~/.openpassword/release-signing.properties` exists (or the file you specify with `-PsigningProperties=…`):

```properties
storeFile=/path/to/openpassword-release.p12
storePassword=…
keyAlias=openpassword
keyPassword=…
```

On GitHub, the CI writes that same file from the secrets `RELEASE_KEYSTORE_BASE64`
(the `.p12` in base64), `RELEASE_STORE_PASSWORD`, `RELEASE_KEY_ALIAS` and `RELEASE_KEY_PASSWORD`. Pull
requests do not receive secrets: their APK is left unsigned.

Every push to `main` updates the `latest` prerelease; a `v*` tag creates its release. The APK is
downloaded without an account from <https://github.com/rldona/OpenPassword/releases>. The CI passes
`-PversionCode` (number of commits, always increasing) and `-PversionName` (the tag or
`0.1.0-<commit>`), so the new build installs over the previous one. It is signed with the v3
scheme, which allows rotating the key in the future.

Certificate of the official releases (check it with `apksigner verify --print-certs`):

```
CN=OpenPassword, O=rldona · RSA 4096
SHA-256: c8:7c:49:b9:b2:57:11:1a:e9:49:07:a8:e1:43:80:2a:1c:22:83:26:81:e7:1c:96:f3:9c:ae:50:ef:7d:7b:57
```
