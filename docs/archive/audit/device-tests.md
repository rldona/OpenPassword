# Manual device tests

Test plan to close, before the external audit, what the internal review left as «unverified on device»
([`internal-review.md`](internal-review.md)), [`hardening.md`](hardening.md)),
[`threat-model.md`](../../threat-model.md))) and what cannot be checked on the JVM or in CI. It is written
so that a person with no prior context can run it and it serves as **evidence for the auditor**.

> **Status: session closed on 2026-10-30; what is pending requires an emulator or an API 28 device and does not block hiring the audit.**
> Partial run on **a single device, API 37** (see [«Session of 2026-10-30»](#sesion-2026-10-30)
> and [«second part»](#sesion-2026-10-30-b)). **Pass**: DT-01 (with limits), DT-04a, DT-05 (debug only),
> DT-07 and the instrumented tests (17 tests, section 3.2). **DT-04b fails**, which confirms
> [ID-INT-14](internal-review.md#id-int-14)), **accepted as residual risk** by the owner on
> 2026-10-30. **Pending, with their reason** (summary in [«Pending at session close»](#pendientes-al-cierre)):
> DT-02 and DT-03 (API 28-30 emulator), DT-12 (emulator or API 28 device), DT-11 (`userdebug` emulator),
> the R8 variant of DT-05, DT-06 (real browser), DT-08 (default browser) and the rest not run
> (DT-04c, DT-04d, DT-09, DT-10, DT-13 to DT-17), whose cells say «pendiente». The «expected
> results» describe what the code intends to do (with `file:line`); they are not results. If the
> device does something else, that is what gets recorded.

<a id="pendientes-al-cierre"></a>
### Pending at session close (2026-10-30)

| Test | Status | Reason | Needs |
|---|---|---|---|
| DT-02 | Pending (`blocked`) | No API 28/30 system images or emulator binary on the machine | API 28-30 emulator |
| DT-03 | Pending | Dialogs on API 28-30, not run | API 28-30 emulator |
| DT-04c, DT-04d | Pending | Screen off and sensitive flag, not run; DT-04 on API 29, 33 and 36 neither | API 29, 33 and 36 devices |
| DT-05, R8 variant | Pending | Only the debug build was run | Release build with R8 |
| DT-06 | Pending | Real browser (Chrome), not run | Device with Chrome |
| DT-08 | Pending | Malicious default browser, not run | Physical device |
| DT-09, DT-10 | Pending | Full autofill and «remember», not run | Physical device |
| DT-11 | Pending | Root: requires a `userdebug` emulator | `google_apis` `userdebug` emulator |
| DT-12 | Pending (`blocked`) | Android 9: no emulator or image; the phone is API 37 | Emulator or API 28 device |
| DT-13 | Pending | Real KDBX 4, not run | KeePassXC and device |
| DT-14, DT-15, DT-16, DT-17 | Pending | KDF/RAM, backups, automatic lock and TOTP, not run | Physical device |

Written on 2026-10-30 against `HEAD` `6827fcd` («Docs: pausar la publicación en F-Droid»). The quoted
lines are from that commit and shift if the code changes: the symbol name is the stable
reference. The version being audited (`v0.2.0`, see [`README.md`](README.md))) fixes which commit must be
tested (section 7, «Closure criterion»).

## Index

1. [Safety rules](#1-safety-rules)
2. [Setup](#2-setup)
3. [Results log](#3-results-log)
4. [Test APKs](#4-test-apks)
5. [Tests](#5-tests): [DT-01](#dt-01) · [DT-02](#dt-02) · [DT-03](#dt-03) · [DT-04](#dt-04) ·
   [DT-05](#dt-05) · [DT-06](#dt-06) · [DT-07](#dt-07) · [DT-08](#dt-08) · [DT-09](#dt-09) ·
   [DT-10](#dt-10) · [DT-11](#dt-11) · [DT-12](#dt-12) · [DT-13](#dt-13) · [DT-14](#dt-14) ·
   [DT-15](#dt-15) · [DT-16](#dt-16) · [DT-17](#dt-17)
6. [Automation](#6-automation)
7. [Closure criterion](#7-closure-criterion)
8. [Out of scope for this plan](#8-out-of-scope-for-this-plan)

### What each test covers

| Test | What it verifies | Finding or threat |
|---|---|---|
| [DT-01](#dt-01) | Anti-tapjacking on Android 12+ (`setHideOverlayWindows`) | A7; [ID-INT-13](internal-review.md#id-int-13)) |
| [DT-02](#dt-02) | Anti-tapjacking on API 28-30 (`filterTouchesWhenObscured`, warning, partially covered touch) | A7; ID-INT-13 |
| [DT-03](#dt-03) | The same on dialogs (`ProtectedAlertDialog`) | A7; ID-INT-13 |
| [DT-04](#dt-04) | Clipboard wipe after 30 s and sensitive flag | A7; [ID-INT-14](internal-review.md#id-int-14)), [ID-INT-15](internal-review.md#id-int-15)) |
| [DT-05](#dt-05) | The public suffix list loads and is applied on the device (with R8) | [ID-INT-20](internal-review.md#id-int-20)); A12, A17 |
| [DT-06](#dt-06) | `webDomain` from a real browser; token down to the right activity | A17; [ID-INT-16](internal-review.md#id-int-16)) |
| [DT-07](#dt-07) | An app that declares itself a browser receives no web datasets | A17; ID-INT-16 (second fix) |
| [DT-08](#dt-08) | Malicious default browser (documented residual risk) | A17 |
| [DT-09](#dt-09) | End-to-end autofill and token after rotation | A12, A18; [ID-INT-26](internal-review.md#id-int-26)) |
| [DT-10](#dt-10) | «Recordar para esta app» only for apps | ID-INT-26 (`AutofillAuthActivity.kt:102,124`) |
| [DT-11](#dt-11) | Root warning: shows up, does not block, is dismissed | A10; ADR-AUD-06 |
| [DT-12](#dt-12) | Biometrics on Android 9 (fix in `Biometrics.kt`) | Fix from `1649636` («biometrics on Android 9»); biometric key on API 28-29, «unverified» in [`internal-review.md`](internal-review.md)) §3 |
| [DT-13](#dt-13) | Import KDBX 4 with a real file | Android README; [ID-INT-02](internal-review.md#id-int-02)) |
| [DT-14](#dt-14) | KDF and RAM ceiling without closing the app | ADR-AUD-07; open risk of abort due to memory |
| [DT-15](#dt-15) | Automatic backup and restore | A4, A5 (backup integrity); functionality |
| [DT-16](#dt-16) | Automatic lock (5 min, 30 s, screen off) | A13 |
| [DT-17](#dt-17) | TOTP: QR, image and `otpauth://` | A16 |

---

## 1. Safety rules

**The owner's phone holds a vault with real data. These tests include destructive steps**
(deleting items, clearing app data, restoring backups, changing the autofill service and
the default browser, importing hostile files).

1. **Never test on the real vault.** First of all, export a copy of the real vault
   (section 2.3) and keep it off the phone. Then create a new, isolated **test vault**
   (section 2.4). All tests are done on it.
2. **Isolation by package.** The debug app is installed under a different identifier
   (`io.github.rldona.openpassword.debug`; `android/app/build.gradle.kts:52`, `applicationIdSuffix`), so
   it has its own data and its own Keystore keys and **does not touch** the official app
   (`io.github.rldona.openpassword`). But:
   - **Do not install the official release APK** on the phone with real data for these tests.
   - If the phone's real vault lives **in the `.debug` package** (the debug build is used
     daily), **do not run the tests on that phone**: use another device, an emulator or a
     secondary Android user (Settings → System → Multiple users, if the manufacturer offers it). The
     checks in section 2.2 detect it.
3. **No root on the main phone.** No step needs it. The root test (DT-11) is done on a
   `userdebug` emulator or a dedicated device, never on the main phone.
4. **No dubious third-party apps.** For the overlay and fake browser tests, two minimal
   APKs of our own are built (section 4). No APK is downloaded from anywhere. The only
   external tools are the official ones (Android SDK, the system Chrome) and KeePassXC (DT-13).
5. **System setting changes that must be undone** (see 2.7): autofill service,
   default browser, screen-off timeout and rotation. The original value is recorded before
   changing it.
6. **The test passwords are made up** and different from any real one. If a screenshot or a
   `logcat` contains real data (notifications, Wi-Fi network names, other apps), it is cropped or
   discarded before delivery.

## 2. Setup

### 2.1 Tools on the computer

- Android SDK with `adb` (`platform-tools`) and, for emulators, `cmdline-tools` and `emulator`.
- JDK 17 or higher (the one in [`android/README.md`](../../../android/README.md)) is 17), to build the app and
  the test APKs.
- To build the app: Rust with the Android targets, `cargo-ndk` and the NDK listed in
  [`android/README.md`](../../../android/README.md)) («Compilar»).
- KeePassXC (DT-13) and, optionally, `qrencode` (DT-17).

```sh
export OP_REPO="$HOME/workspace/OpenPassword"        # adjust to your clone
export PKG=io.github.rldona.openpassword.debug         # debug app (the one under test)
adb devices -l                                         # a single device; note the serial
export ANDROID_SERIAL=<serial>                         # so adb and Gradle do not pick the wrong device
```

> With more than one device connected, `adb` without `ANDROID_SERIAL` fails or, worse, picks one. Check
> **always** that `adb devices` shows only the test device before running anything.

### 2.2 What is installed (before touching anything)

```sh
adb shell pm list packages | grep -i openpassword
adb shell dumpsys package io.github.rldona.openpassword 2>/dev/null | grep -E "versionName|versionCode"
adb shell dumpsys package "$PKG" 2>/dev/null | grep -E "versionName|versionCode"
```

- If only `io.github.rldona.openpassword` (official) shows up: the real vault is there and the debug app
  will leave it untouched. Continue.
- If `io.github.rldona.openpassword.debug` shows up with data that is not test data: **stop** (rule 2).

### 2.3 Export a copy of the real vault

Only if the device holds real data.

1. Open the **official** app → Settings → **Export encrypted backup**. Save the `.opvault` in a folder you
   can copy to the computer.
2. Copy it to the computer and check that its header can be read (no credentials are asked for):
   ```sh
   cd "$OP_REPO" && cargo run -q -p opvault-cli -- inspect /ruta/a/openpassword-AAAA-MM-DD.opvault
   ```
3. Check that you really open it with your password and your secret key (`opvault decrypt`, see
   [`README.md`](../../../README.md)) of the project). Without this check, do not continue: a copy that does not
   open is not a copy.
4. Keep it off the phone. It is the safety net if something goes wrong.

### 2.4 Create the test vault

1. Build and install the debug app (section 2.5) and open it: the welcome screen appears.
2. Create a vault with a **throwaway** password (for example `prueba-dispositivo-1`) and write down
   the secret key the app shows on paper or in a file **labelled «PRUEBAS»**. Do not reuse
   anything from the real vault.
3. Create these test items (type «Login»). The URL is written as is:

   | Title | URL | User | Password | Used in |
   |---|---|---|---|---|
   | `alice.github.io` | `https://alice.github.io` | `alice` | `Prueba-pw-1` | DT-05 |
   | `Sufijo github.io` | `https://github.io` | `suffix` | `Prueba-pw-2` | DT-05 |
   | `GitHub` | `https://github.com` | `testuser` | `Prueba-pw-3` | DT-06 |
   | `Wikipedia` | `https://wikipedia.org` | `testwiki` | `Prueba-pw-4` | DT-05 (control), DT-06 |
   | `Banco falso` | `https://bank.example` | `victima` | `Prueba-pw-5` | DT-07, DT-08, DT-10 |
   | `Borra-me` | (empty) | `x` | `Prueba-pw-6` | DT-03 |
   | `Portapapeles` | (empty) | `clip` | `Prueba-pw-7` | DT-04 |

   Each password is different so that, when you see it appear, you know which item it comes from.

### 2.5 Build and install the debug APK

From the commit to be tested, with a **clean** tree (`git status --short` with no output). The APK does not
carry the commit inside (`BuildConfigInfo.kt` only exposes `versionName`), so **it is noted here**:

```sh
cd "$OP_REPO"
git status --short                    # must be empty; if not, note it on the record sheet
git rev-parse HEAD                    # tested commit: copy it to the record sheet
cd android
./gradlew :app:assembleDebug          # add -PrustAbis=arm64-v8a to build only that ABI
shasum -a 256 app/build/outputs/apk/debug/app-debug.apk   # APK fingerprint: copy it to the record sheet
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell dumpsys package "$PKG" | grep -E "versionName|versionCode|lastUpdateTime"
```

`adb install -r` reinstalls keeping the data of the **same** app (here, the debug one). To start
from scratch, `adb shell pm clear "$PKG"` (only if the `.debug` package holds nothing but the test
vault; see 2.2).

To check that what is installed is what was built (`sha256sum` exists on Android 9+; if not, `adb pull`):

```sh
adb shell pm path "$PKG"                                  # package:/data/app/.../base.apk
adb shell sha256sum "$(adb shell pm path "$PKG" | head -1 | cut -d: -f2 | tr -d '\r')"
```

### 2.6 Device record sheet

One record sheet per device, pasted into the table in section 3 or into a `ficha-dispositivo.txt` file next
to the evidence.

```sh
{
  echo "date: $(date -u +%FT%TZ)"
  for p in ro.product.manufacturer ro.product.model ro.build.version.release ro.build.version.sdk \
           ro.build.version.security_patch ro.product.cpu.abilist ro.build.type ro.build.tags \
           ro.build.fingerprint ro.config.low_ram; do
    echo "$p=$(adb shell getprop "$p" | tr -d '\r')"
  done
  adb shell grep MemTotal /proc/meminfo | tr -d '\r'
  adb shell pm list features | tr -d '\r' | grep -i -E "strongbox|fingerprint|face"
  echo "version: $(adb shell dumpsys package "$PKG" | grep versionName | head -1 | tr -d '\r')"
  echo "commit: $(git -C "$OP_REPO" rev-parse HEAD)"
} | tee ficha-dispositivo.txt
```

Record: **model**, **Android version and API** (`ro.build.version.sdk`), **ABI**
(`ro.product.cpu.abilist`), **RAM** (`MemTotal`; with less than 3 GiB the app uses the `MINIMUM` KDF
profile, `OpenPasswordApp.kt:88-91`), **StrongBox** (a `feature:android.hardware.strongbox_keystore` line in
the output; if it does not appear, there is none), **`versionName`** (currently `0.1.0` in `android/app/build.gradle.kts:30`,
even though the package is called `v0.2.0`: what is recorded is what is installed, not what is expected), **commit**, **SHA-256
fingerprint of the APK** and the system language.

### 2.7 System settings that are changed: record the original

```sh
adb shell settings get secure autofill_service              # current autofill service
adb shell cmd role get-role-holders android.app.role.BROWSER   # default browser (API 29+)
adb shell settings get system screen_off_timeout            # ms
adb shell settings get system accelerometer_rotation
adb shell settings get system user_rotation
```

When all tests are finished, restore each one from System Settings: *Autofill* (back to your usual
service), *Default apps → Browser app*, screen-off timeout and rotation.

### 2.8 Evidence

- **Screenshots and video of OpenPassword come out black**: the app uses `FLAG_SECURE` in its three activities
  (`MainActivity.kt:26`, `AutofillAuthActivity.kt:81`, `SaveLoginActivity.kt:74`). This is the expected
  behaviour, not a bug. To photograph OpenPassword use **another camera** (another phone) or a recording
  of the device with an external camera. Screenshots of other apps (Chrome, the test APKs, the
  system autofill dropdown) do work: `adb exec-out screencap -p > captura.png`.
- **`logcat`**: `adb logcat -d -t 500 > logcat-DT-XX.txt`. For unexpected crashes,
  `adb logcat -b crash -d > crash-DT-XX.txt`. Review it before sharing it (there may be data from other
  apps). Do not use `adb bugreport` as evidence: it includes personal data from the phone.
- **Evidence folder**, outside the repository (they are binaries): `evidencia-dt/AAAA-MM-DD-<modelo>/` with
  files named `DT-XX-<n>-<description>.<ext>`. When finished:
  ```sh
  cd evidencia-dt && find . -type f ! -name SHA256SUMS -exec shasum -a 256 {} + > SHA256SUMS
  ```
  The table cites the file name; the summary and `SHA256SUMS` can be delivered to the auditor.

### 2.9 Minimum device matrix

Each test says which API it needs. Recommended minimum (one device can cover several rows):

| Profile | What for | Device |
|---|---|---|
| **API 33+** (Android 13+) real | DT-01, DT-03, DT-04 (sensitive flag), DT-06 to DT-10, DT-12 to DT-17 | Physical |
| **API 29** | DT-04 (ID-INT-14 asks for API 29, 33 and 36) | Physical or emulator |
| **API 28-30** | DT-02, DT-03 | Physical or emulator (if it is an emulator, it is marked as such in the table) |
| **API 36** | DT-04 (ID-INT-14) | Physical or emulator |
| **API 28** with fingerprint | DT-12 | Emulator with virtual fingerprint or physical device |
| **`userdebug` emulator** | DT-11 | `google_apis` emulator |

Emulators («Google APIs» image, no Play: they are `userdebug`). On a Mac with Apple Silicon, `arm64-v8a`; on
Intel or Linux, `x86_64` (the app includes `arm64-v8a`, `armeabi-v7a` and `x86_64`; not `x86`):

```sh
SDK="$HOME/Library/Android/sdk"
"$SDK/cmdline-tools/latest/bin/sdkmanager" "system-images;android-30;google_apis;arm64-v8a"
"$SDK/cmdline-tools/latest/bin/avdmanager" create avd -n dt-api30 \
  -k "system-images;android-30;google_apis;arm64-v8a" -d pixel_5
"$SDK/emulator/emulator" -avd dt-api30 &
adb -e shell getprop ro.build.type        # userdebug
```

There are `google_apis` images for API 28, 29, 30, 33, 34 and 36 (checked with `sdkmanager --list`). An
emulator is **secondary evidence**: it is recorded as such. Anything that depends on hardware (real fingerprint,
StrongBox, Chrome with its sync) is tested on a physical device.

## 3. Results log

**`result` vocabulary**: `pass` (matches the expected result), `fail` (does not match; what
happened is described in `notes`) or `blocked` (could not be run: the device, the API, the
tool is missing; the reason is stated). An empty cell means «not run».

Rules: one row **per test and per device** (copy the row if there are several devices). A row is never
overwritten: if a test is repeated, a new row is added with the new date. `evidence`
cites files from the evidence folder (2.8).

### 3.1 Device record sheet (one per device)

| Field | Value |
|---|---|
| Device alias (the one that will go in the table) | |
| Model and manufacturer | |
| Android (version) and API | |
| ABI | |
| RAM (`MemTotal`) | |
| StrongBox (yes / no) | |
| Fingerprint or face enrolled (yes / no) | |
| Physical or emulator | |
| `ro.build.type` and `ro.build.tags` | |
| Installed `versionName` | |
| Tested commit (full SHA) | |
| Clean tree (`git status --short` empty) | |
| APK SHA-256 | |
| Original default browser | |
| Original autofill service | |
| Person running it | |
| Start date | |

### 3.2 Results

| ID | date | device/API | result | evidence | notes |
|---|---|---|---|---|---|
| DT-01 | 2026-10-30 | SM-S948B, Android 17 (API 37), physical | **pass** (with limits) | `/tmp/dt-00-launcher.png`, `/tmp/dt-01.png`, `/tmp/dt-02.png`, `dumpsys window` output (see «Session of 2026-10-30»; not archived in the evidence folder) | Positive control: `full` overlay visible over the launcher. With OpenPassword in the foreground (`MainActivity`, `FLAG_SECURE`): overlay with `Surface: shown=false`, `isVisible=false`, `isOnScreen=false` and SurfaceFlinger «hidden»; on returning to the launcher, `shown=true`. `HIDE_OVERLAY_WINDOWS` `granted=true`. A tap on «Crear mi baúl» changed screen. No `FATAL EXCEPTION` or `AndroidRuntime` errors. The «toque tapado» warning was **not** observed (with `setHideOverlayWindows` the touch does not arrive covered; known limit). **Limits**: only `MainActivity` and one tap; not `AutofillAuthActivity` or `SaveLoginActivity`, nor the partial overlay, nor steps 4-8 complete with the vault unlocked |
| DT-02 | 2026-10-30 | — | **blocked** | — | No emulator binary or API 28/30 system images on the machine (only `android-36` and `android-37.0`); the phone is API 37 |
| DT-03 | — | — | **PENDING** | — | API 28-30 emulator; not run |
| DT-04a (foreground) | 2026-10-30 | SM-S948B, Android 17 (API 37), physical | **pass** | Clipboard reader output (`CLIPBOARD_EMPTY`); no archived file (see «second part») | Copy and wait 35 s **with OpenPassword in the foreground**: `CLIPBOARD_EMPTY`. The wipe after 30 s **does** work with the app focused. Only API 37 (ID-INT-14 also asks for 29, 33 and 36). Method different from the plan: the clipboard was read with a reader of our own, not by pasting into `test.fakebrowser` |
| DT-04b (background) | 2026-10-30 | SM-S948B, Android 17 (API 37), physical | **fail** (confirms ID-INT-14; **accepted as residual risk** by the owner, 2026-10-30) | Clipboard reader output (`CLIPBOARD_HAS_TEXT`); no archived file | Copy the password, press Home, wait 36 s and open the reader: **`CLIPBOARD_HAS_TEXT` at 45 s**; the wipe does **not** happen with the app in the background. Controls: copying and reading at 5 s gives `CLIPBOARD_HAS_TEXT` (copying works and the reader reads correctly, in `onWindowFocusChanged`), and 04a gives `CLIPBOARD_EMPTY` (the wipe works in the foreground). Step 5 of the plan was **not** tested (returning to OpenPassword and seeing whether it is wiped on return): what `onForeground` does is still **unverified on device**. It was not determined which of the three ID-INT-14 hypotheses explains the symptom (`null` description, `clearPrimaryClip()` denied or `Handler` not running); all that is established is that, on API 37, the clipboard still holds text after leaving the app |
| DT-04c (screen off) | — | — | **PENDING** | — | Not run |
| DT-04d (sensitive flag) | — | — | **PENDING** | — | Not run |
| DT-05 | 2026-10-30 | SM-S948B, Android 17 (API 37), physical; **debug** build (without R8) | **pass** (debug only; R8 variant not run) | Session output (table in «second part»); no archived screenshots | With `test.fakebrowser` as default browser. `alice.github.io` → «COINCIDEN» only `alice.github.io` (`github.io` under «OTROS LOGINS»); `evil.github.io` → «ELIGE UN LOGIN», no matches and with «Ningún login tiene guardado evil.github.io» (repeated with the vault unlocked); `x.alice.github.io` → offers `alice.github.io`; `en.wikipedia.org` → offers `wikipedia`; `github.io` → offers `sufijo-github-io` (exact). The two positive controls (`x.alice.github.io`, `en.wikipedia.org`) offer the item: **the list loaded and was applied**. They do not prove that the app fails closed if the list did not load. Vault with 4 logins, not the 7 from 2.4 |
| DT-06 | — | — | **PENDING** | — | Real browser; not run |
| DT-07 | 2026-10-30 | SM-S948B, Android 17 (API 37), physical | **pass** | Session output; no archived screenshots | With Chrome as default browser, `test.fakebrowser` declaring `bank.example` produces «Para: test.fakebrowser»; the `webDomain` is ignored and there are no web matches. It was **not recorded** whether there was a «Recordar…» checkbox or whether steps 4 (vault locked) and 5 (5 min cache) of the plan were done |
| DT-08 | — | — | **PENDING** | — | Default browser; not run |
| DT-09a (save) | — | — | **PENDING** | — | Not run |
| DT-09b (fill) | — | — | **PENDING** | — | Not run |
| DT-09c (update password) | — | — | **PENDING** | — | Not run |
| DT-09d (token and rotation) | — | — | **PENDING** | — | Not run |
| DT-10 | — | — | **PENDING** | — | Not run |
| DT-11 | — | — | **PENDING** | — | Requires a `userdebug` emulator; not run |
| DT-12 | 2026-10-30 | — | **blocked** | — | Needs Android 9 (API 28); there is no emulator or system image and the phone is API 37 |
| DT-13a (ChaCha20 + Argon2id) | — | — | **PENDING** | — | Real KDBX 4; not run |
| DT-13b (AES-256 + Argon2d) | — | — | **PENDING** | — | Real KDBX 4; not run |
| DT-13c (with key file) | — | — | **PENDING** | — | Real KDBX 4; not run |
| DT-13d (Twofish: rejection) | — | — | **PENDING** | — | Real KDBX 4; not run |
| DT-13e (KDF too costly: rejection) | — | — | **PENDING** | — | Real KDBX 4; not run |
| DT-14a (above the ceiling) | — | — | **PENDING** | — | Not run |
| DT-14b (at the ceiling) | — | — | **PENDING** | — | Not run |
| DT-15 | — | — | **PENDING** | — | Not run |
| DT-16a (5 min idle) | — | — | **PENDING** | — | Not run |
| DT-16b (30 s after leaving) | — | — | **PENDING** | — | Not run |
| DT-16c (screen off) | — | — | **PENDING** | — | Not run |
| DT-17a (QR with the camera) | — | — | **PENDING** | — | Not run |
| DT-17b (QR from an image) | — | — | **PENDING** | — | Not run |
| DT-17c (paste `otpauth://` or secret) | — | — | **PENDING** | — | Not run |
| Instrumented (`./gradlew :app:connectedDebugAndroidTest`) | 2026-10-30 | SM-S948B, Android 17 (API 37), arm64-v8a, physical | **pass** | `android/app/build/outputs/androidTest-results/connected/debug/TEST-SM-S948B - 17.xml` (see «Session of 2026-10-30») | 17 tests, 0 failures, 0 errors, 0 skipped, 47 s: `EmergencyKitTest` (2), `OverlayProtectionTest` (4), `VaultSessionTest` (11). On commit `183598d` with a dirty tree (`fuzz/deny.toml` modified). Installed version `0.1.0` (`io.github.rldona.openpassword.debug`). The tests cover flags and sessions with isolated vaults: they do not replace the DT tests on real behaviour |

<a id="sesion-2026-10-30"></a>
### 3.3 Session of 2026-10-30

- **Device**: Samsung SM-S948B, Android 17 (API 37), `arm64-v8a`, physical.
- **App**: `versionName` 0.1.0, `io.github.rldona.openpassword.debug`, installed from the working tree
  at commit `183598d`, **with `fuzz/deny.toml` modified without commit** (tree not clean; no SHA-256
  fingerprint of the APK recorded).
- **Instrumented**: `./gradlew :app:connectedDebugAndroidTest`, 17 tests, 0 failures, 0 errors, 0
  skipped, 47 s. `EmergencyKitTest` (2); `OverlayProtectionTest` (4: `mainActivityWindowIsProtected`,
  `autofillAuthActivityWindowIsProtected`, `saveLoginActivityWindowIsProtected`,
  `protectedAlertDialogWindowIsProtected`); `VaultSessionTest` (11, among them `createLockAndUnlock`,
  `nothingIsStoredInClear`, `exportAndRestoreOnANewDevice`, `failedRestoreLeavesNoVaultBehind`,
  `wrongPasswordsTriggerTheWait`, `locksInTheBackgroundWithoutComingBack`, `itemsRoundTripAndKeepRevisions`,
  `importingAnOlderCopyOfTheSameVaultKeepsNewerItems`, `importingANewerCopyUpdatesAndAddsItems`,
  `importingAnotherVaultReencryptsItsItems`; the eleventh was not transcribed). Results file:
  `android/app/build/outputs/androidTest-results/connected/debug/TEST-SM-S948B - 17.xml`.
- **DT-01**: `test.overlay` built in `~/openpassword-testapps` (AGP 9.4.1, JDK 17, `compileSdk 36`,
  `targetSdk 33`) and `SYSTEM_ALERT_WINDOW` granted with `adb shell appops set test.overlay
  SYSTEM_ALERT_WINDOW allow`. Result and limits in the DT-01 row.
- **DT-02 and DT-12**: blocked (no emulator or API 28/30 images; the phone is API 37).
- **Phone state at the end**: `test.overlay` uninstalled; OpenPassword installed **with no vault
  created** (the instrumented tests uninstalled the app and it was reinstalled clean). No real vault was
  touched.
- **Available evidence** (outside the repository): `/tmp/dt-00-launcher.png` (positive control in the
  launcher), `/tmp/dt-01.png` and `/tmp/dt-02.png` (OpenPassword in the foreground; they come out black on purpose because of
  `FLAG_SECURE`) and the `dumpsys window` output (not saved to a file). **`/tmp` can be cleaned**: if
  this evidence is to be delivered to the auditor, it must first be copied to the evidence folder (2.8) and
  its `SHA256SUMS` recorded.

<a id="sesion-2026-10-30-b"></a>
### 3.4 Session of 2026-10-30, second part

- **Device**: the same Samsung SM-S948B, Android 17 (API 37), physical. **Tested commit and APK
  fingerprint: not recorded** (the debug app was installed from the working tree, with uncommitted changes, among
  them the copy message text described below).
- **Method**: a test vault was created with **4 logins** (not the 7 from 2.4; among them `alice.github.io`,
  a `github.io` suffix one titled `sufijo-github-io` and `wikipedia`) and `test.fakebrowser`
  was installed (section 4.3), which declares `webDomain` through a virtual autofill structure. For DT-05 it was
  set as the default browser; for DT-07, Chrome.
- **DT-05 · public suffixes: `pass`** (debug build). Result per declared domain:

  | Declared domain | Observed |
  |---|---|
  | `alice.github.io` | «COINCIDEN» only `alice.github.io`; `github.io` is left under «OTROS LOGINS» |
  | `evil.github.io` | «ELIGE UN LOGIN», no matches, with «Ningún login tiene guardado evil.github.io». Repeated with the vault unlocked |
  | `x.alice.github.io` | Offers `alice.github.io` (positive control: the list loaded) |
  | `en.wikipedia.org` | Offers `wikipedia` (positive control) |
  | `github.io` | Offers `sufijo-github-io` (exact match) |

  The positive controls show that the list **loaded and was applied**; they do not show that the app fails
  closed if it did not load (only JVM tests cover that, and they were not run). **Not run**: the R8 variant (5.R8): the
  debug build does not go through R8.
- **DT-07 · app that declares itself a browser: `pass`**. With Chrome as default, `test.fakebrowser` with
  `bank.example` produces «Para: test.fakebrowser»; the `webDomain` is ignored and there are no web matches.
- **DT-08 (not run as such)**: during DT-05, with `test.fakebrowser` as default, its
  `webDomain` **was taken into account** (there were web matches by domain). This is consistent with the residual
  risk of A17, but the DT-08 procedure was not followed and neither «Para:» nor the «Recordar…» checkbox
  was recorded: the row is still empty.
- **DT-04 · clipboard: `fail` in the background (confirms ID-INT-14)**. The clipboard was read with a
  reader of our own that queries the clipboard in `onWindowFocusChanged` (when it has focus) and writes
  `CLIPBOARD_HAS_TEXT` or `CLIPBOARD_EMPTY`. This method **replaces** pasting into the `test.fakebrowser`
  field from the plan. Controls and results:

  | Sequence | Result |
  |---|---|
  | Copy the password and open the reader at 5 s | `CLIPBOARD_HAS_TEXT` (positive control: copying works and the reader reads) |
  | Copy, wait 35 s with OpenPassword in the foreground, read | `CLIPBOARD_EMPTY` (the wipe works with the app focused) |
  | Copy, press Home, wait 36 s, open the reader | **`CLIPBOARD_HAS_TEXT` at 45 s** (the wipe does **not** happen in the background) |

  Session conclusion: `clearPrimaryClip()` from the background has no effect on API 37; the
  current mechanism only wipes with the app in the foreground. **Unverified**: that it is wiped on returning to the
  app (not tested), DT-04c (screen off), DT-04d (sensitive flag) and API 29, 33 and 36.
- **Associated code change (no commit)**: the message promised «Se borrará del portapapeles en 30 s»
  also in the background. It now says «Se borrará en 30 s, o al volver a la app si sales.»
  (`ui/vault/ItemDetailScreen.kt:99,142,184`). It only corrects the text: it does **not** fix the wipe, and the
  «o al volver a la app» part describes the `onForeground` design, **not verified on device**.
- **Phone state at the end**: autofill service returned to
  `com.google.android.gms/…AutofillService`; default browser back to `com.android.chrome`;
  `test.fakebrowser` uninstalled; OpenPassword debug installed with the test vault. No real vault was
  touched.
- **Evidence**: the clipboard reads and the DT-05 and DT-07 output are session notes; **there
  are no archived files or `SHA256SUMS`**. Before delivering them to the auditor, the capture must be repeated
  (2.8) or it must be accepted that they are the project's testimony.

---

## 4. Test APKs

Two minimal modules in a Gradle project **outside the repository** (for example
`~/openpassword-testapps`), so as not to touch the code or its dependency checks:

- `test.overlay`: draws a translucent `TYPE_APPLICATION_OVERLAY` window that lets touches through
  (`FLAG_NOT_TOUCHABLE`), from a service. This is what a *tapjacking* app would do.
- `test.fakebrowser`: declares a `VIEW` `http`/`https` `intent-filter` and, on its login screen, a
  fake `webDomain` (`ViewStructure.setWebDomain`). This is what an app impersonating a
  browser would do.

They do not request `INTERNET` or anything other than `SYSTEM_ALERT_WINDOW` (the overlay one). Both are Java (no
Kotlin) to depend on as little as possible. They are built with the Gradle *wrapper* and the AGP version from the
repository ([`android/gradle/libs.versions.toml`](../../../android/gradle/libs.versions.toml)): `agp`), which is
downloaded from Google and Maven Central (no dependency verification: they are disposable APKs, not
published or delivered to the user).

> Both modules were built with this recipe (JDK 21, AGP 9.4.1, Gradle 9.8.2 from the repository
> *wrapper*) and `assembleDebug` succeeded. `test.overlay` was installed and
> run on 2026-10-30 (DT-01, with JDK 17 and `compileSdk 36`); `test.fakebrowser` was installed and run the
> same day (second part: DT-05 and DT-07) and uninstalled at the end. That they behave as described is
> part of what the tests check.

### 4.1 Create the project

```sh
mkdir -p ~/openpassword-testapps && cd ~/openpassword-testapps
mkdir -p gradle overlay/src/main/java/test/overlay fakebrowser/src/main/java/test/fakebrowser
cp -R "$OP_REPO/android/gradle/wrapper" gradle/wrapper
cp "$OP_REPO/android/gradlew" .

cat > settings.gradle.kts <<'EOF'
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "openpassword-testapps"
include(":overlay", ":fakebrowser")
EOF

cat > build.gradle.kts <<'EOF'
plugins {
    id("com.android.application") version "9.4.1" apply false
}
EOF

echo "android.useAndroidX=true" > gradle.properties
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties   # adjust if your SDK is at another path

for m in overlay fakebrowser; do
cat > "$m/build.gradle.kts" <<EOF
plugins { id("com.android.application") }

android {
    namespace = "test.$m"
    compileSdk = 36
    defaultConfig {
        applicationId = "test.$m"
        minSdk = 28
        targetSdk = 33
        versionCode = 1
        versionName = "1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
EOF
done
```

`targetSdk = 33` is deliberate: a simple overlay service does not need `foregroundServiceType`
and the APK installs on Android 14 or later without old-version warnings. If the SDK does not have
platform 36, change `compileSdk` to one you have (`ls "$HOME/Library/Android/sdk/platforms"`).

### 4.2 `overlay` module

```sh
cat > overlay/src/main/AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <application android:label="Overlay de prueba" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".OverlayService" android:exported="false" />
    </application>
</manifest>
EOF

cat > overlay/src/main/java/test/overlay/MainActivity.java <<'EOF'
package test.overlay;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.LinearLayout;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);
        root.addView(button("1. Conceder permiso de superposición", v -> startActivity(
                new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:" + getPackageName())))));
        root.addView(button("2. Overlay COMPLETO (toda la pantalla)", v -> start("full")));
        root.addView(button("3. Overlay PARCIAL (franja inferior)", v -> start("partial")));
        root.addView(button("4. Quitar overlay", v -> start("off")));
        setContentView(root);
    }

    private Button button(String text, android.view.View.OnClickListener l) {
        Button x = new Button(this);
        x.setText(text);
        x.setOnClickListener(l);
        return x;
    }

    private void start(String mode) {
        if (!Settings.canDrawOverlays(this)) return;
        startService(new Intent(this, OverlayService.class).putExtra("mode", mode));
    }
}
EOF

cat > overlay/src/main/java/test/overlay/OverlayService.java <<'EOF'
package test.overlay;

import android.app.Service;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.os.IBinder;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.TextView;

/** Draws a translucent TYPE_APPLICATION_OVERLAY window that lets touches through (FLAG_NOT_TOUCHABLE). */
public class OverlayService extends Service {
    private View view;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String mode = intent == null ? "off" : intent.getStringExtra("mode");
        remove();
        if ("full".equals(mode) || "partial".equals(mode)) {
            boolean full = "full".equals(mode);
            TextView v = new TextView(this);
            v.setText("OVERLAY DE PRUEBA (" + mode + ")");
            v.setTextSize(20);
            v.setGravity(Gravity.CENTER);
            v.setTextColor(Color.WHITE);
            v.setBackgroundColor(Color.RED);
            // 0.5 < 0.8: Android 12+ blocks touches through overlays above 0.8 opacity on its own;
            // we want to test OpenPassword's defences, not the system's.
            WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
                    WindowManager.LayoutParams.MATCH_PARENT,
                    full ? WindowManager.LayoutParams.MATCH_PARENT : 300,
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                            | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                            | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                    PixelFormat.TRANSLUCENT);
            lp.alpha = 0.5f;
            lp.gravity = Gravity.BOTTOM;
            getSystemService(WindowManager.class).addView(v, lp);
            view = v;
        } else {
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    private void remove() {
        if (view != null) {
            getSystemService(WindowManager.class).removeView(view);
            view = null;
        }
    }

    @Override
    public void onDestroy() {
        remove();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
EOF
```

Why `alpha = 0.5f`: since Android 12 the system itself blocks touches that go through an
overlay of another app with opacity above 0.8. With 0.5 the touch reaches the window below and what
is tested is OpenPassword's defenses, not the system's.

### 4.3 `fakebrowser` module

```sh
cat > fakebrowser/src/main/AndroidManifest.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:label="Navegador falso" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <!-- Declaring this requires no permission: it is exactly what an attacker would do. -->
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="http" />
                <data android:scheme="https" />
            </intent-filter>
        </activity>
    </application>
</manifest>
EOF

cat > fakebrowser/src/main/java/test/fakebrowser/MainActivity.java <<'EOF'
package test.fakebrowser;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewStructure;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Login screen that declares a fake web domain (webDomain), as a WebView would.
 * Domain: "domain" extra (default bank.example); it is passed when opening it with
 * adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example
 */
public class MainActivity extends Activity {
    /** An EditText that adds webDomain to the autofill structure. */
    static class WebField extends EditText {
        private final String domain;

        WebField(Context c, String domain) {
            super(c);
            this.domain = domain;
        }

        @Override
        public void onProvideAutofillStructure(ViewStructure structure, int flags) {
            super.onProvideAutofillStructure(structure, flags);
            structure.setWebDomain(domain);
        }
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        String domain = getIntent().getStringExtra("domain");
        if (domain == null) domain = "bank.example";
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);

        TextView info = new TextView(this);
        info.setText("Navegador falso. Declara webDomain = " + domain);
        root.addView(info);

        EditText user = new WebField(this, domain);
        user.setHint("usuario");
        user.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);
        user.setAutofillHints(View.AUTOFILL_HINT_USERNAME);
        root.addView(user);

        EditText pass = new WebField(this, domain);
        pass.setHint("contraseña");
        pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pass.setAutofillHints(View.AUTOFILL_HINT_PASSWORD);
        root.addView(pass);

        Button send = new Button(this);
        send.setText("Enviar");
        send.setOnClickListener(v -> finish());
        root.addView(send);
        setContentView(root);
    }
}
EOF
```

The fields on this screen also serve as a **paste target** in DT-04 (the clipboard is only read by
the app with focus: a field of our own avoids depending on another app).

### 4.4 Build, install and grant permissions

```sh
cd ~/openpassword-testapps
./gradlew assembleDebug
adb install -r overlay/build/outputs/apk/debug/overlay-debug.apk
adb install -r fakebrowser/build/outputs/apk/debug/fakebrowser-debug.apk
```

Overlay permission (`SYSTEM_ALERT_WINDOW`), which **must be granted by hand**: it is requested from button 1
of the «Overlay de prueba» app (it opens the *Display over other apps* screen) or, without root, with:

```sh
adb shell appops set test.overlay SYSTEM_ALERT_WINDOW allow
adb shell appops get test.overlay SYSTEM_ALERT_WINDOW        # must say: allow
```

Using the overlay: open «Overlay de prueba» and press **2** (full) or **3** (300 px bottom strip;
it can be changed in `OverlayService.java`), press Home and open OpenPassword: the overlay stays
drawn over any app. Button **4** removes it. Always check in the launcher that the overlay
**is visible** (positive control: without it, nothing has been tested).

Using the fake browser: `adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example`.

### 4.5 Uninstall and clean up

```sh
adb shell am force-stop test.overlay
adb uninstall test.overlay
adb uninstall test.fakebrowser
adb shell pm list packages | grep -E "package:test\." || echo "limpio"
```

Uninstalling `test.fakebrowser` also removes it as default browser if it had been chosen (DT-08).
Granted permissions are lost on uninstall. Then delete `~/openpassword-testapps` if it is not
going to be used again.

## 5. Tests

Conventions for each test: **Devices** (which API it needs), **Prerequisites**, **Steps**,
**Expected result** (what the code intends; it is not a result), and **Covers** (finding or threat).
Unless stated otherwise, the test app is `$PKG` with the test vault (2.4) **unlocked**.

Common steps that are repeated:

- **Restart the process** of OpenPassword (it clears in-memory states such as the «once per process» warning
  and the browser cache): `adb shell am force-stop "$PKG"`.
- **Enable OpenPassword as the autofill service**: in OpenPassword → Settings → *Autorrelleno*
  (it opens the system dialog; `SettingsScreen.kt:236-253`). Note the original service beforehand (2.7).
- **Launch the fake browser**: `adb shell am start -n test.fakebrowser/.MainActivity --es domain <dominio>`.
- **Remove the overlay**: button 4 of «Overlay de prueba».

<a id="dt-01"></a>
### DT-01 · Anti-tapjacking, API 31+

**Goal.** Check that, on Android 12 or later, `setHideOverlayWindows(true)` hides an
overlay from another app while OpenPassword is in the foreground, and that touches work normally.

**What it verifies.** `OverlayProtection.kt:44-46` (`filterTouchesWhenObscured = true` and
`setHideOverlayWindows(true)` if `SDK_INT >= S`), applied in the three activities
(`MainActivity.kt:46`, `AutofillAuthActivity.kt:133`, `SaveLoginActivity.kt:112`); permission
`HIDE_OVERLAY_WINDOWS` in `AndroidManifest.xml:12` (required by `VerifyManifest`).

**Devices.** API 31 or higher, physical. See [2.9](#29-minimum-device-matrix).

**Prerequisites.** `overlay` and `fakebrowser` APKs installed and `SYSTEM_ALERT_WINDOW` permission
granted (4.4). OpenPassword as the autofill service (for the other two activities).

**Steps.**

1. Check that the permission is granted (it is an install-time one):
   `adb shell dumpsys package "$PKG" | grep HIDE_OVERLAY_WINDOWS` must show `granted=true`.
2. Open «Overlay de prueba» and press **2** (full). Press Home. **Positive control**: the red rectangle
   «OVERLAY DE PRUEBA (full)» must be visible over the launcher. Open the fake browser: the overlay is also
   visible over it. Photo.
3. Open OpenPassword with the vault **locked** (unlock screen). Observe: **is the overlay visible?**
   Photo with another camera (screenshots come out black: `FLAG_SECURE`).
4. Type the test password and press **Desbloquear**. Note whether it responds to the first touch.
5. In the list, tap an item and go back. Note whether any touch is lost and whether a message appears
   («Otra app está mostrando algo encima de OpenPassword…») or the red warning card at the top.
6. Press Home: **does the overlay reappear** over the launcher? (It is the control that it is still active.)
7. Repeat 2-6 with the **partial** overlay (button 3).
8. With the full overlay active, repeat 3-5 in the other two activities:
   - `AutofillAuthActivity`: in the fake browser (`--es domain bank.example`), tap the user field and
     the «Buscar en OpenPassword» dropdown.
   - `SaveLoginActivity`: in the fake browser type a user and a password and press **Enviar**;
     accept «Guardar» from the system.

**Expected result.** The overlay **is not visible** while OpenPassword is in the foreground in any of the three
activities, and it is visible in the launcher and in the fake browser. All touches work on the first attempt.
There is no warning (there is no obscured touch).

**Known limit of this test.** With `setHideOverlayWindows` active no obscured touch arrives, so
**the warning cannot be triggered on API 31+** without changing the code. The warning is verified in DT-02 (API
28-30) and its flag classification in the JVM test `OverlayProtectionTest`
(`android/app/src/test/…`). If an API 28-30 device is missing, the warning remains unverified on device
and is recorded as `blocked` in DT-02.

**Covers.** A7; [ID-INT-13](internal-review.md#id-int-13)) (the implementation and its tests do not reach what
the ADR describes).

<a id="dt-02"></a>
### DT-02 · Anti-tapjacking, API 28-30

**Goal.** Check that without `setHideOverlayWindows` (it does not exist before Android 12) the
`filterTouchesWhenObscured` filter discards fully obscured touches, that the warning is shown once, and what
happens with a **partially** obscured touch (documented residual risk).

**What it verifies.** `OverlayProtection.kt:17-31` (`Obscured.FULL`/`PARTIAL`), `:44` (filter), `:57-62`
(`warnIfObscured`: `Toast` once per process, `OverlayWarning.report()` in `:39`), and the
`OverlayWarningBanner` card (`Components.kt:208-219`, mounted in `AppRoot.kt:47`). The threat model says:
«a **partially** obscured touch is delivered (with a warning)» ([`threat-model.md`](../../threat-model.md)), A7).

**Devices.** API 28, 29 or 30 (physical or emulator; it is recorded). See 2.9.

**Prerequisites.** As in DT-01. Vault unlocked, on a screen with a clear button (for example, the
vault list with the add button).

**Steps.**

1. `adb shell am force-stop "$PKG"` and open OpenPassword (the «once per process» warning has not fired).
2. **Full** overlay (button 2). **Positive control**: it is visible over the launcher. Open OpenPassword:
   **the overlay is visible** on top (on API < 31 it is not hidden). Photo.
3. Tap a button in OpenPassword (for example, the add item one). Note whether **the action runs**.
4. Note whether the message «Otra app está mostrando algo encima de OpenPassword. Por seguridad se
   ignoran los toques tapados.» appears (a long `Toast`) and/or the red card with that text at the top.
5. Tap the same button again: note whether a second `Toast` appears (it should not: once per process) and whether the
   card is still there.
6. Remove the overlay (button 4). Note whether the card remains (`OverlayWarning` is not reset until the
   process is closed).
7. `adb shell am force-stop "$PKG"`, open OpenPassword and enable the **partial** overlay (button 3; strip of
   300 px at the bottom).
8. Tap a button **in the upper part** (outside the strip, but with the window partially obscured).
   Note whether the action runs and whether the warning appears.
9. Repeat 8 but tap **inside** the red strip: it must behave as in step 3.

**Expected result.**

- Full overlay: the touch **does not run the action** (the filter discards it) and the warning appears **once**
  (`Toast`) plus the card.
- Partial overlay, touch outside the strip: the touch **is delivered** (the action runs) and the warning appears.
  This is the **documented residual risk**, not a bug: it is recorded that it has been observed.
- Touch inside the strip: as with the full one.

If the system does not set the flag as the code assumes (for example, there is no warning in the partial case), it
is recorded as is and a finding is opened (section 7).

**Covers.** A7; ID-INT-13; the «only the filter remains» caveat in `threat-model.md` A7.

<a id="dt-03"></a>
### DT-03 · Protected dialogs (`ProtectedAlertDialog`)

**Goal.** Repeat DT-01/DT-02 on dialog windows, which are different windows and do not inherit the
activity's protection.

**What it verifies.** `ProtectedAlertDialog` (`Components.kt:187-205`) calls `ProtectDialogWindow`
(`OverlayProtection.kt:67-78`), which finds the `DialogWindowProvider` window and applies the same
protection to it. Dialogs used: «¿Borrar «…»?» (`ItemDetailScreen.kt:221-223`) and «Importar copia»
(`SettingsScreen.kt:429-431`, with a password field).

**Devices.** API 31+ (physical) **and** API 28-30 (physical or emulator).

**Prerequisites.** DT-01/DT-02. For the import dialog, a copy of another vault on the phone:
```sh
cd "$OP_REPO"
SK="$(cargo run -q -p opvault-cli -- new-secret-key)"; echo "$SK"        # write it down: PRUEBAS
printf 'prueba-copia-1\n' | cargo run -q -p opvault-cli -- sample demo.opvault --password-stdin --secret-key "$SK"
adb push demo.opvault /sdcard/Download/demo.opvault
```

**Steps (API 31+).**

1. Full overlay (button 2). Open the `Borra-me` item and tap the bin icon: «¿Borrar «Borra-me»?» appears.
   **Is the overlay visible over the dialog?** Photo. Press **Cancelar**.
2. Settings → **Importar copia** → choose `demo.opvault`: the «Importar copia» dialog appears. **Is the
   overlay visible?** Photo. Cancel.

**Steps (API 28-30).**

3. `adb shell am force-stop "$PKG"`. Full overlay. Open `Borra-me` → bin → dialog. **Tap
   «Borrar»** (with the overlay on top). Note whether the item **is deleted** (it should not be) and whether the warning appears.
   If it was deleted, recreate it (2.4).
4. Remove the overlay and repeat with the import dialog: tap **Importar** with the full overlay and the
   password field filled in. Note whether the import starts (it should not).
5. Partial overlay: open the dialog and tap a button **outside** the strip: it must be delivered (as in DT-02).

**Expected result.** API 31+: the overlay is not visible over any dialog. API 28-30: a fully obscured
touch on a dialog button **does not** run the action and the warning appears; the partial one is delivered.

**Covers.** A7; ID-INT-13 (the finding notes that the current instrumented tests do not cover the
dialogs: `androidTest/…/OverlayProtectionTest.kt:12-16`).

<a id="dt-04"></a>
### DT-04 · Clipboard: wipe after 30 s and sensitive flag

**Goal.** Confirm or refute [ID-INT-14](internal-review.md#id-int-14)): the 30 s wipe
probably **does not act if OpenPassword no longer has focus**, which is the normal use (copy and paste into
another app). And check the sensitive flag on Android 13+.

**What it verifies.** `SensitiveClipboard.kt:21-31` (`copy`: label `OpenPassword`, flag
`EXTRA_IS_SENSITIVE` on API 33+, timer of `CLEAR_AFTER_MS` = 30 000 ms),
`:34-39` (`clearIfOurs`: compares `primaryClipDescription?.label`; the comment itself says that since
Android 10 it can be `null` without focus, and then nothing is wiped) and `OpenPasswordApp.kt:75-80` (when the
screen turns off: `session.lock()` and `clipboard.clearIfOurs()`). ID-INT-14 asks to test on API 29, 33 and 36.

**Devices.** API 29, 33 and 36 (it is run on each; the sensitive flag is only visible on 33+).

**Prerequisites.** `Portapapeles` item (password `Prueba-pw-7`). The **fake browser** installed
(its fields are the paste target). Stopwatch (the phone's is fine; or the computer's).

How to «paste» unambiguously: open the fake browser, **long-press** its password field →
**Pegar**. If there is nothing in the clipboard, «Pegar» does not appear or the field stays empty. Photo/screenshot of the
field (the fake browser screenshot does work).

**DT-04a · Foreground control.**

1. Open `Portapapeles` → reveal and **copy** the password field (`ItemDetailScreen.kt:98`).
2. **Without leaving OpenPassword**, wait 35 s.
3. Go to the fake browser and paste.

**DT-04b · Background (the ID-INT-14 case).**

1. Copy the `Portapapeles` password in OpenPassword. Set the stopwatch to 0.
2. Switch **immediately** to the fake browser and let it stay in the foreground (with the field focused).
3. At 35 s, **paste** into the field.
4. Also note: does the paste show `Prueba-pw-7`?
5. Go back to OpenPassword (still unlocked if less than 30 s of lock have passed; if not, unlock),
   wait another 35 s **in the foreground** and paste again. Note whether the clipboard is wiped on return.

**DT-04c · Screen off.**

1. Copy the password. Turn the screen off (power button). Wait 35 s.
2. Turn it on, unlock the phone, open the fake browser and paste.

**DT-04d · Sensitive flag (API 33+).**

1. Copy the password. Observe the clipboard preview the system shows (Android 13+: a
   box at the bottom left) and, if the keyboard offers the clipboard content, its suggestion.
2. **Is the text `Prueba-pw-7` visible or is it shown hidden (dots)?** Photo. On API 28-32 there is no flag
   (ID-INT-15, accepted): note what is visible, but it does not count as a failure.

**Expected result.** a) On pasting there is nothing (it was wiped). b) and c) By design, it is also wiped: the
`Runnable` and the screen receiver call `clearIfOurs`. **If `Prueba-pw-7` comes out on pasting, the wipe
did not act: `fail` and ID-INT-14 is confirmed** (the probable cause is the one in the comment of
`SensitiveClipboard.kt:37`, although on Android 11+ it may also be that the background process is
frozen and the `Runnable` never runs; only the symptom is recorded). d) On API 33+ the content is
shown hidden.

**Covers.** A7; ID-INT-14; ID-INT-15. It is the test that decides whether «with wipe» stays in the A7 row of
`threat-model.md`.

<a id="dt-05"></a>
### DT-05 · Public suffix list on the device

**Goal.** Confirm that `public_suffix_list.dat` **loads and is applied** on the device (and with R8
in the release build), and that a login saved for a public suffix is not offered on its subdomains.

**What it verifies.** `PublicSuffix.kt:18-25` (loaded through `classLoader.getResourceAsStream`; if it fails,
`isAvailable` is false and it fails closed), `LoginMatcher.kt:43-48` (a subdomain only matches if
`PublicSuffix.isAvailable` and the stored host **is not** a public suffix). See
[ID-INT-20](internal-review.md#id-int-20)): the check of the resource in the APK exists, the check of loading on the
device and with R8 does not. **Limitation**: the debug build does **not** go through R8
(`isMinifyEnabled = true` only in `release`, `android/app/build.gradle.kts:55`); that is why there is a variant
with the release APK.

**Devices.** Any (physical or emulator). The R8 variant only on an emulator or device **without** the
official app installed (see 5.R8).

**Prerequisites.**
- Items from 2.4: `alice.github.io` (`https://alice.github.io`) and `Sufijo github.io`
  (`https://github.io`), `Wikipedia` (`https://wikipedia.org`).
- The **fake browser as default**: System Settings → Apps → Default apps → **Browser
  app** → «Navegador falso». Check with
  `adb shell cmd role get-role-holders android.app.role.BROWSER` (it must list `test.fakebrowser`).
  Then, `adb shell am force-stop "$PKG"` (the browser check is cached for 5 min:
  `BrowserCheck.kt:76`).
- OpenPassword as the autofill service.

This uses the fake browser because, being the default, its `webDomain` is accepted
(`BrowserCheck.kt:68-73`; it is the residual risk of DT-08) and it allows testing any domain without depending
on a real page. The contrast with a real browser is in DT-06.

**Steps.** For each row, launch
`adb shell am start -n test.fakebrowser/.MainActivity --es domain <dominio>`, tap the user field and
note **which items the dropdown offers** (photo):

| Declared domain | Expected | What it shows |
|---|---|---|
| `alice.github.io` | `alice.github.io` (exact match). **Not** `Sufijo github.io` | A suffix login does not cover its subdomains (`LoginMatcher.kt:47`) |
| `evil.github.io` | **None** (only «Buscar en OpenPassword») | The case in the statement: `github.io` is a public suffix, and `alice.github.io` is another domain |
| `x.alice.github.io` | `alice.github.io` | **Positive control**: a subdomain of a registrable domain matches **only if the list loaded** |
| `en.wikipedia.org` | `Wikipedia` | Second positive control (it needs the list) |
| `github.io` | `Sufijo github.io` | Exact match with the stored suffix |

**Expected result.** As in the table. **Interpretation**: if the two positive control rows
(`x.alice.github.io`, `en.wikipedia.org`) offer **nothing**, the list **did not load** and the app is
failing closed (exact match): that is the ID-INT-20 finding, not a pass. A pass requires that
**the controls offer** the item and **the negatives do not**.

**5.R8 · Variant with the release APK** (only an emulator or device without the official app; the package is
`io.github.rldona.openpassword`, with no suffix, and **would clash with the real app** on the main phone):

```sh
cd "$OP_REPO/android" && ./gradlew :app:assembleRelease
ls app/build/outputs/apk/release/        # app-release.apk or app-release-unsigned.apk
BT="$HOME/Library/Android/sdk/build-tools/37.0.0"
"$BT/apksigner" verify --print-certs app/build/outputs/apk/release/app-release.apk   # signed?
```

If it is not signed, sign it with a **throwaway** key (never the release one) and install it:

```sh
keytool -genkeypair -keystore dt-desechable.jks -alias dt -keyalg RSA -keysize 2048 -validity 30 \
  -storepass desechable -keypass desechable -dname "CN=dt-pruebas"
"$BT/zipalign" -p 4 app/build/outputs/apk/release/app-release-unsigned.apk dt-alineado.apk
"$BT/apksigner" sign --ks dt-desechable.jks --ks-pass pass:desechable --out dt-release.apk dt-alineado.apk
adb install -r dt-release.apk
```

Repeat the table with `PKG=io.github.rldona.openpassword` (another test vault, on that device). The
signing commands are the SDK standard ones and **have not been run** when writing this plan.

**Covers.** ID-INT-20; A12 and A17 (subdomain limit).

<a id="dt-06"></a>
### DT-06 · `webDomain` from a real browser (Chrome)

**Goal.** Check with **Chrome** that autofill receives a plausible `webDomain`, that it is accepted
(Chrome is in `KnownBrowsers`), that it offers the correct login and that the token opens the right activity.

**What it verifies.** `StructureParser.kt:27-28` (`targetFor`), `BrowserCheck.kt:28` (`com.android.chrome`
in the list), `LoginMatcher.kt:22-36`, and the token path (`AutofillAuthActivity.kt:87-98`,
`AutofillRequestTokens.kt`).

**Devices.** Physical device with the system Chrome (note its version:
`adb shell dumpsys package com.android.chrome | grep versionName`). Default browser: Chrome.

**Prerequisites.** `GitHub` item (`https://github.com`). Chrome's autofill service:
Chrome → Settings → *Autofill services* → **Autofill with another service**
([`android/README.md`](../../../android/README.md)), «Autorrelleno»), and OpenPassword as the system service.
**Do not submit** the GitHub form: filling it in is enough.

**Steps.**

1. In Chrome open `https://github.com/login`. Tap the user field. **Does `GitHub` appear** in the
   dropdown? Tap it: are the user (`testuser`) and password filled in? Photo.
2. Lock OpenPassword (the padlock icon in the list, `VaultListScreen.kt:87`). Reload the page and tap the field: it must show
   «Desbloquear OpenPassword».
3. Tap it: the OpenPassword window opens. Note the text «Para: …» (it must be `github.com`) and the
   section («Coinciden» with `GitHub`). Unlock, choose `GitHub`: the window closes and Chrome is filled in.
4. Negative: open `https://en.wikipedia.org/w/index.php?title=Special:UserLogin` and tap the user
   field: `GitHub` **must not** appear; `Wikipedia` must (if the item exists).
5. Note whether in any window a login from another site appears without you having chosen it by hand.

**Expected result.** Steps 1-3: the `github.com` login is offered and filled in in Chrome; the target in the
window is `github.com`. Step 4: `GitHub` is not offered on Wikipedia.

**Covers.** A17; [ID-INT-16](internal-review.md#id-int-16)) (fix: the `webDomain` of a browser is only
believed).

<a id="dt-07"></a>
### DT-07 · App that declares itself a browser

**Goal.** Check that an app that declares a `VIEW` `http`/`https` `intent-filter` **and** a
fake `webDomain` **does not** receive web datasets, because it is not a known browser and not the default one.

**What it verifies.** `BrowserCheck.kt:68-73` (`isBrowser`: it is in `KnownBrowsers.PACKAGES` **or** it is the
default and handles `https` and `http`) and `:44` («declaring a filter is not enough: it requires no permission»). It is the
**second fix** of ID-INT-16 (`internal-review.md`, «Segunda corrección»).

**Devices.** Any with a known browser as default (Chrome, Firefox…).

**Prerequisites.** `Banco falso` item (`https://bank.example`). `fakebrowser` installed and **not**
default: `adb shell cmd role get-role-holders android.app.role.BROWSER` must not list
`test.fakebrowser`. `adb shell am force-stop "$PKG"` (cold cache). OpenPassword as the autofill
service.

**Steps.**

1. `adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example`.
2. Tap the user field. Note what the dropdown offers (photo): does **`Banco falso`** appear?
3. Tap «Buscar en OpenPassword». In the window note: the text «Para: …», the section title
   («Coinciden» or «Elige un login») and whether there is a «Recordar el login elegido para esta app» checkbox.
   **Do not choose any login**; close with the X.
4. Lock OpenPassword and repeat 1-2: it must offer «Desbloquear OpenPassword».
5. Repeat 1-3 without restarting the process, after waiting **more than 5 min** (the cache expires,
   `BrowserCheck.kt:76`), to see that the result does not change.

**Expected result.** The dropdown does **not** offer `Banco falso`; only «Buscar en OpenPassword» (or
«Desbloquear…»). In the window: «Para: test.fakebrowser» (the package, **not** `bank.example`), «Elige un
login» and the «Recordar…» checkbox visible (because it is treated as an app).

**Covers.** A17; ID-INT-16 (second fix).

<a id="dt-08"></a>
### DT-08 · Default browser

**Goal.** Document the behaviour when the user chooses an app as the default browser:
it is the **residual risk** of A17 («a browser that the user themselves chooses as
default and that is malicious is believed»).

**What it verifies.** `BrowserCheck.kt:83-87` (`resolveActivity` of `ACTION_VIEW` `https` with
`MATCH_DEFAULT_ONLY`; the `android` package, the system selector, is discarded) and `:72`
(`packageName == current.default && packageName in current.packages`); `AutofillAuthActivity.kt:102,124`
(`canRemember` false in browsers).

**Devices.** Any. **When finished, restore the original browser** (2.7).

**Prerequisites.** As in DT-07 (having done DT-07 first, with the fake browser not yet default).

**Steps.**

1. System Settings → Default apps → **Browser app** → «Navegador falso».
   `adb shell cmd role get-role-holders android.app.role.BROWSER` must list `test.fakebrowser`.
2. `adb shell am force-stop "$PKG"` and unlock OpenPassword.
3. `adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example`; tap the user
   field. Note whether the dropdown offers **`Banco falso`** (photo).
4. Tap «Buscar en OpenPassword» (or the other dropdown) and note «Para: …» and whether there is a «Recordar…» checkbox.
5. Restore Chrome (or the original browser) as default, `adb shell am force-stop "$PKG"`, and
   repeat 3: it must go back to the DT-07 behaviour.

**Expected result (documented).** With the fake browser as default **its `webDomain` is believed**:
`Banco falso` is offered directly, the window says «Para: bank.example» and there is **no** «Recordar…» checkbox.
That **is not a bug**: it is the described residual risk. The result is `pass` if it matches this and
`fail` if not (for example, if it is offered without being the default, or not offered while being it: both
contradict `threat-model.md` A17).

**Covers.** A17 (residual risk); ID-INT-16.

<a id="dt-09"></a>
### DT-09 · End-to-end autofill

**Goal.** Go through a real browser: save a login, fill it in, update its password, and the
token path with the vault locked, including screen rotation.

**What it verifies.** `OpAutofillService.kt:37-45` (`SaveInfo`), `:55-70` (`onSaveRequest`: the typed
password stays in memory and the window receives only a token), `SaveLoginActivity` («Guardar»,
«Actualizar «…»», «Guardar como nuevo»), `AutofillAuthActivity.kt:87-98` (old extras discarded,
request by token, fails closed) and `:159-162` (`RequestHolder` keeps the request on rotation).

**Devices.** Physical device with Chrome, API 33+ (ideally also one with API 28-30).

**Prerequisites.** A login page of **your own** (do not send data, not even made-up data, to a site
of someone else). With GitHub Pages: a public repository `<tu-usuario>.github.io` with a `login.html`
(`<form action="#">`: there is no server, nothing is sent):

```html
<!doctype html><meta charset="utf-8"><title>Login de prueba</title>
<form action="#">
  <input name="user" type="text" autocomplete="username" placeholder="usuario">
  <input name="pass" type="password" autocomplete="current-password" placeholder="contraseña">
  <button>Entrar</button>
</form>
```

Note the URL: `https://<tu-usuario>.github.io/login.html`. **Without** an item saved for that host.
Chrome with OpenPassword as the autofill service (DT-06). Delete the repository when finished.

**DT-09a · Save.**

1. In Chrome open the page; type `alice` and `Prueba-pw-A`; press **Entrar**.
2. The system prompt «Guardar en OpenPassword» must appear. Accept it: «Guardar en
   OpenPassword» opens with «Para: `<tu-usuario>.github.io`» and the user filled in. Press **Guardar**.
3. Open OpenPassword: the login exists with that URL. Repeat 1-2 but **reject** the prompt: nothing must
   be saved.

**DT-09b · Fill in.** Reload the page and tap the user field: the dropdown offers the new login;
tap it: `alice` and `Prueba-pw-A` are filled in.

**DT-09c · Update password.** Clear the fields, type `alice` and `Prueba-pw-B`, **Entrar**. The save
prompt must propose **updating** the existing login («Actualizar «…»»). Accept; in the item, the
password is `Prueba-pw-B` and the password history keeps `Prueba-pw-A`.

**DT-09d · Token and rotation.**

1. Lock the rotation: `adb shell settings put system accelerometer_rotation 0` and
   `adb shell settings put system user_rotation 0`. Lock OpenPassword (the padlock in the list).
2. In Chrome, reload the page, tap the field → **Desbloquear OpenPassword** → its window opens.
3. **Rotate the screen** with `adb shell settings put system user_rotation 1` **before** typing the
   password. Note whether the window is still open.
4. Type the password and unlock (the «Coinciden» list appears). Rotate again
   (`user_rotation 0`). Note whether it is still open.
5. Choose the login: the window closes and Chrome fills in the fields.
6. Restore the rotation (2.7).

**Expected result.** a) The login is only saved after confirming. b) It is filled in. c) Updating is
proposed, not duplication. d) The window **does not close** on rotation and the login is filled in (the request
survives the rotation in the `ViewModel` even though the token is single-use). If the window closes
by itself after rotating, `fail`: the token flow loses the request.

**Covers.** A12, A18; [ID-INT-26](internal-review.md#id-int-26)); save/update functionality.

<a id="dt-10"></a>
### DT-10 · «Recordar para esta app»

**Goal.** Check that the «Recordar el login elegido para esta app» checkbox is only offered (and only
acts) in normal apps, never in browsers.

**What it verifies.** `AutofillAuthActivity.kt:102` (`isBrowserApp`), `:124`
(`canRemember = target is FillTarget.App && !isBrowserApp`) and `PickLogin` (`:195-198`: when choosing by hand a
login that did not match, with the checkbox ticked, `androidapp://<paquete>` is added to its URLs), plus the
warning text for websites with no match («Ningún login tiene guardado …»).

**Devices.** Any. Chrome as default (as in DT-07).

**Prerequisites.** `Banco falso` and `GitHub` items. `fakebrowser` not default.

**Steps.**

1. **Normal app.** `adb shell am start -n test.fakebrowser/.MainActivity --es domain bank.example`; tap the
   field → «Buscar en OpenPassword». Note that the «Recordar…» checkbox is visible and ticked.
2. Choose `Banco falso` with the checkbox ticked. Go back to OpenPassword and open `Banco falso`: its URLs
   now include `androidapp://test.fakebrowser`.
3. Reopen the fake browser and tap the field: the dropdown must offer `Banco falso` **directly**
   (match by exact package).
4. **Browser.** In Chrome open `https://en.wikipedia.org/w/index.php?title=Special:UserLogin`, tap the user
   field → «Buscar en OpenPassword». Note: there is **no** «Recordar…» checkbox and the text «Ningún
   login tiene guardado en.wikipedia.org. Comprueba que es el sitio que esperas antes de rellenar.» is shown.
5. Choose `GitHub` (by hand). Open `GitHub` in OpenPassword: its URLs **must not** have gained
   `androidapp://com.android.chrome` or anything like it.
6. Cleanup: remove the `androidapp://test.fakebrowser` URL from `Banco falso`.

**Expected result.** Checkbox visible only in step 1; in Chrome, absent and with no URL added.

**Covers.** ID-INT-26 (`:102,124`); A12.

<a id="dt-11"></a>
### DT-11 · Root warning

**Goal.** Check that the warning appears when there is a signal of root or of a debug build,
that it **blocks** nothing and that dismissal works and persists.

**What it verifies.** `RootSignals.kt:17-47` (`RootDetector.evaluate`: `SU_BINARY`, `ROOT_MANAGER_APP`,
`TEST_KEYS`, `DEBUG_BUILD` if `Build.TYPE` is `userdebug` or `eng`; `shouldWarn`; text
`ROOT_WARNING_TEXT`), `AndroidDeviceProbe.kt`, `OpenPasswordApp.kt:38-56` (signals and dismissal),
`Components.kt:226-235` (`RootWarning`), `UnlockScreen.kt:145` (dismissible) and `SettingsScreen.kt:235`
(informative, no dismissal). Design decision: [ADR-AUD-06](decisions.md)); it **never blocks**.

**Devices.** A `userdebug` emulator («Google APIs» image, 2.9). The main phone is **not** rooted.
Optional: a dedicated device with Magisk (not needed: `DeviceProbe` is the test boundary;
`RootDetectorTest` covers each signal on the JVM).

**Prerequisites.** Emulator running, `ANDROID_SERIAL` pointing at it
(`adb devices` must list only the emulator). Install the debug APK and create a test vault.
```sh
adb -e shell getprop ro.build.type        # userdebug
adb -e shell getprop ro.build.tags        # usually test-keys on these images
adb -e shell ls /system/xbin/su /system/bin/su 2>&1
adb -e install -r "$OP_REPO/android/app/build/outputs/apk/debug/app-debug.apk"
```

**Steps.**

1. Open OpenPassword with the vault locked. Note whether the unlock screen shows the card with «Este
   dispositivo parece tener root o una compilación de depuración…» and the **Entendido** button.
2. **Without dismissing**, unlock with the password. Note whether there is any block or impediment.
3. Settings → «Seguridad» section: note whether the same text appears as an informative block **without** the
   «Entendido» button.
4. Lock, tap **Entendido** on the unlock screen: the card must disappear.
5. `adb -e shell am force-stop "$PKG"`, open it again: the card must not reappear (the dismissal is
   stored with the set of signals). Settings still show the block.
6. **Negative control** on a normal phone (`ro.build.type=user`, no `su`): the card **must not**
   appear (unless a custom ROM; the cause is recorded).

**Expected result.** 1: it appears. 2: it does not block. 3: informative. 4-5: dismissal works and persists.
6: no false positives on a stock phone.

**Covers.** A10; ADR-AUD-06.

<a id="dt-12"></a>
### DT-12 · Biometrics on Android 9

**Goal.** Check the biometrics fix on API 28: Settings does not crash and the fingerprint is offered.

**What it verifies.** `Biometrics.kt:22-49` (`availabilityCheckFor`: API 28 uses the `Fingerprint` branch),
`:63-74` (`FingerprintManager` by reflection, because it is no longer in the `compileSdk` 37 stubs),
`:79-` (`authenticateBiometric`: on Android 9 the prompt is fingerprint-only and always asks for confirmation),
`SettingsScreen.kt:83,254` (the «Desbloquear con huella» row only appears if `strongBiometricsAvailable`)
and `UnlockScreen.kt` (fingerprint button). Origin: commit `1649636` («biometrics on Android 9»).

**Devices.** API 28. A phone with Android 9 and a fingerprint sensor, or the `system-images;android-28;
google_apis;arm64-v8a` emulator (or `x86_64`) with a **virtual fingerprint**. Optional: API 29 (`ManagerLegacy` branch).

**Prerequisites.** App installed and test vault created. The device with a screen lock (PIN) and
**one fingerprint enrolled**. In the emulator: Settings → Security → Fingerprint → enroll; to «touch the sensor»:
`adb -e emu finger touch 1`.

**Steps.**

1. **With no fingerprint enrolled** (before enrolling): open OpenPassword Settings. Note whether the app crashes (it must
   not) and that the «Desbloquear con huella» row **does not** appear.
2. Enroll a fingerprint. Open Settings again: note whether it crashes and whether the row **appears**.
3. Enable it: the system biometric prompt is shown. «Touch» the sensor. Note the result.
4. Lock and unlock with the fingerprint (button on the unlock screen). Note whether it works.
5. `adb logcat -b crash -d` must be free of `OpenPassword`/`FingerprintManager`/`NoSuchMethod`.

**Expected result.** Settings does not crash in any case; the row only appears with a fingerprint enrolled; the
fingerprint enables and unlocks. A reflection exception (e.g. `NoSuchMethodException`) or Settings closing
is `fail`.

**Covers.** Biometrics fix (`1649636`); `internal-review.md` §3 (Keystore keys on API 28-29).

<a id="dt-13"></a>
### DT-13 · KDBX 4 import with a real file

**Goal.** Close what [`android/README.md`](../../../android/README.md)) says: «La lectura de KDBX 4 aún
no se ha probado con un fichero real». And [`core/src/import/testdata/README.md`](../../../core/src/import/testdata/README.md)),
«Pendiente»: a real KDBX 4 created from the KeePassXC interface is missing.

**What it verifies.** `core/src/import/kdbx.rs` (KDBX 4 path: header, per-block HMAC, ChaCha20,
Argon2; limits in `:33-41` and `:544-561`) through the app's import
(`ExternalImport.kt`; messages in `:65-78`). Note: `keepassxc-cli` only creates KDBX 3.1 (checked with
KeePassXC 2.8.0: `db-create` writes version 3.1 with the «AES» KDF), so **KDBX 4 is created from the
graphical interface**.

**Devices.** Any (with ≥ 1 GiB of free RAM for 13a-13c).

**Prerequisites.** KeePassXC (its version is recorded: `keepassxc-cli --version`). The data is
**made up**.

**How to generate the files** (KeePassXC interface; Database → Settings → Security):

| File | Encryption | KDF | Credentials |
|---|---|---|---|
| `kdbx4-a.kdbx` (13a) | ChaCha20 | Argon2id, 64 MiB, 10 iterations, 2 threads | Password `prueba-kdbx4-a` |
| `kdbx4-b.kdbx` (13b) | AES-256 | Argon2d, 64 MiB, 10 iterations, 2 threads | Password `prueba-kdbx4-b` |
| `kdbx4-c.kdbx` (13c) | ChaCha20 | Argon2id, 64 MiB | Password `prueba-kdbx4-c` **and** key file (`kdbx4-c.keyx`, created by KeePassXC) |
| `kdbx4-d.kdbx` (13d) | **Twofish** | Argon2d, 64 MiB | Password `prueba-kdbx4-d` |
| `kdbx4-e.kdbx` (13e) | ChaCha20 | Argon2id, **1024 MiB** of memory, 3 iterations | Password `prueba-kdbx4-e` |

Content of 13a, 13b and 13c (the same in all three): root group and these entries.

| Entry | Data |
|---|---|
| `Login básico` | user `alice@example.com`, password `Prueba-k-1`, URL `https://example.com`, notes «nota de prueba» |
| `Con TOTP` | a KeePassXC TOTP field (right-click → *TOTP Settings…*, secret `JBSWY3DPEHPK3PXP`) |
| `Campo protegido` | a **protected** custom attribute `PIN` = `4321` |
| `Espacios` | password `  con espacios  ` (two spaces at the start and at the end) |
| `Unicode` | title `Ñandú ✓ — prueba` and user `ñ@example.com` |
| `Con historial` | edit the password twice (the entry keeps history) |
| `En la papelera` | create an entry and **delete it** (it goes to the recycle bin) |

Check the format before taking it to the phone. The version is in bytes 8-11 of the header
(minor and major, in *little-endian*): a KDBX 3.1 from `keepassxc-cli` shows `0100 0300`; a KDBX 4.0 must
show `0000 0400` (a 4.1, `0100 0400`). And check the parameters:

```sh
xxd -l 12 kdbx4-a.kdbx                       # ... 0000 0400  => KDBX 4.0
keepassxc-cli db-info kdbx4-a.kdbx           # encryption and KDF (in your language: «Cifrado», «KDF»)
adb push kdbx4-a.kdbx kdbx4-b.kdbx kdbx4-c.kdbx kdbx4-c.keyx kdbx4-d.kdbx kdbx4-e.kdbx /sdcard/Download/
```

Photo or screenshot of the KeePassXC security screen as evidence of what was tested.

**Steps (each file).** Settings → **Importar de otro gestor** → choose the file → type the password
(and, in 13c, choose `kdbx4-c.keyx`).

- **13a, 13b, 13c**: note the summary the app shows before importing and press import. Then
  check each entry in the vault:
  - `Login básico`: title, user, password, URL and notes identical.
  - `Con TOTP`: the detail shows a 6-digit code with a countdown, and it matches
    `echo 'otpauth://totp/Prueba:alice?secret=JBSWY3DPEHPK3PXP' | cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- totp`
    in the same 30 s interval.
  - `Campo protegido`: `PIN` = `4321`, hidden until revealed.
  - `Espacios`: the password keeps the leading and trailing spaces.
  - `Unicode`: no broken characters.
  - `Con historial`: only the **current** password (the README: «sin papelera ni historial»).
  - `En la papelera`: it is **not** imported.
  - Total counter: that of visible entries minus the recycle bin ones.
- **Re-import** the same file (13a): it must not duplicate what already exists.
- **Wrong password** (13a): message «Contraseña o archivo de clave incorrectos…»
  (`ExternalImport.kt:66-67`) and you can try again without choosing the file again.
- **13c without the key file**: same message.
- **13d (Twofish)**: «Esta base de KeePass usa Twofish. Cámbiala a AES-256 o ChaCha20 en la configuración de
  la base.» (`ExternalImport.kt:70-71`).
- **13e (1 GiB)**: «La protección de esta base de KeePass es demasiado costosa para un teléfono. Bájala en
  la configuración de la base.» (`:72-73`; the KDBX ceiling is in `kdbx.rs:33-41`: 512 MiB of memory and 3
  GiB·pass). The app **must not close** and must reject it **before** deriving (immediately).

**Expected result.** 13a-13c import with the content above; 13d and 13e are rejected with the messages
given; the app does not close in any case. Any difference in a field is `fail` and which one is recorded.

**Covers.** Android README («KDBX 4 not tested with a real file»); [ID-INT-02](internal-review.md#id-int-02))
(KeePass KDF policy against the mobile ceiling: what is covered here is the rejection; the policy remains
open). If 13a and 13b pass, the file can be added to `core/src/import/testdata/` for a Rust test (see 7).

<a id="dt-14"></a>
### DT-14 · KDF and RAM ceiling

**Goal.** Import `.opvault` backups with high KDF parameters and check the message **without the app
closing**; and observe what happens right at the ceiling.

**What it verifies.** `ffi/src/lib.rs:33` (`MOBILE_MAXIMUM` = 512 MiB, 6 passes, 8 threads) and `:452-480`
(rejects **before** deriving), `KdfMemory.kt:10-11` (`kdfMemoryFits`: memory cannot exceed half
of the RAM), `VaultSession.kt:128-131,141,170` (`checkKdfFits`), the message in `VaultSession.kt:513-515`, and the open
risk: a memory failure in Argon2 aborts the process
([`decisions.md`](decisions.md)), «Riesgos que quedan abiertos»; `ffi`/`argon2` 0.5, infallible allocation).

**Devices.** All available; **test 14b is more revealing on the one with the least RAM** (`MemTotal` is
recorded).

**Prerequisites.** A disposable tool, **outside the repository**, that creates backups with a custom
KDF (the `opvault sample` CLI only uses `KdfParams::RECOMMENDED`, `cli/src/main.rs:168`). It was built with
this recipe (stable Rust, the repository's `Cargo.lock`) and generated the two files below:

```sh
mkdir -p ~/openpassword-kdfgen/src && cd ~/openpassword-kdfgen
cat > Cargo.toml <<EOF
[package]
name = "kdfgen"
version = "0.0.0"
edition = "2024"

[dependencies]
op-core = { path = "$OP_REPO/core" }
EOF
cp "$OP_REPO/Cargo.lock" .
cat > src/main.rs <<'EOF'
use op_core::{KdfParams, SecretKey, UnlockedVault, backup};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (m, t, p, out, sk) = (a[1].parse().unwrap(), a[2].parse().unwrap(), a[3].parse().unwrap(), &a[4], &a[5]);
    let sk = SecretKey::parse(sk).unwrap();
    let v = UnlockedVault::create("prueba-kdf-alto", &sk, KdfParams::argon2id(m, t, p)).unwrap();
    std::fs::write(out, backup::write(&v, &[], 0).unwrap()).unwrap();
}
EOF
cargo build --release

SK="$(cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- new-secret-key)"; echo "$SK"   # write it down: PRUEBAS
./target/release/kdfgen 1048576 3 4 alto.opvault "$SK"     # 1 GiB, 3 passes, 4 threads: above the ceiling
./target/release/kdfgen 524288 6 8 techo.opvault "$SK"     # 512 MiB, 6, 8: right at the ceiling
cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- inspect alto.opvault | grep -A4 '"kdf"'
adb push alto.opvault techo.opvault /sdcard/Download/
```

Each backup opens with the password `prueba-kdf-alto` and the secret key `$SK`. The backups are empty
(no items): what is tested is the derivation. Both took ~2 s to generate on a computer.

**DT-14a · Above the ceiling.**

1. Note the PID: `adb shell pidof "$PKG"`.
2. Settings → **Importar copia** → `alto.opvault`. Type the password and the secret key, **Importar**.
3. Note the message and how long it takes to appear. Run `pidof` again.
4. `adb logcat -b crash -d` and `adb logcat -d | grep -i -E "lowmemory|lmkd.*openpassword|OOM"`.

**DT-14b · At the ceiling.**

1. Same with `techo.opvault`. Watch the time with a stopwatch and note whether the app responds, whether any
   message is shown, and the PID before and after (`pidof`).
2. If the device has ≥ 1 GiB of RAM the Kotlin check (`totalMem / 2`) lets it through and 512 MiB
   are actually reserved.

**Expected result.**

- **14a**: «Esta copia necesita 1024 MiB de memoria para abrirse y este dispositivo no
  puede darlos. Ábrela en un dispositivo con más memoria.» appears immediately; the PID does not change; the vault stays unlocked and
  unchanged; with no entries in the crash log.
- **14b**: there is no single «correct» result. It is acceptable for it to open (taking a few seconds) or for it to be
  rejected with the previous message on a device with little RAM. **The app closing (different PID,
  `lmkd` entry, ANR) is `fail`**: it confirms the open risk «memory failure in Argon2 = abort» and
  it is recorded as a finding (section 7), it is not «fixed» here.

The «RAM not enough» case of `kdfMemoryFits` only occurs with less than 1 GiB of RAM for a 512 MiB ceiling;
on a current phone it can only be triggered with 14a (which trips the native ceiling, not the RAM one). The
RAM check is covered by `KdfMemoryTest` on the JVM.

**Covers.** ADR-AUD-07; open risk of abort due to memory; ID-INT-02 (the ceiling on the `.opvault` path).

<a id="dt-15"></a>
### DT-15 · Automatic backup and restore

**Goal.** Check that the automatic backup is written after a change, that rotation only deletes
our own backups, and that an automatic backup is restored into a new test vault.

**What it verifies.** `AutoBackup.kt:52` (`setFolder`: first backup when choosing the folder), `:69-80`
(`onVaultChanged` with `DEBOUNCE_MS` = 5 s and `onUnlocked`), `:96-101` (with the vault locked it stays
pending), `:124-146` (`write` and rotation; `KEEP` = 10 in `:178`), `BackupNames.kt:8-20` (only names
`openpassword-auto-AAAAMMDD-HHMMSS.opvault`), `VaultSession.kt:137` (`restore`: only with no vault on the
device) and `RestoreScreen.kt` (welcome).

**Devices.** Physical, API 33+ (SAF and folders).

**Prerequisites.** Test vault with a few items. A **subfolder of your own** in Documents (for
example `OP-copias-prueba`; Android 11+ does not let you choose the root of «Download» or «Documents»):

```sh
adb shell mkdir -p /sdcard/Documents/OP-copias-prueba
adb shell 'echo notas > /sdcard/Documents/OP-copias-prueba/notas-propias.txt'
adb push demo.opvault /sdcard/Documents/OP-copias-prueba/openpassword-2026-10-30.opvault
```

(`demo.opvault` from DT-03.) These two files do not start with `openpassword-auto-`: they **must not be deleted**.

**Steps.**

1. Settings → **Copia automática** → choose `OP-copias-prueba`. A first backup must be made immediately.
2. `adb shell ls -l /sdcard/Documents/OP-copias-prueba/`: note the `openpassword-auto-…opvault` files.
3. Change the title of an item (for example, `Banco falso` → `Banco falso 2`). Wait ≥ 10 s. List
   again: there must be **a new backup**.
4. Check that this backup contains the change (the CLI reads the backup with the test vault's secret
   key; **test data only**):
   ```sh
   adb pull /sdcard/Documents/OP-copias-prueba/<la-copia-nueva>.opvault .
   printf '<contraseña-de-pruebas>\n' | cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- \
     decrypt <la-copia-nueva>.opvault --password-stdin --secret-key '<clave-secreta-de-pruebas>' | grep -i "banco falso"
   ```
5. **Locked**: lock the vault, change nothing (you cannot), and unlock. Note whether a backup is made on
   unlocking when there were pending changes.
6. **Rotation**: create 10 fake backups with valid, old names, and make a real change:
   ```sh
   for i in 01 02 03 04 05 06 07 08 09 10; do
     adb shell "echo falsa > /sdcard/Documents/OP-copias-prueba/openpassword-auto-20200101-0000$i.opvault"
   done
   ```
   Change an item, wait ≥ 10 s and list: there must be **10** `openpassword-auto-…` files left (the newest
   ones, including the real backup) and `notas-propias.txt` and `openpassword-2026-10-30.opvault` **still**
   there.
7. **Restore**: `adb shell pm clear "$PKG"` (debug app only, with the test vault; see
   2.2). Open the app: welcome → **Restaurar** → choose the most recent automatic backup → type the test
   secret key and the test master password. Note whether it restores and whether the change from step 3 is there.
8. Unlock with the test password.

**Expected result.** Backup when choosing the folder; new backup after the change (with a 5 s debounce);
on unlocking with pending changes the backup is made; rotation leaves 10 of our own backups and does not touch other
files; the restore returns the test vault with the change.

**Covers.** Backup functionality (A4, A5: the backup comes out encrypted and authenticated, see
[`threat-model.md`](../../threat-model.md))); recovery after loss.

<a id="dt-16"></a>
### DT-16 · Automatic lock

**Goal.** Measure on the device the three lock triggers: 5 min idle, 30 s after
leaving the app, and screen off.

**What it verifies.** `VaultSession.kt:482-484` (`BACKGROUND_TIMEOUT_MS` = 30 s, `PICKER_TIMEOUT_MS` = 3 min,
`IDLE_TIMEOUT_MS` = 5 min), `:389-398` (`onAppBackgrounded`: `Handler` timer that locks even if
it is not come back to) and `:399-406` (`onAppForegrounded`: check on return, because `Handler`s may not
run with the device asleep), `:424-427` (`lockIfIdle`), `MainActivity.kt:33-37` (checks every
15 s while the app is visible) and `OpenPasswordApp.kt:75-80` (`ACTION_SCREEN_OFF` receiver: it locks
instantly, for the whole process).

**Devices.** Physical. For DT-16a the screen-off timeout must be more than 5 min:
`adb shell settings put system screen_off_timeout 600000` (restore the original: 2.7).

**Prerequisites.** Test vault. A stopwatch **external** to the phone (the computer's or a
watch). Evidence: video with another camera showing the stopwatch and the phone.

**DT-16a · Idle.**

1. Unlock. **Do not touch the screen** and start the stopwatch.
2. Check at 4:50 (still unlocked) and wait for the lock. Note the moment the unlock screen
   appears.

**DT-16b · 30 s after leaving.**

1. Unlock. Press Home (leave the app). Stopwatch at 0.
2. **At 20 s** return to OpenPassword (via Recents): it must still be unlocked.
3. Leave again, wait **40 s** and return: it must ask for unlock.
4. **Without returning**: unlock, leave, wait 40 s, and without opening OpenPassword use the autofill of the
   fake browser (`--es domain bank.example`; OpenPassword as the service): it must offer **«Desbloquear
   OpenPassword»** and **not** `Banco falso`. (The lock happens even if you do not return to the app: A13.)
5. (Optional) Settings → **Exportar copia cifrada**: the file picker extends the margin to 3 min **once**
   (`beforeSystemPicker`, `PICKER_TIMEOUT_MS`): note whether after 40 s it is still unlocked.

**DT-16c · Screen off.**

1. Unlock and turn the screen off with the power button. Turn it on after 2-3 s and unlock the
   phone: OpenPassword must ask for unlock.
2. Repeat it on the **autofill** screen: with the «Rellenar con OpenPassword» window open, turn it off and
   on: it must ask for unlock (the receiver is for the whole process, not for one activity).

**Expected result.** a) Locks between 5:00 and 5:15 (the check runs every 15 s). b) At 20 s it is still
open; at 40 s, locked; and locked also without returning. c) Locked instantly in both
windows.

**Covers.** A13.

<a id="dt-17"></a>
### DT-17 · TOTP: QR, image and pasting

**Goal.** Check the three ways of entering a TOTP code and that the code shown is correct.

**What it verifies.** `qr/QrScanner.kt` (camera; `CAMERA` only when pressing «Escanear QR»; manifest
`required="false"`), `qr/QrDecoder.kt:45-51` (only `otpauth://totp/`), `ItemEditorScreen.kt:116-120`
(validation on save) and `:156-169` (image; messages), `ItemDetailScreen.kt:141` (the code is copied,
never the secret). Threat A16.

**Devices.** Physical device with a camera.

**Prerequisites.** A test QR, with a made-up secret, and another that is **not** TOTP:

```sh
brew install qrencode          # or your system's package manager
qrencode -s 10 -o totp.png 'otpauth://totp/Prueba:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Prueba'
qrencode -s 10 -o web.png  'https://example.com'
adb push totp.png web.png /sdcard/Download/
echo 'otpauth://totp/Prueba:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Prueba' \
  | cargo run -q --manifest-path "$OP_REPO/Cargo.toml" -p opvault-cli -- totp      # expected code and seconds
```

Open `totp.png` full screen on the computer for the camera. A new `TOTP prueba` login with a TOTP
field.

**DT-17a · QR with the camera.**

1. Login editor → TOTP field → **Escanear QR**. Note that the camera permission is requested **now** and not
   before. **Deny** it once: note that the app does not crash and that it is still possible to read from an image.
2. Grant it and point at the QR: the field is filled in with the link. Save. In the detail check that the
   **6-digit code matches** the one from `opvault totp` in the same 30 s interval.
3. Point the camera at `web.png`: it must reject it («Ese QR no es de verificación en dos pasos.», visible in
   the editor) and not fill in the field.
4. Note that the app saves no frames: `adb shell ls /sdcard/DCIM /sdcard/Pictures` with no new files.

**DT-17b · QR from an image** (without camera permission).

1. TOTP field → **Desde una imagen** → `totp.png`: «Código QR leído.» and the field is filled in.
2. Repeat with `web.png`: «Ese QR no es de verificación en dos pasos.»
3. Repeat with an image with no QR (any photo): «No se encontró ningún código QR en esa imagen.»

**DT-17c · Paste.**

1. Paste `otpauth://totp/Prueba:alice@example.com?secret=JBSWY3DPEHPK3PXP` into the field (copy it from the
   fake browser or a note) and save; then try only the secret `JBSWY3DPEHPK3PXP`.
2. Try an invalid value (`hola`): on saving, «El código TOTP no es válido. Pega el enlace otpauth://
   o el secreto que te dio el servicio.»
3. In the detail, copy the code: paste it into the fake browser: it must be **6 digits, not the secret**.

**Expected result.** The three paths accept the valid TOTP and reject the rest with the messages
given; the code matches the one from the CLI; the secret is not copied.

**Covers.** A16; TOTP functionality. (The code match with the CLI uses the same `op-core::totp`
implementation; for an independent reference `oathtool -b --totp JBSWY3DPEHPK3PXP` can be used.)

---

## 6. Automation

Today **there is no instrumented test in CI** (there are no references to `androidTest`, `connected` or
`emulator` in `.github/workflows/`), and the three classes in `android/app/src/androidTest/kotlin/…/` are:
`EmergencyKitTest`, `OverlayProtectionTest` (4 tests: the three activities and a `ProtectedAlertDialog`,
see ID-INT-13) and `VaultSessionTest` (with an isolated namespace per test). They were run by hand on
2026-10-30 on one device (17 tests green, section 3.2). Note: the test table in
[ADR-AUD-06](decisions.md)) talks about an injected `FLAG_WINDOW_IS_OBSCURED` touch; it **has not been checked**
here that the tests do it, only that they pass.

### What can be turned into `androidTest`

| Test | Instrumented? | How / why |
|---|---|---|
| DT-01, DT-03 (flags) | **Partial** | Check `filterTouchesWhenObscured` and `FLAG_SECURE` in `AutofillAuthActivity` and `SaveLoginActivity` (they need a token from `AutofillRequestTokens.shared`) and in the window of a `ProtectedAlertDialog` with a touch injected with `FLAG_WINDOW_IS_OBSCURED` (Compose UI test). They do **not** test the real compositor behaviour (that the overlay is hidden): that is manual |
| DT-02 | **No** (manual) | Depends on how the system flags touches in front of a real window |
| DT-04 | **Yes, with caveats** | A test with `UiAutomator` that copies, brings another activity to the foreground and at 30 s reads the clipboard. It is exactly what ID-INT-14 asks for (API 29, 33 and 36) and it is **the most worthwhile thing to automate** |
| DT-05 | **Yes** | `PublicSuffix.isAvailable` and `registrableDomain("x.alice.github.io")` against the APK. The debug build does not go through R8: to cover R8 it must be run against `release` (`testBuildType`), which is a build change |
| DT-06, DT-09 | **No** | They need real Chrome and the system autofill framework |
| DT-07 | **Yes, partial** | With `test.fakebrowser` installed, `CachedBrowserCheck.forPackageManager(packageManager).isBrowser("test.fakebrowser")` must be `false` (and it validates the `<queries>` block). The «default» one cannot be set without privileges: DT-08 is manual |
| DT-10 | **No** | Autofill UI |
| DT-11 | **Yes, partial** | On a `userdebug` emulator, `RootDetector.evaluate(AndroidDeviceProbe(context))` contains `DEBUG_BUILD`; the card and dismissal are UI |
| DT-12 | **Yes, partial** | On an API 28 emulator, `strongBiometricsAvailable(context)` does not throw (reflection on `FingerprintManager`) |
| DT-13 | **Better in Rust** | Add the real KDBX 4 to `core/src/import/testdata/` and a test in `kdbx.rs` (no device, in CI). The device only adds the file picker path and FFI |
| DT-14 | **Yes (14a)** | A `VaultSession.importBackup` test with `alto.opvault` as a resource (674 bytes). 14b reserves 512 MiB: it is not fit for CI |
| DT-15 | **Partial** | Rotation (`BackupNames`, already on JVM). The folder picker (SAF) makes the rest hard to automate |
| DT-16 | **Not advisable** | Real 5 min and 30 s timings and screen off; an injectable clock in `VaultSession` on the JVM would be cheaper |
| DT-17 | **No** (camera) | Decoding from an image and parsing `otpauth://` already have JVM tests (`QrDecoderTest`) |

### How to run the instrumented tests, safely

> **Do not run `connectedAndroidTest` on the phone with real data.** It installs the app APK and the test
> APK on the connected device and, depending on the AGP version, uninstalls them at the end (which wipes
> the debug app's data). In addition, `OverlayProtectionTest` launches `MainActivity`, which touches the
> package's real vault (its own comment warns about it). Use **only an emulator or a device with no
> data**.

```sh
adb devices -l                                   # it must list only the emulator
export ANDROID_SERIAL=emulator-5554              # the emulator serial
cd "$OP_REPO/android"
./gradlew :app:connectedDebugAndroidTest
```

Beforehand, check that `ANDROID_SERIAL` points at the emulator. This command was run on 2026-10-30 on a
physical device with no vault (SM-S948B, API 37): 17 tests, all green (see «Session of 2026-10-30»).
The instrumented tests uninstalled the debug app at the end, as the warning above says.

---

## 7. Closure criterion

### 7.1 When «verified on device» can be written

A claim in `internal-review.md` or `threat-model.md` moves from «unverified / not tested on
device» to «verified on device» **only if** all of the following is met for its test:

1. The `result` is **`pass`**, with `evidence` cited and archived (2.8), in the table row (3.2).
2. It has been run on the **commit being audited** (the `v0.2.0` SHA, see [`README.md`](README.md))) or
   on a later one with no changes in the files the test verifies (`git diff --stat
   <commit-probado>..<commit-auditado> -- android/app/src/main core ffi`). If there are changes, it is repeated or
   labelled as «indicative, another commit».
3. It meets the **device coverage** of the following table.
4. There is no open **`fail`** row for that same test without an associated finding (7.2).

| Claim being closed | Tests and minimum coverage |
|---|---|
| A7: anti-tapjacking (`threat-model.md`) | DT-01 `pass` on ≥ 1 physical API 31+ device; DT-02 `pass` on ≥ 1 API 28-30 device (an emulator counts, noted); DT-03 `pass` on one device per range |
| A7: clipboard with wipe / ID-INT-14 | DT-04a-c run on **API 29, 33 and 36**; if 04b or 04c **fail**, ID-INT-14 is **confirmed** (not «verified»): the «with wipe» claim **is removed** from A7 until it is fixed. DT-04d on ≥ 1 API 33+ device |
| ID-INT-20: suffix list on the device | DT-05 `pass` (with the **two positive controls**) in the debug build **and** in the R8 variant (5.R8) |
| A17 / ID-INT-16: `webDomain` | DT-06 on a physical device with Chrome; DT-07 `pass`; DT-08 run and its result recorded (the residual risk becomes «verified», not «removed») |
| ID-INT-26: token, rotation and «remember» | DT-09d and DT-10 `pass` on ≥ 1 physical device |
| A10: root warning | DT-11 `pass` on a `userdebug` emulator **and** the negative control on a stock phone |
| Biometrics on API 28 | DT-12 `pass` on an API 28 device or emulator. Without it, it stays «unverified on API 28» |
| Android README: KDBX 4 | DT-13a, 13b and 13c `pass`, 13d and 13e reject with the messages given |
| KDF ceiling | DT-14a `pass` on all devices; 14b run, noting time and app state |
| Automatic backup, lock, TOTP | DT-15, DT-16 and DT-17 `pass` on ≥ 1 physical device |

`blocked` **does not count** as verified: the claim stays «unverified» and the reason is stated.

**Closure status as of 2026-10-30** (a single device, API 37, debug build; no row is fully closed):

| Claim | Status |
|---|---|
| A7: clipboard / ID-INT-14 | **Confirmed as a failure** on API 37 (DT-04b `fail`): «with wipe» **is removed** from A7 (rule 7.2.5). DT-04c, DT-04d and API 29, 33 and 36 not run. There is no `pass` row to close |
| ID-INT-20: suffix list | DT-05 `pass` in debug with the two positive controls; **the R8 variant is missing**: still open |
| A17 / ID-INT-16: `webDomain` | DT-07 `pass`; DT-06 (real Chrome) and DT-08 (formal) are **missing**; the `iframe` hypothesis is still untested |
| The rest (A7 anti-tapjacking, ID-INT-26, A10, KDBX, KDF, backup, lock, TOTP) | As before this part: see table 3.2 |

In all cases the evidence also still has to be archived (2.8) and the tested commit fixed (7.1, point 2).

On closing, the texts that get updated **(except what is already recorded for ID-INT-14, 16, 20 and A7/A17 after the session of 2026-10-30, which has not been touched in this plan)**: rows in `internal-review.md`
for ID-INT-14, 16, 20 and 26 («sin probar en dispositivo»); `threat-model.md` A7 («sin verificar en
dispositivo») and A17 («Sin probar en dispositivo»); and the «sin verificar» ones in [`hardening.md`](hardening.md)) and
[`README.md`](README.md)) (index). Each change cites the test ID and the commit. If DT-13 passes,
the sentence in the Android README is updated too, and the «Pendiente» in
`core/src/import/testdata/README.md`.

### 7.2 If a test fails

**It is not patched on the fly.** Neither during the test nor «so that it passes».

1. The row is left with `fail`, the evidence and an exact description of what was observed (not of what is
   interpreted). It is not deleted or overwritten: if it is repeated, it is a new row.
2. A **finding is opened**:
   - Before the freeze: a new finding in [`internal-review.md`](internal-review.md)) (the next
     free one is `ID-INT-27`, or the existing one is updated, e.g. ID-INT-14) with the test as evidence, its
     severity according to [`findings-process.md`](findings-process.md#1-severity-scale)) and a row in
     [`hardening.md`](hardening.md)) §4.1.
   - During the audit: a private GitHub advisory according to
     [`findings-process.md`](findings-process.md#2-registry-private-github-security-advisories)).
3. The fix follows the normal flow of [`findings-process.md`](findings-process.md#3-fix)): branch,
   change, **JVM test when possible**, review, and the rules of
   [ADR-AUD-01](decisions.md#adr-aud-01--freeze-strategy)) for `release/0.2`.
4. The **test is repeated** on the fixed commit (new row) before changing the «unverified»
   text.
5. If what was observed **contradicts a text in `threat-model.md`** (for example, «con borrado»), the text is
   corrected to what was observed even if the code fix comes later.
6. **The tests and their expected results are not changed** to make them pass: if the expected result of
   this plan was wrong, the discrepancy is recorded and this document is fixed in a separate commit.

---

## 8. Out of scope for this plan

| What is left out | Why |
|---|---|
| Real root on the main phone; Magisk | Safety rule 3. DT-11 is done with a `userdebug` emulator; the `SU_BINARY` and `ROOT_MANAGER_APP` signals are covered by `RootDetectorTest` with a fake `DeviceProbe` |
| The cross-origin `iframe` hypothesis in a browser ([ID-INT-16](internal-review.md#id-int-16)), residual risk) | It needs a page with two origins and a real browser; it is a new test that was not on the list. Candidate for a DT-18 |
| An app injecting extras into the mutable `PendingIntent` ([ID-INT-26](internal-review.md#id-int-26))) | The `IntentSender` is kept by the autofill framework and never reaches normal app code; reproducing it requires a modified autofill client. The token and rotation are tested (DT-09d); the token logic, on the JVM (`AutofillRequestTokensTest`) |
| Biometric key invalidation when enrolling a new fingerprint (`BiometricKeyStore.kt:40-56`); SQLite journal mode (`-journal`, [`threat-model-review.md`](threat-model-review.md))) | They were not on the requested list. They are reasonable device checks; candidates for DT-19/DT-20 |
| Performance, KDF timings per ABI and low-end devices | The per-ABI ceiling decision is still pending (ADR-AUD-07, decision no. 3). DT-14 records `MemTotal` and timings, but does not measure a catalogue of devices |
| Reproducible build, signing, SBOM and supply chain | They do not depend on the device: see [`dependencies.md`](dependencies.md)) and `docs/fdroid/README.md` |
| Tests on iOS, desktop and the `opvault` CLI | Out of scope for the audit ([`scope.md`](scope.md))). The CLI is used here only as a tool |
| The Kotlin tests on the JVM and the fuzzers | They run in CI or locally (`./gradlew testDebugUnitTest`, [`fuzzing.md`](fuzzing.md))); this plan is what **cannot** be done there |
| Android versions not included in the matrix (2.9) | API 28, 29, 30, 33 and 36 are covered as a minimum. Each additional API is a new row in the table, not a new test |

---

## 9. Later tests: images (2026-10-31)

They were not part of the audit plan; they are added as a record of the first manual check on
device (SM-S948B, Android 17 / API 37, debug build).

| Test | Result |
|---|---|
| Add a gallery image to a document and view it in the viewer | Pass. It is stored encrypted and the detail shows «Imagen cifrada» with the caption «Anverso» |
| Take a photo with the app's camera | Pass. The draft appears without leaving files in `cache/` or in `files/` (only `files/profileInstalled`) |
| Export `.opvault` with the image | Pass. 629.966 bytes; `opvault decrypt` decrypts it and the resulting JPEG (469.095 bytes) decodes and has no APP1/Exif, GPS or COM; only APP0 and the ICC profile |
| Backup and restore on a «new device» | Covered by `ImagesSessionTest` (instrumented): lock, unlock, export, restore and same bytes |
| Screenshots | Blocked by `FLAG_SECURE` (the screenshot comes out black) |

Limits: a single Android version, a single device, and the camera was tested without checking the
visual result inside the app (the window is secure and the screenshot comes out black); the draft was
verified through the accessibility hierarchy. An Ultra HDR photo from the gallery was not tested.
