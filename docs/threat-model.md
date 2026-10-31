# Threat model · v1

What OpenPassword protects, against whom, and what is out of scope. It is reviewed before every major version and before the external audit.

## Assets

| Asset | Examples | Sensitivity |
|---|---|---|
| Secrets | Passwords, CVV, PINs, seed phrases, API keys | Critical |
| Metadata | Which services you use, which banks, titles, URLs | High |
| Access credentials | Master password, secret key | Critical |
| Backups | `.opvault` files | Same as the secrets |

## Assumptions

- The operating system and the hardware are not compromised (no malicious root or altered firmware).
- The system CSPRNG works.
- The user keeps the master password or the emergency kit.

## Attackers and defenses

All the defenses in the table are implemented. «Partial» means that the defense works but has a known limit, which is stated as residual risk in the row itself.

| # | Attacker | Capability | Defense | Status |
|---|---|---|---|---|
| A1 | Thief with the phone locked | Physical access, extraction of the storage | Android encryption; vault encrypted with keys that are not on disk in the clear | Protected |
| A2 | Thief with the phone unlocked | Opens the app | Master password or hardware-bound biometrics; exponential wait between attempts | Protected |
| A3 | Anyone who obtains an `.opvault` | Unlimited offline brute force | Argon2id + 128-bit SK: without the SK, trying passwords is useless | Protected |
| A4 | Cloud provider | Sees the file and its history | Only sees an authenticated blob; the header has no user data | Protected |
| A5 | Tampering with the backup or the database | Modifies, truncates, reorders or swaps blocks | AEAD with context AAD; STREAM with an end marker; authenticated header | Protected |
| A6 | Rollback | Replaces an item with a complete older version | Detectable only with synchronization; accepted in v1 | Accepted |
| A7 | Malicious app without privileges | Overlays, clipboard, screenshots | `FLAG_SECURE` and clipboard marked as sensitive (API 33+) with a wipe after 30 s **that only acts while the app is in the foreground**; against overlays (*tapjacking*): `filterTouchesWhenObscured` (discards fully covered touches) and `setHideOverlayWindows` (hides overlays from other apps), in the three activities and in their dialogs, plus a warning (once per process) when a covered touch arrives. Residual risk **accepted** by the owner's decision (2026-10-30, [ID-INT-14](archive/audit/internal-review.md#id-int-14)): **the clipboard wipe does NOT happen if the app no longer has focus, which is the normal use (copy and paste into another app)**. It is an Android limitation: `clearPrimaryClip()` has no effect from the background. Confirmed on device on 2026-10-30 (SM-S948B, Android 17 / API 37; [DT-04](archive/audit/device-tests.md#dt-04)): the text is still in the clipboard after 45 s with the app in the background, whereas with the app focused it is wiped after 35 s. Mitigations: «sensible» mark (API 33+), wipe after 30 s with the app in the foreground, wipe when returning to the app and when the screen turns off (the last two, **not verified on device**), and an honest message in the interface; the copy button has not been removed. It was not tested on API 29, 33 and 36. The app message reads «Se borrará en 30 s, o al volver a la app si sales.». `setHideOverlayWindows` requires Android 12 (API 31); on API 28-30 only the filter remains, and a **partially** covered touch is delivered (with a warning). Overlay hiding is verified on device only on API 37 and `MainActivity` (DT-01); the warning and API 28-30 (DT-02, DT-03) remain unverified | Partial |
| A8 | Shoulder surfer | Sees the screen | Hidden fields and per-field reveal | Mitigated |
| A9 | Supply chain | Tampered dependency or build | Few dependencies, versioned `Cargo.lock`, `cargo deny` (advisories, licenses and sources), SHA-256 checksum of the Gradle dependencies, Actions pinned by SHA, APK signed in CI with a key that is not in the repository, reproducible builds | Mitigated |
| A10 | Malware with root, keylogger | Reads memory and keystrokes | Only a warning: local heuristics, no network (`su` binaries, known root managers, `test-keys`, `userdebug`/`eng` build). It reports and **never blocks**. Residual risk: a hidden root (e.g. Magisk with hiding) is not detected, a custom ROM may give a false positive, and even if detected the app does not protect against that malware | Out of scope |
| A11 | Coercion | Forces an unlock | None in v1 | Out of scope |
| A12 | *Phishing* website or app | Asks autofill for the credentials of another site | Strict matching: stored host or subdomain on websites; exact package name (verified by Android) in apps; warning when choosing manually | Mitigated |
| A13 | Forgotten vault left open | Autofill offers logins while the app is in the background | Lock after 30 s of leaving the app (3 min, once, if you leave to a system picker the user requested) and when the screen turns off, for the whole process | Protected |
| A14 | Another autofill service (e.g. Google's) | Reads the app's fields or offers to save them to its cloud | Windows excluded from all autofill (`IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS`) | Protected |
| A15 | Anyone who finds another manager's export | Reads the plaintext passwords of the imported CSV or JSON | After importing, the app offers to delete the file; the bytes read are wiped from memory when they are parsed | Mitigated |
| A16 | Malicious QR or camera frames | A QR that is not TOTP, or the app storing images of the surroundings | Only `otpauth://totp/` links are accepted and the secret is validated in the core; frames are parsed in memory, not stored, and the app has no network; the camera is requested only when scanning | Mitigated |
| A17 | App that declares a website's domain | `ViewStructure.setWebDomain` is filled in by the origin app and Android does not verify it: an app can declare a bank's domain | The `webDomain` is accepted only if the package is a browser: one from the fixed list `KnownBrowsers.PACKAGES` (`BrowserCheck.kt:26-39`) or the user's **default** browser (`resolveActivity` of `ACTION_VIEW` `https`, `MATCH_DEFAULT_ONLY`) **and** that it handles `https` and `http` (`:68-73,83-87`). Declaring an `intent-filter` is not enough (it requires no permission). Otherwise it is treated as an app and only matches by package name. The host is validated as an ASCII name (`[a-z0-9.-]+`: no scheme, port, path or Unicode; `LoginMatcher.kt:67-76`); subdomains only match a registrable domain according to the public suffix list and, if the list fails to load (including an `IOException`), exact host matching (`PublicSuffix.kt:21-25`). Residual risk: a browser that the user themselves chooses as default and that is malicious is trusted; the browser list and the suffix list are versioned data with no update process (a new, non-default browser is not recognized: it is treated as an app); an `iframe` from another origin inside a browser is not verified (the `webDomain` is taken from the first node that declares it). **Verified on device** (2026-10-30, SM-S948B, API 37, debug build): an app that declares `webDomain` without being a browser is treated as an app («Para: test.fakebrowser», no web matches; DT-07), and the suffix list loads and is applied (`evil.github.io` does not receive the login of `github.io`; DT-05). **Not verified on device**: real Chrome (DT-06), the malicious default browser as a formal test (DT-08; it was only observed in passing that its `webDomain` was trusted), the suffix list with R8 and the `iframe` | Mitigated |
| A18 | Filled app that triggers the authentication `PendingIntent` | The `IntentSender` of `Dataset.setAuthentication` is handed to the app being filled in, and the `PendingIntent` is **mutable** (the system adds the structure to it): that app can add extras to it with `Intent.fillIn` and, if the destination travelled in them, request the credentials of any domain | The `Intent` carries only a random 16-byte token (hex), single-use and with a 5 min TTL, stored in a `ConcurrentHashMap` of the process (`AutofillRequestTokens.kt:14-47`); the domain or package and the fields are recovered from the store, not from the `Intent` (`AutofillAuthActivity.kt:89-98`). The activity wipes the old extras (`Datasets.LEGACY_EXTRAS`) before reading anything and **fails closed** (unknown, used or expired token: `finish()` with no result). Fixed in the same block as A17 (ID-INT-26). Residual risk: anyone already running code in the OpenPassword process (A10, out of scope) reads the store; the token, while it is neither used nor expired, is only valid for the request it was bound to; the `PendingIntent` is still mutable (the system requires it) | Mitigated |

## Residual risks

- **Total loss**: without the master password or the emergency kit there is no possible recovery.
- **JVM memory**: the `String`s shown on screen cannot be wiped at will (accepted).
- **Secret residues at the FFI boundary** (accepted): `SecretString` (`ffi/src/secret.rs`) and `Zeroizing` wipe in Rust the secrets that enter, but Rust cannot reach the immutable `String`s of the JVM and Compose, nor UniFFI's output `RustBuffer`, which is freed without wiping (nor the `String` that Rust hands over to build it).
- **Importers**: the buffers with secrets of the importers (copy of the `.1pux`, CSV fields, JSON tree, values and key file of KDBX, derived keys, `otpauth://` parameters) are `Zeroizing` or are wiped when leaving scope, also along the error paths (`core/src/import/mod.rs`, module header). What remains, and cannot be wiped from Rust: what the reallocations leave behind when a `String`/`Vec` grows and the internal buffers of `serde_json`, the keys of the JSON objects (field names), the stack temporaries of `sha2` and what happens after crossing the FFI (see above). All of that requires reading the process memory (A10, out of scope).
- **Size metadata**: the size of the backup reveals roughly how much data there is.
- **Images**: the original photo chosen from the gallery stays in the gallery until the user deletes it. The decrypted JPEG that the core returns crosses the FFI in a `RustBuffer` that is freed without wiping (accepted); the app wipes its copy, and bitmaps are wiped when closing the viewer, when leaving the screen or when locking the vault. A deleted image remains in previous backups.
- **Backup size**: images travel in the backups (up to 24 MiB of sealed attachments, about 32 MiB in base64) and the file cap is 64 MiB; exceeding it makes the export fail with a message, never an incomplete backup.
- **Backups with old credentials**: after changing the password, old backups open with the previous one.
