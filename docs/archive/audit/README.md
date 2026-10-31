# External audit package

This directory gathers everything an external auditor needs to review OpenPassword, and everything the
project needs to hire, follow and close that audit. It covers Phase 3 of the
[proposal](../proposal.html)).

## Closing summary (2026-10-30)

> **Phase 3 preparation complete; external audit pending.** Hardening is applied, the internal
> findings are handled and the audit package is written, but **no external audit has been hired or
> performed**. That is why the project is **not** at 1.0 and the warning in
> [`SECURITY.md`](../../../SECURITY.md)) still stands: do not store real data yet.

This section is the entry point for resuming the work.

### What is done

- **Hardening**: the 19 steps of ADR-AUD, with 3 pending or partial (9, 18 and 19), in [`hardening.md`](hardening.md)).
- **Internal review**: 26 findings in [`internal-review.md`](internal-review.md)): **19 fixed, 1 partial (ID-INT-23), 4 accepted (among them ID-INT-14, as residual risk) and 2 open (ID-INT-20 and ID-INT-22)**.
- **Audit package**: scope, vendors, budget, findings process, attack surface, threat model review, dependencies and fuzzing (index below).
- **Tests**: 102 Rust tests green (executed); 17 instrumented tests green on an SM-S948B (API 37); manual device tests partly done (table below). The 186 Kotlin `@Test` on the JVM **have** been run (macOS, JDK 17): 186 pass, 0 fail.

### What is missing

- **Hiring the external audit** (nothing hired): choose a vendor with [`vendors.md`](vendors.md)), request a quote with [`budget-timeline.md`](budget-timeline.md)) and sign with [`scope.md`](scope.md)) as an annex.
- **Budget**: every amount and date in [`budget-timeline.md`](budget-timeline.md)) is a deliberate placeholder; and the deadlines and contacts in `scope.md` are unfilled.
- **Freezing the version**: bump to `0.2.0`, create `release/0.2`, tag `v0.2.0` with a signature and record the SHA here and in `scope.md` (there is no branch or tag yet). Steps 9 (partial), 18 (partial) and 19 of [`hardening.md`](hardening.md)); run the `release` job and `fuzz-nightly.yml` once.
- **Human decisions still open** in [`decisions.md`](decisions.md)): only no. 1 (which key signs the tags and when `release/0.2` is created). The rest were approved on 2026-10-30.
- **Device tests pending**: they do not block hiring (see the table).

### Device tests (SM-S948B, Android 17 / API 37, 2026-10-30)

Details and evidence in [`device-tests.md`](device-tests.md)). Session closed on 2026-10-30; what is
pending requires an API 28 emulator or device and **does not block hiring the audit**.

| Test | Result | Reason or limit |
|---|---|---|
| DT-01 (anti-tapjacking, API 31+) | **Pass** | Only `MainActivity` and one tap |
| DT-04a (wipe after 30 s, foreground) | **Pass** | Only API 37 |
| **DT-04b (wipe in background)** | **Fail** | Confirms ID-INT-14; **accepted as residual risk** |
| DT-05 (public suffix list) | **Pass** | Debug build only; **R8 variant pending** |
| DT-07 (non-browser app with `webDomain`) | **Pass** | Steps 4 and 5 of the plan are missing |
| Instrumented (`connectedDebugAndroidTest`) | **Pass** (17 tests) | A single device |
| DT-02, DT-03 (anti-tapjacking API 28-30 and dialogs) | Pending | Require an API 28-30 emulator (no images on the machine) |
| DT-06 (real Chrome) | Pending | Real browser, not run |
| DT-08 (malicious default browser) | Pending | Not run |
| DT-09, DT-10 (full autofill and «remember») | Pending | Not run |
| DT-11 (root warning) | Pending | Requires a `userdebug` emulator |
| DT-12 (biometrics on Android 9) | Pending | Requires an API 28 emulator or device |
| DT-13 (real KDBX 4) | Pending | Not run |
| DT-14, DT-15, DT-16, DT-17 (KDF/RAM, backups, automatic lock, TOTP) | Pending | Not run |
| DT-04c, DT-04d (screen off, sensitive flag) | Pending | Not run |

### Decisions taken

- **NCSA license** (`libfuzzer-sys`, only in `fuzz/deny.toml`; ID-INT-23): **approved by the owner on 2026-10-30**. ID-INT-23 remains «partial».
- **ID-INT-06** (an unreadable item): it is skipped and reported in the list, instead of blocking the unlock (`EntryLoading.kt`).
- **ID-INT-14** (clipboard): **accepted as residual risk** when closing the phase. Android limitation: `clearPrimaryClip()` has no effect in the background. Mitigations: sensitive flag, wipe after 30 s with the app in the foreground, wipe on returning to the app and on screen off, and an honest message in the UI. The copy button is not removed. See [DT-04](device-tests.md#dt-04)).
- **F-Droid publication: paused** by decision of the owner (2026-10-30); it is resumed from [`docs/fdroid/README.md`](../fdroid/README.md)).

> Note on «no commit»: several documents in the package mention work «without a commit» on `a3daf4e`.
> That work is already in `183598d` («Phase 3: close the findings that do not depend on the device») and
> `3868f4f`; the text keeps the original wording.

## What is audited

| Data | Value |
|---|---|
| Version | `v0.2.0`, frozen after hardening ([ADR-AUD-01](decisions.md#adr-aud-01--freeze-strategy))) |
| Branch | `release/0.2` (does not exist yet; it is created when the audit is hired) |
| Base commit inspected when the decisions were written | `9eb9c7f` («CI: fuzz with the runner's gnu target») |
| `main` commit containing this package | `3868f4f` (device tests and closing), on top of `183598d` (findings that do not depend on the device), `a3daf4e` (hardening, supply chain and package), `700f1a7` (FFI boundary and A7/A10) and `1649636` (closing `v0.1.0`) |
| **Commit that will be audited** | **PENDING**: 40-character SHA of the tip of `release/0.2` tagged `v0.2.0`. It is filled in when the signed tag is created |
| Signed tag | **PENDING** (`git tag -l` shows no tag in the local clone; the signing key is pending approval, see [decisions.md](decisions.md#decisions-that-require-human-approval))) |
| In scope | `op-core`, `op-ffi`, the Android app, the `.opvault` v1 format, reproducible builds and signing |
| Out of scope | The `opvault` CLI, Phase 4, iOS and desktop |

When the tag is created, **this file and [`scope.md`](scope.md))** must be updated with the SHA.
What is audited is the SHA, not the tag name.

## Index and status

Statuses: **done** (written and checked against the repository), **pending** (content that only the
project can provide is missing), **unverified** (contains external data that has not been checked).

| Document | What it is for | Status |
|---|---|---|
| [`decisions.md`](decisions.md)) | ADR-AUD-01 to 07: technical decisions prior to the audit | **done** as a proposal; its header already reflects that `700f1a7` and `a3daf4e` implement ADR-AUD-02 to 07 (see [`hardening.md`](hardening.md))), with the ADR text untouched. There are 10 decisions awaiting human approval |
| [`scope.md`](scope.md)) | *Scope of work* for the auditor | **pending**: the frozen SHA, deadlines and contacts are missing. The rest is checked against the repository |
| [`vendors.md`](vendors.md)) | Shortlist of vendors and funding channels | **unverified** on availability and prices; specialties and public reports checked on each vendor's website (source and date in the document) |
| [`budget-timeline.md`](budget-timeline.md)) | Budget template per vendor and schedule | **pending**: every amount and date is a deliberate placeholder |
| [`findings-process.md`](findings-process.md)) | Severity, tracking, fixes, re-test and `1.0.0` criteria | **done** as a proposal; the new deadlines and criteria need approval |
| [`attack-surface.md`](attack-surface.md)) | Attack surface per component | **done**, not re-checked line by line after `a3daf4e` (the claims for ID-INT-01, 16, 25 and 26 were corrected) |
| [`threat-model-review.md`](threat-model-review.md)) | Review of the [threat model](../../threat-model.md)) before the audit | **done**, with an update note after `a3daf4e`: part of its section 5 was applied to `threat-model.md`, and the sections describing ID-INT-01 and ID-INT-16 reflect the state before their fix |
| [`internal-review.md`](internal-review.md)) | Prior internal review | **done**: 26 findings (2 High, 3 Medium, 11 Low, 10 Info): 19 fixed (those in `a3daf4e`: ID-INT-01, 05, 07, 24 and 25; the rest in `183598d`, including 16 and 26), 1 partial (ID-INT-23; the NCSA license is approved), **4 accepted (ID-INT-04, 15, 19 and **ID-INT-14, accepted residual risk**)** and 2 open (ID-INT-20 and 22). Verified on device on 2026-10-30 (SM-S948B, API 37): ID-INT-13, the instrumented tests for ID-INT-05, 08 and 09, the part of ID-INT-16 about non-browser apps (DT-07) and the loading of the suffix list of ID-INT-20 in the debug build (DT-05). ID-INT-14 was **confirmed as a bug** (the clipboard is not wiped with the app in the background, DT-04) and is **accepted as residual risk**. Pending on device: 16 (real Chrome, DT-08, `iframe`), 18, 20 (R8) and 26 (and DT-02, DT-03 and DT-12, blocked or not run); approved on 2026-10-30: the KDBX policy of ID-INT-02, the NCSA license of ID-INT-23 and the acceptance of ID-INT-14. Rust: 102 tests green; Kotlin on the JVM: 186 pass, 0 fail; instrumented: 17 pass |
| [`dependencies.md`](dependencies.md)) | Dependency inventory and policy | **done** (`cargo-deny`, Gradle verification, SBOM and Actions by SHA already implemented; the `release` job and a build with verification enabled still need to be run) |
| [`fuzzing.md`](fuzzing.md)) | Fuzzing coverage and results | **done** (11 targets, nightly); with no run of the nightly workflow and no execution figures for the new targets |
| [`hardening.md`](hardening.md)) | Applied and pending hardening | **done** (final status of the 19 steps of ADR-AUD); pending steps: 9 partly, 18 partly and 19 |
| [`device-tests.md`](device-tests.md)) | Manual device test plan (DT-01 to DT-17) for what cannot be verified on the JVM or in CI; serves as evidence for the auditor | **partial**, session closed on 2026-10-30: plan with results on a single device (SM-S948B, API 37): DT-01 `pass` (with limits), DT-04 (04a `pass`, **04b `fail`**: ID-INT-14, accepted as residual risk), DT-05 `pass` (debug only) and DT-07 `pass`; DT-02 and DT-12 `blocked`; the rest **pending** (closing summary above). Evidence not archived (see section 3.4) |

All the documents in the index exist.

Repository documents the auditor must read and that are **not** copied here:

- [`docs/crypto-spec.md`](../../crypto-spec.md)): primitives, keys, AAD, STREAM, KDF.
- [`docs/opvault-format.md`](../../opvault-format.md)): the `.opvault` v1 format.
- [`docs/threat-model.md`](../../threat-model.md)): assets, attackers A1–A18 and residual risks.
- [`SECURITY.md`](../../../SECURITY.md)): how vulnerabilities are reported and the deadlines.
- [`android/README.md`](../../../android/README.md)) and [`docs/fdroid/README.md`](../fdroid/README.md)): build and reproducible build.

> **F-Droid publication: paused** by decision of the project owner (2026-10-30). It does not block
> the audit package: the version being audited is delivered as a GitHub pre-release, not from
> F-Droid. See [`docs/fdroid/README.md`](../fdroid/README.md)) to resume it.
- [`core/tests/vectors/op-v1.json`](../../../core/tests/vectors/op-v1.json)): golden vectors for the format.

## How the package is used with a vendor

1. **Before contacting.** Check that the «What is audited» table has no `PENDING` and that
   `scope.md` has the SHA, deadlines and contacts. Without that, nothing is sent.
2. **First contact.** Only `scope.md`, the link to the public repository and the SHA are sent. There is
   nothing secret in the code (GPL-3.0-or-later, public repository); confidentiality concerns
   the findings, not the code.
3. **Budget.** The quote is requested using the template in [`budget-timeline.md`](budget-timeline.md))
   and compared against the criteria in [`vendors.md`](vendors.md)). The included re-test and
   permission to publish the report are required in writing.
4. **Hiring.** It is signed with the scope in `scope.md` as an annex. The auditor is granted read
   access to the repository and, for the findings, to GitHub private advisories according to
   [`findings-process.md`](findings-process.md)).
5. **During the audit.** Only the changes allowed by ADR-AUD-01 are accepted in `release/0.2`.
   Findings follow the `findings-process.md` flow.
6. **Closing.** Re-test, final publishable report, advisories and `1.0.0` criteria
   (see `findings-process.md`).

## Maintenance

- This index is the single source of truth for the status of each document. If one changes, it changes here.
- Technical figures (toolchain versions, KDF limits) are not copied: they are linked to their
  source (`rust-toolchain.toml`, `docs/crypto-spec.md`, `decisions.md`).
