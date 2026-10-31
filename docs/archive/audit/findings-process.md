# Findings process

How the findings of the `v0.2.0` audit are recorded, fixed, verified and published, and what
is needed to publish `1.0.0`.

Status: **proposed**. It respects [`SECURITY.md`](../../../SECURITY.md)) (acknowledgement within 3 days, assessment within 10,
fix within 90 at most) and the branch policy of
[ADR-AUD-01](decisions.md#adr-aud-01--freeze-strategy)). What it **adds** to `SECURITY.md`
(severities with deadlines, `1.0.0` criteria) needs approval and is listed in section 9.

## 1. Severity scale

**CVSS 4.0** is used as the score plus a qualitative label with five levels. The ranges are those
of the CVSS qualitative ratings (*Critical* 9.0–10.0, *High* 7.0–8.9, *Medium* 4.0–6.9,
*Low* 0.1–3.9, *None* 0.0; <https://www.first.org/cvss/>).

| Label | CVSS 4.0 | Criterion in OpenPassword (examples) |
|---|---|---|
| **Critical** | 9.0–10.0 | Secrets or the master password/SK are obtained without knowing them, or the confidentiality or integrity of the format is broken; code execution with a file (`.opvault` or imported) |
| **High** | 7.0–8.9 | Autofill hands credentials to the wrong site or app; a defense described in the threat model does not exist or is bypassed; key in memory after locking with the process alive |
| **Medium** | 4.0–6.9 | Repeatable denial of service with a hostile file; metadata leak; undocumented secret residue |
| **Low** | 0.1–3.9 | Missing defense in depth; message that leaks information with no practical consequence |
| **Info** | 0.0 | Observation, robustness improvement or documentation with no direct security impact |

Rules:

- The auditor proposes the severity; the project discusses it with the auditor **in writing in the
  finding**. If there is no agreement, the highest one prevails until the re-test, and the disagreement is recorded in the
  public report.
- The CVSS vector is computed considering the [threat model](../../threat-model.md)): an attack that
  requires malicious root (A10) is out of scope and is classified Info unless the auditor
  justifies another impact.
- The component (`op-core`, `op-ffi`, Android, format, build) and the **affected
  version** (`v0.1.0`, `v0.2.0` or both) are also recorded.

### Deadlines (aligned with `SECURITY.md`)

`SECURITY.md` sets 3 days (acknowledgement), 10 days (first assessment) and a maximum of 90 days for the
published fix, «sooner if it is serious». For audit findings it is proposed to make the
fix deadline per severity concrete. **These are proposed targets, pending approval**; the 90-day cap does not
change.

| Severity | Acknowledgement | Assessment | Fix in `release/0.2` (target) |
|---|---|---|---|
| Critical | 3 days | 3 days | 14 days |
| High | 3 days | 10 days | 30 days |
| Medium | 3 days | 10 days | 60 days |
| Low | 3 days | 10 days | 90 days |
| Info | 3 days | 10 days | No deadline; decided in the re-test |

The clock starts when the project receives the finding (preliminary report or earlier notice, if the
auditor reports it earlier). If a deadline cannot be met, the reason is written in the finding and
communicated to the auditor; it is not extended silently.

## 2. Registry: private GitHub Security Advisories

- **One private advisory per finding**, created from the repository in the *Security →
  Advisories* tab, using the same channel as [`SECURITY.md`](../../../SECURITY.md)). No public issues
  are opened and no findings are commented on in public PRs.
- The auditor is added as a collaborator on the advisory (or creates it with *Report a vulnerability*).
- Title: `AUD-nn · <summary>`. The identifier `AUD-nn` is the auditor's report one if it has one;
  otherwise the project assigns the next number.
- Minimum content of the advisory:

| Field | Content |
|---|---|
| Identifier | `AUD-nn` |
| Severity and CVSS 4.0 vector | Label and vector |
| Component and file | Path and line on the frozen SHA |
| Affected versions | `v0.1.0`, `v0.2.0` |
| Description, impact and PoC | From the auditor |
| Decision | Accepted, rejected with reason, accepted as residual risk |
| Fix | Link to the PR in `main` and *commit* of the `cherry-pick -x` |
| Regression test | Test path |
| Status | New → Accepted → Being fixed → Fixed → Verified by the auditor → Published |

- **Fixes for findings under embargo** are developed in the advisory's *temporary private fork* and
  merged on the same day the fixed version is published (exception in ADR-AUD-01).
- At the end, the advisory is published (section 6) and the status is reflected in the public report.

## 3. Fix

Each accepted finding is fixed with:

1. **A PR to `main`** whose title starts with `AUD-nn:`. Body: link to the private advisory (or its
   identifier, if it is public), root cause, scope of the change and why it is not something else.
2. **A regression test** that **fails without the fix** and passes with it. Name or comment with
   `AUD-nn`. Accepted types:
   - Rust: test in the affected crate (`core/`, `ffi/`); new vector in `core/tests/vectors/op-v1.json`
     only if the fix does not change the v1 format. If it does, it is a **new version of the format** and
     is decided separately (the existing vectors are not regenerated);
   - Kotlin: unit test (JUnit 4) or instrumented test;
   - a new *fuzzing* target or a seed in `fuzz/seeds/` when the failure is in parsing
     untrusted data;
   - if it is impossible to automate it (e.g. a manifest adjustment), a check in the build
     (such as `VerifyManifest`) or, as a last option, a manual step written in the finding.
3. **Documentation change** if the finding contradicts a claim in
   [`docs/threat-model.md`](../../threat-model.md)), [`docs/crypto-spec.md`](../../crypto-spec.md)) or
   [`android/README.md`](../../../android/README.md)): the text **or** the code is fixed.
4. **`cherry-pick -x` to `release/0.2`** (ADR-AUD-01 policy) and signed tag `v0.2.N`.
5. **Delivery to the auditor** of the `git diff v0.2.(N-1)..v0.2.N` diff and of the link to the regression test.

When the auditor disagrees with the fix, it is discussed in the advisory, not in a separate channel.

## 4. Verification by the auditor (re-test)

- The auditor checks each finding on the `v0.2.N` tag, not on `main`.
- Final states: **Fixed**, **Partial** (with what is missing), **Not fixed** or **Accepted as
  risk** (project decision, with reason, approved by the auditor as «understood»).
- A finding is not closed without the auditor's **written** confirmation.
- A fix that introduces a new problem is a new finding.
- The re-test covers only what changed. Changes of another nature in `release/0.2` are forbidden by
  the ADR-AUD-01 policy; no «incidental» fixes are slipped in.

## 5. Risk acceptance

A finding can be closed without a fix only if:

- it is Low or Info, **or** it is the residue already documented in [`decisions.md`](decisions.md)) (e.g. JVM
  `String`, output `RustBuffer`, abort due to out-of-memory in Argon2);
- the reason, the residual impact and who decides it (the maintainer) are recorded;
- it is listed under «Residual risks» in the [threat model](../../threat-model.md)) and in the public
  report;
- the auditor has had the opportunity to disagree.

**Critical and High are not accepted as risk** without an explicit decision recorded and visible in the
public report; in that case `1.0.0` remains blocked until it is reviewed (section 7).

## 6. Publication

1. **Report.** The final report (section 8 of [`scope.md`](scope.md))) is published with the
   vendor's permission, in the repository or in the release. It must include scope, methodology,
   findings with their final status and limitations. If OSTIF or a funder asks for it, its
   schedule is coordinated (see [`vendors.md`](vendors.md))).
2. **Order.** It is published **after** the fixes are in a signed and published version and
   after the advisories have been published. An unfixed and unagreed finding is not published with
   technical detail without the date agreed with the auditor.
3. **Advisories and CVE.** For each finding that affects an **already published** version (e.g. `v0.1.0`)
   and is Medium or above, the advisory is published with the [GitHub Security
   Advisory](https://docs.github.com/en/code-security/security-advisories) and a CVE is requested from the
   advisory itself (GitHub acts as CNA; deadline details unverified). Findings that only
   affect `v0.2.0` pre-release have no affected users: they are published in the report and, if it is
   considered useful, also as an advisory without CVE. Low or Info findings do not need a CVE.
4. **Release notes.** Each `v0.2.N` states which findings it fixes (by `AUD-nn`) in
   `docs/releases/` and in the `fastlane/` *changelogs*.
5. **Notice in the repository.** `SECURITY.md`, `README.md` and the release notes are updated to
   remove or qualify the «no external audit» notice **only** when section 7 is met.

## 7. Criteria for `1.0.0`

Proposal, pending approval. `1.0.0` is tagged only when **all** of this is met:

| # | Criterion | How it is checked |
|---|---|---|
| 1 | All **Critical and High** findings are Fixed and **Verified by the auditor** | Status in the advisories and in the final report |
| 2 | **Medium** findings are Fixed or Accepted with a written and visible reason | Final report; «Residual risks» section |
| 3 | Each fixed finding has a referenced regression test | Review of the `AUD-nn` PRs |
| 4 | Final report **published** with the vendor's permission | Link in the repository |
| 5 | Advisories and CVEs published for what affects published versions | *Security* tab of the repository |
| 6 | The CI of the `1.0.0` tag is green, the APK is reproducible on Linux and the SHA-256 matches that of an independent build | `ci.yml`, [`docs/fdroid/README.md`](../fdroid/README.md)) |
| 7 | [`docs/threat-model.md`](../../threat-model.md)), [`docs/crypto-spec.md`](../../crypto-spec.md)) and [`android/README.md`](../../../android/README.md)) match the code | Final review; nothing «planned» described as done |
| 8 | The decisions pending approval in [`decisions.md`](decisions.md)) are resolved | Final list of `decisions.md` with no open items |
| 9 | `SECURITY.md` updated (supported versions, reference to the report) | Review |
| 10 | A person independent from the maintainer reviews the checklist (if such a person exists; if not, it is noted) | Recorded in the release PR |

If a criterion is not met, `1.0.0` is not published and `0.x` is tagged with the fixes; it is
decided case by case whether a new re-test round is needed.

## 8. Acknowledgements

- The final report and the release notes credit the vendor and the auditors with their permission.
- Published advisories include the GitHub credits (advisory → *Credits*).
- Those who submit findings outside the audit are also credited, unless they prefer not to
  appear (as [`SECURITY.md`](../../../SECURITY.md)) already promises).
- There is no bounty programme for now.

## 9. Proposed changes (not applied)

This package **does not modify** `SECURITY.md` or the code. Proposed changes, pending approval:

| File | Change |
|---|---|
| `SECURITY.md`, «Supported versions» | Add «the `release/0.2` branch until the audit closes» (ADR-AUD-01 already requires it) |
| `SECURITY.md`, «What to expect» | Add the table of fix targets per severity (section 1) and keep the 90-day maximum |
| `SECURITY.md`, «In scope» | Check that what appears there matches [`scope.md`](scope.md)); when this was written it matched in the essentials |
| `SECURITY.md`, opening notice | Replace «The project has not yet undergone an external audit» with a link to the published report **only** when section 7 is met |
| `docs/threat-model.md` | Link to the report and reflect the accepted residual risks |
| Repository (GitHub) | Enable private vulnerability reporting if it is not enabled (see `SECURITY.md`) and define the `security`, `AUD` labels |

## 10. Contacts and responsibilities

| Role | Person |
|---|---|
| Owner of findings and fixes | `@rldona` |
| Independent verification of `1.0.0` | **PENDING** |
| Auditor contact | **PENDING** |
