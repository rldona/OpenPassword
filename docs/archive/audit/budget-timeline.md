# Budget and timeline

Template for comparing quotes and planning the `v0.2.0` audit
([`scope.md`](scope.md))).

**All amounts and dates are gaps (`___`) on purpose.** There is no budget assigned, no quote has
been requested and no vendor publishes rates (see [`vendors.md`](vendors.md))). It is
filled in when the quotes arrive, and every figure must carry its source (quote with date and reference).

## 1. Template per vendor

Copy one block per vendor (`### <Vendor>`) and fill it in. The components are those of
[`scope.md`](scope.md#4-in-scope)).

### `<Vendor>`

| Data point | Value |
|---|---|
| Source of the quote (date, reference) | `___` |
| Currency and taxes (VAT included yes/no) | `___` |
| Validity of the quote | `___` |
| Rate per person-day | `___` |
| Team profile (people, experience in Rust/Android/cryptography) | `___` |

**Effort per component** (person-days):

| Component | Person-days | Notes |
|---|---|---|
| `op-core`: cryptography, format, STREAM, KDF | `___` | |
| `op-core`: importers (KDBX, 1Password, Bitwarden, CSV) and TOTP | `___` | |
| `op-ffi`: UniFFI, secrets, panics, KDF bounds | `___` | |
| Android app: session, Keystore and biometrics | `___` | |
| Android app: autofill (matching, public suffixes, saving) | `___` | |
| Android app: clipboard, anti-tapjacking, root warning, storage | `___` | |
| `.opvault` format (design review) | `___` | |
| Reproducible builds and signing | `___` | |
| Project management and meetings | `___` | |
| **Audit subtotal** (days × rate) | `___` | |

**Additional costs:**

| Item | Amount | Notes |
|---|---|---|
| Preliminary report | `___` | included in the subtotal? |
| Re-test (rounds included: `___`) | `___` | Each additional round: `___` |
| Publishable final report | `___` | Vendor review included? |
| Summary for users (optional) | `___` | |
| Expenses (travel, licenses, test devices) | `___` | |
| Taxes | `___` | |
| **Total** | `___` | |

**Conditions** (mandatory unless stated otherwise):

| Condition | Met? | Notes |
|---|---|---|
| Written permission to publish the full report | `___` | **Mandatory** |
| Re-test included | `___` | **Mandatory** (at least one round) |
| Critical findings reported immediately | `___` | |
| PoC delivery | `___` | |
| Language of the report | `___` | |
| Deadline from signature to start | `___` | |
| Duration of the audit (weeks) | `___` | |
| Payment method and payment schedule | `___` | |

**Funding** (see [`vendors.md` §3](vendors.md#3-funding-routes))):

| Route | Amount requested | Amount granted | Status and date | Conditions the vendor |
|---|---|---|---|---|
| OSTIF | `___` | `___` | `___` | `___` |
| OTF Security Lab | `___` | `___` | `___` | `___` |
| NLnet Restack | `___` | `___` | `___` | `___` |
| Own funds | `___` | `___` | `___` | no |
| **Total covered** | `___` | | | |
| **Gap to cover** | `___` | | | |

### Comparison

| Vendor | Total | Covered | To cover | Re-test | Publication | Start | Duration |
|---|---|---|---|---|---|---|---|
| `___` | `___` | `___` | `___` | `___` | `___` | `___` | `___` |

## 2. Timeline

The durations are gaps. Each milestone has an **exit condition**: the next one is not started without
meeting it. The branch and change policies during the audit are in
[ADR-AUD-01](decisions.md#adr-aud-01--freeze-strategy)).

| # | Milestone | Target date | Duration | Exit condition |
|---|---|---|---|---|
| 1 | Funding and vendor decided | `___` | `___` | Quote accepted; contract with publication permission and re-test; amount covered |
| 2 | **Freeze**: `release/0.2` and signed tag `v0.2.0` | `___` | `___` | Steps 1–18 of the [`decisions.md`](decisions.md)) plan done and green; CI of the tag green; APK SHA-256 matches an independent build on Linux; SHA noted in [`README.md`](README.md)) and [`scope.md`](scope.md)); package attached to the pre-release |
| 3 | **Start** | `___` | `___` | Kick-off meeting done; access to the repository and to the private advisories; contacts confirmed |
| 4 | Active audit | `___` | `___` | Critical findings reported immediately; the project answers questions within `___` days |
| 5 | **Preliminary report** | `___` | `___` | Report received; each finding recorded in a private advisory |
| 6 | **Fixes** | `___` | `___` | Each accepted finding has a fix with a regression test in `main` and, after `cherry-pick -x`, in `release/0.2`; signed tag `v0.2.N`; diff delivered |
| 7 | **Re-test** | `___` | `___` | The auditor marks each finding as fixed, partial, not fixed or accepted |
| 8 | **Final report** | `___` | `___` | Final report received; public text reviewed; publication date agreed |
| 9 | Publication | `___` | `___` | Report and advisories published ([`findings-process.md`](findings-process.md))) |
| 10 | **`1.0.0`** | `___` | `___` | Criteria of [`findings-process.md`](findings-process.md#7-criteria-for-100)) met |

Dependencies to watch:

- Milestone 2 depends on decisions pending human approval (final list of
  [`decisions.md`](decisions.md#decisions-that-require-human-approval))).
- If there are several vendors or funders, milestone 1 may be delayed; NLnet calls
  are every ~2 months (see [`vendors.md`](vendors.md))).
- Milestone 6 may repeat (`v0.2.N`) before the re-test; the auditor decides how many rounds fit.
- Safety margins (holidays, maintainer availability, a single maintainer) are
  noted in `___`.
