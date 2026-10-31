# Archive

Material from an earlier stage, when OpenPassword was planned as a **public product**: functional
proposal, F-Droid publication, external audit and supply chain for distributing binaries.

The project is for **personal use**. None of this is maintained, updated or run. It is kept because it
contains useful work —the internal review, the expanded threat model, the attack surface analysis and
the device test results— and because it explains why the code has the defenses it has.

| Path | Content | Status |
|---|---|---|
| [`proposal.html`](proposal.html) | Functional and technical proposal with prototypes and roadmap | Historical |
| [`audit/`](audit) | Audit package: scope, vendors, budget, internal review, attack surface, dependencies, fuzzing and device tests | Frozen on 2026-10-30 |
| [`fdroid/`](fdroid) | Recipe and steps to publish on F-Droid | Paused |
| [`releases/`](releases) | Notes from the failed `v0.1.0` | Historical |
| [`fastlane/`](fastlane) | Store metadata | Historical |
| [`scripts/sign-release.sh`](scripts/sign-release.sh) | Signing of the APK built by CI | Historical |

## What is still useful for personal use

- [`audit/internal-review.md`](audit/internal-review.md): the 26 findings and their status, including
  those accepted as residual risk.
- [`audit/attack-surface.md`](audit/attack-surface.md): where each untrusted input enters.
- [`audit/dependencies.md`](audit/dependencies.md): `cargo-deny`, licenses and Gradle verification.
- [`audit/device-tests.md`](audit/device-tests.md): the phone test plan and what is missing.
- [`audit/decisions.md`](audit/decisions.md): why the core behaves the way it does.

## What not to resume unless the project becomes public again

Vendors, budget, NDA, OSTIF, NLnet, Sigstore attestations, SBOM, F-Droid recipe and release notes.
They add nothing for installing the app on your own phone.
