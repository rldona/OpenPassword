# Publishing OpenPassword on F-Droid

> **Status: paused** by decision of the project maintainer on **2026-10-30**. There is no `v0.1.0`
> tag and no published release, and no recipe has been submitted to `fdroiddata`. This document
> is the point to resume from: everything prepared is still in the repository and the manual steps
> have not changed. Nothing needs to be undone to pick it back up; just start with "The steps you
> need to take".
>
> The external audit (Phase 3) **does not depend** on this publication.

F-Droid builds the app from source. With a **reproducible build** it compiles the APK and, if it is
identical to the one you publish on GitHub (apart from the signature), it distributes yours, signed
with your key. That way users always get the same signature, whether they come from F-Droid or from
GitHub.

## What is already prepared in the repository

- Store metadata in `fastlane/metadata/android/` (Spanish and English): title, descriptions and
  release notes for version 1. F-Droid reads them directly from the repository. The icon is taken
  from the APK.
- Reproducible APK **on Linux**, which is where F-Droid builds: two CI runs on different machines
  produce the same APK byte for byte. On macOS it is also reproducible across folders, but it
  **does not match the Linux one**: the NDK linker stores its own build path and Cargo mixes the
  host system into its identifiers, and that changes `libop_ffi.so`. That is why **the APK that
  gets published is the one the CI builds**, signed afterwards on your computer.
  - Dependency paths (`~/.cargo/registry/…`) are rewritten to `/cargo/…`, so the APK does not
    include the user name of whoever builds it.
  - The Rust compiler is pinned in `rust-toolchain.toml` (1.99.1), and the NDK and Gradle are
    pinned in the build.
  - The dependency block signed by Google (`dependenciesInfo`) is not included.
- Recipe draft: `io.github.rldona.openpassword.yml`, in this same folder.
- F-Droid inclusion requirements:
  - All dependencies are free and come from Maven Central, Google or crates.io.
  - There are no trackers, ads or Google services.
  - The app does not use the network. No *anti-feature* is needed.

## The steps you need to take

1. **Back up the signing key**, if you do not have one yet: store `~/.openpassword/`
   (the `.p12` and its `release-signing.properties`) off the computer. If you lose that key, you will
   not be able to publish updates with the same signature.
2. **Tag the version** on the commit you want to publish:
   ```sh
   git tag -a v0.1.0 -m "OpenPassword 0.1.0"
   git push origin v0.1.0
   ```
3. **Sign the CI APK** once the run for the tag finishes (look it up with
   `gh run list -R rldona/OpenPassword --branch v0.1.0`). The script downloads the unsigned APK,
   signs it with your local key (v2 + v3, like Gradle) and checks the certificate:
   ```sh
   scripts/sign-release.sh <run-id> 0.1.0
   ```
   The CI artifact expires after 14 days (`retention-days: 14` in `ci.yml`): sign the APK within
   that window or you will have to re-run the job.
   Do not build the release APK on macOS: it would not match the F-Droid one.
4. **Create the GitHub release** with that APK, using the exact name the recipe expects:
   ```sh
   gh release create v0.1.0 openpassword-0.1.0.apk --title "OpenPassword 0.1.0" --notes-file fastlane/metadata/android/es-ES/changelogs/1.txt
   ```
5. **Submit the recipe to F-Droid**: fork https://gitlab.com/fdroid/fdroiddata with your GitLab
   account, copy `io.github.rldona.openpassword.yml` to `metadata/` and open a *merge request*.
   Their CI will build the app and tell you whether the recipe needs adjustments.

## To confirm before submitting the recipe

- **NDK r30 on the F-Droid server**: if they do not offer it yet, `ndkVersion` (and the `ndk:`
  field) will have to be lowered to the newest version they have and the build re-checked.
- **Version of the `rustup` *srclib*** available in fdroiddata (`rustup@1.28.2` is an assumption).
- **That the F-Droid server reproduces the CI APK**: both are Linux with the same NDK, Rust and
  Gradle, and two CI machines already match, but it is only confirmed once F-Droid builds it.
  Their CI will say so in the *merge request*.
- **Screenshots**: the app blocks screenshots (`FLAG_SECURE`), so there are none. They can be
  added later in `fastlane/metadata/android/<language>/images/phoneScreenshots/`, generated
  with sample data.
