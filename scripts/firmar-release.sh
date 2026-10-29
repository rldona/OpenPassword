#!/usr/bin/env bash
# Signs the release APK built by the CI (Linux) with the local release key.
#
# The published APK must be the Linux build: F-Droid builds on Linux and the NDK and Cargo
# embed host-specific details, so an APK built on macOS never matches theirs byte for byte.
#
# usage: scripts/firmar-release.sh <github-actions-run-id> <version>
#   e.g.: scripts/firmar-release.sh 40939999999 0.1.0
set -euo pipefail

RUN_ID=${1:?run id of the CI run for the tagged commit}
VERSION=${2:?version, e.g. 0.1.0}
PROPS=${SIGNING_PROPERTIES:-$HOME/.openpassword/release-signing.properties}
BUILD_TOOLS=${BUILD_TOOLS:-$(ls -d "$HOME"/Library/Android/sdk/build-tools/* "$HOME"/Android/Sdk/build-tools/* 2>/dev/null | sort -V | tail -1)}
OUT="openpassword-$VERSION.apk"

prop() { grep "^$1=" "$PROPS" | cut -d= -f2-; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

gh run download "$RUN_ID" -R rldona/OpenPassword -n app-release-unsigned -D "$WORK"
UNSIGNED="$WORK/app-release-unsigned.apk"
echo "APK sin firmar de la CI: $(shasum -a 256 "$UNSIGNED" | cut -d' ' -f1)"

# Same schemes as the Gradle release signing: no v1 (minSdk 28), v2 + v3 (key rotation).
STORE_PASS=$(prop storePassword) KEY_PASS=$(prop keyPassword) \
  "$BUILD_TOOLS/apksigner" sign \
    --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true \
    --ks "$(prop storeFile)" --ks-key-alias "$(prop keyAlias)" \
    --ks-pass env:STORE_PASS --key-pass env:KEY_PASS \
    --out "$OUT" "$UNSIGNED"
rm -f "$OUT.idsig"

"$BUILD_TOOLS/apksigner" verify --print-certs "$OUT" | grep -E "certificate SHA-256"
echo "Firmado: $OUT"
