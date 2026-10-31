#!/bin/sh
# User-facing text belongs in res/values/strings.xml, never in Kotlin: a literal cannot be
# translated and silently leaves one of the two languages behind. Android lint does not see
# Compose calls, so this looks for the shapes the app actually uses.
#
# usage: scripts/check-no-ui-literals.sh [--self-test]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC="$ROOT/android/app/src/main/kotlin"

# Files where a Spanish or non-ASCII literal is data, not interface:
#  - FieldClassifier: words the autofill service looks for in other apps' forms.
#  - StoredLabels: labels written inside the vault, frozen by the data format.
#  - FieldLabels: the regex that recognises a numbered image label.
#  - EmergencyKit: brand name and list bullets drawn on the PDF.
ALLOW='(autofill/FieldClassifier\.kt|data/StoredLabels\.kt|ui/vault/FieldLabels\.kt|security/EmergencyKit\.kt)'

# Shapes that paint text, and any literal that is not plain ASCII (a Spanish word).
SHAPES='(Text\(|TextButton\(|label = |title = |contentDescription = |placeholder = |showSnackbar\(|Toast\.makeText\(|setTitle\(|setMessage\()'
NON_ASCII='[áéíóúüñÁÉÍÓÚÜÑ]'

scan() {
    dir=$1
    found=0
    # Text(...), title = ..., etc. with a literal right after.
    if hits=$(grep -rnE "$SHAPES[[:space:]]*\"" "$dir" --include='*.kt' 2>/dev/null | grep -vE "$ALLOW" || true); [ -n "$hits" ]; then
        echo "$hits" >&2
        found=1
    fi
    # Any literal with Spanish characters, except the allowlist.
    if hits=$(grep -rnE "$NON_ASCII" "$dir" --include='*.kt' 2>/dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)' | grep -vE "$ALLOW" || true); [ -n "$hits" ]; then
        echo "$hits" >&2
        found=1
    fi
    return $found
}

if [ "${1:-}" = "--self-test" ]; then
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    mkdir -p "$TMP/clean" "$TMP/dirty" "$TMP/allowed"
    printf 'val x = Text(stringResource(R.string.hello))\n' > "$TMP/clean/A.kt"
    printf 'val x = Text("Hola")\n' > "$TMP/dirty/A.kt"
    printf 'val x = Text("Contraseña")\n' > "$TMP/allowed/FieldClassifier.kt"
    scan "$TMP/clean" || { echo "FAIL: a clean tree must pass" >&2; exit 1; }
    if scan "$TMP/dirty" 2>/dev/null; then echo "FAIL: a literal must fail" >&2; exit 1; fi
    if scan "$TMP/allowed" 2>/dev/null; then echo "FAIL: the allowlist must be honoured" >&2; exit 1; fi
    echo "self-test OK"
    exit 0
fi

if [ ! -d "$SRC" ]; then
    echo "missing $SRC" >&2
    exit 1
fi

if scan "$SRC"; then
    echo "no user-facing literals found in Kotlin"
else
    echo "user-facing text found outside res/strings.xml (see above)" >&2
    exit 1
fi
