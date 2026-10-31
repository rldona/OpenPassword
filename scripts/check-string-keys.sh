#!/bin/sh
# Every user-facing string must exist in both languages, and only in those two: a key that
# lands in one file and not the other shows English text in the Spanish interface (or a
# resource-not-found crash). Compares <string> and <plurals> names.
#
# usage: scripts/check-string-keys.sh [--self-test]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RES="$ROOT/android/app/src/main/res"
DEFAULT="$RES/values/strings.xml"
SPANISH="$RES/values-es/strings.xml"

keys() {
    # One name per line, sorted and unique. Works for <string> and <plurals>.
    sed -nE 's/.*<(string|plurals) name="([^"]*)".*/\2/p' "$1" | sort -u
}

check() {
    default_file=$1
    spanish_file=$2
    keys "$default_file" > "$TMP/default.keys"
    keys "$spanish_file" > "$TMP/spanish.keys"
    missing_in_spanish=$(comm -23 "$TMP/default.keys" "$TMP/spanish.keys")
    extra_in_spanish=$(comm -13 "$TMP/default.keys" "$TMP/spanish.keys")
    status=0
    if [ -n "$missing_in_spanish" ]; then
        echo "missing in $(basename "$(dirname "$spanish_file")")/strings.xml:" >&2
        echo "$missing_in_spanish" | sed 's/^/  /' >&2
        status=1
    fi
    if [ -n "$extra_in_spanish" ]; then
        echo "not in the default values/strings.xml:" >&2
        echo "$extra_in_spanish" | sed 's/^/  /' >&2
        status=1
    fi
    if [ -z "$(cat "$TMP/default.keys")" ]; then
        echo "no keys found in $default_file: wrong path or unreadable file" >&2
        status=1
    fi
    return $status
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "${1:-}" = "--self-test" ]; then
    printf '<resources>\n  <string name="a">A</string>\n  <plurals name="b"><item quantity="other">B</item></plurals>\n</resources>\n' > "$TMP/one.xml"
    printf '<resources>\n  <string name="a">A</string>\n  <plurals name="b"><item quantity="other">B</item></plurals>\n</resources>\n' > "$TMP/same.xml"
    printf '<resources>\n  <string name="a">A</string>\n</resources>\n' > "$TMP/short.xml"
    printf '<resources>\n  <string name="a">A</string>\n  <plurals name="b"><item quantity="other">B</item></plurals>\n  <string name="c">C</string>\n</resources>\n' > "$TMP/long.xml"

    check "$TMP/one.xml" "$TMP/same.xml" || { echo "FAIL: identical files must pass" >&2; exit 1; }
    if check "$TMP/one.xml" "$TMP/short.xml" 2>/dev/null; then echo "FAIL: a missing key must fail" >&2; exit 1; fi
    if check "$TMP/one.xml" "$TMP/long.xml" 2>/dev/null; then echo "FAIL: an extra key must fail" >&2; exit 1; fi
    if check "$TMP/one.xml" "$TMP/does-not-exist.xml" 2>/dev/null; then echo "FAIL: an unreadable file must fail" >&2; exit 1; fi
    echo "self-test OK"
    exit 0
fi

if [ ! -f "$DEFAULT" ] || [ ! -f "$SPANISH" ]; then
    echo "missing $DEFAULT or $SPANISH" >&2
    exit 1
fi

if check "$DEFAULT" "$SPANISH"; then
    echo "string keys match in values/ and values-es/"
else
    exit 1
fi
