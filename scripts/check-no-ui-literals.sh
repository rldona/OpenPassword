#!/bin/sh
# User-facing text belongs in res/values/strings.xml, never in Kotlin: a literal cannot be
# translated and silently leaves one of the two languages behind. Android lint does not see
# Compose calls, so this looks for the shapes the app actually uses.
#
# usage: scripts/check-no-ui-literals.sh [--self-test | <directory>]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEFAULT_SRC="$ROOT/android/app/src/main/kotlin"

scan() {
    python3 - "$1" <<'PY'
import os
import re
import sys

# Files where a Spanish or non-ASCII literal is data, not interface:
#  - FieldClassifier: words the autofill service looks for in other apps' forms.
#  - StoredLabels: labels written inside the vault, frozen by the data format.
#  - FieldLabels: the regex that recognises a numbered image label.
#  - EmergencyKit: brand name and list bullets drawn on the PDF.
ALLOWED = {
    "FieldClassifier.kt",
    "StoredLabels.kt",
    "FieldLabels.kt",
    "EmergencyKit.kt",
}

# Something that paints text, right before a string literal (newlines allowed).
SHAPES = re.compile(
    r"(?:Text\(|TextButton\(|label\s*=|title\s*=|contentDescription\s*=|placeholder\s*=|"
    r"showSnackbar\(|Toast\.makeText\(|setTitle\(|setMessage\(|error\s*=|message\s*=|"
    r"supportingText\s*=|headlineContent\s*=|supportingContent\s*=|"
    r"headlineText\s*=)\s*(?:text\s*=\s*)?$"
)
STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
SPANISH = re.compile(r"[áéíóúüñÁÉÍÓÚÜÑ¿¡]")


def strip_trailing_comment(line: str) -> str:
    """Removes a // comment that is not inside a string literal."""
    out = []
    in_string = False
    escaped = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
                out.append(ch)
            elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out)


def scan_file(path: str):
    text = open(path, encoding="utf-8").read()
    # Block comments (KDoc included) are not interface: blank them, keeping line numbers.
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    lines = text.split("\n")
    problems = []
    for number, line in enumerate(lines, 1):
        code = strip_trailing_comment(line)
        for match in STRING.finditer(code):
            literal = match.group(1)
            if not literal:
                continue
            before = code[: match.start()]
            if SHAPES.search(before):
                problems.append((number, "painted literal", line.strip()))
            elif SPANISH.search(literal):
                problems.append((number, "Spanish literal", line.strip()))
    return problems


def main() -> int:
    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f"missing {root}", file=sys.stderr)
        return 1
    found = 0
    for directory, _, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".kt") or name in ALLOWED:
                continue
            path = os.path.join(directory, name)
            for number, kind, line in scan_file(path):
                print(f"{path}:{number}: {kind}: {line}", file=sys.stderr)
                found += 1
    if found:
        print("user-facing text found outside res/strings.xml (see above)", file=sys.stderr)
        return 1
    print("no user-facing literals found in Kotlin")
    return 0


sys.exit(main())
PY
}

if [ "${1:-}" = "--self-test" ]; then
    TMP=$(mktemp -d)
    trap 'rm -rf "$TMP"' EXIT
    mkdir -p "$TMP/clean" "$TMP/dirty" "$TMP/allowed"
    printf 'val x = Text(stringResource(R.string.hello))\n' > "$TMP/clean/A.kt"
    printf '// a comment with an accent: Contraseña\nval y = 1 // café\n' > "$TMP/clean/B.kt"
    printf 'val a = Text("Hello")\n' > "$TMP/dirty/A.kt"
    printf 'Text(\n    "Hello",\n)\n' > "$TMP/dirty/B.kt"
    printf 'Text(text = "Hello")\n' > "$TMP/dirty/C.kt"
    printf 'Text(if (x) "A" else "B")\n' > "$TMP/dirty/D.kt"
    printf 'error = "Save failed"\n' > "$TMP/dirty/E.kt"
    printf 'snackbar.showSnackbar(\n    "Saved"\n)\n' > "$TMP/dirty/F.kt"
    printf 'contentDescription = "Close"\n' > "$TMP/dirty/G.kt"
    printf 'val x = Text("Contraseña")\n' > "$TMP/allowed/FieldClassifier.kt"

    if ! scan "$TMP/clean" >/dev/null 2>&1; then
        echo "FAIL: a clean tree must pass" >&2
        exit 1
    fi
    if scan "$TMP/dirty" >/dev/null 2>&1; then
        echo "FAIL: literals must fail" >&2
        exit 1
    fi
    if ! scan "$TMP/allowed" >/dev/null 2>&1; then
        echo "FAIL: the allowlist must be honoured" >&2
        exit 1
    fi
    echo "self-test OK"
    exit 0
fi

if [ ! -d "$DEFAULT_SRC" ]; then
    echo "missing $DEFAULT_SRC" >&2
    exit 1
fi

scan "$DEFAULT_SRC"
