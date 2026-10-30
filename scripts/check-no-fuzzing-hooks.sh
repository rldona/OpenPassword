#!/usr/bin/env bash
# Checks that the `cfg(fuzzing)` hooks of op-core are not in a shipped native library.
#
#   scripts/check-no-fuzzing-hooks.sh <libop_ffi.so|.dylib>...   check built libraries
#   scripts/check-no-fuzzing-hooks.sh --self-test                prove that the check can fail
#
# Why a marker and not the hooks' names: the final library only keeps what the exported API
# reaches, so `seal_backup` & co. are gone even when the cfg was on (a name search finds 0 in a
# build WITH the hooks). `op_core::fuzzing::HOOKS_MARKER` is `#[used]` and exists only under
# `--cfg fuzzing`, so it is the thing to look for. Searching an `.rlib` does not work either:
# with `lto = true` it holds LLVM bitcode.
#
# Every checked library must also contain CONTROL, a string that is always there: it proves that
# `strings` can read the file, so an unreadable or empty binary cannot pass as "clean".
set -euo pipefail

MARKER='OPENPASSWORD_FUZZING_HOOKS'
CONTROL='cost above the accepted maximum'

check() {
  local lib=$1
  [ -f "$lib" ] || { echo "FAIL $lib: no such file" >&2; return 1; }
  local text
  text=$(strings -a "$lib")
  if ! grep -qF "$CONTROL" <<<"$text"; then
    echo "FAIL $lib: control string not found, the check cannot read this file" >&2
    return 1
  fi
  if grep -qF "$MARKER" <<<"$text"; then
    echo "FAIL $lib: contains the cfg(fuzzing) marker" >&2
    return 1
  fi
  echo "ok   $lib: no fuzzing hooks (control string present)"
}

if [ "${1:-}" = "--self-test" ]; then
  cd "$(dirname "$0")/.."
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  # Release-like build WITH the hooks. `debug-assertions` is on because op-core refuses
  # `--cfg fuzzing` in a plain release build (compile_error!), as `cargo fuzz build` also has it.
  RUSTFLAGS="--cfg fuzzing" CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_TARGET_DIR="$work" \
    cargo build -p op-ffi --release --locked
  lib=
  for f in "$work"/release/libop_ffi.so "$work"/release/libop_ffi.dylib; do
    [ -f "$f" ] && lib=$f
  done
  [ -n "$lib" ] || { echo "no libop_ffi built in $work/release" >&2; exit 1; }
  # A variable, not a pipe: `grep -q` closing early would make `strings` fail under pipefail.
  text=$(strings -a "$lib")
  if grep -qF "$MARKER" <<<"$text"; then
    echo "positive control ok: the marker is in a build with --cfg fuzzing"
  else
    echo "positive control FAILED: the marker is not in $lib" >&2
    exit 1
  fi
  if check "$lib" 2>/dev/null; then
    echo "self-test FAILED: check() passed a build with the hooks" >&2
    exit 1
  fi
  echo "negative control ok: check() rejects it"
  exit 0
fi

[ "$#" -gt 0 ] || { echo "usage: $0 <lib>... | --self-test" >&2; exit 2; }
status=0
for lib in "$@"; do check "$lib" || status=1; done
exit $status
