#!/usr/bin/env bash
# Compiles GuardBridge.java + GuardApplication.java into a standalone
# classesN.dex, ready for tools/inject_guard_application.py to splice into
# a target APK that has no available source (see docs/GUIDE.md).
#
# Needs: a JDK (javac) and an `android.jar` (any recent API level -- this
# only uses long-stable Application/Context/PackageManager APIs). Get
# android.jar from an installed Android SDK's platforms/android-<N>/
# directory, or download platform-<N>-*.zip from
# https://dl.google.com/android/repository/repository2-3.xml (these are
# architecture-independent, no host-OS variants).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 --android-jar <path> --d8 <path/to/d8> --out <output.dex>" >&2
  exit 1
}

ANDROID_JAR=""
D8=""
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --android-jar) ANDROID_JAR="$2"; shift 2 ;;
    --d8) D8="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done
[[ -n "$ANDROID_JAR" && -n "$D8" && -n "$OUT" ]] || usage
[[ -f "$ANDROID_JAR" ]] || { echo "FATAL: android.jar not found at $ANDROID_JAR" >&2; exit 1; }
[[ -f "$D8" ]] || { echo "FATAL: d8 not found at $D8" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# GuardApplication.java no longer references any Flutter Java class (see
# its class doc: it loads libflutter.so directly via
# System.loadLibrary("flutter") instead of going through Flutter's
# FlutterLoader, which turned out not to reliably survive R8 shrinking in
# release builds). So this only ever needs android.jar -- no compile-time
# stub for a Flutter class is required anymore.
mkdir -p "$WORK/real-classes"
javac -d "$WORK/real-classes" \
  -classpath "$ANDROID_JAR" \
  "$SCRIPT_DIR/src/dev/packer/guard/GuardBridge.java" \
  "$SCRIPT_DIR/src/dev/packer/guard/GuardApplication.java"

mkdir -p "$WORK/dexout"
"$D8" --output "$WORK/dexout" \
  --lib "$ANDROID_JAR" \
  "$WORK/real-classes/dev/packer/guard/GuardBridge.class" \
  "$WORK/real-classes/dev/packer/guard/GuardApplication.class"

mkdir -p "$(dirname "$OUT")"
cp "$WORK/dexout/classes.dex" "$OUT"
echo "wrote $OUT"
