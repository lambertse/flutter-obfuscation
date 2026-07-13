#!/usr/bin/env bash
#
# build_and_pack.sh -- end-to-end pipeline (Handover.md §4, §9, §12):
#
#   flutter build --obfuscate  ->  assert obfuscation actually happened
#     ->  encrypt_snapshot.py (per ABI, in place)
#     ->  build libguard.so (per ABI, via NDK/CMake)
#     ->  inject libguard.so into the APK's lib/<abi>/ dirs
#     ->  repack zip (native libs STORED, matching the unmodified build)
#     ->  zipalign -p 4
#     ->  apksigner sign
#     ->  verify (apksigner verify, zipalign -c)
#
# Every stage fails loudly and stops (set -euo pipefail) rather than
# producing a broken APK silently -- see Handover.md §11 "known failure
# modes": a half-finished repack or a missed obfuscation gate is exactly the
# kind of thing that must never ship.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Args / config
# ---------------------------------------------------------------------------
FLUTTER_PROJECT_DIR=""
KEYSTORE=""
KEY_ALIAS=""
KEYSTORE_PASS_ENV=""   # name of an env var holding the keystore password
KEY_PASS_ENV=""         # name of an env var holding the key password
DEV_KEY_HEX=""          # dev/local override, skips keystore entirely
OUT_DIR="$PACKER_DIR/../build/packed"
MIN_SDK="21"
ABIS="arm64-v8a,armeabi-v7a,x86_64"
OBFUSCATE_GATE_MAX_MATCHES="${OBFUSCATE_GATE_MAX_MATCHES:-5}"

usage() {
  cat <<EOF
Usage: $0 --project-dir <flutter_project> [options]

Release signing (required unless --dev-key-hex is given):
  --keystore <path>            Release keystore (.jks/.p12)
  --key-alias <alias>          Key alias inside the keystore
  --keystore-pass-env <VAR>    Name of an env var holding the keystore password
  --key-pass-env <VAR>         Name of an env var holding the key password
                                (defaults to the same as --keystore-pass-env)

Dev/local (skips keystore entirely -- NOT for release builds):
  --dev-key-hex <64 hex chars> Use this AES-256 key directly instead of
                                deriving one from a release cert.

Other:
  --project-dir <path>         Flutter project root (required)
  --out-dir <path>             Output dir (default: build/packed)
  --min-sdk <n>                (default: 21)
  --abis <csv>                 (default: arm64-v8a,armeabi-v7a,x86_64)
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-dir) FLUTTER_PROJECT_DIR="$2"; shift 2 ;;
    --keystore) KEYSTORE="$2"; shift 2 ;;
    --key-alias) KEY_ALIAS="$2"; shift 2 ;;
    --keystore-pass-env) KEYSTORE_PASS_ENV="$2"; shift 2 ;;
    --key-pass-env) KEY_PASS_ENV="$2"; shift 2 ;;
    --dev-key-hex) DEV_KEY_HEX="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --min-sdk) MIN_SDK="$2"; shift 2 ;;
    --abis) ABIS="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

[[ -n "$FLUTTER_PROJECT_DIR" ]] || { echo "FATAL: --project-dir is required" >&2; usage; }
FLUTTER_PROJECT_DIR="$(cd "$FLUTTER_PROJECT_DIR" && pwd)"

# Signing always needs a keystore, independent of where the AES key comes
# from (--dev-key-hex only replaces snapshot-encryption key derivation, see
# step 4/8 below) -- so this validation is keyed on $KEYSTORE being set, not
# on $DEV_KEY_HEX.
if [[ -z "$DEV_KEY_HEX" && -z "$KEYSTORE" ]]; then
  echo "FATAL: --keystore --key-alias --keystore-pass-env is required (or use --dev-key-hex for a dev build's snapshot key -- signing still needs a keystore)" >&2
  exit 1
fi
if [[ -n "$KEYSTORE" ]]; then
  [[ -n "$KEY_ALIAS" && -n "$KEYSTORE_PASS_ENV" ]] || {
    echo "FATAL: --keystore requires --key-alias and --keystore-pass-env" >&2
    exit 1
  }
  KEY_PASS_ENV="${KEY_PASS_ENV:-$KEYSTORE_PASS_ENV}"
  [[ -n "${!KEYSTORE_PASS_ENV:-}" ]] || { echo "FATAL: env var \$$KEYSTORE_PASS_ENV is not set" >&2; exit 1; }
  [[ -n "${!KEY_PASS_ENV:-}" ]] || { echo "FATAL: env var \$$KEY_PASS_ENV is not set" >&2; exit 1; }
fi

# ---------------------------------------------------------------------------
# Tool checks -- fail loudly up front rather than 20 minutes into the build.
# ---------------------------------------------------------------------------
require_tool() {
  command -v "$1" >/dev/null 2>&1 || { echo "FATAL: required tool '$1' not found on PATH ($2)" >&2; exit 1; }
}
require_tool flutter "Flutter SDK"
require_tool python3 "Python 3, for tools/encrypt_snapshot.py"
require_tool cmake "for building libguard.so"
require_tool zip "for repacking the APK"
require_tool unzip "for extracting the APK"

: "${ANDROID_NDK_HOME:?FATAL: ANDROID_NDK_HOME must point at an installed Android NDK}"
NDK_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake"
[[ -f "$NDK_TOOLCHAIN_FILE" ]] || { echo "FATAL: $NDK_TOOLCHAIN_FILE not found -- check ANDROID_NDK_HOME" >&2; exit 1; }

: "${ANDROID_BUILD_TOOLS:?FATAL: ANDROID_BUILD_TOOLS must point at an Android SDK build-tools dir (contains zipalign, apksigner)}"
ZIPALIGN="$ANDROID_BUILD_TOOLS/zipalign"
APKSIGNER="$ANDROID_BUILD_TOOLS/apksigner"
[[ -x "$ZIPALIGN" ]] || { echo "FATAL: zipalign not found at $ZIPALIGN" >&2; exit 1; }
[[ -x "$APKSIGNER" ]] || { echo "FATAL: apksigner not found at $APKSIGNER" >&2; exit 1; }

if [[ -z "$DEV_KEY_HEX" ]]; then
  require_tool keytool "JDK, for exporting the release cert"
fi

python3 -c "import cryptography" 2>/dev/null || {
  echo "FATAL: python3 'cryptography' package not installed (pip install -r $SCRIPT_DIR/requirements.txt)" >&2
  exit 1
}

mkdir -p "$OUT_DIR"
WORK_DIR="$(mktemp -d "${OUT_DIR}/work.XXXXXX")"
trap 'echo "(leaving work dir for inspection: $WORK_DIR)"' EXIT

IFS=',' read -r -a ABI_ARRAY <<< "$ABIS"

# ---------------------------------------------------------------------------
# 1. flutter build --obfuscate
# ---------------------------------------------------------------------------
echo "== [1/8] flutter build apk --release --obfuscate =="
DEBUG_INFO_DIR="$OUT_DIR/debug-info"
mkdir -p "$DEBUG_INFO_DIR"
( cd "$FLUTTER_PROJECT_DIR" && \
  flutter build apk --release --obfuscate --split-debug-info="$DEBUG_INFO_DIR" )

BUILT_APK="$FLUTTER_PROJECT_DIR/build/app/outputs/flutter-apk/app-release.apk"
[[ -f "$BUILT_APK" ]] || { echo "FATAL: expected build output not found at $BUILT_APK" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 2. Extract
# ---------------------------------------------------------------------------
echo "== [2/8] extracting APK =="
EXTRACT_DIR="$WORK_DIR/apk"
mkdir -p "$EXTRACT_DIR"
unzip -q "$BUILT_APK" -d "$EXTRACT_DIR"

for abi in "${ABI_ARRAY[@]}"; do
  [[ -f "$EXTRACT_DIR/lib/$abi/libapp.so" ]] || { echo "FATAL: lib/$abi/libapp.so missing from built APK -- ABI not present in this build?" >&2; exit 1; }
  [[ -f "$EXTRACT_DIR/lib/$abi/libflutter.so" ]] || { echo "FATAL: lib/$abi/libflutter.so missing from built APK" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# 3. Obfuscation gate (Handover.md §9.7) -- refuse to encrypt an
#    unobfuscated snapshot. Uses the Dart package name (pubspec.yaml `name:`)
#    rather than a generic "package:" grep, matching what --obfuscate
#    actually scrubs from the app's own library URIs.
# ---------------------------------------------------------------------------
echo "== [3/8] obfuscation gate =="
DART_PACKAGE_NAME="$(grep -m1 '^name:' "$FLUTTER_PROJECT_DIR/pubspec.yaml" | awk '{print $2}' | tr -d '[:space:]')"
[[ -n "$DART_PACKAGE_NAME" ]] || { echo "FATAL: could not read 'name:' from $FLUTTER_PROJECT_DIR/pubspec.yaml" >&2; exit 1; }

for abi in "${ABI_ARRAY[@]}"; do
  libapp="$EXTRACT_DIR/lib/$abi/libapp.so"
  # -a: treat binary as text: -o: one match per line so wc -l counts
  # occurrences, not "lines containing a match" (a binary blob is mostly one
  # giant "line" between rare NUL/newline bytes, so -c would undercount).
  matches="$(grep -a -o "package:${DART_PACKAGE_NAME}/" "$libapp" | wc -l | tr -d '[:space:]')"
  echo "  [$abi] 'package:${DART_PACKAGE_NAME}/' occurrences in libapp.so: $matches"
  if (( matches > OBFUSCATE_GATE_MAX_MATCHES )); then
    echo "FATAL: [$abi] libapp.so does not look obfuscated ($matches occurrences of the app's own package URI, expected <= $OBFUSCATE_GATE_MAX_MATCHES)." >&2
    echo "       Encrypting a non-obfuscated snapshot is near-worthless -- see Handover.md §2." >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# 4. Release cert -> key material
# ---------------------------------------------------------------------------
echo "== [4/8] key material =="
REGIONS_H="$WORK_DIR/regions.h"
ENCRYPT_ARGS=(--libs-dir "$EXTRACT_DIR/lib" --abis "$ABIS" --output-regions-h "$REGIONS_H")

if [[ -n "$DEV_KEY_HEX" ]]; then
  echo "  WARNING: using --dev-key-hex, NOT deriving from a release cert. Do not ship this build." >&2
  ENCRYPT_ARGS+=(--key-hex "$DEV_KEY_HEX")
else
  CERT_DER="$WORK_DIR/release_cert.der"
  keytool -exportcert \
    -alias "$KEY_ALIAS" \
    -keystore "$KEYSTORE" \
    -storepass "${!KEYSTORE_PASS_ENV}" \
    -file "$CERT_DER" >/dev/null
  ENCRYPT_ARGS+=(--cert-der "$CERT_DER")
fi

# ---------------------------------------------------------------------------
# 5. Encrypt snapshot regions in place, emit regions.h
# ---------------------------------------------------------------------------
echo "== [5/8] encrypt_snapshot.py =="
python3 "$SCRIPT_DIR/encrypt_snapshot.py" "${ENCRYPT_ARGS[@]}"
cp "$REGIONS_H" "$PACKER_DIR/native/libguard/src/regions.h"

# ---------------------------------------------------------------------------
# 6. Build libguard.so per ABI
# ---------------------------------------------------------------------------
echo "== [6/8] building libguard.so per ABI =="
for abi in "${ABI_ARRAY[@]}"; do
  echo "  -- $abi --"
  BUILD_DIR="$WORK_DIR/cmake-build-$abi"
  cmake -S "$PACKER_DIR/native/libguard" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK_TOOLCHAIN_FILE" \
    -DANDROID_ABI="$abi" \
    -DANDROID_PLATFORM="android-$MIN_SDK" \
    -DCMAKE_BUILD_TYPE=Release
  cmake --build "$BUILD_DIR" --config Release

  SO_OUT="$BUILD_DIR/libguard.so"
  [[ -f "$SO_OUT" ]] || { echo "FATAL: expected $SO_OUT after build" >&2; exit 1; }
  cp "$SO_OUT" "$EXTRACT_DIR/lib/$abi/libguard.so"
done

# ---------------------------------------------------------------------------
# 7. Repack + zipalign
#
#    Update the ORIGINAL build output in place rather than rebuilding the
#    zip from scratch. AES-CTR keeps libapp.so byte-identical in length, so
#    this only ever needs to replace/add the exact lib/<abi>/* entries we
#    touched -- every other entry keeps its original compression method and
#    alignment untouched. That matters beyond just native libs: Android
#    30+ requires resources.arsc specifically to stay STORED and aligned,
#    or install fails with INSTALL_PARSE_FAILED_*. A full rebuild with our
#    own compression policy would silently recompress it (and anything
#    else AAPT deliberately stored); this targeted update avoids that by
#    construction instead of trying to replicate AAPT's packaging choices.
# ---------------------------------------------------------------------------
echo "== [7/8] repack + zipalign =="
UNSIGNED_APK="$OUT_DIR/app-release-packed-unsigned.apk"
ALIGNED_APK="$OUT_DIR/app-release-packed-aligned.apk"
rm -f "$UNSIGNED_APK" "$ALIGNED_APK"

cp "$BUILT_APK" "$UNSIGNED_APK"

REPACK_FILES=()
for abi in "${ABI_ARRAY[@]}"; do
  REPACK_FILES+=("lib/$abi/libapp.so" "lib/$abi/libguard.so")
done
# -0: store (no compression), matching how the original build ships every
# file under lib/ (verified against the reference APK: extractNativeLibs-
# style direct-mmap loading, all lib/*/*.so entries STORED). Plain `zip
# <file>` without -u/-f replaces an already-present entry unconditionally
# (no mtime comparison), which is what we want for lib/<abi>/libapp.so.
( cd "$EXTRACT_DIR" && zip -X -q -0 "$UNSIGNED_APK" "${REPACK_FILES[@]}" )

"$ZIPALIGN" -v -p 4 "$UNSIGNED_APK" "$ALIGNED_APK" >/dev/null

# ---------------------------------------------------------------------------
# 8. Sign + verify
# ---------------------------------------------------------------------------
echo "== [8/8] sign + verify =="
SIGNED_APK="$OUT_DIR/app-release-packed.apk"
rm -f "$SIGNED_APK"

if [[ -z "$KEYSTORE" ]]; then
  echo "FATAL: no keystore available to sign the APK (Android requires a valid signature to install)." >&2
  echo "       --dev-key-hex only replaces snapshot-encryption key derivation; pass --keystore/--key-alias/--keystore-pass-env alongside it for a signed dev build." >&2
  exit 1
fi

"$APKSIGNER" sign \
  --ks "$KEYSTORE" \
  --ks-key-alias "$KEY_ALIAS" \
  --ks-pass "env:$KEYSTORE_PASS_ENV" \
  --key-pass "env:$KEY_PASS_ENV" \
  --out "$SIGNED_APK" \
  "$ALIGNED_APK"

"$APKSIGNER" verify --print-certs "$SIGNED_APK"
"$ZIPALIGN" -c -p 4 "$SIGNED_APK"

echo
echo "== done: $SIGNED_APK =="
echo "   debug symbols (for 'flutter symbolize'): $DEBUG_INFO_DIR"
