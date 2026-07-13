#!/usr/bin/env bash
#
# pack_existing_apk.sh -- the no-Flutter-source-available pipeline (see
# docs/GUIDE.md "Path A: no source, APK only"). Unlike build_and_pack.sh,
# this takes an ALREADY-BUILT APK as input and never invokes `flutter
# build` -- it can't, there's no project to build. Everything happens as
# binary patching of the compiled APK:
#
#   input .apk
#     -> extract
#     -> obfuscation check (best-effort only -- no source means no
#        pubspec.yaml Dart package name to target precisely, see step 2)
#     -> check <application android:name=...> is still the Android
#        default (refuse to overwrite a real custom Application class --
#        see step 3)
#     -> patch that attribute to point at our injected GuardApplication
#     -> compile + inject classesN.dex (packer/apk-inject)
#     -> encrypt_snapshot.py (unchanged from build_and_pack.sh)
#     -> build libguard.so per ABI (unchanged)
#     -> repack + zipalign + sign (same in-place-update discipline as
#        build_and_pack.sh -- see that script's step 7 comment)
#
# Every stage fails loudly rather than silently producing a broken or
# behavior-changed APK. Re-signing with your own key is unavoidable here
# (no source = no original signing key): the output APK's signature will
# NOT match the original app's, which breaks in-place Play Store updates
# and any self-signature/attestation check the app performs. That's
# inherent to repacking without source, not a bug in this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

INPUT_APK=""
OUT_DIR="$PACKER_DIR/../build/packed"
MIN_SDK="21"
ABIS="arm64-v8a,armeabi-v7a,x86_64"
DART_PACKAGE_NAME=""   # optional, sharpens the obfuscation heuristic
OBFUSCATE_GATE_MAX_MATCHES="${OBFUSCATE_GATE_MAX_MATCHES:-5}"
FORCE_APPLICATION_OVERWRITE="0"
KEYSTORE=""
KEY_ALIAS=""
KEYSTORE_PASS_ENV=""
KEY_PASS_ENV=""
DEV_KEY_HEX=""
ANDROID_JAR=""

usage() {
  cat <<EOF
Usage: $0 --input-apk <path> --android-jar <path> [options]

Required:
  --input-apk <path>           Already-built APK (no source needed/used)
  --android-jar <path>         Any recent platforms/android-<N>/android.jar
                                (for compiling packer/apk-inject)

Signing (required unless --dev-key-hex is given):
  --keystore <path>
  --key-alias <alias>
  --keystore-pass-env <VAR>
  --key-pass-env <VAR>         (defaults to --keystore-pass-env)

Dev/local:
  --dev-key-hex <64 hex chars> Snapshot key override; signing still needs
                                a keystore (see --keystore above)

Other:
  --out-dir <path>             (default: build/packed)
  --min-sdk <n>                (default: 21)
  --abis <csv>                 (default: arm64-v8a,armeabi-v7a,x86_64)
  --dart-package-name <name>   Sharpens the obfuscation heuristic (checks
                                for "package:<name>/" instead of a generic
                                pattern). Optional -- without source there's
                                no pubspec.yaml to read this from automatically.
  --force-application-overwrite
                                Proceed even if <application android:name=...>
                                is NOT the Android default -- i.e. the app has
                                a real custom Application class. Its logic
                                will be REPLACED by GuardApplication, not
                                merged. Only pass this if you've confirmed
                                that's acceptable (see docs/GUIDE.md).
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-apk) INPUT_APK="$2"; shift 2 ;;
    --android-jar) ANDROID_JAR="$2"; shift 2 ;;
    --keystore) KEYSTORE="$2"; shift 2 ;;
    --key-alias) KEY_ALIAS="$2"; shift 2 ;;
    --keystore-pass-env) KEYSTORE_PASS_ENV="$2"; shift 2 ;;
    --key-pass-env) KEY_PASS_ENV="$2"; shift 2 ;;
    --dev-key-hex) DEV_KEY_HEX="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --min-sdk) MIN_SDK="$2"; shift 2 ;;
    --abis) ABIS="$2"; shift 2 ;;
    --dart-package-name) DART_PACKAGE_NAME="$2"; shift 2 ;;
    --force-application-overwrite) FORCE_APPLICATION_OVERWRITE="1"; shift 1 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

[[ -n "$INPUT_APK" && -f "$INPUT_APK" ]] || { echo "FATAL: --input-apk not found" >&2; usage; }
[[ -n "$ANDROID_JAR" && -f "$ANDROID_JAR" ]] || { echo "FATAL: --android-jar not found" >&2; usage; }

if [[ -z "$DEV_KEY_HEX" && -z "$KEYSTORE" ]]; then
  echo "FATAL: --keystore --key-alias --keystore-pass-env is required (or use --dev-key-hex for the snapshot key -- signing still needs a keystore)" >&2
  exit 1
fi
if [[ -n "$KEYSTORE" ]]; then
  [[ -n "$KEY_ALIAS" && -n "$KEYSTORE_PASS_ENV" ]] || { echo "FATAL: --keystore requires --key-alias and --keystore-pass-env" >&2; exit 1; }
  KEY_PASS_ENV="${KEY_PASS_ENV:-$KEYSTORE_PASS_ENV}"
  [[ -n "${!KEYSTORE_PASS_ENV:-}" ]] || { echo "FATAL: env var \$$KEYSTORE_PASS_ENV is not set" >&2; exit 1; }
  [[ -n "${!KEY_PASS_ENV:-}" ]] || { echo "FATAL: env var \$$KEY_PASS_ENV is not set" >&2; exit 1; }
fi

require_tool() {
  command -v "$1" >/dev/null 2>&1 || { echo "FATAL: required tool '$1' not found on PATH ($2)" >&2; exit 1; }
}
require_tool python3 "for encrypt_snapshot.py / axml_patch.py"
require_tool cmake "for building libguard.so"
require_tool zip "for repacking the APK"
require_tool unzip "for extracting the APK"
require_tool javac "JDK, for compiling packer/apk-inject"
require_tool jar "JDK, for packer/apk-inject/build.sh"

: "${ANDROID_NDK_HOME:?FATAL: ANDROID_NDK_HOME must point at an installed Android NDK}"
NDK_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake"
[[ -f "$NDK_TOOLCHAIN_FILE" ]] || { echo "FATAL: $NDK_TOOLCHAIN_FILE not found -- check ANDROID_NDK_HOME" >&2; exit 1; }

: "${ANDROID_BUILD_TOOLS:?FATAL: ANDROID_BUILD_TOOLS must point at an Android SDK build-tools dir (contains zipalign, apksigner, d8)}"
ZIPALIGN="$ANDROID_BUILD_TOOLS/zipalign"
APKSIGNER="$ANDROID_BUILD_TOOLS/apksigner"
D8="$ANDROID_BUILD_TOOLS/d8"
[[ -x "$ZIPALIGN" ]] || { echo "FATAL: zipalign not found at $ZIPALIGN" >&2; exit 1; }
[[ -x "$APKSIGNER" ]] || { echo "FATAL: apksigner not found at $APKSIGNER" >&2; exit 1; }
[[ -x "$D8" ]] || { echo "FATAL: d8 not found at $D8" >&2; exit 1; }

python3 -c "import cryptography" 2>/dev/null || {
  echo "FATAL: python3 'cryptography' package not installed (pip install -r $SCRIPT_DIR/requirements.txt)" >&2
  exit 1
}

mkdir -p "$OUT_DIR"
WORK_DIR="$(mktemp -d "${OUT_DIR}/work.XXXXXX")"
trap 'echo "(leaving work dir for inspection: $WORK_DIR)"' EXIT

IFS=',' read -r -a ABI_ARRAY <<< "$ABIS"

# ---------------------------------------------------------------------------
# 1. Extract
# ---------------------------------------------------------------------------
echo "== [1/8] extracting APK =="
EXTRACT_DIR="$WORK_DIR/apk"
mkdir -p "$EXTRACT_DIR"
unzip -q "$INPUT_APK" -d "$EXTRACT_DIR"

for abi in "${ABI_ARRAY[@]}"; do
  [[ -f "$EXTRACT_DIR/lib/$abi/libapp.so" ]] || { echo "FATAL: lib/$abi/libapp.so missing -- ABI not present in this APK?" >&2; exit 1; }
  [[ -f "$EXTRACT_DIR/lib/$abi/libflutter.so" ]] || { echo "FATAL: lib/$abi/libflutter.so missing -- is this actually a Flutter APK?" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# 2. Obfuscation heuristic (best-effort -- see header comment: no source
#    means no pubspec.yaml to read the Dart package name from automatically)
# ---------------------------------------------------------------------------
echo "== [2/8] obfuscation check (best-effort, no source available) =="
for abi in "${ABI_ARRAY[@]}"; do
  libapp="$EXTRACT_DIR/lib/$abi/libapp.so"
  if [[ -n "$DART_PACKAGE_NAME" ]]; then
    pattern="package:${DART_PACKAGE_NAME}/"
  else
    pattern="package:"
  fi
  matches="$(grep -a -o "$pattern" "$libapp" | wc -l | tr -d '[:space:]')"
  echo "  [$abi] '$pattern' occurrences in libapp.so: $matches"
  if [[ -z "$DART_PACKAGE_NAME" ]]; then
    echo "  (no --dart-package-name given: this counts ALL package: strings, including"
    echo "   the Flutter framework's own, which are numerous even in obfuscated builds --"
    echo "   treat this as informational, not a pass/fail gate. Pass --dart-package-name"
    echo "   if you know it, for a real gate.)"
  elif (( matches > OBFUSCATE_GATE_MAX_MATCHES )); then
    echo "FATAL: [$abi] libapp.so does not look obfuscated ($matches occurrences of the app's own package URI)." >&2
    echo "       Encrypting a non-obfuscated snapshot is near-worthless -- see Handover.md §2." >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# 3. Check <application android:name=...> before touching it
# ---------------------------------------------------------------------------
echo "== [3/8] checking existing Application class =="
MANIFEST="$EXTRACT_DIR/AndroidManifest.xml"
CURRENT_APP_NAME="$(python3 "$SCRIPT_DIR/axml_patch.py" --input "$MANIFEST" --element application --attr name --read)"
echo "  current android:name = $CURRENT_APP_NAME"

if [[ "$CURRENT_APP_NAME" != "android.app.Application" && "$CURRENT_APP_NAME" != "ABSENT" ]]; then
  if [[ "$FORCE_APPLICATION_OVERWRITE" != "1" ]]; then
    echo "FATAL: this app already declares a custom Application class ($CURRENT_APP_NAME)." >&2
    echo "       Overwriting it with GuardApplication would silently DISCARD whatever that" >&2
    echo "       class does -- this tool only injects a hook, it does not merge logic into" >&2
    echo "       an existing class. Re-run with --force-application-overwrite only if" >&2
    echo "       you've confirmed losing that class's behavior is acceptable, or extend" >&2
    echo "       axml_patch.py's approach to patch the *existing* class's smali instead" >&2
    echo "       (see docs/GUIDE.md and packer/README.md for the tradeoffs)." >&2
    exit 1
  fi
  echo "  WARNING: --force-application-overwrite set, proceeding anyway. $CURRENT_APP_NAME's logic will be lost." >&2
fi

# ---------------------------------------------------------------------------
# 4. Patch the manifest + inject the compiled GuardApplication/GuardBridge dex
# ---------------------------------------------------------------------------
echo "== [4/8] patching manifest + injecting guard dex =="
PATCHED_MANIFEST="$WORK_DIR/AndroidManifest.xml"
python3 "$SCRIPT_DIR/axml_patch.py" \
  --input "$MANIFEST" --output "$PATCHED_MANIFEST" \
  --element application --attr name --value "dev.packer.guard.GuardApplication"
cp "$PATCHED_MANIFEST" "$EXTRACT_DIR/AndroidManifest.xml"

# classesN.dex: use the next free multidex slot rather than assuming
# classes2.dex is free (some apps already ship multidex).
DEX_N=2
while [[ -f "$EXTRACT_DIR/classes${DEX_N}.dex" ]]; do DEX_N=$((DEX_N + 1)); done
GUARD_DEX="$EXTRACT_DIR/classes${DEX_N}.dex"
"$PACKER_DIR/apk-inject/build.sh" --android-jar "$ANDROID_JAR" --d8 "$D8" --out "$GUARD_DEX"
echo "  injected as classes${DEX_N}.dex"

# ---------------------------------------------------------------------------
# 5. Key material (same as build_and_pack.sh)
# ---------------------------------------------------------------------------
echo "== [5/8] key material =="
REGIONS_H="$WORK_DIR/regions.h"
ENCRYPT_ARGS=(--libs-dir "$EXTRACT_DIR/lib" --abis "$ABIS" --output-regions-h "$REGIONS_H")
if [[ -n "$DEV_KEY_HEX" ]]; then
  echo "  WARNING: using --dev-key-hex, NOT deriving from a release cert. Do not ship this build." >&2
  ENCRYPT_ARGS+=(--key-hex "$DEV_KEY_HEX")
else
  CERT_DER="$WORK_DIR/release_cert.der"
  keytool -exportcert -alias "$KEY_ALIAS" -keystore "$KEYSTORE" \
    -storepass "${!KEYSTORE_PASS_ENV}" -file "$CERT_DER" >/dev/null
  ENCRYPT_ARGS+=(--cert-der "$CERT_DER")
fi

# ---------------------------------------------------------------------------
# 6. Encrypt + build libguard.so (same as build_and_pack.sh)
# ---------------------------------------------------------------------------
echo "== [6/8] encrypt_snapshot.py + libguard.so =="
python3 "$SCRIPT_DIR/encrypt_snapshot.py" "${ENCRYPT_ARGS[@]}"
cp "$REGIONS_H" "$PACKER_DIR/native/libguard/src/regions.h"

for abi in "${ABI_ARRAY[@]}"; do
  echo "  -- $abi --"
  BUILD_DIR="$WORK_DIR/cmake-build-$abi"
  cmake -S "$PACKER_DIR/native/libguard" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK_TOOLCHAIN_FILE" \
    -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$MIN_SDK" -DCMAKE_BUILD_TYPE=Release
  cmake --build "$BUILD_DIR" --config Release
  SO_OUT="$BUILD_DIR/libguard.so"
  [[ -f "$SO_OUT" ]] || { echo "FATAL: expected $SO_OUT after build" >&2; exit 1; }
  cp "$SO_OUT" "$EXTRACT_DIR/lib/$abi/libguard.so"
done

# ---------------------------------------------------------------------------
# 7. Repack + zipalign (same in-place-update discipline as build_and_pack.sh)
# ---------------------------------------------------------------------------
echo "== [7/8] repack + zipalign =="
UNSIGNED_APK="$OUT_DIR/app-packed-unsigned.apk"
ALIGNED_APK="$OUT_DIR/app-packed-aligned.apk"
rm -f "$UNSIGNED_APK" "$ALIGNED_APK"

cp "$INPUT_APK" "$UNSIGNED_APK"

# AndroidManifest.xml changed SIZE (it grew -- new string added to the pool)
# and is normally DEFLATE-compressed, unlike libapp.so/libguard.so which
# are same-size/STORED. Plain `zip` handles a variable-size compressed
# replacement the same way it handles anything else; no special-casing
# needed here, unlike the hand-rolled Node validation harness used to
# develop this against a sandbox with no `zip` binary (see
# packer/README.md's "What has actually been run" for that distinction).
( cd "$EXTRACT_DIR" && zip -X -q "$UNSIGNED_APK" AndroidManifest.xml )
( cd "$EXTRACT_DIR" && zip -X -q "$UNSIGNED_APK" "classes${DEX_N}.dex" )

REPACK_FILES=()
for abi in "${ABI_ARRAY[@]}"; do
  REPACK_FILES+=("lib/$abi/libapp.so" "lib/$abi/libguard.so")
done
( cd "$EXTRACT_DIR" && zip -X -q -0 "$UNSIGNED_APK" "${REPACK_FILES[@]}" )

"$ZIPALIGN" -v -p 4 "$UNSIGNED_APK" "$ALIGNED_APK" >/dev/null

# ---------------------------------------------------------------------------
# 8. Sign + verify
# ---------------------------------------------------------------------------
echo "== [8/8] sign + verify =="
SIGNED_APK="$OUT_DIR/app-packed.apk"
rm -f "$SIGNED_APK"

"$APKSIGNER" sign \
  --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
  --ks-pass "env:$KEYSTORE_PASS_ENV" --key-pass "env:$KEY_PASS_ENV" \
  --out "$SIGNED_APK" "$ALIGNED_APK"

"$APKSIGNER" verify --print-certs "$SIGNED_APK"
"$ZIPALIGN" -c -p 4 "$SIGNED_APK"

echo
echo "== done: $SIGNED_APK =="
echo "   NOTE: signature does not match the original app (no source = no original key)."
echo "   This breaks in-place Play Store updates; install fresh (adb install -r) for testing."
