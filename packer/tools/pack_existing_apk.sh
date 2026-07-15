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
ENCRYPT_ONLY="0"
INJECT_MODE="application"   # application | dt-needed
MECHANISM_TEST="0"
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
  --inject-mode <mode>          How the decrypt hook is loaded (default: application):
                                  application = patch <application android:name> to
                                    GuardApplication + inject a dex. Simplest, but
                                    REPLACES any existing custom Application class, so
                                    it breaks apps that have one (see --force-...).
                                  dt-needed = no Java at all: add libguard.so as a
                                    DT_NEEDED of libflutter.so and bake the AES key
                                    into libguard.so. Touches no Application/manifest/
                                    dex, so it coexists with a custom Application (and
                                    RASP bootstrapped from it). Needs python 'lief'.
  --mechanism-test              (dt-needed only) DIAGNOSTIC. Inject the hook but do
                                NOT encrypt libapp.so (empty region table). Proves the
                                DT_NEEDED load + hook fire on-device with the
                                decryption variable removed -- the recommended FIRST
                                device cycle. Expected: app runs normally and libguard
                                logs "intercepted dlopen('libapp.so'), decrypting 0
                                region(s)".
  --encrypt-only                DIAGNOSTIC. Encrypt libapp.so + re-sign ONLY;
                                skip ALL injection (no manifest patch, no
                                dex, no libguard.so). The result has NO
                                decrypt hook, so it WILL crash once Flutter
                                runs -- the point is to observe WHERE: an
                                early crash in the app's own startup/RASP
                                means the app guards libapp.so's bytes (packing
                                is impossible for it); reaching Flutter and
                                only then crashing (SIGSEGV in libflutter.so
                                at performNativeAttach) means it does NOT, so a
                                real (non-destructive) injection is worth
                                building. See packer/README.md limitation #10.
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
    --encrypt-only) ENCRYPT_ONLY="1"; shift 1 ;;
    --inject-mode) INJECT_MODE="$2"; shift 2 ;;
    --mechanism-test) MECHANISM_TEST="1"; shift 1 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

# ---------------------------------------------------------------------------
# Resolve the mode into per-stage flags, so each numbered step below stays a
# simple guarded block instead of a nested matrix of if/elif. Four shapes:
#   application       : Java inject (overwrite Application + dex) + encrypt + libguard
#   dt-needed         : no Java; patch libflutter DT_NEEDED + embed key + encrypt + libguard
#   dt-needed+mech    : no Java; patch libflutter + libguard, but DO NOT encrypt (empty table)
#   --encrypt-only    : encrypt libapp.so only, no hook of any kind (separate diagnostic)
# ---------------------------------------------------------------------------
case "$INJECT_MODE" in
  application|dt-needed) ;;
  *) echo "FATAL: --inject-mode must be 'application' or 'dt-needed', got '$INJECT_MODE'" >&2; exit 1 ;;
esac
if [[ "$MECHANISM_TEST" == "1" && "$INJECT_MODE" != "dt-needed" ]]; then
  echo "FATAL: --mechanism-test is only valid with --inject-mode dt-needed" >&2; exit 1
fi
if [[ "$ENCRYPT_ONLY" == "1" && "$INJECT_MODE" == "dt-needed" ]]; then
  echo "FATAL: --encrypt-only and --inject-mode dt-needed are mutually exclusive" >&2; exit 1
fi

STAGE_JAVA_INJECT=0     # step 3+4: overwrite <application> + inject dex
STAGE_ENCRYPT_LIBAPP=1  # step 6: actually encrypt libapp.so
STAGE_BUILD_LIBGUARD=1  # step 6: compile libguard.so and add it to the APK
STAGE_PATCH_LIBFLUTTER=0 # step 6b: add libguard.so as DT_NEEDED of libflutter.so
STAGE_EMBED_KEY=0       # encrypt_snapshot --embed-key (bake key into regions.h)
STAGE_EMPTY_REGIONS=0   # encrypt_snapshot --emit-empty-regions (mechanism test)

if [[ "$ENCRYPT_ONLY" == "1" ]]; then
  STAGE_BUILD_LIBGUARD=0
elif [[ "$INJECT_MODE" == "dt-needed" ]]; then
  STAGE_PATCH_LIBFLUTTER=1
  if [[ "$MECHANISM_TEST" == "1" ]]; then
    STAGE_ENCRYPT_LIBAPP=0
    STAGE_EMPTY_REGIONS=1
  else
    STAGE_EMBED_KEY=1
  fi
else # application
  STAGE_JAVA_INJECT=1
fi

[[ -n "$INPUT_APK" && -f "$INPUT_APK" ]] || { echo "FATAL: --input-apk not found" >&2; usage; }
# --android-jar is only needed to compile the injected dex, i.e. only in
# 'application' mode. dt-needed / encrypt-only never compile a dex.
if [[ "$STAGE_JAVA_INJECT" == "1" ]]; then
  [[ -n "$ANDROID_JAR" && -f "$ANDROID_JAR" ]] || { echo "FATAL: --android-jar not found (required for --inject-mode application)" >&2; usage; }
fi

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
require_tool zip "for repacking the APK"
require_tool unzip "for extracting the APK"

# Each requirement is gated on the stage that actually uses it, so a
# dt-needed or diagnostic run doesn't demand tools it never touches.
if [[ "$STAGE_BUILD_LIBGUARD" == "1" ]]; then
  require_tool cmake "for building libguard.so"
  : "${ANDROID_NDK_HOME:?FATAL: ANDROID_NDK_HOME must point at an installed Android NDK}"
  NDK_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake"
  [[ -f "$NDK_TOOLCHAIN_FILE" ]] || { echo "FATAL: $NDK_TOOLCHAIN_FILE not found -- check ANDROID_NDK_HOME" >&2; exit 1; }
fi
if [[ "$STAGE_JAVA_INJECT" == "1" ]]; then
  require_tool javac "JDK, for compiling packer/apk-inject"
  require_tool jar "JDK, for packer/apk-inject/build.sh"
fi
if [[ "$STAGE_PATCH_LIBFLUTTER" == "1" ]]; then
  python3 -c "import lief" 2>/dev/null || {
    echo "FATAL: python3 'lief' package not installed, required for --inject-mode dt-needed" >&2
    echo "       (pip install -r $SCRIPT_DIR/requirements.txt)" >&2
    exit 1
  }
fi

: "${ANDROID_BUILD_TOOLS:?FATAL: ANDROID_BUILD_TOOLS must point at an Android SDK build-tools dir (contains zipalign, apksigner, d8)}"
ZIPALIGN="$ANDROID_BUILD_TOOLS/zipalign"
APKSIGNER="$ANDROID_BUILD_TOOLS/apksigner"
D8="$ANDROID_BUILD_TOOLS/d8"
[[ -x "$ZIPALIGN" ]] || { echo "FATAL: zipalign not found at $ZIPALIGN" >&2; exit 1; }

# build-tools < 34 ships a zipalign that does not 4KB-page-align stored .so via
# -p: it aligns them to 4 instead of 4096, so step 7 fails with '(BAD - <n>)'
# on every lib and "Verification FAILED" (confirmed broken on 29.0.2). Page
# alignment is mandatory here -- the packed libapp.so/libguard.so must be
# directly mmap'able. Fail fast now rather than after the whole compile+encrypt
# pipeline. The build-tools dir is conventionally named by version.
BT_VER="$(basename "$ANDROID_BUILD_TOOLS")"
BT_MAJOR="${BT_VER%%.*}"
if [[ "$BT_MAJOR" =~ ^[0-9]+$ ]] && (( BT_MAJOR < 34 )); then
  echo "FATAL: build-tools $BT_VER is too old -- its zipalign does not 4KB-page-align" >&2
  echo "       stored .so via -p, which this packer requires. Point ANDROID_BUILD_TOOLS" >&2
  echo "       at build-tools >= 34 (e.g. \$ANDROID_HOME/build-tools/35.0.0)." >&2
  exit 1
fi
[[ -x "$APKSIGNER" ]] || { echo "FATAL: apksigner not found at $APKSIGNER" >&2; exit 1; }
[[ "$STAGE_JAVA_INJECT" != "1" ]] || [[ -x "$D8" ]] || { echo "FATAL: d8 not found at $D8" >&2; exit 1; }

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
if [[ "$STAGE_JAVA_INJECT" != "1" ]]; then
  echo "== [3/8] checking existing Application class == (skipped: this mode touches no Java/manifest)"
else
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
fi

# ---------------------------------------------------------------------------
# 4. Patch the manifest + inject the compiled GuardApplication/GuardBridge dex
# ---------------------------------------------------------------------------
if [[ "$STAGE_JAVA_INJECT" != "1" ]]; then
  echo "== [4/8] patching manifest + injecting guard dex == (skipped: $([[ "$INJECT_MODE" == "dt-needed" ]] && echo "dt-needed uses no Java" || echo "--encrypt-only"))"
else
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
fi

# ---------------------------------------------------------------------------
# 5. Key material (same as build_and_pack.sh)
# ---------------------------------------------------------------------------
echo "== [5/8] key material =="
REGIONS_H="$WORK_DIR/regions.h"
ENCRYPT_ARGS=(--libs-dir "$EXTRACT_DIR/lib" --abis "$ABIS" --output-regions-h "$REGIONS_H")
if [[ "$STAGE_EMPTY_REGIONS" == "1" ]]; then
  # Mechanism test: no encryption and no key needed at all.
  ENCRYPT_ARGS+=(--emit-empty-regions)
  echo "  --mechanism-test: empty region table, no key, libapp.so left untouched"
elif [[ "$STAGE_EMBED_KEY" == "1" ]]; then
  # dt-needed: bake the key into libguard.so (no runtime GuardBridge to
  # derive it). Deriving from the cert would add nothing here -- the cert is
  # public in the APK anyway -- so a fresh random key is fine and simplest.
  if [[ -n "$DEV_KEY_HEX" ]]; then
    EMBED_HEX="$DEV_KEY_HEX"
  else
    EMBED_HEX="$(python3 -c 'import os;print(os.urandom(32).hex())')"
  fi
  ENCRYPT_ARGS+=(--key-hex "$EMBED_HEX" --embed-key)
  echo "  dt-needed: AES key generated + embedded into libguard.so (no runtime cert derivation)"
elif [[ -n "$DEV_KEY_HEX" ]]; then
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
# encrypt_snapshot.py always runs: it generates regions.h (and, unless
# --emit-empty-regions, encrypts each libapp.so in place).
python3 "$SCRIPT_DIR/encrypt_snapshot.py" "${ENCRYPT_ARGS[@]}"

if [[ "$STAGE_BUILD_LIBGUARD" != "1" ]]; then
  # --encrypt-only: libapp.so is encrypted but there is NO decrypt hook, on
  # purpose. The only file changed in the APK is libapp.so.
  echo "  (skipped: libguard.so build -- --encrypt-only produces a hook-less, intentionally-broken APK)"
else
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
fi

# ---------------------------------------------------------------------------
# 6b. dt-needed injection: make each libflutter.so depend on libguard.so, so
#     loading the engine auto-loads + runs our constructor (no Java needed).
# ---------------------------------------------------------------------------
if [[ "$STAGE_PATCH_LIBFLUTTER" == "1" ]]; then
  echo "== [6b] patching libflutter.so DT_NEEDED -> libguard.so =="
  for abi in "${ABI_ARRAY[@]}"; do
    python3 "$SCRIPT_DIR/patch_libflutter_needed.py" \
      --input "$EXTRACT_DIR/lib/$abi/libflutter.so"
  done
fi

# ---------------------------------------------------------------------------
# 7. Repack + zipalign (same in-place-update discipline as build_and_pack.sh)
# ---------------------------------------------------------------------------
echo "== [7/8] repack + zipalign =="
UNSIGNED_APK="$OUT_DIR/app-packed-unsigned.apk"
ALIGNED_APK="$OUT_DIR/app-packed-aligned.apk"
rm -f "$UNSIGNED_APK" "$ALIGNED_APK"

cp "$INPUT_APK" "$UNSIGNED_APK"

# Re-add only the entries this mode actually changed. Native libs go in
# STORED (-0) so zipalign can page-align them for direct mmap; the manifest
# is DEFLATE (it grew, but plain `zip` handles a variable-size compressed
# replacement fine).
REPACK_STORED=()
for abi in "${ABI_ARRAY[@]}"; do
  [[ "$STAGE_ENCRYPT_LIBAPP"    == "1" ]] && REPACK_STORED+=("lib/$abi/libapp.so")
  [[ "$STAGE_PATCH_LIBFLUTTER"  == "1" ]] && REPACK_STORED+=("lib/$abi/libflutter.so")
  [[ "$STAGE_BUILD_LIBGUARD"    == "1" ]] && REPACK_STORED+=("lib/$abi/libguard.so")
done

if [[ "$STAGE_JAVA_INJECT" == "1" ]]; then
  ( cd "$EXTRACT_DIR" && zip -X -q "$UNSIGNED_APK" AndroidManifest.xml )
  ( cd "$EXTRACT_DIR" && zip -X -q "$UNSIGNED_APK" "classes${DEX_N}.dex" )
fi

( cd "$EXTRACT_DIR" && zip -X -q -0 "$UNSIGNED_APK" "${REPACK_STORED[@]}" )

# NOTE: zipalign writes its per-entry report AND its errors to STDOUT, not
# stderr. Do NOT redirect this to /dev/null -- doing so silently swallows a
# "Verification FAILED" and leaves a blank log after this step. Capture it and
# surface it on failure instead.
if ! "$ZIPALIGN" -f -v -p 4 "$UNSIGNED_APK" "$ALIGNED_APK" >"$WORK_DIR/zipalign.log" 2>&1; then
  echo "FATAL: zipalign failed. Its output:" >&2
  sed 's/^/  zipalign: /' "$WORK_DIR/zipalign.log" >&2
  echo "       If the failures are '(BAD - <n>)' on lib/*/*.so with <n> a multiple of 4" >&2
  echo "       (not 4096), your zipalign is not 4KB-page-aligning stored .so via -p." >&2
  echo "       This is an OLD build-tools zipalign (seen on 29.0.2); point" >&2
  echo "       ANDROID_BUILD_TOOLS at build-tools >= 34 and re-run." >&2
  exit 1
fi

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
if [[ "$INJECT_MODE" == "dt-needed" ]]; then
  echo "   Injection: dt-needed (libguard.so is a DT_NEEDED of libflutter.so;"
  echo "   no Application/manifest/dex touched). In logcat (tag 'libguard') expect:"
  echo "     guard_hook_got_symbol: hooked 'dlopen' in 'libflutter.so' ..."
fi
if [[ "$MECHANISM_TEST" == "1" ]]; then
  echo
  echo "   *** --mechanism-test DIAGNOSTIC build (dt-needed, encryption OFF) ***"
  echo "   libapp.so is NOT encrypted; the hook installs but decrypts nothing."
  echo "   Install, launch, and read the 'libguard'-tagged logcat lines -- there are"
  echo "   THREE distinct outcomes, and which libguard lines appear tells them apart:"
  echo "     (1) SUCCESS: you see, in order,"
  echo "           guard_hook_got_symbol: hooked 'dlopen' in 'libflutter.so'"
  echo "           dlopen_hook: embedded key installed (no-Java/DT_NEEDED path)"
  echo "           finish_handle: intercepted dlopen('libapp.so'), decrypting 0 region(s)"
  echo "         and the app runs normally => DT_NEEDED load + co-load hook timing +"
  echo "         the app tolerating the patched libflutter.so ALL work. Do the full"
  echo "         run (drop --mechanism-test)."
  echo "     (2) 'dlopen_hook: FATAL, could not hook dlopen in libflutter.so' then"
  echo "         'guard_ctor: FATAL, trigger dlopen_hook failed to install -- aborting'"
  echo "         + SIGABRT => libguard loaded but couldn't find libflutter mid-co-load."
  echo "         This is an approach-internal timing issue, NOT a RASP/pivot"
  echo "         signal. Send me this line."
  echo "     (3) NO libguard lines at all + an early crash => bionic rejected the"
  echo "         LIEF-patched libflutter.so, or libguard didn't resolve/extract. THIS"
  echo "         is the 'patched libflutter won't load / RASP guards it' bucket; the"
  echo "         pivot is a ContentProvider injection (leaves libflutter untouched)."
elif [[ "$STAGE_ENCRYPT_LIBAPP" == "1" && "$STAGE_BUILD_LIBGUARD" == "1" ]]; then
  echo "   Full packed build: install fresh (adb install -r) and confirm the app"
  echo "   launches and all major flows work. In logcat watch for:"
  echo "     'decrypt_exec_regions: replaced ... span'  => decrypt succeeded, or"
  echo "     'decrypt_exec_regions: ... failed (errno=...)' => fail-closed abort."
  echo "   NOTE: the anon-remap that defeats SELinux execmod was proven on a PHYSICAL"
  echo "   enforcing device (OnePlus 6T / Android 11). An emulator is often SELinux-"
  echo "   permissive and can MASK an execmod failure -- confirm the full build on a"
  echo "   real enforcing device, not only an emulator."
elif [[ "$ENCRYPT_ONLY" == "1" ]]; then
  echo
  echo "   *** --encrypt-only DIAGNOSTIC build ***"
  echo "   This APK has an encrypted libapp.so but NO decrypt hook -- it is"
  echo "   EXPECTED to crash. Install, launch, and read the crash in logcat:"
  echo "     - Crashes EARLY (app's own startup / a RASP/integrity check, before"
  echo "       any Flutter UI) => the app guards libapp.so's bytes; packing it is"
  echo "       not possible. Stop here."
  echo "     - Reaches Flutter and only THEN crashes (SIGSEGV in libflutter.so at"
  echo "       performNativeAttach, i.e. garbage instructions) => the app does NOT"
  echo "       guard libapp.so; a real non-destructive injection is worth building."
fi
