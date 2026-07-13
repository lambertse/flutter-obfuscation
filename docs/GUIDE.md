# Flutter Android AOT-Snapshot Packer — Guide

Practical "how do I actually use this" walkthrough. For the full design
rationale, threat model, and acceptance criteria, see [`Handover.md`](../Handover.md)
(the original spec) and [`packer/README.md`](../packer/README.md) (what was
built against it, including what's verified vs. still open). This doc is
the shorter, task-oriented version: what to install, what to run, in what
order.

## What this is

A build-time + runtime pair that encrypts `libapp.so`'s Dart AOT snapshot
at rest inside the APK, and decrypts it transparently in memory when the
app starts. Two halves:

- **Build-time** (`packer/tools/`): after a normal Flutter release build,
  `encrypt_snapshot.py` finds the compiled Dart code inside `libapp.so` and
  AES-256-CTR encrypts it in place. `build_and_pack.sh` orchestrates the
  full pipeline (build → encrypt → compile the runtime piece → repack →
  sign).
- **Runtime** (`packer/native/libguard/`, `packer/android/`): `libguard.so`
  is a small native library that hooks `dlopen` inside `libflutter.so`. The
  first time the Flutter engine opens `libapp.so`, the hook decrypts the
  code back to plaintext in memory before handing control back to the
  engine — the app never sees ciphertext at runtime.

**What it defends against:** someone unzipping the APK and running
`strings`/a decompiler on `libapp.so` directly. **What it does NOT
defend against:** a runtime memory dump (Frida/ptrace) — the snapshot is
plaintext in memory the whole time the app runs. That's a documented,
inherent limitation of this class of tool, not a bug. See
`packer/README.md`'s "What this does and does NOT protect" section.

**On obfuscation:** `--obfuscate` is required for real protection (without
it, a memory dump trivially recovers full class/method names, making the
encryption pointless against anyone past the laziest attacker) — but it is
**not** a functional dependency of the encrypt/decrypt mechanism itself.
You can and should test the mechanism first without it (Path A below), and
only add `--obfuscate` when you move toward a real release build (Path B).

## Which path applies to you

- **You only have a built `.apk`, no Flutter/Android project source.**
  Use **Path A**. This is the common case and the one that's been fully
  validated end to end (see `packer/README.md`). Nothing here touches or
  needs your app's source — every step is binary patching of the compiled
  APK.
- **You have the Flutter project source and control its Gradle build.**
  Path B is a simpler alternative in that case (ordinary source
  integration instead of bytecode injection) — see below.

If you're not sure which applies: if you can run `flutter build apk` on
this app yourself, you have source; if you only ever received a `.apk`
file, you don't.

## Prerequisites

Install once, on a machine with real dev tooling (not applicable to CI
containers stripped down to just a runtime):

| Tool | Used for | Typical source |
|---|---|---|
| Android NDK | compiling `libguard.so` | Android Studio SDK Manager, or standalone |
| Android SDK build-tools | `zipalign`, `apksigner`, `d8` | Android Studio SDK Manager |
| JDK | `apksigner`, `keytool`, `d8`, compiling `packer/apk-inject` | bundled with Android Studio, or standalone |
| `android.jar` | compiling `packer/apk-inject` (Path A only) | any `platforms/android-<N>/android.jar` from an installed SDK |
| Python 3.10+ | `encrypt_snapshot.py`, `axml_patch.py` | system package manager |
| `readelf` | ELF parsing in `encrypt_snapshot.py` | `binutils` (Linux: usually preinstalled; macOS: `brew install binutils`) |
| `zip`, `unzip`, `keytool`, `adb` | packaging / device testing | usually already present with the above |
| Flutter SDK | Path B only (building the app from source) | flutter.dev |

```bash
pip install -r packer/tools/requirements.txt
```

## Path A — APK only, no source (the validated path)

`packer/tools/pack_existing_apk.sh` does this end to end in one command.
Two things to know before running it:

1. **The repacked APK will have a different signature than the original.**
   No source means no original signing key, so the output is re-signed
   with your own throwaway/test key (or a real one, your choice). This
   breaks in-place Play Store updates and any self-signature/attestation
   check the app performs — inherent to repacking without source, not a
   bug. Install with `adb install -r` for testing, don't expect it to
   update the original install.
2. **If the app already declares a real custom `Application` class**
   (i.e. `<application android:name="...">` is something other than the
   Android default), the script refuses to run unless you pass
   `--force-application-overwrite` — because injection *replaces* that
   class's entry point rather than merging into it, silently discarding
   whatever it did. Check first: the script prints the current value in
   step 3 and stops there if it's non-default.

```bash
export ANDROID_NDK_HOME=/path/to/sdk/ndk/<version>
export ANDROID_BUILD_TOOLS=/path/to/sdk/build-tools/<version>

# throwaway keystore for testing
keytool -genkeypair -v -keystore test.jks -storepass testpass -keypass testpass \
  -alias testkey -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Test,O=Test,C=US"

export KS_PASS=testpass
packer/tools/pack_existing_apk.sh \
  --input-apk /path/to/app-release.apk \
  --android-jar /path/to/sdk/platforms/android-34/android.jar \
  --keystore test.jks --key-alias testkey --keystore-pass-env KS_PASS \
  --dev-key-hex "$(openssl rand -hex 32)"
```

Output: `build/packed/app-packed.apk`, already `apksigner verify`'d and
`zipalign -c`'d.

**What this actually does**, for context (all validated, see
`packer/README.md`): compiles a small standalone Java module
(`packer/apk-inject/` — a `GuardApplication` + `GuardBridge` port of the
Kotlin classes, self-contained, no dependency on your app's code) into its
own `classesN.dex`; patches the compiled `AndroidManifest.xml`'s
`<application android:name=...>` to point at it
(`packer/tools/axml_patch.py` — a surgical single-attribute edit, not a
full decompile/rebuild, so `resources.arsc` and everything else stay
byte-identical to the original); encrypts `libapp.so` in place
(`encrypt_snapshot.py`, unchanged); compiles `libguard.so` per ABI
(unchanged); repacks, aligns, and signs.

### Install and confirm it decrypts at runtime

```bash
adb install -r build/packed/app-packed.apk
adb logcat -c
adb shell am start -n <the.original.package>/.MainActivity
adb logcat | grep -i libguard
```

Look for `guard_ctor` hooking `dlopen`, then `finish_handle` intercepting
`libapp.so` and `decrypt_region` succeeding for both instruction regions —
and the app launching normally instead of crashing with a "wrong snapshot
version" error (which is what you'd see if the hook never installed or the
key never got set).

Run this on: a stock arm64 device, an armv7 device, and an x86_64
emulator — the differences between ABIs (32- vs 64-bit ELF layout, symbol
offsets) are exactly the kind of thing that looks fine on one and breaks on
another. This is also the one thing that genuinely cannot be verified
without a device — everything up to this point (manifest patch, dex
injection, encryption, signing) has been structurally confirmed, but
whether the app actually *launches* is unproven until you run it.

## Path B — you have Flutter project source

If you can rebuild the app yourself, source integration is simpler than
bytecode injection: add the Kotlin classes to your project, let Gradle
compile them normally, and let `build_and_pack.sh` also drive the
`flutter build --obfuscate` step for you.

### B0. Wire the runtime bridge into your Flutter project

1. Copy `packer/android/GuardBridge.kt` into your project unchanged, at
   `android/app/src/main/kotlin/dev/packer/guard/GuardBridge.kt`.
2. Copy `packer/android/App.kt` into your project at
   `android/app/src/main/kotlin/<your/package/path>/App.kt`, and edit the
   `package` declaration at the top of the file to match your app's actual
   package.
3. In `android/app/src/main/AndroidManifest.xml`, add
   `android:name=".App"` to the `<application>` tag.

See `packer/android/gradle-notes.md` for packaging-options caveats
(keeping native libs uncompressed, not stripping `libapp.so`'s dynamic
symbols).

### B1. Run the full pipeline

```bash
export ANDROID_NDK_HOME=/path/to/sdk/ndk/<version>
export ANDROID_BUILD_TOOLS=/path/to/sdk/build-tools/<version>
export KS_PASS=...

packer/tools/build_and_pack.sh \
  --project-dir /path/to/your/flutter/app \
  --keystore /path/to/release.jks --key-alias upload \
  --keystore-pass-env KS_PASS
```

This always passes `--obfuscate` to `flutter build` and derives the AES key
from your release signing cert (via `keytool` + HKDF) rather than a
`--dev-key-hex` override. Output: `build/packed/app-release-packed.apk`,
already `apksigner verify`'d and `zipalign -c`'d. Install and verify at
runtime the same way as Path A above.

## Known limitations to keep in mind

- The W^X/SELinux `execmod` fallback described in `Handover.md` §9.1 is a
  **stub** — if in-place `mprotect` is blocked on a device, the app
  currently `abort()`s at startup rather than falling back. Watch `logcat`
  for `execmod`/`avc: denied` on your test matrix.
- `anti_instr.c` (anti-Frida/ptrace detection) is a v1 no-op. Encryption at
  rest is the only protection currently active; see "What this is" above.
- **Path A's manifest patch (`axml_patch.py`) only handles changing an
  attribute's *value*, not adding one that's entirely absent.** If
  `<application>` has no `android:name` attribute at all (rather than an
  explicit default), `pack_existing_apk.sh` will fail at the manifest-patch
  step rather than silently doing nothing. This is a real but narrower
  case than the "custom Application already present" one (which the script
  does handle, by refusing unless you pass
  `--force-application-overwrite`) — extending the patcher to insert a new
  attribute record is a bounded follow-up if you hit this.
- Full details, including what's been empirically verified vs. still open,
  are in `packer/README.md`'s "Known limitations (v1)" section — read it
  before shipping.

## Reference

- [`Handover.md`](../Handover.md) — original design spec, threat model,
  acceptance criteria.
- [`packer/README.md`](../packer/README.md) — implementation notes, repo
  layout, what's been verified, build-vs-buy tradeoffs.
- [`packer/android/gradle-notes.md`](../packer/android/gradle-notes.md) —
  manifest/packaging-options integration notes.
- [`packer/tools/axml_patch.py`](../packer/tools/axml_patch.py) — the
  binary manifest patcher (Path A); see its module docstring for the AXML
  format notes.
- [`packer/apk-inject/`](../packer/apk-inject/) — the standalone
  `GuardApplication`/`GuardBridge` Java module injected in Path A.
