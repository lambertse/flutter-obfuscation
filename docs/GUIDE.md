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

## How it works (the mechanism, in plain terms)

The whole tool rests on one interception point. Here is the entire idea,
start to finish.

### 1. The snapshot, and why we can hide it

A released Flutter app's compiled Dart code (the "AOT snapshot") lives in
`lib/<abi>/libapp.so`, in two executable regions named
`_kDartVmSnapshotInstructions` and `_kDartIsolateSnapshotInstructions`. At
build time we **AES-256-CTR encrypt exactly those two regions in place** —
same file, same size (CTR is a stream cipher, so no layout changes), just
ciphertext where the code used to be. Anyone who unzips the shipped APK and
runs `strings` or a Dart snapshot parser on `libapp.so` now sees noise.

The catch: the app still has to *run*. So the code has to become plaintext
again in memory, at exactly the right moment, without the Flutter engine
noticing. That is what the runtime half does.

### 2. What we hook — `dlopen`, via the GOT

The Flutter engine (`libflutter.so`) loads the Dart code by calling the
standard C function **`dlopen("libapp.so")`**, and only *afterwards* reads
the snapshot symbols out of the handle it gets back. That call is our
interception point:

> We replace `libflutter.so`'s `dlopen` with our own function. Ours calls
> the real `dlopen` (so `libapp.so` loads normally), then **decrypts the two
> instruction regions in memory**, then returns the handle. The engine reads
> the now-plaintext snapshot and runs, none the wiser.

"Replace its `dlopen`" means a **GOT hook**. Every native library has a
*Global Offset Table*: a table of function pointers the linker fills in with
the real addresses of the external functions that library calls (`dlopen`,
`malloc`, …). We don't rewrite any code — we just overwrite the single
pointer in `libflutter.so`'s GOT that says "`dlopen` lives here" so it
points at our function instead. Flipping one pointer is surgical and
reversible; rewriting instructions would not be. (Our hook only fires for
`libapp.so`; any other `dlopen` call is passed straight through untouched.)

The decrypt itself has one wrinkle worth knowing: on modern enforcing-SELinux
devices you may not take a *file-backed* page (like `libapp.so` mapped from
the APK), write to it, and mark it executable again — the "W^X" / `execmod`
rule. So the hook decrypts into a scratch buffer and swaps the page for a
fresh **anonymous** copy at the *same address* before running it. Same
address means every internal reference in the code still resolves; anonymous
memory isn't file-backed, so the `execmod` rule doesn't apply.

### 3. Getting our hook to run in time — the injection problem

Our hook lives in a small native library, **`libguard.so`**. For it to work,
two things must happen *before* the engine calls `dlopen("libapp.so")`:
`libguard.so` must be loaded (so its constructor installs the GOT hook), and
the AES key must be set. A `.so` doesn't load itself — something has to
trigger it. That "something" is the *only* reason the tool has to touch the
app at all, and there are two ways to do it (`--inject-mode`):

- **`application` (default).** Register a tiny `Application` subclass
  (`GuardApplication`) by rewriting `<application android:name>` in the
  manifest and injecting a dex. Its `onCreate` loads `libguard.so` and
  derives the key. Simple — but it **replaces** the app's own `Application`
  class, so it breaks any app that already has one.

- **`dt-needed`.** No Java, no manifest, no dex. Explained next.

### 4. What `DT_NEEDED` is, and why we add one

Every native library carries a list of *other* libraries it depends on. Each
entry in that list is a `DT_NEEDED` record inside the ELF file's "dynamic"
section — e.g. `libflutter.so` already declares `DT_NEEDED` on `libc.so`,
`liblog.so`, and so on. The rule the Android loader follows is the useful
part:

> When the loader loads a library, it first loads everything in that
> library's `DT_NEEDED` list **and runs their constructors**, before the
> depending library finishes loading.

So in `dt-needed` mode we **add one `DT_NEEDED` entry — `libguard.so` — to
the app's own `libflutter.so`** (with the tool [`patch_libflutter_needed.py`](../packer/tools/patch_libflutter_needed.py),
using LIEF). The consequence is exactly the timing we need, for free:

```
engine wants Dart  →  loader loads libflutter.so
                        →  sees DT_NEEDED libguard.so  →  loads it FIRST,
                           runs its constructor  →  GOT hook installed + key set
                        →  libflutter.so finishes loading
   ... later ...       →  engine calls dlopen("libapp.so")  →  our hook fires  →  decrypt
```

Because this touches **no** Java, manifest, or dex, it leaves the app's own
`Application` class — and anything it bootstraps, such as a RASP/anti-tamper
SDK — completely undisturbed. That's the whole reason it exists: it's the
injection method for apps you can't safely modify at the Java layer. The AES
key is baked into `libguard.so` at build time (there's no Java side to derive
it); since the signing cert it would otherwise derive from is public in the
APK anyway, that trade-off costs no real secrecy. The one cost is that we
modify `libflutter.so` itself (a single added dependency entry).

### 5. Scope — what the packer changes in your APK

| Mode | Modifies | Leaves untouched |
|---|---|---|
| both | `lib/<abi>/libapp.so` (2 regions encrypted), adds `lib/<abi>/libguard.so`, re-signs | your Dart logic, resources, assets |
| `application` | `AndroidManifest.xml` (`android:name`), adds a dex | `libflutter.so`, the app's other classes |
| `dt-needed` | `lib/<abi>/libflutter.so` (one `DT_NEEDED` entry) | the manifest, all dex, the app's `Application` class / RASP |

Out of scope entirely: defending the decrypted-in-memory window (a live
memory dump still works — see "What this is" above), and any app whose own
RASP verifies the *bytes* of `libapp.so` at runtime (it would reject the
encryption regardless of how cleanly we inject — see `packer/README.md`
limitation #10).

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
| Python 3.8+ | `encrypt_snapshot.py`, `axml_patch.py` | system package manager |
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
# export ANDROID_NDK_HOME=/Users/tri.le/Library/Android/sdk/ndk/28.2.13676358
export ANDROID_BUILD_TOOLS=/path/to/sdk/build-tools/<version>

# throwaway keystore for testing
keytool -genkeypair -v -keystore test.jks -storepass testpass -keypass testpass \
  -alias testkey -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Test,O=Test,C=US"

export KS_PASS=testpass
packer/tools/pack_existing_apk.sh \
  --input-apk assets/app-release.apk \
  --android-jar /Users/tri.le/Library/Android/sdk/platforms/android-29/android.jar \
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

## Path A-DT — apps with a custom Application class (`--inject-mode dt-needed`)

The default `application` mode replaces the app's own `Application` class,
which breaks any app that already declares one (including apps that
bootstrap a RASP SDK like V-Key V-OS from it). For those, the `dt-needed`
mode injects the hook with no Java at all — see ["How it works" §3–4](#4-what-dt_needed-is-and-why-we-add-one)
for what it does and why. Requires `pip install lief` (see
`requirements.txt`). Usage:

```bash
packer/tools/pack_existing_apk.sh \
  --input-apk your-app.apk \
  --keystore test.jks --key-alias testkey --keystore-pass-env KS_PASS \
  --abis arm64-v8a \
  --inject-mode dt-needed
```

**Run the mechanism test first.** Before a full encrypted build, prove the
injection works on your device with the *encryption turned off*:

```bash
#   ... same command ...  --inject-mode dt-needed --mechanism-test
adb install -r build/packed/app-packed.apk    # then launch it
adb logcat | grep -iE 'libguard|DEBUG'
```

- **App runs normally** and you see `finish_handle: intercepted
  dlopen('libapp.so'), decrypting 0 region(s)` → the `DT_NEEDED` load + GOT
  hook work *and* the app tolerates the patched `libflutter.so`. Now do a
  full run (drop `--mechanism-test`) — it encrypts `libapp.so` and embeds
  the key, and the app should launch decrypted.
- **App crashes at startup, before any Flutter UI** → either the patched
  `libflutter.so` doesn't load on this device or a RASP check rejects it.
  That's the one thing this injection can't sidestep (it's the only native
  lib besides `libapp.so` it modifies). Capture the `libguard`/`DEBUG`
  logcat lines; the fallback is a ContentProvider injection (doesn't touch
  `libflutter.so`), or `--inject-mode application` on a non-RASP app.

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

- The W^X/SELinux `execmod` fallback described in `Handover.md` §9.1 is now
  implemented: exec regions (`_kDartVmSnapshotInstructions`,
  `_kDartIsolateSnapshotInstructions`) decrypt into a scratch buffer, then
  the live file-backed mapping is swapped for anonymous memory at the same
  address before it's marked executable — this is what avoids the
  `execmod` denial (anonymous memory only needs `execmem`, which is always
  granted to `untrusted_app`). If you still see `mprotect`/`MAP_FIXED`
  failures at startup, that's a different, unexpected failure — capture the
  `libguard`-tagged `logcat` lines and the `avc: denied` line if present.
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
