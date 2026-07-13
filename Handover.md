# Handover: Runtime Packer for a Flutter (Android) Release App

**Audience:** Claude Code (implementation agent)
**Type:** Self-protection / app-hardening. This is a *packer* for our **own** app — encrypt the Dart AOT snapshot at rest, decrypt it in-process at runtime via a `dlopen` hook. Not an attack tool; do not add anything that targets other apps or bypasses third-party protections.

---

## 1. Goal

Ship our Flutter Android app so that `libapp.so` (the Dart AOT snapshot) is **encrypted on disk** and **decrypted in memory at runtime**, transparently, so the engine runs normally. This raises the cost of **static** analysis of the APK.

## 2. Threat model & explicit non-goals

**In scope (what this defeats):** a casual attacker who unzips the APK and runs `strings`/a decompiler/Dart snapshot parsers on `libapp.so` statically.

**Explicitly OUT of scope (do NOT claim these):**
- Protection against a running-process memory dump (Frida/ptrace). The plaintext snapshot exists in executable memory after decrypt; it is dumpable. This is inherent to all packers.
- A substitute for symbol obfuscation. See prerequisite below.

**Hard prerequisite — do this first, verify it in CI:** the app MUST be built with
`flutter build apk --release --obfuscate --split-debug-info=build/debug-info`.
Encrypting a non-obfuscated snapshot is near-worthless: a memory dump would reveal readable `package:` paths and class names. Obfuscation is what protects the logic *after* an unpack; the packer only hides it at rest. Fail the build if `--obfuscate` was not used (see §9 check).

## 3. Confirmed technical facts (from analysis of the current build)

Load path on Android (verified): the engine reads `aot-shared-library-name=libapp.so`, calls **`dlopen`** (imported by `libflutter.so` as an `R_AARCH64_JUMP_SLOT` GOT entry), then `dlsym`s these symbols:
`_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`, `_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions`.

The snapshot lives in these symbols inside `libapp.so`:

| Symbol | Segment | Executable? | Holds |
|---|---|---|---|
| `_kDartIsolateSnapshotInstructions` | `.text` | **Yes (R E)** | the compiled app code (largest region, ~5.4 MB in the sample) |
| `_kDartVmSnapshotInstructions` | `.text` | **Yes (R E)** | VM instructions |
| `_kDartIsolateSnapshotData` | `.rodata` | No (R) | object data incl. `package:` strings (~3.6 MB) |
| `_kDartVmSnapshotData` | `.rodata` | No (R) | VM data |
| `_kDartSnapshotBuildId` | — | No | version id — **DO NOT ENCRYPT** (engine version gate reads it) |

> **⚠️ Offsets/sizes are build- and ABI-specific.** The values seen in analysis (e.g. isolate instructions @ `0x396a40` size `0x52b850`) are **reference only**. DO NOT hardcode them. The build step (§6) MUST re-extract per ABI from the actual freshly-built `libapp.so`, and the runtime MUST resolve addresses via `dlsym` (§7). Headers, section table, and `_kDartSnapshotBuildId` must remain untouched so the engine's magic/version/features check still passes.

## 4. Architecture

```
BUILD:  flutter build --obfuscate  ->  per-ABI libapp.so
        encrypt_snapshot.py: for each ABI, parse readelf, AES-CTR encrypt the 4 regions in place,
                             emit regions manifest -> compiled into libguard.so
        repack APK, zipalign, re-sign

RUNTIME (in order):
  App.<clinit> loads libguard.so FIRST (before FlutterActivity)
    -> libguard constructor patches dlopen GOT slot in libflutter.so -> trampoline
  engine init thread calls dlopen("libapp.so")
    -> trampoline: real_dlopen(); if libapp.so, dlsym each _kDart* symbol,
       decrypt its region in place (mprotect RW -> AES-CTR -> mprotect R[X] -> clear_cache);
       return handle
  engine dlsym()s symbols -> now plaintext -> Dart_Initialize runs normally
```

Use **AES-CTR** (stream cipher): length-preserving, in-place, no padding, no ELF layout change.

## 5. Repository layout to create

```
packer/
  native/
    libguard/
      CMakeLists.txt
      src/
        guard.c            # constructor, orchestration, key derivation
        got_hook.c/.h      # find & patch dlopen JUMP_SLOT in libflutter.so
        trampoline.c/.h    # my_dlopen: real_dlopen + decrypt regions
        crypto.c/.h        # AES-CTR (use a vetted lib, e.g. mbedTLS/tiny-AES); no rolled crypto primitives
        regions.h          # GENERATED at build time: per-ABI region sizes + nonces (NOT addresses)
        anti_instr.c/.h    # optional: ptrace/Frida/debugger checks (stub ok in v1)
  tools/
    encrypt_snapshot.py    # post-build: parse readelf, encrypt regions, emit regions.h
    build_and_pack.sh      # orchestrates flutter build -> encrypt -> repack -> zipalign -> sign
  android/                 # integration notes: App.kt static loader, packagingOptions
  README.md                # how to run build_and_pack.sh, key setup, device test matrix
```

## 6. Build-time component: `encrypt_snapshot.py`

Responsibilities:
1. For each ABI dir in the built APK's `lib/*/`, run `readelf --dyn-syms libapp.so`, parse address+size for the 4 `_kDart*Snapshot(Data|Instructions)` symbols (NOT BuildId).
2. AES-CTR encrypt each region in place in the file. Unique deterministic nonce per (abi, region).
3. Emit `regions.h` containing, per region: an enum id, the **size**, the **nonce**, and the **symbol name string** (runtime resolves address by name via dlsym; sizes come from here). Do **not** emit absolute addresses.
4. Leave everything else byte-identical.

Key must come from the same derivation the runtime uses (§8) — the script and `libguard` must agree. For dev, allow a `--key-hex` override; for release, derive from the release signing cert fingerprint (see §8) passed in via env/CI.

## 7. Runtime components (`libguard.so`)

**`got_hook.c`** — install as `__attribute__((constructor))`, or from `JNI_OnLoad`:
- `dl_iterate_phdr` → find the module whose name contains `libflutter.so`.
- From its `PT_DYNAMIC`: locate `.rela.plt`, `.dynsym`, `.dynstr`.
- Iterate `R_AARCH64_JUMP_SLOT` relocs; resolve each symbol name; when name == `"dlopen"`:
  - `slot = base + rela->r_offset`
  - `mprotect(page(slot), PAGE, RW)`; save `real_dlopen = *slot`; `*slot = &my_dlopen`; `mprotect(page(slot), PAGE, R)`.
- Also handle `android_dlopen_ext` if present, for safety.

**`trampoline.c`** — `void* my_dlopen(const char* path, int flags)`:
- `void* h = real_dlopen(path, flags);`
- if `h && path` contains `"libapp.so"`: for each region in `regions.h`:
  - `void* addr = dlsym(h, region.symbol);` (skip if null)
  - `decrypt_region(addr, region.size, region.id, region.exec)`
- return `h`.

**`decrypt_region(addr, size, id, exec)`** — the critical sequence:
```
pg  = addr & ~(pagesize-1)
len = round_up(addr + size - pg, pagesize)
mprotect(pg, len, PROT_READ|PROT_WRITE)          // W^X caveat, see §9
aes_ctr_xcrypt(key, id, addr, size)              // decrypt in place
mprotect(pg, len, exec ? PROT_READ|PROT_EXEC : PROT_READ)
if (exec) __builtin___clear_cache(pg, pg+len)    // MANDATORY on ARM64 or random crashes
```

**Android integration** (`App.kt`):
```kotlin
class App : Application() {
    companion object { init { System.loadLibrary("guard") } }  // MUST run before FlutterActivity
}
```
Ensure ordering: `libguard` patches the GOT before the engine's init thread calls `dlopen`. If a race is observed, additionally gate engine start behind guard init. In `build.gradle`, keep `libapp.so`/`libguard.so` uncompressed & unstripped as needed; verify `packagingOptions` doesn't strip our symbols.

## 8. Key management

- **Do not** store a plaintext key array. Derive at runtime, e.g. `key = HKDF(sha256(release_signing_cert_der) || native_constant)`, reading the cert via `PackageManager`/JNI at startup and passing it to `libguard`.
- The same derivation must be reproducible at build time (CI passes the release cert fingerprint to `encrypt_snapshot.py`).
- Document clearly in README: the key is ultimately on-device; this is cost-raising, not unbreakable. Consider a split/white-boxed key later; out of scope for v1.

## 9. Caveats the implementation MUST handle

1. **W^X / SELinux `execmod`.** Flipping `.text` from RW→RX in place is blocked on some Android 10+ devices. Implement a **fallback**: if `mprotect(...RW)` or the later `...RX` fails on an exec region, copy the decrypted instructions into a fresh **anonymous** `PROT_READ|PROT_EXEC` mapping and switch the engine to **blob mode** (provide snapshot pointers via the embedder instead of the dlopen path). Detect at runtime; log which path was taken. Ship both; select per device.
2. **Instruction-cache coherency:** `__builtin___clear_cache` after every exec-region decrypt. Non-negotiable on ARM64.
3. **Page alignment** for every `mprotect`.
4. **Per-ABI correctness:** regions differ per ABI; `regions.h` is a table keyed by ABI, selected at runtime via the current lib path.
5. **Re-sign + zipalign** after repack; v2/v3 signature over the modified `libapp.so` is required or install fails.
6. **RASP self-collision:** the app already ships root/tamper-detection natives. Verify our GOT patch + memory-permission changes don't trip them; whitelist/ordering as needed.
7. **`--obfuscate` gate:** in `build_and_pack.sh`, assert obfuscation happened — e.g. `strings libapp.so | grep -c 'package:<our_pkg>'` should be ~0 **before** encryption. Fail the build otherwise.

## 10. Acceptance criteria

- [ ] `build_and_pack.sh` produces a signed, zipaligned APK from a clean checkout in one command.
- [ ] Encrypted APK: `strings lib/<abi>/libapp.so | grep package:` on the shipped file returns ~nothing (regions are ciphertext).
- [ ] App installs and launches on: stock arm64 device, armv7 device, x86_64 emulator.
- [ ] All major flows work (login, network, camera/scan) identically to the unpacked build.
- [ ] `logcat` shows **no** `execmod`/`avc: denied` for our process on the target matrix (or the anon-exec fallback is cleanly taken).
- [ ] Forced crash symbolizes via `flutter symbolize` using the preserved `--split-debug-info` symbols.
- [ ] Self-test: run a memory dump against our own build; confirm the recovered snapshot shows **obfuscated** symbols (proves the prerequisite is real), documenting that at-rest static analysis is blocked while in-memory is not.
- [ ] Re-signed APK passes `apksigner verify`; `zipalign -c -p 4` passes.

## 11. Known failure modes to test against

Invalid signature after repack; broken zipalign; wrong `extractNativeLibs`/compression on `libapp.so`; missing `__clear_cache` (nondeterministic crashes); GOT patch too late (engine dlopens before hook installed); decrypting `_kDartSnapshotBuildId` or a header by mistake (engine `Wrong ... snapshot version` / `No full snapshot version found`); ABI/region-table mismatch; RASP tripping on our own loader.

## 12. Deliverables

1. `libguard.so` sources + CMake, building for arm64-v8a, armeabi-v7a, x86_64.
2. `encrypt_snapshot.py` + generated `regions.h`.
3. `build_and_pack.sh` end-to-end pipeline with the `--obfuscate` gate.
4. `README.md`: setup, key derivation, device test matrix, and a plain-English statement of what this does and does **not** protect (per §2).
5. Optional v1 stub + v2 plan for `anti_instr.c` (Frida/ptrace/debugger detection) — the layer that actually defends the decrypted-in-memory window.

## 13. Open decisions (flag to me, don't guess)

- Encrypt **instructions only** (cheaper, protects code) vs **instructions + data** (also hides residual strings). Default: both; confirm.
- Hook via GOT patch (preferred) vs blob-mode-only (no hook, feed decrypted mappings through the embedder). If the Java `FlutterActivity` embedding makes blob mode awkward, GOT hook stays primary and blob mode is the W^X fallback only.
- Build vs buy: if maintenance cost of the loader across Flutter/Android upgrades is a concern, evaluate a commercial packer instead. Note in README.
