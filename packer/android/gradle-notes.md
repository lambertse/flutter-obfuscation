# Gradle / manifest integration notes

`libguard.so` is **not** built as part of the app's own Gradle
`externalNativeBuild` -- it's produced separately by
`tools/build_and_pack.sh` and injected into the already-built APK's
`lib/<abi>/` directories as a post-processing step (see Handover.md §4
architecture). Nothing needs to be added to `build.gradle`'s `android {
externalNativeBuild { ... } }` block for it.

What *does* need attention in the app's own project:

## 1. `AndroidManifest.xml`

Register `App.kt` (adjust the package/path first -- see the TODO at the top
of that file):

```xml
<application android:name=".App" ...>
```

## 2. Keep native libs uncompressed

`build_and_pack.sh` repacks `lib/*/*.so` as STORED (uncompressed) to match
zipalign's `-p 4` page-alignment requirement (Handover.md §9.5, §10). This
only works cleanly if the *original* Flutter/Gradle build already ships
native libs uncompressed -- confirmed true for the reference test APK
(`lib/*/*.so` entries are already STORED / `extractNativeLibs`-style direct
load). If your project's `build.gradle` explicitly sets:

```groovy
android {
    packagingOptions {
        jniLibs {
            useLegacyPackaging = true  // or: android:extractNativeLibs="true" in the manifest
        }
    }
}
```

...that forces compressed native libs and will fight with the repack step.
Leave native lib compression at its (modern AGP / Android 10+) default, or
explicitly set `useLegacyPackaging = false`.

## 3. Don't strip or otherwise post-process `libapp.so`/`libguard.so`

- `libapp.so`'s Dart snapshot symbols (`_kDart*`) must remain in the
  **dynamic** symbol table (`.dynsym`) -- that's what `dlsym()` resolves
  against at runtime and what `encrypt_snapshot.py`'s `readelf --dyn-syms`
  reads at build time. This is Flutter's own default output; don't run an
  extra `strip`/`objcopy --strip-all` pass over `libapp.so` after
  `flutter build`, and don't add one to `build_and_pack.sh`'s pipeline
  either.
- `libguard.so` is built with symbol visibility already minimized
  (`-fvisibility=hidden`, keeping only the one required `JNIEXPORT`
  function -- see `native/libguard/CMakeLists.txt`), so no additional
  Gradle-level stripping is needed or should be applied to it.

## 4. RASP / tamper-detection collision (Handover.md §9.6)

If the app ships its own root/tamper-detection natives, verify they don't
flag `libguard.so`'s GOT patch or `mprotect` calls as tampering. This needs
to be checked empirically on the device test matrix (Handover.md §10) --
nothing in this repo can verify that interaction without the app's actual
RASP implementation.
