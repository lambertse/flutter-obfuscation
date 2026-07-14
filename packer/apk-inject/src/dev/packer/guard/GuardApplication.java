package dev.packer.guard;

import android.app.Application;

/**
 * Java port of packer/android/App.kt, for the no-Flutter-source-available
 * path (see docs/GUIDE.md). This class is compiled standalone (see
 * packer/apk-inject/build.sh) and injected into the target APK as a
 * separate classesN.dex by tools/pack_existing_apk.sh, which also patches
 * the target's AndroidManifest.xml `<application android:name=...>` to
 * point here instead of whatever it originally declared.
 *
 * ORDERING: guard.c's constructor patches a GOT slot *inside
 * libflutter.so*, so libflutter.so must already be mapped into the process
 * before System.loadLibrary("guard") runs (that's inside
 * GuardBridge.install()) -- otherwise dl_iterate_phdr finds no such
 * module and guard_ctor() aborts (fail-closed by design).
 *
 * We load libflutter.so directly here (`System.loadLibrary("flutter")`)
 * rather than going through Flutter's own `FlutterLoader` Java class, for
 * a concrete reason found empirically, not theoretically: on at least one
 * real release build, R8 (Flutter's code shrinker) does NOT keep
 * `io.flutter.embedding.engine.loader.FlutterLoader` as a resolvable
 * class -- it's absent from classes.dex entirely (only its NAME survives,
 * inside unrelated log-message string literals), causing
 * `NoClassDefFoundError` the instant we tried to reference it. Loading the
 * native library directly needs nothing from Flutter's Java API surface at
 * all: our GOT hook operates purely at the native ELF level and doesn't
 * care which Java code (if any) later triggers dlopen("libapp.so") -- it
 * only needs libflutter.so mapped first, and `System.loadLibrary` is the
 * one-line way to guarantee that without depending on internal,
 * shrinker-unstable Flutter classes. This is strictly more robust across
 * Flutter/R8 versions than the FlutterLoader approach, not just a
 * workaround for one broken build.
 *
 * pack_existing_apk.sh only rewires `android:name` to point at this class
 * -- it does not know or care what the *original* Application class did.
 * If the target app had its own custom Application with real logic (not
 * just the Android default), that logic is NOT preserved by this
 * injection and needs to be merged in by hand; see docs/GUIDE.md's note on
 * detecting that case.
 */
public class GuardApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        System.loadLibrary("flutter");
        try {
            GuardBridge.install(this);
        } catch (Exception e) {
            // Rethrow unchecked: Application.onCreate() can't declare
            // checked exceptions, but this must still crash loudly and
            // immediately rather than silently continue with no key set.
            // See GuardBridge.install()'s doc comment for why that's the
            // right failure mode here.
            throw new RuntimeException("GuardApplication: GuardBridge.install() failed", e);
        }
    }
}
