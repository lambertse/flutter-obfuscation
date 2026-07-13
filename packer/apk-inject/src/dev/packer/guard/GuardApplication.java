package dev.packer.guard;

import android.app.Application;
import io.flutter.embedding.engine.loader.FlutterLoader;

/**
 * Java port of packer/android/App.kt, for the no-Flutter-source-available
 * path (see docs/GUIDE.md). This class is compiled standalone (see
 * packer/apk-inject/build.sh) and injected into the target APK as a
 * separate classesN.dex by tools/inject_guard_application.py, which also
 * patches the target's AndroidManifest.xml `<application android:name=...>`
 * to point here instead of whatever it originally declared.
 *
 * ORDERING (same requirement as App.kt, see that file's class doc for the
 * full explanation): guard.c's constructor patches a GOT slot *inside
 * libflutter.so*, so libflutter.so must already be mapped before
 * System.loadLibrary("guard") runs (that's inside GuardBridge.install()).
 * FlutterLoader().startInitialization(this) loads libflutter.so
 * synchronously; it MUST run first. Both must complete in
 * Application.onCreate(), before any Activity (including FlutterActivity)
 * is created -- which is what guarantees the ordering holds relative to
 * the engine's own dlopen("libapp.so") call later.
 *
 * inject_guard_application.py only rewires `android:name` to point at this
 * class -- it does not know or care what the *original* Application class
 * did. If the target app had its own custom Application with real logic
 * (not just the Android default), that logic is NOT preserved by this
 * injection and needs to be merged in by hand; see docs/GUIDE.md's note on
 * detecting that case.
 */
public class GuardApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        new FlutterLoader().startInitialization(this);
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
