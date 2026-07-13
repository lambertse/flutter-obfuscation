package io.flutter.embedding.engine.loader;

import android.content.Context;

/**
 * COMPILE-TIME-ONLY STUB. Never included in the final injected dex --
 * see packer/apk-inject/build.sh. The real io.flutter.embedding.engine.
 * loader.FlutterLoader class is already present in the target APK's own
 * classes.dex (it's a stock Flutter engine class, part of every Flutter
 * app), and that real class is what actually runs at runtime. This stub
 * exists purely so `javac` has something to resolve
 * `new FlutterLoader().startInitialization(this)` against when compiling
 * GuardApplication.java in isolation, without needing Flutter's actual
 * (large, version-specific) embedding jar on hand.
 *
 * If this method signature ever changes upstream in a way that breaks
 * binary compatibility, GuardApplication.java's call site needs updating
 * to match -- this stub existing does NOT mean the two are guaranteed to
 * stay in sync automatically.
 */
public class FlutterLoader {
    public void startInitialization(Context context) {}
}
