package com.example.app // TODO: change to your app's actual package, and
                          // move this file into android/app/src/main/kotlin/...
                          // accordingly. Register it in AndroidManifest.xml:
                          //   <application android:name=".App" ...>

import android.app.Application
import dev.packer.guard.GuardBridge

/**
 * Integration point for the libguard.so packer (Handover.md §7). The
 * ordering below is required, not incidental:
 *
 *  1. System.loadLibrary("flutter") loads libflutter.so. `guard_ctor()`
 *     (native/libguard/src/guard.c) patches the dlopen GOT slot *inside
 *     libflutter.so*, via `dl_iterate_phdr` -- that module must already be
 *     mapped into the process or the hook install fails and libguard
 *     aborts (fail-closed by design, see GuardBridge.kt). A naive
 *     "reference GuardBridge from a companion `init` block so it runs at
 *     class-load time" does NOT satisfy this: libflutter.so is loaded
 *     lazily, later, by the engine's own init path -- there's nothing
 *     that pulls it in at Application class-load time on a plain
 *     Application. This explicit call is what actually guarantees it.
 *
 *     This loads the native library directly rather than going through
 *     Flutter's `FlutterLoader` Java class (an earlier version of this
 *     file did `FlutterLoader().startInitialization(this)`). Changed
 *     after finding, empirically, that a real release build's R8 pass
 *     does not always keep `io.flutter.embedding.engine.loader.
 *     FlutterLoader` as a resolvable class -- it can be absent from
 *     classes.dex entirely (only its name surviving inside unrelated
 *     log-message string literals), which crashes with
 *     `NoClassDefFoundError` the instant it's referenced. Loading the
 *     native library directly sidesteps Flutter's Java API surface
 *     altogether: our GOT hook operates purely at the native ELF level
 *     and doesn't care which Java code (if any) later triggers
 *     dlopen("libapp.so") -- it only needs libflutter.so mapped first.
 *     This is strictly more robust across Flutter/R8 versions, not just a
 *     workaround for one broken build.
 *
 *  2. GuardBridge.install(this) -- only after step 1 -- loads libguard.so
 *     (runs the now-safe GOT-hook constructor) and derives + installs the
 *     AES key (needs a live Context/PackageManager).
 *
 * Both happen in Application.onCreate(), which always runs before any
 * Activity (including FlutterActivity) is created -- so the engine's own
 * dlopen("libapp.so") call, which happens later during FlutterActivity's
 * engine attach, is guaranteed to see the hook already installed and the
 * key already set.
 *
 * If your app creates/warms a FlutterEngine earlier than usual (e.g. a
 * custom Application that pre-spins an engine in a background thread
 * during onCreate itself), make sure that still happens after
 * GuardBridge.install() returns, not concurrently with it.
 */
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        System.loadLibrary("flutter")
        GuardBridge.install(this)
    }
}
