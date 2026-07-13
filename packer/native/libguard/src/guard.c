/*
 * Constructor + orchestration + the native side of key hand-off.
 *
 * Two independent things happen at two different times (see trampoline.h):
 *
 *  1. At library-load time (__attribute__((constructor))): patch
 *     libflutter.so's dlopen (required) and android_dlopen_ext
 *     (best-effort) GOT slots. This has to happen before the engine's init
 *     thread calls dlopen("libapp.so") -- see App.kt / README for why
 *     System.loadLibrary("guard") from a static initializer is early enough.
 *
 *  2. Later, once GuardBridge.kt (Kotlin, from Application.onCreate() --
 *     still always before FlutterActivity) has derived the AES key from the
 *     release signing cert via PackageManager + JCA HKDF, it calls
 *     nativeSetKey() below, which just forwards the already-derived 32
 *     bytes into trampoline.c. No cryptography happens on the native side
 *     for key derivation -- see README "why key derivation is in Kotlin,
 *     not C" for the reasoning (JCA's SHA-256/HMAC are audited; avoids
 *     vendoring a second native crypto primitive on top of tiny-AES-c).
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#include "anti_instr.h"
#include "crypto.h"
#include "got_hook.h"
#include "log.h"
#include "trampoline.h"

__attribute__((constructor)) static void guard_ctor(void) {
  guard_generic_fn real_dlopen = NULL;
  guard_generic_fn real_dlopen_ext = NULL;

  if (guard_hook_got_symbol("libflutter.so", "dlopen", (void *)guard_my_dlopen, &real_dlopen) != 0) {
    /* Without this hook, dlopen("libapp.so") returns the encrypted snapshot
     * untouched and Dart_Initialize will fail deep inside the engine with a
     * confusing "wrong snapshot version" error. Fail fast and loud here
     * instead -- see trampoline.c's decrypt_region() for the same
     * fail-closed philosophy applied to the decrypt step itself. */
    GUARD_LOGE("guard_ctor: FATAL, could not hook dlopen in libflutter.so -- aborting");
    abort();
  }

  /* Best-effort: our reference build's libflutter.so only imports plain
   * dlopen (verified against the sample APK), not android_dlopen_ext. Some
   * engine/NDK versions may differ, so we still try, but absence here is
   * expected and not fatal. */
  if (guard_hook_got_symbol("libflutter.so", "android_dlopen_ext", (void *)guard_my_dlopen_ext, &real_dlopen_ext) != 0) {
    GUARD_LOGI("guard_ctor: android_dlopen_ext not imported by libflutter.so (expected on most builds), skipping");
    real_dlopen_ext = NULL;
  }

  guard_trampoline_init_hooks((guard_dlopen_fn)real_dlopen,
                               real_dlopen_ext ? (guard_dlopen_ext_fn)real_dlopen_ext : NULL);

  guard_anti_instr_check(); /* v1 stub, see anti_instr.h */
}

/*
 * Java_dev_packer_guard_GuardBridge_nativeSetKey -- called once from
 * GuardBridge.kt after HKDF key derivation. `key` must be exactly
 * GUARD_AES_KEY_LEN (32) bytes; anything else is logged and ignored (the
 * key stays unset, and trampoline.c's finish_handle() fails closed on the
 * next libapp.so dlopen -- see its comment).
 *
 * NOTE: rename the package path below (dev_packer_guard) to match wherever
 * GuardBridge.kt actually lives if it's moved out of packer/android/ into
 * the app's own source tree -- JNI resolves natives by fully-qualified
 * class name, not by convention.
 */
JNIEXPORT void JNICALL Java_dev_packer_guard_GuardBridge_nativeSetKey(JNIEnv *env, jobject thiz, jbyteArray key) {
  (void)thiz;
  if (key == NULL || (*env)->GetArrayLength(env, key) != GUARD_AES_KEY_LEN) {
    GUARD_LOGE("nativeSetKey: expected a %d-byte key, got %d -- ignoring", GUARD_AES_KEY_LEN,
               key ? (*env)->GetArrayLength(env, key) : -1);
    return;
  }

  jbyte *bytes = (*env)->GetByteArrayElements(env, key, NULL);
  if (!bytes) {
    GUARD_LOGE("nativeSetKey: GetByteArrayElements failed");
    return;
  }

  guard_trampoline_set_key((const uint8_t *)bytes);

  /* JNI_ABORT: we only read: no need to copy (possibly modified) elements
   * back into the Java-side array. */
  (*env)->ReleaseByteArrayElements(env, key, bytes, JNI_ABORT);
  GUARD_LOGI("nativeSetKey: key installed");
}
