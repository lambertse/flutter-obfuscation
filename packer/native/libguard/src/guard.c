/*
 * Constructor + orchestration + the native side of key hand-off.
 *
 * Two independent things happen at two different times:
 *
 *  1. At library-load time (__attribute__((constructor))): select and install
 *     the trigger for this build. v1 statically selects dlopen_hook, which
 *     patches libflutter.so's dlopen GOT slot. This has to happen before the
 *     engine's init thread calls dlopen("libapp.so"); System.loadLibrary or
 *     the DT_NEEDED co-load both arrange that. v2's preflight.py will emit a
 *     per-target trigger table this constructor iterates instead.
 *
 *  2. Later, on the Java/Application path only, once GuardBridge (Kotlin, from
 *     Application.onCreate() -- still always before FlutterActivity) has
 *     derived the AES key from the release signing cert via PackageManager +
 *     JCA HKDF, it calls nativeSetKey() below, which forwards the 32 bytes
 *     into key.c. No cryptography happens on the native side for key
 *     derivation here -- see README "why key derivation is in Kotlin, not C".
 *     (The no-Java/DT_NEEDED path instead uses the key embedded in regions.h,
 *     installed by the dlopen_hook trigger's install().)
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#include "anti_instr.h"
#include "crypto.h"
#include "dlopen_hook.h"
#include "key.h"
#include "log.h"
#include "trigger.h"

__attribute__((constructor)) static void guard_ctor(void) {
  /* v1: a single, statically-known trigger for the Flutter libapp.so target.
   * v2 iterates a generated per-target table here. */
  const guard_trigger_t *trigger = &guard_trigger_dlopen_hook;

  if (trigger->install() != 0) {
    GUARD_LOGE("guard_ctor: FATAL, trigger '%s' failed to install -- aborting", trigger->name);
    abort();
  }

  guard_anti_instr_check(); /* v1 stub, see anti_instr.h */
}

/*
 * Java_dev_packer_guard_GuardBridge_nativeSetKey -- called once from
 * GuardBridge (Java/Application path) after HKDF key derivation. `key` must be
 * exactly GUARD_AES_KEY_LEN (32) bytes; anything else is logged and ignored
 * (the key stays unset, and finish_handle() fails closed on the next
 * libapp.so dlopen).
 *
 * NOTE: rename the package path below (dev_packer_guard) to match wherever
 * GuardBridge actually lives if it's moved into the app's own source tree --
 * JNI resolves natives by fully-qualified class name, not by convention.
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

  guard_key_set((const uint8_t *)bytes);

  /* JNI_ABORT: we only read; no need to copy elements back into the Java-side
   * array. */
  (*env)->ReleaseByteArrayElements(env, key, bytes, JNI_ABORT);
  GUARD_LOGI("nativeSetKey: key installed");
}
