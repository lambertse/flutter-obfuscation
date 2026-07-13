#ifndef GUARD_TRAMPOLINE_H
#define GUARD_TRAMPOLINE_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

/* Must match the real dlopen/android_dlopen_ext signatures exactly -- these
 * are installed directly into libflutter.so's GOT, so the calling convention
 * has to be identical. */
typedef void *(*guard_dlopen_fn)(const char *filename, int flags);
struct android_dlextinfo; /* opaque; we never touch its fields */
typedef void *(*guard_dlopen_ext_fn)(const char *filename, int flags,
                                      const struct android_dlextinfo *extinfo);

/*
 * Two-phase init, because the two inputs become available at different
 * points in the process lifecycle:
 *
 *  1. guard_trampoline_init_hooks() -- called from guard.c's
 *     __attribute__((constructor)), i.e. as early as System.loadLibrary()
 *     itself. Stores the real dlopen/android_dlopen_ext (the latter
 *     nullable -- best-effort, see got_hook.c) so the hooks can chain to
 *     them. Must happen before the engine's init thread calls dlopen().
 *
 *  2. guard_trampoline_set_key() -- called later, once the JNI key
 *     derivation (reading the release signing cert via PackageManager,
 *     which needs a live JNIEnv/Context and so cannot run inside the
 *     constructor) has produced the AES key. Must happen before
 *     guard_my_dlopen("libapp.so") actually fires; see App.kt/README for
 *     the ordering this relies on (Application.onCreate() runs before any
 *     Activity, including FlutterActivity).
 */
void guard_trampoline_init_hooks(guard_dlopen_fn real_dlopen,
                                  guard_dlopen_ext_fn real_dlopen_ext /* nullable */);

void guard_trampoline_set_key(const uint8_t key[GUARD_AES_KEY_LEN]);

/* Installed into libflutter.so's dlopen GOT slot. */
void *guard_my_dlopen(const char *filename, int flags);

/* Installed into libflutter.so's android_dlopen_ext GOT slot, if present. */
void *guard_my_dlopen_ext(const char *filename, int flags,
                           const struct android_dlextinfo *extinfo);

#endif /* GUARD_TRAMPOLINE_H */
