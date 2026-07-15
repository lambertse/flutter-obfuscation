#ifndef GUARD_KEY_H
#define GUARD_KEY_H

#include <stdint.h>

#include "crypto.h"

/*
 * Process-wide AES key storage, set exactly once before the first decrypt.
 * The key reaches us via one of two suppliers, depending on injection mode:
 *
 *   - GuardBridge.nativeSetKey() (Java/Application path): Kotlin derives the
 *     key from the release signing cert via JCA HKDF and hands it down.
 *   - the embedded key baked into regions.h (no-Java/DT_NEEDED path): applied
 *     from the dlopen_hook trigger's install().
 *
 * Both funnel through guard_key_set(). Keeping key state here (rather than in
 * a specific trigger) lets the reusable decrypt engine in memops.c stay free
 * of global key state -- it takes the key as a parameter.
 */
void guard_key_set(const uint8_t key[GUARD_AES_KEY_LEN]);

/* Non-zero once a key has been installed. */
int guard_key_is_set(void);

/* Pointer to the GUARD_AES_KEY_LEN key bytes. Only valid when
 * guard_key_is_set() is non-zero. */
const uint8_t *guard_key_get(void);

#endif /* GUARD_KEY_H */
