#include "key.h"

#include <string.h>

/* Bionic serializes dlopen (global loader lock) and the Java key hand-off
 * happens once before any decrypt, so a plain flag is sufficient here -- no
 * mutex needed. See dlopen_hook.c's g_libapp_handled for the same reasoning. */
static uint8_t g_key[GUARD_AES_KEY_LEN];
static int g_key_set = 0;

void guard_key_set(const uint8_t key[GUARD_AES_KEY_LEN]) {
  memcpy(g_key, key, GUARD_AES_KEY_LEN);
  g_key_set = 1;
}

int guard_key_is_set(void) { return g_key_set; }

const uint8_t *guard_key_get(void) { return g_key; }
