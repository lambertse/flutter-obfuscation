#include "crypto.h"

#include <string.h>

#include "third_party/aes.h"

_Static_assert(GUARD_NONCE_LEN < AES_BLOCKLEN,
                "nonce must leave room for the CTR block counter");
_Static_assert(AES_KEYLEN == GUARD_AES_KEY_LEN, "aes.h must be built with AES256=1");

/* memset() on a soon-dead buffer can be dead-store-eliminated; a volatile
 * pointer forces the compiler to actually perform the writes. */
static void secure_zero(void *buf, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)buf;
  while (len--) *p++ = 0;
}

void guard_aes_ctr_xcrypt(const uint8_t key[GUARD_AES_KEY_LEN],
                           const uint8_t nonce[GUARD_NONCE_LEN],
                           uint8_t *data, size_t size) {
  uint8_t iv[AES_BLOCKLEN];
  memcpy(iv, nonce, GUARD_NONCE_LEN);
  memset(iv + GUARD_NONCE_LEN, 0, AES_BLOCKLEN - GUARD_NONCE_LEN);

  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);
  AES_CTR_xcrypt_buffer(&ctx, data, size);

  /* Best-effort: scrub the expanded key schedule from the stack. */
  secure_zero(&ctx, sizeof(ctx));
  secure_zero(iv, sizeof(iv));
}
