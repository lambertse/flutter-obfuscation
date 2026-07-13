#ifndef GUARD_CRYPTO_H
#define GUARD_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define GUARD_AES_KEY_LEN 32 /* AES-256 */
#define GUARD_NONCE_LEN 12   /* random per (abi, region); see regions.h */

/*
 * AES-256-CTR is a stream cipher: the same operation encrypts and decrypts.
 * IV = nonce (12 bytes) || 0x00000000 (4-byte big-endian block counter).
 * 4 bytes of counter space covers 2^32 * 16 bytes per region, far beyond any
 * snapshot region size, so the counter never overflows into the nonce.
 *
 * Do not reuse a (key, nonce) pair to encrypt two different plaintexts:
 * encrypt_snapshot.py generates a fresh random nonce per (abi, region) on
 * every build run, so this holds even though the key itself (derived from
 * the release signing cert, see key_derive.h) stays stable across rebuilds.
 */
void guard_aes_ctr_xcrypt(const uint8_t key[GUARD_AES_KEY_LEN],
                           const uint8_t nonce[GUARD_NONCE_LEN],
                           uint8_t *data, size_t size);

#endif /* GUARD_CRYPTO_H */
