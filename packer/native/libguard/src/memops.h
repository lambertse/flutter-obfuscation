#ifndef GUARD_MEMOPS_H
#define GUARD_MEMOPS_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "region_table.h"

/*
 * The reusable decrypt engine, independent of any particular trigger or
 * target. Region addresses are resolved via dlsym(handle, symbol); sizes and
 * nonces come from the region table; the AES key is supplied by the caller
 * (see key.h) so this stays free of global key state and reusable across
 * targets and triggers.
 *
 * Both functions fail closed: on any hard failure they return -1 and the
 * caller must abort. A half-decrypted region is worse than a clean crash.
 */

/*
 * Decrypt one non-exec (data) region in place (mprotect RW -> AES-CTR -> R).
 * A NULL dlsym result is treated as nothing-to-do (returns 0). Returns 0 on
 * success, -1 on a protection failure. Safe in place because a plain RW->R
 * transition never trips SELinux's execmod check -- unlike exec regions.
 */
int guard_decrypt_data_region(void *handle, const guard_region_t *region,
                              const uint8_t key[GUARD_AES_KEY_LEN]);

/*
 * Decrypt every exec region in `regions` together, via a MAP_FIXED anonymous
 * replacement at the same virtual address that sidesteps SELinux execmod (see
 * the implementation comment for the full rationale). Returns 0 on success
 * (including "no exec regions present"), -1 on failure.
 */
int guard_decrypt_exec_regions(void *handle, const guard_region_t *regions,
                               size_t count, const uint8_t key[GUARD_AES_KEY_LEN]);

#endif /* GUARD_MEMOPS_H */
