#ifndef GUARD_REGION_TABLE_H
#define GUARD_REGION_TABLE_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

/*
 * One entry per encrypted snapshot region. The generated regions.h (see
 * tools/encrypt_snapshot.py) fills an array of these, one array per ABI,
 * selected at compile time by preprocessor guard -- CMake builds this
 * library once per ABI, so exactly one array is ever compiled in.
 *
 * `symbol` is resolved at runtime via dlsym() rather than storing an address
 * directly: addresses are build- and load-specific, but the exported symbol
 * name is stable, and dlsym() against the just-opened handle gives us the
 * correct relocated runtime address for free.
 */
typedef struct {
  const char *symbol;
  size_t size;                    /* from readelf at build time; ciphertext length == plaintext length (CTR) */
  uint8_t nonce[GUARD_NONCE_LEN]; /* unique per (abi, region, build); see crypto.h */
  int exec;                       /* 1 => region must end PROT_READ|PROT_EXEC, 0 => PROT_READ */
} guard_region_t;

#endif /* GUARD_REGION_TABLE_H */
