#include "memops.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "crypto.h"
#include "log.h"

/*
 * Decrypts one non-exec (data) region in place. Returns 0 on success. On
 * failure returns -1 and the caller aborts the process: there is no safe
 * partial-failure recovery path. A half-decrypted region is worse than a
 * clean crash.
 *
 * A plain RW->R transition never touches SELinux's execmod check (that check
 * is specifically about marking a *modified file-backed* page executable), so
 * the simple in-place approach is safe here -- unlike exec regions, see
 * guard_decrypt_exec_regions().
 */
int guard_decrypt_data_region(void *handle, const guard_region_t *region,
                              const uint8_t key[GUARD_AES_KEY_LEN]) {
  void *addr = dlsym(handle, region->symbol);
  if (!addr) {
    /* A region symbol can legitimately be absent (e.g. stripped or optimized
     * away in a future engine version); treat that as nothing-to-do rather
     * than fatal. */
    GUARD_LOGW("guard_decrypt_data_region: dlsym('%s') returned NULL, skipping", region->symbol);
    return 0;
  }

  const size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
  const uintptr_t a = (uintptr_t)addr;
  const uintptr_t pg = a & ~(uintptr_t)(pagesize - 1);
  const uintptr_t region_end = a + region->size;
  const uintptr_t pg_end = (region_end + pagesize - 1) & ~(uintptr_t)(pagesize - 1);
  const size_t len = (size_t)(pg_end - pg);

  if (mprotect((void *)pg, len, PROT_READ | PROT_WRITE) != 0) {
    GUARD_LOGE("guard_decrypt_data_region: mprotect(RW) failed for '%s' at %p (errno=%d)", region->symbol, addr, errno);
    return -1;
  }

  guard_aes_ctr_xcrypt(key, region->nonce, (uint8_t *)addr, region->size);

  if (mprotect((void *)pg, len, PROT_READ) != 0) {
    GUARD_LOGE(
        "guard_decrypt_data_region: mprotect(R) failed for '%s' after decrypt "
        "(errno=%d) -- plaintext left RW, aborting",
        region->symbol, errno);
    return -1;
  }

  GUARD_LOGI("guard_decrypt_data_region: decrypted '%s' (%zu bytes) at %p", region->symbol, region->size, addr);
  return 0;
}

/*
 * Exec-region decrypt path. Unlike guard_decrypt_data_region() above, this
 * cannot decrypt in place. On real, unmodified, enforcing-SELinux Android
 * devices (confirmed via an actual device log, not just theory), mprotect(...,
 * PROT_READ|PROT_EXEC) on a page that was just written to via a *file-backed*
 * mapping (libapp.so, mapped straight out of base.apk) is denied by the
 * kernel's SELinux execmod check:
 *   avc: denied { execmod } ... path="...base.apk" tclass=file permissive=0
 * This is not a corner case -- it is standard W^X policy on every stock,
 * non-rooted device from roughly Android 10 onward, and fires 100% of the
 * time for exec regions.
 *
 * The fix: never mark a *modified file-backed* page executable at all.
 * Decrypt into a scratch buffer, then swap the live mapping for a fresh
 * *anonymous* one at the SAME virtual address (MAP_FIXED) before making it
 * executable. Anonymous memory was never file-backed, so execmod does not
 * apply to it -- only execmem does, which is a normal, always-granted
 * permission for untrusted_app (it's exactly how JIT engines get executable
 * pages on Android). Keeping the SAME address (rather than relocating to a new
 * one, which would need every caller redirected via a dlsym hook, and would
 * bet on undocumented Dart AOT position-independence assumptions) means every
 * PC-relative reference *inside* the decrypted instructions, and every address
 * already cached by dlsym() elsewhere, stays correct with no additional
 * bookkeeping.
 *
 * Operates on the union of ALL exec regions' pages in one pass (not one
 * mprotect per region): on the actual binary this ships against, the two
 * instruction regions sit ~32 bytes apart on the same page, so per-region
 * MAP_FIXED replacement would race/clobber across regions. Copying the whole
 * span through a staging buffer first (ciphertext and any unrelated bytes
 * alike), decrypting only the known sub-ranges within that staging copy, then
 * swapping the whole span at once keeps every byte outside our regions
 * bit-identical to the original.
 */
int guard_decrypt_exec_regions(void *handle, const guard_region_t *regions,
                               size_t count, const uint8_t key[GUARD_AES_KEY_LEN]) {
  const size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);

  uintptr_t span_start = 0;
  uintptr_t span_end = 0;
  size_t found = 0;

  /* Pass 1: resolve addresses, compute the covering page-aligned span. */
  for (size_t i = 0; i < count; i++) {
    if (!regions[i].exec) continue;
    void *addr = dlsym(handle, regions[i].symbol);
    if (!addr) {
      GUARD_LOGW("guard_decrypt_exec_regions: dlsym('%s') returned NULL, skipping", regions[i].symbol);
      continue;
    }
    const uintptr_t a = (uintptr_t)addr;
    const uintptr_t pg = a & ~(uintptr_t)(pagesize - 1);
    const uintptr_t end = (a + regions[i].size + pagesize - 1) & ~(uintptr_t)(pagesize - 1);
    if (found == 0) {
      span_start = pg;
      span_end = end;
    } else {
      if (pg < span_start) span_start = pg;
      if (end > span_end) span_end = end;
    }
    found++;
  }

  if (found == 0) return 0; /* nothing to do */

  const size_t len = (size_t)(span_end - span_start);
  uint8_t *staging = (uint8_t *)malloc(len);
  if (!staging) {
    GUARD_LOGE("guard_decrypt_exec_regions: malloc(%zu) failed for staging buffer", len);
    return -1;
  }

  /* Copy the whole span through first -- this preserves any bytes that belong
   * to neither region byte-identical (same PT_LOAD segment, but not one of our
   * regions), since only the sub-ranges below get touched. */
  memcpy(staging, (void *)span_start, len);

  /* Pass 2: decrypt each region's bytes within the staging copy. */
  for (size_t i = 0; i < count; i++) {
    if (!regions[i].exec) continue;
    void *addr = dlsym(handle, regions[i].symbol);
    if (!addr) continue; /* already warned above */
    const uintptr_t off = (uintptr_t)addr - span_start;
    guard_aes_ctr_xcrypt(key, regions[i].nonce, staging + off, regions[i].size);
    GUARD_LOGI("guard_decrypt_exec_regions: decrypted '%s' (%zu bytes) at %p", regions[i].symbol, regions[i].size, addr);
  }

  /* Swap the live file-backed mapping for anon memory at the same address --
   * this is the step that sidesteps execmod entirely (see comment above).
   * MAP_FIXED either lands exactly at span_start or fails; it never silently
   * picks a different address. */
  void *mapped = mmap((void *)span_start, len, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mapped == MAP_FAILED || mapped != (void *)span_start) {
    GUARD_LOGE("guard_decrypt_exec_regions: MAP_FIXED anon replacement failed at %p (errno=%d)", (void *)span_start, errno);
    free(staging);
    return -1;
  }

  memcpy((void *)span_start, staging, len);
  free(staging);

  if (mprotect((void *)span_start, len, PROT_READ | PROT_EXEC) != 0) {
    GUARD_LOGE("guard_decrypt_exec_regions: mprotect(RX) failed on anon replacement at %p (errno=%d)", (void *)span_start, errno);
    return -1;
  }

  __builtin___clear_cache((char *)span_start, (char *)span_end); /* mandatory on ARM64 */
  GUARD_LOGI("guard_decrypt_exec_regions: replaced %zu-byte span at %p with anon RX mapping (%zu region(s))", len, (void *)span_start, found);
  return 0;
}
