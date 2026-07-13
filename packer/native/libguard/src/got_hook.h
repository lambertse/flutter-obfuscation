#ifndef GUARD_GOT_HOOK_H
#define GUARD_GOT_HOOK_H

/*
 * Runtime PLT/GOT hooking of a symbol imported by an already-loaded module.
 *
 * We target dlopen's R_*_JUMP_SLOT relocation inside libflutter.so (found via
 * PT_DYNAMIC's DT_JMPREL, not section headers -- section headers aren't
 * guaranteed to be mapped into memory at runtime, only PT_LOAD/PT_DYNAMIC
 * segments are). This lets us intercept the engine's dlopen("libapp.so")
 * call and decrypt the AOT snapshot before Dart_Initialize reads it.
 */

typedef void *(*guard_generic_fn)(void);

/*
 * Finds `symbol_name`'s JUMP_SLOT GOT entry inside the first loaded module
 * whose soname contains `target_lib_substr` (e.g. "libflutter.so"), and
 * atomically (relative to this thread) redirects it to `hook`.
 *
 * On success, returns 0 and writes the previously-installed function pointer
 * (the real symbol, usually the libc implementation) to *out_original so the
 * caller can chain to it. On failure (target module not found, symbol not
 * imported via a JUMP_SLOT reloc in that module, or the computed GOT address
 * fails a sanity bounds-check against the module's own PT_LOAD ranges),
 * returns -1 and leaves *out_original untouched. Never crashes on failure --
 * callers must treat -1 as "hook not installed" and fail safe (e.g. skip
 * decryption and let the unmodified engine load fail loudly rather than feed
 * it ciphertext).
 */
int guard_hook_got_symbol(const char *target_lib_substr,
                           const char *symbol_name,
                           void *hook,
                           guard_generic_fn *out_original);

#endif /* GUARD_GOT_HOOK_H */
