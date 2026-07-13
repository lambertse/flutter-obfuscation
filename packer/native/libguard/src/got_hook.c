#include "got_hook.h"

#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "log.h"

#if defined(__LP64__)
#define GUARD_R_SYM(info) ELF64_R_SYM(info)
#define GUARD_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define GUARD_R_SYM(info) ELF32_R_SYM(info)
#define GUARD_R_TYPE(info) ELF32_R_TYPE(info)
#endif

#if defined(__aarch64__)
#define GUARD_JUMP_SLOT R_AARCH64_JUMP_SLOT
#elif defined(__arm__)
#define GUARD_JUMP_SLOT R_ARM_JUMP_SLOT
#elif defined(__x86_64__)
#define GUARD_JUMP_SLOT R_X86_64_JUMP_SLOT
#elif defined(__i386__)
#define GUARD_JUMP_SLOT R_386_JUMP_SLOT
#else
#error "guard_hook_got_symbol: unsupported ABI"
#endif

typedef struct {
  const char *target_lib_substr;
  uintptr_t load_bias;
  const ElfW(Phdr) * phdr;
  ElfW(Half) phnum;
  int found;
} find_module_ctx;

static int find_module_cb(struct dl_phdr_info *info, size_t size, void *data) {
  (void)size;
  find_module_ctx *ctx = (find_module_ctx *)data;
  if (!info->dlpi_name || !strstr(info->dlpi_name, ctx->target_lib_substr)) {
    return 0; /* keep iterating */
  }
  ctx->load_bias = (uintptr_t)info->dlpi_addr;
  ctx->phdr = info->dlpi_phdr;
  ctx->phnum = info->dlpi_phnum;
  ctx->found = 1;
  return 1; /* stop iterating */
}

/* Returns the [lo, hi) runtime address range spanned by the module's
 * PT_LOAD segments, used to sanity-check computed dynamic-section pointers
 * before we ever dereference them. */
static void module_load_range(const find_module_ctx *ctx, uintptr_t *lo, uintptr_t *hi) {
  uintptr_t min_addr = UINTPTR_MAX, max_addr = 0;
  for (ElfW(Half) i = 0; i < ctx->phnum; i++) {
    const ElfW(Phdr) *ph = &ctx->phdr[i];
    if (ph->p_type != PT_LOAD) continue;
    uintptr_t start = ctx->load_bias + ph->p_vaddr;
    uintptr_t end = start + ph->p_memsz;
    if (start < min_addr) min_addr = start;
    if (end > max_addr) max_addr = end;
  }
  *lo = min_addr;
  *hi = max_addr;
}

static int in_range(uintptr_t addr, uintptr_t lo, uintptr_t hi) {
  return addr >= lo && addr < hi;
}

int guard_hook_got_symbol(const char *target_lib_substr,
                           const char *symbol_name,
                           void *hook,
                           guard_generic_fn *out_original) {
  find_module_ctx ctx = {0};
  ctx.target_lib_substr = target_lib_substr;
  dl_iterate_phdr(find_module_cb, &ctx);
  if (!ctx.found) {
    GUARD_LOGE("guard_hook_got_symbol: module '%s' not found", target_lib_substr);
    return -1;
  }

  const ElfW(Phdr) *dyn_phdr = NULL;
  for (ElfW(Half) i = 0; i < ctx.phnum; i++) {
    if (ctx.phdr[i].p_type == PT_DYNAMIC) {
      dyn_phdr = &ctx.phdr[i];
      break;
    }
  }
  if (!dyn_phdr) {
    GUARD_LOGE("guard_hook_got_symbol: '%s' has no PT_DYNAMIC", target_lib_substr);
    return -1;
  }

  uintptr_t load_lo, load_hi;
  module_load_range(&ctx, &load_lo, &load_hi);

  const ElfW(Dyn) *dyn = (const ElfW(Dyn) *)(ctx.load_bias + dyn_phdr->p_vaddr);

  const ElfW(Sym) *dynsym = NULL;
  const char *dynstr = NULL;
  const void *jmprel = NULL;
  /* Elf32_Dyn.d_un.d_val is 32-bit, Elf64_Dyn.d_un.d_val is 64-bit; there is
   * no portable ElfW(Xword)/ElfW(Sxword) (ELF32 has no such types), so widen
   * explicitly instead of relying on that macro pattern. */
  size_t pltrelsz = 0;
  long pltrel_type = 0; /* DT_REL(17) or DT_RELA(7) */

  for (; dyn->d_tag != DT_NULL; dyn++) {
    switch (dyn->d_tag) {
      case DT_SYMTAB:
        dynsym = (const ElfW(Sym) *)(ctx.load_bias + dyn->d_un.d_ptr);
        break;
      case DT_STRTAB:
        dynstr = (const char *)(ctx.load_bias + dyn->d_un.d_ptr);
        break;
      case DT_JMPREL:
        jmprel = (const void *)(ctx.load_bias + dyn->d_un.d_ptr);
        break;
      case DT_PLTRELSZ:
        pltrelsz = (size_t)dyn->d_un.d_val;
        break;
      case DT_PLTREL:
        pltrel_type = (long)dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (!dynsym || !dynstr || !jmprel || pltrelsz == 0) {
    GUARD_LOGE("guard_hook_got_symbol: '%s' missing DT_SYMTAB/DT_STRTAB/DT_JMPREL", target_lib_substr);
    return -1;
  }
  /* Sanity-check the pointers we're about to dereference actually land
   * inside this module's own mapped segments -- see the base+d_ptr caveat
   * in README (some loaders/toolchains pre-relocate DT_* pointer tags). */
  if (!in_range((uintptr_t)dynsym, load_lo, load_hi) ||
      !in_range((uintptr_t)dynstr, load_lo, load_hi) ||
      !in_range((uintptr_t)jmprel, load_lo, load_hi)) {
    GUARD_LOGE(
        "guard_hook_got_symbol: computed dynsym/dynstr/jmprel outside "
        "'%s' PT_LOAD range [0x%zx,0x%zx) -- refusing to proceed "
        "(dynsym=%p dynstr=%p jmprel=%p)",
        target_lib_substr, load_lo, load_hi, (void *)dynsym, (void *)dynstr, jmprel);
    return -1;
  }

  const size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
  const size_t rel_entsize = (pltrel_type == DT_RELA) ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel));
  const size_t rel_count = pltrelsz / rel_entsize;
  const uint8_t *rel_base = (const uint8_t *)jmprel;

  for (size_t i = 0; i < rel_count; i++) {
    ElfW(Addr) r_offset;
    uint64_t r_info; /* widened; see d_un comment above */
    if (pltrel_type == DT_RELA) {
      const ElfW(Rela) *r = (const ElfW(Rela) *)(rel_base + i * rel_entsize);
      r_offset = r->r_offset;
      r_info = (uint64_t)r->r_info;
    } else {
      const ElfW(Rel) *r = (const ElfW(Rel) *)(rel_base + i * rel_entsize);
      r_offset = r->r_offset;
      r_info = (uint64_t)r->r_info;
    }

    if (GUARD_R_TYPE(r_info) != GUARD_JUMP_SLOT) continue;

    size_t sym_idx = GUARD_R_SYM(r_info);
    const ElfW(Sym) *sym = &dynsym[sym_idx];
    const char *name = dynstr + sym->st_name;
    if (strcmp(name, symbol_name) != 0) continue;

    uintptr_t slot_addr = ctx.load_bias + r_offset;
    if (!in_range(slot_addr, load_lo, load_hi)) {
      GUARD_LOGE("guard_hook_got_symbol: GOT slot for '%s' outside PT_LOAD range", symbol_name);
      return -1;
    }

    void **slot = (void **)slot_addr;
    uintptr_t page_start = slot_addr & ~(uintptr_t)(pagesize - 1);
    uintptr_t region_end = slot_addr + sizeof(void *);
    uintptr_t page_end = (region_end + pagesize - 1) & ~(uintptr_t)(pagesize - 1);
    size_t len = (size_t)(page_end - page_start);

    if (mprotect((void *)page_start, len, PROT_READ | PROT_WRITE) != 0) {
      GUARD_LOGE("guard_hook_got_symbol: mprotect RW failed for '%s' GOT slot", symbol_name);
      return -1;
    }

    if (out_original) *out_original = (guard_generic_fn)*slot;
    *slot = hook;

    if (mprotect((void *)page_start, len, PROT_READ) != 0) {
      /* Slot is already patched; leaving the page writable is a lesser evil
       * than returning failure and having the caller assume no hook is
       * active. Log loudly so this shows up in the device test matrix. */
      GUARD_LOGW("guard_hook_got_symbol: mprotect R restore failed for '%s' GOT slot", symbol_name);
    }

    GUARD_LOGI("guard_hook_got_symbol: hooked '%s' in '%s' at %p", symbol_name, target_lib_substr, (void *)slot);
    return 0;
  }

  GUARD_LOGE("guard_hook_got_symbol: no JUMP_SLOT reloc for '%s' in '%s'", symbol_name, target_lib_substr);
  return -1;
}
