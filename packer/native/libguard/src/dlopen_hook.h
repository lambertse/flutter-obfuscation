#ifndef GUARD_DLOPEN_HOOK_H
#define GUARD_DLOPEN_HOOK_H

#include "trigger.h"

/*
 * The v1 Flutter trigger. libapp.so is inert until the engine opens it via
 * libflutter.so's dlopen; this trigger patches that dlopen GOT slot so we can
 * decrypt libapp.so's encrypted snapshot regions before Dart_Initialize reads
 * them. install() patches the GOT and (on the no-Java/DT_NEEDED path) applies
 * the embedded key. See Handover.md "dlopen_hook".
 */
extern const guard_trigger_t guard_trigger_dlopen_hook;

#endif /* GUARD_DLOPEN_HOOK_H */
