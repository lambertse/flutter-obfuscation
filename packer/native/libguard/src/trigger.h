#ifndef GUARD_TRIGGER_H
#define GUARD_TRIGGER_H

/*
 * A "trigger" is the mechanism that guarantees our decrypt logic runs before a
 * given target executes its own code. Each backend implements this one
 * interface:
 *
 *   dlopen_hook  inert-until-consumed libs opened via a hookable dlopen GOT
 *                slot (e.g. Flutter's libapp.so) -- the v1 trigger.
 *   dt_needed    target loads as a dependency; decrypt from libguard's ctor.
 *   ctor_thunk   staggered/dlopen-later loads; inject a slot-0 constructor.
 *   page_fault   general fallback (spike-gated; see Handover.md / README).
 *
 * Which trigger is correct for each target is decided at BUILD time by
 * tools/preflight.py and never re-decided at runtime (runtime checks inside a
 * trigger are safety/idempotency guards only -- see Handover.md "ground
 * truths"). v1 ships dlopen_hook; the others land with the generic engine.
 */
typedef struct guard_trigger {
  const char *name;
  /*
   * Arm the trigger for this process. Called once from guard.c's constructor,
   * as early as the library loads (before the target executes). Returns 0 on
   * success, non-zero on a fatal failure the constructor should abort on.
   */
  int (*install)(void);
} guard_trigger_t;

#endif /* GUARD_TRIGGER_H */
