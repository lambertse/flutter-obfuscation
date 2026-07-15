#ifndef GUARD_ANTI_INSTR_H
#define GUARD_ANTI_INSTR_H

/*
 * v1 stub. This is meant to become the layer that actually defends the
 * decrypted-in-memory window -- ptrace/Frida/debugger-attach detection
 * around the period where the AOT snapshot is plaintext in memory. Snapshot
 * encryption-at-rest (crypto.c/memops.c) does NOT protect against a
 * live memory dump; see Handover.md §2. Not implemented in v1; see
 * README "anti_instr (v2 plan)". Currently a no-op so call sites (guard.c)
 * don't need to change once v2 lands.
 */
void guard_anti_instr_check(void);

#endif /* GUARD_ANTI_INSTR_H */
