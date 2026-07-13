# tiny-AES-c

Source: https://github.com/kokke/tiny-AES-c (commit at `master` as of 2026-07-10)
License: The Unlicense (public domain) — see `LICENSE.tiny-aes-c.txt`.

Vendored verbatim (`aes.c`, `aes.h`), unmodified. Only the *build configuration*
differs: `CMakeLists.txt` compiles this unit with `-DCBC=0 -DECB=0 -DCTR=1
-DAES256=1`, so only `AES_init_ctx_iv` and `AES_CTR_xcrypt_buffer` are built in.

Do not hand-edit these two files — if a fix or upstream update is needed,
re-fetch from the upstream repo and update this note.
