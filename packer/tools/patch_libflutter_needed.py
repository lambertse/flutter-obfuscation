#!/usr/bin/env python3
"""
patch_libflutter_needed.py -- add a DT_NEEDED dependency on libguard.so to a
libflutter.so, for the no-Java / DT_NEEDED injection path (see
docs/GUIDE.md and packer/README.md limitation #10).

Why: on the DT_NEEDED path we install the decrypt hook without touching the
app's Application class, manifest, or dex at all. Instead we make the engine's
own libflutter.so depend on libguard.so. Bionic loads a library's DT_NEEDED
dependencies (and runs their constructors) before the library that needs them
finishes loading, so libguard's constructor -- which patches libflutter's
dlopen GOT slot and installs the embedded key -- runs before the engine ever
calls dlopen("libapp.so"). No Java entry point required. This is what makes
the packer work on an app that already has a custom Application class we must
not disturb (e.g. one bootstrapping a RASP SDK).

Uses LIEF for the ELF surgery rather than an in-place byte patch: libflutter's
.dynamic has no spare slot, so adding an entry requires relocating .dynamic
into a fresh segment, which LIEF does correctly (verified: the added entry is
the only change, the code segment and dlopen JUMP_SLOT relocation are
untouched). A hand-rolled patcher was considered and rejected as too risky for
an 11 MB production engine binary.

NOTE: "produces a valid ELF" is necessary but not sufficient -- confirm the
patched libflutter still loads on the target device (the --mechanism-test
build of pack_existing_apk.sh does exactly this with encryption turned off).
"""
import argparse
import sys
from pathlib import Path

NEEDED_NAME = "libguard.so"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True, type=Path, help="libflutter.so to patch")
    p.add_argument("--output", type=Path, help="output path (default: overwrite --input)")
    p.add_argument("--needed", default=NEEDED_NAME, help=f"library to add as DT_NEEDED (default: {NEEDED_NAME})")
    args = p.parse_args()

    try:
        import lief
    except ImportError:
        sys.exit(
            "patch_libflutter_needed.py requires the 'lief' package "
            "(pip install -r packer/tools/requirements.txt)."
        )

    out = args.output or args.input

    binary = lief.ELF.parse(str(args.input))
    if binary is None:
        sys.exit(f"could not parse {args.input} as an ELF")

    def needed_names(b):
        return [e.name for e in b.dynamic_entries
                if e.tag == lief.ELF.DynamicEntry.TAG.NEEDED]

    before = needed_names(binary)
    if args.needed in before:
        # Idempotent: never add a second identical DT_NEEDED (would happen if
        # the pipeline is re-run on an already-patched APK's libflutter.so).
        print(f"{args.input}: already depends on {args.needed}, nothing to do", file=sys.stderr)
        if out != args.input:
            out.write_bytes(args.input.read_bytes())
        return

    binary.add_library(args.needed)
    binary.write(str(out))

    # Verify the surgery: re-parse the output and confirm the ONLY change to
    # the NEEDED list is our one added entry (nothing dropped/renamed).
    patched = lief.ELF.parse(str(out))
    after = needed_names(patched)
    added = [n for n in after if n not in before]
    removed = [n for n in before if n not in after]
    if added != [args.needed] or removed:
        sys.exit(f"FATAL: unexpected DT_NEEDED delta -- added={added} removed={removed}")

    print(f"wrote {out}: added DT_NEEDED '{args.needed}' "
          f"({len(before)} -> {len(after)} deps)", file=sys.stderr)


if __name__ == "__main__":
    main()
