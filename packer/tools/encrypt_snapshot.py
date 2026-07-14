#!/usr/bin/env python3
"""
encrypt_snapshot.py -- build-time half of the libapp.so packer.

For each ABI's freshly-built (and --obfuscate'd) libapp.so, this:
  1. Uses `readelf` to find the file offset + size of the target Dart AOT
     snapshot symbols (NOT `_kDartSnapshotBuildId` -- the engine's
     magic/version gate reads that; touching it breaks every install).
  2. AES-256-CTR encrypts those byte ranges in place, byte-identical
     length (CTR is a stream cipher, no padding, no ELF layout change).
  3. Emits regions.h: a per-ABI, dlsym-name-keyed table (symbol name, size,
     nonce, exec flag) that native/libguard/src/trampoline.c compiles in and
     uses at runtime to find + decrypt the same ranges. Addresses are never
     baked in -- the runtime re-resolves them via dlsym() against the
     freshly dlopen()'d handle.

See Handover.md §6 and native/libguard/src/region_table.h for the full
contract this script and the C runtime must agree on byte-for-byte.
"""
from __future__ import annotations  # PEP 604 `str | None` etc. need this on Python < 3.10

import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Region selection (open decision from Handover.md §13, resolved: encrypt
# instructions-only for v1, architecture kept extensible).
#
# Flipping ENCRYPT_DATA_REGIONS to True requires ZERO changes on the native
# side -- trampoline.c just iterates whatever regions.h contains (see
# native/libguard/src/region_table.h). It only affects this build step.
#
# What each toggle actually protects, so this isn't a black box:
#   - instructions-only (default): hides compiled Dart code (the two
#     executable .text regions). Leaves ~1.8-3.6MB of `.rodata` object data
#     readable, including `package:`/class-name strings (confirmed present
#     via static analysis of the reference test APK, see PR notes).
#   - +data: also hides that residual string data. ~2x the mprotect calls
#     at startup; negligible runtime cost either way.
# --------------------------------------------------------------------------
ENCRYPT_DATA_REGIONS = False

REGIONS = [
    ("_kDartVmSnapshotInstructions", True),
    ("_kDartIsolateSnapshotInstructions", True),
]
if ENCRYPT_DATA_REGIONS:
    REGIONS += [
        ("_kDartVmSnapshotData", False),
        ("_kDartIsolateSnapshotData", False),
    ]

# Symbol explicitly excluded -- the engine's version/feature gate reads this
# to reject incompatible snapshots. Encrypting it breaks every install with
# a "No full snapshot version found" / "Wrong ... snapshot version" error.
# See Handover.md §11 "known failure modes".
FORBIDDEN_SYMBOL = "_kDartSnapshotBuildId"

NONCE_LEN = 12  # must match native/libguard/src/crypto.h GUARD_NONCE_LEN
AES_KEY_LEN = 32  # AES-256, must match native/libguard/src/crypto.h GUARD_AES_KEY_LEN

# ABI name -> the C preprocessor guard region_table.h's generated regions.h
# uses to select the right table at compile time (one CMake build = one ABI
# = exactly one branch compiled in). Must match native/libguard/src/got_hook.c's
# GUARD_JUMP_SLOT arch dispatch and trampoline.c's compile-time selection.
ABI_TO_CPP_GUARD = {
    "arm64-v8a": "defined(__aarch64__)",
    "armeabi-v7a": "defined(__arm__)",
    "x86_64": "defined(__x86_64__)",
}

# --------------------------------------------------------------------------
# Key derivation (Handover.md §8). This MUST match
# packer/android/GuardBridge.kt's nativeSetKey() input byte-for-byte -- see
# that file's header comment for the full HKDF parameter spec and the
# reasoning for doing key derivation in Kotlin/Python (via audited libraries)
# rather than vendoring a second native crypto primitive alongside AES.
#
#   IKM  = SHA-256(release_signing_cert_der) || KDF_CONSTANT
#   PRK  = HKDF-Extract(salt=b"", IKM)
#   OKM  = HKDF-Expand(PRK, info=KDF_INFO, length=32)   # RFC 5869
#
# KDF_CONSTANT / KDF_INFO are fixed, PUBLIC domain-separation strings (not
# secrets) -- they must be byte-identical here and in GuardBridge.kt, but
# do not need to be kept secret themselves.
# --------------------------------------------------------------------------
KDF_CONSTANT = b"flutter-guard-v1"
KDF_INFO = b"flutter-guard-v1-libapp-aes256"


def derive_key_from_cert(cert_der: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        sys.exit(
            "encrypt_snapshot.py requires the 'cryptography' package "
            "(pip install -r packer/tools/requirements.txt) for HKDF key "
            "derivation. Use --key-hex for a dev/local build without it."
        )
    ikm = hashlib.sha256(cert_der).digest() + KDF_CONSTANT
    hkdf = HKDF(algorithm=hashes.SHA256(), length=AES_KEY_LEN, salt=b"", info=KDF_INFO)
    return hkdf.derive(ikm)


# --------------------------------------------------------------------------
# AES-256-CTR, matching native/libguard/src/crypto.c exactly:
#   IV = nonce (12 bytes) || 0x00000000 (4-byte big-endian block counter)
#   Full 128-bit big-endian counter increment (standard CTR, verified
#   against tiny-AES-c's byte-wise carry-propagating increment).
# --------------------------------------------------------------------------
def aes_ctr_xcrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    assert len(key) == AES_KEY_LEN
    assert len(nonce) == NONCE_LEN
    iv = nonce + b"\x00\x00\x00\x00"
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# --------------------------------------------------------------------------
# readelf-based ELF introspection. We prefer parsing `readelf` text output
# over an ELF-parsing library, matching Handover.md §6's explicit
# instruction ("run readelf --dyn-syms ... parse address+size"). If readelf
# isn't on PATH (some minimal CI images ship without binutils, and it's not
# available in the sandbox this was authored in either), fall back
# automatically to _MiniElf, a small dependency-free ELF64 reader that
# extracts the same two things (dyn-symbols, section table) -- same
# addr/size math, just read directly from the file instead of parsed out of
# readelf's text output. This fallback path is what was actually exercised
# against the real reference APK's libapp.so during development, since
# readelf wasn't available there either.
# --------------------------------------------------------------------------
_SYM_RE = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)"
)
_SEC_RE = re.compile(
    r"^\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
)

_readelf_missing_warned = False


class _MiniElf:
    """Minimal ELF32/ELF64-LE reader (stdlib `struct` only). Not a
    general-purpose ELF library -- only implements what
    encrypt_snapshot.py needs: the section header table and
    .dynsym/.dynstr. Both word sizes are needed: arm64-v8a/x86_64 are
    ELF64, armeabi-v7a is ELF32 -- and Elf32_Sym's field ORDER differs
    from Elf64_Sym's, not just the widths (name,value,size,info,other,shndx
    vs. name,info,other,shndx,value,size), so this isn't just a matter of
    swapping struct format widths."""

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file (bad magic)")
        ei_class = data[4]
        if ei_class == 1:
            self._is64 = False
            (e_shoff,) = struct.unpack_from("<I", data, 0x20)
            (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x2E)
        elif ei_class == 2:
            self._is64 = True
            (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
            (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
        else:
            raise ValueError(f"unrecognized ei_class={ei_class}")

        self.data = data
        self.sections = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            if self._is64:
                (name_off, sh_type, _sh_flags, sh_addr, sh_offset, sh_size,
                 _sh_link, _sh_info, _sh_addralign, _sh_entsize) = struct.unpack_from("<IIQQQQIIQQ", data, o)
            else:
                (name_off, sh_type, _sh_flags, sh_addr, sh_offset, sh_size,
                 _sh_link, _sh_info, _sh_addralign, _sh_entsize) = struct.unpack_from("<IIIIIIIIII", data, o)
            self.sections.append({
                "name_off": name_off, "sh_type": sh_type, "sh_addr": sh_addr,
                "sh_offset": sh_offset, "sh_size": sh_size,
            })
        shstrtab_off = self.sections[e_shstrndx]["sh_offset"]
        for s in self.sections:
            s["name"] = self._cstr(shstrtab_off + s["name_off"])

    def _cstr(self, off: int) -> str:
        end = self.data.index(b"\x00", off)
        return self.data[off:end].decode("utf-8", "replace")

    def dyn_symbols(self) -> dict:
        dynsym = next((s for s in self.sections if s["name"] == ".dynsym"), None)
        dynstr = next((s for s in self.sections if s["name"] == ".dynstr"), None)
        if not dynsym or not dynstr:
            return {}
        entsize = 24 if self._is64 else 16
        count = dynsym["sh_size"] // entsize
        syms = {}
        for i in range(count):
            o = dynsym["sh_offset"] + i * entsize
            if self._is64:
                (st_name, _st_info, _st_other, _st_shndx, st_value, st_size) = \
                    struct.unpack_from("<IBBHQQ", self.data, o)
            else:
                (st_name, st_value, st_size, _st_info, _st_other, _st_shndx) = \
                    struct.unpack_from("<IIIBBH", self.data, o)
            name = self._cstr(dynstr["sh_offset"] + st_name)
            if name:
                syms[name] = (st_value, st_size)
        return syms

    def section_list(self) -> list:
        # Matches parse_sections()'s return shape: (name, addr, offset, size).
        return [(s["name"], s["sh_addr"], s["sh_offset"], s["sh_size"])
                for s in self.sections if s["sh_addr"] != 0]


def _run_readelf(args, libapp_path: Path) -> str | None:
    """Returns readelf's stdout, or None if readelf isn't on PATH (caller
    falls back to _MiniElf in that case)."""
    global _readelf_missing_warned
    try:
        result = subprocess.run(
            ["readelf", *args, str(libapp_path)],
            capture_output=True, text=True, check=True,
        )
    except FileNotFoundError:
        if not _readelf_missing_warned:
            print("readelf not found on PATH; falling back to the built-in ELF parser (_MiniElf).", file=sys.stderr)
            _readelf_missing_warned = True
        return None
    except subprocess.CalledProcessError as e:
        sys.exit(f"readelf failed on {libapp_path}:\n{e.stderr}")
    return result.stdout


def parse_dyn_symbols(libapp_path: Path) -> dict:
    """symbol name -> (addr:int, size:int)"""
    out = _run_readelf(["-W", "--dyn-syms"], libapp_path)
    if out is None:
        return _MiniElf(libapp_path.read_bytes()).dyn_symbols()
    syms = {}
    for line in out.splitlines():
        m = _SYM_RE.match(line)
        if not m:
            continue
        addr, size, name = m.groups()
        syms[name] = (int(addr, 16), int(size))
    return syms


def parse_sections(libapp_path: Path) -> list:
    """list of (name, addr:int, offset:int, size:int), address-ordered."""
    out = _run_readelf(["-W", "-S"], libapp_path)
    if out is None:
        return _MiniElf(libapp_path.read_bytes()).section_list()
    sections = []
    for line in out.splitlines():
        m = _SEC_RE.match(line)
        if not m:
            continue
        idx, name, _sec_type, addr, offset, size = m.groups()
        if idx == "0":
            # Section 0 is always the reserved NULL section with a blank
            # Name column; a blank field shifts every \S+ capture left by
            # one instead of a clean "no match", so skip it explicitly by
            # index rather than trying to detect it from (unreliable) field
            # content.
            continue
        sections.append((name, int(addr, 16), int(offset, 16), int(size, 16)))
    return sections


def vaddr_to_file_offset(sections: list, vaddr: int, libapp_path: Path) -> int:
    for _name, addr, offset, size in sections:
        if addr != 0 and addr <= vaddr < addr + size:
            return offset + (vaddr - addr)
    sys.exit(f"{libapp_path}: no section contains vaddr 0x{vaddr:x}")


# --------------------------------------------------------------------------
# Per-ABI processing
# --------------------------------------------------------------------------
def process_abi(abi: str, libapp_path: Path, key: bytes) -> list:
    """Encrypts libapp_path in place; returns the region table for regions.h."""
    print(f"[{abi}] {libapp_path}", file=sys.stderr)

    syms = parse_dyn_symbols(libapp_path)
    if FORBIDDEN_SYMBOL not in syms:
        sys.exit(f"[{abi}] sanity check failed: {FORBIDDEN_SYMBOL} not found in dynsym")

    sections = parse_sections(libapp_path)
    data = bytearray(libapp_path.read_bytes())

    region_entries = []
    for symbol, exec_flag in REGIONS:
        if symbol not in syms:
            sys.exit(f"[{abi}] required symbol '{symbol}' not found in {libapp_path} dynsym table")
        addr, size = syms[symbol]
        if size == 0:
            sys.exit(f"[{abi}] symbol '{symbol}' has size 0 -- refusing to encrypt an empty/malformed region")

        file_off = vaddr_to_file_offset(sections, addr, libapp_path)
        if file_off + size > len(data):
            sys.exit(f"[{abi}] symbol '{symbol}' region [0x{file_off:x}, +{size}) exceeds file size {len(data)}")

        nonce = os.urandom(NONCE_LEN)  # fresh per (abi, region, build run) -- see crypto.h
        plaintext = bytes(data[file_off:file_off + size])
        ciphertext = aes_ctr_xcrypt(key, nonce, plaintext)
        assert len(ciphertext) == size, "AES-CTR must be length-preserving"
        data[file_off:file_off + size] = ciphertext

        print(f"  encrypted {symbol}: vaddr=0x{addr:x} file_off=0x{file_off:x} size={size}", file=sys.stderr)
        region_entries.append((symbol, size, nonce, exec_flag))

    libapp_path.write_bytes(bytes(data))
    return region_entries


# --------------------------------------------------------------------------
# regions.h generation
# --------------------------------------------------------------------------
def _fp(data: bytes) -> str:
    """Non-secret fingerprint: first 4 bytes of SHA-256, hex. Used only to
    compare build-side vs device-side key/cert bytes in logs."""
    return hashlib.sha256(data).hexdigest()[:8]


def format_nonce(nonce: bytes) -> str:
    return "{" + ", ".join(f"0x{b:02x}" for b in nonce) + "}"


def render_regions_h(per_abi_regions: dict, embedded_key: bytes = None) -> str:
    """Renders regions.h. If embedded_key is given, the AES key is baked in
    (GUARD_HAVE_EMBEDDED_KEY=1) for the no-Java / DT_NEEDED injection path,
    where guard_ctor sets the key itself instead of Java's nativeSetKey. An
    empty per-ABI list emits a 0-count table (mechanism test: the hook still
    installs and fires, it just decrypts nothing)."""
    lines = [
        "/* GENERATED by tools/encrypt_snapshot.py -- do not hand-edit. */",
        "#ifndef GUARD_REGIONS_H",
        "#define GUARD_REGIONS_H",
        "",
        '#include "region_table.h"',
        "",
    ]
    abis = list(per_abi_regions.keys())
    for i, abi in enumerate(abis):
        guard = ABI_TO_CPP_GUARD[abi]
        keyword = "#if" if i == 0 else "#elif"
        lines.append(f"{keyword} {guard}")
        lines.append(f"/* {abi} */")
        entries = per_abi_regions[abi]
        if entries:
            lines.append("static const guard_region_t k_regions[] = {")
            for symbol, size, nonce, exec_flag in entries:
                lines.append(
                    f'  {{ "{symbol}", {size}u, {format_nonce(nonce)}, {1 if exec_flag else 0} }},'
                )
            lines.append("};")
            lines.append(f"static const size_t k_regions_count = {len(entries)};")
        else:
            # Zero-length arrays aren't standard C: emit a 1-element unused
            # dummy and force the count to 0 so every loop over it is empty.
            lines.append("/* empty table (mechanism test): hook installs + fires, decrypts nothing */")
            lines.append('static const guard_region_t k_regions[1] = { { "", 0u, {0}, 0 } };')
            lines.append("static const size_t k_regions_count = 0;")
        lines.append("")
    lines.append("#else")
    lines.append('#error "regions.h: unsupported ABI (add it to ABI_TO_CPP_GUARD in encrypt_snapshot.py)"')
    lines.append("#endif")
    lines.append("")
    # The AES key is ABI-independent (one key, per-region/-ABI nonces), so it
    # lives outside the per-ABI #if. guard.c's constructor applies it when
    # GUARD_HAVE_EMBEDDED_KEY is 1 -- see trampoline.c guard_trampoline_apply_embedded_key().
    if embedded_key is not None:
        assert len(embedded_key) == AES_KEY_LEN
        lines.append("#define GUARD_HAVE_EMBEDDED_KEY 1")
        lines.append(f"static const uint8_t k_embedded_key[{AES_KEY_LEN}] = {format_nonce(embedded_key)};")
    else:
        lines.append("#define GUARD_HAVE_EMBEDDED_KEY 0")
    lines.append("")
    lines.append("#endif /* GUARD_REGIONS_H */")
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--libs-dir", required=True, type=Path,
                    help="Directory laid out as <libs-dir>/<abi>/libapp.so (e.g. an extracted APK's lib/ folder)")
    p.add_argument("--abis", default="arm64-v8a,armeabi-v7a,x86_64",
                    help="Comma-separated ABI list (default: all 3 supported ABIs)")
    p.add_argument("--output-regions-h", required=True, type=Path)
    key_group = p.add_mutually_exclusive_group(required=False)
    key_group.add_argument("--key-hex", help="Dev/local override: 64 hex chars = 32-byte AES key directly.")
    key_group.add_argument("--cert-der", type=Path,
                            help="Path to the release signing cert, DER-encoded "
                                 "(keytool -exportcert -alias <a> -keystore <ks> -file cert.der)")
    p.add_argument("--embed-key", action="store_true",
                   help="Bake the AES key into regions.h so guard.c's constructor sets it "
                        "itself. Required for the no-Java DT_NEEDED injection path (there is "
                        "no GuardBridge to call nativeSetKey). The key then lives in "
                        "libguard.so inside the APK -- acceptable because the signing cert it "
                        "would otherwise derive from is itself public in the APK.")
    p.add_argument("--emit-empty-regions", action="store_true",
                   help="Mechanism test: emit a 0-region table (+ a zero embedded key) and DO "
                        "NOT modify any libapp.so. The hook still installs and fires; it just "
                        "decrypts nothing -- isolates 'does the injection work' from 'does "
                        "decryption work' on the first device cycle.")
    args = p.parse_args()

    abis = [a.strip() for a in args.abis.split(",") if a.strip()]
    unknown = [a for a in abis if a not in ABI_TO_CPP_GUARD]
    if unknown:
        sys.exit(f"unsupported ABI(s): {unknown}; known: {list(ABI_TO_CPP_GUARD)}")

    if args.emit_empty_regions:
        # No key needed and no libapp.so touched. Embed an all-zero key so
        # GUARD_HAVE_EMBEDDED_KEY is 1 and finish_handle proceeds to the
        # (empty) region loop and logs "decrypting 0 region(s)" -- a clean
        # positive signal that the hook fired.
        per_abi_regions = {abi: [] for abi in abis}
        embedded_key = bytes(AES_KEY_LEN)
        print("[key] --emit-empty-regions: no encryption, zero embedded key (mechanism test)", file=sys.stderr)
    else:
        if args.key_hex:
            key = bytes.fromhex(args.key_hex)
            if len(key) != AES_KEY_LEN:
                sys.exit(f"--key-hex must decode to {AES_KEY_LEN} bytes, got {len(key)}")
            print(f"[key] source=--key-hex  key-fp={_fp(key)}  embed={args.embed_key}", file=sys.stderr)
        elif args.cert_der:
            cert_der = args.cert_der.read_bytes()
            key = derive_key_from_cert(cert_der)
            # Non-secret fingerprints (first 4 bytes of SHA-256) to diagnose a
            # build-vs-runtime key mismatch on the Java (Application) path.
            # GuardBridge logs the SAME two fingerprints on-device (tag
            # "libguard"). Irrelevant on the DT_NEEDED path (--embed-key), where
            # the key is baked in and never derived at runtime.
            print(f"[key] source=cert  cert-fp={_fp(cert_der)}  key-fp={_fp(key)}  embed={args.embed_key}", file=sys.stderr)
        else:
            sys.exit("one of --key-hex / --cert-der is required (unless --emit-empty-regions)")

        per_abi_regions = {}
        for abi in abis:
            libapp_path = args.libs_dir / abi / "libapp.so"
            if not libapp_path.exists():
                sys.exit(f"missing {libapp_path}")
            per_abi_regions[abi] = process_abi(abi, libapp_path, key)

        embedded_key = key if args.embed_key else None

    args.output_regions_h.parent.mkdir(parents=True, exist_ok=True)
    args.output_regions_h.write_text(render_regions_h(per_abi_regions, embedded_key))
    print(f"wrote {args.output_regions_h}", file=sys.stderr)


if __name__ == "__main__":
    main()
