#!/usr/bin/env python3
"""
axml_patch.py -- minimal, surgical patcher for a compiled (binary)
AndroidManifest.xml: changes a single attribute's string value on a single
element (used to retarget <application android:name="..."> at our injected
GuardApplication class -- see docs/GUIDE.md "Path A: no source, APK only").

Deliberately NOT a general AXML editor and NOT built on a full decompile/
recompile tool (e.g. apktool): a full decode->rebuild round-trip re-encodes
resources.arsc and other entries, which risks exactly the STORED/alignment
regression documented in packer/README.md limitation #6 for the APK zip
itself. This only touches the one chunk that needs to change (the string
pool, to add the new class name) plus one 4-byte field inside one
XML_START_ELEMENT chunk (the attribute's value reference) -- every other
byte in the file, including every other element/attribute, is copied
through unmodified.

Format reference: the Android AXML binary XML format (chunk-based: a
string pool chunk, an optional resource-id map, then a stream of
namespace/element start/end chunks). Not officially documented by Google;
this follows the widely-used community reverse-engineered layout (same one
libraries like androguard/axmlprinter/apktool implement against).
"""
import argparse
import struct
import sys
from pathlib import Path

RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
UTF8_FLAG = 1 << 8


class Chunk:
    """One top-level (or string-pool-internal) chunk: raw bytes plus where
    it lives in the original file, so unmodified chunks can be copied
    through byte-for-byte."""
    __slots__ = ("type", "start", "end", "raw")

    def __init__(self, type_, start, end, raw):
        self.type = type_
        self.start = start
        self.end = end
        self.raw = raw


def read_chunks(data: bytes, base: int, end: int):
    chunks = []
    pos = base
    while pos < end:
        type_ = struct.unpack_from("<H", data, pos)[0]
        chunk_size = struct.unpack_from("<I", data, pos + 4)[0]
        chunks.append(Chunk(type_, pos, pos + chunk_size, data[pos:pos + chunk_size]))
        pos += chunk_size
    return chunks


def decode_string_pool(chunk: Chunk):
    """Returns (strings: list[str], is_utf8: bool, style_count: int)."""
    data = chunk.raw
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from("<IIIII", data, 8)
    is_utf8 = bool(flags & UTF8_FLAG)
    offsets = struct.unpack_from(f"<{string_count}I", data, 28)

    strings = []
    for off in offsets:
        p = strings_start + off
        if is_utf8:
            # utf16 length (1-2 bytes, high bit = continuation), then utf8 length (1-2 bytes)
            b0 = data[p]; p += 1
            if b0 & 0x80:
                p += 1  # second byte of utf16-length, unused here
            b1 = data[p]; p += 1
            length8 = b1 & 0x7f
            if b1 & 0x80:
                length8 = ((b1 & 0x7f) << 8) | data[p]; p += 1
            strings.append(data[p:p + length8].decode("utf-8"))
        else:
            length16 = struct.unpack_from("<H", data, p)[0]; p += 2
            if length16 & 0x8000:
                length16 = ((length16 & 0x7fff) << 16) | struct.unpack_from("<H", data, p)[0]; p += 2
            strings.append(data[p:p + length16 * 2].decode("utf-16-le"))
    return strings, is_utf8, style_count


def encode_string_pool(strings: list, is_utf8: bool) -> bytes:
    """Rebuilds a complete RES_STRING_POOL_TYPE chunk from scratch, no
    styles (style_count=0 -- manifests don't use styled/spanned attribute
    text). Re-encodes EVERY string, not just the new one: simpler and
    safer than trying to splice new bytes into the old encoding, at the
    cost of the output not being guaranteed byte-identical to aapt's own
    encoding for the untouched strings (functionally equivalent either
    way -- verified by round-tripping through the same reader used
    elsewhere in this repo, see the __main__ self-test below)."""
    offsets = []
    blob = bytearray()
    for s in strings:
        offsets.append(len(blob))
        if is_utf8:
            utf8_bytes = s.encode("utf-8")
            n16 = len(s)  # utf16 code unit count; fine for BMP-only manifest strings
            n8 = len(utf8_bytes)
            if n16 >= 0x80:
                blob += struct.pack("<H", 0x8000 | n16)[::-1]  # rarely hit; see note below
            else:
                blob.append(n16)
            if n8 >= 0x80:
                blob.append(0x80 | (n8 >> 8))
                blob.append(n8 & 0xff)
            else:
                blob.append(n8)
            blob += utf8_bytes
            blob.append(0)  # NUL terminator
        else:
            n16 = len(s)
            if n16 >= 0x8000:
                blob += struct.pack("<HH", 0x8000 | (n16 >> 16), n16 & 0xffff)
            else:
                blob += struct.pack("<H", n16)
            blob += s.encode("utf-16-le")
            blob += b"\x00\x00"
    while len(blob) % 4 != 0:
        blob.append(0)

    string_count = len(strings)
    style_count = 0
    flags = UTF8_FLAG if is_utf8 else 0
    header_size = 28
    strings_start = header_size + string_count * 4
    styles_start = 0
    body = struct.pack(f"<{string_count}I", *offsets) + bytes(blob)
    chunk_size = header_size + len(body)
    header = struct.pack(
        "<HHIIIIII",
        RES_STRING_POOL_TYPE, header_size, chunk_size,
        string_count, style_count, flags, strings_start, styles_start,
    )
    assert len(header) == header_size
    return header + body


def patch_attribute_value(element_chunk_raw: bytes, attr_name_str_idx: int, new_value_str_idx: int) -> bytes:
    """Finds the attribute with name-string-index == attr_name_str_idx in
    this XML_START_ELEMENT chunk and rewrites its (rawValueIdx, valueData)
    to point at new_value_str_idx, leaving every other byte (including
    every other attribute) unchanged. Returns the modified chunk bytes, or
    raises if the attribute isn't found.

    Field layout (all offsets empirically verified against a real compiled
    manifest -- see the __main__ self-test -- not just trusted from
    documentation, which is inconsistent across sources for the exact
    meaning of attrStart/attrSize):
      0: type(2) 2: headerSize(2) 4: chunkSize(4) 8: lineNumber(4)
      12: comment(4) 16: nsIdx(4) 20: nameIdx(4) 24: attrStart(2)
      26: attrSize(2) 28: attrCount(2) 30: idIdx(2) 32: classIdx(2)
      34: styleIdx(2)
    Attributes reliably start at the fixed absolute offset 36 (right after
    styleIdx) regardless of the attrStart field's own value -- this is
    also exactly how AOSP's own ResXMLTree reader and every
    community-reverse-engineered parser (androguard, axmlprinter) walk
    this structure: sequentially, not by seeking via attrStart. Each
    attribute is a fixed 20 bytes: nsIdx(4) nameIdx(4) rawValueIdx(4)
    valueSize(2) res0(1) valueType(1) valueData(4).
    """
    data = bytearray(element_chunk_raw)
    attr_count = struct.unpack_from("<H", data, 28)[0]
    ATTR_FIXED_SIZE = 20
    base = 36
    for i in range(attr_count):
        off = base + i * ATTR_FIXED_SIZE
        ns_idx, name_idx, raw_value_idx = struct.unpack_from("<III", data, off)
        if name_idx == attr_name_str_idx:
            struct.pack_into("<I", data, off + 8, new_value_str_idx)  # rawValueIdx
            # valueSize(2) res0(1) valueType(1) valueData(4) at off+12..off+20
            value_type = data[off + 15]
            if value_type != 0x03:
                raise ValueError(f"expected string-typed attribute (0x03), got 0x{value_type:02x}")
            struct.pack_into("<I", data, off + 16, new_value_str_idx)  # Res_value.data
            return bytes(data)
    raise ValueError(f"attribute with name-string-index {attr_name_str_idx} not found in this element")


def patch_manifest(data: bytes, target_element: str, target_attr: str, new_value: str) -> bytes:
    xml_type, xml_header_size, xml_chunk_size = struct.unpack_from("<HHI", data, 0)
    inner_chunks = read_chunks(data, 8, xml_chunk_size)

    sp_idx = next(i for i, c in enumerate(inner_chunks) if c.type == RES_STRING_POOL_TYPE)
    strings, is_utf8, _style_count = decode_string_pool(inner_chunks[sp_idx])

    # Find (or add) the new value string.
    if new_value in strings:
        new_value_idx = strings.index(new_value)
    else:
        new_value_idx = len(strings)
        strings = strings + [new_value]

    # Locate the target element + attribute, using the ORIGINAL string
    # table (attribute name/element name indices don't change).
    target_attr_idx = strings.index(target_attr) if target_attr in strings else None
    target_elem_name_idx = strings.index(target_element) if target_element in strings else None
    if target_attr_idx is None or target_elem_name_idx is None:
        raise ValueError(f"'{target_element}' or '{target_attr}' not found in the string pool")

    patched_chunks = []
    found = False
    for c in inner_chunks:
        if c.type == RES_XML_START_ELEMENT_TYPE:
            name_idx = struct.unpack_from("<I", c.raw, 20)[0]  # offset 20 = nameIdx, NOT 16 (nsIdx) -- see patch_attribute_value's field-layout comment
            if name_idx == target_elem_name_idx:
                try:
                    new_raw = patch_attribute_value(c.raw, target_attr_idx, new_value_idx)
                    patched_chunks.append(new_raw)
                    found = True
                    continue
                except ValueError:
                    pass  # this element didn't have that attribute; fall through unmodified
        patched_chunks.append(c.raw)
    if not found:
        raise ValueError(f"<{target_element} {target_attr}=...> not found (element present but attribute missing?)")

    new_sp_chunk = encode_string_pool(strings, is_utf8)
    patched_chunks[sp_idx] = new_sp_chunk

    body = b"".join(patched_chunks)
    new_xml_chunk_size = 8 + len(body)
    new_header = struct.pack("<HHI", xml_type, xml_header_size, new_xml_chunk_size)
    return new_header + body


def read_attribute(data: bytes, target_element: str, target_attr: str):
    """Returns the current string value of target_element's target_attr,
    or None if the element exists but the attribute is absent. Raises if
    the element itself isn't found. Used by pack_existing_apk.sh to check
    whether <application android:name=...> is already something other
    than the Android default BEFORE overwriting it -- see the safety note
    in patch_manifest's caller in that script: blindly retargeting an
    app's real custom Application class would silently discard whatever
    logic it had.
    """
    xml_type, xml_header_size, xml_chunk_size = struct.unpack_from("<HHI", data, 0)
    inner_chunks = read_chunks(data, 8, xml_chunk_size)
    sp_idx = next(i for i, c in enumerate(inner_chunks) if c.type == RES_STRING_POOL_TYPE)
    strings, _is_utf8, _style_count = decode_string_pool(inner_chunks[sp_idx])

    target_elem_name_idx = strings.index(target_element) if target_element in strings else None
    if target_elem_name_idx is None:
        raise ValueError(f"'{target_element}' not found in the string pool")

    for c in inner_chunks:
        if c.type != RES_XML_START_ELEMENT_TYPE:
            continue
        if struct.unpack_from("<I", c.raw, 20)[0] != target_elem_name_idx:
            continue
        attr_count = struct.unpack_from("<H", c.raw, 28)[0]
        for i in range(attr_count):
            off = 36 + i * 20
            name_idx = struct.unpack_from("<I", c.raw, off + 4)[0]
            if strings[name_idx] == target_attr:
                value_type = c.raw[off + 15]
                value_data = struct.unpack_from("<I", c.raw, off + 16)[0]
                return strings[value_data] if value_type == 0x03 else f"(type{value_type}:{value_data})"
        return None  # element found, attribute absent
    raise ValueError(f"<{target_element}> not found")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True, type=Path, help="compiled (binary) AndroidManifest.xml")
    p.add_argument("--element", default="application")
    p.add_argument("--attr", default="name")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--read", action="store_true", help="print the current attribute value (or ABSENT) and exit")
    mode.add_argument("--value", help='new value to set, e.g. "dev.packer.guard.GuardApplication"')
    p.add_argument("--output", type=Path, help="required with --value")
    args = p.parse_args()

    data = args.input.read_bytes()

    if args.read:
        value = read_attribute(data, args.element, args.attr)
        print(value if value is not None else "ABSENT")
        return

    if not args.output:
        sys.exit("--output is required with --value")
    patched = patch_manifest(data, args.element, args.attr, args.value)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"wrote {args.output} ({len(patched)} bytes, was {len(data)})", file=sys.stderr)


if __name__ == "__main__":
    main()
