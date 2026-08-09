#!/usr/bin/env python3
"""Produce the two fixed-base RTTI fixture images from one linked DLL.

Both outputs keep the link's image base, SizeOfImage, and PE TimeDateStamp, so an identity folded from those three
fields alone reports them as the same image. Variant B differs in a section header name and in the mangled type name
its RTTI graph publishes, which is exactly the same-base section-layout replacement the public image_generation
contract must catch.

The rewrite is deliberately narrow: a section NAME is inert to the loader (sections are mapped by RVA and size, and
the data directories address their contents by RVA, never by name), and the type-name patch is an equal-length
in-place byte swap, so neither output differs from the link in size, layout, or relocations.

Every step fails closed. A header that does not parse, a section name that is already taken, or a type-name run that
does not appear exactly once aborts without writing an output, because a fixture that silently degrades into two
identical images would let the proof pass without proving anything.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
SECTION_HEADER_BYTES = 40
SECTION_NAME_BYTES = 8

class FixtureError(RuntimeError):
    pass


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_pe(data: bytes) -> dict:
    """Returns the offsets this script needs, validating every field it depends on."""
    if len(data) < 0x40 or _u16(data, 0) != IMAGE_DOS_SIGNATURE:
        raise FixtureError("not a DOS image")
    nt_offset = _u32(data, 0x3C)
    if nt_offset <= 0 or nt_offset + 0x108 > len(data):
        raise FixtureError(f"implausible e_lfanew {nt_offset:#x}")
    if _u32(data, nt_offset) != IMAGE_NT_SIGNATURE:
        raise FixtureError("missing PE signature")

    file_header = nt_offset + 4
    number_of_sections = _u16(data, file_header + 2)
    timestamp_offset = file_header + 4
    size_of_optional = _u16(data, file_header + 16)
    optional_header = file_header + 20
    if _u16(data, optional_header) != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        raise FixtureError("not a PE32+ image")
    if number_of_sections == 0 or number_of_sections > 96:
        raise FixtureError(f"implausible section count {number_of_sections}")

    section_table = optional_header + size_of_optional
    if section_table + number_of_sections * SECTION_HEADER_BYTES > len(data):
        raise FixtureError("section table runs past the end of the file")

    return {
        "timestamp_offset": timestamp_offset,
        "size_of_image_offset": optional_header + 56,
        "section_table": section_table,
        "number_of_sections": number_of_sections,
    }


def section_names(data: bytes, layout: dict) -> list[str]:
    names = []
    for index in range(layout["number_of_sections"]):
        start = layout["section_table"] + index * SECTION_HEADER_BYTES
        names.append(data[start : start + SECTION_NAME_BYTES].rstrip(b"\0").decode("latin-1"))
    return names


def force_timestamp(data: bytearray, layout: dict, timestamp: int) -> None:
    struct.pack_into("<I", data, layout["timestamp_offset"], timestamp)


def rename_section(data: bytearray, layout: dict, target: str, replacement: str) -> None:
    """Renames one section header in place, which is what moves the section digest without moving a byte of content."""
    encoded = replacement.encode("latin-1")
    if len(encoded) > SECTION_NAME_BYTES:
        raise FixtureError(f"replacement name {replacement!r} exceeds {SECTION_NAME_BYTES} bytes")
    names = section_names(bytes(data), layout)
    if replacement in names:
        raise FixtureError(f"replacement name {replacement!r} is already used by this image")
    if target not in names:
        raise FixtureError(f"section {target!r} not present; image has {names}")
    index = names.index(target)
    start = layout["section_table"] + index * SECTION_HEADER_BYTES
    data[start : start + SECTION_NAME_BYTES] = encoded.ljust(SECTION_NAME_BYTES, b"\0")


def patch_type_name(data: bytearray, original: str, replacement: str) -> None:
    """Swaps the fixture's mangled type name for an equal-length one, so no offset in the image moves."""
    if len(original) != len(replacement):
        raise FixtureError("the two type names must be the same length")
    encoded = original.encode("ascii")
    occurrences = bytes(data).count(encoded)
    if occurrences != 1:
        raise FixtureError(f"expected exactly one copy of {original!r} in the image, found {occurrences}")
    offset = bytes(data).index(encoded)
    data[offset : offset + len(encoded)] = replacement.encode("ascii")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="the linked fixture DLL")
    parser.add_argument("--variant-a", required=True, type=Path)
    parser.add_argument("--variant-b", required=True, type=Path)
    parser.add_argument("--type-name-a", required=True)
    parser.add_argument("--type-name-b", required=True)
    parser.add_argument("--rename-section", default=".rdata")
    parser.add_argument("--rename-section-to", default=".rdatB")
    parser.add_argument("--timestamp", type=lambda value: int(value, 0), default=0x4D4B0001)
    args = parser.parse_args(argv)

    source = args.input.read_bytes()
    layout = parse_pe(source)

    variant_a = bytearray(source)
    force_timestamp(variant_a, layout, args.timestamp)

    variant_b = bytearray(source)
    force_timestamp(variant_b, layout, args.timestamp)
    rename_section(variant_b, layout, args.rename_section, args.rename_section_to)
    patch_type_name(variant_b, args.type_name_a, args.type_name_b)

    # The proof rests on these three fields matching and the images still differing, so assert it here rather than
    # discovering a degenerate pair as a passing test.
    if _u32(bytes(variant_a), layout["size_of_image_offset"]) != _u32(bytes(variant_b), layout["size_of_image_offset"]):
        raise FixtureError("the variants disagree on SizeOfImage")
    if _u32(bytes(variant_a), layout["timestamp_offset"]) != _u32(bytes(variant_b), layout["timestamp_offset"]):
        raise FixtureError("the variants disagree on TimeDateStamp")
    if bytes(variant_a) == bytes(variant_b):
        raise FixtureError("the variants are byte-identical; the rewrite did nothing")

    args.variant_a.write_bytes(bytes(variant_a))
    args.variant_b.write_bytes(bytes(variant_b))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except FixtureError as error:
        print(f"prepare_rtti_generation_fixtures: {error}", file=sys.stderr)
        sys.exit(1)
