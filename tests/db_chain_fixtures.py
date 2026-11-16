#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic builders for registry hives that exercise large-value "db" chains.

The hives are minimal, syntactically valid primary hives:

    REGF (0x1000) + one HBIN with the following cells:

        nk (root, one value) -> values list -> vk -> db -> indirect -> segments

Every sample is generated from bytes only, without timestamps or randomness, so
the fixtures can be regenerated and compared byte-for-byte (see
``tests/test_db_chain_integration.py``).

Run this module to (re)write the committed fixtures::

    python3 tests/db_chain_fixtures.py tests/reg_samples/db_chain
"""

from __future__ import print_function

import os
import struct
import sys

# Registry value types (kept local so this script does not depend on the parser).
REG_SZ = 0x0001
REG_BIN = 0x0003

HBIN_START = 0x1000
HBIN_HEADER_SIZE = 0x20
CELL_OVERHEAD = 4

#: Maximum payload stored in a single DB chain segment (as used by the parser).
SEGMENT_SIZE = 0x3FD8

#: Neighbour cells are filled with this byte; it must never leak into results.
POISON_BYTE = 0xA5

#: Value name used by every fixture.
VALUE_NAME = "Big"

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "reg_samples", "db_chain")


def payload_for(length):
    """Deterministic payload that deliberately avoids ``POISON_BYTE``."""
    return bytes(bytearray(((i * 37 + 11) % 0x80) for i in range(length)))


def _checksum(buf):
    xsum = 0
    for idx in range(0, 0x200, 4):
        xsum ^= struct.unpack_from("<I", buf, idx)[0]
    if xsum == 0:
        return 1
    if xsum == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return xsum


class HiveBuilder(object):
    """Builds a one-HBIN hive with cells allocated in insertion order."""

    def __init__(self):
        self._cells = []  # (name, size, fill)
        self._locations = {}

    def add(self, name, size, fill):
        """Reserve a cell of ``size`` bytes (including the 4 byte size field)."""
        if size < CELL_OVERHEAD or size % 4 != 0:
            raise ValueError("cell %s must have a dword-aligned size >= 4" % name)
        if name in self._locations:
            raise ValueError("duplicate cell name %s" % name)
        self._cells.append((name, size, fill))
        self._locations[name] = None

    def rel(self, name):
        """Offset of ``name`` relative to the first HBIN."""
        off = self._locations[name]
        if off is None:
            raise ValueError("cell %s was not allocated yet" % name)
        return off - HBIN_START

    def _layout(self, hbin_size):
        off = HBIN_START + HBIN_HEADER_SIZE
        for name, size, _ in self._cells:
            self._locations[name] = off
            off += size
        if off > HBIN_START + hbin_size:
            raise ValueError("cells do not fit in HBIN")
        return off

    def build(self, hbin_size=0x10000):
        end = self._layout(hbin_size)

        cells = bytearray()
        for name, size, fill in self._cells:
            data = fill() if callable(fill) else fill
            if len(data) > size - CELL_OVERHEAD:
                raise ValueError("payload of %s does not fit" % name)
            cells += struct.pack("<i", -size)
            cells += data
            cells += b"\x00" * (size - CELL_OVERHEAD - len(data))

        hbin = bytearray(hbin_size)
        hbin[0x0:0x4] = b"hbin"
        struct.pack_into("<I", hbin, 0x4, 0)            # offset from first HBIN
        struct.pack_into("<I", hbin, 0x8, hbin_size)    # offset of next HBIN
        hbin[HBIN_HEADER_SIZE:] = cells

        regf = bytearray(0x1000)
        regf[0x0:0x4] = b"regf"
        struct.pack_into("<I", regf, 0x4, 1)            # sequence 1
        struct.pack_into("<I", regf, 0x8, 1)            # sequence 2
        struct.pack_into("<Q", regf, 0xC, 0)            # timestamp
        struct.pack_into("<I", regf, 0x14, 1)           # major version
        struct.pack_into("<I", regf, 0x18, 5)           # minor version
        struct.pack_into("<I", regf, 0x1C, 0)           # primary file
        struct.pack_into("<I", regf, 0x20, 1)           # file format
        struct.pack_into("<I", regf, 0x24, self.rel("nk"))  # root key cell
        struct.pack_into("<I", regf, 0x28, hbin_size)   # total HBIN size
        struct.pack_into("<I", regf, 0x2C, 1)           # clustering factor
        name = "\\??\\C:\\db_chain.hive".encode("utf-16le")[:64]
        regf[0x30:0x30 + len(name)] = name
        struct.pack_into("<I", regf, 0x1FC, _checksum(regf))

        assert end <= HBIN_START + hbin_size
        return bytes(regf) + bytes(hbin)


def _nk_fill(builder, values_number):
    key_name = b"ROOT"

    def fill():
        data = bytearray(0x4C + len(key_name))
        data[0x0:0x2] = b"nk"
        struct.pack_into("<H", data, 0x2, 0x0004 | 0x0020)  # root + ascii name
        struct.pack_into("<Q", data, 0x4, 0)
        struct.pack_into("<I", data, 0xC, 0)
        struct.pack_into("<I", data, 0x10, 0xFFFFFFFF)     # no parent
        struct.pack_into("<I", data, 0x14, 0xFFFFFFFF)     # no subkeys
        struct.pack_into("<I", data, 0x1C, 0xFFFFFFFF)
        struct.pack_into("<I", data, 0x24, values_number)
        struct.pack_into("<I", data, 0x28, builder.rel("values"))
        struct.pack_into("<I", data, 0x2C, 0xFFFFFFFF)
        struct.pack_into("<I", data, 0x30, 0xFFFFFFFF)
        struct.pack_into("<H", data, 0x48, len(key_name))
        struct.pack_into("<H", data, 0x4A, 0)
        data[0x4C:] = key_name
        return bytes(data)

    return fill


def _values_fill(builder):
    def fill():
        return struct.pack("<I", builder.rel("vk"))
    return fill


def _vk_fill(builder, data_length, data_offset, data_type, value_name=VALUE_NAME):
    name = value_name.encode("ascii")

    def fill():
        data = bytearray(0x14 + len(name))
        data[0x0:0x2] = b"vk"
        struct.pack_into("<H", data, 0x2, len(name))
        struct.pack_into("<I", data, 0x4, data_length)
        if callable(data_offset):
            off = data_offset()
        else:
            off = data_offset
        struct.pack_into("<I", data, 0x8, off)
        struct.pack_into("<I", data, 0xC, data_type)
        struct.pack_into("<H", data, 0x10, 1)  # ascii name
        data[0x14:] = name
        return bytes(data)

    return fill


def _db_fill(builder, target="indirect"):
    def fill():
        return b"db" + b"\x02\x00" + struct.pack("<I", builder.rel(target))
    return fill


def _indirect_fill(builder, entries):
    """``entries`` is a list of segment cell names or raw dwords."""
    def fill():
        out = bytearray()
        for entry in entries:
            if isinstance(entry, str):
                out += struct.pack("<I", builder.rel(entry))
            else:
                out += struct.pack("<I", entry)
        return bytes(out)
    return fill


def _poison_fill(length):
    return bytearray([POISON_BYTE]) * length


def _round_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def _segments_for(length):
    sizes = []
    remaining = length
    while remaining > 0:
        take = min(SEGMENT_SIZE, remaining)
        sizes.append(take)
        remaining -= take
    return sizes


def _build_chain_hive(payload, data_type, indirect_entries=None, extra_cells=()):
    """Build a hive whose single value is stored in a db segment chain.

    ``payload`` is split into segments of at most ``SEGMENT_SIZE`` bytes.
    ``indirect_entries`` overrides the dwords of the indirect block (used for
    malformed samples); by default it names every segment.  ``extra_cells`` is
    a list of ``(name, size, fill)`` appended after the segments.
    """
    length = len(payload)
    segment_sizes = _segments_for(length)

    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length, lambda: builder.rel("db"), data_type))
    builder.add("db", CELL_OVERHEAD + 12, _db_fill(builder))

    if indirect_entries is None:
        indirect_entries = ["seg%d" % i for i in range(len(segment_sizes))]
    builder.add("indirect", CELL_OVERHEAD + 4 * len(indirect_entries),
                _indirect_fill(builder, indirect_entries))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))

    offset = 0
    for index, size in enumerate(segment_sizes):
        piece = payload[offset:offset + size]
        offset += size
        builder.add("seg%d" % index, _round_up(CELL_OVERHEAD + len(piece), 4), piece)
    for name, size, fill in extra_cells:
        builder.add(name, size, fill)

    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    return builder.build(hbin_size=_round_up(total, 0x1000))


def build_normal(length, data_type=REG_BIN):
    """A well-formed large value whose payload is ``length`` bytes."""
    return _build_chain_hive(payload_for(length), data_type)


def build_normal_string(length):
    """A well-formed large RegSZ value (NUL terminated).

    Returns ``(hive_bytes, decoded_text, raw_payload)``.
    """
    text = "A" * max(0, length // 2 - 1)
    payload = text.encode("utf-16le") + b"\x00\x00"
    return _build_chain_hive(payload, REG_SZ), text, payload


def build_out_of_range_index():
    """Declared length requires 3 segments; the indirect block has room for 2.

    The hive is large enough (three real segment cells are present) so the
    only defect is the number of indirect entries: the third lookup would
    have to read the entry immediately after the indirect cell, i.e. into a
    neighbouring cell.
    """
    length = SEGMENT_SIZE * 3
    pieces = [payload_for(SEGMENT_SIZE) for _ in range(3)]
    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length, lambda: builder.rel("db"), REG_BIN))
    builder.add("db", CELL_OVERHEAD + 12, _db_fill(builder))
    # Two slots only: the third lookup would read the neighbouring poison cell.
    builder.add("indirect", CELL_OVERHEAD + 4 * 2,
                _indirect_fill(builder, ["seg0", "seg1"]))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    for i, piece in enumerate(pieces):
        builder.add("seg%d" % i, _round_up(CELL_OVERHEAD + len(piece), 4), piece)
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    return builder.build(hbin_size=_round_up(total, 0x1000))


def build_out_of_range_offset():
    """The second indirect entry points at an offset far outside the hive.

    The indirect block has enough entries for the declared length; the first
    entry is valid, the second one resolves outside the HBIN region.
    """
    length = SEGMENT_SIZE + 0x100
    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length, lambda: builder.rel("db"), REG_BIN))
    builder.add("db", CELL_OVERHEAD + 12, _db_fill(builder))
    builder.add("indirect", CELL_OVERHEAD + 4 * 2,
                _indirect_fill(builder, ["seg0", 0x40000000]))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    builder.add("seg0", _round_up(CELL_OVERHEAD + SEGMENT_SIZE, 4),
                payload_for(SEGMENT_SIZE))
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    return builder.build(hbin_size=_round_up(total, 0x1000))


def build_duplicate_segments():
    """The same segment cell is referenced twice.

    Two distinct segment cells are present (so the file is large enough for
    the declared length), but the indirect block names the first one twice.
    """
    length = SEGMENT_SIZE * 2
    pieces = [payload_for(SEGMENT_SIZE), bytearray([0x5A]) * SEGMENT_SIZE]
    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length, lambda: builder.rel("db"), REG_BIN))
    builder.add("db", CELL_OVERHEAD + 12, _db_fill(builder))
    builder.add("indirect", CELL_OVERHEAD + 4 * 2,
                _indirect_fill(builder, ["seg0", "seg0"]))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    for i, piece in enumerate(pieces):
        builder.add("seg%d" % i, _round_up(CELL_OVERHEAD + len(piece), 4), piece)
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    return builder.build(hbin_size=_round_up(total, 0x1000))


def build_declared_length_overflow():
    """A ~2 GiB declared length against a single-segment chain."""
    length = 0x7FFFFFFF
    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length, lambda: builder.rel("db"), REG_BIN))
    builder.add("db", CELL_OVERHEAD + 12, _db_fill(builder))
    builder.add("indirect", CELL_OVERHEAD + 4, _indirect_fill(builder, ["seg0"]))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    builder.add("seg0", _round_up(CELL_OVERHEAD + SEGMENT_SIZE, 4),
                payload_for(SEGMENT_SIZE))
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    return builder.build(hbin_size=_round_up(total, 0x1000))


def build_inline_length_overflow(raw_length=0xFFFFFFFF):
    """High bit set ("inline") but the masked length exceeds the 4 byte field."""
    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, raw_length, 0, REG_BIN))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    return builder.build(hbin_size=_round_up(total, 0x1000))


def build_truncated_hbin():
    """A two-segment chain whose file is cut inside the first segment.

    Returns ``(hive_bytes, expected_prefix_length)``.
    """
    length = SEGMENT_SIZE + 0x100
    payload = payload_for(length)
    first, second = payload[:SEGMENT_SIZE], payload[SEGMENT_SIZE:]

    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length, lambda: builder.rel("db"), REG_BIN))
    builder.add("db", CELL_OVERHEAD + 12, _db_fill(builder))
    builder.add("indirect", CELL_OVERHEAD + 4 * 2,
                _indirect_fill(builder, ["seg0", "seg1"]))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    builder.add("seg0", _round_up(CELL_OVERHEAD + SEGMENT_SIZE, 4), first)
    builder.add("seg1", _round_up(CELL_OVERHEAD + len(second), 4), second)

    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    hive = builder.build(hbin_size=_round_up(total, 0x1000))
    builder._layout(_round_up(total, 0x1000))
    cut = builder._locations["seg0"] + CELL_OVERHEAD + SEGMENT_SIZE - 0x80
    return hive[:cut], SEGMENT_SIZE - 0x80


def build_segment_size_overrun():
    """A segment cell whose size field runs past the end of the HBIN."""
    length = SEGMENT_SIZE + 0x100
    payload = payload_for(length)
    first, second = payload[:SEGMENT_SIZE], payload[SEGMENT_SIZE:]

    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length, lambda: builder.rel("db"), REG_BIN))
    builder.add("db", CELL_OVERHEAD + 12, _db_fill(builder))
    builder.add("indirect", CELL_OVERHEAD + 4 * 2,
                _indirect_fill(builder, ["seg0", "seg1"]))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    builder.add("seg0", _round_up(CELL_OVERHEAD + len(first), 4), first)
    builder.add("seg1", _round_up(CELL_OVERHEAD + len(second), 4), second)
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    hbin_size = _round_up(total, 0x1000)
    hive = bytearray(builder.build(hbin_size=hbin_size))
    builder._layout(hbin_size)

    # Rewrite the first segment's size so that it runs past the HBIN end.
    seg = builder._locations["seg0"]
    oversized = (HBIN_START + hbin_size - seg) + 0x1000
    struct.pack_into("<i", hive, seg, -oversized)
    return bytes(hive)


def build_indirect_free_cell():
    """The db record points at a free cell instead of the indirect block."""
    length = SEGMENT_SIZE + 0x100
    payload = payload_for(length)
    first, second = payload[:SEGMENT_SIZE], payload[SEGMENT_SIZE:]

    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length, lambda: builder.rel("db"), REG_BIN))
    builder.add("db", CELL_OVERHEAD + 12, _db_fill(builder, "free"))
    builder.add("free", CELL_OVERHEAD + 8, b"\x00\x00\x00\x00")
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    builder.add("seg0", _round_up(CELL_OVERHEAD + len(first), 4), first)
    builder.add("seg1", _round_up(CELL_OVERHEAD + len(second), 4), second)
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    hbin_size = _round_up(total, 0x1000)
    hive = bytearray(builder.build(hbin_size=hbin_size))
    builder._layout(hbin_size)

    # Mark the target cell free (positive size).
    struct.pack_into("<i", hive, builder._locations["free"],
                     CELL_OVERHEAD + 8)
    return bytes(hive)



def build_mid_cell_pointer():
    """The vk data pointer lands inside a cell instead of at its start.

    A reader that trusts the size field at that offset treats payload bytes as
    a cell size and splices the neighbouring cell into the value.
    """
    length = SEGMENT_SIZE + 0x100
    payload = payload_for(length)
    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    # Point at the middle of a large payload cell rather than at the db cell.
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, length,
                         lambda: builder.rel("seg0") + 0x40, REG_BIN))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    builder.add("seg0", _round_up(CELL_OVERHEAD + len(payload), 4), payload)
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    return builder.build(hbin_size=_round_up(total, 0x1000))


def build_unflagged_inline(data_length):
    """A value of <= 4 bytes that omits the inline high bit.

    Such writers store the bytes in the 0x8 dword without setting it.  The
    reader must return exactly those bytes and never run on into the data type
    and flags fields that follow.
    """
    # Distinctive bytes in the 0x8 dword so a leak of the following data type
    # field (0x00000003) is immediately visible.
    inline_bytes = 0x44332211
    builder = HiveBuilder()
    builder.add("nk", _round_up(CELL_OVERHEAD + 0x4C + 4, 4), _nk_fill(builder, 1))
    builder.add("values", CELL_OVERHEAD + 4, _values_fill(builder))
    builder.add("vk", _round_up(CELL_OVERHEAD + 0x14 + len(VALUE_NAME), 4),
                _vk_fill(builder, data_length, inline_bytes, REG_BIN))
    builder.add("poison", CELL_OVERHEAD + 0x80, _poison_fill(0x80))
    total = HBIN_HEADER_SIZE + sum(size for _, size, _ in builder._cells)
    return builder.build(hbin_size=_round_up(total, 0x1000))


SAMPLES = {
    "normal_bin_16345.hive": lambda: build_normal(SEGMENT_SIZE + 1),
    "normal_bin_32736.hive": lambda: build_normal(SEGMENT_SIZE * 2),
    "normal_bin_32955.hive": lambda: build_normal(SEGMENT_SIZE * 2 + 0x123),
    "normal_sz_32736.hive": lambda: build_normal_string(SEGMENT_SIZE * 2)[0],
    "normal_inline_unflagged.hive": lambda: build_unflagged_inline(3),
    "bad_index.hive": build_out_of_range_index,
    "bad_offset.hive": build_out_of_range_offset,
    "bad_duplicate.hive": build_duplicate_segments,
    "bad_length_overflow.hive": build_declared_length_overflow,
    "bad_inline_overflow_ffffffff.hive": lambda: build_inline_length_overflow(0xFFFFFFFF),
    "bad_inline_overflow_80000005.hive": lambda: build_inline_length_overflow(0x80000005),
    "bad_truncated_hbin.hive": lambda: build_truncated_hbin()[0],
    "bad_segment_size_overrun.hive": build_segment_size_overrun,
    "bad_indirect_free.hive": build_indirect_free_cell,
    "bad_mid_cell_pointer.hive": build_mid_cell_pointer,
}


def build_all(directory):
    """Write every fixture into ``directory`` and return ``{name: bytes}``."""
    if not os.path.isdir(directory):
        os.makedirs(directory)
    built = {}
    for name in sorted(SAMPLES):
        data = SAMPLES[name]()
        with open(os.path.join(directory, name), "wb") as f:
            f.write(data)
        built[name] = data
    return built


def main(argv):
    destination = argv[1] if len(argv) > 1 else SAMPLE_DIR
    built = build_all(destination)
    for name in sorted(built):
        print("%s %d" % (name, len(built[name])))
    return 0


# Names tests need to know about.
TRUNCATED_EXPECTED_LENGTH = SEGMENT_SIZE - 0x80


if __name__ == "__main__":
    sys.exit(main(sys.argv))
