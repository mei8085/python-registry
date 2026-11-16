#!/usr/bin/env python3
"""
Minimal Windows registry hive (REGF/HBIN/NK/VK/LF) builder.

Builds synthetic but structurally valid primary hive files so that
python-registry can parse them. Used to construct name/path edge cases
(compressed names, UTF-16 surrogates, case-equivalent names, embedded
NUL characters) that the Windows API would normally refuse to create.

Only supports what the experiment needs:
  - one HBIN
  - nk records (root + subkeys), vk records, lf subkey lists,
    value lists, and raw data cells
"""

import struct


def _align8(n):
    return (n + 7) & ~7


class HiveBuilder(object):
    def __init__(self, hive_name="$$$PROTO.HIV"):
        self._cells = bytearray()
        self._hbin_data_start = 0x20  # first cell, relative to hbin start
        self.hive_name = hive_name

    # ------------------------------------------------------------------
    # cell allocation
    # ------------------------------------------------------------------
    def _alloc(self, payload):
        """Place a cell with the given payload, return its hive-relative offset."""
        size = _align8(4 + len(payload))
        offset = self._hbin_data_start + len(self._cells)
        cell = struct.pack("<i", -size) + payload
        cell += b"\x00" * (size - len(cell))
        self._cells += cell
        return offset

    # ------------------------------------------------------------------
    # record builders
    # ------------------------------------------------------------------
    def patch_dword(self, cell_offset, rec_rel_offset, value):
        """Patch a dword inside an already-allocated record.
        cell_offset: hive-relative cell offset returned by _alloc/add_*.
        rec_rel_offset: offset within the record payload (after the 4-byte
        cell size header)."""
        pos = (cell_offset - self._hbin_data_start) + 4 + rec_rel_offset
        struct.pack_into("<I", self._cells, pos, value)

    def add_data_cell(self, data):
        return self._alloc(data)

    def add_nk(self, name_bytes, is_root=False, ascii_name=False,
               parent_offset=0xFFFFFFFF, subkey_count=0,
               subkey_list_offset=0xFFFFFFFF, value_count=0,
               values_list_offset=0xFFFFFFFF, timestamp=0):
        flags = 0x0000
        if is_root:
            flags |= 0x0004  # KEY_HIVE_ENTRY (is_root per python-registry)
        if ascii_name:
            flags |= 0x0020  # KEY_COMP_NAME (compressed/ASCII name)
        rec = b"nk"
        rec += struct.pack("<H", flags)          # 0x02 flags
        rec += struct.pack("<Q", timestamp)      # 0x04 last write
        rec += struct.pack("<I", 0)              # 0x0C access bits
        rec += struct.pack("<I", parent_offset)  # 0x10 parent
        rec += struct.pack("<I", subkey_count)   # 0x14 stable subkey count
        rec += struct.pack("<I", 0)              # 0x18 volatile subkey count
        rec += struct.pack("<I", subkey_list_offset)   # 0x1C stable list
        rec += struct.pack("<I", 0xFFFFFFFF)     # 0x20 volatile list
        rec += struct.pack("<I", value_count)    # 0x24 value count
        rec += struct.pack("<I", values_list_offset)   # 0x28 values list
        rec += struct.pack("<I", 0xFFFFFFFF)     # 0x2C sk
        rec += struct.pack("<I", 0xFFFFFFFF)     # 0x30 class name
        rec += b"\x00" * 0x14                    # 0x34..0x47 misc
        rec += struct.pack("<H", len(name_bytes))  # 0x48 name length
        rec += struct.pack("<H", 0)              # 0x4A class name length
        rec += name_bytes                        # 0x4C name
        return self._alloc(rec)

    def add_vk(self, name_bytes, data_type, data, ascii_name=False,
               data_size_override=None):
        """Add a vk record. `data` is stored in a separate cell unless it
        fits inline (<=4 bytes). data_size_override lets tests lie about
        the declared size."""
        if len(data) <= 4:
            inline = data + b"\x00" * (4 - len(data))
            size_field = 0x80000000 | len(data)
            data_field = inline
        else:
            data_off = self._alloc(data)
            size_field = len(data)
            data_field = struct.pack("<I", data_off)
        if data_size_override is not None:
            size_field = data_size_override
        rec = b"vk"
        rec += struct.pack("<H", len(name_bytes))   # 0x02 name length
        rec += struct.pack("<I", size_field)        # 0x04 data size
        rec += data_field                           # 0x08 data offset/inline
        rec += struct.pack("<I", data_type)         # 0x0C type
        rec += struct.pack("<H", 1 if ascii_name else 0)  # 0x10 flags
        rec += struct.pack("<H", 0)                 # 0x12 spare
        rec += name_bytes                           # 0x14 name
        return self._alloc(rec)

    def add_lf(self, entries):
        """entries: list of (nk_offset, hash4bytes)."""
        rec = b"lf"
        rec += struct.pack("<H", len(entries))
        for off, h in entries:
            rec += struct.pack("<I", off) + h
        return self._alloc(rec)

    def add_values_list(self, vk_offsets):
        payload = b"".join(struct.pack("<I", o) for o in vk_offsets)
        return self._alloc(payload)

    # ------------------------------------------------------------------
    # final assembly
    # ------------------------------------------------------------------
    def build(self, root_offset):
        hbin_size = _align8(0x20 + len(self._cells))
        hbin_size = (hbin_size + 0xFFF) & ~0xFFF  # hbin multiple of 0x1000

        regf = bytearray(0x1000)
        regf[0x00:0x04] = b"regf"
        struct.pack_into("<I", regf, 0x04, 1)     # seq1
        struct.pack_into("<I", regf, 0x08, 1)     # seq2
        struct.pack_into("<Q", regf, 0x0C, 0)     # timestamp
        struct.pack_into("<I", regf, 0x14, 1)     # major
        struct.pack_into("<I", regf, 0x18, 3)     # minor
        struct.pack_into("<I", regf, 0x1C, 0)     # primary file
        struct.pack_into("<I", regf, 0x20, 1)     # format
        struct.pack_into("<I", regf, 0x24, root_offset)  # root cell
        struct.pack_into("<I", regf, 0x28, hbin_size)    # hbins size
        struct.pack_into("<I", regf, 0x2C, 1)     # clustering
        name = self.hive_name.encode("utf-16le")[:64]
        regf[0x30:0x30 + len(name)] = name
        # checksum: XOR of dwords 0x00..0x1FB
        xsum = 0
        for i in range(0, 0x1FC, 4):
            xsum ^= struct.unpack_from("<I", regf, i)[0]
        if xsum == 0:
            xsum = 1
        elif xsum == 0xFFFFFFFF:
            xsum = 0xFFFFFFFE
        struct.pack_into("<I", regf, 0x1FC, xsum)

        hbin = bytearray(hbin_size)
        hbin[0x00:0x04] = b"hbin"
        struct.pack_into("<I", hbin, 0x04, 0)          # offset from first hbin
        struct.pack_into("<I", hbin, 0x08, hbin_size)  # hbin size
        hbin[0x20:0x20 + len(self._cells)] = self._cells

        return bytes(regf) + bytes(hbin)


def write_hive(path, builder, root_offset):
    with open(path, "wb") as f:
        f.write(builder.build(root_offset))
