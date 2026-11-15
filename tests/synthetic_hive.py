#!/usr/bin/env python
#
# A minimal, self contained builder for synthetic Windows registry hives.
#
# It only implements the structures needed to exercise subkey index
# traversal (REGF / HBIN / NK / LF / LH / LI / RI cells), which lets the
# corruption tests construct precise index layouts - including cyclic and
# duplicate references that a real registry writer would never produce -
# without depending on external binary fixtures.
from __future__ import print_function
from __future__ import unicode_literals

import struct

HBIN_BASE = 0x1000
HBIN_SIZE = 0x1000
HEADER_SIZE = 0x1000


def _align8(value):
    return (value + 7) & ~7


class Ref(object):
    """A cell allocated in the synthetic hive."""
    def __init__(self, index):
        self.index = index


class SyntheticHive(object):
    def __init__(self):
        # bytearray blobs in allocation order; cell size headers are added at
        # build time, so offsets are computed from blob lengths then.
        self._blobs = []
        # (blob index, offset within blob, target Ref) dword patches
        self._patches = []
        # blob indices that represent free (positive sized) cells
        self._free = set()

    def add_cell(self, data):
        self._blobs.append(bytearray(data))
        return Ref(len(self._blobs) - 1)

    def add_free_cell(self, data_length=16):
        ref = self.add_cell(b"\x00" * data_length)
        self._free.add(ref.index)
        return ref

    def patch_dword(self, holder_ref, field_offset, target_ref):
        self._patches.append((holder_ref.index, field_offset, target_ref))

    # -- structure builders -------------------------------------------------

    def nk(self, name, parent=None, root=False, subkey_count=0,
           subkey_list=None):
        data = bytearray(0x4C + len(name))
        data[0:2] = b"nk"
        flags = 0x20  # ASCII name
        if root:
            flags |= 0x04
        struct.pack_into("<H", data, 0x2, flags)
        # timestamp (0x4) and access bits (0xC) stay zero
        if root:
            struct.pack_into("<I", data, 0x10, 0x4)
        # 0x18 volatile subkey count, 0x20 volatile list stay zero
        struct.pack_into("<I", data, 0x14, subkey_count)
        # no values, no security key, no class name
        struct.pack_into("<i", data, 0x24, -1)
        struct.pack_into("<i", data, 0x28, -1)
        struct.pack_into("<i", data, 0x2C, -1)
        struct.pack_into("<i", data, 0x30, -1)
        struct.pack_into("<H", data, 0x48, len(name))
        struct.pack_into("<H", data, 0x4A, 0)
        data[0x4C:] = name.encode("ascii")
        ref = self.add_cell(bytes(data))
        if not root and parent is not None:
            self.patch_dword(ref, 0x10, parent)
        if subkey_list is not None:
            self.patch_dword(ref, 0x1C, subkey_list)
        return ref
    def direct_list(self, signature, entry_refs):
        entry_size = 8 if signature in (b"lf", b"lh") else 4
        data = bytearray(4 + entry_size * len(entry_refs))
        data[0:2] = signature
        struct.pack_into("<H", data, 0x2, len(entry_refs))
        holder = self.add_cell(bytes(data))
        for index, ref in enumerate(entry_refs):
            self.patch_dword(holder, 4 + index * entry_size, ref)
        return holder

    def ri_list(self, entry_refs):
        data = bytearray(4 + 4 * len(entry_refs))
        data[0:2] = b"ri"
        struct.pack_into("<H", data, 0x2, len(entry_refs))
        holder = self.add_cell(bytes(data))
        for index, ref in enumerate(entry_refs):
            if ref is not None:
                self.patch_dword(holder, 4 + 4 * index, ref)
        return holder

    # -- final assembly -----------------------------------------------------

    def cell_relative(self, ref):
        """Relative offset (from the first HBIN) of an allocated cell."""
        return self._rels[ref.index]

    def cell_abs(self, ref):
        """Absolute buffer offset of an allocated cell."""
        return HBIN_BASE + self._rels[ref.index]

    def build(self, root_ref):
        rels = {}
        cursor = 0x20
        for index, blob in enumerate(self._blobs):
            rels[index] = cursor
            cursor += _align8(4 + len(blob))
        assert cursor <= HBIN_SIZE, "synthetic hive cells overflow a single HBIN"
        self._rels = rels

        for blob_index, field_offset, target_ref in self._patches:
            struct.pack_into("<I", self._blobs[blob_index], field_offset,
                             rels[target_ref.index])

        hbin = bytearray(HBIN_SIZE)
        hbin[0:4] = b"hbin"
        struct.pack_into("<I", hbin, 0x4, 0)
        struct.pack_into("<I", hbin, 0x8, HBIN_SIZE)

        cursor = 0x20
        for index, blob in enumerate(self._blobs):
            total = _align8(4 + len(blob))
            size = total if index in self._free else -total
            struct.pack_into("<i", hbin, cursor, size)
            hbin[cursor + 4:cursor + 4 + len(blob)] = blob
            cursor += total

        header = bytearray(HEADER_SIZE)
        header[0:4] = b"regf"
        struct.pack_into("<I", header, 0x20, 1)  # file format
        struct.pack_into("<I", header, 0x24, rels[root_ref.index])
        struct.pack_into("<I", header, 0x28, HBIN_SIZE)
        checksum = 0
        for offset in range(0, 0x1FC, 4):
            checksum ^= struct.unpack_from("<I", header, offset)[0]
        if checksum == 0:
            checksum = 1
        elif checksum == 0xFFFFFFFF:
            checksum = 0xFFFFFFFE
        struct.pack_into("<I", header, 0x1FC, checksum)

        return bytes(header) + bytes(hbin)
