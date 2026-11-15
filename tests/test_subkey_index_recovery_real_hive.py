#!/usr/bin/env python
#
# Integration tests that corrupt a real, well formed hive on disk
# (UNICODE_TESTS) and confirm the resilient traversal still extracts every
# unaffected key while recording locatable SubkeyIndexError entries.
from __future__ import print_function
from __future__ import unicode_literals

import io
import os
import struct

from Registry import Registry
from Registry.RegistryParse import SubkeyTraversal, SubkeyIndexErrorKind

SAMPLE = os.path.join(os.path.dirname(__file__), "reg_samples", "UNICODE_TESTS")

# The hive's root LF record data starts at 0x138c; its two 8-byte entries
# hold their NK offsets at these absolute file positions.
ENTRY0_OFFSET_FIELD = 0x1390
ENTRY1_OFFSET_FIELD = 0x1398
NK0_REL = 0x180   # ASCII_KEY_NAME0
NK1_REL = 0xAD0   # UNICODE_JUMBLE_...
FREE_CELL_REL = 0x248
LF_CELL_REL = 0x388


def _mutated_registry(patches):
    with open(SAMPLE, "rb") as f:
        buf = bytearray(f.read())
    for field, value in patches:
        struct.pack_into("<I", buf, field, value)
    return Registry.Registry(io.BytesIO(bytes(buf)))


def test_duplicate_entry_on_real_hive_is_deduped():
    reg = _mutated_registry([(ENTRY1_OFFSET_FIELD, NK0_REL)])
    traversal = SubkeyTraversal()
    subkeys = reg.root().subkeys(traversal)

    assert [k.name() for k in subkeys] == ["ASCII_KEY_NAME0"]
    assert len(traversal.errors) == 1
    error = traversal.errors[0]
    assert error.kind == SubkeyIndexErrorKind.DUPLICATE_REFERENCE
    assert error.list_type == b"lf"
    assert error.entry_index == 1
    assert error.referenced_offset == 0x1000 + NK0_REL


def test_free_cell_entry_on_real_hive_is_skipped_sibling_survives():
    reg = _mutated_registry([(ENTRY0_OFFSET_FIELD, FREE_CELL_REL)])
    traversal = SubkeyTraversal()
    subkeys = reg.root().subkeys(traversal)

    assert [k.name() for k in subkeys] == ["UNICODE_JUMBLE_{H~░ô«}"]
    assert len(traversal.errors) == 1
    error = traversal.errors[0]
    assert error.kind == SubkeyIndexErrorKind.INVALID_REFERENCE
    assert error.entry_index == 0
    assert error.referenced_offset == 0x1000 + FREE_CELL_REL
    assert error.parent_key_path == "UNICODE_TESTS"


def test_non_nk_entry_on_real_hive_is_invalid():
    reg = _mutated_registry([(ENTRY0_OFFSET_FIELD, LF_CELL_REL)])
    traversal = SubkeyTraversal()
    subkeys = reg.root().subkeys(traversal)

    assert [k.name() for k in subkeys] == ["UNICODE_JUMBLE_{H~░ô«}"]
    assert traversal.errors[0].kind == SubkeyIndexErrorKind.INVALID_REFERENCE


def test_out_of_range_entry_on_real_hive_does_not_kill_walk():
    reg = _mutated_registry([(ENTRY1_OFFSET_FIELD, 0xFFFFF000)])
    walked = list(reg.walk())
    walked_names = [k.path() for k in walked]

    assert walked_names[0] == "UNICODE_TESTS"
    assert "UNICODE_TESTS\\ASCII_KEY_NAME0" in walked_names
    assert len(reg.recovery_errors()) == 1
    assert (reg.recovery_errors()[0].kind
            == SubkeyIndexErrorKind.INVALID_REFERENCE)

    # a second independent walk yields the same recoverable evidence
    assert [k.path() for k in reg.walk()] == walked_names
