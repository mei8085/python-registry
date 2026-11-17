#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Integration tests for the dirty-page replay boundaries of the transaction
log recovery chain (RegistryParse.REGFBlock.log_entries ->
RegistryLog.RegistryLog.recover_hive / recover_hive_continue).

A transaction log entry declares, for every dirty page, a target range in the
primary hive (offset relative to the first HBIN plus a length carded inline in
the entry) and, for the whole entry, the size of the HBIN area the primary
file should have afterwards. Replay must never let a page escape that
declared extent: a crafted or damaged log may not overwrite the REGF header,
the slack between HBINs, or the tail of the primary file that the entry never
owned.

The tests build new-format transaction logs on top of the small, checked-in
issue22.hive sample (one 0x1000 byte HBIN with a large free cell), so a dirty
page can carry a copy of the HBIN with an inspector marker scribbled into the
free cell. That makes every applied (or refused) write directly observable
through the public Registry API without any external service.

The last group uses the checked-in new_log_1/SYSTEM + LOG1 + LOG2 samples to
exercise the same chain against a real dual-log recovery.
"""
from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import io
import os
import struct

import pytest

from Registry import Registry
from Registry import RegistryLog
from Registry import RegistryParse
from Registry.RegistryParse import (
    LOG_ENTRY_SIZE_ALIGNMENT,
    LOG_ENTRY_SIZE_HEADER,
)

HERE = os.path.dirname(os.path.abspath(__file__))
HIVE_PATH = os.path.join(HERE, "reg_samples", "issue22.hive")
REAL_HIVE_DIR = os.path.join(os.path.dirname(HERE), "testing", "reg_samples", "new_log_1")

HVLE_ID = 0x454C7648
HBIN_ID = 0x6E696268
FILE_TYPE_LOG_NEW = 6

# Markers live in the free cell that starts at relative offset 0x1428 of the
# single HBIN of issue22.hive, so writing a page full of them never disturbs
# an NK/VK/SK structure.
MARK_A = b"MARK-A-DIRTY-PAGE"
MARK_B = b"MARK-B-DIRTY-PAGE"
MARK_C = b"MARK-C-DIRTY-PAGE"
MARK_D = b"MARK-D-DIRTY-PAGE"


def _read(path):
    with open(path, "rb") as f:
        return f.read()


CLEAN_HIVE = _read(HIVE_PATH)
CLEAN_REGF = RegistryParse.REGFBlock(CLEAN_HIVE, 0, False)
HBIN_BASE = CLEAN_REGF.first_hbin_offset()  # 0x1000
HBINS_SIZE = CLEAN_REGF.hbins_size()        # 0x1000
BASE_SEQ = CLEAN_REGF.hive_sequence2()      # 1
ORIGINAL_HBIN = CLEAN_HIVE[HBIN_BASE:HBIN_BASE + HBINS_SIZE]


def _align(value, alignment=LOG_ENTRY_SIZE_ALIGNMENT):
    return (value + alignment - 1) & ~(alignment - 1)


def make_primary(sequence1=BASE_SEQ + 2, hive_bytes=CLEAN_HIVE):
    """
    Build a primary hive caught mid-update: hive_sequence1 differs from
    hive_sequence2, which makes recovery_required().recover_data true while
    the header checksum stays valid.
    """
    data = bytearray(hive_bytes)
    struct.pack_into("<I", data, 0x4, sequence1)
    regf = RegistryParse.REGFBlock(bytes(data), 0, False)
    struct.pack_into("<I", data, 0x1FC, regf.calculate_checksum())
    return bytes(data)


def make_corrupt_header_primary(sequence1=BASE_SEQ + 2, hive_bytes=CLEAN_HIVE):
    """
    Build a primary hive whose REGF checksum is invalid (recover_header), as
    after an interrupted header update.
    """
    data = bytearray(make_primary(sequence1, hive_bytes))
    data[0x30] ^= 0xFF  # damage the hive name, breaking the checksum
    return bytes(data)


def dirty_page(marker, mark_offset=0x500):
    """A copy of the original HBIN with a marker written into the free cell."""
    page = bytearray(ORIGINAL_HBIN)
    page[mark_offset:mark_offset + len(marker)] = marker
    return bytes(page)


class PageBuilder(object):
    """
    Build dirty pages that accumulate markers, the way real log entries carry
    every change made so far in the pages they rewrite.
    """

    def __init__(self):
        self._page = bytearray(ORIGINAL_HBIN)
        self.next_hbin_offset = 0x1000

    def page(self, marker, mark_offset):
        self._page[mark_offset:mark_offset + len(marker)] = marker
        page = bytearray(self._page)
        # The first HBIN points at the HBIN that follows it; growth rewires it.
        struct.pack_into("<I", page, 0x8, self.next_hbin_offset)
        return bytes(page)


def hbin_growth_page(marker=b"GROWTH"):
    """A plausible, empty (free-cell) HBIN block used for hive growth tests."""
    page = bytearray(0x1000)
    struct.pack_into("<I", page, 0x0, HBIN_ID)
    struct.pack_into("<I", page, 0x4, 0x1000)  # offset of this HBIN from the first
    struct.pack_into("<I", page, 0x8, 0x1000)  # offset of the next HBIN from this one
    page[0x20:0x20 + len(marker)] = marker
    return bytes(page)


def build_entry(sequence, pages, hbins_size, hive_flags=0, declared_sizes=None):
    """
    Build one HvLE entry from (relative_offset, data) pages.

    The entries produced here are structurally valid: the sizes are aligned,
    hbins_size is page aligned, and both Marvin32 hashes are computed over the
    final bytes. Tests that want a *rejected* entry therefore exercise the
    boundary checks rather than a hash failure.

    `declared_sizes` overrides the length carded in each dirty page reference,
    which lets a test make the declared range disagree with the data carried
    by the entry.
    """
    references = bytearray()
    payload = bytearray()
    for index, (offset, data) in enumerate(pages):
        size = len(data) if declared_sizes is None else declared_sizes[index]
        references += struct.pack("<II", offset, size)
        payload += data

    raw_size = LOG_ENTRY_SIZE_HEADER + len(references) + len(payload)
    entry = bytearray(_align(raw_size))
    struct.pack_into("<I", entry, 0x0, HVLE_ID)
    struct.pack_into("<I", entry, 0x4, len(entry))
    struct.pack_into("<I", entry, 0x8, hive_flags)
    struct.pack_into("<I", entry, 0xC, sequence)
    struct.pack_into("<I", entry, 0x10, hbins_size)
    struct.pack_into("<I", entry, 0x14, len(pages))
    entry[0x28:0x28 + len(references)] = references
    payload_offset = 0x28 + len(references)
    entry[payload_offset:payload_offset + len(payload)] = payload

    struct.pack_into("<Q", entry, 0x18,
                     RegistryParse.HvLEBlock(bytes(entry), 0, False).calculate_hash_1())
    struct.pack_into("<Q", entry, 0x20,
                     RegistryParse.HvLEBlock(bytes(entry), 0, False).calculate_hash_2())
    return bytes(entry)


def build_log(first_sequence, entries, hbins_size=HBINS_SIZE, trailing=b""):
    """
    Build a new-format transaction log file with consecutive entry sequences.
    """
    header = bytearray(CLEAN_HIVE[:0x200])
    struct.pack_into("<I", header, 0x1C, FILE_TYPE_LOG_NEW)
    struct.pack_into("<I", header, 0x4, first_sequence)
    struct.pack_into("<I", header, 0x8, first_sequence)
    struct.pack_into("<I", header, 0x28, hbins_size)
    regf = RegistryParse.REGFBlock(bytes(header), 0, False)
    struct.pack_into("<I", header, 0x1FC, regf.calculate_checksum())
    return bytes(header) + b"".join(entries) + trailing


def recover(primary_bytes, log_bytes):
    """Run the public single-log recovery entry point on in-memory buffers."""
    primary = io.BytesIO(primary_bytes)
    log = RegistryLog.RegistryLog(primary, io.BytesIO(log_bytes))
    sequence = log.recover_hive()
    primary.seek(0)
    return primary.getvalue(), sequence


def recover_dual(primary_bytes, first_log, second_log):
    """Run the documented dual-log recovery sequence (LOG1 then LOG2)."""
    primary = io.BytesIO(primary_bytes)
    log1 = RegistryLog.RegistryLog(primary, io.BytesIO(first_log))
    primary.seek(0)
    log2 = RegistryLog.RegistryLog(primary, io.BytesIO(second_log))
    primary.seek(0)

    first_sequence = log1.recover_hive()
    second_sequence = None
    if first_sequence is not None:
        second_sequence = log2.recover_hive_continue(first_sequence + 1)

    primary.seek(0)
    return primary.getvalue(), first_sequence, second_sequence


def regf_of(hive_bytes):
    return RegistryParse.REGFBlock(hive_bytes, 0, False)


def recovery_status(hive_bytes):
    status = regf_of(hive_bytes).recovery_required()
    return status.recover_header, status.recover_data


def assert_untouched(original, recovered):
    """
    A refused replay must leave the primary hive byte for byte identical:
    no page was written and no header field (sequence, hbins_size, flags,
    checksum) was updated, so the recovery flag stays set.
    """
    assert recovered == original
    recover_header, recover_data = recovery_status(recovered)
    assert not recover_header, "a damaged but checksum-valid header must not claim header recovery"
    assert recover_data, "a hive that was not recovered must still report that data recovery is required"
    regf = regf_of(recovered)
    assert regf.hive_sequence1() != regf.hive_sequence2()


def visible_value(hive_bytes):
    return Registry.Registry(io.BytesIO(hive_bytes)).root().value("TimeZoneKeyName").value()


# ---------------------------------------------------------------------------
# Target range vs. declared length
# ---------------------------------------------------------------------------

def test_dirty_page_crossing_hbins_boundary_is_not_replayed():
    """
    A hash-valid page that starts inside the HBIN area but ends past the
    extent declared by its own entry must be refused as a unit. The primary
    file must not grow and the bytes beyond the hive must not be written.
    """
    primary_bytes = make_primary(BASE_SEQ + 2)
    # Offset 0x800 + size 0x1000 = 0x1800 > hbins_size 0x1000.
    entry = build_entry(BASE_SEQ + 1, [(0x800, dirty_page(MARK_A, 0x500))], HBINS_SIZE)
    log_bytes = build_log(BASE_SEQ + 1, [entry])

    # The entry itself is well formed (hashes match); only its range is not.
    parsed = RegistryParse.HvLEBlock(log_bytes[0x200:], 0, False)
    assert parsed.validate_log_entry() is False
    assert list(regf_of(log_bytes).log_entries()) == []

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence is None
    assert_untouched(primary_bytes, recovered)
    assert len(recovered) == len(primary_bytes)
    assert visible_value(recovered) == "W. Europe Standard Time"


def test_dirty_page_declared_length_larger_than_carried_data_is_not_replayed():
    """
    A reference may declare a length that does not match the payload actually
    carried by the entry. Replay must not borrow bytes from whatever follows
    the entry (here a filler run placed right behind it).
    """
    primary_bytes = make_primary(BASE_SEQ + 2)
    entry = build_entry(
        BASE_SEQ + 1,
        [(0, ORIGINAL_HBIN[:0x100])],
        HBINS_SIZE,
        declared_sizes=[HBINS_SIZE],  # claims a full page, carries 0x100 bytes
    )
    log_bytes = build_log(BASE_SEQ + 1, [entry], trailing=b"\xAA" * 0x1000)

    parsed = RegistryParse.HvLEBlock(log_bytes[0x200:], 0, False)
    assert parsed.validate_log_entry() is False

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence is None
    assert_untouched(primary_bytes, recovered)
    # The filler behind the entry must never have reached the HBIN area.
    assert b"\xAA" * 16 not in recovered[HBIN_BASE:HBIN_BASE + HBINS_SIZE]


def test_entry_declaring_larger_hive_without_new_pages_is_not_replayed():
    """
    hbins_size declares the size the hive should have after this entry. An
    entry that grows the hive must carry the new pages; if it does not, its
    header update would expose uninitialized space as hive content.
    """
    primary_bytes = make_primary(BASE_SEQ + 2)
    entry = build_entry(BASE_SEQ + 1, [(0, dirty_page(MARK_A))], 0x3000)
    log_bytes = build_log(BASE_SEQ + 1, [entry])

    parsed = RegistryParse.HvLEBlock(log_bytes[0x200:], 0, False)
    # Structurally valid: the new pages are simply missing from the payload.
    assert parsed.validate_log_entry() is True

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence is None
    assert_untouched(primary_bytes, recovered)
    assert regf_of(recovered).hbins_size() == HBINS_SIZE


def test_in_bounds_prefix_is_kept_when_later_entry_exceeds_the_hive():
    """
    The first record of a chain is provable and must be replayed; a later
    record with an out-of-bounds page must be dropped without disturbing the
    units touched by the good record.
    """
    primary_bytes = make_primary(BASE_SEQ + 3)
    good = build_entry(BASE_SEQ + 1, [(0, dirty_page(MARK_A))], HBINS_SIZE)
    bad = build_entry(BASE_SEQ + 2, [(0x800, dirty_page(MARK_B, 0x600))], HBINS_SIZE)
    log_bytes = build_log(BASE_SEQ + 1, [good, bad])

    entries = list(regf_of(log_bytes).log_entries())
    assert [entry.sequence() for entry in entries] == [BASE_SEQ + 1]

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence == BASE_SEQ + 1
    regf = regf_of(recovered)
    assert regf.hive_sequence1() == regf.hive_sequence2() == BASE_SEQ + 1
    assert regf.validate_checksum()
    status = regf.recovery_required()
    assert not status.recover_header and not status.recover_data
    assert recovered[HBIN_BASE + 0x500:HBIN_BASE + 0x500 + len(MARK_A)] == MARK_A
    assert MARK_B not in recovered
    assert visible_value(recovered) == "W. Europe Standard Time"


# ---------------------------------------------------------------------------
# Log truncated mid-way
# ---------------------------------------------------------------------------

def test_log_truncated_mid_entry_replays_only_the_provable_prefix():
    """
    A log cut in the middle of a record loses that record and everything
    after it, but the intact prefix is still replayed and the resulting hive
    is left in a consistent state.
    """
    primary_bytes = make_primary(BASE_SEQ + 4)
    pages = PageBuilder()
    entries = [
        build_entry(BASE_SEQ + 1, [(0, pages.page(MARK_A, 0x500))], HBINS_SIZE),
        build_entry(BASE_SEQ + 2, [(0, pages.page(MARK_B, 0x600))], HBINS_SIZE),
        build_entry(BASE_SEQ + 3, [(0, pages.page(MARK_C, 0x700))], HBINS_SIZE),
    ]
    # Cut inside the third entry, after its header but before its payload.
    truncated = 0x200 + len(entries[0]) + len(entries[1]) + 0x40
    log_bytes = build_log(BASE_SEQ + 1, entries)[:truncated]

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence == BASE_SEQ + 2
    regf = regf_of(recovered)
    assert regf.hive_sequence1() == regf.hive_sequence2() == BASE_SEQ + 2
    assert regf.validate_checksum()
    status = regf.recovery_required()
    assert not status.recover_header and not status.recover_data
    # The two intact records are visible, the damaged one is not.
    assert recovered[HBIN_BASE + 0x500:HBIN_BASE + 0x500 + len(MARK_A)] == MARK_A
    assert recovered[HBIN_BASE + 0x600:HBIN_BASE + 0x600 + len(MARK_B)] == MARK_B
    assert MARK_C not in recovered
    assert visible_value(recovered) == "W. Europe Standard Time"


def test_log_truncated_inside_the_first_entry_leaves_the_hive_untouched():
    """
    If the very first record is incomplete, there is nothing provable to
    replay. The hive must stay byte-identical and keep requesting recovery
    instead of being marked as recovered.
    """
    primary_bytes = make_primary(BASE_SEQ + 1)
    entry = build_entry(BASE_SEQ + 1, [(0, dirty_page(MARK_A))], HBINS_SIZE)
    log_bytes = build_log(BASE_SEQ + 1, [entry])[:0x200 + 0x40]

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence is None
    assert_untouched(primary_bytes, recovered)
    assert MARK_A not in recovered


# ---------------------------------------------------------------------------
# Normal continuation across several records and both logs
# ---------------------------------------------------------------------------

def test_multi_record_log_continues_through_growth_and_dual_log():
    """
    The happy path: LOG1 carries two records, LOG2 continues with two more,
    and the hive grows by one HBIN page in the continuation. Every record is
    applied, the header ends up consistent, and units not named by any dirty
    page stay exactly as they were.
    """
    primary_bytes = make_primary(BASE_SEQ + 4)

    pages = PageBuilder()
    pages.next_hbin_offset = 0x2000  # the hive will consist of two HBINs

    log1 = build_log(BASE_SEQ + 1, [
        build_entry(BASE_SEQ + 1, [(0, pages.page(MARK_A, 0x500))], HBINS_SIZE, hive_flags=0),
        build_entry(BASE_SEQ + 2, [(0, pages.page(MARK_B, 0x600))], HBINS_SIZE, hive_flags=1),
    ])
    log2 = build_log(BASE_SEQ + 3, [
        build_entry(BASE_SEQ + 3, [(0, pages.page(MARK_C, 0x700))], HBINS_SIZE, hive_flags=1),
        build_entry(BASE_SEQ + 4, [(0, pages.page(MARK_D, 0x800)),
                                   (HBINS_SIZE, hbin_growth_page())],
                    HBINS_SIZE * 2, hive_flags=1),
    ])

    recovered, first_sequence, second_sequence = recover_dual(primary_bytes, log1, log2)

    assert first_sequence == BASE_SEQ + 2
    assert second_sequence == BASE_SEQ + 4

    regf = regf_of(recovered)
    assert regf.hive_sequence1() == regf.hive_sequence2() == BASE_SEQ + 4
    assert regf.hbins_size() == HBINS_SIZE * 2
    assert regf.hive_flags() == 1
    assert regf.validate_checksum()
    status = regf.recovery_required()
    assert not status.recover_header and not status.recover_data

    # The file was extended by exactly one HBIN page and the new page carries
    # the growth marker (the HBIN signature occupies the first 4 bytes).
    assert len(recovered) == HBIN_BASE + HBINS_SIZE * 2
    growth = recovered[HBIN_BASE + HBINS_SIZE:HBIN_BASE + HBINS_SIZE * 2]
    assert growth[:4] == b"hbin"
    assert growth[0x20:0x20 + 6] == b"GROWTH"

    # All markers from the ordinary records survive.
    for marker, offset in ((MARK_A, 0x500), (MARK_B, 0x600), (MARK_C, 0x700), (MARK_D, 0x800)):
        assert recovered[HBIN_BASE + offset:HBIN_BASE + offset + len(marker)] == marker

    # Every unit of the first HBIN is either byte-identical to the clean hive
    # or inside the free cell the page builder scribbled into.
    first_hbin = recovered[HBIN_BASE:HBIN_BASE + HBINS_SIZE]
    clean_hbin = bytearray(ORIGINAL_HBIN)
    for marker, offset in ((MARK_A, 0x500), (MARK_B, 0x600), (MARK_C, 0x700), (MARK_D, 0x800)):
        clean_hbin[offset:offset + len(marker)] = marker
    struct.pack_into("<I", clean_hbin, 0x8, 0x2000)
    assert first_hbin == bytes(clean_hbin)
    assert visible_value(recovered) == "W. Europe Standard Time"


def test_declared_hive_growth_without_covering_pages_is_refused_mid_chain():
    """
    Growth must be backed by pages for the newly declared area. A growth
    record that omits them is refused even when earlier records of the same
    log were valid, and the earlier records remain visible.
    """
    primary_bytes = make_primary(BASE_SEQ + 3)
    good = build_entry(BASE_SEQ + 1, [(0, dirty_page(MARK_A))], HBINS_SIZE)
    unbaked_growth = build_entry(BASE_SEQ + 2, [(0, dirty_page(MARK_B, 0x600))], HBINS_SIZE * 2)
    log_bytes = build_log(BASE_SEQ + 1, [good, unbaked_growth])

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence == BASE_SEQ + 1
    regf = regf_of(recovered)
    assert regf.hbins_size() == HBINS_SIZE
    assert regf.hive_sequence1() == regf.hive_sequence2() == BASE_SEQ + 1
    assert recovered[HBIN_BASE + 0x500:HBIN_BASE + 0x500 + len(MARK_A)] == MARK_A
    assert MARK_B not in recovered
    assert len(recovered) == len(primary_bytes)


# ---------------------------------------------------------------------------
# The same chain against the checked-in dual-log sample
# ---------------------------------------------------------------------------

requires_real_sample = pytest.mark.skipif(
    not os.path.exists(os.path.join(REAL_HIVE_DIR, "SYSTEM.LOG2")),
    reason="new_log_1 dual-log sample is not available",
)


def _real_sample():
    return (
        _read(os.path.join(REAL_HIVE_DIR, "SYSTEM")),
        _read(os.path.join(REAL_HIVE_DIR, "SYSTEM.LOG1")),
        _read(os.path.join(REAL_HIVE_DIR, "SYSTEM.LOG2")),
    )


_REAL_METADATA_CACHE = {}


def real_log_metadata(path):
    """
    Return (hbins_size, [(sequence, hbins_size, [(offset, size), ...]), ...])
    for a real log, computed once per process: enumerating the entries checks
    both Marvin32 hashes, which is the expensive part of these tests.
    """
    cached = _REAL_METADATA_CACHE.get(path)
    if cached is not None:
        return cached

    regf = regf_of(_read(path))
    entries = []
    for entry in regf.log_entries():
        references = [(reference.offset(), reference.size())
                      for reference in entry.dirty_pages_references()]
        entries.append((entry.sequence(), entry.hbins_size(), references))

    result = (regf.hbins_size(), entries)
    _REAL_METADATA_CACHE[path] = result
    return result


@requires_real_sample
def test_real_dual_log_sample_recovers_completely():
    """
    The checked-in SYSTEM/LOG1/LOG2 sample must recover end to end: both logs
    are eligible and applied in order, the header ends consistent, and the
    hive's public content is reachable.
    """
    primary_bytes, log1_bytes, log2_bytes = _real_sample()
    log1_path = os.path.join(REAL_HIVE_DIR, "SYSTEM.LOG1")
    log2_path = os.path.join(REAL_HIVE_DIR, "SYSTEM.LOG2")

    primary = io.BytesIO(primary_bytes)
    log1 = RegistryLog.RegistryLog(primary, io.BytesIO(log1_bytes))
    primary.seek(0)
    log2 = RegistryLog.RegistryLog(primary, io.BytesIO(log2_bytes))
    primary.seek(0)

    assert log1.is_eligible_log()
    assert log2.is_eligible_log()
    assert log1.is_starting_log(log2)

    first_sequence = log1.recover_hive()
    assert first_sequence is not None
    primary.seek(0)
    second_sequence = log2.recover_hive_continue(first_sequence + 1)
    assert second_sequence is not None

    primary.seek(0)
    recovered = primary.read()

    regf = regf_of(recovered)
    assert regf.validate_checksum()
    assert regf.validate_sequence_numbers()
    status = regf.recovery_required()
    assert not status.recover_header and not status.recover_data
    assert regf.hive_sequence1() == regf.hive_sequence2() == second_sequence
    # The final hbins_size comes from the last applied entry, which may have
    # grown the hive beyond the extent declared in the log file header.
    _, log2_entries = real_log_metadata(log2_path)
    assert regf.hbins_size() == log2_entries[-1][1]

    registry = Registry.Registry(io.BytesIO(recovered))
    assert registry.open(r"ControlSet001\Control\Terminal Server") \
        .value("fDenyTSConnections").value() in (0, 1)
    assert registry.root().subkeys()


@requires_real_sample
def test_real_log_pages_stay_inside_the_declared_hive_extent():
    """
    Every dirty page of the real sample lies inside the extent declared by
    its own log entry, which is the property the replay code now enforces.
    """
    for name in ("SYSTEM.LOG1", "SYSTEM.LOG2"):
        _, entries = real_log_metadata(os.path.join(REAL_HIVE_DIR, name))
        assert entries
        for sequence, hbins_size, references in entries:
            for offset, size in references:
                assert offset + size <= hbins_size, (
                    "%s entry %d declares a dirty page past its hive extent"
                    % (name, sequence))


@requires_real_sample
def test_real_recovery_writes_only_logged_pages():
    """
    Integration check on real data: after dual-log recovery, the only bytes
    that differ from the original primary file are the REGF header and the
    ranges named by dirty pages of the applied entries. Nothing outside the
    logged units may be disturbed.
    """
    primary_bytes, log1_bytes, log2_bytes = _real_sample()

    applied = []
    for name in ("SYSTEM.LOG1", "SYSTEM.LOG2"):
        for _, _, references in real_log_metadata(os.path.join(REAL_HIVE_DIR, name))[1]:
            for offset, size in references:
                start = HBIN_BASE + offset
                applied.append((start, start + size))

    recovered, _, _ = recover_dual(primary_bytes, log1_bytes, log2_bytes)
    assert len(recovered) == len(primary_bytes)

    # Collapse the logged ranges (the header is rewritten by recovery itself).
    applied.append((0, HBIN_BASE))
    applied.sort()
    merged = []
    for start, end in applied:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    unexpected = []
    previous = 0
    for start, end in merged:
        if primary_bytes[previous:start] != recovered[previous:start]:
            unexpected.append(previous)
            break
        previous = end
    else:
        if primary_bytes[previous:] != recovered[previous:]:
            unexpected.append(previous)

    assert unexpected == [], (
        "bytes outside the logged dirty pages were modified, starting at 0x%x"
        % unexpected[0])

    # Sanity check: the scan really does observe the replay, so an empty
    # "unexpected" list is not the result of comparing nothing.
    assert recovered != primary_bytes


def test_write_primitive_refuses_to_cross_the_hive_boundary():
    """
    The replay primitive itself enforces the boundary: a page reference whose
    range leaves the declared extent raises instead of writing, so no code
    path can turn a crafted reference into an out-of-bounds write.
    """
    primary = io.BytesIO(make_primary(BASE_SEQ + 2))
    log = RegistryLog.RegistryLog(
        primary, io.BytesIO(build_log(BASE_SEQ + 1, [])))

    reference = RegistryParse.DirtyPageReference(
        struct.pack("<II", 0x800, 0x1000), 0, None)
    page = RegistryParse.DirtyPage(ORIGINAL_HBIN, 0, 0x1000, None)

    with pytest.raises(RegistryParse.ParseException):
        log.write_dirty_page(reference, page, HBINS_SIZE)

    # Nothing reached the file.
    primary.seek(0)
    assert primary.read() == make_primary(BASE_SEQ + 2)


# ---------------------------------------------------------------------------
# Header recovery must stay consistent when the replay is refused
# ---------------------------------------------------------------------------

def test_refused_replay_during_header_recovery_keeps_the_hive_unrecovered():
    """
    With a damaged primary header, recovery installs the log's REGF block.
    That header swap must not happen when no page can be replayed: otherwise
    the hive would look consistent while none of its data was restored. The
    primary file must stay byte-identical and keep requesting header recovery.
    """
    primary_bytes = make_corrupt_header_primary()
    entry = build_entry(BASE_SEQ + 1, [(0x800, dirty_page(MARK_A))], HBINS_SIZE)
    log_bytes = build_log(BASE_SEQ + 1, [entry])

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence is None
    assert recovered == primary_bytes
    status = regf_of(recovered).recovery_required()
    assert status.recover_header and status.recover_data
    assert not regf_of(recovered).validate_checksum()


def test_header_recovery_applies_pages_before_publishing_the_new_header():
    """
    When the damaged header can be healed, the replayed pages and the new
    header agree: the hive reports no recovery, the marker is visible, and
    the sequence numbers come from the log.
    """
    primary_bytes = make_corrupt_header_primary()
    entry = build_entry(BASE_SEQ + 1, [(0, dirty_page(MARK_A))], HBINS_SIZE)
    log_bytes = build_log(BASE_SEQ + 1, [entry])

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence == BASE_SEQ + 1
    regf = regf_of(recovered)
    assert regf.validate_checksum()
    status = regf.recovery_required()
    assert not status.recover_header and not status.recover_data
    assert regf.hive_sequence1() == regf.hive_sequence2() == BASE_SEQ + 1
    assert recovered[HBIN_BASE + 0x500:HBIN_BASE + 0x500 + len(MARK_A)] == MARK_A
    assert visible_value(recovered) == "W. Europe Standard Time"


def test_partial_header_recovery_keeps_header_and_data_consistent():
    """
    Records before an out-of-bounds record are applied even in header
    recovery, and the published header matches exactly what was applied.
    """
    primary_bytes = make_corrupt_header_primary(BASE_SEQ + 3)
    good = build_entry(BASE_SEQ + 1, [(0, dirty_page(MARK_A))], HBINS_SIZE)
    bad = build_entry(BASE_SEQ + 2, [(0x800, dirty_page(MARK_B, 0x600))], HBINS_SIZE)
    log_bytes = build_log(BASE_SEQ + 1, [good, bad])

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence == BASE_SEQ + 1
    regf = regf_of(recovered)
    assert regf.validate_checksum()
    status = regf.recovery_required()
    assert not status.recover_header and not status.recover_data
    assert regf.hive_sequence1() == regf.hive_sequence2() == BASE_SEQ + 1
    assert recovered[HBIN_BASE + 0x500:HBIN_BASE + 0x500 + len(MARK_A)] == MARK_A
    assert MARK_B not in recovered


def test_header_recovery_with_legitimate_growth_extends_the_primary_file():
    """
    A growth entry that does carry the new pages is applicable during header
    recovery too: the baseline extent comes from the file's physical size,
    not from the damaged header.
    """
    primary_bytes = make_corrupt_header_primary(BASE_SEQ + 2)
    entry = build_entry(
        BASE_SEQ + 1,
        [(0, dirty_page(MARK_A)), (HBINS_SIZE, hbin_growth_page())],
        HBINS_SIZE * 2)
    log_bytes = build_log(BASE_SEQ + 1, [entry])

    recovered, sequence = recover(primary_bytes, log_bytes)

    assert sequence == BASE_SEQ + 1
    regf = regf_of(recovered)
    assert regf.hbins_size() == HBINS_SIZE * 2
    assert regf.validate_checksum()
    status = regf.recovery_required()
    assert not status.recover_header and not status.recover_data
    assert len(recovered) == HBIN_BASE + HBINS_SIZE * 2
