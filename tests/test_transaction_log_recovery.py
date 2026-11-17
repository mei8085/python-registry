#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Integration tests for the transaction log recovery chain
(Registry.RegistryLog + Registry.RegistryParse).

These tests build a synthetic primary hive and synthetic new-format
transaction logs entirely in memory, then verify that replaying dirty
pages never corrupts parts of the primary hive that are not referenced
by the log ("malicious dirty pages must not cross the primary hive
boundary"):

- a dirty page whose target range exceeds the hive boundary is rejected;
- a dirty page whose declared size exceeds the log entry's data is rejected;
- a log truncated in the middle of an entry applies nothing;
- recovery continues normally across multiple log entries and across
  two log files (recover_hive + recover_hive_continue).

After every failed replay the primary hive's visible content and its
recovery flags must remain consistent (recovery still required), while
well-formed logs must still recover completely.
"""
import struct
from io import BytesIO

import pytest

from Registry import RegistryLog
from Registry import RegistryParse


FIRST_HBIN_OFFSET = 0x1000
HBINS_SIZE = 0x2000  # two 0x1000-byte pages
PAGE_SIZE = 0x1000

FILE_TYPE_PRIMARY = 0
FILE_TYPE_LOG_NEW = 6

# Primary hive starts in the mid-update state: sequence1 != sequence2.
PRIMARY_SEQUENCE1 = 6
PRIMARY_SEQUENCE2 = 5
# The first log entry of an eligible log continues at sequence 6.
FIRST_LOG_SEQUENCE = 6


def _regf_checksum(header):
    """Mirror of REGFBlock.calculate_checksum over a mutable header."""
    xsum = 0
    for idx in range(0, 0x1FC, 4):
        xsum ^= struct.unpack_from(str("<I"), header, idx)[0]
    if xsum == 0:
        return 1
    if xsum == 0xFFFFFFFF:
        return 0xFFFFFFFE
    return xsum


def build_regf_header(sequence1, sequence2, file_type, hbins_size):
    header = bytearray(0x200)
    struct.pack_into(str("<4s"), header, 0x0, b"regf")
    struct.pack_into(str("<I"), header, 0x4, sequence1)
    struct.pack_into(str("<I"), header, 0x8, sequence2)
    struct.pack_into(str("<I"), header, 0x14, 1)  # major version
    struct.pack_into(str("<I"), header, 0x18, 3)  # minor version
    struct.pack_into(str("<I"), header, 0x1C, file_type)
    struct.pack_into(str("<I"), header, 0x20, 1)  # file format
    struct.pack_into(str("<I"), header, 0x24, 0x20)  # root cell offset (unused here)
    struct.pack_into(str("<I"), header, 0x28, hbins_size)
    struct.pack_into(str("<I"), header, 0x2C, 1)  # clustering factor
    struct.pack_into(str("<I"), header, 0x1FC, _regf_checksum(header))
    return bytes(header)


def build_primary(hbins_page0, hbins_page1):
    """A primary hive in the mid-update state (data recovery required)."""
    buf = bytearray()
    buf += build_regf_header(PRIMARY_SEQUENCE1, PRIMARY_SEQUENCE2,
                             FILE_TYPE_PRIMARY, HBINS_SIZE)
    # The REGF block is 4k long; the first HBIN starts at 0x1000.
    buf += b"\x00" * (FIRST_HBIN_OFFSET - len(buf))
    buf += hbins_page0
    buf += hbins_page1
    return BytesIO(bytes(buf))


def build_log_entry(sequence, hive_flags, hbins_size, pages,
                    declared_sizes=None):
    """
    Build one HvLE log entry with valid Marvin32 hashes.
    `pages` is a list of (target_offset, data) tuples; `declared_sizes`
    optionally overrides the sizes stored in the dirty page references
    (used to create malicious entries whose declared length does not
    match the data actually present).
    """
    refs_size = 8 * len(pages)
    data_size = sum(len(data) for _, data in pages)
    body_size = RegistryParse.LOG_ENTRY_SIZE_HEADER + refs_size + data_size
    alignment = RegistryParse.LOG_ENTRY_SIZE_ALIGNMENT
    size = ((body_size + alignment - 1) // alignment) * alignment
    if size <= RegistryParse.LOG_ENTRY_SIZE_HEADER:
        size = alignment

    entry = bytearray(size)
    struct.pack_into(str("<4s"), entry, 0x0, b"HvLE")
    struct.pack_into(str("<I"), entry, 0x4, size)
    struct.pack_into(str("<I"), entry, 0x8, hive_flags)
    struct.pack_into(str("<I"), entry, 0xC, sequence)
    struct.pack_into(str("<I"), entry, 0x10, hbins_size)
    struct.pack_into(str("<I"), entry, 0x14, len(pages))

    rel_offset = 0x28
    for i, (target_offset, data) in enumerate(pages):
        declared = declared_sizes[i] if declared_sizes else len(data)
        struct.pack_into(str("<II"), entry, rel_offset, target_offset, declared)
        rel_offset += 8

    pos = 0x28 + refs_size
    for _, data in pages:
        entry[pos:pos + len(data)] = data
        pos += len(data)

    # Hash-1 covers everything after the 40-byte header; Hash-2 covers
    # the first 32 bytes (including Hash-1), so compute them in order.
    hvle = RegistryParse.HvLEBlock(bytes(entry), 0, None)
    struct.pack_into(str("<Q"), entry, 0x18, hvle.calculate_hash_1())
    hvle = RegistryParse.HvLEBlock(bytes(entry), 0, None)
    struct.pack_into(str("<Q"), entry, 0x20, hvle.calculate_hash_2())
    return bytes(entry)


def build_log(first_sequence, entries):
    """A new-format transaction log with a valid, self-consistent header."""
    buf = bytearray()
    buf += build_regf_header(first_sequence, first_sequence,
                             FILE_TYPE_LOG_NEW, 0)
    for entry in entries:
        buf += entry
    return bytes(buf)


def make_log(primary, log_buf):
    primary.seek(0)
    return RegistryLog.RegistryLog(primary, BytesIO(log_buf))


def primary_regf(primary):
    primary.seek(0)
    return RegistryParse.REGFBlock(primary.read(512), 0, False)


def assert_primary_untouched(primary, expected_bytes):
    assert primary.getvalue() == expected_bytes
    regf = primary_regf(primary)
    recover = regf.recovery_required()
    # The hive must still report itself as mid-update: the failed replay
    # must not have flipped the recovery flags or the sequence numbers.
    assert recover.recover_header is False
    assert recover.recover_data is True
    assert regf.hive_sequence1() == PRIMARY_SEQUENCE1
    assert regf.hive_sequence2() == PRIMARY_SEQUENCE2


def assert_primary_recovered(primary, sequence, hive_flags):
    regf = primary_regf(primary)
    recover = regf.recovery_required()
    assert recover.recover_header is False
    assert recover.recover_data is False
    assert regf.hive_sequence1() == sequence
    assert regf.hive_sequence2() == sequence
    assert regf.hive_flags() == hive_flags
    assert regf.hbins_size() == HBINS_SIZE
    assert regf.validate_checksum()


PAGE0_ORIGINAL = b"A" * PAGE_SIZE
PAGE1_ORIGINAL = b"B" * PAGE_SIZE
PAGE0_RECOVERED = b"R" * PAGE_SIZE
PAGE1_RECOVERED = b"S" * PAGE_SIZE
PAGE0_SECOND_LOG = b"T" * PAGE_SIZE


@pytest.fixture
def primary_bytes():
    return build_primary(PAGE0_ORIGINAL, PAGE1_ORIGINAL).getvalue()


@pytest.fixture
def primary(primary_bytes):
    return BytesIO(primary_bytes)


class TestCleanRecovery(object):
    """Well-formed logs must still recover completely."""

    def test_single_log_multiple_entries(self, primary):
        log = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(0x0, PAGE0_RECOVERED)]),
            build_log_entry(7, 1, HBINS_SIZE, [(0x1000, PAGE1_RECOVERED)]),
        ])
        registry_log = make_log(primary, log)

        assert registry_log.recover_hive() == 7

        content = primary.getvalue()
        assert content[FIRST_HBIN_OFFSET:FIRST_HBIN_OFFSET + PAGE_SIZE] == PAGE0_RECOVERED
        assert content[FIRST_HBIN_OFFSET + PAGE_SIZE:] == PAGE1_RECOVERED
        assert_primary_recovered(primary, 7, 1)

    def test_recovery_continues_across_two_logs(self, primary):
        log1 = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(0x0, PAGE0_RECOVERED)]),
            build_log_entry(7, 0, HBINS_SIZE, [(0x1000, PAGE1_RECOVERED)]),
        ])
        log2 = build_log(8, [
            build_log_entry(8, 1, HBINS_SIZE, [(0x0, PAGE0_SECOND_LOG)]),
        ])
        registry_log1 = make_log(primary, log1)
        registry_log2 = make_log(primary, log2)

        assert registry_log1.recover_hive() == 7
        assert registry_log2.recover_hive_continue(8) == 8

        content = primary.getvalue()
        # The second log overwrote page 0; page 1 from the first log remains.
        assert content[FIRST_HBIN_OFFSET:FIRST_HBIN_OFFSET + PAGE_SIZE] == PAGE0_SECOND_LOG
        assert content[FIRST_HBIN_OFFSET + PAGE_SIZE:] == PAGE1_RECOVERED
        assert_primary_recovered(primary, 8, 1)

    def test_continue_with_unexpected_sequence_is_a_noop(self, primary, primary_bytes):
        log2 = build_log(8, [
            build_log_entry(8, 1, HBINS_SIZE, [(0x0, PAGE0_SECOND_LOG)]),
        ])
        registry_log2 = make_log(primary, log2)

        # Sequence 7 was never applied, so continuing at 9 must refuse.
        assert registry_log2.recover_hive_continue(9) is None
        assert_primary_untouched(primary, primary_bytes)


class TestMaliciousDirtyPages(object):
    """Dirty pages must not cross the primary hive boundary."""

    def test_target_range_beyond_hive_boundary_is_rejected(self, primary, primary_bytes):
        # The entry declares hbins_size 0x2000, but the dirty page covers
        # [0x1800, 0x2800), which crosses the end of the hive.
        log = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(0x1800, PAGE0_RECOVERED)]),
        ])
        registry_log = make_log(primary, log)

        with pytest.raises(RegistryParse.ParseException):
            registry_log.recover_hive()

        # Nothing may be written: the hive keeps its original content,
        # its original size, and still reports that recovery is required.
        assert len(primary.getvalue()) == len(primary_bytes)
        assert_primary_untouched(primary, primary_bytes)

    def test_target_offset_at_hive_end_is_rejected(self, primary, primary_bytes):
        # A page starting exactly at the end of the hbins region would
        # extend past the primary hive boundary entirely.
        log = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(HBINS_SIZE, PAGE0_RECOVERED)]),
        ])
        registry_log = make_log(primary, log)

        with pytest.raises(RegistryParse.ParseException):
            registry_log.recover_hive()

        assert len(primary.getvalue()) == len(primary_bytes)
        assert_primary_untouched(primary, primary_bytes)

    def test_declared_size_exceeding_entry_data_is_rejected(self, primary, primary_bytes):
        # The dirty page reference declares 0x1000 bytes, but the log
        # entry only carries 0x100 bytes of data for it.
        log = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(0x0, PAGE0_RECOVERED[:0x100])],
                            declared_sizes=[PAGE_SIZE]),
        ])
        registry_log = make_log(primary, log)

        with pytest.raises(RegistryParse.ParseException):
            registry_log.recover_hive()

        assert_primary_untouched(primary, primary_bytes)

    def test_malicious_second_entry_preserves_recovery_state(self, primary, primary_bytes):
        # The first entry is valid, the second is malicious. The replay
        # must abort before the header is updated, so the hive still
        # reports recovery as required and can be recovered again.
        log = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(0x0, PAGE0_RECOVERED)]),
            build_log_entry(7, 0, HBINS_SIZE, [(0x1800, PAGE1_RECOVERED)]),
        ])
        registry_log = make_log(primary, log)

        with pytest.raises(RegistryParse.ParseException):
            registry_log.recover_hive()

        regf = primary_regf(primary)
        recover = regf.recovery_required()
        assert recover.recover_header is False
        assert recover.recover_data is True
        assert regf.hive_sequence1() == PRIMARY_SEQUENCE1
        assert regf.hive_sequence2() == PRIMARY_SEQUENCE2
        # The malicious page must not have crossed the boundary.
        assert len(primary.getvalue()) == len(primary_bytes)


class TestTruncatedLog(object):
    """A log truncated mid-way must not corrupt the primary hive."""

    def test_log_truncated_inside_entry_data(self, primary, primary_bytes):
        log = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(0x0, PAGE0_RECOVERED)]),
        ])
        # Cut the log in the middle of the dirty page data.
        truncated = log[:0x200 + 0x100]
        registry_log = make_log(primary, truncated)

        assert registry_log.recover_hive() is None
        assert_primary_untouched(primary, primary_bytes)

    def test_log_truncated_inside_entry_header(self, primary, primary_bytes):
        log = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(0x0, PAGE0_RECOVERED)]),
        ])
        # Only the HvLE signature survives; the entry header is incomplete.
        truncated = log[:0x200 + 0x4]
        registry_log = make_log(primary, truncated)

        assert registry_log.recover_hive() is None
        assert_primary_untouched(primary, primary_bytes)

    def test_log_truncated_after_first_entry_applies_valid_prefix(self, primary):
        log = build_log(FIRST_LOG_SEQUENCE, [
            build_log_entry(6, 0, HBINS_SIZE, [(0x0, PAGE0_RECOVERED)]),
            build_log_entry(7, 1, HBINS_SIZE, [(0x1000, PAGE1_RECOVERED)]),
        ])
        # Keep the first entry fully intact, cut the second one in half.
        first_entry_size = RegistryParse.HvLEBlock(log, 0x200, None).size()
        truncated = log[:0x200 + first_entry_size + 0x100]
        registry_log = make_log(primary, truncated)

        # The valid prefix is applied; the truncated tail is ignored.
        assert registry_log.recover_hive() == 6

        content = primary.getvalue()
        assert content[FIRST_HBIN_OFFSET:FIRST_HBIN_OFFSET + PAGE_SIZE] == PAGE0_RECOVERED
        # The uninvolved page keeps its original content.
        assert content[FIRST_HBIN_OFFSET + PAGE_SIZE:] == PAGE1_ORIGINAL
        assert_primary_recovered(primary, 6, 0)
