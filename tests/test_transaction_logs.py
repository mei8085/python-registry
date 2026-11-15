#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Tests for the audited replay of LOG1/LOG2 transaction log files.

Synthetic transaction logs are built on top of the real issue22.hive sample:
the hive has exactly one HBIN (0x1000 bytes at file offset 0x1000) with a
large free cell at 0x1428, so dirty pages that copy the page and scribble a
marker inside the free cell keep every key/value readable.
"""
import hashlib
import io
import json
import os
import struct
import unittest

from Registry import Registry, RegistryLog, RegistryParse

HIVE_PATH = os.path.join(os.path.dirname(__file__), "reg_samples", "issue22.hive")

REGF_SIZE = 0x1000
FILE_TYPE_LOG_NEW = 6
MARK_OFFSET_1 = 0x500  # relative to the first HBIN, inside the free cell
MARK_OFFSET_2 = 0x600
MARK_OFFSET_3 = 0x700

with open(HIVE_PATH, "rb") as f:
    CLEAN_HIVE = f.read()

CLEAN_REGF = RegistryParse.REGFBlock(CLEAN_HIVE, 0, False)
HBINS_SIZE = CLEAN_REGF.hbins_size()
BASE_SEQ = CLEAN_REGF.hive_sequence2()  # 1
ORIGINAL_PAGE = CLEAN_HIVE[REGF_SIZE:REGF_SIZE + HBINS_SIZE]


def make_dirty_primary(seq1):
    """Simulate a mid-update primary file: sequence1 != sequence2."""
    data = bytearray(CLEAN_HIVE)
    struct.pack_into(str("<I"), data, 0x4, seq1)
    regf = RegistryParse.REGFBlock(bytes(data), 0, False)
    struct.pack_into(str("<I"), data, 0x1FC, regf.calculate_checksum())
    return bytes(data)


def make_corrupt_header_primary():
    """Simulate a primary file with a damaged header (invalid checksum)."""
    data = bytearray(make_dirty_primary(BASE_SEQ + 2))
    data[0x30] ^= 0xFF  # damage the hive name, breaking the checksum
    return bytes(data)


def make_page(marker, mark_offset):
    """A dirty page: the original HBIN page with a marker in the free cell."""
    page = bytearray(ORIGINAL_PAGE)
    page[mark_offset:mark_offset + len(marker)] = marker
    return bytes(page)


def build_entry(seq, pages, corrupt=False):
    """Build one HvLE log entry. pages is a list of (offset, data) tuples."""
    refs = b"".join(struct.pack(str("<II"), offset, len(data)) for offset, data in pages)
    payload = b"".join(data for _, data in pages)
    size = RegistryParse.LOG_ENTRY_SIZE_HEADER + len(refs) + len(payload)
    size_aligned = (size + RegistryParse.LOG_ENTRY_SIZE_ALIGNMENT - 1) & \
        ~(RegistryParse.LOG_ENTRY_SIZE_ALIGNMENT - 1)

    entry = bytearray(size_aligned)
    struct.pack_into(str("<I"), entry, 0x0, 0x454C7648)  # "HvLE"
    struct.pack_into(str("<I"), entry, 0x4, size_aligned)
    struct.pack_into(str("<I"), entry, 0x8, 0)           # hive_flags
    struct.pack_into(str("<I"), entry, 0xC, seq)
    struct.pack_into(str("<I"), entry, 0x10, HBINS_SIZE)
    struct.pack_into(str("<I"), entry, 0x14, len(pages))
    entry[0x28:0x28 + len(refs)] = refs
    entry[0x28 + len(refs):0x28 + len(refs) + len(payload)] = payload

    block = RegistryParse.HvLEBlock(bytes(entry), 0, False)
    struct.pack_into(str("<Q"), entry, 0x18, block.calculate_hash_1())
    block = RegistryParse.HvLEBlock(bytes(entry), 0, False)
    struct.pack_into(str("<Q"), entry, 0x20, block.calculate_hash_2())

    if corrupt:
        entry[-1] ^= 0xFF  # invalidate Hash-1

    return bytes(entry)


def make_log(first_seq, entry_specs):
    """
    Build a new-format transaction log file.
    entry_specs is a list of dicts: {"pages": [(offset, data)], "corrupt": bool}.
    Entries get consecutive sequence numbers starting at first_seq.
    """
    header = bytearray(CLEAN_HIVE[:512])
    struct.pack_into(str("<I"), header, 0x1C, FILE_TYPE_LOG_NEW)
    struct.pack_into(str("<I"), header, 0x4, first_seq)
    struct.pack_into(str("<I"), header, 0x8, first_seq)
    regf = RegistryParse.REGFBlock(bytes(header), 0, False)
    struct.pack_into(str("<I"), header, 0x1FC, regf.calculate_checksum())

    body = b""
    seq = first_seq
    for spec in entry_specs:
        body += build_entry(seq, spec["pages"], corrupt=spec.get("corrupt", False))
        seq += 1
    return bytes(header) + body


def one_page_entry(marker, mark_offset):
    return {"pages": [(0, make_page(marker, mark_offset))]}


class PageBuilder(object):
    """
    Builds dirty pages that accumulate markers, mimicking real log entries
    whose dirty pages contain every change made so far.
    """
    def __init__(self):
        self._page = bytearray(ORIGINAL_PAGE)

    def entry(self, marker, mark_offset, corrupt=False):
        self._page[mark_offset:mark_offset + len(marker)] = marker
        return {"pages": [(0, bytes(self._page))], "corrupt": corrupt}


def recover(primary_bytes, logs, labels=None):
    primary = io.BytesIO(primary_bytes)
    log_ios = [io.BytesIO(log) for log in logs]
    report = RegistryLog.recover_hive_with_logs(primary, log_ios, labels=labels)
    primary.seek(0)
    return primary, report


class TestExistingRecoverySemantics(unittest.TestCase):
    """The pre-existing single-log and dual-log APIs must behave as before."""

    def test_single_log_recover_hive(self):
        pages = PageBuilder()
        log1 = make_log(BASE_SEQ + 1, [pages.entry(b"LOG1-ENTRY-2", MARK_OFFSET_1),
                                       pages.entry(b"LOG1-ENTRY-3", MARK_OFFSET_2)])
        primary = io.BytesIO(make_dirty_primary(BASE_SEQ + 2))
        log = RegistryLog.RegistryLog(primary, io.BytesIO(log1))

        self.assertEqual(log.recover_hive(), BASE_SEQ + 2)

        primary.seek(0)
        data = primary.read()
        regf = RegistryParse.REGFBlock(data, 0, False)
        self.assertTrue(regf.validate_checksum())
        self.assertTrue(regf.validate_sequence_numbers())
        self.assertEqual(regf.hive_sequence1(), BASE_SEQ + 2)
        self.assertEqual(data[REGF_SIZE + MARK_OFFSET_1:REGF_SIZE + MARK_OFFSET_1 + 12],
                         b"LOG1-ENTRY-2")
        reg = Registry.Registry(io.BytesIO(data))
        self.assertEqual(reg.root().value("TimeZoneKeyName").value(),
                         u"W. Europe Standard Time")

    def test_dual_log_recover_hive_continue(self):
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1)])
        pages = PageBuilder()
        log2 = make_log(BASE_SEQ + 2, [pages.entry(b"LOG2-ENTRY-3", MARK_OFFSET_2),
                                       pages.entry(b"LOG2-ENTRY-4", MARK_OFFSET_3)])
        primary = io.BytesIO(make_dirty_primary(BASE_SEQ + 3))

        primary.seek(0)
        first = RegistryLog.RegistryLog(primary, io.BytesIO(log1))
        primary.seek(0)
        second = RegistryLog.RegistryLog(primary, io.BytesIO(log2))
        primary.seek(0)

        self.assertTrue(first.is_starting_log(second))
        seqnum = first.recover_hive()
        self.assertEqual(seqnum, BASE_SEQ + 1)
        seqnum = second.recover_hive_continue(seqnum + 1)
        self.assertEqual(seqnum, BASE_SEQ + 3)

        primary.seek(0)
        data = primary.read()
        regf = RegistryParse.REGFBlock(data, 0, False)
        self.assertTrue(regf.validate_checksum())
        self.assertEqual(regf.hive_sequence1(), BASE_SEQ + 3)
        self.assertEqual(regf.hive_sequence2(), BASE_SEQ + 3)
        self.assertEqual(data[REGF_SIZE + MARK_OFFSET_3:REGF_SIZE + MARK_OFFSET_3 + 12],
                         b"LOG2-ENTRY-4")

    def test_recover_hive_continue_rejects_wrong_sequence(self):
        log2 = make_log(BASE_SEQ + 5, [one_page_entry(b"LOG2-ENTRY-6", MARK_OFFSET_1)])
        primary = io.BytesIO(make_dirty_primary(BASE_SEQ + 1))
        log = RegistryLog.RegistryLog(primary, io.BytesIO(log2))
        self.assertIsNone(log.recover_hive_continue(BASE_SEQ + 2))


class TestAuditedDualLogRecovery(unittest.TestCase):
    def test_recovery_not_required(self):
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1)])
        primary, report = recover(CLEAN_HIVE, [log1])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERY_NOT_REQUIRED)
        self.assertTrue(report.recovered)
        self.assertTrue(report.complete)
        primary.seek(0)
        self.assertEqual(primary.read(), CLEAN_HIVE)

    def test_single_log(self):
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1),
                                       one_page_entry(b"LOG1-ENTRY-3", MARK_OFFSET_2)])
        primary_bytes = make_dirty_primary(BASE_SEQ + 2)
        primary, report = recover(primary_bytes, [log1])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED)
        self.assertTrue(report.recovered)
        self.assertTrue(report.complete)
        self.assertEqual(report.applied_order, ["LOG1"])
        self.assertEqual(report.original_sha256, hashlib.sha256(primary_bytes).hexdigest())
        self.assertEqual(report.original_sequence2, BASE_SEQ)
        self.assertEqual(report.final_sequence1, BASE_SEQ + 2)
        self.assertEqual(report.final_sequence2, BASE_SEQ + 2)
        self.assertTrue(report.final_checksum_valid)
        json.dumps(report.to_dict())  # the audit record must be serializable

    def test_dual_log_full_chain(self):
        pages = PageBuilder()
        log1 = make_log(BASE_SEQ + 1, [pages.entry(b"LOG1-ENTRY-2", MARK_OFFSET_1),
                                       pages.entry(b"LOG1-ENTRY-3", MARK_OFFSET_2)])
        log2 = make_log(BASE_SEQ + 3, [pages.entry(b"LOG2-ENTRY-4", MARK_OFFSET_3)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 3), [log1, log2])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED)
        self.assertTrue(report.complete)
        self.assertEqual(report.applied_order, ["LOG1", "LOG2"])
        self.assertEqual(report.final_sequence1, BASE_SEQ + 3)

        primary.seek(0)
        data = primary.read()
        self.assertEqual(data[REGF_SIZE + MARK_OFFSET_1:REGF_SIZE + MARK_OFFSET_1 + 12],
                         b"LOG1-ENTRY-2")
        self.assertEqual(data[REGF_SIZE + MARK_OFFSET_3:REGF_SIZE + MARK_OFFSET_3 + 12],
                         b"LOG2-ENTRY-4")
        reg = Registry.Registry(io.BytesIO(data))
        self.assertEqual(reg.root().value("TimeZoneKeyName").value(),
                         u"W. Europe Standard Time")

    def test_dual_log_order_is_provable_not_positional(self):
        """Logs passed in the wrong order must still be replayed in sequence order."""
        log_a = make_log(BASE_SEQ + 1, [one_page_entry(b"LOGA-ENTRY-2", MARK_OFFSET_1)])
        log_b = make_log(BASE_SEQ + 2, [one_page_entry(b"LOGB-ENTRY-3", MARK_OFFSET_2)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 2), [log_b, log_a],
                                  labels=["LOG_B", "LOG_A"])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED)
        self.assertEqual(report.applied_order, ["LOG_A", "LOG_B"])
        self.assertEqual(report.final_sequence1, BASE_SEQ + 2)

    def test_sequence_gap_keeps_provable_prefix(self):
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1)])
        log2 = make_log(BASE_SEQ + 4, [one_page_entry(b"LOG2-ENTRY-5", MARK_OFFSET_2)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 4), [log1, log2])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED_SEQUENCE_GAP)
        self.assertTrue(report.recovered)
        self.assertFalse(report.complete)
        self.assertEqual(report.applied_order, ["LOG1"])
        self.assertEqual(report.final_sequence1, BASE_SEQ + 1)
        self.assertEqual(report.log_record("LOG2").role, "not_applied")

        primary.seek(0)
        data = primary.read()
        self.assertEqual(data[REGF_SIZE + MARK_OFFSET_1:REGF_SIZE + MARK_OFFSET_1 + 12],
                         b"LOG1-ENTRY-2")
        self.assertNotEqual(data[REGF_SIZE + MARK_OFFSET_2:REGF_SIZE + MARK_OFFSET_2 + 12],
                            b"LOG2-ENTRY-5")

    def test_sequence_conflict_leaves_hive_untouched(self):
        """Two logs with equal starting sequences but divergent pages: no splicing."""
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-HISTORY", MARK_OFFSET_1)])
        log2 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG2-HISTORY", MARK_OFFSET_1)])
        primary_bytes = make_dirty_primary(BASE_SEQ + 1)
        primary, report = recover(primary_bytes, [log1, log2])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.UNRECOVERED_SEQUENCE_CONFLICT)
        self.assertFalse(report.recovered)
        self.assertFalse(report.complete)
        self.assertEqual(report.applied_order, [])
        self.assertEqual(report.log_record("LOG1").role, "rejected")
        self.assertEqual(report.log_record("LOG2").role, "rejected")
        primary.seek(0)
        self.assertEqual(primary.read(), primary_bytes)  # untouched

    def test_conflict_past_provable_prefix_keeps_prefix(self):
        """A conflict in later logs does not discard the provable earlier chain."""
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1)])
        log2 = make_log(BASE_SEQ + 2, [one_page_entry(b"LOG2-HISTORY", MARK_OFFSET_2)])
        log3 = make_log(BASE_SEQ + 2, [one_page_entry(b"LOG3-HISTORY", MARK_OFFSET_2)])
        log4 = make_log(BASE_SEQ + 3, [one_page_entry(b"LOG4-ENTRY-4", MARK_OFFSET_3)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 3),
                                  [log1, log2, log3, log4],
                                  labels=["LOG1", "LOG2", "LOG3", "LOG4"])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED_SEQUENCE_CONFLICT)
        self.assertTrue(report.recovered)
        self.assertFalse(report.complete)
        self.assertEqual(report.applied_order, ["LOG1"])
        self.assertEqual(report.final_sequence1, BASE_SEQ + 1)
        self.assertEqual(report.log_record("LOG2").role, "rejected")
        self.assertEqual(report.log_record("LOG3").role, "rejected")
        self.assertTrue(report.log_record("LOG4").notes)

        primary.seek(0)
        data = primary.read()
        self.assertEqual(data[REGF_SIZE + MARK_OFFSET_1:REGF_SIZE + MARK_OFFSET_1 + 12],
                         b"LOG1-ENTRY-2")

    def test_equal_start_duplicate_logs(self):
        """Identical chains with equal starts: one is applied, the other recorded."""
        entry = one_page_entry(b"SHARED-ENTRY", MARK_OFFSET_1)
        log1 = make_log(BASE_SEQ + 1, [entry])
        log2 = make_log(BASE_SEQ + 1, [entry])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 1), [log1, log2])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED)
        self.assertTrue(report.complete)
        self.assertEqual(len(report.applied_order), 1)
        roles = sorted(record.role for record in report.logs)
        self.assertEqual(roles, ["applied_first", "duplicate"])

    def test_equal_start_prefix_extension(self):
        """A log that provably extends a duplicate prefix is preferred."""
        shared = one_page_entry(b"SHARED-ENTRY", MARK_OFFSET_1)
        log1 = make_log(BASE_SEQ + 1, [shared])
        log2 = make_log(BASE_SEQ + 1, [shared, one_page_entry(b"LOG2-ENTRY-3", MARK_OFFSET_2)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 2), [log1, log2])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED)
        self.assertEqual(report.applied_order, ["LOG2"])
        self.assertEqual(report.log_record("LOG1").role, "duplicate")
        self.assertEqual(report.final_sequence1, BASE_SEQ + 2)

    def test_identical_overlap_continues_chain(self):
        """Overlapping logs with byte-identical overlap: only the tail is replayed."""
        shared_entry = one_page_entry(b"SHARED-ENTRY", MARK_OFFSET_1)
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_2),
                                       shared_entry])
        log2 = make_log(BASE_SEQ + 2, [shared_entry,
                                       one_page_entry(b"LOG2-ENTRY-4", MARK_OFFSET_3)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 3), [log1, log2])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED)
        self.assertTrue(report.complete)
        self.assertEqual(report.applied_order, ["LOG1", "LOG2"])
        record2 = report.log_record("LOG2")
        self.assertEqual(record2.role, "applied_continuation")
        self.assertEqual(record2.skipped_entry_count, 1)
        self.assertEqual(record2.applied_entry_count, 1)
        self.assertEqual(report.final_sequence1, BASE_SEQ + 3)

    def test_conflicting_overlap_is_not_spliced(self):
        """Overlapping logs with divergent dirty pages: the second log is rejected."""
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_2),
                                       one_page_entry(b"LOG1-HISTORY", MARK_OFFSET_1)])
        log2 = make_log(BASE_SEQ + 2, [one_page_entry(b"LOG2-HISTORY", MARK_OFFSET_1),
                                       one_page_entry(b"LOG2-ENTRY-4", MARK_OFFSET_3)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 3), [log1, log2])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED_DIRTY_PAGE_CONFLICT)
        self.assertTrue(report.recovered)
        self.assertFalse(report.complete)
        self.assertEqual(report.applied_order, ["LOG1"])
        self.assertEqual(report.log_record("LOG2").role, "rejected")
        self.assertEqual(report.final_sequence1, BASE_SEQ + 2)

        primary.seek(0)
        data = primary.read()
        self.assertEqual(data[REGF_SIZE + MARK_OFFSET_1:REGF_SIZE + MARK_OFFSET_1 + 12],
                         b"LOG1-HISTORY")
        self.assertNotEqual(data[REGF_SIZE + MARK_OFFSET_3:REGF_SIZE + MARK_OFFSET_3 + 12],
                            b"LOG2-ENTRY-4")

    def test_truncated_log_partial_replay(self):
        """A chain cut by corruption is replayed up to the last provable entry."""
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1),
                                       one_page_entry(b"LOG1-ENTRY-3", MARK_OFFSET_2),
                                       dict(one_page_entry(b"CORRUPT-ENTRY", MARK_OFFSET_3),
                                            corrupt=True)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 3), [log1])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED_PARTIAL_CHAIN)
        self.assertTrue(report.recovered)
        self.assertFalse(report.complete)
        self.assertEqual(report.final_sequence1, BASE_SEQ + 2)
        record = report.log_record("LOG1")
        self.assertEqual(record.chain_status, "truncated")
        self.assertEqual(record.valid_entry_count, 2)
        self.assertEqual(record.applied_entry_count, 2)

    def test_truncated_first_log_redeemed_by_second(self):
        """Dual logging covers corruption: LOG2 continues where LOG1 was cut."""
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1),
                                       dict(one_page_entry(b"CORRUPT-ENTRY", MARK_OFFSET_2),
                                            corrupt=True)])
        log2 = make_log(BASE_SEQ + 2, [one_page_entry(b"LOG2-ENTRY-3", MARK_OFFSET_2),
                                       one_page_entry(b"LOG2-ENTRY-4", MARK_OFFSET_3)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 3), [log1, log2])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED)
        self.assertTrue(report.complete)
        self.assertEqual(report.applied_order, ["LOG1", "LOG2"])
        self.assertEqual(report.final_sequence1, BASE_SEQ + 3)

    def test_no_eligible_log(self):
        log1 = make_log(BASE_SEQ - 1, [one_page_entry(b"STALE-ENTRY-", MARK_OFFSET_1)])
        primary_bytes = make_dirty_primary(BASE_SEQ + 1)
        primary, report = recover(primary_bytes, [log1])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.UNRECOVERED_NO_ELIGIBLE_LOG)
        self.assertFalse(report.recovered)
        primary.seek(0)
        self.assertEqual(primary.read(), primary_bytes)

    def test_log_without_valid_entries(self):
        log1 = make_log(BASE_SEQ + 1, [dict(one_page_entry(b"CORRUPT-ENTRY", MARK_OFFSET_1),
                                            corrupt=True)])
        primary_bytes = make_dirty_primary(BASE_SEQ + 1)
        primary, report = recover(primary_bytes, [log1])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.UNRECOVERED_NO_VALID_LOG_ENTRIES)
        self.assertFalse(report.recovered)
        primary.seek(0)
        self.assertEqual(primary.read(), primary_bytes)

    def test_unusable_log_is_recorded(self):
        primary_bytes = make_dirty_primary(BASE_SEQ + 1)
        primary, report = recover(primary_bytes, [b"not a registry file at all"])

        self.assertEqual(report.reason, RegistryLog.RecoveryReason.UNRECOVERED_NO_ELIGIBLE_LOG)
        record = report.log_record("LOG1")
        self.assertEqual(record.role, "unusable")
        self.assertIsNotNone(record.error)
        primary.seek(0)
        self.assertEqual(primary.read(), primary_bytes)

    def test_header_recovery_applies_single_latest_log(self):
        """Damaged header: self-healing uses one (the latest) log, as before."""
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1)])
        pages = PageBuilder()
        log2 = make_log(BASE_SEQ + 2, [pages.entry(b"LOG2-ENTRY-3", MARK_OFFSET_2),
                                       pages.entry(b"LOG2-ENTRY-4", MARK_OFFSET_3)])
        primary, report = recover(make_corrupt_header_primary(), [log1, log2])

        self.assertTrue(report.recover_header)
        self.assertEqual(report.reason, RegistryLog.RecoveryReason.RECOVERED)
        self.assertTrue(report.recovered)
        self.assertEqual(report.applied_order, ["LOG2"])
        self.assertEqual(report.log_record("LOG1").role, "not_applied")
        self.assertEqual(report.final_sequence1, BASE_SEQ + 3)
        self.assertTrue(report.final_checksum_valid)

        primary.seek(0)
        data = primary.read()
        self.assertEqual(data[REGF_SIZE + MARK_OFFSET_2:REGF_SIZE + MARK_OFFSET_2 + 12],
                         b"LOG2-ENTRY-3")
        self.assertNotEqual(data[REGF_SIZE + MARK_OFFSET_1:REGF_SIZE + MARK_OFFSET_1 + 12],
                            b"LOG1-ENTRY-2")

    def test_recovered_hive_checksum_and_value_semantics(self):
        """The recovered hive keeps the usual checksum and key/value semantics."""
        log1 = make_log(BASE_SEQ + 1, [one_page_entry(b"LOG1-ENTRY-2", MARK_OFFSET_1)])
        log2 = make_log(BASE_SEQ + 2, [one_page_entry(b"LOG2-ENTRY-3", MARK_OFFSET_2)])
        primary, report = recover(make_dirty_primary(BASE_SEQ + 2), [log1, log2])
        self.assertTrue(report.complete)

        primary.seek(0)
        reg = Registry.Registry(primary)
        regf = reg._regf
        self.assertTrue(regf.validate_checksum())
        self.assertTrue(regf.validate_sequence_numbers())
        self.assertEqual(regf.hbins_size(), HBINS_SIZE)
        self.assertEqual(regf.hive_flags(), 0)
        recover_status = regf.recovery_required()
        self.assertFalse(recover_status.recover_header)
        self.assertFalse(recover_status.recover_data)
        self.assertEqual(reg.root().value("TimeZoneKeyName").value(),
                         u"W. Europe Standard Time")


if __name__ == "__main__":
    unittest.main(verbosity=2)
