#!/bin/python

#    This file is part of python-registry.
#
#   Copyright 2011, 2012 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import print_function
from __future__ import absolute_import

import hashlib
import struct
from ctypes import c_uint32
from enum import Enum
from struct import pack

from Registry import RegistryParse

try:
    from functools import cmp_to_key
except ImportError:
    cmp_to_key = None  # Python 2.6 is not supported by the audited recovery API


class RegistryLog(object):
    """
    A class for parsing and applying a Windows Registry transaction log file.
    """
    def __init__(self, filelikeobject_primary, filelikeobject_log):
        """
        Constructor.
        Arguments:
        - `filelikeobject_primary`: A file-like object with .read(), .write() and .seek() methods.
              This object shall be writable, it will receive the contents of the recovered hive.
        - `filelikeobject_log`: A file-like object with a .read() method.
              If a Python string is passed, it is interpreted as a filename,
              and the corresponding file is opened.
        """
        try:
            self._log_buf = filelikeobject_log.read()
        except AttributeError:
            with open(filelikeobject_log, "rb") as f:
                self._log_buf = f.read()

        self._regf = RegistryParse.REGFBlock(self._log_buf, 0, False)

        if self._regf.is_old_transaction_log_file():
            raise RegistryParse.NotSupportedException("Old transaction log files are not supported")

        if self._regf.is_primary_file():
            raise RegistryParse.ParseException("Cannot load a primary file as a transaction log file")

        if not self._regf.is_new_transaction_log_file():
            raise RegistryParse.NotSupportedException("Unknown file type")

        if self._regf.clustering_factor() != 1:
            raise RegistryParse.NotSupportedException("Clustering factor not equal to 1 is not supported")

        recover = self._regf.recovery_required()
        if recover.recover_header or recover.recover_data:
            raise RegistryParse.NotSupportedException("This transaction log file requires self-healing")

        self._primary_buf = filelikeobject_primary.read(512)
        self._primary = filelikeobject_primary

        self._primary_regf = RegistryParse.REGFBlock(self._primary_buf, 0, False)
        self._hive_flags = None
        self._hive_sequence = None
        self._hbins_size = None

    def reload_primary_regf(self):
        """Fill the _primary_buf and _primary_regf variables again."""
        self._primary.seek(0)
        self._primary_buf = self._primary.read(512)
        self._primary_regf = RegistryParse.REGFBlock(self._primary_buf, 0, False)

    def latest_hive_flags(self):
        """Return the latest hive flags. At present, only one bit mask (0x1) is used."""
        return self._hive_flags

    def latest_hbins_size(self):
        """Return the latest hbins_size."""
        return self._hbins_size

    def latest_hive_sequence(self):
        """Return the latest hive_sequence1 (the same as hive_sequence2 after recovery)."""
        return self._hive_sequence

    def first_log_sequence(self):
        """Returns the first log sequence number."""
        return self._regf.hive_sequence2()

    def log_entries(self):
        """Return a list of all valid log entries (HvLEBlock structures) in this log."""
        return list(self._regf.log_entries())

    def last_valid_sequence(self):
        """Return the sequence number of the last valid log entry, or None."""
        entries = self.log_entries()
        if not entries:
            return None
        return entries[-1].sequence()

    def chain_status(self):
        """
        Inspect the entry slot immediately following the last valid log entry.
        Returns one of:
        - "complete": the valid chain ends cleanly (end of file, stale data from
              an older chain, or a gap in sequence numbers follows);
        - "truncated": an entry carrying the expected next sequence number is
              present but fails validation, so the chain was cut by corruption
              and this log can only be replayed partially.
        """
        entries = self.log_entries()
        if entries:
            next_offset = entries[-1]._offset_next_hvle
            expected_seqnum = c_uint32(entries[-1].sequence() + 1).value
        else:
            next_offset = self._regf.first_log_entry_offset()
            expected_seqnum = self._regf.hive_sequence2()

        if next_offset + 8 > len(self._log_buf):
            return "complete"

        try:
            h = RegistryParse.HvLEBlock(self._log_buf, next_offset, self._regf)
        except (RegistryParse.ParseException, struct.error):
            # Not an HvLE block: stale data, the valid chain ends here.
            return "complete"

        if h.sequence() == expected_seqnum and not h.validate_log_entry():
            return "truncated"

        return "complete"

    def entry_fingerprints(self):
        """
        Return a list of fingerprints, one per valid log entry.
        A fingerprint captures the entry sequence number, the hive flags, the
        hbins size, and every dirty page (offset, size, and data), so two
        entries from different logs can be compared for provable identity.
        """
        fingerprints = []
        for log_entry in self.log_entries():
            pages = []
            for dirty_page_reference, dirty_page in log_entry.dirty_pages_with_references():
                pages.append((dirty_page_reference.offset(),
                              dirty_page_reference.size(),
                              dirty_page.data()))
            fingerprints.append((log_entry.sequence(),
                                 log_entry.hive_flags(),
                                 log_entry.hbins_size(),
                                 tuple(pages)))
        return fingerprints

    def is_eligible_log(self):
        """Check if this log is eligible for the primary file."""
        if not self._primary_regf.validate_checksum():
            return True

        if self.first_log_sequence() >= self._primary_regf.hive_sequence2():
            return True

        return False

    def is_starting_log(self, another_log_file):
        """
        When the dual-logging scheme is used, check if this log shall be applied first.
        Another RegistryLog instance is checked against this one.
        """
        another_seqnum = another_log_file.first_log_sequence()
        this_seqnum = self.first_log_sequence()
        if this_seqnum >= another_seqnum:
            delta = this_seqnum - another_seqnum
            starting = False
        else:
            delta = another_seqnum - this_seqnum
            starting = True

        if c_uint32(delta).value <= 0x7FFFFFFF:
            return starting
        else:
            # Sequence numbers did overflow.
            return not starting

    def write_dirty_page(self, dirty_page_reference, dirty_page):
        """Write a dirty page to the primary file."""
        offset_primary = dirty_page_reference.offset() + self._primary_regf.first_hbin_offset()
        size = dirty_page_reference.size()
        dirty_data = dirty_page.data()
        self._primary.seek(offset_primary)
        self._primary.write(dirty_data)

    def update_regf_header(self, hive_sequence, hbins_size, hive_flags):
        """
        Update the REGF block of the primary file with the new hive_sequence1, hive_sequence2, hbins_size, and hive_flags.
        Recalculate the checksum and reload the REGF block.
        """

        def pack_dword(num):
            return pack(str("<I"), num)

        self._primary.seek(0x4)
        seqnum = pack_dword(hive_sequence)
        self._primary.write(seqnum) # hive_sequence1
        self._primary.write(seqnum) # hive_sequence2

        self._primary.seek(0x28)
        size = pack_dword(hbins_size)
        self._primary.write(size)

        self._primary.seek(0x90)
        flags = pack_dword(hive_flags)
        self._primary.write(flags)

        self.reload_primary_regf()

        self._primary.seek(0x1FC)
        checksum = pack_dword(self._primary_regf.calculate_checksum())
        self._primary.write(checksum)

        self.reload_primary_regf()

    def _apply_log_entries(self, log_entries):
        """
        Apply the given log entries to the primary file and update the REGF header.
        Returns the sequence number of the last log entry applied or None.
        """
        last_sequence = None
        for log_entry in log_entries:
            for dirty_page_reference, dirty_page in log_entry.dirty_pages_with_references():
                self.write_dirty_page(dirty_page_reference, dirty_page)

            self._hive_flags = log_entry.hive_flags()
            self._hive_sequence = log_entry.sequence()
            self._hbins_size = log_entry.hbins_size()
            last_sequence = log_entry.sequence()

        if last_sequence is not None:
            self.update_regf_header(self.latest_hive_sequence(), self.latest_hbins_size(), self.latest_hive_flags())

        return last_sequence

    def recover_hive(self):
        """
        Recover the hive from the transaction log file.
        Returns the sequence number of the last log entry applied or None.
        """
        recover = self._primary_regf.recovery_required()

        if recover.recover_header:
            self._primary.seek(0)
            self._primary.write(self._log_buf[:512])
            self.reload_primary_regf()

        if recover.recover_data:
            return self._apply_log_entries(self.log_entries())

    def recover_hive_continue(self, expected_sequence):
        """
        Continue the recovery from the second transaction log file.
        Returns the sequence number of the last log entry applied or None.
        """
        if expected_sequence != self._regf.hive_sequence2():
            return None

        return self._apply_log_entries(self.log_entries())

    def recover_hive_entries(self, log_entries):
        """
        Apply a specific subset of the valid log entries of this log.
        This is used by the audited dual-log recovery to replay only the tail
        of a log whose leading entries were provably identical to entries
        already applied from another log.
        Returns the sequence number of the last log entry applied or None.
        """
        return self._apply_log_entries(log_entries)


class RecoveryReason(Enum):
    """
    The auditable outcome of an audited dual-log recovery run.
    """
    #: The hive was consistent, nothing had to be replayed.
    RECOVERY_NOT_REQUIRED = "recovery_not_required"
    #: Every provably applicable log entry was replayed.
    RECOVERED = "recovered"
    #: The hive is consistent, but a log chain was cut by corruption
    #: (only a partial prefix of that log could be replayed).
    RECOVERED_PARTIAL_CHAIN = "recovered_partial_chain"
    #: The hive is consistent, but a later log was not applied because
    #: its first sequence number does not continue the applied chain.
    RECOVERED_SEQUENCE_GAP = "recovered_sequence_gap"
    #: The hive is consistent, but a later log was rejected because its
    #: entries conflict (divergent dirty pages) with the applied chain.
    RECOVERED_DIRTY_PAGE_CONFLICT = "recovered_dirty_page_conflict"
    #: The hive is consistent, but later logs were rejected because logs
    #: with equal starting sequence numbers describe divergent histories.
    RECOVERED_SEQUENCE_CONFLICT = "recovered_sequence_conflict"
    #: Nothing was applied: no provided log is eligible for the primary file.
    UNRECOVERED_NO_ELIGIBLE_LOG = "unrecovered_no_eligible_log"
    #: Nothing was applied: no provided log contains valid log entries.
    UNRECOVERED_NO_VALID_LOG_ENTRIES = "unrecovered_no_valid_log_entries"
    #: Nothing was applied: the earliest logs conflict, so no provable
    #: starting chain exists.
    UNRECOVERED_SEQUENCE_CONFLICT = "unrecovered_sequence_conflict"


class LogReplayRecord(object):
    """
    The audit record of a single transaction log file in a recovery run.
    """
    def __init__(self, label):
        self.label = label
        self.sha256 = None
        self.usable = False
        self.error = None
        self.eligible = False
        self.first_sequence = None
        self.last_sequence = None
        self.valid_entry_count = 0
        self.chain_status = None
        #: One of: applied_first, applied_continuation, duplicate, rejected,
        #: not_applied, unusable.
        self.role = "not_applied"
        self.applied_entry_count = 0
        self.skipped_entry_count = 0
        self.notes = []

    def to_dict(self):
        return {
            "label": self.label,
            "sha256": self.sha256,
            "usable": self.usable,
            "error": self.error,
            "eligible": self.eligible,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "valid_entry_count": self.valid_entry_count,
            "chain_status": self.chain_status,
            "role": self.role,
            "applied_entry_count": self.applied_entry_count,
            "skipped_entry_count": self.skipped_entry_count,
            "notes": list(self.notes),
        }


class RecoveryReport(object):
    """
    The auditable result of a recovery run. It durably links the recovered
    state to the original hive (name, sequence numbers, checksum status, and
    content hash), to every log consulted (with per-log provenance), and to
    the reason any log was left unapplied.
    """
    def __init__(self):
        # Identity of the original hive, captured before any modification.
        self.hive_name = None
        self.original_sha256 = None
        self.original_sequence1 = None
        self.original_sequence2 = None
        self.original_checksum_valid = None
        self.recover_header = None
        self.recover_data = None

        self.logs = []
        self.applied_order = []

        self.recovered = False
        self.complete = False
        self.reason = None
        self.reason_detail = ""

        # State of the hive after the recovery run.
        self.final_sha256 = None
        self.final_sequence1 = None
        self.final_sequence2 = None
        self.final_checksum_valid = None

    def log_record(self, label):
        for record in self.logs:
            if record.label == label:
                return record
        return None

    def to_dict(self):
        return {
            "hive_name": self.hive_name,
            "original": {
                "sha256": self.original_sha256,
                "sequence1": self.original_sequence1,
                "sequence2": self.original_sequence2,
                "checksum_valid": self.original_checksum_valid,
                "recover_header": self.recover_header,
                "recover_data": self.recover_data,
            },
            "logs": [record.to_dict() for record in self.logs],
            "applied_order": list(self.applied_order),
            "recovered": self.recovered,
            "complete": self.complete,
            "reason": self.reason.value if self.reason is not None else None,
            "reason_detail": self.reason_detail,
            "final": {
                "sha256": self.final_sha256,
                "sequence1": self.final_sequence1,
                "sequence2": self.final_sequence2,
                "checksum_valid": self.final_checksum_valid,
            },
        }

    def __str__(self):
        lines = []
        lines.append("RecoveryReport(hive=%r, recovered=%s, complete=%s, reason=%s)" % (
            self.hive_name, self.recovered, self.complete,
            self.reason.value if self.reason is not None else None))
        lines.append("  original: seq1=%s seq2=%s checksum_valid=%s sha256=%s" % (
            self.original_sequence1, self.original_sequence2,
            self.original_checksum_valid, self.original_sha256))
        for record in self.logs:
            lines.append("  log %s: role=%s first_seq=%s last_seq=%s applied=%d skipped=%d chain=%s" % (
                record.label, record.role, record.first_sequence, record.last_sequence,
                record.applied_entry_count, record.skipped_entry_count, record.chain_status))
            for note in record.notes:
                lines.append("    note: %s" % note)
            if record.error is not None:
                lines.append("    error: %s" % record.error)
        if self.reason_detail:
            lines.append("  detail: %s" % self.reason_detail)
        lines.append("  final: seq1=%s seq2=%s checksum_valid=%s sha256=%s" % (
            self.final_sequence1, self.final_sequence2,
            self.final_checksum_valid, self.final_sha256))
        return "\n".join(lines)


def _finalize_report(report, primary):
    """Capture the post-recovery state of the primary file in the report."""
    primary.seek(0)
    final_bytes = primary.read()
    report.final_sha256 = hashlib.sha256(final_bytes).hexdigest()
    try:
        regf = RegistryParse.REGFBlock(final_bytes, 0, False)
    except RegistryParse.ParseException:
        report.recovered = False
        return report
    report.final_sequence1 = regf.hive_sequence1()
    report.final_sequence2 = regf.hive_sequence2()
    report.final_checksum_valid = regf.validate_checksum()
    recover = regf.recovery_required()
    report.recovered = not (recover.recover_header or recover.recover_data)
    return report


def _compare_logs(a, b):
    """Order two RegistryLog instances by their first sequence numbers (overflow-aware)."""
    seq_a = a.first_log_sequence()
    seq_b = b.first_log_sequence()
    if seq_a == seq_b:
        return 0
    if a.is_starting_log(b):
        return -1
    return 1


def _resolve_equal_start_group(group):
    """
    Resolve a group of logs that share the same first sequence number.
    Returns the chosen (label, log, record) tuple, or None when the group
    contains divergent histories and no provable choice exists.
    Logs not chosen are marked as duplicates in their records.
    """
    chains = []
    for item in group:
        log = item[1]
        chains.append((item, log.entry_fingerprints()))

    # Longest chain first; the sort is stable, so equal chains keep input order.
    chains.sort(key=lambda chain: len(chain[1]), reverse=True)
    chosen_item, chosen_chain = chains[0]

    for item, chain in chains[1:]:
        if chosen_chain[:len(chain)] != chain:
            return None

    for item, chain in chains[1:]:
        record = item[2]
        record.role = "duplicate"
        record.notes.append("prefix-identical to %s; superseded" % chosen_item[0])

    return chosen_item


def recover_hive_with_logs(filelikeobject_primary, filelikeobjects_logs, labels=None):
    """
    Recover a primary hive file from one or two transaction log files (the
    dual-logging scheme, LOG1 and LOG2), with an auditable replay order.

    The replay order is decided only from provable log sequences:
    - logs are ordered by their first sequence numbers (overflow-aware);
    - logs with equal starting sequences are used only when one chain is a
      prefix-identical duplicate of another; divergent chains are a conflict;
    - a later log is replayed only when its first sequence number continues
      the applied chain exactly, or when its overlapping entries are
      byte-identical to the entries already applied (then only its tail is
      replayed);
    - sequence gaps, conflicting dirty pages, and truncated chains never
      cause silent splicing: the provable prefix is kept, the incompatible
      log is left unapplied, and the reason is recorded.

    When the primary file header itself requires recovery, a single (the
    latest) log is applied, matching the long-standing dual-log semantics of
    this library.

    Arguments:
    - `filelikeobject_primary`: A writable file-like object with the primary
          hive. It is modified in place when (and only when) a provable
          recovery chain exists.
    - `filelikeobjects_logs`: An iterable of transaction log files (file-like
          objects or filenames).
    - `labels`: Optional iterable of audit labels for the logs
          (defaults to LOG1, LOG2, ...).

    Returns a RecoveryReport linking the outcome to the original hive, to the
    log provenance, and to the reasons anything was left unrecovered.
    """
    if cmp_to_key is None:
        raise RegistryParse.NotSupportedException("functools.cmp_to_key is required")

    primary = filelikeobject_primary
    log_sources = list(filelikeobjects_logs)
    if labels is None:
        labels = ["LOG%d" % (i + 1) for i in range(len(log_sources))]
    else:
        labels = list(labels)
    if len(labels) != len(log_sources):
        raise ValueError("The number of labels does not match the number of logs")

    report = RecoveryReport()

    primary.seek(0)
    original_bytes = primary.read()
    primary.seek(0)
    report.original_sha256 = hashlib.sha256(original_bytes).hexdigest()

    original_regf = RegistryParse.REGFBlock(original_bytes, 0, False)
    report.original_sequence1 = original_regf.hive_sequence1()
    report.original_sequence2 = original_regf.hive_sequence2()
    report.original_checksum_valid = original_regf.validate_checksum()
    try:
        report.hive_name = original_regf.hive_name()
    except (UnicodeDecodeError, struct.error):
        report.hive_name = None

    recover = original_regf.recovery_required()
    report.recover_header = recover.recover_header
    report.recover_data = recover.recover_data

    if not (recover.recover_header or recover.recover_data):
        report.recovered = True
        report.complete = True
        report.reason = RecoveryReason.RECOVERY_NOT_REQUIRED
        report.reason_detail = "The hive is consistent; no log was replayed."
        return _finalize_report(report, primary)

    # Parse every provided log, recording provenance even for unusable ones.
    parsed_logs = []
    for label, source in zip(labels, log_sources):
        record = LogReplayRecord(label)
        report.logs.append(record)
        try:
            primary.seek(0)
            log = RegistryLog(primary, source)
        except Exception as e:
            record.role = "unusable"
            record.error = "%s: %s" % (type(e).__name__, e)
            parsed_logs.append((label, None, record))
            continue

        record.usable = True
        record.sha256 = hashlib.sha256(log._log_buf).hexdigest()
        record.first_sequence = log.first_log_sequence()
        entries = log.log_entries()
        record.valid_entry_count = len(entries)
        record.last_sequence = entries[-1].sequence() if entries else None
        record.chain_status = log.chain_status()
        record.eligible = log.is_eligible_log()
        if not record.eligible:
            record.notes.append("not eligible for this primary file")
        parsed_logs.append((label, log, record))

    eligible = [item for item in parsed_logs if item[1] is not None and item[2].eligible]
    if not eligible:
        report.reason = RecoveryReason.UNRECOVERED_NO_ELIGIBLE_LOG
        report.reason_detail = "No provided log is eligible for the primary file; the hive was left unmodified."
        return _finalize_report(report, primary)

    # Order the eligible logs by their first sequence numbers.
    ordered = sorted(eligible, key=cmp_to_key(lambda a, b: _compare_logs(a[1], b[1])))

    # Resolve groups of logs sharing the same starting sequence.
    representatives = []
    conflict_group = None
    i = 0
    while i < len(ordered):
        group = [ordered[i]]
        j = i + 1
        while j < len(ordered) and ordered[j][1].first_log_sequence() == ordered[i][1].first_log_sequence():
            group.append(ordered[j])
            j += 1
        i = j

        if len(group) == 1:
            representatives.append(group[0])
            continue

        chosen = _resolve_equal_start_group(group)
        if chosen is None:
            conflict_group = group
            break
        representatives.append(chosen)

    if conflict_group is not None:
        conflict_labels = [item[0] for item in conflict_group]
        for item in conflict_group:
            item[2].role = "rejected"
            item[2].notes.append("conflicting logs with equal first sequence %d" % item[1].first_log_sequence())
        # Logs ordered after the conflict group are unreachable as well.
        for item in ordered:
            if item[2].role == "not_applied" and item not in representatives and not item[2].notes:
                item[2].notes.append("recovery stopped at the conflicting logs before this log")
        if not representatives:
            report.reason = RecoveryReason.UNRECOVERED_SEQUENCE_CONFLICT
            report.reason_detail = ("Logs %s share the first sequence number but describe divergent "
                                    "histories; no provable starting chain exists, the hive was left "
                                    "unmodified." % ", ".join(conflict_labels))
            return _finalize_report(report, primary)
        # The conflict is past a provable prefix: keep the prefix, reject the rest.
        stop_reason = RecoveryReason.RECOVERED_SEQUENCE_CONFLICT
        stop_detail = ("Logs %s share the first sequence number but describe divergent "
                       "histories; they were not applied." % ", ".join(conflict_labels))
    else:
        stop_reason = None
        stop_detail = ""

    def mark_remaining_not_applied(items, note):
        for item in items:
            record = item[2]
            if record.role == "not_applied" and not record.notes:
                record.notes.append(note)

    if recover.recover_header:
        # Header self-healing semantics: a single (the latest) log is applied,
        # chains of both logs are not merged.
        chosen = None
        for item in reversed(representatives):
            if item[2].valid_entry_count > 0:
                chosen = item
                break

        if chosen is None:
            report.reason = RecoveryReason.UNRECOVERED_NO_VALID_LOG_ENTRIES
            report.reason_detail = "No eligible log contains valid log entries; the hive was left unmodified."
            return _finalize_report(report, primary)

        for item in representatives:
            if item is not chosen and item[2].role == "not_applied":
                item[2].notes.append("header recovery applies a single (latest) log only")

        label, log, record = chosen
        entries = log.log_entries()
        last_sequence = log.recover_hive()
        record.role = "applied_first"
        record.applied_entry_count = len(entries)
        report.applied_order.append(label)
        if log.chain_status() == "truncated":
            record.notes.append("log chain truncated by corruption; a partial prefix was replayed")
            stop_reason = stop_reason or RecoveryReason.RECOVERED_PARTIAL_CHAIN
            stop_detail = stop_detail or ("The applied log %s was cut by corruption after "
                                          "sequence %d." % (label, last_sequence))
    else:
        # Data recovery: replay the provable chain of log entries.
        start_index = None
        for index, item in enumerate(representatives):
            if item[2].valid_entry_count > 0:
                start_index = index
                break
            item[2].role = "rejected"
            item[2].notes.append("no valid log entries")

        if start_index is None:
            report.reason = RecoveryReason.UNRECOVERED_NO_VALID_LOG_ENTRIES
            report.reason_detail = "No eligible log contains valid log entries; the hive was left unmodified."
            return _finalize_report(report, primary)

        label, log, record = representatives[start_index]
        entries = log.log_entries()
        fingerprints = log.entry_fingerprints()
        last_sequence = log.recover_hive()
        record.role = "applied_first"
        record.applied_entry_count = len(entries)
        report.applied_order.append(label)

        applied_fingerprints = {}
        for entry, fingerprint in zip(entries, fingerprints):
            applied_fingerprints[entry.sequence()] = fingerprint

        remaining = representatives[start_index + 1:]
        for item in remaining:
            label, log, record = item
            entries = log.log_entries()
            fingerprints = log.entry_fingerprints()
            first_sequence = log.first_log_sequence()
            expected_sequence = c_uint32(last_sequence + 1).value

            if not entries:
                record.role = "rejected"
                record.notes.append("no valid log entries")
                stop_reason = stop_reason or RecoveryReason.RECOVERED_SEQUENCE_GAP
                stop_detail = stop_detail or ("Log %s has no valid entries; the chain stopped at "
                                              "sequence %d." % (label, last_sequence))
                break

            if first_sequence == expected_sequence:
                result = log.recover_hive_continue(expected_sequence)
                if result is None:
                    record.role = "rejected"
                    record.notes.append("log does not continue the applied chain")
                    stop_reason = stop_reason or RecoveryReason.RECOVERED_SEQUENCE_GAP
                    stop_detail = stop_detail or ("Log %s does not continue the applied chain at "
                                                  "sequence %d." % (label, expected_sequence))
                    break
                record.role = "applied_continuation"
                record.applied_entry_count = len(entries)
                report.applied_order.append(label)
                for entry, fingerprint in zip(entries, fingerprints):
                    applied_fingerprints[entry.sequence()] = fingerprint
                last_sequence = result
            elif first_sequence <= last_sequence:
                # Overlapping logs: the overlap must be byte-identical to what
                # was already applied, otherwise the logs are incompatible.
                conflict = False
                for entry, fingerprint in zip(entries, fingerprints):
                    if entry.sequence() <= last_sequence:
                        if applied_fingerprints.get(entry.sequence()) != fingerprint:
                            conflict = True
                            break

                if conflict:
                    record.role = "rejected"
                    record.notes.append("dirty pages conflict with the applied chain")
                    stop_reason = stop_reason or RecoveryReason.RECOVERED_DIRTY_PAGE_CONFLICT
                    stop_detail = stop_detail or ("Log %s overlaps the applied chain but its dirty "
                                                  "pages diverge; it was not spliced in." % label)
                    break

                tail = [(entry, fingerprint) for entry, fingerprint in zip(entries, fingerprints)
                        if entry.sequence() > last_sequence]
                if not tail:
                    record.role = "duplicate"
                    record.notes.append("fully contained in the already applied chain")
                    continue

                tail_entries = [entry for entry, _ in tail]
                result = log.recover_hive_entries(tail_entries)
                record.role = "applied_continuation"
                record.applied_entry_count = len(tail_entries)
                record.skipped_entry_count = len(entries) - len(tail_entries)
                record.notes.append("leading entries identical to the applied chain; only the "
                                    "tail was replayed")
                report.applied_order.append(label)
                for entry, fingerprint in tail:
                    applied_fingerprints[entry.sequence()] = fingerprint
                last_sequence = result
            else:
                record.role = "not_applied"
                record.notes.append("sequence gap: expected first sequence %d" % expected_sequence)
                stop_reason = stop_reason or RecoveryReason.RECOVERED_SEQUENCE_GAP
                stop_detail = stop_detail or ("Log %s starts at sequence %d, but the applied chain "
                                              "ended at sequence %d; the gap was not bridged." %
                                              (label, first_sequence, last_sequence))
                break

        if stop_reason is None:
            # Everything provided was applied; check whether the last applied
            # log was itself cut short by corruption.
            last_label, last_log, last_record = None, None, None
            for applied_label in reversed(report.applied_order):
                for item in representatives:
                    if item[0] == applied_label:
                        last_label, last_log, last_record = item
                        break
                if last_log is not None:
                    break
            if last_log is not None and last_log.chain_status() == "truncated":
                last_record.notes.append("log chain truncated by corruption; a partial prefix was replayed")
                stop_reason = RecoveryReason.RECOVERED_PARTIAL_CHAIN
                stop_detail = ("The applied log %s was cut by corruption after sequence %d; later "
                               "transactions may be missing." % (last_label, last_sequence))

    if stop_reason is None:
        report.reason = RecoveryReason.RECOVERED
        report.reason_detail = "All provably applicable log entries were replayed."
        report.complete = True
    else:
        report.reason = stop_reason
        report.reason_detail = stop_detail
        report.complete = False

    mark_remaining_not_applied(representatives, "recovery stopped before this log was reached")

    return _finalize_report(report, primary)
