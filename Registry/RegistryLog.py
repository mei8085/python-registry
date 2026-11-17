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

from ctypes import c_uint32
from struct import pack
from Registry import RegistryParse

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

    def _checked_dirty_page(self, dirty_page_reference, dirty_page, hive_extent):
        """
        Validate one dirty page against the hive extent that owns it and
        return its payload.

        A page is only acceptable when it carries exactly the number of bytes
        its reference declares and when its target range stays inside the
        extent. Offsets are relative to the first HBIN. Raises
        RegistryParse.ParseException otherwise, so no caller can turn a
        crafted reference into an out-of-bounds write.
        """
        offset_relative = dirty_page_reference.offset()
        size = dirty_page_reference.size()
        dirty_data = dirty_page.data()

        if size <= 0:
            raise RegistryParse.ParseException(
                "Dirty page at relative offset 0x%x has invalid size %d" % (offset_relative, size))

        if len(dirty_data) != size:
            raise RegistryParse.ParseException(
                "Dirty page at relative offset 0x%x declares %d bytes but carries %d" % (
                    offset_relative, size, len(dirty_data)))

        if offset_relative + size > hive_extent:
            raise RegistryParse.ParseException(
                "Dirty page [0x%x, 0x%x) exceeds the hive extent 0x%x" % (
                    offset_relative, offset_relative + size, hive_extent))

        return dirty_data

    def write_dirty_page(self, dirty_page_reference, dirty_page, hive_extent=None):
        """
        Write a dirty page to the primary file.

        `hive_extent` is the size of the HBIN area declared by the log entry
        that owns the page (relative to the first HBIN). A write is only
        performed when the declared length matches the data actually carried
        by the log and when the target range stays inside that extent, which
        keeps a malicious or malformed dirty page from overwriting bytes of
        the primary hive that the log entry does not own.
        """
        if hive_extent is None:
            hive_extent = self._primary_regf.hbins_size()

        dirty_data = self._checked_dirty_page(dirty_page_reference, dirty_page, hive_extent)

        offset_primary = dirty_page_reference.offset() + self._primary_regf.first_hbin_offset()
        self._primary.seek(offset_primary)
        self._primary.write(dirty_data)

    def _entry_writes(self, log_entry, current_extent):
        """
        Validate a log entry and return the writes it would perform, as a list
        of (absolute_target_offset, data), or None when the entry cannot be
        applied as a unit.

        Validation covers:
        - the declared length of every dirty page matching the data the log
          actually carries for it;
        - every dirty page range staying inside the hive extent that the entry
          declares via hbins_size();
        - every byte of a newly declared HBIN area (growth) being backed by a
          dirty page, so applying the header cannot expose uninitialized space.
        """
        target_extent = log_entry.hbins_size()

        if target_extent > current_extent:
            ranges = sorted(
                (reference.offset(), reference.offset() + reference.size())
                for reference in log_entry.dirty_pages_references())
            cursor = current_extent
            for start, end in ranges:
                if end <= cursor:
                    continue
                if start > cursor:
                    return None
                cursor = end
                if cursor >= target_extent:
                    break
            if cursor < target_extent:
                return None

        writes = []
        hbin_base = self._primary_regf.first_hbin_offset()
        try:
            for dirty_page_reference, dirty_page in log_entry.dirty_pages_with_references():
                dirty_data = self._checked_dirty_page(
                    dirty_page_reference, dirty_page, target_extent)
                writes.append((dirty_page_reference.offset() + hbin_base, dirty_data))
        except RegistryParse.ParseException:
            return None

        return writes

    def _collect_applicable_entries(self, log_entries, starting_extent):
        """
        Walk the valid entries of this log in sequence order and collect the
        prefix that can be applied as units. Returns a list of
        (log_entry, writes) tuples; the first inapplicable entry ends the
        prefix, since later entries build on it.
        """
        applicable = []
        current_extent = starting_extent
        for log_entry in log_entries:
            writes = self._entry_writes(log_entry, current_extent)
            if writes is None:
                break
            applicable.append((log_entry, writes))
            current_extent = log_entry.hbins_size()
        return applicable

    def _apply_applicable_entries(self, applicable):
        """
        Write the entries collected by _collect_applicable_entries() and
        update the REGF header accordingly.

        Returns the sequence number of the last applied entry, or None when
        the list is empty (in which case the primary file is left untouched).
        """
        if not applicable:
            return None

        for log_entry, writes in applicable:
            for offset_primary, dirty_data in writes:
                self._primary.seek(offset_primary)
                self._primary.write(dirty_data)

            self._hive_flags = log_entry.hive_flags()
            self._hive_sequence = log_entry.sequence()
            self._hbins_size = log_entry.hbins_size()

        self.update_regf_header(self.latest_hive_sequence(), self.latest_hbins_size(), self.latest_hive_flags())
        return applicable[-1][0].sequence()

    def _primary_capacity(self):
        """
        Return the HBIN extent the primary file physically holds, derived from
        its current length. This is used as the growth baseline when the REGF
        header is unusable and its hbins_size cannot be trusted.
        """
        self._primary.seek(0, 2)
        size = self._primary.tell()
        return max(0, size - self._primary_regf.first_hbin_offset())

    def _apply_log_entries(self, log_entries):
        """
        Apply the given log entries to the primary file.

        Entries are applied in order and each one is atomic: an entry is fully
        validated before any byte of it is written, and an entry that cannot be
        applied stops the replay chain at the last fully applied sequence
        number. The header is only updated when at least one entry was applied,
        so a refused replay leaves the primary file untouched and still asking
        for recovery.

        Returns the sequence number of the last applied entry, or None when
        nothing was applied.
        """
        applicable = self._collect_applicable_entries(
            log_entries, self._primary_regf.hbins_size())
        return self._apply_applicable_entries(applicable)

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

    def recover_hive(self):
        """
        Recover the hive from the transaction log file.
        Returns the sequence number of the last log entry applied or None.
        """
        recover = self._primary_regf.recovery_required()

        if recover.recover_header:
            # The primary REGF block is unusable, so its hbins_size cannot be
            # trusted: validate hive growth against the extent the file
            # physically holds. The log header is only installed when there is
            # something to replay, otherwise the hive would be marked as
            # consistent without any of its data having been restored.
            entries = list(self._regf.log_entries())
            applicable = self._collect_applicable_entries(entries, self._primary_capacity())
            if not applicable:
                return None

            self._primary.seek(0)
            self._primary.write(self._log_buf[:512])
            self.reload_primary_regf()
            return self._apply_applicable_entries(applicable)

        if recover.recover_data:
            return self._apply_log_entries(self._regf.log_entries())

    def recover_hive_continue(self, expected_sequence):
        """
        Continue the recovery from the second transaction log file.
        Returns the sequence number of the last log entry applied or None.
        """
        if expected_sequence != self._regf.hive_sequence2():
            return None

        return self._apply_log_entries(self._regf.log_entries())

