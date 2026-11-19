#!/usr/bin/python
# -*- coding: utf-8 -*-

#    This file is part of python-registry.
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

import os
import struct
import unittest

from Registry import Registry, RegistryParse, SecurityParse
from Registry.RegistryParse import ParseException
from Registry.SecurityParse import (
    SID, ACL, ACE, RawACE, SecurityDescriptor, AceCategory,
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    SYSTEM_AUDIT_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    OBJECT_INHERIT_ACE, CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE,
    INHERITED_ACE,
    SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
    SE_DACL_PROTECTED,
    KEY_QUERY_VALUE, KEY_SET_VALUE, READ_CONTROL, GENERIC_ALL,
)


def make_sid(identifier_authority, sub_authorities, revision=1):
    """
    Build the on-disk bytes of a SID.
    """
    out = struct.pack(str("<BB"), revision, len(sub_authorities))
    out += struct.pack(str(">Q"), identifier_authority)[2:]
    for sa in sub_authorities:
        out += struct.pack(str("<I"), sa)
    return out


def make_simple_ace(ace_type, flags, mask, sid_bytes):
    """
    Build a classic (non object) ACE.
    """
    body = struct.pack(str("<BBHI"), ace_type, flags, 0, mask) + sid_bytes
    size = len(body)
    # ACEs are 4 byte aligned.
    if size % 4:
        body += b"\x00" * (4 - size % 4)
        size = len(body)
    return struct.pack(str("<BBH"), ace_type, flags, size) + body[4:]


def make_acl(ace_bytes_list, revision=2):
    count = len(ace_bytes_list)
    size = 8 + sum(len(a) for a in ace_bytes_list)
    return struct.pack(str("<BBHHH"), revision, 0, size, count, 0) + \
        b"".join(ace_bytes_list)


def make_sd(owner=b"", group=b"", dacl=b"", sacl=b"",
            extra_control=0, revision=1):
    """
    Build a self relative security descriptor. Empty components yield zero
    offsets. Components are laid out in the conventional order; offsets are
    relative to the start of the descriptor.
    """
    header_size = 0x14
    parts = []
    cursor = header_size

    owner_off = cursor if owner else 0
    if owner:
        parts.append(owner)
        cursor += len(owner)

    group_off = cursor if group else 0
    if group:
        parts.append(group)
        cursor += len(group)

    sacl_off = cursor if sacl else 0
    if sacl:
        parts.append(sacl)
        cursor += len(sacl)

    dacl_off = cursor if dacl else 0
    if dacl:
        parts.append(dacl)
        cursor += len(dacl)

    control = SE_SELF_RELATIVE | extra_control
    if dacl:
        control |= SE_DACL_PRESENT
    if sacl:
        control |= SE_SACL_PRESENT

    header = struct.pack(str("<BBHIIII"), revision, 0, control,
                         owner_off, group_off, sacl_off, dacl_off)
    return header + b"".join(parts)


# Some well known SIDs used throughout the tests
SID_SYSTEM = make_sid(5, (18,))
SID_ADMINS = make_sid(5, (32, 544))
SID_USERS = make_sid(5, (32, 545))
SID_EVERYONE = make_sid(1, (0,))


class TestSID(unittest.TestCase):
    def test_canonical_string(self):
        self.assertEqual(str(SID(SID_SYSTEM)), "S-1-5-18")
        self.assertEqual(str(SID(SID_ADMINS)), "S-1-5-32-544")

    def test_well_known_name(self):
        self.assertEqual(SID(SID_SYSTEM).well_known_name(), "SYSTEM")
        self.assertEqual(SID(SID_ADMINS).well_known_name(),
                         "Administrators")
        self.assertIsNone(SID(make_sid(5, (999, 77))).well_known_name())

    def test_truncated_sid_raises(self):
        # Header declares two sub authorities but the buffer is cut short.
        truncated = struct.pack(str("<BB"), 1, 2) + b"\x00" * 6 + \
            struct.pack(str("<I"), 100)
        with self.assertRaises(ParseException):
            SID(truncated)

    def test_bad_revision_raises(self):
        bad = struct.pack(str("<BB"), 2, 1) + b"\x00" * 6 + \
            struct.pack(str("<I"), 100)
        with self.assertRaises(ParseException):
            SID(bad)

    def test_too_many_subauthorities_raises(self):
        bad = struct.pack(str("<BB"), 1, 16) + b"\x00" * 6
        with self.assertRaises(ParseException):
            SID(bad)

    def test_empty_buffer_raises(self):
        with self.assertRaises(ParseException):
            SID(b"")


class TestACEClassification(unittest.TestCase):
    def setUp(self):
        self.allow = make_simple_ace(
            ACCESS_ALLOWED_ACE_TYPE, 0,
            KEY_QUERY_VALUE | READ_CONTROL, SID_USERS)
        self.deny = make_simple_ace(
            ACCESS_DENIED_ACE_TYPE, 0, KEY_SET_VALUE, SID_EVERYONE)
        self.inherited_allow = make_simple_ace(
            ACCESS_ALLOWED_ACE_TYPE, INHERITED_ACE | CONTAINER_INHERIT_ACE,
            GENERIC_ALL, SID_ADMINS)
        self.inherited_deny = make_simple_ace(
            ACCESS_DENIED_ACE_TYPE, INHERITED_ACE,
            KEY_SET_VALUE, SID_EVERYONE)
        self.audit = make_simple_ace(
            SYSTEM_AUDIT_ACE_TYPE, 0, READ_CONTROL, SID_EVERYONE)
        self.mandatory = make_simple_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0, 1,
            make_sid(16, (4096,)))

    def _first_ace(self, ace_bytes):
        acl = make_acl([ace_bytes])
        return ACL(acl, 0, len(acl))[0]

    def test_explicit_allow(self):
        ace = self._first_ace(self.allow)
        self.assertIsInstance(ace, ACE)
        self.assertEqual(ace.category(), AceCategory.EXPLICIT_ALLOW)
        self.assertTrue(ace.is_allow())
        self.assertFalse(ace.is_inherited())
        self.assertEqual(ace.sid(), SID(SID_USERS))
        self.assertEqual(ace.mask(), KEY_QUERY_VALUE | READ_CONTROL)
        names = ace.mask_names()
        self.assertIn("KEY_QUERY_VALUE", names)
        self.assertIn("READ_CONTROL", names)

    def test_explicit_deny(self):
        ace = self._first_ace(self.deny)
        self.assertEqual(ace.category(), AceCategory.EXPLICIT_DENY)
        self.assertTrue(ace.is_deny())
        self.assertIn("KEY_SET_VALUE", ace.mask_names())

    def test_inherited_allow_and_deny(self):
        self.assertEqual(self._first_ace(self.inherited_allow).category(),
                         AceCategory.INHERITED)
        self.assertEqual(self._first_ace(self.inherited_deny).category(),
                         AceCategory.INHERITED)

    def test_inheritance_flags(self):
        ace = self._first_ace(self.inherited_allow)
        flags = ace.ace_flag_names()
        self.assertIn("INHERITED", flags)
        self.assertIn("CONTAINER_INHERIT", flags)

    def test_system_aces(self):
        self.assertEqual(self._first_ace(self.audit).category(),
                         AceCategory.SYSTEM)
        self.assertEqual(self._first_ace(self.mandatory).category(),
                         AceCategory.SYSTEM)
        self.assertEqual(
            self._first_ace(self.mandatory).ace_type_name(),
            "SYSTEM_MANDATORY_LABEL")

    def test_unknown_type_is_raw_ace(self):
        raw_type = 0x7F
        body = make_simple_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 1, SID_USERS)
        raw = struct.pack(str("<BBH"), raw_type, 0, len(body)) + body[4:]
        acl = make_acl([raw])
        ace = ACL(acl, 0, len(acl))[0]
        self.assertIsInstance(ace, RawACE)
        self.assertFalse(ace.parsable)
        self.assertEqual(ace.category(), AceCategory.RAW)
        self.assertIsNone(ace.sid())
        self.assertEqual(ace.raw_bytes(), raw)
        self.assertIn("unknown ACE type", ace.reason())

    def test_zero_size_ace_in_nonzero_data_raises(self):
        good_acl = make_acl([self.allow])
        good_size = struct.unpack_from(str("<H"), good_acl, 2)[0]
        # Declare an ACL that spans the good ACE plus a trailing ACE header
        # whose type/flags are non zero but whose size is 0: that is
        # corruption, not the all zero padding Windows writers emit.
        corrupted = struct.pack(str("<BBHHH"), 2, 0,
                                good_size + 4, 2, 0) + good_acl[8:] + \
            struct.pack(str("<BBH"), 1, 2, 0)
        with self.assertRaises(ParseException):
            ACL(corrupted, 0, len(corrupted))

    def test_truncated_ace_header_raises(self):
        good_acl = make_acl([self.allow])
        good_size = struct.unpack_from(str("<H"), good_acl, 2)[0]
        # Declared size includes two dangling bytes with no room for a
        # complete ACE header.
        corrupted = struct.pack(str("<BBHHH"), 2, 0,
                                good_size + 2, 2, 0) + good_acl[8:] + \
            b"\x01\x02"
        with self.assertRaises(ParseException):
            ACL(corrupted, 0, len(corrupted))

    def test_zero_padding_is_accepted(self):
        acl = make_acl([self.allow, self.deny])
        padded = acl + b"\x00" * 16
        parsed = ACL(padded, 0, len(padded))
        self.assertEqual(len(parsed), 2)
        self.assertFalse(parsed.ace_count_mismatch())

    def test_ace_overrunning_acl_raises(self):
        ace = make_simple_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 1, SID_USERS)
        # Declare an ACL smaller than the ACE it contains.
        acl = struct.pack(str("<BBHHH"), 2, 0, 12, 1, 0) + ace
        with self.assertRaises(ParseException):
            ACL(acl, 0, len(acl))

    def test_unaligned_ace_size_raises(self):
        bad = struct.pack(str("<BBHI"), ACCESS_ALLOWED_ACE_TYPE, 0, 9, 1) \
            + SID_USERS
        acl = struct.pack(str("<BBHHH"), 2, 0, 8 + len(bad), 1, 0) + bad
        with self.assertRaises(ParseException):
            ACL(acl, 0, len(acl))

    def test_bad_acl_revision_raises(self):
        acl = make_acl([self.allow], revision=1)
        with self.assertRaises(ParseException):
            ACL(acl, 0, len(acl))


class TestObjectACE(unittest.TestCase):
    def test_object_allow_ace_with_guids(self):
        # Object ACE layout: type, flags, size, mask, object flags, then
        # GUIDs for each present object type, then the trustee SID.
        guid1 = b"\x11" * 16
        guid2 = b"\x22" * 16
        sid = SID_USERS
        body = struct.pack(str("<II"), KEY_QUERY_VALUE, 0x3) + \
            guid1 + guid2 + sid
        size = 4 + len(body)
        raw = struct.pack(str("<BBH"),
                          ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0, size) + body
        acl = make_acl([raw])
        ace = ACL(acl, 0, len(acl))[0]
        self.assertTrue(ace.is_object_ace())
        self.assertEqual(ace.category(), AceCategory.EXPLICIT_ALLOW)
        self.assertEqual(ace.sid(), SID(sid))
        self.assertIsNotNone(ace.object_type_guid())
        self.assertIsNotNone(ace.inherited_object_type_guid())
        self.assertTrue(ace.object_type_guid().startswith("{"))

    def test_truncated_object_guid_raises(self):
        sid = SID_USERS
        # Flags claim an object type GUID, but it is missing.
        body = struct.pack(str("<II"), 0x1, KEY_QUERY_VALUE) + sid
        size = 4 + len(body)
        raw = struct.pack(str("<BBH"),
                          ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0, size) + body
        acl = make_acl([raw])
        with self.assertRaises(ParseException):
            ACL(acl, 0, len(acl))


class TestSecurityDescriptor(unittest.TestCase):
    def test_full_descriptor(self):
        aces = [
            make_simple_ace(ACCESS_DENIED_ACE_TYPE, 0,
                            KEY_SET_VALUE, SID_EVERYONE),
            make_simple_ace(ACCESS_ALLOWED_ACE_TYPE,
                            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
                            INHERIT_ONLY_ACE,
                            GENERIC_ALL, SID_ADMINS),
            make_simple_ace(ACCESS_ALLOWED_ACE_TYPE, INHERITED_ACE,
                            READ_CONTROL, SID_SYSTEM),
        ]
        dacl = make_acl(aces)
        data = make_sd(owner=SID_ADMINS, group=SID_SYSTEM, dacl=dacl,
                       extra_control=SE_DACL_PROTECTED)
        sd = SecurityDescriptor(data)

        self.assertEqual(sd.owner(), SID(SID_ADMINS))
        self.assertEqual(sd.group(), SID(SID_SYSTEM))
        self.assertTrue(sd.dacl_present())
        self.assertFalse(sd.dacl_null())
        self.assertTrue(sd.dacl_protected())
        self.assertEqual(len(sd.dacl()), 3)
        self.assertEqual(len(sd.explicit_deny_aces()), 1)
        self.assertEqual(len(sd.explicit_allow_aces()), 1)
        self.assertEqual(len(sd.inherited_aces()), 1)
        self.assertEqual(len(sd.raw_aces()), 0)
        self.assertIn("DACL_PROTECTED", sd.control_flag_names())

    def test_no_dacl_is_legal(self):
        # SE_DACL_PRESENT clear and zero offset: no DACL at all.
        data = make_sd(owner=SID_SYSTEM, group=SID_SYSTEM)
        sd = SecurityDescriptor(data)
        self.assertFalse(sd.dacl_present())
        self.assertFalse(sd.dacl_null())
        self.assertIsNone(sd.dacl())
        self.assertEqual(sd.aces(), [])

    def test_null_dacl_is_legal(self):
        # SE_DACL_PRESENT set with a zero offset: explicit NULL DACL.
        header = struct.pack(
            str("<BBHIIII"), 1, 0,
            SE_SELF_RELATIVE | SE_DACL_PRESENT, 0x14, 0x14, 0, 0)
        data = header + SID_SYSTEM + SID_SYSTEM
        sd = SecurityDescriptor(data)
        self.assertTrue(sd.dacl_present())
        self.assertTrue(sd.dacl_null())
        self.assertIsNone(sd.dacl())

    def test_empty_dacl_denies_everyone(self):
        # Present, non null DACL containing zero ACEs.
        dacl = make_acl([])
        data = make_sd(owner=SID_SYSTEM, group=SID_SYSTEM, dacl=dacl)
        sd = SecurityDescriptor(data)
        self.assertTrue(sd.dacl_present())
        self.assertFalse(sd.dacl_null())
        self.assertEqual(len(sd.dacl()), 0)

    def test_truncated_header_raises(self):
        with self.assertRaises(ParseException):
            SecurityDescriptor(b"\x01\x00")

    def test_not_self_relative_raises(self):
        data = make_sd(owner=SID_SYSTEM, group=SID_SYSTEM)
        data = data[:2] + \
            struct.pack(str("<H"), SE_DACL_PRESENT) + data[4:]
        with self.assertRaises(ParseException):
            SecurityDescriptor(data)

    def test_owner_offset_out_of_bounds_raises(self):
        data = bytearray(make_sd(owner=SID_SYSTEM, group=SID_SYSTEM))
        struct.pack_into(str("<I"), data, 0x8, 0xFFFF)
        with self.assertRaises(ParseException):
            SecurityDescriptor(bytes(data))

    def test_dacl_offset_out_of_bounds_raises(self):
        dacl = make_acl([make_simple_ace(
            ACCESS_ALLOWED_ACE_TYPE, 0, 1, SID_USERS)])
        data = bytearray(make_sd(owner=SID_SYSTEM, group=SID_SYSTEM,
                                 dacl=dacl))
        struct.pack_into(str("<I"), data, 0x14, len(data) + 4)
        with self.assertRaises(ParseException):
            SecurityDescriptor(bytes(data))

    def test_present_flag_without_offset_consistency(self):
        # DACL flag clear but a non zero offset is corruption.
        dacl = make_acl([make_simple_ace(
            ACCESS_ALLOWED_ACE_TYPE, 0, 1, SID_USERS)])
        data = bytearray(make_sd(owner=SID_SYSTEM, group=SID_SYSTEM,
                                 dacl=dacl))
        control = struct.unpack_from(str("<H"), data, 2)[0]
        struct.pack_into(str("<H"), data, 2,
                         control & ~SE_DACL_PRESENT)
        with self.assertRaises(ParseException):
            SecurityDescriptor(bytes(data))

    def test_truncated_dacl_header_raises(self):
        # Point the DACL offset at the final two bytes of the buffer.
        data = bytearray(make_sd(owner=SID_SYSTEM, group=SID_SYSTEM))
        dacl_off = len(data) - 2
        struct.pack_into(str("<I"), data, 0x14, dacl_off)
        control = struct.unpack_from(str("<H"), data, 2)[0]
        struct.pack_into(str("<H"), data, 2,
                         control | SE_DACL_PRESENT)
        with self.assertRaises(ParseException):
            SecurityDescriptor(bytes(data))

    def test_sacl_round_trip(self):
        sacl = make_acl([make_simple_ace(
            SYSTEM_AUDIT_ACE_TYPE, 0, READ_CONTROL, SID_EVERYONE)])
        data = make_sd(owner=SID_SYSTEM, group=SID_SYSTEM, sacl=sacl)
        sd = SecurityDescriptor(data)
        self.assertTrue(sd.sacl_present())
        self.assertEqual(len(sd.sacl()), 1)
        self.assertEqual(sd.sacl()[0].category(), AceCategory.SYSTEM)

    def test_bad_revision_raises(self):
        data = bytearray(make_sd(owner=SID_SYSTEM, group=SID_SYSTEM))
        data[0] = 2
        with self.assertRaises(ParseException):
            SecurityDescriptor(bytes(data))


def make_sk_cell(descriptor_bytes):
    """
    Build an SK HBIN cell: 4 byte (negative) size prefix, the 0x14 byte SK
    header, then the security descriptor. The cell size includes the 4 byte
    size prefix, as on disk.
    """
    cell_size = 4 + 0x14 + len(descriptor_bytes)
    prefix = struct.pack(str("<i"), -cell_size)
    # "sk" + previous SK offset + next SK offset + 8 reserved bytes = 0x14
    sk_header = b"sk" + struct.pack(str("<II"), 0xFFFFFFFF, 0xFFFFFFFF) + \
        b"\x00" * 10
    assert len(sk_header) == 0x14
    return prefix + sk_header + descriptor_bytes


class TestSKRecordBounded(unittest.TestCase):
    def _sk_record(self, cell_bytes):
        # Place the cell at offset 0x1000 inside a buffer with slack after it.
        base = 0x1000
        slack = 0x100
        buf = b"\x00" * base + cell_bytes + b"\xCC" * slack
        cell = RegistryParse.HBINCell(buf, base, None)
        return cell, RegistryParse.SKRecord(buf, cell.data_offset(), cell)

    def test_raw_descriptor_is_bounded_by_cell(self):
        sd_bytes = make_sd(owner=SID_SYSTEM, group=SID_SYSTEM,
                           dacl=make_acl([]))
        cell, sk = self._sk_record(make_sk_cell(sd_bytes))
        raw = sk.raw_security_descriptor()
        # The raw descriptor is exactly the cell content after the 0x14 byte
        # SK record header: it must neither include header bytes nor the
        # 0xCC slack bytes placed after the cell.
        self.assertEqual(raw, sd_bytes)
        self.assertEqual(len(raw), cell.size() - 4 - 0x14)
        self.assertNotIn(b"\xCC", raw)
        # And it parses.
        parsed = sk.security_descriptor()
        self.assertEqual(parsed.owner(), SID(SID_SYSTEM))

    def test_truncated_descriptor_raises_and_does_not_read_past_cell(self):
        good = make_sd(owner=SID_SYSTEM, group=SID_SYSTEM,
                       dacl=make_acl([]))
        # A correctly sized cell whose descriptor has been overwritten in
        # place with a short blob: the cell size still spans the original
        # extent, so the parser must raise on the truncated header rather
        # than dereference anything outside the cell.
        cell_bytes = make_sk_cell(good)
        cell_size = struct.unpack_from(str("<i"), cell_bytes, 0)[0] * -1
        chopped = b"\x01\x00" + b"\x00" * (cell_size - 4 - 0x14 - 2)
        corrupted = cell_bytes[:4 + 0x14] + chopped
        self.assertEqual(len(corrupted), len(cell_bytes))
        cell, sk = self._sk_record(corrupted)
        with self.assertRaises(ParseException):
            sk.security_descriptor()

    def test_out_of_bounds_offset_never_reads_slack(self):
        # A descriptor whose DACL offset points past the cell into the
        # 0xCC marked slack area must raise without those bytes ever being
        # treated as registry data.
        good = make_sd(owner=SID_SYSTEM, group=SID_SYSTEM,
                       dacl=make_acl([]))
        cell, sk = self._sk_record(make_sk_cell(good))
        raw = bytearray(sk.raw_security_descriptor())
        # DACL offset is the last header DWORD (offset 0x10 of the SD).
        struct.pack_into(str("<I"), raw, 0x10, len(raw) + 8)
        # Rebuild the cell around the tampered descriptor.
        base = 0x1000
        prefix = struct.pack(
            str("<i"), -(4 + 0x14 + len(raw)))
        sk_header = b"sk" + struct.pack(
            str("<II"), 0xFFFFFFFF, 0xFFFFFFFF) + b"\x00" * 10
        buf = b"\x00" * base + prefix + sk_header + bytes(raw) + \
            b"\xCC" * 0x100
        cell2 = RegistryParse.HBINCell(buf, base, None)
        sk2 = RegistryParse.SKRecord(buf, cell2.data_offset(), cell2)
        with self.assertRaises(ParseException):
            sk2.security_descriptor()

    def test_abnormal_cell_size_raises(self):
        # A cell whose size is smaller than the SK header.
        buf = b"\x00" * 0x1000 + struct.pack(str("<i"), -4) + b"sk" + \
            b"\x00" * 0x40
        cell = RegistryParse.HBINCell(buf, 0x1000, None)
        sk = RegistryParse.SKRecord(buf, cell.data_offset(), cell)
        with self.assertRaises(ParseException):
            sk.raw_security_descriptor()


class TestRealHive(unittest.TestCase):
    SYSTEM_PATH = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "testing", "reg_samples", "new_log_1", "SYSTEM")
    ISSUE22_PATH = os.path.join(
        os.path.dirname(__file__), "reg_samples", "issue22.hive")

    def test_all_sk_records_parse(self):
        buf = open(self.SYSTEM_PATH, "rb").read()
        regf = RegistryParse.REGFBlock(buf, 0, None)
        count = 0
        ace_count = 0
        for hbin in regf.hbins():
            for cell in hbin.cells():
                if cell.data_id() == b"sk":
                    count += 1
                    sd = cell.child().security_descriptor()
                    self.assertIsNotNone(sd.owner())
                    self.assertIsNotNone(sd.group())
                    self.assertTrue(sd.dacl_present())
                    self.assertFalse(sd.dacl_null())
                    for ace in sd.dacl():
                        ace_count += 1
                        if ace.parsable:
                            self.assertIsNotNone(ace.sid())
                            self.assertIsInstance(ace.mask(), int)
                            self.assertIn(
                                ace.category(),
                                (AceCategory.EXPLICIT_ALLOW,
                                 AceCategory.EXPLICIT_DENY,
                                 AceCategory.INHERITED,
                                 AceCategory.SYSTEM))
                        else:
                            self.assertEqual(ace.category(),
                                             AceCategory.RAW)
        self.assertGreater(count, 100)
        self.assertGreater(ace_count, 1000)

    def test_high_level_key_security_descriptor(self):
        reg = Registry.Registry(self.ISSUE22_PATH)
        key = reg.root()
        sd = key.security_descriptor()
        self.assertTrue(sd.dacl_present())
        self.assertIsNotNone(sd.owner())
        # Reading values must be unaffected by the security descriptor.
        self.assertGreaterEqual(len(key.values()), 1)
        self.assertEqual(
            key.value("TimeZoneKeyName").value(),
            u"W. Europe Standard Time")

    def test_missing_sk_raises_structure_not_exist(self):
        # The root NK of the issue22 hive still has an SK; instead craft the
        # check by validating the low level predicate logic on a key whose SK
        # offset is the sentinel 0xFFFFFFFF.
        buf = open(self.ISSUE22_PATH, "rb").read()
        regf = RegistryParse.REGFBlock(buf, 0, None)
        nk = regf.first_key()
        # Every key in this hive has an SK, so first confirm the positive
        # path, then flip the field in a copied buffer for the negative path.
        self.assertTrue(nk.has_security_descriptor())
        nk_offset = nk.offset()
        corrupted = bytearray(buf)
        struct.pack_into(str("<I"), corrupted, nk_offset + 0x2C,
                         0xFFFFFFFF)
        nk2 = RegistryParse.NKRecord(bytes(corrupted), nk_offset,
                                     nk.parent())
        self.assertFalse(nk2.has_security_descriptor())
        with self.assertRaises(
                RegistryParse.RegistryStructureDoesNotExist):
            nk2.security_descriptor()

    def test_corrupted_descriptor_does_not_break_value_reading(self):
        import io
        buf = bytearray(open(self.ISSUE22_PATH, "rb").read())
        regf = RegistryParse.REGFBlock(bytes(buf), 0, None)
        nk = regf.first_key()
        sk = nk.sk_record()
        # Corrupt the security descriptor revision (first SD byte, located
        # 0x14 bytes into the SK record).
        buf[sk.offset() + 0x14] = 0x7F
        reg = Registry.Registry(io.BytesIO(bytes(buf)))
        key = reg.root()
        with self.assertRaises(ParseException):
            key.security_descriptor()
        # Key/value semantics remain intact despite the bad descriptor.
        self.assertEqual(
            key.value("TimeZoneKeyName").value(),
            u"W. Europe Standard Time")
        self.assertEqual(len(key.subkeys()), 0)


if __name__ == "__main__":
    unittest.main()
