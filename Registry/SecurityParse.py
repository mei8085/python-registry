#!/bin/python

#    This file is part of python-registry.
#
#   Copyright 2024 Will Ballenthin <william.ballenthin@mandiant.com>
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

# Added for python2-3 compatibility
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import absolute_import

import binascii
import struct
from enum import Enum

from Registry.RegistryParse import ParseException

# Self-relative security descriptor header length
SECURITY_DESCRIPTOR_HEADER_SIZE = 0x14
# ACL header length
ACL_HEADER_SIZE = 0x8
# Common ACE header length (type, flags, size)
ACE_HEADER_SIZE = 0x4
# ACE type specific access mask / header remainder (offset of the access mask
# in a classic ACE)
ACE_MASK_OFFSET = 0x4
# Minimum size of an ACCESS_ALLOWED/DENIED_ACE (8 byte header incl. mask)
ACCESS_ACE_HEADER_SIZE = 0x8
# Object ACE fixed prefix size (flags + mask + object flags)
OBJECT_ACE_HEADER_SIZE = 0xC
# SID minimum size (revision + sub authority count + 6 byte authority)
SID_MIN_SIZE = 0x8
# GUID size
GUID_SIZE = 0x10

# Security descriptor control bits
# see: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control
SE_OWNER_DEFAULTED = 0x0001
SE_GROUP_DEFAULTED = 0x0002
SE_DACL_PRESENT = 0x0004
SE_DACL_DEFAULTED = 0x0008
SE_SACL_PRESENT = 0x0010
SE_SACL_DEFAULTED = 0x0020
SE_DACL_AUTO_INHERIT_REQ = 0x0100
SE_SACL_AUTO_INHERIT_REQ = 0x0200
SE_DACL_AUTO_INHERITED = 0x0400
SE_SACL_AUTO_INHERITED = 0x0800
SE_DACL_PROTECTED = 0x1000
SE_SACL_PROTECTED = 0x2000
SE_RM_CONTROL_VALID = 0x4000
SE_SELF_RELATIVE = 0x8000

CONTROL_FLAGS = [
    (SE_OWNER_DEFAULTED, "OWNER_DEFAULTED"),
    (SE_GROUP_DEFAULTED, "GROUP_DEFAULTED"),
    (SE_DACL_PRESENT, "DACL_PRESENT"),
    (SE_DACL_DEFAULTED, "DACL_DEFAULTED"),
    (SE_SACL_PRESENT, "SACL_PRESENT"),
    (SE_SACL_DEFAULTED, "SACL_DEFAULTED"),
    (SE_DACL_AUTO_INHERIT_REQ, "DACL_AUTO_INHERIT_REQ"),
    (SE_SACL_AUTO_INHERIT_REQ, "SACL_AUTO_INHERIT_REQ"),
    (SE_DACL_AUTO_INHERITED, "DACL_AUTO_INHERITED"),
    (SE_SACL_AUTO_INHERITED, "SACL_AUTO_INHERITED"),
    (SE_DACL_PROTECTED, "DACL_PROTECTED"),
    (SE_SACL_PROTECTED, "SACL_PROTECTED"),
    (SE_RM_CONTROL_VALID, "RM_CONTROL_VALID"),
    (SE_SELF_RELATIVE, "SELF_RELATIVE"),
]

# ACE types
# see: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-sec_ace_type
ACCESS_MIN_MS_ACE_TYPE = 0x0
ACCESS_ALLOWED_ACE_TYPE = 0x0
ACCESS_DENIED_ACE_TYPE = 0x1
SYSTEM_AUDIT_ACE_TYPE = 0x2
SYSTEM_ALARM_ACE_TYPE = 0x3
ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x4
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x5
ACCESS_DENIED_OBJECT_ACE_TYPE = 0x6
SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x7
SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x8
ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x9
ACCESS_DENIED_CALLBACK_ACE_TYPE = 0xA
ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB
ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0xC
SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0xD
SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0xE
SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0xF
SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10
SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x12
ACCESS_MAX_MS_ACE_TYPE = 0x12

ACE_TYPE_NAMES = {
    ACCESS_ALLOWED_ACE_TYPE: "ACCESS_ALLOWED",
    ACCESS_DENIED_ACE_TYPE: "ACCESS_DENIED",
    SYSTEM_AUDIT_ACE_TYPE: "SYSTEM_AUDIT",
    SYSTEM_ALARM_ACE_TYPE: "SYSTEM_ALARM",
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE: "ACCESS_ALLOWED_COMPOUND",
    ACCESS_ALLOWED_OBJECT_ACE_TYPE: "ACCESS_ALLOWED_OBJECT",
    ACCESS_DENIED_OBJECT_ACE_TYPE: "ACCESS_DENIED_OBJECT",
    SYSTEM_AUDIT_OBJECT_ACE_TYPE: "SYSTEM_AUDIT_OBJECT",
    SYSTEM_ALARM_OBJECT_ACE_TYPE: "SYSTEM_ALARM_OBJECT",
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE: "ACCESS_ALLOWED_CALLBACK",
    ACCESS_DENIED_CALLBACK_ACE_TYPE: "ACCESS_DENIED_CALLBACK",
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: "ACCESS_ALLOWED_CALLBACK_OBJECT",
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: "ACCESS_DENIED_CALLBACK_OBJECT",
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE: "SYSTEM_AUDIT_CALLBACK",
    SYSTEM_ALARM_CALLBACK_ACE_TYPE: "SYSTEM_ALARM_CALLBACK",
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: "SYSTEM_AUDIT_CALLBACK_OBJECT",
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: "SYSTEM_ALARM_CALLBACK_OBJECT",
    SYSTEM_MANDATORY_LABEL_ACE_TYPE: "SYSTEM_MANDATORY_LABEL",
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: "SYSTEM_SCOPED_POLICY_ID",
}

# ACE inheritance/audit flags
OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
NO_PROPAGATE_INHERIT_ACE = 0x04
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10
SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
FAILED_ACCESS_ACE_FLAG = 0x80

ACE_FLAG_NAMES = [
    (OBJECT_INHERIT_ACE, "OBJECT_INHERIT"),
    (CONTAINER_INHERIT_ACE, "CONTAINER_INHERIT"),
    (NO_PROPAGATE_INHERIT_ACE, "NO_PROPAGATE_INHERIT"),
    (INHERIT_ONLY_ACE, "INHERIT_ONLY"),
    (INHERITED_ACE, "INHERITED"),
    (SUCCESSFUL_ACCESS_ACE_FLAG, "SUCCESSFUL_ACCESS"),
    (FAILED_ACCESS_ACE_FLAG, "FAILED_ACCESS"),
]

# Object ACE flags
ACE_OBJECT_TYPE_PRESENT = 0x1
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2

# Access rights masks
# Generic
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000
# Standard
MAXIMUM_ALLOWED = 0x02000000
ACCESS_SYSTEM_SECURITY = 0x01000000
SYNCHRONIZE = 0x00100000
WRITE_OWNER = 0x00080000
WRITE_DAC = 0x00040000
READ_CONTROL = 0x00020000
DELETE = 0x00010000
# Registry key specific
KEY_QUERY_VALUE = 0x0001
KEY_SET_VALUE = 0x0002
KEY_CREATE_SUB_KEY = 0x0004
KEY_ENUMERATE_SUB_KEYS = 0x0008
KEY_NOTIFY = 0x0010
KEY_CREATE_LINK = 0x0020
KEY_WOW64_64KEY = 0x0100
KEY_WOW64_32KEY = 0x0200

ACCESS_RIGHT_NAMES = [
    (GENERIC_READ, "GENERIC_READ"),
    (GENERIC_WRITE, "GENERIC_WRITE"),
    (GENERIC_EXECUTE, "GENERIC_EXECUTE"),
    (GENERIC_ALL, "GENERIC_ALL"),
    (MAXIMUM_ALLOWED, "MAXIMUM_ALLOWED"),
    (ACCESS_SYSTEM_SECURITY, "ACCESS_SYSTEM_SECURITY"),
    (SYNCHRONIZE, "SYNCHRONIZE"),
    (WRITE_OWNER, "WRITE_OWNER"),
    (WRITE_DAC, "WRITE_DAC"),
    (READ_CONTROL, "READ_CONTROL"),
    (DELETE, "DELETE"),
    (KEY_WOW64_64KEY, "KEY_WOW64_64KEY"),
    (KEY_WOW64_32KEY, "KEY_WOW64_32KEY"),
    (KEY_CREATE_LINK, "KEY_CREATE_LINK"),
    (KEY_NOTIFY, "KEY_NOTIFY"),
    (KEY_ENUMERATE_SUB_KEYS, "KEY_ENUMERATE_SUB_KEYS"),
    (KEY_CREATE_SUB_KEY, "KEY_CREATE_SUB_KEY"),
    (KEY_SET_VALUE, "KEY_SET_VALUE"),
    (KEY_QUERY_VALUE, "KEY_QUERY_VALUE"),
]

# Mandatory integrity level SIDs (S-1-16-*) use these rights
SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x1
SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0x2
SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP = 0x4

# A small table of commonly encountered well known SIDs.
# A complete table is intentionally out of scope; unknown SIDs are still
# rendered in their canonical S-R-I-S-S... form.
WELL_KNOWN_SIDS = {
    "S-1-0-0": "Null SID",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "LOCAL",
    "S-1-2-1": "CONSOLE LOGON",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-1": "CREATOR GROUP",
    "S-1-5-2": "NETWORK",
    "S-1-5-4": "INTERACTIVE",
    "S-1-5-6": "SERVICE",
    "S-1-5-7": "ANONYMOUS LOGON",
    "S-1-5-9": "ENTERPRISE DOMAIN CONTROLLERS",
    "S-1-5-10": "SELF",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "RESTRICTED",
    "S-1-5-13": "TERMINAL SERVER USER",
    "S-1-5-14": "REMOTE INTERACTIVE LOGON",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-556": "Network Configuration Operators",
    "S-1-5-32-557": "Incoming Forest Trust Builders",
    "S-1-5-32-558": "Performance Monitor Users",
    "S-1-5-32-559": "Performance Log Users",
    "S-1-5-32-560": "Windows Authorization Access Group",
    "S-1-5-32-561": "Terminal Server License Servers",
    "S-1-5-32-562": "Distributed COM Users",
    "S-1-5-32-568": "IIS_IUSRS",
    "S-1-5-32-569": "Cryptographic Operators",
    "S-1-5-32-573": "Event Log Readers",
    "S-1-5-32-574": "Certificate Service DCOM Access",
    "S-1-5-32-575": "RDS Remote Access Servers",
    "S-1-5-32-576": "RDS Endpoint Servers",
    "S-1-5-32-577": "RDS Management Servers",
    "S-1-5-32-578": "Hyper-V Administrators",
    "S-1-5-32-579": "Access Control Assistance Operators",
    "S-1-5-32-580": "Remote Management Users",
    "S-1-16-0": "Untrusted Mandatory Level",
    "S-1-16-4096": "Low Mandatory Level",
    "S-1-16-8192": "Medium Mandatory Level",
    "S-1-16-8448": "Medium Plus Mandatory Level",
    "S-1-16-12288": "High Mandatory Level",
    "S-1-16-16384": "System Mandatory Level",
    "S-1-16-20480": "Protected Process Mandatory Level",
}

# ACE families used for forensic classification
ALLOW_ACE_TYPES = frozenset([
    ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
])

DENY_ACE_TYPES = frozenset([
    ACCESS_DENIED_ACE_TYPE,
    ACCESS_DENIED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
])

OBJECT_ACE_TYPES = frozenset([
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
])


class AceCategory(Enum):
    """
    Forensic classification of an ACE.
    """
    EXPLICIT_ALLOW = "explicit-allow"
    EXPLICIT_DENY = "explicit-deny"
    INHERITED = "inherited"
    SYSTEM = "system"
    RAW = "raw"


def _flag_names(mask, table):
    return [name for bit, name in table if mask & bit]


def _unpack(fmt, data, offset, what):
    """
    Bounded struct.unpack_from. Never reads beyond `data`; any truncation is
    surfaced as a ParseException instead of a struct.error.
    """
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ParseException(
            "%s at offset 0x%x (%d bytes) exceeds the allowed boundary "
            "(available: %d bytes)" %
            (what, offset, size, len(data) - max(offset, 0)))
    try:
        return struct.unpack_from(fmt, data, offset)
    except struct.error as e:
        raise ParseException("Failed to parse %s at offset 0x%x: %s" %
                             (what, offset, e))


def format_guid(raw):
    """
    Render a 16 byte Windows (mixed endian) GUID in the conventional
    {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} form.
    """
    if raw is None or len(raw) != GUID_SIZE:
        return None
    d1, d2, d3 = struct.unpack_from(str("<IHH"), raw, 0)
    d4 = raw[8:16]
    return "{%08x-%04x-%04x-%s-%s}" % (
        d1, d2, d3,
        binascii.hexlify(d4[0:2]).decode("ascii"),
        binascii.hexlify(d4[2:8]).decode("ascii"))


class SID(object):
    """
    A Windows security identifier (SID), e.g. S-1-5-18.
    Parsed from a bounded byte string; no read can escape the buffer handed
    to the parser.
    """
    def __init__(self, data, offset=0):
        if offset < 0 or offset + SID_MIN_SIZE > len(data):
            raise ParseException(
                "Truncated SID at offset 0x%x: minimum %d bytes required, "
                "%d bytes available" %
                (offset, SID_MIN_SIZE, len(data) - max(offset, 0)))

        self._raw = data[offset:]
        revision, sub_authority_count = _unpack(
            str("<BB"), data, offset, "SID header")
        self._revision = revision
        self._sub_authority_count = sub_authority_count

        expected_size = SID_MIN_SIZE + 4 * sub_authority_count
        if offset + expected_size > len(data):
            raise ParseException(
                "Truncated SID at offset 0x%x: declares %d sub authorities "
                "(%d bytes total) but only %d bytes are available" %
                (offset, sub_authority_count, expected_size,
                 len(data) - offset))
        if sub_authority_count > 15:
            raise ParseException(
                "Invalid SID at offset 0x%x: sub authority count %d exceeds 15"
                % (offset, sub_authority_count))
        if revision != 1:
            raise ParseException(
                "Unsupported SID revision %d at offset 0x%x" %
                (revision, offset))

        self._raw = bytes(data[offset:offset + expected_size])
        # 6 byte big endian identifier authority
        authority_bytes = bytes(
            data[offset + 2:offset + 8])
        self._identifier_authority = 0
        for b in authority_bytes:
            self._identifier_authority = (
                (self._identifier_authority << 8) | b)

        self._sub_authorities = tuple(
            _unpack(str("<I"), data,
                    offset + 8 + 4 * i, "SID sub authority")[0]
            for i in range(sub_authority_count))

    def __str__(self):
        parts = ["S", str(self._revision),
                 str(self._identifier_authority)]
        parts.extend(str(a) for a in self._sub_authorities)
        return "-".join(parts)

    def __repr__(self):
        return "SID(%s)" % str(self)

    def __eq__(self, other):
        return isinstance(other, SID) and str(self) == str(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(str(self))

    def revision(self):
        return self._revision

    def identifier_authority(self):
        return self._identifier_authority

    def sub_authorities(self):
        return self._sub_authorities

    def raw_bytes(self):
        return self._raw

    def well_known_name(self):
        """
        Return a human readable name for a handful of common well known SIDs,
        or None if the SID is not in the table.
        """
        return WELL_KNOWN_SIDS.get(str(self))


class ACE(object):
    """
    A parsed access control entry.

    The four categories required for forensic work are available through
    category():
      - AceCategory.EXPLICIT_ALLOW: an allow ACE without INHERITED_ACE
      - AceCategory.EXPLICIT_DENY: a deny ACE without INHERITED_ACE
      - AceCategory.INHERITED:    any ACE carrying the INHERITED_ACE flag
      - AceCategory.SYSTEM:       audit / alarm / mandatory label / policy ACEs
    Unparseable entries are represented by the RawACE subclass instead.
    """
    def __init__(self, data, base, ace_type, ace_flags, ace_size):
        self._ace_type = ace_type
        self._ace_flags = ace_flags
        self._size = ace_size
        self._raw = bytes(data[base:base + ace_size])
        self._object_ace = ace_type in OBJECT_ACE_TYPES

        if self._object_ace:
            if ace_size < OBJECT_ACE_HEADER_SIZE + SID_MIN_SIZE:
                raise ParseException(
                    "Object ACE of type 0x%x at offset 0x%x has abnormal "
                    "length %d (minimum %d bytes)" %
                    (ace_type, base, ace_size,
                     OBJECT_ACE_HEADER_SIZE + SID_MIN_SIZE))
            self._mask = _unpack(str("<I"), data,
                                 base + ACE_MASK_OFFSET, "ACE access mask")[0]
            self._object_flags = _unpack(
                str("<I"), data, base + 0x8, "object ACE flags")[0]

            cursor = base + OBJECT_ACE_HEADER_SIZE
            if self._object_flags & ACE_OBJECT_TYPE_PRESENT:
                if cursor + GUID_SIZE > base + ace_size:
                    raise ParseException(
                        "Truncated object type GUID in ACE at offset 0x%x"
                        % base)
                self._object_type_guid_raw = bytes(
                    data[cursor:cursor + GUID_SIZE])
                cursor += GUID_SIZE
            else:
                self._object_type_guid_raw = None

            if (self._object_flags &
                    ACE_INHERITED_OBJECT_TYPE_PRESENT):
                if cursor + GUID_SIZE > base + ace_size:
                    raise ParseException(
                        "Truncated inherited object type GUID in ACE at "
                        "offset 0x%x" % base)
                self._inherited_object_type_guid_raw = bytes(
                    data[cursor:cursor + GUID_SIZE])
                cursor += GUID_SIZE
            else:
                self._inherited_object_type_guid_raw = None

            self._sid = SID(data, cursor)
            if cursor + len(self._sid.raw_bytes()) > base + ace_size:
                raise ParseException(
                    "ACE SID at offset 0x%x overruns its ACE boundary"
                    % cursor)
            self._application_data = bytes(
                data[cursor + len(self._sid.raw_bytes()):base + ace_size])
        else:
            if ace_size < ACCESS_ACE_HEADER_SIZE + SID_MIN_SIZE:
                raise ParseException(
                    "ACE of type 0x%x at offset 0x%x has abnormal length %d "
                    "(minimum %d bytes)" %
                    (ace_type, base, ace_size,
                     ACCESS_ACE_HEADER_SIZE + SID_MIN_SIZE))
            self._mask = _unpack(str("<I"), data,
                                 base + ACE_MASK_OFFSET, "ACE access mask")[0]
            self._object_flags = 0
            self._object_type_guid_raw = None
            self._inherited_object_type_guid_raw = None
            sid_offset = base + ACCESS_ACE_HEADER_SIZE
            self._sid = SID(data, sid_offset)
            if sid_offset + len(self._sid.raw_bytes()) > base + ace_size:
                raise ParseException(
                    "ACE SID at offset 0x%x overruns its ACE boundary"
                    % sid_offset)
            # Callback ACEs carry opaque application data after the SID.
            self._application_data = bytes(
                data[sid_offset + len(self._sid.raw_bytes()):
                     base + ace_size])

    @property
    def parsable(self):
        return True

    def ace_type(self):
        return self._ace_type

    def ace_type_name(self):
        return ACE_TYPE_NAMES.get(self._ace_type,
                                  "UNKNOWN_ACE_TYPE_0x%02x" % self._ace_type)

    def ace_flags(self):
        return self._ace_flags

    def ace_flag_names(self):
        return _flag_names(self._ace_flags, ACE_FLAG_NAMES)

    def is_inherited(self):
        return bool(self._ace_flags & INHERITED_ACE)

    def is_allow(self):
        return self._ace_type in ALLOW_ACE_TYPES

    def is_deny(self):
        return self._ace_type in DENY_ACE_TYPES

    def is_object_ace(self):
        return self._object_ace

    def mask(self):
        return self._mask

    def mask_names(self):
        """
        Return the names of the access right bits set in the access mask.
        Unnamed residual bits are not reported; inspect mask() for the raw
        value.
        """
        return _flag_names(self._mask, ACCESS_RIGHT_NAMES)

    def sid(self):
        return self._sid

    def object_flags(self):
        return self._object_flags

    def object_type_guid(self):
        return format_guid(self._object_type_guid_raw)

    def inherited_object_type_guid(self):
        return format_guid(self._inherited_object_type_guid_raw)

    def application_data(self):
        """
        Opaque data attached to callback ACEs after the SID; empty for the
        classic ACE types.
        """
        return self._application_data

    def raw_bytes(self):
        return self._raw

    def size(self):
        return self._size

    def category(self):
        if self.is_inherited():
            return AceCategory.INHERITED
        if self.is_allow():
            return AceCategory.EXPLICIT_ALLOW
        if self.is_deny():
            return AceCategory.EXPLICIT_DENY
        return AceCategory.SYSTEM

    def __str__(self):
        return "ACE(%s, %s, mask=0x%08x, sid=%s, flags=[%s])" % (
            self.ace_type_name(), self.category().value, self._mask,
            str(self._sid), ", ".join(self.ace_flag_names()))


class RawACE(object):
    """
    An ACE whose framing is structurally intact (so its exact byte extent is
    known and bounded) but whose type is not understood by this parser.

    The raw bytes are preserved for forensic inspection instead of aborting
    the whole ACL parse. It is deliberately distinct from ACE: parsable is
    False, sid() returns None and category() is AceCategory.RAW.
    """
    def __init__(self, data, base, ace_type, ace_flags, ace_size, reason):
        self._ace_type = ace_type
        self._ace_flags = ace_flags
        self._size = ace_size
        self._reason = reason
        self._raw = bytes(data[base:base + ace_size])

    @property
    def parsable(self):
        return False

    def ace_type(self):
        return self._ace_type

    def ace_type_name(self):
        return "UNKNOWN_ACE_TYPE_0x%02x" % self._ace_type

    def ace_flags(self):
        return self._ace_flags

    def ace_flag_names(self):
        return _flag_names(self._ace_flags, ACE_FLAG_NAMES)

    def is_inherited(self):
        return bool(self._ace_flags & INHERITED_ACE)

    def is_allow(self):
        return False

    def is_deny(self):
        return False

    def is_object_ace(self):
        return False

    def mask(self):
        return None

    def mask_names(self):
        return []

    def sid(self):
        return None

    def object_flags(self):
        return None

    def object_type_guid(self):
        return None

    def inherited_object_type_guid(self):
        return None

    def application_data(self):
        return self._raw

    def raw_bytes(self):
        return self._raw

    def size(self):
        return self._size

    def reason(self):
        return self._reason

    def category(self):
        return AceCategory.RAW

    def __str__(self):
        return "RawACE(type=0x%02x, flags=0x%02x, size=%d, reason=%s)" % (
            self._ace_type, self._ace_flags, self._size, self._reason)


class ACL(object):
    """
    An access control list (a DACL or SACL) together with its ACEs.

    ACEs of unknown types are yielded as RawACE objects; framing corruption
    (abnormal sizes, entries that overrun the ACL) raises ParseException.
    """
    def __init__(self, data, offset, end):
        """
        Parse the ACL at `data[offset:end]`. Both bounds are validated
        before any field is read.
        """
        if end < offset:
            raise ParseException(
                "ACL end offset 0x%x precedes start offset 0x%x" %
                (end, offset))
        if offset < 0 or offset + ACL_HEADER_SIZE > len(data) or \
                end > len(data):
            raise ParseException(
                "ACL at offset 0x%x exceeds the allowed boundary" % offset)
        if end - offset < ACL_HEADER_SIZE:
            raise ParseException(
                "Truncated ACL header at offset 0x%x: %d bytes available, "
                "%d required" %
                (offset, end - offset, ACL_HEADER_SIZE))

        revision, sbz1, acl_size, ace_count, sbz2 = _unpack(
            str("<BBHHH"), data, offset, "ACL header")

        if revision not in (2, 4):
            raise ParseException(
                "Unsupported ACL revision %d at offset 0x%x" %
                (revision, offset))
        if acl_size < ACL_HEADER_SIZE:
            raise ParseException(
                "ACL at offset 0x%x has abnormal AclSize %d" %
                (offset, acl_size))
        if offset + acl_size > end:
            raise ParseException(
                "ACL at offset 0x%x declares AclSize %d which overruns its "
                "allowed boundary at 0x%x" % (offset, acl_size, end))

        self._revision = revision
        self._declared_ace_count = ace_count
        self._size = acl_size
        self._raw = bytes(data[offset:offset + acl_size])
        self._aces = []

        cursor = offset + ACL_HEADER_SIZE
        acl_end = offset + acl_size
        parsed = 0
        while cursor < acl_end:
            if acl_end - cursor < ACE_HEADER_SIZE:
                raise ParseException(
                    "Truncated ACE header at offset 0x%x: only %d bytes "
                    "remain in the ACL" % (cursor, acl_end - cursor))

            ace_type, ace_flags, ace_size = _unpack(
                str("<BBH"), data, cursor, "ACE header")

            if ace_type == 0 and ace_flags == 0 and ace_size == 0:
                # Windows writers frequently pad an ACL to its allocation
                # size with zero bytes. Such padding is only legal when the
                # whole remainder of the ACL is zero; a zero size ACE header
                # embedded in non zero data means the ACL is corrupt.
                if any(b != 0 for b in
                       data[cursor:acl_end]):
                    raise ParseException(
                        "ACE at offset 0x%x has abnormal size 0 with non "
                        "zero trailing data" % cursor)
                break

            if ace_size < ACE_HEADER_SIZE:
                raise ParseException(
                    "ACE at offset 0x%x has abnormal size %d" %
                    (cursor, ace_size))
            if cursor + ace_size > acl_end:
                raise ParseException(
                    "ACE at offset 0x%x declares size %d which overruns the "
                    "ACL boundary at 0x%x" % (cursor, ace_size, acl_end))
            if ace_size % 4 != 0:
                # ACEs are always 4 byte aligned; a non aligned size means
                # the walk cannot be trusted.
                raise ParseException(
                    "ACE at offset 0x%x has non 4 byte aligned size %d" %
                    (cursor, ace_size))

            if ace_type > ACCESS_MAX_MS_ACE_TYPE:
                self._aces.append(RawACE(
                    data, cursor, ace_type, ace_flags, ace_size,
                    "unknown ACE type 0x%02x" % ace_type))
            else:
                # A known ACE type whose contents are truncated or malformed
                # raises ParseException: the ACL framing cannot be trusted.
                self._aces.append(
                    ACE(data, cursor, ace_type, ace_flags, ace_size))
            cursor += ace_size
            parsed += 1

        if ace_count != parsed:
            # The declared count is untrusted input; keep the parsed entries,
            # but expose the inconsistency for forensic review.
            self._ace_count_mismatch = True
        else:
            self._ace_count_mismatch = False

    def revision(self):
        return self._revision

    def declared_ace_count(self):
        return self._declared_ace_count

    def ace_count_mismatch(self):
        """
        True if the number of ACEs that could be walked differs from the
        count declared in the ACL header.
        """
        return self._ace_count_mismatch

    def size(self):
        return self._size

    def aces(self):
        return list(self._aces)

    def raw_bytes(self):
        return self._raw

    def __len__(self):
        return len(self._aces)

    def __iter__(self):
        return iter(self._aces)

    def __getitem__(self, index):
        return self._aces[index]


class SecurityDescriptor(object):
    """
    A parsed Windows self relative security descriptor, as stored in an
    registry SK record.

    The parse is strictly bounded by the byte string handed in (which, in
    practice, is exactly the SK cell's data): every offset is checked before
    it is dereferenced and every length is validated, so no read can escape
    the cell.

    Legal states are distinguished from corruption as follows:
      - a descriptor without SE_DACL_PRESENT has no DACL at all:
        dacl_present() is False and dacl() returns None;
      - a NULL DACL (SE_DACL_PRESENT set, offset zero) grants everyone
        access: dacl_present() and dacl_null() are True, dacl() is None;
      - an empty but present DACL denies everyone and parses to an ACL with
        zero ACEs;
      - structural problems (truncation, out of bounds offsets, abnormal
        lengths, a non self relative descriptor) raise ParseException.
    """
    def __init__(self, data):
        self._raw = bytes(data)
        if len(self._raw) < SECURITY_DESCRIPTOR_HEADER_SIZE:
            raise ParseException(
                "Truncated self relative security descriptor: %d bytes "
                "available, %d byte header required" %
                (len(self._raw), SECURITY_DESCRIPTOR_HEADER_SIZE))

        (revision, sbz1, control, owner_offset, group_offset,
         sacl_offset, dacl_offset) = _unpack(
            str("<BBHIIII"), self._raw, 0,
            "security descriptor header")

        if revision != 1:
            raise ParseException(
                "Unsupported security descriptor revision %d" % revision)
        if not (control & SE_SELF_RELATIVE):
            raise ParseException(
                "Security descriptor is not self relative "
                "(control=0x%04x)" % control)

        self._revision = revision
        self._control = control
        self._end = len(self._raw)

        self._owner = self._parse_sid(owner_offset, "owner")
        self._group = self._parse_sid(group_offset, "group")
        self._sacl = self._parse_acl(
            sacl_offset, bool(control & SE_SACL_PRESENT), "SACL")
        self._dacl = self._parse_acl(
            dacl_offset, bool(control & SE_DACL_PRESENT), "DACL")

    def _check_offset(self, offset, what):
        if offset == 0:
            return False
        if offset < SECURITY_DESCRIPTOR_HEADER_SIZE or \
                offset >= self._end:
            raise ParseException(
                "%s offset 0x%x is outside the allowed security descriptor "
                "boundary [0x%x, 0x%x)" %
                (what, offset, SECURITY_DESCRIPTOR_HEADER_SIZE, self._end))
        return True

    def _parse_sid(self, offset, what):
        if offset == 0:
            return None
        self._check_offset(offset, what)
        return SID(self._raw, offset)

    def _parse_acl(self, offset, present, what):
        """
        Returns a tuple (acl_or_None, is_null). Raises on inconsistency
        between the present flag and the offset, and on any out of bounds
        reference.
        """
        if not present:
            if offset != 0:
                raise ParseException(
                    "%s offset 0x%x is set although the corresponding "
                    "PRESENT control flag is clear" % (what, offset))
            return None
        if offset == 0:
            # Legal NULL ACL: explicit "no restrictions".
            return None
        self._check_offset(offset, what)
        return ACL(self._raw, offset, self._end)

    def revision(self):
        return self._revision

    def control(self):
        return self._control

    def control_flag_names(self):
        return _flag_names(self._control, CONTROL_FLAGS)

    def owner(self):
        return self._owner

    def group(self):
        return self._group

    def dacl_present(self):
        return bool(self._control & SE_DACL_PRESENT)

    def dacl_null(self):
        """
        A NULL DACL is present but has a zero offset: everyone is granted
        access. Distinct from dacl_present() being False (no DACL at all).
        """
        return self.dacl_present() and self._dacl is None

    def dacl_protected(self):
        return bool(self._control & SE_DACL_PROTECTED)

    def dacl_auto_inherited(self):
        return bool(self._control & SE_DACL_AUTO_INHERITED)

    def dacl_defaulted(self):
        return bool(self._control & SE_DACL_DEFAULTED)

    def dacl(self):
        """
        The parsed DACL as an ACL, or None when no DACL is present or the
        DACL is a legal NULL DACL (distinguish with dacl_present() and
        dacl_null()).
        """
        return self._dacl

    def sacl_present(self):
        return bool(self._control & SE_SACL_PRESENT)

    def sacl_null(self):
        return self.sacl_present() and self._sacl is None

    def sacl_protected(self):
        return bool(self._control & SE_SACL_PROTECTED)

    def sacl_auto_inherited(self):
        return bool(self._control & SE_SACL_AUTO_INHERITED)

    def sacl_defaulted(self):
        return bool(self._control & SE_SACL_DEFAULTED)

    def sacl(self):
        return self._sacl

    def aces(self):
        """
        All ACEs of the DACL, or an empty list when there is no DACL.
        """
        return self._dacl.aces() if self._dacl is not None else []

    def _aces_of_category(self, category):
        return [a for a in self.aces() if a.category() == category]

    def explicit_allow_aces(self):
        return self._aces_of_category(AceCategory.EXPLICIT_ALLOW)

    def explicit_deny_aces(self):
        return self._aces_of_category(AceCategory.EXPLICIT_DENY)

    def inherited_aces(self):
        return self._aces_of_category(AceCategory.INHERITED)

    def system_aces(self):
        return self._aces_of_category(AceCategory.SYSTEM)

    def raw_aces(self):
        return self._aces_of_category(AceCategory.RAW)

    def raw_bytes(self):
        return self._raw

    def __str__(self):
        owner = str(self._owner) if self._owner else "(none)"
        group = str(self._group) if self._group else "(none)"
        if not self.dacl_present():
            dacl_state = "absent"
        elif self.dacl_null():
            dacl_state = "NULL"
        else:
            dacl_state = "%d ACEs" % len(self._dacl)
        return ("SecurityDescriptor(owner=%s, group=%s, DACL=%s, "
                "control=[%s])" %
                (owner, group, dacl_state,
                 ", ".join(self.control_flag_names())))
