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

import sys
import struct
import ntpath
from enum import Enum

from . import RegistryParse

RegSZ = 0x0001
RegExpandSZ = 0x0002
RegBin = 0x0003
RegDWord = 0x0004
RegMultiSZ = 0x0007
RegQWord = 0x000B
RegNone = 0x0000
RegBigEndian = 0x0005
RegLink = 0x0006
RegResourceList = 0x0008
RegFullResourceDescriptor = 0x0009
RegResourceRequirementsList = 0x000A
RegFileTime = 0x0010

DEVPROP_MASK_TYPE = 0x00000FFF

class HiveType(Enum):
    UNKNOWN = ""
    NTUSER = "ntuser.dat"
    SAM = "sam"
    SECURITY = "security"
    SOFTWARE = "software"
    SYSTEM = "system"
    USRCLASS = "usrclass.dat"
    BCD = "bcd"
    COMPONENTS = "components"
    DEFAULT = "default"
    SCHEMA = "schema.dat"
    SETTINGS = "settings.dat"


class RegistryKeyHasNoParentException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """
        Constructor.
        Arguments:
        - `value`: A string description.
        """
        super(RegistryKeyHasNoParentException, self).__init__(value)

    def __str__(self):
        return "Registry key has no parent key: %s" % (self._value)


class RegistryKeyNotFoundException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """

        Arguments:
        - `value`:
        """
        super(RegistryKeyNotFoundException, self).__init__(value)

    def __str__(self):
        return "Registry key not found: %s" % (self._value)

class RegistryValueNotFoundException(RegistryParse.RegistryStructureDoesNotExist):
    """
    """
    def __init__(self, value):
        """

        Arguments:
        - `value`:
        """
        super(RegistryValueNotFoundException, self).__init__(value)

    def __str__(self):
        return "Registry value not found: %s" % (self._value)


# Re-exported so callers can classify damaged subkey indexes reported by
# Registry.recovery_errors() / RegistryKey walks without reaching into
# the low level parsing module.
SubkeyIndexError = RegistryParse.SubkeyIndexError
SubkeyIndexErrorKind = RegistryParse.SubkeyIndexErrorKind
SubkeyTraversal = RegistryParse.SubkeyTraversal

class RegistryValue(object):
    """
    This is a high level structure for working with the Windows Registry.
    It represents the 3-tuple of (name, type, value) associated with 
      a registry value.
    """
    def __init__(self, vkrecord):
        self._vkrecord = vkrecord

    def __repr__(self):
        return 'RegistryValue(name="{0}", value="{1}", type="{2}")'.format(self.name(), self.value(), self.value_type_str())
        
    def name(self):
        """
        Get the name of the value as a string.
        The name of the default value is returned as "(default)".
        """
        if self._vkrecord.has_name():
            return self._vkrecord.name()
        else:
            return  "(default)"

    def value_type(self):
        """
        Get the type of the value as an integer constant.

        One of:
         - RegSZ = 0x0001
         - RegExpandSZ = 0x0002
         - RegBin = 0x0003
         - RegDWord = 0x0004
         - RegMultiSZ = 0x0007
         - RegQWord = 0x000B
         - RegNone = 0x0000
         - RegBigEndian = 0x0005
         - RegLink = 0x0006
         - RegResourceList = 0x0008
         - RegFullResourceDescriptor = 0x0009
         - RegResourceRequirementsList = 0x000A
         - RegUint8 = 0x101
         - RegInt16 = 0x102
         - RegUint16 = 0x103
         - RegInt32 = 0x104
         - RegUint32 = 0x105
         - RegInt64 = 0x106
         - RegUint64 = 0x107
         - RegFloat = 0x108
         - RegDouble = 0x109
         - RegUnicodeChar = 0x10A
         - RegBoolean = 0x10B
         - RegUnicodeString = 0x10C
         - RegCompositeValue = 0x10D
         - RegDateTimeOffset = 0x10E
         - RegTimeSpan = 0x10F
         - RegGUID = 0x110
         - RegUnk111 = 0x111
         - RegUnk112 = 0x112
         - RegUnk113 = 0x113
         - RegBytesArray = 0x114
         - RegInt16Array = 0x115
         - RegUint16Array = 0x116
         - RegInt32Array = 0x117
         - RegUInt32Array = 0x118
         - RegInt64Array = 0x119
         - RegUInt64Array = 0x11A
         - RegFloatArray = 0x11B
         - RegDoubleArray = 0x11C
         - RegUnicodeCharArray = 0x11D
         - RegBooleanArray = 0x11E
         - RegUnicodeStringArray = 0x11F
        """
        return self._vkrecord.data_type()

    def value_type_str(self):
        """
        Get the type of the value as a string.

        One of:
         - RegSZ
         - RegExpandSZ
         - RegBin
         - RegDWord
         - RegMultiSZ
         - RegQWord
         - RegNone
         - RegBigEndian
         - RegLink
         - RegResourceList
         - RegFullResourceDescriptor
         - RegResourceRequirementsList
         - RegUint8
         - RegInt16
         - RegUint16
         - RegInt32
         - RegUint32
         - RegInt64
         - RegUint64
         - RegFloat
         - RegDouble
         - RegUnicodeChar
         - RegBoolean
         - RegUnicodeString
         - RegCompositeValue
         - RegDateTimeOffset
         - RegTimeSpan
         - RegGUID
         - RegUnk111
         - RegUnk112
         - RegUnk113
         - RegBytesArray
         - RegInt16Array
         - RegUint16Array
         - RegInt32Array
         - RegUInt32Array
         - RegInt64Array
         - RegUInt64Array
         - RegFloatArray
         - RegDoubleArray
         - RegUnicodeCharArray
         - RegBooleanArray
         - RegUnicodeStringArray
        """
        return self._vkrecord.data_type_str()

    def value(self, overrun=0):
        return self._vkrecord.data(overrun)

    def raw_data(self, overrun=0):
        return self._vkrecord.raw_data(overrun)

    def timestamp(self):
        """
        Get the last modified timestamp as a Python datetime. Only valid for
        AppContainer settings.dat reg hive
        """
        return self._vkrecord.timestamp()


class RegistryKey(object):
    """
    A high level structure for use in traversing the Windows Registry.
    A RegistryKey is a node in a tree-like structure.
    A RegistryKey may have a set of values associated with it,
      as well as a last modified timestamp.
    """
    def __init__(self, nkrecord):
        """

        Arguments:
        - `NKRecord`:
        """
        self._nkrecord = nkrecord

    def __str__(self):
        return "Registry Key %s with %d values and %d subkeys" % \
            (self.path(), len(self.values()), len(self.subkeys()))

    def __repr__(self):
        return 'RegistryKey(name="{0}", path="{1}")'.format(self.name(), self.path())
    

    def __getitem__(self, key):
        return self.value(key)

    def timestamp(self):
        """
        Get the last modified timestamp as a Python datetime.
        """
        return self._nkrecord.timestamp()

    def name(self):
        """
        Get the name of the key as a string.

        For example, "Windows" if the key path were
        /{hive name}/SOFTWARE/Microsoft/Windows
        See RegistryKey.path() to get the complete key name.
        """
        return self._nkrecord.name()

    def path(self):
        """
        Get the full path of the RegistryKey as a string.
        For example, "/{hive name}/SOFTWARE/Microsoft/Windows"
        """
        return self._nkrecord.path()

    def cell_offset(self):
        """
        Get the absolute offset (within the hive image) of the HBIN cell that
        stores this key's NK record.

        Together with path(), this identifies the source unit from which the
        key was recovered. It is stable even when damaged indexes reference
        the same key more than once, so it can be used to tell genuine
        same-named sibling keys apart from duplicate index entries.
        """
        return self._nkrecord.cell_offset()

    def parent(self):
        """
        Get the parent RegistryKey of this key, or raise
        RegistryKeyHasNoParentException if it does not exist (for example,
        the root key has no parent).
        """
        # there may be a memory inefficiency here, since we create
        # a new RegistryKey from the NKRecord parent key, rather
        # than using the parent of this instance, if it exists.
        try:
            return RegistryKey(self._nkrecord.parent_key())
        except RegistryParse.ParseException:
            raise RegistryKeyHasNoParentException(self.name())

    def subkeys(self, traversal=None):
        """
        Return a list of all subkeys.
        Each element in the list is a RegistryKey.
        If the key has no subkeys, the empty list is returned.

        Traversal of the ri/lf/lh/li indexes is resilient: cyclic index
        references are broken, duplicate references are suppressed and
        entries that do not resolve to a valid key are skipped, so a single
        damaged index cannot prevent the unaffected sibling keys from being
        returned. Any such problem is recorded as a SubkeyIndexError.

        Arguments:
        - `traversal`: optional SubkeyTraversal object. Pass the same
              instance to several calls (as Registry.walk does) to share the
              cycle/duplicate state and to collect every SubkeyIndexError in
              one place. When omitted, a private traversal is created for
              this call; its errors are discarded once the list is built.
        """
        if self._nkrecord.subkey_number() == 0:
            return []

        try:
            subkey_list = self._nkrecord.subkey_list()
        except (RegistryParse.RegistryStructureDoesNotExist,
                RegistryParse.ParseException, struct.error):
            # The index header itself is unusable; there are no siblings we
            # can recover through it. A shared traversal still gets a record.
            if traversal is not None:
                traversal.record(RegistryParse.SubkeyIndexError(
                    RegistryParse.SubkeyIndexErrorKind.INVALID_REFERENCE,
                    None, -1, -1,
                    "subkey list of '%s' could not be parsed" % self.path(),
                    self._nkrecord))
            return []

        return [RegistryKey(k) for k in subkey_list.keys(traversal)]

    def subkey(self, name, traversal=None):
        """
        Return the subkey with a given name as a RegistryKey.
        Raises RegistryKeyNotFoundException if the subkey with
          the given name does not exist.

        The lookup goes through the same resilient index traversal as
        subkeys(), so a damaged entry cannot hide an unaffected sibling that
        happens to share the name.
        """
        if self._nkrecord.subkey_number() == 0:
            raise RegistryKeyNotFoundException(self.path() + "\\" + name)

        for k in self.subkeys(traversal):
            if k.name().lower() == name.lower():
                return k
        raise RegistryKeyNotFoundException(self.path() + "\\" + name)

    def values(self):
        """
        Return a list containing the values associated with this RegistryKey.
        Each element of the list will be a RegistryValue.
        If there are no values associated with this RegistryKey, then the
        empty list is returned.
        """
        try:
            return [RegistryValue(v) for v in self._nkrecord.values_list().values()]
        except RegistryParse.RegistryStructureDoesNotExist:
            return []

    def value(self, name):
        """
        Return the value with the given name as a RegistryValue.
        Raises RegistryValueNotFoundExceptiono if the value with
          the given name does not exist.
        """
        if name == "(default)":
            name = ""
        try:
            for v in self._nkrecord.values_list().values():
                if v.name().lower() == name.lower():
                    return RegistryValue(v)
        except RegistryParse.RegistryStructureDoesNotExist:
            raise RegistryValueNotFoundException(self.path() + " : " + name)
        raise RegistryValueNotFoundException(self.path() + " : " + name)

    def find_key(self, path):
        """
        Perform a search for a RegistryKey with a specific path.
        """
        if len(path) == 0:
            return self

        (immediate, _, future) = path.partition("\\")
        return self.subkey(immediate).find_key(future)

    def walk(self, traversal=None):
        """
        Depth-first generator over this key and all of its descendants.

        This is the forensic entry point for damaged hives. A single shared
        SubkeyTraversal guarantees:
          - cyclic ri/lf/lh/li references terminate instead of looping,
          - an NK cell is yielded at most once even if several indexes point
            at it, while distinct same-named sibling keys are all yielded,
          - unreadable branches are skipped but never abort the walk, so the
            unrelated parts of the hive are still extracted,
          - every skipped/duplicated/cyclic entry is recorded as a
            SubkeyIndexError retrievable via traversal.errors (or, when used
            through Registry.walk, via Registry.recovery_errors()).

        Each yielded RegistryKey retains its path() and cell_offset(), which
        together identify the source unit the evidence came from.

        Arguments:
        - `traversal`: optional SubkeyTraversal to share with other walks;
              a new one is created when omitted.
        """
        if traversal is None:
            traversal = SubkeyTraversal()

        # The starting key is claimed here. Every descendant is claimed while
        # its parent's indexes are expanded in subkeys(), so cells are never
        # re-claimed and the explicit stack below only needs to expand nodes.
        if not traversal.claim_nk(self._nkrecord.cell_offset()):
            return

        stack = [self._nkrecord]
        while stack:
            nk = stack.pop()
            key = RegistryKey(nk)
            yield key

            # reversed so that, for a healthy hive, children come out in
            # roughly their stored order under depth-first traversal.
            # subkeys() records cyclic/duplicate/invalid entries on the
            # shared traversal and only returns each NK cell once.
            for child in reversed(key.subkeys(traversal)):
                stack.append(child._nkrecord)

    def values_number(self):
    	"""
    	Return the number of values associated with this key
    	"""
    	return self._nkrecord.values_number()

    def subkeys_number(self):
    	"""
    	Return the number of subkeys associated with this key
    	"""
    	return self._nkrecord.subkey_number()


class Registry(object):
    """
    A class for parsing and reading from a Windows Registry file.
    """
    def __init__(self, filelikeobject):
        """
        Constructor.
        Arguments:
        - `filelikeobject`: A file-like object with a .read() method.
              If a Python string is passed, it is interpreted as a filename,
              and the corresponding file is opened.
        """
        try:
            self._buf = filelikeobject.read()
        except AttributeError:
            with open(filelikeobject, "rb") as f:
                self._buf = f.read()
        self._regf = RegistryParse.REGFBlock(self._buf, 0, False)
        # Shared state for the resilient forensic traversal. Each call to
        # Registry.walk resets it, and recovery_errors reports its contents.
        self._traversal = SubkeyTraversal()

    def __repr__(self):
        return 'Registry(hive_name="{0}", hive_type="{1}")'.format(self.hive_name(), self.hive_type())
    
    def hive_name(self):
        """Returns the internal file name"""
        return self._regf.hive_name()

    def hive_type(self):
        """Returns the hive type"""
        temp = self.hive_name()
        temp = temp.replace('\\??\\', '')
        temp = ntpath.basename(temp)

        if temp.lower() == HiveType.NTUSER.value:
            return HiveType.NTUSER
        elif temp.lower() == HiveType.SAM.value:
            return HiveType.SAM
        elif temp.lower() == HiveType.SECURITY.value:
            return HiveType.SECURITY
        elif temp.lower() == HiveType.SOFTWARE.value:
            return HiveType.SOFTWARE
        elif temp.lower() == HiveType.SYSTEM.value:
            return HiveType.SYSTEM
        elif temp.lower() == HiveType.USRCLASS.value:
            return HiveType.USRCLASS
        elif temp.lower() == HiveType.BCD.value:
            return HiveType.BCD
        elif temp.lower() == HiveType.COMPONENTS.value:
            return HiveType.COMPONENTS
        elif temp.lower() == HiveType.DEFAULT.value:
            return HiveType.DEFAULT
        elif temp.lower() == HiveType.SCHEMA.value:
            return HiveType.SCHEMA
        elif temp.lower() == HiveType.SETTINGS.value:
            return HiveType.SETTINGS
        else:
            return HiveType.UNKNOWN

    def root(self):
        """
        Return the first RegistryKey in the hive.
        """
        return RegistryKey(self._regf.first_key())

    def open(self, path):
        """
        Return a RegistryKey by full path.
        Subkeys are separated by the backslash character ('\').
        A trailing backslash may or may not be present.
        The hive name should not be included.
        """
        # is the first registry key always the root?
        # are there any other keys at this
        # level? is this the name of the hive?
        return RegistryKey(self._regf.first_key()).find_key(path)

    def walk(self):
        """
        Single-pass, resilient depth-first generator over every reachable
        RegistryKey in the hive, starting at the root.

        Cyclic ri/lf/lh/li references are broken instead of looping, each NK
        cell is delivered at most once (so no piece of evidence is yielded
        twice), and damaged branches are skipped with a SubkeyIndexError
        recorded while the unrelated sibling keys continue to be extracted.
        Genuine same-named sibling keys are always both delivered, because
        de-duplication is based on the source cell offset rather than the
        name.

        Each call restarts with a fresh SubkeyTraversal, so repeated walks
        each yield the full set of recoverable keys. The problems
        encountered by the most recent walk are available through
        recovery_errors().
        """
        self._traversal = SubkeyTraversal()
        for key in RegistryKey(self._regf.first_key()).walk(self._traversal):
            yield key

    def recovery_errors(self):
        """
        Return the list of SubkeyIndexError entries recorded during the most
        recent Registry.walk() call (empty before the first walk).

        Each entry locates the problem precisely: the index type and offset,
        the offending entry position, the offset it pointed at, and the path
        and offset of the owning key.
        """
        return list(self._traversal.errors)

def print_all(key):
    if len(key.subkeys()) == 0:
        print(key.path())
    else:
        for k in key.subkeys():
            print_all(k)

if __name__ == '__main__':
    r = Registry(sys.argv[1])
    print_all(r.root())
