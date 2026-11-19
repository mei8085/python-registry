#!/usr/bin/env python
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
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import absolute_import

import os
import sys

# Running this script from the repository root without installing the
# package should still work.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Registry import Registry
from Registry.SecurityParse import AceCategory


def describe_ace(ace):
    if not ace.parsable:
        return "    [UNPARSEABLE %s] flags=0x%02x %d raw bytes: %s" % (
            ace.ace_type_name(), ace.ace_flags(), ace.size(),
            ace.raw_bytes().hex())

    sid = ace.sid()
    name = sid.well_known_name()
    principal = "%s (%s)" % (str(sid), name) if name else str(sid)
    return "    [%s] %s mask=0x%08x %s flags=[%s]" % (
        ace.category().value, ace.ace_type_name(), ace.mask(),
        principal, ", ".join(ace.ace_flag_names()))


def main():
    if len(sys.argv) != 2:
        print("Usage: %s <registry hive>" % sys.argv[0])
        return 1

    reg = Registry.Registry(sys.argv[1])
    root = reg.root()

    seen = set()
    stats = {category.value: 0 for category in AceCategory}
    counters = {"corrupt": 0, "raw": 0}

    def walk(key):
        try:
            sd = key.security_descriptor()
        except Registry.RegistryParse.RegistryStructureDoesNotExist:
            for subkey in key.subkeys():
                walk(subkey)
            return
        except Registry.RegistryParse.ParseException as e:
            print("%s: CORRUPT SECURITY DESCRIPTOR: %s" %
                  (key.path(), e))
            counters["corrupt"] += 1
            for subkey in key.subkeys():
                walk(subkey)
            return

        # SK records are shared between keys; report each descriptor once.
        sk = key._nkrecord.sk_record()
        if sk.offset() in seen:
            for subkey in key.subkeys():
                walk(subkey)
            return
        seen.add(sk.offset())

        print("=" * 72)
        print("Key:   %s" % key.path())
        print("Owner: %s%s" % (
            sd.owner(),
            " (%s)" % sd.owner().well_known_name()
            if sd.owner().well_known_name() else ""))
        print("Group: %s%s" % (
            sd.group(),
            " (%s)" % sd.group().well_known_name()
            if sd.group().well_known_name() else ""))
        print("Control: %s" % ", ".join(sd.control_flag_names()))

        if not sd.dacl_present():
            print("DACL: absent (legal: no DACL)")
        elif sd.dacl_null():
            print("DACL: NULL (legal: everyone granted access)")
        else:
            print("DACL: %d ACE(s)" % len(sd.dacl()))
            if sd.dacl().ace_count_mismatch():
                print("  WARNING: declared ACE count does not match the "
                      "entries that could be parsed")
            for ace in sd.dacl():
                print(describe_ace(ace))
                stats[ace.category().value] += 1
                if not ace.parsable:
                    counters["raw"] += 1

        if sd.sacl_present() and sd.sacl() is not None and \
                len(sd.sacl()) > 0:
            print("SACL: %d ACE(s)" % len(sd.sacl()))
            for ace in sd.sacl():
                print(describe_ace(ace))

        for subkey in key.subkeys():
            walk(subkey)

    walk(root)

    print("=" * 72)
    print("Summary across %d distinct security descriptors:" % len(seen))
    for category, count in sorted(stats.items()):
        print("  %-16s %d" % (category, count))
    if counters["raw"]:
        print("  %d ACE(s) could not be parsed; raw bytes preserved" %
              counters["raw"])
    if counters["corrupt"]:
        print("  %d corrupt descriptor(s) reported above" %
              counters["corrupt"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
