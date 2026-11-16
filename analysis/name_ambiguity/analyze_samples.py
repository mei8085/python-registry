#!/usr/bin/env python3
"""
Trace raw record bytes -> decoded name -> path/lookup -> display output
for each synthetic hive, and print a structured evidence log.
"""

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from Registry import Registry
from Registry import RegistryParse

HIVES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hives")


def raw_name_info(nk):
    """Pull the raw name bytes and flags straight off the NKRecord."""
    flags = nk.unpack_word(0x2)
    name_len = nk.unpack_word(0x48)
    raw = nk.unpack_string(0x4C, name_len)
    return flags, raw


def safe(label, fn):
    try:
        return fn()
    except Exception as e:
        return "<%s: %s>" % (type(e).__name__, e)


def show(s):
    """repr that also exposes embedded NULs and surrogates."""
    if isinstance(s, str):
        return ascii(s)
    return repr(s)


def banner(t):
    print("\n" + "=" * 72)
    print(t)
    print("=" * 72)


def trace_key(key, indent="  "):
    nk = key._nkrecord
    flags, raw = raw_name_info(nk)
    ascii_flag = bool(flags & 0x20)
    print("%snk.flags=0x%04x ascii_flag=%s raw_name=%s" %
          (indent, flags, ascii_flag, raw))
    print("%sname()      -> %s" % (indent, show(safe("name", key.name))))
    print("%spath()      -> %s" % (indent, show(safe("path", key.path))))
    # display layer: can the name survive UTF-8 output / JSON?
    name = safe("name", key.name)
    if isinstance(name, str):
        enc = safe("utf8", lambda: name.encode("utf-8"))
        print("%sutf-8 encode-> %s" % (indent,
              "OK" if not str(enc).startswith("<") else enc))
        js = safe("json", lambda: json.dumps({"k": name}))
        print("%sjson dump   -> %s" % (indent,
              "OK" if not str(js).startswith("<") else js))
    for v in key.values():
        vk = v._vkrecord
        vflags = vk.unpack_word(0x10)
        vlen = vk.unpack_word(0x2)
        vraw = vk.unpack_string(0x14, vlen)
        print("%s  vk.flags=0x%04x ascii=%s raw_name=%s" %
              (indent, vflags, bool(vflags & 1), vraw))
        print("%s  value.name() -> %s" % (indent, show(safe("n", v.name))))
        print("%s  value.value()-> %s" % (indent, show(safe("v", v.value))))


def lookup_tests(reg, queries):
    for q in queries:
        r = safe("open", lambda q=q: reg.open(q))
        if isinstance(r, Registry.RegistryKey):
            marker = safe("m", lambda: r.value("Marker").value()
                          if "Marker" in [v.name() for v in r.values()]
                          else "")
            print("  open(%s) -> path=%s marker=%s" %
                  (show(q), show(r.path()), show(marker)))
        else:
            print("  open(%s) -> %s" % (show(q), r))


# ----------------------------------------------------------------------
banner("HIVE 1: compressed (ASCII) vs UTF-16 names, flag/content mismatch")
reg = Registry.Registry(os.path.join(HIVES, "compressed_names.hive"))
print("hive checksum valid:", reg._regf.validate_checksum())
root = reg.root()
for k in root.subkeys():
    trace_key(k)
    print()

# ----------------------------------------------------------------------
banner("HIVE 2: UTF-16 surrogates in names")
reg = Registry.Registry(os.path.join(HIVES, "surrogate_names.hive"))
root = reg.root()
for k in root.subkeys():
    trace_key(k)
    print()

# ----------------------------------------------------------------------
banner("HIVE 3: case-equivalent duplicates + case-fold divergence")
reg = Registry.Registry(os.path.join(HIVES, "case_collision.hive"))
root = reg.root()
print("enumeration order and Marker each key actually holds:")
for k in root.subkeys():
    marker = safe("m", lambda: k.value("Marker").value()) \
        if k.name().lower() == "evidence" else ""
    print("  enumerated: name=%s marker=%s" % (show(k.name()), show(marker)))
print("\nlookup results (case-insensitive subkey()/find_key):")
lookup_tests(reg, ["Evidence", "EVIDENCE", "evidence", "eViDeNcE"])
print("\ncase-fold divergence vs Windows:")
lookup_tests(reg, ["Special", "ſpecial", "Ksign", "ksign", "KSIGN"])
print("\nduplicate values differing only by case:")
kv = reg.open("DupValues")
for v in kv.values():
    print("  enumerated value: name=%s data=%s" % (show(v.name()), show(v.value())))
for q in ["Data", "DATA", "data"]:
    r = safe("v", lambda q=q: kv.value(q))
    if isinstance(r, Registry.RegistryValue):
        print("  value(%s) -> %s" % (show(q), show(r.value())))
    else:
        print("  value(%s) -> %s" % (show(q), r))

# ----------------------------------------------------------------------
banner("HIVE 4: embedded NUL and path separator in names/data")
reg = Registry.Registry(os.path.join(HIVES, "nul_separator.hive"))
root = reg.root()
for k in root.subkeys():
    trace_key(k)
    print()
print("lookup tests:")
lookup_tests(reg, ["Visible", "Visible\x00Hidden", "a\\b", "a",
                   "Values"])
kv = reg.open("Values")
print("value() lookups on Values key:")
for q in ["Val", "Val\x00Suffix", "TruncData", "CjkData"]:
    r = safe("v", lambda q=q: kv.value(q))
    if isinstance(r, Registry.RegistryValue):
        print("  value(%s) -> name=%s data=%s" %
              (show(q), show(r.name()), show(r.value())))
    else:
        print("  value(%s) -> %s" % (show(q), r))
print("\nraw bytes behind CjkData (what decode_utf16le saw):")
for v in kv.values():
    if v.name() == "CjkData":
        print("  raw_data:", v.raw_data())
        print("  parsed  :", show(v.value()))
        print("  overrun=16:", show(v.value(overrun=16)))

# ----------------------------------------------------------------------
banner("HIVE 5: value literally named '(default)' vs real default")
reg = Registry.Registry(os.path.join(HIVES, "default_shadow.hive"))
k = reg.open("Shadow")
print("enumeration (ground truth):")
for v in k.values():
    print("  name=%s has_name=%s data=%s" %
          (show(v.name()), v._vkrecord.has_name(), show(v.value())))
print("lookup value('(default)'):")
r = safe("v", lambda: k.value("(default)"))
print("  -> name=%s data=%s" % (show(r.name()), show(r.value())))
print("lookup value(''):")
r = safe("v", lambda: k.value(""))
print("  -> name=%s data=%s" % (show(r.name()), show(r.value())))

# ----------------------------------------------------------------------
banner("ROUND-TRIP: does open(path-without-root) return the same key?")
for hive in ["compressed_names.hive", "nul_separator.hive",
             "surrogate_names.hive"]:
    reg = Registry.Registry(os.path.join(HIVES, hive))
    print("[%s]" % hive)
    def walk(key):
        for sub in key.subkeys():
            p = safe("p", sub.path)
            if isinstance(p, str):
                rel = p.split("\\", 1)[1] if "\\" in p else ""
                r = safe("o", lambda rel=rel: reg.open(rel))
                ok = isinstance(r, Registry.RegistryKey) and \
                    safe("po", r.path) == p
                print("  path=%s reopen=%s" % (show(p),
                      "OK" if ok else show(r)))
            else:
                print("  path failed: %s" % p)
            walk(sub)
    walk(reg.root())
