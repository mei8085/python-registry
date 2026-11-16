#!/usr/bin/env python3
"""Supplementary probes: crash propagation, offset identity, (default) casing."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
from Registry import Registry

HIVES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hives")

print("== A. lone-surrogate sibling breaks lookup of OTHER keys ==")
reg = Registry.Registry(os.path.join(HIVES, "surrogate_names.hive"))
root = reg.root()
for q in ["Emoji\U0001F600Key", "DoesNotExist"]:
    try:
        k = root.subkey(q)
        print("  subkey(%r) -> %r" % (q, k.name()))
    except Exception as e:
        print("  subkey(%r) -> %s: %s" % (q, type(e).__name__, e))
# and enumeration of names
try:
    names = [k.name() for k in root.subkeys()]
    print("  enumerate names ->", names)
except Exception as e:
    print("  enumerate names -> %s: %s" % (type(e).__name__, e))

print()
print("== B. 'a\\b' single key vs nested a\\b: offset identity ==")
reg = Registry.Registry(os.path.join(HIVES, "nul_separator.hive"))
root = reg.root()
single = None
nested = None
for k in root.subkeys():
    if k.name() == "a\\b":
        single = k
    if k.name() == "a":
        nested = k.subkey("b")
print("  single key 'a\\b'  nk offset = 0x%x" % single._nkrecord.offset())
print("  nested key a->b    nk offset = 0x%x" % nested._nkrecord.offset())
opened = reg.open("a\\b")
print("  open('a\\\\b') resolves to offset 0x%x (%s)" % (
    opened._nkrecord.offset(),
    "SINGLE key" if opened._nkrecord.offset() == single._nkrecord.offset()
    else "NESTED key a->b"))
print("  both display path(): %r vs %r" % (single.path(), nested.path()))

print()
print("== C. value('(default)') vs value('(DEFAULT)') ==")
reg = Registry.Registry(os.path.join(HIVES, "default_shadow.hive"))
k = reg.open("Shadow")
for q in ["(default)", "(DEFAULT)", "(Default)", ""]:
    try:
        v = k.value(q)
        print("  value(%r) -> has_name=%s data=%r" %
              (q, v._vkrecord.has_name(), v.value()))
    except Exception as e:
        print("  value(%r) -> %s: %s" % (q, type(e).__name__, e))

print()
print("== D. find_key with NUL-prefixed query on twin keys ==")
reg = Registry.Registry(os.path.join(HIVES, "nul_separator.hive"))
root = reg.root()
# what a NUL-truncating tool would ask for vs what exists
for q in ["Visible", "Visible\x00Hidden", "Visible\x00AnythingElse"]:
    try:
        kk = root.subkey(q)
        print("  subkey(%r) -> offset 0x%x" % (q, kk._nkrecord.offset()))
    except Exception as e:
        print("  subkey(%r) -> %s" % (q, type(e).__name__))
