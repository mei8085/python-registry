#!/usr/bin/env python3
"""
Build synthetic hives exercising registry name/path attribution edge cases:

  compressed_names.hive   - ASCII(compressed) vs UTF-16 names, flag/content mismatch
  surrogate_names.hive    - valid surrogate pairs and lone surrogates in names
  case_collision.hive     - case-equivalent duplicate subkeys/values, fold divergence
  nul_separator.hive      - embedded NUL and backslash in names, NUL in value data
  default_shadow.hive     - a value literally named "(default)" vs the real default
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hivebuilder import HiveBuilder, write_hive

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hives")

RegSZ = 0x0001
RegDWord = 0x0004


def sz(text):
    return text.encode("utf-16le") + b"\x00\x00"


def u16(text):
    return text.encode("utf-16le")


def a(text):
    return text.encode("latin-1")


def finish(b, root, sub_offsets):
    """Point root at the lf list of its subkeys and write counts."""
    lf = b.add_lf([(o, b"\x00\x00\x00\x00") for o in sub_offsets])
    b.patch_dword(root, 0x14, len(sub_offsets))  # stable subkey count
    b.patch_dword(root, 0x1C, lf)                # subkey list offset
    return root


def key_with_values(b, name_bytes, ascii_name, parent, vk_offsets):
    vl = b.add_values_list(vk_offsets)
    return b.add_nk(name_bytes, ascii_name=ascii_name, parent_offset=parent,
                    value_count=len(vk_offsets), values_list_offset=vl)


# ----------------------------------------------------------------------
# Hive 1: compressed (ASCII) vs UTF-16 names, and flag/content mismatch
# ----------------------------------------------------------------------
def build_compressed():
    b = HiveBuilder("COMPRESSED")
    root = b.add_nk(a("ROOT"), is_root=True, ascii_name=True)

    subs = [
        # 1. normal compressed name (all chars < 0x80)
        b.add_nk(a("PlainASCII"), ascii_name=True, parent_offset=root),
        # 2. compressed name with high latin-1 chars (U+00DC/U+00EF fit one
        #    byte); Windows stores such names compressed too.
        b.add_nk(b"\xdcn\xefcode", ascii_name=True, parent_offset=root),
        # 3. genuine UTF-16 name (CJK cannot be compressed)
        b.add_nk(u16("CJK键"), ascii_name=False, parent_offset=root),
        # 4. FLAG LIES: bytes are UTF-16LE of "FlagLie" but COMP_NAME set.
        b.add_nk(u16("FlagLie"), ascii_name=True, parent_offset=root),
        # 5. REVERSE FLAG LIE: bytes are latin-1 "RawBytes", flag clear.
        b.add_nk(a("RawBytes"), ascii_name=False, parent_offset=root),
        # 6. odd-length UTF-16 name (truncated final unit)
        b.add_nk(u16("OddLen") + b"\x41", ascii_name=False, parent_offset=root),
    ]
    finish(b, root, subs)
    write_hive(os.path.join(OUT, "compressed_names.hive"), b, root)


# ----------------------------------------------------------------------
# Hive 2: UTF-16 surrogates in key and value names
# ----------------------------------------------------------------------
def build_surrogates():
    b = HiveBuilder("SURROGATES")
    root = b.add_nk(a("ROOT"), is_root=True, ascii_name=True)

    # valid surrogate pair: U+1F600 emoji, carrying two values
    v_surr = b.add_vk("Val".encode("utf-16le") + b"\x00\xd8",
                      RegSZ, sz("surrogate-value-name"))
    v_norm = b.add_vk(a("Normal"), RegSZ, sz("normal"), ascii_name=True)
    k_emoji = key_with_values(b, "Emoji\U0001F600Key".encode("utf-16le"),
                              False, root, [v_surr, v_norm])

    # lone HIGH surrogate (crafted; WinAPI would never write this)
    k_lone_hi = b.add_nk("LoneHigh".encode("utf-16le") + b"\x00\xd8" +
                         "Key".encode("utf-16le"), parent_offset=root)
    # lone LOW surrogate
    k_lone_lo = b.add_nk("LoneLow".encode("utf-16le") + b"\x00\xdc" +
                         "Key".encode("utf-16le"), parent_offset=root)
    # reversed "pair": low surrogate followed by high surrogate
    k_reversed = b.add_nk("Reversed".encode("utf-16le") + b"\x00\xdc\x00\xd8",
                          parent_offset=root)

    finish(b, root, [k_emoji, k_lone_hi, k_lone_lo, k_reversed])
    write_hive(os.path.join(OUT, "surrogate_names.hive"), b, root)


# ----------------------------------------------------------------------
# Hive 3: case-equivalent duplicate names + case-fold divergence
# ----------------------------------------------------------------------
def build_case_collision():
    b = HiveBuilder("CASECOLL")
    root = b.add_nk(a("ROOT"), is_root=True, ascii_name=True)

    # three subkeys whose names differ only by case (impossible via WinAPI,
    # but craftable in a raw hive; also arises with deleted/carved keys).
    # Each carries a distinguishing Marker value.
    def marker_key(name_bytes, ascii_name, marker):
        v = b.add_vk(a("Marker"), RegSZ, sz(marker), ascii_name=True)
        return key_with_values(b, name_bytes, ascii_name, root, [v])

    k1 = marker_key(a("Evidence"), True, "first-in-list")
    k2 = marker_key(a("EVIDENCE"), True, "second-in-list")
    k3 = marker_key(u16("evidence"), False, "third-in-list-utf16")

    # case-fold divergence probes:
    #  - U+017F LATIN SMALL LETTER LONG S: Windows upcases to 'S',
    #    Python .lower() leaves it unchanged.
    k_longs = b.add_nk("ſpecial".encode("utf-16le"), parent_offset=root)
    #  - U+212A KELVIN SIGN: Python .lower() maps to 'k',
    #    Windows upcase table keeps it distinct from ASCII 'K'.
    k_kelvin = b.add_nk("Ksign".encode("utf-16le"), parent_offset=root)

    # duplicate *values* differing only by case inside one key
    vA = b.add_vk(a("Data"), RegSZ, sz("value-lower-first"), ascii_name=True)
    vB = b.add_vk(a("DATA"), RegSZ, sz("value-upper-second"), ascii_name=True)
    k_dupvals = key_with_values(b, a("DupValues"), True, root, [vA, vB])

    finish(b, root, [k1, k2, k3, k_longs, k_kelvin, k_dupvals])
    write_hive(os.path.join(OUT, "case_collision.hive"), b, root)


# ----------------------------------------------------------------------
# Hive 4: embedded NUL and path separator in names, NUL in value data
# ----------------------------------------------------------------------
def build_nul_separator():
    b = HiveBuilder("NULSEP")
    root = b.add_nk(a("ROOT"), is_root=True, ascii_name=True)

    # key whose name contains an embedded NUL (UTF-16)
    k_nul = b.add_nk("Visible\x00Hidden".encode("utf-16le"), parent_offset=root)
    # the "clean" twin: what tools that truncate at NUL would collide with
    k_clean = b.add_nk(a("Visible"), ascii_name=True, parent_offset=root)

    # key whose name contains a backslash -> path() is not round-trippable
    k_bs = b.add_nk("a\\b".encode("utf-16le"), parent_offset=root)

    # a genuine nested pair a\b that textually collides with the above
    k_a = b.add_nk(a("a"), ascii_name=True, parent_offset=root)
    k_b_inner = b.add_nk(a("b"), ascii_name=True, parent_offset=k_a)
    lf_a = b.add_lf([(k_b_inner, b"\x00\x00\x00\x00")])
    b.patch_dword(k_a, 0x14, 1)
    b.patch_dword(k_a, 0x1C, lf_a)

    # values exercising NUL handling in names and data
    v_nulname = b.add_vk("Val\x00Suffix".encode("utf-16le"),
                         RegSZ, sz("nul-value-name"))
    v_nuldata = b.add_vk(a("TruncData"), RegSZ, sz("abc\x00def"),
                         ascii_name=True)
    # hits decode_utf16le()'s b"\x00\x00" heuristic:
    # "abcÀ一def" -> bytes ...C0 00 00 4E... look like a terminator
    v_cjk = b.add_vk(a("CjkData"), RegSZ, sz("abcÀ一def"), ascii_name=True)
    v_plain = b.add_vk("Val".encode("utf-16le"), RegSZ, sz("plain-val"))
    k_vals = key_with_values(b, a("Values"), True, root,
                             [v_nulname, v_nuldata, v_cjk, v_plain])

    finish(b, root, [k_nul, k_clean, k_bs, k_a, k_vals])
    write_hive(os.path.join(OUT, "nul_separator.hive"), b, root)


# ----------------------------------------------------------------------
# Hive 5: a value literally named "(default)" shadows the real default
# ----------------------------------------------------------------------
def build_default_shadow():
    b = HiveBuilder("DEFSHADOW")
    root = b.add_nk(a("ROOT"), is_root=True, ascii_name=True)

    v_real_default = b.add_vk(b"", RegSZ, sz("REAL-DEFAULT"), ascii_name=True)
    v_named_default = b.add_vk(a("(default)"), RegSZ, sz("NAMED-(default)"),
                               ascii_name=True)
    k = key_with_values(b, a("Shadow"), True, root,
                        [v_real_default, v_named_default])

    finish(b, root, [k])
    write_hive(os.path.join(OUT, "default_shadow.hive"), b, root)


if __name__ == "__main__":
    build_compressed()
    build_surrogates()
    build_case_collision()
    build_nul_separator()
    build_default_shadow()
    for f in sorted(os.listdir(OUT)):
        print("built", os.path.join(OUT, f),
              os.path.getsize(os.path.join(OUT, f)), "bytes")
