#!/usr/bin/env python
#
# Tests for resilient traversal of damaged subkey indexes (ri/lf/lh/li).
#
# The fixtures are synthetic hives produced by synthetic_hive.py so that
# precise damage - cyclic references, duplicate references, invalid entries
# and legitimate same-named siblings - can be constructed deterministically.
from __future__ import print_function
from __future__ import unicode_literals

import io
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest

from Registry import Registry
from Registry.RegistryParse import (
    SubkeyIndexError,
    SubkeyIndexErrorKind,
    SubkeyTraversal,
)

from synthetic_hive import SyntheticHive


def load(hive, root_ref):
    return Registry.Registry(io.BytesIO(hive.build(root_ref)))


def names(keys):
    return [k.name() for k in keys]


def make_children(hive, child_names):
    refs = [hive.nk(name) for name in child_names]
    return refs


# --------------------------------------------------------------------------
# LF / LH direct indexes
# --------------------------------------------------------------------------

def test_lf_duplicate_reference_is_delivered_once():
    hive = SyntheticHive()
    good_a, good_b = make_children(hive, ["A", "B"])
    # entries: A, B, A (the third entry re-points at A's cell)
    lf = hive.direct_list(b"lf", [good_a, good_b, good_a])
    root = hive.nk("ROOT", root=True, subkey_count=3, subkey_list=lf)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    got = names(reg.root().subkeys(traversal))
    assert got == ["A", "B"]

    assert len(traversal.errors) == 1
    error = traversal.errors[0]
    assert error.kind == SubkeyIndexErrorKind.DUPLICATE_REFERENCE
    assert error.list_type == b"lf"
    assert error.entry_index == 2
    assert error.referenced_offset == hive.cell_abs(good_a)


def test_lf_same_named_distinct_siblings_are_both_kept():
    hive = SyntheticHive()
    first = hive.nk("SAMENAME")
    second = hive.nk("SAMENAME")
    third = hive.nk("OTHER")
    lf = hive.direct_list(b"lf", [first, second, third])
    root = hive.nk("ROOT", root=True, subkey_count=3, subkey_list=lf)
    reg = load(hive, root)

    subkeys = reg.root().subkeys()
    assert names(subkeys) == ["SAMENAME", "SAMENAME", "OTHER"]
    # distinct source cells prove they really are two different branches
    offsets = [k.cell_offset() for k in subkeys]
    assert len(set(offsets)) == 3


def test_lf_invalid_free_cell_entry_is_skipped_but_siblings_continue():
    hive = SyntheticHive()
    good_a, good_b = make_children(hive, ["A", "B"])
    free = hive.add_free_cell()
    lf = hive.direct_list(b"lf", [good_a, free, good_b])
    root = hive.nk("ROOT", root=True, subkey_count=3, subkey_list=lf)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    got = names(reg.root().subkeys(traversal))
    assert got == ["A", "B"]

    assert len(traversal.errors) == 1
    error = traversal.errors[0]
    assert error.kind == SubkeyIndexErrorKind.INVALID_REFERENCE
    assert error.list_type == b"lf"
    assert error.entry_index == 1
    # the error must pinpoint both the offending target and its owning key
    assert error.referenced_offset == hive.cell_abs(free)
    assert error.parent_key_path == "ROOT"
    assert error.parent_key_offset == hive.cell_abs(root) + 4
    assert isinstance(str(error), str) and "lf" in str(error)


def test_lh_duplicate_and_invalid_entries():
    hive = SyntheticHive()
    good_a, good_b = make_children(hive, ["A", "B"])
    free = hive.add_free_cell()
    # A (ok), free (invalid), B (ok), B again (duplicate)
    lh = hive.direct_list(b"lh", [good_a, free, good_b, good_b])
    root = hive.nk("ROOT", root=True, subkey_count=4, subkey_list=lh)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    got = names(reg.root().subkeys(traversal))
    assert got == ["A", "B"]

    kinds = set(e.kind for e in traversal.errors)
    assert kinds == {SubkeyIndexErrorKind.INVALID_REFERENCE,
                     SubkeyIndexErrorKind.DUPLICATE_REFERENCE}
    for error in traversal.errors:
        assert error.list_type == b"lh"


def test_li_index_is_supported_and_resilient():
    hive = SyntheticHive()
    good_a, good_b = make_children(hive, ["A", "B"])
    li = hive.direct_list(b"li", [good_a, good_b, good_a])
    root = hive.nk("ROOT", root=True, subkey_count=3, subkey_list=li)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    got = names(reg.root().subkeys(traversal))
    assert got == ["A", "B"]
    assert len(traversal.errors) == 1
    assert traversal.errors[0].kind == SubkeyIndexErrorKind.DUPLICATE_REFERENCE
    assert traversal.errors[0].list_type == b"li"


# --------------------------------------------------------------------------
# RI indirect indexes
# --------------------------------------------------------------------------

def test_ri_self_cycle_does_not_loop():
    hive = SyntheticHive()
    # an RI cell whose single entry points back at itself
    ri = hive.ri_list([None])
    hive.patch_dword(ri, 4, ri)
    root = hive.nk("ROOT", root=True, subkey_count=1, subkey_list=ri)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    got = reg.root().subkeys(traversal)
    assert got == []
    assert len(traversal.errors) == 1
    assert traversal.errors[0].kind == SubkeyIndexErrorKind.CYCLIC_REFERENCE
    assert traversal.errors[0].list_type == b"ri"


def test_ri_duplicate_list_reference_is_not_reexpanded():
    hive = SyntheticHive()
    a, b = make_children(hive, ["A", "B"])
    lf = hive.direct_list(b"lf", [a, b])
    # same LF listed twice: re-expanding would deliver A and B twice
    ri = hive.ri_list([lf, lf])
    root = hive.nk("ROOT", root=True, subkey_count=2, subkey_list=ri)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    got = names(reg.root().subkeys(traversal))
    assert got == ["A", "B"]
    assert len(traversal.errors) == 1
    assert traversal.errors[0].kind == SubkeyIndexErrorKind.DUPLICATE_REFERENCE


def test_ri_invalid_entry_is_skipped_siblings_survive():
    hive = SyntheticHive()
    a, b, c = make_children(hive, ["A", "B", "C"])
    lf = hive.direct_list(b"lf", [a])
    free = hive.add_free_cell()
    lh = hive.direct_list(b"lh", [b, c])
    ri = hive.ri_list([lf, free, lh])
    root = hive.nk("ROOT", root=True, subkey_count=3, subkey_list=ri)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    got = names(reg.root().subkeys(traversal))
    assert got == ["A", "B", "C"]
    assert len(traversal.errors) == 1
    assert traversal.errors[0].kind == SubkeyIndexErrorKind.INVALID_REFERENCE
    assert traversal.errors[0].entry_index == 1


def test_ri_two_level_nesting_is_traversed():
    hive = SyntheticHive()
    a, b, c, d = make_children(hive, ["A", "B", "C", "D"])
    inner_ri = hive.ri_list([
        hive.direct_list(b"li", [a, b]),
        hive.direct_list(b"lh", [c, d]),
    ])
    outer_ri = hive.ri_list([inner_ri])
    root = hive.nk("ROOT", root=True, subkey_count=1, subkey_list=outer_ri)
    reg = load(hive, root)

    assert names(reg.root().subkeys()) == ["A", "B", "C", "D"]
    assert reg.recovery_errors() == []  # nothing walked yet
    walked = names(reg.walk())
    assert walked == ["ROOT", "A", "B", "C", "D"]
    assert reg.recovery_errors() == []


def test_ri_cycle_through_second_level_index():
    hive = SyntheticHive()
    a = hive.nk("A")
    # outer RI references an inner RI; the inner RI points back at the
    # outer one, forming a cycle, while one healthy branch still exists
    outer = hive.ri_list([None, None])
    inner = hive.ri_list([hive.direct_list(b"lf", [a]), outer])
    hive.patch_dword(outer, 4, inner)
    hive.patch_dword(outer, 8, hive.direct_list(b"lf", []))
    root = hive.nk("ROOT", root=True, subkey_count=2, subkey_list=outer)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    got = names(reg.root().subkeys(traversal))
    assert got == ["A"]
    kinds = [e.kind for e in traversal.errors]
    assert SubkeyIndexErrorKind.CYCLIC_REFERENCE in kinds


# --------------------------------------------------------------------------
# Whole-hive behaviour
# --------------------------------------------------------------------------

def test_walk_survives_damaged_branch_and_keeps_unrelated_subtree():
    hive = SyntheticHive()
    # good branch, with a leaf
    leaf = hive.nk("LEAF")
    good_branch = hive.nk("GOOD", subkey_count=1,
                          subkey_list=hive.direct_list(b"lf", [leaf]))
    hive.patch_dword(leaf, 0x10, good_branch)
    # damaged branch: a self cyclic RI
    cyclic = hive.ri_list([None])
    hive.patch_dword(cyclic, 4, cyclic)
    bad_branch = hive.nk("BAD", subkey_count=1, subkey_list=cyclic)

    root_lf = hive.direct_list(b"lf", [good_branch, bad_branch])
    root = hive.nk("ROOT", root=True, subkey_count=2, subkey_list=root_lf)
    hive.patch_dword(good_branch, 0x10, root)
    hive.patch_dword(bad_branch, 0x10, root)
    reg = load(hive, root)

    walked = list(reg.walk())
    walked_names = [k.path() for k in walked]
    assert "ROOT" in walked_names
    assert "ROOT\\GOOD" in walked_names
    assert "ROOT\\GOOD\\LEAF" in walked_names
    assert "ROOT\\BAD" in walked_names  # the NK itself is fine; its index is not

    # every recovered key carries a path and a source cell
    for key in walked:
        assert key.path()
        assert key.cell_offset() > 0

    errors = reg.recovery_errors()
    assert any(e.kind == SubkeyIndexErrorKind.CYCLIC_REFERENCE for e in errors)
    # the cyclic error is attributable to the BAD branch
    cyclic_errors = [e for e in errors
                     if e.kind == SubkeyIndexErrorKind.CYCLIC_REFERENCE]
    assert cyclic_errors[0].parent_key_path.endswith("BAD")


def test_walk_never_delivers_same_cell_twice_even_with_cross_links():
    hive = SyntheticHive()
    shared = hive.nk("SHARED")
    only_here = hive.nk("ONLY_HERE")
    # two parent indexes both point at the same SHARED NK cell
    first_lf = hive.direct_list(b"lf", [shared])
    second_lf = hive.direct_list(b"lf", [shared, only_here])
    ri = hive.ri_list([first_lf, second_lf])
    root = hive.nk("ROOT", root=True, subkey_count=2, subkey_list=ri)
    reg = load(hive, root)

    walked = list(reg.walk())
    offsets = [k.cell_offset() for k in walked]
    assert len(offsets) == len(set(offsets))
    assert names(walked).count("SHARED") == 1
    assert "ONLY_HERE" in names(walked)
    assert any(e.kind == SubkeyIndexErrorKind.DUPLICATE_REFERENCE
               for e in reg.recovery_errors())


def test_repeated_walks_are_independent():
    hive = SyntheticHive()
    a, b = make_children(hive, ["A", "B"])
    lf = hive.direct_list(b"lf", [a, b, a])
    root = hive.nk("ROOT", root=True, subkey_count=3, subkey_list=lf)
    reg = load(hive, root)

    first = names(reg.walk())
    first_errors = list(reg.recovery_errors())
    second = names(reg.walk())
    second_errors = list(reg.recovery_errors())
    assert first == second == ["ROOT", "A", "B"]
    assert len(first_errors) == len(second_errors) == 1


def test_error_is_exception_and_carries_locator_fields():
    hive = SyntheticHive()
    free = hive.add_free_cell()
    lf = hive.direct_list(b"lf", [free])
    root = hive.nk("ROOT", root=True, subkey_count=1, subkey_list=lf)
    reg = load(hive, root)

    list(reg.walk())
    error = reg.recovery_errors()[0]
    assert isinstance(error, SubkeyIndexError)
    assert isinstance(error, Exception)
    assert error.kind == SubkeyIndexErrorKind.INVALID_REFERENCE
    assert error.list_type == b"lf"
    assert error.list_offset >= 0
    assert error.entry_index == 0
    assert error.referenced_offset == hive.cell_abs(free)
    assert error.parent_key_path == "ROOT"
    assert error.parent_key_offset == hive.cell_abs(root) + 4


def test_healthy_hive_has_no_recovery_errors():
    hive = SyntheticHive()
    a, b, c = make_children(hive, ["A", "B", "C"])
    ri = hive.ri_list([
        hive.direct_list(b"lf", [a]),
        hive.direct_list(b"lh", [b, c]),
    ])
    root = hive.nk("ROOT", root=True, subkey_count=2, subkey_list=ri)
    reg = load(hive, root)

    walked = list(reg.walk())
    assert names(walked) == ["ROOT", "A", "B", "C"]
    assert reg.recovery_errors() == []


def test_subkey_lookup_still_resolves_names_after_damage():
    hive = SyntheticHive()
    good = hive.nk("TARGET")
    free = hive.add_free_cell()
    lf = hive.direct_list(b"lf", [free, good])
    root = hive.nk("ROOT", root=True, subkey_count=2, subkey_list=lf)
    reg = load(hive, root)

    assert reg.root().subkey("TARGET").name() == "TARGET"
    with pytest.raises(Registry.RegistryKeyNotFoundException):
        reg.root().subkey("MISSING")


def test_unusable_index_header_is_recorded_and_does_not_raise():
    hive = SyntheticHive()
    hive.nk("A")
    free = hive.add_free_cell()
    # the root claims one subkey but its list pointer targets a free cell
    root = hive.nk("ROOT", root=True, subkey_count=1, subkey_list=free)
    reg = load(hive, root)

    traversal = SubkeyTraversal()
    assert reg.root().subkeys(traversal) == []
    assert len(traversal.errors) == 1
    error = traversal.errors[0]
    assert error.kind == SubkeyIndexErrorKind.INVALID_REFERENCE
    assert error.parent_key_path == "ROOT"
    assert error.list_offset == -1  # no usable index record exists

    walked = list(reg.walk())
    assert names(walked) == ["ROOT"]
    assert len(reg.recovery_errors()) == 1


def test_find_key_recovers_behind_damaged_entry():
    hive = SyntheticHive()
    target = hive.nk("TARGET")
    free = hive.add_free_cell()
    lf = hive.direct_list(b"lf", [free, target])
    root = hive.nk("ROOT", root=True, subkey_count=2, subkey_list=lf)
    reg = load(hive, root)

    assert reg.open("TARGET").name() == "TARGET"
    with pytest.raises(Registry.RegistryKeyNotFoundException):
        reg.open("MISSING")
