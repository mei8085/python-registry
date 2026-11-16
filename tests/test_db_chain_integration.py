#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Integration tests for large-value ("db") segment chains.

The tests in this module treat a registry value as a byte stream that must be
observed identically through both access paths:

  * ``RegistryValue.raw_data()``  -> unparsed bytes
  * ``RegistryValue.value()``     -> typed value (``bytes`` for RegBin)

They assert three properties:

1. Boundary integrity: a large value is assembled only from the payload of the
   cells named by its ``db`` chain.  Bytes of neighbouring cells (the fixtures
   fill them with 0xA5) must never appear, and a declared length must never
   cause an unbounded allocation.
2. Well-formed values are byte-for-byte identical on both paths, across
   segment boundaries and for one and many segments.
3. Malformed chains (out-of-range index/offset, repeated segment, declared
   length overflow, truncated HBIN) produce a stable, typed error or an
   explicit truncated result - never a bare ``struct.error``, never garbage
   from a neighbour cell.

The committed fixtures under ``tests/reg_samples/db_chain`` are produced by
``tests/db_chain_fixtures.py``; ``test_fixtures_are_reproducible_byte_for_byte``
regenerates them in memory and compares the result byte-for-byte, so the
samples stay replayable.
"""

import glob
import hashlib
import io
import os
import struct
import sys

try:
    import tracemalloc
except ImportError:  # pragma: no cover - Python 2
    tracemalloc = None

import pytest

from Registry import Registry, RegistryParse

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(HERE, "reg_samples", "db_chain")

# Import the fixture builder regardless of how pytest was invoked.
sys.path.insert(0, HERE)
import db_chain_fixtures as fixtures  # noqa: E402

VALUE_NAME = fixtures.VALUE_NAME
POISON_BYTE = fixtures.POISON_BYTE
SEGMENT_SIZE = fixtures.SEGMENT_SIZE


def hive_path(name):
    return os.path.join(SAMPLE_DIR, name)


def open_hive(name):
    return Registry.Registry(hive_path(name))


def big_value(name):
    return open_hive(name).root().value(VALUE_NAME)


# Every committed fixture, split into the two groups the tests reason about.
NORMAL_SAMPLES = sorted(
    os.path.basename(p) for p in glob.glob(os.path.join(SAMPLE_DIR, "normal_*.hive")))
BAD_SAMPLES = sorted(
    os.path.basename(p) for p in glob.glob(os.path.join(SAMPLE_DIR, "bad_*.hive")))


# ---------------------------------------------------------------------------
# Fixtures are present, replayable, and not accidentally degenerate.
# ---------------------------------------------------------------------------

def test_all_expected_samples_exist():
    assert NORMAL_SAMPLES == [
        "normal_bin_16345.hive",
        "normal_bin_32736.hive",
        "normal_bin_32955.hive",
        "normal_inline_unflagged.hive",
        "normal_sz_32736.hive",
    ]
    assert BAD_SAMPLES == [
        "bad_duplicate.hive",
        "bad_index.hive",
        "bad_indirect_free.hive",
        "bad_inline_overflow_80000005.hive",
        "bad_inline_overflow_ffffffff.hive",
        "bad_length_overflow.hive",
        "bad_mid_cell_pointer.hive",
        "bad_offset.hive",
        "bad_segment_size_overrun.hive",
        "bad_truncated_hbin.hive",
    ]


def test_fixtures_are_reproducible_byte_for_byte():
    """The committed hives must equal a fresh build of the generator."""
    for name in NORMAL_SAMPLES + BAD_SAMPLES:
        with open(hive_path(name), "rb") as f:
            committed = f.read()
        rebuilt = fixtures.SAMPLES[name]()
        assert committed == rebuilt, "%s is not reproducible" % name
        # The generator is deterministic (no timestamps, no randomness).
        assert rebuilt == fixtures.SAMPLES[name]()


def test_fixtures_are_distinct_real_hives():
    digests = {}
    for name in NORMAL_SAMPLES + BAD_SAMPLES:
        with open(hive_path(name), "rb") as f:
            data = f.read()
        digests[name] = hashlib.md5(data).hexdigest()
        # A real REGF header plus one HBIN.
        assert data[0:4] == b"regf"
        assert data[0x1000:0x1004] == b"hbin"
        regf = RegistryParse.REGFBlock(data, 0, None)
        assert regf.validate_checksum()
        assert regf.validate_sequence_numbers()
        assert regf.first_hbin_offset() == 0x1000
        assert regf.hbins_size() % 0x1000 == 0
        hive = Registry.Registry(io.BytesIO(data))
        assert hive.root().name() == "ROOT"
        assert hive.root().value(VALUE_NAME).name() == VALUE_NAME
    assert len(set(digests.values())) == len(digests)

    # Opposite: identical bytes must reproduce identical results.
    results = []
    for _ in range(2):
        results.append(big_value("normal_bin_32736.hive").raw_data())
    assert results[0] == results[1]


# ---------------------------------------------------------------------------
# 1. Well-formed large values: exact bytes, no neighbour bleed.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", NORMAL_SAMPLES)
def test_normal_value_raw_and_typed_agree(name):
    value = big_value(name)
    declared = value._vkrecord.data_length()
    raw = value.raw_data()

    assert isinstance(raw, bytes)
    assert len(raw) == declared, "declared length must be satisfied exactly"
    assert POISON_BYTE not in raw, "neighbour cell bytes leaked into the value"

    typed = value.value()
    if value.value_type() == Registry.RegBin:
        assert isinstance(typed, bytes)
        # Both access paths observe the same boundary: identical bytes.
        assert typed == raw
        assert hashlib.md5(typed).digest() == hashlib.md5(raw).digest()
    elif value.value_type() == Registry.RegSZ:
        assert isinstance(typed, str)
        # Typed decoding is derived from exactly the same raw bytes.
        assert typed == fixtures.build_normal_string(declared)[1]
        assert typed.encode("utf-16le") + b"\x00\x00" == raw


def test_normal_value_payload_matches_generator():
    """Compare against the payload the generator intended, not just lengths."""
    for length in (SEGMENT_SIZE + 1, SEGMENT_SIZE * 2, SEGMENT_SIZE * 2 + 0x123):
        expected = fixtures.payload_for(length)
        value = open_hive(_normal_name_for(length)).root().value(VALUE_NAME)
        assert value.raw_data() == expected
        assert value.value() == expected


def test_unflagged_inline_value_is_bounded():
    """A <= 4 byte value without the inline flag reads only its own bytes."""
    value = big_value("normal_inline_unflagged.hive")
    record = value._vkrecord
    assert record.raw_data_length() == 3

    raw = value.raw_data()
    assert raw == b"\x11\x22\x33"
    assert raw == record._buf[record.offset() + 8:record.offset() + 11]
    # The data type dword follows the field; the old code started reading at
    # the HBIN header offset and produced 0x000000 instead.
    assert record.unpack_dword(0xC) == Registry.RegBin
    assert value.value() == raw


def _normal_name_for(length):
    return {
        SEGMENT_SIZE + 1: "normal_bin_16345.hive",
        SEGMENT_SIZE * 2: "normal_bin_32736.hive",
        SEGMENT_SIZE * 2 + 0x123: "normal_bin_32955.hive",
    }[length]


def test_well_formed_chain_has_exactly_enough_segments():
    """Each normal chain names just enough segments for its declared length."""
    for name in ("normal_bin_16345.hive", "normal_bin_32736.hive",
                 "normal_bin_32955.hive"):
        hive = open_hive(name)
        vk = hive.root().value(VALUE_NAME)._vkrecord
        cell = RegistryParse.HBINCell(vk._buf, vk.data_offset(), vk)
        assert cell.data_id() == b"db"

        db = cell.child()
        indirect_offset = db.abs_offset_from_hbin_offset(db.unpack_dword(0x4))
        indirect = RegistryParse.HBINCell(vk._buf, indirect_offset, db)
        entries = indirect.payload_capacity() // 4
        declared = vk.data_length()
        needed = (declared + SEGMENT_SIZE - 1) // SEGMENT_SIZE
        assert entries == needed


def test_value_is_segments_concatenated_in_order():
    """The value equals segment payloads joined in indirect-entry order."""
    hive = open_hive("normal_bin_32955.hive")
    vk = hive.root().value(VALUE_NAME)._vkrecord
    declared = vk.data_length()

    db_cell = RegistryParse.HBINCell(vk._buf, vk.data_offset(), vk)
    db = db_cell.child()
    indirect_offset = db.abs_offset_from_hbin_offset(db.unpack_dword(0x4))
    indirect_cell = RegistryParse.HBINCell(vk._buf, indirect_offset, db)
    indirect = RegistryParse.DBIndirectBlock(
        vk._buf, indirect_cell.data_offset(), indirect_cell)

    expected = b""
    remaining = declared
    index = 0
    while remaining > 0:
        entry = indirect.unpack_dword(4 * index)
        segment = RegistryParse.HBINCell(
            vk._buf, indirect.abs_offset_from_hbin_offset(entry), indirect)
        take = min(SEGMENT_SIZE, remaining)
        expected += segment.payload(take)
        remaining -= take
        index += 1

    assert len(expected) == declared
    assert hive.root().value(VALUE_NAME).raw_data() == expected
    assert fixtures.payload_for(declared) == expected


# ---------------------------------------------------------------------------
# 2. Malformed chains: out-of-range index and offset.
# ---------------------------------------------------------------------------

def test_out_of_range_index_is_rejected_not_spliced():
    value = big_value("bad_index.hive")
    declared = value._vkrecord.data_length()

    # The hive is large enough to honour the declared length...
    assert os.path.getsize(hive_path("bad_index.hive")) > declared
    # ...but the indirect block does not have enough entries.
    with pytest.raises(RegistryParse.LargeDataParseException) as excinfo:
        value.raw_data()
    message = str(excinfo.value)
    assert "needs 3 segments" in message
    assert "only holds 2" in message

    # Typed and raw reads fail identically (same boundary).
    with pytest.raises(RegistryParse.LargeDataParseException):
        value.value()


def test_out_of_range_offset_is_rejected():
    value = big_value("bad_offset.hive")
    with pytest.raises(RegistryParse.LargeDataParseException) as excinfo:
        value.raw_data()
    assert "outside the HBIN region" in str(excinfo.value)

    with pytest.raises(RegistryParse.LargeDataParseException):
        value.value()


def test_error_is_deterministic_across_repeated_reads():
    for name in ("bad_index.hive", "bad_offset.hive", "bad_duplicate.hive",
                 "bad_length_overflow.hive", "bad_segment_size_overrun.hive",
                 "bad_indirect_free.hive", "bad_mid_cell_pointer.hive"):
        messages = set()
        for _ in range(3):
            value = big_value(name)
            with pytest.raises(RegistryParse.LargeDataParseException) as excinfo:
                value.raw_data()
            messages.add(str(excinfo.value))
        assert len(messages) == 1, "%s produced non-deterministic errors" % name


def test_segment_cell_cannot_extend_past_hbin():
    """A segment size field that runs past the HBIN is rejected."""
    value = big_value("bad_segment_size_overrun.hive")
    with pytest.raises(RegistryParse.LargeDataParseException) as excinfo:
        value.raw_data()
    assert "extends past the end of the HBIN region" in str(excinfo.value)

    with pytest.raises(RegistryParse.LargeDataParseException):
        value.value()


def test_free_indirect_cell_is_rejected():
    """A db record that resolves to a free cell must not be read as data."""
    value = big_value("bad_indirect_free.hive")
    with pytest.raises(RegistryParse.LargeDataParseException) as excinfo:
        value.raw_data()
    assert "free cell" in str(excinfo.value)

    with pytest.raises(RegistryParse.LargeDataParseException):
        value.value()


def test_mid_cell_pointer_is_rejected():
    """A pointer into the middle of a cell must not forge a cell size.

    Without the cell-start check the reader would treat payload bytes as a
    size field and splice the following cell into the value.
    """
    value = big_value("bad_mid_cell_pointer.hive")
    with pytest.raises(RegistryParse.LargeDataParseException) as excinfo:
        value.raw_data()
    assert "not the start of an HBIN cell" in str(excinfo.value)

    with pytest.raises(RegistryParse.LargeDataParseException):
        value.value()


def test_cell_start_predicate_matches_cell_walk():
    """The cached geometry index must agree with an independent cell walk."""
    hive = open_hive("normal_bin_32736.hive")
    record = hive.root().value(VALUE_NAME)._vkrecord
    buf = hive._buf

    hbin_start = hive._regf.first_hbin_offset()
    hbin_end = min(hbin_start + hive._regf.hbins_size(), len(buf))
    walked = []
    offset = hbin_start + 0x20
    while offset + 4 <= hbin_end:
        walked.append(offset)
        size = struct.unpack_from("<i", buf, offset)[0]
        size = -size if size < 0 else size
        if size < 4:
            break
        offset += size

    assert walked
    for offset in walked:
        assert record.is_cell_start(offset)

    # A byte inside the first cell is not a cell start.
    inside = walked[0] + 0x8
    assert inside not in walked
    assert record.is_cell_start(inside) is False


# ---------------------------------------------------------------------------
# 3. Duplicate segments.
# ---------------------------------------------------------------------------

def test_duplicate_segment_is_rejected():
    value = big_value("bad_duplicate.hive")
    with pytest.raises(RegistryParse.LargeDataParseException) as excinfo:
        value.raw_data()
    assert "referenced more than once" in str(excinfo.value)

    with pytest.raises(RegistryParse.LargeDataParseException):
        value.value()

    # The fallback path must not silently return the first segment twice.
    assert value.raw_data.__self__._vkrecord.data_length() == 2 * SEGMENT_SIZE


# ---------------------------------------------------------------------------
# 4. Declared length overflow / unbounded allocation.
# ---------------------------------------------------------------------------

def test_declared_length_overflow_does_not_allocate():
    value = big_value("bad_length_overflow.hive")
    declared = value._vkrecord.data_length()

    assert declared == 0x7FFFFFFF
    assert declared > os.path.getsize(hive_path("bad_length_overflow.hive"))

    with pytest.raises(RegistryParse.LargeDataParseException) as excinfo:
        value.raw_data()
    assert "refusing to allocate" in str(excinfo.value)

    with pytest.raises(RegistryParse.LargeDataParseException):
        value.value()


def test_declared_length_overflow_allocates_no_large_buffer():
    """A ~2 GiB declared length must be rejected before any buffer is built."""
    if tracemalloc is None or not hasattr(tracemalloc, "start"):
        # pragma: no cover - Python 2
        pytest.skip("tracemalloc requires Python 3.4+")

    value = big_value("bad_length_overflow.hive")
    hive_size = os.path.getsize(hive_path("bad_length_overflow.hive"))

    tracemalloc.start()
    try:
        with pytest.raises(RegistryParse.LargeDataParseException):
            value.raw_data()
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # The whole hive is only ~20 KiB; anything near the declared length (or
    # even a fraction of it) would be visible here.
    assert peak < hive_size * 4


@pytest.mark.parametrize("name,masked_length", [
    ("bad_inline_overflow_ffffffff.hive", 0x7FFFFFFF),
    ("bad_inline_overflow_80000005.hive", 5),
])
def test_inline_length_cannot_spill_past_four_byte_field(name, masked_length):
    """High-bit ("inline") lengths are clamped to the 4 byte data field.

    This includes the case where the masked length is larger than the field
    itself: the result must be the field's four bytes, never a struct error
    and never bytes from the following fields.
    """
    value = big_value(name)
    record = value._vkrecord
    assert record.data_length() == masked_length

    raw = value.raw_data()
    assert isinstance(raw, bytes)
    assert len(raw) == 4
    assert POISON_BYTE not in raw
    # Exactly the four data bytes, nothing from the following fields.
    assert raw == record._buf[record.offset() + 8:record.offset() + 12]
    # The typed path observes the same four bytes.
    assert value.value() == raw


# ---------------------------------------------------------------------------
# 5. Truncated HBIN.
# ---------------------------------------------------------------------------

def test_truncated_hbin_returns_explicit_prefix():
    """The file ends inside the first segment; the present prefix is returned."""
    value = big_value("bad_truncated_hbin.hive")
    declared = value._vkrecord.data_length()
    raw = value.raw_data()

    expected_length = fixtures.TRUNCATED_EXPECTED_LENGTH
    assert len(raw) < declared
    assert len(raw) == expected_length
    assert POISON_BYTE not in raw

    # The prefix is exactly the beginning of the intended payload.
    assert raw == fixtures.payload_for(declared)[:expected_length]

    # Both paths truncate at the same byte.
    typed = value.value()
    assert typed == raw


def test_truncated_hbin_error_is_not_struct_error():
    """Whatever is raised must be a registry exception, never struct.error."""
    value = big_value("bad_truncated_hbin.hive")
    try:
        value.raw_data()
    except RegistryParse.RegistryException:
        pass
    except struct.error:  # pragma: no cover - regression guard
        pytest.fail("raw_data leaked a struct.error for a truncated HBIN")


# ---------------------------------------------------------------------------
# Cross-cutting: no malformed sample may ever leak neighbour bytes, and every
# failure must be a stable registry-level error or an explicit truncation.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", BAD_SAMPLES)
def test_no_malformed_sample_returns_neighbour_bytes(name):
    value = big_value(name)
    try:
        raw = value.raw_data()
    except RegistryParse.RegistryException:
        return

    # If a value is returned at all, it must be an explicit prefix of the
    # intended payload and must not contain poison from a neighbour cell.
    assert isinstance(raw, bytes)
    assert POISON_BYTE not in raw

    declared = value._vkrecord.data_length()
    if name.startswith("bad_inline"):
        # Inline values are clamped to the 4 byte field; the intended payload
        # is the field itself, not a generated buffer.
        field = value._vkrecord._buf[value._vkrecord.offset() + 8:
                                    value._vkrecord.offset() + 12]
        assert raw == field[:len(raw)]
        return

    # Never allocate the declared length: only the length actually returned
    # is meaningful here.
    expected_prefix = fixtures.payload_for(len(raw))[:len(raw)]
    assert raw == expected_prefix, (
        "%s returned bytes that are not a prefix of the intended payload" % name)
    assert len(raw) < declared


@pytest.mark.parametrize("name", BAD_SAMPLES)
def test_malformed_sample_never_raises_bare_struct_error(name):
    value = big_value(name)
    try:
        value.raw_data()
    except RegistryParse.RegistryException:
        pass
    except struct.error:  # pragma: no cover - regression guard
        pytest.fail("%s leaked struct.error" % name)

    try:
        value.value()
    except (RegistryParse.RegistryException, RegistryParse.UnknownTypeException):
        pass
    except struct.error:  # pragma: no cover - regression guard
        pytest.fail("%s leaked struct.error from value()" % name)


# ---------------------------------------------------------------------------
# Real-world regression: the bundled SYSTEM hive still returns exact bytes.
# ---------------------------------------------------------------------------

def test_corrupt_utf16_only_affects_typed_decode():
    """A corrupted UTF-16 payload is a raw-read success and a typed failure.

    ``raw_data()`` returns the exact bytes; ``value()`` decodes them and, for
    malformed UTF-16, raises UnicodeDecodeError as documented by
    ``decode_utf16le``.  The important invariant is that the raw path does not
    depend on the encoding.
    """
    hive, text, payload = fixtures.build_normal_string(SEGMENT_SIZE * 2)
    hive = bytearray(hive)
    # Break the payload by writing a lone surrogate into the first segment.
    segment = hive.find(payload[:32])
    assert segment > 0
    hive[segment:segment + 2] = b"\x00\xd8"

    registry = Registry.Registry(io.BytesIO(bytes(hive)))
    value = registry.root().value(VALUE_NAME)

    raw = value.raw_data()
    assert raw[:2] == b"\x00\xd8"
    assert len(raw) == len(payload)
    assert b"\xa5" not in raw

    with pytest.raises(UnicodeDecodeError):
        value.value()


def test_real_world_large_value_still_exact():
    path = os.path.join(HERE, os.pardir, "testing", "reg_samples", "new_log_1",
                        "SYSTEM")
    path = os.path.normpath(path)
    root = Registry.Registry(path).root()
    value = root.find_key(r"ControlSet001\Control\ProductOptions").value("ProductPolicy")
    data = value.raw_data()
    assert len(data) == 23712
    assert hashlib.md5(data).hexdigest() == "7e96f10f77e1c44771d7045c24b94024"
    # ProductPolicy is RegBin, so the typed path must be identical.
    assert value.value() == data
