"""ARC tests.

Fixtures are generated in memory by ``macarchives.arc``: a stream of
members, each ``0x1a``, a method byte, a 13-byte NUL-padded name, a
little-endian u32 compressed size, u16 MS-DOS date and time, a u16
CRC-16/ARC (over the DECODED bytes), and — for every method but 1 — a
u32 original size; method 1 ("stored, old") omits it and its compressed
size is its original size.  The archive ends with a lone ``0x1a 0x00``.
A member's CRC is over the decoded bytes; the garble XORs the
upper-cased password over each member's COMPRESSED bytes, resetting at
every member.
"""

import io
import struct
from datetime import datetime, timezone

import pytest

import macextract
from macextract import BadPasswordError, CorruptError, UnsupportedError
from macextract.formats import arc as arcmod

import macarchives

DATA = b"The quick brown fox jumps over the lazy dog. " * 40
PAYLOAD = (b"\x00\x01\x81payload with enough repeats to compress well "
           * 20)
ESCAPE_HEAVY = bytes([0x90, 0x41, 0x90, 0x90]) * 40          # the 0x90 corner
RUN_HEAVY = b"A" * 500 + b"\x90" * 300 + b"B" * 10


def _open(image):
    return macextract.open(io.BytesIO(image))


@pytest.mark.parametrize("method", [1, 2, 3, 4, 8, 9])
def test_every_method_round_trips(method):
    for payload in (DATA, PAYLOAD, ESCAPE_HEAVY, RUN_HEAVY, b""):
        image = macarchives.arc([
            {"name": "File.TXT", "data": payload, "method": method},
        ])
        archive = _open(image)
        entry = archive.entries[0]
        assert archive.read(entry, "data") == payload
        assert entry.name == "File.TXT"
        assert entry.data_size == len(payload)
        assert entry.resource_size == 0


@pytest.mark.parametrize("method", [1, 2, 3, 4, 8, 9])
def test_probe_accepts_generated(method):
    image = macarchives.arc([
        {"name": "File.TXT", "data": DATA, "method": method},
    ])
    assert arcmod.probe(image) > 0


def test_probe_accepts_stored_old_method_1():
    image = macarchives.arc([
        {"name": "Tiny.txt", "data": b"ab", "method": 1},
    ])
    assert arcmod.probe(image) > 0
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == b"ab"


def test_probe_rejects_garbage():
    assert arcmod.probe(b"") == 0
    assert arcmod.probe(b"\x01\x02" * 100) == 0
    assert arcmod.probe(b"\x1a\x60" + b"File.TXT\0\0\0\0\0" + b"\0" * 24) == 0


def test_probe_rejects_implausible_name():
    image = bytearray(macarchives.arc(
        [{"name": "File.TXT", "data": DATA}]))
    image[2] = 0x01                     # control byte in the name field
    assert arcmod.probe(bytes(image)) == 0


def test_garble_round_trips():
    for method in (1, 2, 3, 4, 8, 9):
        image = macarchives.arc(
            [{"name": "Secret.TXT", "data": PAYLOAD, "method": method}],
            garble="k3Yword")
        archive = macextract.open(io.BytesIO(image), password="k3Yword")
        entry = archive.entries[0]
        assert archive.read(entry, "data") == PAYLOAD


def test_garble_password_position_resets_per_member():
    entries = [
        {"name": "One.TXT", "data": PAYLOAD, "method": 2},
        {"name": "Two.TXT", "data": DATA, "method": 2},
    ]
    image = macarchives.arc(entries, garble="s3cret")
    archive = macextract.open(io.BytesIO(image), password="s3cret")
    assert [e.name for e in archive.entries] == ["One.TXT", "Two.TXT"]
    assert archive.read(archive.entries[1], "data") == DATA


def test_garble_password_is_upper_cased_by_the_reader():
    image = macarchives.arc(
        [{"name": "Secret.TXT", "data": PAYLOAD, "method": 2}],
        garble="MixedCase")
    archive = macextract.open(io.BytesIO(image), password="mixedcase")
    assert archive.read(archive.entries[0], "data") == PAYLOAD
    # The upper-cased bytes, typed as-is, work identically.
    archive = macextract.open(io.BytesIO(image), password="MIXEDCASE")
    assert archive.read(archive.entries[0], "data") == PAYLOAD


def test_garble_wrong_password_rejected():
    image = macarchives.arc(
        [{"name": "Secret.TXT", "data": PAYLOAD, "method": 2}],
        garble="right")
    with pytest.raises(BadPasswordError):
        macextract.open(io.BytesIO(image), password="wrong")


def test_garble_wrong_password_rejected_crunched():
    image = macarchives.arc(
        [{"name": "Secret.TXT", "data": PAYLOAD, "method": 4}],
        garble="right")
    with pytest.raises(BadPasswordError):
        macextract.open(io.BytesIO(image), password="wrong")


@pytest.mark.parametrize("method,word", [
    (5, "crunched"), (6, "crunched"), (7, "crunched"),
    (0x0a, "crushed"), (0x0b, "distilled"), (0x7f, "compress"),
])
def test_refused_methods_by_name(method, word):
    image = macarchives.arc([{"name": "File.TXT", "data": DATA,
                              "method": method}])
    assert arcmod.probe(image) > 0
    with pytest.raises(UnsupportedError) as excinfo:
        _open(image)
    message = str(excinfo.value)
    assert "ARC:" in message
    assert word in message
    assert "method" in message


@pytest.mark.parametrize("method", [0x14, 0x15, 0x16, 0x1e, 0x1f])
def test_arc7_container_refused_by_name(method):
    image = macarchives.arc([{"name": "File.TXT", "data": DATA,
                              "method": method}])
    with pytest.raises(UnsupportedError, match="ARC 7"):
        _open(image)


def test_arcmac_refused_by_name():
    # The ArcMac header: 0x1b, kind, 31-byte name, ..., then the PC
    # ARC header 59 bytes in (0x1a at 59, the method byte again at 60).
    inner = macarchives.arc([{"name": "F", "data": b"x", "method": 2}])
    image = b"\x1b\x02" + b"F" + b"\0" * 30 + b"\0" * 26 + inner
    assert image[59] == 0x1A and image[60] == 0x02
    with pytest.raises(UnsupportedError, match="ArcMac"):
        _open(image)


def test_crc_corruption_rejected():
    image = bytearray(macarchives.arc(
        [{"name": "File.TXT", "data": PAYLOAD, "method": 2}]))
    image[30] ^= 0xFF               # inside the member's data
    with pytest.raises(CorruptError, match="CRC"):
        _open(bytes(image))


def test_crc_corruption_rejected_method_4():
    image = bytearray(macarchives.arc(
        [{"name": "File.TXT", "data": PAYLOAD, "method": 4}]))
    image[40] ^= 0x40               # inside the Huffman stream
    with pytest.raises(CorruptError):
        _open(bytes(image))


def test_truncated_archive_rejected():
    image = macarchives.arc(
        [{"name": "File.TXT", "data": DATA * 4, "method": 2}])
    with pytest.raises(CorruptError):
        _open(image[:-5])


def test_truncated_marker_rejected():
    image = macarchives.arc(
        [{"name": "File.TXT", "data": DATA, "method": 2}])
    with pytest.raises(CorruptError):
        _open(image[:-1])           # the 0x1a 0x00 marker cut in half


def test_missing_marker_but_clean_boundary_is_accepted():
    image = macarchives.arc(
        [{"name": "File.TXT", "data": DATA, "method": 2}],
        end_marker=False)
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_trailing_junk_after_marker_rejected():
    image = macarchives.arc(
        [{"name": "File.TXT", "data": DATA, "method": 2}])
    with pytest.raises(CorruptError):
        _open(image + b"JUNK")


def test_byte_where_a_header_is_expected_rejected():
    image = macarchives.arc(
        [{"name": "File.TXT", "data": DATA, "method": 2}])
    # Corrupt the end-of-archive marker into something else.
    image = image[:-2] + b"\x1a\x60"
    with pytest.raises(CorruptError):
        _open(image)


def test_extract_writes_the_entry(tmp_path):
    image = macarchives.arc([
        {"name": "Doc.TXT", "data": DATA, "method": 2},
    ])
    path = tmp_path / "Doc.arc"
    path.write_bytes(image)
    out = tmp_path / "out"
    archive = macextract.open(path)
    written = archive.extract(str(out))
    assert (out / "Doc.TXT").read_bytes() == DATA
    assert written == [str(out / "Doc.TXT")]


def test_member_name_is_path_sanitised(tmp_path):
    image = macarchives.arc([
        {"name": "../Escape.TXT", "data": DATA, "method": 2},
    ])
    archive = _open(image)
    name = archive.entries[0].name
    assert ".." not in name.split("/")
    out = tmp_path / "out"
    archive.extract(str(out))
    assert (out / "Escape.TXT").read_bytes() == DATA
    assert not (tmp_path / "Escape.TXT").exists()


def test_member_name_with_separator_does_not_escape(tmp_path):
    image = macarchives.arc([
        {"name": "a/b.TXT", "data": DATA, "method": 2},
    ])
    archive = _open(image)
    name = archive.entries[0].name
    out = tmp_path / "out"
    archive.extract(str(out))
    written = out.joinpath(name)
    assert written.read_bytes() == DATA
    assert str(written).startswith(str(out))


def test_filename_hint_is_not_needed():
    image = macarchives.arc([
        {"name": "File.TXT", "data": DATA, "method": 2},
    ])
    archive = arcmod.open_data(image)
    assert archive.entries[0].name == "File.TXT"


def test_multiple_members_and_marker():
    entries = [
        {"name": "First.TXT", "data": DATA, "method": 3},
        {"name": "Second.TXT", "data": PAYLOAD, "method": 4},
        {"name": "Third.TXT", "data": ESCAPE_HEAVY, "method": 8},
        {"name": "Fourth.TXT", "data": RUN_HEAVY, "method": 9},
    ]
    image = macarchives.arc(entries)
    archive = _open(image)
    assert [e.name for e in archive.entries] == [
        "First.TXT", "Second.TXT", "Third.TXT", "Fourth.TXT"]
    for entry, spec in zip(archive.entries, entries):
        assert archive.read(entry, "data") == spec["data"]


def test_empty_member():
    image = macarchives.arc([
        {"name": "Empty.TXT", "data": b"", "method": 2},
        {"name": "Real.TXT", "data": b"real", "method": 2},
    ])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == b""
    assert archive.read(archive.entries[1], "data") == b"real"


def test_dos_date_time_fields_decode():
    # 2020-06-15 12:00:00 as DOS date/time words.
    date_word = ((2020 - 1980) << 9) | (6 << 5) | 15
    time_word = (12 << 11) | (0 << 5) | (0 // 2)
    image = macarchives.arc([
        {"name": "Stamped.TXT", "data": b"stamp", "method": 2,
         "date": date_word, "time": time_word},
    ])
    archive = _open(image)
    entry = archive.entries[0]
    assert entry.modified_date == datetime(2020, 6, 15, 12, 0, 0,
                                           tzinfo=timezone.utc)
    assert entry.created == entry.modified


def test_method_1_header_has_no_original_size():
    image = macarchives.arc([
        {"name": "Old.TXT", "data": DATA, "method": 1},
    ])
    # The member is 25 bytes in, so data begins there.
    data_offset = 25
    assert image[data_offset:data_offset + len(DATA)] == DATA
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_wrong_width_byte_for_method_8_rejected():
    image = bytearray(macarchives.arc(
        [{"name": "Crunch.TXT", "data": PAYLOAD, "method": 8}]))
    image[29] = 0x0B                    # the width byte: 11, not 12
    with pytest.raises(CorruptError):
        _open(bytes(image))


def test_garble_bytes_differ_but_headers_do_not():
    plain = macarchives.arc(
        [{"name": "Secret.TXT", "data": PAYLOAD, "method": 2}])
    garbled = macarchives.arc(
        [{"name": "Secret.TXT", "data": PAYLOAD, "method": 2}],
        garble="key")
    header = 29
    assert plain[:header] == garbled[:header]
    assert plain[header:] != garbled[header:]
