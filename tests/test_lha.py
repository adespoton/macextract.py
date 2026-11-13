"""LZH/LHA tests.

Fixtures are generated in memory by ``macarchives.lha``: a stream of
members. Levels 0/1 store MS-DOS date/time words; levels 2 and 3 store
a Unix time and carry no name in the base header — the name comes from
the 0x01 extended header, which is why the fixture defaults it for
levels 2 and 3 in ``_spec`` below.  The archive ends with a lone zero
byte.  ``-lh0-`` and ``-lz4-`` are stored; ``-lh4-`` .. ``-lh7-`` use
the "new" LZSS with three canonical Huffman tables rebuilt per block,
written by the fixture's own encoder, so every round trip here also
exercises the decoder's table reconstruction.
"""

import io
import struct
from datetime import datetime, timezone

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract._crc16 import crc16_arc
from macextract.formats import lha as lhamod

import macarchives

DATA = b"The quick brown fox jumps over the lazy dog. " * 40
ALL_BYTES = bytes(range(256)) * 8
REPEAT_HEAVY = b"ABCD" * 200 + b" run of A" * 0 + b"A" * 1000
ENTROPIC = bytes((i * 2654435761 + i * i + 97) & 0xFF for i in range(4096))


def _spec(spec):
    """Levels 2 and 3 carry no name in the base header; the reader
    takes it from the 0x01 extended header, so the fixture default
    supplies it there."""
    if spec.get("level", 1) >= 2 and "filename_ext" not in spec:
        spec = dict(spec)
        spec["filename_ext"] = spec["name"]
    return spec


def _build(entries, **kwargs):
    return macarchives.lha([_spec(entry) for entry in entries], **kwargs)


def _open(image):
    return macextract.open(io.BytesIO(image))


IMPLEMENTED = ["-lh0-", "-lz4-", "-lh4-", "-lh5-", "-lh6-", "-lh7-"]
PAYLOADS = [DATA, ALL_BYTES, REPEAT_HEAVY, ENTROPIC, b""]


@pytest.mark.parametrize("method", IMPLEMENTED)
@pytest.mark.parametrize("payload", PAYLOADS)
def test_every_method_round_trips(method, payload):
    image = _build([{"name": "File.TXT", "data": payload,
                     "method": method}])
    archive = _open(image)
    entry = archive.entries[0]
    assert entry.name == "File.TXT"
    assert archive.read(entry, "data") == payload
    assert entry.data_size == len(payload)
    assert entry.resource_size == 0


@pytest.mark.parametrize("level", [0, 1, 2, 3])
@pytest.mark.parametrize("method", ["-lh0-", "-lh5-"])
def test_every_level_round_trips(level, method):
    image = _build([{"name": "File.TXT", "data": DATA, "method": method,
                     "level": level}])
    archive = _open(image)
    entry = archive.entries[0]
    assert entry.name == "File.TXT"
    assert archive.read(entry, "data") == DATA


def test_mixed_levels_and_methods_in_one_archive():
    entries = [
        {"name": "Zero.TXT", "data": DATA, "method": "-lh5-", "level": 0},
        {"name": "One.TXT", "data": ALL_BYTES, "method": "-lh7-",
         "level": 1},
        {"name": "Two.TXT", "data": REPEAT_HEAVY, "method": "-lh5-",
         "level": 2},
        {"name": "Three.TXT", "data": ENTROPIC, "method": "-lz4-",
         "level": 3},
    ]
    image = _build(entries)
    archive = _open(image)
    assert [entry.name for entry in archive.entries] == [
        "Zero.TXT", "One.TXT", "Two.TXT", "Three.TXT"]
    for entry, spec in zip(archive.entries, entries):
        assert archive.read(entry, "data") == spec["data"]


# ------------------------------------------------------------------ #
# probe                                                               #
# ------------------------------------------------------------------ #


@pytest.mark.parametrize("method", IMPLEMENTED)
def test_probe_accepts_generated(method):
    image = _build([{"name": "File.TXT", "data": DATA, "method": method}])
    assert lhamod.probe(image) > 0


def test_probe_rejects_garbage():
    assert lhamod.probe(b"") == 0
    assert lhamod.probe(b"\x01\x02" * 100) == 0
    image = _build([{"name": "File.TXT", "data": DATA}])
    image = image[:2] + b"\x00" + image[3:]    # no dash at offset 2
    assert lhamod.probe(image) == 0


def test_probe_rejects_implausible_level():
    image = bytearray(_build([{"name": "File.TXT", "data": DATA}]))
    image[20] = 0x04                          # level 4 does not exist
    assert lhamod.probe(bytes(image)) == 0


def test_probe_claims_refused_method_so_open_can_name_it():
    image = _build([{"name": "File.TXT", "data": DATA,
                     "method": "-lh1-"}])
    assert lhamod.probe(image) > 0
    with pytest.raises(UnsupportedError, match="-lh1-"):
        _open(image)


def test_probe_claims_unknown_method_so_open_can_name_it():
    image = _build([{"name": "File.TXT", "data": DATA,
                     "method": "-zz9-"}])
    assert lhamod.probe(image) > 0
    with pytest.raises(UnsupportedError, match="-zz9-"):
        _open(image)


def test_probe_truncated_archive_still_claimed():
    image = _build([{"name": "File.TXT", "data": DATA}])
    assert lhamod.probe(image[:-3]) > 0


# ------------------------------------------------------------------ #
# refused methods                                                     #
# ------------------------------------------------------------------ #


REFUSED = [
    "-lh1-", "-lh2-", "-lh3-", "-lh8-", "-lh9-", "-lha-", "-lhb-",
    "-lhc-", "-lhe-", "-lhx-", "-lx1-", "-lzs-", "-lz0-", "-lz2-",
    "-lz3-", "-lz5-", "-lz7-", "-lz8-", "-pc1-", "-pm0-", "-pm1-",
    "-pm2-", "-pms-", "-ah0-", "-ari-", "-hf0-", "-lZ0-", "-lZ1-",
    "-lZ5-",
]


@pytest.mark.parametrize("method", REFUSED)
def test_refused_methods_by_name(method):
    image = _build([{"name": "File.TXT", "data": DATA, "method": method}])
    with pytest.raises(UnsupportedError) as excinfo:
        _open(image)
    message = str(excinfo.value)
    assert "LZH:" in message
    assert method in message
    assert "not supported" in message


def test_lh7_with_lhark_os_byte_refused_by_name():
    image = _build([{"name": "File.TXT", "data": DATA, "method": "-lh7-",
                     "os": 0x20}])
    with pytest.raises(UnsupportedError, match="LHArk"):
        _open(image)


def test_level3_header_word_other_than_4_refused():
    image = _build([{"name": "File.TXT", "data": DATA, "level": 3,
                     "level3_word": 2}])
    with pytest.raises(UnsupportedError, match="word size"):
        _open(image)


# ------------------------------------------------------------------ #
# extract, names, dates, locks                                        #
# ------------------------------------------------------------------ #


def test_extract_writes_the_entry(tmp_path):
    image = _build([{"name": "Doc.TXT", "data": DATA, "method": "-lh5-"}])
    path = tmp_path / "Doc.lha"
    path.write_bytes(image)
    out = tmp_path / "out"
    archive = macextract.open(path)
    written = archive.extract(str(out))
    assert (out / "Doc.TXT").read_bytes() == DATA
    assert written == [str(out / "Doc.TXT")]


def test_member_name_is_path_sanitised(tmp_path):
    image = _build([{"name": "../Escape.TXT", "data": DATA,
                     "method": "-lh5-"}])
    archive = _open(image)
    name = archive.entries[0].name
    assert ".." not in name.split("/")
    out = tmp_path / "out"
    archive.extract(str(out))
    assert (out / "Escape.TXT").read_bytes() == DATA
    assert not (tmp_path / "Escape.TXT").exists()


def test_directory_components_split_on_ff_and_slash():
    image = _build([{"name": "File.TXT", "data": DATA, "level": 1,
                     "path_ext": b"Sub\xffDir/Inner"}])
    archive = _open(image)
    assert archive.entries[0].name == "Sub/Dir/Inner/File.TXT"


def test_directory_components_split_on_backslash():
    image = _build([{"name": "File.TXT", "data": DATA, "level": 1,
                     "path_ext": b"Sub\\Dir"}])
    archive = _open(image)
    assert archive.entries[0].name == "Sub/Dir/File.TXT"


def test_directory_marker_is_skipped(tmp_path):
    image = _build([
        {"name": "Dir", "data": b"", "dir": True},
        {"name": "Sub.TXT", "data": DATA},
    ])
    archive = _open(image)
    assert [entry.name for entry in archive.entries] == ["Sub.TXT"]
    out = tmp_path / "out"
    archive.extract(str(out))
    assert (out / "Sub.TXT").read_bytes() == DATA
    assert not (out / "Dir").exists()


def test_member_with_nul_in_name_is_truncated_there():
    image = _build([{"name": "A\0B.TXT", "data": DATA}])
    archive = _open(image)
    assert archive.entries[0].name == "A"


def test_filename_hint_is_not_needed():
    image = _build([{"name": "File.TXT", "data": DATA}])
    archive = lhamod.open_data(image)
    assert archive.entries[0].name == "File.TXT"


def test_dos_date_time_fields_decode():
    # 2020-06-15 12:00:00 as DOS date/time words.
    date_word = ((2020 - 1980) << 9) | (6 << 5) | 15
    time_word = (12 << 11) | (0 << 5) | 0
    image = _build([{"name": "Stamped.TXT", "data": b"stamp",
                     "date": date_word, "time": time_word}])
    entry = _open(image).entries[0]
    assert entry.modified_date == datetime(2020, 6, 15, 12, 0, 0,
                                           tzinfo=timezone.utc)
    assert entry.created == entry.modified


def test_level0_unix_area_overrides_the_dos_date():
    unix_time = 1592222400                    # 2020-06-15 12:00:00 UTC
    image = _build([{"name": "Stamped.TXT", "data": b"stamp", "level": 0,
                     "unix_area": True, "unix_time": unix_time}])
    entry = _open(image).entries[0]
    assert entry.modified_date == datetime(2020, 6, 15, 12, 0, 0,
                                           tzinfo=timezone.utc)


def test_level1_mtime_header_overrides_the_dos_date():
    unix_time = 1609459200                    # 2021-01-01 00:00:00 UTC
    image = _build([{"name": "Stamped.TXT", "data": b"stamp", "level": 1,
                     "mtime54": unix_time, "unix_time": 1592222400}])
    entry = _open(image).entries[0]
    assert entry.modified_date == datetime(2021, 1, 1, 0, 0, 0,
                                           tzinfo=timezone.utc)


def test_level2_mtime_header_overrides_the_base_time():
    unix_time = 1609459200                    # 2021-01-01 00:00:00 UTC
    image = _build([{"name": "Stamped.TXT", "data": b"stamp", "level": 2,
                     "mtime54": unix_time, "unix_time": 1592222400}])
    entry = _open(image).entries[0]
    assert entry.modified_date == datetime(2021, 1, 1, 0, 0, 0,
                                           tzinfo=timezone.utc)


def test_level0_short_header_round_trips():
    image = _build([{"name": "Short.TXT", "data": DATA, "level": 0,
                     "short": True}])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_locked_via_posix_mode_write_bit():
    image = _build([{"name": "Locked.TXT", "data": b"x", "level": 1,
                     "mode": 0o400}])
    assert _open(image).entries[0].locked
    image = _build([{"name": "Free.TXT", "data": b"x", "level": 1,
                     "mode": 0o600}])
    assert not _open(image).entries[0].locked


def test_locked_via_level0_unix_area_mode():
    image = _build([{"name": "Locked.TXT", "data": b"x", "level": 0,
                     "unix_area": True, "mode": 0o400}])
    assert _open(image).entries[0].locked
    image = _build([{"name": "Free.TXT", "data": b"x", "level": 0,
                     "unix_area": True, "mode": 0o644}])
    assert not _open(image).entries[0].locked


def test_locked_via_msdos_attribute():
    image = _build([{"name": "Locked.TXT", "data": b"x", "attr": 0x01}])
    assert _open(image).entries[0].locked
    image = _build([{"name": "Free.TXT", "data": b"x", "attr": 0x20}])
    assert not _open(image).entries[0].locked


def test_msdos_attribute_extended_header_overrides_the_attr_byte():
    image = _build([{"name": "Locked.TXT", "data": b"x", "level": 1,
                     "attr": 0x20,
                     "exts": [(0x40, struct.pack("<H", 0x01))]}])
    assert _open(image).entries[0].locked


def test_comment_and_unknown_extended_headers_are_stepped_over():
    image = _build([{"name": "Doc.TXT", "data": DATA, "level": 1,
                     "comment": "a comment",
                     "exts": [(0x03, b"unknown bytes"),
                              (0x7f, b"more unknown")]}])
    archive = _open(image)
    assert archive.entries[0].name == "Doc.TXT"
    assert archive.read(archive.entries[0], "data") == DATA


# ------------------------------------------------------------------ #
# failure paths                                                       #
# ------------------------------------------------------------------ #


def test_crc_corruption_rejected():
    image = bytearray(_build([{"name": "File.TXT", "data": DATA,
                               "method": "-lh5-"}]))
    image[-20] ^= 0xFF                        # inside the member's data
    with pytest.raises(CorruptError, match="CRC"):
        _open(bytes(image))


def test_crc_corruption_rejected_level2_no_header_sum():
    image = bytearray(_build([{"name": "File.TXT", "data": DATA,
                               "method": "-lh5-", "level": 2}]))
    image[-20] ^= 0xFF
    with pytest.raises(CorruptError, match="CRC"):
        _open(bytes(image))


def test_header_sum_corruption_rejected_level1():
    image = bytearray(_build([{"name": "File.TXT", "data": DATA,
                               "level": 1}]))
    image[1] ^= 0xFF                          # the header sum byte
    with pytest.raises(CorruptError, match="sum"):
        _open(bytes(image))


def test_bad_crc_flag_rejected():
    image = _build([{"name": "File.TXT", "data": DATA, "bad_crc": True}])
    with pytest.raises(CorruptError, match="CRC"):
        _open(image)


def test_bad_csum_flag_rejected():
    for level in (0, 1):
        image = _build([{"name": "File.TXT", "data": DATA,
                         "level": level, "bad_csum": True}])
        with pytest.raises(CorruptError, match="sum"):
            _open(image)


def test_stored_member_size_mismatch_rejected():
    image = bytearray(_build([{"name": "File.TXT", "data": DATA,
                               "method": "-lh0-", "level": 2}]))
    struct.pack_into("<I", image, 11, len(DATA) + 1)  # the CRC still fits
    with pytest.raises(CorruptError, match="stored member"):
        _open(bytes(image))


def test_truncated_archive_rejected():
    image = _build([{"name": "File.TXT", "data": DATA * 4}])
    with pytest.raises(CorruptError):
        _open(image[:-5])


def test_truncated_member_rejected():
    image = _build([{"name": "File.TXT", "data": DATA, "method": "-lh5-"}])
    with pytest.raises(CorruptError):
        _open(image[:30])


def test_missing_end_marker_but_clean_boundary_is_accepted():
    image = _build([{"name": "File.TXT", "data": DATA}],
                   end_marker=False)
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_trailing_junk_after_marker_rejected():
    image = _build([{"name": "File.TXT", "data": DATA}])
    with pytest.raises(CorruptError, match="trailing junk"):
        _open(image + b"JUNK")


def test_zero_padding_after_marker_is_accepted():
    image = _build([{"name": "File.TXT", "data": DATA}])
    archive = _open(image + b"\x00\x00\x00")
    assert archive.read(archive.entries[0], "data") == DATA


def test_corrupted_end_marker_rejected():
    image = _build([{"name": "File.TXT", "data": DATA}])
    image = image[:-1] + b"\x01"
    with pytest.raises(CorruptError):
        _open(image)


def test_empty_member():
    image = _build([
        {"name": "Empty.TXT", "data": b"", "method": "-lh5-"},
        {"name": "Stored.TXT", "data": b"", "method": "-lh0-"},
        {"name": "Real.TXT", "data": b"real", "method": "-lh5-"},
    ])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == b""
    assert archive.read(archive.entries[1], "data") == b""
    assert archive.read(archive.entries[2], "data") == b"real"


def test_empty_block_in_stream_is_skipped():
    image = _build([{"name": "File.TXT", "data": DATA, "method": "-lh5-",
                     "empty_block": True}])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_level2_os9_68k_header_round_trips():
    image = _build([{"name": "File.TXT", "data": DATA, "level": 2,
                     "os9": True}])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_level2_member_without_filename_header_rejected():
    image = _build([{"name": "File.TXT", "data": DATA, "level": 2,
                     "filename_ext": None}])
    with pytest.raises(CorruptError, match="no usable name"):
        _open(image)


def test_level3_oversized_header_rejected():
    image = bytearray(_build([{"name": "File.TXT", "data": DATA,
                               "level": 3}]))
    struct.pack_into("<I", image, 24, (1 << 20) + 1)
    with pytest.raises(CorruptError, match="header size"):
        _open(bytes(image))


def test_level1_more_than_64_extended_headers_rejected():
    image = _build([{"name": "File.TXT", "data": DATA, "level": 1,
                     "exts": [(0x03, b"x")] * 65}])
    with pytest.raises(CorruptError, match="more than 64"):
        _open(image)


def test_level2_chain_without_terminator_rejected():
    comp = b"XYZ"
    chain = struct.pack("<H", 4) + b"\x01A"           # size 4, one ext
    total = 24 + len(chain)                          # no terminator
    body = struct.pack("<H", total)
    body += b"-lh0-"
    body += struct.pack("<I", len(comp))
    body += struct.pack("<I", len(comp))
    body += struct.pack("<I", 1592222400)            # Unix time
    body += b"\x20"                                  # attribute
    body += b"\x02"                                  # level
    body += struct.pack("<H", crc16_arc(comp))
    body += b"U"                                     # OS ID
    body += chain
    with pytest.raises(CorruptError, match="terminator"):
        _open(body + comp)


def test_stored_member_outruns_compressed_size_rejected():
    image = bytearray(_build([{"name": "File.TXT", "data": DATA,
                               "level": 2}]))
    struct.pack_into("<I", image, 11, 0xFFFFFFFF)    # a 4 GiB original
    with pytest.raises(CorruptError):
        _open(bytes(image))

