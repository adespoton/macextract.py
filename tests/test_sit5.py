import io
import struct

import pytest

import macextract
from macextract import (
    BadPasswordError,
    CorruptError,
    PasswordRequiredError,
    UnsupportedError,
)
from macextract import _rc4
from macextract.formats import sit5 as sit5_format

import macarchives

DATA = (b"StuffIt 5 test payload, compressible compressible compressible " * 8
        + b"B" * 300 + b"CCCtail")
RSRC = b"\x00\x00\x01\x00 rsrc blob with some structure " * 4


def _open(image, password=None):
    return macextract.open(io.BytesIO(image), password=password)


def test_rc4_known_answer():
    # The published vector: RC4 is its own inverse.
    assert _rc4.rc4(b"Plaintext", b"Key").hex() == "bbf316e8d940af0ad3"
    assert _rc4.rc4(_rc4.rc4(b"payload", b"key10"), b"key10") == b"payload"
    with pytest.raises(ValueError, match="empty key"):
        _rc4.rc4(b"x", b"")


def test_probe_recognises_the_banner():
    head = macarchives.SIT5_BANNER + b"\0" * 20
    assert sit5_format.probe(head) == 90
    other_year = head.replace(b"2024", b"1999")
    assert sit5_format.probe(other_year) == 90
    assert sit5_format.probe(macarchives.SIT5_BANNER[:99]) == 0  # too short
    assert sit5_format.probe(b"Not a StuffIt banner at all!!" + b"\0" * 80) == 0
    assert sit5_format.probe(b"") == 0


def test_another_archive_version_is_unsupported():
    image = bytearray(macarchives.stuffit5([("A", b"aaa")]))
    image[82] = 6
    with pytest.raises(UnsupportedError, match="version 6"):
        _open(bytes(image))


def test_stored_round_trip_and_entry_fields():
    image = macarchives.stuffit5([{
        "name": b"MyFile", "data": DATA, "rsrc": RSRC, "method": 0,
        "type": b"TEXT", "creator": b"TTxt", "finder_flags": 0x0100,
        "comment": b"a comment",
    }])
    archive = _open(image)
    assert archive.format == "StuffIt 5"
    entry = archive.entries[0]
    assert entry.name == "MyFile"
    assert entry.type == b"TEXT"
    assert entry.creator == b"TTxt"
    assert entry.finder_flags == 0x0100
    assert entry.created == 400000000
    assert entry.modified == 400000100
    assert entry.locked is False
    assert entry.data_size == len(DATA)
    assert entry.resource_size == len(RSRC)
    assert entry.finder_info == (b"TEXT" + b"TTxt" + b"\x01\x00" + b"\0" * 22)
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


@pytest.mark.parametrize("method", [0, 1, 2, 3, 13])
def test_every_supported_method_round_trips(method):
    image = macarchives.stuffit5([{
        "name": b"Doc", "data": DATA, "rsrc": RSRC,
        "method": method, "rsrc_method": method,
    }])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_mixed_methods_per_fork():
    image = macarchives.stuffit5([{
        "name": b"Mixed", "data": DATA, "rsrc": RSRC,
        "method": 13, "rsrc_method": 3,
    }])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_sit13_with_the_shared_second_code():
    image = macarchives.stuffit5([{
        "name": b"D", "data": DATA, "method": 13, "f_bit": True,
    }])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_folders_are_paths_not_entries():
    image = macarchives.stuffit5([
        {"folder": "Dir"},
        {"folder": "Sub"},
        {"name": b"deep", "data": b"deep-data", "rsrc": b"R"},
        {"folder_end": True},
        {"name": "sibling \u2605", "data": b"sib", "method": 13},
        {"folder_end": True},
        {"name": b"root", "data": b"root-data"},
    ])
    archive = _open(image)
    # Folder entries and the marker after each one are not files.
    assert [entry.name for entry in archive.entries] == [
        "Dir/Sub/deep", "Dir/sibling \u2605", "root"]
    assert archive.read(archive.entries[0], "data") == b"deep-data"
    assert archive.read(archive.entries[0], "rsrc") == b"R"


def test_empty_archive():
    archive = _open(macarchives.stuffit5([]))
    assert archive.format == "StuffIt 5"
    assert archive.entries == []


def test_resource_fork_present_but_empty():
    image = macarchives.stuffit5(
        [{"name": b"OnlyData", "data": b"hello", "rsrc": b""}])
    entry = _open(image).entries[0]
    assert entry.resource_size == 0
    assert _open(image).read(entry, "rsrc") == b""


def test_a_comment_inside_the_header_is_walked_past():
    image = macarchives.stuffit5([{
        "name": b"Doc", "data": DATA, "rsrc": RSRC, "comment": b"some words",
    }])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA
    assert archive.read(archive.entries[0], "rsrc") == RSRC


def test_no_comment_space_in_the_header():
    image = macarchives.stuffit5(
        [{"name": b"Doc", "data": DATA, "rsrc": RSRC, "comment": b"ignored"}],
        comment_space=False)
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA
    assert archive.read(archive.entries[0], "rsrc") == RSRC


def test_bad_second_block_crc_drops_only_the_finder_info():
    image = macarchives.stuffit5(
        [{"name": b"Doc", "data": DATA, "bad_block_crc": True}])
    entry = _open(image).entries[0]
    assert entry.finder_info is None
    # Type, creator and Finder flags stand either way.
    assert entry.type == b"TEXT"
    assert entry.creator == b"TTxt"
    assert entry.finder_flags == 0x0100
    assert _open(image).read(entry, "data") == DATA


def test_entry_version_3_has_a_shorter_second_block():
    image = macarchives.stuffit5([{
        "name": b"V3", "data": DATA, "rsrc": RSRC, "entry_version": 3,
    }])
    archive = _open(image)
    entry = archive.entries[0]
    # The version-3 block is not measured upstream: no Finder info.
    assert entry.finder_info is None
    assert entry.type == b"TEXT"
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_encryption_needs_a_password():
    image = macarchives.stuffit5(
        [{"name": b"Secret", "data": DATA, "rsrc": RSRC, "encrypted": True}],
        password="hunter2")
    with pytest.raises(PasswordRequiredError, match="encrypted"):
        _open(image)
    with pytest.raises(BadPasswordError, match="wrong password"):
        _open(image, password="wrong")
    archive = _open(image, password="hunter2")
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_encryption_with_only_a_resource_fork():
    image = macarchives.stuffit5(
        [{"name": b"S", "data": b"", "rsrc": RSRC, "encrypted": True}],
        password="pw")
    archive = _open(image, password="pw")
    entry = archive.entries[0]
    assert entry.data_size == 0
    assert archive.read(entry, "rsrc") == RSRC


def test_two_encrypted_entries_share_one_password_check():
    image = macarchives.stuffit5([
        {"name": b"A", "data": DATA, "encrypted": True},
        {"name": b"B", "data": DATA[::-1], "rsrc": RSRC, "encrypted": True},
    ], password="pw")
    archive = _open(image, password="pw")
    assert archive.read(archive.entries[0], "data") == DATA
    assert archive.read(archive.entries[1], "data") == DATA[::-1]
    assert archive.read(archive.entries[1], "rsrc") == RSRC


def test_password_on_a_clear_archive_is_unused():
    image = macarchives.stuffit5([("A", b"plain")])
    assert _open(image, password="whatever").entries[0].name == "A"


@pytest.mark.parametrize("kwargs", [
    {"blocks14": True},
    {"comment_block": True},
    {"blocks14": True, "comment_block": True},
    {"blocks14": True, "comment_block": True, "archive_comment": b"hi",
     "style": b"\x00\x01"},
])
def test_the_password_hash_sits_behind_its_blocks(kwargs):
    image = macarchives.stuffit5(
        [{"name": b"S", "data": DATA, "encrypted": True}],
        password="pw", **kwargs)
    archive = _open(image, password="pw")
    assert archive.read(archive.entries[0], "data") == DATA
    with pytest.raises(BadPasswordError):
        _open(image, password="nope")


def test_an_encrypted_entry_without_an_archive_hash_is_unsupported():
    image = macarchives.stuffit5(
        [{"name": b"S", "data": DATA, "encrypted": True}])
    with pytest.raises(UnsupportedError, match="no password hash"):
        _open(image)


def test_a_password_hash_that_is_not_five_bytes_is_unsupported():
    image = macarchives.stuffit5(
        [("A", b"aaa")], password="pw", hash_len=3)
    with pytest.raises(UnsupportedError, match="hash length 3"):
        _open(image)


def test_password_key_data_on_a_clear_entry_is_corrupt():
    image = macarchives.stuffit5(
        [{"name": b"A", "data": b"aaa", "data_passlen": 5}])
    with pytest.raises(CorruptError, match="password key data"):
        _open(image)


def test_a_key_that_is_not_five_bytes_is_corrupt():
    image = macarchives.stuffit5(
        [{"name": b"A", "data": b"aaa", "encrypted": True,
          "data_passlen": 3}], password="pw")
    with pytest.raises(CorruptError, match="password key data"):
        _open(image, password="pw")


@pytest.mark.parametrize("method", [14, 15])
def test_unsupported_methods_name_the_method(method):
    # No encoder for these: the payload stands as stored and the method
    # byte says what it is.
    image = macarchives.stuffit5(
        [{"name": b"A", "data": b"payload bytes", "method": method}])
    with pytest.raises(UnsupportedError, match="method %d" % method):
        _open(image)


def test_unsupported_method_on_the_resource_fork():
    image = macarchives.stuffit5(
        [{"name": b"A", "data": b"aaa", "rsrc": b"rr",
          "rsrc_method": 15}])
    with pytest.raises(UnsupportedError, match="method 15"):
        _open(image)


def test_no_entry_identifier_is_corrupt():
    image = macarchives.stuffit5([("A", b"aaa")], bad_id=True)
    with pytest.raises(CorruptError, match="identifier"):
        _open(image)


def test_a_first_entry_offset_past_the_data_is_corrupt():
    image = macarchives.stuffit5([("A", b"aaa")], firstoffs=1 << 20)
    with pytest.raises(CorruptError, match="entry at offset"):
        _open(image)


def test_forks_past_the_end_are_corrupt():
    image = macarchives.stuffit5(
        [{"name": b"A", "data": b"a" * 50, "datacomp_extra": 4}])
    with pytest.raises(CorruptError, match="run past the end of the data"):
        _open(image)


def test_fork_crc_mismatch_is_corrupt():
    image = macarchives.stuffit5(
        [{"name": b"A", "data": b"aaaa", "bad_data_crc": True}])
    with pytest.raises(CorruptError, match="data fork CRC"):
        _open(image)

    image = macarchives.stuffit5([{"name": b"A", "data": b"aaaa",
                                   "rsrc": b"rr", "bad_rsrc_crc": True}])
    with pytest.raises(CorruptError, match="resource fork CRC"):
        _open(image)


def test_a_folder_marker_that_does_not_advance_is_corrupt():
    image = macarchives.stuffit5(
        [{"folder": "Dir"}, {"name": b"A", "data": b"aaa"},
         {"folder_end": True}], marker_headersize=0)
    with pytest.raises(CorruptError, match="does not advance"):
        _open(image)


def test_a_count_shorter_than_the_archive_lists_what_it_says():
    image = macarchives.stuffit5([("A", b"a"), ("B", b"b"), ("C", b"c")],
                                 count=2)
    assert [e.name for e in _open(image).entries] == ["A", "B"]


def test_a_count_longer_than_the_archive_is_corrupt():
    image = macarchives.stuffit5([("A", b"a")], count=5)
    with pytest.raises(CorruptError, match="entry at offset"):
        _open(image)


def test_the_entry_header_crc_is_carried_but_not_checked():
    image = bytearray(macarchives.stuffit5([("A", b"aaa")]))
    first = struct.unpack_from(">I", image, 94)[0]
    image[first + 32] ^= 0xFF
    archive = _open(bytes(image))
    assert archive.entries[0].name == "A"


def test_unrecognised_data_is_unsupported():
    with pytest.raises(UnsupportedError, match="unrecognised|not a StuffIt"):
        macextract.open(io.BytesIO(b"this is not an archive at all"))


def test_extract_writes_the_files(tmp_path):
    image = macarchives.stuffit5([
        {"folder": "Dir"},
        {"name": b"Doc", "data": DATA, "rsrc": RSRC, "method": 13},
        {"folder_end": True},
    ])
    archive = _open(image)
    archive.extract(str(tmp_path))
    assert (tmp_path / "Dir" / "Doc").read_bytes() == DATA
