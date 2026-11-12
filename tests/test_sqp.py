import io
from pathlib import Path

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives

DATA = b"AppleLink package payload, reasonably compressible " * 12
RSRC = b"\x00\x01\x00\x00 rsrc with some structure " * 6
RANDOM = bytes(__import__("random").Random(42).randbytes(2000))


def test_sqp_v1_round_trip():
    image = macarchives.sqp([
        {"name": "Doc", "data": DATA, "rsrc": RSRC,
         "type": b"TEXT", "creator": b"TTxt"},
    ])
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "AppleLink package"
    entry = archive.entries[0]
    assert entry.name == "Doc"
    assert entry.type == b"TEXT"
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC
    assert entry.created == 400000000
    assert entry.modified == 400000100


def test_sqp_v1_stored_forks():
    image = macarchives.sqp([
        {"name": "Stored", "data": RANDOM, "rsrc": RSRC, "stored": True},
    ])
    archive = macextract.open(io.BytesIO(image))
    entry = archive.entries[0]
    assert archive.read(entry, "data") == RANDOM
    assert archive.read(entry, "rsrc") == RSRC


def test_sqp_v1_random_lzw_fork():
    image = macarchives.sqp([
        {"name": "Random", "data": RANDOM, "rsrc": RANDOM[:800]},
    ])
    archive = macextract.open(io.BytesIO(image))
    entry = archive.entries[0]
    assert archive.read(entry, "data") == RANDOM
    assert archive.read(entry, "rsrc") == RANDOM[:800]


def test_sqp_v0_flat_records():
    image = macarchives.sqp([
        {"name": "Old", "data": b"version zero payload", "rsrc": b""},
    ], version=0)
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].name == "Old"
    assert archive.read(archive.entries[0], "data") == b"version zero payload"


def test_sqp_folder_nesting():
    image = macarchives.sqp([
        {"name": "Folder", "folder": True, "level": 1},
        {"name": "Inside", "data": b"inside", "rsrc": b"", "level": 2},
        {"name": "Deep", "folder": True, "level": 2},
        {"name": "Buried", "data": b"buried", "rsrc": b"", "level": 3},
        {"name": "Top", "data": b"top", "rsrc": b"", "level": 1},
    ])
    archive = macextract.open(io.BytesIO(image))
    names = [entry.name for entry in archive.entries]
    assert names == ["Folder/Inside", "Folder/Deep/Buried", "Top"]


def test_sqp_empty_file_fork():
    image = macarchives.sqp([
        {"name": "Empty", "data": b"", "rsrc": b""},
    ])
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == b""
    assert archive.read(archive.entries[0], "rsrc") == b""


def test_sqp_finder_flags_locked():
    image = macarchives.sqp([
        {"name": "Locked", "data": b"x", "rsrc": b"", "flags16": 0x8000},
    ])
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].locked is True


def test_sqp_tiny_prefix_not_recognized():
    image = macarchives.sqp([
        {"name": "Doc", "data": DATA, "rsrc": b""},
    ])
    # The v1 directory lives deep inside the file; a 30-byte prefix is
    # not identifiable as anything.
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(image[:30]))


def test_sqp_truncated_fork():
    image = macarchives.sqp([
        {"name": "Doc", "data": DATA, "rsrc": b""},
    ])
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image[:len(image) - 10]))


def test_sqp_fork_offset_out_of_range():
    image = bytearray(macarchives.sqp([
        {"name": "Doc", "data": b"abc", "rsrc": b""},
    ]))
    # corrupt the HFS record's data-fork offset (record 0, data offset
    # field at 12 within the 86-byte record + 4 prefix)
    hfs_start = 10 + 86 + 12
    import struct
    struct.pack_into(">I", image, hfs_start + 4 + 12, 0x7FFFFFF0)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(bytes(image)))


def test_sqp_bad_version():
    image = bytearray(macarchives.sqp([
        {"name": "Doc", "data": b"abc", "rsrc": b""},
    ]))
    image[1] = 7
    with pytest.raises((CorruptError, UnsupportedError)):
        macextract.open(io.BytesIO(bytes(image)))


def test_sqp_extract_with_rsrc(tmp_path):
    image = macarchives.sqp([
        {"name": "Doc", "data": b"data-bytes", "rsrc": b"rsrc-bytes"},
    ])
    archive = macextract.open(io.BytesIO(image))
    written = archive.extract(tmp_path)
    assert (tmp_path / "Doc").read_bytes() == b"data-bytes"
    assert (tmp_path / "._Doc").exists()


def test_sqp_not_recognized():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"\x51\x50" + b"\0" * 100))
