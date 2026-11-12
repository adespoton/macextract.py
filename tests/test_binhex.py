import io
from pathlib import Path

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives


def test_binhex_round_trip():
    image = macarchives.binhex(name="My File", data=b"some data bytes",
                               rsrc=b"resource payload", type=b"ttxt",
                               creator=b"MACS", flags=0x0400)
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "BinHex 4.0"
    entry = archive.entries[0]
    assert entry.name == "My File"
    assert entry.type == b"ttxt"
    assert entry.creator == b"MACS"
    assert entry.finder_flags == 0x0400
    assert archive.read(entry, "data") == b"some data bytes"
    assert archive.read(entry, "rsrc") == b"resource payload"


def test_binhex_empty_forks():
    image = macarchives.binhex(data=b"", rsrc=b"")
    archive = macextract.open(io.BytesIO(image))
    entry = archive.entries[0]
    assert entry.data_size == 0
    assert entry.resource_size == 0
    assert archive.read(entry, "data") == b""


def test_binhex_rle_runs_round_trip():
    data = b"aaaaaaaa" + b"\x90" * 4 + b"bbbbbbbbbbbbbbbbbbbbbb" + bytes(range(10))
    image = macarchives.binhex(data=data)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == data


def test_binhex_bad_header_crc():
    image = macarchives.binhex(bad_header_crc=True)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image))


def test_binhex_bad_data_crc():
    image = macarchives.binhex(bad_data_crc=True)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image))


def test_binhex_truncated_payload():
    image = macarchives.binhex(data=b"x" * 500)
    head, sep, tail = image.partition(b":")
    cut = head + sep + tail[:len(tail) // 2]
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(cut))


def test_binhex_invalid_character():
    image = bytearray(macarchives.binhex(data=b"abc"))
    colon = image.index(b":", 10)
    pos = image.index(b"a", colon)
    image[pos] = ord("~")  # '~' is not in the 64-character alphabet
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(bytes(image)))


def test_binhex_marker_not_required_when_colon_present():
    image = macarchives.binhex(data=b"abc")
    start = image.index(b":")
    bare = image[start:]
    archive = macextract.open(io.BytesIO(bare))
    assert archive.entries[0].data_size == 3


def test_binhex_trailing_garbage_allowed():
    image = macarchives.binhex(data=b"abc") + b"\nmail footer\n"
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == b"abc"


def test_binhex_not_an_archive():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"\x00" * 200))


def test_binhex_finds_document_after_prologue():
    image = b"Some preamble text the decoder can ignore.\n" + macarchives.binhex(data=b"abc")
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == b"abc"


def test_extract_round_trip_with_resource_fork(tmp_path):
    image = macarchives.binhex(name="Doc", data=b"the data", rsrc=b"the rsrc",
                               type=b"TEXT", creator=b"ttxt")
    archive = macextract.open(io.BytesIO(image))
    written = archive.extract(tmp_path)
    assert Path(tmp_path / "Doc").read_bytes() == b"the data"
    assert (tmp_path / "._Doc").exists()
