import io
from pathlib import Path

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives


def test_uuencode_single_file():
    image = macarchives.uuencode(name="hello.txt", data=b"hello world")
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "uuencode"
    entry = archive.entries[0]
    assert entry.name == "hello.txt"
    assert archive.read(entry, "data") == b"hello world"


def test_uuencode_binary_payload():
    data = bytes(range(256)) * 3
    image = macarchives.uuencode(name="blob.bin", data=data)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == data


def test_uuencode_mu_multi_fork_merge():
    finfo = b"TEXTTtXt\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    image = macarchives.uuencode(name="Doc", data=b"data-bytes",
                                 rsrc=b"rsrc-bytes", finfo=finfo)
    archive = macextract.open(io.BytesIO(image))
    assert len(archive.entries) == 1
    entry = archive.entries[0]
    assert archive.read(entry, "rsrc") == b"rsrc-bytes"
    assert entry.type == b"TEXT"
    assert entry.creator == b"TtXt"
    assert entry.finder_flags == 0x0400


def test_uuencode_multiple_files():
    image = macarchives.uuencode(name="one.txt", data=b"1",
                                 extra_segments=[(0o644, "two.txt", b"22")])
    archive = macextract.open(io.BytesIO(image))
    assert [entry.name for entry in archive.entries] == ["one.txt", "two.txt"]


def test_uuencode_prologue_ignored():
    image = b"This message has uuencode below.\n" + macarchives.uuencode(data=b"abc")
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == b"abc"


def test_uuencode_corrupt_line():
    image = macarchives.uuencode(data=b"abc")
    marker = image.index(b"end")
    broken = image[:marker] + b"\xff\xfe\n" + image[marker:]
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(broken))


def test_uuencode_not_recognized():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"\0" * 100))


def test_extract_uuencode(tmp_path):
    finfo = b"TEXTTtXt\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    image = macarchives.uuencode(name="Doc", data=b"data", rsrc=b"rsrc", finfo=finfo)
    archive = macextract.open(io.BytesIO(image))
    written = archive.extract(tmp_path)
    assert (tmp_path / "Doc").read_bytes() == b"data"
    assert (tmp_path / "._Doc").exists()
