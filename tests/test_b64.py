import io

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives

PAYLOAD = b"the quick brown fox jumps over the lazy dog" * 20


def test_base64_begin_round_trip():
    image = macarchives.base64_begin(name="fox.txt", data=PAYLOAD)
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "base64"
    entry = archive.entries[0]
    assert entry.name == "fox.txt"
    assert archive.read(entry, "data") == PAYLOAD


def test_base64_multiple_sections():
    first = macarchives.base64_begin(name="one.bin", data=b"1" * 600)
    second = macarchives.base64_begin(name="two.bin", data=b"2" * 300)
    archive = macextract.open(io.BytesIO(first + second))
    assert [entry.name for entry in archive.entries] == ["one.bin", "two.bin"]
    assert archive.read(archive.entries[0], "data") == b"1" * 600
    assert archive.read(archive.entries[1], "data") == b"2" * 300


def test_base64_bare_round_trip_with_hint():
    image = macarchives.base64_bare(PAYLOAD)
    archive = macextract.open(io.BytesIO(image), )
    assert archive.format == "base64"
    assert archive.read(archive.entries[0], "data") == PAYLOAD


def test_base64_bare_with_filename_hint(tmp_path):
    target = tmp_path / "download.b64"
    target.write_bytes(macarchives.base64_bare(PAYLOAD))
    archive = macextract.open(str(target))
    assert archive.entries[0].name == "download"


def test_base64_garbage_rejected():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"this is not base64 at all!!!\n"))


def test_base64_bare_with_garbage_line_not_detected():
    # A file with non-alphabet lines is not claimed as bare base64.
    image = b"> comment line\n" + macarchives.base64_bare(PAYLOAD) + b"\n"
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(image))


def test_base64_begin_skips_garbage_lines():
    encoded = macarchives.base64_begin(name="fox.txt", data=PAYLOAD)
    body = encoded.replace(b"begin-base64", b"begin-base64", 1)
    with_garbage = body.replace(b"====", b"> stray comment\n====", 1)
    archive = macextract.open(io.BytesIO(with_garbage))
    assert archive.read(archive.entries[0], "data") == PAYLOAD
