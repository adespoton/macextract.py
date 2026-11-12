import io

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives

PAYLOAD = b"the quick brown fox jumps over the lazy dog, again and again and again"


def test_btoa_v5_round_trip():
    image = macarchives.btoa(name="fox.txt", data=PAYLOAD, newver=True)
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "btoa v5"
    entry = archive.entries[0]
    assert entry.name == "fox.txt"
    assert archive.read(entry, "data") == PAYLOAD


def test_btoa_v4_round_trip():
    image = macarchives.btoa(data=PAYLOAD, newver=False)
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "btoa v4"
    assert archive.read(archive.entries[0], "data") == PAYLOAD


def test_btoa_empty_file():
    image = macarchives.btoa(data=b"", newver=True)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == b""


def test_btoa_all_zeros():
    image = macarchives.btoa(data=b"\0" * 64, newver=False)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == b"\0" * 64


def test_btoa_all_spaces_v5():
    image = macarchives.btoa(data=b" " * 33, newver=True)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == b" " * 33


def test_btoa_unaligned_length():
    for length in (1, 2, 3, 5, 7, 1023):
        payload = (bytes(range(256)) * (length // 256 + 1))[:length]
        image = macarchives.btoa(data=payload, newver=True)
        archive = macextract.open(io.BytesIO(image))
        assert archive.read(archive.entries[0], "data") == payload


def test_btoa_bad_stream_checksum():
    image = macarchives.btoa(data=PAYLOAD, newver=True, bad_sum=True)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image))


def test_btoa_corrupt_body_character():
    image = macarchives.btoa(data=PAYLOAD, newver=True)
    pos = image.index(b"\n", 10)  # end of the begin line
    pos = image.index(b"a", pos)  # some body position
    broken = image[:pos] + b"\x7f" + image[pos + 1:]
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(broken))


def test_btoa_missing_end_line():
    image = macarchives.btoa(data=PAYLOAD, newver=True)
    head = image[: image.rindex(b"xbtoa End")]
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(head))


def test_btoa_not_recognized():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"plain text\nwith no btoa header\n"))


def test_btoa_prologue_text_before_begin():
    image = b"Here is the file you wanted.\n" + macarchives.btoa(
        data=PAYLOAD, newver=True)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == PAYLOAD
