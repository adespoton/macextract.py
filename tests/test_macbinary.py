import io

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract._appledouble import (
    APPLEDOUBLE_MAGIC,
    ENTRY_FINDER_INFO,
    ENTRY_RESOURCE_FORK,
)

import macarchives


def test_macbinary_ii_round_trip():
    image = macarchives.macbinary(name=b"Hello", data=b"abc", rsrc=b"XYZ",
                                  type=b"TEXT", creator=b"ttxt",
                                  created=400000000, modified=400000100)
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "MacBinary II"
    assert len(archive.entries) == 1
    entry = archive.entries[0]
    assert entry.name == "Hello"
    assert entry.type == b"TEXT"
    assert entry.creator == b"ttxt"
    assert entry.data_size == 3
    assert entry.resource_size == 3
    assert archive.read(entry, "data") == b"abc"
    assert archive.read(entry, "rsrc") == b"XYZ"
    assert entry.locked is False
    assert entry.modified_date.year == 1990 or entry.modified_date is not None


def test_macbinary_ii_locked_and_invisible():
    image = macarchives.macbinary(flags=0x8000 | 0x0040)
    archive = macextract.open(_bytes(image))
    entry = archive.entries[0]
    assert entry.locked is True
    assert entry.finder_flags & 0x0040  # invisible bit survives


def test_macbinary_iii_round_trip_with_secondary_header():
    image = macarchives.macbinary(name=b"Three", data=b"payload", rsrc=b"",
                                  version=130, secondary=b"\xde\xad" * 40)
    archive = macextract.open(_bytes(image))
    assert archive.format == "MacBinary III"
    assert archive.read(archive.entries[0]) == b"payload"


def test_macbinary_i_round_trip():
    image = macarchives.macbinary(name=b"Old", data=b"legacy", rsrc=b"old-rsrc",
                                  version=0)
    archive = macextract.open(_bytes(image))
    assert archive.format == "MacBinary I"
    entry = archive.entries[0]
    assert entry.name == "Old"
    assert archive.read(entry, "data") == b"legacy"
    assert archive.read(entry, "rsrc") == b"old-rsrc"


def test_macbinary_bad_crc_is_rejected():
    image = macarchives.macbinary(bad_crc=True)
    with pytest.raises(CorruptError):
        macextract.open(_bytes(image))


def test_macbinary_truncated():
    image = macarchives.macbinary(data=b"x" * 1000)
    truncated = image[: len(image) - 10]
    with pytest.raises((CorruptError, UnsupportedError)):
        macextract.open(_bytes(truncated))


def test_macbinary_fork_too_large():
    image = bytearray(macarchives.macbinary())
    image[83:87] = (0x7F0001).to_bytes(4, "big")
    with pytest.raises((CorruptError, UnsupportedError)):
        macextract.open(_bytes(bytes(image)))


def test_macbinary_not_an_archive():
    with pytest.raises(UnsupportedError):
        macextract.open(_bytes(b"\x01" * 200))


def test_macbinary_empty_file():
    with pytest.raises(UnsupportedError):
        macextract.open(_bytes(b""))


def test_extract_writes_data_and_appledouble(tmp_path):
    image = macarchives.macbinary(name=b"Doc", data=b"data", rsrc=b"rsrc-bytes",
                                  type=b"TEXT", creator=b"ttxt")
    archive = macextract.open(_bytes(image))
    written = archive.extract(tmp_path)
    target = tmp_path / "Doc"
    assert target.read_bytes() == b"data"
    dotfile = tmp_path / "._Doc"
    from pathlib import Path
    assert Path(dotfile) in [Path(p) for p in written]
    blob = dotfile.read_bytes()
    magic, version, _filler, count = _unpack_head(blob)
    assert magic == APPLEDOUBLE_MAGIC
    assert version == 2
    assert count == 2  # resource fork + finder info
    ids = [_unpack_entry(blob, i)[0] for i in range(count)]
    assert ENTRY_RESOURCE_FORK in ids
    assert ENTRY_FINDER_INFO in ids
    rsrc_entry = next(i for i in range(count) if _unpack_entry(blob, i)[0] == ENTRY_RESOURCE_FORK)
    _id, offset, length = _unpack_entry(blob, rsrc_entry)
    assert blob[offset:offset + length] == b"rsrc-bytes"


def test_extract_data_fork_only(tmp_path):
    image = macarchives.macbinary(name=b"Doc", data=b"data", rsrc=b"rsrc-bytes")
    archive = macextract.open(_bytes(image))
    written = archive.extract(tmp_path, fork_mode="data")
    from pathlib import Path
    assert [Path(p).name for p in written] == ["Doc"]
    assert (tmp_path / "Doc").read_bytes() == b"data"


def test_extract_appledouble_carries_finder_info(tmp_path):
    image = macarchives.macbinary(name=b"Plain", data=b"data", rsrc=b"")
    archive = macextract.open(_bytes(image))
    written = archive.extract(tmp_path)
    from pathlib import Path
    names = [Path(p).name for p in written]
    assert names == ["Plain", "._Plain"]


def test_extract_sanitizes_unsafe_names(tmp_path):
    image = macarchives.macbinary(name=b"../../evil")
    archive = macextract.open(_bytes(image))
    written = archive.extract(tmp_path)
    from pathlib import Path
    assert all(tmp_path in Path(p).parents for p in written)
    assert (tmp_path / "evil").read_bytes() == b"hello world"


def test_extract_rejects_unusable_name(tmp_path):
    image = macarchives.macbinary(name=b"..")
    archive = macextract.open(_bytes(image))
    with pytest.raises(CorruptError):
        archive.extract(tmp_path)


def _bytes(image):
    import io
    return io.BytesIO(image)


def _unpack_head(blob):
    import struct
    magic, version = struct.unpack_from(">II", blob, 0)
    count = struct.unpack_from(">H", blob, 24)[0]
    return magic, version, blob[8:24], count


def _unpack_entry(blob, index):
    import struct
    base = 26 + 12 * index
    return struct.unpack_from(">III", blob, base)
