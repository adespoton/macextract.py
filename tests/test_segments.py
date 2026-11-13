"""StuffIt segments and DiskDoubler SPLT: joining split sets."""

import io

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives

DATA = b"StuffIt segment payload, compressible compressible " * 8
RSRC = b"\x00\x01\x02 rsrc blob with some structure " * 4
TOTAL = len(DATA) + len(RSRC)


def _write(tmp_path, parts, names):
    paths = []
    for name, blob in zip(names, parts):
        path = tmp_path / name
        path.write_bytes(blob)
        paths.append(path)
    return paths


def _sit(tmp_path, parts, names):
    return _write(tmp_path, parts, names)


def test_sitseg_roundtrip_open_part_2(tmp_path):
    parts = macarchives.sitseg_parts(name=b"SplitMe", data=DATA, rsrc=RSRC)
    first, second = _sit(tmp_path, parts, ["set.segment.1", "set.segment.2"])
    archive = macextract.open(str(second))
    assert archive.format == "StuffIt segment"
    entry = archive.entries[0]
    assert entry.name == "SplitMe"
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC
    assert entry.type == b"TEXT"
    assert entry.creator == b"ttxt"


def test_sitseg_fork_order_resource_first(tmp_path):
    # The join must place the resource fork before the data fork; if the
    # order were data-first, the forks would swap.
    parts = macarchives.sitseg_parts(data=DATA, rsrc=RSRC)
    first, _ = _sit(tmp_path, parts, ["a.1", "a.2"])
    archive = macextract.open(str(first))
    entry = archive.entries[0]
    assert entry.resource_size == len(RSRC)
    assert entry.data_size == len(DATA)
    assert archive.read(entry, "rsrc") == RSRC
    assert archive.read(entry, "data") == DATA


def test_sitseg_part_straddling_fork_boundary(tmp_path):
    # One part holds the tail of the resource fork and the head of the
    # data fork; it must still join.
    rsrc_len = 50
    data_len = 100
    parts = macarchives.sitseg_parts(
        data=b"d" * data_len, rsrc=b"r" * rsrc_len, chunks=[60, 90])
    _write(tmp_path, parts, ["s.1", "s.2"])
    archive = macextract.open(str(tmp_path / "s.1"))
    entry = archive.entries[0]
    assert archive.read(entry, "rsrc") == b"r" * rsrc_len
    assert archive.read(entry, "data") == b"d" * data_len


def test_sitseg_name_comes_from_header_not_filename(tmp_path):
    parts = macarchives.sitseg_parts(name=b"RealName", data=DATA, rsrc=RSRC)
    _write(tmp_path, parts, ["unrelated-1.bin", "unrelated-2.bin"])
    archive = macextract.open(str(tmp_path / "unrelated-2.bin"))
    assert archive.entries[0].name == "RealName"


def test_sitseg_unrelated_set_in_directory_is_ignored(tmp_path):
    mine = macarchives.sitseg_parts(name=b"Mine", data=DATA, rsrc=RSRC)
    other = macarchives.sitseg_parts(name=b"Other", data=b"other payload" * 8,
                                     rsrc=b"", set_id=b"\x93\xe1")
    _write(tmp_path, mine, ["mine.1", "mine.2"])
    _write(tmp_path, other, ["other.1", "other.2"])
    archive = macextract.open(str(tmp_path / "mine.1"))
    assert archive.read(archive.entries[0], "data") == DATA
    assert archive.entries[0].name == "Mine"


def test_sitseg_missing_part_is_corrupt(tmp_path):
    parts = macarchives.sitseg_parts(data=DATA, rsrc=RSRC)
    _write(tmp_path, parts[1:], ["only.2"])
    with pytest.raises(CorruptError) as excinfo:
        macextract.open(str(tmp_path / "only.2"))
    assert "missing part 1" in str(excinfo.value)


def test_sitseg_trailing_garbage_in_last_part_is_ignored(tmp_path):
    parts = macarchives.sitseg_parts(data=DATA, rsrc=RSRC)
    parts[-1] = parts[-1] + b"\xde\xad\xbe\xef" * 8
    _write(tmp_path, parts, ["last.1", "last.2"])
    archive = macextract.open(str(tmp_path / "last.1"))
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_sitseg_resource_fork_crc_corrupt(tmp_path):
    # Part 1 ends inside the resource fork; its stored running resource
    # CRC must catch a flipped resource byte.
    parts = macarchives.sitseg_parts(data=b"d" * 50, rsrc=b"r" * 100,
                                     chunks=[30, 70, 50])
    damaged = bytearray(parts[0])
    damaged[100 + 7] ^= 0x40
    parts[0] = bytes(damaged)
    _write(tmp_path, parts, ["c.1", "c.2", "c.3"])
    with pytest.raises(CorruptError) as excinfo:
        macextract.open(str(tmp_path / "c.2"))
    assert "part 1" in str(excinfo.value)
    assert "resource" in str(excinfo.value)


def test_sitseg_data_fork_crc_corrupt(tmp_path):
    # Part 2 ends inside the data fork; its stored running data CRC must
    # catch a flipped data byte.
    parts = macarchives.sitseg_parts(data=b"d" * 100, rsrc=b"r" * 50,
                                     chunks=[50, 50, 50])
    damaged = bytearray(parts[1])
    damaged[100 + 10] ^= 0x01
    parts[1] = bytes(damaged)
    _write(tmp_path, parts, ["e.1", "e.2", "e.3"])
    with pytest.raises(CorruptError) as excinfo:
        macextract.open(str(tmp_path / "e.1"))
    assert "part 2" in str(excinfo.value)
    assert "data" in str(excinfo.value)


def test_sitseg_duplicate_part_number_refused(tmp_path):
    parts = macarchives.sitseg_parts(data=DATA, rsrc=RSRC)
    _write(tmp_path, parts, ["dup.1", "dup.2"])
    (tmp_path / "dup-copy.2").write_bytes(parts[1])
    with pytest.raises(CorruptError) as excinfo:
        macextract.open(str(tmp_path / "dup.1"))
    assert "two files claim part 2" in str(excinfo.value)


def test_sitseg_one_part_set_from_file_object():
    payload = RSRC + DATA
    parts = macarchives.sitseg_parts(name=b"Lone", data=DATA, rsrc=RSRC,
                                     chunks=[len(payload)])
    archive = macextract.open(io.BytesIO(parts[0]))
    assert archive.format == "StuffIt segment"
    assert archive.entries[0].name == "Lone"
    assert archive.read(archive.entries[0], "data") == DATA


def test_sitseg_multi_part_from_file_object_refused():
    parts = macarchives.sitseg_parts(data=DATA, rsrc=RSRC)
    with pytest.raises(UnsupportedError) as excinfo:
        macextract.open(io.BytesIO(parts[0]))
    assert "split set" in str(excinfo.value)


def test_splt_roundtrip_open_middle_part(tmp_path):
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC, chunks=[200, 200,
                                                                 TOTAL - 400])
    _write(tmp_path, parts, ["install.1", "install.2", "install.3"])
    archive = macextract.open(str(tmp_path / "install.2"))
    assert archive.format == "DiskDoubler SPLT"
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_splt_name_comes_from_filename_minus_numeric_suffix(tmp_path):
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC)
    _write(tmp_path, parts, ["My Archive.sit.1", "My Archive.sit.2"])
    archive = macextract.open(str(tmp_path / "My Archive.sit.1"))
    assert archive.entries[0].name == "My Archive.sit"


def test_splt_name_strips_dot_digits_only(tmp_path):
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC,
                                   chunks=[TOTAL])
    _write(tmp_path, parts, ["plain.bin"])
    archive = macextract.open(str(tmp_path / "plain.bin"))
    assert archive.entries[0].name == "plain.bin"


def test_splt_one_part_file_object():
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC, chunks=[TOTAL])
    archive = macextract.open(io.BytesIO(parts[0]))
    assert archive.format == "DiskDoubler SPLT"
    entry = archive.entries[0]
    assert entry.name == "split"
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_splt_multi_part_file_object_refused():
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC)
    with pytest.raises(UnsupportedError) as excinfo:
        macextract.open(io.BytesIO(parts[0]))
    assert "split set" in str(excinfo.value)


def test_splt_missing_part_is_corrupt(tmp_path):
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC)
    _write(tmp_path, parts[1:], ["missing.2"])
    with pytest.raises(CorruptError) as excinfo:
        macextract.open(str(tmp_path / "missing.2"))
    assert "missing part(s) 1" in str(excinfo.value)


def test_splt_trailing_garbage_after_declared_payload_ignored(tmp_path):
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC)
    parts[0] = parts[0] + b"g" * 32  # declared paylen does not cover this
    _write(tmp_path, parts, ["g.1", "g.2"])
    archive = macextract.open(str(tmp_path / "g.1"))
    assert archive.read(archive.entries[0], "data") == DATA


def test_splt_payload_crc_corrupt(tmp_path):
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC)
    damaged = bytearray(parts[0])
    damaged[94 + 5] ^= 0x20
    parts[0] = bytes(damaged)
    _write(tmp_path, parts, ["x.1", "x.2"])
    with pytest.raises(CorruptError) as excinfo:
        macextract.open(str(tmp_path / "x.2"))
    assert "part 1" in str(excinfo.value)
    assert "payload CRC" in str(excinfo.value)


def test_splt_fork_order_data_first(tmp_path):
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC)
    _write(tmp_path, parts, ["f.1", "f.2"])
    archive = macextract.open(str(tmp_path / "f.1"))
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_splt_locked_flag_and_finder_info(tmp_path):
    parts = macarchives.splt_parts(data=DATA, rsrc=RSRC, flags=0x8000)
    _write(tmp_path, parts, ["k.1", "k.2"])
    archive = macextract.open(str(tmp_path / "k.1"))
    entry = archive.entries[0]
    assert entry.locked is True
    assert entry.finder_flags == 0x8000
    assert entry.finder_info == b"TEXTttxt" + b"\x80\x00" + b"\0" * 22


def test_joined_packit_image_opens_as_packit(tmp_path):
    image = macarchives.packit(files=[(b"Inside", DATA, b"",
                                       b"TEXT", b"TTxt")],
                               kind="stored")
    for scheme, writer, head in (("sit", macarchives.sitseg_parts, 100),
                                 ("dd", macarchives.splt_parts, 94)):
        parts = writer(data=image, rsrc=b"")
        _write(tmp_path, parts, ["outer.1", "outer.2"])
        archive = macextract.open(str(tmp_path / "outer.1"))
        joined = archive.read(archive.entries[0], "data")
        inner = macextract.open(io.BytesIO(joined))
        assert inner.format == "PackIt"
        assert [e.name for e in inner.entries] == ["Inside"]


def test_extract_writes_appledouble_sibling(tmp_path):
    parts = macarchives.sitseg_parts(name=b"ExtractMe", data=DATA,
                                     rsrc=RSRC)
    _write(tmp_path, parts, ["ex.1", "ex.2"])
    archive = macextract.open(str(tmp_path / "ex.1"))
    out = tmp_path / "out"
    written = archive.extract(str(out))
    assert (out / "ExtractMe").read_bytes() == DATA
    dot = out / "._ExtractMe"
    assert dot.exists()
    magic = int.from_bytes(dot.read_bytes()[:4], "big")
    assert magic == 0x00051607


def test_sitseg_resource_fork_crc_at_part_boundary(tmp_path):
    # The resource fork ends exactly at a part boundary; that part's
    # stored resource CRC is the whole fork's sum, and a damaged fork
    # byte is caught there.
    parts = macarchives.sitseg_parts(data=b"d" * 60, rsrc=b"r" * 60,
                                     chunks=[60, 60])
    damaged = bytearray(parts[0])
    damaged[100 + 12] ^= 0x10
    parts[0] = bytes(damaged)
    _write(tmp_path, parts, ["r.1", "r.2"])
    with pytest.raises(CorruptError):
        macextract.open(str(tmp_path / "r.2"))
