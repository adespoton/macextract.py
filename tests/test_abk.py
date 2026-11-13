"""Apple Backup tests.

Fixtures are generated in memory by ``macarchives``: 0x1000-byte
disks in the format's layout (see the module docstring).  A complete
set is disks 1..N written into one directory and opened by path; a
one-disk set also opens from a file-like object.  Disk files written
under ``tmp_path`` are test scratch, never committed fixtures.
"""

import io
import struct

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract.formats import abk as abkmod

import macarchives

STAMP = 0x11223344


def _pat(n, start):
    return bytes(((start + i) * 7 + 1) & 0xFF for i in range(n))


# The three-disk set: folder "F" and files "F:a" and "F:b" on disk 1
# ("F:b"'s data fork on disk 1, its resource fork cut across 1 and
# 2), files "c" and "d" on disks 2 and 3.

def _disk1(stamp=STAMP):
    d = macarchives.abk_disk(1, 3, stamp, drive=b"HD")
    macarchives.abk_item(d, 0x600, stamp=stamp, start=1, part=1,
                         path="F", folder=True)
    macarchives.abk_item(d, 0x800, stamp=stamp, start=1, part=1,
                         path="F:a", data_len=10, rsrc_len=5,
                         data_have=_pat(10, 0), rsrc_have=_pat(5, 10))
    end = macarchives.abk_item(d, 0xA00, stamp=stamp, start=1, part=1,
                               path="F:b", data_len=300, rsrc_len=250,
                               data_have=_pat(300, 1000),
                               rsrc_have=_pat(100, 1300))
    macarchives.abk_seal(d, end)
    return bytes(d)


def _disk2(stamp=STAMP, with_b=True):
    d = macarchives.abk_disk(2, 3, stamp, drive=b"HD")
    off = 0x600
    if with_b:
        off = macarchives.abk_item(
            d, off, stamp=stamp, start=1, part=2, path="F:b",
            data_len=300, rsrc_len=250, data_have=b"",
            rsrc_have=_pat(150, 1400))
        off = macarchives.abk_align(off)
    end = macarchives.abk_item(d, off, stamp=stamp, start=2, part=1,
                               path="c", data_len=7, rsrc_len=0,
                               data_have=_pat(7, 2000))
    macarchives.abk_seal(d, end)
    return bytes(d)


def _disk3(stamp=STAMP):
    d = macarchives.abk_disk(3, 3, stamp, drive=b"HD")
    end = macarchives.abk_item(d, 0x600, stamp=stamp, start=3, part=1,
                               path="d", data_len=4, rsrc_len=0,
                               data_have=_pat(4, 3000))
    macarchives.abk_seal(d, end)
    return bytes(d)


def _write_set(tmp_path, disks):
    for number, blob in disks.items():
        (tmp_path / ("disk%d.img" % number)).write_bytes(blob)
    return tmp_path / "disk1.img"


def _full_set(tmp_path):
    return _write_set(tmp_path, {1: _disk1(), 2: _disk2(), 3: _disk3()})


def test_probe_accepts_generated_disk():
    assert abkmod.probe(_disk1()) > 0
    assert abkmod.probe(_disk2()) > 0


def test_probe_rejects_zeros():
    assert abkmod.probe(bytes(macarchives.ABK_DISK)) == 0


def test_probe_rejects_bad_magic():
    blob = bytearray(_disk1())
    blob[2:6] = b"XXXX"
    assert abkmod.probe(bytes(blob)) == 0


def test_probe_rejects_bad_disk_number():
    blob = bytearray(_disk1())
    struct.pack_into(">H", blob, 6, 4)          # past the count of 3
    assert abkmod.probe(bytes(blob)) == 0
    struct.pack_into(">H", blob, 6, 0)
    assert abkmod.probe(bytes(blob)) == 0


def test_probe_rejects_used_beyond_declared():
    blob = bytearray(_disk1())
    struct.pack_into(">I", blob, 0x36, macarchives.ABK_DISK + 1)
    assert abkmod.probe(bytes(blob)) == 0


def test_probe_rejects_missing_first_item():
    blob = bytearray(_disk1())
    blob[0x602:0x606] = b"XXXX"
    assert abkmod.probe(bytes(blob)) == 0


def test_single_disk_set_from_memory():
    d = macarchives.abk_disk(1, 1, STAMP, drive=b"Solo")
    end = macarchives.abk_item(d, 0x600, stamp=STAMP, start=1, part=1,
                               path="Solo.TXT", data_len=11, rsrc_len=6,
                               data_have=b"hello world",
                               rsrc_have=b"rsrc!!")
    macarchives.abk_seal(d, end)
    archive = macextract.open(io.BytesIO(bytes(d)))
    assert archive.format == "Apple Backup"
    assert len(archive.entries) == 1
    entry = archive.entries[0]
    assert entry.name == "Solo.TXT"
    assert entry.type == b"TEXT"
    assert entry.creator == b"ttxt"
    assert entry.locked is True
    assert entry.finder_flags == 0x0024
    assert entry.created == 0xA0000001
    assert entry.modified == 0xA0000002
    assert entry.finder_info is not None
    assert entry.finder_info[:4] == b"TEXT"
    assert entry.data_size == 11
    assert entry.resource_size == 6
    assert archive.read(entry, "data") == b"hello world"
    assert archive.read(entry, "rsrc") == b"rsrc!!"


def test_three_disk_set_from_directory(tmp_path):
    anchor = _full_set(tmp_path)
    archive = macextract.open(anchor)
    assert archive.format == "Apple Backup"
    names = [entry.name for entry in archive.entries]
    assert names == ["F/a", "F/b", "c", "d"]
    by_name = {entry.name: entry for entry in archive.entries}
    assert archive.read(by_name["F/a"], "data") == _pat(10, 0)
    assert archive.read(by_name["F/a"], "rsrc") == _pat(5, 10)
    # The resource fork cut across disks 1 and 2, in one entry.
    assert archive.read(by_name["F/b"], "data") == _pat(300, 1000)
    assert archive.read(by_name["F/b"], "rsrc") == (
        _pat(100, 1300) + _pat(150, 1400))
    assert by_name["F/b"].data_size == 300
    assert by_name["F/b"].resource_size == 250
    assert archive.read(by_name["c"], "data") == _pat(7, 2000)
    assert archive.read(by_name["d"], "data") == _pat(4, 3000)


def test_anchor_is_middle_disk(tmp_path):
    _full_set(tmp_path)
    archive = macextract.open(tmp_path / "disk2.img")
    assert [entry.name for entry in archive.entries] == ["F/a", "F/b", "c", "d"]


def test_multi_disk_set_from_memory_refused():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(_disk1()))


def test_missing_disk_refused(tmp_path):
    files = {1: _disk1(), 3: _disk3()}
    anchor = _write_set(tmp_path, files)
    with pytest.raises(CorruptError, match="missing disk"):
        macextract.open(anchor)


def test_other_backup_not_matched(tmp_path):
    files = {1: _disk1(), 2: _disk2(), 3: _disk3(stamp=0x55667788)}
    anchor = _write_set(tmp_path, files)
    with pytest.raises(CorruptError, match="missing disk"):
        macextract.open(anchor)


def test_two_files_claim_one_disk(tmp_path):
    anchor = _full_set(tmp_path)
    (tmp_path / "another.img").write_bytes(_disk2())
    with pytest.raises(CorruptError, match="two files claim disk 2"):
        macextract.open(anchor)


def test_damaged_header_offset_refused(tmp_path):
    disk1 = bytearray(_disk1())
    struct.pack_into(">I", disk1, 0x800 + 0x0C, 0x900)
    anchor = _write_set(tmp_path, {1: bytes(disk1), 2: _disk2(),
                                   3: _disk3()})
    with pytest.raises(CorruptError):
        macextract.open(anchor)


def test_rsrc_before_data_fork_whole(tmp_path):
    disk1 = bytearray(_disk1())
    # "F:b" declares 300 data bytes; give this disk 299 of them plus
    # resource bytes: the resource fork would begin early.
    struct.pack_into(">I", disk1, 0xA00 + 0x66, 299)
    anchor = _write_set(tmp_path, {1: bytes(disk1), 2: _disk2(),
                                   3: _disk3()})
    with pytest.raises(CorruptError, match="resource fork"):
        macextract.open(anchor)


def test_fork_declares_more_than_remain(tmp_path):
    disk1 = bytearray(_disk1())
    struct.pack_into(">I", disk1, 0xA00 + 0x66, 301)
    struct.pack_into(">I", disk1, 0xA00 + 0x6A, 0)
    anchor = _write_set(tmp_path, {1: bytes(disk1), 2: _disk2(),
                                   3: _disk3()})
    with pytest.raises(CorruptError, match="more fork bytes"):
        macextract.open(anchor)


def test_truncated_disk_refused(tmp_path):
    files = {1: _disk1(), 2: _disk2()[:0x700], 3: _disk3()}
    anchor = _write_set(tmp_path, files)
    with pytest.raises(CorruptError):
        macextract.open(anchor)


def test_item_spans_past_last_disk():
    # A one-disk set whose file declares more fork bytes than the
    # disk holds: the item never completes.
    d = macarchives.abk_disk(1, 1, STAMP, drive=b"HD")
    end = macarchives.abk_item(d, 0x600, stamp=STAMP, start=1, part=1,
                               path="Cut.TXT", data_len=11, rsrc_len=0,
                               data_have=b"hello")
    macarchives.abk_seal(d, end)
    with pytest.raises(CorruptError, match="spans past the last disk"):
        macextract.open(io.BytesIO(bytes(d)))


def test_item_identity_change_between_parts(tmp_path):
    bad2 = bytearray(_disk2())
    struct.pack_into(">H", bad2, 0x600 + 6, 2)      # claims start disk 2
    anchor = _write_set(tmp_path, {1: _disk1(), 2: bytes(bad2),
                                   3: _disk3()})
    with pytest.raises(CorruptError, match="identity"):
        macextract.open(anchor)


def test_empty_folder_only(tmp_path):
    d = macarchives.abk_disk(1, 1, STAMP, drive=b"HD")
    end = macarchives.abk_item(d, 0x600, stamp=STAMP, start=1, part=1,
                               path="Empty", folder=True)
    macarchives.abk_seal(d, end)
    archive = macextract.open(io.BytesIO(bytes(d)))
    assert archive.entries == []


def test_folder_with_unreadable_properties(tmp_path):
    d = macarchives.abk_disk(1, 1, STAMP, drive=b"HD")
    off = macarchives.abk_item(d, 0x600, stamp=STAMP, start=1, part=1,
                               path="Q", folder=True, valid=False)
    end = macarchives.abk_item(
        d, macarchives.abk_align(off), stamp=STAMP, start=1, part=1,
        path="Q:x", data_len=4, rsrc_len=0, data_have=b"data")
    macarchives.abk_seal(d, end)
    archive = macextract.open(io.BytesIO(bytes(d)))
    assert [entry.name for entry in archive.entries] == ["Q/x"]
    assert archive.read(archive.entries[0], "data") == b"data"


def test_folder_with_part_number_refused(tmp_path):
    d = macarchives.abk_disk(1, 1, STAMP, drive=b"HD")
    end = macarchives.abk_item(d, 0x600, stamp=STAMP, start=1, part=2,
                               path="Late", folder=True)
    macarchives.abk_seal(d, end)
    with pytest.raises(CorruptError, match="first part"):
        macextract.open(io.BytesIO(bytes(d)))


def test_first_part_seen_is_not_first(tmp_path):
    d = macarchives.abk_disk(1, 1, STAMP, drive=b"HD")
    end = macarchives.abk_item(d, 0x600, stamp=STAMP, start=1, part=2,
                               path="Orphan", data_len=1, rsrc_len=0,
                               data_have=b"x")
    macarchives.abk_seal(d, end)
    with pytest.raises(CorruptError, match="first part"):
        macextract.open(io.BytesIO(bytes(d)))


def test_item_header_bad_magic(tmp_path):
    d = bytearray(_disk1())
    d[0x802:0x806] = b"XXXX"
    anchor = _write_set(tmp_path, {1: bytes(d), 2: _disk2(), 3: _disk3()})
    with pytest.raises(CorruptError):
        macextract.open(anchor)


def test_item_date_stamp_mismatch(tmp_path):
    d = bytearray(_disk1())
    struct.pack_into(">I", d, 0x800 + 8, 0x55667788)
    anchor = _write_set(tmp_path, {1: bytes(d), 2: _disk2(), 3: _disk3()})
    with pytest.raises(CorruptError, match="start date"):
        macextract.open(anchor)


def test_extract_writes_forks_and_appledouble(tmp_path):
    out = tmp_path / "out"
    _full_set(tmp_path)
    archive = macextract.open(tmp_path / "disk1.img")
    archive.extract(str(out))
    assert (out / "F" / "a").read_bytes() == _pat(10, 0)
    assert (out / "F" / "b").read_bytes() == _pat(300, 1000)
    assert (out / "F" / "._a").exists()
    assert (out / "c").read_bytes() == _pat(7, 2000)
    assert (out / "d").read_bytes() == _pat(4, 3000)
