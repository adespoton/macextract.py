import datetime
import io
from pathlib import Path

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives


def _as(**kwargs):
    return macarchives.applesingle(**kwargs)


def test_applesingle_round_trip():
    image = _as(name=b"Report", data=b"spreadsheet bytes", rsrc=b"rsrc-blob",
                type=b"XLS8", creator=b"XCEL", flags=0x0400)
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "AppleSingle"
    entry = archive.entries[0]
    assert entry.name == "Report"
    assert entry.type == b"XLS8"
    assert entry.finder_flags == 0x0400
    assert archive.read(entry, "data") == b"spreadsheet bytes"
    assert archive.read(entry, "rsrc") == b"rsrc-blob"
    assert entry.created_date is not None
    assert entry.modified_date is not None
    assert entry.modified_date.year == 1995


def test_appledouble_standalone_has_no_data_fork():
    image = _as(name=b"", data=None, rsrc=b"only-rsrc",
                magic=0x00051607, include_name=False)
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "AppleDouble"
    entry = archive.entries[0]
    assert entry.data_size == 0
    assert archive.read(entry, "rsrc") == b"only-rsrc"


def test_appledouble_pairs_sibling_data_fork(tmp_path):
    sibling = tmp_path / "Report"
    sibling.write_bytes(b"spreadsheet bytes")
    dotfile = tmp_path / "._Report"
    dotfile.write_bytes(_as(data=None, rsrc=b"rsrc-blob",
                            magic=0x00051607, include_name=False))
    archive = macextract.open(str(dotfile))
    entry = archive.entries[0]
    assert entry.data_size == len(b"spreadsheet bytes")
    assert archive.read(entry, "data") == b"spreadsheet bytes"
    assert entry.name == "Report"  # from the ._ filename


def test_applesingle_locked_via_macinfo_attribute():
    image = _as(macinfo=0x01)
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].locked is True


def test_applesingle_protected_via_macinfo_attribute():
    image = _as(macinfo=0x02)
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].locked is False
    assert archive.entries[0].protected is True


def test_applesingle_bad_magic_rejected():
    image = bytearray(_as())
    image[3] ^= 0xFF
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(bytes(image)))


def test_applesingle_bad_version_rejected():
    image = bytearray(_as(version=0x00030000))
    with pytest.raises((CorruptError, UnsupportedError)):
        macextract.open(io.BytesIO(bytes(image)))


def test_applesingle_entry_past_eof():
    image = bytearray(_as())
    # entry table starts at 26; first descriptor: id, offset, length
    # corrupt the resource-fork-or-first entry's offset to something huge
    import struct
    count = struct.unpack_from(">H", image, 24)[0]
    # walk descriptors and break the first one
    struct.pack_into(">I", image, 26 + 4, 0x7FFFFFF0)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(bytes(image)))


def test_applesingle_truncated_table():
    image = _as()[:20]
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image), password=None) or pytest.fail()


def test_unknown_entries_are_ignored():
    image = _as()
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].data_size > 0


def test_extract_applesingle(tmp_path):
    image = _as(name=b"Report", data=b"data-bytes", rsrc=b"rsrc-bytes")
    archive = macextract.open(io.BytesIO(image))
    written = archive.extract(tmp_path)
    assert (tmp_path / "Report").read_bytes() == b"data-bytes"
    assert (tmp_path / "._Report").exists()


def test_dates_round_trip_known_date():
    dt = datetime.datetime(1993, 6, 1, tzinfo=datetime.timezone.utc)
    secs = macarchives.applesingle_seconds(dt)
    image = _as(created=secs, modified=secs)
    archive = macextract.open(io.BytesIO(image))
    entry = archive.entries[0]
    assert entry.created_date.replace(tzinfo=None) == dt.replace(tzinfo=None)
