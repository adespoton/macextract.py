"""Now Compress tests.

Fixtures are generated in memory by ``macarchives.now_archive``:
the 24-byte ``00 02`` header, 110-byte entry records whose u32 at
+106 sums the 106 bytes before it, each member's data area holding a
block table (a u32 locating the end of the table, one 8-byte record
per block — mode, padding, end offset — and a trailing u32 folded
into the checksum) followed by the blocks themselves, resource fork
first and data fork second.  A bare compressed file ends exactly at
the last member's data area; an archive adds a 16-byte trailer.
"""

import io
import struct

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract.formats import now as nowmod

import macarchives

DATA = b"The quick brown fox jumps over the lazy dog. " * 40
RSRC = b"\x00\x01\x81\x82 rsrc with escape sequences " * 8
PAYLOAD = b"\x00\x01\x81payload with enough repeats " * 20


def _open(image):
    return macextract.open(io.BytesIO(image))


@pytest.mark.parametrize("method", [0, 1, 0x20, 0x21, 0x40])
def test_every_method_round_trips(method):
    image = macarchives.now_archive([
        {"path": "Demo.bin", "data": DATA, "rsrc": RSRC, "method": method},
    ])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


@pytest.mark.parametrize("method", [0, 1, 0x20, 0x21, 0x40])
def test_probe_accepts_generated(method):
    image = macarchives.now_archive([
        {"path": "Demo.bin", "data": b"probe", "method": method},
    ])
    assert nowmod.probe(image) > 0


def test_bare_file_shape_opens_without_trailer():
    image = macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo"},
    ], trailer=False)
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == b"solo"


def test_nested_folder_paths_and_siblings():
    image = macarchives.now_archive([
        {"path": "Folder/Hello.txt", "data": b"hello"},
        {"path": "Folder/Nested/Deep.bin", "data": PAYLOAD,
         "rsrc": RSRC},
        {"path": "Folder/Nested/Sibling.bin", "data": b"sibling"},
        {"path": "Folder/After.txt", "data": b"after"},
        {"path": "Top.txt", "data": b"top"},
    ])
    archive = _open(image)
    assert [e.name for e in archive.entries] == [
        "Folder/Hello.txt",
        "Folder/Nested/Deep.bin",
        "Folder/Nested/Sibling.bin",
        "Folder/After.txt",
        "Top.txt",
    ]
    e = archive.entries[1]
    assert archive.read(e, "data") == PAYLOAD
    assert archive.read(e, "rsrc") == RSRC


def test_folder_only_archive_opens():
    image = macarchives.now_archive([
        {"path": "Solo/Inner/Deep.txt", "data": b"deep"},
    ])
    archive = _open(image)
    names = [e.name for e in archive.entries]
    assert names == ["Solo/Inner/Deep.txt"]
    assert archive.read(archive.entries[0], "data") == b"deep"


def test_empty_member_decodes_to_empty():
    image = macarchives.now_archive([
        {"path": "Empty.bin", "data": b"", "rsrc": b""},
        {"path": "Real.bin", "data": b"real"},
    ])
    archive = _open(image)
    by_name = {e.name: e for e in archive.entries}
    assert archive.read(by_name["Empty.bin"], "data") == b""
    assert archive.read(by_name["Empty.bin"], "rsrc") == b""
    assert archive.read(by_name["Real.bin"], "data") == b"real"


def test_resource_fork_decodes_before_data_fork():
    fork_rsrc = b"rsrc bytes " * 100
    fork_data = b"data bytes " * 100
    image = macarchives.now_archive([
        {"path": "Pair.bin", "data": fork_data, "rsrc": fork_rsrc,
         "method": 0x40},
    ])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "rsrc") == fork_rsrc
    assert archive.read(entry, "data") == fork_data


def test_extract_writes_both_forks(tmp_path):
    image = macarchives.now_archive([
        {"path": "Forked.bin", "data": b"data fork", "rsrc": b"rsrc fork"},
    ])
    path = tmp_path / "Forked.bin.sea"
    path.write_bytes(image)
    out = tmp_path / "out"
    archive = macextract.open(path)
    written = archive.extract(str(out))
    assert written
    data_file = out / "Forked.bin"
    appledouble = out / "._Forked.bin"
    assert data_file.read_bytes() == b"data fork"
    assert appledouble.exists()
    assert b"rsrc fork" in appledouble.read_bytes()


def test_truncated_file_is_rejected():
    image = macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo" * 40},
    ])
    with pytest.raises(CorruptError):
        _open(image[:-5])


def test_wrong_magic_rejected():
    image = macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo"},
    ])
    image = bytearray(image)
    image[0] = 0x01
    with pytest.raises(Exception):
        _open(bytes(image))


def test_record_checksum_mismatch_rejected():
    image = macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo" * 30},
    ])
    image = bytearray(image)
    image[60] ^= 0xFF          # inside the entry record's first 106 bytes
    with pytest.raises(Exception):
        _open(bytes(image))


def test_block_table_checksum_mismatch_rejected():
    image = macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo" * 30, "method": 0},
    ])
    # The block table opens the member's data area; the file header and
    # the single 110-byte entry record occupy the first 134 bytes.
    image = bytearray(image)
    image[138] ^= 0xFF
    with pytest.raises(CorruptError):
        _open(bytes(image))


def test_archive_trailer_corruption_rejected():
    image = macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo" * 40},
    ], trailer=True)
    # The trailer is the last 16 bytes; byte 4 is its first u16.
    for offset in (0, 5, 11, 15):
        corrupted = bytearray(image)
        corrupted[-16 + offset] ^= 0xFF
        with pytest.raises(CorruptError):
            _open(bytes(corrupted))


def test_missing_archive_trailer_rejected():
    image = macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo" * 40},
    ], trailer=True)
    with pytest.raises(CorruptError):
        _open(image[:-6])


def test_data_bounds_overrun_rejected():
    image = bytearray(macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo" * 40},
    ]))
    # The entry record's dataend u32 sits at 24 + 0 + 102.
    record = 24
    end = struct.unpack_from(">I", image, record + 102)[0]
    struct.pack_into(">I", image, record + 102, end + 0x1000)
    # The record checksum no longer matches, so the probe refuses it
    # before the bounds check runs: this test covers that gate.
    with pytest.raises(Exception):
        _open(bytes(image))


def test_probe_rejects_garbage():
    assert nowmod.probe(b"") == 0
    assert nowmod.probe(b"\x01\x02" * 100) == 0


def test_zero_entry_count_rejected():
    # The probe itself refuses a count whose low word is zero, so an
    # all-zero-count file is never claimed as Now Compress.
    image = bytearray(macarchives.now_archive([
        {"path": "Solo.txt", "data": b"solo"},
    ]))
    struct.pack_into(">I", image, 8, 0)
    with pytest.raises(UnsupportedError):
        _open(bytes(image))


def test_created_modified_survive():
    created = 0xC9C00001
    modified = 0xC9C00099
    image = macarchives.now_archive(
        [{"path": "Stamped.bin", "data": b"stamp"}],
        created=created, modified=modified)
    archive = _open(image)
    entry = archive.entries[0]
    assert entry.created == created
    assert entry.modified == modified
