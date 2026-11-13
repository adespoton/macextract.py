"""MAR tests.

Fixtures are generated in memory by ``macarchives.mar``: a sequence of
128-byte records (``'file'``, ``'fold'`` and ``'----'``), each with a
CRC-32 over its first 124 bytes (MSB-first, polynomial 0x1EDC6F41,
initialised to 0, no final xor), followed by stored fork/comment
blocks — payload, a big-endian CRC-32 over the payload, then zero
padding to a 128-byte boundary.  An archive holds exactly one item: a
single file or a folder tree.
"""

import io
import struct
from datetime import datetime, timezone

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract.formats import mar as marmod

import macarchives

DATA = b"The quick brown fox jumps over the lazy dog. " * 40
RSRC = b"\x00\x01\x81rsrc-fork-bytes" * 20
COMMENT = b"A comment worth keeping. " * 8


def _open(image):
    return macextract.open(io.BytesIO(image))


def test_round_trip_single_file():
    image = macarchives.mar([
        {"name": "File.TXT", "data": DATA, "rsrc": RSRC,
         "type": b"TEXT", "creator": b"ttxt",
         "created": 400000000, "modified": 400000100},
    ])
    archive = _open(image)
    assert archive.format == "MAR"
    assert len(archive.entries) == 1
    entry = archive.entries[0]
    assert entry.name == "File.TXT"
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC
    assert entry.data_size == len(DATA)
    assert entry.resource_size == len(RSRC)
    assert entry.type == b"TEXT"
    assert entry.creator == b"ttxt"
    assert entry.created == 400000000
    assert entry.modified == 400000100
    assert entry.created_date == datetime.fromtimestamp(
        400000000 - 2082844800, tz=timezone.utc)


def test_probe_accepts_generated():
    image = macarchives.mar([{"name": "File.TXT", "data": DATA}])
    assert marmod.probe(image) > 0


def test_comment_round_trip_and_cut_at_255():
    long_comment = COMMENT * 20              # 480 bytes
    assert len(long_comment) > 255
    image = macarchives.mar([
        {"name": "File.TXT", "data": DATA, "comment": long_comment},
    ])
    archive = _open(image)
    assert archive.entries[0].comment == long_comment[:255]


def test_comment_block_crc_is_over_the_whole_payload():
    # A 300-byte comment: the fixture writer CRCs all of it, so opening
    # succeeds — and what is carried is cut to 255.
    image = macarchives.mar([
        {"name": "File.TXT", "data": DATA, "comment": b"x" * 300},
    ])
    assert _open(image).entries[0].comment == b"x" * 255


def test_folder_tree_round_trip():
    image = macarchives.mar([
        {"name": "Root/Dir/Sub/Deep.TXT", "data": DATA},
        {"name": "Root/Dir/Other.TXT", "data": b"other"},
        {"name": "Root/EmptyFolder", "folder": True},
        {"name": "Root/Top.TXT", "data": b"top", "rsrc": RSRC},
    ])
    archive = _open(image)
    names = sorted(entry.name for entry in archive.entries)
    assert names == ["Root/Dir/Other.TXT", "Root/Dir/Sub/Deep.TXT",
                     "Root/Top.TXT"]
    by_name = {entry.name: entry for entry in archive.entries}
    assert archive.read(by_name["Root/Dir/Sub/Deep.TXT"], "data") == DATA
    assert archive.read(by_name["Root/Dir/Other.TXT"], "data") == b"other"
    assert archive.read(by_name["Root/Top.TXT"], "data") == b"top"
    assert archive.read(by_name["Root/Top.TXT"], "rsrc") == RSRC


def test_folder_comment_block_is_verified_and_dropped():
    image = macarchives.mar([
        {"name": "Dir", "folder": True, "comment": b"folder comment"},
        {"name": "Dir/File.TXT", "data": b"payload"},
    ])
    archive = _open(image)
    assert [e.name for e in archive.entries] == ["Dir/File.TXT"]


def test_folder_with_stray_data_block_is_tolerated():
    image = macarchives.mar([
        {"name": "Dir", "folder": True, "data": b"junk", "rsrc": b"more"},
        {"name": "Dir/File.TXT", "data": b"payload"},
    ])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == b"payload"


def test_locked_and_protected():
    image = macarchives.mar([
        {"name": "Dir/Locked.TXT", "data": DATA, "file_flags": 0x00000001},
        {"name": "Dir/Protected.TXT", "data": DATA, "file_flags": 0x00000002},
    ])
    archive = _open(image)
    by_name = {e.name: e for e in archive.entries}
    assert by_name["Dir/Locked.TXT"].locked
    assert not by_name["Dir/Locked.TXT"].protected
    assert by_name["Dir/Protected.TXT"].protected
    assert not by_name["Dir/Protected.TXT"].locked


def test_finder_info_layout():
    image = macarchives.mar([
        {"name": "Doc", "data": DATA, "type": b"TEXT", "creator": b"ttxt",
         "flags": 0x0C00},
    ])
    entry = _open(image).entries[0]
    assert len(entry.finder_info) == 32
    assert entry.finder_info[:16] == struct.pack(
        ">4s4sH", b"TEXT", b"ttxt", 0x0C00) + b"\0" * 4 + b"\0\0"
    assert entry.finder_info[16:] == b"\0" * 16
    assert entry.finder_flags == 0x0C00


def test_name_with_literal_slash_is_one_leaf():
    image = macarchives.mar([
        {"name": "ignored", "raw_name": b"a/b", "data": b"slash-leaf"},
    ])
    entry = _open(image).entries[0]
    assert entry.name == "a/b"
    assert _open(image).read(entry, "data") == b"slash-leaf"


def test_extract_writes_files_and_appledouble(tmp_path):
    image = macarchives.mar([
        {"name": "Dir/Doc", "data": DATA, "rsrc": RSRC},
    ])
    archive = _open(image)
    written = archive.extract(str(tmp_path))
    assert (tmp_path / "Dir" / "Doc").read_bytes() == DATA
    dotfile = tmp_path / "Dir" / "._Doc"
    assert dotfile.read_bytes()
    assert len(written) == 2


def test_extract_skip_rsrc_drops_the_sidecar(tmp_path):
    image = macarchives.mar([
        {"name": "Doc", "data": DATA, "rsrc": RSRC},
    ])
    archive = _open(image)
    archive.extract(str(tmp_path), fork_mode="skip-rsrc")
    assert (tmp_path / "Doc").read_bytes() == DATA
    assert not (tmp_path / "._Doc").exists()


def test_bad_header_crc_raises_corrupt():
    image = macarchives.mar([{"name": "File.TXT", "data": DATA}],
                            bad_header_crc=True)
    assert marmod.probe(image) > 0          # still recognised as MAR
    with pytest.raises(CorruptError):
        _open(image)


@pytest.mark.parametrize("which", ["data", "rsrc", "comment"])
def test_bad_block_crc_raises_corrupt(which):
    spec = {"name": "File.TXT", "data": DATA, "rsrc": RSRC,
            "comment": COMMENT}
    if which == "data":
        image = _mar_with_one_bad_block(spec, 0)
    elif which == "rsrc":
        image = _mar_with_one_bad_block(spec, 1)
    else:
        image = _mar_with_one_bad_block(spec, 2)
    with pytest.raises(CorruptError):
        _open(image)


def _mar_with_one_bad_block(spec, block_index):
    """Rebuild the image with exactly one block's CRC corrupted."""
    good = macarchives.mar([spec])
    # The blocks follow the record, in data, rsrc, comment order.
    # Locate each block by walking the record: the sizes are in it.
    data_size, rsrc_size, comment_size = struct.unpack_from(">III", good, 72)
    sizes = [data_size, rsrc_size, comment_size]
    pos = 128
    spans = []
    for size in sizes:
        if size == 0:
            spans.append(None)
            continue
        pad = (128 - ((size + 4) & 127)) & 127
        spans.append((pos, pos + size, pad))
        pos += size + 4 + pad
    start, crc_at, pad = spans[block_index]
    bad = bytearray(good)
    bad[crc_at] ^= 0xFF                 # flip one stored CRC byte
    return bytes(bad)


def test_truncated_in_header_direct():
    image = macarchives.mar([{"name": "File.TXT", "data": DATA}])
    with pytest.raises(CorruptError):
        marmod.open_data(image[:100])


def test_tiny_file_is_unrecognised_through_open():
    image = macarchives.mar([{"name": "File.TXT", "data": DATA}])
    with pytest.raises(UnsupportedError):
        _open(image[:100])


def test_truncated_mid_block():
    image = macarchives.mar([{"name": "File.TXT", "data": DATA}])
    with pytest.raises(CorruptError):
        _open(image[:128 + len(DATA) // 2])


def test_truncated_in_padding():
    image = macarchives.mar([{"name": "File.TXT", "data": b"odd-size!"}])
    with pytest.raises(CorruptError):
        _open(image[:-1])               # cut inside the zero padding


def test_unterminated_folder():
    image = macarchives.mar([{"name": "Dir/File.TXT", "data": b"x"}])
    # Drop the closing '----' record of the outermost folder.
    with pytest.raises(CorruptError):
        _open(image[:-128])


def test_unexpected_end_record():
    image = macarchives._mar_record(macarchives.MAR_END, b"", 0, 0, 0, 0,
                                    0, 0, b"\0" * 16, b"\0" * 4, False)
    with pytest.raises(CorruptError):
        _open(image)


def test_unknown_record_id():
    image = macarchives._mar_record(0xDEADBEEF, b"", 0, 0, 0, 0,
                                    0, 0, b"\0" * 16, b"\0" * 4, False)
    with pytest.raises(CorruptError):
        _open(image)


def test_trailing_garbage_after_root_item():
    image = macarchives.mar([{"name": "File.TXT", "data": b"x"}])
    with pytest.raises(CorruptError):
        _open(image + b"\0" * 128)


def test_two_root_items_refused():
    one = macarchives.mar([{"name": "One.TXT", "data": b"one"}])
    two = macarchives.mar([{"name": "Two.TXT", "data": b"two"}])
    with pytest.raises(CorruptError):
        _open(one + two)


def test_nesting_too_deep():
    deep = "/".join("d%02d" % i for i in range(32)) + "/File.TXT"
    image = macarchives.mar([{"name": deep, "data": b"x"}])
    with pytest.raises(CorruptError):
        _open(image)


def test_expected_crc_is_stable():
    # The two implementations in the tree (the reader's table-driven
    # one and the fixture's bitwise one) agree on these buffers, and
    # the empty buffer is zero.
    for blob in (b"", b"\x00", b"123456789", DATA, bytes(range(256))):
        assert marmod.mar_crc32(blob) == macarchives._mar_crc32(blob)
    assert marmod.mar_crc32(b"") == 0


def test_lz4_wrapped_refused_by_name():
    framed = b"\x04\x22\x4D\x18" + b"\x00" * 64
    with pytest.raises(UnsupportedError):
        marmod.open_data(framed)


def test_lzw_wrapped_refused_by_name():
    wrapped = macarchives.compress_encode(
        macarchives.mar([{"name": "File.TXT", "data": DATA}]))
    with pytest.raises(UnsupportedError):
        marmod.open_data(wrapped)


def test_lzw_wrapped_opens_as_unix_compress_for_now():
    # No envelope chaining exists in this library yet, so a
    # compress(1)-wrapped MAR surfaces through the Unix compress
    # reader as one blob named from the file — the whole-file wrap
    # is the failure mode to know about, not a silent mis-read.
    payload = macarchives.mar([{"name": "File.TXT", "data": DATA}])
    wrapped = macarchives.compress_encode(payload)
    archive = _open(wrapped)
    assert archive.format == "Unix compress"
    assert archive.entries[0]._data == payload


def test_empty_file_is_unsupported_not_corrupt():
    with pytest.raises(UnsupportedError):
        _open(b"")
