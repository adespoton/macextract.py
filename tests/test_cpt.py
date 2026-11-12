import io
import struct

import pytest

import macextract
from macextract import CorruptError, MacExtractError, UnsupportedError
from macextract.formats import cpt as cptmod

import macarchives

DATA = b"Compact Pro payload, compact compact compact " * 12
RSRC = b"\x00\x01\x81\x82 rsrc with escapes " * 4


def _open(image, password=None):
    return macextract.open(io.BytesIO(image), password=password)


# --- The two coders on their own ------------------------------------

@pytest.mark.parametrize("payload", [
    b"plain text",
    b"A" * 300,                          # runs: the 0x81 0x82 escapes
    b"\x00" * 600,
    b"\x81" * 5,                         # runs of the escape byte itself
    b"\x81",                             # a file ending in 0x81
    b"x" + b"\x81" + b"y",               # a lone literal 0x81
    b"\x81\x82" * 20,                    # literal escape pairs
    b"\x81\x82" + b"\x81" * 3 + b"\x82" + b"Z" * 10,
    b"\x81" * 300 + b"\x82" * 300,       # long runs both ways
    bytes(range(256)) * 3,               # every byte value, in order
    DATA,
])
def test_rle_round_trips(payload):
    stored = macarchives.rle8182_encode(payload)
    assert cptmod.rle8182_decode(stored, len(payload)) == payload


def test_rle_stops_on_the_declared_length():
    stored = macarchives.rle8182_encode(DATA)
    with pytest.raises(CorruptError, match="ends before the fork"):
        cptmod.rle8182_decode(stored, len(DATA) + 10)


@pytest.mark.parametrize("payload", [
    b"hello",
    b"The quick brown fox " * 500,       # long enough for one full block
    b"\x81" * 100 + b"tail",             # escapes through the LZH layer
    bytes(range(256)) * 40,
])
def test_lzh_round_trips(payload):
    stored = macarchives.cpt_fork(payload, lzh=True)
    assert cptmod.lzh_decode(stored, len(payload)) == payload


def test_lzh_spans_two_blocks():
    # Over 65272 symbols of cost: 70000 near-incompressible bytes make
    # the encoder cut a second block, with its flush rule between.
    payload = bytes((i * 37 + 11) % 256 for i in range(70000))
    stored = macarchives.cpt_fork(payload, lzh=True)
    assert cptmod.lzh_decode(stored, len(payload)) == payload


def test_lzh_matches_copy_out_of_the_window():
    # Hand-built: literal X, literal Y, one match of length 4 at
    # offset 2 — X Y X Y X Y out of an 8 KB window of zeros.
    out = bytearray(macarchives._CPT_LIT_LIST)
    out += macarchives._CPT_LEN_LIST + macarchives._CPT_OFF_LIST
    writer = macarchives.MsbBitWriter()
    writer.bit(1)
    writer.bits(ord("X"), 8)
    writer.bit(1)
    writer.bits(ord("Y"), 8)
    writer.bit(0)
    writer.bits(4, 6)               # length code symbol 4
    writer.bits(0, 7)               # offset code symbol 0
    writer.bits(2, 6)               # low six bits: offset 2
    assert cptmod.lzh_decode(bytes(out) + writer.to_bytes(), 6) == b"XYXYXY"


def test_lzh_truncated_stream_is_corrupt():
    stored = macarchives.cpt_fork(DATA, lzh=True)
    with pytest.raises(CorruptError):
        cptmod.lzh_decode(stored[:20], len(DATA))


# --- The container ---------------------------------------------------

def test_probe_recognises_a_real_archive():
    image = macarchives.compactpro([{"name": "A", "data": b"x"}])
    assert cptmod.probe(image) >= 80
    assert cptmod.probe(b"\x02" + image[1:]) == 0
    assert cptmod.probe(b"not an archive at all") == 0
    assert cptmod.probe(image[:6]) == 0


def test_probe_rejects_a_damaged_index_crc():
    image = bytearray(macarchives.compactpro([{"name": "A", "data": b"x"}]))
    index_off = struct.unpack_from(">I", image, 4)[0]
    image[index_off + 4] ^= 0xFF         # a count byte of the CRC'd region
    assert cptmod.probe(bytes(image)) == 0


def test_lists_and_reads_both_forks():
    image = macarchives.compactpro([
        {"name": "Doc", "data": DATA, "rsrc": RSRC,
         "type": "TEXT", "creator": "ttxt", "created": 400000000,
         "modified": 400000100, "finder_flags": 0x0100},
    ])
    archive = _open(image)
    assert archive.format == "Compact Pro"
    entry = archive.entries[0]
    assert entry.name == "Doc"
    assert entry.type == b"TEXT"
    assert entry.creator == b"ttxt"
    assert entry.created == 400000000
    assert entry.finder_flags == 0x0100
    assert entry.data_size == len(DATA)
    assert entry.resource_size == len(RSRC)
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_folders_rebuild_paths_with_duplicate_leaves():
    image = macarchives.compactpro([
        {"folder": "One"},
        {"name": "Same", "data": b"first"},
        {"folder": "Two"},
        {"name": "Same", "data": b"second"},
        {"folder_end": True},
        {"folder_end": True},
        {"name": "Same", "data": b"third"},
    ])
    archive = _open(image)
    assert [e.name for e in archive.entries] == [
        "One/Same", "One/Two/Same", "Same"]
    assert [archive.read(e, "data") for e in archive.entries] == [
        b"first", b"second", b"third"]


def test_comment_is_carried():
    image = macarchives.compactpro(
        [{"name": "A", "data": b"x"}], comment=b"hello")
    assert _open(image).comment == b"hello"


def test_lzh_fork_through_the_container():
    image = macarchives.compactpro([
        {"name": "Big", "data": DATA * 30, "rsrc": RSRC, "lzh": True},
    ])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA * 30
    assert archive.read(entry, "rsrc") == RSRC


def test_a_corrupt_fork_fails_the_crc_not_the_window():
    image = bytearray(macarchives.compactpro(
        [{"name": "A", "data": b"payload bytes here"}]))
    index_off = struct.unpack_from(">I", image, 4)[0]
    image[index_off - 4] ^= 0xFF          # inside the first fork's bytes
    with pytest.raises(CorruptError, match="CRC mismatch"):
        cptmod.open_data(bytes(image))
    # Through the sniffer the same damage falls through to "unknown".
    with pytest.raises(MacExtractError):
        _open(bytes(image))


def test_a_bad_index_crc_is_refused_by_name():
    image = bytearray(macarchives.compactpro([{"name": "A", "data": b"x"}]))
    index_off = struct.unpack_from(">I", image, 4)[0]
    image[index_off] ^= 0xFF
    with pytest.raises(CorruptError, match="index CRC mismatch"):
        cptmod.open_data(bytes(image))


def _fix_index_crc(image):
    """Re-derive the index CRC after tampering with a record."""
    index_off = struct.unpack_from(">I", image, 4)[0]
    comment, records = cptmod._walk_index(image, index_off)
    region = cptmod._index_region(image, index_off, comment, records)
    struct.pack_into(">I", image, index_off,
                     cptmod._crc32_raw(region))


def _record_at(image, comment_len=0):
    return struct.unpack_from(">I", image, 4)[0] + 7 + comment_len


def test_a_folder_count_bigger_than_its_parent_is_corrupt():
    image = bytearray(macarchives.compactpro([
        {"folder": "Dir"},
        {"name": "A", "data": b"x"},
        {"folder_end": True},
    ]))
    at = _record_at(image) + 1 + 3        # nl byte, "Dir"
    struct.pack_into(">H", image, at, 99)  # subtree count
    _fix_index_crc(image)
    with pytest.raises(CorruptError, match="subtree bigger"):
        cptmod.open_data(bytes(image))


def test_a_foreign_volume_is_refused_by_name():
    image = bytearray(macarchives.compactpro([{"name": "A", "data": b"x"}]))
    at = _record_at(image) + 1 + 1        # nl byte, "A"
    image[at] = 2                          # the entry's volume byte
    _fix_index_crc(image)
    with pytest.raises(UnsupportedError, match="segmented"):
        cptmod.open_data(bytes(image))


def test_a_truncated_file_does_not_crash():
    image = macarchives.compactpro([{"name": "A", "data": DATA}])
    with pytest.raises(MacExtractError):
        _open(image[:len(image) // 2])


def test_an_empty_archive_lists_nothing():
    archive = _open(macarchives.compactpro([]))
    assert archive.entries == []


# --- Encryption ------------------------------------------------------

def test_encrypted_entry_round_trips_with_the_password():
    image = macarchives.compactpro(
        [{"name": "Secret", "data": DATA, "rsrc": RSRC, "encrypted": True}],
        password="pw")
    archive = _open(image, password="pw")
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_encrypted_entry_with_only_a_data_fork():
    # The eight-byte preamble lands in the data fork when there is no
    # resource fork to carry it.
    image = macarchives.compactpro(
        [{"name": "Secret", "data": b"just data", "encrypted": True}],
        password="pw")
    archive = _open(image, password="pw")
    assert archive.read(archive.entries[0], "data") == b"just data"


def test_encrypted_lzh_fork():
    image = macarchives.compactpro(
        [{"name": "S", "data": DATA, "lzh": True, "encrypted": True}],
        password="hunter2")
    archive = _open(image, password="hunter2")
    assert archive.read(archive.entries[0], "data") == DATA


def test_no_password_is_asked_for_by_name():
    image = macarchives.compactpro(
        [{"name": "S", "data": b"x", "encrypted": True}], password="pw")
    with pytest.raises(macextract.PasswordRequiredError, match="password"):
        _open(image)


def test_a_wrong_password_is_refused_by_name():
    image = macarchives.compactpro(
        [{"name": "S", "data": b"x", "encrypted": True}], password="pw")
    with pytest.raises(macextract.BadPasswordError, match="incorrect password"):
        _open(image, password="nope")


def test_plain_entries_ignore_a_password():
    image = macarchives.compactpro([{"name": "A", "data": DATA}])
    archive = _open(image, password="anything")
    assert archive.read(archive.entries[0], "data") == DATA


# --- Extraction ------------------------------------------------------

def test_extract_writes_the_files(tmp_path):
    image = macarchives.compactpro([
        {"folder": "Dir"},
        {"name": "Doc", "data": DATA, "rsrc": RSRC},
        {"folder_end": True},
    ])
    archive = _open(image)
    written = archive.extract(str(tmp_path))
    assert (tmp_path / "Dir" / "Doc").read_bytes() == DATA
    assert len(written) == 2  # data fork + the ._ AppleDouble dotfile
