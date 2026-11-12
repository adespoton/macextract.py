import io
import struct

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract import _sit13
from macextract._crc16 import crc16_arc
from macextract._rle90 import rle90_decode
from macextract.formats import sit as sit_format

import macarchives

DATA = (b"StuffIt test payload, compressible compressible compressible " * 8
        + b"B" * 300 + b"\x90" * 40 + b"CCCtail")
RSRC = b"\x00\x00\x01\x00 rsrc blob with some structure " * 4


def _open(image):
    return macextract.open(io.BytesIO(image))


def _set_method(image, method, fork="data"):
    """Patch a fork's method byte and repair the header CRC, so the
    walk reaches the method switch with a valid header."""
    img = bytearray(image)
    img[22 + (0 if fork == "rsrc" else 1)] = method
    struct.pack_into(">H", img, 22 + 110, crc16_arc(bytes(img[22:132])))
    return bytes(img)


def _bump_dcomp(image, extra):
    """Declare more stored data bytes than the file holds, with the
    header CRC repaired."""
    img = bytearray(image)
    dcomp = struct.unpack_from(">I", img, 22 + 96)[0]
    struct.pack_into(">I", img, 22 + 96, dcomp + extra)
    struct.pack_into(">H", img, 22 + 110, crc16_arc(bytes(img[22:132])))
    return bytes(img)


def _write_meta(ops):
    writer = macarchives.LsbBitWriter()
    for op in ops:
        if op[0] == "v":
            writer.put(_sit13.META_CODES[op[1]], _sit13.META_LENGTHS[op[1]])
        else:
            writer.put(op[1], op[2])
    return writer.flush()


def test_crc16_arc_check_value():
    assert crc16_arc(b"123456789") == 0xBB3D


def test_probe_recognises_the_magic_words():
    def head(magic):
        return magic + b"\0\0" + struct.pack(">I", 22) + b"rLau"
    assert sit_format.probe(head(b"SIT!")) == 90
    assert sit_format.probe(head(b"ST46")) > 0
    assert sit_format.probe(head(b"STin")) > 0
    assert sit_format.probe(head(b"STi5")) > 0
    assert sit_format.probe(head(b"STab")) == 0
    assert sit_format.probe(b"SIT!" + b"\0" * 20) == 0  # no rLau
    assert sit_format.probe(b"ST!") == 0                 # too short
    assert sit_format.probe(b"") == 0


def test_stored_round_trip_and_entry_fields():
    image = macarchives.stuffit([{
        "name": b"MyFile", "data": DATA, "rsrc": RSRC, "method": 0,
        "type": b"TEXT", "creator": b"TTxt", "finder_flags": 0x0100,
        "created": 400000000, "modified": 400000100,
    }])
    archive = _open(image)
    assert archive.format == "StuffIt"
    entry = archive.entries[0]
    assert entry.name == "MyFile"
    assert entry.type == b"TEXT"
    assert entry.creator == b"TTxt"
    assert entry.finder_flags == 0x0100
    assert entry.created == 400000000
    assert entry.modified == 400000100
    assert entry.locked is False
    assert entry.data_size == len(DATA)
    assert entry.resource_size == len(RSRC)
    assert entry.finder_info == b"TEXT" + b"TTxt" + b"\x01\x00" + b"\0" * 22
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


@pytest.mark.parametrize("method", [0, 1, 2, 3, 13])
def test_every_supported_method_round_trips(method):
    image = macarchives.stuffit([{
        "name": b"Doc", "data": DATA, "rsrc": RSRC,
        "method": method, "rsrc_method": method,
    }])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_mixed_methods_per_fork():
    image = macarchives.stuffit([{
        "name": b"Mixed", "data": DATA, "rsrc": RSRC,
        "method": 13, "rsrc_method": 3,
    }])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


@pytest.mark.parametrize("kwargs", [
    {"selector": None, "f_bit": False},
    {"selector": None, "f_bit": True},
    {"selector": 1},
    {"selector": 2},
    {"selector": 3},
    {"selector": 4},
    {"selector": 5},
])
def test_sit13_selectors(kwargs):
    image = macarchives.stuffit([{"name": b"D", "data": DATA,
                                  "method": 13, **kwargs}])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_folders_are_paths_not_entries():
    image = macarchives.stuffit([
        {"folder": "Dir"},
        {"folder": "Sub"},
        {"name": b"deep", "data": b"deep-data", "rsrc": b"R", "method": 1},
        {"folder_end": True},
        {"name": b"sibling", "data": b"sib"},
        {"folder_end": True},
        {"name": b"root", "data": b"root-data"},
    ])
    archive = _open(image)
    assert [entry.name for entry in archive.entries] == [
        "Dir/Sub/deep", "Dir/sibling", "root"]
    assert archive.read(archive.entries[0], "data") == b"deep-data"
    assert archive.read(archive.entries[0], "rsrc") == b"R"


def test_locked_needs_a_valid_name_crc():
    image = macarchives.stuffit(
        [{"name": b"L", "data": b"x", "locked": True}])
    assert _open(image).entries[0].locked is True

    image = macarchives.stuffit(
        [{"name": b"L", "data": b"x", "locked": True, "bad_name_crc": True}])
    assert _open(image).entries[0].locked is False


def test_empty_archive():
    archive = _open(macarchives.stuffit([]))
    assert archive.format == "StuffIt"
    assert archive.entries == []


def test_not_a_stuffit_is_unrecognised():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"this is not an archive at all"))


def test_header_crc_mismatch_is_corrupt():
    image = bytearray(macarchives.stuffit([{"name": b"A", "data": b"aaa"}]))
    image[22 + 40] ^= 0xFF          # inside the entry header, before the CRC
    struct.pack_into(">H", image, 22 + 110,
                     crc16_arc(bytes(image[22:132])) ^ 0xFFFF)
    with pytest.raises(CorruptError, match="header CRC"):
        _open(bytes(image))


def test_fork_crc_mismatch_is_corrupt():
    image = macarchives.stuffit(
        [{"name": b"A", "data": b"aaaa", "bad_data_crc": True}])
    with pytest.raises(CorruptError, match="data fork CRC"):
        _open(image)

    image = macarchives.stuffit([{"name": b"A", "data": b"aaaa",
                                  "rsrc": b"rr", "bad_rsrc_crc": True}])
    with pytest.raises(CorruptError, match="resource fork CRC"):
        _open(image)


def test_archive_size_field_is_checked():
    with pytest.raises(CorruptError, match="size field"):
        _open(macarchives.stuffit([{"name": b"A", "data": b"a"}],
                                  totalsize=10))
    with pytest.raises(CorruptError, match="claims"):
        _open(macarchives.stuffit([{"name": b"A", "data": b"a"}],
                                  totalsize=1 << 24))
    # a file shorter than the archive says
    image = macarchives.stuffit([{"name": b"A", "data": b"a" * 100}])
    with pytest.raises(CorruptError, match="claims"):
        _open(image[:-10])


def test_forks_past_the_end_are_corrupt():
    image = macarchives.stuffit([{"name": b"A", "data": b"a" * 50}])
    with pytest.raises(CorruptError, match="past the end"):
        _open(_bump_dcomp(image, 40))


def test_rle90_illegal_count_is_corrupt():
    # stored stream is the literal byte, 0x90, and the count: 50
    image = macarchives.stuffit([{"name": b"A", "data": b"B" * 50,
                                  "method": 1}])
    assert image[22 + 112:22 + 112 + 3] == b"B\x90\x32"
    img = bytearray(image)
    img[22 + 112 + 2] = 0x01       # 0x90 0x01 is not a legal count
    with pytest.raises(CorruptError, match="0x90 0x01"):
        _open(bytes(img))


def test_rle90_exhausted_stream_is_corrupt():
    image = macarchives.stuffit([{"name": b"A", "data": b"B" * 50,
                                  "method": 1}])
    img = bytearray(image)
    del img[22 + 112 + 2]          # count byte gone; stream must end
    struct.pack_into(">I", img, 22 + 96, 2)   # dcomp = 2
    struct.pack_into(">H", img, 22 + 110, crc16_arc(bytes(img[22:132])))
    struct.pack_into(">I", img, 6, len(img))
    with pytest.raises(CorruptError):
        _open(bytes(img))


def test_stored_fork_shorter_than_its_length_is_corrupt():
    image = macarchives.stuffit([{"name": b"A", "data": b"a" * 50}])
    img = bytearray(image)
    struct.pack_into(">I", img, 22 + 88, 60)  # dlen says 60
    struct.pack_into(">H", img, 22 + 110, crc16_arc(bytes(img[22:132])))
    with pytest.raises(CorruptError, match="shorter than its length"):
        _open(bytes(img))


@pytest.mark.parametrize("method", [5, 6, 7, 8, 14])
def test_unsupported_methods_name_the_method(method):
    image = macarchives.stuffit([{"name": b"A", "data": b"aaaa"}])
    with pytest.raises(UnsupportedError, match="method %d" % method):
        _open(_set_method(image, method))


def test_unsupported_method_on_the_resource_fork():
    image = macarchives.stuffit(
        [{"name": b"A", "data": b"aaaa", "rsrc": b"rr"}])
    with pytest.raises(UnsupportedError, match="method 6"):
        _open(_set_method(image, 6, fork="rsrc"))


@pytest.mark.parametrize("bit", [0x80, 0x10])
def test_encrypted_forks_are_refused(bit):
    image = macarchives.stuffit(
        [{"name": b"A", "data": b"aaaa", "encrypt_bit": bit}])
    with pytest.raises(UnsupportedError, match="encrypted"):
        _open(image)


def test_encrypted_flag_on_empty_forks_changes_nothing():
    image = macarchives.stuffit(
        [{"name": b"Empty", "data": b"", "rsrc": b"", "encrypt_bit": 0x80}])
    archive = _open(image)
    assert archive.entries[0].data_size == 0


def test_optimizer_other_than_255_is_refused():
    image = macarchives.stuffit(
        [{"name": b"A", "data": b"aaaa", "optimizer": 3}])
    with pytest.raises(UnsupportedError, match="optimizer"):
        _open(image)


def test_optimizer_255_stands_as_stored():
    image = macarchives.stuffit(
        [{"name": b"A", "data": DATA, "method": 1, "optimizer": 255}])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == DATA


def test_sit13_bad_selector_is_corrupt():
    with pytest.raises(CorruptError, match="selector"):
        _sit13.sit13_decode(b"\x60", 1)


def test_sit13_end_marker_before_the_length_is_corrupt():
    stream = macarchives.sit13_encode(b"whatever", end_marker=True)
    with pytest.raises(CorruptError, match="end marker"):
        _sit13.sit13_decode(stream, 8)


def test_sit13_truncated_stream_is_corrupt():
    stream = macarchives.sit13_encode(DATA)
    with pytest.raises(CorruptError):
        _sit13.sit13_decode(stream[:20], len(DATA))


def test_sit13_build_rejects_impossible_lengths():
    with pytest.raises(CorruptError, match="over-subscribed"):
        _sit13._build([1] * 321)
    with pytest.raises(CorruptError, match="out of range"):
        _sit13._build([32])


def test_sit13_meta_lengths_parse():
    # one explicit value writes one entry; repeats are "in addition"
    assert _sit13.read_lengths(_write_meta([("v", 8)]), 1) == [9]
    stream = _write_meta([("v", 8), ("v", 35), ("b", 1, 3)])
    assert _sit13.read_lengths(stream, 5) == [9, 9, 9, 9, 9]
    # value 34 with a zero bit writes nothing in-switch, only the final
    # entry — so three entries need three reads
    stream = _write_meta([("v", 8), ("v", 34), ("b", 0, 1), ("v", 8)])
    assert _sit13.read_lengths(stream, 3) == [9, 9, 9]
    # value 34 with a one bit writes its entry AND the final one
    stream = _write_meta([("v", 8), ("v", 34), ("b", 1, 1)])
    assert _sit13.read_lengths(stream, 3) == [9, 9, 9]


def test_sit13_meta_value_31_is_the_invalid_marker():
    # value 31 sets the length variable to -1 (the published marker),
    # which writes 0; a following 32 increments it to 0, still 0.
    stream = _write_meta([("v", 31), ("v", 32)])
    assert _sit13.read_lengths(stream, 2) == [0, 0]


def test_sit13_meta_repeats_past_the_array_are_corrupt():
    ops = [("v", 8)]
    ops += [("v", 35), ("b", 7, 3)] * 31   # 1 + 310 entries
    ops += [("v", 36), ("b", 10, 6)]       # 20 more would overrun
    with pytest.raises(CorruptError, match="past the array"):
        _sit13.read_lengths(_write_meta(ops), 321)


def test_sit13_meta_stream_that_runs_out_is_corrupt():
    # The meta code is complete (Kraft sum 1, longest code 12 bits), so
    # a meta symbol the table lacks cannot occur — bad data surfaces as
    # the stream running dry instead.
    with pytest.raises(CorruptError, match="exhausted"):
        _sit13.read_lengths(b"\xff", 5)   # two bytes of meta fill 4 entries


def test_rle90_encode_decode_round_trips():
    payload = (b"A" * 5 + b"B" * 2 + b"C" * 255 + b"D" * 300
               + b"\x90" * 70 + b"\x90" + b"tail" + b"\x90\x90" * 40
               + bytes(range(256)) + b"\x90" * 2 + b"end")
    assert rle90_decode(macarchives.rle90_encode(payload),
                        len(payload)) == payload


def test_extract_writes_the_files(tmp_path):
    image = macarchives.stuffit([
        {"folder": "Dir"},
        {"name": b"Doc", "data": DATA, "rsrc": RSRC, "method": 13},
        {"folder_end": True},
    ])
    archive = _open(image)
    archive.extract(str(tmp_path))
    assert (tmp_path / "Dir" / "Doc").read_bytes() == DATA
