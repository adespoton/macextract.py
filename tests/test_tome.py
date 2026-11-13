"""Apple Installer Tome tests.

Fixtures are generated in memory by ``macarchives.tome``: a 0x24-byte
header (magic ``6b 63 00 01``, the long at 0x16 holding 0x24, a u16
record count at 0x1a), one 0x80-byte record per file, then each fork's
block stream.  A block is one per absolute 64 KiB of output; a stored
block opens with ``01 00 00 00``; a compressed block opens with
``00`` and a codec byte (1 = InstaCompOne, 0 = the text codec).  Both
codecs are MSB-first token streams; decode-ends at the fork's stated
compressed length, and a decoded stream must end exactly there.
"""

import io
import struct

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract.formats import tome as tomemod

import macarchives

LINE = (b"LaserWriter 8500 v1.0 PPD text with repeated line content "
        b"for compression testing\n")
TEXT = LINE * 40
BINARY = bytes(range(256)) * 300          # 76 800 bytes, mixed blocks
STORED_DATA = b"plain stored fork bytes, no compression at all\n" * 9
RSRC = b"\x00\x01\x00\x00rsrc-fork-payload\x80\x81" * 40


def _open(image):
    return macextract.open(io.BytesIO(image))


def _round_trip(payload, codec=None, stated=None, label=""):
    image = macarchives.tome([
        {"name": "Member", "data": payload, "data_codec": codec,
         "data_stated": stated, "type": b"TEXT", "creator": b"ttxt"},
    ])
    archive = _open(image)
    assert archive.format == "Apple Installer Tome"
    entry = archive.entries[0]
    if stated is not None:
        expected = payload.ljust(stated, b"\0")
    else:
        expected = payload
    assert archive.read(entry, "data") == expected
    assert entry.data_size == len(expected)


def test_round_trip_stored():
    _round_trip(STORED_DATA, label="stored")


def test_round_trip_instacompone():
    _round_trip(TEXT, codec="ic1", label="ic1 text")


def test_round_trip_text_codec():
    _round_trip(LINE * 12, codec="text", label="text codec")


def test_round_trip_binary_multiblock():
    payload = BINARY
    assert len(payload) > 65536
    _round_trip(payload, codec="ic1", label="multiblock ic1")


def test_round_trip_mixed_blocks():
    payload = b"a" * 70000
    image = macarchives.tome([
        {"name": "Member", "data": payload,
         "data_block_codecs": ["ic1", "stored"],
         "type": b"TEXT", "creator": b"ttxt"},
    ])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == payload


def test_round_trip_mixed_blocks_reverse():
    payload = b"a" * 70000
    image = macarchives.tome([
        {"name": "Member", "data": payload,
         "data_block_codecs": ["stored", "ic1"],
         "type": b"TEXT", "creator": b"ttxt"},
    ])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == payload


def test_round_trip_overshoot():
    # A copy in block 0 runs past the 64 KiB boundary into block 1's
    # range; block 1 still ends at the next fixed multiple of 65536.
    payload = b"a" * 70000
    _round_trip(payload, codec="ic1", label="overshoot")


def test_round_trip_both_forks():
    image = macarchives.tome([
        {"name": "Member", "data": TEXT, "data_codec": "ic1",
         "rsrc": RSRC, "rsrc_codec": "ic1",
         "type": b"TEXT", "creator": b"ttxt"},
    ])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "data") == TEXT
    assert archive.read(entry, "rsrc") == RSRC
    assert entry.data_size == len(TEXT)
    assert entry.resource_size == len(RSRC)


def test_round_trip_absent_resource_fork():
    image = macarchives.tome([
        {"name": "Member", "data": STORED_DATA,
         "type": b"TEXT", "creator": b"ttxt"},
    ])
    archive = _open(image)
    entry = archive.entries[0]
    assert entry.resource_size == 0
    assert archive.read(entry, "rsrc") == b""


def test_round_trip_record_fields():
    image = macarchives.tome([
        {"name": "Member Name", "data": b"x",
         "type": b"TEXT", "creator": b"ttxt",
         "created": 400000000, "modified": 400000100,
         "finder_flags": 0x1234},
    ])
    archive = _open(image)
    entry = archive.entries[0]
    assert entry.name == "Member Name"
    assert entry.type == b"TEXT"
    assert entry.creator == b"ttxt"
    assert entry.created == 400000000
    assert entry.modified == 400000100
    assert entry.finder_flags == 0x1234
    assert entry.finder_info == (b"TEXT" + b"ttxt"
                                 + struct.pack(">H", 0x1234) + b"\0" * 22)


def test_round_trip_mac_roman_name():
    image = macarchives.tome([
        {"name": "naïve café", "data": b"x",
         "type": b"TEXT", "creator": b"ttxt"},
    ])
    archive = _open(image)
    assert archive.entries[0].name == "naïve café"


def test_round_trip_multiple_entries_in_order():
    names = ["Apple", "Beta", "Gamma", "Delta"]
    image = macarchives.tome([
        {"name": name, "data": name.encode() * 100, "data_codec": "ic1",
         "type": b"TEXT", "creator": b"ttxt"}
        for name in names
    ])
    archive = _open(image)
    assert [entry.name for entry in archive.entries] == names
    for entry, name in zip(archive.entries, names):
        assert archive.read(entry, "data") == name.encode() * 100


def test_round_trip_zero_filled_allocation_fork():
    # A fork's stated length is larger than its decoded content: the
    # tail is zeros and the stream may stop early.
    _round_trip(b"x" * 100, codec="ic1", stated=140,
                label="zero fill")


def test_probe_accepts_generated():
    image = macarchives.tome([{"name": "T", "data": b"x"}])
    assert tomemod.probe(image) > 0


def test_probe_without_spec_measured_long():
    # The long at 0x16 is measured to be 0x24 in real Tomes; this reader
    # treats the file as a weaker-match Tome, never as a non-Tome.
    image = macarchives.tome([{"name": "T", "data": b"x"}],
                             header_long=False)
    score = tomemod.probe(image)
    assert 0 < score < 90
    archive = _open(image)
    assert archive.entries[0].name == "T"


def test_probe_rejects_bad_magic():
    image = bytearray(macarchives.tome([{"name": "T", "data": b"x"}]))
    image[0] = 0x00
    assert tomemod.probe(bytes(image)) == 0
    with pytest.raises(UnsupportedError):
        _open(bytes(image))


def test_probe_rejects_zero_record_count():
    image = bytearray(macarchives.tome([{"name": "T", "data": b"x"}]))
    struct.pack_into(">H", image, 0x1A, 0)
    assert tomemod.probe(bytes(image)) == 0
    with pytest.raises(UnsupportedError):
        _open(bytes(image))


def test_probe_rejects_record_table_that_does_not_fit():
    image = bytearray(macarchives.tome([{"name": "T", "data": b"x"}]))
    struct.pack_into(">H", image, 0x1A, 0xFFFF)
    assert tomemod.probe(bytes(image)) == 0
    with pytest.raises(UnsupportedError):
        _open(bytes(image))


def test_too_small_is_corrupt_not_unsupported():
    with pytest.raises(CorruptError):
        tomemod.open_data(b"\x6b\x63\x00\x01")


def test_fork_stream_past_end_of_file_is_corrupt():
    image = bytearray(macarchives.tome([{"name": "T", "data": b"x" * 30,
                                         "data_codec": "ic1"}]))
    record = 0x24
    # the data fork's stream offset is the u32 at record + 0x40
    struct.pack_into(">I", image, record + 0x40, len(image) + 100)
    with pytest.raises(CorruptError):
        _open(bytes(image))


def test_stream_ending_past_its_stated_length_is_corrupt():
    # Appending a byte to a fork's stream makes the decoded length fall
    # short of the stream's stated length: the one integrity test the
    # format leaves.
    image = macarchives.tome([{"name": "T", "data": TEXT,
                               "data_codec": "ic1"}])
    record = 0x24
    stream_len = struct.unpack_from(">I", image, record + 0x44)[0]
    image += b"\x00"
    image = bytearray(image)
    struct.pack_into(">I", image, record + 0x44, stream_len + 1)
    with pytest.raises(CorruptError):
        _open(bytes(image))


def test_unknown_codec_is_refused_by_name():
    payload = b"some bytes to encode" * 4
    image = macarchives.tome([{"name": "T", "data": payload,
                               "data_stream": b"\x00\x07\x00\x00" + b"\0" * 64,
                               "data_stated": len(payload)}])
    with pytest.raises(UnsupportedError, match="codec 7"):
        _open(image)


def test_copy_before_stream_start_is_corrupt():
    # A first-token copy reaching before the start of the fork is damage,
    # never a match.  Hand-built: InstaCompOne len code c=2 (100) then
    # the distance form `10` + 2 bits `00` (d = 2 > 0).
    payload = b"whatever payload bytes are declared"
    writer = macarchives.MsbBitWriter()
    writer.bits(0b100, 3)          # c = 2
    writer.bits(0b10, 2)           # form `10`
    writer.bits(0b00, 2)           # level 0: d = 0 + 1 + 1 = 2
    stream = b"\x00\x01\x00\x00" + writer.to_bytes()
    image = macarchives.tome([{"name": "T", "data": payload,
                               "data_stream": stream,
                               "data_stated": len(payload)}])
    with pytest.raises(CorruptError):
        _open(image)


def _literal_chunks(writer, table, byte, count):
    left = count
    while left:
        take = min(left, 63)
        macarchives._tome_emit_code(writer, table, 0)
        macarchives._tome_emit_code(writer, macarchives.TOME_LIT, take)
        for _ in range(take):
            writer.bits(byte, 8)
        left -= take


def test_instacompone_1004_exception():
    # Pos 1648: x = pos - 5*2^7 = 1008, inside the 1004..1024 window
    # where the long-field widens from 10 to 11 bits.  The copy reaches
    # back 1005 bytes (over the B block).  A decoder reading 10 bits
    # mis-syncs everything after this token.
    payload = b"A" * 643 + b"B" * 1005 + b"B" * 1005
    writer = macarchives.MsbBitWriter()
    writer_ic1 = macarchives.TOME_IC1_LEN
    _literal_chunks(writer, writer_ic1, ord("A"), 630)   # 10 x 63
    _literal_chunks(writer, writer_ic1, ord("A"), 10)    # mode -> 0
    # short copy, d=1, len 3 (mode 0 rule): 'AAA' again
    macarchives._tome_emit_code(writer, writer_ic1, 0)
    macarchives.tome_distance_bits(writer, 640, 1, "ic1")
    pos = 643
    _literal_chunks(writer, writer_ic1, ord("B"), 1005)
    pos += 1005
    assert pos == 1648
    # mode == 0 after the last 60-byte chunk; len = 1002 + 2 + 1
    macarchives._tome_emit_code(writer, writer_ic1, 1002)
    macarchives.tome_distance_bits(writer, pos, 1005, "ic1")
    stream = b"\x00\x01\x00\x00" + writer.to_bytes()
    image = macarchives.tome([{"name": "T", "data": payload,
                               "data_stream": stream}])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == payload


def test_padding_token_at_end_of_stream_is_dropped():
    # After the copy, a token whose bits run past the fork's stated
    # compressed length is padding; it is dropped and the output is
    # zero-filled from where the real content ends.
    writer = macarchives.MsbBitWriter()
    writer_ic1 = macarchives.TOME_IC1_LEN
    macarchives._tome_emit_code(writer, writer_ic1, 0)
    macarchives._tome_emit_code(writer, macarchives.TOME_LIT, 3)
    for byte in b"abc":
        writer.bits(byte, 8)
    # mode == 0 now: c=0 means copy of 3 (mode 0 rule)
    macarchives._tome_emit_code(writer, writer_ic1, 0)
    writer.bits(0b10, 2)            # distance form `10`
    writer.bits(0b01, 2)            # level 0: d = 1 + 1 + 1 = 3
    # mode == 1 now: a padding literal-run token straddling the end
    macarchives._tome_emit_code(writer, writer_ic1, 0)
    macarchives._tome_emit_code(writer, macarchives.TOME_LIT, 63)
    stream = b"\x00\x01\x00\x00" + writer.to_bytes()
    expected = b"abcabc" + b"\0" * 3
    image = macarchives.tome([{"name": "T", "data": expected,
                               "data_stream": stream}])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == expected


def test_stored_block_past_stream_end_is_corrupt():
    stream = b"\x01\x00\x00\x00" + b"abc"
    image = macarchives.tome([{"name": "T", "data": b"abc" + b"x" * 100,
                               "data_stream": stream,
                               "data_stated": 104}])
    with pytest.raises(CorruptError):
        _open(image)


def test_extract_writes_data_fork_and_appledouble(tmp_path):
    image = macarchives.tome([
        {"name": "Member", "data": TEXT, "data_codec": "ic1",
         "rsrc": RSRC, "rsrc_codec": "ic1",
         "type": b"TEXT", "creator": b"ttxt",
         "finder_flags": 0x0800},
    ])
    archive = _open(image)
    written = archive.extract(str(tmp_path))
    out = tmp_path / "Member"
    assert out.read_bytes() == TEXT
    assert (tmp_path / "._Member").exists()
    assert str(out) in written


def test_extract_sanitises_names(tmp_path):
    image = macarchives.tome([
        {"name": "../escape", "data": b"x",
         "type": b"TEXT", "creator": b"ttxt"},
    ])
    archive = _open(image)
    archive.extract(str(tmp_path))
    assert not (tmp_path / ".." / "escape").exists()
    assert (tmp_path / "escape").exists()


def test_format_name_and_registry():
    image = macarchives.tome([{"name": "T", "data": b"x"}])
    archive = _open(image)
    assert archive.format == "Apple Installer Tome"


def test_crafted_fork_end_to_end():
    # A fork built token by token: 5 literal Bs, copy of 11 more
    payload = b"B" * 16
    writer = macarchives.MsbBitWriter()
    writer_ic1 = macarchives.TOME_IC1_LEN
    macarchives._tome_emit_code(writer, writer_ic1, 0)
    macarchives._tome_emit_code(writer, macarchives.TOME_LIT, 5)
    for _ in range(5):
        writer.bits(ord("B"), 8)
    # mode == 0: copy c=9 (len 11) d=5
    macarchives._tome_emit_code(writer, writer_ic1, 9)
    macarchives.tome_distance_bits(writer, 5, 5, "ic1")
    stream = b"\x00\x01\x00\x00" + writer.to_bytes()
    image = macarchives.tome([{"name": "T", "data": payload,
                               "data_stream": stream}])
    archive = _open(image)
    assert archive.read(archive.entries[0], "data") == payload
