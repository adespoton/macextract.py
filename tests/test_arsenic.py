import io
import struct

import pytest

import macextract
from macextract import CorruptError
from macextract._arsenic import arsenic_decode
from macextract._crc16 import crc16_arc

import macarchives

DATA = (b"Arsenic test payload, compressible compressible compressible "
        * 6 + b"B" * 400 + b"CCCtail")
RSRC = b"\x00\x00\x01\x00 rsrc blob with some structure " * 5


def _open(image, password=None):
    return macextract.open(io.BytesIO(image), password=password)


# --- The codec on its own --------------------------------------------

@pytest.mark.parametrize("payload", [
    b"hello",
    b"\x00" * 300,                       # zero runs: the selector 0/1 path
    b"X" * 5,                            # a run of exactly four plus one
    b"Q" * 600,                          # runs past 255, split by the RLE
    b"abab" * 50,                        # periodic: the BWT has ties
    b"aabaab" * 40,                      # ties with a wrapping index
    bytes(range(256)) * 3,               # every byte value once
    DATA,
])
def test_round_trips(payload):
    stream = macarchives.arsenic_encode(payload)
    assert arsenic_decode(stream, len(payload)) == payload


@pytest.mark.parametrize("blockbits", [9, 10, 12])
@pytest.mark.parametrize("randomized", [False, True])
def test_every_block_size_and_the_randomisation_bit(blockbits, randomized):
    # blockbits 9 is the smallest legal block (512 bytes), so DATA and
    # the long payloads are cut into several blocks.
    stream = macarchives.arsenic_encode(
        DATA, blockbits=blockbits, randomized=randomized)
    assert arsenic_decode(stream, len(DATA)) == DATA


def test_a_run_that_straddles_several_blocks():
    payload = (b"A" * 500 + b"B" * 500 + b"C" * 500)
    stream = macarchives.arsenic_encode(payload, blockbits=9)
    assert arsenic_decode(stream, len(payload)) == payload


def test_empty_payload_has_no_encoder():
    with pytest.raises(ValueError, match="empty payload"):
        macarchives.arsenic_encode(b"")


def test_a_flipped_first_byte_is_not_arsenic():
    stream = bytearray(macarchives.arsenic_encode(DATA))
    stream[0] ^= 0xFF
    with pytest.raises(CorruptError):
        arsenic_decode(bytes(stream), len(DATA))


def test_a_truncated_stream_is_corrupt():
    stream = macarchives.arsenic_encode(DATA)
    with pytest.raises(CorruptError, match="ends inside"):
        arsenic_decode(stream[:-1], len(DATA))


def test_the_stream_must_reach_the_declared_length():
    stream = macarchives.arsenic_encode(DATA)
    with pytest.raises(CorruptError, match="before the fork does"):
        arsenic_decode(stream, len(DATA) + 50)


def test_the_crc32_covers_the_whole_output():
    stream = macarchives.arsenic_encode(DATA)
    # Stopping early leaves the stream's CRC-32 over the wrong bytes.
    with pytest.raises(CorruptError, match="CRC-32 mismatch"):
        arsenic_decode(stream, len(DATA) - 10)


# --- Through the containers ------------------------------------------

def test_stuffs_both_forks_of_a_stuffit5():
    image = macarchives.stuffit5([{
        "name": b"Doc", "data": DATA, "rsrc": RSRC,
        "method": 15, "rsrc_method": 15,
    }])
    archive = _open(image)
    assert archive.format == "StuffIt 5"
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_mixed_with_the_classic_coders():
    image = macarchives.stuffit5([{
        "name": b"Mixed", "data": DATA, "rsrc": RSRC,
        "method": 15, "rsrc_method": 3,
    }])
    archive = _open(image)
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_an_encrypted_arsenic_fork():
    image = macarchives.stuffit5(
        [{"name": b"Secret", "data": DATA, "method": 15, "encrypted": True}],
        password="pw")
    archive = _open(image, password="pw")
    assert archive.read(archive.entries[0], "data") == DATA


def test_stuffit5_skips_the_fork_crc16_for_method_15():
    image = bytearray(macarchives.stuffit5(
        [{"name": b"A", "data": DATA, "method": 15}]))
    first = struct.unpack_from(">I", image, 94)[0]
    # The data fork's CRC-16 field, zero for method 15; a nonzero wrong
    # value must not matter, because the stream checks itself.
    struct.pack_into(">H", image, first + 42, 0xBEEF)
    archive = _open(bytes(image))
    assert archive.read(archive.entries[0], "data") == DATA


def test_stuffs_a_stuffit_classic():
    image = macarchives.stuffit(
        [{"name": b"Doc", "data": DATA, "rsrc": RSRC, "method": 15}])
    archive = _open(image)
    assert archive.format == "StuffIt"
    entry = archive.entries[0]
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_stuffit_classic_skips_the_fork_crc16_for_method_15():
    image = bytearray(macarchives.stuffit(
        [{"name": b"A", "data": DATA, "method": 15}]))
    # Data fork CRC-16 at header offset 102; repair the header CRC at
    # 110 so the walk still accepts the entry.
    struct.pack_into(">H", image, 22 + 102, 0xBEEF)
    struct.pack_into(">H", image, 22 + 110,
                     crc16_arc(bytes(image[22:132])))
    archive = _open(bytes(image))
    assert archive.read(archive.entries[0], "data") == DATA


def test_a_corrupt_arsenic_fork_fails_the_entry_not_the_window():
    # A stored-length claim that runs past the data is caught before
    # the codec; a codec failure surfaces as CorruptError either way.
    image = macarchives.stuffit5(
        [{"name": b"A", "data": DATA, "method": 15,
          "datacomp_extra": 4}])
    with pytest.raises(CorruptError, match="run past the end of the data"):
        _open(image)


def test_extract_writes_the_files(tmp_path):
    image = macarchives.stuffit5([
        {"folder": "Dir"},
        {"name": b"Doc", "data": DATA, "method": 15},
        {"folder_end": True},
    ])
    archive = _open(image)
    archive.extract(str(tmp_path))
    assert (tmp_path / "Dir" / "Doc").read_bytes() == DATA
