"""Unix compress (.Z) reader tests. Fixtures are generated in memory by
``macarchives.compress_encode``; the decoder must agree with the
writer's width schedule, so both are exercised across the width
growth boundary."""

import hashlib
import io

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract.formats import z as zmod

import macarchives

# Deterministic, high-entropy payload: every 32-byte block of its own
# sha256, so the table fills and the width schedule advances.
ENTROPIC = b"".join(hashlib.sha256(b"z-test-%d" % i).digest()
                    for i in range(2048))


def _open(image, filename=None):
    return macextract.open(io.BytesIO(image)) if filename is None else \
        macextract.open(image) if False else macextract.open(filename)


@pytest.mark.parametrize("size", [0, 1, 100, 1024, 32768])
@pytest.mark.parametrize("maxbits", [9, 12, 16])
@pytest.mark.parametrize("blockmode", [True, False])
def test_round_trip(size, maxbits, blockmode):
    if size == 0:
        payload = b""
    elif maxbits <= 9 and size > 0:
        payload = bytes((i * 61 + 7) & 0x7F for i in range(size))
    else:
        payload = ENTROPIC[:size] if size <= len(ENTROPIC) else \
            (ENTROPIC * (size // len(ENTROPIC) + 1))[:size]
    image = macarchives.compress_encode(payload, maxbits=maxbits,
                                        blockmode=blockmode)
    archive = macextract.open(io.BytesIO(image))
    entry = archive.entries[0]
    assert archive.read(entry, "data") == payload


def test_round_trip_width_growth_blockmode():
    # 24 KB of high-entropy data drives the table past every width
    # boundary at 16 bits.
    payload = ENTROPIC[:24576]
    image = macarchives.compress_encode(payload, maxbits=16, blockmode=True)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == payload


def test_probe():
    image = macarchives.compress_encode(b"probe me")
    assert zmod.probe(image) > 0
    assert zmod.probe(b"") == 0
    assert zmod.probe(b"\x1f\x9d\x00") == 0     # maxbits 0 out of range
    assert zmod.probe(b"\x1f\x9d\x08") == 0     # maxbits 8 out of range
    assert zmod.probe(b"\x1f\x9e\x10") == 0


def test_entry_named_from_filename(tmp_path):
    payload = b"named by the archive's filename"
    image = macarchives.compress_encode(payload)
    path = tmp_path / "payload.tar.Z"
    path.write_bytes(image)
    archive = macextract.open(path)
    assert archive.entries[0].name == "payload.tar"
    assert archive.read(archive.entries[0], "data") == payload


def test_entry_without_filename_hint():
    image = macarchives.compress_encode(b"hintless")
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].name == "uncompressed"


def test_extract_writes_payload(tmp_path):
    payload = b"extract this through the .Z door" * 8
    image = macarchives.compress_encode(payload)
    path = tmp_path / "payload.txt.Z"
    path.write_bytes(image)
    out = tmp_path / "out"
    archive = macextract.open(path)
    written = archive.extract(str(out))
    assert written
    assert (out / "payload.txt").read_bytes() == payload


def test_bad_magic_rejected():
    image = bytearray(macarchives.compress_encode(b"bad magic"))
    image[0] = 0x1E
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(bytes(image)))


def test_truncated_stream_ends_cleanly_not_crash():
    payload = b"truncate me somewhere inside the code stream" * 4
    image = macarchives.compress_encode(payload)
    archive = macextract.open(io.BytesIO(image[:-3]))
    assert archive.read(archive.entries[0], "data") != b""
    assert len(archive.read(archive.entries[0], "data")) <= len(payload) + 256


def test_garbage_after_header_rejected():
    image = b"\x1f\x9d\x10" + b"\xff" * 64
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image))


def test_clear_code_round_trip_self_consistency():
    # A real compress(1) stream essentially never contains a clear;
    # the corpus at hand shows none even at 717 KB, and ncompress,
    # gzip and busybox all refuse a 9-bit clear stream. This grade is
    # encoder/decoder self-consistency for the decoder's clear path
    # only, which is why it uses force_clear.
    payload = b"clear me repeatedly clear me repeatedly " * 12
    image = macarchives.compress_encode(payload, maxbits=9, blockmode=True,
                                        force_clear=True)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == payload


def test_saturation_round_trip_at_nine_bits():
    # Full table at maxbits 9: no clear is emitted (as the real
    # encoder saturates) and decoding keeps going at 9 bits. The
    # -b9 envelope is unportable (ncompress, gzip and busybox all
    # refuse real -b9 files), so this is self-consistency only.
    payload = bytes((i * 61 + 7) & 0x7F for i in range(1000))
    image = macarchives.compress_encode(payload, maxbits=9, blockmode=True)
    archive = macextract.open(io.BytesIO(image))
    assert archive.read(archive.entries[0], "data") == payload
