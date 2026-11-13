"""gzip reader tests. Fixtures are generated in memory (the stdlib
``gzip`` module mostly, plus hand-built headers for the corner cases);
the stdlib writer is also the black-box oracle for round-trips."""

import io
import zlib

import pytest

import macextract
from macextract import CorruptError, UnsupportedError
from macextract.formats import gzip as gzipmod

GZIP_MAGIC = b"\x1f\x8b\x08"


def _member(payload, mtime=0, name=None, flg_extra=False, comment=None,
            hcrc=False, level=9):
    """Hand-build one RFC 1952 member (stdlib ``gzip`` never emits the
    FEXTRA/FCOMMENT paths, so tests need their own)."""
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    body = compressor.compress(payload) + compressor.flush()
    flags = 0
    extra = b""
    if flg_extra:
        flags |= gzipmod.FLG_FEXTRA
        extra = b"\x04\x00XY\xde\xad"
    out = io.BytesIO()
    out.write(b"\x1f\x8b\x08")
    extra_head = bytearray()
    if name is not None:
        flags |= gzipmod.FLG_FNAME
        extra_head += bytes(name) + b"\0"
    if comment is not None:
        flags |= gzipmod.FLG_FCOMMENT
        extra_head += bytes(comment) + b"\0"
    out.write(bytes([flags]))
    out.write(mtime.to_bytes(4, "little"))
    out.write(b"\x02\x03")          # XFL, OS = Unix
    if flags & gzipmod.FLG_FEXTRA:
        out.write(len(extra).to_bytes(2, "little"))
        out.write(extra)
    out.write(extra_head)
    if hcrc:
        flags |= gzipmod.FLG_FHCRC
        # the flags byte gains FHCRC and the header CRC is computed
        # over the header with FHCRC set, then appended
        head = bytearray(out.getvalue())
        head[3] = flags
        header_crc = zlib.crc32(bytes(head)) & 0xFFFF
        out = io.BytesIO()
        out.write(bytes(head))
        out.write(header_crc.to_bytes(2, "little"))
    out.write(body)
    out.write(zlib.crc32(payload).to_bytes(4, "little"))
    out.write((len(payload) & 0xFFFFFFFF).to_bytes(4, "little"))
    return out.getvalue()


def test_round_trip():
    import gzip
    payload = b"gzip payload " * 1000
    blob = gzip.compress(payload, compresslevel=9, mtime=0)
    archive = macextract.open(io.BytesIO(blob))
    assert archive.format == "gzip"
    entry = archive.entries[0]
    assert archive.read(entry, "data") == payload
    assert entry.data_size == len(payload)


def test_round_trip_empty():
    import gzip
    blob = gzip.compress(b"", mtime=0)
    archive = macextract.open(io.BytesIO(blob))
    assert archive.read(archive.entries[0], "data") == b""


def test_multi_member_concatenated():
    import gzip
    blob = gzip.compress(b"AAA", mtime=0) + gzip.compress(b"BBBB", mtime=0)
    archive = macextract.open(io.BytesIO(blob))
    assert archive.read(archive.entries[0], "data") == b"AAABBBB"


def test_multi_member_three():
    import gzip
    blob = b"".join(gzip.compress(bytes([i]) * 50, mtime=0) for i in range(3))
    archive = macextract.open(io.BytesIO(blob))
    assert archive.read(archive.entries[0], "data") == \
        bytes([0]) * 50 + bytes([1]) * 50 + bytes([2]) * 50


def test_member_crc_mismatch():
    import gzip
    payload = b"crc check payload" * 50
    blob = bytearray(gzip.compress(payload, mtime=0))
    blob[-5] ^= 0xFF                # inside the CRC-32 trailer
    with pytest.raises(CorruptError, match="CRC-32"):
        macextract.open(io.BytesIO(bytes(blob)))


def test_member_isize_mismatch():
    import gzip
    payload = b"isize check payload" * 50
    blob = bytearray(gzip.compress(payload, mtime=0))
    blob[-1] ^= 0xFF                # ISIZE low byte
    with pytest.raises(CorruptError, match="ISIZE"):
        macextract.open(io.BytesIO(bytes(blob)))


def test_truncated_member():
    import gzip
    blob = gzip.compress(b"truncate me" * 100, mtime=0)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(blob[:len(blob) // 2]))


def test_truncated_trailer():
    import gzip
    blob = gzip.compress(b"no trailer left", mtime=0)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(blob[:-4]))


def test_trailing_junk_after_member():
    import gzip
    blob = gzip.compress(b"fine", mtime=0) + b"junkjunk"
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(blob))


def test_reserved_method_refused():
    blob = bytearray(_member(b"data"))
    blob[2] = 9                     # CM = reserved, not deflate
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(bytes(blob)))


def test_reserved_flag_bits_rejected():
    blob = bytearray(_member(b"data"))
    blob[3] |= 0xE0                 # reserved FLG bits
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(bytes(blob)))


def test_fname_member_decodes():
    payload = b"payload with a name"
    blob = _member(payload, name=b"original.txt")
    archive = macextract.open(io.BytesIO(blob))
    assert archive.read(archive.entries[0], "data") == payload


def test_fextra_member_decodes():
    payload = b"payload with extra"
    blob = _member(payload, flg_extra=True)
    archive = macextract.open(io.BytesIO(blob))
    assert archive.read(archive.entries[0], "data") == payload


def test_fcomment_member_decodes():
    payload = b"payload with comment"
    blob = _member(payload, comment=b"a comment")
    archive = macextract.open(io.BytesIO(blob))
    assert archive.read(archive.entries[0], "data") == payload


def test_fhcrc_member_decodes():
    payload = b"payload with header crc"
    blob = _member(payload, hcrc=True)
    archive = macextract.open(io.BytesIO(blob))
    assert archive.read(archive.entries[0], "data") == payload


def test_fhcrc_member_bad_header_crc():
    payload = b"bad header crc"
    blob = bytearray(_member(payload, hcrc=True))
    blob[5] ^= 0xFF                 # MTIME byte inside the header
    with pytest.raises(CorruptError, match="header CRC"):
        macextract.open(io.BytesIO(bytes(blob)))


def test_filename_hint_strips_gz(tmp_path):
    import gzip
    path = tmp_path / "payload.tar.gz"
    path.write_bytes(gzip.compress(b"hint name", mtime=0))
    archive = macextract.open(path)
    assert archive.entries[0].name == "payload.tar"


def test_filename_hint_uppercase_suffix(tmp_path):
    import gzip
    path = tmp_path / "Payload.GZ"
    path.write_bytes(gzip.compress(b"hint name", mtime=0))
    archive = macextract.open(path)
    assert archive.entries[0].name == "Payload"


def test_no_filename_hint():
    import gzip
    blob = gzip.compress(b"no hint", mtime=0)
    archive = macextract.open(io.BytesIO(blob))
    assert archive.entries[0].name == "uncompressed"


def test_extract_writes_payload(tmp_path):
    import gzip
    payload = b"extract me " * 200
    src = tmp_path / "thing.txt.gz"
    src.write_bytes(gzip.compress(payload, mtime=0))
    archive = macextract.open(src)
    out = tmp_path / "out"
    written = archive.extract(out)
    assert (out / "thing.txt").read_bytes() == payload
    assert written


def test_probe():
    import gzip
    blob = gzip.compress(b"probe", mtime=0)
    assert gzipmod.probe(blob) > 0
    assert gzipmod.probe(b"") == 0
    assert gzipmod.probe(b"\x1f\x8b") == 0
    assert gzipmod.probe(b"\x1f\x8b\x09abc") == 0    # CM != 8
    assert gzipmod.probe(b"\x1f\x9d\x08") == 0       # that's .Z, not .gz


def test_password_refused():
    import gzip
    blob = gzip.compress(b"no encryption in gzip", mtime=0)
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(blob), password="secret")


def test_blackbox_oracle_agrees():
    """The stdlib reader is the oracle: for every fixture, outputs match."""
    import gzip
    for payload in (b"", b"x", b"hello" * 500, bytes(range(256)) * 20):
        blob = gzip.compress(payload, mtime=12345)
        archive = macextract.open(io.BytesIO(blob))
        assert archive.read(archive.entries[0], "data") == gzip.decompress(blob)
