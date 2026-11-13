"""zip reader tests. Fixtures are generated in memory with the
stdlib ``zipfile`` module (the black-box oracle) plus hand-built
streams for the data-descriptor, ZIP64-extra and encrypted corners."""

import io
import struct
import zipfile
import zlib

import pytest

import macextract
from macextract import CorruptError, PasswordRequiredError, UnsupportedError
from macextract.formats import zip as zipmod


def _zip_bytes(members, comment=None):
    """members: list of (name, payload, compress_type)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, payload, ctype in members:
            zf.writestr(name, payload, compress_type=ctype)
        if comment:
            zf.comment = comment
    return buf.getvalue()


def _stored(payload):
    return (zlib.crc32(payload), len(payload), len(payload))


def _open(blob):
    return macextract.open(io.BytesIO(blob))


def test_deflate_round_trip():
    payload = b"zip payload " * 500
    blob = _zip_bytes([("doc.txt", payload, zipfile.ZIP_DEFLATED)])
    archive = _open(blob)
    entry = archive.entries[0]
    assert archive.format == "ZIP"
    assert entry.name == "doc.txt"
    assert archive.read(entry, "data") == payload


def test_stored_round_trip():
    payload = b"stored " * 400
    blob = _zip_bytes([("s.bin", payload, zipfile.ZIP_STORED)])
    archive = _open(blob)
    assert archive.read(archive.entries[0], "data") == payload


def test_mixed_methods_and_sizes():
    members = [("a.txt", b"a" * 1000, zipfile.ZIP_STORED),
               ("sub/b.txt", b"b" * 3000, zipfile.ZIP_DEFLATED),
               ("c.txt", b"", zipfile.ZIP_DEFLATED)]
    blob = _zip_bytes(members)
    archive = _open(blob)
    assert [e.name for e in archive.entries] == [m[0] for m in members]
    for entry, (_, payload, _) in zip(archive.entries, members):
        assert archive.read(entry, "data") == payload


def test_directory_entries_skipped():
    payload = b"file inside dir"
    blob = _zip_bytes([("adir/", b"", zipfile.ZIP_STORED),
                       ("adir/file.txt", payload, zipfile.ZIP_DEFLATED)])
    archive = _open(blob)
    assert [e.name for e in archive.entries] == ["adir/file.txt"]


def test_utf8_name():
    payload = b"unicode name" * 10
    blob = _zip_bytes([("naïve café ✓.txt", payload, zipfile.ZIP_DEFLATED)])
    archive = _open(blob)
    assert archive.entries[0].name == "naïve café ✓.txt"
    assert archive.read(archive.entries[0], "data") == payload


def test_cp437_name_decoded():
    # no UTF-8 flag: the name bytes are CP437 (APPNOTE default)
    payload = b"cp437"
    raw_name = "caf\u00e9.txt".encode("cp437")   # \xe9 in cp437
    name_field = raw_name
    header = b"PK\x03\x04" + struct.pack(
        "<HHHHHIIIHH", 20, 0, 0, 0, 0,
        zlib.crc32(payload), len(payload), len(payload),
        len(name_field), 0) + name_field + payload
    central = b"PK\x01\x02" + struct.pack(
        "<HHHHHHIIIHHHHHII", 20, 20, 0, 0, 0, 0,
        zlib.crc32(payload), len(payload), len(payload),
        len(name_field), 0, 0, 0, 0, 0, 0) + name_field
    eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, 1, 1,
                       len(central), len(header), 0)
    archive = _open(header + central + eocd)
    assert archive.entries[0].name == "caf\u00e9.txt"
    assert archive.read(archive.entries[0], "data") == payload


def test_archive_with_comment():
    payload = b"commented"
    blob = _zip_bytes([("c.txt", payload, zipfile.ZIP_STORED)],
                      comment=b"a zip comment" * 100)
    archive = _open(blob)
    assert archive.read(archive.entries[0], "data") == payload


def test_empty_archive():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    archive = _open(buf.getvalue())
    assert archive.format == "ZIP"
    assert archive.entries == []


def test_truncated_archive_refused():
    blob = _zip_bytes([("t.txt", b"t" * 100, zipfile.ZIP_DEFLATED)])
    # the probe will not claim a blob whose EOCD is damaged
    with pytest.raises(UnsupportedError):
        _open(blob[:-10])
    with pytest.raises(CorruptError):
        zipmod.open_data(blob[:-10])


def test_garbage_refused():
    with pytest.raises(UnsupportedError):
        _open(b"definitely not a zip file at all" * 10)


def test_no_eocd_refused():
    # the probe will not claim a zip-shaped orphan (no EOCD), so the
    # registry reports it as unrecognised; the parser called directly
    # says what is actually wrong.
    payload = b"orphan local header"
    local = (b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 0, 0, 0,
                                         zlib.crc32(payload),
                                         len(payload), len(payload),
                                         5, 0)
             + b"a.txt" + payload)
    with pytest.raises(UnsupportedError):
        _open(local)
    with pytest.raises(CorruptError, match="end of central directory"):
        zipmod.open_data(local)


def test_corrupt_stored_payload():
    payload = bytearray(b"stored payload " * 100)
    blob = bytearray(_zip_bytes([("s.bin", bytes(payload),
                                  zipfile.ZIP_STORED)]))
    index = bytes(blob).index(b"stored payload")
    blob[index] ^= 0xFF
    with pytest.raises(CorruptError, match="CRC-32"):
        _open(bytes(blob))


def test_corrupt_deflate_payload():
    payload = b"deflate payload " * 300
    blob = bytearray(_zip_bytes([("d.bin", payload,
                                  zipfile.ZIP_DEFLATED)]))
    # flip a byte inside the compressed stream (after the 30-byte local
    # header and the 5-byte name)
    blob[40] ^= 0xFF
    with pytest.raises(CorruptError):
        _open(bytes(blob))


def test_corrupt_central_crc():
    payload = b"crc field tamper"
    blob = bytearray(_zip_bytes([("c.bin", payload,
                                  zipfile.ZIP_STORED)]))
    cd = bytes(blob).index(b"PK\x01\x02")
    crc_at = cd + 16
    blob[crc_at] ^= 0xFF
    with pytest.raises(CorruptError, match="CRC-32"):
        _open(bytes(blob))


def test_bzip2_member_refused_by_name():
    payload = b"bzip2 me" * 100
    blob = _zip_bytes([("b.bin", payload, zipfile.ZIP_BZIP2)])
    with pytest.raises(UnsupportedError, match="bzip2"):
        _open(blob)


def test_lzma_member_refused_by_name():
    payload = b"lzma me" * 100
    blob = _zip_bytes([("l.bin", payload, zipfile.ZIP_LZMA)])
    with pytest.raises(UnsupportedError, match="LZMA"):
        _open(blob)


def test_encrypted_member_password_required():
    payload = b"encrypted payload"
    blob = bytearray(_zip_bytes([("secret.txt", payload,
                                  zipfile.ZIP_STORED)]))
    # set flag bit 0x0001 in the local header (offset 6) and in the
    # central directory record (offset 8 past the signature)
    struct.pack_into("<H", blob, 6, 0x0001)
    cd = bytes(blob).index(b"PK\x01\x02")
    struct.pack_into("<H", blob, cd + 8, 0x0001)
    with pytest.raises(PasswordRequiredError):
        _open(bytes(blob))


def test_zip64_refused():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", allowZip64=True) as zf:
        info = zipfile.ZipInfo("big.bin")
        with zf.open(info, "w", force_zip64=True) as handle:
            handle.write(b"x" * 100)
    with pytest.raises(UnsupportedError, match="ZIP64"):
        _open(buf.getvalue())


def test_multi_disk_refused():
    payload = b"multi disk"
    blob = bytearray(_zip_bytes([("m.txt", payload,
                                  zipfile.ZIP_STORED)]))
    eocd = bytes(blob).rfind(b"PK\x05\x06")
    struct.pack_into("<H", blob, eocd + 4, 1)    # disk number = 1
    with pytest.raises(UnsupportedError, match="multi-disk"):
        _open(bytes(blob))


def test_multi_disk_member_refused():
    payload = b"member on disk two"
    blob = bytearray(_zip_bytes([("m.txt", payload,
                                  zipfile.ZIP_STORED)]))
    cd = bytes(blob).index(b"PK\x01\x02")
    struct.pack_into("<H", blob, cd + 34, 1)     # disk start = 1
    with pytest.raises(UnsupportedError, match="multi-disk"):
        _open(bytes(blob))


def test_data_descriptor_member():
    # Hand-build a streamed member: bit 3 set, zero sizes in the local
    # header, real sizes in the central directory, descriptor after data.
    payload = b"data descriptor payload " * 50
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    compressed = comp.compress(payload) + comp.flush()
    crc = zlib.crc32(payload)
    name = b"streamed.txt"

    local = bytearray()
    local += b"PK\x03\x04"
    local += struct.pack("<HHHHHIIIHH", 20, 0x0008, 8, 0, 0,
                         0, 0, 0,
                         len(name), 0)
    local += name
    local += compressed
    local += b"PK\x07\x08"
    local += struct.pack("<III", crc, len(compressed), len(payload))

    central = bytearray()
    local_offset = 0
    central += b"PK\x01\x02"
    central += struct.pack("<HHHHHHIIIHHHHHII", 20, 20, 0x0008, 8, 0, 0,
                           crc, len(compressed), len(payload),
                           len(name), 0, 0, 0, 0, 0, local_offset)
    central += name

    eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, 1, 1,
                       len(central), len(local), 0)
    blob = bytes(local) + bytes(central) + eocd
    archive = _open(blob)
    entry = archive.entries[0]
    assert entry.name == "streamed.txt"
    assert archive.read(entry, "data") == payload


def test_zip64_extra_in_central_refused():
    # A central directory record carrying a 0x0001 (ZIP64) extra field
    # is refused even when the sentinel values are absent.
    payload = b"zip64 extra"
    name = b"z.txt"
    crc = zlib.crc32(payload)
    local = bytearray()
    local += b"PK\x03\x04"
    local += struct.pack("<HHHHHIIIHH", 20, 0, 0, 0, 0,
                         crc, len(payload), len(payload), len(name), 0)
    local += name
    local += payload

    extra = struct.pack("<HH", 0x0001, 16) + b"\0" * 16
    central = bytearray()
    central += b"PK\x01\x02"
    central += struct.pack("<HHHHHHIIIHHHHHII", 20, 20, 0, 0, 0, 0,
                           crc, len(payload), len(payload),
                           len(name), len(extra), 0, 0, 0, 0, 0)
    central += name + extra

    eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, 1, 1,
                       len(central), len(local), 0)
    blob = bytes(local) + bytes(central) + eocd
    with pytest.raises(UnsupportedError, match="ZIP64"):
        _open(blob)


def test_extract_sanitises_parent_names(tmp_path):
    payload = b"escaped"
    blob = _zip_bytes([("../../evil.txt", payload, zipfile.ZIP_STORED)])
    archive = _open(blob)
    out = tmp_path / "out"
    archive.extract(out)
    assert (out / "evil.txt").read_bytes() == payload


def test_extract_round_trip(tmp_path):
    members = [("x/y.txt", b"nested file " * 50, zipfile.ZIP_DEFLATED),
               ("top.txt", b"top level", zipfile.ZIP_STORED)]
    blob = _zip_bytes(members)
    archive = _open(blob)
    out = tmp_path / "out"
    archive.extract(out)
    assert (out / "x" / "y.txt").read_bytes() == b"nested file " * 50
    assert (out / "top.txt").read_bytes() == b"top level"


def test_probe():
    blob = _zip_bytes([("p.txt", b"probe", zipfile.ZIP_STORED)])
    assert zipmod.probe(blob) > 0
    assert zipmod.probe(b"") == 0
    # bare local-header magic with no EOCD is not claimed
    assert zipmod.probe(b"PK\x03\x04\x00" + b"\0" * 100) == 0
    assert zipmod.probe(b"\x1f\x8b\x08") == 0


def test_blackbox_oracle_agrees():
    """stdlib zipfile is the oracle: names and contents match."""
    members = [("one.txt", b"first", zipfile.ZIP_STORED),
               ("dir/two.txt", b"second " * 500, zipfile.ZIP_DEFLATED),
               ("deep/a.bin", bytes(range(256)) * 20,
                zipfile.ZIP_DEFLATED)]
    blob = _zip_bytes(members)
    archive = _open(blob)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        orated = [(info.filename, zf.read(info))
                  for info in zf.infolist()
                  if not info.filename.endswith("/")]
    mine = [(entry.name, archive.read(entry, "data"))
            for entry in archive.entries]
    assert mine == orated
