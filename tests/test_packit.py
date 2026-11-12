import io
from pathlib import Path

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives

DATA = b"PackIt test payload, compressible compressible compressible " * 8
RSRC = b"\x00\x00\x01\x00 rsrc blob with some structure " * 4


def test_packit_stored_round_trip():
    image = macarchives.packit(
        files=[(b"MyFile", DATA, RSRC, b"TEXT", b"TTxt")], kind="stored")
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "PackIt"
    entry = archive.entries[0]
    assert entry.name == "MyFile"
    assert entry.type == b"TEXT"
    assert entry.creator == b"TTxt"
    assert entry.finder_flags == 0x0100
    assert entry.locked is False
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC
    assert entry.created == 400000000
    assert entry.modified == 400000100


def test_packit_huffman_round_trip():
    image = macarchives.packit(
        files=[(b"Coded", DATA, RSRC, b"TEXT", b"TTxt")], kind="huffman")
    archive = macextract.open(io.BytesIO(image))
    entry = archive.entries[0]
    assert entry.name == "Coded"
    assert archive.read(entry, "data") == DATA
    assert archive.read(entry, "rsrc") == RSRC


def test_packit_mixed_stored_and_huffman():
    image = macarchives.packit(files=[
        {"name": b"Stored", "data": b"stored-bytes", "rsrc": b"",
         "type": b"TEXT", "creator": b"TTxt", "kind": "stored"},
        {"name": b"Coded", "data": DATA, "rsrc": RSRC,
         "type": b"TEXT", "creator": b"TTxt", "kind": "huffman"},
    ])
    archive = macextract.open(io.BytesIO(image))
    assert [entry.name for entry in archive.entries] == ["Stored", "Coded"]
    assert archive.read(archive.entries[1], "data") == DATA
    assert archive.read(archive.entries[1], "rsrc") == RSRC


def test_packit_locked_flag():
    image = macarchives.packit(
        files=[{"name": b"Lock", "data": b"x", "locked": True, "kind": "stored"}])
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].locked is True


def test_packit_encrypted_subfile_clear_error():
    image = macarchives.packit(
        files=[(b"Secret", b"payload", b"", b"TEXT", b"TTxt")], kind="encrypted")
    with pytest.raises(UnsupportedError) as excinfo:
        macextract.open(io.BytesIO(image))
    assert "PMa5" in str(excinfo.value)


def test_packit_unknown_type_word_midstream():
    image = macarchives.packit(files=[(b"x", b"y", b"", b"TEXT", b"TTxt")])
    image = image[:-4] + b"P???"  # replace PEnd with an unknown word
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image))


def test_packit_unknown_type_word_at_start():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"P???" + b"\0" * 100))


def test_packit_missing_pend():
    image = macarchives.packit(files=[(b"x", b"y", b"", b"TEXT", b"TTxt")],
                               tail_word=False)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image))


def test_packit_truncated_stored():
    image = macarchives.packit(files=[(b"x", DATA, b"", b"TEXT", b"TTxt")])
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image[:-40]))


def test_packit_truncated_coded_stream():
    image = macarchives.packit(files=[(b"x", DATA, b"", b"TEXT", b"TTxt")],
                               kind="huffman", tail_word=False)
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image[:len(image) * 2 // 3]))


def test_packit_empty_archive():
    archive = macextract.open(io.BytesIO(b"PEnd"))
    assert archive.entries == []


def test_packit_not_recognized():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"PK\x03\x04" + b"\0" * 100))


def test_packit_extract_with_rsrc(tmp_path):
    image = macarchives.packit(
        files=[(b"Doc", b"data-bytes", b"rsrc-bytes", b"TEXT", b"TTxt")])
    archive = macextract.open(io.BytesIO(image))
    written = archive.extract(tmp_path)
    assert (tmp_path / "Doc").read_bytes() == b"data-bytes"
    dotfile = tmp_path / "._Doc"
    assert dotfile.read_bytes()[:4] == b"\x00\x05\x16\x07"


def test_packit_name_with_colon_sanitized(tmp_path):
    image = macarchives.packit(
        files=[(b"Folder:Doc", b"data", b"", b"TEXT", b"TTxt")])
    archive = macextract.open(io.BytesIO(image))
    written = archive.extract(tmp_path)
    assert (tmp_path / "Folder" / "Doc").read_bytes() == b"data"


def test_packit_header_crc_not_enforced():
    # The CRC polynomial is not established by the format notes; a
    # deliberately wrong CRC value must still open.
    image = macarchives.packit(
        files=[(b"x", b"y", b"", b"TEXT", b"TTxt")])
    # offset of the header CRC field: 4 (type word) + 92
    broken = image[:4 + 92] + b"\xbe\xef" + image[4 + 94:]
    archive = macextract.open(io.BytesIO(broken))
    assert archive.entries[0].name == "x"
