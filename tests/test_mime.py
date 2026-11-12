import base64
import io
from pathlib import Path

import pytest

import macextract
from macextract import CorruptError, UnsupportedError

import macarchives


def test_mime_base64_attachment():
    part = macarchives.mime_b64_part("fox.txt", b"attachment bytes" * 100)
    image = macarchives.mime_message([part])
    archive = macextract.open(io.BytesIO(image))
    assert archive.format == "MIME"
    assert len(archive.entries) == 1
    entry = archive.entries[0]
    assert entry.name == "fox.txt"
    assert archive.read(entry, "data") == b"attachment bytes" * 100


def test_mime_multiple_attachments_and_body_skip():
    parts = [
        macarchives.mime_b64_part("one.bin", b"1" * 400),
        macarchives.mime_b64_part("two.bin", b"2" * 300),
    ]
    image = macarchives.mime_message(parts, preamble="Hi, see attached.\n")
    archive = macextract.open(io.BytesIO(image))
    assert [entry.name for entry in archive.entries] == ["one.bin", "two.bin"]


def test_mime_quoted_printable_attachment():
    part = {
        "headers": ("Content-Type: text/plain; name=\"note.txt\"\r\n"
                    "Content-Transfer-Encoding: quoted-printable\r\n"
                    "Content-Disposition: attachment; filename=\"note.txt\""),
        "body": "hello=20world=0A=C3=A9tude",
    }
    image = macarchives.mime_message([part], preamble="")
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].name == "note.txt"
    assert archive.read(archive.entries[0], "data") == "hello world\nétude".encode()


def test_mime_unnamed_non_text_attachment_gets_part_name():
    body = base64.b64encode(b"\x00\x01\x02" * 40).decode()
    part = {
        "headers": ("Content-Type: application/octet-stream\r\n"
                    "Content-Transfer-Encoding: base64"),
        "body": body,
    }
    image = macarchives.mime_message([part], preamble="")
    archive = macextract.open(io.BytesIO(image))
    assert archive.entries[0].name == "part1"
    assert archive.read(archive.entries[0], "data") == b"\x00\x01\x02" * 40


def test_mime_appledouble_part_pairs_forks():
    image = macarchives.mime_appledouble(name=b"Report",
                                         data=b"spreadsheet bytes",
                                         rsrc=b"rsrc-bytes",
                                         type=b"XLS8", creator=b"XCEL")
    archive = macextract.open(io.BytesIO(image))
    assert len(archive.entries) == 1
    entry = archive.entries[0]
    assert entry.name == "Report"
    assert archive.read(entry, "data") == b"spreadsheet bytes"
    assert archive.read(entry, "rsrc") == b"rsrc-bytes"
    assert entry.type == b"XLS8"
    assert entry.creator == b"XCEL"


def test_mime_appledouble_extract(tmp_path):
    image = macarchives.mime_appledouble(name=b"Report",
                                         data=b"data-bytes",
                                         rsrc=b"rsrc-bytes")
    archive = macextract.open(io.BytesIO(image))
    written = archive.extract(tmp_path)
    assert (tmp_path / "Report").read_bytes() == b"data-bytes"
    assert (tmp_path / "._Report").exists()


def test_mime_nested_multipart():
    inner_part = macarchives.mime_b64_part("inner.bin", b"inner-payload")
    inner = macarchives.mime_message([inner_part], boundary="InnerBoundary",
                                     preamble="",
                                     headers=("Content-Type: multipart/mixed; boundary=\"InnerBoundary\""))
    inner_text = inner.decode("latin-1").split("\r\n", 2)[2]  # drop inner headers
    outer_part = {
        "headers": ("Content-Type: multipart/mixed; boundary=\"InnerBoundary\"\r\n"
                    "Content-Disposition: attachment; filename=\"nested\""),
        "body": inner_text,
    }
    image = macarchives.mime_message([outer_part], preamble="")
    archive = macextract.open(io.BytesIO(image))
    names = [entry.name for entry in archive.entries]
    assert "inner.bin" in names


def test_mime_paste_uuencode_body():
    uue = macarchives.uuencode(name="pasted.txt", data=b"pasted content").decode("ascii")
    part = {
        "headers": "Content-Type: text/plain\r\nContent-Transfer-Encoding: 7bit",
        "body": uue,
    }
    image = macarchives.mime_message([part], preamble="")
    archive = macextract.open(io.BytesIO(image))
    assert any(entry.name == "pasted.txt" for entry in archive.entries)


def test_mime_text_body_only_rejected():
    part = {
        "headers": "Content-Type: text/plain\r\nContent-Transfer-Encoding: 7bit",
        "body": "Just a letter, no attachments.",
    }
    image = macarchives.mime_message([part], preamble="")
    with pytest.raises(CorruptError):
        macextract.open(io.BytesIO(image))


def test_mime_no_headers_rejected():
    with pytest.raises(UnsupportedError):
        macextract.open(io.BytesIO(b"just some prose\nwithout any headers at all\n"))


def test_mime_base64_entry_is_single_binary_payload():
    # Nested archives are NOT unwrapped by the library; the Filer
    # re-opens extracted archives itself.
    inner = macarchives.macbinary(name=b"Inner", data=b"inner-data")
    part = macarchives.mime_b64_part("Inner.bin", inner)
    image = macarchives.mime_message([part])
    archive = macextract.open(io.BytesIO(image))
    entry = archive.entries[0]
    assert entry.name == "Inner.bin"
    assert archive.read(entry, "data") == inner
