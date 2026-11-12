"""base64 (RFC 2045 section 6.8, RFC 4648) in the two shapes a file
arrives in when it is not inside a MIME message (those are fmt_mime's
job).

Two shapes:

  ``begin-base64 <mode> <name>`` ... ``====`` — sharutils/``uuencode -m``
  output; carries a name. Several documents in one file are read, the
  same as uuencode and BinHex.

  bare body — the whole file is base64, with no name; the caller's
  filename hint names the entry.

Characters outside the alphabet are skipped (mail garbage). A stream
that stops part-way through a group yields the bytes its partial group
implies, matching deark's reading.
"""

import base64
import binascii

from .._core import Archive, Entry
from ..errors import CorruptError

ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BEGIN_PREFIX = b"begin-base64 "


def _decode_b64(data):
    """Lenient RFC 2045 base64: skip non-alphabet bytes, stop at '='."""
    cleaned = bytearray()
    for byte in data:
        if byte == ord("="):
            break
        if byte in ALPHABET:
            cleaned.append(byte)
    cleaned = bytes(cleaned)
    remainder = len(cleaned) % 4
    if remainder:
        # A stream that stops mid-group still implies whole bytes;
        # pad to the next quantum and let the decoder emit them.
        padding = 4 - remainder
        if remainder == 1:
            # One character implies nothing; drop it.
            cleaned = cleaned[:-1]
            remainder = 0
            padding = 0
        cleaned += b"=" * padding
    try:
        return base64.b64decode(cleaned)
    except binascii.Error as error:
        raise CorruptError("base64: %s" % error)


def _is_alphabet_line(line):
    stripped = line.rstrip(b"\r")
    for byte in stripped:
        if byte not in ALPHABET and byte not in b"=+/":
            return False
    return True


def _probe_bare(data):
    lines = [line for line in data.split(b"\n") if line.strip()]
    if len(lines) < 3:
        return 0
    body_lines = lines[:-1]
    width = len(body_lines[0].rstrip(b"\r"))
    if width < 4:
        return 0
    if any(len(line.rstrip(b"\r")) != width for line in body_lines):
        return 0
    if not all(_is_alphabet_line(line) for line in lines):
        return 0
    # Require padding in the final line so a file of plain text that
    # happens to be alphabet-shaped is not claimed.
    if b"=" not in lines[-1]:
        return 0
    return 55


def _split_begin_sections(data):
    """Yield (name, body_bytes) for each begin-base64 section."""
    sections = []
    current = None  # [name, bytearray]
    for raw in data.split(b"\n"):
        line = raw.rstrip(b"\r")
        if line.startswith(_BEGIN_PREFIX):
            if current is not None:
                sections.append((current[0], bytes(current[1])))
            rest = line[len(_BEGIN_PREFIX):].decode("latin-1").split(None, 1)
            name = "unnamed"
            if len(rest) == 2:
                name = rest[1].strip() or "unnamed"
            elif len(rest) == 1:
                try:
                    int(rest[0], 8)  # a lone mode with no name
                except ValueError:
                    name = rest[0].strip() or "unnamed"
            current = [name, bytearray()]
            continue
        if line.rstrip() == b"====":
            if current is not None:
                sections.append((current[0], bytes(current[1])))
                current = None
            continue
        if current is not None:
            current[1] += raw + b"\n"
    if current is not None:
        sections.append((current[0], bytes(current[1])))
    return sections


def _parse(data, name_hint=None):
    if not data:
        raise CorruptError("base64: empty file")
    entries = []
    if any(line.startswith(_BEGIN_PREFIX) for line in data.split(b"\n")):
        for name, body in _split_begin_sections(data):
            payload = _decode_b64(body)
            entries.append(Entry(name=name, data_size=len(payload), _data=payload))
        if not entries:
            raise CorruptError("base64: no decodable begin-base64 sections")
    else:
        payload = _decode_b64(data)
        if not payload:
            raise CorruptError("base64: nothing decodable")
        entries.append(Entry(name=name_hint or "unnamed",
                             data_size=len(payload), _data=payload))

    archive = Archive()
    archive.format = "base64"
    archive.entries = entries
    return archive


def probe(data):
    if not data:
        return 0
    if any(line.startswith(_BEGIN_PREFIX) for line in data.split(b"\n")):
        return 85
    return _probe_bare(data)


def open_data(data, password=None, filename=None):
    # base64 has no encryption; a supplied password is simply unused.
    hint = filename
    if hint:
        base = hint.replace("\\", "/").rsplit("/", 1)[-1]
        if base.lower().endswith(".b64"):
            base = base[:-4]
        hint = base or None
    return _parse(data, name_hint=hint)
