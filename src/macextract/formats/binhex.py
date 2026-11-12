"""BinHex 4.0 (.hqx, .hex, .hcx).

Layout: an optional human-readable prologue ending in the marker line
"(This file must be converted with BinHex 4.0)", then a colon, the
6-bit encoded payload, and a closing colon. The payload bytes are a
run-length-encoded stream of three sections, each followed by a 16-bit
CRC (polynomial 0x1021, init 0x0000): header, data fork, resource fork.
Written from Peter N. Lewis's BinHex 4.0 Definition (August 1991) and
RFC 1741 Appendix A.
"""

import struct

from .._core import Archive, Entry
from .._crc16 import crc16_ccitt
from ..errors import CorruptError

MARKER = b"This file must be converted with BinHex"
ALPHABET = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr"
_REVERSE = {c: i for i, c in enumerate(ALPHABET)}
_SKIP = b"\r\n\t "  # return-class whitespace the decoder must ignore


def _sixbit_decode(chars):
    out = bytearray()
    acc = 0
    nbits = 0
    for char in chars:
        value = _REVERSE.get(char)
        if value is None:
            raise CorruptError("BinHex: invalid character %r" % char)
        acc = (acc << 6) | value
        nbits += 6
        if nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
    return bytes(out)


def _rle_decode(src):
    out = bytearray()
    last = None
    i = 0
    while i < len(src):
        byte = src[i]
        if byte == 0x90:
            if i + 1 >= len(src):
                raise CorruptError("BinHex: truncated run-length marker")
            count = src[i + 1]
            i += 2
            if count == 0:
                out.append(0x90)
                last = 0x90
                continue
            if last is None:
                raise CorruptError("BinHex: run with no preceding byte")
            out += bytes((last,)) * (count - 1)
            continue
        out.append(byte)
        last = byte
        i += 1
    return bytes(out)


def _check_section(section, label):
    if len(section) < 2:
        raise CorruptError("BinHex: %s section missing its CRC" % label)
    stored = struct.unpack_from(">H", section, len(section) - 2)[0]
    if crc16_ccitt(section[:-2] + b"\0\0") != stored:
        raise CorruptError("BinHex: %s CRC mismatch" % label)


def _find_payload(data):
    marker = data.find(MARKER)
    if marker >= 0:
        opener = data.find(b":", marker + len(MARKER))
        if opener < 0:
            raise CorruptError("BinHex: marker found but no opening colon")
        return opener
    window = data[:512]
    opener = window.find(b":")
    if opener >= 0:
        return opener
    raise CorruptError("BinHex: no marker and no opening colon")


def _payload_chars(data, opener):
    chars = []
    i = opener + 1
    while i < len(data):
        byte = data[i]
        if byte == ord(":"):
            return bytes(chars), i
        if byte in _SKIP:
            i += 1
            continue
        chars.append(byte)
        i += 1
    raise CorruptError("BinHex: missing closing colon")


def _parse(data):
    if not data:
        raise CorruptError("BinHex: empty file")
    opener = _find_payload(data)
    payload, closer = _payload_chars(data, opener)
    if not payload:
        raise CorruptError("BinHex: empty payload")
    # Leftover bits that do not fill a byte are padding; an extra trailing
    # 0-valued 6-bit group is tolerated for the same reason.
    decoded = _rle_decode(_sixbit_decode(payload.decode("latin-1")))

    if len(decoded) < 1 + 1 + 1 + 4 + 4 + 2 + 4 + 4 + 2:
        raise CorruptError("BinHex: header too small")
    name_len = decoded[0]
    if name_len < 1 or name_len > 63:
        raise CorruptError("BinHex: filename length %d out of range" % name_len)
    header_end = 1 + name_len + 1 + 4 + 4 + 2 + 4 + 4 + 2
    if len(decoded) < header_end:
        raise CorruptError("BinHex: truncated header")
    header = decoded[:header_end]
    _check_section(header, "header")
    name_bytes = header[1:1 + name_len]
    if header[1 + name_len] != 0:
        raise CorruptError("BinHex: missing NUL after filename")
    type_off = 1 + name_len + 1
    file_type = header[type_off:type_off + 4]
    creator = header[type_off + 4:type_off + 8]
    flags = struct.unpack_from(">H", header, type_off + 8)[0]
    data_len = struct.unpack_from(">I", header, type_off + 10)[0]
    rsrc_len = struct.unpack_from(">I", header, type_off + 14)[0]

    data_start = header_end
    data_end = data_start + data_len + 2
    rsrc_start = data_end
    rsrc_end = rsrc_start + rsrc_len + 2
    if len(decoded) < rsrc_end:
        raise CorruptError("BinHex: truncated forks")
    data_section = decoded[data_start:data_end]
    rsrc_section = decoded[rsrc_start:rsrc_end]
    _check_section(data_section, "data fork")
    _check_section(rsrc_section, "resource fork")

    try:
        name = name_bytes.decode("mac_roman")
    except UnicodeDecodeError:
        name = name_bytes.decode("mac_roman", errors="replace")

    # FInfo is 16 bytes: type+creator+flags+fdLocation(4)+reserved(2).
    # AppleDouble finder info is 32 bytes: FInfo + zero ExtendedFinderInfo.
    finder_info = file_type + creator + struct.pack(">H", flags) + b"\0" * 6 + b"\0" * 16

    entry = Entry(
        name=name,
        type=file_type,
        creator=creator,
        finder_flags=flags,
        locked=bool(flags & 0x8000),
        created=0,
        modified=0,
        finder_info=finder_info,
        data_size=data_len,
        resource_size=rsrc_len,
        _data=data_section[:-2],
        _rsrc=rsrc_section[:-2],
    )
    archive = Archive()
    archive.format = "BinHex 4.0"
    archive.entries = [entry]
    return archive


def probe(data):
    if not data:
        return 0
    marker = data.find(MARKER)
    if marker >= 0 and b":" in data[marker:]:
        return 100
    if b":" in data[:512]:
        try:
            _parse(data)
        except CorruptError:
            return 0
        return 50
    return 0


def open_data(data, password=None, filename=None):
    # BinHex has no encryption; a supplied password is simply unused.
    return _parse(data)
