"""MacBinary I, II and III.

Layout (all integers big-endian, seconds since 1904-01-01):

    0    1   version: 0 (I), 129 (II), 130 (III)
    1    1   filename length, 1-63
    2    63  filename
    65   4   file type
    69   4   file creator
    73   1   Finder flags, high byte
    74   1   zero
    75   2   window vertical position
    77   2   window horizontal position
    79   2   window/folder ID
    81   1   protected flag (low bit)
    82   1   zero
    83   4   data fork length
    87   4   resource fork length
    91   4   creation date
    95   4   modification date
    99   2   Get Info comment length (II and later)
    101  1   Finder flags, low byte (II and later)
    116  4   total packed size (III)
    120  2   secondary header length, padded to 128 (III)
    122  1   version byte (see above)
    123  1   minimum MacBinary version needed to read (II and later)
    124  2   CRC-16/AUG-CCITT of bytes 0-123 (II and later)
    126  2   zero

The data fork follows the header (and any secondary header) padded to a
128-byte boundary; the resource fork follows it, padded likewise.
"""

import struct

from .._core import Archive, Entry
from .._crc16 import crc16_ccitt
from ..errors import CorruptError

MAX_FORK = 0x007FFFFF  # 0x7F FFFF, per the MacBinary II standard
VERSION_MB1, VERSION_MB2, VERSION_MB3 = 0, 129, 130


def _pad128(n):
    return (n + 127) & ~127


def _parse(data):
    if len(data) < 128:
        raise CorruptError("MacBinary: file too small for a header")
    if data[0] != 0:
        raise CorruptError("MacBinary: version byte must be zero")
    name_len = data[1]
    if not 1 <= name_len <= 63:
        raise CorruptError("MacBinary: filename length %d out of range" % name_len)
    if data[74] != 0 or data[82] != 0:
        raise CorruptError("MacBinary: reserved byte not zero")
    data_len, rsrc_len = struct.unpack_from(">II", data, 83)
    if data_len > MAX_FORK or rsrc_len > MAX_FORK:
        raise CorruptError("MacBinary: fork length out of range")

    version = data[122]
    min_version = data[123]
    if version in (VERSION_MB2, VERSION_MB3):
        want = struct.unpack_from(">H", data, 124)[0]
        got = crc16_ccitt(data[:124])
        if want != got:
            raise CorruptError("MacBinary: header CRC mismatch (0x%04x != 0x%04x)" % (want, got))
        flags_low = data[101]
        secondary = _secondary_header_length(data, version)
        comment_len = struct.unpack_from(">H", data, 99)[0]
    elif version == VERSION_MB1 and data[101:126] == b"\0" * 25:
        flags_low = 0
        secondary = 0
        comment_len = 0
    else:
        raise CorruptError("MacBinary: unsupported version combination (%d, %d)" % (version, min_version))

    body_start = 128 + _pad128(secondary)
    data_start = body_start
    rsrc_start = data_start + _pad128(data_len)
    needed = rsrc_start + _pad128(rsrc_len)
    if needed > len(data):
        raise CorruptError("MacBinary: truncated (need %d bytes, have %d)" % (needed, len(data)))

    name_bytes = data[2:2 + name_len]
    try:
        name = name_bytes.decode("mac_roman")
    except UnicodeDecodeError:
        name = name_bytes.decode("mac_roman", errors="replace")

    flags_high = data[73]
    flags = (flags_high << 8) | flags_low

    finder_info = (data[65:81] + b"\0" * 16)

    entry = Entry(
        name=name,
        type=data[65:69],
        creator=data[69:73],
        finder_flags=flags,
        locked=bool(flags & 0x8000) or bool(data[81] & 1),
        created=struct.unpack_from(">I", data, 91)[0],
        modified=struct.unpack_from(">I", data, 95)[0],
        finder_info=finder_info,
        data_size=data_len,
        resource_size=rsrc_len,
        _data=data[data_start:data_start + data_len],
        _rsrc=data[rsrc_start:rsrc_start + rsrc_len],
    )
    archive = Archive()
    archive.format = {VERSION_MB1: "MacBinary I", VERSION_MB2: "MacBinary II",
                      VERSION_MB3: "MacBinary III"}[version]
    archive.entries = [entry]
    return archive


def _secondary_header_length(data, version):
    if version >= VERSION_MB3:
        return struct.unpack_from(">H", data, 120)[0]
    return 0


def probe(data):
    if len(data) < 128:
        return 0
    if data[0] != 0:
        return 0
    if not 1 <= data[1] <= 63:
        return 0
    if data[74] != 0 or data[82] != 0:
        return 0
    data_len, rsrc_len = struct.unpack_from(">II", data, 83)
    if data_len > MAX_FORK or rsrc_len > MAX_FORK:
        return 0
    version = data[122]
    if version in (VERSION_MB2, VERSION_MB3):
        secondary = _secondary_header_length(data, version)
        if 128 + _pad128(secondary) + _pad128(data_len) + _pad128(rsrc_len) > len(data):
            return 0
        # Structure is sound; even a bad CRC means it is MacBinary that is
        # damaged, not some other format, so recognise it either way.
        return 90
    if version == VERSION_MB1 and data[101:126] == b"\0" * 25:
        if 128 + _pad128(data_len) + _pad128(rsrc_len) == len(data):
            return 20
        return 0
    return 0


def open_data(data, password=None):
    # MacBinary has no encryption; a supplied password is simply unused.
    return _parse(data)
