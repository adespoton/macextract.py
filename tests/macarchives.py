"""Generators for synthetic archives used as test fixtures.

Everything here builds byte strings in memory; no binary fixtures are
committed. Writers aim to match the published formats, including the
weird corners the tests exercise.
"""

import struct

from macextract._crc16 import crc16_ccitt

MAC_EPOCH = 2082844800


def macbinary(name=b"TestFile", data=b"hello world", rsrc=b"", type=b"TEXT",
              creator=b"ttxt", version=129, flags=0, created=400000000,
              modified=400000100, comment=b"", secondary=b"",
              bad_crc=False, zero_pad=True):
    """Build a MacBinary image. ``version`` 0 = MB I, 129 = II, 130 = III."""
    name = bytes(name)
    header = bytearray(128)
    header[0] = 0
    header[1] = len(name)
    header[2:2 + len(name)] = name
    header[65:69] = type
    header[69:73] = creator
    header[73] = (flags >> 8) & 0xFF
    header[75:77] = struct.pack(">H", 10)   # window vertical
    header[77:79] = struct.pack(">H", 20)   # window horizontal
    header[79:81] = struct.pack(">H", 100)  # window/folder ID
    header[81] = 0
    struct.pack_into(">II", header, 83, len(data), len(rsrc))
    struct.pack_into(">II", header, 91, created, modified)
    if version >= 129:
        struct.pack_into(">H", header, 99, len(comment))
        header[101] = flags & 0xFF
        if version >= 130:
            struct.pack_into(">I", header, 116, 128 + len(data) + len(rsrc))
            struct.pack_into(">H", header, 120, len(secondary))
        header[122] = version
        header[123] = 129
        crc = crc16_ccitt(bytes(header[:124]))
        if bad_crc:
            crc ^= 0xFFFF
        struct.pack_into(">H", header, 124, crc)
    out = bytearray(header)
    if version >= 130 and secondary:
        sec = secondary.ljust(len(secondary) + (-len(secondary)) % 128, b"\0")
        out += sec
    pad = lambda n: (n + 127) & ~127
    data_part = data.ljust(pad(len(data)), b"\0")
    out += data_part
    out += rsrc.ljust(pad(len(rsrc)), b"\0")
    if comment:
        out += comment.ljust(pad(len(comment)), b"\0")
    return bytes(out)
