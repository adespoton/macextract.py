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


BINHEX_ALPHABET = "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr"


def binhex(name="TestFile", data=b"hello world", rsrc=b"", type=b"TEXT",
           creator=b"ttxt", flags=0, bad_header_crc=False, bad_data_crc=False,
           rle_marker_zero=True):
    """Build a BinHex 4.0 image in memory (test generator)."""
    name_bytes = name.encode("mac_roman") if isinstance(name, str) else name
    header = bytearray(b"\0")  # placeholder
    body = bytearray()
    body.append(len(name_bytes))
    body += name_bytes
    body.append(0)
    body += type + creator
    body += struct.pack(">H", flags)
    body += struct.pack(">II", len(data), len(rsrc))
    header_crc = crc16_ccitt(bytes(body) + b"\0\0")
    if bad_header_crc:
        header_crc ^= 0xFF
    body += struct.pack(">H", header_crc)

    data_crc = crc16_ccitt(data + b"\0\0")
    if bad_data_crc:
        data_crc ^= 0xFF
    body += data + struct.pack(">H", data_crc)

    rsrc_crc = crc16_ccitt(rsrc + b"\0\0")
    body += rsrc + struct.pack(">H", rsrc_crc)

    encoded = _binhex_rle(bytes(body))
    payload = _sixbit_encode(encoded)
    lines = []
    first = ":" + payload[:63]
    lines.append(first)
    rest = payload[63:]
    width = 64
    lines += [rest[i:i + width] for i in range(0, len(rest), width)]
    return ("(This file must be converted with BinHex 4.0)\n"
            + "\n".join(lines) + ":\n").encode("ascii")


def _binhex_rle(src):
    out = bytearray()
    i = 0
    while i < len(src):
        byte = src[i]
        if byte == 0x90:
            out += b"\x90\x00"
            i += 1
            continue
        run = 1
        while i + run < len(src) and src[i + run] == byte and run < 255:
            run += 1
        if run >= 3:
            out.append(byte)
            out.append(0x90)
            out.append(run)
            i += run
        else:
            out.append(byte)
            i += 1
    return bytes(out)


def _sixbit_encode(src):
    out = []
    acc = 0
    nbits = 0
    for byte in src:
        acc = (acc << 8) | byte
        nbits += 8
        while nbits >= 6:
            nbits -= 6
            out.append(BINHEX_ALPHABET[(acc >> nbits) & 0x3F])
    if nbits:
        out.append(BINHEX_ALPHABET[(acc << (6 - nbits)) & 0x3F])
    return "".join(out)
