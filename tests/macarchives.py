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


AS_EPOCH = __import__("datetime").datetime(2000, 1, 1, tzinfo=__import__("datetime").timezone.utc)


def applesingle_seconds(dt):
    delta = dt - AS_EPOCH
    return int(delta.total_seconds())


def applesingle(name=b"TestFile", data=b"hello world", rsrc=b"",
                type=b"TEXT", creator=b"ttxt", flags=0, created=None, modified=None,
                magic=0x00051600, version=0x00020000, macinfo=0x00,
                include_dates=True, include_finder=True, include_name=True):
    """Build an AppleSingle (or AppleDouble header, magic=0x00051607)."""
    entries = []
    if data is not None and magic == 0x00051600:
        entries.append((1, data))
    if rsrc:
        entries.append((2, rsrc))
    if include_name and name is not None:
        entries.append((3, bytes(name)))
    if include_dates:
        created = created if created is not None else applesingle_seconds(
            __import__("datetime").datetime(1993, 6, 1, tzinfo=__import__("datetime").timezone.utc))
        modified = modified if modified is not None else applesingle_seconds(
            __import__("datetime").datetime(1995, 11, 4, tzinfo=__import__("datetime").timezone.utc))
        entries.append((8, struct.pack(">iiii", created, modified, 0, 0)))
    if include_finder:
        finder = type + creator + struct.pack(">H", flags) + b"\0" * 22
        entries.append((9, finder))
    entries.append((10, b"\0\0\0" + bytes([macinfo])))

    header_size = 26 + 12 * len(entries)
    offset = header_size
    parts = []
    descriptors = []
    for entry_id, payload in entries:
        descriptors.append((entry_id, offset, len(payload)))
        offset += len(payload)
    parts.append(struct.pack(">II", magic, version) + b"\0" * 16)
    parts.append(struct.pack(">H", len(entries)))
    for entry_id, off, length in descriptors:
        parts.append(struct.pack(">III", entry_id, off, length))
    for _, payload in entries:
        parts.append(payload)
    return b"".join(parts)


def uuencode(name="TestFile", data=b"hello world", mode=0o644,
             rsrc=None, finfo=None, extra_segments=()):
    """Build a uuencode stream; optionally with MU-style fork sections."""
    segments = [(mode, name, data)]
    if rsrc is not None:
        segments.append((mode, name + ".rsrc", rsrc))
    if finfo is not None:
        segments.append((mode, name + ".finfo", finfo))
    segments.extend(extra_segments)
    out = []
    for seg_mode, seg_name, payload in segments:
        out.append("begin %03o %s" % (seg_mode, seg_name))
        i = 0
        while i < len(payload):
            chunk = payload[i:i + 45]
            i += len(chunk)
            line = chr(len(chunk) + 32)
            for j in range(0, len(chunk), 3):
                b = chunk[j:j + 3].ljust(3, b"\0")
                n = (b[0] << 16) | (b[1] << 8) | b[2]
                line += "".join(chr(((n >> shift) & 0x3F) + 32) for shift in (18, 12, 6, 0))
            out.append(line)
        out.append("`")
        out.append("end")
    return ("\n".join(out) + "\n").encode("ascii")


def btoa(name="file.txt", data=b"hello world", newver=True, bad_sum=False):
    """Build a .btoa image in memory (v4 or v5)."""
    lines_out = ["xbtoa5 78 %s Begin" % (name or "-") if newver else "xbtoa Begin"]
    eor = 0; total = 0; rot = 0
    def chk(ch):
        nonlocal eor, total, rot
        eor ^= ch
        total = (total + ch + 1) & 0xFFFFFFFF
        rot = (((rot << 1) | (rot >> 31)) & 0xFFFFFFFF) + ch
    body = []
    i = 0
    groups = []
    while i < len(data):
        quad = data[i:i+4]
        i += len(quad)
        full = len(quad) == 4
        groups.append((quad.ljust(4, b"\0"), full))
    if not groups:
        groups = []
    chars = []
    for padded, full in groups:
        if full and padded == b"\0\0\0\0":
            chars.append("z")
            continue
        if full and newver and padded == b" " * 4:
            chars.append("y")
            continue
        code = int.from_bytes(padded, "big")
        block = []
        for _ in range(5):
            block.append(code % 85 + 33)
            code //= 85
        chars.extend(chr(c) for c in reversed(block))
    perline = 78 if newver else 78
    line_chars = []
    lines = []
    for ch in chars:
        line_chars.append(ch)
        if len(line_chars) >= perline:
            lines.append(line_chars); line_chars = []
    if line_chars:
        lines.append(line_chars)
    for lc in lines:
        text = "".join(lc)
        for c in text:
            chk(ord(c))
        if newver:
            lines_out.append(text + chr(33 + (total % 85)))
        else:
            lines_out.append(text)
    if not newver:
        # version 4 checksums the decoded quad bytes (padding included)
        eor = 0; total = 0; rot = 0
        for padded, _full in groups:
            for b in padded:
                chk(b)
    want_hex = "%x" % len(data)
    if bad_sum:
        eor ^= 0xFF
    lines_out.append("xbtoa End N %d %s E %x S %x R %x" % (len(data), want_hex, eor, total, rot))
    return ("\n".join(lines_out) + "\n").encode("latin-1")


import base64 as _b64mod


def base64_begin(name="TestFile", data=b"hello world", mode=0o644):
    encoded = _b64mod.b64encode(data).decode()
    lines = [encoded[i:i + 76] for i in range(0, len(encoded), 76)]
    return ("begin-base64 %03o %s\n%s\n====\n" % (mode, name, "\n".join(lines))).encode("ascii")


def base64_bare(data=b"hello world"):
    encoded = _b64mod.b64encode(data).decode()
    lines = [encoded[i:i + 76] for i in range(0, len(encoded), 76)]
    return ("\n".join(lines) + "\n").encode("ascii")


def mime_message(parts, boundary="Apple-Mail-Boundary",
                 preamble="This is the message body.\n",
                 headers=None):
    if headers is None:
        headers = ("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n" % boundary)
    out = [headers.rstrip("\r\n"), ""]
    if preamble:
        out.append(preamble.rstrip("\n"))
    for part in parts:
        out.append("--" + boundary)
        out.append(part.get("headers", ""))
        out.append("")
        out.append(part["body"])
    out.append("--" + boundary + "--")
    return "\r\n".join(out).encode("latin-1")


def mime_b64_part(filename, data, ctype="application/octet-stream"):
    encoded = _b64mod.b64encode(data).decode()
    lines = [encoded[i:i + 76] for i in range(0, len(encoded), 76)]
    return {
        "headers": ("Content-Type: %s; name=\"%s\"\r\n"
                    "Content-Transfer-Encoding: base64\r\n"
                    "Content-Disposition: attachment; filename=\"%s\"" % (ctype, filename, filename)),
        "body": "\r\n".join(lines),
    }


def appledouble_part_headers():
    return ("Content-Type: application/applefile\r\n"
            "Content-Transfer-Encoding: base64")


def mime_appledouble(name=b"Doc", data=b"data-fork-bytes", rsrc=b"rsrc-bytes",
                     type=b"TEXT", creator=b"ttxt"):
    applefile = applesingle(name=name, data=None, rsrc=rsrc,
                            type=type, creator=creator,
                            magic=0x00051607)
    first = {
        "headers": appledouble_part_headers(),
        "body": "\r\n".join(_b64mod.b64encode(applefile).decode()[i:i + 76]
                          for i in range(0, len(_b64mod.b64encode(applefile).decode()), 76)),
    }
    second = {
        "headers": ("Content-Type: application/octet-stream\r\n"
                    "Content-Transfer-Encoding: base64"),
        "body": "\r\n".join(_b64mod.b64encode(data).decode()[i:i + 76]
                          for i in range(0, len(_b64mod.b64encode(data).decode()), 76)),
    }
    boundary = "AppleMailBoundary"
    headers = ("MIME-Version: 1.0\r\n"
               "Content-Type: multipart/appledouble; boundary=\"%s\"\r\n" % boundary)
    return mime_message([first, second], boundary=boundary, headers=headers, preamble="")


import heapq
from collections import Counter


def huffman_encode(payload):
    """Encode bytes as a bit-serialized Huffman stream (tree + codes),
    matching the layout the PackIt reader (and StuffIt method 3 /
    DiskDoubler method 4) consumes. Test-side counterpart only."""
    if not payload:
        raise ValueError("huffman_encode needs at least one byte")
    freq = Counter(payload)
    heap = [(weight, index, ("leaf", symbol)) for index, (symbol, weight)
            in enumerate(sorted(freq.items()))]
    heapq.heapify(heap)
    counter = len(heap)
    while len(heap) > 1:
        weight_a, _, node_a = heapq.heappop(heap)
        weight_b, _, node_b = heapq.heappop(heap)
        heapq.heappush(heap, (weight_a + weight_b, counter,
                              ("node", node_a, node_b)))
        counter += 1
    root = heap[0][2]

    def serialize(node):
        if node[0] == "leaf":
            return "1" + format(node[1], "08b")
        return "0" + serialize(node[1]) + serialize(node[2])

    bits = serialize(root)
    if root[0] != "leaf":
        codes = {}

        def assign(node, prefix):
            if node[0] == "leaf":
                codes[node[1]] = prefix
                return
            assign(node[1], prefix + "0")
            assign(node[2], prefix + "1")

        assign(root, "")
        bits += "".join(codes[byte] for byte in payload)
    pad = (-len(bits)) % 8
    bits += "0" * pad
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def _packit_header(name, data_len, rsrc_len, type=b"TEXT", creator=b"TTxt",
                   flags=0x0100, locked=False, created=400000000,
                   modified=400000100):
    name_bytes = name.encode("mac_roman") if isinstance(name, str) else name
    header = bytearray(94)
    header[0] = len(name_bytes)
    header[1:64] = name_bytes.ljust(63, b"\0")
    header[64:68] = type
    header[68:72] = creator
    header[72] = (flags >> 8) & 0xFF
    struct.pack_into(">H", header, 74, 1 if locked else 0)
    struct.pack_into(">II", header, 76, data_len, rsrc_len)
    struct.pack_into(">II", header, 84, created, modified)
    # Header CRC polynomial is not established by the format notes;
    # the field exists, we write a fixed value.
    struct.pack_into(">H", header, 92, 0x1234)
    return bytes(header)


def packit(files=((b"TestFile", b"hello world", b"", b"TEXT", b"TTxt"),),
           kind="stored", tail_word=True):
    """Build a .pit image. ``files`` items are
    (name, data, rsrc, type, creator) tuples or full dicts.
    ``kind`` is 'stored', 'huffman' or 'encrypted'."""
    out = bytearray()
    for spec in files:
        if isinstance(spec, dict):
            name = spec.get("name", b"TestFile")
            data = spec.get("data", b"")
            rsrc = spec.get("rsrc", b"")
            type_ = spec.get("type", b"TEXT")
            creator = spec.get("creator", b"TTxt")
            flags = spec.get("flags", 0x0100)
            locked = spec.get("locked", False)
            created = spec.get("created", 400000000)
            modified = spec.get("modified", 400000100)
            spec_kind = spec.get("kind", kind)
        else:
            name, data, rsrc, type_, creator = spec
            flags, locked, created, modified, spec_kind = 0x0100, False, 400000000, 400000100, kind
        header = _packit_header(name, len(data), len(rsrc), type_, creator,
                                flags, locked, created, modified)
        stream = header + data + rsrc + b"\xde\xad"
        if spec_kind == "stored":
            out += b"PMag" + stream
        elif spec_kind == "huffman":
            out += b"PMa4" + huffman_encode(stream)
        elif spec_kind == "encrypted":
            out += b"PMa5" + stream
        else:
            raise ValueError("unknown kind %r" % spec_kind)
    if tail_word:
        out += b"PEnd"
    return bytes(out)
